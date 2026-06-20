// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * FORENSIQ — S3 archival of audit artifacts.
 *
 * Why archive: Postgres holds the structured report (findings, scores,
 * metadata). The raw tool outputs and rendered PDFs are bulky and
 * rarely re-read. Putting them in S3 with a lifecycle policy (hot →
 * IA → Glacier) keeps the DB lean and gives us a cheap audit trail.
 *
 * Why no AWS SDK: the SDK adds ~5MB to the worker bundle and 10+
 * transitive deps. We only need PutObject/GetObject. SigV4 signing is
 * ~100 lines of HMAC, and `fetch` does the rest. If we grow the S3
 * surface (multipart uploads, presigned URLs, lifecycle reads) it's
 * worth pulling in @aws-sdk/client-s3 at that point.
 *
 * Optional: if S3_BUCKET isn't set, archive() is a no-op. The worker
 * still produces the in-memory PDF for the synchronous /api/audits/:id/pdf
 * download — S3 is purely an archive tier.
 */

import { createHash, createHmac } from 'crypto';

interface ArchiveOpts {
  bucket: string;
  region: string;
}

function getOpts(): ArchiveOpts | null {
  const bucket = process.env.S3_REPORTS_BUCKET;
  if (!bucket) return null;
  return { bucket, region: process.env.AWS_REGION || 'us-east-1' };
}

// ─── SigV4 helpers ───────────────────────────────────────────────────
// Minimal SigV4 implementation. Tested against AWS S3 PutObject.
// References:
//   https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html

function hexHash(buf: Buffer | string): string {
  return createHash('sha256').update(buf).digest('hex');
}

function hmac(key: Buffer | string, data: string): Buffer {
  return createHmac('sha256', key).update(data).digest();
}

function signingKey(secret: string, date: string, region: string, service: string): Buffer {
  const kDate    = hmac('AWS4' + secret, date);
  const kRegion  = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, 'aws4_request');
}

interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

/**
 * Read credentials. Order of precedence matches the AWS SDK:
 *   1. Explicit env (AWS_ACCESS_KEY_ID/SECRET_ACCESS_KEY)
 *   2. IRSA — k8s service account → web identity token → STS
 *      For pods with AWS_WEB_IDENTITY_TOKEN_FILE + AWS_ROLE_ARN set,
 *      we exchange the token for temporary creds. Cached for the token's
 *      validity period.
 *
 * In production on EKS the worker pod has IRSA configured via the
 * worker_iam_role_arn from Terraform.
 */
let cachedCreds: { creds: AwsCredentials; expiresAt: number } | null = null;

async function getCredentials(): Promise<AwsCredentials | null> {
  // 1. Direct env
  if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
    return {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      sessionToken: process.env.AWS_SESSION_TOKEN,
    };
  }

  // 2. IRSA via STS:AssumeRoleWithWebIdentity
  const tokenFile = process.env.AWS_WEB_IDENTITY_TOKEN_FILE;
  const roleArn = process.env.AWS_ROLE_ARN;
  if (!tokenFile || !roleArn) return null;

  // Cache valid for 5 minutes shy of expiry
  if (cachedCreds && cachedCreds.expiresAt > Date.now() + 5 * 60_000) {
    return cachedCreds.creds;
  }

  try {
    const fs = await import('fs/promises');
    const token = (await fs.readFile(tokenFile, 'utf8')).trim();

    // STS AssumeRoleWithWebIdentity is form-encoded GET
    const params = new URLSearchParams({
      Action: 'AssumeRoleWithWebIdentity',
      Version: '2011-06-15',
      RoleArn: roleArn,
      RoleSessionName: 'forensiq-worker',
      WebIdentityToken: token,
      DurationSeconds: '3600',
    });
    const res = await fetch(`https://sts.amazonaws.com/?${params}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) throw new Error(`STS returned ${res.status}`);
    // STS returns XML by default; with Accept: application/json it returns JSON
    const data = await res.json() as {
      AssumeRoleWithWebIdentityResponse?: {
        AssumeRoleWithWebIdentityResult: {
          Credentials: {
            AccessKeyId: string;
            SecretAccessKey: string;
            SessionToken: string;
            Expiration: string;
          };
        };
      };
    };
    const c = data.AssumeRoleWithWebIdentityResponse?.AssumeRoleWithWebIdentityResult?.Credentials;
    if (!c) throw new Error('STS response missing Credentials');

    cachedCreds = {
      creds: {
        accessKeyId: c.AccessKeyId,
        secretAccessKey: c.SecretAccessKey,
        sessionToken: c.SessionToken,
      },
      expiresAt: new Date(c.Expiration).getTime(),
    };
    return cachedCreds.creds;
  } catch (e) {
    console.warn('[s3] IRSA exchange failed:', (e as Error).message);
    return null;
  }
}

// ─── Public API ──────────────────────────────────────────────────────

/**
 * Upload an object to the archive bucket. Returns the S3 URI (s3://...)
 * which can be stored on the report row for later retrieval.
 *
 * On any failure we log and return null — archival is best-effort.
 * The audit still completes successfully even if S3 is down.
 */
export async function archive(
  key: string,
  body: Buffer | string,
  contentType: string,
): Promise<string | null> {
  const opts = getOpts();
  if (!opts) return null;

  const creds = await getCredentials();
  if (!creds) {
    console.warn('[s3] no AWS credentials available; skipping archive');
    return null;
  }

  const payload = Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
  const payloadHash = hexHash(payload);
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const host = `${opts.bucket}.s3.${opts.region}.amazonaws.com`;

  const headers: Record<string, string> = {
    'host': host,
    'x-amz-content-sha256': payloadHash,
    'x-amz-date': amzDate,
    'content-type': contentType,
  };
  if (creds.sessionToken) headers['x-amz-security-token'] = creds.sessionToken;

  // Canonical request
  const sortedHeaderNames = Object.keys(headers).sort();
  const canonicalHeaders = sortedHeaderNames.map(n => `${n}:${headers[n]}\n`).join('');
  const signedHeaders = sortedHeaderNames.join(';');
  const canonicalRequest = [
    'PUT',
    '/' + key.split('/').map(encodeURIComponent).join('/'),
    '',  // query string
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  // String to sign
  const credentialScope = `${dateStamp}/${opts.region}/s3/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    hexHash(canonicalRequest),
  ].join('\n');

  // Sign
  const signature = createHmac('sha256',
    signingKey(creds.secretAccessKey, dateStamp, opts.region, 's3')
  ).update(stringToSign).digest('hex');

  const authHeader =
    `AWS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  // PUT
  try {
    const res = await fetch(`https://${host}/${key}`, {
      method: 'PUT',
      headers: { ...headers, Authorization: authHeader },
      body: payload,
    });
    if (!res.ok) {
      const text = await res.text();
      console.warn(`[s3] put failed: ${res.status} ${text.slice(0, 200)}`);
      return null;
    }
    return `s3://${opts.bucket}/${key}`;
  } catch (e) {
    console.warn('[s3] upload error:', (e as Error).message);
    return null;
  }
}

/**
 * Archive an audit's artifacts. Called from the worker on completion.
 * Returns a map of artifact name → S3 URI so the worker can record
 * pointers on the report row.
 *
 * Layout:
 *   reports/{auditId}/report.json   structured payload
 *   reports/{auditId}/report.pdf    rendered PDF
 *   raw/{auditId}/{tool}.json       raw tool outputs (lifecycle → Glacier)
 */
export async function archiveAudit(opts: {
  auditId: string;
  reportJson: unknown;
  pdf?: Buffer;
  rawByTool?: Record<string, unknown>;
}): Promise<Record<string, string>> {
  const uris: Record<string, string> = {};

  const reportUri = await archive(
    `reports/${opts.auditId}/report.json`,
    JSON.stringify(opts.reportJson),
    'application/json',
  );
  if (reportUri) uris.report = reportUri;

  if (opts.pdf) {
    const pdfUri = await archive(
      `reports/${opts.auditId}/report.pdf`,
      opts.pdf,
      'application/pdf',
    );
    if (pdfUri) uris.pdf = pdfUri;
  }

  if (opts.rawByTool) {
    for (const [tool, raw] of Object.entries(opts.rawByTool)) {
      const uri = await archive(
        `raw/${opts.auditId}/${tool}.json`,
        JSON.stringify(raw),
        'application/json',
      );
      if (uri) uris[`raw_${tool}`] = uri;
    }
  }

  return uris;
}
