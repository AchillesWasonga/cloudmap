# CloudMap — Cloud Security Notes & Roadmap

Source: a hands-on session hardening the `wasonga.com` S3 + CloudFront setup. Captured here as reference + feature inspiration for CloudMap (multi-cloud misconfiguration scanner, Nmap-inspired).

---

## Part 1 — The S3 / CloudFront hardening walkthrough (reference findings)

This is the exact misconfiguration pattern and remediation, written up the way a scanner finding + fix should read.

### The core S3 access model (two independent layers)

There are two separate questions about any bucket, controlled by different mechanisms. Conflating them is the root of most real-world findings.

1. **Can my backend/CDN read it?** → Controlled by IAM roles / bucket policy (auth'd access). This is the *correct* way to grant access.
2. **Can the public read it?** → Controlled by Block Public Access (BPA), bucket policy `Principal: "*"`, and ACLs.

Key insight: **a backend never needs the bucket to be public to read from it.** Making a bucket public "so EC2/CloudFront could reach it" is the misconfiguration — wrong lever. Use IAM/OAC instead.

### The two S3 endpoints (this is what confuses people)

A bucket exposes two different URLs that behave oppositely:

| Endpoint | Example | Auth behavior | Public required? |
|---|---|---|---|
| REST endpoint | `bucket.s3.region.amazonaws.com` | Respects IAM/bucket-policy; OAC works here | No — should be private |
| Website endpoint | `bucket.s3-website-region.amazonaws.com` | Cannot authenticate; anonymous only | Yes — requires public-read |

**Why "deploy needed public but production doesn't":** deploy tooling often serves directly from the *website endpoint* (Path A → needs public). Later a CDN is layered on using the *REST endpoint* + OAC (Path B → must be private). Closing public access kills Path A but leaves Path B untouched — site keeps working.

### Why Block Public Access can be flipped ON without breaking a CloudFront site

BPA only blocks **anonymous/public** access. CloudFront OAC requests are **authenticated** (signed as the `cloudfront.amazonaws.com` service principal), so BPA does not apply to them. If flipping BPA on breaks the site → it was still on the public website-endpoint path. If it keeps working → it's on the authenticated REST/OAC path.

### The secure end-state (CloudFront + OAC)

- Bucket: **Block all public access = ON**, private.
- Bucket policy: `Principal: cloudfront.amazonaws.com`, `Action: s3:GetObject` only, `Condition` on `AWS:SourceArn = <distribution ARN>` (scopes to one distribution).
- CloudFront origin: the **S3 REST endpoint**, `Origin access = Origin access control (OAC)`.
- Static website hosting on the bucket: **Disabled** (vestigial once CDN serves everything).
- SPA routing + custom 404: handled at the **CloudFront layer** via custom error responses (403/404 → `/index.html` 200), independent of bucket website hosting.

### How to verify (read-only, safe)

```bash
# DNS / surface recon
shodan domain example.com
shodan search hostname:example.com   # "No results" = clean perimeter (CDN-only, no exposed origin)

# Bucket posture
aws s3 ls
aws s3api get-public-access-block --bucket BUCKET
aws s3api get-bucket-policy --bucket BUCKET
aws s3api get-bucket-acl --bucket BUCKET

# Unauthenticated direct-access test — want 403
curl -s -o /dev/null -w "%{http_code}\n" https://BUCKET.s3.amazonaws.com/index.html
```

Behavioral test for SPA fallback (confirms CloudFront owns 404 handling, so website hosting can be disabled):
- `/` → home loads
- `/realroute` → loads content
- `/doesnotexist` → app's *own styled 404* (not S3 XML `AccessDenied`/`NoSuchKey`)

### Finding pattern worth remembering

"The deploy wizard told me to allow public access" is one of the most common root causes of public-bucket findings in the wild. Tooling defaults to the simplest path (direct public S3); people wire up a CDN later and never revisit. Recognize that the CDN makes public access obsolete, then close it.

---

## Part 2 — Translating this into CloudMap detections

Everything above is a checklist a scanner can automate. Concrete checks CloudMap should emit as findings:

### S3 detections
- **Public bucket via BPA off** — any of the 4 BPA settings disabled. Severity scales with what else is true (policy/ACL granting public).
- **Public bucket via policy** — statement with `Principal: "*"` (or `AWS: "*"`) and no restricting `Condition`.
- **Public bucket via ACL** — `AllUsers` / `AuthenticatedUsers` grants.
- **World-writable bucket** — `s3:PutObject`/`s3:*` to public principal. (High severity — content-tampering / malware injection.)
- **Website endpoint enabled + public** — flag the website-endpoint-requires-public pattern; recommend CloudFront + OAC migration.
- **Over-broad CloudFront/OAC policy** — `Principal: cloudfront.amazonaws.com` *without* the `AWS:SourceArn` distribution condition (any distribution in any account could read).
- **Sensitive object heuristics** — object keys matching `.env`, `.bak`, `.sql`, `dump`, `backup`, `config`, `.pem`, `.key` in a bucket that is (or ever was) public.
- **BPA-off-but-policy-clean** — informational: guardrail down even though nothing public today (the exact wasonga.com starting state).

### CloudFront detections
- Origin pointing at S3 **website endpoint** instead of REST+OAC.
- Origin set to **Public** or **legacy OAI** instead of OAC.
- Viewer protocol policy allowing HTTP (no redirect-to-HTTPS).
- Missing/weak TLS (deprecated `SSLv3`/`TLSv1`).

### Cross-cutting (multi-cloud parity — Azure / GCP)
- **Azure**: public Blob containers (`Public access level = Container/Blob`), Storage account `AllowBlobPublicAccess = true`.
- **GCP**: buckets with `allUsers`/`allAuthenticatedUsers` IAM bindings; uniform bucket-level access disabled.
- Normalize all three into one finding schema so a "public object storage" check reads identically across providers.

---

## Part 3 — How to improve & scale the tool

### A. Detection engine
- **Policy-as-data evaluation.** Don't pattern-match JSON with regex. Parse IAM/bucket policies into a model and evaluate effective access (Effect + Principal + Action + Resource + Condition). This catches the subtle cases (e.g. `Principal:"*"` neutralized by a `Condition`, or OAC scoped vs unscoped).
- **Effective-access reasoning, not setting-by-setting.** The wasonga.com lesson: "BPA off" alone isn't an exposure; exposure = the *combination* of BPA + policy + ACL + endpoint. Compute the net result, report that, and list contributing factors.
- **Severity model.** Score by (a) is it actually reachable by the public right now, (b) read vs write, (c) data sensitivity signals, (d) guardrail-down-but-safe = low/informational. Avoid alert fatigue.
- **Active vs passive modes.** Passive = read cloud APIs only (always safe, default). Active = optional unauthenticated reachability probe (e.g. curl the public URL, expect 403). Keep active mode opt-in and scope-gated — same legal boundary as any scanning.

### B. Coverage / scale
- **Plugin architecture per service** (`s3`, `cloudfront`, `iam`, `rds`, `ec2-sg`, `lambda`, …) so new checks are drop-in. Mirror the structure across providers.
- **Pagination + rate-limit handling + retries/backoff** for large accounts; assume thousands of buckets/objects.
- **Concurrency** with a worker pool; cap parallel API calls to respect provider throttling.
- **Multi-account / org scanning.** AWS: assume-role across an Organization; enumerate accounts via Organizations API. Azure: management groups / subscriptions. GCP: org → folders → projects.
- **Credential hygiene.** Never take keys as CLI args (they leak into shell history / process list). Use the provider's default credential chain (env, profile, instance role). This ties directly to the secret-leak patterns — don't make the scanner itself a leak vector.

### C. Output / usability
- **Multiple reporters:** human-readable table (default), JSON, SARIF (so it drops into GitHub code-scanning / CI), and a remediation-script emitter (print the exact `aws s3api put-public-access-block ...` fix, but never auto-apply).
- **Remediation guidance per finding** — link the fix, like the OAC + BPA-on recipe above.
- **Diff / drift mode** — compare against a previous scan; alert only on *new* exposures. Great for CI gating.
- **Allowlist / suppressions file** — for intentionally-public buckets (e.g. genuine static asset CDN origins), with required justification field.

### D. Productization
- **CI/CD integration** — run on PR, fail the build on new high-severity public-storage findings (SARIF makes this native on GitHub).
- **Scheduled scans + delta alerts** to Slack/email.
- **IaC pre-deployment scanning** — parse Terraform/CloudFormation and catch the misconfig *before* it ships (shift-left), which is the real fix for the "deploy wizard made it public" pattern.
- **Benchmarks mapping** — map findings to CIS Benchmarks / AWS Foundational Security Best Practices so output speaks the language auditors expect.

### E. Testing & trust
- **Fixture-based unit tests** per detection (known-bad and known-good policy JSON → expected finding/no-finding). The wasonga.com states are perfect fixtures: BPA-off-but-clean (no finding / informational), public-via-website-endpoint (finding), REST+OAC-scoped (no finding), OAC-unscoped (finding).
- **Golden-file tests** for report output formats.
- **Mock cloud APIs** (e.g. moto for AWS) so the test suite runs without real credentials or network.

---

## TL;DR priorities for the next CloudMap iteration
1. Replace regex policy checks with a real policy-evaluation model (effective access).
2. Add the S3 + CloudFront detection set above, scored by real reachability not raw settings.
3. SARIF output + GitHub Action so it gates PRs.
4. Multi-account assume-role scanning.
5. IaC/shift-left scanning to catch the misconfig before deploy.
6. Fixture tests built from the four wasonga.com states.
