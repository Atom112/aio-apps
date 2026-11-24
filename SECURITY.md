# Security policy

This catalog distributes executable UI bundles to AIO desktops. Two properties matter:

1. **What users install is what was reviewed.** `registry.json` is signed with an ed25519 key
   held only in the `production` environment secret; clients verify the signature over the
   payload bytes and then sha256 of every artifact before extracting it.
2. **Revocation is a first-class action.** A malicious or compromised version is revoked in
   the index (by artifact digest or `id`+`version`) and clients disable it on their next
   refresh, keeping uninstall available.

## Reporting a vulnerability

- Prefer **GitHub Security Advisories** on this repository ("Report a vulnerability"), or open
  a private issue if advisories are unavailable.
- Include the app id and version, what the bundle does, and the artifact sha256 when you have it
  (visible in `registry.json`).
- Please do not publish a working exploit before a revocation is out.

## What to expect

| Step                               | Target                                      |
| ---------------------------------- | ------------------------------------------- |
| Acknowledgement                    | 72 hours                                    |
| Triage + revocation (if confirmed) | 7 days                                      |
| Public advisory                    | after clients can refresh the revoked index |

Revocation is a signed index change: the affected version is added to `revoked[]`, CI re-signs,
and installed clients stop it. The bundle stays in the repository history for audit; it is never
silently deleted.

## Scope

In scope: bundles in `apps/`, the CI workflow, the vendored gate/tool under `.aio-tools/`, the
signing/verification path. Out of scope: vulnerabilities in AIO itself (report them to
<https://github.com/Atom112/AIO/security>) and in third-party services the bundles may mention.
