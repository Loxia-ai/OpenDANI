# Security reporting

This is a public development preview. It has no supported production release or
published security support window yet. Public-network deployment requires further
review and hardening.

## Reporting a concern

Do not disclose vulnerabilities, exploits, private prompts or credentials in public
issues. Use [GitHub private vulnerability reporting](https://github.com/Loxia-ai/OpenDANI/security/advisories/new),
which is enabled for this repository. If it is unavailable, contact the project
owner through an existing private communication channel to arrange a secure report.

No separate security email address or response/remediation deadline is established
for this preview.

A useful private report includes the affected commit/version, environment, expected
and observed behavior, a minimal reproduction using synthetic data, and impact.
Do not test systems you do not control without their owner's authorization.

## Evaluation boundaries

Use public or synthetic data on volunteer workers; a processing node sees request
inputs. Keep private organizational identities, collections and credentials separate.
Development defaults and the optional code-executing demo endpoint are not an
Internet deployment profile. Source checks passing does not constitute a security
audit or a public-service readiness claim.
