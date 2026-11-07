# Security policy

## Supported versions

The project has not published a release yet. After the first release, only the latest minor version receives security fixes.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No |

## Reporting a vulnerability

Please report security problems privately. Do not open a public issue, discussion, or pull request.

Use GitHub private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. If that option is not available, email <opensource@faithfuloversight.com> with "SECURITY" in the subject.

Include:

- A description of the problem and its impact.
- Steps to reproduce, using synthetic data only.
- The version or commit you tested.

Never include real directory exports, logs, credentials, or other data from a real organization.

## What to expect

- Acknowledgement within 5 business days.
- An initial assessment within 10 business days.
- Coordinated disclosure: a fix, a release, and a published advisory, with credit to you unless you prefer otherwise.

## Scope

In scope: this repository's code, its release artifacts, and its build pipeline.

Out of scope: problems in third-party dependencies (report those upstream), and findings that require an attacker who already controls the operator's machine.

## Security design

See [docs/threat-model.md](docs/threat-model.md) for the threat model and the controls in place.
