# Security policy

Vulnyard handles tokens for GitLab and Dependency-Track and controls what gets
scanned, so we take security reports seriously.

## Reporting a vulnerability

**Please do not report security issues in public issues or pull requests.**

Instead, either:

- use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  ("Report a vulnerability" on the Security tab of the repository), or
- e-mail **lukas@zuzanak.eu** with the subject "Vulnyard security".

Include what you found, how to reproduce it and the version you tested. You can
expect an acknowledgement within a few working days; once a fix is available we
will credit you in the release notes unless you prefer to stay anonymous.

## Supported versions

Security fixes go into the latest published version. Please make sure the issue
is still present there before reporting.

## Deployment notes

Some behaviour is by design and documented in the README, not a vulnerability:

- With `AUTH_MODE=none` (the default) the application has no sign-in – anyone
  who can reach it over the network has access. Run it behind a VPN or an
  authenticating reverse proxy.
- With `AUTH_MODE=proxy-header` the identity comes from proxy headers, so the
  application must not be reachable outside the proxy.

See [Sign-in and security](README.md#sign-in-and-security).
