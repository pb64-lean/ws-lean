# Security policy

## Supported versions

Only the current pre-release `main` development line receives security fixes.
There is no stable-version support commitment yet.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
vulnerability-reporting flow from the repository's **Security** tab. If that
flow is unavailable, contact the maintainers privately through the owning
organization.

Include the affected revision and environment, a minimal reproduction, the
expected and observed behavior, potential impact, and any known mitigation.

## Security boundary

The native DEFLATE adapter, Lean runtime, operating system networking, DNS,
system trust store, and TLS implementation are within the trusted computing
boundary. Remote peers are untrusted. Pure protocol checks and conformance tests
do not establish that external components implement their contracts faithfully.
