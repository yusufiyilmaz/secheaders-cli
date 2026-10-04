# Security Policy

## Reporting a vulnerability

If you find a security problem in `secheaders` (for example, a way to make it crash on a crafted response,
or to make it report a site as safe when it is not), please **do not open a public issue**.

Instead, report it privately through GitHub:
**Security → Report a vulnerability** on this repository (private vulnerability reporting).

Please include:

- what you found and why it matters,
- steps or a sample response to reproduce it,
- the version (`secheaders --version`) and your Python version.

I will reply as soon as I can and credit you in the changelog if you wish.

## Supported versions

Only the latest release receives fixes.

## Scope

`secheaders` only sends ordinary GET requests, like a browser. Reports about the sites it scans
(rather than about the tool itself) should go to the owners of those sites.
