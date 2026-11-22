# Security Policy

Basilisk is an obfuscator: it raises the cost of reading a script, it does not make a script impossible to
recover, and it is not a substitute for encryption. Do not rely on it to protect secrets embedded in a
script. See the "Security notes" section of the README.

## Reporting a vulnerability

If you believe you have found a security issue in Basilisk itself (for example, a way to make it emit
broken or non-equivalent output, or a crash on untrusted input), please report it privately rather than
opening a public issue:

- Open a GitHub security advisory on this repository, or
- Contact the maintainer via https://escaliba.net

Please include a minimal reproducing input and the command used.
