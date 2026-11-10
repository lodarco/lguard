# Security

Lguard runs as root and handles hostile files, so reports about it are
taken seriously.

## Reporting a problem

Please do not open a public issue for something that can be used against
people who run Lguard. Use **Security → Report a vulnerability** on the
GitHub page of this repository (private vulnerability reporting). Say which
version you used (`lguard status`), what you did and what happened.

## What counts

- anything that lets a local user without administrator rights read, change,
  delete or take ownership of a file through Lguard, or stop or blind it;
- a way to make Lguard record a file as checked when it was not;
- a crash or hang of `lguardd` or the scan engine caused by a file or by a
  request on the local socket;
- a file that is released by a trusted publisher of this repository but does
  not match its build provenance.

Detection gaps of the signature engine itself (a sample ClamAV does not know)
belong to the ClamAV project.

## How the parts are separated

- `lguardd` runs as root: it needs to read every file and to move threats
  away. It never parses file contents beyond the first bytes.
- The scan engine runs as its own unprivileged user without network, without
  write access to its signatures and without access to home folders. Files
  reach it only as open descriptors.
- The signature updater runs as that same unprivileged user and is the only
  part that talks to the network.
- The desktop app runs as the user and talks to `lguardd` over a local
  socket. The caller is identified by the kernel; changes need the
  administrator password (polkit).

## Checking a download

Release packages are built by GitHub Actions from the tagged source and
carry a signed build provenance:

```sh
gh attestation verify lguard_<version>_amd64.deb --repo lodarco/lguard
sha256sum -c SHA256SUMS
```
