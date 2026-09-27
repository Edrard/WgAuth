# Changelog

## Unreleased — planned 1.0.1

- Remove the previous 1 MiB authentication response cap and read the complete body without a package-defined size limit.
- Clear inherited Guzzle query defaults for POST and disable transport debug output, preventing configured query credentials from appearing in authentication URLs.
- Read short stream chunks correctly, reject ambiguous endpoint URLs, and declare the directly used PSR-7 dependency.
- Add security regression coverage and PHP 8.5 CI; retain one-time browser state, token ownership checks and no automatic POST retry.

## 1.0.0 — 2026-09-27

Initial PHP 8.5 release for World of Tanks authentication in EU, NA and ASIA.

- Obtain WG login locations with HTTPS POST and verify the selected realm's login host.
- Bind one-time random state to the initiating browser session with bounded expiration.
- Verify callback token ownership using private account data; ignore the untrusted callback nickname.
- Implement explicit token renewal and revocation without automatic mutation retries.
- Add injectable POST/state storage contracts and a native PHP session adapter.
- Sanitize errors and redact token debug output; block token serialization.
- Add HTTPS/browser and live smoke examples, MIT license, PHPUnit, PHPStan level 6 and PSR-12 checks.

Validation: 60 tests / 159 assertions. Live login locations and invalid-token rejection passed in three realms. A real successful user callback and real token renewal/revocation have not been verified live. Applications own identity linking, verified email, callback-log redaction and global quotas.
