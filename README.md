# WgAuth — PHP 8.5

Independent Wargaming World of Tanks authentication library for EU, NA and ASIA. It implements browser login, session-bound one-time state, server-side token ownership verification, token renewal and revocation. It does not create application users, verify email, issue application sessions or implement your application's OAuth server.

## Install and check

Requires PHP 8.5, Composer 2, ctype, filter and session. Guzzle 7 (MIT) performs HTTPS POST requests; sibling WgApi (Edrard, MIT) provides canonical realms and application configuration. Development tools are PHPUnit, PHPStan and PHP CS Fixer.

Release 1.0.2 reads complete authentication responses without a package-defined byte limit. The POST transport explicitly clears injected Guzzle query defaults and disables debug output. Custom middleware/transports must preserve credential redaction. The directly used guzzlehttp/psr7 dependency (MIT) provides the stream-reading utilities. These protections are included in the stable release.

From this directory:

```sh
composer install
composer test
composer analyse
composer format:check
composer validate --strict
composer audit
```

Release: v1.0.2. Composer name: edrard/wgauth; stable constraint: ^1.0.2; development alias: 1.0.x-dev. WgApi uses a stable ^2.0 constraint and its GitHub VCS repository.

Until the packages are registered on Packagist, a consuming application's **root composer.json** must declare both repositories; dependency repositories are not inherited:

```json
{
    "repositories": [
        { "type": "vcs", "url": "https://github.com/Edrard/WgAuth.git" },
        { "type": "vcs", "url": "https://github.com/Edrard/WgApi.git" }
    ],
    "require": { "php": "^8.5", "edrard/wgauth": "^1.0.2" }
}
```

For local development, use root path repositories with explicit versions edrard/wgauth = 1.0.2 and edrard/wgapi = 2.0.0. Local symlinks do not provide a release deployment artifact.

## Configure

```php
use edrard\WgApi\Realm;
use edrard\WgAuth\AuthClient;
use edrard\WgAuth\Session\PhpSessionStateStore;
use edrard\WgAuth\WgAuth;

require __DIR__.'/vendor/autoload.php';

$applicationId = getenv('WG_APPLICATION_ID');
if (!$applicationId) {
    throw new LogicException('Configure WG_APPLICATION_ID.');
}
$client = new AuthClient($applicationId); // explicitly applies this ID to all 3 realms

// Alternatively: new AuthClient(['eu' => $euId, 'na' => $naId, 'asia' => $asiaId]);
session_start([
    'use_strict_mode' => true,
    'cookie_secure' => true,
    'cookie_httponly' => true,
    'cookie_samesite' => 'Lax',
]);
$auth = new WgAuth($client, new PhpSessionStateStore());
```

Use HTTPS and server-side session storage. The PHP session adapter relies on the session handler's exclusive lock for atomic consumption; keep the session active until completeLogin() finishes. A handler that disables locking needs a custom atomic StateStoreInterface implementation. The adapter permits at most 10 pending attempts per browser and prunes expired entries.

For Laravel, implement StateStoreInterface over a browser-bound server-side session with atomic removal/locking. Do not start a separate native PHP session inside Laravel. State must be scoped to the initiating browser: a global cache indexed only by the nonce does not prevent login CSRF.

## Redirect to WG

```php
// Use a callback URI from trusted application configuration.
$location = $auth->beginLogin(
    Realm::EU,
    'https://your-app.example/auth/wargaming/callback',
    tokenLifetime: 3600,
    stateLifetime: 600,
);
header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');
header('Location: '.$location, true, 303);
exit;
```

beginLogin() sends auth/login as POST with nofollow=1, validates the returned HTTPS login host against the selected realm, stores a random 256-bit nonce in the browser's session and embeds that nonce in redirect_uri. WG does not document a standalone state parameter; the nonce travels in your callback URI's query. Existing unrelated query parameters are preserved; reserved authentication parameter collisions are rejected.

State lifetime is 1–900 seconds (default 600). Token lifetime is 1–1,209,600 seconds (default 3,600), sent as an absolute UNIX timestamp. Both the realm and nonce come from the stored attempt, never a callback-supplied realm or account range heuristic.

## Complete and verify the callback

```php
use edrard\WgAuth\AuthException;

header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');
try {
    $account = $auth->completeLogin($_GET);
    $identity = $account->identity; // server-verified realm + account ID + nickname

    // Initial identity proof only: revoke and discard the WG credential.
    $client->logout($account->token);
    unset($account);

    // Pass $identity to your application's identity-linking/registration service.
    // New application users still need the application's verified-email flow.
    // Redirect immediately to a clean URL before rendering a page.
    header('Location: /registration/continue', true, 303);
    exit;
} catch (AuthException $exception) {
    // Numeric providerCode/httpStatus are safe diagnostics; do not log $_GET.
    header('Location: /login/failed', true, 303);
    exit;
}
```

completeLogin() atomically consumes state before checking provider status, so replay, cancellation, malformed callbacks and verification failures all require a new attempt. Missing, mismatched, cross-session or expired state fails before any provider verification request.

Callback fields are unsigned input. The callback nickname is ignored. The client POSTs account/info with the token and only account_id,nickname,private.is_premium. A matching account ID and a boolean private field (including false) prove current token access to that account; public account data or private=null cannot authenticate it. Private data is discarded and only identity is returned. This requires a World of Tanks account; support for identities with no WoT account is outside this package's current contract.

The callback's expires_at is validated as future and within two weeks, but is unsigned metadata, not independently proven expiration. Verification proves the token works now. For initial identity proof revoke/discard immediately. For explicitly authorized persistent private access, use server-returned renewal metadata, encrypted credential storage and a separate consent/lifecycle policy in the application.

## Renew and revoke

```php
// $token is an in-memory AccessToken obtained from the verified callback.
$renewed = $client->prolongate($token, tokenLifetime: 3600);
// WG returns a NEW access_token; use $renewed for subsequent requests.
$client->logout($renewed); // invalidates this WG access token
unset($token, $renewed);
```

prolongate() validates expiration and requires the returned account ID to match the original owner. Renewal/revocation use form-encoded POST bodies. There are no automatic retries or background renewal: a timeout on a mutation can have an unknown outcome, so the application decides recovery. WG revocation does not end the application's own login session, and logging out of your application does not automatically revoke WG tokens.

## Runnable examples

[examples/public/index.php](examples/public/index.php) is a minimal HTTPS browser example with /login, /callback and /result routes. Configure WG_APPLICATION_ID and WG_CALLBACK_URI; the latter must end in /callback and use the host serving the example. Forward these routes to the file through your HTTPS server. Start with /login?realm=eu, /login?realm=na or /login?realm=asia. It keeps only temporary identity proof in the session, revokes the WG credential, redirects to a clean URL and does not create a logged-in application user.

[examples/verify-regions.php](examples/verify-regions.php) is an opt-in live smoke check:

```sh
php examples/verify-regions.php
# Supply the application ID through WG_APPLICATION_ID or stdin.
```

It obtains login URLs, checks public account data over POST and confirms a deliberately invalid token is rejected. It never completes user login, obtains a real user token, renews or revokes a real token.

## Boundaries and security

- API origins are fixed to the official WoT hosts; redirects, HTTP credentials, unsafe callback URLs and non-matching login hosts are rejected.
- Default network timeouts: 15 seconds overall, 5 seconds to connect. TLS verification is enabled; HTTP redirects are disabled.
- AuthTransportInterface permits a replacement transport. It must sanitize errors, protect credentials and avoid automatic retries of mutations.
- StateStoreInterface is the storage boundary. Its consume operation must be atomic and browser-bound. A consumed attempt is not restored on failure.
- Transport errors expose only fixed messages and numeric codes, never raw WG messages, bodies, URLs or Guzzle exceptions. SensitiveParameter redacts credential arguments from PHP exception traces.
- AccessToken deliberately has no string conversion; value() is explicit. var_dump is redacted, JSON omits the private credential, and PHP serialization is blocked. Do not use var_export, reflection, custom dumpers or logging on token objects.
- WG sends access_token in the callback URL. Configure reverse proxy, web-server, request tracing and APM to redact the callback query BEFORE application code runs. The library cannot erase browser history or upstream access logs. Use no-store/no-referrer headers, no third-party assets on callback pages and an immediate clean redirect.
- Never persist the raw callback or place WG tokens in application logs, browser storage, analytics, desktop clients or application OAuth tokens.
- Quotas belong to the application ID; coordinate limits in the consuming application across this package and data collectors. AuthClient performs no distributed rate limiting.

## Verified coverage

On 2026-09-26, PHP 8.5.11 in WSL: local tests cover successful ownership verification, forged/public-only account rejection, replay, expired state/tokens, cancellation, session isolation, renewal owner matching, POST body encoding and sanitized errors. Live checks with one owner-provided ID passed for EU, NA and ASIA login locations and invalid-token rejection. A real successful browser callback and real token renewal/revocation remain unverified live.

Source: [Edrard/WgAuth](https://github.com/Edrard/WgAuth). New implementation for Edrard; MIT, see LICENSE. Intended consumer: the future Laravel application and other explicitly integrated PHP applications. No application integration or deployment has been performed.

Official references: [login](https://developers.wargaming.net/reference/all/wot/auth/login/), [prolongate](https://developers.wargaming.net/reference/all/wot/auth/prolongate/), [logout](https://developers.wargaming.net/reference/all/wot/auth/logout/), [account/info](https://developers.wargaming.net/reference/all/wot/account/info/).

Dependency updates: run `composer update "edrard/*" --with-all-dependencies --prefer-stable` in the consuming application to upgrade the WG complex to the latest versions allowed by its constraints. Caret constraints allow compatible upgrades; `composer install` preserves the lock file. Dependency repositories must be declared in the application root.

Token arguments are marked SensitiveParameter in internal expiry validation as well as public operations, so exception argument traces redact them even when zend.exception_ignore_args=0. Applications must also redact their own request logs and diagnostic context.
