<?php

declare(strict_types=1);

use edrard\WgApi\Realm;
use edrard\WgAuth\AuthClient;
use edrard\WgAuth\AuthException;
use edrard\WgAuth\Session\PhpSessionStateStore;
use edrard\WgAuth\WgAuth;

require dirname(__DIR__, 2).'/vendor/autoload.php';

// Serve through your HTTPS server with these routes forwarded to this file.
// Redact callback query strings in reverse-proxy, web-server and APM logs.
header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');
header('Content-Type: text/plain; charset=UTF-8');
session_start([
    'use_strict_mode' => true, 'cookie_secure' => true,
    'cookie_httponly' => true, 'cookie_samesite' => 'Lax',
]);
$applicationId = getenv('WG_APPLICATION_ID');
$callbackUri = getenv('WG_CALLBACK_URI');
if (!$applicationId || !$callbackUri) {
    http_response_code(500);
    exit('Configure WG_APPLICATION_ID and WG_CALLBACK_URI.');
}
$client = new AuthClient($applicationId);
$auth = new WgAuth($client, new PhpSessionStateStore());
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
try {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
        http_response_code(405);
        header('Allow: GET');
        exit('Use GET.');
    }
    if ($path === '/login') {
        unset($_SESSION['wg_verified_identity']);
        $requestedRealm = $_GET['realm'] ?? 'eu';
        if (!is_string($requestedRealm) || ($realm = Realm::tryFrom($requestedRealm)) === null) {
            http_response_code(400);
            exit('Choose eu, na or asia.');
        }
        $location = $auth->beginLogin($realm, $callbackUri);
        header('Location: '.$location, true, 303);
        exit;
    }
    if ($path === '/callback') {
        $account = $auth->completeLogin($_GET);
        // Initial identity proof only: revoke and discard the provider token.
        // No WG token is stored in the session or exposed in the response.
        $client->logout($account->token);
        session_regenerate_id(true);
        $_SESSION['wg_verified_identity'] = [
            'realm' => $account->identity->realm->value,
            'account_id' => $account->identity->accountId,
            'nickname' => $account->identity->nickname,
        ];
        unset($account);
        header('Location: /result', true, 303);
        exit;
    }
    if ($path === '/result') {
        $verified = isset($_SESSION['wg_verified_identity']);
        unset($_SESSION['wg_verified_identity']);
        echo $verified ? 'WG identity verified. Continue application registration or identity linking.' : 'WG login did not complete. Start a new login.';
        exit;
    }
    http_response_code(404);
    echo 'Start with /login?realm=eu (or na, asia).';
} catch (AuthException) {
    // Never echo the original callback, token, provider body or URL.
    header('Location: /result', true, 303);
    exit;
}
