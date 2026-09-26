<?php

declare(strict_types=1);

use edrard\WgApi\Realm;
use edrard\WgAuth\AccessToken;
use edrard\WgAuth\AuthClient;
use edrard\WgAuth\AuthException;
use edrard\WgAuth\Http\GuzzleAuthTransport;

require dirname(__DIR__).'/vendor/autoload.php';

// Opt-in live check; obtains login locations without authenticating a user.
$applicationId = getenv('WG_APPLICATION_ID') ?: trim((string) fgets(STDIN));
if ($applicationId === '') {
    fwrite(STDERR, "Provide WG_APPLICATION_ID or the application ID on stdin.\n");
    exit(1);
}
$client = new AuthClient($applicationId);
$transport = new GuzzleAuthTransport();
$failures = 0;
foreach (Realm::cases() as $realm) {
    try {
        $client->loginLocation($realm, 'https://example.test/callback?state='.bin2hex(random_bytes(32)));
        echo json_encode(['realm' => $realm->value, 'method' => 'auth/login', 'result' => 'ok'], JSON_THROW_ON_ERROR)."\n";
        $origin = match ($realm) {
            Realm::EU => 'https://api.worldoftanks.eu',
            Realm::NA => 'https://api.worldoftanks.com',
            Realm::ASIA => 'https://api.worldoftanks.asia',
        };
        $players = $transport->post($origin.'/wot/account/list/', [
            'application_id' => $applicationId, 'search' => 'tank', 'limit' => 1, 'fields' => 'account_id',
        ]);
        $accountId = $players[0]['account_id'] ?? null;
        if (!is_int($accountId)) {
            throw new RuntimeException('No account fixture.');
        }
        $public = $transport->post($origin.'/wot/account/info/', [
            'application_id' => $applicationId, 'account_id' => $accountId, 'fields' => 'account_id,nickname,private.is_premium',
        ]);
        if (!is_array($public[$accountId] ?? null) || ($public[$accountId]['private'] ?? null) !== null) {
            throw new RuntimeException('Unexpected public account response.');
        }
        echo json_encode(['realm' => $realm->value, 'method' => 'account/info POST without token', 'result' => 'private unavailable'], JSON_THROW_ON_ERROR)."\n";
        try {
            $client->verifyIdentity(new AccessToken($realm, $accountId, 'invalid-test-token', time() + 300));
            throw new RuntimeException('Invalid token was accepted.');
        } catch (AuthException $exception) {
            if ($exception->providerCode !== 407 && $exception->getMessage() !== 'WG token ownership could not be verified.') {
                throw $exception;
            }
            echo json_encode(['realm' => $realm->value, 'method' => 'verifyIdentity invalid token', 'result' => 'rejected', 'code' => $exception->getCode()], JSON_THROW_ON_ERROR)."\n";
        }
    } catch (Throwable $exception) {
        ++$failures;
        echo json_encode(['realm' => $realm->value, 'method' => 'auth/login', 'result' => 'failed', 'code' => $exception->getCode()], JSON_THROW_ON_ERROR)."\n";
    }
}
exit($failures === 0 ? 0 : 1);
