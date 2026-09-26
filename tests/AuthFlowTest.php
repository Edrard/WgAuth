<?php

declare(strict_types=1);

namespace edrard\Tests\WgAuth;

use edrard\WgApi\Realm;
use edrard\WgAuth\AccessToken;
use edrard\WgAuth\AuthClient;
use edrard\WgAuth\AuthException;
use edrard\WgAuth\Contracts\AuthTransportInterface;
use edrard\WgAuth\Contracts\StateStoreInterface;
use edrard\WgAuth\LoginAttempt;
use edrard\WgAuth\WgAuth;
use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SensitiveParameter;

final class AuthFlowTest extends TestCase
{
    private RecordingTransport $transport;
    private MemoryStates $states;
    private AuthClient $client;
    private WgAuth $flow;

    protected function setUp(): void
    {
        $this->transport = new RecordingTransport();
        $this->states = new MemoryStates();
        $this->client = new AuthClient('test-application', $this->transport, static fn () => 1000);
        $this->flow = new WgAuth($this->client, $this->states, static fn () => 1000);
    }

    public function testBeginAndCompleteConsumeStateAndVerifyPrivateData(): void
    {
        $location = $this->flow->beginLogin(Realm::NA, 'https://example.test/callback?source=wg');
        self::assertSame('https://na.wargaming.net/id/', $location);
        $attempt = $this->states->attempt;
        self::assertNotNull($attempt);
        self::assertSame(Realm::NA, $attempt->realm);
        self::assertSame(1600, $attempt->expiresAt);
        $request = $this->transport->requests[0];
        self::assertSame('https://api.worldoftanks.com/wot/auth/login/', $request[0]);
        self::assertSame(1, $request[1]['nofollow']);
        self::assertSame(4600, $request[1]['expires_at']);
        self::assertSame('https://example.test/callback?source=wg&state='.$attempt->state, $request[1]['redirect_uri']);
        $this->transport->data = [42 => ['account_id' => 42, 'nickname' => 'server-name', 'private' => ['is_premium' => false]]];
        $result = $this->flow->completeLogin($this->query($attempt->state));
        self::assertSame(Realm::NA, $result->identity->realm);
        self::assertSame(42, $result->identity->accountId);
        self::assertSame('server-name', $result->identity->nickname);
        self::assertSame('fake-token', $result->token->value());
        self::assertNull($this->states->attempt);
        self::assertSame('account_id,nickname,private.is_premium', $this->transport->requests[1][1]['fields']);
        $this->expectException(AuthException::class);
        $this->flow->completeLogin($this->query($attempt->state));
    }

    /** @return iterable<string, array{array<array-key, mixed>|null}> */
    public static function invalidPrivateResponses(): iterable
    {
        yield 'null account' => [[42 => null]];
        yield 'public only' => [[42 => ['account_id' => 42, 'nickname' => 'public']]];
        yield 'private null' => [[42 => ['account_id' => 42, 'nickname' => 'public', 'private' => null]]];
        yield 'private empty' => [[42 => ['account_id' => 42, 'nickname' => 'public', 'private' => []]]];
        yield 'wrong owner' => [[42 => ['account_id' => 99, 'nickname' => 'wrong', 'private' => ['is_premium' => true]]]];
        yield 'wrong private type' => [[42 => ['account_id' => 42, 'nickname' => 'wrong', 'private' => ['is_premium' => 'false']]]];
        yield 'nickname missing' => [[42 => ['account_id' => 42, 'private' => ['is_premium' => true]]]];
        yield 'no response' => [null];
    }

    #[DataProvider('invalidPrivateResponses')]
    public function testForgedPublicAccountCannotAuthenticate(?array $data): void
    {
        $this->transport->data = $data;
        $this->expectException(AuthException::class);
        $this->client->verifyIdentity(new AccessToken(Realm::EU, 42, 'fake-token', 2000));
    }

    public function testUnknownOrCrossSessionStateDoesNotCallProvider(): void
    {
        $this->states->attempt = new LoginAttempt(Realm::EU, str_repeat('a', 64), 2000);
        try {
            $this->flow->completeLogin($this->query(str_repeat('b', 64)));
            self::fail('Mismatched state accepted.');
        } catch (AuthException) {
            self::assertSame([], $this->transport->requests);
            self::assertNotNull($this->states->attempt);
        }
    }

    public function testExpiredStateIsConsumedWithoutProviderCall(): void
    {
        $this->states->attempt = new LoginAttempt(Realm::EU, str_repeat('a', 64), 1000);
        try {
            $this->flow->completeLogin($this->query(str_repeat('a', 64)));
            self::fail('Expired state accepted.');
        } catch (AuthException) {
            self::assertNull($this->states->attempt);
            self::assertSame([], $this->transport->requests);
        }
    }

    public function testCancellationConsumesStateAndDoesNotExposeMessage(): void
    {
        $this->states->attempt = new LoginAttempt(Realm::EU, str_repeat('a', 64), 2000);
        try {
            $this->flow->completeLogin(['state' => str_repeat('a', 64), 'status' => 'error', 'code' => '401', 'message' => 'sensitive']);
            self::fail('Cancelled login accepted.');
        } catch (AuthException $exception) {
            self::assertSame(401, $exception->providerCode);
            self::assertStringNotContainsString('sensitive', $exception->getMessage());
            self::assertNull($this->states->attempt);
            self::assertSame([], $this->transport->requests);
        }
    }

    /** @return iterable<string, array{array<string, mixed>}> */
    public static function badCallbacks(): iterable
    {
        yield 'token missing' => [['access_token' => null]];
        yield 'token array' => [['access_token' => ['fake']]];
        yield 'token empty' => [['access_token' => '']];
        yield 'token newline' => [['access_token' => "fake\nsecret"]];
        yield 'token too long' => [['access_token' => str_repeat('a', 4097)]];
        yield 'account array' => [['account_id' => ['42']]];
        yield 'account negative' => [['account_id' => '-1']];
        yield 'account overflow' => [['account_id' => '99999999999999999999999999']];
        yield 'expired' => [['expires_at' => '1000']];
        yield 'too far' => [['expires_at' => 1210601]];
        yield 'expiration array' => [['expires_at' => ['2000']]];
        yield 'status array' => [['status' => ['ok']]];
    }

    #[DataProvider('badCallbacks')]
    public function testMalformedCallbackConsumesStateWithoutVerifying(array $changes): void
    {
        $state = str_repeat('a', 64);
        $this->states->attempt = new LoginAttempt(Realm::EU, $state, 2000);
        try {
            $this->flow->completeLogin(array_replace($this->query($state), $changes));
            self::fail('Malformed callback accepted.');
        } catch (AuthException) {
            self::assertNull($this->states->attempt);
            self::assertSame([], $this->transport->requests);
        }
    }

    /** @return iterable<string, array{string}> */
    public static function badRedirects(): iterable
    {
        yield 'http' => ['http://example.test/callback'];
        yield 'fragment' => ['https://example.test/callback#fragment'];
        yield 'credentials' => ['https://user:pass@example.test/callback'];
        yield 'state collision' => ['https://example.test/callback?state=value'];
        yield 'array state collision' => ['https://example.test/callback?state%5B%5D=value'];
        yield 'token collision' => ['https://example.test/callback?access_token=value'];
        yield 'dot state collision' => ['https://example.test/callback?state.value=value'];
        yield 'newline' => ["https://example.test/callback\n"];
    }

    #[DataProvider('badRedirects')]
    public function testUnsafeRedirectsAreRejected(string $url): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->flow->beginLogin(Realm::EU, $url);
    }

    public function testStateDoesNotPersistWhenProviderLoginFails(): void
    {
        foreach ([
            'https://attacker.test/',
            'http://eu.wargaming.net/id/',
            'https://na.wargaming.net/id/',
            'https://eu.wargaming.net.attacker.test/id/',
            'https://user:pass@eu.wargaming.net/id/',
            'https://eu.wargaming.net:8443/id/',
            'https://eu.wargaming.net/id/#fragment',
            "https://eu.wargaming.net/id/\n",
        ] as $location) {
            $this->transport->data = ['location' => $location];
            try {
                $this->flow->beginLogin(Realm::EU, 'https://example.test/callback');
                self::fail('Untrusted provider URL accepted.');
            } catch (AuthException) {
                self::assertNull($this->states->attempt);
            }
        }
    }

    public function testProlongateRotatesTokenAndLogoutUsesSameRealm(): void
    {
        $this->transport->data = ['account_id' => 42, 'access_token' => 'renewed-token', 'expires_at' => 3000];
        $token = new AccessToken(Realm::ASIA, 42, 'old-token', 2000);
        $renewed = $this->client->prolongate($token, 2000);
        self::assertSame('renewed-token', $renewed->value());
        self::assertSame(Realm::ASIA, $renewed->realm);
        self::assertSame('https://api.worldoftanks.asia/wot/auth/prolongate/', $this->transport->requests[0][0]);
        self::assertSame('old-token', $this->transport->requests[0][1]['access_token']);
        self::assertSame(3000, $this->transport->requests[0][1]['expires_at']);
        $this->transport->data = null;
        $this->client->logout($renewed);
        self::assertSame('https://api.worldoftanks.asia/wot/auth/logout/', $this->transport->requests[1][0]);
        self::assertSame('renewed-token', $this->transport->requests[1][1]['access_token']);
    }

    public function testRenewedTokenOwnerMustMatch(): void
    {
        $this->transport->data = ['account_id' => 99, 'access_token' => 'renewed-token', 'expires_at' => 2000];
        $this->expectException(AuthException::class);
        $this->client->prolongate(new AccessToken(Realm::EU, 42, 'fake', 2000));
    }

    public function testExpiredTokensAreRejectedLocally(): void
    {
        $this->expectException(AuthException::class);
        $this->client->verifyIdentity(new AccessToken(Realm::EU, 42, 'fake', 1000));
    }

    public function testLifetimeBounds(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->flow->beginLogin(Realm::EU, 'https://example.test/callback', tokenLifetime: 1209601);
    }

    public function testStateLifetimeBounds(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->flow->beginLogin(Realm::EU, 'https://example.test/callback', stateLifetime: 901);
    }

    public function testTokenDebugIsRedactedAndSerializationBlocked(): void
    {
        $token = new AccessToken(Realm::EU, 42, 'never-dump-me', 2000);
        ob_start();
        var_dump($token);
        $debug = ob_get_clean();
        self::assertStringNotContainsString('never-dump-me', $debug);
        self::assertStringContainsString('[redacted]', $debug);
        self::assertStringNotContainsString('never-dump-me', json_encode($token, JSON_THROW_ON_ERROR));
        $this->expectException(LogicException::class);
        serialize($token);
    }

    /** @return array<string, string> */
    private function query(string $state): array
    {
        return ['state' => $state, 'status' => 'ok', 'account_id' => '42', 'access_token' => 'fake-token', 'expires_at' => '2000', 'nickname' => 'forged-name'];
    }
}
