<?php

declare(strict_types=1);

namespace edrard\Tests\WgAuth;

use edrard\WgApi\Realm;
use edrard\WgAuth\AccessToken;
use edrard\WgAuth\AuthClient;
use edrard\WgAuth\AuthException;
use edrard\WgAuth\Http\GuzzleAuthTransport;
use edrard\WgAuth\LoginAttempt;
use edrard\WgAuth\WgAuth;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use RuntimeException;
use Stringable;

final class LoggingTest extends TestCase
{
    public function testSuccessfulLoginEmitsOneSafeDebugRecord(): void
    {
        $logger = $this->logger();
        $transport = new RecordingTransport();
        $client = new AuthClient('private-application-id', $transport, static fn () => 1000, $logger);
        $states = new MemoryStates();
        $flow = new WgAuth($client, $states, static fn () => 1000, $logger);
        $flow->beginLogin(Realm::EU, 'https://example.test/private-callback');
        self::assertNotNull($states->attempt);
        $state = $states->attempt->state;
        $transport->data = [42 => ['account_id' => 42, 'nickname' => 'private-name', 'private' => ['is_premium' => false]]];
        $account = $flow->completeLogin([
            'state' => $state, 'status' => 'ok', 'account_id' => 42,
            'access_token' => 'private-token', 'expires_at' => 2000,
        ]);
        self::assertSame('private-token', $account->token->value());
        self::assertNull($states->attempt);
        self::assertSame([['debug', 'WG login completed for {realm}.', ['realm' => 'eu']]], $logger->records);
        $serialized = serialize($logger->records);
        foreach (['private-application-id', 'private-callback', 'private-name', 'private-token', $state] as $secret) {
            self::assertStringNotContainsString($secret, $serialized);
        }
    }

    /** @return iterable<string, array{bool}> */
    public static function loggerModes(): iterable
    {
        yield 'recording' => [false];
        yield 'throwing' => [true];
    }

    #[DataProvider('loggerModes')]
    public function testLoggerDoesNotChangeRenewalAndRevocation(bool $throws): void
    {
        $logger = $this->logger($throws);
        $transport = new RecordingTransport();
        $transport->data = ['account_id' => 42, 'access_token' => 'renewed-secret', 'expires_at' => 3000];
        $client = new AuthClient('app', $transport, static fn () => 1000, $logger);
        $token = $client->prolongate(new AccessToken(Realm::ASIA, 42, 'old-secret', 2000));
        self::assertSame('renewed-secret', $token->value());
        $transport->data = null;
        $client->logout($token);
        self::assertCount(2, $transport->requests);
        self::assertSame([
            ['debug', 'WG token renewed for {realm}.', ['realm' => 'asia']],
            ['debug', 'WG token revoked for {realm}.', ['realm' => 'asia']],
        ], $logger->records);
    }

    public function testThrowingLoggerDoesNotChangeSuccessfulLogin(): void
    {
        $logger = $this->logger(true);
        $transport = new RecordingTransport();
        $transport->data = [42 => ['account_id' => 42, 'nickname' => 'name', 'private' => ['is_premium' => true]]];
        $states = new MemoryStates();
        $states->attempt = new LoginAttempt(Realm::EU, str_repeat('a', 64), 2000);
        $flow = new WgAuth(new AuthClient('app', $transport, static fn () => 1000, $logger), $states, static fn () => 1000, $logger);
        $account = $flow->completeLogin([
            'state' => str_repeat('a', 64), 'status' => 'ok', 'account_id' => 42,
            'access_token' => 'secret', 'expires_at' => 2000,
        ]);
        self::assertSame(42, $account->identity->accountId);
        self::assertNull($states->attempt);
        self::assertCount(1, $logger->records);
    }

    #[DataProvider('loggerModes')]
    public function testOwnershipFailureIsNotDuplicatedOrReplaced(bool $throws): void
    {
        $logger = $this->logger($throws);
        $transport = new RecordingTransport();
        $transport->data = [42 => ['account_id' => 42, 'nickname' => 'private-name']];
        $states = new MemoryStates();
        $states->attempt = new LoginAttempt(Realm::EU, str_repeat('a', 64), 2000);
        $flow = new WgAuth(new AuthClient('app', $transport, static fn () => 1000, $logger), $states, static fn () => 1000, $logger);
        try {
            $flow->completeLogin([
                'state' => str_repeat('a', 64), 'status' => 'ok', 'account_id' => 42,
                'access_token' => 'secret', 'expires_at' => 2000,
            ]);
            self::fail('Ownership failure was swallowed.');
        } catch (AuthException $exception) {
            self::assertSame('WG token ownership could not be verified.', $exception->getMessage());
            self::assertNull($states->attempt);
            self::assertSame([['warning', 'WG token ownership verification rejected for {realm}.', ['realm' => 'eu']]], $logger->records);
        }
    }

    #[DataProvider('loggerModes')]
    public function testStateRejectionDoesNotLogUntrustedInput(bool $throws): void
    {
        $logger = $this->logger($throws);
        $transport = new RecordingTransport();
        $flow = new WgAuth(new AuthClient('app', $transport), new MemoryStates(), logger: $logger);
        try {
            $flow->completeLogin(['state' => 'secret-invalid-state', 'access_token' => 'secret']);
            self::fail('Invalid state accepted.');
        } catch (AuthException $exception) {
            self::assertSame('Invalid login state.', $exception->getMessage());
            self::assertSame([], $transport->requests);
            self::assertSame([['debug', 'WG login state rejected.', []]], $logger->records);
        }
    }

    #[DataProvider('loggerModes')]
    public function testHttpFailureRemainsSanitizedAndLogsOnce(bool $throws): void
    {
        $logger = $this->logger($throws);
        $http = new Client(['handler' => HandlerStack::create(new MockHandler([new Response(503, [], 'private-body')]))]);
        $transport = new GuzzleAuthTransport($http, logger: $logger);
        $client = new AuthClient('private-app', $transport, logger: $logger);
        try {
            $client->logout(new AccessToken(Realm::EU, 42, 'private-token', 2000));
            self::fail('HTTP failure was swallowed.');
        } catch (AuthException $exception) {
            self::assertSame('WG authentication HTTP request failed.', $exception->getMessage());
            self::assertSame(503, $exception->httpStatus);
            self::assertSame([['warning', 'WG authentication HTTP request failed with status {http_status}.', ['http_status' => 503]]], $logger->records);
        }
    }

    public function testRawTransportExceptionNeverReachesLogger(): void
    {
        $logger = $this->logger(true);
        $http = new Client(['handler' => HandlerStack::create(new MockHandler([new RuntimeException('secret-credentials')]))]);
        $transport = new GuzzleAuthTransport($http, logger: $logger);
        try {
            $transport->post('https://api.worldoftanks.eu/wot/auth/logout/', ['access_token' => 'secret']);
            self::fail('Transport failure was swallowed.');
        } catch (AuthException $exception) {
            self::assertSame('WG authentication transport failed.', $exception->getMessage());
            self::assertNull($exception->getPrevious());
            self::assertSame([['warning', 'WG authentication transport failed.', []]], $logger->records);
        }
    }

    private function logger(bool $throws = false): AbstractLogger
    {
        return new class ($throws) extends AbstractLogger {
            /** @var list<array{mixed, string, array<string, mixed>}> */
            public array $records = [];

            public function __construct(private bool $throws)
            {
            }

            public function log($level, string|Stringable $message, array $context = []): void
            {
                $this->records[] = [$level, (string) $message, $context];
                if ($this->throws) {
                    throw new \Error('Logger failed.');
                }
            }
        };
    }
}
