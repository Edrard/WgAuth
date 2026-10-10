<?php

declare(strict_types=1);

namespace edrard\Tests\WgAuth;

use edrard\WgApi\Realm;
use edrard\WgAuth\AuthClient;
use edrard\WgAuth\AuthException;
use edrard\WgAuth\Http\GuzzleAuthTransport;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;
use Stringable;

final class LoggingTest extends TestCase
{
    private function logger(?\Throwable $failure = null): AbstractLogger
    {
        return new class ($failure) extends AbstractLogger {
            public array $records = [];
            public function __construct(private ?\Throwable $failure)
            {
            }
            public function log($level, string|Stringable $message, array $context = []): void
            {
                $this->records[] = ['level' => $level, 'message' => (string) $message, 'context' => $context];
                if ($this->failure !== null) {
                    throw $this->failure;
                }
            }
        };
    }

    public function testOneSafeRecordPerFailedRequestAndNoSuccessRecords(): void
    {
        $logger = $this->logger();
        $mock = new MockHandler([new Response(200, [], '{"status":"error","error":{"code":407,"message":"SECRET_PROVIDER"}}'), new Response(200, [], '{"status":"ok","data":null}')]);
        $transport = new GuzzleAuthTransport(new Client(['handler' => HandlerStack::create($mock)]), logger: $logger);
        try {
            $transport->post('https://api.worldoftanks.eu/wot/auth/logout/', ['access_token' => 'SECRET_TOKEN']);
            self::fail('Failed request accepted.');
        } catch (AuthException $failure) {
            self::assertSame(407, $failure->providerCode);
        }
        self::assertCount(1, $logger->records);
        self::assertSame('warning', $logger->records[0]['level']);
        self::assertSame(['reason' => 'provider_rejected', 'providerCode' => 407, 'httpStatus' => null], $logger->records[0]['context']);
        self::assertStringNotContainsString('SECRET_', json_encode($logger->records, JSON_THROW_ON_ERROR));
        self::assertStringNotContainsString('https://', json_encode($logger->records, JSON_THROW_ON_ERROR));
        self::assertNull($transport->post('https://api.worldoftanks.eu/wot/auth/logout/', []));
        self::assertCount(1, $logger->records);
        self::assertSame(0, $mock->count());
    }

    public function testThrowingLoggersDoNotReplaceAuthFailuresOrChangeSuccessfulResults(): void
    {
        foreach ([new \RuntimeException('logger secret'), new \Error('logger secret')] as $error) {
            $mock = new MockHandler([new Response(503, [], 'SECRET_RESPONSE'), new Response(200, [], '{"status":"ok","data":null}')]);
            $logger = $this->logger($error);
            $transport = new GuzzleAuthTransport(new Client(['handler' => HandlerStack::create($mock)]), logger: $logger);
            try {
                $transport->post('https://api.worldoftanks.eu/wot/auth/logout/', []);
                self::fail('HTTP failure accepted.');
            } catch (AuthException $failure) {
                self::assertSame('WG authentication HTTP request failed.', $failure->getMessage());
                self::assertSame(503, $failure->httpStatus);
                self::assertNull($failure->getPrevious());
            }
            self::assertNull($transport->post('https://api.worldoftanks.eu/wot/auth/logout/', []));
            self::assertCount(1, $logger->records);
        }
    }

    public function testCustomTransportAndMissingLoggerRemainIndependent(): void
    {
        $transport = new RecordingTransport();
        $logger = $this->logger(new \Error('must not be called'));
        $client = new AuthClient('synthetic-app', $transport, static fn () => 1000, logger: $logger);
        self::assertSame('https://eu.wargaming.net/id/', $client->loginLocation(Realm::EU, 'https://example.test/callback'));
        self::assertSame([], $logger->records);
        $quiet = new GuzzleAuthTransport(new Client(['handler' => HandlerStack::create(new MockHandler([new Response(200, [], '{"status":"ok","data":null}')]))]));
        self::assertNull($quiet->post('https://api.worldoftanks.eu/wot/auth/logout/', []));
    }
}
