<?php

declare(strict_types=1);

namespace edrard\Tests\WgAuth;

use edrard\WgAuth\Http\GuzzleAuthTransport;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

final class SecurityReviewTest extends TestCase
{
    public function testExpiredTokenCannotLeakThroughInternalValidationTrace(): void
    {
        $previous = ini_set('zend.exception_ignore_args', '0');
        try {
            foreach (['verifyIdentity', 'prolongate'] as $method) {
                $transport = new RecordingTransport();
                $client = new \edrard\WgAuth\AuthClient('fixture', $transport, static fn (): int => 2000);
                $token = new \edrard\WgAuth\AccessToken(\edrard\WgApi\Realm::EU, 42, 'synthetic-trace-secret', 1000);
                try {
                    $client->$method($token);
                    self::fail('Expired token accepted.');
                } catch (\edrard\WgAuth\AuthException $exception) {
                    $frames = array_values(array_filter($exception->getTrace(), static fn (array $frame): bool => $frame['function'] === 'assertUnexpired'));
                    self::assertCount(1, $frames);
                    self::assertInstanceOf(\SensitiveParameterValue::class, $frames[0]['args'][0]);
                    self::assertStringNotContainsString('synthetic-trace-secret', var_export($exception->getTrace(), true));
                    self::assertSame([], $transport->requests);
                }
            }
        } finally {
            ini_set('zend.exception_ignore_args', $previous);
        }
    }

    public function testDefaultQueryCannotLeak(): void
    {
        $history = [];
        $stack = HandlerStack::create(new MockHandler([new Response(200, [], '{"status":"ok","data":null}')]));
        $stack->push(Middleware::history($history));
        $http = new Client(['handler' => $stack, 'query' => ['access_token' => 'fixture-secret'], 'debug' => true]);
        (new GuzzleAuthTransport($http))->post('https://api.worldoftanks.eu/wot/auth/logout/', ['access_token' => 'fixture-secret']);
        self::assertSame('', $history[0]['request']->getUri()->getQuery());
        self::assertFalse($history[0]['options']['debug']);
    }

    public function testResponseAboveFormerSizeLimitIsReturnedInFull(): void
    {
        $data = ['value' => str_repeat('x', 2 * 1024 * 1024)];
        $body = json_encode(['status' => 'ok', 'data' => $data], JSON_THROW_ON_ERROR);
        $http = new Client(['handler' => HandlerStack::create(new MockHandler([new Response(200, [], $body)]))]);
        self::assertSame($data, (new GuzzleAuthTransport($http))->post('https://api.worldoftanks.eu/wot/account/info/', []));
    }
}
