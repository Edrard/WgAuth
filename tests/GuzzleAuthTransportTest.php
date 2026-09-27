<?php

declare(strict_types=1);

namespace edrard\Tests\WgAuth;

use edrard\WgAuth\AuthException;
use edrard\WgAuth\Http\GuzzleAuthTransport;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class GuzzleAuthTransportTest extends TestCase
{
    public function testPostKeepsCredentialsOutOfUrlAndDisablesRedirects(): void
    {
        $history = [];
        $stack = HandlerStack::create(new MockHandler([new Response(200, [], '{"status":"ok","data":null}')]));
        $stack->push(Middleware::history($history));
        $transport = new GuzzleAuthTransport(new Client(['handler' => $stack]));
        self::assertNull($transport->post('https://api.worldoftanks.eu/wot/auth/logout/', ['access_token' => 'fake secret', 'application_id' => 'test']));
        self::assertCount(1, $history);
        self::assertSame('POST', $history[0]['request']->getMethod());
        self::assertSame('', $history[0]['request']->getUri()->getQuery());
        self::assertSame('access_token=fake+secret&application_id=test', (string) $history[0]['request']->getBody());
        self::assertSame('application/x-www-form-urlencoded', $history[0]['request']->getHeaderLine('Content-Type'));
        self::assertFalse($history[0]['options']['allow_redirects']);
        self::assertFalse($history[0]['options']['http_errors']);
        self::assertTrue($history[0]['options']['verify']);
        self::assertSame(15.0, $history[0]['options']['timeout']);
    }

    /** @return iterable<string, array{int, string}> */
    public static function failures(): iterable
    {
        yield 'HTTP redirect' => [302, '{"status":"ok","data":null}'];
        yield 'HTTP limited' => [429, 'raw secret'];
        yield 'HTTP upstream' => [503, 'raw secret'];
        yield 'invalid JSON' => [200, 'raw secret'];
        yield 'scalar JSON' => [200, '"raw secret"'];
        yield 'missing data' => [200, '{"status":"ok"}'];
        yield 'scalar data' => [200, '{"status":"ok","data":"raw secret"}'];
        yield 'missing status' => [200, '{"data":null}'];
        yield 'unknown status' => [200, '{"status":"unknown","data":null}'];
        yield 'large invalid JSON' => [200, str_repeat('s', 1048577)];
        yield 'WG error' => [200, '{"status":"error","error":{"code":407,"message":"raw secret","value":"raw secret"}}'];
        yield 'malformed error' => [200, '{"status":"error","error":"raw secret"}'];
    }

    #[DataProvider('failures')]
    public function testFailuresAreSanitizedAndNotRetried(int $status, string $body): void
    {
        $mock = new MockHandler([new Response($status, [], $body), new Response(200, [], '{"status":"ok","data":null}')]);
        $transport = new GuzzleAuthTransport(new Client(['handler' => HandlerStack::create($mock)]));
        try {
            $transport->post('https://api.worldoftanks.eu/wot/auth/prolongate/', ['access_token' => 'input secret']);
            self::fail('Bad response accepted.');
        } catch (AuthException $exception) {
            self::assertStringNotContainsString('raw secret', $exception->getMessage());
            self::assertStringNotContainsString('input secret', $exception->getMessage());
            self::assertNull($exception->getPrevious());
            self::assertSame(1, $mock->count());
        }
    }

    public function testTransportExceptionsDoNotExposeRequests(): void
    {
        $transport = new GuzzleAuthTransport(new Client(['handler' => HandlerStack::create(new MockHandler([new RuntimeException('raw secret')]))]));
        try {
            $transport->post('https://api.worldoftanks.eu/wot/auth/logout/', ['access_token' => 'input secret']);
            self::fail('Transport failure accepted.');
        } catch (AuthException $exception) {
            self::assertSame('WG authentication transport failed.', $exception->getMessage());
            self::assertNull($exception->getPrevious());
            self::assertSame(0, $exception->getCode());
        }
    }

    public function testProviderCodeIsAvailableWithoutProviderMessage(): void
    {
        $transport = new GuzzleAuthTransport(new Client(['handler' => HandlerStack::create(new MockHandler([new Response(200, [], '{"status":"error","error":{"code":407,"message":"raw secret"}}')]))]));
        try {
            $transport->post('https://api.worldoftanks.eu/wot/auth/logout/', []);
            self::fail('Provider failure accepted.');
        } catch (AuthException $exception) {
            self::assertSame(407, $exception->providerCode);
            self::assertNull($exception->httpStatus);
        }
    }

    public function testUnsecuredEndpointsAreRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        (new GuzzleAuthTransport())->post('http://example.test/auth/', []);
    }

    public function testInvalidTimeoutsAreRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new GuzzleAuthTransport(timeout: INF);
    }
}
