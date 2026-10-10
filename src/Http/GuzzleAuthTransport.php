<?php

declare(strict_types=1);

namespace edrard\WgAuth\Http;

use edrard\WgAuth\AuthException;
use edrard\WgAuth\Contracts\AuthTransportInterface;
use edrard\WgAuth\Internal\BestEffortLogger;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Psr7\Utils;
use InvalidArgumentException;
use JsonException;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use SensitiveParameter;
use Throwable;

final class GuzzleAuthTransport implements AuthTransportInterface
{
    private ClientInterface $client;
    private readonly BestEffortLogger $logger;

    public function __construct(?ClientInterface $client = null, private float $timeout = 15, private float $connectTimeout = 5, ?LoggerInterface $logger = null)
    {
        if (!is_finite($timeout) || !is_finite($connectTimeout) || $timeout <= 0 || $connectTimeout <= 0) {
            throw new InvalidArgumentException('Timeouts must be finite and positive.');
        }
        $this->client = $client ?? new Client();
        $this->logger = new BestEffortLogger($logger);
    }

    public function post(string $url, #[SensitiveParameter] array $parameters): ?array
    {
        $parts = parse_url($url);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])
            || preg_match('/[\x00-\x20\x7f\\\\]/', $url)) {
            throw new InvalidArgumentException('Authentication endpoint must be HTTPS without credentials or query.');
        }
        try {
            $response = $this->client->request('POST', $url, [
                'query' => [], 'debug' => false,
                'form_params' => $parameters,
                'timeout' => $this->timeout, 'connect_timeout' => $this->connectTimeout,
                'verify' => true, 'allow_redirects' => false, 'http_errors' => false,
                'headers' => ['Accept' => 'application/json'],
            ]);
            $status = $response->getStatusCode();
            $stream = $response->getBody();
            if ($stream->isSeekable()) {
                $stream->rewind();
            }
            $body = Utils::copyToString($stream);
        } catch (Throwable) {
            // Do not retain Guzzle exceptions: they contain requests and credentials.
            $this->logger->log(LogLevel::WARNING, 'WG authentication transport failed.');
            throw new AuthException('WG authentication transport failed.');
        }
        if ($status < 200 || $status >= 300) {
            $this->logger->log(LogLevel::WARNING, 'WG authentication HTTP request failed with status {http_status}.', ['http_status' => $status]);
            throw new AuthException('WG authentication HTTP request failed.', httpStatus: $status);
        }
        try {
            $envelope = json_decode($body, true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $this->logger->log(LogLevel::WARNING, 'Invalid WG authentication response.');
            throw new AuthException('Invalid WG authentication response.');
        }
        if (!is_array($envelope)) {
            $this->logger->log(LogLevel::WARNING, 'Invalid WG authentication envelope.');
            throw new AuthException('Invalid WG authentication envelope.');
        }
        if (($envelope['status'] ?? null) === 'error') {
            $code = is_array($envelope['error'] ?? null) ? ($envelope['error']['code'] ?? null) : null;
            $this->logger->log(LogLevel::DEBUG, 'WG rejected the authentication request.');
            throw new AuthException('WG rejected the authentication request.', is_int($code) ? $code : null);
        }
        if (($envelope['status'] ?? null) !== 'ok' || !array_key_exists('data', $envelope)
            || ($envelope['data'] !== null && !is_array($envelope['data']))) {
            $this->logger->log(LogLevel::WARNING, 'Invalid WG authentication envelope.');
            throw new AuthException('Invalid WG authentication envelope.');
        }
        return $envelope['data'];
    }
}
