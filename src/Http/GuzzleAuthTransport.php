<?php

declare(strict_types=1);

namespace edrard\WgAuth\Http;

use edrard\WgAuth\AuthException;
use edrard\WgAuth\Contracts\AuthTransportInterface;
use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use InvalidArgumentException;
use JsonException;
use SensitiveParameter;
use Throwable;

final class GuzzleAuthTransport implements AuthTransportInterface
{
    private ClientInterface $client;

    public function __construct(?ClientInterface $client = null, private float $timeout = 15, private float $connectTimeout = 5)
    {
        if (!is_finite($timeout) || !is_finite($connectTimeout) || $timeout <= 0 || $connectTimeout <= 0) {
            throw new InvalidArgumentException('Timeouts must be finite and positive.');
        }
        $this->client = $client ?? new Client();
    }

    public function post(string $url, #[SensitiveParameter] array $parameters): ?array
    {
        $parts = parse_url($url);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            throw new InvalidArgumentException('Authentication endpoint must be HTTPS without credentials or query.');
        }
        try {
            $response = $this->client->request('POST', $url, [
                'form_params' => $parameters,
                'timeout' => $this->timeout, 'connect_timeout' => $this->connectTimeout,
                'verify' => true, 'allow_redirects' => false, 'http_errors' => false,
                'headers' => ['Accept' => 'application/json'],
            ]);
            $status = $response->getStatusCode();
            $body = $response->getBody()->read(1048577);
        } catch (Throwable) {
            // Do not retain Guzzle exceptions: they contain requests and credentials.
            throw new AuthException('WG authentication transport failed.');
        }
        if ($status < 200 || $status >= 300) {
            throw new AuthException('WG authentication HTTP request failed.', httpStatus: $status);
        }
        if (strlen($body) > 1048576) {
            throw new AuthException('WG authentication response is too large.');
        }
        try {
            $envelope = json_decode($body, true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new AuthException('Invalid WG authentication response.');
        }
        if (!is_array($envelope)) {
            throw new AuthException('Invalid WG authentication envelope.');
        }
        if (($envelope['status'] ?? null) === 'error') {
            $code = is_array($envelope['error'] ?? null) ? ($envelope['error']['code'] ?? null) : null;
            throw new AuthException('WG rejected the authentication request.', is_int($code) ? $code : null);
        }
        if (($envelope['status'] ?? null) !== 'ok' || !array_key_exists('data', $envelope)
            || ($envelope['data'] !== null && !is_array($envelope['data']))) {
            throw new AuthException('Invalid WG authentication envelope.');
        }
        return $envelope['data'];
    }
}
