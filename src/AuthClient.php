<?php

declare(strict_types=1);

namespace edrard\WgAuth;

use Closure;
use edrard\WgApi\ApiConfiguration;
use edrard\WgApi\Realm;
use edrard\WgAuth\Contracts\AuthTransportInterface;
use edrard\WgAuth\Http\GuzzleAuthTransport;
use edrard\WgAuth\Internal\BestEffortLogger;
use InvalidArgumentException;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use SensitiveParameter;

final class AuthClient
{
    private ApiConfiguration $configuration;
    private AuthTransportInterface $transport;
    /** @var Closure(): int */
    private Closure $clock;
    private readonly BestEffortLogger $logger;

    /**
     * A single ID is applied explicitly to EU, NA and ASIA.
     * @param string|array<string, string> $applicationIds
     * @param (callable(): int)|null $clock
     */
    public function __construct(#[SensitiveParameter] string|array $applicationIds, ?AuthTransportInterface $transport = null, ?callable $clock = null, ?LoggerInterface $logger = null)
    {
        $this->configuration = new ApiConfiguration(is_string($applicationIds) ? array_fill_keys(['eu', 'na', 'asia'], $applicationIds) : $applicationIds);
        $this->transport = $transport ?? new GuzzleAuthTransport(logger: $logger);
        $this->clock = $clock === null ? time(...) : Closure::fromCallable($clock);
        $this->logger = new BestEffortLogger($logger);
    }

    public function loginLocation(Realm $realm, string $redirectUri, int $tokenLifetime = 3600): string
    {
        self::validateCallbackUrl($redirectUri);
        $data = $this->post($realm, 'auth/login', [
            'redirect_uri' => $redirectUri, 'nofollow' => 1, 'display' => 'page',
            'expires_at' => $this->expiration($tokenLifetime),
        ]);
        $location = $data['location'] ?? null;
        $parts = is_string($location) ? parse_url($location) : false;
        $expectedHost = $realm->value.'.wargaming.net';
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https'
            || strtolower($parts['host'] ?? '') !== $expectedHost
            || isset($parts['user']) || isset($parts['pass']) || (isset($parts['port']) && $parts['port'] !== 443)
            || isset($parts['fragment'])
            || preg_match('/[\x00-\x20\x7f\\\\]/', $location)) {
            $this->logger->log(LogLevel::WARNING, 'WG login location rejected for {realm}.', ['realm' => $realm->value]);
            throw new AuthException('Invalid WG authentication location.');
        }
        return $location;
    }

    public function verifyIdentity(#[SensitiveParameter] AccessToken $token): Identity
    {
        $this->assertUnexpired($token);
        $data = $this->post($token->realm, 'account/info', [
            'account_id' => $token->accountId, 'access_token' => $token->value(),
            'fields' => 'account_id,nickname,private.is_premium',
        ]);
        $account = $data[$token->accountId] ?? null;
        // Public account data alone cannot prove ownership of the submitted token.
        if (!is_array($account) || ($account['account_id'] ?? null) !== $token->accountId
            || !is_array($account['private'] ?? null) || !is_bool($account['private']['is_premium'] ?? null)
            || !is_string($account['nickname'] ?? null) || $account['nickname'] === '') {
            $this->logger->log(LogLevel::WARNING, 'WG token ownership verification rejected for {realm}.', ['realm' => $token->realm->value]);
            throw new AuthException('WG token ownership could not be verified.');
        }
        return new Identity($token->realm, $token->accountId, $account['nickname']);
    }

    public function prolongate(#[SensitiveParameter] AccessToken $token, int $tokenLifetime = 3600): AccessToken
    {
        $this->assertUnexpired($token);
        $data = $this->post($token->realm, 'auth/prolongate', [
            'access_token' => $token->value(), 'expires_at' => $this->expiration($tokenLifetime),
        ]);
        $renewed = $this->tokenFromData($token->realm, $data ?? []);
        if ($renewed->accountId !== $token->accountId) {
            $this->logger->log(LogLevel::WARNING, 'WG renewal owner mismatch for {realm}.', ['realm' => $token->realm->value]);
            throw new AuthException('WG returned a different token owner.');
        }
        $this->logger->log(LogLevel::DEBUG, 'WG token renewed for {realm}.', ['realm' => $token->realm->value]);
        return $renewed;
    }

    public function logout(#[SensitiveParameter] AccessToken $token): void
    {
        $this->post($token->realm, 'auth/logout', ['access_token' => $token->value()]);
        $this->logger->log(LogLevel::DEBUG, 'WG token revoked for {realm}.', ['realm' => $token->realm->value]);
    }

    /** @param array<array-key, mixed> $data */
    public function tokenFromData(Realm $realm, #[SensitiveParameter] array $data): AccessToken
    {
        $accountId = self::positiveInteger($data['account_id'] ?? null);
        $expiresAt = self::positiveInteger($data['expires_at'] ?? null);
        $secret = $data['access_token'] ?? null;
        if ($accountId === null || $expiresAt === null || !is_string($secret)
            || $expiresAt <= ($this->clock)() || $expiresAt > ($this->clock)() + 1209600) {
            throw new AuthException('Invalid or expired WG token response.');
        }
        try {
            return new AccessToken($realm, $accountId, $secret, $expiresAt);
        } catch (InvalidArgumentException) {
            throw new AuthException('Invalid WG token response.');
        }
    }

    public static function positiveInteger(mixed $value): ?int
    {
        if (!is_int($value) && (!is_string($value) || !ctype_digit($value))) {
            return null;
        }
        $number = filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        return is_int($number) ? $number : null;
    }

    public static function validateCallbackUrl(string $url): void
    {
        $parts = parse_url($url);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
            || preg_match('/[\x00-\x20\x7f\\\\]/', $url)) {
            throw new InvalidArgumentException('Callback must be a trusted HTTPS URL without credentials or fragment.');
        }
    }

    /** @param array<string, int|string> $parameters
     * @return array<array-key, mixed>|null
     */
    private function post(Realm $realm, string $path, #[SensitiveParameter] array $parameters): ?array
    {
        $parameters['application_id'] = $this->configuration->applicationId($realm);
        return $this->transport->post($this->configuration->baseUrl($realm).'/wot/'.$path.'/', $parameters);
    }

    private function expiration(int $lifetime): int
    {
        if ($lifetime < 1 || $lifetime > 1209600) {
            throw new InvalidArgumentException('Token lifetime must be between 1 and 1209600 seconds.');
        }
        return ($this->clock)() + $lifetime;
    }

    private function assertUnexpired(#[SensitiveParameter] AccessToken $token): void
    {
        if ($token->expiresAt <= ($this->clock)()) {
            throw new AuthException('WG access token has expired.');
        }
    }
}
