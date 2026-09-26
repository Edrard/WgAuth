<?php

declare(strict_types=1);

namespace edrard\WgAuth;

use Closure;
use edrard\WgApi\Realm;
use edrard\WgAuth\Contracts\StateStoreInterface;
use InvalidArgumentException;
use SensitiveParameter;

final class WgAuth
{
    /** @var Closure(): int */
    private Closure $clock;

    /** @param (callable(): int)|null $clock */
    public function __construct(private AuthClient $client, private StateStoreInterface $states, ?callable $clock = null)
    {
        $this->clock = $clock === null ? time(...) : Closure::fromCallable($clock);
    }

    /** Callback URI must come from application configuration, never request input. */
    public function beginLogin(Realm $realm, string $callbackUri, int $tokenLifetime = 3600, int $stateLifetime = 600): string
    {
        AuthClient::validateCallbackUrl($callbackUri);
        if ($stateLifetime < 1 || $stateLifetime > 900) {
            throw new InvalidArgumentException('Login state lifetime must be between 1 and 900 seconds.');
        }
        $parts = parse_url($callbackUri);
        foreach (explode('&', $parts['query'] ?? '') as $pair) {
            $key = urldecode(explode('=', $pair, 2)[0]);
            if (preg_match('/^(state|status|access_token|expires_at|account_id|nickname|code|message)(?:$|[. \\[])/', $key)) {
                throw new InvalidArgumentException('Callback URL contains a reserved authentication parameter.');
            }
        }
        $state = bin2hex(random_bytes(32));
        $attempt = new LoginAttempt($realm, $state, ($this->clock)() + $stateLifetime);
        $redirect = $callbackUri.(str_contains($callbackUri, '?') ? '&' : '?').'state='.$state;
        $location = $this->client->loginLocation($realm, $redirect, $tokenLifetime);
        $this->states->store($attempt);
        return $location;
    }

    /** @param array<array-key, mixed> $query */
    public function completeLogin(#[SensitiveParameter] array $query): AuthenticatedAccount
    {
        $state = $query['state'] ?? null;
        if (!is_string($state) || !preg_match('/^[a-f0-9]{64}$/D', $state)) {
            throw new AuthException('Invalid login state.');
        }
        // Consumption precedes verification, including cancelled and malformed callbacks.
        $attempt = $this->states->consume($state);
        if ($attempt === null || !hash_equals($attempt->state, $state) || $attempt->expiresAt <= ($this->clock)()) {
            throw new AuthException('Invalid or expired login state.');
        }
        if (($query['status'] ?? null) !== 'ok') {
            throw new AuthException('WG login was cancelled or rejected.', AuthClient::positiveInteger($query['code'] ?? null));
        }
        $token = $this->client->tokenFromData($attempt->realm, $query);
        $identity = $this->client->verifyIdentity($token);
        return new AuthenticatedAccount($identity, $token);
    }
}
