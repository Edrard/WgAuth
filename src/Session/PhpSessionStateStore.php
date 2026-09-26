<?php

declare(strict_types=1);

namespace edrard\WgAuth\Session;

use edrard\WgApi\Realm;
use edrard\WgAuth\Contracts\StateStoreInterface;
use edrard\WgAuth\LoginAttempt;
use InvalidArgumentException;
use LogicException;

final class PhpSessionStateStore implements StateStoreInterface
{
    public function __construct(private string $namespace = 'wg_auth', private int $maxAttempts = 10)
    {
        if ($namespace === '' || $maxAttempts < 1) {
            throw new InvalidArgumentException('Invalid session state configuration.');
        }
    }

    public function store(LoginAttempt $attempt): void
    {
        $this->assertActive();
        $entries = $_SESSION[$this->namespace] ?? [];
        if (!is_array($entries)) {
            throw new LogicException('Invalid session state storage.');
        }
        foreach ($entries as $key => $entry) {
            if (!is_array($entry) || !is_int($entry['expiresAt'] ?? null) || $entry['expiresAt'] <= time()) {
                unset($entries[$key]);
            }
        }
        if (count($entries) >= $this->maxAttempts) {
            throw new LogicException('Too many pending WG login attempts.');
        }
        $entries[$attempt->state] = ['realm' => $attempt->realm->value, 'expiresAt' => $attempt->expiresAt];
        $_SESSION[$this->namespace] = $entries;
    }

    public function consume(string $state): ?LoginAttempt
    {
        $this->assertActive();
        $entries = $_SESSION[$this->namespace] ?? [];
        if (!is_array($entries)) {
            throw new LogicException('Invalid session state storage.');
        }
        $entry = $entries[$state] ?? null;
        unset($entries[$state]);
        $_SESSION[$this->namespace] = $entries;
        if (!is_array($entry) || !is_string($entry['realm'] ?? null) || !is_int($entry['expiresAt'] ?? null)) {
            return null;
        }
        $realm = Realm::tryFrom($entry['realm']);
        return $realm === null ? null : new LoginAttempt($realm, $state, $entry['expiresAt']);
    }

    private function assertActive(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new LogicException('Start a server-side PHP session before using the state store.');
        }
    }
}
