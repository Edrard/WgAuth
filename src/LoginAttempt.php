<?php

declare(strict_types=1);

namespace edrard\WgAuth;

use edrard\WgApi\Realm;
use InvalidArgumentException;

final readonly class LoginAttempt
{
    public function __construct(public Realm $realm, public string $state, public int $expiresAt)
    {
        if (!preg_match('/^[a-f0-9]{64}$/D', $state) || $expiresAt < 1) {
            throw new InvalidArgumentException('Invalid login attempt.');
        }
    }
}
