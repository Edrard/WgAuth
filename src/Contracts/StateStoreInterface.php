<?php

declare(strict_types=1);

namespace edrard\WgAuth\Contracts;

use edrard\WgAuth\LoginAttempt;

interface StateStoreInterface
{
    /** Store in the initiating browser's server-side session, never a global state-only cache. */
    public function store(LoginAttempt $attempt): void;

    /** Atomically remove and return once, scoped to that same browser session. */
    public function consume(string $state): ?LoginAttempt;
}
