<?php

declare(strict_types=1);

namespace edrard\Tests\WgAuth;

use edrard\WgAuth\Contracts\StateStoreInterface;
use edrard\WgAuth\LoginAttempt;

final class MemoryStates implements StateStoreInterface
{
    public ?LoginAttempt $attempt = null;
    public function store(LoginAttempt $attempt): void
    {
        $this->attempt = $attempt;
    }
    public function consume(string $state): ?LoginAttempt
    {
        if ($this->attempt?->state !== $state) {
            return null;
        }
        $attempt = $this->attempt;
        $this->attempt = null;
        return $attempt;
    }
}
