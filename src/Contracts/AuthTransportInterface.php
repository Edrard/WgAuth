<?php

declare(strict_types=1);

namespace edrard\WgAuth\Contracts;

use SensitiveParameter;

interface AuthTransportInterface
{
    /**
     * Send one form-encoded HTTPS POST and return validated WG data.
     * Implementations must not log credentials or automatically retry token mutations.
     * @param array<string, int|string> $parameters
     * @return array<array-key, mixed>|null
     */
    public function post(string $url, #[SensitiveParameter] array $parameters): ?array;
}
