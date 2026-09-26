<?php

declare(strict_types=1);

namespace edrard\WgAuth;

use RuntimeException;

final class AuthException extends RuntimeException
{
    public function __construct(string $message, public readonly ?int $providerCode = null, public readonly ?int $httpStatus = null)
    {
        parent::__construct($message, $providerCode ?? $httpStatus ?? 0);
    }
}
