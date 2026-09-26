<?php

declare(strict_types=1);

namespace edrard\WgAuth;

use edrard\WgApi\Realm;
use InvalidArgumentException;
use LogicException;
use SensitiveParameter;

final readonly class AccessToken
{
    public function __construct(
        public Realm $realm,
        public int $accountId,
        #[SensitiveParameter] private string $secret,
        public int $expiresAt,
    ) {
        if ($accountId < 1 || $expiresAt < 1 || $secret === '' || strlen($secret) > 4096
            || preg_match('/[^\x21-\x7E]/', $secret)) {
            throw new InvalidArgumentException('Invalid access token.');
        }
    }

    /** Explicit credential access for provider requests; never log this value. */
    public function value(): string
    {
        return $this->secret;
    }

    /** @return array<string, int|string> */
    public function __debugInfo(): array
    {
        return ['realm' => $this->realm->value, 'accountId' => $this->accountId, 'expiresAt' => $this->expiresAt, 'secret' => '[redacted]'];
    }

    /** @return array<never, never> */
    public function __serialize(): array
    {
        throw new LogicException('Access tokens must not be serialized.');
    }
}
