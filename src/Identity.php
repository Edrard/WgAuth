<?php

declare(strict_types=1);

namespace edrard\WgAuth;

use edrard\WgApi\Realm;

/** Verified WG account identity, not an application user or verified email. */
final readonly class Identity
{
    public function __construct(public Realm $realm, public int $accountId, public string $nickname)
    {
    }
}
