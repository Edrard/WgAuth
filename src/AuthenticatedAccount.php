<?php

declare(strict_types=1);

namespace edrard\WgAuth;

final readonly class AuthenticatedAccount
{
    public function __construct(public Identity $identity, public AccessToken $token)
    {
    }
}
