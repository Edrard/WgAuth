<?php

declare(strict_types=1);

namespace edrard\Tests\WgAuth;

use edrard\WgAuth\Contracts\AuthTransportInterface;
use SensitiveParameter;

final class RecordingTransport implements AuthTransportInterface
{
    /** @var array<array-key, mixed>|null */
    public ?array $data = ['location' => 'https://eu.wargaming.net/id/'];
    /** @var list<array{string, array<string, int|string>}> */
    public array $requests = [];
    public function post(string $url, #[SensitiveParameter] array $parameters): ?array
    {
        $this->requests[] = [$url, $parameters];
        if (str_contains($url, '/auth/login/') && $this->data === ['location' => 'https://eu.wargaming.net/id/']) {
            $host = str_contains($url, 'worldoftanks.com') ? 'na' : (str_contains($url, 'worldoftanks.asia') ? 'asia' : 'eu');
            return ['location' => 'https://'.$host.'.wargaming.net/id/'];
        }
        return $this->data;
    }
}
