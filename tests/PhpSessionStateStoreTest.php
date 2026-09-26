<?php

declare(strict_types=1);

namespace edrard\Tests\WgAuth;

use edrard\WgApi\Realm;
use edrard\WgAuth\LoginAttempt;
use edrard\WgAuth\Session\PhpSessionStateStore;
use LogicException;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;

#[RunTestsInSeparateProcesses]
#[PreserveGlobalState(false)]
final class PhpSessionStateStoreTest extends TestCase
{
    protected function tearDown(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_destroy();
        }
    }

    public function testActiveSessionIsRequired(): void
    {
        $this->expectException(LogicException::class);
        (new PhpSessionStateStore())->consume(str_repeat('a', 64));
    }

    public function testStateIsConsumedOnceAndBoundToSession(): void
    {
        session_start(['use_cookies' => false, 'cache_limiter' => '']);
        $_SESSION = [];
        $store = new PhpSessionStateStore();
        $attempt = new LoginAttempt(Realm::EU, str_repeat('a', 64), time() + 600);
        $store->store($attempt);
        $initiatingSession = $_SESSION;
        $_SESSION = [];
        self::assertNull($store->consume($attempt->state));
        $_SESSION = $initiatingSession;
        self::assertEquals($attempt, $store->consume($attempt->state));
        self::assertNull($store->consume($attempt->state));
    }

    public function testExpiredEntriesArePrunedAndPendingAttemptsBounded(): void
    {
        session_start(['use_cookies' => false, 'cache_limiter' => '']);
        $_SESSION = [];
        $store = new PhpSessionStateStore(maxAttempts: 1);
        $store->store(new LoginAttempt(Realm::EU, str_repeat('a', 64), time() - 1));
        $store->store(new LoginAttempt(Realm::EU, str_repeat('b', 64), time() + 600));
        self::assertArrayNotHasKey(str_repeat('a', 64), $_SESSION['wg_auth']);
        $this->expectException(LogicException::class);
        $store->store(new LoginAttempt(Realm::EU, str_repeat('c', 64), time() + 600));
    }

    public function testCorruptStateFailsClosed(): void
    {
        session_start(['use_cookies' => false, 'cache_limiter' => '']);
        $_SESSION = ['wg_auth' => [str_repeat('a', 64) => ['realm' => 'ru', 'expiresAt' => time() + 600]]];
        $store = new PhpSessionStateStore();
        self::assertNull($store->consume(str_repeat('a', 64)));
        self::assertSame([], $_SESSION['wg_auth']);
    }
}
