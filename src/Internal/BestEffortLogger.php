<?php

declare(strict_types=1);

namespace edrard\WgAuth\Internal;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Throwable;

/** @internal */
final class BestEffortLogger
{
    private readonly LoggerInterface $logger;

    public function __construct(?LoggerInterface $logger)
    {
        $this->logger = $logger ?? new NullLogger();
    }

    /** @param array<string, int|string> $context */
    public function log(string $level, string $message, array $context = []): void
    {
        try {
            $this->logger->log($level, $message, $context);
        } catch (Throwable) {
            // Optional diagnostics must never affect authentication or its exceptions.
        }
    }
}
