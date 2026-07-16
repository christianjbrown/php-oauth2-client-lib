<?php

declare(strict_types=1);

namespace ChristianBrown\OAuth2Client\Lock;

/**
 * A mutual-exclusion lock used to serialise the token refresh across processes
 * or instances, so a rotating refresh token is never spent by two refreshes at
 * once. Implementations back this with whatever shared primitive is available
 * (e.g. a database advisory lock).
 */
interface LockInterface
{
    /**
     * Acquire the lock, blocking until it is held. Implementations throw if the
     * lock cannot be acquired (for example on timeout).
     */
    public function acquire(): void;

    /**
     * Release a previously acquired lock.
     */
    public function release(): void;
}
