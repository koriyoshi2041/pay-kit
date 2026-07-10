<?php

declare(strict_types=1);

namespace PayKit\Store;

/**
 * Affirmative production replay-store capability.
 *
 * Unknown Store implementations fail closed. Implement this interface only
 * when putIfAbsent is atomic across every process that accepts credentials and
 * replay markers survive the relevant process lifetime.
 */
interface DurableStore extends Store
{
    public function isDurable(): bool;
}
