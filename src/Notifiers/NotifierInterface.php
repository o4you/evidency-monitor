<?php

declare(strict_types=1);

namespace EvidencyMonitor\Notifiers;

/**
 * Notifier Interface
 */
interface NotifierInterface
{
    /**
     * Send notification with scan results
     *
     * @param array $results Scan results
     * @return bool Success status
     */
    public function send(array $results): bool;

    /**
     * Get notifier name
     */
    public function getName(): string;
}
