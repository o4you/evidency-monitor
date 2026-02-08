<?php

declare(strict_types=1);

namespace EvidencyMonitor\Reporters;

/**
 * Reporter Interface
 */
interface ReporterInterface
{
    /**
     * Generate reports from scan results
     *
     * @param array $results Scan results
     * @return array List of generated report files
     */
    public function generate(array $results): array;

    /**
     * Get reporter name
     */
    public function getName(): string;
}
