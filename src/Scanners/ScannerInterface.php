<?php

declare(strict_types=1);

namespace EvidencyMonitor\Scanners;

/**
 * Scanner Interface
 */
interface ScannerInterface
{
    /**
     * Scan files in a directory
     *
     * @param string $path Directory path
     * @param array $files List of files to scan
     * @return array Scan results
     */
    public function scan(string $path, array $files): array;

    /**
     * Get scanner name
     */
    public function getName(): string;
}
