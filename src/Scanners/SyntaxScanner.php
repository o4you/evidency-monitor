<?php

declare(strict_types=1);

namespace EvidencyMonitor\Scanners;

/**
 * PHP Syntax Scanner
 *
 * Validates PHP syntax using php -l
 */
class SyntaxScanner implements ScannerInterface
{
    private array $config;

    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    public function getName(): string
    {
        return 'syntax';
    }

    public function scan(string $path, array $files): array
    {
        $result = [
            'name' => $this->getName(),
            'files_checked' => 0,
            'errors' => 0,
            'warnings' => 0,
            'issues' => [],
        ];

        foreach ($files as $file) {
            if (pathinfo($file, PATHINFO_EXTENSION) !== 'php') {
                continue;
            }

            $result['files_checked']++;
            $checkResult = $this->checkFile($file);

            if (!$checkResult['valid']) {
                $result['errors']++;
                $result['issues'][] = [
                    'file' => $this->getRelativePath($file, $path),
                    'type' => 'error',
                    'message' => $checkResult['message'],
                    'line' => $checkResult['line'] ?? null,
                ];
            }
        }

        return $result;
    }

    private function checkFile(string $file): array
    {
        $output = [];
        $returnVar = 0;

        exec('php -l ' . escapeshellarg($file) . ' 2>&1', $output, $returnVar);

        $outputStr = implode("\n", $output);

        if ($returnVar === 0) {
            return ['valid' => true];
        }

        // Extract line number from error message
        $line = null;
        if (preg_match('/on line (\d+)/', $outputStr, $matches)) {
            $line = (int) $matches[1];
        }

        return [
            'valid' => false,
            'message' => $outputStr,
            'line' => $line,
        ];
    }

    private function getRelativePath(string $file, string $basePath): string
    {
        return str_replace($basePath . DIRECTORY_SEPARATOR, '', $file);
    }
}
