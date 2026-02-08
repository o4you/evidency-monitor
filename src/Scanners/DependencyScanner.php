<?php

declare(strict_types=1);

namespace EvidencyMonitor\Scanners;

/**
 * Dependency Scanner
 *
 * Checks for vulnerable dependencies using composer audit
 */
class DependencyScanner implements ScannerInterface
{
    private array $config;

    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    public function getName(): string
    {
        return 'dependencies';
    }

    public function scan(string $path, array $files): array
    {
        $result = [
            'name' => $this->getName(),
            'errors' => 0,
            'warnings' => 0,
            'has_composer' => false,
            'has_lockfile' => false,
            'packages' => [],
            'vulnerabilities' => [],
            'outdated' => [],
        ];

        $composerFile = $path . DIRECTORY_SEPARATOR . 'composer.json';
        $lockFile = $path . DIRECTORY_SEPARATOR . 'composer.lock';

        if (!file_exists($composerFile)) {
            return $result;
        }

        $result['has_composer'] = true;
        $result['has_lockfile'] = file_exists($lockFile);

        // Parse composer.json
        $composer = json_decode(file_get_contents($composerFile), true);
        if ($composer) {
            $result['packages'] = $this->parsePackages($composer);
        }

        // Run composer audit if lock file exists
        if ($result['has_lockfile']) {
            $cwd = getcwd();
            chdir($path);

            try {
                $result['vulnerabilities'] = $this->runAudit();
                $result['errors'] = count($result['vulnerabilities']);

                // Check for outdated packages
                $result['outdated'] = $this->checkOutdated();
                $result['warnings'] = count($result['outdated']);

            } finally {
                chdir($cwd);
            }
        }

        return $result;
    }

    private function parsePackages(array $composer): array
    {
        $packages = [];

        $require = $composer['require'] ?? [];
        foreach ($require as $name => $version) {
            if ($name === 'php' || strpos($name, 'ext-') === 0) {
                continue;
            }
            $packages[] = [
                'name' => $name,
                'version' => $version,
                'dev' => false,
            ];
        }

        $requireDev = $composer['require-dev'] ?? [];
        foreach ($requireDev as $name => $version) {
            $packages[] = [
                'name' => $name,
                'version' => $version,
                'dev' => true,
            ];
        }

        return $packages;
    }

    private function runAudit(): array
    {
        $vulnerabilities = [];

        // Try composer audit (Composer 2.4+)
        $output = shell_exec('composer audit --format=json 2>&1') ?? '';

        if (strpos($output, '"advisories"') !== false) {
            $data = json_decode($output, true);

            if (isset($data['advisories']) && is_array($data['advisories'])) {
                foreach ($data['advisories'] as $package => $advisories) {
                    foreach ($advisories as $advisory) {
                        $vulnerabilities[] = [
                            'package' => $package,
                            'title' => $advisory['title'] ?? 'Unknown',
                            'cve' => $advisory['cve'] ?? null,
                            'link' => $advisory['link'] ?? null,
                            'affected_versions' => $advisory['affectedVersions'] ?? null,
                            'severity' => $this->determineSeverity($advisory),
                        ];
                    }
                }
            }
        }

        return $vulnerabilities;
    }

    private function determineSeverity(array $advisory): string
    {
        // Try to determine severity from title or CVE
        $title = strtolower($advisory['title'] ?? '');

        if (strpos($title, 'critical') !== false || strpos($title, 'remote code') !== false) {
            return 'critical';
        }
        if (strpos($title, 'sql injection') !== false || strpos($title, 'xss') !== false) {
            return 'high';
        }
        if (strpos($title, 'denial') !== false || strpos($title, 'dos') !== false) {
            return 'medium';
        }

        return 'unknown';
    }

    private function checkOutdated(): array
    {
        $outdated = [];

        $output = shell_exec('composer outdated --direct --format=json 2>&1') ?? '';

        if (strpos($output, '"installed"') !== false) {
            $data = json_decode($output, true);

            if (isset($data['installed']) && is_array($data['installed'])) {
                foreach ($data['installed'] as $package) {
                    // Only report major/minor updates as warnings
                    if ($this->isSignificantUpdate($package['version'] ?? '', $package['latest'] ?? '')) {
                        $outdated[] = [
                            'name' => $package['name'] ?? '',
                            'current' => $package['version'] ?? '',
                            'latest' => $package['latest'] ?? '',
                            'description' => $package['description'] ?? '',
                        ];
                    }
                }
            }
        }

        return $outdated;
    }

    private function isSignificantUpdate(string $current, string $latest): bool
    {
        // Extract major.minor from versions
        preg_match('/^v?(\d+)\.(\d+)/', $current, $currentMatch);
        preg_match('/^v?(\d+)\.(\d+)/', $latest, $latestMatch);

        if (empty($currentMatch) || empty($latestMatch)) {
            return false;
        }

        // Major version difference
        if ($latestMatch[1] > $currentMatch[1]) {
            return true;
        }

        // Minor version difference (more than 2 versions behind)
        if ($latestMatch[1] === $currentMatch[1] && ($latestMatch[2] - $currentMatch[2]) >= 2) {
            return true;
        }

        return false;
    }
}
