<?php

declare(strict_types=1);

namespace EvidencyMonitor;

use EvidencyMonitor\Scanners\SyntaxScanner;
use EvidencyMonitor\Scanners\SecurityScanner;
use EvidencyMonitor\Scanners\DependencyScanner;
use EvidencyMonitor\Scanners\GitScanner;
use EvidencyMonitor\Reporters\ReporterInterface;
use EvidencyMonitor\Reporters\TextReporter;
use EvidencyMonitor\Reporters\JsonReporter;
use EvidencyMonitor\Reporters\HtmlReporter;
use EvidencyMonitor\Notifiers\NotifierInterface;

/**
 * EvidencyMonitor - ISO Compliance Code Validation Tool
 *
 * @package EvidencyMonitor
 * @author Output4you <info@output4you.nl>
 * @version 1.0.0
 */
class EvidencyMonitor
{
    private array $config;
    private array $scanners = [];
    private array $reporters = [];
    private array $notifiers = [];
    private array $results = [];

    public function __construct(array $config = [])
    {
        $this->config = array_merge($this->getDefaultConfig(), $config);
        $this->initializeScanners();
        $this->initializeReporters();
    }

    private function getDefaultConfig(): array
    {
        return [
            'output_dir' => getcwd() . '/reports',
            'projects' => [],
            'scanners' => [
                'syntax' => true,
                'security' => true,
                'dependencies' => true,
                'git' => true,
            ],
            'reporters' => [
                'text' => true,
                'json' => true,
                'html' => false,
            ],
            'security' => [
                'check_eval' => true,
                'check_exec' => true,
                'check_sql_injection' => true,
                'check_xss' => true,
                'check_file_inclusion' => true,
            ],
            'exclude_dirs' => ['vendor', 'node_modules', '.git', 'tests'],
            'file_extensions' => ['php'],
        ];
    }

    private function initializeScanners(): void
    {
        if ($this->config['scanners']['syntax'] ?? true) {
            $this->scanners['syntax'] = new SyntaxScanner($this->config);
        }
        if ($this->config['scanners']['security'] ?? true) {
            $this->scanners['security'] = new SecurityScanner($this->config);
        }
        if ($this->config['scanners']['dependencies'] ?? true) {
            $this->scanners['dependencies'] = new DependencyScanner($this->config);
        }
        if ($this->config['scanners']['git'] ?? true) {
            $this->scanners['git'] = new GitScanner($this->config);
        }
    }

    private function initializeReporters(): void
    {
        if ($this->config['reporters']['text'] ?? true) {
            $this->reporters['text'] = new TextReporter($this->config);
        }
        if ($this->config['reporters']['json'] ?? true) {
            $this->reporters['json'] = new JsonReporter($this->config);
        }
        if ($this->config['reporters']['html'] ?? false) {
            $this->reporters['html'] = new HtmlReporter($this->config);
        }
    }

    public function addNotifier(NotifierInterface $notifier): self
    {
        $this->notifiers[] = $notifier;
        return $this;
    }

    public function addProject(string $name, string $path, array $options = []): self
    {
        $this->config['projects'][$name] = array_merge([
            'path' => $path,
            'exclude' => [],
        ], $options);
        return $this;
    }

    public function scan(): array
    {
        $this->results = [
            'timestamp' => date('Y-m-d H:i:s'),
            'projects' => [],
            'summary' => [
                'total_files' => 0,
                'total_errors' => 0,
                'total_warnings' => 0,
                'status' => 'OK',
            ],
        ];

        foreach ($this->config['projects'] as $name => $project) {
            echo "Scanning: $name\n";
            $projectResult = $this->scanProject($name, $project);
            $this->results['projects'][$name] = $projectResult;

            $this->results['summary']['total_files'] += $projectResult['files_scanned'];
            $this->results['summary']['total_errors'] += $projectResult['errors'];
            $this->results['summary']['total_warnings'] += $projectResult['warnings'];
        }

        if ($this->results['summary']['total_errors'] > 0) {
            $this->results['summary']['status'] = 'ERRORS';
        } elseif ($this->results['summary']['total_warnings'] > 0) {
            $this->results['summary']['status'] = 'WARNINGS';
        }

        return $this->results;
    }

    private function scanProject(string $name, array $project): array
    {
        $result = [
            'name' => $name,
            'path' => $project['path'],
            'timestamp' => date('Y-m-d H:i:s'),
            'files_scanned' => 0,
            'errors' => 0,
            'warnings' => 0,
            'has_changes' => false,
            'scanner_results' => [],
        ];

        if (!is_dir($project['path'])) {
            $result['error'] = "Directory not found: {$project['path']}";
            $result['errors'] = 1;
            return $result;
        }

        // Get files to scan
        $files = $this->findFiles($project['path'], $project['exclude'] ?? []);
        $result['files_scanned'] = count($files);

        // Run each scanner
        foreach ($this->scanners as $scannerName => $scanner) {
            echo "  Running $scannerName scanner...\n";
            $scanResult = $scanner->scan($project['path'], $files);
            $result['scanner_results'][$scannerName] = $scanResult;

            $result['errors'] += $scanResult['errors'] ?? 0;
            $result['warnings'] += $scanResult['warnings'] ?? 0;

            if (isset($scanResult['has_changes'])) {
                $result['has_changes'] = $result['has_changes'] || $scanResult['has_changes'];
            }
        }

        return $result;
    }

    private function findFiles(string $dir, array $exclude = []): array
    {
        $files = [];
        $excludeDirs = array_merge($this->config['exclude_dirs'], $exclude);
        $extensions = $this->config['file_extensions'];

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveCallbackFilterIterator(
                new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
                function ($file, $key, $iterator) use ($excludeDirs) {
                    if ($file->isDir()) {
                        return !in_array($file->getFilename(), $excludeDirs);
                    }
                    return true;
                }
            )
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && in_array($file->getExtension(), $extensions)) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    public function generateReports(): array
    {
        $reportFiles = [];

        // Ensure output directory exists
        if (!is_dir($this->config['output_dir'])) {
            mkdir($this->config['output_dir'], 0755, true);
        }

        foreach ($this->reporters as $name => $reporter) {
            $files = $reporter->generate($this->results);
            $reportFiles = array_merge($reportFiles, $files);
        }

        return $reportFiles;
    }

    public function notify(): void
    {
        foreach ($this->notifiers as $notifier) {
            $notifier->send($this->results);
        }
    }

    public function getResults(): array
    {
        return $this->results;
    }

    public function run(): array
    {
        $this->scan();
        $reports = $this->generateReports();
        $this->notify();

        return [
            'results' => $this->results,
            'reports' => $reports,
        ];
    }
}
