<?php

declare(strict_types=1);

namespace EvidencyMonitor\Reporters;

/**
 * Text Reporter
 *
 * Generates human-readable text reports
 */
class TextReporter implements ReporterInterface
{
    private array $config;

    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    public function getName(): string
    {
        return 'text';
    }

    public function generate(array $results): array
    {
        $files = [];
        $date = date('Y-m-d');
        $outputDir = $this->config['output_dir'] ?? getcwd() . '/reports';

        // Generate per-project reports
        foreach ($results['projects'] ?? [] as $name => $project) {
            $safeName = preg_replace('/[^a-zA-Z0-9_-]/', '_', $name);
            $changesSuffix = ($project['has_changes'] ?? false) ? '' : '-no_changes';
            $filename = "{$date}-{$safeName}{$changesSuffix}.txt";
            $filepath = $outputDir . DIRECTORY_SEPARATOR . $filename;

            $content = $this->generateProjectReport($project);
            file_put_contents($filepath, $content);
            $files[] = $filepath;
        }

        // Generate summary report
        $summaryFile = "{$date}-SUMMARY.txt";
        $summaryPath = $outputDir . DIRECTORY_SEPARATOR . $summaryFile;
        $summaryContent = $this->generateSummaryReport($results);
        file_put_contents($summaryPath, $summaryContent);
        $files[] = $summaryPath;

        return $files;
    }

    private function generateProjectReport(array $project): string
    {
        $lines = [];
        $sep = str_repeat('=', 70);
        $sepMini = str_repeat('-', 70);

        $lines[] = $sep;
        $lines[] = "CODE VALIDATION REPORT - {$project['name']}";
        $lines[] = $sep;
        $lines[] = "";
        $lines[] = "Timestamp:      {$project['timestamp']}";
        $lines[] = "Project:        {$project['name']}";
        $lines[] = "Path:           {$project['path']}";
        $lines[] = "Files scanned:  {$project['files_scanned']}";
        $lines[] = "Errors:         {$project['errors']}";
        $lines[] = "Warnings:       {$project['warnings']}";
        $lines[] = "";

        foreach ($project['scanner_results'] ?? [] as $scannerName => $scanResult) {
            $lines[] = $sepMini;
            $lines[] = strtoupper($scannerName) . " SCANNER";
            $lines[] = $sepMini;

            switch ($scannerName) {
                case 'syntax':
                    $lines = array_merge($lines, $this->formatSyntaxResults($scanResult));
                    break;
                case 'security':
                    $lines = array_merge($lines, $this->formatSecurityResults($scanResult));
                    break;
                case 'git':
                    $lines = array_merge($lines, $this->formatGitResults($scanResult));
                    break;
                case 'dependencies':
                    $lines = array_merge($lines, $this->formatDependencyResults($scanResult));
                    break;
                default:
                    $lines[] = json_encode($scanResult, JSON_PRETTY_PRINT);
            }

            $lines[] = "";
        }

        $lines[] = $sep;
        $lines[] = "END OF REPORT";
        $lines[] = $sep;

        return implode("\n", $lines);
    }

    private function formatSyntaxResults(array $result): array
    {
        $lines = [];

        if (empty($result['issues'])) {
            $lines[] = "Status: OK - No syntax errors found";
            $lines[] = "Files checked: {$result['files_checked']}";
        } else {
            $lines[] = "Status: ERRORS FOUND (" . count($result['issues']) . ")";
            $lines[] = "";

            foreach ($result['issues'] as $issue) {
                $lines[] = "File: {$issue['file']}" . ($issue['line'] ? " (line {$issue['line']})" : "");
                $lines[] = "Error: {$issue['message']}";
                $lines[] = "";
            }
        }

        return $lines;
    }

    private function formatSecurityResults(array $result): array
    {
        $lines = [];

        if (empty($result['issues'])) {
            $lines[] = "Status: OK - No security issues found";
        } else {
            $lines[] = "Status: ISSUES FOUND";
            $lines[] = "";
            $lines[] = "Summary:";
            $lines[] = "  Critical: {$result['summary']['critical']}";
            $lines[] = "  High:     {$result['summary']['high']}";
            $lines[] = "  Medium:   {$result['summary']['medium']}";
            $lines[] = "  Low:      {$result['summary']['low']}";
            $lines[] = "";

            // Group by severity
            $bySeverity = ['critical' => [], 'high' => [], 'medium' => [], 'low' => []];
            foreach ($result['issues'] as $issue) {
                $bySeverity[$issue['severity']][] = $issue;
            }

            foreach (['critical', 'high', 'medium', 'low'] as $severity) {
                if (empty($bySeverity[$severity])) {
                    continue;
                }

                $lines[] = strtoupper($severity) . " Issues:";
                foreach ($bySeverity[$severity] as $issue) {
                    $lines[] = "  [{$issue['cwe']}] {$issue['file']}:{$issue['line']}";
                    $lines[] = "    {$issue['message']}";
                }
                $lines[] = "";
            }
        }

        return $lines;
    }

    private function formatGitResults(array $result): array
    {
        $lines = [];

        if (!$result['is_git_repo']) {
            $lines[] = "Not a git repository";
            return $lines;
        }

        $lines[] = "Branch:      {$result['current_branch']}";
        $lines[] = "Last commit: {$result['last_commit']['short_hash']} - {$result['last_commit']['message']}";
        $lines[] = "Author:      {$result['last_commit']['author']} <{$result['last_commit']['email']}>";
        $lines[] = "Date:        {$result['last_commit']['date']}";
        $lines[] = "";

        if (!empty($result['recent_commits'])) {
            $lines[] = "Recent commits (last 7 days): " . count($result['recent_commits']);
            foreach (array_slice($result['recent_commits'], 0, 10) as $commit) {
                $lines[] = "  {$commit['hash']} {$commit['message']}";
            }
        } else {
            $lines[] = "No commits in the last 7 days";
        }

        if (!empty($result['uncommitted_changes'])) {
            $lines[] = "";
            $lines[] = "Uncommitted changes: " . count($result['uncommitted_changes']);
            foreach ($result['uncommitted_changes'] as $change) {
                $lines[] = "  [{$change['status']}] {$change['file']}";
            }
        }

        return $lines;
    }

    private function formatDependencyResults(array $result): array
    {
        $lines = [];

        if (!$result['has_composer']) {
            $lines[] = "No composer.json found";
            return $lines;
        }

        $lines[] = "Packages: " . count($result['packages']);

        if (!empty($result['vulnerabilities'])) {
            $lines[] = "";
            $lines[] = "VULNERABILITIES FOUND: " . count($result['vulnerabilities']);
            foreach ($result['vulnerabilities'] as $vuln) {
                $lines[] = "  [{$vuln['severity']}] {$vuln['package']}";
                $lines[] = "    {$vuln['title']}";
                if ($vuln['cve']) {
                    $lines[] = "    CVE: {$vuln['cve']}";
                }
            }
        } else {
            $lines[] = "No known vulnerabilities";
        }

        if (!empty($result['outdated'])) {
            $lines[] = "";
            $lines[] = "Outdated packages: " . count($result['outdated']);
            foreach ($result['outdated'] as $pkg) {
                $lines[] = "  {$pkg['name']}: {$pkg['current']} -> {$pkg['latest']}";
            }
        }

        return $lines;
    }

    private function generateSummaryReport(array $results): string
    {
        $lines = [];
        $sep = str_repeat('=', 70);
        $sepMini = str_repeat('-', 70);

        $lines[] = $sep;
        $lines[] = "EVIDENCY MONITOR - SUMMARY REPORT";
        $lines[] = $sep;
        $lines[] = "";
        $lines[] = "Timestamp:   {$results['timestamp']}";
        $lines[] = "Projects:    " . count($results['projects']);
        $lines[] = "";
        $lines[] = $sepMini;
        $lines[] = sprintf("%-20s | %-10s | %-8s | %-10s | %s",
            "Project", "Files", "Errors", "Warnings", "Changes");
        $lines[] = $sepMini;

        foreach ($results['projects'] as $name => $project) {
            $changes = ($project['has_changes'] ?? false) ? 'YES' : 'NO';
            $lines[] = sprintf("%-20s | %-10d | %-8d | %-10d | %s",
                substr($name, 0, 20),
                $project['files_scanned'],
                $project['errors'],
                $project['warnings'],
                $changes
            );
        }

        $lines[] = $sepMini;
        $lines[] = "";
        $lines[] = "TOTALS:";
        $lines[] = "  Files:    {$results['summary']['total_files']}";
        $lines[] = "  Errors:   {$results['summary']['total_errors']}";
        $lines[] = "  Warnings: {$results['summary']['total_warnings']}";
        $lines[] = "";
        $lines[] = "STATUS: {$results['summary']['status']}";
        $lines[] = "";
        $lines[] = $sep;

        return implode("\n", $lines);
    }
}
