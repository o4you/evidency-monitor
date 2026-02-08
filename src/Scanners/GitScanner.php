<?php

declare(strict_types=1);

namespace EvidencyMonitor\Scanners;

/**
 * Git Scanner
 *
 * Analyzes git repository for changes, commits, and contributors
 */
class GitScanner implements ScannerInterface
{
    private array $config;

    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    public function getName(): string
    {
        return 'git';
    }

    public function scan(string $path, array $files): array
    {
        $result = [
            'name' => $this->getName(),
            'errors' => 0,
            'warnings' => 0,
            'is_git_repo' => false,
            'has_changes' => false,
            'current_branch' => null,
            'last_commit' => null,
            'recent_commits' => [],
            'uncommitted_changes' => [],
            'contributors' => [],
        ];

        if (!$this->isGitRepo($path)) {
            $result['warnings'] = 1;
            $result['message'] = 'Not a git repository';
            return $result;
        }

        $result['is_git_repo'] = true;

        $cwd = getcwd();
        chdir($path);

        try {
            // Current branch
            $result['current_branch'] = trim(shell_exec('git rev-parse --abbrev-ref HEAD 2>&1') ?? '');

            // Last commit
            $result['last_commit'] = $this->getLastCommit();

            // Recent commits (last 7 days)
            $result['recent_commits'] = $this->getRecentCommits(7);
            $result['has_changes'] = !empty($result['recent_commits']);

            // Uncommitted changes
            $result['uncommitted_changes'] = $this->getUncommittedChanges();
            if (!empty($result['uncommitted_changes'])) {
                $result['has_changes'] = true;
                $result['warnings'] = count($result['uncommitted_changes']);
            }

            // Contributors
            $result['contributors'] = $this->getContributors();

            // Statistics
            $result['stats'] = $this->getStats();

        } finally {
            chdir($cwd);
        }

        return $result;
    }

    private function isGitRepo(string $path): bool
    {
        return is_dir($path . DIRECTORY_SEPARATOR . '.git');
    }

    private function getLastCommit(): array
    {
        $format = '%H|%h|%an|%ae|%ai|%s';
        $output = trim(shell_exec("git log -1 --format=\"$format\" 2>&1") ?? '');

        if (empty($output) || strpos($output, 'fatal:') !== false) {
            return [];
        }

        $parts = explode('|', $output);
        return [
            'hash' => $parts[0] ?? '',
            'short_hash' => $parts[1] ?? '',
            'author' => $parts[2] ?? '',
            'email' => $parts[3] ?? '',
            'date' => $parts[4] ?? '',
            'message' => $parts[5] ?? '',
        ];
    }

    private function getRecentCommits(int $days = 7): array
    {
        $output = shell_exec("git log --oneline --since=\"$days days ago\" 2>&1") ?? '';

        if (strpos($output, 'fatal:') !== false) {
            return [];
        }

        $lines = array_filter(explode("\n", trim($output)));
        $commits = [];

        foreach ($lines as $line) {
            $parts = explode(' ', $line, 2);
            $commits[] = [
                'hash' => $parts[0] ?? '',
                'message' => $parts[1] ?? '',
            ];
        }

        return $commits;
    }

    private function getUncommittedChanges(): array
    {
        $output = trim(shell_exec('git status --porcelain 2>&1') ?? '');

        if (empty($output) || strpos($output, 'fatal:') !== false) {
            return [];
        }

        $lines = array_filter(explode("\n", $output));
        $changes = [];

        foreach ($lines as $line) {
            $status = substr($line, 0, 2);
            $file = trim(substr($line, 3));

            $changes[] = [
                'status' => trim($status),
                'file' => $file,
                'type' => $this->getStatusType($status),
            ];
        }

        return $changes;
    }

    private function getStatusType(string $status): string
    {
        $status = trim($status);

        return match ($status[0] ?? '') {
            'M' => 'modified',
            'A' => 'added',
            'D' => 'deleted',
            'R' => 'renamed',
            'C' => 'copied',
            '?' => 'untracked',
            '!' => 'ignored',
            default => 'unknown',
        };
    }

    private function getContributors(): array
    {
        $output = shell_exec('git shortlog -sne --all 2>&1') ?? '';

        if (strpos($output, 'fatal:') !== false) {
            return [];
        }

        $lines = array_filter(explode("\n", trim($output)));
        $contributors = [];

        foreach ($lines as $line) {
            if (preg_match('/^\s*(\d+)\s+(.+?)\s+<(.+?)>$/', $line, $matches)) {
                $contributors[] = [
                    'commits' => (int) $matches[1],
                    'name' => $matches[2],
                    'email' => $matches[3],
                ];
            }
        }

        return $contributors;
    }

    private function getStats(): array
    {
        $totalCommits = (int) trim(shell_exec('git rev-list --count HEAD 2>&1') ?? '0');

        $firstCommit = trim(shell_exec('git log --reverse --format="%ai" | head -1 2>&1') ?? '');
        $lastCommit = trim(shell_exec('git log -1 --format="%ai" 2>&1') ?? '');

        return [
            'total_commits' => $totalCommits,
            'first_commit_date' => $firstCommit,
            'last_commit_date' => $lastCommit,
        ];
    }
}
