<?php

declare(strict_types=1);

namespace EvidencyMonitor\Scanners;

/**
 * Security Scanner
 *
 * Checks for common security vulnerabilities in PHP code
 */
class SecurityScanner implements ScannerInterface
{
    private array $config;

    private array $patterns = [
        // Code execution
        'eval' => [
            'pattern' => '/\beval\s*\(/i',
            'severity' => 'critical',
            'message' => 'eval() can execute arbitrary code - avoid if possible',
            'cwe' => 'CWE-95',
        ],
        'exec' => [
            'pattern' => '/\bexec\s*\(/i',
            'severity' => 'high',
            'message' => 'exec() - ensure input is properly sanitized',
            'cwe' => 'CWE-78',
        ],
        'shell_exec' => [
            'pattern' => '/\bshell_exec\s*\(/i',
            'severity' => 'high',
            'message' => 'shell_exec() - ensure input is properly sanitized',
            'cwe' => 'CWE-78',
        ],
        'system' => [
            'pattern' => '/\bsystem\s*\(/i',
            'severity' => 'high',
            'message' => 'system() - ensure input is properly sanitized',
            'cwe' => 'CWE-78',
        ],
        'passthru' => [
            'pattern' => '/\bpassthru\s*\(/i',
            'severity' => 'high',
            'message' => 'passthru() - ensure input is properly sanitized',
            'cwe' => 'CWE-78',
        ],
        'proc_open' => [
            'pattern' => '/\bproc_open\s*\(/i',
            'severity' => 'high',
            'message' => 'proc_open() - ensure input is properly sanitized',
            'cwe' => 'CWE-78',
        ],
        'backticks' => [
            'pattern' => '/`[^`]+`/',
            'severity' => 'high',
            'message' => 'Backtick operator executes shell commands',
            'cwe' => 'CWE-78',
        ],

        // SQL Injection
        'sql_concat' => [
            'pattern' => '/\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\./',
            'severity' => 'high',
            'message' => 'Possible SQL injection - user input concatenated',
            'cwe' => 'CWE-89',
        ],
        'mysql_query' => [
            'pattern' => '/\bmysql_query\s*\(/i',
            'severity' => 'medium',
            'message' => 'Deprecated mysql_* function - use PDO with prepared statements',
            'cwe' => 'CWE-89',
        ],
        'mysqli_query_concat' => [
            'pattern' => '/mysqli_query\s*\([^,]+,\s*["\'][^"\']*\$/',
            'severity' => 'high',
            'message' => 'Possible SQL injection in mysqli_query',
            'cwe' => 'CWE-89',
        ],

        // XSS
        'echo_get' => [
            'pattern' => '/echo\s+\$_(GET|POST|REQUEST)\s*\[/',
            'severity' => 'high',
            'message' => 'Possible XSS - echoing user input without sanitization',
            'cwe' => 'CWE-79',
        ],
        'print_get' => [
            'pattern' => '/print\s+\$_(GET|POST|REQUEST)\s*\[/',
            'severity' => 'high',
            'message' => 'Possible XSS - printing user input without sanitization',
            'cwe' => 'CWE-79',
        ],

        // File inclusion
        'include_var' => [
            'pattern' => '/\b(include|require|include_once|require_once)\s*\(\s*\$/',
            'severity' => 'critical',
            'message' => 'Possible LFI/RFI - dynamic file inclusion',
            'cwe' => 'CWE-98',
        ],

        // Deserialization
        'unserialize' => [
            'pattern' => '/\bunserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/',
            'severity' => 'critical',
            'message' => 'Unsafe deserialization of user input',
            'cwe' => 'CWE-502',
        ],

        // Hardcoded credentials
        'hardcoded_password' => [
            'pattern' => '/(\$password|\$pass|\$pwd)\s*=\s*["\'][^"\']{3,}["\']/',
            'severity' => 'medium',
            'message' => 'Possible hardcoded password',
            'cwe' => 'CWE-798',
        ],
        'hardcoded_api_key' => [
            'pattern' => '/api[_-]?key\s*[=:]\s*["\'][a-zA-Z0-9]{20,}["\']/',
            'severity' => 'high',
            'message' => 'Possible hardcoded API key',
            'cwe' => 'CWE-798',
        ],

        // Information disclosure
        'phpinfo' => [
            'pattern' => '/\bphpinfo\s*\(\s*\)/',
            'severity' => 'medium',
            'message' => 'phpinfo() exposes sensitive server information',
            'cwe' => 'CWE-200',
        ],
        'var_dump_get' => [
            'pattern' => '/var_dump\s*\(\s*\$_(GET|POST|REQUEST|SERVER)/',
            'severity' => 'low',
            'message' => 'var_dump of superglobal - may expose sensitive data',
            'cwe' => 'CWE-200',
        ],

        // Weak crypto
        'md5_password' => [
            'pattern' => '/md5\s*\(\s*\$.*pass/i',
            'severity' => 'high',
            'message' => 'MD5 is weak for password hashing - use password_hash()',
            'cwe' => 'CWE-328',
        ],
        'sha1_password' => [
            'pattern' => '/sha1\s*\(\s*\$.*pass/i',
            'severity' => 'high',
            'message' => 'SHA1 is weak for password hashing - use password_hash()',
            'cwe' => 'CWE-328',
        ],

        // File upload
        'move_uploaded' => [
            'pattern' => '/move_uploaded_file\s*\([^,]+,\s*\$_(GET|POST|REQUEST)/',
            'severity' => 'critical',
            'message' => 'Unsafe file upload - user controls destination',
            'cwe' => 'CWE-434',
        ],

        // SSRF
        'curl_user_input' => [
            'pattern' => '/curl_setopt\s*\([^,]+,\s*CURLOPT_URL\s*,\s*\$_(GET|POST|REQUEST)/',
            'severity' => 'high',
            'message' => 'Possible SSRF - user controls URL',
            'cwe' => 'CWE-918',
        ],
        'file_get_user' => [
            'pattern' => '/file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)/',
            'severity' => 'high',
            'message' => 'Possible SSRF - user controls file/URL',
            'cwe' => 'CWE-918',
        ],
    ];

    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    public function getName(): string
    {
        return 'security';
    }

    public function scan(string $path, array $files): array
    {
        $result = [
            'name' => $this->getName(),
            'files_checked' => 0,
            'errors' => 0,
            'warnings' => 0,
            'issues' => [],
            'summary' => [
                'critical' => 0,
                'high' => 0,
                'medium' => 0,
                'low' => 0,
            ],
        ];

        foreach ($files as $file) {
            if (pathinfo($file, PATHINFO_EXTENSION) !== 'php') {
                continue;
            }

            $result['files_checked']++;
            $issues = $this->checkFile($file, $path);

            foreach ($issues as $issue) {
                $result['issues'][] = $issue;
                $result['summary'][$issue['severity']]++;

                if (in_array($issue['severity'], ['critical', 'high'])) {
                    $result['warnings']++;
                }
            }
        }

        return $result;
    }

    private function checkFile(string $file, string $basePath): array
    {
        $issues = [];
        $content = file_get_contents($file);
        $lines = explode("\n", $content);
        $relativePath = str_replace($basePath . DIRECTORY_SEPARATOR, '', $file);

        foreach ($this->patterns as $name => $check) {
            if (preg_match_all($check['pattern'], $content, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $lineNumber = substr_count(substr($content, 0, $match[1]), "\n") + 1;

                    $issues[] = [
                        'file' => $relativePath,
                        'line' => $lineNumber,
                        'type' => $name,
                        'severity' => $check['severity'],
                        'message' => $check['message'],
                        'cwe' => $check['cwe'] ?? null,
                        'code' => trim($lines[$lineNumber - 1] ?? ''),
                    ];
                }
            }
        }

        return $issues;
    }

    public function addPattern(string $name, array $pattern): self
    {
        $this->patterns[$name] = $pattern;
        return $this;
    }
}
