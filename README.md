# EvidencyMonitor

**ISO Compliance Code Validation Tool**

EvidencyMonitor is a PHP-based code validation tool designed for ISO compliance evidence gathering. It performs automated code analysis and generates audit-ready reports.

## Features

- **Syntax Validation** - PHP syntax checking using `php -l`
- **Security Scanning** - Detection of common vulnerabilities (OWASP Top 10)
- **Dependency Audit** - Composer vulnerability checking
- **Git Analysis** - Change tracking and commit history
- **Multiple Report Formats** - Text, JSON, and HTML reports
- **Email Notifications** - Automated alerts on scan completion
- **ISO Evidence** - Reports formatted for audit compliance

## Installation

### Via Composer

```bash
composer require output4you/evidency-monitor
```

### Manual Installation

```bash
git clone https://github.com/output4you/evidency-monitor.git
cd evidency-monitor
composer install
```

## Quick Start

1. **Initialize configuration**
   ```bash
   php bin/evidency init
   ```

2. **Edit `evidency.json`** with your projects

3. **Run scan**
   ```bash
   php bin/evidency scan
   ```

## Configuration

Create an `evidency.json` file:

```json
{
    "output_dir": "./reports",
    "projects": {
        "MyProject": {
            "path": "/path/to/project",
            "exclude": ["vendor", "node_modules"]
        }
    },
    "scanners": {
        "syntax": true,
        "security": true,
        "dependencies": true,
        "git": true
    },
    "reporters": {
        "text": true,
        "json": true,
        "html": false
    },
    "email": {
        "enabled": false,
        "to": "admin@example.com",
        "from": "noreply@example.com"
    }
}
```

## CLI Usage

```bash
# Run scan with default config
php bin/evidency scan

# Use custom config file
php bin/evidency scan --config=my-config.json

# Send email notification
php bin/evidency scan --email

# Generate HTML report
php bin/evidency scan --html

# Show version
php bin/evidency version
```

## Scanners

### Syntax Scanner
Validates PHP syntax using `php -l`. Reports:
- Parse errors
- Syntax errors with line numbers

### Security Scanner
Checks for common security vulnerabilities:

| Check | CWE | Severity |
|-------|-----|----------|
| eval() usage | CWE-95 | Critical |
| Command injection (exec, shell_exec) | CWE-78 | High |
| SQL injection patterns | CWE-89 | High |
| XSS (unescaped output) | CWE-79 | High |
| File inclusion (LFI/RFI) | CWE-98 | Critical |
| Unsafe deserialization | CWE-502 | Critical |
| Hardcoded credentials | CWE-798 | Medium |
| Weak cryptography | CWE-328 | High |
| SSRF patterns | CWE-918 | High |

### Dependency Scanner
Uses `composer audit` to check for:
- Known vulnerabilities in packages
- Outdated dependencies (major/minor versions)

### Git Scanner
Analyzes git repository:
- Current branch and last commit
- Recent commits (configurable days)
- Uncommitted changes
- Contributors list
- Repository statistics

## Reports

### Text Report
Human-readable format suitable for auditors:
```
======================================================================
CODE VALIDATION REPORT - MyProject
======================================================================

Timestamp:      2024-01-15 10:30:00
Project:        MyProject
Files scanned:  150

----------------------------------------------------------------------
SYNTAX SCANNER
----------------------------------------------------------------------
Status: OK - No syntax errors found
```

### JSON Report
Machine-readable format for integration:
```json
{
    "timestamp": "2024-01-15 10:30:00",
    "projects": { ... },
    "summary": {
        "total_files": 150,
        "total_errors": 0,
        "total_warnings": 5,
        "status": "WARNINGS"
    }
}
```

### HTML Report
Visual dashboard with:
- Color-coded status badges
- Summary statistics cards
- Collapsible project sections
- Severity-based issue highlighting

## Scheduling

### Windows Task Scheduler

```batch
@echo off
cd /d D:\wwwroot\EvidencyMonitor
php bin\evidency scan --email
```

Schedule: Weekly on Sunday at 20:00

### Linux Cron

```bash
# Run every Sunday at 20:00
0 20 * * 0 cd /var/www/evidency-monitor && php bin/evidency scan --email
```

## Programmatic Usage

```php
use EvidencyMonitor\EvidencyMonitor;
use EvidencyMonitor\Notifiers\EmailNotifier;

$config = [
    'output_dir' => '/path/to/reports',
    'scanners' => ['syntax' => true, 'security' => true],
];

$monitor = new EvidencyMonitor($config);
$monitor->addProject('MyApp', '/path/to/myapp');
$monitor->addNotifier(new EmailNotifier('admin@example.com'));

$results = $monitor->run();
```

## ISO Compliance

EvidencyMonitor is designed for ISO 27001 compliance:

- **A.12.6.1** - Technical vulnerability management
- **A.14.2.1** - Secure development policy
- **A.14.2.5** - Secure system engineering principles

Reports are formatted for audit evidence and include:
- Timestamps for all scans
- File-level issue tracking
- Severity classifications (Critical/High/Medium/Low)
- CWE references for security issues

## Requirements

- PHP 8.1 or higher
- ext-json
- ext-pdo (for future database logging)
- Composer (for dependency scanning)
- Git (for repository analysis)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

**Output4you**
- Website: https://output4you.nl
- Email: info@output4you.nl
- GitHub: https://github.com/output4you

---

*EvidencyMonitor v1.0.0*
