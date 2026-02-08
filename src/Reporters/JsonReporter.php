<?php

declare(strict_types=1);

namespace EvidencyMonitor\Reporters;

/**
 * JSON Reporter
 *
 * Generates machine-readable JSON reports
 */
class JsonReporter implements ReporterInterface
{
    private array $config;

    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    public function getName(): string
    {
        return 'json';
    }

    public function generate(array $results): array
    {
        $files = [];
        $date = date('Y-m-d');
        $outputDir = $this->config['output_dir'] ?? getcwd() . '/reports';

        // Generate full JSON report
        $filename = "{$date}-full-report.json";
        $filepath = $outputDir . DIRECTORY_SEPARATOR . $filename;

        $json = json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        file_put_contents($filepath, $json);
        $files[] = $filepath;

        // Generate per-project JSON reports
        foreach ($results['projects'] ?? [] as $name => $project) {
            $safeName = preg_replace('/[^a-zA-Z0-9_-]/', '_', $name);
            $projectFilename = "{$date}-{$safeName}.json";
            $projectFilepath = $outputDir . DIRECTORY_SEPARATOR . $projectFilename;

            $projectJson = json_encode($project, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
            file_put_contents($projectFilepath, $projectJson);
            $files[] = $projectFilepath;
        }

        return $files;
    }
}
