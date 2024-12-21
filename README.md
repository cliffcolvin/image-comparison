# helmscan
Container Image and Helm Chart CVE comparison tool

This tool allows you to scan and compare Container images or Helm charts and analyze their CVE (Common Vulnerabilities and Exposures) reports.
When comparing Helm charts, the tool will download the charts and scan every container image in the chart.

## Usage

The tool supports two main operations:
1. Single artifact scanning
2. Artifact comparison

### Single Artifact Scanning

```bash
helmscan [--json] [--report] <artifact>
```

Examples:
```bash
# Scan a Docker image
helmscan --json --report docker.io/library/ubuntu:22.04

# Scan a Helm chart
helmscan --report myrepo/mychart@1.0.0
```

### Artifact Comparison

```bash
helmscan --compare [--json] [--report] <artifact1> <artifact2>
```

Examples:
```bash
# Compare Docker images
helmscan --compare --json --report docker.io/library/ubuntu:20.04 docker.io/library/ubuntu:22.04

# Compare Helm charts
helmscan --compare --report myrepo/mychart@1.0.0 myrepo/mychart@2.0.0
```

### Flags
- `--compare`: Enable comparison mode
- `--report`: Generate a report file (optional)
- `--json`: Output in JSON format (optional, defaults to markdown)

### Output

Reports are automatically saved in the `working-files` directory when using `--report`:
```
working-files/
  scans/
    {scan-name}/
      scan_report.{md,json}
  tmp/
    trivy_output/
      {image}_trivy_output.json
```

## Requirements
- Trivy must be installed and accessible in your PATH
- For Helm charts, use the format `repo/chart@version`
