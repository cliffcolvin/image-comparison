package reports

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	helmscanTypes "github.com/cliffcolvin/helmscan/internal/helmScanTypes"
)

func GenerateReport(generator ReportGenerator, generateJSON bool, generateMD bool) string {
	var lastReport string
	baseFilename := CreateSafeFileName(generator.GetBaseFilename())

	if generateMD {
		lastReport = generateMarkdownReport(generator)
		if err := SaveToFile(lastReport, baseFilename+".md"); err != nil {
			fmt.Printf("Error saving markdown report: %v\n", err)
		}
	}

	if generateJSON {
		lastReport = generateJSONReport(generator)
		if err := SaveToFile(lastReport, baseFilename+".json"); err != nil {
			fmt.Printf("Error saving JSON report: %v\n", err)
		}
	}

	return lastReport
}

func generateMarkdownReport(generator ReportGenerator) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("## %s\n", generator.GetTitle()))

	comparison := generator.GetComparison()
	if len(comparison) > 0 {
		for key, value := range comparison {
			sb.WriteString(fmt.Sprintf("### %s: %s\n", key, value))
		}
		sb.WriteString("\n")
	}

	// Severity counts
	headers := []string{"Severity", "Count", "Prev Count", "Difference"}
	rows := formatSeverityRows(generator.GetSeverityCounts())
	sb.WriteString(FormatSection("CVE by Severity",
		FormatMarkdownTable(headers, rows)))

	// CVEs sections
	sb.WriteString("### Unchanged CVEs\n\n")
	if unchangedCVEs := generator.GetUnchangedCVEs(); len(unchangedCVEs) == 0 {
		sb.WriteString("No unchanged vulnerabilities found.\n\n")
	} else {
		sb.WriteString(formatVulnerabilitySection(unchangedCVEs))
	}

	sb.WriteString("### Added CVEs\n\n")
	if addedCVEs := generator.GetAddedCVEs(); len(addedCVEs) == 0 {
		sb.WriteString("No new vulnerabilities found.\n\n")
	} else {
		sb.WriteString(formatVulnerabilitySection(addedCVEs))
	}

	sb.WriteString("### Removed CVEs\n\n")
	if removedCVEs := generator.GetRemovedCVEs(); len(removedCVEs) == 0 {
		sb.WriteString("No removed vulnerabilities found.\n\n")
	} else {
		sb.WriteString(formatVulnerabilitySection(removedCVEs))
	}

	return sb.String()
}

func generateJSONReport(generator ReportGenerator) string {
	report := JSONReport{
		ReportType: generator.GetTitle(),
		Comparison: generator.GetComparison(),
		Summary: Summary{
			SeverityCounts: generator.GetSeverityCounts(),
		},
		AddedCVEs:     ConvertToJSONCVEs(generator.GetAddedCVEs()),
		RemovedCVEs:   ConvertToJSONCVEs(generator.GetRemovedCVEs()),
		UnchangedCVEs: ConvertToJSONCVEs(generator.GetUnchangedCVEs()),
	}

	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error generating JSON report: %v", err)
	}
	return string(jsonBytes)
}

func formatSeverityRows(counts []SeverityCount) [][]string {
	var rows [][]string
	for _, count := range counts {
		rows = append(rows, []string{
			count.Severity,
			fmt.Sprintf("%d", count.Current),
			fmt.Sprintf("%d", count.Previous),
			fmt.Sprintf("%+d", count.Difference),
		})
	}
	return rows
}

func formatVulnerabilitySection(cves map[string]map[string]helmscanTypes.Vulnerability) string {
	if len(cves) == 0 {
		return "No CVEs found.\n\n"
	}

	var sortedCVEs SortableCVEList
	for cveID, imageVulns := range cves {
		var images []string
		var severity string
		for imageName, vuln := range imageVulns {
			images = append(images, imageName)
			severity = vuln.GetSeverity()
		}
		sortedCVEs = append(sortedCVEs, SortableCVE{
			ID:       cveID,
			Severity: severity,
			Images:   images,
		})
	}

	sort.Sort(sortedCVEs)

	var sb strings.Builder
	currentSeverity := ""
	for _, cve := range sortedCVEs {
		if cve.Severity != currentSeverity {
			if currentSeverity != "" {
				sb.WriteString("\n")
			}
			sb.WriteString(fmt.Sprintf("#### %s\n", strings.Title(cve.Severity)))
			sb.WriteString("| CVE ID | Severity | Affected Images |\n")
			sb.WriteString("|--------|----------|------------------|\n")
			currentSeverity = cve.Severity
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", cve.ID, cve.Severity, strings.Join(cve.Images, ", ")))
	}
	return sb.String()
}
