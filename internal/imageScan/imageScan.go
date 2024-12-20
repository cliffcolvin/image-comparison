package imageScan

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/cliffcolvin/helmscan/internal/reports"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.SugaredLogger

func init() {
	// Create a custom encoder config
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	// Create a custom core that writes to console
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.AddSync(os.Stdout),
		zap.InfoLevel,
	)

	// Create a logger with the custom core
	zapLogger := zap.New(core)
	defer zapLogger.Sync()

	// Create a sugared logger
	logger = zapLogger.Sugar()
}

type GitHubRelease struct {
	TagName string `json:"tag_name"`
}

type ScanResult struct {
	Image           string
	Vulnerabilities SeverityCounts
	VulnsByLevel    map[string][]string
	VulnList        []Vulnerability
}

type ImageComparisonReport struct {
	Image1        ScanResult
	Image2        ScanResult
	RemovedCVEs   map[string][]Vulnerability
	AddedCVEs     map[string][]Vulnerability
	UnchangedCVEs map[string][]Vulnerability
}

type Vulnerability struct {
	ID       string
	Severity string
}

type SeverityCounts struct {
	Low      int
	Medium   int
	High     int
	Critical int
}

func ScanImage(imageName string) (ScanResult, error) {
	if strings.Contains(imageName, "alpine") {
		return ScanResult{}, nil
	}

	// Create a safe filename from the image name
	safeFileName := reports.CreateSafeFileName(imageName)
	outputFile := fmt.Sprintf("working-files/%s_trivy_output.json", safeFileName)

	cmd := exec.Command("trivy", "image",
		"-f", "json",
		"-o", outputFile,
		"--severity", "HIGH,MEDIUM,LOW,CRITICAL",
		"--pkg-types", "os,library",
		"--scanners", "vuln,secret,misconfig",
		imageName)

	combinedOutput, err := cmd.CombinedOutput()
	if err != nil {
		return ScanResult{}, fmt.Errorf("error running command: %w\nOutput: %s", err, string(combinedOutput))
	}

	jsonData, err := os.ReadFile(outputFile)
	if err != nil {
		return ScanResult{}, fmt.Errorf("error reading %s: %w", outputFile, err)
	}

	vulns := extractVulnerabilities(string(jsonData))

	result := ScanResult{
		Image:           imageName,
		Vulnerabilities: countVulnerabilities(vulns),
		VulnsByLevel:    groupVulnerabilitiesByLevel(vulns),
		VulnList:        vulns,
	}

	return result, nil
}

func countVulnerabilities(vulns []Vulnerability) SeverityCounts {
	counts := SeverityCounts{}
	for _, vuln := range vulns {
		incrementSeverityCount(&counts, vuln.Severity)
	}
	return counts
}

func groupVulnerabilitiesByLevel(vulns []Vulnerability) map[string][]string {
	grouped := make(map[string][]string)
	for _, vuln := range vulns {
		grouped[vuln.Severity] = append(grouped[vuln.Severity], vuln.ID)
	}
	return grouped
}

func CompareScans(firstScan, secondScan ScanResult) *ImageComparisonReport {
	comparison := &ImageComparisonReport{
		Image1:        firstScan,
		Image2:        secondScan,
		RemovedCVEs:   make(map[string][]Vulnerability),
		AddedCVEs:     make(map[string][]Vulnerability),
		UnchangedCVEs: make(map[string][]Vulnerability),
	}

	// Create maps for easier lookup
	firstVulns := make(map[string]Vulnerability)
	for _, vuln := range firstScan.VulnList {
		firstVulns[vuln.ID] = vuln
	}

	secondVulns := make(map[string]Vulnerability)
	for _, vuln := range secondScan.VulnList {
		secondVulns[vuln.ID] = vuln
	}

	// Find removed and unchanged vulnerabilities
	for id, vuln := range firstVulns {
		if _, exists := secondVulns[id]; exists {
			comparison.UnchangedCVEs[vuln.Severity] = append(comparison.UnchangedCVEs[vuln.Severity], vuln)
		} else {
			comparison.RemovedCVEs[vuln.Severity] = append(comparison.RemovedCVEs[vuln.Severity], vuln)
		}
	}

	// Find added vulnerabilities
	for id, vuln := range secondVulns {
		if _, exists := firstVulns[id]; !exists {
			comparison.AddedCVEs[vuln.Severity] = append(comparison.AddedCVEs[vuln.Severity], vuln)
		}
	}

	return comparison
}

func extractVulnerabilities(scan string) []Vulnerability {
	var result struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
				Severity        string `json:"Severity"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	err := json.Unmarshal([]byte(scan), &result)
	if err != nil {
		fmt.Printf("Error parsing JSON: %v\n", err)
		return nil
	}

	var vulns []Vulnerability
	for _, res := range result.Results {
		for _, vuln := range res.Vulnerabilities {
			vulns = append(vulns, Vulnerability{
				ID:       vuln.VulnerabilityID,
				Severity: strings.ToLower(vuln.Severity),
			})
		}
	}

	return vulns
}

func incrementSeverityCount(counts *SeverityCounts, severity string) {
	switch severity {
	case "low":
		counts.Low++
	case "medium":
		counts.Medium++
	case "high":
		counts.High++
	case "critical":
		counts.Critical++
	}
}

func difference(a, b []string) []string {
	bMap := make(map[string]bool)
	for _, v := range b {
		bMap[v] = true
	}

	var diff []string
	for _, v := range a {
		if !bMap[v] {
			diff = append(diff, v)
		}
	}
	return diff
}

func CheckTrivyInstallation() error {
	// Check if Trivy is installed
	_, err := exec.LookPath("trivy")
	if err != nil {
		return fmt.Errorf("Trivy is not installed. Please install Trivy and ensure it's in your PATH")
	}

	// Check Trivy version
	cmd := exec.Command("trivy", "--version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("Failed to get Trivy version: %v", err)
	}

	version := strings.TrimSpace(strings.TrimPrefix(string(output), "Version: "))
	fmt.Printf("Trivy version %s is installed.\n", version)

	return nil
}

func calculateDifference(before, after map[string][]string) map[string][]Vulnerability {
	diff := make(map[string][]Vulnerability)

	for severity, vulns := range before {
		for _, vuln := range vulns {
			if !contains(after[severity], vuln) {
				diff[severity] = append(diff[severity], Vulnerability{
					ID:       vuln,
					Severity: severity,
				})
			}
		}
	}

	return diff
}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func GenerateReport(comparison *ImageComparisonReport, generateJSON bool, generateMD bool) string {
	var lastReport string

	// Create base filename once
	baseFilename := reports.CreateSafeFileName(
		fmt.Sprintf("%s_to_%s_image_comparison",
			comparison.Image1.Image,
			comparison.Image2.Image))

	// Generate markdown report if requested
	if generateMD {
		mdReport := generateMarkdownReport(comparison)
		lastReport = mdReport

		if err := reports.SaveToFile(mdReport, baseFilename+".md"); err != nil {
			fmt.Printf("Error saving markdown report: %v\n", err)
		}
	}

	// Generate JSON report if requested
	if generateJSON {
		jsonReport := generateJSONReport(comparison)
		lastReport = jsonReport

		if err := reports.SaveToFile(jsonReport, baseFilename+".json"); err != nil {
			fmt.Printf("Error saving JSON report: %v\n", err)
		}
	}

	return lastReport
}

func generateJSONReport(comparison *ImageComparisonReport) string {
	// Convert the map[string][]Vulnerability to map[string]map[string]interface{}
	addedCVEs := convertVulnMapToInterface(comparison.AddedCVEs)
	removedCVEs := convertVulnMapToInterface(comparison.RemovedCVEs)
	unchangedCVEs := convertVulnMapToInterface(comparison.UnchangedCVEs)

	report := reports.JSONReport{
		ReportType: "image_comparison",
		Comparison: map[string]string{
			"image1": comparison.Image1.Image,
			"image2": comparison.Image2.Image,
		},
		Summary: reports.Summary{
			SeverityCounts: generateJSONSeverityCounts(comparison),
		},
		AddedCVEs:     reports.ConvertToJSONCVEs(addedCVEs),
		RemovedCVEs:   reports.ConvertToJSONCVEs(removedCVEs),
		UnchangedCVEs: reports.ConvertToJSONCVEs(unchangedCVEs),
	}

	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error generating JSON report: %v", err)
	}
	return string(jsonBytes)
}

func generateJSONSeverityCounts(comparison *ImageComparisonReport) []reports.SeverityCount {
	severities := []string{"critical", "high", "medium", "low"}
	counts := make([]reports.SeverityCount, 0, len(severities))

	prevCounts := make(map[string]int)
	currentCounts := make(map[string]int)

	for _, vuln := range comparison.Image1.VulnList {
		prevCounts[vuln.Severity]++
	}
	for _, vuln := range comparison.Image2.VulnList {
		currentCounts[vuln.Severity]++
	}

	for _, severity := range severities {
		current := currentCounts[severity]
		previous := prevCounts[severity]
		counts = append(counts, reports.SeverityCount{
			Severity:   severity,
			Current:    current,
			Previous:   previous,
			Difference: current - previous,
		})
	}

	return counts
}

func generateMarkdownReport(comparison *ImageComparisonReport) string {
	var sb strings.Builder

	sb.WriteString("## Image Comparison Report\n")
	sb.WriteString(fmt.Sprintf("### Comparing images: %s and %s\n\n",
		comparison.Image1.Image, comparison.Image2.Image))

	// CVE by Severity section
	headers := []string{"Severity", "Count", "Prev Count", "Difference"}
	rows := generateSeverityRows(comparison) // helper function to generate rows
	sb.WriteString(reports.FormatSection("CVE by Severity",
		reports.FormatMarkdownTable(headers, rows)))

	// Unchanged CVEs section
	sb.WriteString("### Unchanged CVEs\n\n")
	if len(comparison.UnchangedCVEs) == 0 {
		sb.WriteString("No unchanged vulnerabilities found.\n\n")
	} else {
		sb.WriteString(formatVulnerabilitySection(comparison.UnchangedCVEs))
	}

	// Added CVEs section
	sb.WriteString("### Added CVEs\n\n")
	if len(comparison.AddedCVEs) == 0 {
		sb.WriteString("No new vulnerabilities found.\n\n")
	} else {
		sb.WriteString(formatVulnerabilitySection(comparison.AddedCVEs))
	}

	// Removed CVEs section
	sb.WriteString("### Removed CVEs\n\n")
	if len(comparison.RemovedCVEs) == 0 {
		sb.WriteString("No removed vulnerabilities found.\n\n")
	} else {
		sb.WriteString(formatVulnerabilitySection(comparison.RemovedCVEs))
	}

	return sb.String()
}

func formatVulnerabilitySection(vulns map[string][]Vulnerability) string {
	var sb strings.Builder

	if len(vulns) == 0 {
		return "No vulnerabilities found.\n\n"
	}

	// Sort severities
	severities := make([]string, 0, len(vulns))
	for severity := range vulns {
		severities = append(severities, severity)
	}
	sort.Slice(severities, func(i, j int) bool {
		return reports.SeverityValue(severities[i]) > reports.SeverityValue(severities[j])
	})

	for _, severity := range severities {
		if len(vulns[severity]) > 0 {
			sb.WriteString(fmt.Sprintf("#### %s\n", strings.Title(severity)))
			sb.WriteString("| CVE ID | Severity |\n")
			sb.WriteString("|---------|----------|\n")

			// Sort vulnerabilities by ID
			sort.Slice(vulns[severity], func(i, j int) bool {
				return vulns[severity][i].ID < vulns[severity][j].ID
			})

			for _, vuln := range vulns[severity] {
				sb.WriteString(fmt.Sprintf("| %s | %s |\n", vuln.ID, vuln.Severity))
			}
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

func generateSeverityRows(comparison *ImageComparisonReport) [][]string {
	severities := []string{"critical", "high", "medium", "low"}
	var rows [][]string

	// Count current and previous vulnerabilities by severity
	prevCounts := make(map[string]int)
	currentCounts := make(map[string]int)

	// Count previous vulnerabilities
	for _, vuln := range comparison.Image1.VulnList {
		prevCounts[vuln.Severity]++
	}

	// Count current vulnerabilities
	for _, vuln := range comparison.Image2.VulnList {
		currentCounts[vuln.Severity]++
	}

	// Generate table rows
	for _, severity := range severities {
		count := currentCounts[severity]
		prevCount := prevCounts[severity]
		difference := count - prevCount
		differenceStr := fmt.Sprintf("%+d", difference) // Use %+d to always show the sign

		rows = append(rows, []string{
			severity,
			fmt.Sprintf("%d", count),
			fmt.Sprintf("%d", prevCount),
			differenceStr,
		})
	}

	return rows
}

// Add GetSeverity method to Vulnerability type to satisfy the interface
func (v Vulnerability) GetSeverity() string {
	return v.Severity
}

// Add GetID method to satisfy the reports.Vulnerability interface
func (v Vulnerability) GetID() string {
	return v.ID
}

// Update convertVulnMapToInterface to convert []Vulnerability to map[string]Vulnerability
func convertVulnMapToInterface(vulns map[string][]Vulnerability) map[string]map[string]reports.Vulnerability {
	result := make(map[string]map[string]reports.Vulnerability)

	for severity, vulnList := range vulns {
		if _, exists := result[severity]; !exists {
			result[severity] = make(map[string]reports.Vulnerability)
		}
		for _, vuln := range vulnList {
			result[vuln.ID] = map[string]reports.Vulnerability{
				"vulnerability": vuln,
			}
		}
	}

	return result
}

func ScanSingleImage(imageURL string, saveReport bool, jsonOutput bool) {
	logger.Infof("Scanning image: %s", imageURL)
	result, err := ScanImage(imageURL)
	if err != nil {
		logger.Errorf("Error scanning image: %v", err)
		return
	}

	// Convert vulnerabilities to map
	vulns := make(map[string]reports.Vulnerability)
	for _, v := range result.VulnList {
		vulns[v.ID] = v
	}

	// Generate report using the centralized report generator
	report := reports.GenerateSingleScanReport("image", imageURL, vulns, jsonOutput)

	// Save report if requested
	if saveReport {
		ext := ".md"
		if jsonOutput {
			ext = ".json"
		}
		filename := fmt.Sprintf("image_scan_%s%s", reports.CreateSafeFileName(imageURL), ext)
		if err := reports.SaveToFile(report, filename); err != nil {
			logger.Errorf("Error saving report: %v", err)
		}
	}

	// Print to console
	fmt.Println(report)
}
