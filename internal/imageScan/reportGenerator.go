package imageScan

import (
	"fmt"

	helmscanTypes "github.com/cliffcolvin/helmscan/internal/helmScanTypes"
	"github.com/cliffcolvin/helmscan/internal/reports"
)

type ImageReportGenerator struct {
	comparison *helmscanTypes.ImageComparisonReport
}

func NewImageReportGenerator(comparison *helmscanTypes.ImageComparisonReport) *ImageReportGenerator {
	return &ImageReportGenerator{comparison: comparison}
}

func (g *ImageReportGenerator) GetTitle() string {
	return "Image Comparison Report"
}

func (g *ImageReportGenerator) GetComparison() map[string]string {
	return map[string]string{
		"Comparing images": fmt.Sprintf("%s and %s", g.comparison.Image1.Image, g.comparison.Image2.Image),
	}
}

func (g *ImageReportGenerator) GetSeverityCounts() []reports.SeverityCount {
	severities := []string{"critical", "high", "medium", "low"}
	counts := make([]reports.SeverityCount, 0, len(severities))

	prevCounts := make(map[string]int)
	currentCounts := make(map[string]int)

	for _, vuln := range g.comparison.Image1.VulnList {
		prevCounts[vuln.Severity]++
	}
	for _, vuln := range g.comparison.Image2.VulnList {
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

func (g *ImageReportGenerator) GetAddedCVEs() map[string]map[string]helmscanTypes.Vulnerability {
	result := make(map[string]map[string]helmscanTypes.Vulnerability)
	for severity, vulns := range g.comparison.AddedCVEs {
		result[severity] = make(map[string]helmscanTypes.Vulnerability)
		for _, vuln := range vulns {
			result[severity][vuln.ID] = vuln
		}
	}
	return result
}

func (g *ImageReportGenerator) GetRemovedCVEs() map[string]map[string]helmscanTypes.Vulnerability {
	result := make(map[string]map[string]helmscanTypes.Vulnerability)
	for severity, vulns := range g.comparison.RemovedCVEs {
		result[severity] = make(map[string]helmscanTypes.Vulnerability)
		for _, vuln := range vulns {
			result[severity][vuln.ID] = vuln
		}
	}
	return result
}

func (g *ImageReportGenerator) GetUnchangedCVEs() map[string]map[string]helmscanTypes.Vulnerability {
	result := make(map[string]map[string]helmscanTypes.Vulnerability)
	for severity, vulns := range g.comparison.UnchangedCVEs {
		result[severity] = make(map[string]helmscanTypes.Vulnerability)
		for _, vuln := range vulns {
			result[severity][vuln.ID] = vuln
		}
	}
	return result
}

func (g *ImageReportGenerator) GetBaseFilename() string {
	return fmt.Sprintf("image_comparison_%s_to_%s",
		g.comparison.Image1.Image,
		g.comparison.Image2.Image)
}
