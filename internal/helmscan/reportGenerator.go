package helmscan

import (
	"fmt"

	helmscanTypes "github.com/cliffcolvin/helmscan/internal/helmScanTypes"
	"github.com/cliffcolvin/helmscan/internal/reports"
)

type HelmReportGenerator struct {
	comparison helmscanTypes.HelmComparison
}

func NewHelmReportGenerator(comparison helmscanTypes.HelmComparison) *HelmReportGenerator {
	return &HelmReportGenerator{comparison: comparison}
}

func (g *HelmReportGenerator) GetTitle() string {
	return "Helm Chart Comparison Report"
}

func (g *HelmReportGenerator) GetComparison() map[string]string {
	return map[string]string{
		"Before Chart": fmt.Sprintf("%s/%s@%s", g.comparison.Before.HelmRepo, g.comparison.Before.Name, g.comparison.Before.Version),
		"After Chart":  fmt.Sprintf("%s/%s@%s", g.comparison.After.HelmRepo, g.comparison.After.Name, g.comparison.After.Version),
	}
}

func (g *HelmReportGenerator) GetSeverityCounts() []reports.SeverityCount {
	return reports.GenerateJSONSeverityCounts(g.comparison)
}

func (g *HelmReportGenerator) GetAddedCVEs() map[string]map[string]helmscanTypes.Vulnerability {
	return g.comparison.AddedCVEs
}

func (g *HelmReportGenerator) GetRemovedCVEs() map[string]map[string]helmscanTypes.Vulnerability {
	return g.comparison.RemovedCVEs
}

func (g *HelmReportGenerator) GetUnchangedCVEs() map[string]map[string]helmscanTypes.Vulnerability {
	return g.comparison.UnchangedCVEs
}

func (g *HelmReportGenerator) GetBaseFilename() string {
	return fmt.Sprintf("%s_%s_%s_to_%s_%s_%s_helm_comparison",
		g.comparison.Before.HelmRepo,
		g.comparison.Before.Name,
		g.comparison.Before.Version,
		g.comparison.After.HelmRepo,
		g.comparison.After.Name,
		g.comparison.After.Version)
}
