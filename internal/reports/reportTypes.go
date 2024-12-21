package reports

import helmscanTypes "github.com/cliffcolvin/helmscan/internal/helmScanTypes"

type ReportGenerator interface {
	GetTitle() string
	GetComparison() map[string]string
	GetSeverityCounts() []SeverityCount
	GetAddedCVEs() map[string]map[string]helmscanTypes.Vulnerability
	GetRemovedCVEs() map[string]map[string]helmscanTypes.Vulnerability
	GetUnchangedCVEs() map[string]map[string]helmscanTypes.Vulnerability
	GetBaseFilename() string
}
