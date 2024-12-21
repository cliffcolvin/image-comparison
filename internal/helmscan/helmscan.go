package helmscan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cliffcolvin/helmscan/internal/imageScan"
	"github.com/cliffcolvin/helmscan/internal/reports"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/cli"
)

var logger *zap.SugaredLogger

func init() {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.AddSync(os.Stdout),
		zap.InfoLevel,
	)

	zapLogger := zap.New(core)
	defer zapLogger.Sync()

	logger = zapLogger.Sugar()

	logger.Info("Application started")

	if err := imageScan.CheckTrivyInstallation(); err != nil {
		logger.Fatalf("Trivy installation check failed: %v", err)
	}
}

type HelmComparison struct {
	Before          HelmChart
	After           HelmChart
	AddedImages     map[string][]*ContainerImage
	RemovedImages   map[string][]*ContainerImage
	ChangedImages   map[string][]*ContainerImage
	UnChangedImages map[string][]*ContainerImage
	RemovedCVEs     map[string]map[string]reports.Vulnerability
	AddedCVEs       map[string]map[string]reports.Vulnerability
	UnchangedCVEs   map[string]map[string]reports.Vulnerability
}

type HelmChart struct {
	Name           string
	Version        string
	HelmRepo       string
	ContainsImages []*ContainerImage
}

func (hc HelmChart) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Name: %s, Version: %s, HelmRepo: %s\n", hc.Name, hc.Version, hc.HelmRepo))
	sb.WriteString("ContainsImages:\n")
	for _, img := range hc.ContainsImages {
		sb.WriteString(fmt.Sprintf("  %s\n", img))
	}
	return sb.String()
}

type ContainerImage struct {
	Repository      string
	Tag             string
	ImageName       string
	ScanResult      imageScan.ScanResult
	Vulnerabilities map[string]imageScan.Vulnerability
}

func (ci ContainerImage) String() string {
	return fmt.Sprintf("Repository: %s\n, Tag: %s\n, ImageName: %s\n\n", ci.Repository, ci.Tag, ci.ImageName)
}

func Scan(chartRef string) (HelmChart, error) {
	if err := os.MkdirAll("working-files", 0755); err != nil {
		return HelmChart{}, fmt.Errorf("error creating working-files directory: %w", err)
	}

	repoName, chartName, version, err := parseChartReference(chartRef)
	if err != nil {
		return HelmChart{}, err
	}

	helm_repo_update_cmd := exec.Command("helm", "repo", "update")
	output, err := helm_repo_update_cmd.CombinedOutput()
	if err != nil {
		logger.Errorf("Error updating Helm repo: %v\nOutput: %s", err, string(output))
		return HelmChart{}, fmt.Errorf("error updating Helm repo: %v\nOutput: %s", err, string(output))
	}
	logger.Infof("Helm repo update output: %s", string(output))

	cmd := exec.Command("helm", "template", fmt.Sprintf("%s/%s", repoName, chartName), "--version", version)
	output, err = cmd.CombinedOutput()
	if err != nil {
		logger.Errorf("Error templating chart: %v\nOutput: %s", err, string(output))
		return HelmChart{}, fmt.Errorf("error templating chart: %v\nOutput: %s", err, string(output))
	}

	outputFileName := fmt.Sprintf("working-files/%s_%s_%s_helm_output.yaml", repoName, chartName, version)
	err = os.WriteFile(outputFileName, output, 0644)
	if err != nil {
		return HelmChart{}, fmt.Errorf("error saving helm output to file: %w", err)
	}

	images, err := extractImagesFromYAML(output)
	if err != nil {
		return HelmChart{}, fmt.Errorf("error extracting images: %w", err)
	}

	helmChart := HelmChart{
		Name:           chartName,
		Version:        version,
		HelmRepo:       repoName,
		ContainsImages: make([]*ContainerImage, len(images)),
	}

	var scanErrors []string
	for id, img := range images {
		imageName := fmt.Sprintf("%s/%s:%s", img.Repository, img.ImageName, img.Tag)
		scanResult, err := imageScan.ScanImage(imageName)
		if err != nil {
			scanErrors = append(scanErrors, fmt.Sprintf("error scanning image %s: %v", img.ImageName, err))
		} else {
			tmpVulns := make(map[string]imageScan.Vulnerability)
			for i := range scanResult.VulnList {
				if _, exists := tmpVulns[scanResult.VulnList[i].ID]; !exists {
					tmpVulns[scanResult.VulnList[i].ID] = scanResult.VulnList[i]
				}
			}
			helmChart.ContainsImages[id] = &ContainerImage{
				Repository:      img.Repository,
				ImageName:       img.ImageName,
				Tag:             img.Tag,
				ScanResult:      scanResult,
				Vulnerabilities: tmpVulns,
			}
		}
	}

	if len(scanErrors) > 0 {
		return helmChart, fmt.Errorf("errors occurred during image scanning:\n%s", strings.Join(scanErrors, "\n"))
	}

	return helmChart, nil
}

func CompareHelmCharts(before, after HelmChart) HelmComparison {
	comparison := HelmComparison{
		Before:          before,
		After:           after,
		AddedImages:     make(map[string][]*ContainerImage),
		RemovedImages:   make(map[string][]*ContainerImage),
		ChangedImages:   make(map[string][]*ContainerImage),
		UnChangedImages: make(map[string][]*ContainerImage),
		RemovedCVEs:     make(map[string]map[string]reports.Vulnerability),
		AddedCVEs:       make(map[string]map[string]reports.Vulnerability),
		UnchangedCVEs:   make(map[string]map[string]reports.Vulnerability),
	}

	beforeImages := make(map[string]*ContainerImage)
	afterImages := make(map[string]*ContainerImage)

	for _, img := range before.ContainsImages {
		beforeImages[img.ImageName] = img
	}

	for _, img := range after.ContainsImages {
		afterImages[img.ImageName] = img
	}

	for name, beforeImg := range beforeImages {
		if afterImg, exists := afterImages[name]; exists {
			if beforeImg.Tag != afterImg.Tag {
				comparison.ChangedImages[name] = []*ContainerImage{beforeImg, afterImg}
				compareImageVulnerabilities(beforeImg, afterImg, &comparison)
			} else {
				comparison.UnChangedImages[name] = []*ContainerImage{beforeImg, afterImg}
				for ID, vuln := range beforeImg.Vulnerabilities {
					if _, exists := comparison.UnchangedCVEs[ID]; !exists {
						comparison.UnchangedCVEs[ID] = make(map[string]reports.Vulnerability)
					}
					comparison.UnchangedCVEs[ID][name] = vuln
				}
			}
		} else {
			comparison.RemovedImages[name] = []*ContainerImage{beforeImg}
			for ID, vuln := range beforeImg.Vulnerabilities {
				if _, exists := comparison.RemovedCVEs[ID]; !exists {
					comparison.RemovedCVEs[ID] = make(map[string]reports.Vulnerability)
					comparison.RemovedCVEs[ID][name] = vuln
				} else {
					comparison.RemovedCVEs[ID][name] = vuln
				}
			}
		}
	}

	for name, afterImg := range afterImages {
		if _, exists := beforeImages[name]; !exists {
			comparison.AddedImages[name] = []*ContainerImage{afterImg}
			for ID, vuln := range afterImg.Vulnerabilities {
				if _, exists := comparison.AddedCVEs[ID]; !exists {
					comparison.AddedCVEs[ID] = make(map[string]reports.Vulnerability)
					comparison.AddedCVEs[ID][name] = vuln
				} else {
					comparison.AddedCVEs[ID][name] = vuln
				}
			}
		}
	}

	return comparison
}

func compareImageVulnerabilities(before, after *ContainerImage, comparison *HelmComparison) {
	for id, vuln := range before.Vulnerabilities {
		if _, exists := after.Vulnerabilities[id]; !exists {
			if _, exists := comparison.RemovedCVEs[id]; !exists {
				comparison.RemovedCVEs[id] = make(map[string]reports.Vulnerability)
			}
			comparison.RemovedCVEs[id][before.ImageName] = vuln
		} else {
			if _, exists := comparison.UnchangedCVEs[id]; !exists {
				comparison.UnchangedCVEs[id] = make(map[string]reports.Vulnerability)
			}
			comparison.UnchangedCVEs[id][before.ImageName] = vuln
		}
	}

	for id, vuln := range after.Vulnerabilities {
		if _, exists := before.Vulnerabilities[id]; !exists {
			if _, exists := comparison.AddedCVEs[id]; !exists {
				comparison.AddedCVEs[id] = make(map[string]reports.Vulnerability)
			}
			comparison.AddedCVEs[id][after.ImageName] = vuln
		}
	}
}

func extractImagesFromYAML(yamlData []byte) ([]*ContainerImage, error) {
	cmd := exec.Command("bash", "-c", `yq e -o json - | jq -r '.. | .image? | select(.)'`)
	cmd.Stdin = bytes.NewReader(yamlData)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error extracting images: %w", err)
	}

	imageStrings := strings.Split(strings.TrimSpace(string(output)), "\n")

	var images []*ContainerImage
	for _, imageString := range imageStrings {
		image := parseImageString(imageString)
		images = append(images, image)
	}

	return images, nil
}

func parseImageString(imageString string) *ContainerImage {
	parts := strings.Split(imageString, ":")
	var repository, imageName, tag string

	if len(parts) > 1 {
		tag = parts[len(parts)-1]
		repoAndImage := strings.Join(parts[:len(parts)-1], ":")
		repoParts := strings.Split(repoAndImage, "/")
		if len(repoParts) > 1 {
			imageName = repoParts[len(repoParts)-1]
			repository = strings.Join(repoParts[:len(repoParts)-1], "/")
		} else {
			imageName = repoAndImage
		}
	} else {
		repoParts := strings.Split(imageString, "/")
		if len(repoParts) > 1 {
			imageName = repoParts[len(repoParts)-1]
			repository = strings.Join(repoParts[:len(repoParts)-1], "/")
		} else {
			imageName = imageString
		}
		tag = "latest"
	}

	return &ContainerImage{
		Repository: repository,
		ImageName:  imageName,
		Tag:        tag,
	}
}

func parseChartReference(chartRef string) (string, string, string, error) {
	parts := strings.Split(chartRef, "/")
	if len(parts) != 2 {
		return "", "", "", fmt.Errorf("invalid chart reference: %s", chartRef)
	}
	repoAndChart := parts[1]
	repoParts := strings.Split(repoAndChart, "@")
	if len(repoParts) != 2 {
		return "", "", "", fmt.Errorf("invalid chart reference: %s", chartRef)
	}
	return parts[0], repoParts[0], repoParts[1], nil
}

func downloadChart(repoName, chartName, version, destDir string) (string, error) {
	settings := cli.New()
	actionConfig := new(action.Configuration)
	client := action.NewInstall(actionConfig)
	client.DryRun = true
	client.ReleaseName = "test"
	client.Replace = true
	client.ClientOnly = true
	client.IncludeCRDs = false

	cp, err := client.ChartPathOptions.LocateChart(fmt.Sprintf("%s/%s", repoName, chartName), settings)
	if err != nil {
		return "", fmt.Errorf("error locating chart: %w", err)
	}

	chartPath := filepath.Join(destDir, filepath.Base(cp))
	err = os.Rename(cp, chartPath)
	if err != nil {
		return "", fmt.Errorf("error moving chart: %w", err)
	}

	return chartPath, nil
}

func GenerateReport(comparison HelmComparison, generateJSON bool, generateMD bool) string {
	var lastReport string

	baseFilename := reports.CreateSafeFileName(
		fmt.Sprintf("%s_%s_%s_to_%s_%s_%s_helm_comparison",
			comparison.Before.HelmRepo,
			comparison.Before.Name,
			comparison.Before.Version,
			comparison.After.HelmRepo,
			comparison.After.Name,
			comparison.After.Version))

	if generateMD {
		mdReport := generateMarkdownReport(comparison)
		lastReport = mdReport

		if err := reports.SaveToFile(mdReport, baseFilename+".md"); err != nil {
			fmt.Printf("Error saving markdown report: %v\n", err)
		}
	}

	if generateJSON {
		jsonReport := generateJSONReport(comparison)
		lastReport = jsonReport

		if err := reports.SaveToFile(jsonReport, baseFilename+".json"); err != nil {
			fmt.Printf("Error saving JSON report: %v\n", err)
		}
	}

	return lastReport
}

func generateMarkdownReport(comparison HelmComparison) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("## Helm Chart Comparison Report %s/%s@%s to %s/%s@%s\n\n",
		comparison.Before.HelmRepo, comparison.Before.Name, comparison.Before.Version,
		comparison.After.HelmRepo, comparison.After.Name, comparison.After.Version))

	sb.WriteString("### CVE by Severity\n\n")
	sb.WriteString("| Severity | Count | Prev Count | Difference |\n")
	sb.WriteString("|----------|-------|------------|------------|\n")

	severities := []string{"critical", "high", "medium", "low"}
	prevCounts := make(map[string]int)
	currentCounts := make(map[string]int)

	for _, img := range comparison.Before.ContainsImages {
		for _, vuln := range img.Vulnerabilities {
			prevCounts[vuln.Severity]++
		}
	}
	for _, img := range comparison.After.ContainsImages {
		for _, vuln := range img.Vulnerabilities {
			currentCounts[vuln.Severity]++
		}
	}

	for _, severity := range severities {
		count := currentCounts[severity]
		prevCount := prevCounts[severity]
		difference := count - prevCount
		differenceStr := fmt.Sprintf("%+d", difference)

		sb.WriteString(fmt.Sprintf("| %s | %d | %d | %s |\n", severity, count, prevCount, differenceStr))
	}
	sb.WriteString("\n\n")

	// Images table
	sb.WriteString("### Images\n\n")
	sb.WriteString("| Image Name | Status | Before Repo | After Repo | Before Tag | After Tag |\n")
	sb.WriteString("|------------|--------|-------------|------------|------------|-----------|\n")

	var imageRows []string

	for name, images := range comparison.AddedImages {
		imageRows = append(imageRows, fmt.Sprintf("| %s | Added | - | %s | - | %s |",
			name, images[0].Repository, images[0].Tag))
	}

	for name, images := range comparison.RemovedImages {
		imageRows = append(imageRows, fmt.Sprintf("| %s | Removed | %s | - | %s | - |",
			name, images[0].Repository, images[0].Tag))
	}

	for name, images := range comparison.ChangedImages {
		imageRows = append(imageRows, fmt.Sprintf("| %s | Changed | %s | %s | %s | %s |",
			name, images[0].Repository, images[1].Repository, images[0].Tag, images[1].Tag))
	}

	for name, images := range comparison.UnChangedImages {
		imageRows = append(imageRows, fmt.Sprintf("| %s | Unchanged | %s | %s | %s | %s |",
			name, images[0].Repository, images[1].Repository, images[0].Tag, images[1].Tag))
	}

	sb.WriteString(strings.Join(imageRows, "\n"))
	sb.WriteString("\n\n")

	// CVEs tables
	sb.WriteString("### Unchanged CVEs\n\n")
	sb.WriteString(sortAndFormatCVEs(comparison.UnchangedCVEs))
	sb.WriteString("\n\n")

	sb.WriteString("### Added CVEs\n\n")
	sb.WriteString(sortAndFormatCVEs(comparison.AddedCVEs))
	sb.WriteString("\n\n")

	sb.WriteString("### Removed CVEs\n\n")
	sb.WriteString(sortAndFormatCVEs(comparison.RemovedCVEs))
	sb.WriteString("\n")

	return sb.String()
}

func generateJSONReport(comparison HelmComparison) string {
	report := reports.JSONReport{
		ReportType: "helm_comparison",
		Comparison: map[string]string{
			"before_chart": fmt.Sprintf("%s/%s@%s", comparison.Before.HelmRepo, comparison.Before.Name, comparison.Before.Version),
			"after_chart":  fmt.Sprintf("%s/%s@%s", comparison.After.HelmRepo, comparison.After.Name, comparison.After.Version),
		},
		Summary: reports.Summary{
			SeverityCounts: generateJSONSeverityCounts(comparison),
			ImageChanges:   generateJSONImageChanges(comparison),
		},
		AddedCVEs:     reports.ConvertToJSONCVEs(comparison.AddedCVEs),
		RemovedCVEs:   reports.ConvertToJSONCVEs(comparison.RemovedCVEs),
		UnchangedCVEs: reports.ConvertToJSONCVEs(comparison.UnchangedCVEs),
	}

	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error generating JSON report: %v", err)
	}
	return string(jsonBytes)
}

func sortAndFormatCVEs(cves map[string]map[string]reports.Vulnerability) string {
	if len(cves) == 0 {
		return "No CVEs found.\n\n"
	}

	var sortedCVEs reports.SortableCVEList
	for cveID, imageVulns := range cves {
		var images []string
		var severity string
		for imageName, vuln := range imageVulns {
			images = append(images, imageName)
			severity = vuln.GetSeverity()
		}
		sortedCVEs = append(sortedCVEs, reports.SortableCVE{
			ID:       cveID,
			Severity: severity,
			Images:   images,
		})
	}

	sort.Sort(sortedCVEs)

	var sb strings.Builder
	sb.WriteString("| CVE ID | Severity | Affected Images |\n")
	sb.WriteString("|--------|----------|------------------|\n")

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

func generateJSONSeverityCounts(comparison HelmComparison) []reports.SeverityCount {
	severities := []string{"critical", "high", "medium", "low"}
	counts := make([]reports.SeverityCount, 0, len(severities))

	prevCounts := make(map[string]int)
	currentCounts := make(map[string]int)

	for _, img := range comparison.Before.ContainsImages {
		for _, vuln := range img.Vulnerabilities {
			prevCounts[vuln.Severity]++
		}
	}
	for _, img := range comparison.After.ContainsImages {
		for _, vuln := range img.Vulnerabilities {
			currentCounts[vuln.Severity]++
		}
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

func generateJSONImageChanges(comparison HelmComparison) []reports.ImageChange {
	var changes []reports.ImageChange

	// Add added images
	for name, images := range comparison.AddedImages {
		changes = append(changes, reports.ImageChange{
			Name:      name,
			Status:    "Added",
			AfterRepo: images[0].Repository,
			AfterTag:  images[0].Tag,
		})
	}

	// Add removed images
	for name, images := range comparison.RemovedImages {
		changes = append(changes, reports.ImageChange{
			Name:       name,
			Status:     "Removed",
			BeforeRepo: images[0].Repository,
			BeforeTag:  images[0].Tag,
		})
	}

	// Add changed images
	for name, images := range comparison.ChangedImages {
		changes = append(changes, reports.ImageChange{
			Name:       name,
			Status:     "Changed",
			BeforeRepo: images[0].Repository,
			AfterRepo:  images[1].Repository,
			BeforeTag:  images[0].Tag,
			AfterTag:   images[1].Tag,
		})
	}

	// Add unchanged images
	for name, images := range comparison.UnChangedImages {
		changes = append(changes, reports.ImageChange{
			Name:       name,
			Status:     "Unchanged",
			BeforeRepo: images[0].Repository,
			AfterRepo:  images[0].Repository,
			BeforeTag:  images[0].Tag,
			AfterTag:   images[0].Tag,
		})
	}

	return changes
}

func GenerateSingleScanReport(chart HelmChart, jsonOutput bool) string {
	// Collect all vulnerabilities from all images
	vulns := make(map[string]reports.Vulnerability)
	for _, img := range chart.ContainsImages {
		for id, v := range img.Vulnerabilities {
			// Create a composite key that includes the image name to avoid overwriting
			vulns[fmt.Sprintf("%s:%s", img.ImageName, id)] = v
		}
	}

	chartRef := fmt.Sprintf("%s/%s@%s", chart.HelmRepo, chart.Name, chart.Version)
	return reports.GenerateSingleScanReport("helm", chartRef, vulns, jsonOutput)
}

func scanSingleHelmChart(chartRef string, saveReport bool, jsonOutput bool) {
	logger.Infof("Scanning Helm chart: %s", chartRef)
	result, err := Scan(chartRef)
	if err != nil {
		logger.Errorf("Error scanning Helm chart: %v", err)
		return
	}

	report := GenerateSingleScanReport(result, jsonOutput)

	if saveReport {
		ext := ".md"
		if jsonOutput {
			ext = ".json"
		}
		filename := fmt.Sprintf("helm_scan_%s%s", reports.CreateSafeFileName(chartRef), ext)
		if err := reports.SaveToFile(report, filename); err != nil {
			logger.Errorf("Error saving report: %v", err)
		}
	}

	fmt.Println(report)
}
