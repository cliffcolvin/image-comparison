package helmscanTypes

import (
	"fmt"
	"strings"
)

type HelmComparison struct {
	Before          HelmChart
	After           HelmChart
	AddedImages     map[string][]*ContainerImage
	RemovedImages   map[string][]*ContainerImage
	ChangedImages   map[string][]*ContainerImage
	UnChangedImages map[string][]*ContainerImage
	RemovedCVEs     map[string]map[string]Vulnerability
	AddedCVEs       map[string]map[string]Vulnerability
	UnchangedCVEs   map[string]map[string]Vulnerability
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
	ScanResult      ScanResult
	Vulnerabilities map[string]Vulnerability
}

func (ci ContainerImage) String() string {
	return fmt.Sprintf("Repository: %s\n, Tag: %s\n, ImageName: %s\n\n", ci.Repository, ci.Tag, ci.ImageName)
}

type Vulnerability struct {
	ID       string
	Severity string
}

func (v Vulnerability) GetID() string {
	return v.ID
}

func (v Vulnerability) GetSeverity() string {
	return v.Severity
}

type ScanResult struct {
	Image           string
	Vulnerabilities SeverityCounts
	VulnsByLevel    map[string][]string
	VulnList        []Vulnerability
}

type GitHubRelease struct {
	TagName string `json:"tag_name"`
}
type ImageComparisonReport struct {
	Image1        ScanResult
	Image2        ScanResult
	RemovedCVEs   map[string][]Vulnerability
	AddedCVEs     map[string][]Vulnerability
	UnchangedCVEs map[string][]Vulnerability
}

type SeverityCounts struct {
	Low      int
	Medium   int
	High     int
	Critical int
}
