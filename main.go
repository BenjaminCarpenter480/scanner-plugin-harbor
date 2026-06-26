package main

import (
	"encoding/json"
	"fmt"
	"os"


	harborTypes "github.com/goharbor/harbor/src/pkg/scan/vuln/report.go"	
	v1alpha1 "github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
)

type HarborParser struct{}

// parseHarborReport parses a harbor report from a file
func parseHarborReport(file string) (*HarborReport, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var harborReport harborTypes.Report
	if err = json.Unmarshal(data, &harbor); err != nil {
		return nil, err
	}

	return &harborReport, nil
}

func newHarborParser() *HarborParser {
	return &HarborParser{}
}

func (k *HarborParser) parse(file string) (*v1alpha1.UpdateManifest, error) {
	// Parse the harbor report
	report, err := parseHarborReport(file)
	if err != nil {
		return nil, err
	}

	if report["application/vnd.security.vulnerability.report; version=1.1"].Vulnerabilities == nil {
		return nil, fmt.Errorf("no vulnerabilities found in the report or report is not in the expected format")
	}

	// Create the standardized report
	updates := v1alpha1.UpdateManifest{
		APIVersion: v1alpha1.APIVersion,
		Metadata: v1alpha1.Metadata{
			// Modify types to include harbor types?
			OS: v1alpha1.OS{
				Type: "Unknown",
				Version: "Unknown",
			},
			Config: v1alpha1.Config{
			Arch: "Unknown",
			},
		},
	}

	// Convert the harbor report to the standardized report
	for vuln_index, vuln := range report.vulnerabilities {
		pkg_name := &report.vulnerabilities[vuln_index].package
		if vuln.fix_version != "" {
			updates.Updates = append(updates.Updates, v1alpha1.UpdatePackage{
				Name: pkg_name,
				InstalledVersion: vuln.version,
				FixedVersion: vuln.fix_version,
				VulnerabilityID: vuln.id
			})
		}
	}

	return &updates, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <image report>\n", os.Args[0])
		os.Exit(1)
	}

	// Initialize the parser
	harborParser := newHarborParser()

	// Get the image report from command line
	imageReport := os.Args[1]

	report, err := harborParser.parse(imageReport)
	if err != nil {
		fmt.Printf("error parsing report: %v\n", err)
		os.Exit(1)
	}

	// Serialize the standardized report and print it to stdout
	reportBytes, err := json.Marshal(report)
	if err != nil {
		fmt.Printf("Error serializing report: %v\n", err)
		os.Exit(1)
	}

	os.Stdout.Write(reportBytes)
}
