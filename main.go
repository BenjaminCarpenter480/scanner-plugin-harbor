package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/goharbor/harbor/src/pkg/scan/vuln"
	v1alpha1 "github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
)

// HarborReportEnvelope wraps the vuln.Report in the API envelope format,
//  which is a map with the MIME type as the key and the report as the value.
// This should stop errors if we get different MIME types in the future, as we can just check for the key and extract the report.
type HarborReportEnvelope map[string]vuln.Report

type HarborParser struct{}

// parseHarborReport parses a harbor report from a file and extracts the Report data
func parseHarborReport(file string) (*vuln.Report, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var envelope HarborReportEnvelope
	if err = json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}

	// Extract the report data from the envelope using the MIME type key
	reportData, ok := envelope["application/vnd.security.vulnerability.report; version=1.1"]
	if !ok {
		return nil, fmt.Errorf("missing report data in envelope with expected MIME type key")
	}

	return &reportData, nil
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

	if len(report.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("no vulnerabilities found in the report or report is not in the expected format")
	}

	// Create the standardized report
	updates := v1alpha1.UpdateManifest{
		APIVersion: v1alpha1.APIVersion,
		Metadata: v1alpha1.Metadata{
			OS: v1alpha1.OS{
				Type:    "Unknown",
				Version: "Unknown",
			},
			Config: v1alpha1.Config{
				Arch: "Unknown",
			},
		},
	}

	// Convert the harbor report vulnerabilities to the standardized format
	for _, vulnItem := range report.Vulnerabilities {
		// Only include vulnerabilities that have a fix version available
		if vulnItem.FixVersion != "" {
			updates.Updates = append(updates.Updates, v1alpha1.UpdatePackage{
				Name:             vulnItem.Package,
				InstalledVersion: vulnItem.Version,
				FixedVersion:     vulnItem.FixVersion,
				VulnerabilityID:  vulnItem.ID,
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
