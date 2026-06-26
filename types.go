// Type definitions for harbor scanner report
package main

// harborReport contains OS, Arch, and Package information
type harborReport struct {
	OSType    string
	OSVersion string
	Arch      string
	Packages  []harborPackage
}

// harborPackage contains package and vulnerability information
type harborPackage struct {
	Name             string
	InstalledVersion string
	FixedVersion     string
	VulnerabilityID  string
}
