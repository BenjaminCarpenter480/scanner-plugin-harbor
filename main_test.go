package main

import (
	"testing"

	v1alpha1 "github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
	"github.com/goharbor/harbor/src/pkg/scan/vuln"
)

func TestParseHarborReport(t *testing.T) {
	type args struct {
		file string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		check   func(*vuln.Report) bool
	}{
		{
			name: "valid report",
			args: args{file: "testdata/harbor_report.json"},
			check: func(report *vuln.Report) bool {
				return report != nil && len(report.Vulnerabilities) > 0
			},
			wantErr: false,
		},
		{
			name:    "invalid file",
			args:    args{file: "testdata/nonexistent_file.json"},
			check:   nil,
			wantErr: true,
		},
		{
			name:    "invalid json",
			args:    args{file: "testdata/invalid_report.json"},
			check:   nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHarborReport(tt.args.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseHarborReport() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.check != nil && !tt.check(got) {
				t.Errorf("parseHarborReport() validation failed for %v", got)
			}
		})
	}
}

func TestNewHarborParser(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "creates parser successfully",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newHarborParser()
			if got == nil {
				t.Errorf("newHarborParser() returned nil")
			}
		})
	}
}

func TestHarborParser_Parse(t *testing.T) {
	type args struct {
		file string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		check   func(*v1alpha1.UpdateManifest) bool
	}{
		{
			name: "valid report with vulnerabilities",
			args: args{file: "testdata/harbor_report.json"},
			check: func(manifest *v1alpha1.UpdateManifest) bool {
				if manifest == nil {
					return false
				}
				// Check that we extracted at least one vulnerability with a fix version
				return len(manifest.Updates) > 0
			},
			wantErr: false,
		},
		{
			name:    "invalid file",
			args:    args{file: "testdata/nonexistent_file.json"},
			check:   nil,
			wantErr: true,
		},
		{
			name:    "invalid json",
			args:    args{file: "testdata/invalid_report.json"},
			check:   nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := newHarborParser()
			got, err := k.parse(tt.args.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("harborParser.parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.check != nil && !tt.check(got) {
				t.Errorf("harborParser.parse() validation failed for %v", got)
			}
		})
	}
}
