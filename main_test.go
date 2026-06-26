package main

import (
	"reflect"
	"testing"

	v1alpha1 "github.com/project-copacetic/copacetic/pkg/types/v1alpha1"
)

func Test_parseharborReport(t *testing.T) {
	type args struct {
		file string
	}
	tests := []struct {
		name    string
		args    args
		want    *harborReport
		wantErr bool
	}{
		{
			name: "valid report",
			args: args{file: "testdata/harbor_report.json"},
			want: &harborReport{
				OSType:    "harborOS",
				OSVersion: "42",
				Arch:      "amd64",
				Packages: []harborPackage{
					{
						Name:             "foo",
						InstalledVersion: "1.0.0",
						FixedVersion:     "1.0.1",
						VulnerabilityID:  "VULN001",
					},
					{
						Name:             "bar",
						InstalledVersion: "2.0.0",
						FixedVersion:     "2.0.1",
						VulnerabilityID:  "VULN002",
					},
					{
						Name:             "baz",
						InstalledVersion: "3.0.0",
						FixedVersion:     "",
						VulnerabilityID:  "VULN003",
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "invalid file",
			args:    args{file: "testdata/nonexistent_file.json"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid json",
			args:    args{file: "testdata/invalid_report.json"},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseharborReport(tt.args.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseharborReport() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseharborReport() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewharborParser(t *testing.T) {
	tests := []struct {
		name string
		want *harborParser
	}{
		{
			name: "valid parser",
			want: &harborParser{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := newharborParser(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewharborParser() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestharborParser_Parse(t *testing.T) {
	type args struct {
		file string
	}
	tests := []struct {
		name    string
		k       *harborParser
		args    args
		want    *v1alpha1.UpdateManifest
		wantErr bool
	}{
		{
			name: "valid report",
			k:    &harborParser{},
			args: args{file: "testdata/harbor_report.json"},
			want: &v1alpha1.UpdateManifest{
				APIVersion: v1alpha1.APIVersion,
				Metadata: v1alpha1.Metadata{
					OS: v1alpha1.OS{
						Type:    "harborOS",
						Version: "42",
					},
					Config: v1alpha1.Config{
						Arch: "amd64",
					},
				},
				Updates: []v1alpha1.UpdatePackage{
					{
						Name:             "foo",
						InstalledVersion: "1.0.0",
						FixedVersion:     "1.0.1",
						VulnerabilityID:  "VULN001",
					},
					{
						Name:             "bar",
						InstalledVersion: "2.0.0",
						FixedVersion:     "2.0.1",
						VulnerabilityID:  "VULN002",
					},
				},
			},
			wantErr: false,
		},
		{
			name:    "invalid file",
			k:       &harborParser{},
			args:    args{file: "testdata/nonexistent_file.json"},
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid json",
			k:       &harborParser{},
			args:    args{file: "testdata/invalid_report.json"},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.k.parse(tt.args.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("harborParser.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("harborParser.Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}
