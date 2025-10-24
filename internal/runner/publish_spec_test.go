package runner

import (
	"strings"
	"testing"
)

func TestParsePublishSpecSuccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  publishSpec
	}{
		{
			name:  "containerOnly",
			input: "3000",
			want: publishSpec{
				HostIP:        "127.0.0.1",
				HostPort:      "",
				ContainerPort: "3000",
				Proto:         "tcp",
				AutoHostPort:  true,
			},
		},
		{
			name:  "hostAndContainer",
			input: "8080:80",
			want: publishSpec{
				HostIP:        "127.0.0.1",
				HostPort:      "8080",
				ContainerPort: "80",
				Proto:         "tcp",
				AutoHostPort:  false,
			},
		},
		{
			name:  "autoHostWithContainer",
			input: ":443",
			want: publishSpec{
				HostIP:        "127.0.0.1",
				HostPort:      "",
				ContainerPort: "443",
				Proto:         "tcp",
				AutoHostPort:  true,
			},
		},
		{
			name:  "explicitIPWithHostAndContainer",
			input: "0.0.0.0:9000:9001/udp",
			want: publishSpec{
				HostIP:        "0.0.0.0",
				HostPort:      "9000",
				ContainerPort: "9001",
				Proto:         "udp",
				AutoHostPort:  false,
			},
		},
		{
			name:  "explicitIPAutoHost",
			input: " 0.0.0.0::8443 ",
			want: publishSpec{
				HostIP:        "0.0.0.0",
				HostPort:      "",
				ContainerPort: "8443",
				Proto:         "tcp",
				AutoHostPort:  true,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parsePublishSpec(tt.input)
			if err != nil {
				t.Fatalf("parsePublishSpec(%q) returned error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("parsePublishSpec(%q) = %#v, want %#v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParsePublishSpecErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		wantSubstr string
	}{
		{name: "empty", input: "", wantSubstr: "empty"},
		{name: "unknownProtocol", input: "3000/tcpx", wantSubstr: "unknown protocol"},
		{name: "missingContainerPort", input: ":", wantSubstr: "container port required"},
		{name: "missingContainerPortWithHost", input: "8080:", wantSubstr: "container port required"},
		{name: "missingContainerPortWithIP", input: "0.0.0.0:9000:", wantSubstr: "container port required"},
		{name: "tooManySegments", input: "1:2:3:4", wantSubstr: "invalid publish format"},
		{name: "nonNumericContainerPort", input: "abc", wantSubstr: "invalid port"},
		{name: "nonNumericHostPort", input: "x:123", wantSubstr: "invalid port"},
		{name: "nonNumericHostPortWithIP", input: "0.0.0.0:x:123", wantSubstr: "invalid port"},
		{name: "zeroContainerPort", input: "0", wantSubstr: "invalid port"},
		{name: "zeroHostPort", input: "0:123", wantSubstr: "invalid port"},
		{name: "zeroHostPortWithIP", input: "0.0.0.0:0:123", wantSubstr: "invalid port"},
		{name: "hostPortTooLarge", input: "0.0.0.0:70000:123", wantSubstr: "invalid port"},
		{name: "containerPortTooLarge", input: "0.0.0.0:123:70000", wantSubstr: "invalid port"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := parsePublishSpec(tt.input)
			if err == nil {
				t.Fatalf("parsePublishSpec(%q) expected error, got nil", tt.input)
			}
			if tt.wantSubstr != "" && !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Fatalf("parsePublishSpec(%q) error = %q, want substring %q", tt.input, err.Error(), tt.wantSubstr)
			}
		})
	}
}
