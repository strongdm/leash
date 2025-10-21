package listen

import "testing"

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    Config
		wantErr bool
	}{
		{
			name:  "empty disables",
			input: "",
			want:  Config{Disable: true},
		},
		{
			name:  "port only",
			input: "19080",
			want:  Config{Host: "", Port: "19080"},
		},
		{
			name:  "prefixed port",
			input: ":19081",
			want:  Config{Host: "", Port: "19081"},
		},
		{
			name:  "host only defaults port",
			input: "127.0.0.1",
			want:  Config{Host: "127.0.0.1", Port: defaultPort},
		},
		{
			name:  "host and port",
			input: "0.0.0.0:20000",
			want:  Config{Host: "0.0.0.0", Port: "20000"},
		},
		{
			name:  "ipv6 host only",
			input: "[::1]",
			want:  Config{Host: "::1", Port: defaultPort},
		},
		{
			name:  "ipv6 host and port",
			input: "[::]:21000",
			want:  Config{Host: "::", Port: "21000"},
		},
		{
			name:    "invalid port",
			input:   ":abc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Parse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tt.input, err)
			}
			if got.Disable != tt.want.Disable || got.Host != tt.want.Host || got.Port != tt.want.Port {
				t.Fatalf("Parse(%q) = %+v, want %+v", tt.input, got, tt.want)
			}
		})
	}
}

func TestDisplayURL(t *testing.T) {
	t.Parallel()

	cfg := Config{Host: "", Port: "18080"}
	if got := cfg.DisplayURL(); got != "http://localhost:18080/" {
		t.Fatalf("DisplayURL default = %s", got)
	}

	ipv6 := Config{Host: "::1", Port: "18081"}
	if got := ipv6.DisplayURL(); got != "http://[::1]:18081/" {
		t.Fatalf("DisplayURL ipv6 = %s", got)
	}
}
