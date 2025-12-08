package consensus

import "testing"

func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "http", input: "http://localhost:26657", want: "http://localhost:26657"},
		{name: "https", input: "https://example.com:26657", want: "https://example.com:26657"},
		{name: "tcp", input: "tcp://localhost:26657", want: "tcp://localhost:26657"},
		{name: "no-scheme", input: "localhost:26657", want: "http://localhost:26657"},
		{name: "empty", input: "  ", wantErr: true},
	}

	for _, tt := range tests {
		got, err := normalizeEndpoint(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("%s: expected error, got nil", tt.name)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tt.name, err)
		}
		if got != tt.want {
			t.Fatalf("%s: expected %q, got %q", tt.name, tt.want, got)
		}
	}
}
