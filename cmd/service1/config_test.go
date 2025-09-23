package main

import "testing"

func TestParseKeycloakIssuer(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantBase  string
		wantRealm string
		wantErr   bool
	}{
		{name: "empty", input: "", wantBase: "", wantRealm: ""},
		{name: "simple", input: "http://localhost:8080/realms/demo", wantBase: "http://localhost:8080", wantRealm: "demo"},
		{name: "with prefix", input: "http://example.com/auth/realms/demo", wantBase: "http://example.com/auth", wantRealm: "demo"},
		{name: "missing realm", input: "http://localhost:8080/realms/", wantErr: true},
		{name: "no realms", input: "http://localhost:8080/foo", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base, realm, err := parseKeycloakIssuer(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if base != tc.wantBase {
				t.Fatalf("base = %q, want %q", base, tc.wantBase)
			}
			if realm != tc.wantRealm {
				t.Fatalf("realm = %q, want %q", realm, tc.wantRealm)
			}
		})
	}
}
