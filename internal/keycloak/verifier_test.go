package keycloak

import "testing"

func TestNormaliseIssuer(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "trim spaces and trailing slash",
			input: "  http://example.com/realms/demo/  ",
			want:  "http://example.com/realms/demo",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "leave without trailing slash",
			input: "https://idp.example.com/realms/demo",
			want:  "https://idp.example.com/realms/demo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normaliseIssuer(tt.input)
			if got != tt.want {
				t.Fatalf("normaliseIssuer(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestVerifierIsValidIssuer(t *testing.T) {
	verifier := &Verifier{
		validIssuer: map[string]struct{}{
			"http://keycloak:8080/realms/demo":  {},
			"http://localhost:8080/realms/demo": {},
		},
	}

	cases := []struct {
		name   string
		issuer string
		want   bool
	}{
		{
			name:   "primary issuer",
			issuer: "http://keycloak:8080/realms/demo",
			want:   true,
		},
		{
			name:   "alias issuer with whitespace and slash",
			issuer: "  http://localhost:8080/realms/demo/  ",
			want:   true,
		},
		{
			name:   "unknown issuer",
			issuer: "http://example.com/realms/demo",
			want:   false,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := verifier.isValidIssuer(tt.issuer)
			if got != tt.want {
				t.Fatalf("isValidIssuer(%q) = %t, want %t", tt.issuer, got, tt.want)
			}
		})
	}
}
