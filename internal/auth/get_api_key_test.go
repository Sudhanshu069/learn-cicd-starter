package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	const malformed = "malformed authorization header"

	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr string
	}{
		{"valid", http.Header{"Authorization": {"ApiKey abc123"}}, "abc123", ""},
		{"no header", http.Header{}, "", ErrNoAuthHeaderIncluded.Error()},
		{"empty header", http.Header{"Authorization": {""}}, "", ErrNoAuthHeaderIncluded.Error()},
		{"wrong scheme", http.Header{"Authorization": {"Bearer abc123"}}, "", malformed},
		{"scheme only", http.Header{"Authorization": {"ApiKey"}}, "", malformed},
		{"no separator", http.Header{"Authorization": {"ApiKeyabc123"}}, "", malformed},
		{"empty key", http.Header{"Authorization": {"ApiKey "}}, "", malformed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("key = %q, want %q", gotKey, tt.wantKey)
			}

			gotErr := ""
			if err != nil {
				gotErr = err.Error()
			}
			if gotErr != tt.wantErr {
				t.Errorf("err = %q, want %q", gotErr, tt.wantErr)
			}

			if tt.wantErr == ErrNoAuthHeaderIncluded.Error() && !errors.Is(err, ErrNoAuthHeaderIncluded) {
				t.Errorf("err is not ErrNoAuthHeaderIncluded: %v", err)
			}
		})
	}
}
