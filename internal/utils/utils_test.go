package utils

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestShouldBase64Decode(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   bool
	}{
		{"nil labels", nil, false},
		{"label absent", map[string]string{}, false},
		{"label false", map[string]string{"base64_decode": "false"}, false},
		{"label 1 strict", map[string]string{"base64_decode": "1"}, false},
		{"label true", map[string]string{"base64_decode": "true"}, true},
		{"label TRUE", map[string]string{"base64_decode": "TRUE"}, true},
		{"label trimmed true", map[string]string{"base64_decode": " true "}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldBase64Decode(tt.labels); got != tt.want {
				t.Errorf("ShouldBase64Decode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodeBase64Secret_Success(t *testing.T) {
	binaryData := []byte{0x00, 0xFF, 0xFE, 0x80, 0x7F, 0x12, 0x34, 0x56}
	validBase64Binary := base64.StdEncoding.EncodeToString(binaryData)
	validBase64Text := base64.StdEncoding.EncodeToString([]byte("hello world"))

	tests := []struct {
		name  string
		input []byte
		want  []byte
	}{
		{"valid text", []byte(validBase64Text), []byte("hello world")},
		{"whitespace trimmed", []byte("  " + validBase64Text + " \r\n"), []byte("hello world")},
		{"binary non-UTF8", []byte(validBase64Binary), binaryData},
		{"empty value", []byte(""), []byte{}},
		{"whitespace only", []byte("   \r\n\t  "), []byte{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeBase64Secret(tt.input, "", "")
			if err != nil {
				t.Fatalf("DecodeBase64Secret() unexpected error = %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("DecodeBase64Secret() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodeBase64Secret_Invalid(t *testing.T) {
	input := []byte("super-secret-not-base64!@#$")

	tests := []struct {
		name             string
		dockerSecretName string
		secretField      string
		wantMsg          string
	}{
		{
			name:             "docker secret name branch",
			dockerSecretName: "my-secret",
			secretField:      "",
			wantMsg:          `"my-secret"`,
		},
		{
			name:             "secret field branch",
			dockerSecretName: "",
			secretField:      "api-key",
			wantMsg:          `secret field "api-key"`,
		},
		{
			name:             "generic branch",
			dockerSecretName: "",
			secretField:      "",
			wantMsg:          "failed to base64-decode secret:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeBase64Secret(input, tt.dockerSecretName, tt.secretField)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got != nil {
				t.Errorf("expected nil value on error, got %v", got)
			}

			errMsg := err.Error()
			if !strings.Contains(errMsg, tt.wantMsg) {
				t.Errorf("error %q should contain %q", errMsg, tt.wantMsg)
			}
			if strings.Contains(errMsg, string(input)) {
				t.Errorf("error %q leaked input secret value %q", errMsg, string(input))
			}
		})
	}
}

func TestDecodeBase64Secret_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		expectError bool
		want        []byte
	}{
		{
			name:        "invalid padding two pads when one expected",
			input:       []byte("aGVsbG8=="),
			expectError: true,
		},
		{
			name:        "invalid padding single data char with three pads",
			input:       []byte("a==="),
			expectError: true,
		},
		{
			name:        "invalid padding pad in middle",
			input:       []byte("a=b="),
			expectError: true,
		},
		{
			name:        "invalid unpadded length",
			input:       []byte("aGVsb"),
			expectError: true,
		},
		{
			name:        "url-safe alphabet rejected by standard decoder",
			input:       []byte("aGVsbG8-_w=="),
			expectError: true,
		},
		{
			name:        "corrupted characters",
			input:       []byte("????"),
			expectError: true,
		},
		{
			name:        "internal whitespace rejected",
			input:       []byte("aGV sbG8="),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeBase64Secret(tt.input, "test-secret", "test-field")
			if tt.expectError {
				if err == nil {
					t.Fatalf("expected error for %s, got nil", tt.name)
				}
				if got != nil {
					t.Errorf("expected nil result on error, got %v", got)
				}
				if strings.Contains(err.Error(), string(tt.input)) {
					t.Errorf("error %q leaked secret input %q", err.Error(), string(tt.input))
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for %s: %v", tt.name, err)
				}
				if !bytes.Equal(got, tt.want) {
					t.Errorf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}
