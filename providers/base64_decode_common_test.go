package providers

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// runSharedBase64DecodeCases checks the same opt-in decoding contract for Vault
// and OpenBao while leaving provider-specific initialization to the caller.
func runSharedBase64DecodeCases(t *testing.T, initProvider func(serverURL string) SecretsProvider) {
	t.Helper()

	binaryPayload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02}
	encodedPayload := base64.StdEncoding.EncodeToString(binaryPayload)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/secret/data/app/binary":
			_, _ = fmt.Fprintf(w, `{"data":{"data":{"keystore":"%s"}}}`, encodedPayload)
		default:
			t.Errorf("unexpected request path: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := initProvider(server.URL)
	defer func() { _ = provider.Close() }()

	tests := []struct {
		name   string
		labels map[string]string
		want   []byte
	}{
		{name: "decoded", labels: map[string]string{"base64_decode": "true"}, want: binaryPayload},
		{name: "unchanged", want: []byte(encodedPayload)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &SecretInfo{
				DockerSecretName: "test-keystore",
				SecretPath:       "secret/data/app/binary",
				SecretField:      "keystore",
				Labels:           tt.labels,
			}
			got, err := provider.GetSecret(t.Context(), info)
			if err != nil {
				t.Fatalf("GetSecret() error = %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("GetSecret() = %v, want %v", got, tt.want)
			}
		})
	}
}
