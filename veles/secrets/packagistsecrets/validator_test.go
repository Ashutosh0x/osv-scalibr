// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package packagistsecrets_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/packagistsecrets"
)

type mockTransport struct {
	testServer *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Host, "packagist.com") {
		req.URL.Scheme = "http"
		req.URL.Host = m.testServer.Listener.Addr().String()
	}
	return http.DefaultTransport.RoundTrip(req)
}

func mockPackagistServer(t *testing.T, expectedToken string, statusCode int) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/packages.json") {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		token := r.Header.Get("X-Packagist-Token")
		if token != expectedToken {
			t.Errorf("expected X-Packagist-Token header %q, got: %q", expectedToken, token)
		}

		w.WriteHeader(statusCode)
	}))
}

func TestValidator(t *testing.T) {
	const testToken = "packagist_ack_testtokenmatchingregexruleshere12345"

	cases := []struct {
		name       string
		statusCode int
		want       veles.ValidationStatus
	}{
		{
			name:       "valid_token",
			statusCode: http.StatusOK,
			want:       veles.ValidationValid,
		},
		{
			name:       "invalid_token",
			statusCode: http.StatusUnauthorized,
			want:       veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := mockPackagistServer(t, testToken, tc.statusCode)
			defer server.Close()

			client := &http.Client{
				Transport: &mockTransport{testServer: server},
			}

			validator := packagistsecrets.NewValidator()
			validator.HTTPC = client

			secret := packagistsecrets.PackagistSecret{Token: testToken}
			got, err := validator.Validate(t.Context(), secret)

			if err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}

			if got != tc.want {
				t.Errorf("Validate() = %v, want %v", got, tc.want)
			}
		})
	}
}
