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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/packagistsecrets"
)

func TestDetector_Detect(t *testing.T) {
	engine, err := veles.NewDetectionEngine([]veles.Detector{packagistsecrets.NewDetector()})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		input string
		want  []veles.Secret
	}{
		{
			name:  "empty_input",
			input: "",
			want:  nil,
		},
		{
			name:  "valid_uut_token",
			input: "packagist_uut_1234567890abcdef1234567890abcdef",
			want: []veles.Secret{
				packagistsecrets.PackagistSecret{Token: "packagist_uut_1234567890abcdef1234567890abcdef"},
			},
		},
		{
			name:  "valid_ack_key",
			input: "packagist_ack_1234567890abcdef1234567890abcdef12345678",
			want: []veles.Secret{
				packagistsecrets.PackagistSecret{Token: "packagist_ack_1234567890abcdef1234567890abcdef12345678"},
			},
		},
		{
			name:  "valid_acs_secret",
			input: "packagist_acs_1234567890abcdef1234567890abcdef1234567890abcdef",
			want: []veles.Secret{
				packagistsecrets.PackagistSecret{Token: "packagist_acs_1234567890abcdef1234567890abcdef1234567890abcdef"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := engine.Detect(t.Context(), strings.NewReader(tc.input))
			if err != nil {
				t.Errorf("Detect() error: %v, want nil", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Detect() diff (-want +got):\n%s", diff)
			}
		})
	}
}
