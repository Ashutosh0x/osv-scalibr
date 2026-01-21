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

package packagistsecrets

import (
	"net/http"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

const (
	packagistValidationEndpoint = "https://packagist.com/packages.json"
)

// NewValidator creates a new Validator that validates the Packagist secret.
//
// It performs a GET request to the packages endpoint.
// For Private Packagist, the user update token can be used as a password in Basic Auth,
// or as an API key. We'll use the API key approach where possible.
func NewValidator() *sv.Validator[PackagistSecret] {
	return &sv.Validator[PackagistSecret]{
		Endpoint:   packagistValidationEndpoint,
		HTTPMethod: http.MethodGet,
		HTTPHeaders: func(s PackagistSecret) map[string]string {
			// For Private Packagist API, an API key or token is used.
			// Depending on the prefix, we might need different auth methods.
			// Generic approach for Private Packagist is Basic Auth or X-Packagist-Token.
			return map[string]string{
				"X-Packagist-Token": s.Token,
			}
		},
		ValidResponseCodes:   []int{http.StatusOK},
		InvalidResponseCodes: []int{http.StatusUnauthorized, http.StatusForbidden},
	}
}
