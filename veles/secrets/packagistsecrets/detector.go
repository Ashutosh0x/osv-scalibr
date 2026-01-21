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
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/simpletoken"
)

const (
	maxSecretLen = 256
)

var (
	// packagistTokenRe matches Packagist User Update Tokens, API Keys, and Secret Keys.
	packagistTokenRe = regexp.MustCompile(`\bpackagist_(uut|ack|acs)_[0-9a-f]{32,}\b`)
)

// NewDetector returns a detector that matches Packagist secrets.
func NewDetector() veles.Detector {
	return &simpletoken.Detector{
		MaxLen: maxSecretLen,
		Re:     packagistTokenRe,
		FromMatch: func(m []byte) (veles.Secret, bool) {
			return PackagistSecret{Token: string(m)}, true
		},
	}
}
