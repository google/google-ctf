// Copyright 2021 Google LLC
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

// Author: Kegan Thorrez

package captcha

import (
	"context"
	"errors"
	"fmt"

	recaptcha "cloud.google.com/go/recaptchaenterprise/apiv1"
	recaptchapb "google.golang.org/genproto/googleapis/cloud/recaptchaenterprise/v1"
)

type Checker struct {
	siteKey       string
	parentProject string            // e.g. "projects/my-project"
	client        *recaptcha.Client // not nil
}

// parentProject is of the form "my-project".
func New(ctx context.Context, siteKey string, parentProject string) (*Checker, error) {
	client, err := recaptcha.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	return &Checker{
		siteKey:       siteKey,
		parentProject: "projects/" + parentProject,
		client:        client,
	}, nil
}

// First checks whether token is empty.
func (c *Checker) Check(ctx context.Context, token string) error {
	if token == "" {
		return errors.New("empty captcha token")
	}

	request := &recaptchapb.CreateAssessmentRequest{
		Assessment: &recaptchapb.Assessment{
			Event: &recaptchapb.Event{
				Token:   token,
				SiteKey: c.siteKey,
			},
		},
		Parent: c.parentProject,
	}

	response, err := c.client.CreateAssessment(ctx, request)
	if err != nil {
		return err
	}

	if !response.TokenProperties.Valid {
		return fmt.Errorf("captcha was invalid: %v", response.TokenProperties.InvalidReason)
	}
	if response.RiskAnalysis.Score < 0.2 {
		return fmt.Errorf("captcha had a bad score: %f", response.RiskAnalysis.Score)
	}
	return nil
}
