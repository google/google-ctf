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

package userhandler

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"example.com/empty-ls/central/captcha"
	"example.com/empty-ls/central/clientcrtgen"
)

type Handler struct {
	// Both non-nil
	ccg  *clientcrtgen.Generator
	capt *captcha.Checker
}

func New(capt *captcha.Checker) (*Handler, error) {
	ccg, err := clientcrtgen.New()
	if err != nil {
		return nil, fmt.Errorf("Error creating client cert generator: %v", err)
	}

	return &Handler{
		ccg:  ccg,
		capt: capt,
	}, nil
}

// Returns respBody, statusCode, err. If err is nil, then statusCode is
// http.StatusOK and respBody contains it a PKCS #12 file. Otherwise,
// respBody contains a plain text error message for the user, statusCode
// contains an error value, and err contains a specific error message not for
// the user, but to be logged together with respBody.
func (h *Handler) createPKCS12(req *http.Request) ([]byte, int, error) {
	if req.Method != "POST" {
		return []byte("Needs POST"), http.StatusMethodNotAllowed, errors.New("error")
	}

	captchaToken := req.FormValue("g-recaptcha-response")
	if err := h.capt.Check(req.Context(), captchaToken); err != nil {
		return []byte("Bad captcha"), http.StatusBadRequest, err
	}

	user := req.FormValue("user")
	user = strings.TrimSpace(user)
	if user == "" {
		return []byte("The user cannot be empty."), http.StatusBadRequest, errors.New("error")
	}

	// Ideally we would have a database of registered users. That's too much work,
	// so instead just have this hardcoded list of "registered users" to prevent
	// players from registering one of them. The only one that matters is "admin",
	// the rest are there for basically no reason at all.
	if user == "admin" ||
		user == "www" ||
		user == "administrator" ||
		user == "goog" ||
		user == "google" {
		return []byte("That username is already taken."), http.StatusBadRequest, errors.New("error")
	}

	rsp, err := h.ccg.Generate(user)
	if err != nil {
		return rsp, http.StatusBadRequest, err
	}

	return rsp, http.StatusOK, nil
}

func (h *Handler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	log.Printf("Got new user request")
	respBody, statusCode, err := h.createPKCS12(req)
	resp.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
	if err != nil {
		log.Printf("Error creating PKCS #12: %d, %s, %v", statusCode, respBody, err)
		resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		// https://pki-tutorial.readthedocs.io/en/latest/mime.html
		resp.Header().Set("Content-Type", "application/x-pkcs12")
		resp.Header().Set("Content-Disposition", "attachment; filename=\"cert_and_key.p12\"")
	}
	resp.WriteHeader(statusCode)
	n, err := resp.Write(respBody)
	if err != nil {
		log.Printf("Error when writing response body (after %d bytes): %v", n, err)
	}
	log.Printf("Responded to new user request")
}
