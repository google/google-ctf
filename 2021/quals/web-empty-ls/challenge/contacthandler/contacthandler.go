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

package contacthandler

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"example.com/empty-ls/central/captcha"
)

type Handler struct {
	capt     *captcha.Checker // non-nil
	urlRegex *regexp.Regexp
}

// New creates a new Handler. domain is the domain the bot will check, e.g. example.com (no leading
// or trailing dot).
func New(domain string, capt *captcha.Checker) (*Handler, error) {
	// YOLO
	// This isn't really for much security, just for defense in depth.
	// This might have whitespace at the beginning, so that needs to be trimmed before use.
	urlRegexStr := `(^|\s)https://[a-z0-9-]+\.` + regexp.QuoteMeta(domain) + `(/[-?.~\w/#:@!$&'()*+,;=%]*)?`
	urlRegex, err := regexp.Compile(urlRegexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to compile url regex: %v", err)
	}

	return &Handler{
		capt:     capt,
		urlRegex: urlRegex,
	}, nil
}

// Returns respBody, statusCode, err. If err is nil, then statusCode is http.StatusOK and respBody
// contains an html body. Otherwise, respBody contains a plain text error message for the user,
// statusCode contains an error value, and err contains a specific error message not for the user,
// but to be logged together with respBody.
func (h *Handler) contact(req *http.Request) ([]byte, int, error) {
	if req.Method != "POST" {
		return []byte("Needs POST"), http.StatusMethodNotAllowed, errors.New("error")
	}

	captchaToken := req.FormValue("g-recaptcha-response")
	if err := h.capt.Check(req.Context(), captchaToken); err != nil {
		return []byte("Bad captcha"), http.StatusBadRequest, err
	}

	msg := req.FormValue("text")
	if msg == "" {
		return []byte("The message cannot be empty."), http.StatusBadRequest, errors.New("error")
	}

	const successMsg = "The admin will read your message soon. Thanks!"

	url := h.urlRegex.FindString(msg)
	url = strings.TrimSpace(url)
	if url == "" {
		// Give the same message regardless of whether a URL was detected. This is more realistic,
		// because a real admin contact form would have the same message regardless of whether there was
		// a URL or not.
		// Contestants might still be able to tell the difference via timing, but that doesn't really
		// matter since the regex doesn't really need to be secret.
		return []byte(successMsg), http.StatusOK, nil
	}

	log.Printf("Found url: %s", url)

	if err := doXSSBot(url); err != nil {
		// This is not expected to happen, so it's not really a problem to give the user an error which
		// essentially indicates the challenge is broken.
		return []byte("There was an error recording your message."), http.StatusInternalServerError, err
	}

	return []byte(successMsg), http.StatusOK, nil
}

// doXSSBot starts the XSS bot. It returns an error if there was an error starting the bot. It
// doesn't wait for the bot to finish though, so it only catches errors talking to the bot, not
// errors that the bot has requesting the url.
func doXSSBot(url string) error {
	dialer := net.Dialer{
		Timeout: 3 * time.Second,
	}
	conn, err := dialer.Dial("tcp", "empty-ls-xss-bot.default.svc.cluster.local:1337")
	if err != nil {
		return fmt.Errorf("failed to dial the bot: %v", err)
	}
	defer conn.Close()

	// bot.js already has a 5s timeout. We add our own 15s timeout in case that timeout fails or
	// there's a network error between here and the bot.
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	if _, err := conn.Write([]byte(url)); err != nil {
		return fmt.Errorf("failed to write to the bot: %v", err)
	}

	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read from the bot: %v", err)
	}
	resp = resp[:n]

	if string(resp) != "Loading page\n" {
		return fmt.Errorf("bad resp from the bot: %s", resp)
	}

	return nil
}

func (h *Handler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	log.Printf("Got contact request")
	respBody, statusCode, err := h.contact(req)
	resp.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
	if err != nil {
		log.Printf("Error with contact: %d, %s, %v", statusCode, respBody, err)
		resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		resp.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	resp.WriteHeader(statusCode)
	n, err := resp.Write(respBody)
	if err != nil {
		log.Printf("Error when writing response body (after %d bytes): %v", n, err)
	}
	log.Printf("Responded to contact request")
}
