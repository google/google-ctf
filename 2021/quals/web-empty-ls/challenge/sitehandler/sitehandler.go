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

package sitehandler

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"example.com/empty-ls/central/captcha"
	dns "google.golang.org/api/dns/v1"
)

var siteRegex = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
var punyRegex = regexp.MustCompile(`^..--`)

type Options struct {
	Captcha        *captcha.Checker // non-nil
	Domain         string           // Where subdomains will go under. e.g. example.com (no leading or trailing dot)
	DnsProject     string           // e.g. my-project
	DnsManagedZone string           // e.g. my-zone (not necessarily a domain name)
}

type Handler struct {
	// All non-nil
	badWords       *regexp.Regexp
	capt           *captcha.Checker
	dnsService     *dns.Service
	domain         string
	dnsProject     string
	dnsManagedZone string
}

func New(ctx context.Context, opt Options) (*Handler, error) {
	badWordsB64, err := ioutil.ReadFile("/home/user/bad_words.b64.txt")
	if err != nil {
		return nil, fmt.Errorf("Error reading the bad words file: %v", err)
	}
	badWordsContent, err := base64.StdEncoding.DecodeString(string(badWordsB64))
	if err != nil {
		return nil, fmt.Errorf("Error decoding the bad words file: %v", err)
	}
	badWordsContent = bytes.TrimRight(badWordsContent, "\n")
	// We assume words don't contain metacharacters. - is ok, because this isn't going in square
	// brackets.
	badWordsRegexBytes := bytes.ReplaceAll(badWordsContent, []byte{'\n'}, []byte{'|'})
	badWords, err := regexp.Compile(string(badWordsRegexBytes))
	if err != nil {
		return nil, fmt.Errorf("Error compiling bad words regex: %v", err)
	}

	dnsService, err := dns.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("Error creating DNS service: %v", err)
	}

	return &Handler{
		badWords:       badWords,
		capt:           opt.Captcha,
		dnsService:     dnsService,
		domain:         opt.Domain,
		dnsProject:     opt.DnsProject,
		dnsManagedZone: opt.DnsManagedZone,
	}, nil
}

// Returns respBody, statusCode, err. If err is nil, then statusCode is http.StatusOK and respBody
// contains an html body. Otherwise, respBody contains a plain text error message for the user,
// statusCode contains an error value, and err contains a specific error message not for the user,
// but to be logged together with respBody.
func (h *Handler) createSite(req *http.Request) ([]byte, int, error) {
	if req.Method != "POST" {
		return []byte("Needs POST"), http.StatusMethodNotAllowed, errors.New("error")
	}

	captchaToken := req.FormValue("g-recaptcha-response")
	if err := h.capt.Check(req.Context(), captchaToken); err != nil {
		return []byte("Bad captcha"), http.StatusBadRequest, err
	}

	site := req.FormValue("subdomain")
	site = strings.TrimSpace(site)
	if site == "" {
		return []byte("The subdomain cannot be empty."), http.StatusBadRequest, errors.New("error")
	}

	if !siteRegex.MatchString(site) {
		return []byte("The subdomain isn't in the proper format."), http.StatusBadRequest, errors.New("error")
	}

	if punyRegex.MatchString(site) {
		return []byte("We don't allow punycode."), http.StatusBadRequest, errors.New("error")
	}

	// This probably isn't necessary. "admin" and "www" would probably simply fail during the API call
	// below due to already being registered manually with Cloud DNS. But just in case that error
	// wouldn't happen, or if the challenge runners forgot to register them manually, this check is
	// here.
	// "administrator" is pointless, but let's put it in here anyways.
	// Ideally we would have a real database to remember which domain is registered, when, and by who
	// (aka, what client IP requested the registration). That's too much work, so this combo of manual
	// checks and hoping the API call will fail for duplicates should be good enough.
	if site == "admin" ||
		site == "www" ||
		site == "administrator" {
		return []byte("That site is already registered."), http.StatusBadRequest, errors.New("error")
	}

	if h.badWords.MatchString(site) {
		return []byte("The subdomain has a bad word."), http.StatusBadRequest, errors.New("error")
	}

	ipStr := req.FormValue("ip")
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return []byte("The ip cannot be empty."), http.StatusBadRequest, errors.New("error")
	}

	ip := net.ParseIP(ipStr)
	if len(ip) == 0 {
		return []byte("The ip has a bad format."), http.StatusBadRequest, errors.New("error")
	}

	var dnsType string
	if ip.To4() == nil {
		dnsType = "AAAA"
	} else {
		dnsType = "A"
	}

	change := &dns.Change{
		Additions: []*dns.ResourceRecordSet{
			{
				Name:    site + "." + h.domain + ".",
				Rrdatas: []string{ip.String()},
				Ttl:     300, // seconds
				Type:    dnsType,
			},
		},
	}
	changesCreateCall := h.dnsService.Changes.Create(h.dnsProject, h.dnsManagedZone, change)
	changesCreateCall.Context(req.Context())
	json, err := change.MarshalJSON()
	log.Printf("about to send: %s %v", json, err)
	change, err = changesCreateCall.Do()
	if err != nil {
		// The most likely cause of this is a record with the same name already existing.
		return []byte("Failed to create the DNS record. That subdomain must be taken."), http.StatusInternalServerError, err
	}
	json, err = change.MarshalJSON()
	log.Printf("finished change: %s, %v", json, err)

	// Ideally we might repeatedly query ChangeService.Get() with the change ID returned from Do().
	// until it returns non-pending. That's too much work.

	return []byte("Success"), http.StatusOK, nil
}

func (h *Handler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	log.Printf("Got new site request")
	respBody, statusCode, err := h.createSite(req)
	resp.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
	if err != nil {
		log.Printf("Error creating site: %d, %s, %v", statusCode, respBody, err)
		resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		resp.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	resp.WriteHeader(statusCode)
	n, err := resp.Write(respBody)
	if err != nil {
		log.Printf("Error when writing response body (after %d bytes): %v", n, err)
	}
	log.Printf("Responded to new site request")
}
