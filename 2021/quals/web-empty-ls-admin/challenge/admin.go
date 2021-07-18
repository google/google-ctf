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

// The admin command runs the admin site.
//
// This code listens on port 8443, so it needs something like socat to listen on port 443 and proxy
// traffic here.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"
)

// port is the port to listen on.
const port = 8443

// handler handles the incoming HTTP requests.
type handler struct {
	flag string // No whitespace (so no newline)
}

// getRespBody returns a plain text string to be returned in the body of the HTTP response.
func (h *handler) getRespBody(req *http.Request) string {
	if req.TLS == nil {
		// It's unclear if this can ever happen.
		return "Error, there was no TLS.\n"
	}

	if len(req.TLS.PeerCertificates) == 0 {
		return "You are not logged in.\n"
	}

	// If there are multiple certificates, just take the first one, which is the leaf.
	// This is not expected to ever happen because we don't issue intermediate CA certs.
	user := req.TLS.PeerCertificates[0].Subject.CommonName

	if user == "" {
		// This should never happen, we don't issue certs with empty usernames.
		return "Error the username was empty.\n"
	}

	if user == "admin" {
		// The space before the period is intentional. It aids with copy and pasting.
		return "Hello, admin. The flag is: " + h.flag + " .\n"
	}
	return "Hello, " + user + ". You are not the admin.\n"
}

// ServeHTTP is the top level HTTP handler function.
func (h *handler) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	log.Print("Got req")

	if req.URL.Path != "/" {
		log.Print("Bad path")
		http.NotFound(resp, req)
		return
	}

	body := h.getRespBody(req)
	log.Print(body)
	resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
	resp.Header().Set("Content-Length", strconv.Itoa(len(body)))
	resp.WriteHeader(http.StatusOK)
	resp.Write([]byte(body))
	log.Print("Done")
}

// clientCAPool consructs a CertPool containing the client CA.
func clientCAPool() (*x509.CertPool, error) {
	caCertPem, err := ioutil.ReadFile("clientca.crt.pem")
	if err != nil {
		return nil, fmt.Errorf("error reading clientca cert: %v", err)
	}
	caCertBlock, rest := pem.Decode(caCertPem)
	if caCertBlock == nil || len(rest) > 0 {
		return nil, fmt.Errorf("error decoding clientca cert PEM block. caCertBlock: %v, len(rest): %d", caCertBlock, len(rest))
	}
	if caCertBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("clientca cert had a bad type: %s", caCertBlock.Type)
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing clientca cert ASN.1 DER: %v", err)
	}

	cas := x509.NewCertPool()
	cas.AddCert(caCert)
	return cas, nil
}

func main() {
	clientCAPool, err := clientCAPool()
	if err != nil {
		log.Fatalf("Failed to create client CA pool: %v", err)
	}

	s := http.Server{
		Addr: fmt.Sprintf(":%d", port),
		TLSConfig: &tls.Config{
			ClientAuth: tls.VerifyClientCertIfGiven,
			ClientCAs:  clientCAPool,
		},
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 14,
	}

	flag, err := ioutil.ReadFile("flag")
	if err != nil {
		log.Fatalf("Failed to read the flag file: %v", err)
	}

	http.Handle("/", &handler{flag: string(flag)})

	log.Printf("About to listen on %d", port)
	err = s.ListenAndServeTLS("zone443.dev.fullchain.crt.pem", "zone443.dev.key.pem")
	log.Printf("Serving is over: %v", err)
}
