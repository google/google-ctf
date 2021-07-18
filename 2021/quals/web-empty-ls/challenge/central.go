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

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"example.com/empty-ls/central/captcha"
	"example.com/empty-ls/central/contacthandler"
	"example.com/empty-ls/central/sitehandler"
	"example.com/empty-ls/central/userhandler"
)

const port = 8443
const domain = "zone443.dev"

func main() {
	s := http.Server{
		Addr:           fmt.Sprintf(":%d", port),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 14,
	}

	ctx := context.Background()
	const project = "your-project"

	const captchaSiteKey = "your_site_key"
	capt, err := captcha.New(ctx, captchaSiteKey, project)
	if err != nil {
		log.Fatalf("Error creating captcha client: %v", err)
	}

	newUserHandler, err := userhandler.New(capt)
	if err != nil {
		log.Fatalf("Error creating user handler: %v", err)
	}
	http.Handle("/new_user", newUserHandler)

	newSiteHandler, err := sitehandler.New(ctx, sitehandler.Options{
		Captcha:        capt,
		Domain:         domain,
		DnsProject:     project,
		DnsManagedZone: "empty-ls-real-zone",
	})
	if err != nil {
		log.Fatalf("Error creating site handler: %v", err)
	}
	http.Handle("/new_site", newSiteHandler)

	contactHandler, err := contacthandler.New(domain, capt)
	if err != nil {
		log.Fatalf("Error creating contact handler: %v", err)
	}
	http.Handle("/contact", contactHandler)

	http.Handle("/", http.FileServer(http.Dir("/home/user/static")))

	log.Printf("About to listen on %d", port)
	err = s.ListenAndServeTLS("/home/user/zone443.dev.fullchain.crt.pem", "/home/user/zone443.dev.key.pem")
	log.Printf("Serving is over: %v", err)
}
