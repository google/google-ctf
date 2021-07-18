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

// The tool command generates a client cert with the name from the --user flag
// and writes it to the file provided by the --output flag.
// The password of the output file is "changeit".
package main

import (
	"flag"
	"io/ioutil"
	"log"

	"example.com/empty-ls/central/clientcrtgen"
)

var user = flag.String("user", "", "The username to get a cert for.")
var output = flag.String("output", "client.p12", "The name of the file to write the generated client cert and key to. It should have the .p12 extension because it's a PKCS #12 file.")

func main() {
	flag.Parse()

	ccg, err := clientcrtgen.New()
	if err != nil {
		log.Fatalf("Failed to create client cert generator: %v", err)
	}

	crt, err := ccg.Generate(*user)
	if err != nil {
		log.Fatalf("Failed to generate cert: %s, %v", crt, err)
	}

	if err := ioutil.WriteFile(*output, crt, 0644); err != nil {
		log.Fatalf("Failed to write output file: %v", err)
	}
}
