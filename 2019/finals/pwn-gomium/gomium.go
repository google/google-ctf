/*
Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Browser for the Web 3.0.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"go/parser"
	"go/printer"
	"go/token"
	"html"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var flagService = flag.Bool("service", false, "Run as service.")

func main() {
	flag.Parse()
	if err := launch(); err != nil {
		log.Fatal(err)
	}
}

func launch() error {
	dest := "about:blank"
	if *flagService {
		fmt.Printf("Where are we surfing today? ")
		to, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return err
		}
		if to := strings.TrimSpace(to); to != "" {
			dest = to
		}
	} else if flag.NArg() > 0 {
		dest = flag.Arg(0)
	}
	return browse(dest)
}

func browse(uri string) error {
	title := "Gomium Browser"
	page, err := render(uri)
	if err != nil {
		title = fmt.Sprintf("Error | %s", title)
		page = err.Error()
	}
	const width = 75  // + 4 for borders
	const height = 14 // + 6 for borders and interface
	fmt.Printf("┏━%s━┓\n", strings.Repeat("━", width))
	fmt.Printf("┃ %s ┃\n", center(title, width))
	fmt.Printf("┣━━━━━━━┳━%s━┫\n", strings.Repeat("━", width-8))
	if strings.HasPrefix(uri, "https://") {
		fmt.Printf("┃ ← → ↻ ┃ 🔒 %s ┃\n", left(uri, width-11))
	} else {
		fmt.Printf("┃ ← → ↻ ┃ %s ┃\n", left(uri, width-8))
	}
	fmt.Printf("┣━━━━━━━┻━%s━┫\n", strings.Repeat("━", width-8))
	for _, line := range wordwrap(textify(page), width, height) {
		fmt.Printf("┃ %s ┃\n", left(line, width))
	}
	fmt.Printf("┗━%s━┛\n", strings.Repeat("━", width))
	return nil
}

func center(text string, width int) string {
	textLength := stringLength(text)
	if textLength >= width {
		return text[:width]
	}
	left := width/2 - textLength/2
	right := width - left - textLength
	return fmt.Sprintf("%s%s%s", strings.Repeat(" ", left), text, strings.Repeat(" ", right))
}

func left(text string, width int) string {
	textLength := stringLength(text)
	if textLength >= width {
		return text[:width]
	}
	right := width - textLength
	return fmt.Sprintf("%s%s", text, strings.Repeat(" ", right))
}

var runeLengths = map[rune]int{
	'👤': 2,
	'🔑': 2,
	'💳': 2,
	'📌': 2,
	'🔍': 2,
	'✅': 2,
	'🎉': 2,
	'⚠': 1,
	'⇒': 1,
	'⭧': 1,
	'⮕': 1,
	'☐': 1,
	'┏': 1,
	'┗': 1,
	'┓': 1,
	'┛': 1,
	'┃': 1,
	'━': 1,
	'┣': 1,
	'┫': 1,
	'┳': 1,
	'┻': 1,
}

func runeLength(r rune) int {
	if n, ok := runeLengths[r]; ok {
		return n
	}
	return 1
}

func stringLength(s string) int {
	n := 0
	for _, r := range s {
		n += runeLength(r)
	}
	return n
}

func printable(r rune) bool {
	if r >= ' ' && r <= '~' {
		return true
	}
	if _, ok := runeLengths[r]; ok {
		return true
	}
	return false
}

func wordwrap(text string, width int, height int) []string {
	var lines []string
	var buf bytes.Buffer
	for _, r := range text {
		if r == '\n' {
			lines = append(lines, buf.String())
			buf.Reset()
			if len(lines) == height {
				return lines
			}
			continue
		}
		if !printable(r) {
			r = '.'
		}
		buf.WriteRune(r)
		if stringLength(buf.String()) >= width {
			lines = append(lines, buf.String())
			buf.Reset()
			if len(lines) == height {
				return lines
			}
		}
	}
	if buf.Len() > 0 {
		lines = append(lines, buf.String())
	}
	for i := len(lines); i < height; i++ {
		lines = append(lines, "")
	}
	return lines
}

var (
	bodyRE     = regexp.MustCompile(`(?s)<body[^>]*>(.*)</body>`)
	scriptRE   = regexp.MustCompile(`(?s)<script[^>]*>.*?</script>`)
	styleRE    = regexp.MustCompile(`(?s)<style[^>]*>.*?</style>`)
	htmlTagsRE = regexp.MustCompile(`<[^>]*>`)
)

func textify(s string) string {
	if m := bodyRE.FindStringSubmatch(s); len(m) == 2 {
		s = m[1]
	}
	s = scriptRE.ReplaceAllString(s, "")
	s = styleRE.ReplaceAllString(s, "")
	s = htmlTagsRE.ReplaceAllString(s, "")
	s = strings.Replace(s, "&nbsp;", " ", -1) // avoid \u00a0
	s = html.UnescapeString(s)
	s = strings.Replace(s, "\t", "  ", -1)
	return s
}

func render(uri string) (string, error) {
	page, err := fetch(uri)
	if err != nil {
		return "", err
	}
	html, err := runScripts(page)
	if err != nil {
		return "", fmt.Errorf("Aw, Snap!\n\n%v", err)
	}
	return html, nil
}

var httpClient = &http.Client{
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 5 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       5 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

const (
	aboutBlank = `               ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓               
               ┃   Welcome to the Gomium Browser! 🎉  ┃
               ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

Tired of slow browsers and bloated websites? We too!

Together, let's build the Web 3.0 to make the world a better place.

                       [Start navigation]


 ⇒ Search the web (https://google.com/)
 ⇒ Gomium Settings (gomium://settings)
 ⇒ Gomium Version (gomium://version)
`
	googleSearch = `                     _____                   _      
                    / ____|                 | |     
                   | |  __  ___   ___   __ _| | ___ 
                   | | |_ |/ _ \ / _ \ / _` + "`" + ` | |/ _ \
                   | |__| | (_) | (_) | (_| | |  __/
                    \_____|\___/ \___/ \__, |_|\___|
                                        __/ |       
                                       |___/        

               ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓               
               ┃ 🔍                                      ┃
               ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
                 [Google Search]     [I'm Feeling Lucky]
`
	gomiumSettings = `                       ┏━━━━━━━━━━━━━━━━━━━━┓
                       ┃ 🔍 Search settings ┃
                       ┗━━━━━━━━━━━━━━━━━━━━┛

People
━━━━━━
👤 Person 1                    ⮕
Sync and Gomium services       ⮕
Import bookmarks and settings  ⮕

Autofill
━━━━━━━━
🔑 Passwords                   ⮕
💳 Payment methods             ⮕
📌 Addresses and more          ⮕
`
	gomiumVersion = `                          ┏━━━━━━━━━━━━━━┓
                          ┃ About Gomium ┃
                          ┗━━━━━━━━━━━━━━┛

Gomium Browser is up to date

✅  Version 31.3.3.7 (Official Build) (64-bit)

Get help with Gomium   ⭧
Report an issue        ⭧
`
	insecureWarning = `
                  ⚠  Your connection is not private ⚠                    


Attackers might be trying to steal your information (for example,
passwords, messages, credit cards, or exploits). [Learn more]

☐ Help improve Safe Browsing by sending information. [Privacy Policy]


[Advanced]                                                [Back to safety]

`
)

func fetch(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", errors.New("invalid URL")
	}
	switch u.Scheme {
	case "file":
		if *flagService {
			return "", errors.New("404 Not Found")
		}
		b, err := ioutil.ReadFile(u.Path)
		if err != nil {
			return "", err
		}
		return string(b), nil

	case "about":
		switch u.String() {
		case "about:blank":
			return aboutBlank, nil
		}
		return "", errors.New("404 Not Found")

	case "gomium":
		switch u.String() {
		case "gomium://settings":
			return gomiumSettings, nil
		case "gomium://version":
			return gomiumVersion, nil
		}
		return "", errors.New("404 Not Found")

	case "http":
		return "", errors.New(insecureWarning)

	case "https":
		if (u.Host == "google.com" || u.Host == "www.google.com") &&
			(u.Path == "" || u.Path == "/") {
			return googleSearch, nil
		}
		// fallthrough

	default:
		return "", errors.New("invalid URL")
	}
	resp, err := httpClient.Get(u.String())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func runScripts(page string) (string, error) {
	const start = `<script type="text/goscript">`
	const end = `</script>`
	var buf bytes.Buffer
	for {
		p := strings.Index(page, start)
		if p == -1 {
			break
		}
		buf.WriteString(page[:p])
		page = page[p:]
		p = strings.Index(page, end)
		if p == -1 {
			break
		}
		out, err := sanitizeAndRun(page[len(start):p])
		if err != nil {
			return "", err
		}
		buf.WriteString(out)
		page = page[p+len(end):]
	}
	buf.WriteString(page)
	return buf.String(), nil
}

func sanitizeAndRun(script string) (string, error) {
	code, err := sanitize(script)
	if err != nil {
		return "", err
	}
	return run(code)
}

func sanitize(script string) (string, error) {
	fs := token.NewFileSet()
	file, err := parser.ParseFile(fs, "", script, parser.AllErrors)
	if err != nil {
		return "", err
	}
	for _, s := range file.Imports {
		switch s.Path.Value {
		case `"fmt"`:
		default:
			return "", fmt.Errorf("import %v not allowed", s.Path.Value)
		}
	}
	var b bytes.Buffer
	if err := printer.Fprint(&b, fs, file); err != nil {
		return "", err
	}
	return b.String(), nil
}

func run(script string) (string, error) {
	dir, err := ioutil.TempDir("", "gobrowser")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	source := filepath.Join(dir, "main.go")
	if err := ioutil.WriteFile(source, []byte(script), 0600); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", source)
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("timeout: %v", err)
		}
		return "", err
	}
	binary := filepath.Join(dir, "main")
	out, err := exec.CommandContext(ctx, binary).CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("timeout: %v", err)
		}
		return "", err
	}
	return string(out), nil
}
