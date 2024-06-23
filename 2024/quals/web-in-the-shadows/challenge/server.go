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
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// The naming of the variables below is not really idiomatic Go,
// but probably will be easier to grasp for people who don't know Go very well.

var (
	//go:embed js/*.js
	JS_FS embed.FS
	//go:embed views/*.html
	HTML_FS embed.FS
	//go:embed style.css
	CSS_FS embed.FS

	TEMPLATES              = template.Must(template.ParseFS(HTML_FS, "views/*.html"))
	INDEX_TMPL             = TEMPLATES.Lookup("index.html")
	SHARE_TMPL             = TEMPLATES.Lookup("share.html")
	ADMIN_COOKIE_NAME      = "session"
	ADMIN_BYTE             = byte(0x11)
	NON_ADMIN_BYTE         = byte(0x00)
	SECRET_PAYLOAD_LEN     = 24
	SECRET_LEN             = len(generateSecret(false, 0))
	NONCE_LEN              = 25
	PUBLIC_ORIGIN          = "https://in-the-shadows-web.2024.ctfcompetition.com"
	SECRET_EXPIRATION_TIME = 5 * time.Minute
	BOT_TIMEOUT            = 5 * time.Second

	//go:embed admin_cookie_value.txt
	ADMIN_COOKIE_VALUE string
	//go:embed hmac_key.txt
	HMAC_KEY []byte
	//go:embed flag.txt
	FLAG string
)

func computeHMAC(data []byte) []byte {
	mac := hmac.New(sha256.New, HMAC_KEY)
	mac.Write(data)
	return mac.Sum(nil)
}

func randomBytes(length int) []byte {
	r := make([]byte, length)
	_, err := rand.Read(r)
	if err != nil {
		panic(err)
	}

	return r
}

func generateNonce() string {
	return hex.EncodeToString(randomBytes(NONCE_LEN))
}

func generateSecret(isAdmin bool, expirationTime uint64) string {
	BYTE_LEN := 1
	TIMESTAMP_LEN := 8
	randomPartLength := SECRET_PAYLOAD_LEN - BYTE_LEN - TIMESTAMP_LEN

	buf := &bytes.Buffer{}
	if isAdmin {
		buf.WriteByte(ADMIN_BYTE)
	} else {
		buf.WriteByte(NON_ADMIN_BYTE)
	}

	buf.Write(randomBytes(randomPartLength))
	binary.Write(buf, binary.LittleEndian, expirationTime)
	payload := buf.Bytes()
	return hex.EncodeToString(payload) + hex.EncodeToString(computeHMAC(payload))
}

func parseSecret(secret string) (valid bool, isAdmin bool) {
	if len(secret) != SECRET_LEN {
		return false, false
	}
	s, err := hex.DecodeString(secret)
	if err != nil {
		return false, false
	}
	payload := s[:SECRET_PAYLOAD_LEN]
	gotHmac := s[SECRET_PAYLOAD_LEN:]
	wantHmac := computeHMAC(payload)
	if !hmac.Equal(gotHmac, wantHmac) {
		return false, false
	}
	timestampBytes := payload[len(payload)-8:]
	timestamp := binary.LittleEndian.Uint64(timestampBytes)
	now := uint64(time.Now().Unix())
	if timestamp < now {
		// Token expired.
		return false, false
	}
	return true, payload[0] == ADMIN_BYTE
}

type templateData struct{ Nonce, Secret, HTML, RecaptchaSiteKey string }

func isAdminRequest(r *http.Request) bool {
	cookie, err := r.Cookie(ADMIN_COOKIE_NAME)
	if err != nil {
		return false
	}
	return cookie.Value == ADMIN_COOKIE_VALUE
}

func generateTemplateData(r *http.Request, recaptchaSiteKey string) *templateData {
	time := time.Now().Add(SECRET_EXPIRATION_TIME).Unix()
	return &templateData{
		Nonce:            generateNonce(),
		Secret:           generateSecret(isAdminRequest(r), uint64(time)),
		RecaptchaSiteKey: recaptchaSiteKey,
	}
}

func addHeaders(w http.ResponseWriter, data *templateData) {
	csp := fmt.Sprintf("script-src 'nonce-%s'", data.Nonce)
	w.Header().Add("Content-Security-Policy", csp)
	w.Header().Add("Cache-Control", "no-cache")
}

func sendToBot(host, port, url string) error {
	addr := host + ":" + port
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(BOT_TIMEOUT))

	buf := make([]byte, 128)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		msg := string(buf[:n])
		if strings.TrimSpace(msg) == "Please send me a URL to open." {
			conn.Write([]byte(url))
			conn.Write([]byte{'\n'})
			return nil
		}
	}
}

type recaptchaResponse struct {
	Success bool `json:"success"`
}

func isValidRecaptcha(token, recaptchaSecretKey string) bool {
	URL := "https://www.google.com/recaptcha/api/siteverify"
	form := url.Values{
		"secret":   {recaptchaSecretKey},
		"response": {token},
	}
	resp, err := http.PostForm(URL, form)
	if err != nil {
		panic(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	recaptchaResponse := &recaptchaResponse{}
	err = json.Unmarshal(body, recaptchaResponse)
	if err != nil {
		panic(err)
	}
	return recaptchaResponse.Success
}

func main() {
	http.Handle("/js/", http.FileServerFS(JS_FS))
	http.Handle("/style.css", http.FileServerFS(CSS_FS))

	recaptchaSiteKey := os.Getenv("RECAPTCHA_SITE_KEY")
	recaptchaSecretKey := os.Getenv("RECAPTCHA_SECRET_KEY")

	http.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		data := generateTemplateData(r, recaptchaSiteKey)
		addHeaders(w, data)
		INDEX_TMPL.Execute(w, data)
	})

	http.HandleFunc("/share", func(w http.ResponseWriter, r *http.Request) {
		data := generateTemplateData(r, recaptchaSiteKey)
		data.HTML = r.URL.Query().Get("body")
		addHeaders(w, data)
		SHARE_TMPL.Execute(w, data)
	})

	http.HandleFunc("/check-secret", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "text/plain;charset=utf-8")
		secret := r.URL.Query().Get("secret")
		valid, isAdmin := parseSecret(secret)
		if !valid {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Invalid secret"))
			return
		}
		if !isAdmin {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Valid secret but it doesn't belong to the admin!"))
			return
		}
		// Now you got it!
		w.Write([]byte(FLAG))
	})

	botPort := os.Getenv("XSSBOT_PORT")
	botHost := os.Getenv("XSSBOT_HOST")
	fmt.Println("XSSBOT_HOST", botHost)
	fmt.Println("XSSBOT_PORT", botPort)

	http.HandleFunc("/share-with-admin", func(w http.ResponseWriter, r *http.Request) {
		if botHost == "" || botPort == "" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("xssbot not configured"))
			return
		}
		recaptcha := r.URL.Query().Get("recaptcha")
		if !isValidRecaptcha(recaptcha, recaptchaSecretKey) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("bad recaptcha"))
			return
		}

		body := r.URL.Query().Get("body")
		url := fmt.Sprintf("%s/share?body=%s", PUBLIC_ORIGIN, url.QueryEscape(body))

		err := sendToBot(botHost, botPort, url)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("not ok"))
		} else {
			w.Write([]byte("ok"))
		}
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "1337"
	}
	addr := fmt.Sprintf(":%s", port)
	fmt.Println("Listening on", addr)
	err := http.ListenAndServe(addr, nil)
	if err != nil {
		fmt.Println(err)
	}
}
