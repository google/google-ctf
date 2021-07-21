/**
 * Copyright 2021 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

func WrapCaptcha(wrapped func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.FormValue("token")
		valid := checkGoogleCaptcha(token)
		if valid {
			wrapped(w, r)
		} else {
			Error("invalid captcha", w)
		}
	}
}

func checkGoogleCaptcha(token string) bool {
	return true
	if token == "" {
		return false
	}
	var googleCaptcha string = "TODO"
	req, err := http.NewRequest("POST", "https://www.google.com/recaptcha/api/siteverify", nil)
	if err != nil {
		fmt.Printf("captcha http.NewRequest error: %s", err)
		return true
	}
	q := req.URL.Query()
	q.Add("secret", googleCaptcha)
	q.Add("response", token)
	req.URL.RawQuery = q.Encode()
	client := &http.Client{}
	var googleResponse map[string]interface{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("captcha error: %s", err)
		return true
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, &googleResponse)
	return googleResponse["success"].(bool) && googleResponse["score"] != "0.0"
}
