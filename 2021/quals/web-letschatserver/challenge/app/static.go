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
	"fmt"
	"io/ioutil"
	"net/http"
)

type Static struct {
	files map[string]string
}

func (s *Static) Handle(w http.ResponseWriter, r *http.Request) {
	var contentType string
	key := r.URL.Path
	switch r.URL.Path {
	case "/", "/index.html":
		contentType = "text/html"
		key = "/index.html"
	case "/style.css":
		contentType = "text/css"
	case "/app.js":
		contentType = "text/javascript;charset=UTF-8"
	case "/icon.png":
		contentType = "image/png"
	default:
		Error("ERROR", w)
		return
	}
	w.Header().Set("Content-Type", contentType)
	fmt.Fprintf(w, "%s", s.files[key])
}

func NewStatic() (*Static, error) {
	files := map[string]string{}
	for _, file := range []string{"/app.js", "/index.html", "/style.css", "/icon.png"} {
		a, err := ioutil.ReadFile("./static" + file)
		if err != nil {
			return nil, err
		}
		files[file] = string(a)
	}
	return &Static{files: files}, nil

}
