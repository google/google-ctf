// Copyright 2022 Google LLC
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
package main

import (
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
)

type staticFiles map[string]string

func (m *staticFiles) String() string {
	return "List of files to serve"
}

func (m *staticFiles) Set(value string) error {
	parts := strings.Split(value, "=")
	if len(parts) == 2 {
		(*m)[parts[0]] = parts[1]
	} else {
		(*m)[path.Base(value)] = value
	}
	return nil
}

var (
	portFlag    = flag.Int("port", 1337, "Server HTTP port number")
	captureFlag = flag.String("capture", "traces.json.gz", "Capture file to load")
	staticsFlag = make(staticFiles)
)

type Trace struct {
	Ct                []byte    `json:"ct"`
	FlagXorSS         []byte    `json:"flag_xor_ss"`
	PowerMeasurements []float64 `json:"pm"`
}

type TraceMetadata struct {
	Id         int    `json:"Id"`
	Ct         string `json:"CT"`
	FlagXorSS  string `json:"FlagXorSS"`
	NumSamples int    `json:"NumSamples"`
}

type CaptureMetadata struct {
	Pk     string          `json:"Pk"`
	Traces []TraceMetadata `json:"Traces"`
}

type Capture struct {
	Pk     []byte  `json:"pk"`
	Traces []Trace `json:"sessions"`
}

func loadCaptureIo(src io.Reader) (*Capture, error) {
	capture := &Capture{}
	zipper, err := gzip.NewReader(src)
	if err != nil {
		return nil, fmt.Errorf("gzip NewReader failed %v", err)
	}
	decoder := json.NewDecoder(zipper)
	if err = decoder.Decode(capture); err != nil {
		return nil, fmt.Errorf("JSON decoder failed %v", err)
	}
	return capture, nil
}

func loadCapture(filename string) (*Capture, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("Error opening capture file: %v", err)
	}
	defer f.Close()
	return loadCaptureIo(f)
}

func main() {
	flag.Var(&staticsFlag, "static", "List of static files to serve.")
	flag.Parse()
	e := echo.New()

	capture, err := loadCapture(*captureFlag)
	if err != nil {
		e.Logger.Fatal(err)
		return
	}

	// Static files.
	e.File("/", "index.html")
	e.File("/viewer.js", "viewer.js")
	e.File("/viewer.css", "viewer.css")
	for k, v := range staticsFlag {
		e.File("/"+k, v)
	}

	// Returns list of static files.
	e.GET("/files", func(c echo.Context) error {
		var files []string
		for k := range staticsFlag {
			files = append(files, k)
		}
		return c.JSON(http.StatusOK, files)
	})

	// Returns trace data from a single capture file.
	e.GET("/data", func(c echo.Context) error {
		var metadata CaptureMetadata
		metadata.Pk = hex.EncodeToString(capture.Pk)
		for i, t := range capture.Traces {
			metadata.Traces = append(metadata.Traces, TraceMetadata{i,
				hex.EncodeToString(t.Ct),
				hex.EncodeToString(t.FlagXorSS),
				len(t.PowerMeasurements)})
		}
		return c.JSON(http.StatusOK, metadata)
	})
	e.GET("/data/:trace", func(c echo.Context) error {
		trace, err := strconv.Atoi(c.Param("trace"))
		if err != nil || trace < 0 || trace >= len(capture.Traces) {
			return c.String(http.StatusInternalServerError, "Invalid trace")
		}
		return c.JSON(http.StatusOK, capture.Traces[trace].PowerMeasurements)
	})

	e.Logger.Fatal(e.Start(fmt.Sprintf("0.0.0.0:%d", *portFlag)))
}
