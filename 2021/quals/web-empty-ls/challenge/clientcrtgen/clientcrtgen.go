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

package clientcrtgen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"regexp"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// Some people say all-numeric names should be banned. Who cares.
var userRegex = regexp.MustCompile(`^[a-z0-9]+$`)

// https://golang.org/src/crypto/tls/generate_cert.go
// https://shaneutt.com/blog/golang-ca-and-signed-cert-go/
type Generator struct {
	// Both non-nil
	caCert    *x509.Certificate
	caPrivKey *rsa.PrivateKey
}

func New() (*Generator, error) {
	caCertPem, err := ioutil.ReadFile("/home/user/clientca.crt.pem")
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

	caPrivKeyPem, err := ioutil.ReadFile("/home/user/clientca.key.pem")
	if err != nil {
		return nil, fmt.Errorf("Error reading clientca key: %v", err)
	}
	caPrivKeyBlock, rest := pem.Decode(caPrivKeyPem)
	if caPrivKeyBlock == nil || len(rest) > 0 {
		return nil, fmt.Errorf("Error decoding clientca key PEM block. caPrivKeyBlock: %v, len(rest): %d", caPrivKeyBlock, len(rest))
	}
	// openssl creates files with PRIVATE KEY of type PKCS #8
	if caPrivKeyBlock.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("clientca key had a bad type: %s", caPrivKeyBlock.Type)
	}
	caPrivKey, err := x509.ParsePKCS8PrivateKey(caPrivKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Error parsing clientca key PKCS #8 ASN.1 DER: %v", err)
	}
	caPrivKeyRsa, ok := caPrivKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("clientca key wasn't rsa, it was %T", caPrivKey)
	}

	return &Generator{
		caCert:    caCert,
		caPrivKey: caPrivKeyRsa,
	}, nil
}

// Generate generates PKCS #12 cert and private key for the given user.
// This verifies that user contains only valid characters and isn't empty,
// but doesn't prevent names such as admin or www.
// The password of the returned cert+key is "changeit".
//
// If the returned error is non-nil, the []byte has a plain text error
// message that should be given to the user and logged, and the returned error
// should be logged as well, but not given to the user.
func (g *Generator) Generate(user string) ([]byte, error) {
	if user == "" {
		return []byte("The user cannot be empty."), errors.New("error")
	}

	if !userRegex.MatchString(user) {
		return []byte("The user has a bad character."), errors.New("error")
	}

	serialNumberLimit := (&big.Int{}).Lsh(big.NewInt(1), 160)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return []byte("Bad serial number generation"), err
	}

	now := time.Now()
	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: user,
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return []byte("Bad RSA generation"), err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, g.caCert, &privKey.PublicKey, g.caPrivKey)
	if err != nil {
		return []byte("Bad certificate generation"), err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return []byte("Bad certificate parsing"), err
	}

	pkcs12Bytes, err := pkcs12.Encode(rand.Reader, privKey, cert, nil, pkcs12.DefaultPassword)
	if err != nil {
		return []byte("Bad PKCS #12 generation"), err
	}

	return pkcs12Bytes, nil
}
