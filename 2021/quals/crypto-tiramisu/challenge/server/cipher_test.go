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

package server

import (
	"bytes"
	"testing"
)

var testSecret = []byte("Test master secret")
var testCipherKdfInfo = []byte("Cipher info")
var testMacKdfInfo = []byte("Mac info")

var testMessage = []byte("Hello World")
var testIV = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

func newTestAuthCipher(t *testing.T) *AuthCipher {
	authCipher, err := newAuthCipher(testSecret, testCipherKdfInfo, testMacKdfInfo)
	if err != nil {
		t.Fatal(err)
	}
	return authCipher
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	authCipher := newTestAuthCipher(t)
	ct, err := authCipher.Encrypt(testIV, testMessage)
	if err != nil {
		t.Errorf("authCipher.Encrypt(testIV, testMessage) = %v, want nil err", err)
	}
	pt, err := authCipher.Decrypt(ct)
	if err != nil {
		t.Errorf("authCipher.Decrypt(ct) = %v, want nil err", err)
	}
	if bytes.Compare(pt, testMessage) != 0 {
		t.Errorf("pt != testMessage, want %X got %X", testMessage, pt)
	}
}

func TestDecryptFailsOnModifiedCiphertext(t *testing.T) {
	authCipher := newTestAuthCipher(t)
	ct, err := authCipher.Encrypt(testIV, testMessage)
	if err != nil {
		t.Errorf("authCipher.Encrypt(testIV, testMessage) = %v, want nil err", err)
	}
	ct.Data[0] ^= 1
	_, err = authCipher.Decrypt(ct)
	if err == nil {
		t.Errorf("authCipher.Decrypt(ct) expected to fail on modified ciphertext")
	}
}

func TestDecryptFailsOnModifiedIV(t *testing.T) {
	authCipher := newTestAuthCipher(t)
	ct, err := authCipher.Encrypt(testIV, testMessage)
	if err != nil {
		t.Errorf("authCipher.Encrypt(testIV, testMessage) = %v, want nil err", err)
	}
	ct.Iv[0] ^= 1
	_, err = authCipher.Decrypt(ct)
	if err == nil {
		t.Errorf("authCipher.Decrypt(ct) expected to fail on modified IV")
	}
}

func TestDecryptFailsOnModifiedMac(t *testing.T) {
	authCipher := newTestAuthCipher(t)
	ct, err := authCipher.Encrypt(testIV, testMessage)
	if err != nil {
		t.Errorf("authCipher.Encrypt(testIV, testMessage) = %v, want nil err", err)
	}
	ct.Mac[0] ^= 1
	_, err = authCipher.Decrypt(ct)
	if err == nil {
		t.Errorf("authCipher.Decrypt(ct) expected to fail on modified MAC")
	}
}
