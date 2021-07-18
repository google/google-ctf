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
	"crypto-tiramisu/pb"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

type AuthCipher struct {
	aes    cipher.Block
	macKey []byte
}

func deriveKey(secret, info []byte) ([]byte, error) {
	hash := sha256.New
	hkdf := hkdf.New(hash, secret, nil, info)

	key := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, err
	}
	return key, nil
}

func newAuthCipher(secret, cipherInfo, macInfo []byte) (*AuthCipher, error) {
	var err error
	authCipher := &AuthCipher{}
	cipherKey, err := deriveKey(secret, cipherInfo)
	if err != nil {
		return nil, err
	}
	authCipher.aes, err = aes.NewCipher(cipherKey)
	if err != nil {
		return nil, err
	}
	authCipher.macKey, err = deriveKey(secret, macInfo)
	if err != nil {
		return nil, err
	}
	return authCipher, nil
}

func (authCipher *AuthCipher) Encrypt(iv, plaintext []byte) (*pb.Ciphertext, error) {
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("len(iv) != aes.BlockSize, want %d, got %d", aes.BlockSize, len(iv))
	}

	ciphertext := make([]byte, len(plaintext))

	stream := cipher.NewCTR(authCipher.aes, iv)
	stream.XORKeyStream(ciphertext, plaintext)

	mac := hmac.New(sha256.New, authCipher.macKey)
	mac.Write(iv)
	mac.Write(ciphertext)

	return &pb.Ciphertext{
		Iv:   iv,
		Data: ciphertext,
		Mac:  mac.Sum(nil),
	}, nil
}

func (authCipher *AuthCipher) Decrypt(ciphertext *pb.Ciphertext) ([]byte, error) {
	if len(ciphertext.Iv) != aes.BlockSize {
		return nil, fmt.Errorf("len(iv) != aes.BlockSize, want %d, got %d", aes.BlockSize, len(ciphertext.Iv))
	}
	mac := hmac.New(sha256.New, authCipher.macKey)
	mac.Write(ciphertext.Iv)
	mac.Write(ciphertext.Data)
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(ciphertext.Mac, expectedMAC) {
		return nil, fmt.Errorf("mac mismatch, want %x, got %x", expectedMAC, ciphertext.Mac)
	}

	plaintext := make([]byte, len(ciphertext.Data))
	stream := cipher.NewCTR(authCipher.aes, ciphertext.Iv)
	stream.XORKeyStream(plaintext, ciphertext.Data)

	return plaintext, nil
}
