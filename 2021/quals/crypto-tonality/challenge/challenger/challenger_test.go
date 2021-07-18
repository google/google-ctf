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

package challenger

import (
	"crypto-tonality/pb"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"
)

var testFlag = "hello"

// Copied from ecdsa.go
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func TestSignWithZeroScalarFails(t *testing.T) {
	chal, err := NewChallenger(testFlag)
	if err != nil {
		t.Errorf("NewChallenger failed: %s", err)
		return
	}

	for _, a := range []*big.Int{new(big.Int).SetInt64(0), elliptic.P256().Params().N} {
		res := chal.SignFirstMessage(&pb.SignRequest{Scalar: a.Bytes()})
		if res.Message0Sig != nil {
			t.Errorf("SignFirstMessage expected to fail, got %+v", res)
		}
	}
}

func TestSignWithOneScalarSucceeds(t *testing.T) {
	chal, err := NewChallenger(testFlag)
	if err != nil {
		t.Errorf("NewChallenger failed: %s", err)
		return
	}

	hello := chal.Hello(&pb.HelloRequest{})
	pk := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(hello.Pubkey.X),
		Y:     new(big.Int).SetBytes(hello.Pubkey.Y),
	}

	a := new(big.Int).SetInt64(1)
	res := chal.SignFirstMessage(&pb.SignRequest{Scalar: a.Bytes()})
	r := new(big.Int).SetBytes(res.Message0Sig.R)
	s := new(big.Int).SetBytes(res.Message0Sig.S)
	ok := ecdsa.Verify(pk, hashMessage(hello.Message0), r, s)
	if !ok {
		t.Errorf("ecdsa.Verify failed to verify m0 signature")
	}
}

// Section 4.2 in https://eprint.iacr.org/2015/1135
// "On the Security of the Schnorr Signature Scheme and DSA against Related-Key Attacks"
// Hiraku Morita and Jacob C.N. Schuldt and Takahiro Matsuda and Goichiro Hanaoka and Tetsu Iwata
func TestRelatedKeyAttack(t *testing.T) {
	chal, err := NewChallenger(testFlag)
	if err != nil {
		t.Errorf("NewChallenger failed: %s", err)
		return
	}

	hello := chal.Hello(&pb.HelloRequest{})
	z0 := hashToInt(hashMessage(hello.Message0), elliptic.P256())
	z1 := hashToInt(hashMessage(hello.Message1), elliptic.P256())
	n := elliptic.P256().Params().N

	// a <- z0 / z1 mod N
	a := new(big.Int)
	a.Mul(z0, new(big.Int).ModInverse(z1, n))
	a.Mod(a, n)

	// Query signing oracle.
	sig := chal.SignFirstMessage(&pb.SignRequest{Scalar: a.Bytes()})
	r := new(big.Int).SetBytes(sig.Message0Sig.R)
	s := new(big.Int).SetBytes(sig.Message0Sig.S)

	// s <- s / a mod N
	s.Mul(s, new(big.Int).ModInverse(a, n))
	s.Mod(s, n)

	// Send forged signature for m1.
	res := chal.VerifySecondMessage(&pb.VerifyRequest{
		Message1Sig: &pb.Signature{
			R: r.Bytes(),
			S: s.Bytes(),
		},
	})

	if res.Flag != testFlag {
		t.Errorf("VerifySecondMessage did not return the flag")
	}
}
