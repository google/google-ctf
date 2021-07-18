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
	"crypto/rand"
	"crypto/sha1"
	"io"
	"math/big"
)

const m0 = "Server says 1+1=2"
const m1 = "Server says 1+1=3"

func hashMessage(m string) []byte {
	h := sha1.New()
	io.WriteString(h, m)
	return h.Sum(nil)
}

type Challenger struct {
	flag string
	sk   *ecdsa.PrivateKey
}

func NewChallenger(flag string) (*Challenger, error) {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Challenger{
		flag: flag,
		sk:   sk,
	}, nil
}

func (chal *Challenger) Hello(req *pb.HelloRequest) *pb.HelloResponse {
	return &pb.HelloResponse{
		Message0: m0,
		Message1: m1,
		Pubkey: &pb.Point{
			X: chal.sk.PublicKey.X.Bytes(),
			Y: chal.sk.PublicKey.Y.Bytes(),
		},
	}
}

func (chal *Challenger) scalePrivate(t *big.Int) *ecdsa.PrivateKey {
	rk := new(big.Int).Mul(chal.sk.D, t)
	rk.Mod(rk, chal.sk.PublicKey.Curve.Params().N)

	ret := new(ecdsa.PrivateKey)
	ret.PublicKey.Curve = chal.sk.PublicKey.Curve
	ret.D = rk
	ret.PublicKey.X, ret.PublicKey.Y = chal.sk.PublicKey.Curve.ScalarBaseMult(ret.D.Bytes())
	return ret
}

func (chal *Challenger) SignFirstMessage(req *pb.SignRequest) *pb.SignResponse {
	t := new(big.Int).SetBytes(req.Scalar)
	r, s, err := ecdsa.Sign(rand.Reader, chal.scalePrivate(t), hashMessage(m0))
	if err != nil {
		return &pb.SignResponse{}
	}
	return &pb.SignResponse{
		Message0Sig: &pb.Signature{
			R: r.Bytes(),
			S: s.Bytes(),
		},
	}
}

func (chal *Challenger) VerifySecondMessage(req *pb.VerifyRequest) *pb.VerifyResponse {
	r := new(big.Int).SetBytes(req.Message1Sig.R)
	s := new(big.Int).SetBytes(req.Message1Sig.S)

	ok := ecdsa.Verify(&chal.sk.PublicKey, hashMessage(m1), r, s)
	if !ok {
		return &pb.VerifyResponse{}
	}

	return &pb.VerifyResponse{Flag: chal.flag}
}
