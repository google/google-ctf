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
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
)

func proto2ecdsaKey(key *pb.EcdhKey) (*ecdsa.PublicKey, error) {
	out := &ecdsa.PublicKey{
		X: new(big.Int).SetBytes(key.Public.X),
		Y: new(big.Int).SetBytes(key.Public.Y),
	}
	switch key.Curve {
	case pb.EcdhKey_SECP224R1:
		out.Curve = elliptic.P224()
	case pb.EcdhKey_SECP256R1:
		out.Curve = elliptic.P256()
	default:
		return nil, fmt.Errorf("unsupported curve id %d", key.Curve)
	}
	return out, nil
}

func proto2ecdsaPrivateKey(priv *pb.EcdhPrivateKey) (*ecdsa.PrivateKey, error) {
	pub, err := proto2ecdsaKey(priv.Key)
	if err != nil {
		return nil, err
	}
	return &ecdsa.PrivateKey{
		PublicKey: *pub,
		D:         new(big.Int).SetBytes(priv.Private),
	}, nil
}
