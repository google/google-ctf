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
	"fmt"
	"math/big"
)

const serverCurveId = pb.EcdhKey_SECP224R1

var flagCipherKdfInfo = []byte("Flag Cipher v1.0")
var flagMacKdfInfo = []byte("Flag MAC v1.0")
var flagFixedIV = []byte{0x73, 0x40, 0x76, 0xd5, 0x67, 0xe0, 0x9, 0x2a, 0xbc, 0xe1, 0x9, 0x15, 0x82, 0x55, 0x43, 0x7d}

var channelCipherKdfInfo = []byte("Channel Cipher v1.0")
var channelMacKdfInfo = []byte("Channel MAC v1.0")

type Server struct {
	flag          string
	encryptedFlag *pb.Ciphertext
	key           *ecdsa.PrivateKey
	channel       *AuthCipher
}

func buildFlagCipher(priv *ecdsa.PrivateKey) (*AuthCipher, error) {
	secret := make([]byte, priv.Params().BitSize/8)
	priv.D.FillBytes(secret)

	return newAuthCipher(secret, flagCipherKdfInfo, flagMacKdfInfo)
}

func NewServer(flag string, priv *pb.EcdhPrivateKey) (*Server, error) {
	// Load private key.
	if priv.Key.Curve != serverCurveId {
		return nil, fmt.Errorf("priv.Key.Curve != serverCurveId, want %d, got %d", serverCurveId, priv.Key.Curve)
	}
	key, err := proto2ecdsaPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("proto2ecdsaPrivateKey() = %v, want nil error", err)
	}

	// Private key sanity checks.
	x, y := key.ScalarBaseMult(key.D.Bytes())
	if x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
		return nil, fmt.Errorf("input private key does not match public")
	}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, fmt.Errorf("input key not on curve X=%X, Y=%X", key.X, key.Y)
	}

	// Encrypt flag.
	flagCipher, err := buildFlagCipher(key)
	if err != nil {
		return nil, fmt.Errorf("deriveFlagKey()=%v, want nil error", err)
	}
	encryptedFlag, err := flagCipher.Encrypt(flagFixedIV, []byte(flag))
	if err != nil {
		return nil, fmt.Errorf("encryptFlag()=%v, want nil error", err)
	}

	return &Server{
		flag:          flag,
		encryptedFlag: encryptedFlag,
		key:           key,
	}, nil
}

func (server *Server) ServerHello() *pb.ServerHello {
	return &pb.ServerHello{
		Key: &pb.EcdhKey{
			Curve: serverCurveId,
			Public: &pb.Point{
				X: server.key.X.Bytes(),
				Y: server.key.Y.Bytes(),
			},
		},
		EncryptedFlag: server.encryptedFlag,
	}
}

func (server *Server) EstablishChannel(clientHello *pb.ClientHello) error {
	// Load peer key.
	peer, err := proto2ecdsaKey(clientHello.Key)
	if err != nil {
		return err
	}

	// Key sanity checks.
	if !peer.Curve.IsOnCurve(peer.X, peer.Y) {
		return fmt.Errorf("point (%X, %X) not on curve", peer.X, peer.Y)
	}

	// Compute shared secret.
	P := server.key.Params().P
	D := server.key.D.Bytes()
	sharedX, _ := server.key.ScalarMult(new(big.Int).Mod(peer.X, P), new(big.Int).Mod(peer.Y, P), D)

	masterSecret := make([]byte, server.key.Params().BitSize/8)
	sharedX.FillBytes(masterSecret)

	// Derive AES+MAC session keys.
	server.channel, err = newAuthCipher(masterSecret, channelCipherKdfInfo, channelMacKdfInfo)
	if err != nil {
		return fmt.Errorf("newAuthCipher()=%v, want nil error", err)
	}
	return nil
}

// Read and re-encrypt client's message.
func (server *Server) EchoSessionMessage(clientMsg *pb.SessionMessage) *pb.SessionMessage {
	data, err := server.channel.Decrypt(clientMsg.EncryptedData)
	if err != nil {
		return &pb.SessionMessage{}
	}

	iv := make([]byte, len(clientMsg.EncryptedData.Iv))
	copy(iv, clientMsg.EncryptedData.Iv)
	iv[0] ^= 1

	encryptedData, err := server.channel.Encrypt(iv, data)
	if err != nil {
		return &pb.SessionMessage{}
	}
	return &pb.SessionMessage{
		EncryptedData: encryptedData,
	}
}
