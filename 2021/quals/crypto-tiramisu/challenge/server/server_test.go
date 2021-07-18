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
	"crypto-tiramisu/pb"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

var zero = new(big.Int).SetInt64(0)

type attackPoint struct {
	n *big.Int
	x *big.Int
	y *big.Int
}

// Following point was found using sage/find_attack_points.sage.
func getAttackPoint() *attackPoint {
	n := new(big.Int).SetInt64(29201)
	x, _ := new(big.Int).SetString("2573149408563135267767286357803004470937842274186541684548965869435248882088592112721463665323093104335955766798680132975409745202902588513752870", 0)
	y, _ := new(big.Int).SetString("1138950493388784561054767746144900399082909629312765631357435018595469522740828846479784291280955273799509435811484617242474956987963551482260445", 0)
	return &attackPoint{
		n: n,
		x: x,
		y: y,
	}
}

func attackPoint2ClientHello(pt *attackPoint) *pb.ClientHello {
	return &pb.ClientHello{
		Key: &pb.EcdhKey{
			Curve: pb.EcdhKey_SECP256R1,
			Public: &pb.Point{
				X: pt.x.Bytes(),
				Y: pt.y.Bytes(),
			},
		},
	}
}

func newTestServer(t *testing.T) *Server {
	var err error
	server := &Server{}
	server.key, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate server key %v", err)
	}
	return server
}

func TestAttackPointIsOnP256(t *testing.T) {
	pt := getAttackPoint()
	if !elliptic.P256().IsOnCurve(pt.x, pt.y) {
		t.Errorf("testpoint (%X, %X) expected to be on the P256 curve", pt.x, pt.y)
	}
}

func TestAttackPointIsNotOnP224(t *testing.T) {
	pt := getAttackPoint()
	if elliptic.P224().IsOnCurve(pt.x, pt.y) {
		t.Errorf("testpoint (%X, %X) expected not to be on the P224 curve", pt.x, pt.y)
	}
}

func TestAttackPointMultiplicationHasSmallOrder(t *testing.T) {
	pt := getAttackPoint()
	curve := elliptic.P224()

	pt.x.Mod(pt.x, curve.Params().P)
	pt.y.Mod(pt.y, curve.Params().P)

	d := new(big.Int).Set(pt.n)
	d.Sub(d, new(big.Int).SetInt64(1))
	resX, resY := curve.ScalarMult(pt.x, pt.y, d.Bytes())
	if resX.Cmp(zero) == 0 && resY.Cmp(zero) == 0 {
		t.Errorf("point*(order-1) returned zero point")
	}

	d = new(big.Int).Set(pt.n)
	resX, resY = curve.ScalarMult(pt.x, pt.y, d.Bytes())
	if !(resX.Cmp(zero) == 0 && resY.Cmp(zero) == 0) {
		t.Errorf("point*order did not return zero point")
	}

	d, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		t.Fatal(err)
	}
	d.Div(d, pt.n)
	d.Mul(d, pt.n)
	resX, resY = curve.ScalarMult(pt.x, pt.y, d.Bytes())
	if !(resX.Cmp(zero) == 0 && resY.Cmp(zero) == 0) {
		t.Errorf("point*order did not return zero point")
	}
}

func TestEstablishChannelAndBruteForceSmallOrder(t *testing.T) {
	var err error
	pt := getAttackPoint()
	clientHello := attackPoint2ClientHello(pt)
	server := newTestServer(t)

	err = server.EstablishChannel(clientHello)
	if err != nil {
		t.Error(err)
	}

	P := elliptic.P224().Params().P
	var got *big.Int
	for i := int64(1); i < 30000; i++ {
		d := new(big.Int).SetInt64(i)
		sharedX, _ := elliptic.P224().ScalarMult(new(big.Int).Mod(pt.x, P), new(big.Int).Mod(pt.y, P), d.Bytes())

		masterSecret := make([]byte, elliptic.P224().Params().BitSize/8)
		sharedX.FillBytes(masterSecret)

		channel, err := newAuthCipher(masterSecret, channelCipherKdfInfo, channelMacKdfInfo)
		if err != nil {
			t.Error(err)
		}

		if bytes.Compare(channel.macKey, server.channel.macKey) == 0 {
			got = new(big.Int).Set(d)
			break
		}
	}

	if got == nil {
		t.Fatalf("key bits not got")
	}

	got.Mod(got, pt.n)
	t.Logf("got key bits %d modulo %d", got, pt.n)

	wantK := new(big.Int).Mod(server.key.D, pt.n)
	wantMinusK := new(big.Int).Sub(pt.n, wantK)

	if !(got.Cmp(wantK) == 0 || got.Cmp(wantMinusK) == 0) {
		t.Errorf("Did not recover key bits, wantK = %d, wantMinusK = %d, got = %d", wantK, wantMinusK, got)
	}
}

func TestEchoSessionMessage(t *testing.T) {
	server := newTestServer(t)
	serverHello := server.ServerHello()
	serverKey, err := proto2ecdsaKey(serverHello.Key)
	if err != nil {
		t.Fatalf("failed to parse server hello %v", err)
	}

	clientKey, err := ecdsa.GenerateKey(serverKey.Curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key %v", err)
	}

	clientHello := &pb.ClientHello{
		Key: &pb.EcdhKey{
			Curve: serverHello.Key.Curve,
			Public: &pb.Point{
				X: clientKey.PublicKey.X.Bytes(),
				Y: clientKey.PublicKey.Y.Bytes(),
			},
		},
	}
	err = server.EstablishChannel(clientHello)
	if err != nil {
		t.Errorf("Server.EstablishChannel()=%v, want nil error", err)
	}

	sharedX, _ := clientKey.ScalarMult(serverKey.X, serverKey.Y, clientKey.D.Bytes())

	masterSecret := make([]byte, server.key.Params().BitSize/8)
	sharedX.FillBytes(masterSecret)

	channel, err := newAuthCipher(masterSecret, channelCipherKdfInfo, channelMacKdfInfo)
	if err != nil {
		t.Errorf("newAuthCipher() = %v, want nil err", err)
	}

	if bytes.Compare(channel.macKey, server.channel.macKey) != 0 {
		t.Errorf("failed to establish same session keys")
	}

	encryptedData, err := channel.Encrypt(testIV, testMessage)
	if err != nil {
		t.Errorf("channel.Encrypt() = %v, want nil error", err)
	}
	reply := server.EchoSessionMessage(&pb.SessionMessage{EncryptedData: encryptedData})
	if reply.EncryptedData == nil {
		t.Errorf("server.EchoSessionMessage returned an empty message")
	}

	decryptedData, err := channel.Decrypt(reply.EncryptedData)
	if bytes.Compare(decryptedData, testMessage) != 0 {
		t.Errorf("decryptedData=%X did not match testMessage=%X", decryptedData, testMessage)
	}
}
