package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"github.com/gtank/ristretto255"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// The join handshake is a CPace-style password-authenticated key exchange over
// ristretto255. Both sides derive a generator from the session id and the join
// code, exchange one share each, and end up with the same keys only if they
// used the same code. A wrong guess costs the guesser one attempt and reveals
// nothing about the code to someone watching the network.
//
// web/vendor.js (built from websrc/crypto-entry.js) is the browser half and
// must stay byte-for-byte compatible with this file.

type sessionKeys struct {
	c2s, s2c  []byte // message keys, one per direction
	token     string // bearer token the guest presents when polling and sending
	clientMac []byte
	hostMac   []byte
}

type sealedBox struct {
	N string `json:"n"`
	C string `json:"c"`
}

func pakeGenerator(sid, code string) *ristretto255.Element {
	h := sha512.Sum512([]byte("drop-cpace-v1\x00" + sid + "\x00" + code))
	return ristretto255.NewElement().FromUniformBytes(h[:])
}

func randomScalar(r io.Reader) (*ristretto255.Scalar, error) {
	var b [64]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return nil, err
	}
	s := ristretto255.NewScalar().FromUniformBytes(b[:])
	if s.Equal(ristretto255.NewScalar()) == 1 {
		return nil, errors.New("zero scalar")
	}
	return s, nil
}

func decodeShare(b []byte) (*ristretto255.Element, error) {
	e := ristretto255.NewElement()
	if len(b) != 32 {
		return nil, errors.New("bad share length")
	}
	if err := e.Decode(b); err != nil {
		return nil, err
	}
	if e.Equal(ristretto255.NewIdentityElement()) == 1 {
		return nil, errors.New("identity share")
	}
	return e, nil
}

func deriveKeys(sid string, X, Y, K []byte) *sessionKeys {
	th := sha512.New()
	th.Write([]byte(sid))
	th.Write(X)
	th.Write(Y)
	okm := make([]byte, 128)
	if _, err := io.ReadFull(hkdf.New(sha256.New, K, th.Sum(nil), []byte("drop-v1 keys")), okm); err != nil {
		panic(err)
	}
	mac := func(label string) []byte {
		m := hmac.New(sha256.New, okm[64:96])
		m.Write([]byte(label))
		return m.Sum(nil)
	}
	return &sessionKeys{
		c2s:       okm[0:32],
		s2c:       okm[32:64],
		token:     base64.StdEncoding.EncodeToString(okm[96:128]),
		clientMac: mac("client"),
		hostMac:   mac("server"),
	}
}

// pakeRespond is the host half: given the guest's share X it returns the
// host's share Y and the keys the two sides share if the codes match.
func pakeRespond(sid, code string, X []byte) (Y []byte, keys *sessionKeys, err error) {
	xe, err := decodeShare(X)
	if err != nil {
		return nil, nil, err
	}
	y, err := randomScalar(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	Y = ristretto255.NewElement().ScalarMult(y, pakeGenerator(sid, code)).Encode(nil)
	K := ristretto255.NewElement().ScalarMult(y, xe).Encode(nil)
	return Y, deriveKeys(sid, X, Y, K), nil
}

// pakeStart and pakeFinish are the guest half. The host never calls them;
// they exist so tests can play the browser's part.
func pakeStart(sid, code string, r io.Reader) (x *ristretto255.Scalar, X []byte, err error) {
	x, err = randomScalar(r)
	if err != nil {
		return nil, nil, err
	}
	return x, ristretto255.NewElement().ScalarMult(x, pakeGenerator(sid, code)).Encode(nil), nil
}

func pakeFinish(sid string, x *ristretto255.Scalar, X, Y []byte) (*sessionKeys, error) {
	ye, err := decodeShare(Y)
	if err != nil {
		return nil, err
	}
	K := ristretto255.NewElement().ScalarMult(x, ye).Encode(nil)
	return deriveKeys(sid, X, Y, K), nil
}

func seal(key []byte, aad string, v any) (sealedBox, error) {
	pt, err := json.Marshal(v)
	if err != nil {
		return sealedBox{}, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return sealedBox{}, err
	}
	n := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(n); err != nil {
		return sealedBox{}, err
	}
	return sealedBox{
		N: base64.StdEncoding.EncodeToString(n),
		C: base64.StdEncoding.EncodeToString(aead.Seal(nil, n, pt, []byte(aad))),
	}, nil
}

func open(key []byte, aad string, box sealedBox, v any) error {
	n, err := base64.StdEncoding.DecodeString(box.N)
	if err != nil || len(n) != chacha20poly1305.NonceSizeX {
		return errors.New("bad nonce")
	}
	c, err := base64.StdEncoding.DecodeString(box.C)
	if err != nil {
		return errors.New("bad ciphertext")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	pt, err := aead.Open(nil, n, c, []byte(aad))
	if err != nil {
		return errors.New("decryption failed")
	}
	return json.Unmarshal(pt, v)
}
