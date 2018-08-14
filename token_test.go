package sessions

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

var testSigningKey = []byte("testsigningkey")

type errorReader struct{}

func (r *errorReader) Read(buf []byte) (int, error) {
	return 0, errors.New("test error")
}

func TestNewTokenOfLength(t *testing.T) {
	cases := []struct {
		name        string
		length      int
		signingKey  []byte
		expectError bool
	}{
		{
			"min length",
			MinIDLength,
			testSigningKey,
			false,
		},
		{
			"default length",
			DefaultIDLength,
			testSigningKey,
			false,
		},
		{
			"specific length",
			64,
			testSigningKey,
			false,
		},
		{
			"long length",
			256,
			testSigningKey,
			false,
		},
		{
			"length too short",
			MinIDLength - 1,
			testSigningKey,
			true,
		},
		{
			"zero-length key",
			MinIDLength,
			[]byte{},
			true,
		},
	}

	for _, c := range cases {
		token, err := NewTokenOfLength(c.signingKey, c.length)
		//if we expect an error...
		if c.expectError {
			//ensure we got one
			if err == nil {
				t.Errorf("case %s: did not receive expected error", c.name)
			}
			//and continue to the next case
			continue
		}
		if err != nil {
			t.Errorf("case %s: unexpected error: %v", c.name, err)
			continue
		}
		if token == nil {
			t.Errorf("case %s: nil token returned", c.name)
			continue
		}

		//ensure ID is correct length
		idLen := token.ID().Len()
		if idLen != c.length {
			t.Errorf("case %s: incorrect ID length: expected %d but got %d", c.name, c.length, idLen)
		}

		//we can't predict what the ID will be, but ensure that it's not all zeros
		zeroBuf := make([]byte, c.length)
		b64zb := base64.URLEncoding.EncodeToString(zeroBuf)
		if token.ID().String() == b64zb {
			t.Errorf("case %s: ID is all zero bytes", c.name)
		}

		//we can't predict the base64-encoded version, but ensure it's non-zero length
		b64 := token.String()
		if len(b64) == 0 {
			t.Errorf("case %s: base64-encoded string was zero-length", c.name)
		}

		//verify the token
		token2, err := VerifyToken(b64, c.signingKey)
		if err != nil {
			t.Errorf("case %s: error verifying base64-encoded version of token: %v", c.name, err)
		}

		//verify they match
		if token.String() != token2.String() {
			t.Errorf("case %s: verified token buffer does not match original token: expected %s but got %s",
				c.name, token.String(), token2.String())
		}

	}
}

func TestNewTokenErrorReadingRandom(t *testing.T) {
	//use errorReader to simulate an error reading random bytes
	randReader = &errorReader{}
	_, err := NewToken(testSigningKey)
	if err == nil {
		t.Error("did not receive expected error when simulating error reading random bytes")
	}
	randReader = rand.Reader
}

func TestNewToken(t *testing.T) {
	cases := []struct {
		name        string
		signingKey  []byte
		expectError bool
	}{
		{
			"valid key",
			testSigningKey,
			false,
		},
		{
			"invalid key",
			nil,
			true,
		},
	}

	for _, c := range cases {
		token, err := NewToken(c.signingKey)
		if c.expectError {
			if err == nil {
				t.Errorf("case %s: did not receive expected error", c.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("case %s: unexpected error %v", c.name, err)
		}

		//ensure ID length is default length
		idLen := token.ID().Len()
		if idLen != DefaultIDLength {
			t.Errorf("case %s: incorrect ID length: expected %d but got %d", c.name, DefaultIDLength, idLen)
		}
	}
}

func modToken(token string) string {
	buf := []byte(token)
	if buf[0] == 'A' {
		buf[0] = 'B'
	} else {
		buf[0] = 'A'
	}
	return string(buf)
}

func TestVerifyToken(t *testing.T) {
	//valid token case
	token, err := NewToken(testSigningKey)
	if err != nil {
		t.Errorf("unexpected error generating token: %v", err)
	}
	tokenString := token.String()
	_, err = VerifyToken(tokenString, testSigningKey)
	if err != nil {
		t.Errorf("unexpected error verifying valid token: %v", err)
	}

	//failure cases
	cases := []struct {
		name       string
		token      string
		signingKey []byte
	}{
		{
			"empty token",
			"",
			testSigningKey,
		},
		{
			"invalid base64",
			"ABC~😜",
			testSigningKey,
		},
		{
			"zero-length signing key",
			tokenString,
			nil,
		},
		{
			"incorrect signing key",
			tokenString,
			[]byte("incorrect signing key"),
		},
		{
			"modified token",
			modToken(tokenString),
			testSigningKey,
		},
	}

	for _, c := range cases {
		_, err := VerifyToken(c.token, c.signingKey)
		if err == nil {
			t.Errorf("case %s: did not receive expected error", c.name)
		}
	}
}

func TestTokenIDString(t *testing.T) {
	//ensure that the ID string is non-zero length
	//and can be base64-decoded
	token, err := NewToken(testSigningKey)
	if err != nil {
		t.Fatalf("unexpected error while creating token: %v", err)
	}
	id := token.ID().String()
	if len(id) == 0 {
		t.Errorf("ID string is zero-length")
	}
	if _, err := base64.URLEncoding.DecodeString(id); err != nil {
		t.Errorf("error base64-decoding ID string: %v", err)
	}
}
