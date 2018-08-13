package sessions

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

var defaultSigningKey = []byte("testsigningkey")

type errorReader struct{}

func (r *errorReader) Read(buf []byte) (int, error) {
	return 0, errors.New("test error")
}

func TestNewTokenFromReader(t *testing.T) {
	cases := []struct {
		name        string
		length      int
		signingKey  []byte
		reader      io.Reader
		expectError bool
	}{
		{
			"min length",
			MinIDLength,
			defaultSigningKey,
			rand.Reader,
			false,
		},
		{
			"default length",
			DefaultIDLength,
			defaultSigningKey,
			rand.Reader,
			false,
		},
		{
			"specific length",
			64,
			defaultSigningKey,
			rand.Reader,
			false,
		},
		{
			"long length",
			256,
			defaultSigningKey,
			rand.Reader,
			false,
		},
		{
			"length too short",
			MinIDLength - 1,
			defaultSigningKey,
			rand.Reader,
			true,
		},
		{
			"zero-length key",
			MinIDLength,
			[]byte{},
			rand.Reader,
			true,
		},
		{
			"nil reader",
			MinIDLength,
			defaultSigningKey,
			nil,
			true,
		},
		{
			"error from reader",
			MinIDLength,
			defaultSigningKey,
			&errorReader{},
			true,
		},
	}

	for _, c := range cases {
		token, err := NewRandTokenFromReader(c.length, c.reader, c.signingKey)
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
		idLen := len(token.ID())
		if idLen != c.length {
			t.Errorf("case %s: incorrect ID length: expected %d but got %d", c.name, c.length, idLen)
		}

		//we can't predict what the ID will be, but ensure that it's not all zeros
		zeroBuf := make([]byte, c.length)
		if bytes.Equal(token.ID(), zeroBuf) {
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

		//verify that buffers match
		if !bytes.Equal(token.buf, token2.buf) {
			t.Errorf("case %s: verified token buffer does not match original token buffer: expected %v but got %v",
				c.name, token.buf, token2.buf)
		}

	}
}

func TestNewToken(t *testing.T) {
	cases := []struct {
		name        string
		signingKey  []byte
		expectError bool
	}{
		{
			"valid key",
			defaultSigningKey,
			false,
		},
		{
			"invalid key",
			nil,
			true,
		},
	}

	for _, c := range cases {
		token, err := NewRandToken(c.signingKey)
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
		idLen := len(token.ID())
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
	token, err := NewRandToken(defaultSigningKey)
	if err != nil {
		t.Errorf("unexpected error generating token: %v", err)
	}
	tokenString := token.String()
	_, err = VerifyToken(tokenString, defaultSigningKey)
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
			defaultSigningKey,
		},
		{
			"invalid base64",
			"ABC~😜",
			defaultSigningKey,
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
			defaultSigningKey,
		},
	}

	for _, c := range cases {
		_, err := VerifyToken(c.token, c.signingKey)
		if err == nil {
			t.Errorf("case %s: did not receive expected error", c.name)
		}
	}
}
