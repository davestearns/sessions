package sessions

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

//MinIDLength is the minimum ID byte length allowed.
//See https://www.owasp.org/index.php/Insufficient_Session-ID_Length
const MinIDLength = 16

//DefaultIDLength is the default ID byte length.
const DefaultIDLength = 32

//RandToken represents a crypto-randon, digitally-signed session token.
//Use NewToken() or NewTokenFromReader() to generate a new token.
//Use the String() method to generate a base64-encoded version of the token
//that is safe to transport over HTTPS, and use VerifyToken to verify
//a base64-encoded token sent by the client.
type RandToken struct {
	buf []byte
}

//NewRandToken constructs a new token, using DefaultIDLength,
//the crypto/rand reader, and the provided signing key.
func NewRandToken(signingKey []byte) (*RandToken, error) {
	return NewRandTokenFromReader(DefaultIDLength, rand.Reader, signingKey)
}

//NewRandTokenFromReader constructs a new Token. Use idLength to set the length of the session ID
//in bytes (must be >= MinIDLength). The ID bytes will be read from randReader. The signingKey
//must be non-zero length, and will be used with the HMAC algorithm to digitally sign the ID.
func NewRandTokenFromReader(idLength int, randReader io.Reader, signingKey []byte) (*RandToken, error) {
	//preconditions:
	// - len(signingKey) > 0
	// - idLength >= MinIDLength
	// - randReader != nil
	if len(signingKey) == 0 {
		return nil, fmt.Errorf("zero-length signing key")
	}
	if idLength < MinIDLength {
		return nil, fmt.Errorf("ID length must be at least %d", MinIDLength)
	}
	if randReader == nil {
		return nil, fmt.Errorf("nil passed for random reader")
	}

	//allocate the token buffer with a length of idLength,
	//but a capacity that includes the length of the signature
	token := &RandToken{buf: make([]byte, idLength, idLength+sha256.Size)}

	//read random bytes from the reader for the ID portion
	if _, err := randReader.Read(token.buf); err != nil {
		return nil, fmt.Errorf("error reading random bytes: %v", err)
	}

	//sign and return
	h := hmac.New(sha256.New, signingKey)
	h.Write(token.buf)
	token.buf = h.Sum(token.buf)
	return token, nil
}

//VerifyToken verifies a base64-encoded token string using the provided signingKey.
func VerifyToken(token string, signingKey []byte) (*RandToken, error) {
	if len(signingKey) == 0 {
		return nil, fmt.Errorf("zero-length signing key")
	}
	buf, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("error base64-decoding the token: %v", err)
	}
	//if the buffer is not longer than the size of a SHA256 hash, it can't be valid
	if len(buf) <= sha256.Size {
		return nil, fmt.Errorf("token not long enough")
	}

	//split the ID from the signature
	sigStart := len(buf) - sha256.Size
	id, sig := buf[:sigStart], buf[sigStart:]

	//re-sign and compare
	h := hmac.New(sha256.New, signingKey)
	h.Write(id)
	sig2 := h.Sum(nil)
	if !hmac.Equal(sig, sig2) {
		return nil, fmt.Errorf("token has been modified since signed")
	}

	return &RandToken{buf}, nil
}

//String returns a base64-encoded version of the token, suitable
//for transporting over a text-based protocol like HTTP.
func (t *RandToken) String() string {
	return base64.URLEncoding.EncodeToString(t.buf)
}

//ID returns the session ID crypto-random bytes.
//You can use these to generate a shorter key in your session store.
func (t *RandToken) ID() []byte {
	//optimize for performance by slicing and not copying
	return t.buf[:len(t.buf)-sha256.Size]
}
