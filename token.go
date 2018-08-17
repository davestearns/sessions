package sessions

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

//MinIDLength is the minimum ID byte length allowed.
//See https://www.owasp.org/index.php/Insufficient_Session-ID_Length
const MinIDLength = 16

//DefaultIDLength is the default ID byte length.
const DefaultIDLength = 32

//randReader is the reader used to generate random bytes for sessionIDs.
//This can be reset during automated tests to simulate an error from
//the crypto/rand reader.
var randReader = rand.Reader

//ID provides read-only access to the ID portion of the token.
type ID interface {
	//Len returns the length of the session ID in bytes
	Len() int
	//String returns a base64-encoded version of the ID,
	//suitable for use as a key in a session store
	String() string
}

//id is the concrete implementation of the ID interface
type id struct {
	buf []byte
}

//Token represents a crypto-randon, digitally-signed session token.
//Use NewToken() or NewTokenFromReader() to generate a new token.
//Use the String() method to generate a base64-encoded version of the token
//that is safe to transport over HTTPS, and use VerifyToken to verify
//a base64-encoded token sent by the client.
type Token interface {
	//String returns a base64-encoded version of the entire token
	String() string
	//ID returns a read-only interface to the ID portion of the token
	ID() ID
}

//token is the concrete implementation of the Token interface
type token struct {
	//buf holds both the session ID bytes, and the HMAC signature bytes.
	//The first bytes are the crypto-random session ID, which can be
	//of any length >= MinIDLength. The last sha256.Size (32) bytes are
	//the HMAC signature of those session ID bytes.
	// ---------------------------------------------------------
	// | ID bytes (>= MinIDLength) | HMAC signature (32 bytes) |
	// ---------------------------------------------------------
	buf []byte
}

//NewToken constructs a new Token of DefaultIDLength, using the
//provided signingKey for generating the HMAC signature.
func NewToken(signingKey []byte) (Token, error) {
	return NewTokenOfLength(signingKey, DefaultIDLength)
}

//NewTokenOfLength constructs a new Token using idLength as the length of the session ID
//in bytes (must be >= MinIDLength). The signingKey must be non-zero length,
//and will be used with the HMAC algorithm to digitally sign the ID.
func NewTokenOfLength(signingKey []byte, idLength int) (Token, error) {
	//preconditions:
	// - len(signingKey) > 0
	// - idLength >= MinIDLength
	if len(signingKey) == 0 {
		return nil, fmt.Errorf("zero-length signing key")
	}
	if idLength < MinIDLength {
		return nil, fmt.Errorf("ID length must be at least %d", MinIDLength)
	}

	//allocate the token buffer with a length of idLength,
	//but a capacity that includes the length of the signature
	tk := &token{buf: make([]byte, idLength, idLength+sha256.Size)}

	//read random bytes from the reader for the ID portion
	if _, err := randReader.Read(tk.buf); err != nil {
		return nil, fmt.Errorf("error reading random bytes: %v", err)
	}

	//sign and return
	h := hmac.New(sha256.New, signingKey)
	h.Write(tk.buf)
	tk.buf = h.Sum(tk.buf)
	return tk, nil
}

//VerifyToken verifies a base64-encoded token string using the provided signingKey.
func VerifyToken(b64token string, signingKey []byte) (Token, error) {
	if len(signingKey) == 0 {
		return nil, fmt.Errorf("zero-length signing key")
	}
	buf, err := base64.URLEncoding.DecodeString(b64token)
	if err != nil {
		return nil, fmt.Errorf("error base64-decoding the token: %v", err)
	}
	//if the buffer is not longer than the size of a SHA256 hash + MinIDLength, it can't be valid
	if len(buf) < sha256.Size+MinIDLength {
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

	return &token{buf}, nil
}

//String returns a base64-encoded version of the token, suitable
//for transporting over a text-based protocol like HTTP.
func (t *token) String() string {
	return base64.URLEncoding.EncodeToString(t.buf)
}

//ID returns the session ID from the token. The returned interface
//provides read-only access to the ID bytes, reporting their length,
//and allowing you to generate a base64-encoded version of the bytes,
//which can be used as a key in a session store.
func (t *token) ID() ID {
	return &id{
		buf: t.buf[:len(t.buf)-sha256.Size],
	}
}

//Len returns the length of the ID in bytes
func (i *id) Len() int {
	return len(i.buf)
}

//String returns a base64-encoded string of the ID
func (i *id) String() string {
	return base64.URLEncoding.EncodeToString(i.buf)
}
