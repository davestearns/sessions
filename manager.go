package sessions

import (
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

const headerAuthorization = "Authorization"
const paramAuthorization = "auth"
const authTypeBearer = "Bearer"

//ErrNoToken is returned from GetState and EndSession
//when there is no session token in the provided request
var ErrNoToken = errors.New("no session token")

//ErrUnsupportedTokenType is returned when the type prefix for
//the session token is not supported
var ErrUnsupportedTokenType = errors.New("unsupported session token type")

//keyIndexGenerator is used to generate random signing key indexes
var keyIndexGenerator = rand.New(rand.NewSource(time.Now().UnixNano()))

//Manager describes what session managers can do
type Manager interface {
	BeginSession(w http.ResponseWriter, sessionState interface{}) (Token, error)
	GetToken(r *http.Request) (Token, error)
	GetState(r *http.Request, sessionState interface{}) (Token, error)
	UpdateState(token Token, sessionState interface{}) error
	EndSession(r *http.Request) error
}

//manager is the concrete implementation of the Manager interface
type manager struct {
	idLength    int
	signingKeys [][]byte
	store       Store
}

//NewManager constructs a new manager. Use idLength to specify a byte length
//for newly-generate session IDs (see DefaultIDLength). Pass one or more
//signingKeys to use for signing session tokens--if multiple are provided,
//the manager will rotate which key is used over time. The store will be
//used to save, get, and delete session state associated with tokens.
func NewManager(idLength int, signingKeys [][]byte, store Store) Manager {
	return &manager{
		idLength:    idLength,
		signingKeys: signingKeys,
		store:       store,
	}
}

//BeginSession begins a new session, saving the provided sessionState to the store.
//The new Token for the session is returned, or an error if a problem occurs.
func (m *manager) BeginSession(w http.ResponseWriter, sessionState interface{}) (Token, error) {
	//generate a new token
	keyidx := keyIndexGenerator.Intn(len(m.signingKeys))
	tk, err := NewTokenOfLength(m.signingKeys[keyidx], m.idLength)
	if err != nil {
		return nil, fmt.Errorf("error generating new token: %v", err)
	}

	//save the session state
	if err := m.store.Save(tk, sessionState); err != nil {
		return nil, fmt.Errorf("error saving session state: %v", err)
	}
	//add the token to the Authorization header as a bearer token
	w.Header().Add(headerAuthorization, fmt.Sprintf("%s %s", authTypeBearer, tk.String()))
	return tk, nil
}

//GetToken gets the Token (if any) from the request.
//ErrNoToken is returned if there is no session token.
//ErrUnsupportedTokenType is returned if the token type is unsupported. Currently, we
//only support "Bearer" tokens.
func (m *manager) GetToken(r *http.Request) (Token, error) {
	//get the Authorization header
	authHeader := r.Header.Get(headerAuthorization)
	//if empty, fallback to the query string parameter
	if len(authHeader) == 0 {
		authHeader = r.URL.Query().Get(paramAuthorization)
	}

	//if still empty, return appropriate error
	if len(authHeader) == 0 {
		return nil, ErrNoToken
	}

	//ensure it has the Bearer prefix
	if !strings.HasPrefix(authHeader, authTypeBearer) {
		return nil, ErrUnsupportedTokenType
	}

	//verify the token that follows the "Bearer " prefix
	b64tk := authHeader[len(authTypeBearer)+1:]
	var tk Token
	var err error
	for _, key := range m.signingKeys {
		tk, err = VerifyToken(b64tk, key)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("error verifying session token: %v", err)
	}

	return tk, nil
}

//GetState gets and validates the session Token, populates sessionState from the Store,
//and returns the Token.
func (m *manager) GetState(r *http.Request, sessionState interface{}) (Token, error) {
	tk, err := m.GetToken(r)
	if err != nil {
		return nil, err
	}

	//get the associated session state
	if err := m.store.Get(tk, sessionState); err != nil {
		return nil, fmt.Errorf("error getting session state: %v", err)
	}
	return tk, nil
}

//UpdateState updates the session state for the provided token.
func (m *manager) UpdateState(token Token, sessionState interface{}) error {
	return m.store.Save(token, sessionState)
}

//EndSession deletes the session state associated with the token.
func (m *manager) EndSession(r *http.Request) error {
	tk, err := m.GetToken(r)
	if err != nil {
		return err
	}
	return m.store.Delete(tk)
}
