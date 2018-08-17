package sessions

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const headerAuthorization = "Authorization"
const paramAuthorization = "auth"
const authTypeBearer = "Bearer"

//ErrNoSession is returned from GetState and EndSession
//when there is no session token in the provided request
var ErrNoSession = errors.New("no session token")

//ErrUnsupportedTokenType is returned when the type prefix for
//the session token is not supported
var ErrUnsupportedTokenType = errors.New("unsupported session token type")

//Manager describes what session managers can do
type Manager interface {
	BeginSession(w http.ResponseWriter, sessionState interface{}) (Token, error)
	GetState(r *http.Request, sessionState interface{}) (Token, error)
	UpdateState(token Token, sessionState interface{}) error
	EndSession(token Token) error
}

//manager is the concrete implementation of the Manager interface
type manager struct {
	idLength   int
	signingKey []byte
	store      Store
}

//NewManager constructs a new manager. The idLength and signingKey will
//be used when generating new Tokens in BeginSession(), as well as verifying
//tokens in GetState(). The store is used to save, get, and delete session state.
func NewManager(idLength int, signingKey []byte, store Store) Manager {
	return &manager{
		idLength:   idLength,
		signingKey: signingKey,
		store:      store,
	}
}

//BeginSession begins a new session, saving the provided sessionState to the store.
//The new Token for the session is returned, or an error if a problem occurs.
func (m *manager) BeginSession(w http.ResponseWriter, sessionState interface{}) (Token, error) {
	//generate a new token
	tk, err := NewTokenOfLength(m.signingKey, m.idLength)
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

//GetState gets and validates the session Token, populates sessionState from the Store,
//and returns the Token. ErrNoSession is returned if there is no session token.
//ErrUnsupportedTokenType is returned if the token type is unsupported. Currently, we
//only support "Bearer" tokens.
func (m *manager) GetState(r *http.Request, sessionState interface{}) (Token, error) {
	//get the Authorization header
	authHeader := r.Header.Get(headerAuthorization)
	//if empty, fallback to the query string parameter
	if len(authHeader) == 0 {
		authHeader = r.URL.Query().Get(paramAuthorization)
	}

	//if still empty, return appropriate error
	if len(authHeader) == 0 {
		return nil, ErrNoSession
	}

	//ensure it has the Bearer prefix
	if !strings.HasPrefix(authHeader, authTypeBearer) {
		return nil, ErrUnsupportedTokenType
	}

	//verify the token that follows the "Bearer " prefix
	tk, err := VerifyToken(authHeader[len(authTypeBearer)+1:], m.signingKey)
	if err != nil {
		return nil, fmt.Errorf("error verifying session token: %v", err)
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
func (m *manager) EndSession(token Token) error {
	return m.store.Delete(token)
}
