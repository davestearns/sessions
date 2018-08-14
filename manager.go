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

//NewManager constructs a new manager
func NewManager(idLength int, signingKey []byte, store Store) Manager {
	return &manager{
		idLength:   idLength,
		signingKey: signingKey,
		store:      store,
	}
}

//BeginSession begins a new session
func (m *manager) BeginSession(w http.ResponseWriter, sessionState interface{}) (Token, error) {
	//generate a new token
	tk, err := NewTokenOfLength(m.signingKey, m.idLength)
	if err != nil {
		return nil, err
	}

	//save the session state
	if err := m.store.Save(tk, sessionState); err != nil {
		return nil, err
	}
	//add the token to the Authorization header as a bearer token
	w.Header().Add(headerAuthorization, fmt.Sprintf("%s %s", authTypeBearer, tk.String()))
	return tk, nil
}

//GetState gets and validates the session Token, populates sessionState from the Store,
//and returns the Token. ErrNoSession is returned if there is no session token.
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
		return nil, err
	}

	//get the associated session state
	if err := m.store.Get(tk, sessionState); err != nil {
		return nil, err
	}
	return tk, nil
}

func (m *manager) UpdateState(token Token, sessionState interface{}) error {
	return m.store.Save(token, sessionState)
}

func (m *manager) EndSession(token Token) error {
	return m.store.Delete(token)
}
