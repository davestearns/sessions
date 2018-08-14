package sessions

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type mockStore struct {
	entries      map[string][]byte
	triggerError bool
}

func newMockStore(triggerError bool) *mockStore {
	return &mockStore{
		entries:      make(map[string][]byte),
		triggerError: triggerError,
	}
}

func (ms *mockStore) Save(token Token, sessionState interface{}) error {
	if ms.triggerError {
		return fmt.Errorf("test error")
	}
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(sessionState); err != nil {
		return err
	}
	ms.entries[token.ID().String()] = buf.Bytes()
	return nil
}

func (ms *mockStore) Get(token Token, sessionState interface{}) error {
	if ms.triggerError {
		return fmt.Errorf("test error")
	}
	val, found := ms.entries[token.ID().String()]
	if !found {
		return errors.New("no data found")
	}
	if err := gob.NewDecoder(bytes.NewReader(val)).Decode(sessionState); err != nil {
		return err
	}
	return nil
}

func (ms *mockStore) Delete(token Token) error {
	if ms.triggerError {
		return fmt.Errorf("test error")
	}
	delete(ms.entries, token.ID().String())
	return nil
}

func TestManagerBeginSession(t *testing.T) {
	store := newMockStore(false)
	mgr := NewManager(DefaultIDLength, testSigningKey, store)
	respRec := httptest.NewRecorder()
	state := "test state"

	token, err := mgr.BeginSession(respRec, state)
	if err != nil {
		t.Errorf("unexpected error beginning session: %v", err)
	}

	//ensure store has state
	if _, found := store.entries[token.ID().String()]; !found {
		t.Errorf("session state not saved to store")
	}
	//ensure response has Authorization header
	authHeader := respRec.Header().Get(headerAuthorization)
	expectedHeader := fmt.Sprintf("%s %s", authTypeBearer, token.String())
	if authHeader != expectedHeader {
		t.Errorf("incorrect Authorization header in response: expected %s but got %s", expectedHeader, authHeader)
	}

	//trigger an error from the store and ensure we get it
	store.triggerError = true
	if _, err := mgr.BeginSession(respRec, state); err == nil {
		t.Error("did not get expected error from store when beginning session")
	}

	//trigger an error while generating the new token and ensure we get it
	store.triggerError = false
	randReader = &errorReader{}
	if _, err := mgr.BeginSession(respRec, state); err == nil {
		t.Error("did not get expected error when beginning session with error rand reader")
	}
	randReader = rand.Reader
}

func TestManagerGetState(t *testing.T) {
	token, err := NewToken(testSigningKey)
	if err != nil {
		t.Fatalf("unexpected erorr generating token: %v", err)
	}

	cases := []struct {
		name        string
		request     *http.Request
		store       Store
		expectError bool
	}{
		{
			"no session token",
			httptest.NewRequest("GET", "http://example.com", nil),
			newMockStore(false),
			true,
		},
		{
			"invalid session token type",
			func() *http.Request {
				r := httptest.NewRequest("GEt", "http://example.com", nil)
				r.Header.Add(headerAuthorization, fmt.Sprintf("INVALID %s", token.String()))
				return r
			}(),
			newMockStore(false),
			true,
		},
		{
			"invalid session token",
			func() *http.Request {
				r := httptest.NewRequest("GEt", "http://example.com", nil)
				r.Header.Add(headerAuthorization, fmt.Sprintf("%s INVALID", authTypeBearer))
				return r
			}(),
			newMockStore(false),
			true,
		},
		{
			"error from store",
			func() *http.Request {
				r := httptest.NewRequest("GEt", "http://example.com", nil)
				r.Header.Add(headerAuthorization, fmt.Sprintf("%s %s", authTypeBearer, token.String()))
				return r
			}(),
			newMockStore(true),
			true,
		},
		{
			"valid token in Authorization header",
			func() *http.Request {
				r := httptest.NewRequest("GEt", "http://example.com", nil)
				r.Header.Add(headerAuthorization, fmt.Sprintf("%s %s", authTypeBearer, token.String()))
				return r
			}(),
			newMockStore(false),
			false,
		},
		{
			"valid token in auth query string param",
			httptest.NewRequest("GEt", fmt.Sprintf("http://example.com?auth=%s+%s", authTypeBearer, token.String()), nil),
			newMockStore(false),
			false,
		},
	}

	for _, c := range cases {
		expectedState := "test"
		c.store.Save(token, expectedState)

		mgr := NewManager(DefaultIDLength, testSigningKey, c.store)

		var state string
		actualToken, err := mgr.GetState(c.request, &state)
		if c.expectError {
			if err == nil {
				t.Errorf("case %s: did not receive expected error", c.name)
			}
			continue
		}

		if actualToken.String() != token.String() {
			t.Errorf("case %s: incorrect token: expected %s but got %s", c.name, token.String(), actualToken.String())
		}

		if state != expectedState {
			t.Errorf("case %s: incorrect session state: expected %s but got %s", c.name, expectedState, state)
		}
	}
}

func TestManagerUpdateState(t *testing.T) {
	token, err := NewToken(testSigningKey)
	if err != nil {
		t.Fatalf("unexpected erorr generating token: %v", err)
	}

	cases := []struct {
		store       Store
		expectError bool
	}{
		{
			newMockStore(true),
			true,
		},
		{
			newMockStore(false),
			false,
		},
	}

	for _, c := range cases {
		mgr := NewManager(DefaultIDLength, testSigningKey, c.store)
		expectedState := "test"
		err := mgr.UpdateState(token, expectedState)
		if c.expectError {
			if err == nil {
				t.Error("did not receive expected error")
			}
			continue
		}

		var actualState string
		c.store.Get(token, &actualState)
		if actualState != expectedState {
			t.Errorf("state not saved to store: expected %s but got %s", expectedState, actualState)
		}
	}
}

func TestManagerEndSession(t *testing.T) {
	token, err := NewToken(testSigningKey)
	if err != nil {
		t.Fatalf("unexpected erorr generating token: %v", err)
	}

	store := newMockStore(false)
	expectedState := "test"
	store.Save(token, expectedState)

	mgr := NewManager(DefaultIDLength, testSigningKey, store)
	if err := mgr.EndSession(token); err != nil {
		t.Errorf("unexpected error ending session: %v", err)
	}
	var actualState string
	if err := store.Get(token, &actualState); err == nil {
		t.Error("did not receive expected error when trying to get state after EndSession()")
	}

	store.triggerError = true
	if err := mgr.EndSession(token); err == nil {
		t.Error("did nto receive triggered error from store")
	}
}
