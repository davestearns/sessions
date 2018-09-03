package sessions

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/rafaeljusto/redigomock"

	"github.com/gomodule/redigo/redis"
)

func TestRedisStoreIntegration(t *testing.T) {
	token, err := NewToken(testSigningKey)
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}
	type user struct {
		Name string
	}
	type sessionstate struct {
		U    *user
		Reqs int
	}
	state := &sessionstate{&user{"tester"}, 0}
	store := NewRedisStore(NewRedisPool("127.0.0.1:6379", time.Minute*10), time.Hour)

	//ensure we get an error when getting before saving
	stateGet := &sessionstate{}
	if err := store.Get(token, stateGet); err == nil {
		t.Errorf("did not receive expected error when getting state that does not yet exist")
	}

	//save the sate
	if err := store.Save(token, state); err != nil {
		t.Errorf("error saving state: %v", err)
	}

	//get the state and compare
	stateGet = &sessionstate{}
	if err := store.Get(token, stateGet); err != nil {
		t.Errorf("error getting session state: %v", err)
	}
	if !reflect.DeepEqual(stateGet, state) {
		t.Errorf("fetched session state did not match original state: expected %+v but got %+v", state, stateGet)
	}

	//update the session state
	state.Reqs++
	if err := store.Save(token, state); err != nil {
		t.Errorf("error saving state: %v", err)
	}

	//get again and ensure it was updated
	stateGet = &sessionstate{}
	if err := store.Get(token, stateGet); err != nil {
		t.Errorf("error getting session state: %v", err)
	}
	if !reflect.DeepEqual(stateGet, state) {
		t.Errorf("fetched session state did not match original state: expected %+v but got %+v", state, stateGet)
	}

	//try to get passing a target value that will cause a decoding error
	//and ensure we get an error
	var stringVal string
	if err := store.Get(token, &stringVal); err == nil {
		t.Error("did not recieve expected decoding error")
	}

	//delete
	if err := store.Delete(token); err != nil {
		t.Errorf("error deleting session state: %v", err)
	}

	//get again and ensure we get an error
	stateGet = &sessionstate{}
	if err := store.Get(token, stateGet); err == nil {
		t.Errorf("did not receive expected error when getting state after delete")
	}
}

func TestNewRedisPool(t *testing.T) {
	mockConn := redigomock.NewConn()
	//create a pool with a 0 test on idle duration
	//and override the Dial() function to return a mock
	//connection instead. That way we can enusre the
	//TestOnBorrow() function does a PING command before
	//returning a new connection
	numDials := 0
	pool := NewRedisPool("", 0)
	pool.Dial = func() (redis.Conn, error) {
		numDials++
		return mockConn, nil
	}

	conn := pool.Get()
	if numDials != 1 {
		t.Errorf("expected numDials to be 1, but got %d", numDials)
	}
	if err := conn.Err(); err != nil {
		t.Errorf("connection returned from Get has error: %v", err)
	}
	conn.Close()
	if err := mockConn.ExpectationsWereMet(); err != nil {
		t.Errorf("some expectations were not met: %v", err)
	}

	//second .Get() should PING
	mockConn.Command("PING").Expect("PONG")
	conn = pool.Get()
	if err := conn.Err(); err != nil {
		t.Errorf("connection returned from Get has error: %v", err)
	}
	conn.Close()
	if err := mockConn.ExpectationsWereMet(); err != nil {
		t.Errorf("some expectations were not met: %v", err)
	}

	//and if PING returns an error, it should dial a new connection
	//and give us a new connection without an error
	mockConn.Command("PING").ExpectError(fmt.Errorf("test error"))
	conn = pool.Get()
	if numDials != 2 {
		t.Errorf("expected numDials to be 2, but got %d", numDials)
	}
	if err := conn.Err(); err != nil {
		t.Errorf("connection returned from Get has error: %v", err)
	}
	conn.Close()
	if err := mockConn.ExpectationsWereMet(); err != nil {
		t.Errorf("some expectations were not met: %v", err)
	}
}

func TestRedisStoreDeleteErrors(t *testing.T) {
	token, err := NewToken(testSigningKey)
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}

	conn := redigomock.NewConn()
	conn.Command("DEL", getRedisKey(token)).ExpectError(fmt.Errorf("test error"))
	store := NewRedisStore(getMockPool(conn), time.Hour)

	if err := store.Delete(token); err == nil {
		t.Error("did not receive expected error from mock")
	}
	if err := conn.ExpectationsWereMet(); err != nil {
		t.Errorf("some expectations were not met: %v", err)
	}
}

func TestRedisStoreSaveErrors(t *testing.T) {
	token, err := NewToken(testSigningKey)
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}

	conn := redigomock.NewConn()
	conn.Command("SETEX", getRedisKey(token), time.Hour.Seconds(), redigomock.NewAnyData()).ExpectError(fmt.Errorf("test error"))
	store := NewRedisStore(getMockPool(conn), time.Hour)

	//try to save something that can't be encoded
	if err := store.Save(token, func() {}); err == nil {
		t.Error("did not receive expected error when saving un-serializable state")
	}

	if err := store.Save(token, "test state"); err == nil {
		t.Error("did not receive expected error from mock")
	}
	if err := conn.ExpectationsWereMet(); err != nil {
		t.Errorf("some expectations were not met: %v", err)
	}
}

func getMockPool(conn *redigomock.Conn) *redis.Pool {
	return &redis.Pool{
		Dial: func() (redis.Conn, error) { return conn, nil },
	}
}
