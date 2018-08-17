package sessions

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"time"

	"github.com/gomodule/redigo/redis"
)

//NewRedisPool constructs a redis.Pool with defaults that should work
//well in most situations. If the pool returns a connection that has beeen
//idle for testAfterIdle or longer, it will be health-tested by executing a PING.
//Set testAfterIdle to 0 to always health-test existing connections before they are returned.
//Callers may adjust any settings on the returned pool before passing it to NewRedisStore().
func NewRedisPool(addr string, testAfterIdle time.Duration) *redis.Pool {
	return &redis.Pool{
		Dial: func() (redis.Conn, error) { return redis.Dial("tcp", addr) },
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			if time.Since(t) < testAfterIdle {
				return nil
			}
			_, err := c.Do("PING")
			return err
		},
		MaxIdle:     128,
		MaxActive:   512,
		IdleTimeout: time.Minute * 10,
		Wait:        true,
	}
}

//RedisStore represents a Store backed by redis.
type RedisStore struct {
	//Used for key expiry time on redis. Callers
	//may adjust this after construction.
	SessionDuration time.Duration
	//redis conection pool
	pool *redis.Pool
}

//NewRedisStore constructs a new RedisStore
func NewRedisStore(pool *redis.Pool, sessionDuration time.Duration) *RedisStore {
	return &RedisStore{
		SessionDuration: sessionDuration,
		pool:            pool,
	}
}

//Save saves the provided sessionState into the store, associated with
//the provided session token. The sessionState must be gob-encodable.
func (rs *RedisStore) Save(token Token, sessionState interface{}) error {
	//gob-encode the session state
	buf := bytes.NewBuffer(nil)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(sessionState); err != nil {
		return fmt.Errorf("error encoding session state: %v", err)
	}

	conn := rs.pool.Get()
	defer conn.Close()

	//use SETEX to set it with a TTL
	_, err := conn.Do("SETEX", getRedisKey(token), rs.SessionDuration.Seconds(), buf)
	if err != nil {
		return fmt.Errorf("error executing SETEX: %v", err)
	}
	return nil
}

//Get gets the session state associated with the provided session token,
//and resets the expiry time. The previously-stored state will be decoded
//into the sessionState value, so that must be passed by reference.
func (rs *RedisStore) Get(token Token, sessionState interface{}) error {
	conn := rs.pool.Get()
	defer conn.Close()

	//pipeline GET and EXPIRE commands
	//to get the state and reset its TTL
	key := getRedisKey(token)
	conn.Send("GET", key)
	conn.Send("EXPIRE", key, rs.SessionDuration.Seconds())
	conn.Flush()

	//GET command reply
	getReply, err := redis.Bytes(conn.Receive())
	if err != nil {
		return fmt.Errorf("error executing GET: %v", err)
	}
	if err := gob.NewDecoder(bytes.NewBuffer(getReply)).Decode(sessionState); err != nil {
		return fmt.Errorf("error decoding session state: %v", err)
	}

	//no need to look at the EXPIRE command reply
	return nil
}

//Delete deletes all session state data associated with the provided session token.
func (rs *RedisStore) Delete(token Token) error {
	conn := rs.pool.Get()
	defer conn.Close()
	_, err := conn.Do("DEL", getRedisKey(token))
	if err != nil {
		return fmt.Errorf("error executing DEL: %v", err)
	}
	return nil
}

//getRedisKey() returns the redis key to use for the SessionID
func getRedisKey(token Token) string {
	//add the prefix "sid:" to keep session keys separate from
	//other keys that might end up in this redis instance
	return "sid:" + token.ID().String()
}
