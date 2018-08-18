# Go Sessions

[![Build Status](https://travis-ci.org/davestearns/sessions.png?branch=master)](https://travis-ci.org/davestearns/sessions)
[![GoDoc](https://godoc.org/github.com/davestearns/sessions?status.png)](https://godoc.org/github.com/davestearns/sessions)

A simple, modular sessions package for Go web services. Key features include:

- Very simple to integrate and use
- Modular design so you can use as much or as little as you wish
- Session tokens are crypto-random and digitally-signed to prevent session hopping
- Supports signing key rotation for added security
- You define the struct for session state, so it remains type-safe in your own code
- Session state can be stored in any database for which a Store implementation exists. Currently there is an implementation for redis, but others are welcome via a PR.

## Installation

```bash
go get github.com/davestearns/sessions
```

## Basic Usage

### Initialization

Start by constructing a session `Store` in your startup code. For example, to create a new redis store, use code like this:

```go
import (
    "time"
    "github.com/davestearns/sessions"
)

func main() {
    redisAddr := // ... network address of your redis server
    store := sessions.NewRedisStore(
        sessions.NewRedisPool(redisAddr, time.Minute*5), 
        time.Hour)
}
```

The `NewRedisPool()` function creates a new `redis.Pool` instance that is configured with defaults that should work well in most situations. The time duration passed as the second parameter controls when the pool will do a health check on the connection: if the connection has been idle for longer than the duration, the pool will execute a `PING` request to ensure that the connection is still alive.

The time duration passed as the second parameter to `NewRedisStore()` controls the time-to-live for session state. The TTL is reset each time you get the state, so this controls how long idle sessions will remain before expiring.

Next, construct a `Manager` and give it your token signing key(s), along with your store. The keys are used to digitally sign the session tokens returned to clients, so that we can easily detect attempts to modify the token to session-hop. If you supply more than one key, the manager will rotate which key it uses, making it harder for an attacker to crack your signing key.

```go
    //load your token signing keys from environment variables or wherever
    signingKeys := [][]byte{[]byte(os.GetEnv(SIGNKEY_1)), []byte(os.GetEnv(SIGNKEY_2))}
    manager := sessions.NewManager(sessions.DefaultIDLength, signingKeys, store)
```

### Beginning a Session

To begin a session within one of your handler functions, use `manager.BeginSession()`:

```go
func SignInHandler(w http.ResponseWriter, r *http.Request) {
    //...authentication code...

    //construct and initialize your own session state struct
    sessionState := NewSessionState(/* ... */)

    //begin a new session: this will add an Authorization header to the response
    //containing the new session token. The new token is returned in case you
    //want to do something with it.
    token, err := manager.BeginSession(w, sessionState)
    if err != nil {
        //...handle error...
    }

    //...write response body...
}
```

The `.BeginSession()` method will add an `Authorization` header to the response containing the value `Bearer <token-string>`. The `<token-string>` will be a base64-encoded version of the newly-generated session token. The session ID portion of the token is a series of crypto-random bytes, the length of which is controlled by the `idLength` parameter passed to `sessions.NewManager`. The token also contains an HMAC signature of the ID, which is generated using one of your signing keys.

Clients should hold on to this `Authorization` response header value and send it back to the server with all subsequent requests. The `.GetState()` method described below will extract the session token from the `Authorization` request header, verify it, and fetch the associated state from the store. If the client attempted to modify the token, the HMAC signature verification will fail, an the token will be considered invalid.

This package uses the `Authorization` header instead of a cookie to avoid [CSRF attacks](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)). Since `Authorization` headers are not handled automatically by the browser, they are not susceptible to typical CSRF attacks, but they do require some client-side JavaScript to receive the response header value, and include that value in the `Authorization` header on all subsequent requests.

For strategies on how you can share your global `Manager` instance with your handler functions see [Sharing Values with Go Handlers](https://drstearns.github.io/tutorials/gohandlerctx/).

### Getting Session State

To get the previously-saved session state during subsequent requests, use `manager.GetState()`:

```go
func SomeStatefulHandler(w http.ResponseWriter, r *http.Request) {
    //create a new empty session state
    sessionState := &SessionState{}
    //fill it using .GetSession()
    token, err := manager.GetState(r, sessionState)
    if err != nil {
        //...handle error...
    }

    //...use sessionState...
}
```

### Ending Sessions

To end a session, simply call `manager.EndSession()` passing the current request. This will get and verify the token from the request, and then delete the session state from the `Store`. Once the token and associated session state is deleted, the token will be treated as invalid on all subsequent requests.

```go
func SignOutHandler(w http.ResponseWriter, r *http.Request) {
    //end the current session
    if err := manager.EndSession(r); err != nil {
        //...handle error...
    }
}
```

## Modular Usage

The `Manager` object uses the `Authorization` HTTP header to transmit the session token. If you would prefer to use a different header, or perhaps a cookie, you can use the `Token` and `Store` objects directly. For example:

```go
func SignInHandler(w http.ResponseWriter, r *http.Request) {
    //...authentication code...

    //construct your own session state struct
    sessionState := NewSessionState(/* ... */)

    //generate a new session Token, passing your signingKey
    token, err := NewToken(signignKey)
    if err != nil {
        //...handle error...
        //this would only happen if the system didn't have
        //enough entropy to generate enough random bytes
    }

    //save the state to the store
    if err := sessionStore.Save(token, sessionState); err != nil {
        //...handle error...
    }

    //...include token in response...
    //you can use a cookie, or a different header, or put it in the response body
}
```

