# Go Sessions

This package is a simple, modular sessions package for Go web services. Key features include:

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
    store := sessions.NewRedisStore(sessions.NewRedisPool(redisAddr), time.Hour)
}
```

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

To end a session, simply call `manager.EndSession()`. This will delete the session state from the `Store`, which will cause the current token to be treated as invalid on all subsequent requests.

```go
func SignOutHandler(w http.ResponseWriter, r *http.Request) {
    //get the current session state and token to ensure there is an active session
    sessionState := &SessionState{}
    token, err := manager.GetState(r, sessionState)
    if err != nil {
        //...handle error...
    }

    //end the session associated with the token
    if err := manager.EndSession(token); err != nil {
        //...handle error...
    }
}
```

## Modular Usage

If you don't want to use the `Manager` object, you can instead use the `Token` and `Store` objects directly. This allows you to include the session token in the response in other ways (e.g. a cookie, or in the response body). For example:

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

