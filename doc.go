/*Package sessions provides a simple, modular sessions package for Go web services.

Installation

Use `go get` to install:

	go get github.com/davestearns/sessions

Basic Usage

Start by constructing a session `Store` in your startup code. For example,
to create a new redis store, use code like this:

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

The `NewRedisPool()` function creates a new `redis.Pool` instance that is configured
with defaults that should work well in most situations. The time duration passed as
the second parameter controls when the pool will do a health check on the connection:
if the connection has been idle for longer than the duration, the pool will execute
a `PING` request to ensure that the connection is still alive.

The time duration passed as the second parameter to `NewRedisStore()` controls the
time-to-live for session state. The TTL is reset each time you get the state,
so this controls how long idle sessions will remain before expiring.

Next, construct a `Manager` and give it your token signing key(s), along with your store.
The keys are used to digitally sign the session tokens returned to clients, so that we can
easily detect attempts to modify the token to session-hop. If you supply more than one key,
the manager will rotate which key it uses, making it harder for an attacker to
crack your signing key.

	//load your token signing keys from environment variables or wherever
	signingKeys := []string{os.GetEnv(SIGNKEY_1), os.GetEnv(SIGNKEY_2)}
	manager := sessions.NewManager(sessions.DefaultIDLength, signingKeys, store)

To begin a session within one of your handler functions, use `manager.BeginSession()`:

	func SignInHandler(w http.ResponseWriter, r *http.Request) {
		//...authentication code...

		//construct and initialize your own session state struct
		sessionState := NewSessionState(...)

		//begin a new session: this will add an Authorization header to the response
		//containing the new session token. The new token is returned in case you
		//want to do something with it.
		token, err := manager.BeginSession(w, sessionState)
		if err != nil {
			//...handle error...
		}

		//...write response body...
	}

The `.BeginSession()` method will add an `Authorization` header to the response containing
the value `Bearer <token-string>`. The `<token-string>` will be a base64-encoded version
of the newly-generated session token. The session ID portion of the token is a series of
crypto-random bytes, the length of which is controlled by the `idLength` parameter passed
to `sessions.NewManager`. The token also contains an HMAC signature of the ID, which is
generated using one of your signing keys.

Clients should hold on to this `Authorization` response header value and send it back
to the server with all subsequent requests. The `.GetState()` method described below will
extract the session token from the `Authorization` request header, verify it, and fetch
the associated state from the store. If the client attempted to modify the token, the
HMAC signature verification will fail, an the token will be considered invalid.

This package uses the `Authorization` header instead of a cookie to avoid CSRF attacks
(see https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)).
Since `Authorization` headers are not handled automatically by the browser,
they are not susceptible to typical CSRF attacks, but they do require some client-side
JavaScript to receive the response header value, and include that value in the
`Authorization` header on all subsequent requests.

If you would prefer to use a cookie, or some other method of transmission, you can
bypass the `Manager` object and use the `Token` and `Store` objects directly.

For strategies on how you can share your global `Manager` instance with your handler
functions see https://drstearns.github.io/tutorials/gohandlerctx/.

To get the previously-saved session state during subsequent requests, use `manager.GetState()`:

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

To end a session, simply call `manager.EndSession()` passing the current request.
This will get and verify the token from the request, and then delete the session
state from the `Store`. Once the token and associated session state is deleted,
the token will be treated as invalid on all subsequent requests.

	func SignOutHandler(w http.ResponseWriter, r *http.Request) {
		//end the current session
		if err := manager.EndSession(r); err != nil {
			//...handle error...
		}
	}
*/
package sessions
