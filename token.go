package sessions

//Token represents a session token
type Token interface {
	//String returns a base64-encoded version of the token
	String() string
	//ID returns the ID portion of the token
	ID() []byte
}
