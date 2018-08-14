package sessions

//Store is the common interface for all session state stores
type Store interface {
	//Save saves the sessionState to the store, associated with the token
	Save(token Token, sessionState interface{}) error
	//Get populates sessionState with the previously-saved state associated with the token
	Get(token Token, sessionState interface{}) error
	//Delete removes state from the store associated with the token
	Delete(token Token) error
}
