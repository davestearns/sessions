package sessions

//Store describes what a session store can do
type Store interface {
	//Save saves the sessionState to the store, associated with the token
	Save(token Token, sessionState interface{}) error
	//Get populates sessionState with the data previously saved with the token
	Get(token Token, sessionState interface{}) error
	//Delete removes state associated with the token
	Delete(token Token) error
}
