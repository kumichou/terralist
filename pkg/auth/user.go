package auth

import "encoding/gob"

// User holds the user authorized user data.
type User struct {
	Name        string                 `json:"name"`
	Email       string                 `json:"email"`
	AuthorityID string                 `json:"authority_id"`
	Claims      map[string]interface{} `json:"claims"`
}

func init() {
	// Register the user interface.
	gob.Register(&User{})
}
