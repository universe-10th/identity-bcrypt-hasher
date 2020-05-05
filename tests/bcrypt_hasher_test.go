package tests

import (
	bcrypt "github.com/universe-10th/identity-bcrypt-hasher"
	bcrypt2 "golang.org/x/crypto/bcrypt"
	"testing"
)

func TestHasherPassword(t *testing.T) {
	const pass1 = "foo$123"
	const pass2 = "foo$456"

	if hashed1, err := bcrypt.Default.Hash(pass1); err != nil {
		t.Errorf("No error should be raised on hashing. Error returned: %s\n", err)
	} else if err := bcrypt.Default.Validate(pass1, hashed1); err != nil {
		t.Errorf("No error should be raised on validating. Error returned: %s\n", err)
	} else if err := bcrypt.Default.Validate(pass2, hashed1); err != bcrypt2.ErrMismatchedHashAndPassword {
		t.Errorf("Error should be raised on invalid password: bcrypt.ErrMismatchedHashAndPassword. Error returned: %s\n", err)
	}
}
