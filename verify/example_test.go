package verify_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"

	"github.com/moapis/authenticator/verify"
)

func ExampleVerificationErr() {
	token := base64.RawURLEncoding.EncodeToString([]byte("{\"Alg\": \"foo\"}"))
	_, err := verify.ParseJWTHeader(token)
	var ve *verify.VerificationErr
	if errors.As(err, &ve) {
		fmt.Printf("Error is of type %T", ve)
	}
	// Output: Error is of type *verify.VerificationErr
}

func ExampleParseJWTHeader() {
	token := base64.RawURLEncoding.EncodeToString([]byte("{\"Alg\": \"EdDSA\", \"Kid\": \"10\"}"))
	kid, err := verify.ParseJWTHeader(token)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Key ID: %d", kid)
	// Output: Key ID: 10
}
