package sully_test

import (
	"fmt"

	"github.com/alwindoss/sully"
)

func Example_fetchOpenIDToken() {
	cfg := &sully.Config{
		UserPoolID:     "dummy-user-pool-id",
		IdentityPoolID: "dummy-identity-pool-id",
		ClientID:       "dummy-client-id",
		Region:         "dummy-region",
	}
	client := sully.NewCognitoClient(cfg)
	token, err := client.Authenticate("user-name", "password")
	if err != nil {
		fmt.Printf("Error: %v", err)
		return
	}
	fmt.Printf("Token: %s\n", token)
}
