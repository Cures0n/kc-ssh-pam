package main

import (
	"log"
	"os"
	"strings"
	"fmt"

	"github.com/Cures0n/kc-ssh-pam/internal/auth"
	"github.com/Cures0n/kc-ssh-pam/internal/conf"
	"github.com/Cures0n/kc-ssh-pam/internal/flags"
)

var (
	version   string
	buildDate string
	commitSha string
)

func main() {
	flags.ParseFlags(version, buildDate, commitSha)
	c, err := conf.LoadConfig()
	if err != nil {
		log.Fatalf("Error reading config file: %s", err)
	}

	providerEndpoint := c.Endpoint + "/realms/" + c.Realm
	username := os.Getenv("PAM_USER")
    hostname, err := os.Hostname()
    as_code := strings.Split(hostname, "-")[0]
    groupName := fmt.Sprintf("%s_GPB_USER", strings.ToUpper(as_code))

	// Analyze the input from stdIn and split the password if it containcts "/"  return otp and pass
	password, otp, err := auth.ReadPasswordWithOTP()
	if err != nil {
		log.Fatal(err)
	}

	// Get provider configuration
	provider, err := auth.GetProviderInfo(providerEndpoint)
	if err != nil {
		log.Fatalf("Failed to retrieve provider configuration for provider %v with error %v\n", providerEndpoint, err)
	}

	// Retrieve an OIDC token using the password grant type
	accessToken, err := auth.RequestJWT(username, password, otp, provider.TokenURL, c.ClientID, c.ClientSecret, c.ClientScope)
	if err != nil {
		log.Fatalf("Failed to retrieve token for %v - error: %v\n", username, err)
		os.Exit(2)
	}

	// Verify the token and retrieve the ID token
	if err := provider.VerifyToken(accessToken); err != nil {
		// handle the error
		log.Fatalf("Failed to verify token %v for user %v\n", err, username)
		os.Exit(3)
	}

     // Проверка членства пользователя в группе
     isUserMember, err := auth.IsUserInGroup(provider.UserInfoURL, accessToken, groupName)
     if err != nil {
        log.Fatalf("Ошибка проверки членства: %v\n", err)
        os.Exit(3)
     }

     if isUserMember {
        log.Printf("User %s is a member of %s group\n", username, groupName)
     } else {
        log.Printf("User %s is NOT a member of %s group\n", username, groupName)
        os.Exit(3)
     }

	log.Println("Token acquired and verified Successfully for user -", username)
}
