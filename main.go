package main

import (
	"log"
	"os"
	"strings"

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
    as_code := strings.Split(os.Getenv("HOSTNAME"), "-")[0]

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

    // Получение ID группы
     groupID, err := auth.GetGroupID(providerEndpoint, accessToken, as_code)
     if err != nil {
        log.Fatalf("Ошибка получения groupID: %v\n", err)
        os.Exit(3)
     }

     // Проверка членства пользователя в группе
     isUserMember, err := auth.IsUserInGroup(providerEndpoint, accessToken, groupID, username)
     if err != nil {
        log.Fatalf("Ошибка проверки членства: %v\n", err)
        os.Exit(3)
     }
    //  fmt.Printf(isUserMember)

     if isUserMember {
        log.Printf("User %s is a member of %s_GPB_USER group\n", username, strings.ToUpper(as_code))
     } else {
        log.Printf("User %s is NOT a member of %s_GPB_USER group\n", username, strings.ToUpper(as_code))
        os.Exit(3)
     }

	log.Println("Token acquired and verified Successfully for user -", username)
}
