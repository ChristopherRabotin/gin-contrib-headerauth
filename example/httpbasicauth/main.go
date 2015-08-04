package main

import (
	"errors"
	"github.com/ChristopherRabotin/gin-contrib-headerauth"
	"github.com/gin-gonic/gin"
)

// HTTPBasicDemo is an example of an HTTP Basic Auth.
type HTTPBasicDemo struct {
	Accounts map[string]string // Stores usernames to accounts.
	*headerauth.HTTPBasicAuth // Embedded struct greatly helps in defining HTTP Basic Auth.
}

// Authorize checks that the provided authorization is valid.
func (m HTTPBasicDemo) Authorize(auth *headerauth.AuthInfo) (val interface{}, err *headerauth.AuthErr) {
	if password, ok := m.Accounts[auth.AccessKey]; !ok || password != auth.Secret {
		err = &headerauth.AuthErr{401, errors.New("invalid credentials")}
	} else {
		// In CheckHeader we changed the AccessKey to be the actual username, instead
		// of the Base64 encoded authentication string.
		val = auth.AccessKey
	}
	return
}

func main() {
	mgr := HTTPBasicDemo{Accounts: map[string]string{"user": "password"}, HTTPBasicAuth: headerauth.NewHTTPBasicAuthManager("user", "My Protected Group")}
	router := gin.Default()
	router.Use(headerauth.HeaderAuth(mgr))
	router.GET("/test/", func(c *gin.Context) {
		c.String(200, "Success.")
	})
	router.Run("localhost:31337")
}
