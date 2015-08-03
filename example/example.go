package main

import (
	"github.com/ChristopherRabotin/gin-contrib-signedauth"
	"github.com/gin-gonic/gin"
	"net/http"
)

func main() {
	mgr := SHA384Manager{"super-secret-password", signedauth.NewHMACSHA384Manager("SAUTH", "contextKey")}
	router := gin.Default()
	router.Use(signedauth.SignatureAuth(mgr))
	router.POST("/test/", func(c *gin.Context) {
		c.String(http.StatusOK, "Success.")
	})
	router.PUT("/test/", func(c *gin.Context) {
		c.String(http.StatusOK, "Success.")
	})
	router.Run("localhost:31337")
}
