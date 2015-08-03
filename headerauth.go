// Package signedauth provides a Gin middleware for checking signed requests.
// Signed requests is a good way to secure endpoint which may alter databases.
package headerauth

import (
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"github.com/gin-gonic/gin"
	"hash"
	"net/http"
	"strings"
)

// AuthErr defines the authentication failure with a status. The error string will *not* be returned by Gin.
type AuthErr struct {
	Status int   // The status for this failure.
	Err    error // The error associated to this failure.
}

// HeaderAuth is the middleware function. It must be called with a struct which implements the Manager interface.
func HeaderAuth(m Manager) gin.HandlerFunc {

	return func(c *gin.Context) {
		accesskey, signature, err := extractAuthInfo(m, c.Request.Header.Get(m.HeaderName()))
		if err != nil {
			// Credentials doesn't match, we return 401 Unauthorized and abort request.
			c.AbortWithError(err.Status, err.Err)
		} else if accesskey == "" && signature == "" && !m.HeaderRequired() {
			c.Next()
		} else {
			// Authorization header has the correct format.
			secret, dataToSign, err := m.CheckHeader(accesskey, c.Request)
			if err != nil {
				c.AbortWithError(err.Status, err.Err)
			} else if hashFunc := m.HashFunction(); hashFunc != nil && !isSignatureValid(hashFunc, secret, dataToSign, signature) {
				// Accesskey is valid but signature is not.
				c.AbortWithError(http.StatusUnauthorized, errors.New("wrong access key or signature"))
			} else {
				// Accesskey and signature are valid.
				c.Set(m.ContextKey(), m.Authorize(accesskey))
				c.Next()
			}
		}
	}
}

// extractAuthInfo extracts the authentication information from the provided auth string.
func extractAuthInfo(m Manager, auth string) (string, string, *AuthErr) {
	if strings.HasPrefix(auth, m.HeaderPrefix()+" ") {
		splitheader := strings.Split(auth, " ")
		if len(splitheader) != 2 {
			return "", "", &AuthErr{http.StatusUnauthorized, errors.New("invalid authorization header")}
		}

		if hasSep, sep := m.HeaderSeparator(); hasSep {
			splitauth := strings.Split(splitheader[1], sep)
			if len(splitauth) != 2 {
				return "", "", &AuthErr{http.StatusUnauthorized, errors.New("invalid format for access key and signature")}
			}
			return splitauth[0], splitauth[1], nil
		}
		return splitheader[1], "", nil

	} else if m.HeaderRequired() {
		return "", "", &AuthErr{http.StatusUnauthorized, errors.New("invalid authorization header")}
	}
	return "", "", nil
}

// isSignatureValid signs the request with the provided secret, and returns that signature.
func isSignatureValid(hashFunc func() hash.Hash, secret string, data string, signature string) bool {
	hash := hmac.New(hashFunc, []byte(secret))
	hash.Write([]byte(data))
	if messageMAC, err := hex.DecodeString(signature); err == nil {
		return hmac.Equal(hash.Sum(nil), messageMAC)
	}
	return false
}
