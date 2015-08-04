// Package headerauth provides a Gin middleware for checking signed requests.
// Signed requests is a good way to secure endpoint which may alter databases.
package headerauth

import (
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

// AuthErr defines the authentication failure with a status. The error string will *not* be returned by Gin.
type AuthErr struct {
	Status int   // Status for this failure.
	Err    error // Error associated to this failure.
}

// AuthInfo stores the authentication information.
type AuthInfo struct {
	AccessKey  string // AccessKey as extracted from the header.
	Secret     string // Secret as set in manager.Authorize.
	Signature  string // Signature as extracted from the header.
	DataToSign string // DataToSign as set in manager.CheckHeader.
}

// HeaderAuth is the middleware function. It must be called with a struct which implements the Manager interface.
func HeaderAuth(m Manager) gin.HandlerFunc {

	return func(c *gin.Context) {
		auth := &AuthInfo{}
		if err := extractAuthInfo(m, auth, c.Request.Header.Get(m.HeaderName())); err != nil {
			// Credentials doesn't match, we return 401 Unauthorized and abort request.
			c.AbortWithError(err.Status, err.Err)
		} else if auth.AccessKey == "" && auth.Signature == "" && !m.HeaderRequired() {
			c.Next()
		} else {
			// Authorization header has the correct format.
			if err := m.CheckHeader(auth, c.Request); err != nil {
				c.AbortWithError(err.Status, err.Err)
			} else if !isSignatureValid(m, auth) {
				// Accesskey is valid but signature is not.
				c.AbortWithError(http.StatusUnauthorized, errors.New("wrong access key or signature"))
			} else {
				// Accesskey and signature are valid.
				c.Set(m.ContextKey(), m.Authorize(auth))
				c.Next()
			}
		}
	}
}

// extractAuthInfo extracts the authentication information from the provided auth string.
func extractAuthInfo(m Manager, auth *AuthInfo, hdr string) (err *AuthErr) {
	if strings.HasPrefix(hdr, m.HeaderPrefix()+" ") {
		splitheader := strings.Split(hdr, " ")
		if len(splitheader) != 2 {
			return &AuthErr{http.StatusUnauthorized, errors.New("invalid authorization header")}
		}

		if hasSep, sep := m.HeaderSeparator(); hasSep {
			splitauth := strings.Split(splitheader[1], sep)
			if len(splitauth) != 2 {
				return &AuthErr{http.StatusUnauthorized, errors.New("invalid format for access key and signature")}
			}
			auth.AccessKey = splitauth[0]
			auth.Signature = splitauth[1]
			return
		}
		auth.AccessKey = splitheader[1]
		return

	} else if m.HeaderRequired() {
		return &AuthErr{http.StatusUnauthorized, errors.New("invalid authorization header")}
	}
	return
}

// isSignatureValid signs the request with the provided secret, and returns that signature.
func isSignatureValid(m Manager, auth *AuthInfo) bool {
	hashFunc := m.HashFunction()
	if hashFunc == nil {
		return true
	}
	hash := hmac.New(hashFunc, []byte(auth.Secret))
	hash.Write([]byte(auth.DataToSign))
	if messageMAC, err := hex.DecodeString(auth.Signature); err == nil {
		return hmac.Equal(hash.Sum(nil), messageMAC)
	}
	return false
}
