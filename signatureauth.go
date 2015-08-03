// Package signedauth provides a Gin middleware for checking signed requests.
// Signed requests is a good way to secure endpoint which may alter databases.
package signedauth

import (
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"github.com/gin-gonic/gin"
	"hash"
	"net/http"
	"strings"
)

// Error defines the authentication failure with a status. The error string will *not* be returned by Gin.
type Error struct {
	Status int   // The status for this failure.
	Err    error // The error associated to this failure.
}

// SignatureAuth is the middleware function. It must be called with a struct which implements the Manager interface.
func SignatureAuth(mgr Manager) gin.HandlerFunc {

	return func(c *gin.Context) {
		accesskey, signature, err := extractAuthInfo(mgr, c.Request.Header.Get("Authorization"))
		if err != nil {
			// Credentials doesn't match, we return 401 Unauthorized and abort request.
			c.AbortWithError(err.Status, err.Err)
		} else if accesskey == "" && signature == "" && !mgr.AuthHeaderRequired() {
			c.Next()
		} else {
			// Authorization header has the correct format.
			secret, keyerr := mgr.SecretKey(accesskey, c.Request)
			if keyerr != nil {
				c.AbortWithError(keyerr.Status, keyerr.Err)
			} else {
				data, dataerr := mgr.DataToSign(c.Request)
				if dataerr != nil {
					c.AbortWithError(dataerr.Status, dataerr.Err)
				} else if !isSignatureValid(mgr.HashFunction(), secret, data, signature) {
					// Accesskey is valid but signature is not.
					c.AbortWithError(http.StatusUnauthorized, errors.New("wrong access key or signature"))
				} else {
					// Accesskey and signature are valid.
					c.Set(mgr.ContextKey(), mgr.ContextValue(accesskey))
					c.Next()
				}
			}
		}
	}
}

// extractAuthInfo extracts the authentication information from the provided auth string.
func extractAuthInfo(mgr Manager, auth string) (string, string, *Error) {
	if strings.HasPrefix(auth, mgr.AuthHeaderPrefix()+" ") {
		splitheader := strings.Split(auth, " ")
		if len(splitheader) != 2 {
			return "", "", &Error{http.StatusUnauthorized, errors.New("invalid authorization header")}
		}

		splitauth := strings.Split(splitheader[1], ":")
		if len(splitauth) != 2 {
			return "", "", &Error{http.StatusUnauthorized, errors.New("invalid format for access key and signature")}
		}
		return splitauth[0], splitauth[1], nil

	} else if mgr.AuthHeaderRequired() {
		return "", "", &Error{http.StatusUnauthorized, errors.New("invalid authorization header")}
	} else {
		return "", "", nil
	}

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
