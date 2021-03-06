package headerauth

// Managers has some help definitions for creating auth managers.

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"github.com/gin-gonic/gin"
	"hash"
	"net/http"
	"strconv"
	"strings"
)

// Manager defines the functions needed to fulfill an auth key managing role.
type Manager interface {
	Authorize(*AuthInfo) (interface{}, *AuthErr)   // Authenticate after valid signature (or fail to authenticate), return the value which will be stored in the context from the access key.
	CheckHeader(*AuthInfo, *http.Request) *AuthErr // Checks the header for protocol validation, returns an error if the headers are invalid.
	ContextKey() string                            // The key in the context where will be set the appropriate value if the request was correctly signed.
	HashFunction() func() hash.Hash                // Returns the hash function to use, e.g. sha1.New (imported from "crypto/sha1"), or sha512.New384 for SHA-384.
	HeaderName() string                            // Name of the header where the access key and (optional) signature should be, e.g. "Authorization".
	HeaderPrefix() string                          // The beginning of the string from the HTTP_AUTHORIZATION header. The exact header must be followed by a space.
	HeaderRequired() bool                          // Whether or not a request without any header should be accepted (c.Next) or forbidden (c.AbortWithError with status 403).
	HeaderSeparator() (bool, string)               // Whether there is a separator between the access key and signature, and what that separator is.
	PreAbort(*gin.Context, *AuthInfo, *AuthErr)    // Called just prior to aborting the request.
	PostAuth(*gin.Context, *AuthInfo, *AuthErr)    // Called right after auth, i.e prior to calling context.Next()
}

// HMACManager is a partial implementation of Manager which helps in defining an HMAC manager.
type HMACManager struct {
	Required bool             // Whether the missing header should lead to an error or continue with the next middleware (set to false to allow for multiple auth schemes on the same endpoint).
	Prefix   string           // Prefix in the Authorization header to which should be checked for this auth scheme.
	Key      string           // Gin context key where will be stored the successful auth and uniquely identifiable value.
	Hash     func() hash.Hash // Hash function used for HMAC computation.
}

// HeaderName is set to Authorization for an HMAC manager.
func (m HMACManager) HeaderName() string {
	return "Authorization"
}

// HeaderPrefix returns the prefix used in the initialization.
func (m HMACManager) HeaderPrefix() string {
	return m.Prefix
}

// HeaderRequired returns true because we want to forbid any non-signed request in this group.
func (m HMACManager) HeaderRequired() bool {
	return m.Required
}

// HeaderSeparator is a colon (":") for an HMAC manager.
func (m HMACManager) HeaderSeparator() (bool, string) {
	return true, ":"
}

// ContextKey returns the key which will store the return from ContextValue() in Gin's context.
func (m HMACManager) ContextKey() string {
	return m.Key
}

// HashFunction returns the hash function used for HMAC computation.
func (m HMACManager) HashFunction() func() hash.Hash {
	return m.Hash
}

// PreAbort defaults to NO-OP.
func (m HMACManager) PreAbort(*gin.Context, *AuthInfo, *AuthErr) {}

// PostAuth defaults to NO-OP.
func (m HMACManager) PostAuth(*gin.Context, *AuthInfo, *AuthErr) {}

// NewHMACManager returns a new HMACManager with the provided parameters.
func NewHMACManager(prefix string, contextKey string, hash func() hash.Hash) *HMACManager {
	return &HMACManager{Prefix: prefix, Key: contextKey, Hash: hash, Required: true}
}

// NewHMACSHA1Manager returns a new HMACManager with the hash function set to SHA1 (which has known theoretical attacks).
func NewHMACSHA1Manager(prefix string, contextKey string) *HMACManager {
	return NewHMACManager(prefix, contextKey, sha1.New)
}

// NewHMACSHA384Manager returns a new HMACManager with the hash function set to SHA384.
func NewHMACSHA384Manager(prefix string, contextKey string) *HMACManager {
	return NewHMACManager(prefix, contextKey, sha512.New384)
}

// TokenManager is an auth manager which does not check for signatures but only for a valid token (or access key).
type TokenManager struct {
	HdrName  string // Name of the header which contains the token.
	Required bool   // Whether the missing header should lead to an error or continue with the next middleware (set to false to allow for multiple auth schemes on the same endpoint).
	Prefix   string // Prefix in the Authorization header to which should be checked for this auth scheme.
	Key      string // Gin context key where will be stored the successful auth and uniquely identifiable value.
}

// HeaderName returns the header name for this Token based auth manager.
func (t TokenManager) HeaderName() string {
	return t.HdrName
}

// HeaderPrefix returns the header prefix for this Token based auth manager.
func (t TokenManager) HeaderPrefix() string {
	return t.Prefix
}

// HeaderRequired returns whether a successful auth is required for this Token based auth manager.
func (t TokenManager) HeaderRequired() bool {
	return t.Required
}

// HeaderSeparator returns false, because we are only looking to extract the token and no signature from the header.
func (t TokenManager) HeaderSeparator() (bool, string) {
	return false, ""
}

// ContextKey returns the context key prefix for this Token based auth manager.
func (t TokenManager) ContextKey() string {
	return t.Key
}

// HashFunction returns nil because no signature will be computed.
func (t TokenManager) HashFunction() func() hash.Hash {
	return nil
}

// PreAbort defaults to NO-OP.
func (t TokenManager) PreAbort(*gin.Context, *AuthInfo, *AuthErr) {}

// PostAuth defaults to NO-OP.
func (t TokenManager) PostAuth(*gin.Context, *AuthInfo, *AuthErr) {}

// NewTokenManager returns a new AccesKeyManager which does not check for signatures, but only validity of access key.
func NewTokenManager(hdrName string, prefix string, contextKey string) *TokenManager {
	return &TokenManager{Prefix: prefix, Key: contextKey, HdrName: hdrName, Required: true}
}

// HTTPBasicAuth is an example of an HTTP Basic Auth "protection".
// There is no signature to be computed nor a separator, so it's effectively a Token based auth.
// Whether the username and password are correct happen in the Authorize function.
type HTTPBasicAuth struct {
	Realm string // The Realm returned for custom authentication name.
	*TokenManager
}

// HeaderPrefix is set to "Basic" as per RFC for HTTP Basic Auth.
func (m HTTPBasicAuth) HeaderPrefix() string {
	return "Basic"
}

// HeaderName returns Authorization, as per RFC for HTTP Basic Auth.
func (m HTTPBasicAuth) HeaderName() string {
	return "Authorization"
}

// CheckHeader checks that the provided auth string is correctly formatted, and
// set the access key and secret key of AuthInfo to the username and password given.
func (m HTTPBasicAuth) CheckHeader(auth *AuthInfo, req *http.Request) (err *AuthErr) {
	// At this step, auth.AccessKey contains the Base64 encoded authentication string.
	// Let's extract the provided username and password.
	access, berr := base64.StdEncoding.DecodeString(auth.AccessKey)
	if berr != nil {
		return &AuthErr{Status: 401, Err: errors.New("could not base64 decode access string")}
	}

	splitauth := strings.Split(string(access), ":")
	if len(splitauth) != 2 {
		return &AuthErr{401, errors.New("invalid format for username and password")}
	}
	// The format is correct, let's set the authInfo.
	auth.AccessKey = splitauth[0]
	auth.Secret = splitauth[1]
	return
}

// PreAbort will set the appropriate HTTP Basic header.
func (m HTTPBasicAuth) PreAbort(c *gin.Context, auth *AuthInfo, err *AuthErr) {
	if m.Realm == "" {
		m.Realm = "Authorization Required"
	}
	m.Realm = "Basic realm=" + strconv.Quote(m.Realm)
	c.Header("WWW-Authenticate", m.Realm)
}

// NewHTTPBasicAuthManager returns a new HTTP Basic Auth manager.
func NewHTTPBasicAuthManager(contextKey string, realm string) *HTTPBasicAuth {
	return &HTTPBasicAuth{Realm: realm, TokenManager: &TokenManager{Key: contextKey, Required: true}}
}
