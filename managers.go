package signedauth

// Managers has some help definitions for creating auth managers.

import (
	"crypto/sha1"
	"crypto/sha512"
	"hash"
	"net/http"
)

// Manager defines the functions needed to fulfill an auth key managing role.
type Manager interface {
	HeaderName() string                                 // Name of the header where the access key and (optional) signature should be, e.g. "Authorization".
	HeaderPrefix() string                               // The beginning of the string from the HTTP_AUTHORIZATION header. The exact header must be followed by a space.
	HeaderRequired() bool                               // Whether or not a request without any header should be accepted (c.Next) or forbidden (c.AbortWithError with status 403).
	HeaderSeparator() (bool, string)                    // Whether there is a separator between the access key and signature, and what that separator is.
	Authorize(string, *http.Request) (string, *AuthErr) // Given the access key and the request object, returns the secret key associated (which will be used to compute the HMAC), or return an error. Header verification should happen here, and an error returned to fail.
	ContextKey() string                                 // The key in the context where will be set the appropriate value if the request was correctly signed.
	ContextValue(string) interface{}                    // The value which will be stored in the context if authentication is successful, from the access key.
	DataToSign(*http.Request) (string, *AuthErr)        // The data which must be signed and verified, or an error to return.
	HashFunction() func() hash.Hash                     // Returns the hash function to use, e.g. sha1.New (imported from "crypto/sha1"), or sha512.New384 for SHA-384.
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

// DataToSign returns an empty string which is used to the (non) computation of the signature.
func (t TokenManager) DataToSign(*http.Request) (string, *AuthErr) {
	return "", nil
}

// HashFunction returns nil because no signature will be computed.
func (t TokenManager) HashFunction() func() hash.Hash {
	return nil
}

// NewTokenManager returns a new AccesKeyManager which does not check for signatures, but only validity of access key.
func NewTokenManager(hdrName string, prefix string, contextKey string) *TokenManager {
	return &TokenManager{Prefix: prefix, Key: contextKey, HdrName: hdrName, Required: true}
}
