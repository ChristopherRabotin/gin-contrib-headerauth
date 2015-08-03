package signedauth

import (
	"crypto/sha1"
	"hash"
	"net/http"
)

// Manager defines the functions needed to fulfill an auth key managing role.
type Manager interface {
	AuthHeaderPrefix() string                         // The beginning of the string from the HTTP_AUTHORIZATION header. The exact header must be followed by a space.
	SecretKey(string, *http.Request) (string, *Error) // The secret key for the provided access key and request. Header verification should happen here, and an error returned to fail.
	DataToSign(*http.Request) (string, *Error)        // The data which must be signed and verified, or an error to return.
	AuthHeaderRequired() bool                         // Whether or not a request without any header should be accepted (c.Next) or forbidden (c.AbortWithError with status 403).
	HashFunction() func() hash.Hash                   // Returns the hash function to use, e.g. sha1.New (imported from "crypto/sha1"), or sha512.New384 for SHA-384.
	ContextKey() string                               // The key in the context where will be set the appropriate value if the request was correctly signed.
	ContextValue(string) interface{}                  // The value which will be stored in the context if authentication is successful, from the access key.
}

// HMACManager is a partial implementation of Manager which helps in defining an HMAC manager.
type HMACManager struct {
	Required bool             // Whether the missing header should lead to an error or continue with the next middleware (set to false to allow for multiple auth schemes on the same endpoint).
	Prefix   string           // Prefix in the Authorization header to which should be checked for this auth scheme.
	Key      string           // Gin context key where will be stored the successful auth and uniquely identifiable value.
	Hash     func() hash.Hash // Hash function used for HMAC computation.
}

// AuthHeaderPrefix returns the prefix used in the initialization.
func (m HMACManager) AuthHeaderPrefix() string {
	return m.Prefix
}

// ContextKey returns the key which will store the return from ContextValue() in Gin's context.
func (m HMACManager) ContextKey() string {
	return m.Key
}

// AuthHeaderRequired returns true because we want to forbid any non-signed request in this group.
func (m HMACManager) AuthHeaderRequired() bool {
	return m.Required
}

// HashFunction returns the hash function used for HMAC computation.
func (m HMACManager) HashFunction() func() hash.Hash {
	return m.Hash
}

// NewHMACManager returns a new HMACManager with the provided parameters.
func NewHMACManager(prefix string, contextKey string, hash func() hash.Hash) *HMACManager {
	return &HMACManager{Prefix: prefix, Key: contextKey, Hash: hash, Required: true}
}

// NewHMACSHA1Manager returns a new HMACManager with the provided parameters.
func NewHMACSHA1Manager(prefix string, contextKey string) *HMACManager {
	return NewHMACManager(prefix, contextKey, sha1.New)
}

// TODO: NewAccessKeyManager returns a new AccesKeyManager which does not check for signatures, but only validity of access key.
