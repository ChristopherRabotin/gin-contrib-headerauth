# ChristopherRabotin/gin-contrib-headerauth
[![Build Status](https://travis-ci.org/ChristopherRabotin/gin-contrib-headerauth.svg?branch=master)](https://travis-ci.org/ChristopherRabotin/gin-contrib-headerauth) [![Coverage Status](https://coveralls.io/repos/ChristopherRabotin/gin-contrib-headerauth/badge.svg?branch=master&service=github)](https://coveralls.io/github/ChristopherRabotin/gin-contrib-headerauth?branch=master)
# Purpose
Allows to protect routes with a header authentication, with a HMAC signature validation or without it.

# Features
Quite customizable, including the following custom settings.
* Hash used for signature (e.g. SHA-1), cf `managers.Manager.HashFunction`.
* Authorization header prefix (e.g. SAUTH), cf `managers.Manager.HeaderPrefix`.
* Access key to secret key logic, header validation and data extraction for HMAC signature (e.g. hardcoded strings, database connection, etc.), cf `managers.Manager.CheckHeader`.
* Allow unsigned requests, so they can be intercepted by another middleware for example, cf. `managers.Manager.HeaderRequired`.
* Context key and value which can be used in the rest of the calls, cf. `managers.Manager.ContextKey` and cf. `managers.Manager.Authorize`.
* Custom functions prior to an authentication failure (`managers.Manager.PreAbort`) and post success (`managers.Manager.PostAuth`).
* Allow access on token in header only (without signature verification), cf `managers.TokenManager`.
* Allow access HTTP Basic Auth , cf `managers.HTTPBasicAuth` and the [HTTP Basic Auth example](./example/httpbasicauth/).

## Performance
Since we're using Gin, the performance is quite blazing fast. Running the full test suite takes about 0.05 seconds on a 2013 Intel core i5.

# Examples
Refer to the [tests](./headerauth_test.go) and the [example](./example/) directory.

# Quick start
## Table of Contents
+ [Access key and secret key authentication](./README.md#access-key-and-secret-authorization)
	+ [Code](./README.md#code)
+ [Token authentication](./README.md#token-based-authorization)
	+ [Code](./README.md#code-1)
+ [HTTP Basic authentication](./README.md#http-basic-authentication)
	+ [Code](./README.md#code-2)

## Access key and secret authorization
### Usage example
Server *S* (running Gin) allows external parties to provide it information. We want to ensure that the data provided by the external party does come from
that external party, and is not vulnerable to [replay attacks](https://en.wikipedia.org/wiki/Replay_attack).

### Set up
#### Key pair
Create a key pair of an access key and a secret key, both of which are provided to the external party, herein *E*.

In this example, we are using *static* access keys and secret keys, where the access key is `"my_access_key"` and the secret key is `"super-secret-password"`.
A more concrete example, as commented below, will most likely use a database connection to store and retrieve access and secret keys.

#### Signature protocol
A signature protocol must be determined and known by the *S* and all the external parties (such as *E*) which will be doing requests to the endpoint.

Here, we'll be implementing a *similar* signing method to the [Amazon AWS REST one](http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html).
##### Data to sign
In the following example, what is in curly brackets (`{` and `}`) corresponds to a variable. There will be an example below (new lines are `\n`).
```
{REQUEST METHOD}
hex_digest(md5_checksum({REQUEST BODY}))
iso_format({DATE TIME})
```
For example, in the case of a POST request at `2015-08-03T19:24:21.807Z` where the body is set to `"This is the body of my request."` and the secret is `"super-secret-password"`,
the signature should be `44393657f98352b9cfeb16f6152f1d02682c3885`. The signature data which led to this signature is as follows:
```
POST
6ed0e5471b9d353fab364c65f73f94f9
2015-08-03T19:24:21.807Z
```

##### Headers
A MIME-valid header must select to store the type authentication scheme used, the access key and the signature. Additional MIME-valid headers may be used for more data.
In this example, we'll also request *E* to set to `Date` header to the date at which the request was sent. Also in this example, any request which is older than fifteen
minutes will be rejected.

**Important note:** if your header is not MIME-valid, then Go [will not allow access to it](https://golang.org/src/net/textproto/reader.go). For example, mixed caps are only
allowed if there is a dash before each uppercase letter (apart from the first letter of the header name): `AccessKey` is **invalid** but `Access-Key` is valid.

For example, let's say that the header which will contain the access key and signature is `Authorization` and the prefix prior to the access key and signature is `SAUTH`.
The prefix avoids conflict with other middlewares which read that same header. It also allows for support of several headerauth middleware on the same routes, but whose
logic is different based on the protocol (one could imagine an update to the protocol while still having to support old clients, e.g. `SAUTH` and `SAUTH2`).

Building on the example above, we will set the following headers:
* `Authorization` to `SAUTH my_access_key:44393657f98352b9cfeb16f6152f1d02682c3885`;
* `Date` to `2015-08-03T19:24:21.807Z`.

### Code
#### Auth manager code
We'll start be defining a `struct` which details how the manager should work.

**Note:** we'll be embedding the `HMACManager` struct from `managers.go` which massively simplifies the definition of an auth manager by already partially implementing the `Manager`
interface. If you need (or *want* for some odd reason) to write your full implementation of the `Manager` interface, check out [managers.go](./managers.go).

```go
// SHA384Manager is an example definition of an Manager struct.
type SHA384Manager struct {
	// --> If using a database to check for the secret, you'll probably use a different struct, which may have a pointer
	// --> to your database connection or even not set it, and have all the database connection, querying, and friends
	// --> performed in the `CheckHeader` function.
	Secret string
	*headerauth.HMACManager
}
```

We now need to define how the backend should check that the access key is valid, what the expected secret key for this access key is, and especially ensure that the protocol agreed
upon is respected (i.e. check that the Date header is within fifteen minutes, and build and return the expected string which will be signed).
All this is done in the `CheckHeader(string, *http.Request) (string, string, *AuthErr)` function.

**Note:** it is good practice to have as little difference between error statuses throughout the verification process to avoid to play [Mastermind](https://en.wikipedia.org/wiki/Mastermind_%28board_game%29)
with a potential attacker.

**Note:** `headerauth.AuthErr` will call the Gin context function `AbortWithError`, which will only return the error code to the client without any error message. The error message is only visible
in the server logs.

```go
 // CheckHeader returns the secret key and the data to sign from the provided access key.
// Here should reside additional verifications on the header, or other parts of the request, if needed.
func (m SHA384Manager) CheckHeader(auth *headerauth.AuthInfo, req *http.Request) (err *headerauth.AuthErr) {
	if req.ContentLength != 0 && req.Body == nil {
		// Not sure whether net/http or Gin handles these kinds of fun situations.
		return &headerauth.AuthErr{400, errors.New("received a forged packet")}
	}
	// Grabbing the date and making sure it's in the correct format and is within fifteen minutes.
	dateHeader := req.Header.Get("Date")
	if dateHeader == "" {
		return &headerauth.AuthErr{406, errors.New("no Date header provided")}
	}
	date, derr := time.Parse("2006-01-02T15:04:05.000Z", dateHeader)
	if derr != nil {
		return &headerauth.AuthErr{408, errors.New("could not parse date")}
	} else if time.Since(date) > time.Minute*15 {
		return &headerauth.AuthErr{410, errors.New("request is too old")}
	}

	// --> Here is where you would do a database call to check if the access key is valid
	// --> and what the appropriate secret key is, e.g.:
	// if secretKey, dbErr := getSecretFromDB(access); dbErr == nil && auth.Secret == secretKey { ...
	if auth.AccessKey == "my_access_key" {
		// In this example, we'll be implementing a *similar* signing method to the Amazon AWS REST one.
		// We'll use the HTTP-Verb, the MD5 checksum of the Body, if any, and the Date header in ISO format.
		// http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
		// Note: We are returning a variety of error codes which don't follow the spec only for the purpose of testing.
		serializedData := req.Method + "\n"
		if req.ContentLength != 0 {
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				return &headerauth.AuthErr{402, errors.New("could not read the body")}
			}
			hash := md5.New()
			hash.Write(body)
			serializedData += hex.EncodeToString(hash.Sum(nil)) + "\n"
		} else {
			serializedData += "\n"
		}
		// We know from Authorize that the Date header is present and fits our time constaints.
		serializedData += req.Header.Get("Date")

		auth.Secret = m.Secret
		auth.DataToSign = serializedData
		return
	}
	return &headerauth.AuthErr{418, errors.New("you are a teapot")}
}
```

Finally, we only need to define the value to store in the Gin context for a valid authentication. This will be useful for subsequent parts of the
code which perform tasks based on the valid access key.

```go
// Authorize returns the value to store in Gin's context at ContextKey().
// This is only called once the requested has been authorized to pursue,
// so logging of success should happen here.
func (m SHA384Manager) Authorize(auth *headerauth.AuthInfo) (interface{}, *headerauth.AuthErr) {
	if auth.AccessKey == "my_access_key" {
		return "All good with my access key!", nil
	}
	return "All good with any access key!", nil
}
```

### Defaults
Since `SHA384Manager` embeds the `HMACManager`, the following defaults apply:
* Header name where the access key and signature should be: `Authorization`
* Hash function used for signing the data with the secret key [SHA384](https://en.wikipedia.org/wiki/SHA-2) (`sha512.New384` in Go).
* Header separator between the access key and the signature is a colon `:`. This must be a character which **cannot** be found in the access key.

### Setting the auth manager as a middleware
In the main Gin router, you must initialize and set this created auth manager.
```go
func main() {
	// Setting the secret to "super-secret-password".
	// Setting the header prefix to `SAUTH`, and the context key in Gin to be called `contextKey`.
	mgr := SHA384Manager{"super-secret-password", headerauth.NewHMACSHA384Manager("SAUTH", "contextKey")}
	router := gin.Default()
	router.Use(headerauth.SignatureAuth(mgr))
	router.POST("/test/", func(c *gin.Context) {
		c.String(http.StatusOK, "Success.")
	})
	router.PUT("/test/", func(c *gin.Context) {
		c.String(http.StatusOK, "Success.")
	})
	router.Run("localhost:31337")
}
```

## Token based authorization
### Usage example
Server *S* (running Gin) allows external parties to provide it information based on very simple auth scheme where only a unique token is used.
For example, a (large) list of valid tokens can be provided to an external party, *E*, which only needs to specify one of those per request in
order to be granted access. 

### Set up
The set up is trivial for this scheme because there is no signature involved.

#### Tokens
A list of valid tokens must be provided to *E*.

#### Headers
It should be agreed what the headers should be. For example, we can expect the header to be `X-Token-Auth` and the prefix to be `Token`.

### Code
#### Manager code
```go
// TMgr is an example definition of an AuthKeyManager struct.
type TMgr struct {
	*headerauth.TokenManager
}

// Authorize returns the secret key from the provided access key.
func (m TMgr) CheckHeader(auth *AuthInfo, req *http.Request) (err *AuthErr) {
	auth.Secret = ""     // There is no secret key, just an access key.
	auth.DataToSign = "" // There is no data to sign in Token auth.
	if auth.AccessKey != "valid" {
		err = &AuthErr{403, errors.New("invalid access key")}
	}
	return
}

func (m TMgr) Authorize(auth *AuthInfo) (val interface{}, err *AuthErr) {
	return true, nil
}
```

#### Defaults
* Required is `true` meaning that if the authentication fails, the request will abort.

#### Setting the auth manager as a middleware
```go
func main() {
	// Setting the Gin context key to "accessKey". 
	mgr := TMgr{NewTokenManager("X-Token-Auth", "Token", "accessKey")}
	router := gin.Default()
	router.Use(SignatureAuth(mgr))
	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	for _, meth := range methods {
		router.Handle(meth, "/tokenTest/", []gin.HandlerFunc{func(c *gin.Context) {
			c.String(http.StatusOK, "Success.")
		}}[0])
	}
}
```

### Header example
With the previously defined manager, the following auth header would be valid.
* `X-Token-Auth`: `Token MyValidTokenWhichOnlyIKnow!`

## HTTP Basic Authentication
[HTTP Basic Auth](https://en.wikipedia.org/wiki/Basic_access_authentication) is an **insecure** auth scheme. However, we have it as an example here
because it's commonly used, and it demonstrates a good usage of the `PreAbort` function called just prior to aborting the Gin request if there is an
authentification failure. In this case, we'll be setting a custom header.

### Usage example
Server *S* has a list of valid username and passwords. For some obscure reason, it is required to use HTTP Basic Auth, maybe because it is commonly
supported by browsers.

### Code
#### Manager code
The simplest, as with the other schemes, is to embed the helping struct, in this case `headerauth.HTTPBasicAuth`.

For `headerauth.HTTPBasicAuth`, the username and password checking happens in the `Authorize` function. In the following example, we use a `map[string]string`
but a more prod-like implementation would surely use a database connection to check that the user provided exists, and the password matches.

**Note:** When the `Authorize` function is reached, the username is stored in `auth.AccessKey` and the password in `auth.Secret`
(cf `(m HTTPBasicAuth) CheckHeader(auth *AuthInfo, req *http.Request) (err *AuthErr)` in  `managers.go`).

```go
// HTTPBasicDemo is an example of an HTTP Basic Auth.
type HTTPBasicDemo struct {
	Accounts map[string]string // --> Here we are using a hard coded map, but the logic is up to the dev.
	*headerauth.HTTPBasicAuth // Embedded struct greatly helps in defining HTTP Basic Auth.
}

// Authorize checks that the provided authorization is valid.
// --> Here is where you can interface with a database, or something which stores the list of valid usernames
// --> and their associated passwords. Note that in the other schemes we try to fail earlier (in CheckHeader).
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
```

#### Setting the auth manager as a middleware
As usual, this is trivial.
```go
func main() {
	mgr := HTTPBasicDemo{Accounts: map[string]string{"user": "password"}, HTTPBasicAuth: headerauth.NewHTTPBasicAuthManager("user", "My Protected Group")}
	router := gin.Default()
	router.Use(headerauth.HeaderAuth(mgr))
	router.GET("/test/", func(c *gin.Context) {
		c.String(200, "Success.")
	})
	router.Run("localhost:31337")
}
```

### Header example
With an HTTP Basic Auth manager, and with the example above, you'll get 200 Success with the following header.
* `Authorization`:`Basic dXNlcjpwYXNzd29yZA==`