package headerauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	. "github.com/smartystreets/goconvey/convey"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// StrictSHAManager is an example definition of an AuthKeyManager struct.
type StrictSHAManager struct {
	Secret string
	*HMACManager
}

// CheckHeader returns an error if something is wrong with the header, or the auth fails (if it can fail here).
// Here should reside additional verifications on the header, or other parts of the request, if needed.
func (m StrictSHAManager) CheckHeader(auth *AuthInfo, req *http.Request) (err *AuthErr) {
	if req.ContentLength != 0 && req.Body == nil {
		// Not sure whether net/http or Gin handles these kinds of fun situations.
		return &AuthErr{400, errors.New("received a forged packet")}
	}
	// Grabbing the date and making sure it's in the correct format and is within fifteen minutes.
	dateHeader := req.Header.Get("Date")
	if dateHeader == "" {
		return &AuthErr{406, errors.New("no Date header provided")}
	}
	date, derr := time.Parse("2006-01-02T15:04:05.000Z", dateHeader)
	if derr != nil {
		return &AuthErr{408, errors.New("could not parse date")}
	} else if time.Since(date) > time.Minute*15 {
		return &AuthErr{410, errors.New("request is too old")}
	}

	// The headers look good, let's check the access key, and get the data to sign.
	// The data to sign is a string representing the data which will be HMAC'd with
	// the secret and used to check authenticity of the request.
	// If the reading the access key requires any kind of IO (database, or file reading, etc.)
	// it's quite good to only verify if that access key is valid once all the checks are done.
	if auth.AccessKey == "my_access_key" {
		// In this example, we'll be implementing a *similar* signing method to the Amazon AWS REST one.
		// We'll use the HTTP-Verb, the MD5 checksum of the Body, if any, and the Date header in ISO format.
		// http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
		// Note: We are returning a variety of error codes which don't follow the spec only for the purpose of testing.
		serializedData := req.Method + "\n"
		if req.ContentLength != 0 {
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				return &AuthErr{402, errors.New("could not read the body")}
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
	return &AuthErr{418, errors.New("you are a teapot")}
}

// Authorize returns the value to store in Gin's context at ContextKey(), or an error if the auth fails.
// This is only called once the requested has been authorized to pursue, i.e. access key and signature are valid,
// so logging of success should happen here.
func (m StrictSHAManager) Authorize(auth *AuthInfo) (val interface{}, err *AuthErr) {
	if auth.AccessKey == "my_access_key" {
		val = "All good with my access key!"
	}
	val = "All good with any access key!"
	return
}

// EmptyManager is an example definition of an AuthKeyManager struct.
type EmptyManager struct {
	*TokenManager
}

// CheckHeader returns an error if the header(s) are not as per protocol.
func (m EmptyManager) CheckHeader(auth *AuthInfo, req *http.Request) (err *AuthErr) {
	auth.Secret = ""     // There is no secret key, just an access key.
	auth.DataToSign = "" // There is no data to sign in Token auth.
	if auth.AccessKey != "valid" {
		err = &AuthErr{403, errors.New("invalid access key")}
	}
	return
}

// Authorize returns the value to store in Gin's context at ContextKey(), or an error.
func (m EmptyManager) Authorize(auth *AuthInfo) (val interface{}, err *AuthErr) {
	return true, nil
}

// PreAbort will set a header to the error received to confirm failure.
func (m EmptyManager) PreAbort(c *gin.Context, auth *AuthInfo, err *AuthErr) {
	c.Header("X-Token-Auth-Err", err.Err.Error())
}

// PostAuth will set a header to a specific value to confirm call.
func (m EmptyManager) PostAuth(c *gin.Context, auth *AuthInfo, err *AuthErr) {
	c.Header("X-Token-Auth-Success", "True")
}

// FailingManager is an example definition of an AuthKeyManager struct.
type FailingManager struct {
	*HMACManager
}

// Authorize returns the secret key from the provided access key.
func (m FailingManager) CheckHeader(auth *AuthInfo, req *http.Request) *AuthErr {
	return &AuthErr{418, errors.New("teapot failing manager")}
}

// ContextValue returns the value to store in Gin's context at ContextKey().
func (m FailingManager) Authorize(auth *AuthInfo) (val interface{}, err *AuthErr) {
	return false, nil
}

// HTTPBasicDemo is an example of an HTTP Basic Auth.
type HTTPBasicDemo struct {
	Accounts map[string]string
	*HTTPBasicAuth
}

// Authorize returns the value to store in Gin's context at ContextKey().
func (m HTTPBasicDemo) Authorize(auth *AuthInfo) (val interface{}, err *AuthErr) {
	if password, ok := m.Accounts[auth.AccessKey]; !ok || password != auth.Secret {
		err = &AuthErr{401, errors.New("invalid credentials")}
	} else {
		// In CheckHeader we changed the AccessKey to be the actual username, instead
		// of the Base64 encoded authentication string.
		val = auth.AccessKey
	}
	return
}

// TestExtractAuthInfo tests the correct extraction of information from the headers.
func TestExtractAuthInfo(t *testing.T) {
	// https://github.com/smartystreets/goconvey/wiki#get-going-in-25-seconds
	Convey("Given a static manager with prefix SAUTH", t, func() {
		mgr := StrictSHAManager{"super-secret-password", NewHMACSHA384Manager("SAUTH", "contextKey")}

		Convey("When the header has an incorrect prefix", func() {
			auth := &AuthInfo{}
			err := extractAuthInfo(mgr, auth, "INCORRECT Something:ThereWasASpace")
			Convey("Accesskey and signature should be empty strings", func() {
				So(auth.AccessKey, ShouldEqual, "")
				So(auth.Secret, ShouldEqual, "")
				So(auth.Signature, ShouldEqual, "")
				So(auth.DataToSign, ShouldEqual, "")
			})
			Convey("The error should be a 401 with a specific message.", func() {
				So(err.Status, ShouldEqual, 401)
				So(err.Err.Error(), ShouldEqual, "invalid authorization header")
			})
		})

		Convey("When the header has the correct prefix but more than one space", func() {
			auth := &AuthInfo{}
			err := extractAuthInfo(mgr, auth, "SAUTH Something ThereWasASpace")
			Convey("Accesskey and signature should be empty strings", func() {
				So(auth.AccessKey, ShouldEqual, "")
				So(auth.Secret, ShouldEqual, "")
				So(auth.Signature, ShouldEqual, "")
				So(auth.DataToSign, ShouldEqual, "")
			})
			Convey("The error should be a 401 with a specific message.", func() {
				So(err.Status, ShouldEqual, 401)
				So(err.Err.Error(), ShouldEqual, "invalid authorization header")
			})
		})

		Convey("When the header has the correct prefix but missing the seperation colon", func() {
			auth := &AuthInfo{}
			err := extractAuthInfo(mgr, auth, "SAUTH SomethingThereIsNoSepColon")
			Convey("Accesskey and signature should be empty strings", func() {
				So(auth.AccessKey, ShouldEqual, "")
				So(auth.Secret, ShouldEqual, "")
				So(auth.Signature, ShouldEqual, "")
				So(auth.DataToSign, ShouldEqual, "")
			})
			Convey("The error should be a 401 with a specific message.", func() {
				So(err.Status, ShouldEqual, 401)
				So(err.Err.Error(), ShouldEqual, "invalid format for access key and signature")
			})
		})

		Convey("When the header is valid", func() {
			auth := &AuthInfo{}
			err := extractAuthInfo(mgr, auth, "SAUTH SomeAccessKey:SomeSignature")
			Convey("Accesskey and signature should be extracted correctly", func() {
				So(auth.AccessKey, ShouldEqual, "SomeAccessKey")
				So(auth.Secret, ShouldEqual, "")
				So(auth.Signature, ShouldEqual, "SomeSignature")
				So(auth.DataToSign, ShouldEqual, "")
			})
			Convey("The error should be nil.", func() {
				So(err, ShouldEqual, nil)
			})
		})
	})
}

// TestMiddleware tests the whole signature auth middleware behavior.
func TestMiddleware(t *testing.T) {

	Convey("Given a strict manager", t, func() {
		mgr := StrictSHAManager{"super-secret-password", NewHMACSHA1Manager("SAUTH", "contextKey")}
		router := gin.Default()
		router.Use(HeaderAuth(mgr))
		methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
		for _, meth := range methods {
			router.Handle(meth, "/HMACtest/", []gin.HandlerFunc{func(c *gin.Context) {
				c.String(http.StatusOK, "Success.")
			}}[0])
		}
		Convey("When there is no header", func() {
			for _, meth := range methods {
				Convey(fmt.Sprintf("and doing a %s request", meth), func() {
					req := performRequest(router, meth, "/HMACtest/", nil, nil)
					Convey("the middleware should respond forbidden", func() {
						So(req.Code, ShouldEqual, 401)
					})
				})
			}
		})

		Convey("When the header has an incorrect prefix", func() {
			headers := make(map[string][]string)
			headers["Authorization"] = []string{"INCORRECT Something:ThereWasASpace"}
			for _, meth := range methods {
				Convey(fmt.Sprintf("and doing a %s request", meth), func() {
					req := performRequest(router, meth, "/HMACtest/", headers, nil)
					Convey("the middleware should respond unauthorized", func() {
						So(req.Code, ShouldEqual, 401)
					})
				})
			}
		})

		Convey("When the header has the correct prefix and date headers but an incorrect access key", func() {
			headers := make(map[string][]string)
			headers["Authorization"] = []string{"SAUTH Something:ThereWasASpace"}
			headers["Date"] = []string{time.Now().Format("2006-01-02T15:04:05.000Z")}
			for _, meth := range methods {
				Convey(fmt.Sprintf("and doing a %s request", meth), func() {
					req := performRequest(router, meth, "/HMACtest/", headers, nil)
					Convey("the middleware should respond with the Manager's secret key provided status.", func() {
						So(req.Code, ShouldEqual, 418)
					})
				})
			}
		})

		Convey("When the header has the correct prefix and access key, but incorrect signature", func() {
			headers := make(map[string][]string)
			headers["Authorization"] = []string{"SAUTH my_access_key:InvalidSignature"}

			Convey("And missing the Date header", func() {
				for _, meth := range methods {
					Convey(fmt.Sprintf("and doing a %s request", meth), func() {
						req := performRequest(router, meth, "/HMACtest/", headers, nil)
						Convey("the middleware should respond as requested by the manager.", func() {
							So(req.Code, ShouldEqual, 406)
						})
					})
				}
			})

			Convey("And the Date header is in the incorrect format", func() {
				headers["Date"] = []string{time.Now().Format("01/02 03 04 05 06")}
				for _, meth := range methods {
					Convey(fmt.Sprintf("and doing a %s request", meth), func() {
						req := performRequest(router, meth, "/HMACtest/", headers, nil)
						Convey("the middleware should respond as requested by the manager.", func() {
							So(req.Code, ShouldEqual, 408)
						})
					})
				}
			})

			Convey("And the Date header is valid but too old", func() {
				utc, _ := time.LoadLocation("UTC")
				oldDate := time.Date(2006, 05, 04, 03, 02, 01, 00, utc)
				headers["Date"] = []string{oldDate.Format("2006-01-02T15:04:05.000Z")}
				for _, meth := range methods {
					Convey(fmt.Sprintf("and doing a %s request", meth), func() {
						req := performRequest(router, meth, "/HMACtest/", headers, nil)
						Convey("the middleware should respond as requested by the manager.", func() {
							So(req.Code, ShouldEqual, 410)
						})
					})
				}
			})

			Convey("And the Date header is completely valid", func() {
				headers["Date"] = []string{time.Now().Format("2006-01-02T15:04:05.000Z")}
				for _, meth := range methods {
					Convey(fmt.Sprintf("and doing a %s request", meth), func() {
						req := performRequest(router, meth, "/HMACtest/", headers, nil)
						Convey("the middleware should respond unauthorized.", func() {
							So(req.Code, ShouldEqual, 401)
						})
					})
				}
			})

		})

		Convey("When the full signature is valid with no body.", func() {
			headers := make(map[string][]string)
			now := time.Now().Format("2006-01-02T15:04:05.000Z")
			headers["Date"] = []string{now}
			for _, meth := range methods {
				Convey(fmt.Sprintf("and doing a %s request", meth), func() {
					sigData := meth + "\n\n" + now
					hash := hmac.New(sha1.New, []byte(mgr.Secret))
					hash.Write([]byte(sigData))
					signature := hex.EncodeToString(hash.Sum(nil))
					headers["Authorization"] = []string{"SAUTH my_access_key:" + signature}
					req := performRequest(router, meth, "/HMACtest/", headers, nil)
					Convey("the middleware should respond 200 OK.", func() {
						So(req.Code, ShouldEqual, 200)
					})
				})
			}
		})

		Convey("When the full signature is valid with a body.", func() {
			headers := make(map[string][]string)
			secret := "super-secret-password"
			now := time.Now().Format("2006-01-02T15:04:05.000Z")
			headers["Date"] = []string{now}
			for _, meth := range methods {
				Convey(fmt.Sprintf("and doing a %s request", meth), func() {
					body := "This is the body of my request."
					bhash := md5.New()
					bhash.Write([]byte(body))
					sigData := meth + "\n" + hex.EncodeToString(bhash.Sum(nil)) + "\n" + now
					hash := hmac.New(sha1.New, []byte(secret))
					hash.Write([]byte(sigData))
					signature := hex.EncodeToString(hash.Sum(nil))
					headers["Authorization"] = []string{"SAUTH my_access_key:" + signature}
					req := performRequest(router, meth, "/HMACtest/", headers, bytes.NewBufferString(body))
					Convey("the middleware should respond 200 OK.", func() {
						So(req.Code, ShouldEqual, 200)
					})
				})
			}
		})

	})

	Convey("Given a non required manager", t, func() {
		mgr := StrictSHAManager{"super-secret-password", NewHMACSHA1Manager("SAUTH", "contextKey")}
		mgr.Required = false
		router := gin.Default()
		router.Use(HeaderAuth(mgr))
		methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
		for _, meth := range methods {
			router.Handle(meth, "/notRequiredTest/", []gin.HandlerFunc{func(c *gin.Context) {
				c.String(http.StatusOK, "Success.")
			}}[0])
		}

		for _, meth := range methods {
			Convey(fmt.Sprintf("and doing a %s request", meth), func() {
				req := performRequest(router, meth, "/notRequiredTest/", nil, nil)
				Convey("the middleware should respond success", func() {
					So(req.Code, ShouldEqual, 200)
				})
			})
		}

	})

	Convey("Given an access key only manager", t, func() {
		mgr := EmptyManager{NewTokenManager("Access-Key", "Token", "cKey")}
		router := gin.Default()
		router.Use(HeaderAuth(mgr))
		methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
		for _, meth := range methods {
			router.Handle(meth, "/tokenTest/", []gin.HandlerFunc{func(c *gin.Context) {
				c.String(http.StatusOK, "Success.")
			}}[0])
		}

		Convey("When the access key is valid.", func() {
			headers := make(map[string][]string)
			for _, meth := range methods {
				Convey(fmt.Sprintf("and doing a %s request", meth), func() {
					headers["Access-Key"] = []string{"Token valid"}
					req := performRequest(router, meth, "/tokenTest/", headers, nil)
					Convey("the middleware should respond 200 OK.", func() {
						So(req.Code, ShouldEqual, 200)
						So(req.HeaderMap.Get("X-Token-Auth-Success"), ShouldEqual, "True")
					})
				})
			}
		})

		Convey("When the access key is invalid.", func() {
			headers := make(map[string][]string)
			for _, meth := range methods {
				Convey(fmt.Sprintf("and doing a %s request", meth), func() {
					headers["Access-Key"] = []string{"Token invalid"}
					req := performRequest(router, meth, "/tokenTest/", headers, nil)
					Convey("the middleware should respond 403.", func() {
						So(req.Code, ShouldEqual, 403)
						So(req.HeaderMap.Get("X-Token-Auth-Err"), ShouldEqual, "invalid access key")
					})
				})
			}
		})

		Convey("When the access key is missing.", func() {
			headers := make(map[string][]string)
			for _, meth := range methods {
				Convey(fmt.Sprintf("and doing a %s request", meth), func() {
					headers["AccessKey"] = []string{""}
					req := performRequest(router, meth, "/tokenTest/", headers, nil)
					Convey("the middleware should respond 401.", func() {
						So(req.Code, ShouldEqual, 401)
					})
				})
			}
		})
	})

	Convey("Given a failing manager", t, func() {
		mgr := FailingManager{NewHMACSHA1Manager("FAIL", "allGood")}
		router := gin.Default()
		router.Use(HeaderAuth(mgr))
		methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
		for _, meth := range methods {
			router.Handle(meth, "/failTest/", []gin.HandlerFunc{func(c *gin.Context) {
				c.String(http.StatusOK, "Success.")
			}}[0])
		}

		Convey("When the access key is valid.", func() {
			headers := make(map[string][]string)
			for _, meth := range methods {
				Convey(fmt.Sprintf("and doing a %s request", meth), func() {
					hash := hmac.New(sha1.New, []byte(""))
					hash.Write([]byte(""))
					signature := hex.EncodeToString(hash.Sum(nil))
					headers["Authorization"] = []string{"FAIL valid:" + signature}
					req := performRequest(router, meth, "/failTest/", headers, nil)
					Convey("the middleware should respond 418 Teapot.", func() {
						So(req.Code, ShouldEqual, 418)
					})
				})
			}
		})
	})

	Convey("Given an HTTP Basic manager with custom Realm", t, func() {
		mgr := HTTPBasicDemo{Accounts: map[string]string{"user": "password"}, HTTPBasicAuth: NewHTTPBasicAuthManager("user", "My Protected Group")}
		router := gin.Default()
		router.Use(HeaderAuth(mgr))
		methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
		for _, meth := range methods {
			router.Handle(meth, "/HTTPBasicAuthTest/", []gin.HandlerFunc{func(c *gin.Context) {
				c.String(http.StatusOK, "Success.")
			}}[0])
		}

		Convey("When the username and password are valid.", func() {
			auth := base64.StdEncoding.EncodeToString([]byte("user:password"))
			headers := make(map[string][]string)
			for _, meth := range methods {
				Convey(fmt.Sprintf("and doing a %s request", meth), func() {
					headers["Authorization"] = []string{"Basic " + auth}
					req := performRequest(router, meth, "/HTTPBasicAuthTest/", headers, nil)
					Convey("the middleware should respond 200 OK.", func() {
						So(req.Code, ShouldEqual, 200)
					})
				})
			}
		})

		Convey("When the username is valid but not the password.", func() {
			auth := base64.StdEncoding.EncodeToString([]byte("user:password!"))
			headers := make(map[string][]string)
			for _, meth := range methods {
				Convey(fmt.Sprintf("and doing a %s request", meth), func() {
					headers["Authorization"] = []string{"Basic " + auth}
					req := performRequest(router, meth, "/HTTPBasicAuthTest/", headers, nil)
					Convey("the middleware should respond 401 Unauthorized with appropriate headers", func() {
						So(req.Code, ShouldEqual, 401)
						So(req.HeaderMap.Get("WWW-Authenticate"), ShouldEqual, "Basic realm=\"My Protected Group\"")
					})
				})
			}
		})

		Convey("When the username is not valid.", func() {
			auth := base64.StdEncoding.EncodeToString([]byte("user!:unused"))
			headers := make(map[string][]string)
			for _, meth := range methods {
				Convey(fmt.Sprintf("and doing a %s request", meth), func() {
					headers["Authorization"] = []string{"Basic " + auth}
					req := performRequest(router, meth, "/HTTPBasicAuthTest/", headers, nil)
					Convey("the middleware should respond 401 Unauthorized with appropriate headers", func() {
						So(req.Code, ShouldEqual, 401)
						So(req.HeaderMap.Get("WWW-Authenticate"), ShouldEqual, "Basic realm=\"My Protected Group\"")
					})
				})
			}
		})

		Convey("When the username and password are not correctly encoded.", func() {
			auth := base64.StdEncoding.EncodeToString([]byte("user!unused"))
			headers := make(map[string][]string)
			for _, meth := range methods {
				Convey(fmt.Sprintf("and doing a %s request", meth), func() {
					headers["Authorization"] = []string{"Basic " + auth}
					req := performRequest(router, meth, "/HTTPBasicAuthTest/", headers, nil)
					Convey("the middleware should respond 401 Unauthorized with appropriate headers", func() {
						So(req.Code, ShouldEqual, 401)
						So(req.HeaderMap.Get("WWW-Authenticate"), ShouldEqual, "Basic realm=\"My Protected Group\"")
					})
				})
			}
		})

		Convey("When the auth string is not valid base64.", func() {
			auth := base64.StdEncoding.EncodeToString([]byte("user!:unused")) + "a="
			headers := make(map[string][]string)
			for _, meth := range methods {
				Convey(fmt.Sprintf("and doing a %s request", meth), func() {
					headers["Authorization"] = []string{"Basic " + auth}
					req := performRequest(router, meth, "/HTTPBasicAuthTest/", headers, nil)
					Convey("the middleware should respond 401 Unauthorized with appropriate headers", func() {
						So(req.Code, ShouldEqual, 401)
						So(req.HeaderMap.Get("WWW-Authenticate"), ShouldEqual, "Basic realm=\"My Protected Group\"")
					})
				})
			}
		})
	})

	Convey("Given an HTTP Basic manager with default Realm", t, func() {
		mgr := HTTPBasicDemo{Accounts: map[string]string{"user": "password"}, HTTPBasicAuth: NewHTTPBasicAuthManager("user", "")}
		router := gin.Default()
		router.Use(HeaderAuth(mgr))
		methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
		for _, meth := range methods {
			router.Handle(meth, "/HTTPBasicAuthTest/", []gin.HandlerFunc{func(c *gin.Context) {
				c.String(http.StatusOK, "Success.")
			}}[0])
		}

		Convey("When the username is valid but not the password.", func() {
			auth := base64.StdEncoding.EncodeToString([]byte("user:password!"))
			headers := make(map[string][]string)
			for _, meth := range methods {
				Convey(fmt.Sprintf("and doing a %s request", meth), func() {
					headers["Authorization"] = []string{"Basic " + auth}
					req := performRequest(router, meth, "/HTTPBasicAuthTest/", headers, nil)
					Convey("the middleware should respond 401 Unauthorized with appropriate headers", func() {
						So(req.Code, ShouldEqual, 401)
						So(req.HeaderMap.Get("WWW-Authenticate"), ShouldEqual, "Basic realm=\"Authorization Required\"")
					})
				})
			}
		})
	})
}

// performRequest is a helper to test requests, based on https://github.com/gin-gonic/gin/blob/c467186d2004be8ade88a35f5bcf71cc2c676635/routes_test.go#L19.
func performRequest(r http.Handler, method, path string, headers map[string][]string, body io.Reader) *httptest.ResponseRecorder {
	req, _ := http.NewRequest(method, path, body)
	req.Header = headers
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
