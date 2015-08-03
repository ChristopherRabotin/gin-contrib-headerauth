package main

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"github.com/ChristopherRabotin/gin-contrib-headerauth"
	"io/ioutil"
	"net/http"
	"time"
)

// SHA384Manager is an example definition of an Manager struct.
type SHA384Manager struct {
	Secret string
	*headerauth.HMACManager
}

// CheckHeader returns the secret key and the data to sign from the provided access key.
// Here should reside additional verifications on the header, or other parts of the request, if needed.
func (m SHA384Manager) CheckHeader(access string, req *http.Request) (string, string, *headerauth.AuthErr) {
	if req.ContentLength != 0 && req.Body == nil {
		// Not sure whether net/http or Gin handles these kinds of fun situations.
		return "", "", &headerauth.AuthErr{400, errors.New("received a forged packet")}
	}
	// Grabbing the date and making sure it's in the correct format and is within fifteen minutes.
	dateHeader := req.Header.Get("Date")
	if dateHeader == "" {
		return "", "", &headerauth.AuthErr{406, errors.New("no Date header provided")}
	}
	date, derr := time.Parse("2006-01-02T15:04:05.000Z", dateHeader)
	if derr != nil {
		return "", "", &headerauth.AuthErr{408, errors.New("could not parse date")}
	} else if time.Since(date) > time.Minute*15 {
		return "", "", &headerauth.AuthErr{410, errors.New("request is too old")}
	}

	// The headers look good, let's check the access key, and get the data to sign.
	// The data to sign is a string representing the data which will be HMAC'd with
	// the secret and used to check authenticity of the request.
	// If the reading the access key requires any kind of IO (database, or file reading, etc.)
	// it's quite good to only verify if that access key is valid once all the checks are done.
	if access == "my_access_key" {
		// In this example, we'll be implementing a *similar* signing method to the Amazon AWS REST one.
		// We'll use the HTTP-Verb, the MD5 checksum of the Body, if any, and the Date header in ISO format.
		// http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
		// Note: We are returning a variety of error codes which don't follow the spec only for the purpose of testing.
		serializedData := req.Method + "\n"
		if req.ContentLength != 0 {
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				return "", "", &headerauth.AuthErr{402, errors.New("could not read the body")}
			}
			hash := md5.New()
			hash.Write(body)
			serializedData += hex.EncodeToString(hash.Sum(nil)) + "\n"
		} else {
			serializedData += "\n"
		}
		// We know from Authorize that the Date header is present and fits our time constaints.
		serializedData += req.Header.Get("Date")

		return m.Secret, serializedData, nil
	}
	return "", "", &headerauth.AuthErr{418, errors.New("you are a teapot")}
}

// Authorize returns the value to store in Gin's context at ContextKey().
// This is only called once the requested has been authorized to pursue,
// so logging of success should happen here.
func (m SHA384Manager) Authorize(access string) interface{} {
	if access == "my_access_key" {
		return "All good with my access key!"
	}
	return "All good with any access key!"
}
