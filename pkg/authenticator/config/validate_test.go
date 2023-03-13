package config

import (
	"errors"
	"fmt"
	"testing"

	logger "github.com/cyberark/conjur-authn-k8s-client/pkg/log"
	"github.com/stretchr/testify/assert"
)

type errorAssertFunc func(*testing.T, []error)

func TestValidate(t *testing.T) {
	TestCases := []struct {
		description string
		settings    AuthnSettings
		assert      errorAssertFunc
	}{
		{
			description: "happy path - k8s",
			settings: AuthnSettings{
				// required variables
				"CONJUR_AUTHN_URL":   "authn-k8s",
				"CONJUR_ACCOUNT":     "testAccount",
				"CONJUR_AUTHN_LOGIN": "host/myapp",
				"MY_POD_NAME":        "testPodName",
				"MY_POD_NAMESPACE":   "testNameSpace",
				// correct value types
				"CONJUR_CLIENT_CERT_RETRY_COUNT_LIMIT": "7",
				"CONJUR_TOKEN_TIMEOUT":                 "6m0s",
				"CONTAINER_MODE":                       "init",
				// certificate provided
				"CONJUR_SSL_CERTIFICATE": "samplecertificate",
			},
			assert: assertEmptyErrorList(),
		},
		{
			description: "happy path - jwt",
			settings: AuthnSettings{
				// required variables
				"CONJUR_AUTHN_URL": "authn-jwt",
				"CONJUR_ACCOUNT":   "testAccount",
				"JWT_TOKEN_PATH":   "/tmp/token",
				// correct value types
				"CONJUR_CLIENT_CERT_RETRY_COUNT_LIMIT": "7",
				"CONJUR_TOKEN_TIMEOUT":                 "6m0s",
				"CONTAINER_MODE":                       "init",
				// certificate provided
				"CONJUR_SSL_CERTIFICATE": "samplecertificate",
			},
			assert: assertEmptyErrorList(),
		},
		{
			description: "invalid jwt token path",
			settings: AuthnSettings{
				// required variables
				"CONJUR_AUTHN_URL": "authn-jwt",
				"CONJUR_ACCOUNT":   "testAccount",
				// correct value types
				"CONJUR_CLIENT_CERT_RETRY_COUNT_LIMIT": "7",
				"CONJUR_TOKEN_TIMEOUT":                 "6m0s",
				"CONTAINER_MODE":                       "init",
				// certificate provided
				"CONJUR_SSL_CERTIFICATE": "samplecertificate",
				"JWT_TOKEN_PATH":         "invalid//path",
			},
			assert: assertErrorInList(fmt.Errorf(logger.CAKC065, "invalid//path")),
		},
		{
			description: "error raised for missing required setting",
			settings: AuthnSettings{
				"CONJUR_AUTHN_URL": "authn-jwt",
			},
			assert: assertErrorInList(fmt.Errorf(logger.CAKC062, "CONJUR_ACCOUNT")),
		},
		{
			description: "error raised for invalid username",
			settings: AuthnSettings{
				"CONJUR_AUTHN_URL":   "authn-k8s",
				"CONJUR_ACCOUNT":     "testAccount",
				"CONJUR_AUTHN_LOGIN": "bad-username",
				"MY_POD_NAME":        "testPodName",
				"MY_POD_NAMESPACE":   "testNameSpace",
			},
			assert: assertErrorInList(fmt.Errorf(logger.CAKC032, "bad-username")),
		},
		{
			description: "error raised for invalid retry count limit",
			settings: AuthnSettings{
				"CONJUR_AUTHN_URL":                     "authn-k8s",
				"CONJUR_ACCOUNT":                       "testAccount",
				"CONJUR_AUTHN_LOGIN":                   "host",
				"MY_POD_NAME":                          "testPodName",
				"MY_POD_NAMESPACE":                     "testNameSpace",
				"CONJUR_CLIENT_CERT_RETRY_COUNT_LIMIT": "seven",
			},
			assert: assertErrorInList(fmt.Errorf(logger.CAKC060, "CONJUR_CLIENT_CERT_RETRY_COUNT_LIMIT", "seven")),
		},
		{
			description: "error raised for invalid timeout",
			settings: AuthnSettings{
				"CONJUR_AUTHN_URL":                     "authn-k8s",
				"CONJUR_ACCOUNT":                       "testAccount",
				"CONJUR_AUTHN_LOGIN":                   "host",
				"MY_POD_NAME":                          "testPodName",
				"MY_POD_NAMESPACE":                     "testNameSpace",
				"CONJUR_CLIENT_CERT_RETRY_COUNT_LIMIT": "7",
				"CONJUR_TOKEN_TIMEOUT":                 "seventeen",
			},
			assert: assertErrorInList(fmt.Errorf(logger.CAKC060, "CONJUR_TOKEN_TIMEOUT", "seventeen")),
		},
		{
			description: "error raised for invalid certificate",
			settings: AuthnSettings{
				"CONJUR_AUTHN_URL":                     "authn-k8s",
				"CONJUR_ACCOUNT":                       "testAccount",
				"CONJUR_AUTHN_LOGIN":                   "host",
				"MY_POD_NAME":                          "testPodName",
				"MY_POD_NAMESPACE":                     "testNameSpace",
				"CONJUR_CLIENT_CERT_RETRY_COUNT_LIMIT": "7",
				"CONJUR_TOKEN_TIMEOUT":                 "6m0s",
				"CONTAINER_MODE":                       "init",
				"CONJUR_SSL_CERTIFICATE":               "",
				"CONJUR_CERT_FILE":                     "",
			},
			assert: assertErrorInList(errors.New(logger.CAKC007)),
		},
	}

	for _, tc := range TestCases {
		t.Run(tc.description, func(t *testing.T) {
			// SETUP & EXERCISE
			configObj, _ := getConfiguration(tc.settings["CONJUR_AUTHN_URL"])
			errLogs := tc.settings.validate(configObj, successfulMockReadFile)

			// ASSERT
			tc.assert(t, errLogs)
		})
	}
}

func assertErrorInList(err error) errorAssertFunc {
	return func(t *testing.T, errorList []error) {
		assert.Contains(t, errorList, err)
	}
}

func successfulMockReadFile(filename string) ([]byte, error) {
	return []byte{}, nil
}

func assertEmptyErrorList() errorAssertFunc {
	return func(t *testing.T, errorList []error) {
		assert.Empty(t, errorList)
	}
}

func assertErrorNotInList(err error) errorAssertFunc {
	return func(t *testing.T, errorList []error) {
		assert.NotContains(t, errorList, err)
	}
}
