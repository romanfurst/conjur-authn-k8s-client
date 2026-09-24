package utils

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Different types of file scenarios to test. (For file scenarios that use
// mock file utilities as configured in the testConfigMap below, the string
// values are arbitrary but must be unique.)
const (
	existingFilePath    = "path/to/existing/file"
	nonexistentFilePath = "path/to/nonexistent/file"
	nonRegularFilePath  = "/tmp"
	unpermittedFilePath = "path/to/unpermitted/file"
	invalidArgsFilePath = "invalid/args/in/file/access"
)

// Test config for a given file scenario
type testConfig struct {
	useOSUtils bool
	statError  error // This is a don't care if useOSUtils is 'true'
	isRegular  bool  // This is a don't care if useOSUtils is 'true'
}

// Map of test configuration based on file scenario
var testConfigMap = map[string]testConfig{
	existingFilePath: {
		useOSUtils: false,
		statError:  nil,
		isRegular:  true,
	},
	nonexistentFilePath: {
		useOSUtils: false,
		statError:  os.ErrNotExist,
		isRegular:  false,
	},
	nonRegularFilePath: {
		useOSUtils: true,
		statError:  nil,
		isRegular:  false,
	},
	unpermittedFilePath: {
		useOSUtils: false,
		statError:  os.ErrPermission,
		isRegular:  false,
	},
	invalidArgsFilePath: {
		useOSUtils: false,
		statError:  os.ErrInvalid,
		isRegular:  false,
	},
}

func testCaseFileUtils(path string) *fileUtils {
	config := testConfigMap[path]

	if config.useOSUtils {
		return osFileUtils
	}

	return &fileUtils{
		func(s string) (os.FileInfo, error) {
			return nil, config.statError
		},
		func(info os.FileInfo) bool {
			return config.isRegular
		},
	}
}

func TestFile(t *testing.T) {
	t.Run("waitForFile", func(t *testing.T) {
		retryCountLimit := 10
		t.Run("Returns nil if file exists", func(t *testing.T) {
			path := existingFilePath
			utilities := testCaseFileUtils(path)

			assert.Nil(
				t,
				waitForFile(
					path,
					retryCountLimit,
					utilities,
				),
			)
		})

		t.Run("Waits for whole time if file does not exist", func(t *testing.T) {
			path := nonexistentFilePath
			utilities := testCaseFileUtils(path)
			expectedOutput := fmt.Errorf(
				"CAKC033 Timed out after waiting for %d seconds for file to exist: %s",
				retryCountLimit,
				path,
			)

			assert.EqualValues(
				t,
				waitForFile(
					path,
					retryCountLimit,
					utilities,
				),
				expectedOutput,
			)
		})
	})

	t.Run("verifyFileExists", func(t *testing.T) {
		t.Run("An existing file returns nil error", func(t *testing.T) {
			path := existingFilePath
			utilities := testCaseFileUtils(path)

			err := verifyFileExists(path, utilities)

			assert.NoError(t, err)
		})

		t.Run("A path to an unpermitted file returns a logged error", func(t *testing.T) {
			path := unpermittedFilePath
			utilities := testCaseFileUtils(path)
			expectedOutput := fmt.Errorf(
				"CAKC058 Permissions error occured when checking if file exists: %s",
				path,
			)

			err := verifyFileExists(path, utilities)

			assert.EqualError(t, err, expectedOutput.Error())
		})

		t.Run("A path to a non-regular file returns a logged error", func(t *testing.T) {
			path := nonRegularFilePath
			utilities := testCaseFileUtils(path)
			expectedOutput := fmt.Errorf(
				"CAKC059 Path exists but does not contain regular file: %s",
				path,
			)

			err := verifyFileExists(path, utilities)

			assert.EqualError(t, err, expectedOutput.Error())
		})

		t.Run("A non-existing file returns an error without logging", func(t *testing.T) {
			path := nonexistentFilePath
			utilities := testCaseFileUtils(path)

			err := verifyFileExists(path, utilities)

			assert.True(t, os.IsNotExist(err))
		})

		t.Run("A non-ErrNotExist error is returned without logging", func(t *testing.T) {
			path := invalidArgsFilePath
			utilities := testCaseFileUtils(path)

			err := verifyFileExists(path, utilities)

			assert.EqualError(t, err, "invalid argument")
		})
	})
}

// Host ids from the PSDOP-29272 production failure. Both hosts live under the
// same policy branch and their ids differ only by a leading "M", so a
// substring match on the username suffix pairs one host with the other's cert.
const (
	scSupportSuffix = "SCSUPPORT.conjur-secret-provider.k8s-provider"
	scSupportCN     = "host.conjur.authn-k8s.nprod.AP_CLD_09831_SQ015.SCSUPPORT.conjur-secret-provider.k8s-provider"
	mscSupportCN    = "host.conjur.authn-k8s.nprod.AP_CLD_09831_SQ015.MSCSUPPORT.conjur-secret-provider.k8s-provider"
)

func TestMatchesUsernameSuffix(t *testing.T) {
	testCases := []struct {
		description    string
		commonName     string
		usernameSuffix string
		expected       bool
	}{
		{
			description:    "CN of the requested host matches",
			commonName:     scSupportCN,
			usernameSuffix: scSupportSuffix,
			expected:       true,
		},
		{
			description:    "CN equal to the suffix matches",
			commonName:     scSupportSuffix,
			usernameSuffix: scSupportSuffix,
			expected:       true,
		},
		{
			description:    "CN of a host whose id differs by a leading letter does not match",
			commonName:     mscSupportCN,
			usernameSuffix: scSupportSuffix,
			expected:       false,
		},
		{
			description:    "CN of a host in another policy branch does not match",
			commonName:     "host.conjur.authn-k8s.prod.AP_CLD_09831_SQ015.OTHER.conjur-secret-provider.k8s-provider",
			usernameSuffix: scSupportSuffix,
			expected:       false,
		},
		{
			description:    "CN that only starts with the suffix does not match",
			commonName:     scSupportSuffix + ".extra",
			usernameSuffix: scSupportSuffix,
			expected:       false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			assert.Equal(
				t,
				tc.expected,
				matchesUsernameSuffix(tc.commonName, tc.usernameSuffix),
			)
		})
	}
}

func TestTakeCertFromCache(t *testing.T) {
	resetCertCache := func() {
		certCacheMu.Lock()
		defer certCacheMu.Unlock()
		certCache = map[string]cachedCert{}
	}

	t.Run("Does not return the cert of a host whose id differs by a leading letter", func(t *testing.T) {
		resetCertCache()
		putCertInCache(mscSupportCN, []byte("mscsupport-pem"))

		_, ok := takeCertFromCache(scSupportSuffix)

		assert.False(t, ok)
	})

	t.Run("Returns the cert of the requested host", func(t *testing.T) {
		resetCertCache()
		putCertInCache(mscSupportCN, []byte("mscsupport-pem"))
		putCertInCache(scSupportCN, []byte("scsupport-pem"))

		cachedPEM, ok := takeCertFromCache(scSupportSuffix)

		assert.True(t, ok)
		assert.Equal(t, []byte("scsupport-pem"), cachedPEM)
	})

	t.Run("Removes the returned cert so it is not handed out twice", func(t *testing.T) {
		resetCertCache()
		putCertInCache(scSupportCN, []byte("scsupport-pem"))

		_, ok := takeCertFromCache(scSupportSuffix)
		assert.True(t, ok)

		_, ok = takeCertFromCache(scSupportSuffix)
		assert.False(t, ok)
	})

	t.Run("Does not return an expired cert", func(t *testing.T) {
		resetCertCache()
		certCacheMu.Lock()
		certCache[scSupportCN] = cachedCert{
			rawPEM:    []byte("scsupport-pem"),
			expiresAt: time.Now().Add(-1 * time.Second),
		}
		certCacheMu.Unlock()

		_, ok := takeCertFromCache(scSupportSuffix)

		assert.False(t, ok)
	})
}
