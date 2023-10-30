package utils

import (
	"os"
	"time"

	"github.com/cenkalti/backoff"

	"github.com/cyberark/conjur-authn-k8s-client/pkg/log"
)

// statFunc type is defined so that the dependency 'os.Stat()'
// can be mocked for testing.
type statFunc func(string) (os.FileInfo, error)

// isRegularFunc type is defined so that the dependency
// 'os.FileInfo.Mode().IsRegular()' can be mocked for testing.
type isRegularFunc func(info os.FileInfo) bool

type fileUtils struct {
	stat      statFunc
	isRegular isRegularFunc
}

var osFileUtils = &fileUtils{
	os.Stat,
	func(info os.FileInfo) bool {
		return info.Mode().IsRegular()
	},
}

// WaitForFile waits for retryCountLimit seconds to see if the file
// exists in the given path. If it's not there by the end of the retry
// count limit, it returns an error.
func WaitForFile(
	path string,
	retryCountLimit int,
) error {
	return waitForFile(path, retryCountLimit, osFileUtils)
}

func waitForFile(
	path string,
	retryCountLimit int,
	utilities *fileUtils,
) error {

	//on the Conjur server side this path is hardcoded
	staticPath := "/etc/conjur/ssl/client.pem"
	limitedBackOff := NewLimitedBackOff(
		time.Millisecond*100,
		retryCountLimit,
	)

	err := backoff.Retry(func() error {
		if limitedBackOff.RetryCount() > 0 {
			log.Debug(log.CAKC051, path)
		}

		return verifyFileExists(staticPath, utilities)
	}, limitedBackOff)

	if err != nil {
		return log.RecordedError(log.CAKC033, retryCountLimit, staticPath)
	}

	//copy default 'staticPath' filename file to auth specific 'path'
	//e.g.  "/etc/conjur/ssl/client.pem" ->  "/etc/conjur/ssl/SELDON-client.pem"
	err = os.Rename(staticPath, path)
	if err != nil {
		return log.RecordedError("Certificate file %s not created", path)
	}

	return nil
}

// VerifyFileExists verifies that a file exists at a given path and is a
// regular file.
func VerifyFileExists(path string) error {
	return verifyFileExists(path, osFileUtils)
}

func verifyFileExists(path string, utilities *fileUtils) error {
	info, err := utilities.stat(path)
	if os.IsPermission(err) {
		// Permissions error occured when checking if file exists
		return log.RecordedError(log.CAKC058, path)
	}
	if err == nil && !utilities.isRegular(info) {
		// Path exists but does not container regular file
		err = log.RecordedError(log.CAKC059, path)
	}
	return err
}
