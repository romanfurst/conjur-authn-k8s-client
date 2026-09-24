package utils

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"strings"
	"sync"
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

type cachedCert struct {
	rawPEM    []byte
	expiresAt time.Time
}

// certDropPath is the path Conjur injects the client certificate into. It is
// hardcoded on the server side; it is a var only so tests can redirect it.
var certDropPath = "/etc/conjur/ssl/client.pem"

var (
	certCacheTTL = 30 * time.Second
	certCacheMu  sync.Mutex
	certCache    = map[string]cachedCert{}

	cacheCleanupOnce sync.Once
)

// startCertCacheCleanup starts one background cleaner for expired records.
func startCertCacheCleanup() {
	cacheCleanupOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()

			for now := range ticker.C {
				certCacheMu.Lock()
				for cn, entry := range certCache {
					if now.After(entry.expiresAt) {
						delete(certCache, cn)
					}
				}
				certCacheMu.Unlock()
			}
		}()
	})
}

func putCertInCache(commonName string, rawPEM []byte) {
	startCertCacheCleanup()

	certCacheMu.Lock()
	defer certCacheMu.Unlock()

	buf := make([]byte, len(rawPEM))
	copy(buf, rawPEM)

	certCache[commonName] = cachedCert{
		rawPEM:    buf,
		expiresAt: time.Now().Add(certCacheTTL),
	}
}

// matchesUsernameSuffix reports whether a certificate CN belongs to the host
// identified by usernameSuffix. The match is anchored on a dot boundary so that
// a CN ending in ".MSCSUPPORT.app.host" is not accepted for the username suffix
// "SCSUPPORT.app.host".
func matchesUsernameSuffix(commonName string, usernameSuffix string) bool {
	return commonName == usernameSuffix ||
		strings.HasSuffix(commonName, "."+usernameSuffix)
}

// takeCertFromCache returns a cached cert whose CN belongs to usernameSuffix and
// removes it from the cache, so the same cert is never handed out twice.
func takeCertFromCache(usernameSuffix string) ([]byte, bool) {
	certCacheMu.Lock()
	defer certCacheMu.Unlock()

	for cachedCN, entry := range certCache {
		// Safety check in case cleanup has not run yet.
		if time.Now().After(entry.expiresAt) {
			continue
		}
		if !matchesUsernameSuffix(cachedCN, usernameSuffix) {
			continue
		}

		delete(certCache, cachedCN)
		return entry.rawPEM, true
	}

	return nil, false
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

func WaitCorrectCertificate(
	path string,
	retryCountLimit int,
	usernameSuffix string,
) error {
	staticPath := certDropPath
	limitedBackOff := NewLimitedBackOff(
		time.Millisecond*100,
		retryCountLimit,
	)

	err := backoff.Retry(func() error {
		if limitedBackOff.RetryCount() > 0 {
			log.Debug(log.CAKC051, path)
		}

		// A concurrent authenticator may already have parked our cert in the
		// cache. Check that before the drop path, which by now may be empty or
		// already overwritten by the next login.
		if cachedPEM, ok := takeCertFromCache(usernameSuffix); ok {
			if err := os.WriteFile(path, cachedPEM, 0600); err != nil {
				return log.RecordedError("unable to write cached certificate to file %s: %s", path, err.Error())
			}
			return nil
		}

		err := verifyFileExists(staticPath, osFileUtils)
		if err != nil {
			return err
		}

		rawPEM, err := ioutil.ReadFile(staticPath)
		if err != nil {
			return err
		}

		// The cert is injected with an in-place write, so it can be read back
		// empty or half-written. Retry instead of dereferencing a nil block.
		certDERBlock, _ := pem.Decode(rawPEM)
		if certDERBlock == nil {
			return errors.New("incomplete PEM at " + staticPath)
		}

		cert, err := x509.ParseCertificate(certDERBlock.Bytes)
		if err != nil {
			return log.RecordedError(log.CAKC013, staticPath, err)
		}

		// Nothing clears the drop path, so a cert from an earlier login can
		// still be sitting there. Never accept one that has already expired,
		// and never cache it for another authenticator either.
		if time.Now().After(cert.NotAfter) {
			return errors.New("expired cert at " + staticPath)
		}

		if !matchesUsernameSuffix(cert.Subject.CommonName, usernameSuffix) {
			// Park it for the authenticator it does belong to.
			putCertInCache(cert.Subject.CommonName, rawPEM)

			return errors.New("not cert for " + usernameSuffix)
		}

		err = os.WriteFile(path, rawPEM, 0600) //write cert content into authn specific PEM file <authnName>-client.pem
		if err != nil {
			return log.RecordedError("unable to write certificate to file %s: %s", path, err.Error())
		}

		return nil

	}, limitedBackOff)

	if err != nil {
		return log.RecordedError(log.CAKC033+" for "+usernameSuffix, retryCountLimit, staticPath)
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
