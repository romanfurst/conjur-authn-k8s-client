package config

import (
	"fmt"
	"io/ioutil"
	"os"
)

// Config defines the configuration parameters
// for the authentication requests
type Config struct {
	ContainerMode  string
	ConjurVersion  string
	Account        string
	URL            string
	Username       string
	PodName        string
	PodNamespace   string
	SSLCertificate []byte
	ClientCertPath string
	TokenFilePath  string
}

// New returns a new authenticator configuration object
func NewFromEnv(clientCertPath *string, tokenPath *string) (*Config, error) {
	var err error

	// Check that required environment variables are set
	for _, envvar := range []string{
		"CONJUR_AUTHN_URL",
		"CONJUR_ACCOUNT",
		"CONJUR_AUTHN_LOGIN",
		"MY_POD_NAMESPACE",
		"MY_POD_NAME",
	} {
		if os.Getenv(envvar) == "" {
			err = fmt.Errorf(
				"%s must be provided", envvar)
			return nil, err
		}
	}

	// Load CA cert
	caCert, err := readSSLCert()
	if err != nil {
		return nil, err
	}

	// Load configuration from the environment
	authnURL := os.Getenv("CONJUR_AUTHN_URL")
	account := os.Getenv("CONJUR_ACCOUNT")
	authnLogin := os.Getenv("CONJUR_AUTHN_LOGIN")
	podNamespace := os.Getenv("MY_POD_NAMESPACE")
	podName := os.Getenv("MY_POD_NAME")

	containerMode := os.Getenv("CONTAINER_MODE")

	conjurVersion := os.Getenv("CONJUR_VERSION")
	if len(conjurVersion) == 0 {
		conjurVersion = "5"
	}

	return &Config{
		ContainerMode:  containerMode,
		ConjurVersion:  conjurVersion,
		Account:        account,
		URL:            authnURL,
		Username:       authnLogin,
		PodName:        podName,
		PodNamespace:   podNamespace,
		SSLCertificate: caCert,
		ClientCertPath: *clientCertPath,
		TokenFilePath:  *tokenPath,
	}, nil
}

func readSSLCert() ([]byte, error) {
	SSLCert := os.Getenv("CONJUR_SSL_CERTIFICATE")
	SSLCertPath := os.Getenv("CONJUR_CERT_FILE")
	if SSLCert == "" && SSLCertPath == "" {
		return nil, fmt.Errorf(
			"at least one of CONJUR_SSL_CERTIFICATE and CONJUR_CERT_FILE must be provided")
	}

	if SSLCert != "" {
		return []byte(SSLCert), nil
	}
	return ioutil.ReadFile(SSLCertPath)
}
