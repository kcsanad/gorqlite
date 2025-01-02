package tls

import (
	"crypto/tls"
	"crypto/x509"
	"os"
)

// SecureCiphers updates a *tls.Config with a secure ciphersuite configuration.
// If c is nil, a new config will be provided.
func SetTLSWithCiphers(c *tls.Config, servername *string, insecure bool, caFile *string) (*tls.Config, error) {
	if c == nil {
		c = &tls.Config{}
	}

	c.MinVersion = tls.VersionTLS12
	c.MaxVersion = tls.VersionTLS13

	c.CipherSuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	}

	if servername != nil && *servername != "" {
		c.ServerName = *servername
	}

	c.InsecureSkipVerify = insecure

	if caFile != nil && *caFile != "" {
		caCert, err := os.ReadFile(*caFile)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		c.RootCAs = caCertPool
	}

	return c, nil
}
