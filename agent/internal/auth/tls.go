// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"time"
)

var ErrTLS = errors.New("TLS_IDENTITY_INVALID")

func Certificate(certPEM, keyPEM []byte) (tls.Certificate, *x509.Certificate, error) {
	cert, e := tls.X509KeyPair(certPEM, keyPEM)
	if e != nil || len(cert.Certificate) == 0 {
		return tls.Certificate{}, nil, ErrTLS
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) || len(leaf.DNSNames)+len(leaf.IPAddresses) == 0 {
		return tls.Certificate{}, nil, ErrTLS
	}
	cert.Leaf = leaf
	return cert, leaf, nil
}
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}
func ServerTLS(cert tls.Certificate) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}}
}

// Standard certificate validation stays enabled: a pinned leaf is an explicit
// trust anchor, not permission to ignore hostname, expiry or TLS verification.
func PinnedTLS(leaf *x509.Certificate, name, pin string) (*tls.Config, error) {
	hash, e := hex.DecodeString(pin)
	if e != nil || len(hash) != 32 || name == "" || len(name) > 253 {
		return nil, ErrTLS
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: name, NextProtos: []string{"http/1.1"}, VerifyConnection: func(s tls.ConnectionState) error {
		if len(s.PeerCertificates) == 0 {
			return ErrTLS
		}
		actual := sha256.Sum256(s.PeerCertificates[0].Raw)
		if subtle.ConstantTimeCompare(hash, actual[:]) != 1 {
			return ErrTLS
		}
		return nil
	}}, nil
}
