package rpc

import (
		"bytes"
		"crypto"
		"crypto/tls"
		"crypto/x509"
		"crypto/ecdsa"
		"crypto/rsa"
		"crypto/ed25519"
		"errors"
		"os"
		"strings"
	)
	
func MakeServerTLSConfig() (*tls.Config, error) {
	certPath := os.Getenv("RATLS_CRT_PATH")
	keyPath := os.Getenv("RATLS_KEY_PATH")
	
	config := &tls.Config{
		PreferServerCipherSuites: true,
	}
	
	// Load certificate/key
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if strings.Contains(certPath, ".der") || strings.Contains(keyPath, ".der") {
		cert, err = LoadX509KeyPairDER(certPath, keyPath)
	}
	if err == nil {
		config.Certificates = []tls.Certificate{cert}
	}
	
	return config, nil
}
	
// X509KeyPair parses a public/private key pair from a pair of
// PEM encoded data. On successful return, Certificate.Leaf will be nil because
// the parsed form of the certificate is not retained.
func LoadX509KeyPairDER(certFile, keyFile string) (tls.Certificate, error) {
	fail := func(err error) (tls.Certificate, error) { return tls.Certificate{}, err }

	certDER, err := os.ReadFile(certFile)
	keyDER, err := os.ReadFile(keyFile)
	
	var cert tls.Certificate
	
	cert.Certificate = append(cert.Certificate, certDER)
	
	// We don't need to parse the public key for TLS, but we so do anyway
	// to check that it looks sane and matches the private key.
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fail(err)
	}
	
	cert.PrivateKey, err = parsePrivateKey(keyDER)
	if err != nil {
		return fail(err)
	}
	
	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if pub.N.Cmp(priv.N) != 0 {
			return fail(errors.New("tls: private key does not match public key"))
		}
	case *ecdsa.PublicKey:
		priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return fail(errors.New("tls: private key does not match public key"))
		}
	case ed25519.PublicKey:
		priv, ok := cert.PrivateKey.(ed25519.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
			return fail(errors.New("tls: private key does not match public key"))
		}
	default:
		return fail(errors.New("tls: unknown public key algorithm"))
	}
	
	return cert, nil
}
	
// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS #1 private keys by default, while OpenSSL 1.0.0 generates PKCS #8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	
	return nil, errors.New("tls: failed to parse private key")
}