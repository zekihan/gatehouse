package controller

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	corev1 "k8s.io/api/core/v1"

	"github.com/zekihan/gatehouse/internal/snapshot"
)

func classOf(protection, prefix string) string {
	if class, found := strings.CutPrefix(protection, prefix); found {
		return class
	}
	return ""
}

func secretValues(obj *unstructured.Unstructured) (map[string][]byte, bool) {
	secret, ok := decode[corev1.Secret](obj)
	if !ok {
		return nil, false
	}
	return secret.Data, true
}

func validCA(data []byte, now time.Time) bool {
	var active bool
	for len(bytes.TrimSpace(data)) != 0 {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return false
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid {
			return false
		}
		if !now.Before(cert.NotBefore) && now.Before(cert.NotAfter) {
			active = true
		}
		data = rest
	}
	return active
}

func keyPair(obj *unstructured.Unstructured, host string, now time.Time) *snapshot.KeyPair {
	values, ok := secretValues(obj)
	if !ok {
		return nil
	}
	cert, err := tls.X509KeyPair(values[corev1.TLSCertKey], values[corev1.TLSPrivateKeyKey])
	if err != nil || cert.Leaf == nil || now.Before(cert.Leaf.NotBefore) ||
		!now.Before(cert.Leaf.NotAfter) {
		return nil
	}
	pub, ok := cert.Leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || cert.Leaf.VerifyHostname(host) != nil {
		return nil
	}
	return &snapshot.KeyPair{
		CertPEM: values[corev1.TLSCertKey], KeyPEM: values[corev1.TLSPrivateKeyKey],
	}
}
