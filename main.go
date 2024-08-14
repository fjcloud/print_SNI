package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
)

type TLSData struct {
	ServerName       string   `json:"server_name"`
	Version          uint16   `json:"version"`
	CipherSuite      uint16   `json:"cipher_suite"`
	PeerCertificates []string `json:"peer_certificates"`
}

func generateCert(commonName string) (tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privateKey,
	}, nil
}

func main() {
	port := "8443"
	cn := os.Getenv("CERT_CN")
	if cn == "" {
		cn = "localhost"
	}

	cert, err := generateCert(cn)
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			log.Printf("Received SNI: %s\n", hello.ServerName)
			return nil, nil
		},
	}

	server := &http.Server{
		Addr:      ":" + port,
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil {
				http.Error(w, "TLS connection required", http.StatusBadRequest)
				return
			}

			tlsData := TLSData{
				ServerName:  r.TLS.ServerName,
				Version:     r.TLS.Version,
				CipherSuite: r.TLS.CipherSuite,
			}

			for _, cert := range r.TLS.PeerCertificates {
				tlsData.PeerCertificates = append(tlsData.PeerCertificates, cert.Subject.CommonName)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(tlsData)
		}),
	}

	log.Printf("Starting server on :%s with CN=%s...\n", port, cn)
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
