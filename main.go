package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
)

type ClientHelloInfo struct {
	ServerName        string   `json:"server_name"`
	SupportedVersions []string `json:"supported_versions"`
	SupportedCurves   []string `json:"supported_curves"`
	SignatureSchemes  []string `json:"signature_schemes"`
	SupportedProtos   []string `json:"supported_protos"`
	CipherSuites      []string `json:"cipher_suites"`
	CompressMethods   []uint8  `json:"compress_methods"`
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
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

	var clientHelloInfo *tls.ClientHelloInfo

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			clientHelloInfo = hello
			return nil, nil
		},
	}

	server := &http.Server{
		Addr:      ":" + port,
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if clientHelloInfo == nil {
				http.Error(w, "No TLS ClientHello information available", http.StatusInternalServerError)
				return
			}

			info := ClientHelloInfo{
				ServerName:        clientHelloInfo.ServerName,
				SupportedVersions: make([]string, len(clientHelloInfo.SupportedVersions)),
				SupportedCurves:   make([]string, len(clientHelloInfo.SupportedCurves)),
				SignatureSchemes:  make([]string, len(clientHelloInfo.SignatureSchemes)),
				SupportedProtos:   clientHelloInfo.SupportedProtos,
				CipherSuites:      make([]string, len(clientHelloInfo.CipherSuites)),
				CompressMethods:   clientHelloInfo.CompressionMethods,
			}

			for i, v := range clientHelloInfo.SupportedVersions {
				info.SupportedVersions[i] = tls.VersionName(v)
			}

			for i, c := range clientHelloInfo.SupportedCurves {
				info.SupportedCurves[i] = c.String()
			}

			for i, s := range clientHelloInfo.SignatureSchemes {
				info.SignatureSchemes[i] = s.String()
			}

			for i, c := range clientHelloInfo.CipherSuites {
				info.CipherSuites[i] = tls.CipherSuiteName(c)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(info)
		}),
	}

	log.Printf("Starting server on :%s with CN=%s...\n", port, cn)
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
