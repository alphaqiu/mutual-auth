package main

import (
	"io/ioutil"
	"crypto/x509"
	"crypto/tls"
	"fmt"
	"net/http"
	"io"
	"net"
	"encoding/json"
)

const (
	certFile   = "../tls/server.pem"
	keyFile    = "../tls/server.key"
	caCertFile = "../tls/ca.pem"
)

/**
 * https双向认证机制演示。
 */
func main() {
	http.HandleFunc("/", defaultHandler)
	config, err := setTLSConfig()
	if err != nil {
		return
	}

	srv := newServer(":8443", config)
	if err = srv.ListenAndServeTLS(certFile, keyFile); err != nil {
		fmt.Printf("found error: %v\n", err)
		return
	}

}

func setTLSConfig() (*tls.Config, error) {
	clientCertPool := x509.NewCertPool()
	clientBytes, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		fmt.Printf("read client pem failed. cause: %v\n", err)
		return nil, err
	}

	if !clientCertPool.AppendCertsFromPEM(clientBytes) {
		fmt.Printf("add client pem failed. then exit!\n")
		return nil, err
	}

	return &tls.Config{
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      clientCertPool,
		GetCertificate: getCertificateHook,
	}, nil
}

func newServer(addr string, config *tls.Config) *http.Server {
	return &http.Server{
		Addr:      addr,
		Handler:   nil,
		ConnState: connStateHook,
		TLSConfig: config,
	}
}

func defaultHandler(w http.ResponseWriter, _ *http.Request) {
	if _, err := io.WriteString(w, "Hello World!"); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func connStateHook(c net.Conn, state http.ConnState) {
	if state == http.StateActive {
		if cc, ok := c.(*tls.Conn); ok {
			state := cc.ConnectionState()
			fmt.Printf("# Handshake complete? %v, negotiated protocol: %s\n", state.HandshakeComplete, state.NegotiatedProtocol)
			switch state.Version {
			case tls.VersionSSL30:
				fmt.Println("negotiated to Version: VersionSSL30")
			case tls.VersionTLS10:
				fmt.Println("negotiated to Version: VersionTLS10")
			case tls.VersionTLS11:
				fmt.Println("negotiated to Version: VersionTLS11")
			case tls.VersionTLS12:
				fmt.Println("negotiated to Version: VersionTLS12")
			default:
				fmt.Println("negotiated to Unknown TLS version")
			}
		}
	}

	fmt.Printf("# Current state: %v \n", state)
}

type output struct {
	SupportedSuites []string `json:"supported_suites"`
	SupportedCurves []string `json:"supported_curves"`
	SupportedPoints []string `json:"supported_points"`
}

func getCertificateHook(helloInfo *tls.ClientHelloInfo) (*tls.Certificate, error) {
	fmt.Printf("#Invoke getCertificateHook\n")
	o := &output{}
	for _, suite := range helloInfo.CipherSuites {
		if v, exists := CipherSuiteMap[suite]; exists {
			o.SupportedSuites = append(o.SupportedSuites, v)
		} else {
			o.SupportedSuites = append(o.SupportedSuites, fmt.Sprintf("Unknown, 0x%x", suite))
		}
	}

	for _, curve := range helloInfo.SupportedCurves {
		if v, exists := CurveMap[curve]; exists {
			o.SupportedCurves = append(o.SupportedCurves, v)
		} else {
			o.SupportedCurves = append(o.SupportedCurves, fmt.Sprintf("Unknown, 0x%x", curve))
		}
		// http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8
	}
	for _, point := range helloInfo.SupportedPoints {
		// http://tools.ietf.org/html/rfc4492#section-5.1.2).
		o.SupportedPoints = append(o.SupportedPoints, fmt.Sprintf("0x%x", point))
	}

	j, _ := json.Marshal(o)
	fmt.Println(string(j))
	return nil, nil
}

func getClientCertificate(reqInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return nil, nil
}
