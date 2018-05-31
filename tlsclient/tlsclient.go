package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"crypto/x509"
	"net/http"
)

func main() {
	// 该路径只能通过 go build . 到该目录下编译。
	clientCert, err := tls.LoadX509KeyPair("../tls/client.pem", "../tls/client.key")
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	certBytes, err := ioutil.ReadFile("../tls/ca.pem")
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}

	clientCertPool := x509.NewCertPool()
	if !clientCertPool.AppendCertsFromPEM(certBytes) {
		fmt.Printf("Can not add pem into the pool")
		return
	}

	config := tls.Config{
		RootCAs: clientCertPool,
		Certificates: []tls.Certificate{clientCert},
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &config,
		},
	}

	resp, err := client.Get("https://localhost:8443/")
	if err != nil {
		fmt.Printf("get remote url failed. cause: %v\n", err)
		return
	}

	body := resp.Body
	defer body.Close()

	payload, err := ioutil.ReadAll(body)
	if err != nil {
		fmt.Printf("read body failed. cause: %v\n", err)
		return
	}

	fmt.Printf("%s\n", payload)

}
