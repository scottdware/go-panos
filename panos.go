// Package panos interacts with Palo Alto firewalls using the REST API.
package panos

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// PaloAlto is a container for our session state.
type PaloAlto struct {
	Host      string
	Key       string
	Transport *http.Transport
}

// authKey holds our API key.
type authKey struct {
	XMLName xml.Name `xml:"response"`
	Key     string   `xml:"result>key"`
}

// APIRequest builds our request before sending it to the server.
type APIRequest struct {
	Method string
	URL    string
	Body   string
	Action string
	XPath  string
}

// requestError contains information about any error we get from a request.
type requestError struct {
	XMLName xml.Name `xml:"response"`
	Message string   `xml:"msg>line,omitempty"`
}

// NewSession sets up our connection to the Palo Alto firewall system.
func NewSession(host, user, passwd string) *PaloAlto {
	var key authKey
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Get(fmt.Sprintf("https://%s/api/?type=keygen&user=%s&password=%s", host, user, passwd))
	if err != nil {
		fmt.Println(err)
	}

	data, _ := ioutil.ReadAll(resp.Body)
	xml.Unmarshal(data, &key)

	return &PaloAlto{
		Host: host,
		Key:  key.Key,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
}

// APICall is used to query the Palo Alto API.
func (p *PaloAlto) APICall(options *APIRequest) ([]byte, error) {
	var req *http.Request
	client := &http.Client{Transport: p.Transport}
	url := fmt.Sprintf("https://%s/api/?type=config&key=%s&action=%s&xpath=%s", p.Host, p.Key, options.Action, options.XPath)
	body := bytes.NewReader([]byte(options.Body))
	req, _ = http.NewRequest(strings.ToUpper(options.Method), url, body)
	req.Header.Set("Content-Type", "application/xml")

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	data, _ := ioutil.ReadAll(res.Body)

	return data, nil
}

// checkError handles any errors we get from our API requests. It returns either the
// message of the error, if any, or nil.
func (p *PaloAlto) checkError(resp []byte) error {
	var reqError requestError

	err := xml.Unmarshal(resp, &reqError)
	if err != nil {
		return err
	}

	if reqError.Message != "" {
		return errors.New(reqError.Message)
	}

	return nil
}
