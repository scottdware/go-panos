// Package panos interacts with Palo Alto firewalls using the REST API.
package panos

import (
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/scottdware/go-rested"
)

// PaloAlto is a container for our session state.
type PaloAlto struct {
	Host string
	Key  string
}

// authKey holds our API key.
type authKey struct {
	XMLName xml.Name `xml:"response"`
	Key     string   `xml:"result>key"`
}

// requestError contains information about any error we get from a request.
type requestError struct {
	XMLName xml.Name `xml:"response"`
	Message string   `xml:"msg>line,omitempty"`
}

// NewSession sets up our connection to the Palo Alto firewall system.
func NewSession(host, user, passwd string) *PaloAlto {
	var key authKey

	resp := rested.Send(fmt.Sprintf("https://%s/api/?type=keygen&user=%s&password=%s", host, user, passwd), nil)
	if resp.Error != nil {
		fmt.Println(resp.Error)
	}

	err := xml.Unmarshal(resp.Body, &key)
	if err != nil {
		fmt.Println(err)
	}

	return &PaloAlto{
		Host: host,
		Key:  key.Key,
	}
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
