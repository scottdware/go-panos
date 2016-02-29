package panos

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"github.com/scottdware/go-rested"
	"io"
	"mime/multipart"
	"net/http"
	"os"
)

// Wildfire contains information about our session.
type Wildfire struct {
	APIKey string
	URL    string
}

// wildfireError contains any error message we recieve.
type wildfireError struct {
	XMLName xml.Name `xml:"error"`
	Message string   `xml:"error-message"`
}

// NewWildfireSession establishes a new session to your Wildfire account.
func NewWildfireSession(apikey string) *Wildfire {
	return &Wildfire{
		APIKey: apikey,
		URL:    "https://wildfire.paloaltonetworks.com/publicapi/",
	}
}

// SubmitFile submits a file to Wildfire for analyzing.
func (w *Wildfire) SubmitFile(file string) error {
	var b bytes.Buffer
	mwriter := multipart.NewWriter(&b)
	uri := fmt.Sprintf("%ssubmit/file", w.URL)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	f, err := os.Open(file)
	if err != nil {
		return err
	}

	fw, err := mwriter.CreateFormFile("file", file)
	if err != nil {
		return err
	}

	if _, err := io.Copy(fw, f); err != nil {
		return err
	}

	if fw, err = mwriter.CreateFormField("apikey"); err != nil {
		return err
	}

	if _, err = fw.Write([]byte(w.APIKey)); err != nil {
		return err
	}

	mwriter.Close()

	req, err := http.NewRequest("POST", uri, &b)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", mwriter.FormDataContentType())
	res, err := client.Do(req)
	if err != nil {
		return err
	}

	if res.Status != "200 OK" {
		return fmt.Errorf("file submission error: %s", res.Status)
	}

	return nil
}

// SubmitURL submits a URL to Wildfire for analyzing.
func (w *Wildfire) SubmitURL(url string) error {
	r := rested.NewRequest()
	uri := fmt.Sprintf("%ssubmit/url", w.URL)

	form := map[string]string{
		"url":    url,
		"apikey": w.APIKey,
	}

	resp := r.Send("post", uri, form, nil, nil)
	if resp.Error != nil {
		return resp.Error
	}

	return nil
}

// GetReport retrieves the report on the given file hash (MD5, SHA-1 or SHA-256), and returns the output in XML format.
func (w *Wildfire) GetReport(hash, format string) (string, error) {
	r := rested.NewRequest()
	uri := fmt.Sprintf("%sget/report", w.URL)
	form := map[string]string{
		"hash":   hash,
		"format": format,
		"apikey": w.APIKey,
	}

	resp := r.Send("post", uri, form, nil, nil)
	if resp.Error != nil {
		return "", resp.Error
	}

	return string(resp.Body), nil
}
