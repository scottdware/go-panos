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

// WildfireMalwareReport contains information about the submitted file and it's behavior.
type WildfireMalwareReport struct {
	XMLName  xml.Name         `xml:"wildfire"`
	Malware  string           `xml:"file_info>malware"`
	FileType string           `xml:"file_info>filetype"`
	FileSize int              `xml:"file_info>size"`
	MD5      string           `xml:"file_info>md5"`
	SHA1     string           `xml:"file_info>sha1"`
	SHA256   string           `xml:"file_info>sha256"`
	Reports  []WildfireReport `xml:"task_info>report"`
}

// WildfireReport contains information about the analyzed file in a VM environment.
type WildfireReport struct {
	Malware           string                `xml:"malware"`
	VMSoftware        string                `xml:"software"`
	BehavioralSummary []string              `xml:"summary>entry"`
	DNSQueries        []WildfireDNSQuery    `xml:"network>dns"`
	TCPPorts          []WildfireTCPPort     `xml:"network>TCP"`
	UDPPorts          []WildfireUDPPort     `xml:"network>UDP"`
	HTTPRequests      []WildfireHTTPRequest `xml:"network>url"`
}

// WildfireDNSQuery contains information about each DNS query the malware made.
type WildfireDNSQuery struct {
	Type     string `xml:"type,attr"`
	Response string `xml:"response,attr"`
	Query    string `xml:"query,attr"`
}

// WildfireTCPPort contains information about the TCP connections the malware made.
type WildfireTCPPort struct {
	Port      string `xml:"port,attr"`
	IPAddress string `xml:"ip,attr"`
	Country   string `xml:"country,attr"`
}

// WildfireUDPPort contains information about the UDP connections the malware made.
type WildfireUDPPort struct {
	Port      string `xml:"port,attr"`
	IPAddress string `xml:"ip,attr"`
	Country   string `xml:"country,attr"`
}

// WildfireHTTPRequest contains information about each HTTP request the malware made.
type WildfireHTTPRequest struct {
	UserAgent string `xml:"user_agent,attr"`
	URI       string `xml:"uri,attr"`
	Method    string `xml:"method,attr"`
	Host      string `xml:"host,attr"`
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

	resp := r.SendForm("post", uri, form, nil, nil)
	if resp.Error != nil {
		return resp.Error
	}

	return nil
}

// GetReport retrieves the XML report on the given file hash (MD5, SHA-1 or SHA-256), and returns summarized information about the analyzed file.
// Only the behavioral summary, DNS queries, TCP/UDP port connections, and HTTP request information is returned.
func (w *Wildfire) GetReport(hash string) (*WildfireMalwareReport, error) {
	var report WildfireMalwareReport
	r := rested.NewRequest()
	uri := fmt.Sprintf("%sget/report", w.URL)
	form := map[string]string{
		"hash":   hash,
		"format": "xml",
		"apikey": w.APIKey,
	}

	resp := r.SendForm("post", uri, form, nil, nil)
	if resp.Error != nil {
		return nil, resp.Error
	}

	if err := xml.Unmarshal(resp.Body, &report); err != nil {
		return nil, err
	}

	return &report, nil
}
