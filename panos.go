// Package panos interacts with Palo Alto and Panorama devices using the XML API.
package panos

import (
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/parnurzeal/gorequest"
)

// PaloAlto is a container for our session state.
type PaloAlto struct {
	Host            string
	Key             string
	URI             string
	Platform        string
	Model           string
	Serial          string
	SoftwareVersion string
	DeviceType      string
	Panorama        bool
	Shared          bool
}

// Jobs holds information about all jobs on the device.
type Jobs struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Jobs    []Job    `xml:"result>job"`
}

// Job holds information about each individual job.
type Job struct {
	ID            int      `xml:"id"`
	User          string   `xml:"user"`
	Type          string   `xml:"type"`
	Status        string   `xml:"status"`
	Queued        string   `xml:"queued"`
	Stoppable     string   `xml:"stoppable"`
	Result        string   `xml:"result"`
	Description   string   `xml:"description,omitempty"`
	QueuePosition int      `xml:"positionInQ"`
	Progress      string   `xml:"progress"`
	Details       []string `xml:"details>line"`
	Warnings      string   `xml:"warnings,omitempty"`
	StartTime     string   `xml:"tdeq"`
	EndTime       string   `xml:"tfin"`
}

// authKey holds our API key.
type authKey struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Key     string   `xml:"result>key"`
}

// systemInfo holds basic system information.
type systemInfo struct {
	XMLName         xml.Name `xml:"response"`
	Status          string   `xml:"status,attr"`
	Code            string   `xml:"code,attr"`
	Platform        string   `xml:"result>system>platform-family"`
	Model           string   `xml:"result>system>model"`
	Serial          string   `xml:"result>system>serial"`
	SoftwareVersion string   `xml:"result>system>sw-version"`
}

// commandOutput holds the results of our operational mode commands that were issued.
type commandOutput struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Data    string   `xml:"result"`
}

// requestError contains information about any error we get from a request.
type requestError struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Message string   `xml:"result>msg,omitempty"`
}

// testURL contains the results of the operational command test url.
type testURL struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Result  string   `xml:"result"`
}

// testRoute contains the results of the operational command test routing fib-lookup.
type testRoute struct {
	XMLName   xml.Name `xml:"response"`
	Status    string   `xml:"status,attr"`
	Code      string   `xml:"code,attr"`
	NextHop   string   `xml:"result>nh"`
	Source    string   `xml:"result>src"`
	IP        string   `xml:"result>ip"`
	Metric    int      `xml:"result>metric"`
	Interface string   `xml:"result>interface"`
}

var (
	r = gorequest.New().TLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	errorCodes = map[string]string{
		"400": "Bad request - Returned when a required parameter is missing, an illegal parameter value is used",
		"403": "Forbidden - Returned for authentication or authorization errors including invalid key, insufficient admin access rights",
		"1":   "Unknown command - The specific config or operational command is not recognized",
		"2":   "Internal error - Check with technical support when seeing these errors",
		"3":   "Internal error - Check with technical support when seeing these errors",
		"4":   "Internal error - Check with technical support when seeing these errors",
		"5":   "Internal error - Check with technical support when seeing these errors",
		"6":   "Bad Xpath - The xpath specified in one or more attributes of the command is invalid. Check the API browser for proper xpath values",
		"7":   "Object not present - Object specified by the xpath is not present. For example, entry[@name=’value’] where no object with name ‘value’ is present",
		"8":   "Object not unique - For commands that operate on a single object, the specified object is not unique",
		"9":   "Internal error - Check with technical support when seeing these errors",
		"10":  "Reference count not zero - Object cannot be deleted as there are other objects that refer to it. For example, address object still in use in policy",
		"11":  "Internal error - Check with technical support when seeing these errors",
		"12":  "Invalid object - Xpath or element values provided are not complete",
		"13":  "Operation failed - A descriptive error message is returned in the response",
		"14":  "Operation not possible - Operation is not possible. For example, moving a rule up one position when it is already at the top",
		"15":  "Operation denied - For example, Admin not allowed to delete own account, Running a command that is not allowed on a passive device",
		"16":  "Unauthorized - The API role does not have access rights to run this query",
		"17":  "Invalid command - Invalid command or parameters",
		"18":  "Malformed command - The XML is malformed",
		"19":  "Success - Command completed successfully",
		"20":  "Success - Command completed successfully",
		"21":  "Internal error - Check with technical support when seeing these errors",
		"22":  "Session timed out - The session for this query timed out",
	}
)

// splitSWVersion
func splitSWVersion(version string) []int {
	re := regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
	match := re.FindStringSubmatch(version)
	maj, _ := strconv.Atoi(match[1])
	min, _ := strconv.Atoi(match[2])
	rel, _ := strconv.Atoi(match[3])

	return []int{maj, min, rel}
}

// NewSession sets up our connection to the Palo Alto firewall or Panorama device.
func NewSession(host, user, passwd string) (*PaloAlto, error) {
	var key authKey
	var info systemInfo
	var pan commandOutput
	status := false
	deviceType := "panos"

	_, body, errs := r.Get(fmt.Sprintf("https://%s/api/?type=keygen&user=%s&password=%s", host, user, passwd)).End()
	if errs != nil {
		return nil, errs[0]
	}

	err := xml.Unmarshal([]byte(body), &key)
	if err != nil {
		return nil, err
	}

	if key.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s (keygen)", key.Code, errorCodes[key.Code])
	}

	uri := fmt.Sprintf("https://%s/api/?", host)
	_, getInfo, errs := r.Get(fmt.Sprintf("%s&key=%s&type=op&cmd=<show><system><info></info></system></show>", uri, key.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	err = xml.Unmarshal([]byte(getInfo), &info)
	if err != nil {
		return nil, err
	}

	if info.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s (show system info)", info.Code, errorCodes[info.Code])
	}

	_, panStatus, errs := r.Get(fmt.Sprintf("%s&key=%s&type=op&cmd=<show><panorama-status></panorama-status></show>", uri, key.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	err = xml.Unmarshal([]byte(panStatus), &pan)
	if err != nil {
		return nil, err
	}

	if info.Platform == "m" || info.Model == "Panorama" {
		deviceType = "panorama"
	}

	if strings.Contains(pan.Data, ": yes") {
		status = true
	}

	return &PaloAlto{
		Host:            host,
		Key:             key.Key,
		URI:             fmt.Sprintf("https://%s/api/?", host),
		Platform:        info.Platform,
		Model:           info.Model,
		Serial:          info.Serial,
		SoftwareVersion: info.SoftwareVersion,
		DeviceType:      deviceType,
		Panorama:        status,
		Shared:          false,
	}, nil
}

// Commit issues a commit on the device. When issuing a commit against a Panorama device,
// the configuration will only be committed to Panorama, and not an individual device-group.
func (p *PaloAlto) Commit() error {
	var reqError requestError

	_, resp, errs := r.Get(p.URI).Query(fmt.Sprintf("type=commit&cmd=<commit></commit>&key=%s", p.Key)).End()
	if errs != nil {
		return errs[0]
	}

	if err := xml.Unmarshal([]byte(resp), &reqError); err != nil {
		return err
	}

	if reqError.Status != "success" {
		return fmt.Errorf("error code %s: %s", reqError.Code, errorCodes[reqError.Code])
	}

	return nil
}

// CommitAll issues a commit to a Panorama device, with the given 'devicegroup.' You can (optionally) specify
// individual devices within that device group by adding each serial number as an additional parameter.
func (p *PaloAlto) CommitAll(devicegroup string, devices ...string) error {
	var reqError requestError
	var cmd string

	if p.DeviceType == "panorama" && len(devices) <= 0 {
		cmd = fmt.Sprintf("<commit-all><shared-policy><device-group><entry name=\"%s\"/></device-group></shared-policy></commit-all>", devicegroup)
	}

	if p.DeviceType == "panorama" && len(devices) > 0 {
		cmd = fmt.Sprintf("<commit-all><shared-policy><device-group><name>%s</name><devices>", devicegroup)

		for _, d := range devices {
			cmd += fmt.Sprintf("<entry name=\"%s\"/>", d)
		}

		cmd += "</devices></device-group></shared-policy></commit-all>"
	}

	_, resp, errs := r.Get(p.URI).Query(fmt.Sprintf("type=commit&action=all&cmd=%s&key=%s", cmd, p.Key)).End()
	if errs != nil {
		return errs[0]
	}

	if err := xml.Unmarshal([]byte(resp), &reqError); err != nil {
		return err
	}

	if reqError.Status != "success" {
		return fmt.Errorf("error code %s: %s", reqError.Code, errorCodes[reqError.Code])
	}

	return nil
}

// RestartSystem will issue a system restart to the device.
func (p *PaloAlto) RestartSystem() error {
	var reqError requestError
	command := "<request><restart><system></system></restart></request>"

	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=op&cmd=%s&key=%s", command, p.Key)).End()
	if errs != nil {
		return errs[0]
	}

	if err := xml.Unmarshal([]byte(resp), &reqError); err != nil {
		return err
	}

	if reqError.Status != "success" {
		return fmt.Errorf("error code %s: %s", reqError.Code, errorCodes[reqError.Code])
	}

	return nil
}

// TestURL will verify what category the given URL falls under. It will return two results in a string slice ([]string). The
// first one is from the Base db categorization, and the second is from the Cloud db categorization. If you specify a URL
// with a wildcard, such as *.paloaltonetworks.com, it will not return a result.
func (p *PaloAlto) TestURL(url string) ([]string, error) {
	var urlResults testURL
	rex := regexp.MustCompile(`(?m)^([\d\.a-zA-Z-]+)\s([\w-]+)\s.*seconds\s([\d\.a-zA-Z-]+)\s([\w-]+)\s`)
	command := fmt.Sprintf("<test><url>%s</url></test>", url)

	if p.DeviceType == "panorama" {
		return nil, errors.New("you can only test URL's from a local device")
	}

	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=op&cmd=%s&key=%s", command, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(resp), &urlResults); err != nil {
		return nil, err
	}

	if urlResults.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", urlResults.Code, errorCodes[urlResults.Code])
	}

	categorization := rex.FindStringSubmatch(urlResults.Result)

	if len(categorization) == 0 {
		return nil, fmt.Errorf("cannot resolve the site %s", url)
	}

	results := []string{
		fmt.Sprintf("%s", categorization[2]),
		fmt.Sprintf("%s", categorization[4]),
	}

	return results, nil
}

// TestRouteLookup will lookup the given destination IP in the virtual-router 'vr' and check the routing (fib) table and display the results.
func (p *PaloAlto) TestRouteLookup(vr, destination string) (string, error) {
	var routeLookup testRoute
	command := fmt.Sprintf("<test><routing><fib-lookup><virtual-router>%s</virtual-router><ip>%s</ip></fib-lookup></routing></test>", vr, destination)

	if p.DeviceType == "panorama" {
		return "", errors.New("you can only test route lookups from a local device")
	}

	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=op&cmd=%s&key=%s", command, p.Key)).End()
	if errs != nil {
		return "", errs[0]
	}

	if err := xml.Unmarshal([]byte(resp), &routeLookup); err != nil {
		return "", err
	}

	if routeLookup.Status != "success" {
		return "", fmt.Errorf("error code %s: %s", routeLookup.Code, errorCodes[routeLookup.Code])
	}

	result := fmt.Sprintf("Destination %s via %s interface %s, source %s, metric %d (%s)\n", destination, routeLookup.IP, routeLookup.Interface, routeLookup.Source, routeLookup.Metric, vr)

	return result, nil
}

// Jobs returns information about every job on the device. "status" can be one of: "all," "pending," or "processed." If you want
// information about a specific job, specify the id instead of one of the other options.
func (p *PaloAlto) Jobs(status interface{}) (*Jobs, error) {
	var jobs Jobs
	var cmd string

	switch status.(type) {
	case string:
		if status == "all" {
			cmd += "<show><jobs><all></all></jobs></show>"
		}

		if status == "pending" {
			cmd += "<show><jobs><pending></pending></jobs></show>"
		}

		if status == "processed" {
			cmd += "<show><jobs><processed></processed></jobs></show>"
		}
	case int:
		cmd += fmt.Sprintf("<show><jobs><id>%d</id></jobs></show>", status)
	}

	_, res, errs := r.Get(fmt.Sprintf("%s&key=%s&type=op&cmd=%s", p.URI, p.Key, cmd)).End()
	if errs != nil {
		return nil, errs[0]
	}

	err := xml.Unmarshal([]byte(res), &jobs)
	if err != nil {
		return nil, err
	}

	return &jobs, nil
}

// Command lets you run any operational mode command against the given device, and it returns the output.
// func (p *PaloAlto) Command(command string) (string, error) {
// 	var output commandOutput
// 	var cmd string
//
// 	if len(command) > 0 {
// 		secs := strings.Split(command, " ")
// 		nSecs := len(secs)
//
// 		if nSecs >= 0 {
// 			for i := 0; i < nSecs; i++ {
// 				cmd += fmt.Sprintf("<%s>", secs[i])
// 			}
// 			// cmd += fmt.Sprintf("<%s/>", secs[nSecs])
//
// 			for j := nSecs - 1; j >= 0; j-- {
// 				cmd += fmt.Sprintf("</%s>", secs[j])
// 			}
// 			// command += fmt.Sprint("</configuration></get-configuration>")
// 		}
// 	}
//
// 	fmt.Println(cmd)
//
// 	_, res, errs := r.Get(fmt.Sprintf("%s&key=%s&type=op&cmd=%s", p.URI, p.Key, cmd)).End()
// 	if errs != nil {
// 		return "", errs[0]
// 	}
//
// 	fmt.Println(res)
//
// 	err := xml.Unmarshal([]byte(res), &output)
// 	if err != nil {
// 		return "", err
// 	}
//
// 	return output.Data, nil
// }

// ARPTable will gather all of the ARP entires on the device. Without any parameters, it will return all ARP entries.
// You can specify an interface name for the 'option' parameter if you choose to only view the ARP entries for that specific
// interface (i.e. "ethernet1/1.200" or "ethernet1/21"). Status codes are as follows: s - static, c - complete, e - expiring, i - incomplete.
func (p *PaloAlto) ARPTable(option ...string) (*ARPTable, error) {
	var arpTable ARPTable
	command := "<show><arp><entry name = 'all'/></arp></show>"

	if p.DeviceType == "panorama" {
		return nil, errors.New("you cannot view the ARP table on a Panorama device")
	}

	if len(option) > 0 {
		command = fmt.Sprintf("<show><arp><entry name = '%s'/></arp></show>", option[0])
	}

	_, resp, errs := r.Get(p.URI).Query(fmt.Sprintf("type=op&cmd=%s&key=%s", command, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	formatted := strings.Replace(resp, "  ", "", -1)
	if err := xml.Unmarshal([]byte(formatted), &arpTable); err != nil {
		return nil, err
	}

	return &arpTable, nil
}
