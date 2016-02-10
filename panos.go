// Package panos interacts with Palo Alto firewalls using the REST API.
package panos

import (
	"encoding/xml"
	"fmt"
	"github.com/scottdware/go-rested"
	"strings"
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
}

// Tags contains information about all tags on the system.
type Tags struct {
	Tags []Tag
}

// Tag contains information about each individual tag.
type Tag struct {
	Name     string
	Color    string
	Comments string
}

// xmlTags is used for parsing all tags on the system.
type xmlTags struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Tags    []xmlTag `xml:"result>tag>entry"`
}

// xmlTag is used for parsing each individual tag.
type xmlTag struct {
	Name     string `xml:"name,attr"`
	Color    string `xml:"color,omitempty"`
	Comments string `xml:"comments,omitempty"`
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

// panoramaStatus gets the connection status to Panorama.
type panoramaStatus struct {
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

var (
	headers = map[string]string{
		"Content-Type": "application/xml",
	}
	tagColors = map[string]string{
		"color1":  "Red",
		"color2":  "Green",
		"color3":  "Blue",
		"color4":  "Yellow",
		"color5":  "Copper",
		"color6":  "Orange",
		"color7":  "Purple",
		"color8":  "Gray",
		"color9":  "Light Green",
		"color10": "Cyan",
		"color11": "Light Gray",
		"color12": "Blue Gray",
		"color13": "Lime",
		"color14": "Black",
		"color15": "Gold",
		"color16": "Brown",
	}
	errorCodes = map[string]string{
		"400": "Bad request",
		"403": "Forbidden",
		"1":   "Unknown command",
		"2":   "Internal error",
		"3":   "Internal error",
		"4":   "Internal error",
		"5":   "Internal error",
		"6":   "Bad Xpath",
		"7":   "Object not present",
		"8":   "Object not unique",
		"9":   "Internal error",
		"10":  "Reference count not zero",
		"11":  "Internal error",
		"12":  "Invalid object",
		"13":  "Operation failed",
		"14":  "Operation not possible",
		"15":  "Operation denied",
		"16":  "Unauthorized",
		"17":  "Invalid command",
		"18":  "Malformed command",
		"19":  "Success",
		"20":  "Success",
		"21":  "Internal error",
		"22":  "Session timed out",
	}
)

// NewSession sets up our connection to the Palo Alto firewall system.
func NewSession(host, user, passwd string) (*PaloAlto, error) {
	var key authKey
	var info systemInfo
	var pan panoramaStatus
	status := false
	deviceType := "panos"
	r := rested.NewRequest()

	resp := r.Send("get", fmt.Sprintf("https://%s/api/?type=keygen&user=%s&password=%s", host, user, passwd), nil, nil, nil)
	if resp.Error != nil {
		return nil, resp.Error
	}

	err := xml.Unmarshal(resp.Body, &key)
	if err != nil {
		return nil, err
	}

	if key.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s (keygen)", key.Code, errorCodes[key.Code])
	}

	uri := fmt.Sprintf("https://%s/api/?", host)
	getInfo := r.Send("get", fmt.Sprintf("%s&key=%s&type=op&cmd=<show><system><info></info></system></show>", uri, key.Key), nil, nil, nil)

	if getInfo.Error != nil {
		return nil, getInfo.Error
	}

	err = xml.Unmarshal(getInfo.Body, &info)
	if err != nil {
		return nil, err
	}

	if info.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s (show system info)", info.Code, errorCodes[info.Code])
	}

	panStatus := r.Send("get", fmt.Sprintf("%s&key=%s&type=op&cmd=<show><panorama-status></panorama-status></show>", uri, key.Key), nil, nil, nil)
	if panStatus.Error != nil {
		return nil, panStatus.Error
	}

	err = xml.Unmarshal(panStatus.Body, &pan)
	if err != nil {
		return nil, err
	}

	if info.Platform == "m" {
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
	}, nil
}

// Tags returns information about all tags on the system.
func (p *PaloAlto) Tags() (*Tags, error) {
	var parsedTags xmlTags
	var tags Tags
	xpath := "/config/devices/entry//tag"
	// xpath := "/config/devices/entry/vsys/entry/tag"
	r := rested.NewRequest()

	if p.DeviceType == "panos" && p.Panorama == true {
		xpath = "/config/panorama//tag"
	}

	if p.DeviceType == "panorama" {
		// xpath = "/config/devices/entry/device-group/entry/tag"
		xpath = "/config/devices/entry//tag"
	}

	query := map[string]string{
		"type":   "config",
		"action": "get",
		"xpath":  xpath,
		"key":    p.Key,
	}
	tData := r.Send("get", p.URI, nil, headers, query)

	if err := xml.Unmarshal(tData.Body, &parsedTags); err != nil {
		return nil, err
	}

	if parsedTags.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", parsedTags.Code, errorCodes[parsedTags.Code])
	}

	for _, t := range parsedTags.Tags {
		tname := t.Name
		tcolor := tagColors[t.Color]
		tcomments := t.Comments

		tags.Tags = append(tags.Tags, Tag{Name: tname, Color: tcolor, Comments: tcomments})
	}

	return &tags, nil

}
