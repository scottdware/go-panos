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
	Host            string
	Key             string
	URI             string
	Platform        string
	Model           string
	Serial          string
	SoftwareVersion string
	DeviceType      string
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
	Key     string   `xml:"result>key"`
}

// systemInfo holds basic system information.
type systemInfo struct {
	XMLName         xml.Name `xml:"response"`
	Platform        string   `xml:"result>system>platform-family"`
	Model           string   `xml:"result>system>model"`
	Serial          string   `xml:"result>system>serial"`
	SoftwareVersion string   `xml:"result>system>sw-version"`
}

// requestError contains information about any error we get from a request.
type requestError struct {
	XMLName xml.Name `xml:"response"`
	Message string   `xml:"msg>line,omitempty"`
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
)

// NewSession sets up our connection to the Palo Alto firewall system.
func NewSession(host, user, passwd string) *PaloAlto {
	var key authKey
	var info systemInfo
	deviceType := "panos"
	r := rested.NewRequest()

	resp := r.Send("get", fmt.Sprintf("https://%s/api/?type=keygen&user=%s&password=%s", host, user, passwd), nil, nil, nil)
	if resp.Error != nil {
		fmt.Println(resp.Error)
	}

	err := xml.Unmarshal(resp.Body, &key)
	if err != nil {
		fmt.Println(err)
	}

	uri := fmt.Sprintf("https://%s/api/?", host)
	getInfo := r.Send("get", fmt.Sprintf("%s&key=%s&type=op&cmd=<show><system><info></info></system></show>", uri, key.Key), nil, nil, nil)

	if getInfo.Error != nil {
		fmt.Println(getInfo.Error)
	}

	err = xml.Unmarshal(getInfo.Body, &info)
	if err != nil {
		fmt.Println(err)
	}

	if info.Platform == "m" {
		deviceType = "panorama"
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
	}
}

func (p *PaloAlto) Tags() *Tags {
	var parsedTags xmlTags
	var tags Tags
	r := rested.NewRequest()

	// xpath := "/config/devices/entry/vsys/entry/address"
	xpath := "/config/devices/entry//tag"

	if p.DeviceType == "panorama" {
		// xpath = "/config/devices/entry/device-group/entry/address"
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
		fmt.Println(err)
	}

	for _, t := range parsedTags.Tags {
		tname := t.Name
		tcolor := tagColors[t.Color]
		tcomments := t.Comments

		tags.Tags = append(tags.Tags, Tag{Name: tname, Color: tcolor, Comments: tcomments})
	}

	return &tags

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
