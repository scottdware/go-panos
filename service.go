package panos

import (
	"encoding/xml"
	"fmt"
	"github.com/scottdware/go-rested"
)

// ServiceObjects contains a slice of all service objects.
type ServiceObjects struct {
	XMLName  xml.Name  `xml:"response"`
	Status   string    `xml:"status,attr"`
	Code     string    `xml:"code,attr"`
	Services []Service `xml:"result>service>entry"`
}

// Service contains information about each individual service object.
type Service struct {
	Name        string `xml:"name,attr"`
	TCPPort     string `xml:"protocol>tcp>port,omitempty"`
	UDPPort     string `xml:"protocol>udp>port,omitempty"`
	Description string `xml:"description,omitempty"`
}

// ServiceGroups contains a slice of all service groups.
type ServiceGroups struct {
	XMLName xml.Name       `xml:"response"`
	Status  string         `xml:"status,attr"`
	Code    string         `xml:"code,attr"`
	Groups  []ServiceGroup `xml:"result>service-group>entry"`
}

// ServiceGroup contains information about each individual service group.
type ServiceGroup struct {
	Name        string   `xml:"name,attr"`
	Members     []string `xml:"members>member,omitempty"`
	Description string   `xml:"description,omitempty"`
}

// Services returns information about all of the address objects.
func (p *PaloAlto) Services() (*ServiceObjects, error) {
	var svcs ServiceObjects
	xpath := "/config/devices/entry//service"
	// xpath := "/config/devices/entry/vsys/entry/address"
	r := rested.NewRequest()

	if p.DeviceType == "panos" && p.Panorama == true {
		xpath = "/config/panorama//service"
	}

	if p.DeviceType == "panorama" {
		// xpath = "/config/devices/entry/device-group/entry/address"
		xpath = "/config/devices/entry//service"
	}

	query := map[string]string{
		"type":   "config",
		"action": "get",
		"xpath":  xpath,
		"key":    p.Key,
	}
	svcData := r.Send("get", p.URI, nil, headers, query)

	if err := xml.Unmarshal(svcData.Body, &svcs); err != nil {
		return nil, err
	}

	if svcs.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", svcs.Code, errorCodes[svcs.Code])
	}

	return &svcs, nil
}

// ServiceGroups returns information about all of the service groups.
func (p *PaloAlto) ServiceGroups() (*ServiceGroups, error) {
	var groups ServiceGroups
	xpath := "/config/devices/entry//service-group"
	// xpath := "/config/devices/entry/vsys/entry/address-group"
	r := rested.NewRequest()

	if p.DeviceType == "panos" && p.Panorama == true {
		xpath = "/config/panorama//service-group"
	}

	if p.DeviceType == "panorama" {
		// xpath = "/config/devices/entry/device-group/entry/address-group"
		xpath = "/config/devices/entry//service-group"
	}

	query := map[string]string{
		"type":   "config",
		"action": "get",
		"xpath":  xpath,
		"key":    p.Key,
	}
	groupData := r.Send("get", p.URI, nil, headers, query)

	if err := xml.Unmarshal(groupData.Body, &groups); err != nil {
		return nil, err
	}

	if groups.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", groups.Code, errorCodes[groups.Code])
	}

	return &groups, nil
}
