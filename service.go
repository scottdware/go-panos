package panos

import (
	"encoding/xml"
	"fmt"
	"github.com/scottdware/go-rested"
)

// ServiceObjects contains a slice of all service objects.
type ServiceObjects struct {
	XMLName  xml.Name  `xml:"response"`
	Services []Service `xml:"result>service>entry"`
}

// Service contains information about each individual service object.
type Service struct {
	Name        string `xml:"name,attr"`
	TCPPort     string `xml:"protocol>tcp>port"`
	UDPPort     string `xml:"protocol>udp>port"`
	Description string `xml:"description,omitempty"`
}

// ServiceGroups contains a slice of all service groups.
type ServiceGroups struct {
	XMLName xml.Name       `xml:"response"`
	Groups  []ServiceGroup `xml:"result>service-group>entry"`
}

// ServiceGroup contains information about each individual service group.
type ServiceGroup struct {
	Name        string   `xml:"name,attr"`
	Description string   `xml:"description"`
	Members     []string `xml:"members>member,omitempty"`
}

// Services returns information about all of the address objects.
func (p *PaloAlto) Services() *ServiceObjects {
	var svcs ServiceObjects
	r := rested.NewRequest()

	// xpath := "/config/devices/entry/vsys/entry/address"
	xpath := "/config/devices/entry//service"

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
		fmt.Println(err)
	}

	return &svcs
}

// ServiceGroups returns information about all of the service groups.
func (p *PaloAlto) ServiceGroups() *ServiceGroups {
	var groups ServiceGroups
	r := rested.NewRequest()

	// xpath := "/config/devices/entry/vsys/entry/address-group"
	xpath := "/config/devices/entry//service-group"

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
		fmt.Println(err)
	}

	return &groups
}
