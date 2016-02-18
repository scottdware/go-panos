package panos

import (
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/scottdware/go-rested"
	"strings"
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

// Services returns information about all of the service objects. When run against a Panorama device,
// services from all device-groups are returned.
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

// ServiceGroups returns information about all of the service groups. When run against a Panorama device,
// service groups from all device-groups are returned.
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

// CreateService adds a new service object to the device. Port can be a single port #, range (1-65535), or comma separated (80, 8080, 443).
// If creating a service object on a Panorama device, then specify the given device-group name as the last parameter.
func (p *PaloAlto) CreateService(name, protocol, port, description string, devicegroup ...string) error {
	var xmlBody string
	var xpath string
	var reqError requestError
	r := rested.NewRequest()

	switch protocol {
	case "tcp":
		xmlBody = fmt.Sprintf("<protocol><tcp><port>%s</port></tcp></protocol>", strings.Replace(port, " ", "", -1))
	case "udp":
		xmlBody = fmt.Sprintf("<protocol><udp><port>%s</port></udp></protocol>", strings.Replace(port, " ", "", -1))
	}

	if description != "" {
		xmlBody += fmt.Sprintf("<description>%s</description>", description)
	}

	if p.DeviceType == "panorama" && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when connected to a Panorama device")
	}

	query := map[string]string{
		"type":    "config",
		"action":  "set",
		"xpath":   xpath,
		"element": xmlBody,
		"key":     p.Key,
	}

	resp := r.Send("post", p.URI, nil, nil, query)
	if resp.Error != nil {
		return resp.Error
	}

	if err := xml.Unmarshal(resp.Body, &reqError); err != nil {
		return err
	}

	if reqError.Status != "success" {
		return fmt.Errorf("error code %s: %s", reqError.Code, errorCodes[reqError.Code])
	}

	return nil
}

// DeleteService will remove a service object from the device. If deleting a service object on a
// Panorama device, then specify the given device-group name as the last parameter.
func (p *PaloAlto) DeleteService(name string, devicegroup ...string) error {
	var xpath string
	var reqError requestError
	r := rested.NewRequest()

	if p.DeviceType == "panos" && p.Panorama == false {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when connected to a Panorama device")
	}

	query := map[string]string{
		"type":   "config",
		"action": "delete",
		"xpath":  xpath,
		"key":    p.Key,
	}

	resp := r.Send("get", p.URI, nil, nil, query)
	if resp.Error != nil {
		return resp.Error
	}

	if err := xml.Unmarshal(resp.Body, &reqError); err != nil {
		return err
	}

	if reqError.Status != "success" {
		return fmt.Errorf("error code %s: %s", reqError.Code, errorCodes[reqError.Code])
	}

	return nil
}
