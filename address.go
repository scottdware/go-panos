package panos

import (
	"encoding/xml"
	"fmt"
	"github.com/scottdware/go-rested"
	"strings"
)

// AddressObjects contains a slice of all address objects.
type AddressObjects struct {
	XMLName   xml.Name  `xml:"response"`
	Status    string    `xml:"status,attr"`
	Code      string    `xml:"code,attr"`
	Addresses []Address `xml:"result>address>entry"`
}

// Address contains information about each individual address object.
type Address struct {
	Name        string `xml:"name,attr"`
	IPAddress   string `xml:"ip-netmask,omitempty"`
	IPRange     string `xml:"ip-range,omitempty"`
	FQDN        string `xml:"fqdn,omitempty"`
	Description string `xml:"description,omitempty"`
}

// AddressGroups contains a slice of all address groups.
type AddressGroups struct {
	Groups []AddressGroup
}

// AddressGroup contains information about each individual address group.
type AddressGroup struct {
	Name          string
	Type          string
	Members       []string
	DynamicFilter string
	Description   string
}

// xmlAddressGroups is used for parsing of all address groups.
type xmlAddressGroups struct {
	XMLName xml.Name          `xml:"response"`
	Status  string            `xml:"status,attr"`
	Code    string            `xml:"code,attr"`
	Groups  []xmlAddressGroup `xml:"result>address-group>entry"`
}

// xmlAddressGroup is used for parsing each individual address group.
type xmlAddressGroup struct {
	Name          string   `xml:"name,attr"`
	Members       []string `xml:"static>member,omitempty"`
	DynamicFilter string   `xml:"dynamic>filter,omitempty"`
	Description   string   `xml:"description,omitempty"`
}

// Addresses returns information about all of the address objects.
func (p *PaloAlto) Addresses() (*AddressObjects, error) {
	var addrs AddressObjects
	xpath := "/config/devices/entry//address"
	// xpath := "/config/devices/entry/vsys/entry/address"
	r := rested.NewRequest()

	if p.DeviceType == "panos" && p.Panorama == true {
		xpath = "/config/panorama//address"
	}

	if p.DeviceType == "panorama" {
		// xpath = "/config/devices/entry/device-group/entry/address"
		xpath = "/config/devices/entry//address"
	}

	query := map[string]string{
		"type":   "config",
		"action": "get",
		"xpath":  xpath,
		"key":    p.Key,
	}
	addrData := r.Send("get", p.URI, nil, headers, query)

	if err := xml.Unmarshal(addrData.Body, &addrs); err != nil {
		return nil, err
	}

	if addrs.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", addrs.Code, errorCodes[addrs.Code])
	}

	return &addrs, nil
}

// AddressGroups returns information about all of the address groups.
func (p *PaloAlto) AddressGroups() (*AddressGroups, error) {
	var parsedGroups xmlAddressGroups
	var groups AddressGroups
	xpath := "/config/devices/entry//address-group"
	// xpath := "/config/devices/entry/vsys/entry/address-group"
	r := rested.NewRequest()

	if p.DeviceType == "panos" && p.Panorama == true {
		xpath = "/config/panorama//address-group"
	}

	if p.DeviceType == "panorama" {
		// xpath = "/config/devices/entry/device-group/entry/address-group"
		xpath = "/config/devices/entry//address-group"
	}

	query := map[string]string{
		"type":   "config",
		"action": "get",
		"xpath":  xpath,
		"key":    p.Key,
	}
	groupData := r.Send("get", p.URI, nil, headers, query)

	if err := xml.Unmarshal(groupData.Body, &parsedGroups); err != nil {
		return nil, err
	}

	if parsedGroups.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", parsedGroups.Code, errorCodes[parsedGroups.Code])
	}

	for _, g := range parsedGroups.Groups {
		gname := g.Name
		gtype := "Static"
		gmembers := g.Members
		gfilter := strings.TrimSpace(g.DynamicFilter)
		gdesc := g.Description

		if g.DynamicFilter != "" {
			gtype = "Dynamic"
		}

		groups.Groups = append(groups.Groups, AddressGroup{Name: gname, Type: gtype, Members: gmembers, DynamicFilter: gfilter, Description: gdesc})
	}

	return &groups, nil
}

// CreateAddress will add a new address object to they system. addrtype should be one of: ip, range, or fqdn.
func (p *PaloAlto) CreateAddress(name, addrtype, address, description string) error {
	var xmlBody string
	var xpath string
	var reqError requestError
	r := rested.NewRequest()

	switch addrtype {
	case "ip":
		xmlBody = fmt.Sprintf("<ip-netmask>%s</ip-netmask>", address)
	case "range":
		xmlBody = fmt.Sprintf("<ip-range>%s</ip-range>", address)
	case "fqdn":
		xmlBody = fmt.Sprintf("<fqdn>%s</fqdn>", address)
	}

	if description != "" {
		xmlBody += fmt.Sprintf("<description>%s</description>", description)
	}

	if p.DeviceType == "panos" && p.Panorama == false {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='%s']", name)
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
		return fmt.Errorf("error code %s: %s (%s)", reqError.Code, errorCodes[reqError.Code], reqError.Message)
	}

	return nil
}
