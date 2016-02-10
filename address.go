package panos

import (
	"encoding/xml"
	"fmt"
	"github.com/scottdware/go-rested"
)

// AddressObjects contains a slice of all address objects.
type AddressObjects struct {
	XMLName   xml.Name  `xml:"response"`
	Addresses []Address `xml:"result>address>entry"`
}

// Address contains information about each individual address object.
type Address struct {
	Name        string `xml:"name,attr"`
	IPAddress   string `xml:"ip-netmask,omitempty"`
	FQDN        string `xml:"fqdn,omitempty"`
	Description string `xml:"description,omitempty"`
}

// AddressGroups contains a slice of all address groups.
type AddressGroups struct {
	XMLName xml.Name       `xml:"response"`
	Groups  []AddressGroup `xml:"result>address-group>entry"`
}

// AddressGroup contains information about each individual address group.
type AddressGroup struct {
	Name         string   `xml:"name,attr"`
	StaticMember []string `xml:"static>member,omitempty"`
}

// Addresses returns information about all of the address objects.
func (p *PaloAlto) Addresses() *AddressObjects {
	var addrs AddressObjects
	r := rested.NewRequest()

	// xpath := "/config/devices/entry/vsys/entry/address"
	xpath := "/config/devices/entry//address"

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
		fmt.Println(err)
	}

	return &addrs
}

// AddressGroups returns information about all of the address groups.
func (p *PaloAlto) AddressGroups() *AddressGroups {
	var groups AddressGroups
	r := rested.NewRequest()

	// xpath := "/config/devices/entry/vsys/entry/address-group"
	xpath := "/config/devices/entry//address-group"

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

	if err := xml.Unmarshal(groupData.Body, &groups); err != nil {
		fmt.Println(err)
	}

	return &groups
}
