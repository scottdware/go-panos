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
func (p *PaloAlto) Addresses() *AddressObjects {
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
		fmt.Println(err)
	}

	return &addrs
}

// AddressGroups returns information about all of the address groups.
func (p *PaloAlto) AddressGroups() *AddressGroups {
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
		fmt.Println(err)
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

	return &groups
}
