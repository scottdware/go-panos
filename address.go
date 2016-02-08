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
	XMLName xml.Name `xml:"response"`
	Groups  []Group  `xml:"result>address-group>entry"`
}

// Group contains information about each individual address group.
type Group struct {
	Name         string   `xml:"name,attr"`
	StaticMember []string `xml:"static>member,omitempty"`
}

// Addresses returns information about all of the address objects.
func (p *PaloAlto) Addresses() *AddressObjects {
	var addrs AddressObjects
	addrOpts := &rested.Request{
		Method: "get",
		Query: map[string]string{
			"type":   "config",
			"action": "get",
			"xpath":  "/config/devices/entry/device-group/entry/address",
			"key":    p.Key,
		},
	}
	addrData := rested.Send(p.URI, addrOpts)

	if err := xml.Unmarshal(addrData.Body, &addrs); err != nil {
		fmt.Println(err)
	}

	return &addrs
}

// AddressGroups returns information about all of the address groups.
func (p *PaloAlto) AddressGroups() *AddressGroups {
	var groups AddressGroups
	aGroupOpts := &rested.Request{
		Method: "get",
		Query: map[string]string{
			"type":   "config",
			"action": "get",
			"xpath":  "/config/devices/entry/device-group/entry/address-group",
			"key":    p.Key,
		},
	}
	groupData := rested.Send(p.URI, aGroupOpts)

	if err := xml.Unmarshal(groupData.Body, &groups); err != nil {
		fmt.Println(err)
	}

	return &groups
}
