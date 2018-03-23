package panos

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/scottdware/go-easycsv"
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

// Addresses returns information about all of the address objects. You can (optionally) specify a device-group
// when ran against a Panorama device. If no device-group is specified, then all objects are returned, including
// shared objects if run against a Panorama device.
func (p *PaloAlto) Addresses(devicegroup ...string) (*AddressObjects, error) {
	var addrs AddressObjects
	xpath := "/config//address"

	if p.DeviceType != "panorama" && len(devicegroup) > 0 {
		return nil, errors.New("you must be connected to a Panorama device when specifying a device-group")
	}

	if p.DeviceType == "panos" && p.Panorama == true {
		xpath = "/config//address"
	}

	if p.DeviceType == "panos" && p.Panorama == false {
		xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address"
	}

	if p.DeviceType == "panorama" && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address", devicegroup[0])
	}

	_, addrData, errs := r.Get(p.URI).Query(fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", xpath, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(addrData), &addrs); err != nil {
		return nil, err
	}

	if addrs.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", addrs.Code, errorCodes[addrs.Code])
	}

	return &addrs, nil
}

// AddressGroups returns information about all of the address groups. You can (optionally) specify a device-group
// when ran against a Panorama device. If no device-group is specified, then all address groups are returned, including
// shared objects if run against a Panorama device.
func (p *PaloAlto) AddressGroups(devicegroup ...string) (*AddressGroups, error) {
	var parsedGroups xmlAddressGroups
	var groups AddressGroups
	xpath := "/config//address-group"

	if p.DeviceType != "panorama" && len(devicegroup) > 0 {
		return nil, errors.New("you must be connected to a Panorama device when specifying a device-group")
	}

	if p.DeviceType == "panos" && p.Panorama == true {
		xpath = "/config//address-group"
	}

	if p.DeviceType == "panos" && p.Panorama == false {
		xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group"
	}

	if p.DeviceType == "panorama" && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address-group", devicegroup[0])
	}

	_, groupData, errs := r.Get(p.URI).Query(fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", xpath, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(groupData), &parsedGroups); err != nil {
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

// CreateAddress will add a new address object to the device. Addrtype should be one of: ip, range, or fqdn. If creating an address
// object on a Panorama device, specify the device-group as the last parameter.
func (p *PaloAlto) CreateAddress(name, addrtype, address, description string, devicegroup ...string) error {
	var xmlBody string
	var xpath string
	var reqError requestError

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

	if p.DeviceType == "panos" {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" {
		if p.Shared == true {
			xpath = fmt.Sprintf("/config/shared/address/entry[@name='%s']", name)
		}

		if len(devicegroup) > 0 && devicegroup[0] == "shared" {
			xpath = fmt.Sprintf("/config/shared/address/entry[@name='%s']", name)
		}

		if p.Shared == false && len(devicegroup) > 0 && devicegroup[0] != "shared" {
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address/entry[@name='%s']", devicegroup[0], name)
		}

		if p.Shared == false && len(devicegroup) <= 0 {
			return errors.New("you must specify a device-group when creating address objects on a Panorama device")
		}
	}

	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=set&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
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

// CreateAddressGroup will create a new static or dynamic address group on the device, as specified by the grouptype
// parameter. If you are creating a static address group, you must add pre-existing members to the group by specifying them using a
// []string type, for the members parameter. You can specify this as a variable like so:
//
// hosts := []string{"web-server", "db-server", "mail-server"}
//
// When creating a dynamic address group, the match criteria (tags) must be a string type, specified for the members parameter like so:
//
// match := "'web-servers' and 'dmz-servers'"
//
// If you do not want to include a description, just leave the parameter blank using double-quotes (""). If creating an address group on
// a Panorama device, specify the device-group as the last parameter.
func (p *PaloAlto) CreateAddressGroup(name, grouptype string, members interface{}, description string, devicegroup ...string) error {
	var xmlBody string
	var xpath string
	var reqError requestError

	switch grouptype {
	case "static":
		staticMembers := members.([]string)
		if len(staticMembers) <= 0 {
			return errors.New("you cannot create a static address group without any members")
		}

		xmlBody = "<static>"
		for _, member := range staticMembers {
			xmlBody += fmt.Sprintf("<member>%s</member>", strings.TrimSpace(member))
		}
		xmlBody += "</static>"
	case "dynamic":
		criteria := members.(string)
		xmlBody = fmt.Sprintf("<dynamic><filter>%s</filter></dynamic>", criteria)
	}

	if description != "" {
		xmlBody += fmt.Sprintf("<description>%s</description>", description)
	}

	if p.DeviceType == "panos" {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" {
		if p.Shared == true {
			xpath = fmt.Sprintf("/config/shared/address-group/entry[@name='%s']", name)
		}

		if len(devicegroup) > 0 && devicegroup[0] == "shared" {
			xpath = fmt.Sprintf("/config/shared/address-group/entry[@name='%s']", name)
		}

		if p.Shared == false && len(devicegroup) > 0 && devicegroup[0] != "shared" {
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address-group/entry[@name='%s']", devicegroup[0], name)
		}

		if p.Shared == false && len(devicegroup) <= 0 {
			return errors.New("you must specify a device-group when creating address groups on a Panorama device")
		}
	}

	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=set&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
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

// DeleteAddress will remove an address object from the device. If deleting an address object on a
// Panorama device, specify the device-group as the last parameter.
func (p *PaloAlto) DeleteAddress(name string, devicegroup ...string) error {
	var xpath string
	var reqError requestError

	if p.DeviceType == "panos" {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && p.Shared == true {
		xpath = fmt.Sprintf("/config/shared/address/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when deleting address objects on a Panorama device")
	}

	_, resp, errs := r.Get(p.URI).Query(fmt.Sprintf("type=config&action=delete&xpath=%s&key=%s", xpath, p.Key)).End()
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

// DeleteAddressGroup will remove an address group from the device. If deleting an address group on a
// Panorama device, specify the device-group as the last parameter.
func (p *PaloAlto) DeleteAddressGroup(name string, devicegroup ...string) error {
	var xpath string
	var reqError requestError

	if p.DeviceType == "panos" {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && p.Shared == true {
		xpath = fmt.Sprintf("/config/shared/address-group/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address-group/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when deleting address groups on a Panorama device")
	}

	_, resp, errs := r.Get(p.URI).Query(fmt.Sprintf("type=config&action=delete&xpath=%s&key=%s", xpath, p.Key)).End()
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

// CreateObjectsFromCsv takes a CSV file and creates the given address objects and address groups defined within.
// The format of the CSV file must follow this layout:
//
// name, type, address, description (optional), tag (optional), device-group
//
// For the type column, you can specify: ip, range, fqdn for address objects. For group objects, you must specify
// either static or dynamic. The description and tag columns are optional, so just leave them blank if you do not
// need them.
//
// If you are creating an address group, then the address field must contain the following:
//
// For a static address group: list of members to add separated by a space, i.e.: ip-host1 ip-net1 fqdn-example.com
// For a dynamic address group: the criteria (tags) to match on, i.e.: web-servers or db-servers and linux
//
// If any of the objects you are creating need to be shared objects, then specify the word "shared" in the device-group (last)
// column.
func (p *PaloAlto) CreateObjectsFromCsv(file string) error {
	c, err := easycsv.Open(file)
	if err != nil {
		return err
	}

	for _, line := range c {
		var tagged bool
		var description, tag, dg string
		linelen := len(line)
		name := line[0]
		addrtype := line[1]
		address := line[2]

		if linelen > 3 && len(line[3]) > 0 {
			description = line[3]
		}

		if linelen > 4 && len(line[4]) > 0 {
			tag = line[4]
			tagged = true
		}

		if linelen > 5 && len(line[5]) > 0 {
			dg = line[5]
		}

		switch addrtype {
		case "ip", "range", "fqdn":
			if len(description) > 0 && len(dg) > 0 {
				err = p.CreateAddress(name, addrtype, address, description, dg)
				if err != nil {
					return err
				}
			}

			if len(description) == 0 && len(dg) == 0 {
				err = p.CreateAddress(name, addrtype, address, "")
				if err != nil {
					return err
				}
			}

			if len(description) > 0 && len(dg) == 0 {
				err = p.CreateAddress(name, addrtype, address, description)
				if err != nil {
					return err
				}
			}

			if len(description) == 0 && len(dg) > 0 {
				err = p.CreateAddress(name, addrtype, address, "", dg)
				if err != nil {
					return err
				}
			}
		case "static":
			groupMembers := strings.Split(address, " ")

			if len(description) > 0 && len(dg) > 0 {
				err = p.CreateAddressGroup(name, "static", groupMembers, description, dg)
				if err != nil {
					return err
				}
			}

			if len(description) == 0 && len(dg) == 0 {
				err = p.CreateAddressGroup(name, "static", groupMembers, "")
				if err != nil {
					return err
				}
			}

			if len(description) > 0 && len(dg) == 0 {
				err = p.CreateAddressGroup(name, "static", groupMembers, description)
				if err != nil {
					return err
				}
			}

			if len(description) == 0 && len(dg) > 0 {
				err = p.CreateAddressGroup(name, "static", groupMembers, "", dg)
				if err != nil {
					return err
				}
			}
		case "dynamic":
			criteria := fmt.Sprintf("%s", address)

			if len(description) > 0 && len(dg) > 0 {
				err = p.CreateAddressGroup(name, "dynamic", criteria, description, dg)
				if err != nil {
					return err
				}
			}

			if len(description) == 0 && len(dg) == 0 {
				err = p.CreateAddressGroup(name, "dynamic", criteria, "")
				if err != nil {
					return err
				}
			}

			if len(description) > 0 && len(dg) == 0 {
				err = p.CreateAddressGroup(name, "dynamic", criteria, description)
				if err != nil {
					return err
				}
			}

			if len(description) == 0 && len(dg) > 0 {
				err = p.CreateAddressGroup(name, "dynamic", criteria, "", dg)
				if err != nil {
					return err
				}
			}
		}

		time.Sleep(10 * time.Millisecond)

		if tagged && dg != "" {
			err = p.TagObject(tag, name, dg)
			if err != nil {
				return err
			}
		}

		if tagged && dg == "" {
			err = p.TagObject(tag, name)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
