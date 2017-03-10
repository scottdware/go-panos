package panos

import (
	"encoding/csv"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
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

// CreateAddress will add a new address object to the device. addrtype should be one of: ip, range, or fqdn. If creating
// a shared address object on a Panorama device, then specify "true" for the shared parameter, and omit the device-group.
// If not creating a shared object, then just specify "false."
func (p *PaloAlto) CreateAddress(name, addrtype, address, description string, shared bool, devicegroup ...string) error {
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

	if p.DeviceType == "panos" && shared == false {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='%s']", name)
	}

	if p.DeviceType == "panos" && shared == true {
		return errors.New("you can only create a shared address object on a Panorama device")
	}

	if p.DeviceType == "panorama" && shared == true {
		xpath = fmt.Sprintf("/config/shared/address/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when creating address objects on a Panorama device")
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

// CreateAddressGroup will create a new static address group on the device. You can specify members to add
// by using a []string variable (i.e. members := []string{"server1", "server2"}). If creating
// a shared address group on a Panorama device, then specify "true" for the shared parameter, and omit the device-group.
// If not creating a shared object, then just specify "false."
func (p *PaloAlto) CreateAddressGroup(name string, members []string, description string, shared bool, devicegroup ...string) error {
	var xmlBody string
	var xpath string
	var reqError requestError

	if len(members) <= 0 {
		return errors.New("you cannot create a static address group without any members")
	}

	xmlBody = "<static>"
	for _, member := range members {
		xmlBody += fmt.Sprintf("<member>%s</member>", strings.TrimSpace(member))
	}
	xmlBody += "</static>"

	if description != "" {
		xmlBody += fmt.Sprintf("<description>%s</description>", description)
	}

	if p.DeviceType == "panos" && shared == false {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='%s']", name)
	}

	if p.DeviceType == "panos" && shared == true {
		return errors.New("you can only create a shared address group on a Panorama device")
	}

	if p.DeviceType == "panorama" && shared == true {
		xpath = fmt.Sprintf("/config/shared/address-group/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address-group/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when creating address groups on a Panorama device")
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

// CreateDynamicAddressGroup will create a new dynamic address group on the device. The filter must be written like so:
// 'vm-servers' and 'some tag' or 'pcs' - using the tags as the match criteria. If creating
// a shared address group on a Panorama device, then specify "true" for the shared parameter, and omit the device-group.
// If not creating a shared object, then just specify "false."
func (p *PaloAlto) CreateDynamicAddressGroup(name, criteria, description string, shared bool, devicegroup ...string) error {
	xmlBody := fmt.Sprintf("<dynamic><filter>%s</filter></dynamic>", criteria)
	var xpath string
	var reqError requestError

	if criteria == "" {
		return errors.New("you cannot create a dynamic address group without any filter")
	}

	if description != "" {
		xmlBody += fmt.Sprintf("<description>%s</description>", description)
	}

	if p.DeviceType == "panos" && shared == false {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='%s']", name)
	}

	if p.DeviceType == "panos" && shared == true {
		return errors.New("you can only create a shared address group on a Panorama device")
	}

	if p.DeviceType == "panorama" && shared == true {
		xpath = fmt.Sprintf("/config/shared/address-group/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address-group/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when creating address groups on a Panorama device")
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

// DeleteAddress will remove an address object from the device. If deleting
// a shared address object on a Panorama device, then specify "true" for the shared parameter, and omit the device-group.
// If not deleting a shared object, then just specify "false."
func (p *PaloAlto) DeleteAddress(name string, shared bool, devicegroup ...string) error {
	var xpath string
	var reqError requestError

	if p.DeviceType == "panos" && shared == false {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='%s']", name)
	}

	if p.DeviceType == "panos" && shared == true {
		return errors.New("you can only delete a shared address object on a Panorama device")
	}

	if p.DeviceType == "panorama" && shared == true {
		xpath = fmt.Sprintf("/config/shared/address/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
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

// DeleteAddressGroup will remove an address group from the device. If deleting
// a shared address group on a Panorama device, then specify "true" for the shared parameter, and omit the device-group.
// If not deleting a shared object, then just specify "false."
func (p *PaloAlto) DeleteAddressGroup(name string, shared bool, devicegroup ...string) error {
	var xpath string
	var reqError requestError

	if p.DeviceType == "panos" && shared == false {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='%s']", name)
	}

	if p.DeviceType == "panos" && shared == true {
		return errors.New("you can only delete a shared address group on a Panorama device")
	}

	if p.DeviceType == "panorama" && shared == true {
		xpath = fmt.Sprintf("/config/shared/address-group/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address-group/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
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

// CreateAddressFromCsv takes a .csv file with the following format: name,type,address,description,address-group.
// 'name' is what you want the address object to be called. 'type' is one of: ip, range, or fqdn.
// 'address' is the address of the object. 'description' is optional, just leave the field blank if you do not want one.
// 'address-group' will assign the object to the given address-group if you wish (leave blank if you do not want to add it to a group).
// If creating shared address objects on a Panorama device, then specify "true" for the shared parameter, and omit the device-group.
// If not creating a shared object, then just specify "false."
func (p *PaloAlto) CreateAddressFromCsv(file string, shared bool, devicegroup ...string) error {
	fn, err := os.Open(file)
	if err != nil {
		return err
	}

	defer fn.Close()

	reader := csv.NewReader(fn)
	fields, err := reader.ReadAll()
	if err != nil {
		fmt.Println(err)
	}

	for _, line := range fields {
		var addrgroup string
		linelen := len(line)
		name := line[0]
		addrtype := line[1]
		ip := line[2]
		description := ""

		if linelen == 4 && len(line[3]) > 0 {
			description = line[3]
		}

		if linelen == 5 && len(line[4]) > 0 {
			addrgroup = line[4]
		}

		if shared {
			err = p.CreateAddress(name, addrtype, ip, description, true)
			if err != nil {
				return err
			}

			time.Sleep(10 * time.Millisecond)

			if len(addrgroup) > 0 {
				err = p.EditGroup("address", "add", name, addrgroup, true)
				if err != nil {
					return err
				}
			}
		}

		if !shared && len(devicegroup) > 0 {
			err = p.CreateAddress(name, addrtype, ip, description, false, devicegroup[0])
			if err != nil {
				return err
			}

			time.Sleep(10 * time.Millisecond)

			if len(addrgroup) > 0 {
				err = p.EditGroup("address", "add", name, addrgroup, false, devicegroup[0])
				if err != nil {
					return err
				}
			}
		}

		if !shared {
			err = p.CreateAddress(name, addrtype, ip, description, false)
			if err != nil {
				return err
			}

			time.Sleep(10 * time.Millisecond)

			if len(addrgroup) > 0 {
				err = p.EditGroup("address", "add", name, addrgroup, false)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}
