package panos

import (
	"encoding/xml"
	"errors"
	"fmt"
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

// Services returns information about all of the service objects. You can (optionally) specify a device-group
// when ran against a Panorama device. If no device-group is specified, then all objects are returned, including
// shared objects if ran against a Panorama device.
func (p *PaloAlto) Services(devicegroup ...string) (*ServiceObjects, error) {
	var svcs ServiceObjects
	xpath := "/config//service"

	if p.DeviceType != "panorama" && len(devicegroup) > 0 {
		return nil, errors.New("you must be connected to a Panorama device when specifying a device-group")
	}

	if p.DeviceType == "panos" && p.Panorama == true {
		xpath = "/config//service"
	}

	if p.DeviceType == "panos" && p.Panorama == false {
		xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service"
	}

	if p.DeviceType == "panorama" && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service", devicegroup[0])
	}

	_, svcData, errs := r.Get(p.URI).Query(fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", xpath, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(svcData), &svcs); err != nil {
		return nil, err
	}

	if svcs.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", svcs.Code, errorCodes[svcs.Code])
	}

	return &svcs, nil
}

// ServiceGroups returns information about all of the service groups. You can (optionally) specify a device-group
// when ran against a Panorama device. If no device-group is specified, then all service groups are returned, including
// shared objects if ran against a Panorama device.
func (p *PaloAlto) ServiceGroups(devicegroup ...string) (*ServiceGroups, error) {
	var groups ServiceGroups
	// xpath := "/config/devices/entry//service-group"
	xpath := "/config//service-group"

	if p.DeviceType != "panorama" && len(devicegroup) > 0 {
		return nil, errors.New("you must be connected to a Panorama device when specifying a device-group")
	}

	if p.DeviceType == "panos" && p.Panorama == true {
		xpath = "/config//service-group"
	}

	if p.DeviceType == "panos" && p.Panorama == false {
		xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group"
	}

	if p.DeviceType == "panorama" && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service-group", devicegroup[0])
	}

	_, groupData, errs := r.Get(p.URI).Query(fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", xpath, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(groupData), &groups); err != nil {
		return nil, err
	}

	if groups.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", groups.Code, errorCodes[groups.Code])
	}

	return &groups, nil
}

// CreateService adds a new service object to the device. Port can be a single port #, range (1-65535), or comma separated (80, 8080, 443).
// If creating
// a shared service object on a Panorama device, then specify "true" for the shared parameter, as well as the device-group
// name as the last parameter. If not creating a shared object, then just specify "false."
func (p *PaloAlto) CreateService(name, protocol, port, description string, shared bool, devicegroup ...string) error {
	var xmlBody string
	var xpath string
	var reqError requestError

	switch protocol {
	case "tcp":
		xmlBody = fmt.Sprintf("<protocol><tcp><port>%s</port></tcp></protocol>", strings.Replace(port, " ", "", -1))
	case "udp":
		xmlBody = fmt.Sprintf("<protocol><udp><port>%s</port></udp></protocol>", strings.Replace(port, " ", "", -1))
	}

	if description != "" {
		xmlBody += fmt.Sprintf("<description>%s</description>", description)
	}

	if p.DeviceType == "panos" && shared == false {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service/entry[@name='%s']", name)
	}

	if p.DeviceType == "panos" && shared == true {
		return errors.New("you can only create a shared service object on a Panorama device")
	}

	if p.DeviceType == "panorama" && shared == true {
		xpath = fmt.Sprintf("/config/shared/service/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when creating service objects on a Panorama device")
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

// CreateServiceGroup will create a new service group on the device. You can specify members to add
// by using a []string variable (i.e. members := []string{"tcp-service1", "udp-service1"}). If creating
// a shared service group on a Panorama device, then specify "true" for the shared parameter, as well as the device-group
// name as the last parameter. If not creating a shared object, then just specify "false."
func (p *PaloAlto) CreateServiceGroup(name string, members []string, shared bool, devicegroup ...string) error {
	var xmlBody string
	var xpath string
	var reqError requestError

	if len(members) <= 0 {
		return errors.New("you cannot create a service group without any members")
	}

	xmlBody = "<members>"
	for _, member := range members {
		xmlBody += fmt.Sprintf("<member>%s</member>", strings.TrimSpace(member))
	}
	xmlBody += "</members>"

	if p.DeviceType == "panos" && shared == false {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group/entry[@name='%s']", name)
	}

	if p.DeviceType == "panos" && shared == true {
		return errors.New("you can only create a shared service group on a Panorama device")
	}

	if p.DeviceType == "panorama" && shared == true {
		xpath = fmt.Sprintf("/config/shared/service-group/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service-group/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when creating service groups on a Panorama device")
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

// DeleteService will remove a service object from the device. If deleting
// a shared service object on a Panorama device, then specify "true" for the shared parameter, as well as the device-group
// name as the last parameter. If not deleting a shared object, then just specify "false."
func (p *PaloAlto) DeleteService(name string, shared bool, devicegroup ...string) error {
	var xpath string
	var reqError requestError

	if p.DeviceType == "panos" && shared == false {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service/entry[@name='%s']", name)
	}

	if p.DeviceType == "panos" && shared == true {
		return errors.New("you can only delete a shared service object on a Panorama device")
	}

	if p.DeviceType == "panorama" && shared == true {
		xpath = fmt.Sprintf("/config/shared/service/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when deleting service objects on a Panorama device")
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

// DeleteServiceGroup will remove a service group from the device. If deleting
// a shared service group on a Panorama device, then specify "true" for the shared parameter, as well as the device-group
// name as the last parameter. If not deleting a shared object, then just specify "false."
func (p *PaloAlto) DeleteServiceGroup(name string, shared bool, devicegroup ...string) error {
	var xpath string
	var reqError requestError

	if p.DeviceType == "panos" && shared == false {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group/entry[@name='%s']", name)
	}

	if p.DeviceType == "panos" && shared == true {
		return errors.New("you can only delete a shared service group on a Panorama device")
	}

	if p.DeviceType == "panorama" && shared == true {
		xpath = fmt.Sprintf("/config/shared/service-group/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service-group/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when deleting service groups on a Panorama device")
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
