package panos

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

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

// Services returns information about all of the service objects. You can (optionally) specify a device-group
// when ran against a Panorama device. If no device-group is specified, then all objects are returned.
func (p *PaloAlto) Services(devicegroup ...string) (*ServiceObjects, error) {
	var svcs ServiceObjects
	xpath := "/config/devices/entry//service"
	r := rested.NewRequest()

	if p.DeviceType != "panorama" && len(devicegroup) > 0 {
		return nil, errors.New("you must be connected to a Panorama device when specifying a device-group")
	}

	if p.DeviceType == "panos" && p.Panorama == true {
		xpath = "/config/panorama//service"
	}

	if p.DeviceType == "panos" && p.Panorama == false {
		xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service"
	}

	if p.DeviceType == "panorama" && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service", devicegroup[0])
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

// ServiceGroups returns information about all of the service groups. You can (optionally) specify a device-group
// when ran against a Panorama device. If no device-group is specified, then all service groups are returned.
func (p *PaloAlto) ServiceGroups(devicegroup ...string) (*ServiceGroups, error) {
	var groups ServiceGroups
	xpath := "/config/devices/entry//service-group"
	r := rested.NewRequest()

	if p.DeviceType != "panorama" && len(devicegroup) > 0 {
		return nil, errors.New("you must be connected to a Panorama device when specifying a device-group")
	}

	if p.DeviceType == "panos" && p.Panorama == true {
		xpath = "/config/panorama//service-group"
	}

	if p.DeviceType == "panos" && p.Panorama == false {
		xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group"
	}

	if p.DeviceType == "panorama" && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service-group", devicegroup[0])
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

	if p.DeviceType == "panos" {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service/entry[@name='%s']", name)
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

// CreateSharedService adds a new shared service object to Panorama. Port can be a single port #, range (1-65535), or comma separated (80, 8080, 443).
func (p *PaloAlto) CreateSharedService(name, protocol, port, description string) error {
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

	if p.DeviceType == "panos" {
		return errors.New("you can only create shared objects when connected to a Panorama device")
	}

	if p.DeviceType == "panorama" {
		xpath = fmt.Sprintf("/config/shared/service/entry[@name='%s']", name)
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

// CreateServiceGroup will create a new service group on the device. You can specify multiple members
// by separating them with a comma, i.e. "tcp-ports, udp-ports". If creating a service group on
// a Panorama device, then specify the given device-group name as the last parameter.
func (p *PaloAlto) CreateServiceGroup(name, members string, devicegroup ...string) error {
	var xmlBody string
	var xpath string
	var reqError requestError
	r := rested.NewRequest()
	m := strings.Split(members, ",")

	if members == "" {
		return errors.New("you cannot create a service group without any members")
	}

	xmlBody = "<members>"
	for _, member := range m {
		xmlBody += fmt.Sprintf("<member>%s</member>", strings.TrimSpace(member))
	}
	xmlBody += "</members>"

	if p.DeviceType == "panos" {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service-group/entry[@name='%s']", devicegroup[0], name)
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

// CreateSharedServiceGroup will create a new shared service group on Panorama. You can specify multiple members
// by separating them with a comma, i.e. "tcp-ports, udp-ports".
func (p *PaloAlto) CreateSharedServiceGroup(name, members string) error {
	var xmlBody string
	var xpath string
	var reqError requestError
	r := rested.NewRequest()
	m := strings.Split(members, ",")

	if members == "" {
		return errors.New("you cannot create a service group without any members")
	}

	xmlBody = "<members>"
	for _, member := range m {
		xmlBody += fmt.Sprintf("<member>%s</member>", strings.TrimSpace(member))
	}
	xmlBody += "</members>"

	if p.DeviceType == "panos" {
		return errors.New("you can only create shared objects when connected to a Panorama device")
	}

	if p.DeviceType == "panorama" {
		xpath = fmt.Sprintf("/config/shared/service-group/entry[@name='%s']", name)
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

	if p.DeviceType == "panos" {
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

// DeleteSharedService will remove a shared service object from Panorama.
func (p *PaloAlto) DeleteSharedService(name string) error {
	var xpath string
	var reqError requestError
	r := rested.NewRequest()

	if p.DeviceType == "panos" {
		return errors.New("you can only create shared objects when connected to a Panorama device")
	}

	if p.DeviceType == "panorama" {
		xpath = fmt.Sprintf("/config/shared/service/entry[@name='%s']", name)
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

// DeleteServiceGroup will remove a service group from the device. If deleting a service group on a
// Panorama device, then specify the given device-group name as the last parameter.
func (p *PaloAlto) DeleteServiceGroup(name string, devicegroup ...string) error {
	var xpath string
	var reqError requestError
	r := rested.NewRequest()

	if p.DeviceType == "panos" {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service-group/entry[@name='%s']", devicegroup[0], name)
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

// DeleteSharedServiceGroup will remove a shared service group from Panorama.
func (p *PaloAlto) DeleteSharedServiceGroup(name string) error {
	var xpath string
	var reqError requestError
	r := rested.NewRequest()

	if p.DeviceType == "panos" {
		return errors.New("you can only create shared objects when connected to a Panorama device")
	}

	if p.DeviceType == "panorama" {
		xpath = fmt.Sprintf("/config/shared/service-group/entry[@name='%s']", name)
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
