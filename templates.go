package panos

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

	"github.com/scottdware/go-rested"
)

// Templates lists all of the templates in Panorama.
type Templates struct {
	XMLName   xml.Name   `xml:"response"`
	Status    string     `xml:"status,attr"`
	Code      string     `xml:"code,attr"`
	Templates []Template `xml:"result>template>entry"`
}

// Template contains information about each individual template.
type Template struct {
	Name        string   `xml:"name,attr"`
	Description string   `xml:"description"`
	Devices     []Serial `xml:"devices>entry"`
}

// TemplateStacks lists all of the template stacks in Panorama.
type TemplateStacks struct {
	XMLName   xml.Name        `xml:"response"`
	Status    string          `xml:"status,attr"`
	Code      string          `xml:"code,attr"`
	Templates []TemplateStack `xml:"result>template-stack>entry"`
}

// TemplateStack contains information about each individual template stack.
type TemplateStack struct {
	Name        string   `xml:"name,attr"`
	Description string   `xml:"description"`
	Members     []string `xml:"templates>member"`
	Devices     []Serial `xml:"devices>entry"`
}

// Templates returns information about all of the templates in Panorama, and what devices they are
// applied to.
func (p *PaloAlto) Templates() (*Templates, error) {
	var temps Templates
	xpath := "/config/devices/entry//template"
	// xpath := "/config/devices/entry/vsys/entry/address"
	r := rested.NewRequest()

	if p.DeviceType != "panorama" {
		return nil, errors.New("templates can only be listed on a Panorama device")
	}

	query := map[string]string{
		"type":   "config",
		"action": "get",
		"xpath":  xpath,
		"key":    p.Key,
	}

	tData := r.Send("get", p.URI, nil, headers, query)

	if err := xml.Unmarshal(tData.Body, &temps); err != nil {
		return nil, err
	}

	if temps.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", temps.Code, errorCodes[temps.Code])
	}

	return &temps, nil
}

// TemplateStacks returns information about all of the template stacks in Panorama, and what templates, devices
// are assigned to them. This is ONLY available on Panorama version 7.0.0 and higher.
func (p *PaloAlto) TemplateStacks() (*TemplateStacks, error) {
	var temps TemplateStacks
	ver := splitSWVersion(p.SoftwareVersion)
	xpath := "/config/devices/entry//template-stack"
	// xpath := "/config/devices/entry/vsys/entry/address"
	r := rested.NewRequest()

	if p.DeviceType != "panorama" {
		return nil, errors.New("template stacks can only be listed on a Panorama device")
	}

	if ver[0] < 7 {
		return nil, errors.New("you must be running version 7.0.0 or higher to use template stacks")
	}

	query := map[string]string{
		"type":   "config",
		"action": "get",
		"xpath":  xpath,
		"key":    p.Key,
	}

	tData := r.Send("get", p.URI, nil, headers, query)

	if err := xml.Unmarshal(tData.Body, &temps); err != nil {
		return nil, err
	}

	if temps.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", temps.Code, errorCodes[temps.Code])
	}

	return &temps, nil
}

// CreateTemplate adds a new template to Panorama. If you wish to associate devices, then
// separate them with a comma, i.e.: "0101010101, 0202020202".
func (p *PaloAlto) CreateTemplate(name, description string, devices ...string) error {
	var reqError requestError
	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']", name)
	xmlBody := "<settings><default-vsys>vsys1</default-vsys></settings><config><devices><entry name=\"localhost.localdomain\"><vsys><entry name=\"vsys1\"/></vsys></entry></devices></config>"
	r := rested.NewRequest()

	if p.DeviceType != "panorama" {
		return errors.New("templates can only be created on a Panorama device")
	}

	if len(description) > 0 {
		xmlBody += fmt.Sprintf("<description>%s</description>", description)
	}

	if len(devices) > 0 {
		xmlBody += "<devices>"
		for _, d := range strings.Split(devices[0], ",") {
			xmlBody += fmt.Sprintf("<entry name=\"%s\"/>", strings.TrimSpace(d))
		}
		xmlBody += "</devices>"
	}

	query := map[string]string{
		"type":    "config",
		"action":  "set",
		"xpath":   xpath,
		"key":     p.Key,
		"element": xmlBody,
	}

	resp := r.Send("get", p.URI, nil, headers, query)
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

// CreateTemplateStack adds a new template stack to Panorama. Templates must be separated by a comma, i.e.: "user_template, object_template".
// If you wish to associate devices, then separate them with a comma, just like you would template names. This is ONLY available on Panorama version 7.0.0 and higher.
func (p *PaloAlto) CreateTemplateStack(name, description, templates string, devices ...string) error {
	var reqError requestError
	ver := splitSWVersion(p.SoftwareVersion)
	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/template-stack/entry[@name='%s']", name)
	xmlBody := "<templates>"
	for _, t := range strings.Split(templates, ",") {
		xmlBody += fmt.Sprintf("<member>%s</member>", strings.TrimSpace(t))
	}
	xmlBody += "</templates>"
	r := rested.NewRequest()

	if p.DeviceType != "panorama" {
		return errors.New("template stacks can only be created on a Panorama device")
	}

	if ver[0] < 7 {
		return errors.New("you must be running version 7.0.0 or higher to use template stacks")
	}

	if len(description) > 0 {
		xmlBody += fmt.Sprintf("<description>%s</description>", description)
	}

	if len(devices) > 0 {
		xmlBody += "<devices>"
		for _, d := range strings.Split(devices[0], ",") {
			xmlBody += fmt.Sprintf("<entry name=\"%s\"/>", strings.TrimSpace(d))
		}
		xmlBody += "</devices>"
	}

	query := map[string]string{
		"type":    "config",
		"action":  "set",
		"xpath":   xpath,
		"key":     p.Key,
		"element": xmlBody,
	}

	resp := r.Send("get", p.URI, nil, headers, query)
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

// AssignTemplate will assign devices to the given template. Devices must be serial numbers,
// and each serial must be separated by a comma, i.e.: "010101010101, 020202020202". If you wish to assign
// devices to a template stack, then specify "true" for the stack parameter. Template stacks are ONLY
// available on Panorama version 7.0.0 and higher.
func (p *PaloAlto) AssignTemplate(name, devices string, stack bool) error {
	var reqError requestError
	ver := splitSWVersion(p.SoftwareVersion)
	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']", name)
	xmlBody := "<devices>"
	for _, d := range strings.Split(devices, ",") {
		xmlBody += fmt.Sprintf("<entry name=\"%s\"/>", strings.TrimSpace(d))
	}
	xmlBody += "</devices>"
	r := rested.NewRequest()

	if stack {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/template-stack/entry[@name='%s']", name)
	}

	if p.DeviceType != "panorama" {
		return errors.New("templates can only be assigned on a Panorama device")
	}

	if ver[0] < 7 && stack {
		return errors.New("you must be running version 7.0.0 or higher to use template stacks")
	}

	query := map[string]string{
		"type":    "config",
		"action":  "set",
		"xpath":   xpath,
		"key":     p.Key,
		"element": xmlBody,
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

// DeleteTemplate removes the given template from Panorama. If you wish to delete
// a template stack, then specify "true" for the stack parameter. Template stacks are ONLY
// available on Panorama version 7.0.0 and higher.
func (p *PaloAlto) DeleteTemplate(name string, stack bool) error {
	var reqError requestError
	ver := splitSWVersion(p.SoftwareVersion)
	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='%s']", name)
	r := rested.NewRequest()

	if stack {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/template-stack/entry[@name='%s']", name)
	}

	if p.DeviceType != "panorama" {
		return errors.New("templates can only be deleted on a Panorama device")
	}

	if ver[0] < 7 && stack {
		return errors.New("you must be running version 7.0.0 or higher to use template stacks")
	}

	query := map[string]string{
		"type":   "config",
		"action": "delete",
		"xpath":  xpath,
		"key":    p.Key,
	}

	resp := r.Send("get", p.URI, nil, headers, query)
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
