package panos

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Devices lists all of the devices in Panorama.
type Devices struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Devices []Serial `xml:"result>devices>entry"`
}

// DeviceGroups lists all of the device-group's in Panorama.
type DeviceGroups struct {
	XMLName xml.Name      `xml:"response"`
	Status  string        `xml:"status,attr"`
	Code    string        `xml:"code,attr"`
	Groups  []DeviceGroup `xml:"result>device-group>entry"`
}

// DeviceGroup contains information about each individual device-group.
type DeviceGroup struct {
	Name    string   `xml:"name,attr"`
	Devices []Serial `xml:"devices>entry"`
}

// Serial contains the serial number of each device in the device-group.
type Serial struct {
	Serial string `xml:"name,attr"`
}

// SetShared will set Panorama's device-group to shared for all subsequent configuration changes. For example, if you set this
// to "true" and then create address or service objects, they will all be shared objects. Set this back to "false" to return to normal mode.
func (p *PaloAlto) SetShared(shared bool) {
	if p.DeviceType == "panos" {
		panic(errors.New("you can only set the shared option on a Panorama device"))
	}

	p.Shared = shared
}

// Devices returns information about all of the devices that are managed by Panorama.
func (p *PaloAlto) Devices() (*Devices, error) {
	var devices Devices
	xpath := "/config/mgt-config/devices"

	if p.DeviceType != "panorama" {
		return nil, errors.New("devices can only be listed from a Panorama device")
	}

	_, devData, errs := r.Get(p.URI).Query(fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", xpath, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(devData), &devices); err != nil {
		return nil, err
	}

	if devices.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", devices.Code, errorCodes[devices.Code])
	}

	return &devices, nil
}

// DeviceGroups returns information about all of the device-groups in Panorama, and what devices are
// linked to them.
func (p *PaloAlto) DeviceGroups() (*DeviceGroups, error) {
	var devices DeviceGroups
	xpath := "/config/devices/entry//device-group"

	if p.DeviceType != "panorama" {
		return nil, errors.New("device-groups can only be listed from a Panorama device")
	}

	_, devData, errs := r.Get(p.URI).Query(fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", xpath, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(devData), &devices); err != nil {
		return nil, err
	}

	if devices.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", devices.Code, errorCodes[devices.Code])
	}

	return &devices, nil
}

// CreateDeviceGroup will create a new device-group on a Panorama device. You can add devices as well by
// specifying the serial numbers in a string slice ([]string). Specify "nil" if you do not wish to add any.
func (p *PaloAlto) CreateDeviceGroup(name, description string, devices []string) error {
	var xmlBody string
	var xpath string
	var reqError requestError

	if p.DeviceType == "panos" || p.DeviceType != "panorama" {
		return errors.New("you must be connected to a Panorama device when creating a device-group")
	}

	if p.DeviceType == "panorama" {
		xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group"
		xmlBody = fmt.Sprintf("<entry name=\"%s\">", name)
	}

	if devices != nil {
		xmlBody += "<devices>"
		for _, s := range devices {
			xmlBody += fmt.Sprintf("<entry name=\"%s\"/>", strings.TrimSpace(s))
		}
		xmlBody += "</devices>"
	}

	if description != "" {
		xmlBody += fmt.Sprintf("<description>%s</description>", description)
	}

	xmlBody += "</entry>"

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

// DeleteDeviceGroup will delete the given device-group from Panorama.
func (p *PaloAlto) DeleteDeviceGroup(name string) error {
	var xpath string
	var reqError requestError

	if p.DeviceType == "panos" || p.DeviceType != "panorama" {
		return errors.New("you must be connected to a Panorama device when deleting a device-group")
	}

	if p.DeviceType == "panorama" {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']", name)
	}

	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=delete&xpath=%s&key=%s", xpath, p.Key)).End()
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

// AddDevice will add a new device to a Panorama. If you specify the optional devicegroup parameter,
// it will also add the device to the given device-group.
func (p *PaloAlto) AddDevice(serial string, devicegroup ...string) error {
	var reqError requestError

	if p.DeviceType == "panos" || p.DeviceType != "panorama" {
		return errors.New("you must be connected to Panorama when adding devices")
	}

	if p.DeviceType == "panorama" && len(devicegroup) <= 0 {
		xpath := "/config/mgt-config/devices"
		xmlBody := fmt.Sprintf("<entry name=\"%s\"/>", serial)

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
	}

	if p.DeviceType == "panorama" && len(devicegroup) > 0 {
		deviceXpath := "/config/mgt-config/devices"
		deviceXMLBody := fmt.Sprintf("<entry name=\"%s\"/>", serial)
		xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']", devicegroup[0])
		xmlBody := fmt.Sprintf("<devices><entry name=\"%s\"/></devices>", serial)

		_, addResp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=set&xpath=%s&element=%s&key=%s", deviceXpath, deviceXMLBody, p.Key)).End()
		if errs != nil {
			return errs[0]
		}

		if err := xml.Unmarshal([]byte(addResp), &reqError); err != nil {
			return err
		}

		if reqError.Status != "success" {
			return fmt.Errorf("error code %s: %s", reqError.Code, errorCodes[reqError.Code])
		}

		time.Sleep(200 * time.Millisecond)

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
	}

	return nil
}

// SetPanoramaServer will configure a device to be managed by the given Panorama server's primary IP address.
// You can optionally add a second Panorama server by specifying an IP address for the "secondary" parameter.
func (p *PaloAlto) SetPanoramaServer(primary string, secondary ...string) error {
	var reqError requestError
	xpath := "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system"
	xmlBody := fmt.Sprintf("<panorama-server>%s</panorama-server>", primary)

	if len(secondary) > 0 {
		xmlBody = fmt.Sprintf("<panorama-server>%s</panorama-server><panorama-server-2>%s</panorama-server-2>", primary, secondary[0])
	}

	if p.DeviceType == "panorama" && p.Panorama == true {
		return errors.New("you must be connected to a non-Panorama device in order to configure a Panorama server")
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

// RemoveDevice will remove a device from Panorama. If you specify the optional devicegroup parameter,
// it will only remove the device from the given device-group.
func (p *PaloAlto) RemoveDevice(serial string, devicegroup ...string) error {
	var xpath string
	var reqError requestError

	if p.DeviceType == "panos" || p.DeviceType != "panorama" {
		return errors.New("you must be connected to Panorama when removing devices")
	}

	if p.DeviceType == "panorama" && len(devicegroup) <= 0 {
		xpath = fmt.Sprintf("/config/mgt-config/devices/entry[@name='%s']", serial)
	}

	if p.DeviceType == "panorama" && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/devices/entry[@name='%s']", devicegroup[0], serial)
	}

	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=delete&xpath=%s&key=%s", xpath, p.Key)).End()
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
