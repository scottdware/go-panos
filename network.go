package panos

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
)

// CreateL3Interface adds a new layer-3 interface to the device. You must specify the subnet mask in
// CIDR notation when specifying the IP address, i.e.: 1.1.1.1/32.
func (p *PaloAlto) CreateL3Interface(ifname, ipaddress string, comment ...string) error {
	var xmlBody string
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot create interfaces on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='%s']", ifname)
	xmlBody = fmt.Sprintf("<layer3><ip><entry name=\"%s\"/></ip></layer3>", ipaddress)

	if len(comment) > 0 {
		xmlBody += fmt.Sprintf("<comment>%s</comment>", comment[0])
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

// CreateZone will add a new zone to the device. zonetype must be one of: tap, vwire, layer2, layer3.
func (p *PaloAlto) CreateZone(name, zonetype string) error {
	var xmlBody string
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot create zones on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone/entry[@name='%s']", name)
	switch zonetype {
	case "tap":
		xmlBody = "<network><tap/></network>"
	case "vwire":
		xmlBody = "<network><virtual-wire/></network>"
	case "layer2":
		xmlBody = "<network><layer2/></network>"
	case "layer3":
		xmlBody = "<network><layer3/></network>"
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

// AddInterfaceToZone adds an interface or interfaces to the given zone. zonetype must be one of: tap, vwire, layer2, layer3.
// Separate multiple interfaces using a comma, i.e.: "ethernet1/2, ethernet1/3"
func (p *PaloAlto) AddInterfaceToZone(name, zonetype, ifname string) error {
	var xmlBody string
	var reqError requestError
	ints := strings.Split(ifname, ",")

	if p.DeviceType == "panorama" {
		return errors.New("you cannot add interfaces to zones on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone/entry[@name='%s']", name)
	switch zonetype {
	case "tap":
		xmlBody = "<network><tap>"
		for _, i := range ints {
			xmlBody += fmt.Sprintf("<member>%s</member>", strings.TrimSpace(i))
		}
		xmlBody += "</tap></network>"
	case "vwire":
		xmlBody = "<network><virtual-wire>"
		for _, i := range ints {
			xmlBody += fmt.Sprintf("<member>%s</member>", strings.TrimSpace(i))
		}
		xmlBody += "</virtual-wire></network>"
	case "layer2":
		xmlBody = "<network><layer2>"
		for _, i := range ints {
			xmlBody += fmt.Sprintf("<member>%s</member>", strings.TrimSpace(i))
		}
		xmlBody += "</layer2></network>"
	case "layer3":
		xmlBody = "<network><layer3>"
		for _, i := range ints {
			xmlBody += fmt.Sprintf("<member>%s</member>", strings.TrimSpace(i))
		}
		xmlBody += "</layer3></network>"
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

// CreateVirtualRouter will add a new virtual-router to the device.
func (p *PaloAlto) CreateVirtualRouter(name string) error {
	var xmlBody string
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot create virtual-routers on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='%s']", name)
	xmlBody = "<protocol><bgp><routing-options><graceful-restart><enable>yes</enable></graceful-restart><as-format>2-byte</as-format></routing-options><enable>no</enable></bgp></protocol>"

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

// AddInterfaceToVirtualRouter will add an interface or interfaces to the given virtual-router. Separate multiple
// interfaces using a comma, i.e.: "ethernet1/2, ethernet1/3"
func (p *PaloAlto) AddInterfaceToVirtualRouter(name, ifname string) error {
	var xmlBody string
	var reqError requestError
	ints := strings.Split(ifname, ",")

	if p.DeviceType == "panorama" {
		return errors.New("you cannot add interfaces to virtual-routers on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='%s']", name)
	xmlBody = "<interface>"
	for _, i := range ints {
		xmlBody += fmt.Sprintf("<member>%s</member>", strings.TrimSpace(i))
	}
	xmlBody += "</interface>"

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
