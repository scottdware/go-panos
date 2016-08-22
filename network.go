package panos

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
)

// CreateL3Interface adds a new layer-3 interface or sub-interface to the device. If adding a sub-interface,
// be sure to append the VLAN tag to the interface name like so: ethernet1/1.700. You must specify the subnet mask in
// CIDR notation when specifying the IP address, i.e.: 1.1.1.1/32.
func (p *PaloAlto) CreateL3Interface(ifname, ipaddress string, comment ...string) error {
	var xmlBody string
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot create interfaces on a Panorama device")
	}

	ifDetails := strings.Split(ifname, ".")
	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='%s']", ifDetails[0])

	if len(ifDetails[1]) > 0 {
		xmlBody = fmt.Sprintf("<layer3><units><entry name=\"%s.%s\"><ip><entry name=\"%s\"/></ip><tag>%s</tag>", ifDetails[0], ifDetails[1], ipaddress, ifDetails[1])
		if len(comment) > 0 {
			xmlBody += fmt.Sprintf("<comment>%s</comment></entry></units></layer3>", comment[0])
		} else {
			xmlBody += "</entry></units></layer3>"
		}
	} else {
		xmlBody = fmt.Sprintf("<layer3><ip><entry name=\"%s\"/></ip></layer3>", ipaddress)
		if len(comment) > 0 {
			xmlBody += fmt.Sprintf("<comment>%s</comment>", comment[0])
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

// DeleteL3Interface removes a layer-3 interface or sub-interface from the device.
func (p *PaloAlto) DeleteL3Interface(ifname string) error {
	var reqError requestError
	var xpath string

	if p.DeviceType == "panorama" {
		return errors.New("you cannot delete interfaces on a Panorama device")
	}

	ifDetails := strings.Split(ifname, ".")
	subIntName := fmt.Sprintf("%s.%s", ifDetails[0], ifDetails[1])

	if len(ifDetails[1]) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='%s']/layer3/units/entry[@name='%s']", ifDetails[0], subIntName)
	} else {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='%s']", ifDetails[0])
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

// DeleteZone will remove a zone from the device.
func (p *PaloAlto) DeleteZone(name string) error {
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot delete zones on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone/entry[@name='%s']", name)

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

// RemoveInterfaceFromZone removes an interface from the specified zone.
func (p *PaloAlto) RemoveInterfaceFromZone(name, zonetype, ifname string) error {
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot remove interfaces from zones on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone/entry[@name='%s']", name)

	switch zonetype {
	case "tap":
		xpath += fmt.Sprintf("/network/tap/member[text()='%s']", ifname)
	case "vwire":
		xpath += fmt.Sprintf("/network/virtual-wire/member[text()='%s']", ifname)
	case "layer2":
		xpath += fmt.Sprintf("/network/layer2/member[text()='%s']", ifname)
	case "layer3":
		xpath += fmt.Sprintf("/network/layer3/member[text()='%s']", ifname)
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

// DeleteVirtualRouter removes a virtual-router from the device.
func (p *PaloAlto) DeleteVirtualRouter(vr string) error {
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot delete a virtual-router on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='%s']", vr)

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

// AddInterfaceToVirtualRouter will add an interface or interfaces to the given virtual-router. Separate multiple
// interfaces using a comma, i.e.: "ethernet1/2, ethernet1/3"
func (p *PaloAlto) AddInterfaceToVirtualRouter(vr, ifname string) error {
	var xmlBody string
	var reqError requestError
	ints := strings.Split(ifname, ",")

	if p.DeviceType == "panorama" {
		return errors.New("you cannot add interfaces to virtual-routers on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='%s']", vr)
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

// RemoveInterfaceFromVirtualRouter removes a given interface from the specified virtual-router.
func (p *PaloAlto) RemoveInterfaceFromVirtualRouter(vr, ifname string) error {
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot remove interfaces from a virtual-router on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='%s']/interface/member[text()='%s']", vr, ifname)

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

// CreateStaticRoute adds a new static route to a given virtual-router. For the destination, you must
// include the mask, i.e. "192.168.0.0/24" or "0.0.0.0/0." For nexthop, you can also specify an interface
// instead of an IP address. You can optionally specify a metric for the route, and if you do not, the metric will be 10.
func (p *PaloAlto) CreateStaticRoute(vr, name, destination, nexthop string, metric ...int) error {
	var xmlBody string
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot create static routes on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='%s']", vr)
	xmlBody = fmt.Sprintf("<routing-table><ip><static-route><entry name=\"%s\">", name)

	if strings.Contains(nexthop, "ethernet") {
		xmlBody += fmt.Sprintf("<interface>%s</interface><destination>%s</destination>", nexthop, destination)
	} else {
		xmlBody += fmt.Sprintf("<nexthop><ip-address>%s</ip-address></nexthop><destination>%s</destination>", nexthop, destination)
	}

	if len(metric) > 0 {
		xmlBody += fmt.Sprintf("<metric>%d</metric>", metric[0])
	} else {
		xmlBody += "<metric>10</metric>"
	}

	xmlBody += "</entry></static-route></ip></routing-table>"

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

// DeleteStaticRoute will remove a static route from the device.
func (p *PaloAlto) DeleteStaticRoute(vr, name string) error {
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot delete static routes on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='%s']/routing-table/ip/static-route/entry[@name='%s']", vr, name)

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
