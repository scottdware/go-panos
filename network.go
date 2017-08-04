package panos

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
)

// ARPTable contains information about all of the ARP entries on the device.
type ARPTable struct {
	XMLName        xml.Name   `xml:"response"`
	MaxEntries     int        `xml:"result>max"`
	TotalEntries   int        `xml:"result>total"`
	DefaultTimeout int        `xml:"result>timeout"`
	Entries        []ARPEntry `xml:"result>entries>entry"`
}

// ARPEntry contains information about each individual ARP entry.
type ARPEntry struct {
	Status     string `xml:"status"`
	IPAddress  string `xml:"ip"`
	MACAddress string `xml:"mac"`
	TTL        int    `xml:"ttl"`
	Interface  string `xml:"interface"`
	Port       string `xml:"port"`
}

// Tunnels contains information of all the IPsec tunnels configured on a device.
// type Tunnels struct {
// 	XMLName xml.Name `xml:"response"`
// 	Status  string   `xml:"status,attr"`
// 	Code    string   `xml:"code,attr"`
// 	Tunnels []Tunnel `xml:"result>ipsec>entry"`
// }

// Tunnel contains information for each individual tunnel.
// type Tunnel struct {
// 	Name     string    `xml:"name,attr"`
// 	ProxyIDs []ProxyID `xml:"auto-key>proxy-id>entry"`
// }

// ProxyID contains information for each individual proxy-id.
// type ProxyID struct {
// 	Name     string `xml:"name,attr"`
// 	LocalIP  string `xml:"local"`
// 	RemoteIP string `xml:"remote"`
// }

// CreateLayer3Interface adds a new layer-3 interface or sub-interface to the device. If adding a sub-interface,
// be sure to append the VLAN tag to the interface name like so: ethernet1/1.700. You must specify the subnet mask in
// CIDR notation when specifying the IP address, i.e.: 1.1.1.1/32.
func (p *PaloAlto) CreateLayer3Interface(ifname, ipaddress string, comment ...string) error {
	var xmlBody string
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot create interfaces on a Panorama device")
	}

	ifDetails := strings.Split(ifname, ".")
	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='%s']", ifDetails[0])

	if len(ifDetails) > 1 {
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

// CreateInterface creates the given interface type specified in the "iftype" parameter: tap, vwire, layer2, layer3, vlan,
// loopback or tunnel. If adding a sub-interface, be sure to append the VLAN tag to the interface name like so: ethernet1/1.700.
// The (optional)ipaddr parameter allows you to assign an IP address to a layer 3/vlan/loopback or tunnel interface, or an
// IP classifier to a virtual-wire sub-interface. You do not need to specify the ipaddr parameter on a "tap" or "layer2" interface type.
// Note that you must specify the subnet mask in CIDR notation when including an IP address, i.e.: 1.1.1.1/24.
func (p *PaloAlto) CreateInterface(iftype, ifname, comment string, ipaddr ...string) error {
	var xmlBody string
	var xpath string
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot create interfaces on a Panorama device")
	}

	ifDetails := strings.Split(ifname, ".")
	xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='%s']", ifDetails[0])

	switch iftype {
	case "tap":
		xmlBody = "<tap/>"
		if len(comment) > 0 {
			xmlBody += fmt.Sprintf("<comment>%s</comment>", comment)
		}
	case "vwire":
		xmlBody = "<virtual-wire><lldp><enable>no</enable></lldp></virtual-wire>"
		if len(comment) > 0 {
			xmlBody += fmt.Sprintf("<comment>%s</comment>", comment)
		}

		if len(ifDetails) > 1 {
			xmlBody = fmt.Sprintf("<virtual-wire><lldp><enable>no</enable></lldp><units><entry name=\"%s.%s\"><tag>%s</tag>", ifDetails[0], ifDetails[1], ifDetails[1])

			if len(ipaddr) > 0 {
				xmlBody = fmt.Sprintf("<virtual-wire><lldp><enable>no</enable></lldp><units><entry name=\"%s.%s\"><ip-classifier><member>%s</member></ip-classifier><tag>%s</tag>", ifDetails[0], ifDetails[1], ipaddr[0], ifDetails[1])
			}

			if len(comment) > 0 {
				xmlBody += fmt.Sprintf("<comment>%s</comment></entry></units></virtual-wire>", comment)
			} else {
				xmlBody += "</entry></units></virtual-wire>"
			}
		}
	case "layer2":
		xmlBody = "<layer2><lldp><enable>no</enable></lldp></layer2>"
		if len(comment) > 0 {
			xmlBody += fmt.Sprintf("<comment>%s</comment>", comment)
		}

		if len(ifDetails) > 1 {
			xmlBody = fmt.Sprintf("<layer2><lldp><enable>no</enable></lldp><units><entry name=\"%s.%s\"><tag>%s</tag>", ifDetails[0], ifDetails[1], ifDetails[1])

			if len(comment) > 0 {
				xmlBody += fmt.Sprintf("<comment>%s</comment></entry></units></virtual-wire>", comment)
			} else {
				xmlBody += "</entry></units></layer2>"
			}
		}
	case "layer3":
		xmlBody = "<layer3/>"

		if len(ipaddr) > 0 {
			xmlBody = fmt.Sprintf("<layer3><ip><entry name=\"%s\"/></ip></layer3>", ipaddr[0])
		}

		if len(comment) > 0 {
			xmlBody += fmt.Sprintf("<comment>%s</comment>", comment)
		}

		if len(ifDetails) > 1 {
			xmlBody = fmt.Sprintf("<layer3><units><entry name=\"%s.%s\"><tag>%s</tag>", ifDetails[0], ifDetails[1], ifDetails[1])

			if len(ipaddr) > 0 {
				xmlBody = fmt.Sprintf("<layer3><units><entry name=\"%s.%s\"><ip><entry name=\"%s\"/></ip><tag>%s</tag>", ifDetails[0], ifDetails[1], ipaddr[0], ifDetails[1])
			}

			if len(comment) > 0 {
				xmlBody += fmt.Sprintf("<comment>%s</comment></entry></units></layer3>", comment)
			} else {
				xmlBody += "</entry></units></layer3>"
			}
		}
	case "vlan":
		if len(ifDetails) == 1 {
			return errors.New("you must specify a numeric identifier (i.e. vlan.1) greater than 0 for the vlan interface")
		}

		xpath = "/config/devices/entry[@name='localhost.localdomain']/network/interface/vlan/units"

		if len(ifDetails) > 1 {
			xmlBody = fmt.Sprintf("<entry name=\"%s.%s\">", ifDetails[0], ifDetails[1])

			if len(ipaddr) > 0 {
				xmlBody = fmt.Sprintf("<entry name=\"%s.%s\"><ip><entry name=\"%s\"/></ip>", ifDetails[0], ifDetails[1], ipaddr[0])
			}

			if len(comment) > 0 {
				xmlBody += fmt.Sprintf("<comment>%s</comment></entry>", comment)
			} else {
				xmlBody += "</entry>"
			}
		}
	case "loopback":
		if len(ifDetails) == 1 {
			return errors.New("you must specify a numeric identifier (i.e. loopback.1) greater than 0 for the loopback interface")
		}

		xpath = "/config/devices/entry[@name='localhost.localdomain']/network/interface/loopback/units"

		if len(ifDetails) > 1 {
			xmlBody = fmt.Sprintf("<entry name=\"%s.%s\">", ifDetails[0], ifDetails[1])

			if len(ipaddr) > 0 {
				ip := strings.Split(ipaddr[0], "/")

				if ip[1] != "32" {
					return errors.New("you can only specify a /32 subnet mask for a loopback interface")
				}

				xmlBody = fmt.Sprintf("<entry name=\"%s.%s\"><ip><entry name=\"%s\"/></ip>", ifDetails[0], ifDetails[1], ipaddr[0])
			}

			if len(comment) > 0 {
				xmlBody += fmt.Sprintf("<comment>%s</comment></entry>", comment)
			} else {
				xmlBody += "</entry>"
			}
		}
	case "tunnel":
		if len(ifDetails) == 1 {
			return errors.New("you must specify a numeric identifier (i.e. tunnel.1) greater than 0 for the tunnel interface")
		}

		xpath = "/config/devices/entry[@name='localhost.localdomain']/network/interface/tunnel/units"

		if len(ifDetails) > 1 {
			xmlBody = fmt.Sprintf("<entry name=\"%s.%s\">", ifDetails[0], ifDetails[1])

			if len(ipaddr) > 0 {
				xmlBody = fmt.Sprintf("<entry name=\"%s.%s\"><ip><entry name=\"%s\"/></ip>", ifDetails[0], ifDetails[1], ipaddr[0])
			}

			if len(comment) > 0 {
				xmlBody += fmt.Sprintf("<comment>%s</comment></entry>", comment)
			} else {
				xmlBody += "</entry>"
			}
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

// DeleteInterface removes an interface or sub-interface from the device. You must specify the interface
// type in the "iftype" parameter: tap, vwire, layer2, layer3, vlan, loopback or tunnel.
func (p *PaloAlto) DeleteInterface(iftype, ifname string) error {
	var reqError requestError
	var xpath string

	if p.DeviceType == "panorama" {
		return errors.New("you cannot delete interfaces on a Panorama device")
	}

	ifDetails := strings.Split(ifname, ".")
	subIntName := fmt.Sprintf("%s.%s", ifDetails[0], ifDetails[1])

	xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='%s']", ifDetails[0])

	switch iftype {
	case "vwire":
		if len(ifDetails) > 1 {
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='%s']/virtual-wire/units/entry[@name='%s']", ifDetails[0], subIntName)
		}
	case "layer2":
		if len(ifDetails) > 1 {
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='%s']/layer2/units/entry[@name='%s']", ifDetails[0], subIntName)
		}
	case "layer3":
		if len(ifDetails) > 1 {
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='%s']/layer3/units/entry[@name='%s']", ifDetails[0], subIntName)
		}
	case "vlan":
		if len(ifDetails) > 1 {
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/vlan/units/entry[@name='%s']", subIntName)
		}
	case "loopback":
		if len(ifDetails) > 1 {
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/loopback/units/entry[@name='%s']", subIntName)
		}
	case "tunnel":
		if len(ifDetails) > 1 {
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/tunnel/units/entry[@name='%s']", subIntName)
		}
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

// CreateZone will add a new zone to the device. zonetype must be one of: tap, vwire, layer2, layer3. If
// you wish to enable user-id on the zone, specify "true" for the userid parameter, "false" if not.
func (p *PaloAlto) CreateZone(name, zonetype string, userid bool) error {
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

	if userid == true {
		xmlBody += "<enable-user-identification>yes</enable-user-identification>"
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

// CreateVlan will add a new layer 2 vlan to the device. Optionally, if you wish to assign a vlan interface to the vlan,
// specify the interface name as the last parameter. Otherwise, only specify the name of the vlan when creating it.
func (p *PaloAlto) CreateVlan(name string, vlaninterface ...string) error {
	var xmlBody string
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot create vlans on a Panorama device")
	}

	xpath := "/config/devices/entry[@name='localhost.localdomain']/network/vlan"
	xmlBody = fmt.Sprintf("<entry name=\"%s\"/>", name)

	if len(vlaninterface) > 0 {
		xmlBody = fmt.Sprintf("<entry name=\"%s\"><virtual-interface><interface>%s</interface></virtual-interface></entry>", name, vlaninterface[0])
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

// ListTunnels will return a list of all configured IPsec tunnels on the device.
// func (p *PaloAlto) ListTunnels() (*Tunnels, error) {
// 	var tunnels Tunnels
// 	xpath := "/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec"
//
// 	if p.DeviceType != "panos" {
// 		return nil, errors.New("tunnels can only be listed from a local device")
// 	}
//
// 	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", xpath, p.Key)).End()
// 	if errs != nil {
// 		return nil, errs[0]
// 	}
//
// 	if err := xml.Unmarshal([]byte(resp), &tunnels); err != nil {
// 		return nil, err
// 	}
//
// 	if tunnels.Status != "success" {
// 		return nil, fmt.Errorf("error code %s: %s", tunnels.Code, errorCodes[tunnels.Code])
// 	}
//
// 	return &tunnels, nil
// }

// AddProxyID will add a new proxy-id to the given IPsec tunnel.
// func (p *PaloAlto) AddProxyID(tunnel, name, localip, remoteip string) error {
// 	var xmlBody string
// 	var reqError requestError
//
// 	if p.DeviceType == "panorama" {
// 		return errors.New("you cannot add a proxy-id on a Panorama device")
// 	}
//
// 	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec/entry[@name='%s']/auto-key/proxy-id/entry[@name='%s']", tunnel, name)
// 	xmlBody = fmt.Sprintf("<protocol><any/></protocol><local>%s</local><remote>%s</remote>", localip, remoteip)
//
// 	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=set&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
// 	if errs != nil {
// 		return errs[0]
// 	}
//
// 	if err := xml.Unmarshal([]byte(resp), &reqError); err != nil {
// 		return err
// 	}
//
// 	if reqError.Status != "success" {
// 		return fmt.Errorf("error code %s: %s", reqError.Code, errorCodes[reqError.Code])
// 	}
//
// 	return nil
// }

// DeleteProxyID will remove a proxy-id from the given IPsec tunnel.
// func (p *PaloAlto) DeleteProxyID(tunnel, name string) error {
// 	var reqError requestError
//
// 	if p.DeviceType == "panorama" {
// 		return errors.New("you cannot delete a proxy-id on a Panorama device")
// 	}
//
// 	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec/entry[@name='%s']/auto-key/proxy-id/entry[@name='%s']", tunnel, name)
//
// 	_, resp, errs := r.Get(p.URI).Query(fmt.Sprintf("type=config&action=delete&xpath=%s&key=%s", xpath, p.Key)).End()
// 	if errs != nil {
// 		return errs[0]
// 	}
//
// 	if err := xml.Unmarshal([]byte(resp), &reqError); err != nil {
// 		return err
// 	}
//
// 	if reqError.Status != "success" {
// 		return fmt.Errorf("error code %s: %s", reqError.Code, errorCodes[reqError.Code])
// 	}
//
// 	return nil
// }
