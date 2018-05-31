package panos

import (
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
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
type Tunnels struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Tunnels []Tunnel `xml:"result>ipsec>entry"`
}

// Tunnel contains information for each individual tunnel.
type Tunnel struct {
	Name     string    `xml:"name,attr"`
	ProxyIDs []ProxyID `xml:"auto-key>proxy-id>entry"`
}

// ProxyID contains information for each individual proxy-id.
type ProxyID struct {
	Name   string `xml:"name,attr"`
	Local  string `xml:"local"`
	Remote string `xml:"remote"`
}

// Gateways contains information of all the IKE gateways configured on a device.
type Gateways struct {
	XMLName  xml.Name     `xml:"response"`
	Status   string       `xml:"status,attr"`
	Code     string       `xml:"code,attr"`
	Gateways []IKEGateway `xml:"result>gateway>entry"`
}

// IKEGateway contains information about each individual IKE gateway.
type IKEGateway struct {
	Name                string `xml:"name,attr"`
	PSK                 string `xml:"authentication>pre-shared-key>key"`
	Version             string `xml:"protocol>version"`
	V1DeadPeerDetection string `xml:"protocol>ikev1>dpd>enable"`
	V1ExchangeMode      string `xml:"protocol>ikev1>exchange-mode"`
	V2DeadPeerDetection string `xml:"protocol>ikev2>dpd>enable"`
	V2CookieValidation  string `xml:"protocol>ikev2>require-cookie"`
	LocalAddress        string `xml:"local-address>ip"`
	LocalInterface      string `xml:"local-address>interface"`
	PeerAddress         string `xml:"peer-address>ip"`
	PeerDynamicAddress  string `xml:"peer-address>dynamic"`
	LocalID             string `xml:"local-id>id"`
	LocalIDType         string `xml:"local-id>type"`
	PeerID              string `xml:"peer-id>id"`
	PeerIDType          string `xml:"peer-id>type"`
	NATTraversal        string `xml:"protocol-common>nat-traversal>enable"`
	Fragmentation       string `xml:"protocol-common>fragmentation>enable"`
	PassiveMode         string `xml:"protocol-common>passive-mode"`
}

// EncryptionProfiles contains information about all of the IKE and IPSec crypto profiles on a device.
type EncryptionProfiles struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	IKE     []IKEProfile
	IPSec   []IPSecProfile
}

// ikeCryptoProfiles contains information about each individual IKE crypto profile.
type ikeCryptoProfiles struct {
	XMLName  xml.Name     `xml:"response"`
	Status   string       `xml:"status,attr"`
	Code     string       `xml:"code,attr"`
	Profiles []IKEProfile `xml:"result>ike-crypto-profiles>entry"`
}

// ipsecCryptoProfiles contains information about each individual IPSec crypto profile.
type ipsecCryptoProfiles struct {
	XMLName  xml.Name       `xml:"response"`
	Status   string         `xml:"status,attr"`
	Code     string         `xml:"code,attr"`
	Profiles []IPSecProfile `xml:"result>ipsec-crypto-profiles>entry"`
}

// IKEProfile contains information about each individual IKE crypto profile.
type IKEProfile struct {
	Name            string   `xml:"name,attr"`
	Encryption      []string `xml:"encryption>member"`
	Authentication  []string `xml:"hash>member"`
	DHGroup         []string `xml:"dh-group>member"`
	LifetimeHours   int      `xml:"lifetime>hours"`
	LifetimeSeconds int64    `xml:"lifetime>seconds"`
	LifetimeDays    int      `xml:"lifetime>days"`
	LifetimeMinutes int64    `xml:"lifetime>minutes"`
}

// IPSecProfile contains information about each individual IPSec crypto profile.
type IPSecProfile struct {
	Name              string   `xml:"name,attr"`
	ESPEncryption     []string `xml:"esp>encryption>member"`
	ESPAuthentication []string `xml:"esp>authentication>member"`
	AHAuthentication  []string `xml:"ah>authentication>member"`
	DHGroup           string   `xml:"dh-group"`
	LifetimeHours     int      `xml:"lifetime>hours"`
	LifetimeSeconds   int64    `xml:"lifetime>seconds"`
	LifetimeDays      int      `xml:"lifetime>days"`
	LifetimeMinutes   int64    `xml:"lifetime>minutes"`
}

// IKEOptions ...
type IKEOptions struct {
	// PassiveMode decides whether or not to have the firewall only respond to IKE connections
	// and never initiate them.
	PassiveMode bool

	// NATTraversal enables UDP encapsulation to be used on IKE and UDP protocols, enabling them
	// to pass through intermediate NAT devices. Enable NAT Traversal if Network Address Translation (NAT)
	// is configured on a device between the IPSec VPN terminating points.
	NATTraversal bool

	// LocalIDType must be one of: ipaddr, fqdn, ufqdn or keyid
	LocalIDType string

	// LocalID specifies either the IP address, FQDN, email address, or binary format
	// ID string in HEX.
	LocalID string

	// PeerIDType must be one of: ipaddr, fqdn, ufqdn or keyid
	PeerIDType string

	// PeerID specifies either the IP address, FQDN, email address, or binary format
	// ID string in HEX.
	PeerID string

	// DPDRetry defines the delay before retrying. The value must be between 2 and 100.
	DPDRetry int

	// DPDInterval defines the interval between tries. The value must be between 2 and 100.
	DPDInterval int

	// RequireCookie enables Strict Cookie Validation on the IKE gateway.
	RequireCookie bool
}

// CreateLayer3Interface adds a new layer-3 interface or sub-interface to the device. If adding a sub-interface,
// be sure to append the VLAN tag to the interface name (e.g. ethernet1/1.700). You must also specify the subnet mask in
// CIDR notation when specifying the IP address.
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

// CreateInterface creates the given interface type specified in the `iftype`` parameter (e.g. tap, vwire, layer2, layer3, vlan,
// loopback or tunnel). If adding a sub-interface, be sure to append the VLAN tag to the interface name (e.g. ethernet1/1.700).
// The (optional) ipaddr parameter allows you to assign an IP address to a layer 3/vlan/loopback or tunnel interface, or an
// IP classifier to a virtual-wire sub-interface. You do not need to specify the ipaddr parameter on a tap or layer2 interface type.
// Note that you must specify the subnet mask in CIDR notation when including an IP address.
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
// type in the iftype parameter (e.g. tap, vwire, layer2, layer3, vlan, loopback or tunnel).
func (p *PaloAlto) DeleteInterface(iftype, ifname string) error {
	var reqError requestError
	var xpath string
	var ifDetails []string
	var subIntName string

	if p.DeviceType == "panorama" {
		return errors.New("you cannot delete interfaces on a Panorama device")
	}

	if strings.Contains(ifname, ".") {
		ifDetails = strings.Split(ifname, ".")
		subIntName = fmt.Sprintf("%s.%s", ifDetails[0], ifDetails[1])
	} else {
		ifDetails = []string{ifname}
	}

	xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='%s']", ifDetails[0])

	switch iftype {
	case "vwire":
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='%s']", ifDetails[0])

		if len(ifDetails) > 1 {
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='%s']/virtual-wire/units/entry[@name='%s']", ifDetails[0], subIntName)
		}
	case "layer2":
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='%s']", ifDetails[0])

		if len(ifDetails) > 1 {
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='%s']/layer2/units/entry[@name='%s']", ifDetails[0], subIntName)
		}
	case "layer3":
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='%s']", ifDetails[0])

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

// CreateZone will add a new zone to the device. Zonetype must be one of tap, vwire, layer2, layer3. If
// you wish to enable user-id on the zone, specify true for the userid parameter, false if not.
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

// AddInterfaceToZone adds an interface or interfaces to the given zone. Zonetype must be one of tap, vwire, layer2, layer3.
// Separate multiple interfaces using a comma (e.g. "ethernet1/2, ethernet1/3").
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
// interfaces using a comma (e.g. "ethernet1/2, ethernet1/3").
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
// include the mask (e.g. "192.168.0.0/24" or "0.0.0.0/0"). For nexthop, you can also specify an interface
// instead of an IP address. You can optionally specify a metric for the route (default metric is 10).
func (p *PaloAlto) CreateStaticRoute(vr, name, destination, nexthop string, metric ...int) error {
	var xmlBody string
	var reqError requestError
	re := regexp.MustCompile("ethernet|tunnel|ae|loopback|vlan")
	ints := re.FindAllString(nexthop, -1)

	if p.DeviceType == "panorama" {
		return errors.New("you cannot create static routes on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='%s']", vr)
	xmlBody = fmt.Sprintf("<routing-table><ip><static-route><entry name=\"%s\">", name)

	if len(ints) > 0 {
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

// AddInterfaceToVlan will add an interface or interfaces to the given vlan. Separate multiple
// interfaces using a comma (e.g. "ethernet1/2, ethernet1/3").
func (p *PaloAlto) AddInterfaceToVlan(vlan, ifname string) error {
	var xmlBody string
	var reqError requestError
	ints := strings.Split(ifname, ",")

	if p.DeviceType == "panorama" {
		return errors.New("you cannot add interfaces to a vlan on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/vlan/entry[@name='%s']", vlan)
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

// RemoveInterfaceFromVlan removes a given interface from the specified vlan.
func (p *PaloAlto) RemoveInterfaceFromVlan(vlan, ifname string) error {
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot remove interfaces from a vlan on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/vlan/entry[@name='%s']/interface/member[text()='%s']", vlan, ifname)

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

// DeleteVlan removes a vlan from the device.
func (p *PaloAlto) DeleteVlan(vlan string) error {
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot delete a vlan on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/vlan/entry[@name='%s']", vlan)

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

// CreateVwire creates a virtual-wire on the device. For the tagallowed parameter, enter integers (e.g. 10)
// or ranges (100-200) separated by commas (e.g. 1-10,15,20-30). Integer values can be between 0 and 4094.
func (p *PaloAlto) CreateVwire(name, interface1, interface2, tagallowed string) error {
	var xmlBody string
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot create vlans on a Panorama device")
	}

	xpath := "/config/devices/entry[@name='localhost.localdomain']/network/virtual-wire"
	xmlBody = fmt.Sprintf("<entry name=\"%s\"><interface1>%s</interface1><interface2>%s</interface2><tag-allowed>%s</tag-allowed></entry>", name, interface1, interface2, tagallowed)

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

// DeleteVwire removes a virtual-wire from the device.
func (p *PaloAlto) DeleteVwire(name string) error {
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot delete a vlan on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/virtual-wire/entry[@name='%s']", name)

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

// ARPTable will gather all of the ARP entires on the device. Without any parameters, it will return all ARP entries.
// You can specify an interface name for the option parameter if you choose to only view the ARP entries for that specific
// interface (e.g. "ethernet1/1.200" or "ethernet1/21"). Status codes are as follows:
//
// s - static, c - complete, e - expiring, i - incomplete.
func (p *PaloAlto) ARPTable(option ...string) (*ARPTable, error) {
	var arpTable ARPTable
	command := "<show><arp><entry name = 'all'/></arp></show>"

	if p.DeviceType == "panorama" {
		return nil, errors.New("you cannot view the ARP table on a Panorama device")
	}

	if len(option) > 0 {
		command = fmt.Sprintf("<show><arp><entry name = '%s'/></arp></show>", option[0])
	}

	_, resp, errs := r.Get(p.URI).Query(fmt.Sprintf("type=op&cmd=%s&key=%s", command, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	formatted := strings.Replace(resp, "  ", "", -1)
	if err := xml.Unmarshal([]byte(formatted), &arpTable); err != nil {
		return nil, err
	}

	return &arpTable, nil
}

// IPSecTunnels will return a list of all configured IPsec tunnels on the device.
func (p *PaloAlto) IPSecTunnels() (*Tunnels, error) {
	var tunnels Tunnels
	xpath := "/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec"

	if p.DeviceType != "panos" {
		return nil, errors.New("tunnels can only be listed from a local device")
	}

	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", xpath, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(resp), &tunnels); err != nil {
		return nil, err
	}

	if tunnels.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", tunnels.Code, errorCodes[tunnels.Code])
	}

	return &tunnels, nil
}

// IKEGateways will return a list of all configured IKE gateways on the device.
func (p *PaloAlto) IKEGateways() (*Gateways, error) {
	var gws Gateways
	xpath := "/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway"

	if p.DeviceType != "panos" {
		return nil, errors.New("IKE gateways can only be listed from a local device")
	}

	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", xpath, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(resp), &gws); err != nil {
		return nil, err
	}

	if gws.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", gws.Code, errorCodes[gws.Code])
	}

	return &gws, nil
}

// CryptoProfiles will return a list of all configured IKE and IPSec crypto profiles on the device.
func (p *PaloAlto) CryptoProfiles() (*EncryptionProfiles, error) {
	var ike ikeCryptoProfiles
	var ipsec ipsecCryptoProfiles
	var profiles EncryptionProfiles
	ikeXpath := "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles"
	ipsecXpath := "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles"

	if p.DeviceType != "panos" {
		return nil, errors.New("IKE crypto profiles can only be listed from a local device")
	}

	_, ikeData, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", ikeXpath, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(ikeData), &ike); err != nil {
		return nil, err
	}

	if ike.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", ike.Code, errorCodes[ike.Code])
	}

	_, ipsecData, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", ipsecXpath, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(ipsecData), &ipsec); err != nil {
		return nil, err
	}

	if ipsec.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", ipsec.Code, errorCodes[ipsec.Code])
	}

	profiles.IKE = ike.Profiles
	profiles.IPSec = ipsec.Profiles

	return &profiles, nil
}

// AddProxyID will add a new proxy-id to the given IPsec tunnel.
func (p *PaloAlto) AddProxyID(tunnel, name, localip, remoteip string) error {
	var xmlBody string
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot add a proxy-id on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec/entry[@name='%s']/auto-key/proxy-id/entry[@name='%s']", tunnel, name)
	xmlBody = fmt.Sprintf("<protocol><any/></protocol><local>%s</local><remote>%s</remote>", localip, remoteip)

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

// DeleteProxyID will remove a proxy-id from the given IPsec tunnel.
func (p *PaloAlto) DeleteProxyID(tunnel, name string) error {
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot delete a proxy-id on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec/entry[@name='%s']/auto-key/proxy-id/entry[@name='%s']", tunnel, name)

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

// CreateIKEProfile creates a new IKE crypto profile on the device. Please see the below
// options that each parameter must contain at least one of (you can have multiple).
//
// Encryption: des, 3des, aes-128-cbc, aes-192-cbc, aes-256-cbc
// Authentication: md5, sha1, sha256, sha384, sha512
// Diffe-Hellman Group: 1, 2, 5, 14, 19, 20
//
// For lifetime, you must specify the value, followed by seconds, minutes, hours, or days,
// all surrounded in quotes (e.g. "8 hours" or "86400 seconds").
func (p *PaloAlto) CreateIKEProfile(name, encryption, authentication, dhgroup string, lifetime string) error {
	var xmlBody string
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot create IKE profiles on a Panorama device")
	}

	lt := strings.Split(lifetime, " ")

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles/entry[@name='%s']", name)
	xmlBody = fmt.Sprintf("<lifetime><%s>%s</%s></lifetime>", lt[1], lt[0], lt[1])

	xmlBody += "<encryption>"
	for _, encr := range strings.Split(encryption, ", ") {
		xmlBody += fmt.Sprintf("<member>%s</member>", strings.TrimSpace(encr))
	}
	xmlBody += "</encryption>"

	xmlBody += "<hash>"
	for _, hash := range strings.Split(authentication, ", ") {
		xmlBody += fmt.Sprintf("<member>%s</member>", strings.TrimSpace(hash))
	}
	xmlBody += "</hash>"

	xmlBody += "<dh-group>"
	for _, dh := range strings.Split(dhgroup, ", ") {
		xmlBody += fmt.Sprintf("<member>group%s</member>", strings.TrimSpace(dh))
	}
	xmlBody += "</dh-group>"

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

// CreateIPSecProfile creates a new IPSec crypto profile on the device. Please see the below
// options that each parameter must contain at least one of (you can have multiple).
//
// Encryption: des, 3des, aes-128-cbc, aes-192-cbc, aes-256-cbc, aes-128-ccm, aes-192-gcm, aes-256-gcm
// Authentication: md5, sha1, sha256, sha384, sha512
// Diffe-Hellman Group: 1, 2, 5, 14, 19, 20
//
// For lifetime, you must specify the value, followed by seconds, minutes, hours, or days,
// all surrounded in quotes (e.g. "8 hours" or "86400 seconds").
func (p *PaloAlto) CreateIPSecProfile(name, encryption, authentication, lifetime string, dhgroup ...string) error {
	var xmlBody string
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot create IPSec profiles on a Panorama device")
	}

	lt := strings.Split(lifetime, " ")

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name='%s']", name)
	xmlBody = fmt.Sprintf("<lifetime><%s>%s</%s></lifetime>", lt[1], lt[0], lt[1])

	xmlBody += "<esp><encryption>"
	for _, encr := range strings.Split(encryption, ", ") {
		xmlBody += fmt.Sprintf("<member>%s</member>", strings.TrimSpace(encr))
	}
	xmlBody += "</encryption>"

	xmlBody += "<authentication>"
	for _, hash := range strings.Split(authentication, ", ") {
		xmlBody += fmt.Sprintf("<member>%s</member>", strings.TrimSpace(hash))
	}
	xmlBody += "</authentication></esp>"

	if len(dhgroup) > 0 {
		xmlBody += "<dh-group>"
		for _, dh := range strings.Split(dhgroup[0], ", ") {
			xmlBody += fmt.Sprintf("<member>group%s</member>", strings.TrimSpace(dh))
		}
		xmlBody += "</dh-group>"
	} else {
		xmlBody += "<dh-group>no-pfs</dh-group>"
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

// CreateIKEGateway creates a new IKE gateway on the device. For the IKE version parameter,
// you must specify one of the following: v1, v2, or v2-preferred. The local parameter specifies
// the local interface and IP address to use. If you do not need an IP address, just specify
// the interface name (e.g. "ethernet1/1"). If you do have an IP address assigned, then you must
// enclose the interface name and IP address within quotes, separated by a space in between
// (e.g. "ethernet1/1 10.1.1.1/24"). The peer must be an IP address or the word "dynamic." Mode
// must be one of 'auto', 'main', or 'aggressive.' Profile is the name of a pre-existing IKE
// crypto profile on the device. The options parameter is optional, and contains additional IKE
// parameters that you can set. Please see the documentation for the IKEOptions struct.
func (p *PaloAlto) CreateIKEGateway(name, version, local, peer, psk, mode, profile string, options ...*IKEOptions) error {
	var xmlBody string
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot create IKE gateways on a Panorama device")
	}

	localaddr := strings.Split(local, " ")

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway/entry[@name='%s']", name)
	xmlBody += fmt.Sprintf("<authentication><pre-shared-key><key>%s</key></pre-shared-key></authentication>", psk)
	xmlBody += fmt.Sprintf("<protocol><ikev1><ike-crypto-profile>%s</ike-crypto-profile><exchange-mode>%s</exchange-mode>", profile, mode)

	if len(options) > 0 {
		if options[0].DPDInterval > 0 && options[0].DPDRetry > 0 {
			xmlBody += fmt.Sprintf("<dpd><enable>yes</enable><interval>%d</interval><retry>%d</retry></dpd>", options[0].DPDInterval, options[0].DPDRetry)
		}
	}

	xmlBody += "</ikev1>"
	xmlBody += fmt.Sprintf("<ikev2><ike-crypto-profile>%s</ike-crypto-profile><dpd><enable>no</enable></dpd>", profile)

	if len(options) > 0 {
		if options[0].RequireCookie == true {
			xmlBody += "<require-cookie>yes</require-cookie>"
		}
	}

	xmlBody += fmt.Sprintf("</ikev2><version>ike%s</version></protocol>", version)

	switch len(localaddr) {
	case 1:
		xmlBody += fmt.Sprintf("<local-address><interface>%s</interface></local-address>", localaddr[0])
	case 2:
		xmlBody += fmt.Sprintf("<local-address><interface>%s</interface><ip>%s</ip></local-address>", localaddr[0], localaddr[1])
	}

	if peer == "dynamic" {
		xmlBody += "<peer-address><dynamic/></peer-address>"
	} else {
		xmlBody += fmt.Sprintf("<peer-address><ip>%s</ip></peer-address>", peer)
	}

	if len(options) > 0 {
		if len(options[0].LocalID) > 0 {
			xmlBody += fmt.Sprintf("<local-id><type>%s</type><id>%s</id></local-id>", options[0].LocalIDType, options[0].LocalID)
		}
	}

	if len(options) > 0 {
		if len(options[0].PeerID) > 0 {
			xmlBody += fmt.Sprintf("<peer-id><type>%s</type><id>%s</id></peer-id>", options[0].PeerIDType, options[0].PeerID)
		}
	}

	if len(options) > 0 {
		if options[0].NATTraversal == true {
			xmlBody += "<protocol-common><nat-traversal><enable>yes</enable></nat-traversal><fragmentation><enable>no</enable></fragmentation></protocol-common>"
		}
	}

	if len(options) > 0 {
		if options[0].PassiveMode == true {
			xmlBody += "<protocol-common><passive-mode>yes</passive-mode><fragmentation><enable>no</enable></fragmentation></protocol-common>"
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

// CreateIPSecTunnel creates a new IPSec tunnel on the device. The iface parameter must
// be the name of a tunnel interface (e.g. "tunnel.1"). The gateway and profile settings
// must contain the name of a pre-existing IKE gateway and IPSec crypto profile, respectively.
func (p *PaloAlto) CreateIPSecTunnel(name, iface, gateway, profile string) error {
	var xmlBody string
	var reqError requestError

	if p.DeviceType == "panorama" {
		return errors.New("you cannot create IPSec tunnels on a Panorama device")
	}

	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec/entry[@name='%s']", name)
	xmlBody = fmt.Sprintf("<auto-key><ike-gateway><entry name=\"%s\"/></ike-gateway><ipsec-crypto-profile>%s</ipsec-crypto-profile></auto-key>", gateway, profile)
	xmlBody += fmt.Sprintf("<tunnel-interface>%s</tunnel-interface>", iface)

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
