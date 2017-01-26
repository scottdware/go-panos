// Package panos interacts with Palo Alto and Panorama devices using the XML API.
package panos

import (
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/parnurzeal/gorequest"
)

// PaloAlto is a container for our session state.
type PaloAlto struct {
	Host            string
	Key             string
	URI             string
	Platform        string
	Model           string
	Serial          string
	SoftwareVersion string
	DeviceType      string
	Panorama        bool
}

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

// Tags contains information about all tags on the system.
type Tags struct {
	Tags []Tag
}

// Tag contains information about each individual tag.
type Tag struct {
	Name     string
	Color    string
	Comments string
}

// Policy lists all of the security rules for a given device-group.
type Policy struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Rules   []Rule   `xml:"result>rules>entry"`
}

// Rule contains information about each individual security rule.
type Rule struct {
	Name                 string   `xml:"name,attr"`
	From                 string   `xml:"from>member"`
	To                   string   `xml:"to>member"`
	Source               []string `xml:"source>member"`
	Destination          []string `xml:"destination>member"`
	SourceUser           []string `xml:"source-user>member"`
	Application          []string `xml:"application>member"`
	Service              []string `xml:"service>member"`
	Action               string   `xml:"action"`
	LogStart             string   `xml:"log-start"`
	LogEnd               string   `xml:"log-end"`
	Tag                  []string `xml:"tag>member"`
	LogSetting           string   `xml:"log-setting"`
	AntiVirusProfile     string   `xml:"profile-setting>profiles>virus>member"`
	AntiSpywareProfile   string   `xml:"profile-setting>profiles>spyware>member"`
	VulnerabilityProfile string   `xml:"profile-setting>profiles>vulnerability>member"`
	WildfireProfile      string   `xml:"profile-setting>profiles>wildfire-analysis>member"`
	SecurityProfileGroup string   `xml:"profile-setting>group>member"`
}

// SecurityProfiles contains a list of security profiles to apply to a rule. If you have a security group
// then you can just specify that and omit the individual ones.
type SecurityProfiles struct {
	AntiVirus     string
	AntiSpyware   string
	Vulnerability string
	Wildfire      string
	Group         string
}

// xmlTags is used for parsing all tags on the system.
type xmlTags struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Tags    []xmlTag `xml:"result>tag>entry"`
}

// xmlTag is used for parsing each individual tag.
type xmlTag struct {
	Name     string `xml:"name,attr"`
	Color    string `xml:"color,omitempty"`
	Comments string `xml:"comments,omitempty"`
}

// authKey holds our API key.
type authKey struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Key     string   `xml:"result>key"`
}

// systemInfo holds basic system information.
type systemInfo struct {
	XMLName         xml.Name `xml:"response"`
	Status          string   `xml:"status,attr"`
	Code            string   `xml:"code,attr"`
	Platform        string   `xml:"result>system>platform-family"`
	Model           string   `xml:"result>system>model"`
	Serial          string   `xml:"result>system>serial"`
	SoftwareVersion string   `xml:"result>system>sw-version"`
}

// panoramaStatus gets the connection status to Panorama.
type panoramaStatus struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Data    string   `xml:"result"`
}

// requestError contains information about any error we get from a request.
type requestError struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Message string   `xml:"result>msg,omitempty"`
}

// testURL contains the results of the operational command test url.
type testURL struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Result  string   `xml:"result"`
}

// testRoute contains the results of the operational command test routing fib-lookup.
type testRoute struct {
	XMLName   xml.Name `xml:"response"`
	Status    string   `xml:"status,attr"`
	Code      string   `xml:"code,attr"`
	NextHop   string   `xml:"result>nh"`
	Source    string   `xml:"result>src"`
	IP        string   `xml:"result>ip"`
	Metric    int      `xml:"result>metric"`
	Interface string   `xml:"result>interface"`
}

var (
	r = gorequest.New().TLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	tagColors = map[string]string{
		"Red":         "color1",
		"Green":       "color2",
		"Blue":        "color3",
		"Yellow":      "color4",
		"Copper":      "color5",
		"Orange":      "color6",
		"Purple":      "color7",
		"Gray":        "color8",
		"Light Green": "color9",
		"Cyan":        "color10",
		"Light Gray":  "color11",
		"Blue Gray":   "color12",
		"Lime":        "color13",
		"Black":       "color14",
		"Gold":        "color15",
		"Brown":       "color16",
	}

	errorCodes = map[string]string{
		"400": "Bad request - Returned when a required parameter is missing, an illegal parameter value is used",
		"403": "Forbidden - Returned for authentication or authorization errors including invalid key, insufficient admin access rights",
		"1":   "Unknown command - The specific config or operational command is not recognized",
		"2":   "Internal error - Check with technical support when seeing these errors",
		"3":   "Internal error - Check with technical support when seeing these errors",
		"4":   "Internal error - Check with technical support when seeing these errors",
		"5":   "Internal error - Check with technical support when seeing these errors",
		"6":   "Bad Xpath - The xpath specified in one or more attributes of the command is invalid. Check the API browser for proper xpath values",
		"7":   "Object not present - Object specified by the xpath is not present. For example, entry[@name=’value’] where no object with name ‘value’ is present",
		"8":   "Object not unique - For commands that operate on a single object, the specified object is not unique",
		"9":   "Internal error - Check with technical support when seeing these errors",
		"10":  "Reference count not zero - Object cannot be deleted as there are other objects that refer to it. For example, address object still in use in policy",
		"11":  "Internal error - Check with technical support when seeing these errors",
		"12":  "Invalid object - Xpath or element values provided are not complete",
		"13":  "Operation failed - A descriptive error message is returned in the response",
		"14":  "Operation not possible - Operation is not possible. For example, moving a rule up one position when it is already at the top",
		"15":  "Operation denied - For example, Admin not allowed to delete own account, Running a command that is not allowed on a passive device",
		"16":  "Unauthorized - The API role does not have access rights to run this query",
		"17":  "Invalid command - Invalid command or parameters",
		"18":  "Malformed command - The XML is malformed",
		"19":  "Success - Command completed successfully",
		"20":  "Success - Command completed successfully",
		"21":  "Internal error - Check with technical support when seeing these errors",
		"22":  "Session timed out - The session for this query timed out",
	}
)

// splitSWVersion
func splitSWVersion(version string) []int {
	re := regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
	match := re.FindStringSubmatch(version)
	maj, _ := strconv.Atoi(match[1])
	min, _ := strconv.Atoi(match[2])
	rel, _ := strconv.Atoi(match[3])

	return []int{maj, min, rel}
}

// NewSession sets up our connection to the Palo Alto firewall or Panorama device.
func NewSession(host, user, passwd string) (*PaloAlto, error) {
	var key authKey
	var info systemInfo
	var pan panoramaStatus
	status := false
	deviceType := "panos"

	_, body, errs := r.Get(fmt.Sprintf("https://%s/api/?type=keygen&user=%s&password=%s", host, user, passwd)).End()
	if errs != nil {
		return nil, errs[0]
	}

	err := xml.Unmarshal([]byte(body), &key)
	if err != nil {
		return nil, err
	}

	if key.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s (keygen)", key.Code, errorCodes[key.Code])
	}

	uri := fmt.Sprintf("https://%s/api/?", host)
	_, getInfo, errs := r.Get(fmt.Sprintf("%s&key=%s&type=op&cmd=<show><system><info></info></system></show>", uri, key.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	err = xml.Unmarshal([]byte(getInfo), &info)
	if err != nil {
		return nil, err
	}

	if info.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s (show system info)", info.Code, errorCodes[info.Code])
	}

	_, panStatus, errs := r.Get(fmt.Sprintf("%s&key=%s&type=op&cmd=<show><panorama-status></panorama-status></show>", uri, key.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	err = xml.Unmarshal([]byte(panStatus), &pan)
	if err != nil {
		return nil, err
	}

	if info.Platform == "m" {
		deviceType = "panorama"
	}

	if strings.Contains(pan.Data, ": yes") {
		status = true
	}

	return &PaloAlto{
		Host:            host,
		Key:             key.Key,
		URI:             fmt.Sprintf("https://%s/api/?", host),
		Platform:        info.Platform,
		Model:           info.Model,
		Serial:          info.Serial,
		SoftwareVersion: info.SoftwareVersion,
		DeviceType:      deviceType,
		Panorama:        status,
	}, nil
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
// specifying the serial numbers in a string slice ([]string). Use 'nil' if you do not wish to add any.
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

// AddDevice will add a new device to a Panorama. If you specify the optional 'devicegroup' parameter,
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

// SetPanoramaServer will configure a device to be managed by the given Panorama server's IP address.
func (p *PaloAlto) SetPanoramaServer(ip string) error {
	var reqError requestError
	xpath := "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system"
	xmlBody := fmt.Sprintf("<panorama-server>%s</panorama-server>", ip)

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

// RemoveDevice will remove a device from Panorama. If you specify the optional 'devicegroup' parameter,
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

// Tags returns information about all tags on the system.
func (p *PaloAlto) Tags() (*Tags, error) {
	var parsedTags xmlTags
	var tags Tags
	var tcolor string
	xpath := "/config//tag"

	if p.DeviceType == "panos" && p.Panorama == true {
		xpath = "/config//tag"
	}

	if p.DeviceType == "panorama" {
		xpath = "/config//tag"
	}

	_, tData, errs := r.Get(p.URI).Query(fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", xpath, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(tData), &parsedTags); err != nil {
		return nil, err
	}

	if parsedTags.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", parsedTags.Code, errorCodes[parsedTags.Code])
	}

	for _, t := range parsedTags.Tags {
		tname := t.Name
		for k, v := range tagColors {
			if t.Color == v {
				tcolor = k
			}
		}
		tcomments := t.Comments

		tags.Tags = append(tags.Tags, Tag{Name: tname, Color: tcolor, Comments: tcomments})
	}

	return &tags, nil

}

// CreateTag will add a new tag to the device. You can use the following colors: Red, Green, Blue, Yellow, Copper,
// Orange, Purple, Gray, Light Green, Cyan, Light Gray, Blue Gray, Lime, Black, Gold, Brown. If creating
// a shared tag on a Panorama device, then specify "true" for the shared parameter, as well as the device-group
// name as the last parameter. If not creating a shared object, then just specify "false."
func (p *PaloAlto) CreateTag(name, color, comments string, shared bool, devicegroup ...string) error {
	var xmlBody string
	var xpath string
	var reqError requestError

	xmlBody = fmt.Sprintf("<color>%s</color>", tagColors[color])

	if comments != "" {
		xmlBody += fmt.Sprintf("<comments>%s</comments>", comments)
	}

	if p.DeviceType == "panos" && shared == false {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/tag/entry[@name='%s']", name)
	}

	if p.DeviceType == "panos" && shared == true {
		return errors.New("you can only create a shared tag on a Panorama device")
	}

	if p.DeviceType == "panorama" && shared == true {
		xpath = fmt.Sprintf("/config/shared/tag/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/tag/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when creating a tag to a Panorama device")
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

// DeleteTag will remove a tag from the device. If deleting
// a shared tag on a Panorama device, then specify "true" for the shared parameter, as well as the device-group
// name as the last parameter. If not creating a shared object, then just specify "false."
func (p *PaloAlto) DeleteTag(name string, shared bool, devicegroup ...string) error {
	var xpath string
	var reqError requestError

	if p.DeviceType == "panos" && shared == false {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/tag/entry[@name='%s']", name)
	}

	if p.DeviceType == "panos" && shared == true {
		return errors.New("you can only delete a tag on a Panorama device")
	}

	if p.DeviceType == "panorama" && shared == true {
		xpath = fmt.Sprintf("/config/shared/tag/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/tag/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when deleting a tag on a Panorama device")
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

// ApplyTag will apply the given tag to the specified address or service object(s). You can specify multiple tags
// by separating them with a comma, i.e. "servers, vm". If you have address/service objects with the same
// name, then the tag(s) will be applied to all that match. When tagging
// a shared object on a Panorama device, then specify "true" for the shared parameter, as well as the device-group
// name as the last parameter. If not creating a shared object, then just specify "false."
func (p *PaloAlto) ApplyTag(tag, object string, shared bool, devicegroup ...string) error {
	var xpath string
	var reqError requestError
	tags := strings.Split(tag, ",")
	adObj, _ := p.Addresses()
	agObj, _ := p.AddressGroups()
	sObj, _ := p.Services()
	sgObj, _ := p.ServiceGroups()

	xmlBody := "<tag>"
	for _, t := range tags {
		xmlBody += fmt.Sprintf("<member>%s</member>", strings.TrimSpace(t))
	}
	xmlBody += "</tag>"

	for _, a := range adObj.Addresses {
		if object == a.Name {
			if p.DeviceType == "panos" && shared == false {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='%s']/tag", object)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=edit&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
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

			if p.DeviceType == "panos" && shared == true {
				return errors.New("you can only apply a tag to a shared object on a Panorama device")
			}

			if p.DeviceType == "panorama" && shared == true {
				xpath = fmt.Sprintf("/config/shared/address/entry[@name='%s']/tag", object)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=edit&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) >= 0 {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address/entry[@name='%s']/tag", devicegroup[0], object)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=edit&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when tagging objects on a Panorama device")
			}
		}
	}

	for _, ag := range agObj.Groups {
		if object == ag.Name {
			if p.DeviceType == "panos" && shared == false {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='%s']/tag", object)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=edit&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
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

			if p.DeviceType == "panos" && shared == true {
				return errors.New("you can only apply a tag to a shared object on a Panorama device")
			}

			if p.DeviceType == "panorama" && shared == true {
				xpath = fmt.Sprintf("/config/shared/address-group/entry[@name='%s']/tag", object)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=edit&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address-group/entry[@name='%s']/tag", devicegroup[0], object)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=edit&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when tagging objects on a Panorama device")
			}
		}
	}

	for _, s := range sObj.Services {
		if object == s.Name {
			if p.DeviceType == "panos" && shared == false {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service/entry[@name='%s']/tag", object)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=edit&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
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

			if p.DeviceType == "panos" && shared == true {
				return errors.New("you can only apply a tag to a shared object on a Panorama device")
			}

			if p.DeviceType == "panorama" && shared == true {
				xpath = fmt.Sprintf("/config/shared/service/entry[@name='%s']/tag", object)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=edit&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service/entry[@name='%s']/tag", devicegroup[0], object)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=edit&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when tagging objects on a Panorama device")
			}
		}
	}

	for _, sg := range sgObj.Groups {
		if object == sg.Name {
			if p.DeviceType == "panos" && shared == false {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group/entry[@name='%s']/tag", object)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=edit&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
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

			if p.DeviceType == "panos" && shared == true {
				return errors.New("you can only apply a tag to a shared object on a Panorama device")
			}

			if p.DeviceType == "panorama" && shared == true {
				xpath = fmt.Sprintf("/config/shared/service-group/entry[@name='%s']/tag", object)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=edit&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service-group/entry[@name='%s']/tag", devicegroup[0], object)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=edit&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when tagging objects on a Panorama device")
			}
		}
	}

	return nil
}

// RemoveTag will remove a single tag from an address/service object. If removing
// a tag from a shared object on a Panorama device, then specify "true" for the shared parameter, as well as the device-group
// name as the last parameter. If not creating a shared object, then just specify "false."
func (p *PaloAlto) RemoveTag(tag, object string, shared bool, devicegroup ...string) error {
	var xpath string
	var reqError requestError
	adObj, _ := p.Addresses()
	agObj, _ := p.AddressGroups()
	sObj, _ := p.Services()
	sgObj, _ := p.ServiceGroups()

	for _, a := range adObj.Addresses {
		if object == a.Name {
			if p.DeviceType == "panos" && shared == false {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='%s']/tag/member[text()='%s']", object, tag)

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

			if p.DeviceType == "panos" && shared == true {
				return errors.New("you can only remove a tag from a shared object on a Panorama device")
			}

			if p.DeviceType == "panorama" && shared == true {
				xpath = fmt.Sprintf("/config/shared/address/entry[@name='%s']/tag/member[text()='%s']", object, tag)

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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address/entry[@name='%s']/tag/member[text()='%s']", devicegroup[0], object, tag)

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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when removing tags on a Panorama device")
			}
		}
	}

	for _, ag := range agObj.Groups {
		if object == ag.Name {
			if p.DeviceType == "panos" && shared == false {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='%s']/tag/member[text()='%s']", object, tag)

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

			if p.DeviceType == "panos" && shared == true {
				return errors.New("you can only remove a tag from a shared object on a Panorama device")
			}

			if p.DeviceType == "panorama" && shared == true {
				xpath = fmt.Sprintf("/config/shared/address-group/entry[@name='%s']/tag/member[text()='%s']", object, tag)

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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address-group/entry[@name='%s']/tag/member[text()='%s']", devicegroup[0], object, tag)

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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when removing tags on a Panorama device")
			}
		}
	}

	for _, s := range sObj.Services {
		if object == s.Name {
			if p.DeviceType == "panos" && shared == false {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service/entry[@name='%s']/tag/member[text()='%s']", object, tag)

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

			if p.DeviceType == "panos" && shared == true {
				return errors.New("you can only remove a tag from a shared object on a Panorama device")
			}

			if p.DeviceType == "panorama" && shared == true {
				xpath = fmt.Sprintf("/config/shared/service/entry[@name='%s']/tag/member[text()='%s']", object, tag)

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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service/entry[@name='%s']/tag/member[text()='%s']", devicegroup[0], object, tag)

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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when removing tags on a Panorama device")
			}
		}
	}

	for _, sg := range sgObj.Groups {
		if object == sg.Name {
			if p.DeviceType == "panos" && shared == false {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group/entry[@name='%s']/tag/member[text()='%s']", object, tag)

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

			if p.DeviceType == "panos" && shared == true {
				return errors.New("you can only remove a tag from a shared object on a Panorama device")
			}

			if p.DeviceType == "panorama" && shared == true {
				xpath = fmt.Sprintf("/config/shared/service-group/entry[@name='%s']/tag/member[text()='%s']", object, tag)

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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service-group/entry[@name='%s']/tag/member[text()='%s']", devicegroup[0], object, tag)

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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when removing tags on a Panorama device")
			}
		}
	}

	return nil
}

// Commit issues a commit on the device. When issuing a commit against a Panorama device,
// the configuration will only be committed to Panorama, and not an individual device-group.
func (p *PaloAlto) Commit() error {
	var reqError requestError

	_, resp, errs := r.Get(p.URI).Query(fmt.Sprintf("type=commit&cmd=<commit></commit>&key=%s", p.Key)).End()
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

// CommitAll issues a commit to a Panorama device, with the given 'devicegroup.' You can (optionally) specify
// individual devices within that device group by adding each serial number as an additional parameter.
func (p *PaloAlto) CommitAll(devicegroup string, devices ...string) error {
	var reqError requestError
	var cmd string

	if p.DeviceType == "panorama" && len(devices) <= 0 {
		cmd = fmt.Sprintf("<commit-all><shared-policy><device-group><entry name=\"%s\"/></device-group></shared-policy></commit-all>", devicegroup)
	}

	if p.DeviceType == "panorama" && len(devices) > 0 {
		cmd = fmt.Sprintf("<commit-all><shared-policy><device-group><name>%s</name><devices>", devicegroup)

		for _, d := range devices {
			cmd += fmt.Sprintf("<entry name=\"%s\"/>", d)
		}

		cmd += "</devices></device-group></shared-policy></commit-all>"
	}

	_, resp, errs := r.Get(p.URI).Query(fmt.Sprintf("type=commit&action=all&cmd=%s&key=%s", cmd, p.Key)).End()
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

// Policy returns information about all of the security rules for the given device-group.
func (p *PaloAlto) Policy(devicegroup string) (*Policy, error) {
	var policy Policy
	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/pre-rulebase/security/rules", devicegroup)

	if p.DeviceType != "panorama" {
		return nil, errors.New("policies can only be listed from a Panorama device")
	}

	_, policyData, errs := r.Get(p.URI).Query(fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", xpath, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(policyData), &policy); err != nil {
		return nil, err
	}

	if len(policy.Rules) == 0 {
		return nil, fmt.Errorf("there are no rules created, or the device-group %s does not exist", devicegroup)
	}

	if policy.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", policy.Code, errorCodes[policy.Code])
	}

	return &policy, nil
}

// ApplyLogForwardingProfile will apply a Log Forwarding profile to every rule in the policy for the given device-group.
// If you wish to apply it to a single rule, instead of every single one, you can optionally specify the rule name as the last parameter.
// For policies with a large number of rules, this process may take a few minutes to complete.
func (p *PaloAlto) ApplyLogForwardingProfile(logprofile, devicegroup string, rule ...string) error {
	if p.DeviceType != "panorama" {
		return errors.New("log forwarding profiles can only be applied on a Panorama device")
	}

	if len(rule) <= 0 {
		rules, err := p.Policy(devicegroup)
		if err != nil {
			return err
		}

		for _, rule := range rules.Rules {
			var reqError requestError
			xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/pre-rulebase/security/rules/entry[@name='%s']", devicegroup, rule.Name)
			xmlBody := fmt.Sprintf("<log-setting>%s</log-setting>", logprofile)

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

			time.Sleep(10 * time.Millisecond)
		}
	}

	if len(rule) > 0 {
		var reqError requestError
		xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/pre-rulebase/security/rules/entry[@name='%s']", devicegroup, rule[0])
		xmlBody := fmt.Sprintf("<log-setting>%s</log-setting>", logprofile)

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

		time.Sleep(10 * time.Millisecond)
	}

	return nil
}

// ApplySecurityProfile will apply the following security profiles (Antivirus, Anti-Spyware, Vulnerability, Wildfire)
// to every rule in the policy for the given device-group. If you wish to apply it to a single rule, instead of every
// single one, you can optionally specify the rule name as the last parameter. You can also specify a security group instead of individual ones.
// This is done by ONLY specifying the "Group" field in the SecurityProfiles struct. For policies with a large number of rules,
// this process may take a few minutes to complete.
func (p *PaloAlto) ApplySecurityProfile(secprofiles *SecurityProfiles, devicegroup string, rule ...string) error {
	if p.DeviceType != "panorama" {
		return errors.New("security profiles can only be applied on a Panorama device")
	}

	if len(rule) <= 0 {
		rules, err := p.Policy(devicegroup)
		if err != nil {
			return err
		}

		for _, rule := range rules.Rules {
			var reqError requestError
			var xmlBody string
			xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/pre-rulebase/security/rules/entry[@name='%s']", devicegroup, rule.Name)

			if len(secprofiles.Group) > 0 {
				xmlBody = fmt.Sprintf("<profile-setting><group><member>%s</member></group></profile-setting>", secprofiles.Group)
			} else {
				xmlBody = "<profile-setting><profiles>"

				if len(secprofiles.AntiVirus) > 0 {
					xmlBody += fmt.Sprintf("<virus><member>%s</member></virus>", secprofiles.AntiVirus)
				}

				if len(secprofiles.AntiSpyware) > 0 {
					xmlBody += fmt.Sprintf("<spyware><member>%s</member></spyware>", secprofiles.AntiSpyware)
				}

				if len(secprofiles.Vulnerability) > 0 {
					xmlBody += fmt.Sprintf("<vulnerability><member>%s</member></vulnerability>", secprofiles.AntiSpyware)
				}

				if len(secprofiles.Wildfire) > 0 {
					xmlBody += fmt.Sprintf("<wildfire-analysis><member>%s</member></wildfire-analysis>", secprofiles.Wildfire)
				}

				xmlBody += "</profiles></profile-setting>"
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

			time.Sleep(10 * time.Millisecond)
		}
	}

	if len(rule) > 0 {
		var reqError requestError
		var xmlBody string
		xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/pre-rulebase/security/rules/entry[@name='%s']", devicegroup, rule[0])

		if len(secprofiles.Group) > 0 {
			xmlBody = fmt.Sprintf("<profile-setting><group><member>%s</member></group></profile-setting>", secprofiles.Group)
		} else {
			xmlBody = "<profile-setting><profiles>"

			if len(secprofiles.AntiVirus) > 0 {
				xmlBody += fmt.Sprintf("<virus><member>%s</member></virus>", secprofiles.AntiVirus)
			}

			if len(secprofiles.AntiSpyware) > 0 {
				xmlBody += fmt.Sprintf("<spyware><member>%s</member></spyware>", secprofiles.AntiSpyware)
			}

			if len(secprofiles.Vulnerability) > 0 {
				xmlBody += fmt.Sprintf("<vulnerability><member>%s</member></vulnerability>", secprofiles.AntiSpyware)
			}

			if len(secprofiles.Wildfire) > 0 {
				xmlBody += fmt.Sprintf("<wildfire-analysis><member>%s</member></wildfire-analysis>", secprofiles.Wildfire)
			}

			xmlBody += "</profiles></profile-setting>"
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

		time.Sleep(10 * time.Millisecond)
	}

	return nil
}

// RestartSystem will issue a system restart to the device.
func (p *PaloAlto) RestartSystem() error {
	var reqError requestError
	command := "<request><restart><system></system></restart></request>"

	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=op&cmd=%s&key=%s", command, p.Key)).End()
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

// TestURL will verify what category the given URL falls under.
func (p *PaloAlto) TestURL(url string) (string, error) {
	var urlResults testURL
	command := fmt.Sprintf("<test><url>%s</url></test>", url)

	if p.DeviceType == "panorama" {
		return "", errors.New("you can only test URL's from a local device")
	}

	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=op&cmd=%s&key=%s", command, p.Key)).End()
	if errs != nil {
		return "", errs[0]
	}

	if err := xml.Unmarshal([]byte(resp), &urlResults); err != nil {
		return "", err
	}

	if urlResults.Status != "success" {
		return "", fmt.Errorf("error code %s: %s", urlResults.Code, errorCodes[urlResults.Code])
	}

	return urlResults.Result, nil
}

// TestRouteLookup will lookup the given destination IP in the virtual-router 'vr' and check the routing (fib) table and display the results.
func (p *PaloAlto) TestRouteLookup(vr, destination string) (string, error) {
	var routeLookup testRoute
	command := fmt.Sprintf("<test><routing><fib-lookup><virtual-router>%s</virtual-router><ip>%s</ip></fib-lookup></routing></test>", vr, destination)

	if p.DeviceType == "panorama" {
		return "", errors.New("you can only test route lookups from a local device")
	}

	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=op&cmd=%s&key=%s", command, p.Key)).End()
	if errs != nil {
		return "", errs[0]
	}

	if err := xml.Unmarshal([]byte(resp), &routeLookup); err != nil {
		return "", err
	}

	if routeLookup.Status != "success" {
		return "", fmt.Errorf("error code %s: %s", routeLookup.Code, errorCodes[routeLookup.Code])
	}

	result := fmt.Sprintf("Destination %s via %s interface %s, source %s, metric %d (%s)\n", destination, routeLookup.IP, routeLookup.Interface, routeLookup.Source, routeLookup.Metric, vr)

	return result, nil
}
