package panos

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"
)

// URLCategory contains a slice of all custom URL category objects.
type URLCategory struct {
	XMLName xml.Name    `xml:"response"`
	Status  string      `xml:"status,attr"`
	Code    string      `xml:"code,attr"`
	URLs    []CustomURL `xml:"result>custom-url-category>entry"`
}

// CustomURL contains information about each individual custom URL category object.
type CustomURL struct {
	Name        string   `xml:"name,attr"`
	Description string   `xml:"description,omitempty"`
	Members     []string `xml:"list>member,omitempty"`
}

// Recurrance contains the information for external dynamic lists when it comes to how often they are downloaded. Method
// must be one of: five-minute, hourly, daily, weekly, monthly. DayOfWeek is the name of the day, such as "tuesday." DayOfMonth
// is specified as a number, ranging from 1-31. Hour must be in 23-hour format, such as "03" for 3 am. The hourly and five-minute
// methods do not require any additional fields. DayOfWeek and DayOfMonth both require the Hour field as well.
type Recurrance struct {
	Method     string
	DayOfWeek  string
	DayOfMonth int
	Hour       string
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

// SecurityProfiles contains a list of security profiles to apply to a rule. If you have a security group
// then you can just specify that and omit the individual ones.
type SecurityProfiles struct {
	URLFiltering  string
	FileBlocking  string
	AntiVirus     string
	AntiSpyware   string
	Vulnerability string
	Wildfire      string
	Group         string
}

var (
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
)

// URLCategory returns a list of all custom URL category objects. You can (optionally) specify a device-group
// when ran against a Panorama device. If no device-group is specified, then all objects are returned.
func (p *PaloAlto) URLCategory(devicegroup ...string) (*URLCategory, error) {
	var urls URLCategory
	xpath := "/config/devices/entry//custom-url-category"

	if p.DeviceType != "panorama" && len(devicegroup) > 0 {
		return nil, errors.New("you must be connected to a Panorama device when specifying a device-group")
	}

	if p.DeviceType == "panos" && p.Panorama == true {
		xpath = "/config/panorama//custom-url-category"
	}

	if p.DeviceType == "panos" && p.Panorama == false {
		xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/custom-url-category"
	}

	if p.DeviceType == "panorama" && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/profiles/custom-url-category", devicegroup[0])
	}

	_, urlData, errs := r.Get(p.URI).Query(fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", xpath, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(urlData), &urls); err != nil {
		return nil, err
	}

	if urls.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", urls.Code, errorCodes[urls.Code])
	}

	return &urls, nil
}

// CreateURLCategory creates a custom URL category to be used in a policy. When specifying multiple URL's, use a
// []string variable for the url parameter (i.e. members := []string{"www.*.com", "*.somesite.net"}). If creating a
// URL category on a Panorama device, specify the device-group as the last parameter.
func (p *PaloAlto) CreateURLCategory(name string, urls []string, description string, devicegroup ...string) error {
	var xpath string
	var reqError requestError

	xmlBody := "<list>"
	for _, m := range urls {
		xmlBody += fmt.Sprintf("<member>%s</member>", strings.TrimSpace(m))
	}
	xmlBody += "</list>"

	if description != "" {
		xmlBody += fmt.Sprintf("<description>%s</description>", description)
	}

	if p.DeviceType == "panos" {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/custom-url-category/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && p.Shared == true {
		xpath = fmt.Sprintf("/config/shared/profiles/custom-url-category/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/profiles/custom-url-category/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when creating a URL category on a Panorama device")
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

// EditURLCategory adds or removes URL's from the given custom URL category. Action must be "add" or "remove." If editing
// a URL category on a Panorama device, specify the device-group as the last parameter.
func (p *PaloAlto) EditURLCategory(action, url, name string, devicegroup ...string) error {
	var xpath string
	var xmlBody string
	var reqError requestError

	query := fmt.Sprintf("type=config&key=%s", p.Key)

	if p.DeviceType == "panos" {
		if action == "add" {
			xmlBody += fmt.Sprintf("<member>%s</member>", url)
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/custom-url-category/entry[@name='%s']/list", name)

			query += fmt.Sprintf("&action=set&xpath=%s&element=%s", xpath, xmlBody)
		}

		if action == "remove" {
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/custom-url-category/entry[@name='%s']/list/member[text()='%s']", name, url)

			query += fmt.Sprintf("&action=delete&xpath=%s", xpath)
		}
	}

	if p.DeviceType == "panorama" && p.Shared == true {
		if action == "add" {
			xmlBody = fmt.Sprintf("<member>%s</member>", url)
			xpath = fmt.Sprintf("/config/shared/profiles/custom-url-category/entry[@name='%s']/list", name)

			query += fmt.Sprintf("&action=set&xpath=%s&element=%s", xpath, xmlBody)
		}

		if action == "remove" {
			xpath = fmt.Sprintf("/config/shared/profiles/custom-url-category/entry[@name='%s']/list/member[text()='%s']", name, url)

			query += fmt.Sprintf("&action=delete&xpath=%s", xpath)
		}
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
		if action == "add" {
			xmlBody = fmt.Sprintf("<member>%s</member>", url)
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/profiles/custom-url-category/entry[@name='%s']/list", devicegroup[0], name)

			query += fmt.Sprintf("&action=set&xpath=%s&element=%s", xpath, xmlBody)
		}

		if action == "remove" {
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/profiles/custom-url-category/entry[@name='%s']/list/member[text()='%s']", devicegroup[0], name, url)

			query += fmt.Sprintf("&action=delete&xpath=%s", xpath)
		}
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when editing a URL category on a Panorama device")
	}

	_, resp, errs := r.Post(p.URI).Query(query).End()
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

// DeleteURLCategory removes a custom URL category from the device. If deleting a URL category on a
// Panorama device, specify the device-group as the last parameter.
func (p *PaloAlto) DeleteURLCategory(name string, devicegroup ...string) error {
	var xpath string
	var reqError requestError

	if p.DeviceType == "panos" {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/custom-url-category/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && p.Shared == true {
		xpath = fmt.Sprintf("/config/shared/profiles/custom-url-category/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/profiles/custom-url-category/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when deleting a URL category on a Panorama device")
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

// EditGroup will add or remove objects from the specified group type (i.e., "address" or "service"). Action must be
// "add" or "remove." If editing a group on a Panorama device, specify the device-group as the last parameter.
func (p *PaloAlto) EditGroup(objecttype, action, object, group string, devicegroup ...string) error {
	var xmlBody string
	var xpath string
	var reqError requestError

	query := fmt.Sprintf("type=config&key=%s", p.Key)

	if p.DeviceType == "panos" {
		if action == "add" {
			xmlBody = fmt.Sprintf("<member>%s</member>", object)
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='%s']/static", group)
			if objecttype == "service" {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group/entry[@name='%s']/members", group)
			}

			query += fmt.Sprintf("&action=set&xpath=%s&element=%s", xpath, xmlBody)
		}

		if action == "remove" {
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='%s']/static/member[text()='%s']", group, object)
			if objecttype == "service" {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group/entry[@name='%s']/members/member[text()='%s']", group, object)
			}

			query += fmt.Sprintf("&action=delete&xpath=%s", xpath)
		}
	}

	if p.DeviceType == "panorama" && p.Shared == true {
		if action == "add" {
			xmlBody = fmt.Sprintf("<member>%s</member>", object)
			xpath = fmt.Sprintf("/config/shared/address-group/entry[@name='%s']/static", group)
			if objecttype == "service" {
				xpath = fmt.Sprintf("/config/shared/service-group/entry[@name='%s']/members", group)
			}

			query += fmt.Sprintf("&action=set&xpath=%s&element=%s", xpath, xmlBody)
		}

		if action == "remove" {
			xpath = fmt.Sprintf("/config/shared/address-group/entry[@name='%s']/static/member[text()='%s']", group, object)
			if objecttype == "service" {
				xpath = fmt.Sprintf("/config/shared/service-group/entry[@name='%s']/members/member[text()='%s']", group, object)
			}

			query += fmt.Sprintf("&action=delete&xpath=%s", xpath)
		}
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
		if action == "add" {
			xmlBody = fmt.Sprintf("<member>%s</member>", object)
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address-group/entry[@name='%s']/static", devicegroup[0], group)
			if objecttype == "service" {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service-group/entry[@name='%s']/members", devicegroup[0], group)
			}

			query += fmt.Sprintf("&action=set&xpath=%s&element=%s", xpath, xmlBody)
		}

		if action == "remove" {
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address-group/entry[@name='%s']/static/member[text()='%s']", devicegroup[0], group, object)
			if objecttype == "service" {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service-group/entry[@name='%s']/members/member[text()='%s']", devicegroup[0], group, object)
			}

			query += fmt.Sprintf("&action=delete&xpath=%s", xpath)
		}
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when editing a shared group on a Panorama device")
	}

	_, resp, errs := r.Post(p.URI).Query(query).End()
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

// RenameObject will rename the given object from oldname to the newname. You can rename the following
// object types: address, address-groups, service, service-groups, tags. If renaming objects on a
// Panorama device, specify the device-group as the last parameter.
func (p *PaloAlto) RenameObject(oldname, newname string, devicegroup ...string) error {
	var xpath string
	var reqError requestError
	adObj, _ := p.Addresses()
	agObj, _ := p.AddressGroups()
	sObj, _ := p.Services()
	sgObj, _ := p.ServiceGroups()
	tags, _ := p.Tags()

	for _, a := range adObj.Addresses {
		if oldname == a.Name {
			if p.DeviceType == "panos" {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='%s']", oldname)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=rename&xpath=%s&newname=%s&key=%s", xpath, newname, p.Key)).End()
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

			if p.DeviceType == "panorama" && p.Shared == true {
				xpath = fmt.Sprintf("/config/shared/address/entry[@name='%s']", oldname)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=rename&xpath=%s&newname=%s&key=%s", xpath, newname, p.Key)).End()
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address/entry[@name='%s']", devicegroup[0], oldname)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=rename&xpath=%s&newname=%s&key=%s", xpath, newname, p.Key)).End()
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when renaming an object on a Panorama device")
			}
		}
	}

	for _, ag := range agObj.Groups {
		if oldname == ag.Name {
			if p.DeviceType == "panos" {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='%s']", oldname)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=rename&xpath=%s&newname=%s&key=%s", xpath, newname, p.Key)).End()
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

			if p.DeviceType == "panorama" && p.Shared == true {
				xpath = fmt.Sprintf("/config/shared/address-group/entry[@name='%s']", oldname)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=rename&xpath=%s&newname=%s&key=%s", xpath, newname, p.Key)).End()
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address-group/entry[@name='%s']", devicegroup[0], oldname)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=rename&xpath=%s&newname=%s&key=%s", xpath, newname, p.Key)).End()
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when connected to a Panorama device")
			}
		}
	}

	for _, s := range sObj.Services {
		if oldname == s.Name {
			if p.DeviceType == "panos" {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service/entry[@name='%s']", oldname)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=rename&xpath=%s&newname=%s&key=%s", xpath, newname, p.Key)).End()
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

			if p.DeviceType == "panorama" && p.Shared == true {
				xpath = fmt.Sprintf("/config/shared/service/entry[@name='%s']", oldname)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=rename&xpath=%s&newname=%s&key=%s", xpath, newname, p.Key)).End()
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service/entry[@name='%s']", devicegroup[0], oldname)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=rename&xpath=%s&newname=%s&key=%s", xpath, newname, p.Key)).End()
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when connected to a Panorama device")
			}
		}
	}

	for _, sg := range sgObj.Groups {
		if oldname == sg.Name {
			if p.DeviceType == "panos" {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group/entry[@name='%s']", oldname)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=rename&xpath=%s&newname=%s&key=%s", xpath, newname, p.Key)).End()
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

			if p.DeviceType == "panorama" && p.Shared == true {
				xpath = fmt.Sprintf("/config/shared/service-group/entry[@name='%s']", oldname)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=rename&xpath=%s&newname=%s&key=%s", xpath, newname, p.Key)).End()
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service-group/entry[@name='%s']", devicegroup[0], oldname)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=rename&xpath=%s&newname=%s&key=%s", xpath, newname, p.Key)).End()
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when connected to a Panorama device")
			}
		}
	}

	for _, t := range tags.Tags {
		if oldname == t.Name {
			if p.DeviceType == "panos" {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/tag/entry[@name='%s']", oldname)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=rename&xpath=%s&newname=%s&key=%s", xpath, newname, p.Key)).End()
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

			if p.DeviceType == "panorama" && p.Shared == true {
				xpath = fmt.Sprintf("/config/shared/tag/entry[@name='%s']", oldname)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=rename&xpath=%s&newname=%s&key=%s", xpath, newname, p.Key)).End()
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/tag/entry[@name='%s']", devicegroup[0], oldname)

				_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=rename&xpath=%s&newname=%s&key=%s", xpath, newname, p.Key)).End()
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when connected to a Panorama device")
			}
		}
	}

	return nil
}

// CreateExternalDynamicList will create an external dynamic list on the device. Listtype must be one of: ip, domain, or url. Configuring the
// recurrance requires you to use the Recurrance struct when passing the configuration for this parameter - please see the documentation for that struct.
// If creating an EDL on a Panorama device, specify the device-group as the last parameter.
func (p *PaloAlto) CreateExternalDynamicList(listtype string, name string, url string, recurrance *Recurrance, devicegroup ...string) error {
	var xpath string
	var reqError requestError
	var xmlBody string
	var recurring string

	ver := splitSWVersion(p.SoftwareVersion)

	switch recurrance.Method {
	case "hourly":
		recurring = "<hourly/>"
	case "five-minute":
		recurring = "<five-minute/>"
	case "daily":
		recurring = fmt.Sprintf("<daily><at>%s</at></daily>", recurrance.Hour)
	case "weekly":
		recurring = fmt.Sprintf("<weekly><day-of-week>%s</day-of-week><at>%s</at></weekly>", recurrance.DayOfWeek, recurrance.Hour)
	case "monthly":
		recurring = fmt.Sprintf("<monthly><day-of-month>%d</day-of-month><at>%s</at></monthly>", recurrance.DayOfMonth, recurrance.Hour)
	}

	if ver[0] >= 8 {
		xmlBody = fmt.Sprintf("<type><%s><recurring>%s</recurring><url>%s</url></%s></type>", listtype, recurring, url, listtype)
	}

	if ver[0] <= 7 {
		xmlBody = fmt.Sprintf("<recurring>%s</recurring><url>%s</url><type>%s</type>", recurring, url, listtype)
	}

	if p.DeviceType == "panos" {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/external-list/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && p.Shared == true {
		xpath = fmt.Sprintf("/config/shared/external-list/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/external-list/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when creating an external dynamic list on a Panorama device")
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

// DeleteExternalDynamicList removes an external dynamic list from the device. If deleting an EDL on a
// Panorama device, specify the device-group as the last parameter.
func (p *PaloAlto) DeleteExternalDynamicList(name string, devicegroup ...string) error {
	var xpath string
	var reqError requestError

	if p.DeviceType == "panos" {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/external-list/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && p.Shared == true {
		xpath = fmt.Sprintf("/config/shared/external-list/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/external-list/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when deleting a external dynamic list on a Panorama device")
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
// Orange, Purple, Gray, Light Green, Cyan, Light Gray, Blue Gray, Lime, Black, Gold, Brown. If creating a tag on a
// Panorama device, specify the device-group as the last parameter.
func (p *PaloAlto) CreateTag(name, color, comments string, devicegroup ...string) error {
	var xmlBody string
	var xpath string
	var reqError requestError

	xmlBody = fmt.Sprintf("<color>%s</color>", tagColors[color])

	if comments != "" {
		xmlBody += fmt.Sprintf("<comments>%s</comments>", comments)
	}

	if p.DeviceType == "panos" {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/tag/entry[@name='%s']", name)
	}

	if p.DeviceType == "panos" && len(devicegroup) > 0 {
		return errors.New("you do not need to specify a device-group on a non-Panorama device")
	}

	if p.DeviceType == "panorama" && p.Shared == true {
		xpath = fmt.Sprintf("/config/shared/tag/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/tag/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
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

// DeleteTag will remove a tag from the device. If deleting a tag on a Panorama device, specify the
// device-group as the last parameter.
func (p *PaloAlto) DeleteTag(name string, devicegroup ...string) error {
	var xpath string
	var reqError requestError

	if p.DeviceType == "panos" {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/tag/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && p.Shared == true {
		xpath = fmt.Sprintf("/config/shared/tag/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/tag/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
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

// TagObject will apply the given tag to the specified address or service object(s). You can specify multiple tags
// by separating them with a comma, i.e. "servers, vm". If you have address/service objects with the same
// name, then the tag(s) will be applied to all that match. If tagging objects on a
// Panorama device, specify the device-group as the last parameter.
func (p *PaloAlto) TagObject(tag, object string, devicegroup ...string) error {
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
			if p.DeviceType == "panos" {
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

			if p.DeviceType == "panorama" && p.Shared == true {
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) >= 0 {
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when tagging objects on a Panorama device")
			}
		}
	}

	for _, ag := range agObj.Groups {
		if object == ag.Name {
			if p.DeviceType == "panos" {
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

			if p.DeviceType == "panorama" && p.Shared == true {
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when tagging objects on a Panorama device")
			}
		}
	}

	for _, s := range sObj.Services {
		if object == s.Name {
			if p.DeviceType == "panos" {
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

			if p.DeviceType == "panorama" && p.Shared == true {
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when tagging objects on a Panorama device")
			}
		}
	}

	for _, sg := range sgObj.Groups {
		if object == sg.Name {
			if p.DeviceType == "panos" {
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

			if p.DeviceType == "panorama" && p.Shared == true {
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when tagging objects on a Panorama device")
			}
		}
	}

	return nil
}

// RemoveTag will remove a single tag from an address/service object. If removing a tag on a
// Panorama device, specify the device-group as the last parameter.
func (p *PaloAlto) RemoveTag(tag, object string, devicegroup ...string) error {
	var xpath string
	var reqError requestError
	adObj, _ := p.Addresses()
	agObj, _ := p.AddressGroups()
	sObj, _ := p.Services()
	sgObj, _ := p.ServiceGroups()

	for _, a := range adObj.Addresses {
		if object == a.Name {
			if p.DeviceType == "panos" {
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

			if p.DeviceType == "panorama" && p.Shared == true {
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when removing tags on a Panorama device")
			}
		}
	}

	for _, ag := range agObj.Groups {
		if object == ag.Name {
			if p.DeviceType == "panos" {
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

			if p.DeviceType == "panorama" && p.Shared == true {
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when removing tags on a Panorama device")
			}
		}
	}

	for _, s := range sObj.Services {
		if object == s.Name {
			if p.DeviceType == "panos" {
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

			if p.DeviceType == "panorama" && p.Shared == true {
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when removing tags on a Panorama device")
			}
		}
	}

	for _, sg := range sgObj.Groups {
		if object == sg.Name {
			if p.DeviceType == "panos" {
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

			if p.DeviceType == "panorama" && p.Shared == true {
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) > 0 {
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

			if p.DeviceType == "panorama" && p.Shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when removing tags on a Panorama device")
			}
		}
	}

	return nil
}

// ApplyLogForwardingProfile will apply a Log Forwarding profile to every rule in the policy for the given device-group.
// If you wish to apply it to a single rule, instead of every rule in the policy, you can optionally specify the rule name as the last parameter.
// For policies with a large number of rules, this process may take a few minutes to complete.
func (p *PaloAlto) ApplyLogForwardingProfile(logprofile, devicegroup string, rule ...string) error {
	if p.DeviceType != "panorama" {
		return errors.New("log forwarding profiles can only be applied on a Panorama device")
	}

	rules, err := p.Policy(devicegroup)
	if err != nil {
		return err
	}

	if len(rule) <= 0 {
		// rules, err := p.Policy(devicegroup)
		// if err != nil {
		// 	return err
		// }

		if len(rules.Pre) > 0 {
			for _, rule := range rules.Pre {
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

		if len(rules.Post) > 0 {
			for _, rule := range rules.Post {
				var reqError requestError
				xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/post-rulebase/security/rules/entry[@name='%s']", devicegroup, rule.Name)
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

		// for _, rule := range rules.Rules {
		// 	var reqError requestError
		// 	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/pre-rulebase/security/rules/entry[@name='%s']", devicegroup, rule.Name)
		// 	xmlBody := fmt.Sprintf("<log-setting>%s</log-setting>", logprofile)

		// 	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=set&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
		// 	if errs != nil {
		// 		return errs[0]
		// 	}

		// 	if err := xml.Unmarshal([]byte(resp), &reqError); err != nil {
		// 		return err
		// 	}

		// 	if reqError.Status != "success" {
		// 		return fmt.Errorf("error code %s: %s", reqError.Code, errorCodes[reqError.Code])
		// 	}

		// 	time.Sleep(10 * time.Millisecond)
		// }
	}

	if len(rule) > 0 {
		if len(rules.Pre) > 0 {
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

		if len(rules.Post) > 0 {
			var reqError requestError
			xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/post-rulebase/security/rules/entry[@name='%s']", devicegroup, rule[0])
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

		// var reqError requestError
		// xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/pre-rulebase/security/rules/entry[@name='%s']", devicegroup, rule[0])
		// xmlBody := fmt.Sprintf("<log-setting>%s</log-setting>", logprofile)

		// _, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=set&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
		// if errs != nil {
		// 	return errs[0]
		// }

		// if err := xml.Unmarshal([]byte(resp), &reqError); err != nil {
		// 	return err
		// }

		// if reqError.Status != "success" {
		// 	return fmt.Errorf("error code %s: %s", reqError.Code, errorCodes[reqError.Code])
		// }

		// time.Sleep(10 * time.Millisecond)
	}

	return nil
}

// ApplySecurityProfile will apply the following security profiles: URL Filtering, File-Blocking, Antivirus, Anti-Spyware, Vulnerability, Wildfire
// to every rule in the policy for the given device-group. If you wish to apply it to a single rule, instead of every
// rule in the policy, you can optionally specify the rule name as the last parameter. You can also specify a security group profile instead of individual profiles.
// This is done by ONLY populating the "Group" field in the SecurityProfiles struct. For policies with a large number of rules,
// this process may take a few minutes to complete.
func (p *PaloAlto) ApplySecurityProfile(secprofiles *SecurityProfiles, devicegroup string, rule ...string) error {
	if p.DeviceType != "panorama" {
		return errors.New("security profiles can only be applied on a Panorama device")
	}

	rules, err := p.Policy(devicegroup)
	if err != nil {
		return err
	}

	if len(rule) <= 0 {
		// rules, err := p.Policy(devicegroup)
		// if err != nil {
		// 	return err
		// }

		if len(rules.Pre) > 0 {
			for _, rule := range rules.Pre {
				var reqError requestError
				var xmlBody string
				xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/pre-rulebase/security/rules/entry[@name='%s']", devicegroup, rule.Name)

				if len(secprofiles.Group) > 0 {
					xmlBody = fmt.Sprintf("<profile-setting><group><member>%s</member></group></profile-setting>", secprofiles.Group)
				} else {
					xmlBody = "<profile-setting><profiles>"

					if len(secprofiles.URLFiltering) > 0 {
						xmlBody += fmt.Sprintf("<url-filtering><member>%s</member></url-filtering>", secprofiles.URLFiltering)
					}

					if len(secprofiles.FileBlocking) > 0 {
						xmlBody += fmt.Sprintf("<file-blocking><member>%s</member></file-blocking>", secprofiles.FileBlocking)
					}

					if len(secprofiles.AntiVirus) > 0 {
						xmlBody += fmt.Sprintf("<virus><member>%s</member></virus>", secprofiles.AntiVirus)
					}

					if len(secprofiles.AntiSpyware) > 0 {
						xmlBody += fmt.Sprintf("<spyware><member>%s</member></spyware>", secprofiles.AntiSpyware)
					}

					if len(secprofiles.Vulnerability) > 0 {
						xmlBody += fmt.Sprintf("<vulnerability><member>%s</member></vulnerability>", secprofiles.Vulnerability)
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

		if len(rules.Post) > 0 {
			for _, rule := range rules.Post {
				var reqError requestError
				var xmlBody string
				xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/post-rulebase/security/rules/entry[@name='%s']", devicegroup, rule.Name)

				if len(secprofiles.Group) > 0 {
					xmlBody = fmt.Sprintf("<profile-setting><group><member>%s</member></group></profile-setting>", secprofiles.Group)
				} else {
					xmlBody = "<profile-setting><profiles>"

					if len(secprofiles.URLFiltering) > 0 {
						xmlBody += fmt.Sprintf("<url-filtering><member>%s</member></url-filtering>", secprofiles.URLFiltering)
					}

					if len(secprofiles.FileBlocking) > 0 {
						xmlBody += fmt.Sprintf("<file-blocking><member>%s</member></file-blocking>", secprofiles.FileBlocking)
					}

					if len(secprofiles.AntiVirus) > 0 {
						xmlBody += fmt.Sprintf("<virus><member>%s</member></virus>", secprofiles.AntiVirus)
					}

					if len(secprofiles.AntiSpyware) > 0 {
						xmlBody += fmt.Sprintf("<spyware><member>%s</member></spyware>", secprofiles.AntiSpyware)
					}

					if len(secprofiles.Vulnerability) > 0 {
						xmlBody += fmt.Sprintf("<vulnerability><member>%s</member></vulnerability>", secprofiles.Vulnerability)
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

		// for _, rule := range rules.Rules {
		// 	var reqError requestError
		// 	var xmlBody string
		// 	xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/pre-rulebase/security/rules/entry[@name='%s']", devicegroup, rule.Name)

		// 	if len(secprofiles.Group) > 0 {
		// 		xmlBody = fmt.Sprintf("<profile-setting><group><member>%s</member></group></profile-setting>", secprofiles.Group)
		// 	} else {
		// 		xmlBody = "<profile-setting><profiles>"

		// 		if len(secprofiles.AntiVirus) > 0 {
		// 			xmlBody += fmt.Sprintf("<virus><member>%s</member></virus>", secprofiles.AntiVirus)
		// 		}

		// 		if len(secprofiles.AntiSpyware) > 0 {
		// 			xmlBody += fmt.Sprintf("<spyware><member>%s</member></spyware>", secprofiles.AntiSpyware)
		// 		}

		// 		if len(secprofiles.Vulnerability) > 0 {
		// 			xmlBody += fmt.Sprintf("<vulnerability><member>%s</member></vulnerability>", secprofiles.AntiSpyware)
		// 		}

		// 		if len(secprofiles.Wildfire) > 0 {
		// 			xmlBody += fmt.Sprintf("<wildfire-analysis><member>%s</member></wildfire-analysis>", secprofiles.Wildfire)
		// 		}

		// 		xmlBody += "</profiles></profile-setting>"
		// 	}

		// 	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=set&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
		// 	if errs != nil {
		// 		return errs[0]
		// 	}

		// 	if err := xml.Unmarshal([]byte(resp), &reqError); err != nil {
		// 		return err
		// 	}

		// 	if reqError.Status != "success" {
		// 		return fmt.Errorf("error code %s: %s", reqError.Code, errorCodes[reqError.Code])
		// 	}

		// 	time.Sleep(10 * time.Millisecond)
		// }
	}

	if len(rule) > 0 {
		if len(rules.Pre) > 0 {
			var reqError requestError
			var xmlBody string
			xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/pre-rulebase/security/rules/entry[@name='%s']", devicegroup, rule[0])

			if len(secprofiles.Group) > 0 {
				xmlBody = fmt.Sprintf("<profile-setting><group><member>%s</member></group></profile-setting>", secprofiles.Group)
			} else {
				xmlBody = "<profile-setting><profiles>"

				if len(secprofiles.URLFiltering) > 0 {
					xmlBody += fmt.Sprintf("<url-filtering><member>%s</member></url-filtering>", secprofiles.URLFiltering)
				}

				if len(secprofiles.FileBlocking) > 0 {
					xmlBody += fmt.Sprintf("<file-blocking><member>%s</member></file-blocking>", secprofiles.FileBlocking)
				}

				if len(secprofiles.AntiVirus) > 0 {
					xmlBody += fmt.Sprintf("<virus><member>%s</member></virus>", secprofiles.AntiVirus)
				}

				if len(secprofiles.AntiSpyware) > 0 {
					xmlBody += fmt.Sprintf("<spyware><member>%s</member></spyware>", secprofiles.AntiSpyware)
				}

				if len(secprofiles.Vulnerability) > 0 {
					xmlBody += fmt.Sprintf("<vulnerability><member>%s</member></vulnerability>", secprofiles.Vulnerability)
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

		if len(rules.Post) > 0 {
			var reqError requestError
			var xmlBody string
			xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/post-rulebase/security/rules/entry[@name='%s']", devicegroup, rule[0])

			if len(secprofiles.Group) > 0 {
				xmlBody = fmt.Sprintf("<profile-setting><group><member>%s</member></group></profile-setting>", secprofiles.Group)
			} else {
				xmlBody = "<profile-setting><profiles>"

				if len(secprofiles.URLFiltering) > 0 {
					xmlBody += fmt.Sprintf("<url-filtering><member>%s</member></url-filtering>", secprofiles.URLFiltering)
				}

				if len(secprofiles.FileBlocking) > 0 {
					xmlBody += fmt.Sprintf("<file-blocking><member>%s</member></file-blocking>", secprofiles.FileBlocking)
				}

				if len(secprofiles.AntiVirus) > 0 {
					xmlBody += fmt.Sprintf("<virus><member>%s</member></virus>", secprofiles.AntiVirus)
				}

				if len(secprofiles.AntiSpyware) > 0 {
					xmlBody += fmt.Sprintf("<spyware><member>%s</member></spyware>", secprofiles.AntiSpyware)
				}

				if len(secprofiles.Vulnerability) > 0 {
					xmlBody += fmt.Sprintf("<vulnerability><member>%s</member></vulnerability>", secprofiles.Vulnerability)
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

		// var reqError requestError
		// var xmlBody string
		// xpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/pre-rulebase/security/rules/entry[@name='%s']", devicegroup, rule[0])

		// if len(secprofiles.Group) > 0 {
		// 	xmlBody = fmt.Sprintf("<profile-setting><group><member>%s</member></group></profile-setting>", secprofiles.Group)
		// } else {
		// 	xmlBody = "<profile-setting><profiles>"

		// 	if len(secprofiles.AntiVirus) > 0 {
		// 		xmlBody += fmt.Sprintf("<virus><member>%s</member></virus>", secprofiles.AntiVirus)
		// 	}

		// 	if len(secprofiles.AntiSpyware) > 0 {
		// 		xmlBody += fmt.Sprintf("<spyware><member>%s</member></spyware>", secprofiles.AntiSpyware)
		// 	}

		// 	if len(secprofiles.Vulnerability) > 0 {
		// 		xmlBody += fmt.Sprintf("<vulnerability><member>%s</member></vulnerability>", secprofiles.AntiSpyware)
		// 	}

		// 	if len(secprofiles.Wildfire) > 0 {
		// 		xmlBody += fmt.Sprintf("<wildfire-analysis><member>%s</member></wildfire-analysis>", secprofiles.Wildfire)
		// 	}

		// 	xmlBody += "</profiles></profile-setting>"
		// }

		// _, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=config&action=set&xpath=%s&element=%s&key=%s", xpath, xmlBody, p.Key)).End()
		// if errs != nil {
		// 	return errs[0]
		// }

		// if err := xml.Unmarshal([]byte(resp), &reqError); err != nil {
		// 	return err
		// }

		// if reqError.Status != "success" {
		// 	return fmt.Errorf("error code %s: %s", reqError.Code, errorCodes[reqError.Code])
		// }

		// time.Sleep(10 * time.Millisecond)
	}

	return nil
}
