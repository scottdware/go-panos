package panos

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
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

// Recurrance contains the information for external dynamic lists when it comes to how often they are downloaded. "Method"
// must be one of: five-minute, hourly, daily, weekly, monthly. "DayOfWeek" is the name of the day, such as "tuesday." "DayOfMonth"
// is specified as a number, ranging from 1-31. "Hour" must be in 23-hour format, such as "03" for 3 am. The "hourly" and "five-minute"
// methods do not require any additional fields. "DayOfWeek" and "DayOfMonth" both require the "Hour" field as well.
type Recurrance struct {
	Method     string
	DayOfWeek  string
	DayOfMonth int
	Hour       string
}

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
// []string variable for the url parameter (i.e. members := []string{"www.*.com", "*.somesite.net"}). If creating
// a shared URL category on a Panorama device, then specify "true" for the shared parameter, and omit the device-group.
// If not creating a shared object, then just specify "false."
func (p *PaloAlto) CreateURLCategory(name string, urls []string, description string, shared bool, devicegroup ...string) error {
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

	if p.DeviceType == "panos" && shared == false {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/custom-url-category/entry[@name='%s']", name)
	}

	if p.DeviceType == "panos" && shared == true {
		return errors.New("you can only create a shared URL category on a Panorama device")
	}

	if p.DeviceType == "panorama" && shared == true {
		xpath = fmt.Sprintf("/config/shared/profiles/custom-url-category/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/profiles/custom-url-category/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
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

// EditURLCategory adds or removes URL's from the given custom URL category. Action must be "add" or "remove". If editing
// a shared URL category on a Panorama device, then specify "true" for the shared parameter, and omit the device-group.
// If not editing a shared object, then just specify "false."
func (p *PaloAlto) EditURLCategory(action, url, name string, shared bool, devicegroup ...string) error {
	var xpath string
	var xmlBody string
	var reqError requestError

	query := fmt.Sprintf("type=config&key=%s", p.Key)

	if p.DeviceType == "panos" && shared == false {
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

	if p.DeviceType == "panos" && shared == true {
		return errors.New("you can only edit a shared URL category on a Panorama device")
	}

	if p.DeviceType == "panorama" && shared == true {
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

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
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

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
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

// DeleteURLCategory removes a custom URL category from the device. If deleting
// a shared URL category on a Panorama device, then specify "true" for the shared parameter, and omit the device-group.
// If not editing a shared object, then just specify "false."
func (p *PaloAlto) DeleteURLCategory(name string, shared bool, devicegroup ...string) error {
	var xpath string
	var reqError requestError

	if p.DeviceType == "panos" && shared == false {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/custom-url-category/entry[@name='%s']", name)
	}

	if p.DeviceType == "panos" && shared == true {
		return errors.New("you can only delete a shared URL category on a Panorama device")
	}

	if p.DeviceType == "panorama" && shared == true {
		xpath = fmt.Sprintf("/config/shared/profiles/custom-url-category/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/profiles/custom-url-category/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
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
// "add" or "remove". If editing
// a group on a Panorama device, then specify "true" for the shared parameter, and omit the device-group.
// If not editing a shared object, then just specify "false."
func (p *PaloAlto) EditGroup(objecttype, action, object, group string, shared bool, devicegroup ...string) error {
	var xmlBody string
	var xpath string
	var reqError requestError

	query := fmt.Sprintf("type=config&key=%s", p.Key)

	if p.DeviceType == "panos" && shared == false {
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

	if p.DeviceType == "panos" && shared == true {
		return errors.New("you can only edit a shared group on a Panorama device")
	}

	if p.DeviceType == "panorama" && shared == true {
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

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
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

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
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

// RenameObject will rename the given object from it's 'oldname' to the 'newname.' You can rename the following
// object types: address, address-groups, service, service-groups, tags. If renaming
// a shared object on a Panorama device, then specify "true" for the shared parameter, and omit the device-group.
// If not editing a shared object, then just specify "false."
func (p *PaloAlto) RenameObject(oldname, newname string, shared bool, devicegroup ...string) error {
	var xpath string
	var reqError requestError
	adObj, _ := p.Addresses()
	agObj, _ := p.AddressGroups()
	sObj, _ := p.Services()
	sgObj, _ := p.ServiceGroups()
	tags, _ := p.Tags()

	for _, a := range adObj.Addresses {
		if oldname == a.Name {
			if p.DeviceType == "panos" && shared == false {
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

			if p.DeviceType == "panos" && shared == true {
				return errors.New("you can only rename a shared object on a Panorama device")
			}

			if p.DeviceType == "panorama" && shared == true {
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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when renaming an object on a Panorama device")
			}
		}
	}

	for _, ag := range agObj.Groups {
		if oldname == ag.Name {
			if p.DeviceType == "panos" && shared == false {
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

			if p.DeviceType == "panos" && shared == true {
				return errors.New("you can only rename a shared object on a Panorama device")
			}

			if p.DeviceType == "panorama" && shared == true {
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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when connected to a Panorama device")
			}
		}
	}

	for _, s := range sObj.Services {
		if oldname == s.Name {
			if p.DeviceType == "panos" && shared == false {
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

			if p.DeviceType == "panos" && shared == true {
				return errors.New("you can only rename a shared object on a Panorama device")
			}

			if p.DeviceType == "panorama" && shared == true {
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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when connected to a Panorama device")
			}
		}
	}

	for _, sg := range sgObj.Groups {
		if oldname == sg.Name {
			if p.DeviceType == "panos" && shared == false {
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

			if p.DeviceType == "panos" && shared == true {
				return errors.New("you can only rename a shared object on a Panorama device")
			}

			if p.DeviceType == "panorama" && shared == true {
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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when connected to a Panorama device")
			}
		}
	}

	for _, t := range tags.Tags {
		if oldname == t.Name {
			if p.DeviceType == "panos" && shared == false {
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

			if p.DeviceType == "panos" && shared == true {
				return errors.New("you can only rename a shared object on a Panorama device")
			}

			if p.DeviceType == "panorama" && shared == true {
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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
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

			if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when connected to a Panorama device")
			}
		}
	}

	return nil
}

// CreateExternalDynamicList will create an external dynamic list on the device. "listtype" must be one of: ip, domain, or url. Configuring the
// recurrance requires you to use the Recurrance struct when passing the configuration for this parameter - please see the documentation for that struct.
// If creating a shared object on a Panorama device, then specify "true" for the shared parameter, and omit the device-group.
// If not creating a shared object, then just specify "false."
func (p *PaloAlto) CreateExternalDynamicList(listtype string, name string, url string, recurrance *Recurrance, shared bool, devicegroup ...string) error {
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

	if p.DeviceType == "panos" && shared == false {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/external-list/entry[@name='%s']", name)
	}

	if p.DeviceType == "panos" && shared == true {
		return errors.New("you can only create a shared external dynamic list on a Panorama device")
	}

	if p.DeviceType == "panorama" && shared == true {
		xpath = fmt.Sprintf("/config/shared/external-list/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/external-list/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
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

// DeleteExternalDynamicList removes an external dynamic list from the device. If deleting
// a shared EDL on a Panorama device, then specify "true" for the shared parameter, and omit the device-group.
// If not removing a shared object, then just specify "false."
func (p *PaloAlto) DeleteExternalDynamicList(name string, shared bool, devicegroup ...string) error {
	var xpath string
	var reqError requestError

	if p.DeviceType == "panos" && shared == false {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/external-list/entry[@name='%s']", name)
	}

	if p.DeviceType == "panos" && shared == true {
		return errors.New("you can only delete a shared external dynamic list on a Panorama device")
	}

	if p.DeviceType == "panorama" && shared == true {
		xpath = fmt.Sprintf("/config/shared/external-list/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/external-list/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && shared == false && len(devicegroup) <= 0 {
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
