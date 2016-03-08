package panos

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

	"github.com/scottdware/go-rested"
)

// CreateURLCategory creates a custom URL category to be used in a policy. When specifying multiple URL's, separate them
// using a comma, i.e. "www.*.com, *.sdubs.org". When creating a custom URL category on a Panorama device, specify the
// device-group as the last parameter.
func (p *PaloAlto) CreateURLCategory(name, urls, description string, devicegroup ...string) error {
	var xpath string
	var reqError requestError
	r := rested.NewRequest()
	u := strings.Split(urls, ",")

	xmlBody := "<list>"
	for _, m := range u {
		xmlBody += fmt.Sprintf("<member>%s</member>", strings.TrimSpace(m))
	}
	xmlBody += "</list>"

	if description != "" {
		xmlBody += fmt.Sprintf("<description>%s</description>", description)
	}

	if p.DeviceType == "panos" {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/custom-url-category/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/profiles/custom-url-category/entry[@name='%s']", devicegroup[0], name)
	}

	if p.DeviceType == "panorama" && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when connected to a Panorama device")
	}

	query := map[string]string{
		"type":    "config",
		"action":  "set",
		"xpath":   xpath,
		"key":     p.Key,
		"element": xmlBody,
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

// EditURLCategory adds or removes URL's from the given custom URL category. Action must be "add" or "remove". When editing a
// custom URL category on a Panorama device, specify the device-group as the last parameter.
func (p *PaloAlto) EditURLCategory(action, url, name string, devicegroup ...string) error {
	var xpath string
	var xmlBody string
	var reqError requestError
	r := rested.NewRequest()

	query := map[string]string{
		"type": "config",
		"key":  p.Key,
	}

	if p.DeviceType == "panos" {
		if action == "add" {
			xmlBody += fmt.Sprintf("<member>%s</member>", url)
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/custom-url-category/entry[@name='%s']/list", name)
			query["action"] = "set"
			query["element"] = xmlBody
			query["xpath"] = xpath
		}

		if action == "remove" {
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/custom-url-category/entry[@name='%s']/list/member[text()='%s']", name, url)
			query["action"] = "delete"
			query["xpath"] = xpath
		}
	}

	if p.DeviceType == "panorama" && len(devicegroup) > 0 {
		if action == "add" {
			xmlBody = fmt.Sprintf("<member>%s</member>", url)
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/profiles/custom-url-category/entry[@name='%s']/list", devicegroup[0], name)
			query["action"] = "set"
			query["element"] = xmlBody
			query["xpath"] = xpath
		}

		if action == "remove" {
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/profiles/custom-url-category/entry[@name='%s']/list/member[text()='%s']", devicegroup[0], name, url)
			query["action"] = "delete"
			query["xpath"] = xpath
		}
	}

	if p.DeviceType == "panorama" && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when connected to a Panorama device")
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

// DeleteURLCategory removes a custom URL category from the device. When removing a custom URL category on a Panorama device, specify the
// device-group as the last parameter.
func (p *PaloAlto) DeleteURLCategory(name string, devicegroup ...string) error {
	var xpath string
	var reqError requestError
	r := rested.NewRequest()

	if p.DeviceType == "panos" {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/custom-url-category/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && len(devicegroup) > 0 {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/profiles/custom-url-category/entry[@name='%s']", devicegroup[0], name)
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

// EditGroup will add or remove objects from the specified group type (i.e., "address" or "service"). Action must be
// "add" or "remove". When editing a group on a Panorama device, you must specify the device-group as the last parameter.
func (p *PaloAlto) EditGroup(objecttype, action, object, group string, devicegroup ...string) error {
	var xmlBody string
	var xpath string
	var reqError requestError
	r := rested.NewRequest()

	query := map[string]string{
		"type": "config",
		"key":  p.Key,
	}

	if p.DeviceType == "panos" {
		if action == "add" {
			xmlBody = fmt.Sprintf("<member>%s</member>", object)
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='%s']/static", group)
			if objecttype == "service" {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group/entry[@name='%s']/members", group)
			}
			query["action"] = "set"
			query["element"] = xmlBody
			query["xpath"] = xpath
		}

		if action == "remove" {
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='%s']/static/member[text()='%s']", group, object)
			if objecttype == "service" {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group/entry[@name='%s']/members/member[text()='%s']", group, object)
			}
			query["action"] = "delete"
			query["xpath"] = xpath
		}
	}

	if p.DeviceType == "panorama" && len(devicegroup) > 0 {
		if action == "add" {
			xmlBody = fmt.Sprintf("<member>%s</member>", object)
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address-group/entry[@name='%s']/static", devicegroup[0], group)
			if objecttype == "service" {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service-group/entry[@name='%s']/members", devicegroup[0], group)
			}
			query["action"] = "set"
			query["element"] = xmlBody
			query["xpath"] = xpath
		}

		if action == "remove" {
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address-group/entry[@name='%s']/static/member[text()='%s']", devicegroup[0], group, object)
			if objecttype == "service" {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service-group/entry[@name='%s']/members/member[text()='%s']", devicegroup[0], group, object)
			}
			query["action"] = "delete"
			query["xpath"] = xpath
		}
	}

	if p.DeviceType == "panorama" && len(devicegroup) <= 0 {
		return errors.New("you must specify a device-group when connected to a Panorama device")
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

// RenameObject will rename the given object from it's 'oldname' to the 'newname.' You can rename the following
// object types: address, address-groups, service, service-groups, tags. When renaming an object
// on a Panorama device, you must specify the device-group as the last parameter.
func (p *PaloAlto) RenameObject(oldname, newname string, devicegroup ...string) error {
	var xpath string
	var reqError requestError
	r := rested.NewRequest()
	adObj, _ := p.Addresses()
	agObj, _ := p.AddressGroups()
	sObj, _ := p.Services()
	sgObj, _ := p.ServiceGroups()
	tags, _ := p.Tags()

	query := map[string]string{
		"type":    "config",
		"action":  "rename",
		"key":     p.Key,
		"newname": newname,
	}

	for _, a := range adObj.Addresses {
		if oldname == a.Name {
			if p.DeviceType == "panos" {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='%s']", oldname)

				query["xpath"] = xpath

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

			if p.DeviceType == "panorama" && len(devicegroup) > 0 {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address/entry[@name='%s']", devicegroup[0], oldname)

				query["xpath"] = xpath

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

			if p.DeviceType == "panorama" && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when connected to a Panorama device")
			}
		}
	}

	for _, ag := range agObj.Groups {
		if oldname == ag.Name {
			if p.DeviceType == "panos" {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address-group/entry[@name='%s']", oldname)

				query["xpath"] = xpath

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

			if p.DeviceType == "panorama" && len(devicegroup) > 0 {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/address-group/entry[@name='%s']", devicegroup[0], oldname)

				query["xpath"] = xpath

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

			if p.DeviceType == "panorama" && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when connected to a Panorama device")
			}
		}
	}

	for _, s := range sObj.Services {
		if oldname == s.Name {
			if p.DeviceType == "panos" {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service/entry[@name='%s']", oldname)

				query["xpath"] = xpath

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

			if p.DeviceType == "panorama" && len(devicegroup) > 0 {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service/entry[@name='%s']", devicegroup[0], oldname)

				query["xpath"] = xpath

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

			if p.DeviceType == "panorama" && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when connected to a Panorama device")
			}
		}
	}

	for _, sg := range sgObj.Groups {
		if oldname == sg.Name {
			if p.DeviceType == "panos" {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/service-group/entry[@name='%s']", oldname)

				query["xpath"] = xpath

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

			if p.DeviceType == "panorama" && len(devicegroup) > 0 {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/service-group/entry[@name='%s']", devicegroup[0], oldname)

				query["xpath"] = xpath

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

			if p.DeviceType == "panorama" && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when connected to a Panorama device")
			}
		}
	}

	for _, t := range tags.Tags {
		if oldname == t.Name {
			if p.DeviceType == "panos" {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/tag/entry[@name='%s']", oldname)

				query["xpath"] = xpath

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

			if p.DeviceType == "panorama" && len(devicegroup) > 0 {
				xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/tag/entry[@name='%s']", devicegroup[0], oldname)

				query["xpath"] = xpath

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

			if p.DeviceType == "panorama" && len(devicegroup) <= 0 {
				return errors.New("you must specify a device-group when connected to a Panorama device")
			}
		}
	}

	return nil
}
