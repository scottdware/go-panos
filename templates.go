package panos

import (
	"encoding/xml"
	"errors"
	"fmt"

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
	Name    string   `xml:"name,attr"`
	Devices []Serial `xml:"devices>entry"`
}

// Templates returns information about all of the templates in Panorama, and what devices they are
// applied to.
func (p *PaloAlto) Templates() (*Templates, error) {
	var temps Templates
	xpath := "/config/devices/entry//template"
	// xpath := "/config/devices/entry/vsys/entry/address"
	r := rested.NewRequest()

	if p.DeviceType != "panorama" {
		return nil, errors.New("templates can only be listed from a Panorama device")
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
