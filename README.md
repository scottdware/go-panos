## go-panos
[![GoDoc](https://godoc.org/github.com/scottdware/go-panos?status.svg)](https://godoc.org/github.com/scottdware/go-panos) [![Travis-CI](https://travis-ci.org/scottdware/go-panos.svg?branch=master)](https://travis-ci.org/scottdware/go-panos)
[![license](http://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://raw.githubusercontent.com/scottdware/go-panos/master/LICENSE)

A Go package that interacts with Palo Alto devices using their XML API. For official package documentation, please visit the [GoDoc][godoc-go-panos] page.

This API allows you to do the following:

* List various types of objects: address, service, custom-url-category, device-groups, policies, tags, templates, managed devices (Panorama), etc..
* Create, rename, and delete objects
* Create address objects by using a .csv file.
* Create, apply, and remove tags from objects
* Edit/modify address, service groups and custom-url-categories
* Create templates, template stacks and assign devices, templates to them (Panorama)
* Commit configurations and commit to device-groups (Panorama)
* Apply a log forwarding or security profile to an entire policy.

The following features are currently available only on the local device:

* Create layer-3 interfaces (including sub-interfaces), zones, virtual-routers and static routes.
* Assign and remove interfaces to zones and virtual-routers.
* Delete interfaces, zones, virtual-routers and static routes.
* Test URL's to see what they are being categorized under.
* Test route lookup.

### Installation

`go get -u github.com/scottdware/go-panos`

### Example

Establish a session to a Panorama device

```Go
pan, err := panos.NewSession("panorama.company.com", "admin", "paloalto")
if err != nil {
    fmt.Println(err)
}

// Add a device to Panorama.
pan.AddDevice("00102345678")

// Create a device-group on Panorama, and add the device from above.
pan.CreateDeviceGroup("Some-DeviceGroup", "", "00102345678")

// Create address objects from a csv file within our device-group we added above.
pan.CreateAddressFromCsv("addresses.csv", false, "Some-DeviceGroup")

//
```

[godoc-go-panos]: http://godoc.org/github.com/scottdware/go-panos
[license]: https://github.com/scottdware/go-panos/blob/master/LICENSE
