## go-panos
[![GoDoc](https://godoc.org/github.com/scottdware/go-panos?status.svg)](https://godoc.org/github.com/scottdware/go-panos) [![Travis-CI](https://travis-ci.org/scottdware/go-panos.svg?branch=master)](https://travis-ci.org/scottdware/go-panos)
[![license](http://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://raw.githubusercontent.com/scottdware/go-panos/master/LICENSE)

A Go package that interacts with Palo Alto devices using their XML API. For official package documentation, please visit the [Godoc][godoc-go-panos] page.

This API allows you to do the following:

* List various types of objects: address, service, custom-url-category, device-groups, policies, tags, templates, managed devices (Panorama), etc..
* Create, rename, and delete objects
* Create multiple address objects at once by using a CSV file.
    * You can also specify which device-group you want the object to be created under.
* Create, apply, and remove tags from objects
* Edit/modify address, service groups and custom-url-categories
* Create templates, template stacks and assign devices and templates to them (Panorama)
* Commit configurations and commit to device-groups (Panorama)
* Apply a log forwarding or security profile to an entire policy or individual rules.
* Manipulate the configuration using Xpath functions.

The following features are currently available only on the local firewall:

* Create interfaces (including sub-interfaces), zones, vlans, virtual-wires, virtual-routers and static routes.
    * Delete operation on the above as well.
* Add and remove interfaces to zones, vlans and virtual-routers.
* Test URL's to see what they are being categorized under.
* Test route lookup.

### Installation

`go get -u github.com/scottdware/go-panos`

### Usage

`import "github.com/scottdware/go-panos"`

### Establishing A Session

There are two ways you can authenticate to a device: username and password, or using the API key. Here is an
example of both methods.

```Go
// Username and password
creds := panos.AuthMethod{
    Credentials: []string{"admin", "password"},
}

pan, err := panos.NewSession("pan-firewall.company.com", &creds)
if err != nil {
    fmt.Println(err)
}

// API key
creds := panos.AuthMethod{
    APIKey: "Awholemessofrandomcharactersandnumbers1234567890=",
}

pan, err := panos.NewSession("panorama.company.com", &creds)
if err != nil {
    fmt.Println(err)
}
```

### Configuration Using Xpath

Outside of the built in functions that make working with the configuration simpler, there are also functions that
allow you to modify any part of the configuration using Xpath. The following configuration actions are supported:

`show, get, set, edit, delete, rename, override, move, clone, multi-move, multi-clone`

> *NOTE*: For specific examples of how to use xpath values when using these actions, visit the [PAN-OS XML API configuration API][pan-xml-api-config].

The above actions are used in the following `go-panos` functions:

`XpathConfig(), XpathGetConfig(), XpathClone(), XpathMove(), XpathMulti()`

### Handling Shared objects on Panorama

By default, when you establish a session to a Panorama server, all object creation will be in the 
device-group you specify. If you want to create them as shared, you need to first tell your session
that shared objects will be preferred by doing the following:

```Go
// Establish a session
creds := panos.AuthMethod{
    Credentials: []string{"admin", "password"},
}

pan, err := panos.NewSession("panorama.company.com", &creds)
if err != nil {
    fmt.Println(err)
}

// Enable shared object creation
pan.SetShared(true)

// Create an address object
pan.CreateAddress("test-ipv4-obj", "ip", "1.1.1.2/32", "A test object")

// Turn off shared object creation
pan.SetShared(false)
```

### Examples

Establish a session to a Panorama device

```Go
creds := panos.AuthMethod{
    Credentials: []string{"admin", "password"},
}

pan, err := panos.NewSession("panorama.company.com", &creds)
if err != nil {
    fmt.Println(err)
}

// Add a device to Panorama.
pan.AddDevice("00102345678")

// Create a device-group on Panorama, and add the device from above.
pan.CreateDeviceGroup("Some-DeviceGroup", "", "00102345678")

// Create address objects from a CSV file. In the CSV file you can specify which device-group
// you want the addresses created under.
pan.CreateAddressFromCsv("addresses.csv")
```

[godoc-go-panos]: http://godoc.org/github.com/scottdware/go-panos
[license]: https://github.com/scottdware/go-panos/blob/master/LICENSE
[pan-xml-api-config]: https://www.paloaltonetworks.com/documentation/80/pan-os/xml-api/pan-os-xml-api-request-types/configuration-api
