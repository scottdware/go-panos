## go-panos
[![GoDoc](https://godoc.org/github.com/scottdware/go-panos?status.svg)](https://godoc.org/github.com/scottdware/go-panos) [![Travis-CI](https://travis-ci.org/scottdware/go-panos.svg?branch=master)](https://travis-ci.org/scottdware/go-panos) [![Go Report Card](https://goreportcard.com/badge/github.com/scottdware/go-panos)](https://goreportcard.com/report/github.com/scottdware/go-panos)

A Go package that interacts with Palo Alto devices using their XML API. For official package documentation, please visit the [Godoc][godoc-go-panos] page.

This API allows you to do the following:

* List various types of objects: address, service, custom-url-category, device-groups, policies, tags, templates, log forwarding profiles, security profile groups, managed devices (Panorama), etc..
* Create, rename, and delete objects.
* View the jobs on a device.
* Create multiple address objects (including groups) at once by using a CSV file. You can also specify different device-groups you want the object to be created under, as well as tag them.
* Create, apply, and remove tags from objects
* Edit/modify address, service groups and custom-url-categories
* Create templates, template stacks and assign devices and templates to them (Panorama)
* Commit configurations and commit to device-groups (Panorama)
* Apply a log forwarding or security profile to an entire policy or individual rules.
* Manipulate any part the configuration using Xpath functions (advanced).

The following features are currently available only on the local firewall:

* Create interfaces (including sub-interfaces), zones, vlans, virtual-wires, virtual-routers and static routes.
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
creds := &panos.AuthMethod{
    Credentials: []string{"admin", "password"},
}

pan, err := panos.NewSession("pan-firewall.company.com", creds)
if err != nil {
    fmt.Println(err)
}

// API key
creds := &panos.AuthMethod{
    APIKey: "Awholemessofrandomcharactersandnumbers1234567890=",
}

pan, err := panos.NewSession("panorama.company.com", creds)
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

`XpathConfig()` | `XpathGetConfig()` | `XpathClone()` | `XpathMove()` | `XpathMulti()`
:---: | :---: | :---: | :---: | :---:
`set`, `edit`, `delete`, `rename`, `override` | `show`, `get` | `clone` | `move` | `multi-move`, `multi-clone`

> *NOTE*: These functions are more suited for "power users," as there is a lot more that you have to know in regards to
Xpath and XML, as well as knowing how the PANOS XML is structured.

### Handling Shared objects on Panorama

By default, when you establish a session to a Panorama server, all object creation will be in the 
device-group you specify. If you want to create them as shared, you need to first tell your session
that shared objects will be preferred by doing the following:

```Go
// Establish a session
creds := &panos.AuthMethod{
    Credentials: []string{"admin", "password"},
}

pan, err := panos.NewSession("panorama.company.com", creds)
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

**Establish a session to a Panorama device**

```Go
creds := &panos.AuthMethod{
    Credentials: []string{"admin", "password"},
}

pan, err := panos.NewSession("panorama.company.com", creds)
if err != nil {
    fmt.Println(err)
}

// Add a device to Panorama.
pan.AddDevice("00102345678")

// Create a device-group on Panorama, and add the device from above.
pan.CreateDeviceGroup("Some-DeviceGroup", "", "00102345678")
```

**Creating Address Objects via CSV**

This example shows you how to create multiple address and address group objects using a CSV file. You can also do object overrides
by creating an object in a parent device-group, then creating the same object in a child device-group. Tagging
objects upon creation is supported as well.

The CSV file should be organized with the following columns: `name, type, address, description (optional), tag (optional), device-group`.

If you are tagging an object upon creation, please make sure that the tags exist prior to creating the objects.

If you are creating address objects, the `type` field can be one of: `ip`, `range`, or `fqdn`. When creating address groups, the `type` field
must be either `static` or `dynamic`. The `address` field differs for either of those options as well.

For a static address group, `address` must contain a list of members to add to the group, separated by a space, i.e.: `ip-host1 ip-net1 fqdn-example.com`.
For a dynamic address group, `address` must contain the criteria (tags) to match on, i.e.: `web-servers or db-servers and linux`

Let's assume we have a CSV file called `objects.csv` that looks like the following:

![alt-text](https://raw.githubusercontent.com/scottdware/images/master/csv.PNG "objects.csv")

<!-- ```
web-server,ip,10.255.255.1,,,Vader
file-server-shared,ip,1.1.1.1,,,shared
server-net-shared,ip,2.2.2.0/24,,,shared
vm-host,fqdn,server.company.com,,jedi,Vader
pc-net-range-shared,range,1.1.1.10-1.1.1.20,,,shared
db-server,ip,10.1.1.1,,,Vader
web-server,ip,5.5.5.5,,,Luke
server-network,ip,3.3.3.0/24,,,Vader
internet-access-group,static,web-server vm-host,,,Vader
block-bad-hosts,dynamic,bad-host or bad-site,,,Vader
data-centers,static,file-server-shared server-net-shared pc-net-range-shared,,,shared
``` -->

Running the below code against a Panorama device will create the objects above.

```Go
// Connect to Panorama
creds := &panos.AuthMethod{
    Credentials: []string{"admin", "password"},
}

pan, err := panos.NewSession("panorama.company.com", creds)
if err != nil {
    fmt.Println(err)
}

pan.CreateObjectsFromCsv("objects.csv")
```

If we take a look at Panorama, and view the `Vader` device-group address objects, we can see all of our objects:

![alt-text](https://raw.githubusercontent.com/scottdware/images/master/addresses.PNG "Vader device-group")

And here are our address group objects:

![alt-text](https://raw.githubusercontent.com/scottdware/images/master/address-groups.PNG "Vader device-group")

We specified a `web-server` address object in the `Vader` device-group, as well as a `web-server` address object in the `Luke` device-group. This is an example of how you do object overrides. The `Luke` device-group
is a child of the `Vader` device-group, but needs to have a different IP address assigned to the `web-serve` object. This is visible by the override green/yellow icon next to the `web-server` object name.

![alt-text](https://raw.githubusercontent.com/scottdware/images/master/override.PNG "Vader device-group")


[godoc-go-panos]: http://godoc.org/github.com/scottdware/go-panos
[license]: https://github.com/scottdware/go-panos/blob/master/LICENSE
[pan-xml-api-config]: https://www.paloaltonetworks.com/documentation/80/pan-os/xml-api/pan-os-xml-api-request-types/configuration-api
