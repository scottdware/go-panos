## go-panos
[![GoDoc](https://godoc.org/github.com/scottdware/go-panos?status.svg)](https://godoc.org/github.com/scottdware/go-panos) [![Travis-CI](https://travis-ci.org/scottdware/go-panos.svg?branch=master)](https://travis-ci.org/scottdware/go-panos) [![Go Report Card](https://goreportcard.com/badge/github.com/scottdware/go-panos)](https://goreportcard.com/report/github.com/scottdware/go-panos)

A Go package that interacts with Palo Alto devices using their XML API. For official and detailed package documentation, please visit the [Godoc][godoc-go-panos] page.

* [Installation](https://github.com/scottdware/go-panos#installation)
* [Establishing a session](https://github.com/scottdware/go-panos#establishing-a-session)
* [Configuring devices using Xpath](https://github.com/scottdware/go-panos#configuration-using-xpath)
* [Handling shared objects on Panorama](https://github.com/scottdware/go-panos#handling-shared-objects-on-panorama)
* [Retrieving logs](https://github.com/scottdware/go-panos#retrieving-logs)
* [Creating objects from a CSV file](https://github.com/scottdware/go-panos#creating-objects-from-a-csv-file)
* [Modifying groups from a CSV file](https://github.com/scottdware/go-panos#modifying-object-groups-from-a-csv-file)

---

This API allows you to do the following:

* List objects on devices: address, service, custom-url-category, device-groups (Panorama), policies, tags, templates, log forwarding profiles, security profile groups, managed devices (Panorama), etc..
* Retrieve information about all applications (predefined) or a single one.
* Create, rename, and delete objects.
* Create security rules.
* View jobs on a device.
* Query and retrieve the following log-types: `config`, `system`, `traffic`, `threat`, `wildfire`, `url`, `data`.
* Create multiple objects at once from a CSV file. You can also specify different device-groups you want the object to be created under (object overrides), as well as tag them.
* Modify address and service groups using a CSV file.
* Create, apply, and remove tags from objects and rules.
* Create EDL's (External Dynamic List).
* Add/remove objects from address/service groups and custom-url-categories.
* Create templates, template stacks and assign devices and templates to them (Panorama).
* Commit configurations and commit to device-groups (Panorama).
* Apply a log forwarding or security profile to an entire policy or individual rules.
* Manipulate any part the configuration using Xpath functions (advanced).

The following features are currently available only on the local firewall:

* List the NAT policy.
* View the entire routing table and details about each route.
* Gather information about each session in the session table.
* Get all of the interface information configured on a firewall.
* Create interfaces (including sub-interfaces), zones, vlans, virtual-wires, virtual-routers and static routes.
* Add and remove interfaces to zones, vlans and virtual-routers.
* List all configured IPSec VPN tunnels, gateways, and crypto profiles.
* Create IPSec VPN tunnels, gateways, and crypto profiles.
* Add/delete proxy-id's to IPSec VPN tunnels.
* Test URL's to see what they are being categorized under.
* Test route lookup.

## Installation

`go get -u github.com/scottdware/go-panos`

##### Usage

`import "github.com/scottdware/go-panos"`

## Establishing A Session

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

The moment you establish a successful connection to the device, various information and statistics are gathered. They are
assigned to a field in the [Palo Alto][paloalto-struct] struct (click the link for the list of fields), and can then be iterated over.

```Go
// View the device's uptime
fmt.Println(pan.Uptime)

// View the device's application and threat version, as well as when they were released
fmt.Printf("App Version: %s (Released: %s)\n", pan.AppVersion, pan.AppReleaseDate)
fmt.Printf("Threat Version: %s (Released: %s)\n", pan.ThreatVersion, pan.ThreatReleaseDate)
```

## Configuration Using Xpath

Outside of the built in functions that make working with the configuration simpler, there are also functions that
allow you to modify any part of the configuration using Xpath. The following configuration actions are supported:

`show, get, set, edit, delete, rename, override, move, clone, multi-move, multi-clone`

> *NOTE*: For specific examples of how to use xpath values when using these actions, visit the [PAN-OS XML API configuration API][pan-xml-api-config].

The above actions are used in the following `go-panos` functions:

`XpathConfig()` | `XpathGetConfig()` | `XpathClone()` | `XpathMove()` | `XpathMulti()`
:---: | :---: | :---: | :---: | :---:
`set`, `edit`, `delete`, `rename`, `override` | `show/get` active or candidate configuration | `clone` | `move` | `multi-move`, `multi-clone`

> **_<span style="color:red">NOTE</span>_**: These functions are more suited for "power users," as there is a lot more that you have to know in regards to
Xpath and XML, as well as knowing how the PANOS XML is structured.

## Handling Shared objects on Panorama

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

## Retrieving Logs

You can retrieve logs from any Palo Alto device using the `QueryLogs()` and `RetrieveLogs()` functions. The `QueryLogs()` function is used to first
specify what type of log you want to retrieve, as well as any optional parameters such as a query: `(addr.src in 10.1.1.1) and (port.dst eq 443)`. These
optional parameters are defined using the `LogParameters` struct.

When you run the `QueryLogs()` function, it will return a job ID. This job ID is then used by `RetrieveLogs()` to query the system to see if the job has
completed, and the data is ready to be exported. If the job status is not `FIN` then you will need to run `RetrieveLogs()` again until it has finished.

> **_<span style="color:red">NOTE</span>_**: In regards to how long you should wait to run `RetrieveLogs()`, I have tested a query against a lot of data, both on Panorama and a local firewall,
and waited up to 2 minutes before retrieving them. Most times, you will get results within 5-10 seconds depending on your query.

View the documentation for the [LogParameters][log-parameters-struct] struct.

When iterating over the returned logs, there are many fields you can choose to display. View the documentation for the [Log][log-struct] struct fields for
a complete list.

Below is an example of how to retrieve traffic logs.

```Go
// Establish a session
creds := &panos.AuthMethod{
    Credentials: []string{"admin", "password"},
}

pan, err := panos.NewSession("panorama.company.com", creds)
if err != nil {
    fmt.Println(err)
}

// Query traffic logs for a specific source address, and return 20 logs.
params := &panos.LogParameters{
    Query: "(addr.src in 10.1.1.1) and (app eq ssl)",
    NLogs: 20,
}

jobID, err := pan.QueryLogs("traffic", params)
if err != nil {
    fmt.Println(err)
}

// Wait 5 seconds before retrieving the logs. If the job still has not finished, then you will have to 
// run this same function again until it does.
time.Sleep(5 * time.Second)

logs, err := pan.RetrieveLogs(jobID)
if err != nil {
    fmt.Println(err)
}

// Here, we are looping over every log returned, and just printing out the data. You can manipulate the data and
// choose to display any field that you want.
for _, log := range log.Logs {
    fmt.Printf("%+v\n", log)
}
```

## Creating Objects from a CSV File

This example shows you how to create multiple address and service objects, as well as address and service groups using a CSV file. You can also do object overrides by creating an object in a parent device-group, then creating the same object in a child device-group with a different value. Tagging objects upon creation is supported as well.

The CSV file should be organized with the following columns:

`name,type,value,description (optional),tag (optional),device-group`.

> **_<span style="color:red">NOTE</span>_**: Here are a few things to keep in mind when creating objects:
> * For the name of the object, it cannot be longer than 63 characters, and must only include letters, numbers, spaces, hyphens, and underscores.
> * If you are tagging an object upon creation, please make sure that the tags exist prior to creating the objects.
> * When creating service groups, you DO NOT need to specify a description, as they do not have that capability.
> * When you create address or service groups, I would place them at the bottom of the CSV file, that way you don't risk adding a member that doesn't exist.
> * When creating objects on a local firewall, and not Panorama, you can leave the device-group column blank.

#### Creating Address Objects
When creating address objects:

Column | Description
:--- | :---
`name` | Name of the object you wish to create.
`type` | **ip**, **range**, or **fqdn**
`value` | Must contain the IP address, FQDN, or IP range of the object.
`description` | (Optional) A description of the object.
`tag` | (Optional) Name of a pre-existing tag on the device to apply.
`device-group` | Name of the device-group, or **shared** if creating a shared object.

When creating address groups:

Column | Description
:--- | :---
`name` | Name of the address group you wish to create.
`type` | **static** or **dynamic**
`value` | * See below explanation
`description` | (Optional) A description of the object.
`tag` | (Optional) Name of a pre-existing tag on the device to apply.
`device-group` | Name of the device-group, or **shared** if creating a shared object.

For a **_static_** address group, `value` must contain a comma-separated list of members to add to the group, enclosed in quotes `""`, e.g.:

`"ip-host1, ip-net1, fqdn-example.com"`

For a **_dynamic_** address group, `value` must contain the criteria (tags) to match on. This **_MUST_** be enclosed in quotes `""`, and
each criteria (tag) must be surrounded by single-quotes `'`, e.g.:

`"'web-servers' or 'db-servers' and 'linux'"`

#### Creating Service Objects
When creating service objects:

Column | Description
:--- | :---
`name` | Name of the object you wish to create.
`type` | **tcp** or **udp**
`value` | * See below
`description` | (Optional) A description of the object.
`tag` | (Optional) Name of a pre-existing tag on the device to apply.
`device-group` | Name of the device-group, or **shared** if creating a shared object.

* `value` must contain a single port number, range (1023-3000), or comma-separated list of ports, enclosed in quotes `""` and separated by a comma, e.g.: `"80, 443, 2000"`.

When creating service groups:

Column | Description
:--- | :---
`name` | Name of the object you wish to create.
`type` | **service**
`value` | * See below
`description` | Not available on service groups.
`tag` | (Optional) Name of a pre-existing tag on the device to apply.
`device-group` | Name of the device-group, or **shared** if creating a shared object.

* `value` must contain a comma-separated list of service objects to add to the group, enclosed in quotes `""`, e.g.: `"tcp_8080, udp_666, tcp_range"`.

#### Example
*__Address Object Creation on Panorama__*

Let's assume we have a CSV file called `objects.csv` that looks like the following:

![alt-text](https://raw.githubusercontent.com/scottdware/images/master/csv.PNG "objects.csv")

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
is a child of the `Vader` device-group, but needs to have a different IP address assigned to the `web-server` object. This is visible by the override green/yellow icon next to the `web-server` object name.

![alt-text](https://raw.githubusercontent.com/scottdware/images/master/override.PNG "Vader device-group")

## Modifying Object Groups from a CSV File

This example shows you how to modify address and service group objects using a CSV file.

The CSV file should be organized with the following columns:

`grouptype,action,object-name,group-name,device-group`.

Column | Description
:--- | :---
`grouptype` | **address** or **service**
`action` | **add** or **remove**
`object-name` | Name of the object to add or remove from group.
`group-name` | Name of the group to modify.
`device-group` | Name of the device-group, or **shared** if creating a shared object.

#### Example
*__Group Modification on a Local Firewall__*

Let's assume we have a CSV file called `modify.csv` that looks like the following:

![alt-text](https://raw.githubusercontent.com/scottdware/images/master/modify_csv.PNG "modify.csv")

Running the below code against a firewall will modify the groups either adding or removing objects that you specified.

```Go
// Connect to Panorama
creds := &panos.AuthMethod{
    Credentials: []string{"admin", "password"},
}

pan, err := panos.NewSession("firewall.company.com", creds)
if err != nil {
    fmt.Println(err)
}

pan.ModifyGroupsFromCsv("modify.csv")
```

Here is what the address group `home_lab_group` looks like before and after running the above script.

![alt-text](https://raw.githubusercontent.com/scottdware/images/master/address_group.PNG "Address group prior to change")

![alt-text](https://raw.githubusercontent.com/scottdware/images/master/modified_address_group.PNG "Address group after change")

Here is what the service group `tcp_services` looks like before and after running the above script.

![alt-text](https://raw.githubusercontent.com/scottdware/images/master/service_group.PNG "Service group prior to change")

![alt-text](https://raw.githubusercontent.com/scottdware/images/master/modified_service_group.PNG "Service group after change")

[godoc-go-panos]: http://godoc.org/github.com/scottdware/go-panos
[license]: https://github.com/scottdware/go-panos/blob/master/LICENSE
[pan-xml-api-config]: https://www.paloaltonetworks.com/documentation/80/pan-os/xml-api/pan-os-xml-api-request-types/configuration-api
[log-parameters-struct]: http://godoc.org/github.com/scottdware/go-panos#LogParameters
[log-struct]: http://godoc.org/github.com/scottdware/go-panos#Log
[paloalto-struct]: http://godoc.org/github.com/scottdware/go-panos#PaloAlto
