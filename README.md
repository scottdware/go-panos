## go-panos
[![GoDoc](https://godoc.org/github.com/scottdware/go-panos?status.svg)](https://godoc.org/github.com/scottdware/go-panos) [![Travis-CI](https://travis-ci.org/scottdware/go-panos.svg?branch=master)](https://travis-ci.org/scottdware/go-panos)
[![license](http://img.shields.io/badge/license-MIT-red.svg?style=flat)](https://raw.githubusercontent.com/scottdware/go-panos/master/LICENSE)

A Go package that interacts with Palo Alto and Panorama devices using the XML API. For official package documentation, visit the [GoDoc][godoc-go-panos] page.

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
* Add and remove proxy-id's to VPN tunnels.

[godoc-go-panos]: http://godoc.org/github.com/scottdware/go-panos
[license]: https://github.com/scottdware/go-panos/blob/master/LICENSE
