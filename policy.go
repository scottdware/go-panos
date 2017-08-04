package panos

import (
	"encoding/xml"
	"errors"
	"fmt"
)

// Policy lists all of the security rules for a given device-group.
type Policy struct {
	Pre  []Rule
	Post []Rule
}

// prePolicy lists all of the pre-rulebase security rules for a given device-group.
type prePolicy struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Rules   []Rule   `xml:"result>rules>entry"`
}

// postPolicy lists all of the post-rulebase security rules for a given device-group.
type postPolicy struct {
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
	Category             []string `xml:"category>member"`
	Action               string   `xml:"action"`
	LogStart             string   `xml:"log-start"`
	LogEnd               string   `xml:"log-end"`
	Tag                  []string `xml:"tag>member"`
	LogSetting           string   `xml:"log-setting"`
	URLFilteringProfile  string   `xml:"profile-setting>profiles>url-filtering>member"`
	FileBlockingProfile  string   `xml:"profile-setting>profiles>file-blocking>member"`
	AntiVirusProfile     string   `xml:"profile-setting>profiles>virus>member"`
	AntiSpywareProfile   string   `xml:"profile-setting>profiles>spyware>member"`
	VulnerabilityProfile string   `xml:"profile-setting>profiles>vulnerability>member"`
	WildfireProfile      string   `xml:"profile-setting>profiles>wildfire-analysis>member"`
	SecurityProfileGroup string   `xml:"profile-setting>group>member"`
}

// Policy returns information about the security policies for the given device-group. If you have pre and/or post rules,
// then both of them will be returned. They are separated under a "Pre" and "Post" field in the returned "Policy" struct.
func (p *PaloAlto) Policy(devicegroup string) (*Policy, error) {
	var policy Policy
	var prePolicy prePolicy
	var postPolicy postPolicy
	preXpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/pre-rulebase/security/rules", devicegroup)
	postXpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/post-rulebase/security/rules", devicegroup)

	// if p.DeviceType == "panos" && len(devicegroup) > 0 {
	// 	return nil, errors.New("you do not need to specify a device-group when connected to a non-Panorama device")
	// }

	if p.DeviceType == "panos" {
		return nil, errors.New("you must be connected to a Panorama device to view policies")
	}

	if p.DeviceType == "panorama" && len(devicegroup) == 0 {
		return nil, errors.New("you must specify a device-group when viewing policies on a Panorama device")
	}

	// if p.DeviceType == "panos" && rulebase == "pre" {
	// 	xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/pre-rulebase/security/rules"
	// }

	// if p.DeviceType == "panos" && rulebase == "post" {
	// 	xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/post-rulebase/security/rules"
	// }

	_, prePolicyData, errs := r.Get(p.URI).Query(fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", preXpath, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(prePolicyData), &prePolicy); err != nil {
		return nil, err
	}

	_, postPolicyData, errs := r.Get(p.URI).Query(fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", postXpath, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(postPolicyData), &postPolicy); err != nil {
		return nil, err
	}

	// if p.DeviceType == "panos" && len(policy.Rules) == 0 {
	// 	return nil, errors.New("there are no rules created")
	// }

	if len(prePolicy.Rules) == 0 && len(postPolicy.Rules) == 0 {
		return nil, fmt.Errorf("there are no rules created, or the device-group %s does not exist", devicegroup)
	}

	if prePolicy.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", prePolicy.Code, errorCodes[prePolicy.Code])
	}

	if postPolicy.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", postPolicy.Code, errorCodes[postPolicy.Code])
	}

	policy.Pre = prePolicy.Rules
	policy.Post = postPolicy.Rules

	return &policy, nil
}
