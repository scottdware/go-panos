package panos

import (
	"encoding/xml"
	"errors"
	"fmt"
)

// Policy lists all of the security rules for a given device-group, or the local rules on a firewall.
// The IncludedRules field contains information about which rules are defined. The values are as follows:
//
// pre, post, both, local
//
// If both is present, then the policy contains pre and post rules.
type Policy struct {
	IncludedRules string
	Pre           []Rule
	Post          []Rule
	Local         []Rule
}

// prePolicy lists all of the pre-rulebase security rules for a given device-group.
// type prePolicy struct {
// 	XMLName xml.Name `xml:"response"`
// 	Status  string   `xml:"status,attr"`
// 	Code    string   `xml:"code,attr"`
// 	Rules   []Rule   `xml:"result>rules>entry"`
// }

// postPolicy lists all of the post-rulebase security rules for a given device-group.
// type postPolicy struct {
// 	XMLName xml.Name `xml:"response"`
// 	Status  string   `xml:"status,attr"`
// 	Code    string   `xml:"code,attr"`
// 	Rules   []Rule   `xml:"result>rules>entry"`
// }

type policyRules struct {
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
	HIPProfiles          []string `xml:"hip-profiles>member"`
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

// Policy returns information about the security policies for the given device-group. If no device-group is specified
// then the local rules are returned when run against a fireall. If you have pre and/or post rules,
// then both of them will be returned. They are separated under a "Pre" and "Post" field in the returned "Policy" struct.
// Local rules are returned in the "Local" field.
func (p *PaloAlto) Policy(devicegroup ...string) (*Policy, error) {
	var policy Policy
	var prePolicy policyRules
	var postPolicy policyRules
	var localPolicy policyRules

	switch p.DeviceType {
	case "panos":
		xpath := "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules"

		if len(devicegroup) == 0 {
			return nil, errors.New("you do not need to specify a device-group when connected to a fireawll")
		}

		_, localPolicyData, errs := r.Get(p.URI).Query(fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", xpath, p.Key)).End()
		if errs != nil {
			return nil, errs[0]
		}

		if err := xml.Unmarshal([]byte(localPolicyData), &localPolicy); err != nil {
			return nil, err
		}

		if localPolicy.Status != "success" {
			return nil, fmt.Errorf("error code %s: %s", localPolicy.Code, errorCodes[localPolicy.Code])
		}

		if len(localPolicy.Rules) == 0 {
			return nil, errors.New("there are no rules created")
		}

		policy.IncludedRules = "local"
		policy.Local = localPolicy.Rules
	case "panorama":
		if len(devicegroup) == 0 {
			return nil, errors.New("you must specify a device-group when viewing policies on a Panorama device")
		}

		preXpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/pre-rulebase/security/rules", devicegroup[0])
		postXpath := fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/post-rulebase/security/rules", devicegroup[0])

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

		if len(prePolicy.Rules) == 0 && len(postPolicy.Rules) == 0 {
			return nil, fmt.Errorf("there are no rules created, or the device-group %s does not exist", devicegroup[0])
		}

		if len(prePolicy.Rules) > 0 && len(postPolicy.Rules) > 0 {
			policy.IncludedRules = "both"
		}

		if len(prePolicy.Rules) > 0 && len(postPolicy.Rules) == 0 {
			policy.IncludedRules = "pre"
		}

		if len(prePolicy.Rules) == 0 && len(postPolicy.Rules) > 0 {
			policy.IncludedRules = "post"
		}

		if prePolicy.Status != "success" {
			return nil, fmt.Errorf("error code %s: %s", prePolicy.Code, errorCodes[prePolicy.Code])
		}

		if postPolicy.Status != "success" {
			return nil, fmt.Errorf("error code %s: %s", postPolicy.Code, errorCodes[postPolicy.Code])
		}

		policy.Pre = prePolicy.Rules
		policy.Post = postPolicy.Rules
	}

	return &policy, nil
}
