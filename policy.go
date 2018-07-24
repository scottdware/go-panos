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

type policyRules struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Rules   []Rule   `xml:"result>rules>entry"`
}

// Rule contains information about each individual security rule.
type Rule struct {
	Name                 string   `xml:"name,attr"`
	Tag                  []string `xml:"tag>member,omitempty"`
	From                 []string `xml:"from>member,omitempty"`
	To                   []string `xml:"to>member,omitempty"`
	Source               []string `xml:"source>member,omitempty"`
	Destination          []string `xml:"destination>member,omitempty"`
	SourceUser           []string `xml:"source-user>member,omitempty"`
	Application          []string `xml:"application>member,omitempty"`
	Service              []string `xml:"service>member,omitempty"`
	HIPProfiles          []string `xml:"hip-profiles>member,omitempty"`
	Category             []string `xml:"category>member,omitempty"`
	Action               string   `xml:"action,omitempty"`
	LogStart             string   `xml:"log-start,omitempty"`
	LogEnd               string   `xml:"log-end,omitempty"`
	LogSetting           string   `xml:"log-setting,omitempty"`
	Disabled             string   `xml:"disabled,omitempty"`
	URLFilteringProfile  string   `xml:"profile-setting>profiles>url-filtering>member,omitempty"`
	FileBlockingProfile  string   `xml:"profile-setting>profiles>file-blocking>member,omitempty"`
	AntiVirusProfile     string   `xml:"profile-setting>profiles>virus>member,omitempty"`
	AntiSpywareProfile   string   `xml:"profile-setting>profiles>spyware>member,omitempty"`
	VulnerabilityProfile string   `xml:"profile-setting>profiles>vulnerability>member,omitempty"`
	WildfireProfile      string   `xml:"profile-setting>profiles>wildfire-analysis>member,omitempty"`
	SecurityProfileGroup string   `xml:"profile-setting>group>member,omitempty"`
	Description          string   `xml:"description,omitempty"`
}

// RuleContent is used to hold the information that will be used
// to create a new rule
type RuleContent struct {
	// Name of the rule.
	Name string
	// Tag or tags that you want the rule to be a part of.
	Tag []string
	// The source zone. If you wish to use "any" for the value, please use []string{"any"}.
	From []string
	// The destination zone. If you wish to use "any" for the value, please use []string{"any"}.
	To []string
	// The source address. If you wish to use "any" for the value, please use []string{"any"}.
	Source []string
	// The destination address. If you wish to use "any" for the value, please use []string{"any"}.
	Destination []string
	// The source user or users. If you wish to use "any" for the value, please use []string{"any"}.
	SourceUser []string
	// The applications you want to include. If you wish to use "any" for the value, please use []string{"any"}.
	Application []string
	// The services you want to include. If you wish to use "any" for the value, please use []string{"any"}.
	Service []string
	// HIP profiles to check traffic against. If you wish to use "any" for the value, please use []string{"any"}.
	HIPProfiles []string
	// The URL category. If you wish to use "any" for the value, please use []string{"any"}.
	Category []string
	// The action you want to take on the rule.
	Action string
	// Log at session start.
	LogStart string
	// Log at session end.
	LogEnd string
	// The log setting, such as forwarding them to Panorama.
	LogSetting string
	// Disable the rule.
	Disabled string
	// URL filtering profile.
	URLFilteringProfile string
	// File blocking profile.
	FileBlockingProfile string
	// Antivirus profile.
	AntiVirusProfile string
	// Anti-spyware profile.
	AntiSpywareProfile string
	// Vulnderability profile.
	VulnerabilityProfile string
	// Wildfire profile.
	WildfireProfile string
	// Security profile group.
	SecurityProfileGroup string
	// Description (optional)
	Description string
}

// NATPolicy contains information about all of the NAT rules on the device.
type NATPolicy struct {
	XMLName xml.Name  `xml:"response"`
	Status  string    `xml:"status,attr"`
	Code    string    `xml:"code,attr"`
	Rules   []NATRule `xml:"result>rules>entry"`
}

// NATRule contains information about each individual NAT rule.
type NATRule struct {
	Name                            string   `xml:"name,attr"`
	From                            []string `xml:"from>member"`
	To                              []string `xml:"to>member"`
	Source                          []string `xml:"source>member"`
	Destination                     []string `xml:"destination>member"`
	Service                         []string `xml:"service>member"`
	SrcDynamicInterfaceIP           string   `xml:"source-translation>dynamic-ip-and-port>interface-address>ip"`
	SrcDynamicInterface             string   `xml:"source-translation>dynamic-ip-and-port>interface-address>interface"`
	SrcDynamicIPAndPortTranslatedIP string   `xml:"source-translation>dynamic-ip-and-port>translated-address>member"`
	SrcDynamicTranslatedIP          []string `xml:"source-translation>dynamic-ip>translated-address>member"`
	DestinationTransltedIP          string   `xml:"destination-translation>translated-address"`
	SrcStaticTranslatedIP           string   `xml:"source-translation>static-ip>translated-address"`
	BiDirectional                   string   `xml:"source-translation>static-ip>bi-directional"`
}

// Policy returns information about the security policies for the given device-group. If no device-group is specified
// then the local rules are returned when run against a firewall. If you have pre and/or post rules,
// then both of them will be returned. They are separated under a Pre and Post field in the returned Policy struct.
// Local rules are returned in the Local field.
func (p *PaloAlto) Policy(devicegroup ...string) (*Policy, error) {
	var policy Policy
	var prePolicy policyRules
	var postPolicy policyRules
	var localPolicy policyRules

	switch p.DeviceType {
	case "panos":
		xpath := "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules"

		if len(devicegroup[0]) > 0 {
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

// NATPolicy returns information about the NAT policy on a device.
func (p *PaloAlto) NATPolicy() (*NATPolicy, error) {
	var policy NATPolicy

	if p.DeviceType != "panos" {
		return nil, errors.New("you can only view NAT policies on a firewall")
	}

	xpath := "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/nat/rules"

	_, natPolicyData, errs := r.Get(p.URI).Query(fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", xpath, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(natPolicyData), &policy); err != nil {
		return nil, err
	}

	if policy.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", policy.Code, errorCodes[policy.Code])
	}

	if len(policy.Rules) == 0 {
		return nil, errors.New("there are no rules created")
	}

	return &policy, nil
}

// CreateRule will create a new rule on the device. If you are connected to a Panorama device, then
// you must specify the device-group as the last parameter. You do not need this when connected to
// a firewall.
//
// Ruletype must be one of:
//
// pre, post, local (only if used on a firewall)
//
// You will need to create the rules contents within the RuleContent struct. Please see the documentation
// for the struct on how to structure it.
func (p *PaloAlto) CreateRule(name, ruletype string, content *RuleContent, devicegroup ...string) error {
	var xmlBody string
	var reqError requestError
	var xpath string

	urlp := len(content.URLFilteringProfile)
	fp := len(content.FileBlockingProfile)
	wfp := len(content.WildfireProfile)
	avp := len(content.AntiVirusProfile)
	asp := len(content.AntiSpywareProfile)
	vp := len(content.VulnerabilityProfile)

	if p.DeviceType == "panos" {
		xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules/entry[@name='%s']", name)
	}

	if p.DeviceType == "panorama" && len(devicegroup) == 0 {
		return errors.New("you must specify a device-group when creating a rule on a Panorama device")
	}

	if len(devicegroup) > 0 {
		switch ruletype {
		case "pre":
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/pre-rulebase/security/rules/entry[@name='%s']", devicegroup[0], name)
		case "post":
			xpath = fmt.Sprintf("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/post-rulebase/security/rules/entry[@name='%s']", devicegroup[0], name)
		}
	}

	if len(content.Tag) > 0 {
		xmlBody += fmt.Sprintf("<tag>")
		for _, tag := range content.Tag {
			xmlBody += fmt.Sprintf("<member>%s</member>", tag)
		}
		xmlBody += fmt.Sprintf("</tag>")
	}

	xmlBody += fmt.Sprintf("<to>")
	for _, to := range content.To {
		xmlBody += fmt.Sprintf("<member>%s</member>", to)
	}
	xmlBody += fmt.Sprintf("</to>")

	xmlBody += fmt.Sprintf("<from>")
	for _, from := range content.From {
		xmlBody += fmt.Sprintf("<member>%s</member>", from)
	}
	xmlBody += fmt.Sprintf("</from>")

	xmlBody += fmt.Sprintf("<source>")
	for _, source := range content.Source {
		xmlBody += fmt.Sprintf("<member>%s</member>", source)
	}
	xmlBody += fmt.Sprintf("</source>")

	xmlBody += fmt.Sprintf("<destination>")
	for _, destination := range content.Destination {
		xmlBody += fmt.Sprintf("<member>%s</member>", destination)
	}
	xmlBody += fmt.Sprintf("</destination>")

	xmlBody += fmt.Sprintf("<source-user>")
	for _, srcuser := range content.SourceUser {
		xmlBody += fmt.Sprintf("<member>%s</member>", srcuser)
	}
	xmlBody += fmt.Sprintf("</source-user>")

	xmlBody += fmt.Sprintf("<category>")
	for _, category := range content.Category {
		xmlBody += fmt.Sprintf("<member>%s</member>", category)
	}
	xmlBody += fmt.Sprintf("</category>")

	xmlBody += fmt.Sprintf("<application>")
	for _, app := range content.Application {
		xmlBody += fmt.Sprintf("<member>%s</member>", app)
	}
	xmlBody += fmt.Sprintf("</application>")

	xmlBody += fmt.Sprintf("<service>")
	for _, service := range content.Service {
		xmlBody += fmt.Sprintf("<member>%s</member>", service)
	}
	xmlBody += fmt.Sprintf("</service>")

	xmlBody += fmt.Sprintf("<hip-profiles>")
	for _, hip := range content.HIPProfiles {
		xmlBody += fmt.Sprintf("<member>%s</member>", hip)
	}
	xmlBody += fmt.Sprintf("</hip-profiles>")

	xmlBody += fmt.Sprintf("<action>%s</action>", content.Action)

	if len(content.LogStart) > 0 {
		xmlBody += fmt.Sprintf("<log-start>%s</log-start>", content.LogStart)
	}

	if len(content.LogEnd) > 0 {
		xmlBody += fmt.Sprintf("<log-end>%s</log-end>", content.LogEnd)
	}

	if len(content.LogSetting) > 0 {
		xmlBody += fmt.Sprintf("<log-setting>%s</log-setting>", content.LogSetting)
	}

	if len(content.SecurityProfileGroup) > 0 {
		xmlBody += fmt.Sprintf("<profile-setting><group><member>%s</member></group></profile-setting>", content.SecurityProfileGroup)
	}

	if len(content.Description) > 0 {
		xmlBody += fmt.Sprintf("<description>%s</description>", content.Description)
	}

	if len(content.Disabled) > 0 {
		xmlBody += fmt.Sprintf("<disabled>%s</disabled>", content.Disabled)
	}

	if urlp > 0 || fp > 0 || wfp > 0 || avp > 0 || asp > 0 || vp > 0 {
		xmlBody += "<profile-setting><profiles>"

		if urlp > 0 {
			xmlBody += fmt.Sprintf("<url-filtering><member>%s</member></url-filtering>", content.URLFilteringProfile)
		}

		if fp > 0 {
			xmlBody += fmt.Sprintf("<file-blocking><member>%s</member></file-blocking>", content.FileBlockingProfile)
		}

		if wfp > 0 {
			xmlBody += fmt.Sprintf("<wildfire-analysis><member>%s</member></wildfire-analysis>", content.WildfireProfile)
		}

		if avp > 0 {
			xmlBody += fmt.Sprintf("<virus><member>%s</member></virus>", content.AntiVirusProfile)
		}

		if asp > 0 {
			xmlBody += fmt.Sprintf("<spyware><member>%s</member></spyware>", content.AntiSpywareProfile)
		}

		if vp > 0 {
			xmlBody += fmt.Sprintf("<vulnerability><member>%s</member></vulnerability>", content.VulnerabilityProfile)
		}

		xmlBody += "</profiles></profile-setting>"
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
