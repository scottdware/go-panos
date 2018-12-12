// Package panos interacts with Palo Alto and Panorama devices using the XML API.
package panos

import (
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/parnurzeal/gorequest"
)

// PaloAlto is a container for our session state. It also holds information about the device
// that is gathered upon a successful connection to it.
type PaloAlto struct {
	Host                       string
	Key                        string
	URI                        string
	Platform                   string
	Model                      string
	Serial                     string
	SoftwareVersion            string
	DeviceType                 string
	Panorama                   bool
	Shared                     bool
	IPAddress                  string
	Netmask                    string
	DefaultGateway             string
	MACAddress                 string
	Time                       string
	Uptime                     string
	GPClientPackageVersion     string
	GPDatafileVersion          string
	GPDatafileReleaseDate      string
	GPClientlessVPNVersion     string
	GPClientlessVPNReleaseDate string
	AppVersion                 string
	AppReleaseDate             string
	AntiVirusVersion           string
	AntiVirusReleaseDate       string
	ThreatVersion              string
	ThreatReleaseDate          string
	WildfireVersion            string
	WildfireReleaseDate        string
	URLDB                      string
	URLFilteringVersion        string
	LogDBVersion               string
	MultiVsys                  string
	OperationalMode            string
}

// AuthMethod defines how we want to authenticate to the device. If using a
// username and password to authenticate, the Credentials field must contain the username and password
//, respectively (e.g. []string{"admin", "password"}). If you are using the API key for
// authentication, provide the entire key for the APIKey field.
type AuthMethod struct {
	Credentials []string
	APIKey      string
}

// Jobs holds information about all jobs on the device.
type Jobs struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Jobs    []Job    `xml:"result>job"`
}

// Job holds information about each individual job.
type Job struct {
	ID            int      `xml:"id"`
	User          string   `xml:"user"`
	Type          string   `xml:"type"`
	Status        string   `xml:"status"`
	Queued        string   `xml:"queued"`
	Stoppable     string   `xml:"stoppable"`
	Result        string   `xml:"result"`
	Description   string   `xml:"description,omitempty"`
	QueuePosition int      `xml:"positionInQ"`
	Progress      string   `xml:"progress"`
	Details       []string `xml:"details>line"`
	Warnings      string   `xml:"warnings,omitempty"`
	StartTime     string   `xml:"tdeq"`
	EndTime       string   `xml:"tfin"`
}

// Logs holds all of the log data retrieved from querying the system.
type Logs struct {
	XMLName   xml.Name `xml:"response"`
	Status    string   `xml:"status,attr"`
	Code      string   `xml:"code,attr"`
	StartTime string   `xml:"result>job>tdeq"`
	EndTime   string   `xml:"result>job>tfin"`
	JobStatus string   `xml:"result>job>status"`
	JobID     int      `xml:"result>job>id"`
	Logs      []Log    `xml:"result>log>logs>entry"`
}

// Log holds information about each individual log retrieved for the following log-types:
//
// config, system, traffic, threat, wildfire, url, data
//
// Certain fields are omitted or populated based on the log type that is specified when querying the system. See https://goo.gl/PPLjVZ for the
// fields assigned for the different log types.
type Log struct {
	DeviceName                 string `xml:"device_name,omitempty"`
	Serial                     string `xml:"serial,omitempty"`
	Rule                       string `xml:"rule,omitempty"`
	TimeGenerated              string `xml:"time_generated,omitempty"`
	TimeReceived               string `xml:"time_received,omitempty"`
	Type                       string `xml:"type,omitempty"`
	Subtype                    string `xml:"subtype,omitempty"`
	From                       string `xml:"from,omitempty"`
	To                         string `xml:"to,omitempty"`
	Source                     string `xml:"src,omitempty"`
	SourceUser                 string `xml:"srcuser,omitempty"`
	SourcePort                 int    `xml:"sport,omitempty"`
	SourceCountry              string `xml:"srcloc,omitempty"`
	Destination                string `xml:"dst,omitempty"`
	DestinationPort            int    `xml:"dport,omitempty"`
	DestinationCountry         string `xml:"dstloc,omitempty"`
	Application                string `xml:"app,omitempty"`
	Action                     string `xml:"action,omitempty"`
	NATSourceIP                string `xml:"natsrc,omitempty"`
	NATSourcePort              int    `xml:"natsport,omitempty"`
	NATDestinationIP           string `xml:"natdst,omitempty"`
	NATDestinationPort         int    `xml:"natdport,omitempty"`
	Packets                    int    `xml:"packets,omitempty"`
	PacketsSent                int    `xml:"pkts_sent,omitempty"`
	PacketsReceived            int    `xml:"pkts_received,omitempty"`
	Bytes                      int    `xml:"bytes,omitempty"`
	BytesSent                  int    `xml:"bytes_sent,omitempty"`
	BytesReceived              int    `xml:"bytes_received,omitempty"`
	SessionID                  int    `xml:"sessionid,omitempty"`
	SessionEndReason           string `xml:"session_end_reason,omitempty"`
	RepeatCount                int    `xml:"repeatcnt,omitempty"`
	Start                      string `xml:"start,omitempty"`
	Elapsed                    string `xml:"elapsed,omitempty"`
	Category                   string `xml:"category,omitempty"`
	ThreatCategory             string `xml:"thr_category,omitempty"`
	ThreatName                 string `xml:"threatid,omitempty"`
	ThreatID                   int    `xml:"tid,omitempty"`
	Misc                       string `xml:"misc,omitempty"`
	Severity                   string `xml:"severity,omitempty"`
	Direction                  string `xml:"direction,omitempty"`
	InboundInterface           string `xml:"inbound_if,omitempty"`
	OutboundInterface          string `xml:"outbound_if,omitempty"`
	ID                         int    `xml:"logid,attr"`
	Domain                     int    `xml:"domain,omitempty"`
	ReceiveTime                string `xml:"receive_time,omitempty"`
	SequenceNumber             string `xml:"seqno,omitempty"`
	ActionFlags                string `xml:"actionflags,omitempty"`
	ConfigVersion              int    `xml:"config_ver,omitempty"`
	Vsys                       string `xml:"vsys,omitempty"`
	Logset                     string `xml:"logset,omitempty"`
	Flags                      string `xml:"flags,omitempty"`
	Pcap                       string `xml:"flag-pcap,omitempty"`
	PcapID                     int    `xml:"pcap_id,omitempty"`
	Flagged                    string `xml:"flag-flagged,omitempty"`
	Proxy                      string `xml:"flag-proxy,omitempty"`
	URLDenied                  string `xml:"flag-url-denied,omitempty"`
	NAT                        string `xml:"flag-nat,omitempty"`
	CaptivePortal              string `xml:"captive-portal"`
	NonStandardDestinationPort string `xml:"non-std-dport"`
	Transaction                string `xml:"transaction,omitempty"`
	PBFClient2Server           string `xml:"pbf-c2s,omitempty"`
	PBFServer2Client           string `xml:"pbf-s2c,omitempty"`
	TemporaryMatch             string `xml:"temporary-match,omitempty"`
	SymmetricReturn            string `xml:"sym-return,omitempty"`
	SSLDecryptMirror           string `xml:"decrypt-mirror,omitempty"`
	CredentialDetected         string `xml:"credential-detected,omitempty"`
	MPTCP                      string `xml:"flag-mptcp-set,omitempty"`
	TunnelInspected            string `xml:"flag-tunnel-inspected,omitempty"`
	ReconExcluded              string `xml:"flag-recon-excluded,omitempty"`
	Protocol                   string `xml:"proto,omitempty"`
	TunnelType                 string `xml:"tunnel,omitempty"`
	TPadding                   int    `xml:"tpadding,omitempty"`
	CPadding                   int    `xml:"cpadding,omitempty"`
	TunnelIMSI                 int    `xml:"tunnelid_imsi,omitempty"`
	VsysID                     int    `xml:"vsys_id,omitempty"`
	ParentSessionID            int    `xml:"parent_session_id,omitempty"`
	ReportID                   int    `xml:"reportid,omitempty"`
	URLIndex                   int    `xml:"url_idx,omitempty"`
	HTTPMethod                 string `xml:"http_method,omitempty"`
	XForwardedFor              string `xml:"xff,omitempty"`
	Referer                    string `xml:"referer,omitempty"`
	UserAgent                  string `xml:"user_agent,omitempty"`
	SignatureFlags             string `xml:"sig_flags,omitempty"`
	ContentVersion             string `xml:"contentver,omitempty"`
	FileDigest                 string `xml:"filedigest,omitempty"`
	Filetype                   string `xml:"filetype,omitempty"`
	Sender                     string `xml:"sender,omitempty"`
	Recipient                  string `xml:"recipient,omitempty"`
	Subject                    string `xml:"subject,omitempty"`
	Cloud                      string `xml:"cloud,omitempty"`
	Padding                    int    `xml:"padding,omitempty"`
	ActionSource               string `xml:"action_source,omitempty"`
	TunnelID                   int    `xml:"tunnelid,omitempty"`
	IMSI                       string `xml:"imsi,omitempty"`
	MonitorTag                 string `xml:"monitortag,omitempty"`
	IMEI                       string `xml:"imei,omitempty"`
	DeviceGroupHierarchy1      int    `xml:"dg_hier_level_1,omitempty"`
	DeviceGroupHierarchy2      int    `xml:"dg_hier_level_2,omitempty"`
	DeviceGroupHierarchy3      int    `xml:"dg_hier_level_3,omitempty"`
	DeviceGroupHierarchy4      int    `xml:"dg_hier_level_4,omitempty"`
	Host                       string `xml:"host,omitempty"`
	Command                    string `xml:"cmd,omitempty"`
	Admin                      string `xml:"admin,omitempty"`
	Client                     string `xml:"client,omitempty"`
	Result                     string `xml:"result,omitempty"`
	Path                       string `xml:"path,omitempty"`
	BeforeChangePreview        string `xml:"before-change-preview,omitempty"`
	AfterChangePreview         string `xml:"after-change-preview,omitempty"`
	FullPath                   string `xml:"full-path,omitempty"`
	EventID                    string `xml:"eventid,omitempty"`
	Module                     string `xml:"module,omitempty"`
	Description                string `xml:"opaque,omitempty"`
}

// LogParameters specifies additional parameters that can be used when retrieving logs. These are all optional.
type LogParameters struct {
	// Query specifies the match criteria for the logs. This is similar to the query provided in the web interface under the Monitor
	// tab when viewing the logs. The query must be URL encoded.
	Query string

	// NLogs specifies the number of logs to retrieve. The default is 20 when the parameter is not specified. The maximum is 5000.
	NLogs int

	// Skip specifies the number of logs to skip when doing a log retrieval. The default is 0. This is useful when retrieving
	// logs in batches where you can skip the previously retrieved logs.
	Skip int

	// Direction specifies whether logs are shown oldest first (forward) or newest first (backward). Default is backward.
	Direction string

	// Action is not used at the moment. Log data sizes can be large so the API uses an asynchronous job scheduling approach to retrieve
	// log data. The initial query returns a Job ID (job-id) that you can then use for future queries with the action parameter: action=get
	// will check status of an active job or retrieve the log data when the status is FIN (finished).
	Action string
}

// RoutingTable contains all of the routes in the devices routing table.
type RoutingTable struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Flags   string   `xml:"result>flags"`
	Routes  []Route  `xml:"result>entry"`
}

// Route contains information about each individual route in the devices routing table.
type Route struct {
	VirtualRouter string `xml:"virtual-router"`
	Destination   string `xml:"destination"`
	NextHop       string `xml:"nexthop"`
	Metric        int    `xml:"metric"`
	Flags         string `xml:"flags"`
	Age           int64  `xml:"age"`
	Interface     string `xml:"interface"`
}

// authKey holds our API key.
type authKey struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Key     string   `xml:"result>key"`
}

// systemInfo holds basic system information.
type systemInfo struct {
	XMLName                    xml.Name `xml:"response"`
	Status                     string   `xml:"status,attr"`
	Code                       string   `xml:"code,attr"`
	Platform                   string   `xml:"result>system>platform-family"`
	Model                      string   `xml:"result>system>model"`
	Serial                     string   `xml:"result>system>serial"`
	SoftwareVersion            string   `xml:"result>system>sw-version"`
	IPAddress                  string   `xml:"result>system>ip-address"`
	Netmask                    string   `xml:"result>system>netmask"`
	DefaultGateway             string   `xml:"result>system>default-gateway"`
	MACAddress                 string   `xml:"result>system>mac-address"`
	Time                       string   `xml:"result>system>time"`
	Uptime                     string   `xml:"result>system>uptime"`
	GPClientPackageVersion     string   `xml:"result>system>global-protect-client-package-version"`
	GPDatafileVersion          string   `xml:"result>system>global-protect-datafile-version"`
	GPDatafileReleaseDate      string   `xml:"result>system>global-protect-datafile-release-date"`
	GPClientlessVPNVersion     string   `xml:"result>system>global-protect-clientless-vpn-version"`
	GPClientlessVPNReleaseDate string   `xml:"result>system>global-protect-clientless-vpn-release-date"`
	AppVersion                 string   `xml:"result>system>app-version"`
	AppReleaseDate             string   `xml:"result>system>app-release-date"`
	AntiVirusVersion           string   `xml:"result>system>av-version"`
	AntiVirusReleaseDate       string   `xml:"result>system>av-release-date"`
	ThreatVersion              string   `xml:"result>system>threat-version"`
	ThreatReleaseDate          string   `xml:"result>system>threat-release-date"`
	WildfireVersion            string   `xml:"result>system>wildfire-version"`
	WildfireReleaseDate        string   `xml:"result>system>wildfire-release-date"`
	URLDB                      string   `xml:"result>system>url-db"`
	URLFilteringVersion        string   `xml:"result>system>url-filtering-version"`
	LogDBVersion               string   `xml:"result>system>logdb-version"`
	MultiVsys                  string   `xml:"result>system>multi-vsys"`
	OperationalMode            string   `xml:"result>system>operational-mode"`
}

// commandOutput holds the results of our operational mode commands that were issued.
type commandOutput struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Data    string   `xml:"result"`
}

// requestError contains information about any error we get from a request.
type requestError struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Message string   `xml:"result>msg,omitempty"`
}

// testURL contains the results of the operational command test url.
type testURL struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	Result  string   `xml:"result"`
}

// logID contains the job ID when querying the device for log retrieval.
type logID struct {
	XMLName xml.Name `xml:"response"`
	Status  string   `xml:"status,attr"`
	Code    string   `xml:"code,attr"`
	ID      int      `xml:"result>job"`
}

// routeLookupResults contains the results of testing a route lookup.
type routeLookupResults struct {
	XMLName   xml.Name `xml:"response"`
	Status    string   `xml:"status,attr"`
	Code      string   `xml:"code,attr"`
	NextHop   string   `xml:"result>nh"`
	Source    string   `xml:"result>src"`
	IP        string   `xml:"result>ip"`
	Metric    int      `xml:"result>metric"`
	Interface string   `xml:"result>interface"`
	DataPlane string   `xml:"result>dp"`
}

// RouteLookup contains the results of the operational command: test routing fib-lookup <ip> <virtual-router>.
type RouteLookup struct {
	NextHop   string
	Source    string
	IP        string
	Metric    int
	Interface string
	DataPlane string
}

// SessionTable holds information about every session on the device.
type SessionTable struct {
	XMLName  xml.Name  `xml:"response"`
	Status   string    `xml:"status,attr"`
	Code     string    `xml:"code,attr"`
	Sessions []Session `xml:"result>entry"`
}

// Session holds information about each individual session on the device.
type Session struct {
	Application           string `xml:"application"`
	IngressInterface      string `xml:"ingress"`
	EgressInterface       string `xml:"egress"`
	VsysID                int    `xml:"vsys-idx"`
	NATSourceAddress      string `xml:"xsource"`
	SourceNAT             string `xml:"srcnat"`
	SourcePort            int    `xml:"sport"`
	SecurityRule          string `xml:"security-rule"`
	From                  string `xml:"from"`
	Protocol              int    `xml:"proto"`
	DestinationAddress    string `xml:"dst"`
	To                    string `xml:"to"`
	State                 string `xml:"state"`
	NATDestinationAddress string `xml:"xdst"`
	NAT                   string `xml:"nat"`
	Type                  string `xml:"type"`
	StartTime             string `xml:"start-time"`
	Proxy                 string `xml:"proxy"`
	DecryptMirror         string `xml:"decrypt-mirror"`
	ID                    int    `xml:"idx"`
	TotalByteCount        int    `xml:"total-byte-count"`
	DestinationNAT        string `xml:"dstnat"`
	Vsys                  string `xml:"vsys"`
	NATSourcePort         int    `xml:"xsport"`
	NATDestinationPort    int    `xml:"xdport"`
	Flags                 string `xml:"flags,omitempty"`
	SourceAddress         string `xml:"source"`
	DestinationPort       int    `xml:"dport"`
}

// ApplicationInformation contains information about every application.
type ApplicationInformation struct {
	XMLName      xml.Name      `xml:"response"`
	Status       string        `xml:"status,attr"`
	Code         string        `xml:"code,attr"`
	Applications []Application `xml:"result>application>entry"`
}

// Application contains information about each individual application.
type Application struct {
	ID                      string                  `xml:"id,attr"`
	Name                    string                  `xml:"name,attr"`
	OriginCountry           string                  `xml:"ori_country,attr"`
	OriginLanguage          string                  `xml:"ori_language,attr"`
	Category                string                  `xml:"category"`
	Subcategory             string                  `xml:"subcategory"`
	Technology              string                  `xml:"technology"`
	VirusIdent              string                  `xml:"virus-ident"`
	FileTypeIdent           string                  `xml:"file-type-ident"`
	TunnelOtherApplications string                  `xml:"tunnel-other-applications"`
	DataIdent               string                  `xml:"data-ident"`
	FileForward             string                  `xml:"file-forward"`
	IsSAAS                  string                  `xml:"is-saas"`
	EvasiveBehavior         string                  `xml:"evasive-behavior"`
	ConsumeBigBandwidth     string                  `xml:"consume-big-bandwidth"`
	UsedByMalware           string                  `xml:"used-by-malware"`
	AbleToTransferFile      string                  `xml:"able-to-transfer-file"`
	HasKnownVulnerability   string                  `xml:"has-known-vulnerability"`
	ProneToMisuse           string                  `xml:"prone-to-misuse"`
	PervasiveUse            string                  `xml:"pervasive-use"`
	References              []ApplicationReferences `xml:"references>entry"`
	DefaultPort             []string                `xml:"default>port>member"`
	UseApplications         []string                `xml:"use-applications>member"`
	ImplicitUseApplications []string                `xml:"implicit-use-applications>member"`
	Risk                    int                     `xml:"risk"`
}

// ApplicationReferences contains the name and link of the reference site.
type ApplicationReferences struct {
	Name string `xml:"name,attr"`
	Link string `xml:"link"`
}

var (
	r = gorequest.New().TLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	errorCodes = map[string]string{
		"400": "Bad request - Returned when a required parameter is missing, an illegal parameter value is used",
		"403": "Forbidden - Returned for authentication or authorization errors including invalid key, insufficient admin access rights",
		"1":   "Unknown command - The specific config or operational command is not recognized",
		"2":   "Internal error - Check with technical support when seeing these errors",
		"3":   "Internal error - Check with technical support when seeing these errors",
		"4":   "Internal error - Check with technical support when seeing these errors",
		"5":   "Internal error - Check with technical support when seeing these errors",
		"6":   "Bad Xpath - The xpath specified in one or more attributes of the command is invalid. Check the API browser for proper xpath values",
		"7":   "Object not present - Object specified by the xpath is not present. For example, entry[@name=’value’] where no object with name ‘value’ is present",
		"8":   "Object not unique - For commands that operate on a single object, the specified object is not unique",
		"9":   "Internal error - Check with technical support when seeing these errors",
		"10":  "Reference count not zero - Object cannot be deleted as there are other objects that refer to it. For example, address object still in use in policy",
		"11":  "Internal error - Check with technical support when seeing these errors",
		"12":  "Invalid object - Xpath or element values provided are not complete",
		"13":  "Operation failed - A descriptive error message is returned in the response",
		"14":  "Operation not possible - Operation is not possible. For example, moving a rule up one position when it is already at the top",
		"15":  "Operation denied - For example, Admin not allowed to delete own account, Running a command that is not allowed on a passive device",
		"16":  "Unauthorized - The API role does not have access rights to run this query",
		"17":  "Invalid command - Invalid command or parameters",
		"18":  "Malformed command - The XML is malformed",
		"19":  "Success - Command completed successfully",
		"20":  "Success - Command completed successfully",
		"21":  "Internal error - Check with technical support when seeing these errors",
		"22":  "Session timed out - The session for this query timed out",
	}
)

// splitSWVersion breaks up the version numbering into a []int.
func splitSWVersion(version string) []int {
	re := regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
	match := re.FindStringSubmatch(version)
	maj, _ := strconv.Atoi(match[1])
	min, _ := strconv.Atoi(match[2])
	rel, _ := strconv.Atoi(match[3])

	return []int{maj, min, rel}
}

// sliceToString converts a slice to a string, separated by a comma.
func sliceToString(slice []string) string {
	var str string

	for _, item := range slice {
		str += fmt.Sprintf("%s, ", item)
	}

	return strings.TrimRight(str, ", ")
}

// stringToSlice converts a comma separated string to a []string.
func stringToSlice(str string) []string {
	var slice []string

	list := strings.Split(str, ", ")
	for _, item := range list {
		slice = append(slice, strings.Trim(item, " "))
	}

	return slice
}

// NewSession sets up our connection to the Palo Alto firewall or Panorama device. The authmethod parameter
// is used to define two ways of authenticating to the device. One is via username/password, the other is with
// the API key if you already have generated it. Please see the documentation for the AuthMethod struct for further
// details.
func NewSession(host string, authmethod *AuthMethod) (*PaloAlto, error) {
	var keygen authKey
	var key string
	var info systemInfo
	var pan commandOutput
	status := false
	deviceType := "panos"

	if len(authmethod.Credentials) > 0 {
		_, body, errs := r.Get(fmt.Sprintf("https://%s/api/?type=keygen&user=%s&password=%s", host, authmethod.Credentials[0], authmethod.Credentials[1])).End()
		if errs != nil {
			return nil, errs[0]
		}

		err := xml.Unmarshal([]byte(body), &keygen)
		if err != nil {
			return nil, err
		}

		if keygen.Status != "success" {
			return nil, fmt.Errorf("error code %s: %s (keygen)", keygen.Code, errorCodes[keygen.Code])
		}

		key = keygen.Key
	}

	if len(authmethod.APIKey) > 0 {
		key = authmethod.APIKey
	}

	uri := fmt.Sprintf("https://%s/api/?", host)
	_, getInfo, errs := r.Get(fmt.Sprintf("%s&key=%s&type=op&cmd=<show><system><info></info></system></show>", uri, key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	err := xml.Unmarshal([]byte(getInfo), &info)
	if err != nil {
		return nil, err
	}

	if info.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s (show system info)", info.Code, errorCodes[info.Code])
	}

	_, panStatus, errs := r.Get(fmt.Sprintf("%s&key=%s&type=op&cmd=<show><panorama-status></panorama-status></show>", uri, key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	err = xml.Unmarshal([]byte(panStatus), &pan)
	if err != nil {
		return nil, err
	}

	if info.Platform == "m" || info.Model == "Panorama" {
		deviceType = "panorama"
	}

	if strings.Contains(pan.Data, ": yes") {
		status = true
	}

	return &PaloAlto{
		Host:                       host,
		Key:                        key,
		URI:                        fmt.Sprintf("https://%s/api/?", host),
		Platform:                   info.Platform,
		Model:                      info.Model,
		Serial:                     info.Serial,
		SoftwareVersion:            info.SoftwareVersion,
		DeviceType:                 deviceType,
		Panorama:                   status,
		Shared:                     false,
		IPAddress:                  info.IPAddress,
		Netmask:                    info.Netmask,
		DefaultGateway:             info.DefaultGateway,
		MACAddress:                 info.MACAddress,
		Time:                       strings.Trim(info.Time, "[\r\n]"),
		Uptime:                     info.Uptime,
		GPClientPackageVersion:     info.GPClientPackageVersion,
		GPDatafileVersion:          info.GPDatafileVersion,
		GPDatafileReleaseDate:      info.GPDatafileReleaseDate,
		GPClientlessVPNVersion:     info.GPClientlessVPNVersion,
		GPClientlessVPNReleaseDate: info.GPClientlessVPNReleaseDate,
		AppVersion:                 info.AppVersion,
		AppReleaseDate:             info.AppReleaseDate,
		AntiVirusVersion:           info.AntiVirusVersion,
		AntiVirusReleaseDate:       info.AntiVirusReleaseDate,
		ThreatVersion:              info.ThreatVersion,
		ThreatReleaseDate:          info.ThreatReleaseDate,
		WildfireVersion:            info.WildfireVersion,
		WildfireReleaseDate:        info.WildfireReleaseDate,
		URLDB:                      info.URLDB,
		URLFilteringVersion:        info.URLFilteringVersion,
		LogDBVersion:               info.LogDBVersion,
		MultiVsys:                  info.MultiVsys,
		OperationalMode:            info.OperationalMode,
	}, nil
}

// Commit issues a commit on the device. When issuing a commit against a Panorama device,
// the configuration will only be committed to Panorama, and not an individual device-group.
func (p *PaloAlto) Commit() error {
	var reqError requestError

	_, resp, errs := r.Get(p.URI).Query(fmt.Sprintf("type=commit&cmd=<commit></commit>&key=%s", p.Key)).End()
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

// CommitAll issues a commit to a Panorama device, for the given devicegroup. If you wish to push to specific
// firewalls within the specified device group only, add each firewalls serial number as an additional parameter,
// (e.g. CommitAll("Some-DeviceGroup", "000000000001", "000000000002")).
func (p *PaloAlto) CommitAll(devicegroup string, devices ...string) error {
	var reqError requestError
	var cmd string

	if p.DeviceType == "panorama" && len(devices) <= 0 {
		cmd = fmt.Sprintf("<commit-all><shared-policy><device-group><entry name=\"%s\"/></device-group></shared-policy></commit-all>", devicegroup)
	}

	if p.DeviceType == "panorama" && len(devices) > 0 {
		cmd = fmt.Sprintf("<commit-all><shared-policy><device-group><entry name=\"%s\"/>><devices>", devicegroup)

		for _, d := range devices {
			cmd += fmt.Sprintf("<entry name=\"%s\"/>", d)
		}

		cmd += "</devices></entry></device-group></shared-policy></commit-all>"
	}

	_, resp, errs := r.Get(p.URI).Query(fmt.Sprintf("type=commit&action=all&cmd=%s&key=%s", cmd, p.Key)).End()
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

// RestartSystem will issue a system restart to the device.
func (p *PaloAlto) RestartSystem() error {
	var reqError requestError
	command := "<request><restart><system></system></restart></request>"

	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=op&cmd=%s&key=%s", command, p.Key)).End()
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

// TestURL will verify what category the given URL falls under. It will return two results in a string slice ([]string). The
// first one is from the Base db categorization, and the second is from the Cloud db categorization. If you specify a URL
// with a wildcard, such as *.paloaltonetworks.com, it will not return a result.
func (p *PaloAlto) TestURL(url string) ([]string, error) {
	var urlResults testURL
	rex := regexp.MustCompile(`(?m)^([\d\.a-zA-Z-]+)\s([\w-]+)\s.*seconds\s([\d\.a-zA-Z-]+)\s([\w-]+)\s`)
	command := fmt.Sprintf("<test><url>%s</url></test>", url)

	if p.DeviceType == "panorama" {
		return nil, errors.New("you can only test URL's from a local device")
	}

	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=op&cmd=%s&key=%s", command, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(resp), &urlResults); err != nil {
		return nil, err
	}

	if urlResults.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", urlResults.Code, errorCodes[urlResults.Code])
	}

	categorization := rex.FindStringSubmatch(urlResults.Result)

	if len(categorization) == 0 {
		return nil, fmt.Errorf("cannot resolve the site %s", url)
	}

	results := []string{
		fmt.Sprintf("%s", categorization[2]),
		fmt.Sprintf("%s", categorization[4]),
	}

	return results, nil
}

// TestRouteLookup will lookup the given destination IP in the virtual-router "vr" and return the results.
func (p *PaloAlto) TestRouteLookup(vr, destination string) (*RouteLookup, error) {
	var testRouteLookup routeLookupResults
	command := fmt.Sprintf("<test><routing><fib-lookup><virtual-router>%s</virtual-router><ip>%s</ip></fib-lookup></routing></test>", vr, destination)

	if p.DeviceType == "panorama" {
		return nil, errors.New("you can only test route lookups from a local device")
	}

	_, resp, errs := r.Post(p.URI).Query(fmt.Sprintf("type=op&cmd=%s&key=%s", command, p.Key)).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(resp), &testRouteLookup); err != nil {
		return nil, err
	}

	if testRouteLookup.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", testRouteLookup.Code, errorCodes[testRouteLookup.Code])
	}

	return &RouteLookup{
		NextHop:   testRouteLookup.NextHop,
		Source:    testRouteLookup.Source,
		IP:        testRouteLookup.IP,
		Metric:    testRouteLookup.Metric,
		Interface: testRouteLookup.Interface,
		DataPlane: testRouteLookup.DataPlane,
	}, nil
}

// Jobs returns information about every job on the device. Status can be one of: all, pending, or processed. If you want
// information about a specific job, specify the job ID instead of one of the other options.
func (p *PaloAlto) Jobs(status interface{}) (*Jobs, error) {
	var jobs Jobs
	var cmd string

	switch status.(type) {
	case string:
		if status == "all" {
			cmd += "<show><jobs><all></all></jobs></show>"
		}

		if status == "pending" {
			cmd += "<show><jobs><pending></pending></jobs></show>"
		}

		if status == "processed" {
			cmd += "<show><jobs><processed></processed></jobs></show>"
		}
	case int:
		cmd += fmt.Sprintf("<show><jobs><id>%d</id></jobs></show>", status)
	}

	_, res, errs := r.Get(fmt.Sprintf("%s&key=%s&type=op&cmd=%s", p.URI, p.Key, cmd)).End()
	if errs != nil {
		return nil, errs[0]
	}

	err := xml.Unmarshal([]byte(res), &jobs)
	if err != nil {
		return nil, err
	}

	return &jobs, nil
}

// QueryLogs allows you to pull logs from the system, given a specific log-type. Currently, the
// supported log types are as follows:
//
// config, system, traffic, threat, wildfire, url, data
//
// The LogParameters struct lists optional parameters you can use in your query. See the documentation for a full
// description of options. If you do not wish to use any of the optional parameters, just specify nil. The job ID is
// returned from the query, and should be passed to RetrieveLogs().
func (p *PaloAlto) QueryLogs(logtype string, parameters *LogParameters) (int, error) {
	var id logID
	req := fmt.Sprintf("%s&key=%s&type=log&log-type=%s", p.URI, p.Key, logtype)

	if parameters != nil {
		if parameters.Query != "" {
			req += fmt.Sprintf("&query=%s", url.QueryEscape(parameters.Query))
		}

		if parameters.NLogs > 0 {
			req += fmt.Sprintf("&nlogs=%d", parameters.NLogs)
		}

		if parameters.Direction != "" {
			req += fmt.Sprintf("&dir=%s", parameters.Direction)
		}

		if parameters.Skip > 0 {
			req += fmt.Sprintf("&skip=%d", parameters.Skip)
		}
	}

	_, res, errs := r.Get(req).End()
	if errs != nil {
		return 0, errs[0]
	}

	err := xml.Unmarshal([]byte(res), &id)
	if err != nil {
		return 0, err
	}

	return id.ID, nil
}

// RetrieveLogs will return the log data as specified in the QueryLogs() function, given the job ID. If the job
// status is not FIN, then you will have to query the job ID until it has finished and then it will return the
// results.
func (p *PaloAlto) RetrieveLogs(id int) (*Logs, error) {
	var logs Logs

	_, res, errs := r.Get(fmt.Sprintf("%s&key=%s&type=log&action=get&job-id=%d", p.URI, p.Key, id)).End()
	if errs != nil {
		return nil, errs[0]
	}

	err := xml.Unmarshal([]byte(res), &logs)
	if err != nil {
		return nil, err
	}

	return &logs, nil
}

// XpathConfig allows you to configure the device using an Xpath expression for the given xpath parameter.
// The element parameter can either be an XML file or an XML string when configuring the device. The action parameter can be one of:
//
// set, edit, rename, override or delete
//
// Set actions add, update, or merge configuration nodes, while edit actions replace configuration nodes
// - use the edit action with caution! If you are renaming an object, specify the new name for the
// object in the element parameter. If you are deleting a part of the configuration, you do not need
// the element parameter. For all other actions you will need to provide it.
//
// See https://goo.gl/G1vzJT for details regarding all of the actions available.
func (p *PaloAlto) XpathConfig(action, xpath string, element ...string) error {
	var reqError requestError
	var query string

	switch action {
	case "set", "edit", "override":
		if len(element) <= 0 {
			return errors.New("you must specify the element parameter")
		}

		if strings.Contains(element[0], ".xml") {
			c, err := ioutil.ReadFile(element[0])
			if err != nil {
				return err
			}

			xmlcontents := string(c)
			query = fmt.Sprintf("type=config&action=%s&xpath=%s&element=%s&key=%s", action, xpath, xmlcontents, p.Key)
		} else {
			query = fmt.Sprintf("type=config&action=%s&xpath=%s&element=%s&key=%s", action, xpath, element[0], p.Key)
		}
	case "rename":
		if len(element) <= 0 {
			return errors.New("you must specify the element parameter when renaming an object")
		}

		query = fmt.Sprintf("type=config&action=%s&xpath=%s&newname=%s&key=%s", action, xpath, element[0], p.Key)
	case "delete":
		query = fmt.Sprintf("type=config&action=%s&xpath=%s&key=%s", action, xpath, p.Key)
	}

	_, resp, errs := r.Post(p.URI).Query(query).End()
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

// XpathClone allows you to clone an existing part of the devices configuration. Use the xpath parameter
// to specify the location of the object to be cloned. Use the from parameter to specify the source object,
// and the newname parameter to provide a name for the cloned object.
//
// See https://goo.gl/ZfmBB6 for details.
func (p *PaloAlto) XpathClone(xpath, from, newname string) error {
	var reqError requestError

	query := fmt.Sprintf("type=config&action=clone&xpath=%s&from=%s&newname=%s&key=%s", xpath, from, newname, p.Key)

	_, resp, errs := r.Post(p.URI).Query(query).End()
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

// XpathMove allows you to move the location of an existing configuration object. Use the xpath parameter to specify
// the location of the object to be moved, and the where parameter to specify type of move. You can optionally use the
// destination parameter to specify the destination path.
//
// See https://goo.gl/LbkQDG for details.
func (p *PaloAlto) XpathMove(xpath, where string, destination ...string) error {
	var reqError requestError
	var query string

	query = fmt.Sprintf("type=config&action=move&xpath=%s&where=%s&key=%s", xpath, where, p.Key)

	if len(destination) > 0 {
		query = fmt.Sprintf("type=config&action=move&xpath=%s&where=%s&dst=%s&key=%s", xpath, where, destination[0], p.Key)
	}

	_, resp, errs := r.Post(p.URI).Query(query).End()
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

// XpathMulti allows you to move and clone multiple objects across device groups and virtual systems. The element parameter
// can be either an XML file or XML string. The action parameter must be one of: clone or move.
// The xpath parameter is for the destination where the addresses will be moved to. The element parameter must
// include in the XML the xpath for the source and the list of objects within the specified source.
//
// See https://goo.gl/oeufnu for details.
func (p *PaloAlto) XpathMulti(action, xpath, element string) error {
	var reqError requestError
	var query string

	if strings.Contains(element, ".xml") {
		c, err := ioutil.ReadFile(element)
		if err != nil {
			return err
		}

		xmlcontents := string(c)
		query = fmt.Sprintf("type=config&action=multi-%s&xpath=%s&element=%s&key=%s", action, xpath, xmlcontents, p.Key)
	} else {
		query = fmt.Sprintf("type=config&action=multi-%s&xpath=%s&element=%s&key=%s", action, xpath, element, p.Key)
	}

	_, resp, errs := r.Post(p.URI).Query(query).End()
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

// XpathGetConfig allows you to view the active or candidate configuration at the location specified in the
// xpath parameter.
func (p *PaloAlto) XpathGetConfig(configtype, xpath string) (string, error) {
	var reqError requestError
	var query string

	switch configtype {
	case "active":
		query = fmt.Sprintf("type=config&action=show&xpath=%s&key=%s", xpath, p.Key)
	case "candidate":
		query = fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", xpath, p.Key)
	}

	_, resp, errs := r.Post(p.URI).Query(query).End()
	if errs != nil {
		return "", errs[0]
	}

	if err := xml.Unmarshal([]byte(resp), &reqError); err != nil {
		return "", err
	}

	if reqError.Status != "success" {
		return "", fmt.Errorf("error code %s: %s", reqError.Code, errorCodes[reqError.Code])
	}

	return resp, nil
}

// Command lets you run any operational mode command against the given device, and it returns the output. You
// must use the XML-formatted version of the command string as if you were calling the API yourself,
// (e.g. "<show><running><ippool></ippool></running></show>")
func (p *PaloAlto) Command(command string) (string, error) {
	var output commandOutput

	_, res, errs := r.Get(fmt.Sprintf("%s&key=%s&type=op&cmd=%s", p.URI, p.Key, command)).End()
	if errs != nil {
		return "", errs[0]
	}

	err := xml.Unmarshal([]byte(res), &output)
	if err != nil {
		return "", err
	}

	return output.Data, nil
}

// Routes will retrieve information about each route in the devices routing table(s). You can (optionally) specify
// a specific virtual router to retrieve routes from.
func (p *PaloAlto) Routes(vr ...string) (*RoutingTable, error) {
	var rt RoutingTable
	query := fmt.Sprintf("%s&key=%s&type=op&cmd=<show><routing><route></route></routing></show>", p.URI, p.Key)

	if p.DeviceType != "panos" {
		return nil, errors.New("you can only retrieve the routing table on a local firewall")
	}

	if len(vr) > 0 {
		query = fmt.Sprintf("%s&key=%s&type=op&cmd=<show><routing><route><virtual-router>%s</virtual-router></route></routing></show>", p.URI, p.Key, vr[0])
	}

	_, resp, errs := r.Post(p.URI).Query(query).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(resp), &rt); err != nil {
		return nil, err
	}

	if rt.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", rt.Code, errorCodes[rt.Code])
	}

	return &rt, nil
}

// Sessions will retrieve information about each session within the session table on a firewall. You
// can optionally define a filter, and use the same criteria as you would on the command line. The filter
// query must be enclosed in quotes "", and the format is:
//
// option=value (e.g. "application=ssl")
//
// Your filter can include multiple items, and each group must be separated by a comma, e.g.:
//
// "application=ssl, ssl-decrypt=yes, protocol=tcp"
func (p *PaloAlto) Sessions(filter ...string) (*SessionTable, error) {
	var st SessionTable
	query := fmt.Sprintf("%s&key=%s&type=op&cmd=<show><session><all></all></session></show>", p.URI, p.Key)

	if len(filter[0]) > 0 {
		var filterString string
		tcpudp := map[string]int{
			"tcp": 6,
			"udp": 17,
		}

		params := strings.Split(filter[0], ", ")

		for _, p := range params {
			f := strings.Split(p, "=")
			if f[0] == "protocol" {
				filterString += fmt.Sprintf("<%s>%d</%s>", f[0], tcpudp[f[1]], f[0])
				continue
			}

			filterString += fmt.Sprintf("<%s>%s</%s>", f[0], f[1], f[0])
		}

		query = fmt.Sprintf("%s&key=%s&type=op&cmd=<show><session><all><filter>%s</filter></all></session></show>", p.URI, p.Key, filterString)
	}

	if p.DeviceType != "panos" {
		return nil, errors.New("you can only retrieve the session table on a local firewall")
	}

	_, resp, errs := r.Post(p.URI).Query(query).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(resp), &st); err != nil {
		return nil, err
	}

	if st.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", st.Code, errorCodes[st.Code])
	}

	return &st, nil
}

// ApplicationInfo gathers information about every pre-defined application on the device.
func (p *PaloAlto) ApplicationInfo(name ...string) (*ApplicationInformation, error) {
	var apps ApplicationInformation
	xpath := "/config/predefined/application"

	if len(name) > 0 {
		xpath = fmt.Sprintf("/config/predefined/application/entry[@name='%s']", name[0])
	}

	query := fmt.Sprintf("type=config&action=get&xpath=%s&key=%s", xpath, p.Key)

	_, resp, errs := r.Post(p.URI).Query(query).End()
	if errs != nil {
		return nil, errs[0]
	}

	if err := xml.Unmarshal([]byte(resp), &apps); err != nil {
		return nil, err
	}

	if apps.Status != "success" {
		return nil, fmt.Errorf("error code %s: %s", apps.Code, errorCodes[apps.Code])
	}

	return &apps, nil
}
