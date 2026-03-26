package main

import (
	"net/netip"
	"time"

	netboxapi "network_maintainence_tools/internal/netbox"
)

type choice struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

type idRef struct {
	ID int `json:"id"`
}

type namedRef struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type deviceTypeRef struct {
	ID    int    `json:"id"`
	Model string `json:"model"`
}

type moduleTypeRef struct {
	ID    int    `json:"id"`
	Model string `json:"model"`
}

type vlanRef struct {
	ID   int    `json:"id"`
	VID  int    `json:"vid"`
	Name string `json:"name"`
}

type vrfRef struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type macAddressRef struct {
	ID         int    `json:"id"`
	MACAddress string `json:"mac_address"`
}

type moduleBayRef struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type moduleRef struct {
	ID        int           `json:"id"`
	ModuleBay *moduleBayRef `json:"module_bay"`
}

type device struct {
	ID           int           `json:"id"`
	Name         string        `json:"name"`
	DeviceType   deviceTypeRef `json:"device_type"`
	Role         namedRef      `json:"role"`
	Status       choice        `json:"status"`
	Site         *namedRef     `json:"site"`
	Location     *namedRef     `json:"location"`
	Rack         *namedRef     `json:"rack"`
	Position     *float64      `json:"position"`
	Face         *choice       `json:"face"`
	ParentDevice *namedRef     `json:"parent_device"`
	Description  string        `json:"description"`
	Tags         []tagRef      `json:"tags"`
}

type connectedEndpoint struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Device      *namedRef `json:"device"`
}

type iface struct {
	ID                 int                 `json:"id"`
	Name               string              `json:"name"`
	Device             namedRef            `json:"device"`
	Module             *moduleRef          `json:"module"`
	Type               choice              `json:"type"`
	MgmtOnly           bool                `json:"mgmt_only"`
	POEMode            *choice             `json:"poe_mode"`
	POEType            *choice             `json:"poe_type"`
	Enabled            bool                `json:"enabled"`
	ConnectedEndpoints []connectedEndpoint `json:"connected_endpoints"`
	Mode               *choice             `json:"mode"`
	UntaggedVLAN       *vlanRef            `json:"untagged_vlan"`
	TaggedVLANs        []vlanRef           `json:"tagged_vlans"`
	VRF                *vrfRef             `json:"vrf"`
	MACAddress         string              `json:"mac_address"`
	PrimaryMACAddress  *macAddressRef      `json:"primary_mac_address"`
	MACAddresses       []macAddressRef     `json:"mac_addresses"`
	Description        string              `json:"description"`
}

type interfaceTemplate struct {
	ID         int     `json:"id"`
	DeviceType *idRef  `json:"device_type"`
	ModuleType *idRef  `json:"module_type"`
	Name       string  `json:"name"`
	Type       choice  `json:"type"`
	Enabled    bool    `json:"enabled"`
	MgmtOnly   bool    `json:"mgmt_only"`
	POEMode    *choice `json:"poe_mode"`
	POEType    *choice `json:"poe_type"`
}

type typedComponent struct {
	ID     int        `json:"id"`
	Name   string     `json:"name"`
	Device namedRef   `json:"device"`
	Module *moduleRef `json:"module"`
	Type   choice     `json:"type"`
}

type typedComponentTemplate struct {
	ID         int    `json:"id"`
	DeviceType *idRef `json:"device_type"`
	ModuleType *idRef `json:"module_type"`
	Name       string `json:"name"`
	Type       choice `json:"type"`
}

type namedComponent struct {
	ID     int        `json:"id"`
	Name   string     `json:"name"`
	Device namedRef   `json:"device"`
	Module *moduleRef `json:"module"`
}

type namedComponentTemplate struct {
	ID         int    `json:"id"`
	DeviceType *idRef `json:"device_type"`
	ModuleType *idRef `json:"module_type"`
	Name       string `json:"name"`
}

type portMap struct {
	Position  int `json:"position"`
	FrontPort int `json:"front_port"`
	RearPort  int `json:"rear_port"`
}

type cableRef struct {
	ID int `json:"id"`
}

type frontPort struct {
	ID        int        `json:"id"`
	Name      string     `json:"name"`
	Device    namedRef   `json:"device"`
	Module    *moduleRef `json:"module"`
	Type      choice     `json:"type"`
	Cable     *cableRef  `json:"cable"`
	RearPorts []portMap  `json:"rear_ports"`
}

type rearPort struct {
	ID         int        `json:"id"`
	Name       string     `json:"name"`
	Device     namedRef   `json:"device"`
	Module     *moduleRef `json:"module"`
	Type       choice     `json:"type"`
	Cable      *cableRef  `json:"cable"`
	FrontPorts []portMap  `json:"front_ports"`
}

type frontPortTemplate struct {
	ID         int    `json:"id"`
	DeviceType *idRef `json:"device_type"`
	ModuleType *idRef `json:"module_type"`
	Name       string `json:"name"`
	Type       choice `json:"type"`
}

type rearPortTemplate struct {
	ID         int    `json:"id"`
	DeviceType *idRef `json:"device_type"`
	ModuleType *idRef `json:"module_type"`
	Name       string `json:"name"`
	Type       choice `json:"type"`
}

type installedModuleRef struct {
	ID int `json:"id"`
}

type moduleBay struct {
	ID              int                 `json:"id"`
	Name            string              `json:"name"`
	Device          namedRef            `json:"device"`
	Module          *moduleRef          `json:"module"`
	InstalledModule *installedModuleRef `json:"installed_module"`
}

type module struct {
	ID         int           `json:"id"`
	Device     namedRef      `json:"device"`
	ModuleBay  *moduleBayRef `json:"module_bay"`
	ModuleType moduleTypeRef `json:"module_type"`
}

type tagRef struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type assignedObjectRef struct {
	ID     int       `json:"id"`
	Name   string    `json:"name"`
	Device *namedRef `json:"device"`
}

type ipAddress struct {
	ID                 int                `json:"id"`
	Address            string             `json:"address"`
	VRF                *vrfRef            `json:"vrf"`
	Status             choice             `json:"status"`
	DNSName            string             `json:"dns_name"`
	AssignedObjectType string             `json:"assigned_object_type"`
	AssignedObjectID   int                `json:"assigned_object_id"`
	AssignedObject     *assignedObjectRef `json:"assigned_object"`
	Description        string             `json:"description"`
	Tags               []tagRef           `json:"tags"`
}

type ipRange struct {
	ID           int      `json:"id"`
	StartAddress string   `json:"start_address"`
	EndAddress   string   `json:"end_address"`
	VRF          *vrfRef  `json:"vrf"`
	Tags         []tagRef `json:"tags"`
}

type prefix struct {
	ID     int      `json:"id"`
	Prefix string   `json:"prefix"`
	VRF    *vrfRef  `json:"vrf"`
	VLAN   *vlanRef `json:"vlan"`
}

type terminationObject struct {
	ID     int       `json:"id"`
	Name   string    `json:"name"`
	Device *namedRef `json:"device"`
}

type termination struct {
	ObjectType string             `json:"object_type"`
	ObjectID   int                `json:"object_id"`
	Object     *terminationObject `json:"object"`
}

type cable struct {
	ID            int           `json:"id"`
	Type          string        `json:"type"`
	Status        choice        `json:"status"`
	ATerminations []termination `json:"a_terminations"`
	BTerminations []termination `json:"b_terminations"`
}

type macAddressRecord struct {
	ID                 int                `json:"id"`
	MACAddress         string             `json:"mac_address"`
	AssignedObjectType string             `json:"assigned_object_type"`
	AssignedObjectID   int                `json:"assigned_object_id"`
	AssignedObject     *assignedObjectRef `json:"assigned_object"`
}

type snapshot struct {
	LatestChange               netboxapi.ObjectChange
	SnapshotAttempts           int
	LoadStats                  snapshotLoadStats
	Devices                    []device
	Interfaces                 []iface
	InterfaceTemplates         []interfaceTemplate
	ConsolePorts               []typedComponent
	ConsolePortTemplates       []typedComponentTemplate
	ConsoleServerPorts         []typedComponent
	ConsoleServerPortTemplates []typedComponentTemplate
	PowerPorts                 []typedComponent
	PowerPortTemplates         []typedComponentTemplate
	PowerOutlets               []typedComponent
	PowerOutletTemplates       []typedComponentTemplate
	FrontPorts                 []frontPort
	FrontPortTemplates         []frontPortTemplate
	RearPorts                  []rearPort
	RearPortTemplates          []rearPortTemplate
	DeviceBays                 []namedComponent
	DeviceBayTemplates         []namedComponentTemplate
	ModuleBays                 []moduleBay
	ModuleBayTemplates         []namedComponentTemplate
	Modules                    []module
	IPAddresses                []ipAddress
	IPRanges                   []ipRange
	Prefixes                   []prefix
	Cables                     []cable
	MACAddresses               []macAddressRecord

	// Pre-computed indexes — built once after fetch, used by all parallel checks.
	DevicesByID        map[int]device
	InterfacesByID     map[int]iface
	InterfacesByDevice map[int][]iface
	IPsByInterface     map[int][]ipAddress
	ModuleBaysByID     map[int]moduleBay
}

type snapshotLoadStats struct {
	Duration     time.Duration
	RequestCount int
	Fetches      []fetchTiming
}

type fetchTiming struct {
	Name     string
	Requests int
	Duration time.Duration
	Pages    int
	Items    int
}

type checkTiming struct {
	ID       string
	Name     string
	Duration time.Duration
	Findings int
}

type reportTiming struct {
	Total    time.Duration
	Snapshot snapshotLoadStats
	Checks   []checkTiming
}

type componentSpec struct {
	Type     string
	MgmtOnly *bool
	POEMode  string
	POEType  string
	Enabled  *bool
}

type driftRecord struct {
	Device  string   `json:"device"`
	Model   string   `json:"model"`
	Details []string `json:"details"`
}

type snapshotMeta struct {
	Attempts int                    `json:"attempts"`
	Change   netboxapi.ObjectChange `json:"latest_change"`
}

type checkResult struct {
	Name     string        `json:"name"`
	Findings []string      `json:"findings"`
	Extra    []driftRecord `json:"extra,omitempty"`
}

type report struct {
	Snapshot snapshotMeta  `json:"snapshot"`
	Checks   []checkResult `json:"checks"`
	Timing   reportTiming  `json:"-"`
}

type componentDriftCheck struct {
	label                string
	expectedByDeviceType map[int]map[string]componentSpec
	expectedByModuleType map[int]map[string]componentSpec
	actualByDevice       map[int]map[string]componentSpec
	diffSpec             func(expected, actual componentSpec) []string
}

type parsedPrefix struct {
	Prefix netip.Prefix
	VLAN   *vlanRef
	VRFID  int
}
