package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	netbox "network_maintainence_tools/internal/netbox"
)

const (
	defaultBaseURL    = "http://mini.dev.yanch.ar:8000"
	defaultTokenFile  = ".netbox_api_token"
	defaultConfigFile = "netbox_audit.config.json"
	defaultMaxAttempt = 5
)

type auditConfig struct {
	Rules              auditRules      `json:"rules"`
	Checks             checksConfig    `json:"checks"`
	compiledWANRoleSet map[string]bool `json:"-"`
	compiledRackTagSet map[string]bool `json:"-"`
}

type auditRules struct {
	InterfaceVRF          interfaceVRFRules          `json:"interface-vrf"`
	PrivateIPVRF          privateIPVRFRules          `json:"private-ip-vrf"`
	WirelessNormalization wirelessNormalizationRules `json:"wireless-normalization"`
	RackPlacement         rackPlacementRules         `json:"rack-placement"`
	PoEPower              poePowerRules              `json:"poe-power"`
}

type interfaceVRFRules struct {
	WANDeviceRoles      []string `json:"wan_device_roles"`
	RequireOnInterfaces bool     `json:"require_on_interfaces"`
}

type privateIPVRFRules struct {
	RequireOnPrivateIPs bool `json:"require_on_private_ips"`
	RequireOnPublicIPs  bool `json:"require_on_public_ips"`
}

type wirelessNormalizationRules struct {
	SuppressIfConnectedWiredInterfaceIsComplete bool `json:"suppress_if_connected_wired_interface_is_complete"`
	RequireMode                                 bool `json:"require_mode"`
	RequireUntaggedVLAN                         bool `json:"require_untagged_vlan"`
	RequirePrimaryMAC                           bool `json:"require_primary_mac"`
}

type rackPlacementRules struct {
	ExemptChildDevices bool     `json:"exempt_child_devices"`
	ExemptDeviceTags   []string `json:"exempt_device_tags"`
}

type poePowerRules struct {
	CheckPoweredDeviceSupply bool   `json:"check_powered_device_supply"`
	RequirePSEModeOnPeer     bool   `json:"require_pse_mode_on_peer"`
	UnknownTypePolicy        string `json:"unknown_type_policy"`
}

type checksConfig struct {
	Enabled  []string `json:"enabled"`
	Disabled []string `json:"disabled"`
}

func defaultAuditConfig() auditConfig {
	return auditConfig{
		Rules: auditRules{
			InterfaceVRF: interfaceVRFRules{
				WANDeviceRoles:      []string{"ISP Equipment"},
				RequireOnInterfaces: true,
			},
			PrivateIPVRF: privateIPVRFRules{
				RequireOnPrivateIPs: true,
				RequireOnPublicIPs:  false,
			},
			WirelessNormalization: wirelessNormalizationRules{
				SuppressIfConnectedWiredInterfaceIsComplete: true,
				RequireMode:         true,
				RequireUntaggedVLAN: true,
				RequirePrimaryMAC:   true,
			},
			RackPlacement: rackPlacementRules{
				ExemptChildDevices: true,
				ExemptDeviceTags:   []string{"0u-rack-device"},
			},
			PoEPower: poePowerRules{
				CheckPoweredDeviceSupply: true,
				RequirePSEModeOnPeer:     true,
				UnknownTypePolicy:        poeUnknownTypeFail,
			},
		},
	}
}

func loadAuditConfig(path string, required bool) (auditConfig, error) {
	cfg := defaultAuditConfig()
	if err := cfg.compile(); err != nil {
		return auditConfig{}, err
	}
	if strings.TrimSpace(path) == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && !required {
			return cfg, nil
		}
		return auditConfig{}, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return auditConfig{}, err
	}
	if err := cfg.compile(); err != nil {
		return auditConfig{}, err
	}
	return cfg, nil
}

func defaultConfigPath() string {
	if cwd, err := os.Getwd(); err == nil {
		candidates := []string{
			filepath.Join(cwd, defaultConfigFile),
			filepath.Join(cwd, "..", "..", defaultConfigFile),
		}
		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
		return ""
	}
	return ""
}

func (c *auditConfig) compile() error {
	c.compiledWANRoleSet = make(map[string]bool, len(c.Rules.InterfaceVRF.WANDeviceRoles))
	for _, role := range c.Rules.InterfaceVRF.WANDeviceRoles {
		c.compiledWANRoleSet[strings.TrimSpace(role)] = true
	}
	c.compiledRackTagSet = make(map[string]bool, len(c.Rules.RackPlacement.ExemptDeviceTags))
	for _, tag := range c.Rules.RackPlacement.ExemptDeviceTags {
		c.compiledRackTagSet[strings.TrimSpace(tag)] = true
	}
	switch strings.ToLower(strings.TrimSpace(c.Rules.PoEPower.UnknownTypePolicy)) {
	case "", poeUnknownTypeFail:
		c.Rules.PoEPower.UnknownTypePolicy = poeUnknownTypeFail
	case poeUnknownTypeIgnore:
		c.Rules.PoEPower.UnknownTypePolicy = poeUnknownTypeIgnore
	default:
		return fmt.Errorf("unsupported poe-power.unknown_type_policy %q", c.Rules.PoEPower.UnknownTypePolicy)
	}
	return nil
}

func (c auditConfig) isWANRole(role string) bool {
	return c.compiledWANRoleSet[role]
}

func (c auditConfig) isRackTagExempt(tags []netbox.TagRef) bool {
	for _, tag := range tags {
		if c.compiledRackTagSet[tag.Slug] {
			return true
		}
	}
	return false
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
