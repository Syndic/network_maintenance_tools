package main

const (
	envNetBoxAuditColor = "NETBOX_AUDIT_COLOR"
	envNetBoxAuditCfg   = "NETBOX_AUDIT_CONFIG"

	flagBaseURL        = "netbox-base-url"
	flagTokenFile      = "netbox-token-file"
	flagConfig         = "config"
	flagFormat         = "format"
	flagColor          = "color"
	flagMaxAttempts    = "max-snapshot-attempts"
	flagRetryDelay     = "snapshot-retry-delay"
	flagFailOnFindings = "fail-on-findings"

	deviceStatusPlanned = "planned"
	roleAccessPoint     = "Access Point"
	roleSwitch          = "Switch"
	vlanModeAccess = "access"

	tagHoneypot = "honeypot"
	tagDHCPReserved = "dhcp-reserved"
	tagDHCPPool     = "dhcp-pool"

	poeUnknownTypeFail   = "fail"
	poeUnknownTypeIgnore = "ignore"
	poeModePD            = "pd"
	poeModePSE           = "pse"

	poeTypeAF  = "type1-ieee802.3af"
	poeTypeAT  = "type2-ieee802.3at"
	poeTypeBT3 = "type3-ieee802.3bt"
	poeTypeBT4 = "type4-ieee802.3bt"

	wirelessTypePrefix = "ieee802.11"
)
