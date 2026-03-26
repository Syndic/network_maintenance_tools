# Config Reference

The example audit policy is defined in `netbox_audit.config.json`.

The config file is optional:
- if it is absent, the audit uses built-in defaults
- if it is present but omits fields, the missing fields fall back to built-in defaults
- if you explicitly pass `-config` or set `NETBOX_AUDIT_CONFIG`, that file is required to exist

## Schema

```json
{
  "checks": {
    "enabled": [
      "device-locations"
    ],
    "disabled": [
      "poe-power"
    ]
  },
  "rules": {
    "wan": {
      "device_roles": [
        "ISP Equipment"
      ]
    },
    "vrf": {
      "require_on_private_ips": true,
      "require_on_public_ips": false,
      "require_on_interfaces": true
    },
    "wireless": {
      "suppress_if_connected_wired_interface_is_complete": true,
      "require_mode": true,
      "require_untagged_vlan": true,
      "require_primary_mac": true
    },
    "rack_placement": {
      "exempt_child_devices": true,
      "exempt_device_tags": [
        "0u-rack-device"
      ]
    },
    "poe": {
      "check_powered_device_supply": true,
      "require_pse_mode_on_peer": true,
      "unknown_type_policy": "fail"
    }
  }
}
```

## `checks`

- `enabled`
  - if omitted or empty, all checks are eligible to run
  - if set, only the listed check IDs run
- `disabled`
  - removes listed check IDs from the run
  - unknown IDs are treated as configuration errors

Check IDs are documented in [CHECKS.md](CHECKS.md).

## `rules.wan`

- `device_roles`
  - device roles treated as WAN-side equipment

Current use:
- suppress WAN-side false positives in interface VRF checks

## `rules.vrf`

- `require_on_private_ips`
  - require VRF on RFC1918/private IP addresses
- `require_on_public_ips`
  - require VRF on public IP addresses
- `require_on_interfaces`
  - require VRF on in-use interfaces, except WAN-side exceptions

## `rules.wireless`

- `suppress_if_connected_wired_interface_is_complete`
  - if true, ignore incomplete Wi-Fi interfaces when the same device already has a connected, sufficiently modeled wired interface
- `require_mode`
  - require `802.1Q mode` on unsuppressed Wi-Fi interfaces
- `require_untagged_vlan`
  - require `untagged VLAN` on unsuppressed Wi-Fi interfaces
- `require_primary_mac`
  - require `primary_mac_address` on unsuppressed Wi-Fi interfaces

## `rules.rack_placement`

- `exempt_child_devices`
  - skip rack-position checks for child devices
- `exempt_device_tags`
  - device-instance tags that should exempt a rack-mounted device from explicit U-position checks

## `rules.poe`

- `check_powered_device_supply`
  - enable or disable PoE supply checking
- `require_pse_mode_on_peer`
  - require the connected peer interface to be explicitly modeled as `poe_mode: pse`
- `unknown_type_policy`
  - behavior when `poe_type` is missing or not comparable
  - supported values:
    - `fail`
    - `ignore`

PoE type ordering used by the audit:
- `type1-ieee802.3af`
- `type2-ieee802.3at`
- `type3-ieee802.3bt`
- `type4-ieee802.3bt`

Higher levels satisfy lower requirements.

## Updating Policy

If you want to change audit behavior without changing code:
1. Edit `netbox_audit.config.json`
2. Rerun the audit
