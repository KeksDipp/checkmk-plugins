# Changelog – sophos_sfos

## 1.0.0 – 2026-11-20

- First release: SNMP checks for Sophos Firewall OS based on `SFOS-FIREWALL-MIB`
- Services *Sophos System*, *Sophos Memory*, *Sophos Disk*, *Sophos Services*, *Sophos HA*,
  *Sophos Licenses*, *Sophos IPsec*
- Hardware sensors (SFOS 22.0+): *Temperature CPU/NPU*, *Fan*, *Power Supply*, *Sophos PoE*
- HA: active node, failover detection via serial number and role stored at discovery
- IPsec: deactivated connections are reported separately from connections that are down;
  active tunnels as metric
- Licenses: all modules in one service; the worst module determines the state, the next expiry
  is shown in the summary and as a metric; single modules can be ignored. Perpetual licenses
  (expiry year 2999) are shown as "no expiry date"
- SNMP: all sections fetch the SFOS MIB with one bulk walk. SFOS answers single requests
  slowly, so a *Timing settings for SNMP access* rule (timeout 3 s) is recommended, see README
- HW/SW inventory: model, serial number, firmware, memory
