# Sophos Firewall (SFOS)

SNMP checks for Sophos Firewall OS (XGS, XG, virtual and cloud appliances), including HA
clusters. All data comes from the vendor MIB `SFOS-FIREWALL-MIB` (`.1.3.6.1.4.1.2604.5.1`);
no special agent or API access is needed.

- **Checkmk:** 2.5 (2.4 untested)
- **SFOS:** tested against SFOS 22.0 MR-3 (XGS 138, Active-Passive cluster). Hardware sensors
  need SFOS 22.0 GA build 411 or later.

## Services

| Service | What it checks | Ruleset |
|---|---|---|
| **Sophos System** | Model, firmware, serial number, IPS and web category versions; live users and HTTP hits as metrics | – |
| **Sophos Memory** | RAM and swap usage (without cache/buffers) | Sophos Firewall memory |
| **Sophos Disk** | Usage of the data partition | Sophos Firewall disk usage |
| **Sophos Services** | All 21 SFOS system services in one service; every service that was running at discovery has to stay running | Sophos Firewall services |
| **Sophos HA** | HA state of both nodes, active node, mode, HA link; failover detection | Sophos Firewall high availability |
| **Sophos Licenses** | All license modules in one service: subscription status, next expiry | Sophos Firewall licenses |
| **Sophos IPsec *connection*** | Connection status, active tunnels (child SAs); deactivated vs. down | Sophos Firewall IPsec connections |
| **Temperature CPU / NPU** | Temperatures (SFOS 22.0+) | built-in: Temperature |
| **Fan *n*** | Fan speed (SFOS 22.0+) | built-in: FAN speed of hardware devices |
| **Power Supply *n*** | Power supply up/down (appliances with redundant PSUs) | – |
| **Sophos PoE** | Enabled PoE ports, power draw per port against its limit | – |

Services for hardware sensors and PoE are only created if the firewall reports them.

All sections share one SNMP table, so Checkmk fetches the whole SFOS MIB with a single bulk walk
per check cycle instead of one walk per OID.

### Sophos HA

- **OK:** this device and the peer are primary/auxiliary.
- **CRIT:** a node is *faulty*, *standalone* or *not applicable* (peer gone); both nodes report
  the same role; there is no primary; HA has been disabled since discovery.
- **WARN:** a node reports *ready* (transitional state, configurable).
- **Active node:** in Active-Passive mode the primary carries the traffic. The summary shows its
  serial number and whether it is this device or the peer.
- **Failover detection:** the serial number and the HA role of the monitored address are stored
  at discovery. If you monitor the cluster's admin IP, a failover changes the serial number; if
  you monitor a node's own admin IP (e.g. the auxiliary admin port), it changes the role.
  Either way the service goes **WARN** (configurable) until you rediscover it, which
  acknowledges the new active node.

### Sophos Services

The list of services that were running at discovery is stored with the service. If one of
them stops, the service goes **CRIT** (configurable). Services that were not running at
discovery (features not in use) are only listed. Rediscover the service after enabling or
disabling features on the firewall, or ignore single services via the rule.

SFOS names `av` and `as` are shown as `antivirus` and `antispam`.

### Sophos Licenses

All license modules are checked in one service. The modules that are *subscribed* or
*evaluating* at discovery are stored with the service; the worst of them determines the state.
Modules with a problem are named in the summary, e.g.
`Web Protection: subscribed, expires on 2026-12-11 (in 21 days)`. The summary always shows the
next expiring module; its remaining time is also a metric.

- **Expired:** CRIT. Also if the expiry date has passed while the status still says subscribed.
- **Not subscribed / deactivated / no longer reported:** WARN.
- **Remaining time:** WARN below 30 days, CRIT below 14 days.
- **Perpetual licenses:** SFOS reports them with an expiry date in the year 2999 (e.g. Base
  Firewall). They show "no expiry date".
- **Ignore:** single modules (e.g. one you let expire on purpose) can be excluded via the rule;
  they are only listed in the details.

Rediscover the service after buying or dropping a license module.

### Sophos IPsec

- **Activated and connected:** OK.
- **Activated but down:** CRIT.
- **Partially active** (not all tunnels up): WARN.
- **Deactivated by the administrator:** OK by default, so connections you switched off on
  purpose don't alert.
- **Active tunnels:** number of child SAs, e.g. one per local/remote network pair. Optional
  lower levels via the rule; they are not applied to deactivated connections.

**Throughput:** the SFOS MIB has no traffic counters per IPsec connection.

- *Route-based* VPNs use xfrm interfaces, whose traffic is visible in the regular interface
  check.
- *Policy-based* VPNs have no throughput via SNMP. `ipsec0` reports zero counters.

## Installation

Download `sophos_sfos-<version>.mkp` from the
[Releases](https://github.com/KeksDipp/checkmk-plugins/releases) page and install it:

```bash
# as site user
mkp add sophos_sfos-<version>.mkp
mkp enable sophos_sfos <version>
omd restart apache
omd restart automation-helper   # otherwise a running site does not load the new plugin
```

or via *Setup → Extension packages* (commercial editions).

### Firewall side

Enable SNMP on the firewall (*Administration → SNMP*). SNMPv3 (authPriv) is recommended. Also
allow SNMP in *Administration → Device access* for the zone the Checkmk server connects from.

### Checkmk host

Create the host with *Checkmk agent / API integrations: No API integrations, no Checkmk agent*
and *SNMP: SNMP v2 or v3*, set the credentials, then run a service discovery.

For a cluster you can monitor:

- the cluster's admin IP only: always the active node, failover detection via serial number;
- or both nodes, the auxiliary via its dedicated admin port (shown in the HA service details).

### SNMP timing

SFOS answers a single SNMP request slowly (1–2 s on an XGS 138). With Checkmk's default timeout
the host goes CRIT with *SNMP query timed out* and all services miss their data. Create the rule
*Timing settings for SNMP access* for your Sophos hosts (e.g. via a folder or host label):

- **Timeout:** 3 s
- **Retries:** 1–2 (keeps a check on an unreachable firewall short)

Leave *Bulk walk: Number of OIDs per bulk* at its default; larger bulks make each request slower.

Optional: licenses and hardware don't need to be fetched every minute. With *Fetch intervals for
SNMP sections* you can poll e.g. `sophos_sfos_licenses` hourly and `sophos_sfos_hardware` every
5 minutes.

## Notes

### CPU, uptime and interfaces

These come from built-in Checkmk checks and need no configuration:

- **CPU utilization:** `hr_cpu` (HOST-RESOURCES-MIB). The SFOS MIB has no CPU value.
- **Uptime:** `snmp_uptime`.
- **Interfaces:** the regular interface check, with traffic, errors and speed.

Checkmk's own memory checks do not apply to SFOS. That is intended: HOST-RESOURCES-MIB counts
cache and buffers and would report ~95% used memory. **Sophos Memory** shows the real value.

### Interface discovery

SFOS exposes many internal interfaces. Exclude them in the rule
*Network interface and switch port discovery* (condition: *Match interface alias / description*)
with this regular expression:

```
^(lo|dummy\d+|ipsec\d+|sit\d+|ip6tnl\d+|mv-pcimux\d+|mvmgmt\d+|pport_.*|gre\d+|gretap\d+|erspan\d+|ifb\d+|spq)$
```

Ports (`Port1`, `PortF1`, …), LAGs, VLANs (`LAG1.80`), SSL VPN (`tun0`/`tun1`), RED and xfrm
interfaces remain. Some ports report `ifSpeed` 4294967295; Checkmk uses `ifHighSpeed` then.

### RED

RED tunnels appear as `reds*` interfaces in the interface check. The plugin itself has no
RED service. The device this plugin was developed with has no RED, so this is untested.

### Failed logins and certificates

These are not available via SNMP polling:

- **Failed logins:** SFOS sends them as syslog or SNMP traps. Use the Event Console.
- **Certificate expiry:** use the active check *Check certificates* (`check_cert`) against the
  web admin port, the user portal or VPN endpoints.

## License

GNU General Public License v2.0, see [LICENSE](../../LICENSE).
