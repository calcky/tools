# Metrics And Data Status

## Check Units And Scope

| Display | Meaning |
| --- | --- |
| bit/s | Byte delta × 8 / actual elapsed time |
| PPS / packets/s | Rate at this accounting point, not necessarily wire frames |
| intr/s | Interrupt-handler rate, not PPS |
| Raw totals | Kernel cumulative values, not necessarily since program start |
| SINCE BASELINE | Changes since the current valid baseline |
| Current values | Queue, connection-count, window and MTU gauges |

netlens observes the current network namespace. Some memory and CPU interrupt data is host-wide and labelled separately.
`-i` does not turn host totals into interface totals. Different layers may count different packet units.
TCP and queue fields are explained on their task pages instead of treating every type as one accounting domain.

## Rates, Baselines And Caches

Press `t` for interval/since-baseline values; selected-socket details use their own live measurements.
The first sample establishes a baseline without a rate. Resets, device-identity changes and collection gaps establish a new baseline; deltas do not cross gaps.

Collection follows the visible page. Leaving stops unrelated collectors; returning first establishes a new rate baseline.
Space or `p` pauses display only, not background collection.

Configuration may refresh less often than traffic. Cached values retain their true observation time rather than pretending to be new samples.
Slow-source rates average their collection interval and may smooth short bursts.

## Diagnose Missing Data

```sh
netlens providers
```

Check sources, errors and observation age before diagnosing application problems.

| Status | Interpretation |
| --- | --- |
| ACTIVE | Currently usable source, not proof of a healthy network |
| PARTIAL | Only some fields or entries are available |
| DEGRADED | Reduced collection quality; inspect errors or stale data |
| UNAVAILABLE | The source cannot currently be read |
| UNSUPPORTED | Unsupported kernel, driver or feature |
| NO PROVIDER | No usable source covers this observation point |
| n/a | No value for this field, not zero |
| TRUNCATED | Retention limit reached; filtered results may be incomplete |

`LIVE`, `DATA GAPS` and `NO DATA` describe collection, not network health.
`signals` counts valid nonzero diagnostic metrics; `unavailable` counts unavailable summary metrics, not faulty connections.
Zero matches in an incomplete snapshot do not prove no matching connection exists.

## Permissions And Namespaces

```sh
netlens
netlens
```

Start with data visible to the current user. FD, conntrack and NIC sources may require additional privileges; start the tool inside the target network namespace to inspect it.
`hidepid`, container permissions and security policies may still restrict process scans. Root cannot supply a disabled kernel feature.
Run inside the namespace you want to observe; `-i` does not switch namespaces.

## Avoid Cross-Layer Sums

- Interfaces, qdiscs, IP, TCP, softnet and IRQs use different points, units and scopes.
- Do not sum root/child qdiscs, overlapping error categories or iptables-nft/native nftables views.
- GRO/GSO, forwarding offload, XDP and virtual devices change which layers observe traffic.
- Missing values, old samples and gaps are not fresh zeros or healthy states.

netlens is read-only: no capture, BPF loading or firewall, TC, XDP, sysctl or NIC changes.
Use separate capture, tracing or active-probe tools for per-packet paths or application RTT.
