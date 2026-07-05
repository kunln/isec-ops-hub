---
name: honeypot-event-analysis-sop
description: SOP for using honeypot events as supporting evidence in security triage.
---

# Honeypot Event Analysis SOP

Honeypot events are supporting signals. They can raise priority and confidence but usually do not prove compromise alone.

## Analyze

- Source IP and target IP.
- Protocol, service and event type.
- Payload and threat label.
- Time overlap with production alerts.
- Whether the same source IP appears in XDR, EDR, NDR, WAF or SIEM alerts.

## Use in Triage

- Same source IP plus production alert increases confidence.
- Same target asset plus exploit_probe increases risk for that asset.
- Honeypot-only events should be reported as hostile probing unless other evidence exists.

Never treat a honeypot hit as direct compromise of a production asset without corroborating evidence.
