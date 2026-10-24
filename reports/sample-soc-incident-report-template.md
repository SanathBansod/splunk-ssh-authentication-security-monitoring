# Sample SOC Incident Report — SSH Authentication Anomaly

> **Training template:** This report uses an educational/simulated dataset. It does not claim that a real incident occurred. Fill in the evidence after running and validating the searches in your own lab.

## 1. Case summary

| Field | Value |
|---|---|
| Case ID | LAB-SSH-001 |
| Alert | Repeated SSH authentication failures |
| Environment | Local Splunk training lab |
| Data | Simulated SSH authentication events |
| Initial priority | Medium — triage required |
| Status | Training investigation / awaiting validation |
| Analyst | Sanath Bansod |
| Time range | Record the exact Splunk search window |

## 2. Detection trigger

The starter rule flags a source/account pair with at least 10 failed events within a five-minute bucket. Tune this threshold for your dataset and environment.

~~~spl
source="ssh_logs_new.json" sourcetype="_json" event_type="Failed SSH Login"
| bin _time span=5m
| stats count AS failed_attempts dc(username) AS distinct_users values(username) AS targeted_users by _time id.orig_h
| where failed_attempts >= 10
| sort - failed_attempts
~~~

## 3. Evidence to collect

- Source IP and destination host(s).
- Targeted account(s).
- Failed event count in the defined time window.
- Any successful authentication and its exact timestamp.
- Whether success definitely happened after the failures.
- Relevant host/process/network events after login, if available.
- Splunk index, source, sourcetype, query, and time range.
- Sanitized screenshot or exported events without secrets.

## 4. Analysis workflow

1. Confirm raw events are parsed correctly.
2. Verify the time range and timezone.
3. Group failures by source and username.
4. Determine whether one source targeted one account or many accounts.
5. Search the same source/account for successful logins.
6. Review the full timeline to establish event order.
7. Check for approved scanners, jump hosts, NAT gateways, monitoring, and automation.
8. Examine post-login activity where endpoint telemetry exists.

## 5. False-positive review

| Check | Result to record |
|---|---|
| Known admin or monitoring source? | Yes / No / Unknown + evidence |
| Scheduled testing or automation? | Yes / No / Unknown + evidence |
| Shared NAT or proxy possible? | Yes / No / Unknown + evidence |
| Successful login definitely followed failures? | Yes / No / Unable to determine |
| Unusual post-login activity? | Yes / No / Not available |
| Fields and timestamps validated? | Yes / No |

## 6. Assessment

Choose only after reviewing evidence:

- **Benign / expected activity:** Supported by known-good context.
- **Suspicious, needs more investigation:** Unusual but not conclusive.
- **Confirmed incident:** Corroborated evidence supports unauthorized activity.

A threshold match alone does not prove compromise.

## 7. Recommended response

For a real environment, follow the organization's incident-response policy. Depending on validated evidence, actions may include notifying the host/account owner, reviewing MFA and authentication policy, terminating confirmed unauthorized sessions, rotating compromised credentials, applying approved network controls, and preserving logs. Do not automatically block an IP or disable an account based solely on this training rule.

## 8. Conclusion

- **Final finding:** Complete after running and validating the searches.
- **Confidence:** Low / Medium / High, with a reason.
- **Gaps:** Record missing timestamps, host telemetry, account context, or other limitations.
- **Next actions:** Assign an owner and specific action for each unresolved item.

## 9. Evidence appendix

- Search query and time range:
- Event count:
- Source/account pair:
- Screenshot path:
- Relevant event IDs:
- Analyst notes:
