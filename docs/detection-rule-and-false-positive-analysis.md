# Detection Rules, Alert Triage & False-Positive Analysis

## Purpose
This document extends the SSH authentication monitoring lab into a repeatable SOC workflow. It uses simulated training data and is not proof of a real attack.

## Data assumptions
The current SPL examples expect fields such as event_type, id.orig_h, username, host, and _time. Confirm fields in your own Splunk data before relying on the searches.

## Detection 1 — Repeated failed SSH authentication

~~~spl
source="ssh_logs_new.json" sourcetype="_json" event_type="Failed SSH Login"
| bin _time span=5m
| stats count AS failed_attempts dc(username) AS distinct_users values(username) AS targeted_users by _time id.orig_h
| where failed_attempts >= 10
| sort - failed_attempts
~~~

**Logic:** Find a source that produces at least 10 failed attempts in a five-minute bucket.

**Suggested starting severity:** Medium, pending validation.

**Tuning:** A generic threshold is not universal. Establish a baseline and adjust for the environment.

## Detection 2 — Repeated failures plus a successful login

~~~spl
source="ssh_logs_new.json" sourcetype="_json"
| stats count(eval(event_type="Failed SSH Login")) AS failed_logins
        count(eval(event_type="Successful SSH Login")) AS successful_logins
        values(event_type) AS event_types
        by id.orig_h username
| where failed_logins >= 10 AND successful_logins > 0
| sort - failed_logins
~~~

This highlights source/account pairs with repeated failures and at least one successful event in the selected time range. It does **not** prove the success followed the failures. Validate event order using timestamps and a chronological timeline.

## Detection 3 — Review timeline for a source/account

~~~spl
source="ssh_logs_new.json" sourcetype="_json"
| table _time id.orig_h username event_type host
| sort 0 _time
~~~

Add filters for the specific source IP or username you are investigating. Confirm time-zone and timestamp parsing.

## Detection 4 — A source targeting many accounts

~~~spl
source="ssh_logs_new.json" sourcetype="_json" event_type="Failed SSH Login"
| stats count AS failed_attempts dc(username) AS unique_users values(username) AS users_targeted by id.orig_h
| where unique_users >= 5 AND failed_attempts >= 10
| sort - unique_users
~~~

A source attempting many accounts may indicate password spraying or automation, but benign scanners and tests can create similar patterns.

## False-positive checklist

Before marking an event malicious, investigate:

1. **Expected automation:** Monitoring, deployment, backup jobs, or scheduled scripts.
2. **Shared NAT/proxy:** Many users may appear behind one public source IP.
3. **User mistakes:** A low volume of failures may be normal.
4. **Approved testing:** A penetration test or audit may have been scheduled.
5. **Service accounts:** Some applications make repeated authentication attempts.
6. **Time quality:** Check event timestamp parsing, timezone, and clock skew.
7. **Successful login context:** Verify whether success followed the failures and whether the host matches.
8. **Baseline:** Compare against normal activity for the account, source, and system.
9. **Post-login activity:** Look for unexpected processes, privilege changes, commands, and network connections.
10. **Threat intelligence:** Reputation can add context, but reputation alone is not proof.

## Analyst decision matrix

| Observation | Suggested action |
|---|---|
| Few failures with expected user context | Review context; may be benign |
| Many failures from one source against many accounts | Investigate possible password spraying |
| Repeated failures plus a later success | Validate ordering and examine post-login activity |
| Unexpected source or login time | Compare with account baseline and approved activity |
| Missing fields or unreliable timestamps | Mark inconclusive and fix parsing first |

## Alert lifecycle

1. Detect when a search or scheduled alert matches.
2. Triage source, user, destination, time, and event counts.
3. Enrich with asset criticality and known-good activity.
4. Correlate authentication with endpoint and network events.
5. Classify as benign, suspicious/inconclusive, or confirmed based on evidence.
6. Respond according to the approved process; do not block an IP or disable an account using an unvalidated threshold alone.
7. Document query, time range, events, findings, false-positive checks, and next steps.
8. Tune the threshold after reviewing representative data.

## Reproducibility and privacy

- Record the exact time range and index/source used.
- Label sample data as simulated.
- Never publish real credentials or sensitive production logs.
- Replace illustrative screenshots with your own current lab results.
