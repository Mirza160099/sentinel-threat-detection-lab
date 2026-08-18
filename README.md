# Microsoft Sentinel Threat Detection Lab

A recruiter-facing cybersecurity portfolio project demonstrating **KQL threat hunting, detection engineering concepts, MITRE ATT&CK mapping and SOC incident triage** for Microsoft Sentinel-style identity telemetry.

> **Important:** This is a portfolio lab using synthetic data. It does not contain MAS Tech/customer data and does not claim that these rules were deployed into an employer's production Sentinel tenant.

## Objectives

- Translate threat hypotheses into KQL hunting logic.
- Detect brute-force / password-spray style behaviour.
- Identify successful authentication after repeated failures.
- Hunt for unusual authentication geography.
- Review privileged identity activity.
- Map detections to MITRE ATT&CK.
- Define investigation and response steps.
- Explain how detections should be tuned before production deployment.

## Repository

```text
sentinel-threat-detection-lab/
├── data/
│   ├── synthetic_signin_logs.csv
│   └── suspicious_signin_scenario.csv
├── kql/
│   ├── failed_signin_burst.kql
│   ├── success_after_failures.kql
│   ├── unusual_country_signin.kql
│   └── privileged_activity.kql
├── detections/
│   └── detection_catalog.csv
├── docs/
│   ├── architecture.md
│   ├── triage_playbook.md
│   └── interview_case_study.md
└── README.md
```

## Detection Catalogue

| Detection | Severity | ATT&CK | Purpose |
|---|---|---|---|
| Failed Sign-in Burst | Medium | T1110 | Surface repeated authentication failures |
| Success After Repeated Failures | High | T1110 / T1078 | Identify potential successful compromise |
| Unexpected Country Authentication | Medium | T1078 | Surface authentication outside example baseline |
| Privileged Role Activity | High | T1098 | Review potentially sensitive identity changes |

## Example KQL

```kusto
SigninLogs
| where ResultType != 0
| summarize FailedAttempts=count(), IPs=make_set(IPAddress)
    by UserPrincipalName, bin(TimeGenerated, 10m)
| where FailedAttempts >= 8
| order by FailedAttempts desc
```

The threshold is deliberately a **lab starting point**, not a claim that `8` is appropriate for every production environment.

## Detection Engineering Workflow

```text
Threat hypothesis
      ↓
Required telemetry
      ↓
KQL hunting query
      ↓
Historical testing
      ↓
False-positive analysis
      ↓
Threshold / entity tuning
      ↓
Analytics rule
      ↓
SOC triage playbook
      ↓
Review & continuous improvement
```

## Interview Talking Points

Be ready to explain:

1. Hunting query vs scheduled analytics rule.
2. Why thresholds require baselining.
3. Password spraying vs brute force.
4. Why a successful login after failures increases risk.
5. How MFA, device and user-risk context improve fidelity.
6. False positives caused by VPNs/travel/service accounts.
7. How MITRE ATT&CK helps organise detection coverage.
8. What evidence you would collect during identity compromise.
9. How you would tune the rule after deployment.
10. How detection-as-code/version control could be introduced.

## Production Enhancements

- Microsoft Entra ID risk signals
- MFA result correlation
- Device compliance context
- Watchlists for trusted VPN/proxy ranges
- UEBA/entity behaviour
- Automated incident enrichment
- Detection-as-code CI/CD
- Dev/UAT/Prod rule lifecycle
- SOC metrics and detection-health monitoring

## Ethics & Privacy

All supplied data is synthetic. No employer, customer or personally sensitive production telemetry is included.
