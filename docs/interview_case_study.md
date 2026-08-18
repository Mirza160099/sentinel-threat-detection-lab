# Interview Case Study

## Problem
Demonstrate how identity-focused threats can be hunted and converted into reusable Microsoft Sentinel detection logic.

## Approach
I created synthetic sign-in scenarios, mapped common identity threats to MITRE ATT&CK, wrote KQL hunting queries, documented detection thresholds and created a SOC triage playbook.

## What I would change in production
I would baseline normal user behaviour, tune thresholds using historical telemetry, add MFA/device/risk context, test false-positive rates, use peer review/change control and deploy through Dev/Test/Prod rather than treating example thresholds as universal.
