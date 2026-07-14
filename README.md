# sentinel-soc-detection-lab

# Microsoft Sentinel — End-to-End Detection & Response Lab
 
Building a working SOC pipeline in Microsoft Sentinel from an empty Azure subscription: log ingestion → custom detection → incident triage → threat hunting → visualisation → SOAR automation.
 
Every screenshot is from my own Azure tenant. Every problem hit along the way is documented, including the one I didn't fully solve.
 
**Stack:** Microsoft Sentinel · Log Analytics · KQL · Azure Policy · Diagnostic Settings · Azure Logic Apps · Microsoft Defender XDR portal · MITRE ATT&CK
 
---
 
## Why this lab
 
Most Sentinel walkthroughs stop at "connector enabled, dashboard is green." That proves nothing. I wanted to build the full loop an analyst actually works:
 
**an event happens → a detection I wrote catches it → an incident lands in the queue → I triage and classify it → automation responds.**
 
To prove the detection worked, I generated the attack signal myself (deliberately deleting an Azure resource) and confirmed my own rule caught it.
 
---
 
## Architecture
 
```
Azure Subscription (control-plane activity)
        │
        │  Diagnostic Settings  ← streams AzureActivity logs
        ▼
Log Analytics Workspace  (SC200-Sentinel-Workspace, UK South)
        │
        ▼
Microsoft Sentinel
        │
        ├── Analytics rule (scheduled KQL) ──► Alert ──► Incident ──► Triage
        │                                                     │
        │                                                     ▼
        │                                          Automation rule ──► Logic App playbook
        │
        ├── Hunting query (manual, proactive)
        │
        └── Workbook (visualisation)
```
 
**Cost control:** a £10 budget with alerts at 50% and 80% was set on the subscription *before* any resource was created. Actual spend stayed in pennies. Everything was deployed into a single resource group (`SC200-Lab-RG`) so the entire lab could be torn down in one action.
 
---
 
## 1. Foundation — workspace, Sentinel, and log ingestion
 
Created a Log Analytics workspace and enabled Microsoft Sentinel on top of it. The workspace is the log store; Sentinel is the SIEM layer that reads from it.
 
![Log Analytics workspace](https://github.com/KevoT0/sentinel-soc-detection-lab/blob/main/1.png)
![Sentinel enabled](screenshots/02-sentinel-enabled.png)
 
Installed the **Azure Activity** solution from the Content Hub and opened the data connector. Azure Activity logs record control-plane operations — who created, changed or deleted resources. Low volume, high signal, and free.
 
![Content Hub](screenshots/03-content-hub-azure-activity.png)
![Data connector](screenshots/04-data-connector-config.png)
 
### Problem 1: the connector wouldn't stream
 
Microsoft's documented path is to assign an **Azure Policy** that configures log streaming across current and future subscriptions. I assigned it correctly — with a remediation task, scoped to the subscription, pointing at the right workspace.
 
![Policy assignment](screenshots/05-azure-policy-assignment.png)
![Policy confirmed in Assignments](screenshots/06-policy-assignment-confirmed.png)
 
The assignment succeeded. **No data arrived.** After waiting well past normal ingestion latency, the connector still showed `Not connected` with no `Last Log Received` timestamp.
 
**Root cause:** the policy is only an automated wrapper around a **Diagnostic Setting** — it's supposed to create one for you. The remediation task hadn't applied it.
 
**Fix:** I configured the Diagnostic Setting directly on the subscription's Activity Log, streaming all categories (Administrative, Security, ServiceHealth, Alert, Recommendation, Policy, Autoscale, ResourceHealth) into the workspace.
 
![Diagnostic settings](screenshots/07-diagnostic-settings-fix.png)
 
Data started flowing.
 
> **Takeaway:** Diagnostic Settings is the underlying mechanism for getting Azure resource logs into Log Analytics. Azure Policy is just a way to apply it at scale. Knowing what sits underneath the abstraction is what let me fix it when the abstraction failed.
 
Verified with KQL:
 
```kql
AzureActivity
| take 10
```
 
Sentinel was also connected to the unified **Microsoft Defender XDR** portal — worth noting, since Microsoft is consolidating Sentinel into Defender and retiring the Azure portal experience.
 
![Sentinel connected to Defender XDR](screenshots/09-sentinel-defender-xdr-connected.png)
 
---
 
## 2. Detection engineering
 
### Generating the signal
 
A detection you've never seen fire is a detection you don't trust. I created a storage account and deleted it, deliberately producing the exact control-plane event I wanted to catch.
 
![Storage account](screenshots/08-storage-account-created.png)
 
### The rule
 
**`Azure Resource Deletion Detected`** — a scheduled analytics rule.
 
```kql
AzureActivity
| where OperationNameValue contains "delete"
| where ActivityStatusValue == "Success"
```
 
Filtering on `Success` is deliberate: failed deletion *attempts* are a different signal (possible reconnaissance or a permissions problem). This rule is about destruction that actually happened.
 
| Setting | Value | Reasoning |
|---|---|---|
| MITRE ATT&CK | **Impact — T1485 (Data Destruction)** | Resource deletion is destructive, not reconnaissance or persistence |
| Severity | Medium | Real signal, but deletion is also routine admin activity |
| Frequency | Every 5 minutes | |
| Lookback | 15 minutes | Wider than the interval, to catch late-arriving logs (ingestion lag is real) |
| Threshold | > 0 results | |
| Entity mapping | Account → `FullName` → `Caller` | **This is what makes an incident investigable** — it turns a text row into a pivotable entity |
 
![Analytics rule](screenshots/10-analytics-rule-review.png)
 
The rule fired. An alert was raised, an incident created, and the `Caller` entity resolved correctly.
 
### Problem 2: I built a noisy rule
 
The first version ran **every 5 minutes with a 1-hour lookback**. That meant the same deletion was re-detected up to 12 times before it aged out of the window.
 
The workbook made it obvious: **20 alerts and 21 incidents** from a handful of real deletions. In a production SOC, that's alert fatigue — the thing that gets real incidents missed.
 
**Fix — two changes:**
1. Narrowed the lookback from 1 hour to **15 minutes** (still wider than the 5-minute interval, so late-arriving events are still caught).
2. Enabled **alert grouping** — alerts with matching entities collapse into a single incident over a 5-hour window.
![Rule tuning](screenshots/14-rule-tuning-alert-grouping.png)
 
> **Takeaway:** the trade-off is real. A wide lookback protects against ingestion lag but creates duplicates. Grouping is how you keep the buffer without flooding the queue. Detection engineering is tuning, not just writing.
 
---
 
## 3. Incident triage
 
Worked the incident the way I would on shift: assigned it, set it In Progress, reviewed the mapped entity (`kevotosin`) and the seven underlying log rows, then classified and documented it.
 
![Alert triage](screenshots/11-alert-triage-classification.png)
 
The classification comment matters as much as the classification:
 
> *Authorised test activity. Storage account deleted deliberately as part of SC-200 lab exercise. Caller (kevotosin) is the tenant administrator. No malicious activity. Rule functioning as designed.*
 
Classification data drives rule tuning. Marking authorised admin activity as a genuine threat pollutes your metrics and means nobody learns the rule needs a known-good exclusion. In the Defender portal this maps to **"Informational, expected activity"** rather than a true positive.
 
---
 
## 4. Threat hunting
 
**Detection is automated and looks for known-bad. Hunting is manual and looks for unknown-bad.**
 
Saved hunting query — **`Unusual Azure Operations by Caller`**:
 
```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where ActivityStatusValue == "Success"
| summarize OperationCount = count() by Caller, OperationNameValue
| sort by OperationCount desc
```
 
There's no threshold and no alert here. The point is to look at the *shape* of the data and spot what's abnormal.
 
![Hunting query](screenshots/12-hunting-query-saved.png)
 
**What the hunt surfaced:** `MICROSOFT.AUTHORIZATION` operations sat at the top (12 and 8). In a real environment, a spike in permission and role-assignment changes is exactly what privilege escalation looks like — an attacker with a foothold granting themselves rights. `MICROSOFT.KEYVAULT` operations also appeared, which in a real tenant would be a Credential Access flag.
 
In this lab both were benign (my own setup activity). **A hunt that finds nothing isn't a failed hunt — it's a hunt that confirms the environment is clean.**
 
The natural next step, and the reason hunting and detection feed each other: if this pattern were judged worth alerting on, you'd promote the hunting query into an analytics rule. Every good detection started life as somebody's hunt.
 
---
 
## 5. Visualisation
 
A two-tile workbook. Raw logs are unreadable to anyone but an analyst — a workbook is how you make the environment legible to a manager or a client.
 
![Workbook](screenshots/13-workbook-dashboard.png)
 
**Tile 1 — operations by type (bar):**
```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where ActivityStatusValue == "Success"
| summarize OperationCount = count() by OperationNameValue
| sort by OperationCount desc
| take 10
```
 
**Tile 2 — deletions over time (time chart):**
```kql
AzureActivity
| where TimeGenerated > ago(7d)
| where OperationNameValue contains "delete"
| summarize Deletions = count() by bin(TimeGenerated, 1d)
```
 
This is also where the noise problem became visible — the dashboard is what told me my rule was over-firing.
 
---
 
## 6. SOAR — automated response
 
Built a Logic App playbook, **`Add-Incident-Comment`**, with a **Microsoft Sentinel incident trigger** and one action: post an enrichment comment onto the incident.
 
I deliberately chose a non-destructive action. The goal was to prove the orchestration chain, not to wire up something that could break the environment.
 
![Automation](screenshots/15-automation-create-playbook.png)
![Deploy playbook](screenshots/16-playbook-deploy.png)
![Logic App designer](screenshots/17-logic-app-designer.png)
 
Attached to the detection rule via an **automation rule**, and enabled.
 
![Active playbook](screenshots/18-active-playbook-enabled.png)
 
### Permissions run in two directions
 
This is the part that catches people, and it caught me:
 
1. **Sentinel needs permission to *run* the playbook** — granted by scoping playbook permissions to the resource group (Sentinel Automation Contributor).
2. **The playbook needs permission to *act on* Sentinel** — granted by assigning **Microsoft Sentinel Responder** to the Logic App's managed identity.
![Managed identity role assignment](screenshots/19-managed-identity-rbac.png)
 
Granting the first without the second gets you a playbook that fires and then fails. That's least privilege working as designed — Sentinel can't run arbitrary Logic Apps, and a Logic App can't touch Sentinel, unless you explicitly say so.
 
---
 
## Known issue: playbook action failure
 
**Documented rather than hidden, because the debugging is the point.**
 
**Symptom:** trigger history shows **12 runs, all Succeeded, all Fired**. Run history shows **0 successful, 12 failed**.
 
![Trigger history](screenshots/20-trigger-history-succeeded.png)
 
That split is the whole diagnostic. The **trigger** reports "I was invoked and started a run." The **run** reports "everything after the trigger completed." Trigger succeeded + run failed = **the orchestration works; something inside the workflow broke.**
 
**What that proves:** the detection rule fired, created an incident, the automation rule matched it, and successfully invoked the playbook. The automated-response chain is verified end to end. The failure is in the final action.
 
**Error:**
```json
{
  "error": {
    "code": 400,
    "message": "The response is not in a JSON format.",
    "innerError": "Incident Arm id missing"
  }
}
```
 
**Hypothesis tested and rejected:** permissions. I assigned Microsoft Sentinel Responder to the Logic App's managed identity on the workspace. The failure persisted — and the error message was never a 403. **The evidence said permissions weren't the problem, so I dropped the theory.**
 
**Actual root cause:** the incident ARM ID isn't reaching the action. The action sends a request with an empty identifier, and Sentinel returns a malformed response. Rebinding the dynamic content and using the raw expression `triggerBody()?['object']?['id']` both failed to resolve it.
 
**Suspected origin:** earlier in the build I hit a `401 — access token is from the wrong issuer` error caused by a tenant/directory mismatch. I suspect the Sentinel API connection was created in that broken state and is passing a malformed payload.
 
**Decision:** timeboxed and deferred. The orchestration is verified; the outstanding fault is a payload-binding issue in one connector in a lab tenant with a known bad-token history. In a production team, the correct move at this point is to document the findings and escalate or raise a support ticket — not to burn a day alone on a platform bug.
 
> **Takeaway:** *don't fix what you haven't diagnosed.* The permissions theory was plausible and wrong, and the error message said so immediately. Reading the actual failure beat guessing at a likely one.
 
---
 
## Note on Defender for Cloud
 
I enabled Defender for Cloud (free CSPM tier) intending to review Secure Score and remediate recommendations. **It returned N/A with 0 assessed resources.**
 
That's not a fault — it's an accurate result. The subscription contained almost nothing to assess. **Posture management needs workloads to have a posture.**
 
I also uploaded an [EICAR test file](https://en.wikipedia.org/wiki/EICAR_test_file) to a storage container to see whether it would be flagged. It wasn't — and that's correct behaviour, not a miss:
 
- **Defender for Cloud CSPM (free)** = *posture*. Is this resource configured badly? It doesn't inspect file contents.
- **Defender for Storage (paid)** = *workload protection*. Is there malware in this storage account? That plan was deliberately not enabled, to stay inside the budget.
Knowing which Defender plan covers which signal is the actual lesson here.
 
---
 
## What I'd do next
 
- Onboard an endpoint and ingest device telemetry — the current build only sees control-plane activity
- Rebuild the playbook in a clean tenant to isolate the payload-binding fault
- Write detections mapped to more MITRE techniques (T1110 brute force, T1059 PowerShell, T1071 C2 beaconing) and tune each against false positives
- Promote the hunting query into a scheduled analytics rule with a sensible threshold
- Onboard workloads so Defender for Cloud has something to grade, then remediate against Secure Score
---
 
## What this lab actually taught me
 
The parts that broke taught me more than the parts that worked.
 
- **Ingestion lag is a property of every SIEM, not a fault.** What you see in the console is always slightly behind reality, which is why lookback windows exist.
- **Detection engineering is tuning.** Writing the KQL is the easy half. The hard half is not drowning the queue.
- **Understand what sits under the abstraction.** Azure Policy failed; knowing it was just wrapping a Diagnostic Setting is what let me fix it by hand.
- **Read the error before you form a theory.** The permissions hypothesis was reasonable and completely wrong.
- **Timebox and document.** Knowing when to stop, write up your findings, and escalate is a professional skill, not a retreat.
---
 
*Built in a personal Azure subscription under a £10 budget cap. All resources deployed to a single resource group and torn down after documentation.*
