![hierarchy-1-1](https://github.com/user-attachments/assets/d8b40e23-64e0-43cc-a314-8c3541d4295b)

1. What Azure privilege escalation is (with examples, but not exploit steps)
2. Detection: native tools + Prowler for Azure
3. Prevention & mitigation: detailed GUI + CLI steps for common risky patterns
4. Ongoing governance: policies, PIM, Defender for Cloud, monitoring

---

## 1. What is Privilege Escalation in Azure?

In Azure, **privilege escalation** means a principal (user, group, service principal, managed identity, workload identity) with limited intended permissions can leverage misconfigurations to gain **higher privileges** in:

* **Microsoft Entra ID (formerly Azure AD)** – directory / global admin level
* **Azure RBAC** – subscription, resource group, or resource scopes (Owner, Contributor, etc.)

Typical causes are:

* Overly broad **Azure RBAC** roles (e.g., too many Owners, or Contributor + User Access Administrator).([Security Boulevard][1])
* High privilege **Entra ID roles** (e.g., Global Admin, Privileged Role Administrator, Application Administrator) assigned unnecessarily.
* Misconfigured **service principals / app registrations** with powerful **Graph API permissions** (Directory.ReadWrite.All, etc.).([CoreView][2])
* Over-privileged **managed identities** attached to VMs, Functions, Logic Apps, etc., that can be used to perform actions as those identities.
* Weak or missing **MFA / Conditional Access** for privileged roles.

### 1.1 High-Level Example (No Exploit Detail)

**Example path:**

1. A user has **Contributor** and **User Access Administrator** on a subscription.
2. Contributor allows them to deploy resources; User Access Administrator allows them to modify role assignments.
3. They can assign themselves (or a service principal they control) the **Owner** role at subscription scope.
4. Once Owner, they essentially fully control resources and role assignments in that subscription (effective escalation).

Our goal is to **detect these patterns and remove them**, not to exploit them.

---

## 2. Detection – Step-by-Step

We will use:

* **Prowler for Azure** (multi-cloud CSPM that also supports Azure).([GitHub][3])
* **Azure native tools**:

  * Azure Portal (RBAC, Role Assignments)
  * Entra ID roles + Privileged Identity Management (PIM)
  * Microsoft Defender for Cloud recommendations([Azure Documentation][4])
  * Azure Policy, Activity Logs, Entra Audit Logs

### 2.1 Prepare Scope and Access

#### 2.1.1 Decide Scope

List:

* Azure tenants (usually one)
* Subscriptions in scope (Prod, Non-prod, Shared, etc.)

For each subscription, you will identify privileged roles and run assessments.

#### 2.1.2 Create a Security “Audit” Identity

For **Prowler and native analysis**, use **least-privileged read roles**:

* At subscription level:

  * `Reader`
  * `Security Reader` (for Defender for Cloud & security alerts)([doppler.com][5])

For Entra ID checks, create a **Service Principal** (App registration) with:

* `Directory.Read.All`
* `Policy.Read.All`
* Optionally `UserAuthenticationMethod.Read.All` (for MFA-related checks).([Cloud Infrastructure Services][6])

You can do this in GUI or CLI.

---

### 2.2 Configure Prowler for Azure (Detection Engine)

Prowler now supports **Azure** with hundreds of checks, including identity and misconfiguration issues.([GitHub][3])

#### 2.2.1 Install Prowler (CLI)

On a security workstation / VM:

```bash
pip install prowler
```

(or clone from GitHub if you prefer).

#### 2.2.2 Create Azure Service Principal for Prowler

Using Azure CLI (in a security or tooling subscription):

```bash
az ad sp create-for-rbac \
  --name prowler-sp \
  --role "Reader" \
  --scopes /subscriptions/<SUBSCRIPTION_ID>
```

This outputs:

* `appId`  → `AZURE_CLIENT_ID`
* `tenant` → `AZURE_TENANT_ID`
* `password` → `AZURE_CLIENT_SECRET`

Export these in your environment:

```bash
export AZURE_CLIENT_ID="XXXXXXXXX"
export AZURE_TENANT_ID="XXXXXXXXX"
export AZURE_CLIENT_SECRET="XXXXXXX"
```

(Or configure via Prowler App as per docs.([prowler.mintlify.app][7]))

#### 2.2.3 Run Prowler for Azure

Run a baseline scan:

```bash
prowler azure --sp-env-auth \
  -o azure-reports/ \
  -M json,csv
```

This will produce JSON/CSV with findings for:

* Azure RBAC, Entra ID, storage, compute, etc.([Microsoft Marketplace][8])

Focus first on:

* Identity & Access findings
* Recommendations about high privilege assignments, missing MFA, public access, etc.

Keep reports in a central repo (e.g., storage account + Defender for Cloud / SIEM).

---

### 2.3 Use Azure Native Views for Privilege Analysis

#### 2.3.1 Discover Highly-Privileged Azure RBAC Assignments

**Via Portal (GUI)**

1. Go to **Azure Portal** → **Subscriptions**
2. Select a subscription → **Access control (IAM)**
3. Use **View access to this resource** and **Role assignments**
4. Filter by roles:

   * Owner
   * User Access Administrator
   * Contributor (esp. combined with others)

Export assignments if needed.

**Via Azure CLI**

List all role assignments at subscription scope:

```bash
az role assignment list \
  --subscription <SUBSCRIPTION_ID> \
  --include-inherited \
  --output table
```

Filter for Owner:

```bash
az role assignment list \
  --subscription <SUBSCRIPTION_ID> \
  --include-inherited \
  --role "Owner" \
  --output table
```

Filter for User Access Administrator:

```bash
az role assignment list \
  --subscription <SUBSCRIPTION_ID> \
  --include-inherited \
  --role "User Access Administrator" \
  --output table
```

These are prime candidates for potential escalation (too many Owners, UAAs, etc.).

---

#### 2.3.2 Discover High-Privilege Entra ID Roles

**Via Portal**

1. Go to **Entra ID** → **Roles and administrators**
2. Inspect roles:

   * Global Administrator
   * Privileged Role Administrator
   * Security Administrator
   * Application Administrator / Cloud Application Administrator
3. For each role, click and view **Assignments**:

   * Look for permanent + large group assignments
   * Identify external or non-human accounts

**Via Azure CLI**

List all directory roles:

```bash
az ad role list --output table
```

List members of a specific role (e.g., Global Administrator):

```bash
az ad role assignment list \
  --role "Global Administrator" \
  --output table
```

(For Entra ID, sometimes you use `az role assignment list` with `--assignee` and `--role` or PowerShell / Graph API for more detail.)

---

#### 2.3.3 Identify Over-Privileged Service Principals & Managed Identities

**Service Principals & App Registrations**

In Portal:

1. Entra ID → **App registrations** and **Enterprise applications**
2. Look for applications with:

   * Delegated or application permissions such as `Directory.ReadWrite.All`, `Directory.AccessAsUser.All`, `Files.ReadWrite.All`, etc.([CoreView][2])
3. Check **Permissions → Grant admin consent** history.

Via CLI:

```bash
# List service principals with roles at subscription
az role assignment list \
  --subscription <SUBSCRIPTION_ID> \
  --include-inherited \
  --output table \
  --assignee-object-id <SP_OBJECT_ID>
```

**Managed Identities**

For each VM / Function / Logic App / Automation Account:

* Portal → Resource → **Identity**
* Check what role assignments exist for the managed identity (Subscriptions → IAM → filter by principal name).

Over-privileged managed identities are strong escalation vectors.

---

#### 2.3.4 Defender for Cloud Recommendations

**Microsoft Defender for Cloud** (formerly Azure Security Center) continuously evaluates misconfigurations and identity risks.([Azure Documentation][4])

In Portal:

1. Go to **Defender for Cloud**
2. Under **Workload protections** and **Recommendations**, filter:

   * Security Controls → **Identity & Access**
3. Pay attention to:

   * Too many owners
   * Missing MFA for privileged accounts
   * Defender plans disabled (Resource Manager, Azure AD, etc.)

These recommendations give additional context on identity-driven risk.

---

### 2.4 Prioritize Findings

Create a simple matrix:

* **Critical**:

  * Non-PIM, permanent Global Admin / Owner on production.
  * Many Owners at subscription/management-group scope.
  * Service principals or managed identities with high privileges + access to compute.
* **High**:

  * User Access Administrator widely assigned.
  * App registrations with Directory.*.All or Graph privileges + admin consent.
  * Automation accounts or Logic Apps running as high-privilege identities.
* **Medium / Low**:

  * Missing MFA, non-hardened conditional access, etc.

Log each in your tracking system with:

* Principal
* Scope
* Risk description (high-level escalation path)
* Recommended fix
* Owner team

---

## 3. Mitigation & Prevention – Step-by-Step (GUI + Azure CLI)

We will handle the most important problem types and show **how to fix via Portal and `az`**.

---

### 3.1 Problem 1 – Too Many `Owner` or `User Access Administrator` Assignments

These principals can grant themselves or others high access → classic privilege-escalation base.

#### 3.1.1 Fix in Azure Portal (GUI)

Per subscription:

1. Go to **Subscriptions** → select subscription → **Access control (IAM)**.
2. Click **Role assignments**.
3. Filter by **Role: Owner**.
4. For each non-essential owner:

   * Click the triple-dot `...` → **Remove**.
5. Repeat for **User Access Administrator**.
6. Reassign lesser roles when needed:

   * e.g., `Contributor` or a custom scoped role for that team/project.

#### 3.1.2 Fix Using Azure CLI

List Owners:

```bash
az role assignment list \
  --subscription <SUBSCRIPTION_ID> \
  --role "Owner" \
  --include-inherited \
  --output json > owners.json
```

Inspect the file and identify `id` or the `principalId` you want to remove.

Remove specific Owner assignment:

```bash
az role assignment delete \
  --ids <ROLE_ASSIGNMENT_ID>
```

Or, by parameters:

```bash
az role assignment delete \
  --assignee <PRINCIPAL_ID_OR_UPN> \
  --role "Owner" \
  --scope "/subscriptions/<SUBSCRIPTION_ID>"
```

Do the same for `User Access Administrator`.

---

### 3.2 Problem 2 – Over-Privileged Custom Roles (Wildcard Actions)

Custom roles with `"actions": ["*"]` or too broad scopes are risky.

#### 3.2.1 Detect & Fix via Portal

1. Portal → **Subscriptions** → **Access control (IAM)** → **Roles**
2. Filter by **Type: Custom role**.
3. Open each suspicious role and inspect **Permissions**:

   * Look for `*` actions or very broad operations.
4. Edit the role:

   * Use **Edit** → remove wildcard actions.
   * Replace with specific actions required by the workload.
5. Save and ensure dependent assignments still work as intended (least privilege).

#### 3.2.2 Fix via Azure CLI

Export a custom role definition:

```bash
az role definition list --name "<CustomRoleName>" > role.json
```

Open `role.json` and edit:

* Replace `"actions": ["*"]` with a limited set, e.g.:

```json
"actions": [
  "Microsoft.Storage/storageAccounts/read",
  "Microsoft.Storage/storageAccounts/blobServices/containers/*"
]
```

Apply updated definition:

```bash
az role definition update --role-definition role.json
```

Repeat for each dangerous role.

---

### 3.3 Problem 3 – Over-Privileged Service Principals (App Registrations)

Service principals with high Graph or RBAC privileges can be used to escalate if compromised.

#### 3.3.1 Fix Application API Permissions (GUI)

1. Entra ID → **App registrations** → select app.
2. Go to **API permissions**.
3. Look for:

   * Microsoft Graph permissions like `Directory.ReadWrite.All`, `Directory.AccessAsUser.All`, `User.ReadWrite.All`, etc.([CoreView][2])
4. Remove unnecessary high-privilege permissions:

   * Select permission → **Remove**.
5. Re-grant only what is minimal and obtain admin consent for those.

#### 3.3.2 Fix RBAC Role Assignments of Service Principals (GUI)

1. Subscriptions → **Access control (IAM)** → **Role assignments**.
2. Filter by **Principal type: Service principal**.
3. Identify service principals with:

   * Owner, Contributor, User Access Administrator, or custom high roles.
4. Reduce their roles or revoke as needed:

   * `...` → **Remove** role assignment.
5. Optionally assign a narrower role (e.g., `Reader` at specific resource group).

#### 3.3.3 Fix via Azure CLI

List role assignments for a specific service principal:

```bash
SP_ID="<SERVICE_PRINCIPAL_OBJECT_ID>"

az role assignment list \
  --assignee $SP_ID \
  --include-inherited \
  --output table
```

Remove a high-privilege assignment:

```bash
az role assignment delete \
  --assignee $SP_ID \
  --role "Owner" \
  --scope "/subscriptions/<SUBSCRIPTION_ID>"
```

Then, if needed, re-assign a scoped role:

```bash
az role assignment create \
  --assignee $SP_ID \
  --role "Reader" \
  --scope "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RG_NAME>"
```

---

### 3.4 Problem 4 – Managed Identities with Broad RBAC

Managed identities tied to workloads (VMs, Functions, Logic Apps) with high rights are a ready-made escalation path if that workload is compromised.

#### 3.4.1 Fix Using Portal

For each resource (VM, Function, Logic App, Automation Account):

1. Portal → Select resource → **Identity**.
2. Identify the **System-assigned** or **User-assigned managed identity**.
3. Click the identity name to open it (or search in Entra ID → **Enterprise applications**).
4. For the managed identity:

   * Check **Azure role assignments** at subscription, resource group, and resource.
   * Remove Owner/Contributor/User Access Administrator where not strictly needed.
   * Replace with more scoped roles (e.g., `Storage Blob Data Reader` on a single storage account).

#### 3.4.2 Fix Using Azure CLI

List role assignments for a managed identity:

```bash
MI_ID="<MANAGED_IDENTITY_OBJECT_ID>"

az role assignment list \
  --assignee $MI_ID \
  --include-inherited \
  --output table
```

Remove high-privilege:

```bash
az role assignment delete \
  --assignee $MI_ID \
  --role "Contributor" \
  --scope "/subscriptions/<SUBSCRIPTION_ID>"
```

Re-assign with least privilege:

```bash
az role assignment create \
  --assignee $MI_ID \
  --role "Storage Blob Data Reader" \
  --scope "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/<RG_NAME>/providers/Microsoft.Storage/storageAccounts/<ACCOUNT_NAME>"
```

---

### 3.5 Problem 5 – Privileged Roles Without MFA / PIM

Even if permissions are correct, lack of **MFA** and **JIT elevation** increases the risk of abuse.

#### 3.5.1 Fix via Entra ID – Conditional Access

1. Entra ID → **Security → Conditional Access → Policies**.
2. Create or edit a policy:

   * Assignments → Users: select **Directory roles** and choose privileged roles.
   * Cloud apps: **All cloud apps** (or at least management apps).
   * Grant → **Require multi-factor authentication**.
3. Enable the policy (after testing with report-only mode).

#### 3.5.2 Enable and Configure Privileged Identity Management (PIM)

PIM allows **just-in-time role activation**.([Microsoft Learn][9])

1. Entra ID → **Privileged Identity Management**.
2. Configure PIM for:

   * Entra ID roles (Global Admin, etc.).
   * Azure resource roles (Owner, Contributor, etc.).
3. Convert permanent role assignments into:

   * **Eligible** assignments with approval workflows.
4. Require MFA for activation, set maximum activation durations.

This significantly reduces the window for privilege escalation misuse.

---

### 3.6 Problem 6 – Automation Accounts / Runbooks / Logic Apps Running as High-Privilege Identities

These can be used to automate escalation if roles are too powerful.

#### 3.6.1 Fix via Portal

For **Automation Accounts**:

1. Portal → Automation Account → **Account settings → Identity**
2. See which identity it uses (system/user managed).
3. Reduce RBAC for that identity as in 3.4.

For **Logic Apps / Functions**:

1. Check **Identity** and **Access control (IAM)** at subscription/RG/resource.
2. Ensure they use least privilege roles.

#### 3.6.2 Fix via CLI

This is similar to the managed identity steps: you adjust the RBAC of the identity used by the automation resource.

---

## 4. Continuous Governance & Monitoring

Once you fix current issues, you need **repeatable controls**.

### 4.1 Azure Policy – Prevent New Misconfigurations

Use **Azure Policy** to block or flag risky configurations:

* Disallow assigning `Owner` to anything but a small set of principals.
* Enforce that only certain roles can be used at subscription scope.
* Require MFA/Defender plans via built-in policies and initiatives.([Microsoft Learn][10])

Deploy at:

* Management Group scope (prod vs non-prod), or
* Subscription level for smaller environments.

---

### 4.2 Microsoft Defender for Cloud – Ongoing Misconfiguration Detection

Defender for Cloud provides:

* CSPM (Cloud Security Posture Management) capabilities
* Identity & Access recommendations
* Threat alerts (suspicious role assignments, unusual operations).([Azure Documentation][4])

Configure:

1. Enable Defender for Cloud on all subscriptions.
2. Turn on the relevant Defender plans (Servers, Resource Manager, etc.).
3. Integrate with your SIEM (e.g., Sentinel) for alerting and correlation.([wiz.io][11])

---

### 4.3 Regular Prowler Scans

Operationalize Prowler:

* Schedule Prowler scans (e.g., daily/weekly) against your subscriptions.([GitHub][3])
* Export reports to:

  * Storage Account + Log Analytics, or
  * Your SIEM.
* Create alerting or ticketing integration for new **Critical/High** findings.

---

### 4.4 Logging & Audit

Enable and use:

* **Azure Activity Log** for subscription-level operations (role assignments, policy changes).
* **Entra Audit Logs** for directory changes (role assignments, app registrations).
* **Entra Sign-in Logs** for risky sign-ins.

Route them to:

* **Log Analytics / Sentinel** for correlation with alerts such as “suspicious privilege escalation”, “new owner assignment”, etc.([Microsoft Learn][9])

---

### 4.5 Process & SOP

Document a formal **Azure Privilege Escalation SOP**:

* How to run Prowler for Azure and interpret results
* How to review RBAC & Entra roles
* Standard mitigation steps (like the ones above)
* SLAs per severity (Critical, High, etc.)
* Who owns fixing what (platform team vs app teams)

---

  * Azure/Prowler finding → Risk → Portal Fix → `az` CLI Fix → Owner → SLA.

[1]: https://securityboulevard.com/2025/07/common-misconfigurations-found-during-azure-pentesting/?utm_source=chatgpt.com "Common Misconfigurations Found During Azure Pentesting"
[2]: https://www.coreview.com/blog/elevation-of-privilege-vulnerabilities?utm_source=chatgpt.com "Microsoft 365 Attack Surfaces: Elevation of Privilege ..."
[3]: https://github.com/prowler-cloud/prowler?utm_source=chatgpt.com "prowler-cloud/prowler"
[4]: https://docs.azure.cn/en-us/defender-for-cloud/prevent-misconfigurations?utm_source=chatgpt.com "How to prevent misconfigurations - Microsoft Defender for ..."
[5]: https://www.doppler.com/blog/securing-azure-cloud-environments-implementing-prowler-cspm-with-doppler-integration?utm_source=chatgpt.com "Securing Azure cloud environments: implementing Prowler ..."
[6]: https://cloudinfrastructureservices.co.uk/cloud-security-assessment-tool-using-prowler-on-azure-aws-gcp/?utm_source=chatgpt.com "Cloud Security Assessment Tool using Prowler on Azure/AWS ..."
[7]: https://prowler.mintlify.app/user-guide/providers/azure/getting-started-azure?utm_source=chatgpt.com "Getting Started With Azure on Prowler"
[8]: https://marketplace.microsoft.com/en-us/marketplace/apps/cloud-infrastructure-services.prowler?tab=Overview&utm_source=chatgpt.com "Cloud Security Posture Management (CSPM) Tool"
[9]: https://learn.microsoft.com/en-us/answers/questions/5508556/privilege-escalation-trigger-%28admin-investigation?utm_source=chatgpt.com "Privilege Escalation Trigger (Admin Investigation Required ..."
[10]: https://learn.microsoft.com/en-us/azure/defender-for-cloud/recommendations-reference-data?utm_source=chatgpt.com "Reference table for all data security recommendations ..."
[11]: https://www.wiz.io/academy/azure-security-risks?utm_source=chatgpt.com "Azure Security Risks & Mitigation Steps"
