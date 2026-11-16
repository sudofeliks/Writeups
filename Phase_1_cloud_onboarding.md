# Phase 1: Cloud Foundation, Break-Glass Security & IaC Deployment

## 1. Objective
Following the zero-cost preparation of the on-premises Proxmox environment, Phase 1 focuses on establishing the cloud-based Security Operations Center (SOC). The goal is to provision the Azure landing zone using Infrastructure as Code (Bicep), secure the Microsoft Entra ID tenant with emergency access accounts, and unify the threat hunting portals (Microsoft Sentinel, Defender XDR, and Intune) into a single pane of glass.

## 2. Identity Security: Break-Glass Accounts Deployment
Implementing strict Conditional Access (CA) policies and Phishing-Resistant MFA (Passkeys) introduces the risk of an accidental tenant lockout. To adhere to Enterprise Identity best practices, two cloud-only emergency access accounts were created before any CA policies were configured.

* **Account Structure:** `breakglass1@<TENANT_DOMAIN>.onmicrosoft.com` and `breakglass2@<TENANT_DOMAIN>.onmicrosoft.com`.
* **Privileges:** Both accounts were assigned the `Global Administrator` and `Owner` RBAC roles.
* **Security Control:** These accounts utilize highly complex, 32+ character passwords stored securely offline. They will be strictly excluded from all future Conditional Access policies to ensure persistent backend access during identity outages.

> 📸 **\[Screenshot: BreakGlass Accounts\]**
> ![[Screenshot From 2026-11-15 10-51-33.png]]
>
 *Figure 1: View of the Entra ID Users panel showing the primary `socadmin` account and the two emergency Break-Glass accounts.*

## 3. Infrastructure as Code: Bicep Deployment
Instead of manual ClickOps, the core SOC infrastructure was deployed declaratively via Azure CLI using the pre-authored Bicep templates from Phase 0. 

A technical hurdle was encountered during the execution of `sentinel-onboarding.bicep`. The Azure CLI returned a `MissingSubscriptionRegistration` error for the `Microsoft.OperationsManagement` namespace. This is a common mechanism in fresh Azure subscriptions where resource providers are not enabled by default.

**Troubleshooting & Resolution:**
The missing resource providers were manually registered using the following CLI commands, after which the deployment succeeded:

```bash
az provider register --namespace Microsoft.OperationsManagement
az provider register --namespace Microsoft.SecurityInsights
az deployment group create --resource-group rg-cyberrange-prod-cus --template-file sentinel-onboarding.bicep
```

> 📸 **\[Screenshot: Azure Cloud Shell\]**
> ![[Screenshot From 2026-11-15 14-47-34.png]]
> 
  *Figure 2: Azure Cloud Shell terminal confirming the `provisioningState: Succeeded` output for the Bicep template deployments.*

## 4. XDR & SIEM Unification
The final step involved bridging the standalone Microsoft Sentinel workspace with the unified Microsoft Defender portal, allowing for seamless incident correlation across endpoints, identities, and cloud apps.

1. **UEBA & Entra ID Sync:** Inside Microsoft Sentinel, the User and Entity Behavior Analytics (UEBA) engine was enabled, and the Entra ID sync was configured to begin profiling cloud identities.
2. **Workspace Connection:** The `law-cyberrange-prod-cus` Log Analytics workspace was directly attached to `security.microsoft.com`.
3. **Endpoint Management Bridge:** To facilitate the automatic onboarding of Windows endpoints in subsequent phases, the Microsoft Intune connection was toggled on within Defender. The connection status in the Intune portal initially showed as `Available`. It was fully `Enabled` by toggling the "Allow Microsoft Defender for Endpoint to enforce Endpoint Security Configurations" and Windows device connection settings.

> 📸 **\[Microsoft Defender - Sentinel connected \]**
> ![[Writeups/Pictures/Cloud-onboarding/Screenshot From 2026-11-16 11-12-04.png]]
 `Sentinel-Defender-Unified.png` - *Microsoft Defender portal showing Microsoft Sentinel successfully connected to the unified workspace.*

> 📸 **\[Microsoft Intune Endpoint Security - Microsoft Defender for Endpoint - Enabled  \]**
> ![[Screenshot From 2026-11-16 11-22-11.png]]
> 
 `Intune-MDE-Connection.png` - *Microsoft Intune Endpoint Security panel displaying the connection status to Microsoft Defender for Endpoint as Enabled.*

## 5.  Phase 1 Completion Status & Next Steps (Phase 2)
With the cloud infrastructure provisioned and the portals unified, the environment is ready for **Phase 2**, which will focus on hybrid identity synchronization (Entra Connect) and dual-channel EDR onboarding for the on-premises servers and the Windows 11 victim machine.