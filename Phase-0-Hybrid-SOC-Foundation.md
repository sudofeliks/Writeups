# Phase 0: On-Premises Hybrid SOC Foundation, Threat Intelligence Node & Cloud IaC Preparation

> **OPSEC & Sanitization Note:** In accordance with enterprise security documentation standards (*TLP:CLEAR*), all internal network addresses, subnet CIDRs, and host IPs in this writeup are represented using semantic placeholders (e.g., `<DC_IP>`, `<CTI_NODE_IP>`, `<LAB_GATEWAY_IP>`, `<SOC_LAB_SUBNET>`, `<HOME_LAN_SUBNET>`).

## 1. Executive Summary & Hybrid Architecture Strategy

Traditional cybersecurity homelabs typically rely on isolated, self-hosted open-source tools such as a standalone Wazuh SIEM instance. While effective for learning basic log collection, this model diverges significantly from modern enterprise environments, which predominantly operate on unified cloud security ecosystems—specifically **Microsoft Sentinel**, **Microsoft Defender XDR**, **Microsoft Entra ID P2**, and **Microsoft Intune**.

The objective of this project is to engineer an enterprise-grade **Hybrid Security Operations Center (SOC) and Cyber Range** that bridges on-premises virtualization (**Proxmox VE**) with **Microsoft Cloud Security**:

* **FinOps & Compute Optimization:** Hosting core corporate workloads locally on Proxmox VE (Windows Server 2025 Active Directory Domain Controller, Windows 11 corporate workstation, Ubuntu Docker host for MISP Threat Intelligence and OWASP Juice Shop, and a Kali Linux Red Team machine) eliminates continuous cloud VM compute charges.

## 2. Step 1: Active Directory Configuration, Test Identities & Advanced GPO Auditing

Identity represents the primary security perimeter in hybrid enterprises, with the vast majority of intrusions originating from credential theft or session token hijacking. On the **Windows Server 2025** virtual machine, the Active Directory Domain Services (`AD DS`) role was deployed to establish the root forest for `soclab.local`.

### Organizational Unit (OU) Design for Red/Blue Team Scenarios

Within *Active Directory Users and Computers* (`dsa.msc`), dedicated Organizational Units were structured to mirror corporate hierarchy and prepare for hybrid synchronization with **Microsoft Entra ID** via **Microsoft Entra Connect**:

* **`SOC_Users`:** Contains domain user identities, specifically `analyst01` (SOC tier-1/2 analyst account) and `aitm-target` (the designated victim identity for Phase 4 *Adversary-in-the-Middle* session hijacking simulations).

* **`SOC_Workstations`:** Houses domain-joined corporate endpoints subject to centralized security telemetry and EDR onboarding policies.

> 📸 **\[Screenshot: Active Directory `SOC_Users` Organizational Unit\]**
> 
> ![Figure 1: Active Directory SOC_Users Organizational Unit](Pictures/On-Premises%20Foundation/Screenshot%20From%202026-11-06%2012-32-07.png)
> 
> *Figure 1: `dsa.msc` on Windows Server 2025 (`<DC_IP>`) displaying the `SOC_Users` OU with the `analyst01` and `aitm-target` accounts.*

> 📸 **\[Screenshot: Active Directory `SOC_Workstations` Organizational Unit\]**
> ![Figure 2: Active Directory SOC_Workstations Organizational Unit](Pictures/On-Premises%20Foundation/Screenshot%20From%202026-11-06%2012-33-07.png)
> 
> *Figure 2: `dsa.msc` displaying the `SOC_Workstations` OU containing the domain-joined Windows 11 endpoint.*

### Enforcing Granular Authentication Telemetry via GPO (Event ID 4624 & 4625)

By default, Windows does not log all granular authentication events required for SIEM correlation rules. To ensure the **Azure Monitor Agent (AMA)** captures both successful and failed authentication attempts (especially over Remote Desktop Protocol) for **Microsoft Sentinel**, the `Default Domain Policy` was modified in the *Group Policy Management Editor* (`gpmc.msc`).

Under `Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> Audit Policies -> Logon/Logoff`, both **Audit Logon** and **Audit Other Logon/Logoff Events** were configured to record **Success and Failure** events (generating Windows Security Event IDs `4624` and `4625`).

> 📸 **\[Screenshot: Group Policy Management Editor – Advanced Audit Policy Configuration\]**
> > > ![Figure 3: Enforcing Success and Failure logon auditing](Pictures/On-Premises%20Foundation/Screenshot%20From%202026-11-06%2012-40-34.png)
> 
> *Figure 3: Enforcing `Success and Failure` logon auditing via Domain Group Policy (`gpmc.msc`).*

### Endpoint Domain Join (`Win11Victim`)

The Windows 11 workstation was renamed to `Win11Victim`, configured to use the Domain Controller (`<DC_IP>`) as its primary DNS resolver with the pfSense firewall as secondary, and joined to the `soclab.local` domain. A domain session was established under `soclab\aitm-target` and Group Policy application was verified via `gpresult /r`.

> 📸 **\[Screenshot: Domain Session & GPO Verification on `Win11Victim`\]**
> 
> ![Figure 4: Domain Session and GPO Verification on Win11Victim](Pictures/On-Premises%20Foundation/Screenshot%20From%202026-11-06%2012-29-14.png)
> 
> *Figure 4: Terminal verification on `Win11Victim` confirming authentication as `soclab\aitm-target` (`whoami`) and successful retrieval of domain Group Policy objects (`gpresult /r`).*

## 3. Step 2: Ubuntu Server Transformation – Containerized MISP CTI & OWASP Juice Shop

In the legacy homelab iteration, the Ubuntu Server VM hosted a local Wazuh SIEM stack. By migrating SIEM/SOAR operations to **Microsoft Sentinel**, the resource-heavy Wazuh/OpenSearch services were completely purged, reclaiming significant RAM and SSD I/O capacity. The server was repurposed into a lightweight Docker container host serving two distinct functions:

1. **Cyber Threat Intelligence (CTI) Node (MISP):** Aggregating open-source intelligence (OSINT) feeds containing malicious Indicators of Compromise (IOCs) and exposing them via REST API for automated ingestion into Microsoft Sentinel.

2. **Vulnerable Web Application Target (OWASP Juice Shop):** Running an intentionally vulnerable e-commerce web application on port `3000` to test layer-7 inspection and blocking via **Azure Application Gateway Web Application Firewall (WAF v2)**.

The legacy Wazuh installation was removed and Docker Engine with Docker Compose v2 was deployed:

```bash
sudo systemctl stop wazuh-manager wazuh-indexer wazuh-dashboard filebeat
sudo apt-get purge -y wazuh-manager wazuh-indexer wazuh-dashboard filebeat
sudo rm -rf /var/ossec /etc/wazuh* /var/lib/wazuh* /usr/share/wazuh*
sudo apt-get autoremove -y

sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 git curl
sudo systemctl enable --now docker
```

Next, the **OWASP Juice Shop** container was deployed with an automatic restart policy, followed by cloning the official `misp-docker` repository and configuring `BASE_URL=https://<CTI_NODE_IP>` inside the `.env` configuration file:

```bash
sudo docker run -d --restart always -p 3000:3000 --name juice-shop bkimminich/juice-shop

git clone https://github.com/MISP/misp-docker.git
cd misp-docker
cp template.env .env
sed -i 's|BASE_URL=.*|BASE_URL=https://<CTI_NODE_IP>|' .env
sudo docker compose up -d
```

### Engineering Challenges & Troubleshooting: Resolving the `misp-nginx` Crash Loop & TLS Certificate Provisioning

During the initial deployment of the MISP multi-container stack (`sudo docker compose up -d`), two realistic deployment issues emerged and were systematically diagnosed:

1. **Database Initialization Timeout (`misp-core-1 is unhealthy`):** While supporting containers (`redis`, `db`, `mail`, `misp-modules`) started immediately, `misp-docker-misp-core-1` initially reported `dependency failed to start: container misp-docker-misp-core-1 is unhealthy`. Inspecting the live container stream (`sudo docker logs -f misp-docker-misp-core-1`) revealed that first-boot MariaDB schema population and PHP-FPM configuration exceeded Docker's default healthcheck window. Allowing the initialization to reach `MISP now live, users can now log in` and re-running `sudo docker compose up -d` transitioned `misp-core-1` to a stable `healthy` state.

2. **Reverse Proxy Crash Loop (`misp-docker-misp-nginx-1 Restarting (1)`):** Although the core application and `juice-shop` (port `3000`) were operational, attempting to access `https://<CTI_NODE_IP>` from the internal subnet resulted in `Connection refused`. Running `sudo docker ps -a` showed `misp-docker-misp-nginx-1` stuck in a continuous `Restarting (1)` loop without binding ports `80` or `443`.

> 📸 **\[Screenshot: Docker Diagnostics – `misp-nginx` Restart Loop\]**
> ![Figure 5: misp-docker-misp-nginx-1 Restarting state](Pictures/On-Premises%20Foundation/Screenshot%20From%202026-11-07%2013-18-26%201.png)
> 
> *Figure 5: Container diagnostics showing `misp-docker-misp-nginx-1` in a `Restarting (1)` state prior to TLS certificate provisioning.*

#### Root Cause Analysis & Resolution

Inspecting the container logs directly (`sudo docker logs misp-docker-misp-nginx-1`) and examining the entrypoint initialization script inside the image (`sudo docker run --rm --entrypoint cat ghcr.io/misp/misp-docker/misp-nginx:latest /docker-entrypoint.d/01-listen.sh`) uncovered the exact failure condition:

```text
BASE_URL starts with https:// but SSL certificate is NOT present. Please update your env variables.
```

The entrypoint script `01-listen.sh` explicitly checks for `/etc/nginx/certs/cert.pem` and `/etc/nginx/certs/key.pem` (mapped from the host `./ssl` directory) whenever `BASE_URL` uses the `https://` scheme. To resolve this, a 2048-bit RSA private key and a self-signed X.509 certificate (`CN=<CTI_NODE_IP>`) were generated directly inside `~/misp-docker/ssl` with read permissions granted to the container process:

```bash
cd ~/misp-docker
mkdir -p ssl
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout ssl/key.pem \
  -out ssl/cert.pem \
  -subj "/C=PL/ST=SOC/L=Lab/O=HybridSOC/CN=<CTI_NODE_IP>"
sudo chmod 644 ssl/key.pem ssl/cert.pem
sudo docker compose up -d
```

Immediately after provisioning the X.509 certificate pair, `misp-docker-misp-nginx-1` bound ports `80/tcp` and `443/tcp` on `<ANY_INTERFACE_IP>` and achieved a `healthy` status. Inside the MISP web interface (`https://<CTI_NODE_IP>`), default administrator credentials were rotated, default OSINT feed metadata was loaded (`Sync Actions -> Feeds -> Load default feed metadata`), public threat feeds (**CIRCL OSINT Feed** and **The Botvrij.eu Data**) were enabled and cached, and a dedicated REST API authentication key (`MISP_KEY`) was generated for Microsoft Sentinel integration.

> 📸 **\[Screenshot: Healthy Docker Stack (`sudo docker ps`)\]**
> ![Figure 6: Healthy Docker Stack verification](Pictures/On-Premises%20Foundation/Screenshot%20From%202026-11-07%2014-04-19%201.png)
>
*Figure 6: Verification via `sudo docker ps` confirming all MISP microservices and the `juice-shop` container are running and `healthy`.*

> 📸 **\[Screenshot: OWASP Juice Shop Web Application on Port 3000\]**
> ![Figure 7: OWASP Juice Shop Web Application](Pictures/On-Premises%20Foundation/Screenshot%20From%202026-11-07%2014-09-53%201.png)
>
*Figure 7: OWASP Juice Shop running at `http://<CTI_NODE_IP>:3000`, ready for Azure Application Gateway WAF v2 testing.*

> 📸 **\[Screenshot: MISP Threat Intelligence Platform – Ingested OSINT IOCs\]**
> ![Figure 8: MISP Threat Intelligence Platform Ingested OSINT IOCs](Pictures/On-Premises%20Foundation/Screenshot%20From%202026-11-07%2014-55-21%201.png)
>
*Figure 8: MISP instance (`https://<CTI_NODE_IP>`) populated with network and domain Indicators of Compromise from public OSINT feeds.*

## 4. Step 3: Infrastructure as Code (Bicep), API Automation (Python) & Detection Engineering (KQL)

To ensure that the cloud deployment in **Phase 1** is repeatable, automated, and strictly aligned with budget constraints, all cloud infrastructure templates, API connectors, and SIEM detection queries were written and committed to the repository in advance.

### A. Declarative Azure Landing Zone (`iac/landing-zone.bicep` & `iac/sentinel-onboarding.bicep`)

Rather than relying on manual portal configuration (*ClickOps*), the cloud security foundation is defined declaratively using **Azure Bicep** following **Microsoft Cloud Adoption Framework (CAF)** naming conventions:

* **Cost-Conscious Parameterization (`param deployBastion bool = false`):** Because Azure Bastion (Standard SKU) incurs continuous hourly charges, the template wraps the `pip-bastion-cyberrange` and `bas-cyberrange` resources in a conditional `if (deployBastion)` block defaulted to `false`. This allows deploying the entire virtual network and SIEM storage at zero fixed cost, provisioning Bastion on-demand only when administrative sessions are required.

* **Centralized Telemetry Workspace (`law-cyberrange-prod-cus`):** Deploys a `Microsoft.OperationalInsights/workspaces` resource using the `PerGB2018` SKU with a `90`-day retention policy. The template exports `output workspaceId string = law.id` for downstream automation.

* **Perimeter Hardening via NSG (`nsg-cyberrange`):** Implements rule `deny-inbound-mgmt-internet` (Priority `4000`), which explicitly drops (`Deny`) all inbound traffic originating from the public `Internet` service tag destined for management ports SSH (`22`) and RDP (`3389`).

* **Virtual Network Segmentation (`vnet-cyberrange-prod-cus`):** Allocates the `<AZURE_VNET_CIDR>` address space segmented into three subnets: `snet-servers` (`<AZURE_SERVERS_SUBNET>`), `snet-clients` (`<AZURE_CLIENTS_SUBNET>`)—both protected by `nsg-cyberrange`—and the dedicated `AzureBastionSubnet` (`<AZURE_BASTION_SUBNET>`).

* **Automated SIEM Activation (`iac/sentinel-onboarding.bicep`):** References the existing Log Analytics Workspace and deploys the `Microsoft.SecurityInsights/onboardingStates@2024-03-01` resource at the workspace scope, programmatically enabling **Microsoft Sentinel**.

### B. Automated Threat Intelligence Connector (`src/misp_sentinel_connector.py`)

The custom Python 3 script automates the extraction of network IOCs from the on-premises MISP container and pushes them into Microsoft Sentinel via the **Upload Indicators REST API**:

1. **`get_entra_token()` – OAuth 2.0 Client Credentials Flow:** Authenticates against `https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token` using an Entra ID App Registration (`CLIENT_ID` and `CLIENT_SECRET`) scoped to `https://management.azure.com/.default`, retrieving a short-lived `Bearer` access token.

2. **`fetch_misp_ip_indicators()` – MISP REST API Extraction:** Queries `https://<CTI_NODE_IP>/attributes/restSearch` via HTTP `POST` using the `MISP_KEY` header. The JSON payload filters purely for actionable network indicators (`type: ["ip-dst", "ip-src"]`) that have the intrusion detection flag enabled (`to_ids: 1`).

3. **`build_stix_indicators()` – STIX 2.1 Normalization:** Microsoft Sentinel's Upload Indicators API requires indicators formatted in **STIX 2.1**. This function transforms raw MISP attributes into compliant STIX 2.1 `indicator` JSON objects containing deterministic IDs (`indicator--{uuid}`), detection patterns (`[ipv4-addr:value = '{ip_val}']`), `confidence: 100`, and classification labels (`["misp-osint", "malicious-ip"]`).

4. **`push_to_sentinel()` & Local Dry-Run Safeguard:** Transmits the STIX batch via `POST` to `https://sentinelus.azure-api.net/workspaces/{WORKSPACE_ID}/threatintelligenceindicators:upload?api-version=2022-07-01`, populating the `ThreatIntelligenceIndicator` table in Sentinel. If cloud environment variables are not yet populated (as during Phase 0 local testing), the `__main__` block automatically executes a local dry-run, verifying MISP connectivity and STIX serialization without throwing cloud authentication errors.

### C. Detection Engineering & Threat Hunting (`kql/sentinel-detections.kql`)

Four custom **Kusto Query Language (KQL)** queries were engineered to cover infrastructure, application, and identity attack surfaces across the hybrid environment:

1. **On-Premises RDP Logon vs. MISP Threat Intel Correlation (`SecurityEvent` + `ThreatIntelligenceIndicator`):** Declares an in-memory set `let Malicious_IPs` containing all high-confidence (`ConfidenceScore == 100`) IP addresses ingested from MISP. It then queries the `SecurityEvent` table (streamed from Proxmox Windows VMs via Azure Monitor Agent) for successful RDP logons (`EventID == 4624` and `LogonType == 10`) where `IpAddress in (Malicious_IPs)`, immediately alerting on remote access from known malicious infrastructure.

2. **OWASP Top 10 Web Attack Detection via WAF (`AzureDiagnostics`):** Filters `MICROSOFT.NETWORK` diagnostic logs within the `ApplicationGatewayFirewallLog` category for requests where `action_s == "Matched"` or `action_s == "Blocked"`. It projects the attacker IP (`clientIp_s`), target URI (`requestUri_s`), triggered OWASP CRS rule ID (`ruleId_s`), and inspection payload message (`details_message_s`).

3. **Entra ID Protection AiTM Risk Telemetry (`AADUserRiskEvents`):** Monitors identity risk detections for `aitm-target@yourlab.com` across a 24-hour window, specifically hunting for `attackerinTheMiddle`, `anomalousToken`, and `unfamiliarFeatures` flags generated during reverse-proxy phishing attacks.

4. **Advanced Hunting – Session Cookie Replay Detection (`AADSignInEventsBeta`):** When an attacker steals `ESTSAUTH` / `ESTSAUTHPERSISTENT` session cookies via `evilginx2` and imports them into another browser, the underlying `SessionId` remains identical across both locations. This Defender XDR Advanced Hunting query groups sign-in events `by SessionId`, aggregates distinct source IP addresses (`IPs = make_set(IPAddress)`), and triggers when `array_length(IPs) > 1`—providing high-fidelity detection of session token replay.

## 5. Step 4: Network Segmentation & Firewall Isolation on pfSense

The final step of Phase 0 enforced strict network isolation on the virtualized **pfSense** firewall to ensure that offensive simulations inside the SOC Lab cannot traverse into the private home LAN:

* **Red Team Repositioning:** The `Kali-Attacker` VM (`103`) network adapter was moved in Proxmox VE to bridge `vmbr1`, placing the attacker directly inside the isolated corporate lab segment.

* **RFC 1918 Home LAN Block Rule:** A top-priority firewall rule was configured on the pfSense `LAN` interface (`Action: Block`, `Interface: LAN`, `Protocol: Any`, `Source: LAN net`, `Destination: <HOME_LAN_SUBNET>`). This enforces a *silent drop* on all packets attempting to reach the private home network while permitting outbound HTTPS (`443`) traffic required by Azure Monitor Agent, Microsoft Defender for Endpoint, and the MISP-to-Sentinel API connector.

* **Verification:** Connectivity tests from `Win11Victim` confirmed 100% packet loss (`100% loss` / silent drop) when pinging the home gateway (`ping <HOME_GATEWAY_IP>`), while external connectivity (`ping <EXTERNAL_DNS_IP>`) succeeded without interruption.

## 6. Phase 0 Completion Status & Next Steps (Phase 1)

With the local Proxmox VE infrastructure hardened, Active Directory auditing active, the MISP Threat Intelligence and OWASP Juice Shop containers operational, and all Bicep/Python/KQL code committed to GitHub, **Phase 0 is 100% complete**.
