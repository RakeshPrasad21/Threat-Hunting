# Threat-Hunting

## Getting Started

Before you start using this tool, you should register and login to these website and get your API keys. 
Please NOTE DOWN the API keys, some websites will show you the API keys only once.

| Api         | Description                                                | Auth    | Link    |
|-------------|------------------------------------------------------------|---------|---------|
| virustotal  | Check Whois information for IP address/Domain              | `apikey`|[Link](https://www.virustotal.com/gui/sign-in)|
| getipintel  | Check check if the IP is a proxy or spoofed                | `email` |[Link](https://getipintel.net/free-proxy-vpn-tor-detection-api/)|
| iphub       | Check check if the IP is a proxy or spoofed                | `apikey`|[Link](https://iphub.info/register)|
| shodan      | Check information about host and see if it was compromised | `apikey`|[Link](https://account.shodan.io/login)|
| apility.io  | Check reputation and activity through time                 | `apikey`|[Link](https://apility.io/)|
| hybrid      | Check association with malware                             | `apikey`|[Link](https://www.hybrid-analysis.com/)|
| malshare    | Check IP address/Domain was used to spread malware         | `apikey`|[Link](http://www.malshare.com/doc.php)|
| urlhause    | Check IP address/Domain was used to spread malware         | none    |none |
| threatcrowd | Check Current status                                       | none    |none |
| abuseipdb   | Check if it's blacklisted                                  | `apikey`|[Link](https://www.abuseipdb.com/)|
| urlscan.io  | Check further more information                             | none    |none |
| threatminer | Check further more information                             | none    |none |


Threat hunting is a proactive approach to identifying and mitigating potential security threats within an environment. Microsoft Sentinel, a cloud-native SIEM (Security Information and Event Management) solution, offers powerful tools for threat detection and investigation. Below is a general threat hunting procedure using Microsoft Sentinel:
 
### Microsoft Sentinel Threat Hunting Procedure:
 
#### 1. **Define Objectives:**
   - Clearly define the objectives of your threat hunting expedition.
   - Identify the types of threats or anomalies you are looking for.
 
#### 2. **Access Microsoft Sentinel:**
   - Log in to the Microsoft Sentinel dashboard.
 
#### 3. **Review Data Sources:**
   - Identify and review the data sources relevant to your threat hunting objectives.
   - Ensure that necessary logs, events, and telemetry are being ingested into Sentinel.
 
#### 4. **Create a Hunting Query:**
   - Develop a hunting query based on the identified threat indicators or suspicious activities.
   - Utilize Kusto Query Language (KQL) for creating queries.
 
#### 5. **Run the Query:**
   - Execute the query against the data sources to identify potential threats.
   - Refine the query as needed based on initial results.
 
#### 6. **Investigate Alerts and Incidents:**
   - Examine the generated alerts and incidents.
   - Correlate data from different sources to validate and understand the scope of the potential threat.
 
#### 7. **Enrich Data:**
   - Use threat intelligence feeds or additional context to enrich the data.
   - Leverage external information to determine the severity of the threat.
 
#### 8. **Create Custom Detection Rules:**
   - If necessary, create custom detection rules based on the identified threat patterns.
   - Fine-tune existing rules to improve detection accuracy.
 
#### 9. **Automate Responses:**
   - Set up automated response actions for identified threats.
   - Implement playbooks or workflows to respond to specific threat scenarios.
 
#### 10. **Document Findings:**
   - Document all findings, including false positives or negatives.
   - Keep a record of the steps taken during the investigation.
 
#### 11. **Share Insights:**
   - Collaborate with relevant teams, such as the SOC (Security Operations Center) or incident response teams.
   - Share insights and findings to improve overall security posture.
 
#### 12. **Iterate and Improve:**
   - Continuously iterate on the threat hunting process based on feedback and new threat intelligence.
   - Update queries, detection rules, and response actions to adapt to evolving threats.
 
#### 13. **Train and Enhance Skills:**
   - Regularly train security analysts on new techniques, tools, and threat landscapes.
   - Foster a culture of continuous improvement in threat hunting capabilities.
 
By following this procedure, security teams can proactively identify and mitigate potential threats within their environment using Microsoft Sentinel's capabilities. Regularly reviewing and updating the threat hunting process is essential to staying ahead of evolving security challenges.

#### 1. Define the Attack Scenario
Rather than generally searching for various types of threats, the starting point is to define a specific, narrowly focused threat that could be underway in the environment. In this step, the hunter should think through the overall techniques that could be used, the targets within the network that could be attacked, and the various vulnerabilities that can be exploited.
 
#### 2. Formulate an Initial Hypothesis
In thinking through the goals of the attacker for each stage in the attack chain, threat hunters make a series of informed guesses about what tools and techniques the attacker might use and what evidence might be created by their activities. The hunt is then structured to look for the evidence that would be generated if indeed each sequential hypothesis is valid.
 
#### 3. Identify and Gather Evidence to Investigate each Hypothesis
Your hunt team will need to assemble the data sources that will be analyzed within the hunt. To prove or disprove a hypothesis with a high degree of confidence, multiple forms of evidence are usually needed. Hunters will also need to document where data comes from to ensure that sources are both contextualized and consistent.
 
#### 4. Leverage Analytics to Reveal Results
During this stage, evidence is correlated and subject to analytical and visualization techniques to uncover relationships within it. Threat hunters need a deep understanding of adversarial tradecraft as well as what’s normal within the environment to be successful here.
 
#### 5. Report Results
It’s key to document the types of evidence collected, the nature of the analysis performed, and the logic behind the conclusions that are reached while the hunt is still in process. This enables the hunt team to communicate with management as well as incident responders.

### Threat hunting activities include:
#### Hunting for insider threats or outside attackers
  - Cyber threat hunters can detect threats posed by insiders, like an employee, or outsiders, like a criminal organization.
#### Proactively hunting for known adversaries 
  - A known attacker is one who is listed in threat intelligence services, or whose code pattern is on the denylist of known malicious programs.
#### Searching for hidden threats to prevent the attack from happening 
  - Threat hunters analyze the computing environment by using constant monitoring. Using behavioral analysis, they can detect anomalies which could indicate a threat.
