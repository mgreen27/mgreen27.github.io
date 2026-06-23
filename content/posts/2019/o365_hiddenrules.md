---
layout: post
title:  "O365: Hidden InboxRules"
date:   2019-06-09
categories: posts
tags: [DFIR,O365,Powershell]
showTags: true
readTime: true
summary: In this post Im going to talk about Office365 hidden inbox rules. Im going to give some background, show rule modification, and talk about detection methodology.
aliases: /posts/2019/06/09/O365HiddenRules.html
---
![](00title.png)

# Background
Attacks against Office 365 have generated a fair amount of industry acknowledgement in recent times as more and more organisations have moved towards cloud based services. Misconfiguration combined with less than optimal threat awareness means even the most simple attacks can provide access to this crucial service.

Inbox rules are typically part of evil methodology and can be abused across the attack lifecycle:
* Defence Evasion
* Reconnaissance
* Persistence
* Data collection / Exfiltration

Typically inbox rules are simple to detect statically via GUI access or in bulk from the Exchange Management Shell (EMS).


![](01rule.png)
|:--:| 
| *O365 OWA: Inbox rule https://outlook.office.com/mail/options/mail/rules* |


![](01rule2.png)
|:--:| 
| *O365 EMS: Typical Powershell detection.* |


# Hidden Rules
Minimally documented, Damian Pfammatter at Compass Security explained the methodology in his September 2018 [blog post](https://blog.compass-security.com/2018/09/hidden-inbox-rules-in-microsoft-exchange/). In summary, inbox rules can be hidden by leveraging an API called Messaging Application Programming Interface (MAPI), which provides low level access to exchange data stores. 

Below I am accessing the inbox rule manually via the [MFCMAPI tool](https://github.com/stephenegriffin/mfcmapi) from a machine with an Outlook profile configured to our in scope mailbox. IPM.Rule.Version2.Message objects indicate an inbox rule.

![](02mapi.png)
|:--:| 
| *EvilMove inbox rule: prior to change* |

Modification is simply adding an unsupported value to the PR_RULE_MSG_PROVIDER field (or blanking out). 

![](02mapi2.png)
|:--:| 
| *EvilMove inbox rule hidden: fake provider details.* |

Once modified, the inbox rule is hidden and completely operational:
![](02mapi4.png)
|:--:| 
| *InboxRule hidden: no view in WebUI, InboxRule works as expected.* |
![](02mapi5.png)
|:--:| 
| *InboxRule hidden: EMS results.* |

# Detection

At scale detection of hidden inbox rules comes down to two main areas.

#### 1. MAPI based - point in time.  
Microsoft have released a script for use over Exchange Web Services (EWS) - Get-AllTenantRulesAndForms that enables tenant wide collection of Exchange Rules and Forms querying the low level data stores. This script enables visibility of Hidden Rules but leaves out an essential PR_RULE_MSG_PROVIDER field for detection. A modified version from Glen Scales collecting the PR_RULE_MSG_PROVIDER field is available [here - Get-AllTenantRulesAndForms](https://github.com/gscales/O365-InvestigationTooling/blob/master/Get-AllTenantRulesAndForms.ps1) (screenshot below).
* Frequency analysis on RuleMsgProvider field is recommended as a starting point for detection.
* Alert and investigate any inbox rules with blank or unusual RuleMsgProvider fields.
* Alert and investigate IsPotentiallyMalicious = True - i.e rule action is an executable object.
* Limitations are high privilege requirements - Global Admin role AND EWS ApplicationImpersonation.

![](03Detection.png)
|:--:| 
| *Exchange Web Services (EWS): Empty RuleName and RuleMsgProvider fields.*|

The action, condition and command fields (if populated) are base64 encoded raw byte arrays. I have yet to find documentation on the format for decoding or reverse engineer the data but there are some identifiable strings that can provide insights into the rule. 

![](03Detection1a.png)
|:--:| 
| *Decoded Action: Rule to forward email to external SMTP account.*|

For investigations, it is also possible to attempt to reanimate the strings and unhide the rules using MFCMAPI. In my testing I have been able to have the rule reappear adding in a known PR_RULE_MSG_PROVIDER field value.
* A fake, mistyped or blank PR_RULE_MSG_PROVIDER the rule would remain hidden. 
* Protocol documentation can be found [here](https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxorule/70ac9436-501e-43e2-9163-20d2b546b886).
* Remediation instructions can be found in the Further Reading section below.


#### 2. Unified Audit Log - telemetry. 
The Unified Audit Log (UAL) is a centralised log storing audit events for all Azure services. It can be accessed via O365 WebUI: Security & Compliance > Search > AuditLog Search or EMS Administration: Search-UnifiedAuditLog commandlet.
* This method is best suited to active monitoring via a SIEM or monitoring solution.  
* Alert and investigate any unusual New-InboxRule (creation) or Set-InboxRule (modification) events.  
* Benefits include reduced privilege requirements - e.g a user with View-Only Audit Logs or Audit Logs roles enabled.  
* Logging must be enabled and retention is a consideration for historical searches.

![](03Detection2.png)
|:--:| 
| *Telemetry based detection - Search-UnifiedAuditLog: New-InboxRule event*|


#### Other Forwarding specific
O365 has other indirect detection capabilities that assist spotting hidden rules. One of those is built in alerting on forwarding of mail to external addresses. This alert is also generated as a SecurityComplianceAlert in the UAL. Keep in mind on compromise of a privileged account an attacker could simply suppress these alerts to stay under the radar.

![](03Detection3a.png)
|:--:| 
| *Redirect Threat Management alert - Email also sent.*|

It is also possible to monitor traffic patterns of forwarded or redirected traffic. Below I have shown a summary inside the Security and Compliance Mailflow Dashboard.

![](03Detection4.png)
|:--:| 
| *Mailflow Dashboard: https://protection.office.com/mailflow/dashboard* |

# Final Thoughts
In this post I have covered detection points for hidden inbox rules:
* Point in time query via Exchange Web Services (EWS).
* Rule creation and modification inside the Unified Audit Log.
* Other alerts in O365 ecosystem

Although this post has an example of an inbox rule with external forwarding, hidden rules can be leveraged for other evil use cases including: persistence, reconnaissance and data collection. Best practice would include creation of a low privilege account for active monitoring of telemetry and periodic assessments leveraging a higher privilege account via Exchange Web Services.

I hope others found this post useful, feel free to reach out if you have any feedback, questions, or improvements.


# Further reading
1. Griffin, Stephen. [MFCMAPI github](https://github.com/stephenegriffin/mfcmapi)
2. Hartley, Dave. [Malicious Outlook Rules](https://labs.mwrinfosecurity.com/blog/malicous-outlook-rules), 2016
3. Lambert, John. [Office 365 Attacks](https://onedrive.live.com/view.aspx?resid=F32A9F4F1477E49!122&ithint=file,pptx&authkey=!ACC5Ztb5uVED22k), May 2019
4. MSDN. [How to delete corrupted, hidden inbox rules from a mailbox using MFCMAPI](https://blogs.msdn.microsoft.com/hkong/2015/02/27/how-to-delete-corrupted-hidden-inbox-rules-from-a-mailbox-using-mfcmapi/), February 2015
5. Pfammatter, Damian. [Hidden Inbox Rules in Microsoft Exchange](https://blog.compass-security.com/2018/09/hidden-inbox-rules-in-microsoft-exchange/), September 2018
6. Scales, Glen. [Auditing Inbox rules with EWS and the Graph API in Powershell](https://gsexdev.blogspot.com/2019/05/audting-inbox-rules-with-ews-and-graph.html), May 2019
