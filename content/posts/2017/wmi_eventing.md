---
layout: post
title:  "Blue Team Hacks - WMI Eventing"
date:   2017-04-03
categories: posts
tags: [DFIR, Powershell, WMI]
image: 00Title_cogs.jpg
showTags: true
readTime: true
summary: In this post I am going to cover a little Windows Management Instrumentation (WMI), and in particular an interesting use case for potential use in older environments with Process Monitoring gaps. Thinking about this gap led to me looking at WMI starting as an alternate near real time detection fix, and during feature investigation ended with another technically novel solution I thought was interesting enough to share.
aliases: /posts/2017/04/03/Blue_Team_Hacks-WMI_Eventing.html
---
![ ](00Title.jpg)

# The problem
I recently worked an engagement where our Process Monitoring tool of choice utilised Microsoft Sysmon. Unfortunately Sysmon only supports Windows 2008R2 and above, presenting with an interesting visibility gap for older machines. The first question was, how can I provide some advanced capability without needing to install another agent?

Another interesting question is what if as a defender I would like to run an automated action directly on the endpoint if certain conditions exist? A use case of file recovery to mitigate a potential threat actor over a short timeframe dropping a few files, running the tools and collecting output, then removing artefacts from disk with little chance of deleted file recovery. In this instance developing a solution that could also enable an alert, then copy, of files soon after they hit a staging folder could increase recoverability.

# So what is WMI?
Windows Management Instrumentation is a framework used to manage Windows Systems and has been an important part of all Windows operating systems since Windows Millennium Edition. The WMI schema is Microsoft’s implementation of the Common Information Model (CIM) and Web-Based Enterprise Management (WBEM) standards by the Distributed Management Taskforce. The purpose of WMI is to enable a standardisation in the way environment classes are modelled, representing the environment data that can be accessed in a common way.

In layman terms, WMI both describes and is part of the “guts” of Windows internals. WMI can collect informative things like current state, or performance statistics but also capability to query, configure and take actions. WMI is often invoked through various scripting languages like PowerShell or VBScript, with both IT Operations and Offensive types using various WMI capabilities for many years. Some of the more interesting offensive use cases are persistence, reconnoissance, lateral movement, hidden storage and even command & control.

Unfortunately WMI is minimally documented beyond MSDN and technical code references, all of which will not be covered in this post. For those interested I have included some relevant links in my references section below for further research.


# WMI Eventing
A WMI event subscription is a method of subscribing to certain system events. WMI eventing can be used to action on almost any operating system event. For example - logon, process, registry or file activity. In my use case I am particularly interested in files being created in known staging locations on the endpoint or a particular method of lateral movement that leveraged WMI process creation. I would also require a relevant action of alert, event log generation and for the staging locations, file copy to a different folder.

WMI Eventing comes in two flavours, a local single process context or permanent WMI Event Subscriptions which are our focus today. These permanent subscriptions are stored in the WMI repository and persist across system shutdown / reboots. It is also worthy to note permanent WMI events run as SYSTEM level privileges.  

![ ](01WMIOverview.png)

There are 3 components in WMI Eventing:
  
#### **1. An Event Filter**
An Event Filter is a WQL query that outlines the event of interest. Think of this as the "signature” component of which are two types covering almost all conceivable operating system events.

- **Intrinsic events** are polled events that fire upon a polling interval. In research there was some concern around best practice for performance of polling intervals, in my testing I found no large performance hits however would recommend at least 30 seconds as standard, especially when deploying many Intrinsic event filters.
In my use case I used a a WQL query that polls every 30 seconds to report on all file creations in relevant staging location. For example: C:\Windows\VSS.

```sql
	SELECT * FROM __InstanceCreationEvent WITHIN 30
	WHERE TargetInstance ISA "CIM_DataFile" 
	AND TargetInstance.Drive = "C:" 
	AND TargetInstance.Path = "\\Windows\\VSS\\” 
```
- Alternatively, **Extrinsic events** are real time filters. The downside is there are not a lot of Extrinsic events available, but they should take preference over Intrinsic.

Below will alert on WMI Process Create event and trigger on some WMI based lateral movement.

```sql
	SELECT * FROM MSFT_WmiProvider_ExecMethodAsyncEvent_Pre 
	WHERE ObjectPath="Win32_Process" AND MethodName="Create"
```
  

#### **2. Event Consumer**
An Event Consumer is an action to perform upon triggering an event. There are 5 possible classes.

- **ActiveScriptEventConsumer** - Executes a script by reference or embedded in the consumer itself, support for VBScript via WSH.
- **CommandLineEventConsumer**  - Executes a specified binary or command line, preferred for PowerShell execution, potential for use with an encoded command for embedded PowerShell.
- **LogFileEventConsumer** - Write to a specified log file.
- **NTEventLogEventConsumer** - Logs a Message to the Application EventLog
- **SMTPEventConsumer** - Sends an email message using SMTP every time that an event is delivered to it.

I initially was looking at NTEventLogEventConsumer which could be the preferred option for most organisations looking for a monitoring capability. For my use case above, I ended up implementing an ActiveScriptEventConsumer that wrote to a particular log file and completed the file copy in a single Event Consumer to a friendly folder. The alerts and file copy status for each machine is managed and retrieved by a centralised dashboard, however the solution could alert, post, or write to any scriptable resource.
  

#### **3. Filter to Consumer Binding**
Filter to consumer Binding is the registration mechanism that binds a filter to a consumer.
  
  
# Final Thoughts
With WMI we have a powerful but difficult to manage capability that can be used in some interesting technical use cases. The scope of capabilities being limited to understanding WMI classes and taking the time to build filters and event consumers.

Its worthy to note there is a proof of concept capability currently available from the research community. FLARE WMI-IDS and Invoke-IR Uproot-IDS (see references) provides a good starting point for those looking to build their own solution.

One of the major difficulties with WMI Eventing is troubleshooting problems with event consumers. With this in mind I found best workflow came with using some reference code to develop a simple template to assist understanding and troubleshooting efforts then expand into using the above frameworks as new functionality not incorporated is validated and understood.

For those interested, I have also included a reference PowerShell script on GitHub - [HERE](https://gist.github.com/mgreen27/ef726db0baac5623dc7f76bfa0fc494c?lipi=urn%3Ali%3Apage%3Ad_flagship3_pulse_read%3B9G70WaahSY2Z0vfHlD4oXg%3D%3D) -  to help anyone looking to create a similar ActiveScriptEventConsumer described above.

Hopefully this post has provided some good food for thought and pointed interested parties in the direction for further research and reference material. Feel free to reach out if you have any questions.


### References:
1. Ballenthin,William. Graeber, Matt. Teodorescu Claudiu. [Windows Management Instrumentation (WMI) Offense, Defense, and Forensics](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf?lipi=urn%3Ali%3Apage%3Ad_flagship3_pulse_read%3B9G70WaahSY2Z0vfHlD4oXg%3D%3D), 2015

2. Distributed Management Task Force, [Common Information Model](http://www.dmtf.org/standards/cim?lipi=urn%3Ali%3Apage%3Ad_flagship3_pulse_read%3B9G70WaahSY2Z0vfHlD4oXg%3D%3D)

3. Distributed Management Task Force, [Web-Based Enterprise Management](http://www.dmtf.org/standards/wbem?lipi=urn%3Ali%3Apage%3Ad_flagship3_pulse_read%3B9G70WaahSY2Z0vfHlD4oXg%3D%3D)

4. Fireeye FLARE. [WMI-IDS](https://github.com/fireeye/flare-wmi/tree/master/WMI-IDS?lipi=urn%3Ali%3Apage%3Ad_flagship3_pulse_read%3B9G70WaahSY2Z0vfHlD4oXg%3D%3D), 2015

5. Invoke IR. [Uproot](https://github.com/Invoke-IR/Uproot?lipi=urn%3Ali%3Apage%3Ad_flagship3_pulse_read%3B9G70WaahSY2Z0vfHlD4oXg%3D%3D)

6. Kerr, [Devon.There's Something About WMI](https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/sans-dfir-2015.pdf?lipi=urn%3Ali%3Apage%3Ad_flagship3_pulse_read%3B9G70WaahSY2Z0vfHlD4oXg%3D%3D), 2015

7. MSDN. [Windows Management Instrumentation](https://msdn.microsoft.com/en-us/library/aa394582(v=vs.85).aspx?lipi=urn%3Ali%3Apage%3Ad_flagship3_pulse_read%3B9G70WaahSY2Z0vfHlD4oXg%3D%3D)

8. Parisi, Timothy. Pena, Evan. [WMI vs. WMI: Monitoring for Malicious Activity](https://www.fireeye.com/blog/threat-research/2016/08/wmi_vs_wmi_monitor.html?lipi=urn%3Ali%3Apage%3Ad_flagship3_pulse_read%3B9G70WaahSY2Z0vfHlD4oXg%3D%3D), 2016

9. US Department of Homeland Security. [WMI for Detection and Response](https://ics-cert.us-cert.gov/sites/default/files/documents/WMI_for_Detection_and_Response_S508C.pdf?lipi=urn%3Ali%3Apage%3Ad_flagship3_pulse_read%3B9G70WaahSY2Z0vfHlD4oXg%3D%3D), 2016
