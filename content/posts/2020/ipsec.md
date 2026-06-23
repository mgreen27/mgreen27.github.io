---
layout: post
title:  "Windows IPSEC for endpoint quarantine"
date:   2020-07-23
categories: posts
tags: [DFIR,Velociraptor,VQL]
showTags: true
readTime: true
summary: This post is going to talk about using Windows IPSec for a quarantine use case. Im going to explain the background, how to configure a policy and some of the design decisions as I was initially looking at building an endpoint based containment capability.
aliases: /posts/2020/07/23/IPSEC.html
---

![](00quarantine.png)


### Background
As a consultant part of our workflow may be to contain a machine whilst we carry out an investigation. There are often complexities when carrying out cross team tasks so any capability that enables remote management typically saves time and resources. Most modern EDR has some kind of quarantine capability built in, however my current goto endpoint IR tool does not. Im looking for a scriptable, native tool based containment capability that can be deployed via Velociraptor.

IPSec has been included in every Microsoft Windows operating system since Windows 2000. Most practitioners believe IPSec as a purely VPN based technology, however the Windows implementation enables additional endpoint focused IP Security. In addition to encryption and authentication, IPSec uses the same engine as Windows Firewall so can be used for packet filtering. With these capabilities in mind, IPSec adds some nice options for teams looking to implement best practices in host based segmentation.

IPSec can be configured via Group Policy Object, Local Security Policy, Powershell, or Netsh in modern windows versions. This post will only focus on my use case of IPSec as a local policy deployment. Although Powershell is the goto tool for administration of Windows systems, its support is lacking for IPSec configuration prior to Windows 2012R2. For this reason, I decided to use the built in Netsh tool which has support for IPsec from Windows 7 through to the current iterations of Windows 10 / Server.

Even though this post is not covering all the IPSec use cases. I have included some links in my resources section for anyone interested in more information and best practice around centralised group policy based configuration.


### IPSec policy definitions  
First of all, we need to understand what makes up an IPSec policy.  

Netsh IPSec can be deployed in 2 different modes - Dynamic and Static:    
**Dynamic** - Is applied to current state and is not a persistent configuration.  
**Static** - Is applied as a policy and is simply a container for one or more rules. When enabled the policy populates the dynamic configuration and persists across reboot. When deleted, all objects attached to the policy are removed.

One of my requirements was to enable policy removal with minimal changes to current configuration. Using netsh static IPSec policies, we have a simplified process that can be built, applied and removed cleanly.

To create a policy: 
```cmd
netsh ipsec static add policy name=<string> description=<string>
```  

To enable a policy:
```cmd
netsh ipsec static set policy name=<string> assign=[y|n]
```

To delete a policy: 
```cmd
netsh ipsec static delete policy name=<string>
```  
NOTE: when deleting a policy it is disabled and all policy objects are also deleted.

**Filter List** - Is simply a named container for one or more filters.  

**Filter** - Filters determine when to activate IPSec Rules.  

To create a filter:  
```cmd
netsh ipsec static add filter filterlist=<string>  
	srcaddr=[me|any|<dns>|<server>|<ipv4>|<ipv6>|<ipv4-ipv4>|<ipv6-ipv6>] # source address.  
	srcmask=[<mask>|<prefix>] # source netmask, only needed if network IP specified.    
	srcport=[<port>] # source port as integer. 0 for all.  
	dstaddr=[me|any|<dns>|<server>|<ipv4>|<ipv6>|<ipv4-ipv4>|<ipv6-ipv6>] # destination. 
	dstmask=[<mask>|<prefix>] # destination netmask, only needed if network IP specified.  
	dstport=[<port>] # destination port as integer. 0 for all.  
	protocol=[ANY|ICMP|TCP|UDP|RAW|<integer>] # protocol as name or port.    
	mirrored=[<yes>|<no>] # optional and defaults to yes as it enables reverse communication.
	description=[<string>]  
```

For example: Allowing RDP traffic inbound to a machine from any IP  
(Example only - stay away from this rule in an IR)    
```cmd
netsh ipsec static add filter filterlist="Test Filter List"
	srcaddr=me srcport=3389 dstaddr=any dstport=0 protocol=tcp`   
	description="quick and dirty RDP filter"
```

**Filter Action** - Occurs when a Filter is satisfied. An IPSec filter can be permit, block, encrypt or sign the data stream. In my use case, I am only interested in permit and block as we are not interested in traffic encryption or validation usecases.  

To create a filter action:
```cmd
netsh ipsec static add filteraction name=<string> action=<permit>|<block>
```

**Rules** - An IPSec rule requries a filter list and a filter action and connects them to a policy. An optional component of a rule is authentication, which is out of scope for my current implementation.

To create a rule:  
```cmd
netsh ipsec static add rule name=<string> policy=<string>
	filterlist=<string> filteraction=<string> description=<string>
```

### Rolling into Velociraptor
The summary of the above commands translate into a defined process:  
1. Create policy.  
2. Create filter lists.  
3. Add filters to filter lists.  
4. Create filter actions.  
5. Create rules (link all together).  
7. Apply policy.  
8. Test it works.  
 
Velociraptor implementation of this process is transparent apart from a few select components. The goals being a repeatable capability that is reliable.  

![](01parameters.png)
|:--:| 
| *Quarantine: Parameter options* |

Configurable items are:  
**PolicyName** - for auditing purposes

**RuleLookUpTable**  
This enables custom IPSec filters to be added to the permit or block rule configuration easily. Each field corresponds to a Netsh switch discussed above and the only requirements are action, source and destination addresses. All other items will simply add the entry to the relevant switch in netsh and bad commands will be observed in results.  

![](02log.png)
|:--:| 
| *Artifact log: executed netsh commands.* |

The commands in my screenshots resulted from adding to the artifact defaults: 
![](02error.png)
|:--:| 
| *Custom filters: RDP and force error* |

![](02results.png)
|:--:| 
| *Artifact results: see netsh stderr on incorrect entry.* |

**MessageBox** - if configured will show a messagebox to all logged in users. There is a limitation of 256 Characters that will be trucated if exceeded.

![](02messagebox.png)
|:--:| 
| *Example messagebox* |

**RemovePolicy** - will simply run the remove policy command for configured policy name.  

### Caveats
There are a couple of considerations when deploying local IPSec policy.  

First being, it is dangerous to apply local policy and there is a real risk of locking yourself out of access to the machine. DNS resolutions can change, DHCP leases expire or the block all approach may accidentally block an unintended resource. Understanding the network and entering appropriate exclusions to mitigate these issues are important. In addition to exclusions, it is reccomended to test content prior to live fire. 

To simplify this process, I have implemented a capability to extract the agent config and add the Velociraptor server configuration automatically to exclusions. After policy deployment, the machine will attempt communication back to the Velociraptor server and if it fails, roll back the quarantine policy. Similarly all DNS and DHCP traffic is allowed by default in user customisable configuration.   

The final caveat is local IPSec policy can not be applied if a domain level IPSec policy is applied. In this case the reccomendation is to add a seperate quarantine rule via Active Directory.  


### Final Thoughts
In this post I have walked through local IPSec policy to implement machine quarantine in the Velociraptor platform. Despite limitations, this feature has been useful for me to call on as needed. Testing and the age old "understanding your tools" is very important. 

I already have several optimisations planned - feel free to send through any other thoughts, feedback and optimisations.

Content can be found - [Windows.Remediation.Quarantine](https://github.com/Velocidex/velociraptor/blob/master/artifacts/definitions/Windows/Remediation/Quarantine.yaml)


# Further resources
1. [Microsoft Docs, Network Shell (Netsh).](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh)
2. [Microsoft Docs, New-NetIPsecRule.](https://docs.microsoft.com/en-us/powershell/module/netsecurity/new-netipsecrule?view=win10-ps)
3. [Microsoft Docs, Windows Firewall with Advanced Security.](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754274(v=ws.11)?redirectedfrom=MSDN)
4. [Payne, Jessica. Demystifying the Windows Firewall, Ignite 2016](https://channel9.msdn.com/Events/Ignite/New-Zealand-2016/M377)
5. [Stuckey, Dane. Endpoint Isolation with the Windows Firewall, 2018](https://blog.dane.io/2018/04/22/endpoint-isolation-with-the-windows-firewall.html)