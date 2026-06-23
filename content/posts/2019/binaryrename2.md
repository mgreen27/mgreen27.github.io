---
layout: post
title:  "Binary Rename 2"
date:   2019-05-29
categories: posts
tags: [DFIR,Powershell,Yara,Detection]
image: hello.png
showTags: true
readTime: true
summary: This is my second Binary Rename post, in this post I am focusing on static detection, that is assessing files on disk. I am going to describe differences between both Yara and Powershell based detections, then share the code.
aliases: /posts/2019/05/29/BinaryRename2.html
---
For the first post and a detailed description of what Binary Rename is, please see: [Blue Team Hacks - Binary Rename](../binaryrename/).  


# Yara Detection
Firstly Yara - Yara is a command line driven tool used mainly for pattern matching in malware or detection use cases. Rule based, though strings or binary patterns - matching can be leveraged with logic like boolean, counts or regular expressions. Although traditionally pattern based, Yara is modular and expandable such that a "PE" module is available focusing on querying common binary attributes. The PE module allows you to create rules targeted specifically to the PE file format and file headers, providing functions which can be used to write more effective rules for PE file use cases.

The example I am using is leveraging pe.versioninfo InternalName attribute:

![](01yara.png)
|:--:| 
| *PE module import and InternalName rule for renamed cmd.exe* |

Our Yara use case is interesting as we require to compare an expected filename with the actual filename which is not typically a Yara capability. Florian Roth wrote about an "inverse" technique back in 2014 leveraging a Powershell script to obtain all files to be scanned and pass each filename into a yara scan as an external variable. The idea is a new yara instance is created for each file, passing in the relevant filename as the variable to allow comparison. In my code below I have expanded out the use case to cover x32 and x64 bit machines.

![](01inversePS.png)
|:--:| 
| *Powershell: inverseYara.ps1* |

For execution we require the following files in our execution path:
- inverseYara.ps1
- yara binaries x86 or x64
- rename.yar  

Then execution via a bat file or commandline as below:

![](01yararesults.png)
|:--:| 
| *Yara: Binary Rename detection results* |


This technique works very well from a detection standpoint, however in my testing performance does not appear to be optimal due to the overhead of generating a new yara process for each file scanned. It is worthy to note, the yara scan could be targeted without the filename match focusing on unexpected locations for the files in scope, but this doesn't match the binary rename usecase as required.

# Powershell Detection
In this case, the preferred detection is moving to Powershell only. The Windows API provides access to PE attributes via the FileVersionInfo Class with support back to Powershell 2.0 /.NET 2. Speed is significantly improved and logic can be optimised adding additional items in the output that may aid analysis. In my script output below you can see I have added a sha1 hash to the output object.

![](02psresults.png)
|:--:| 
| *Powershell results: 6 times faster than yara!* |

# Limitations
The biggest limitation with any static detection capability that queries the whole disk is performance. Leveraging Powershell and native Windows API seems to optimise performance significantly. Other optimisations added are setting CPU priority to Idle only and configuring logic to filter effectively to minimise processing footprint. Additional optimisations around performance, could be targeted queries for specific staging locations of interest as part of a targeted detection.

One consideration to keep in mind is the Powershell method leverages the Windows API. Although not a huge concern for my usecase of renamed binaries in a living off the land scenario, if there was tampering with rootkit like functionality a raw collection would be preferred.

# Final Thoughts
Hopefully you will find this summary useful, closing the loop on an open source detection capability for the Binary Rename use case. Feel free to reach out if you have any feedback, questions, or improvements.

Powershell and Yara detection code can be found here - [Get-BinaryRename](https://gist.github.com/mgreen27/036c2b33f928d188ddc60f26b4c9a097)

# Further reading
1) Green, Matthew. [Blue Team Hacks - Binary Rename](https://mgreen27.github.io/posts/2019/05/12/BinaryRename.html), 2019
2) The MITRE Corporation. [Technique: Masquerading - MITRE ATT&CK™](https://attack.mitre.org/techniques/T1036/)
3) MSDN. [FileVersionInfo](https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.fileversioninfo?view=netframework-2.0)
4) Roth, Florian. [Inverse Yara Signature Matching (Part 1/2)](https://www.bsk-consulting.de/2014/05/27/inverse-yara-signature-matching/), 2014
5) Roth, Florian. [Inverse Yara Signature Matching (Part 2/2)](https://www.bsk-consulting.de/2014/08/28/scan-system-files-manipulations-yara-inverse-matching-22/), 2014
6) YARA v3.10.0. [PE Module](https://yara.readthedocs.io/en/v3.10.0/modules/pe.html)