---
layout: post
title:  "Local Live Response with Velociraptor ++"
date:   2019-12-08
categories: posts
tags: [DFIR,Velociraptor,VQL]
showTags: true
readTime: true
summary: In this post im going to talk about a live response use case leveraging the Velociraptor project worth sharing. Specifically, live response with ancillary collection by third party tools embedded to minimise user impact. As usual, im going to provide some background and walk through the steps then share the code.  
aliases: /posts/2019/12/08/LocalLRwithVRaptor.html
---
![](00title.png)
 
EDIT: Please use this post for education only. Although the content and themes of this post are valid, the examples included have been superseeded by a GUI based local collector builder from the Velociraptor server.

#### Background
Live response collection is one of the most critical stages of modern incident response. A quick targeted collection of important artefacts means timely answers and more efficient results. Although I prefer a remote agent keeping the human element out of collection as much as possible, a common use case I encounter is needing to run a local collection from a USB or network share. Typically this means providing a script of some sort with a binaries folder and collection protocol, sometimes to less technical users with a margin for error.

Mike at Velocidex has posted recently about triage collection (local live response) with Velociraptor:
* [Triage with Velociraptor — Pt 1](https://medium.com/velociraptor-ir/triage-with-velociraptor-pt-1-253f57ce96c0)  
* [Triage with Velociraptor — Pt 2](https://medium.com/velociraptor-ir/triage-with-velociraptor-pt-2-d0f79066ca0e)  
* [Triage with Velociraptor — Pt 3](https://medium.com/velociraptor-ir/triage-with-velociraptor-pt-3-d6f63215f579)  

One undocumented feature is Velociraptor's ability to append additional tools to the end of the binary and enable execution. This capability opens up some really nice use cases for ancillary data collection during a local Velociraptor triage. Im going to cover creating a Velicraptor local live binary with WinPMem for memory and Autoruns for autostart extensibility point (ASEP) collection.  


#### What do I need?
I will be using the current Velociraptor release and building on a linux platform. Im looking at building both a x64 and x86 Windows version, so I want to download the relevant Velociraptor binaries to my staging folder.

![](01Latest.png)
|:--:| 
| *Download Velociraptor binaries* |

We will also download both x86 and x64 third party binaries supporting my use cases. In this instance Autoruns and WinPMem, which I then add to the relevant "bitness" payload zip files.

![](01Other.png)
|:--:| 
| *payload.zip: x64 binaries, payload_x86.zip: x86 binaries* |


#### Velociraptor configuration
Setting up for local live response requires setting up an autoexecution object and output configuration. In my case, I setup artifact called "MultiCollection" with a zipfile output "collection\_HOSTNAME.zip". As there is no folder path specified, the zip will end up in the "start in folder".

Once the structure of VQL is understood it is trivial to add in additional use cases. Under the parameters section, I also have included an "uploadTable" parameter to add additional direct file downloads not covered by other components. In this case, im adding pagefile, swapfile and hybernation files if they exist as default. This table is helpful for quick collection and can also be represented in a glob style search.

![](02Config.png)
|:--:| 
| *Autoexecution VQL object* |

Next component is the "sources" section which outlines the VQL queries to run. In my screenshot below, supporting order of volatility, I am running memory collection first then supporting file uploads. Worthy to note: my VQL does not "upload" to the output zip file, instead I have decided to output to "HOSTNAME.aff4" to the same folder as the binary to optimise resouce use and remove the need to push the aff4 to a temporary location prior to adding to the zip.

![](02Config2.png)
|:--:| 
| *Memory acquisition* |

Velociraptor allows modular use of the collection profiles from Eric Zimmerman’s KapeFiles project. I have chosen KapeFiles.Targets \_BasicCollection and some supporting items is my next VQL sources. I have also included a version of [all currently available switches](https://gist.github.com/mgreen27/22cd70739e733647e1e23338ca35c9a9#file-local_all-yaml) (at time of writing), to use as a template and remove unwanted items prior to build.

![](02Config3.png)
|:--:| 
| *KapeFiles acquisition* |

Finally, I am collecting an Autoruns output for autostart extensibility point (ASEP) collection. In my VQL I have specifically used wildcards to cover both x86 and x64 binaries and enable use of the same configuration across bitness. I am also using the same trick as my WinPMem execution and output to the binary root folder as "HOSTNAME\_autoruns.csv"

![](02Config4.png)
|:--:| 
| *Autoruns aquisition* |


#### How do I build it?
To build we run velociraptor in "repack" mode. That is specifying: the input binary, relevant payload zip, configuration file and output binary.

![](03Build.png)
|:--:| 
| *Velociraptor repack* | 

One thing to note, is that using this technique the created binary will not contain a valid certificate as the binary is modified with the "repack" command. This condition occurs through any of the Velociraptor customisations and typically is not a problem during live response.


#### How do I run it?
Copy the relevant binaries to your collection USB, folder or share and execute with administrator privilege.

![](04Run.png)
|:--:| 
![](04Run2.png)
| *Local live response execution* | 

Output will be to the binary folder.

![](04Run3.png)
|:--:| 
| *Live response output* | 

Opening collection_HOSTNAME.zip we can see all files that were configured for collection / upload.

![](04Run4.png)
|:--:| 
| *collection zip contents* | 


#### Final Thoughts
In this post I have walked through using Velociraptor to wrap third party binaries into an easy to use local live response tool. Velociraptor's modular architecture enables rolling in and out capabilities fast for a simple end user experience.

For those that are interested I have included below:  
1. [A build script for building x86 and x64 versions of my local live response tool](https://gist.github.com/mgreen27/22cd70739e733647e1e23338ca35c9a9#file-buildlocallr-sh)
2. [A configuration file with ALL KapeFiles switches](https://gist.github.com/mgreen27/22cd70739e733647e1e23338ca35c9a9#file-local_all-yaml)
3. [The reduced configuration from my example](https://gist.github.com/mgreen27/22cd70739e733647e1e23338ca35c9a9#file-local-yaml)

I hope you have gained some knowledge on Velociraptor for local live response. Please feel free to reach out and provide feedback or improvements.  

#### Further resources
1. [Velociraptor Documentation](https://www.velocidex.com/about/)
2. [Triage with Velociraptor — Pt 1](https://medium.com/velociraptor-ir/triage-with-velociraptor-pt-1-253f57ce96c0)  
3. [Triage with Velociraptor — Pt 2](https://medium.com/velociraptor-ir/triage-with-velociraptor-pt-2-d0f79066ca0e)
4. [Triage with Velociraptor — Pt 3](https://medium.com/velociraptor-ir/triage-with-velociraptor-pt-3-d6f63215f579)  
