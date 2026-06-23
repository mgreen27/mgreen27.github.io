---
layout: post
title:  "Live Response Script Builder"
date:   2019-04-07
categories: posts
tags: [DFIR, Powershell]
image: 00title.jpg
showTags: true
readTime: true
summary: In this post I thought I would share some practical new features implemented in a recent refactor of Invoke-LiveResponse. These features enable fast and modular generation of live response scripts compatible with legacy Powershell. Im going to walk through the background then some of the new features and script creation.
aliases: /posts/2019/04/07/ILRScriptBuilder.html
---

![](00title.jpg)


# Background
Invoke-LiveResponse (I-LR) is a Powershell module I put together 18 months ago to enable raw disk collections over WinRM. Leveraging Powerforensics via a custom Powershell function it enabled collections of key forensic artefacts and stdout of script results typical for live response tasks. More information can be found at the wiki, from my previous post or the code.

Unless your running a preinstalled agent based solution, an important component of live response is local execution. As WinRM is not going to be deployed in most environments a common usecase may be via system management tools, scripting or local USB based collection. Secondly, simple expandability and the ability to write new collection capabilities quickly is an important design factor. I-LR’s supportability on Powershell 2.0 and no additional requirements beyond base operating system makes it a good candidate for this task.

With that in mind, im going to explain some of the features below and walk through how custom live response scripts can be generated.

# Modular
Invoke-LiveResponse leverages a new modular component for running collections. We still have the standard preconfigured collection options however a new “-custom” switch allows for dropping a scriptblock or multiple scriptblocks into the custom folder for ForensicCopy mode execution and script generation.

![](01CustomFolder.png)
|:--:| 
![](01CustomAll.png)
| *Invoke-LiveResponse: -all -vss -custom with four custom collections* |


#### Copy Preparation and Search
Under the hood, Invoke-LiveResponse now leverages a copy preparation function to simplify creating collection content. A function: Copy-LiveResponse checks for existence of items and builds a hash table of files and folders using Get-ChildItem. This enables generic glob searching on path and filtering using both Get-ChildItem or Powershell’s powerful “Where-Object” syntax. Depending on mode: Windows API via Copy-Item, or a raw copy via Invoke-ForensicCopy, copies files with fallback to the alternate method if failure.

Availible switches are familiar to anyone who uses Powershell Get-ChildItem:

![](02copyswitches.png)
|:--:| 
| *Copy-LiveResponse: configuration options.* |

![](02execution.png)
|:--:| 
| *Example collection: Evidence of Execution.* |

![](02forensicmode.png)
|:--:| 
| *Example raw collection: Event Logs.* |


Its worthy to note: Copy-LiveResponse leverages the Windows API for search. For basic live response of known files this was decided as the best approach as speed is improved greatly. Permissions searching with this technique does not inhibit results as the script runs as SYSTEM and “Get- ChildItem -Force” typically has complete visibility of even protected files. For NTFS special files or raw disk based search, direct use of Invoke- ForensicCopy is required.
For reference, I have included an example below:

![](02rawexample.png)
|:--:| 
| *Example collection: NTFS special files.* |


WriteScriptBlock and LocalOut
WriteScriptBlock writes a .ps1 file containing the Invoke-LiveResponse scriptblock to the current working directory. This is useful for creating a script that will be manually run on a host without WinRM configured or troubleshooting development efforts.

![](03writescriptblock.png)
|:--:| 
| *Invoke-LiveResponse -writescriptblock switch writes script to working folder.* |

Writescriptblock also writes a scriptblock to allow for local LiveResponse and Memory collection mode. For LiveResponse mode, additional scripts with desired standard-out can be placed into a Content folder in the same location as the script to run on execution. Simlilarly the “-Mem” switch will look for a WinPMem binary in the same folder path as the generated script.

![](03writescriptblock1.png)
|:--:| 
| *Invoke-LiveResponse -writescriptblock folder structure for local execution.* |

Combined with “-LocalOut:$True” enables building a ps1 file to run from LiveResponse USB or tool with execution. The results and collected artefacts are copied to the path of the script on execution.

![](03writescriptblock2.png)
|:--:| 
| *Invoke-LiveResponse -writescriptblock -localout:$true for local out to script location on execution.* |


Alternatively a localout or UNC path can be defined. Note: UNC path will map a drive to copy, specifying localout will only use preexisting mappings or write to local drives (which is potentially forensically destructive).


#### Volume ShadowCopy
The “-VSS” switch enables collection of Volume ShadowCopy Service artefacts for all selected collections. The feature invokes CreateSymbolicLink via PInvoke to minimise forensic footprint, mounting all available VSC then copying artefacts if available. A dedup feature will take a hash of the VSS item and compare it to hashable collected files, skipping if previously copied.


#### NoBase64
For raw disk access I-LR will utilise reflection to load an embedded Powerforensics module to memory. In field, some EDR / Powershell prevention tools will block the conversion function from base64. The “-Nobase64” switch leverages a direct byte array and GzipStream to bypass this technique. It is worthy to note, the created script is slightly larger size than its base64 equivalent.


#### PSReflect
One of the components I have started rolling into Invoke-LiveResponse is reflection via pinvoke and Matt Graeber’s [PSreflect template](https://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/). Initial implementations have been mounting UNC destination, Volume Shadow Copy and SYSTEM elevation via token impersonation. The longer term plan is to eventually run a significant LiveResponse capability via reflection for both forensic collection and live response summary information for use cases Powershell doesn’t provide legacy capability.


# Putting it all together
After walking through the availible features, I thought I would walk through a script generation for a custom collection.

For installation please [download Invoke-LiveResponse](https://github.com/mgreen27/Invoke-LiveResponse/archive/master.zip) and add to your Powershell profile. Detailed instructions can be found on the [wiki](https://github.com/mgreen27/Invoke-LiveResponse/wiki/Installation).

To import the module:  
```powershell
PS> Import-Module Invoke-LiveResponse
```
    
To view help:  
```powershell
PS> Get-Help Invoke-LiveResponse -detailed
```

#### Memory and custom disk
In this usecase I will be collecting memory artefacts. I am interested in collecting a memory dump in addition to memory artefacts on the file system.

For Memory dump simple use of the inbuilt “-Mem” switch after ensuring WinPMem is available. For the FileSystem memory artefacts, I need to create a custom collection scriptblock.
Firstly, I am interested in pagefile and swapfile collection targeting the root folder (line 6). I have chosen forensic mode as I know these files are typically locked and require special access to download.

![](06scriptblock.png)
|:--:| 
| *Custom Scrtipblock: sbMemoryDisk.ps1* |


Secondly, I am interested in any \*.dmp files on the filesystem (line 7). For this search I have also targeted the root folder but have also added the “-recurse” switch. This will enable the recursive search to find any dump files on the filesystem by filename. I will also use the “-VSS” switch to mount and search Volume ShadowCopy. It is worthy to note if your looking for a traditional forensic carve / pattern match this is not the method for you - this is a fairly intensive search and typically during a live response we would aim to be more targeted.

![](06setup.png)
|:--:| 
| *Custom Scrtipblock: add to custom folder and run Invoke-LiveResponse* |

Next, add the custom scriptblock into the Invoke-LiveResponse module folder, load and then execute Invoke-LiveResponse. 

The Command line is:
```powershell
PS> Invoke-LiveResponse -mem -custom -vss -WriteScriptblock -LocalOut:$True
```

This command will output the generated live response script, to which we need to add a copy of WinPMem to the root of the target location. In my case, this was a removable SSD drive mounted as E:.

![](06execution.png)
|:--:| 
| *Invoke-LiveResponse: Local Execution from USB.* |

On script execution, memory is collected and several files are found on the filesystem. As seen in the screenshot below, several process dumps were located on my desktop, the VSS and recyclebin.

![](06results.png)
|:--:| 
| *Memory Artefacts: Results* |



# Final Thoughts
I have learnt a lot implementing some of these features in a tool that has been fairly handy to have available in the time I have been using it. There are many ways to run live response and collect data, Invoke-LiveResponse provides a solution with minimal requirements beyond what is available by default from Windows 7 and above. I hope others can get some value using it so please feel free to reach out and provide feedback and improvements.




