---
layout: post
title: "Finding the LNK: Techniques and methodology for advanced analysis"
date: 2024-11-01
tags: [DFIR,CTI,Velociraptor]
showTags: true
summary: Advanced LNK analysis with Velociraptor, covering shortcut structures, suspicious fields, and useful clustering points for DFIR and CTI workflows.
originalUrl: "https://www.rapid7.com/blog/post/2024/11/01/finding-the-lnk-techniques-and-methodology-for-advanced-analysis-with-velociraptor/"
---

> This is a local backup. Read the original article on the [Rapid7 blog](https://www.rapid7.com/blog/post/2024/11/01/finding-the-lnk-techniques-and-methodology-for-advanced-analysis-with-velociraptor/).

Malicious exploitation of LNK files, commonly known as Windows shortcuts, is a well-established technique used by threat actors for delivery and persistence. While the value of LNK forensics for cyber [threat intelligence](https://www.rapid7.com/fundamentals/what-is-threat-intelligence/) (CTI) is fairly well-understood, analysts may overlook less well-known data points and miss valuable insights. In this post, we explore the structure of LNK files using Velociraptor, our open-source [digital forensics and incident response (DFIR)](https://www.rapid7.com/fundamentals/digital-forensics-and-incident-response-dfir/) tool. We will walk through each LNK structure and discuss some analysis techniques frequently used on the Rapid7 Labs team. Many of these capabilities are now featured in the latest Velociraptor, which we have shared with the community in the [0.73 release](https://github.com/Velocidex/velociraptor/releases/tag/v0.73).

## So what is a LNK?

Windows shortcut files are used by the Windows operating system to reference files, folders, or applications, and to enhance user experience. A LNK file often stores extensive metadata about the target object, including file paths, timestamps, network, and other details about the local machine.

Malicious use we observe in the field often involves phishing with an attacker-crafted LNK inside a container to bypass email controls. The LNK is a delivery mechanism for an embedded malicious binary, a script, or command line to provide initial access to a victim. In some cases we also see lures integrated with this kind of execution chain to legitimize the execution of the phish for the unsuspecting user.

The binary structure of a LNK file is based on [Shell Link Binary file format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/) with a header and several optional data structures typically present.

![Screenshot-2024-10-30-at-1.50.07-PM.png](/posts/2024/finding_the_lnk/01-Screenshot-2024-10-30-at-1.50.07-PM.png)

## Collection/Processing

Using Velociraptor, LNK files can be collected directly from endpoints during incident response for user forensics, or targeted threat hunting. LNK files can also be collected from malware repositories like VirusTotal, then processed offline for analysis during research. Depending on the analysis task, we can hunt for specific IOC strings and attributes or build our own processing in a Velociraptor Query Language ([VQL](https://docs.velociraptor.app/docs/vql/)) notebook to manipulate the parsed data post-collection.

![Screenshot-2024-10-30-at-1.50.59-PM.png](/posts/2024/finding_the_lnk/02-Screenshot-2024-10-30-at-1.50.59-PM.png)

Velociraptor output includes a field for each of the LNK data structures and a **Suspicious** field. The concept is to bubble up broader features that may be useful as an investigation tip or classification. During the next sections, we will walk through each LNK structure in Velociraptor output and discuss some of the new features used for analysis.

![Screenshot-2024-10-30-at-1.51.41-PM.png](/posts/2024/finding_the_lnk/03-Screenshot-2024-10-30-at-1.51.41-PM.png)

This is the only mandatory component of a LNK file; it contains target attributes and timestamps. Critically, it also contains [\[LinkFlags\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/ae350202-3ba9-4790-9e9e-98935f4ee5af) to configure what optional structures exist.

In figure 3 below you can see several flags have been set.

-   HasArguments - command line arguments
-   HasExpString - environment variable data block
-   HasIconLocation - icon path is set
-   HasName - description/name is set
-   PreferEnvironmentPath - use environment variable over LinkTarget

![Screenshot-2024-10-30-at-1.53.07-PM.png](/posts/2024/finding_the_lnk/04-Screenshot-2024-10-30-at-1.53.07-PM.png)

One of the anomalies we review for malicious intent is **Zeroed Headers.** This may indicate that the LNK file has been stripped of metadata after creation or was created using a builder tool, bypassing normal metadata generation.

It's important to note that context is important — zeroed headers are not by themselves an indicator of evil. For example: when running user forensics, we see system generated LNK files for user activity generating zeroed values but also generally missing structures we would expect in a malicious payload as shown in figure 3. We also see malicious LNKs commonly without zeroed headers.

## LINKTARGET\_IDLIST

LINKTARGET\_IDLIST is an optional structure enabled by the HasLinkTargetIDList flag, and provides an itemized path to the LNK target. The [ItemIDList structure](https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc) is shared across other Windows “Shell Items” with the ShellBags registry artifact probably the most well known.

In figure 4 below, we can see the relation of LinkTarget timestamps to the ShellLinkHeader. From an analysis standpoint, the most interesting component of this structure is it may contain details of relevant MFT entries of each object in the target path.

![Screenshot-2024-10-30-at-2.19.03-PM.png](/posts/2024/finding_the_lnk/05-Screenshot-2024-10-30-at-2.19.03-PM.png)

Clustering by Name and MFT ID can provide an interesting data point into the machine from which a LNK has been generated. Post-processing using Velociraptor, we can extract each shell item MFT ID and allow for comparison. This technique helps find potential LNKs generated by the same machine even if host metadata has been modified. Figure 5 below shows post-processing a collection of older publicly shared APT29 LNK files with matching MFT IDs and different machine metadata.

![Screenshot-2024-10-30-at-2.22.32-PM.png](/posts/2024/finding_the_lnk/06-Screenshot-2024-10-30-at-2.22.32-PM.png)

## LINKINFO

Enabled by the HasLinkInfo flag, this structure specifies information necessary to resolve the target if it is not found in its original location. A LNK target path is one of the first data points reviewed by analysts. For example, looking for suspicious LOLBins is an easy win when combined with LNK arguments.

Volume information like DriveSerialNumber and label, are the most well-known data points for threat research, but this structure may also store UNC/WebDAV path details as shown in figure 6.

![Screenshot-2024-10-30-at-2.23.15-PM.png](/posts/2024/finding_the_lnk/07-Screenshot-2024-10-30-at-2.23.15-PM.png)

## STRING\_DATA

This structure contains optional structures with high-value data points like description (name), relative path, working directory, icon location, and command line arguments. As per other structures these are configured by [\[Link Flags\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/ae350202-3ba9-4790-9e9e-98935f4ee5af) — HasName, HasRelativePath, HasWorkingDir, HasArguments, and HasIconLocation respectively.

The Arguments field is the go-to structure of most analysis. Some of the things we classify for include:

-   General and custom defined suspicious strings
-   Large size arguments
-   Leading spaces
-   Ticks for cmd and PowerShell which may be obfuscation techniques
-   Environment variables
-   Rare characters
-   HTTP and UNC strings
-   Large Base64-encoded strings

Figure 7 showcases Velociraptor StringsData output. It’s worthwhile to note that we have also included LinkInfo.TargetPath in this field for presentation, as it is typically useful during analysis.

![Screenshot-2024-10-30-at-2.24.38-PM.png](/posts/2024/finding_the_lnk/08-Screenshot-2024-10-30-at-2.24.38-PM.png)

As Base64 encoding is fairly common in malicious payloads, it is useful to be able to automatically decode and apply the argument anomaly detection to the encoded text. In Figure 8 below, we have flagged the arguments field as unusually long, extracted the Base64 and flagged the previously encoded environment variable reference — $env:temp.

![Screenshot-2024-10-30-at-2.41.15-PM.png](/posts/2024/finding_the_lnk/09-Screenshot-2024-10-30-at-2.41.15-PM.png)

ExtraData contains several optional structures that are of interest to CTI teams.

**TrackerData** is the most well-known source of threat research data. Detecting known hostnames and MAC addresses may assist with tracking LNK sources.

![Screenshot-2024-10-30-at-2.42.42-PM.png](/posts/2024/finding_the_lnk/10-Screenshot-2024-10-30-at-2.42.42-PM.png)

The **EnvironmentVariable** data block can be used to execute a payload without a target. In the example below, we are highlighting a LNK using the SyncAppvPublishingServer.vbs living off the land script to execute a PowerShell command.

![Screenshot-2024-10-30-at-2.43.37-PM.png](/posts/2024/finding_the_lnk/11-Screenshot-2024-10-30-at-2.43.37-PM.png)

The **PropertyStore** data block stores various file properties about the target file on LNK creation. Some useful anomalies may include:

-   ParsingPath - to compare to LinkInfo.Target.Path
-   System.Size - to compare with ShellLinkHeader.FileSize
-   SID for adversary tracking or determining if a LNK was generated by a local admin

![Screenshot-2024-10-30-at-2.44.25-PM.png](/posts/2024/finding_the_lnk/12-Screenshot-2024-10-30-at-2.44.25-PM.png)

**Languages** are a common theme when hunting adversaries and can also be useful for finding insights into LNK file attribution. The PropertyStore is a great source, as languages detected here are a good indication of language on the originating machine.

![Screenshot-2024-10-30-at-2.45.07-PM.png](/posts/2024/finding_the_lnk/13-Screenshot-2024-10-30-at-2.45.07-PM.png)

Similarly, **Console** datablock font information may also contain alternate language characters. CodePage reference can also highlight alternative character encoding; in figure 13 below, we can see Korean Unified Hangul CodePage 949.

![Screenshot-2024-10-30-at-2.45.54-PM.png](/posts/2024/finding_the_lnk/14-Screenshot-2024-10-30-at-2.45.54-PM.png)

It is worthy of note that we can also detect languages in STRING\_DATA fields or using YARA over the whole LNK file. Language characters here often can point to targeting as part of a lure or a filename reference; or hard to validate if detected by YARA and hitting on bytes in an embedded file.

## Overlay files

Some malicious LNKs also have embedded files. An example may be an embedded .exe, script, or even lure as part of a phishing campaign that is dropped and run as part of LNK execution. As normal LNK data isn't too large, a simple way to detect overlays is to check for any large LNK file sizes in bytes. We can also check for additional data beyond the end of the EXTRA\_DATA structure.

In Velociraptor we have written some parsing to provide insights of any Overlay detected in a parsed LNK file. This has been added as an Overlay section in ExtraData. The examples below show several of the methods observed in the field so far: padding, directly appended and encoded (padding may also encode the appended file). Generally, embedded files are extracted and executed when running the LNK, but occasionally we see some overlays that are not used. As a general rule, any overlay indicates a malicious LNK file.

![Screenshot-2024-10-30-at-2.48.11-PM.png](/posts/2024/finding_the_lnk/15-Screenshot-2024-10-30-at-2.48.11-PM.png)

## Similarity and Clustering

When grouping various payloads into clusters, analysts look at the bigger picture for data points in the attack chain, like malware, infrastructure and targeting in addition to key features of the LNK file. Nevertheless, it is often useful to compare similarity of objects to determine how alike they are. We have recently added a similarity() function in Velociraptor to compare two dictionaries for similarity on a scale of 0 to 1. This is a great capability to compare generic LNK features automatically and is not limited by needing to compare specific items, which are prone to have minor changes. An example is an attacker making slight changes to each version command-line payload that hinders automated matching.

In the example below, we have generated several clear clusters from a loose YARA-based collection targeting a LNK builder tool. We started by parsing our target LNK, then created a dictionary using its suspicious field and added its unique OverlayHeader field, which relates to padding. We then compared for similarity to each collected file and grouped for frequency analysis. It is worthy to note, depending on the analysis goal we can easily create our own features to test using VQL to modify, add or remove items to our dictionary set:

![Screenshot-2024-10-30-at-2.49.06-PM.png](/posts/2024/finding_the_lnk/16-Screenshot-2024-10-30-at-2.49.06-PM.png)

![Screenshot-2024-10-30-at-2.49.42-PM.png](/posts/2024/finding_the_lnk/17-Screenshot-2024-10-30-at-2.49.42-PM.png)

## Conclusion

In this post, we have discussed the structure of LNK files and covered some useful LNK data points in Velociraptor with techniques used by Rapid7 Labs in real-world analysis. These capabilities are now available in the [recently released Velociraptor 0.73](https://github.com/Velocidex/velociraptor/releases/tag/v0.73) so please let us know if you find this useful and feel free to provide feedback via [Discord](https://www.velocidex.com/discord) or [Github](https://github.com/Velocidex/velociraptor/). Rapid7 supports open source, providing the community with Velociraptor and amazing DFIR capabilities for free. This includes some features that are unavailable, even in paid tools.
