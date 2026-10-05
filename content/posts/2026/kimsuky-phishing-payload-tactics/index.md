---
layout: post
title: "Kimsuky's Phishing and Payload Tactics"
date: 2026-10-05
area: "Threat Intel"
tags: [CTI, Kimsuky, Phishing, Malware]
description: "Earlier research into Kimsuky's phishing and payload tactics, co-authored for Rapid7 in 2024."
summary: "My 2024 Rapid7 research with Natalie Zargarov and Anna Širokova on Kimsuky's social engineering, delivery methods and payloads."
hideDescription: true
reportUrl: "https://www.rapid7.com/globalassets/_pdfs/whitepaperguide/rapid7-Kimsukys-Phishing-and-Payload-Tactics_wp.pdf"
reportPages: 18
reportSha256: "807adcc3a7f4b8308d67f7f3c66403f3b088bc504fb24091e0fbc122e9f8e36c"
showTags: true
readTime: true
---

I co-authored this Rapid7 white paper with **Natalie Zargarov** and **Anna Širokova** in 2024. It examines Kimsuky's social engineering and payload tactics. This overview revisits that research; the findings reflect the reporting period.

**[Read the full white paper (PDF, 18 pages)](https://www.rapid7.com/globalassets/_pdfs/whitepaperguide/rapid7-Kimsukys-Phishing-and-Payload-Tactics_wp.pdf).**

## Building trust before delivery

The report describes repeated correspondence before credential phishing or payload delivery, using credible personas and tailored lures.

![Email exchanges followed by a cloud-hosted archive, LNK file, PowerShell and final payloads.](phishing-chain.png "Rapid7, figure 1, page 4: phishing and delivery chain.")

## Disguised files and execution

One example used a password-protected archive containing a shortcut disguised as a Hangul document. The research also examines LNK toolmarks, CHM files and scripting-based execution.

![Archive contents showing an HWP document name with an additional LNK extension.](disguised-lnk.jpg "Rapid7, figure 4, page 7: disguised shortcut.")

An MSC sample presented a document lure through Microsoft Management Console.

![Microsoft Management Console displaying a Word-style icon and document lure.](msc-lure.jpg "Rapid7, figure 9, page 10: MSC document lure.")

## Attribution needs context

Shared LNK-builder characteristics alone were insufficient for attribution. The report combines toolmarks with targeting, payloads and infrastructure, and includes further analysis, references and indicator links.

*Figures extracted from the original Rapid7 white paper. Copyright Rapid7, 2024.*
