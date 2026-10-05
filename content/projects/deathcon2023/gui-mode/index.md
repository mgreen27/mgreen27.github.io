---
title: "GUI mode and lab setup"
layout: "workshop-lesson"
date: "2023-11-20"
url: "/projects/deathcon2023-practical-death-by-velociraptor/gui-mode/"
weight: 1
description: "Run Velociraptor in GUI mode and import additional artifact content."
workshopLesson: true
videoUrl: "https://youtu.be/i_HgfOCgFMw"
---

## **Objective**

This lab is a guided walk-through for running Velociraptor in GUI mode.

GUI mode will be used throughout the workshop.

We also walk through importing additional content into Velociraptor.

The Velociraptor GUI is configured to open automatically upon boot, but the credentials are available below:

- URL: [`https://127.0.0.1:8889/`](https://127.0.0.1:8889/)
- Username: `admin`
- Password: `password`

## **Dependencies**

Windows 10+ VM with administrator level access.

- UEFI enabled for UEFI use cases (detail later)

Internet access if you would like to do content import.

## Tasks

{{< workshop-task number="1" >}}

### Download and run Velociraptor in GUI mode

1. Download latest velociraptor release

    0.7.0-3 at time of writing.

    [https://github.com/Velocidex/velociraptor/releases](https://github.com/Velocidex/velociraptor/releases)


![GUI mode and lab setup: Download and run Velociraptor in GUI mode (01)](screenshot-01.png)

Please copy the downloaded exe to the desktop and rename to velociraptor.exe

2. Open cmd.exe as administrator and cd to your desktop. Run `velociraptor.exe -h` to scope options via help

![GUI mode and lab setup: Download and run Velociraptor in GUI mode (02)](screenshot-02.png)

Many velociraptor features are available via the cli and at any level you can view help to understand what switches are available.

As we are running GUI mode run: `velociraptor.exe gui -h`

![GUI mode and lab setup: Download and run Velociraptor in GUI mode (03)](screenshot-03.png)

By default Velociraptor will use a datastore in the temp folder. This may not be desired as the OS may purge temp folders and we may loose our work. We can use the datastore switch to specify a path.

3. Create VRdata folder and run Velociraptor

`mkdir VRdata`

`velociraptor.exe gui --datastore=./VRdata -v`

![GUI mode and lab setup: Download and run Velociraptor in GUI mode (04)](screenshot-04.png)

Running -v enables us to review verbose mode in Stdout. Take a moment to scroll up through the output to see what the velociraptor gui mode is doing.

By default a web browser will also load and automatically log into the local velociraptor instance.

NOTE: In windows 11 this feature was not working with Edge only default installs and manual load is required.

Open a browser and goto:

- URL: [`https://127.0.0.1:8889/`](https://127.0.0.1:8889/)
- Username: `admin`
- Password: `password`

![GUI mode and lab setup: Download and run Velociraptor in GUI mode (05)](screenshot-05.png)

4. Explore GUI and follow demo.

Ensure you familiarise yourself with items important for detection development.

- VFS
- Collection
- Artifacts
- Notebook


{{< /workshop-task >}}

{{< workshop-task number="2" >}}

### Import additional content

1. Open server collection view and run Server.Import.ArtifactExchange

![GUI mode and lab setup: Import additional content (06)](screenshot-06.png)

![GUI mode and lab setup: Import additional content (07)](screenshot-07.png)

We can configure a prefix to add to each imported artifact, but in this case we will keep as default.

![GUI mode and lab setup: Import additional content (08)](screenshot-08.png)

When imported you can see all artifacts have this prefix.

![GUI mode and lab setup: Import additional content (09)](screenshot-09.png)

You should now have several Exchange prefixed artifacts in your artifact view.

![GUI mode and lab setup: Import additional content (10)](screenshot-10.png)

We will use several of these artifacts later 🙂

2. Run the same import process for **Exchange.Server.Import.DetectRaptor**

![GUI mode and lab setup: Import additional content (11)](screenshot-11.png)

![GUI mode and lab setup: Import additional content (12)](screenshot-12.png)


{{< /workshop-task >}}
