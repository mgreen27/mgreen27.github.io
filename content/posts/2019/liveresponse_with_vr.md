---
layout: post
title:  "Live response automation with Velociraptor"
date:   2019-11-10
categories: posts
tags: [DFIR,Velociraptor,VQL]
showTags: true
readTime: true
summary: This post is going to talk about the Velociraptor project. Specifically, live response and automation I have built for my own engagements. Im going to provide some background and walk through a proof of concept, then share the code. 
aliases: /posts/2019/11/10/LRwithVRaptor.html 
---
![](00title.png)


EDIT: Please use this post for historical education only. Although the content and themes of this post are valid, the examples included are no longer valid for the current Velociraptor version. For current API configuration, please refer to the following links or feel free to contact me directly.  
+ [Chat with us on Discord](https://www.velocidex.com/discord)   
+ [Documentation](https://www.velocidex.com/docs/user-interface/api/)  
+ [Blog Post](https://www.velocidex.com/blog/medium/2020-03-06-velociraptor-post-processing-with-jupyter-notebook-and-pandas-8a344d05ee8c/)  




### Background
Velociraptor is an endpoint collection tool developed by Michel Cohen at Velocidex. Mike was the lead developer on many open source tools we know pretty well in our industry: for example Rekall/WinPMem, AFF4 and GRR. Velociraptor was created to simplify the GRR architecture and some of the complexity poblems of clunky back end and bloated data models. The result is a robust query language (VQL) and open source collection framework that is the building blocks of greatness.  

The ability to collect and process data efficiently as part of live response workflow is critial for timely incident response. This is all made possible by Velociraptor, and its open ended API enables interoperability with other tools, speeding up this process.  

Basic setup of Velociraptor is out of scope for this post. I am running Velociraptor on hardened linux platform and plan to walk through setting up a live response processing service. For setup background, I have added a lot of great resources in the references section below.  Although not required, this post assumes some familiarity with Velociraptor and it is reccomended to review some of the references if not familiar with the platform.  


### API Basics
The Velociraptor API is fairly simple architecture and enables VQL queries with an output of familiar VQL result rows. The power to this approach is those rows can then be enriched and processed to enable completx workflows.  It can be invoked both locally or over the network, providing the building blocks we desire in mature incident response. 

![](01APIServices.png)
|:--:| 
| *Velociraptor Services Architecture* | 

The modularity means post processing work is not part of the Velociraptor front end. We are able to essentially watch an event queue, then execute our API based use cases as desired. Performance can be optimised as with an accessable file system, intensive tasks like Live Response processing can be run on dedicated servers.


### API Setup
[Python bindings](https://github.com/Velocidex/velociraptor/tree/master/bindings/python) are included in the project a long with a [working client example](https://github.com/Velocidex/velociraptor/blob/master/bindings/python/client_example.py). The velocidex team also have a great amount of API connection information on the documentation page. This ensures connection and content development are simple and we can focus on the content.

![](02APIinstall.png)
|:--:| 
| *Velociraptor Python bindings install commands* | 

An API configuration file is also required for authentication and key materials are generated similar to other Velociraptor configuration items. 
```bash 
velociraptor --config server.config.yaml config api_client --name [APIName] > api_client.yaml
```

api_client.yaml:  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*\<SNIP Certificate information\>*  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*api_connection_string: 127.0.0.1:8001*  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*name: [APIName]*  

Note: default server.config.yaml configures the API service to bind to all interfaces and listen on port 8001. Please ensure relevant bindings and ports availible.

The example client script contains a great example of setting up API connection and a query stub. I have chosen to modify the script and add some global variables to simplify execution. 

![](03APIQuery.png)
|:--:| 
| *Example API python global variables* | 


CONFIG is my generated client API configuration path. I have chosen the default velociraptor config path but this can be any location.  

CASES is my output folder path. This can be an ingestion path or distributed storage to plug processed data into additional workflow.   

QUERY is my VQL I plan to query through the API. The query monitors the Velociraptor server for completed flow events; i.e *watch_monitoring(artifact=’System.Flow.Completion’)*. A WHERE clause extracts Flows containing artefacts with results and names containing  “KapeFiles” or “LiveResponse”.   
  
What makes VQL so powerful is we can enrich with additional VQL or formatting. In my example, the SELECT statement extracts relevant fields pertaining to a completed flow for my processing use cases. This includes a list of uploaded files, their path and other flow metadata.  


### API Processing
Now we have collected data points requried for processing, its as simple as running our normal processing logic applied to each row of results.

![](04Process.png)
|:--:| 
| *Extraction and printing of Flow results* | 

![](04ProcessStdOut.png)
|:--:| 
| *StdOut: Flow results* | 

After setting up relevant variables for processing, we can then shuttle off to tasks. Below is my plaso based timeliner function for a quick and dirty timeline.

![](05TimelinerFlow.png)
|:--:| 
| *Calling timeliner* | 

![](05Timeliner.png)
|:--:| 
| *Timeliner: plaso based timeline function* | 

The function sets up relevant paths for the command, creates target folder and shells out to the relevant plaso script. Modification is simple and the results can be collected manually or by data platform agent of choice.  

Similarly, file specific processing based on upload_paths enables traversing the flow upload paths once for optimal performance. I have also included a test and will only process some paths if the artifact of interest was collected.

![](05ProcessingPathBased.png)
|:--:| 
| *Example path specific processing flow* | 


### So what do we collect?
The Velociraptor project has built in artefacts that are able to be customised easily. In the early days of Velociraptor I had written custom ntfs collection artifacts to accommodate my collection use cases. The velocidex team have recently developed an artefact that makes this process much easier. The artefact is called Windows.KapeFiles.Targets and extracts the collection profiles from Eric Zimmerman’s KapeFiles project.

![](06KapeTargets.png)
|:--:| 
| *Artifact: KapeTargets* | 

From a user perspective this is very easy with preset levels of live response enabled or individual targetted artefact collection. Of course I still have my own live response preferences based on use case, but Kape files is a fairly mature and modular collection capability.


### How do I run it?
To run simply call the client script inside the same folder as the bindings.  
For example    
```bash
/usr/bin/python3 $VRAPTOR/api/processing.py
```  

In my usecase I prefer an on demand Velociraptor processing service with the following attributes:  

![](07Service.png)
|:--:| 
| *Velociraptor Processing Service* | 

Set to on demand, I simply execute service startup with:
```bash
sudo systemctl start vraptor-processing
```  

Stop with:
```bash
sudo systemctl stop vraptor-processing
```  

And view status with:
```bash
sudo systemctl status vraptor-processing -l
```  
Once running, the service will wait for relevant rows to be returned and process as configured.


### Final Thoughts
In this post I have walked through using the Velociraptor API for live response processing. Velociraptor is modular providing access to underlying services and enabling blue teams to build the workflow that they need, on the infastructure that works for them. In my instance the example covers a small subset of what I plan to deply but is already saving on some really time consuming tasks.  

For those that are interested I have included below:  
1. [An install script for the API bindings and service install](https://github.com/mgreen27/mgreen27.github.io/blob/master/static/Velociraptor/VRaptorAPISetup.sh)
2. [A POC processsing script](https://github.com/mgreen27/mgreen27.github.io/blob/master/static/Velociraptor/processing.py)

I hope you have gained some knowledge on Velociraptor API setup and one of the most important use cases for incident response. Please feel free to reach out and provide feedback or improvements.  


# Further resources
1. [Velociraptor Documentation](https://www.velocidex.com/about/)
2. [Velociraptor Overview at 2019 SANs DFIR Summit](https://www.velocidex.com/docs/presentations/sans_dfir_summit2019/)
3. [Velociraptor Getting started](https://www.velocidex.com/docs/getting-started/)
4. [Velociraptor API documentation](https://www.velocidex.com/docs/user-interface/api/)
5. [Velociraptor Python Bindings](https://github.com/Velocidex/velociraptor/tree/master/bindings/python)
