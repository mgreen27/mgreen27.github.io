#!/usr/bin/python3

import json
import grpc
import yaml
import api_pb2
import api_pb2_grpc

import sys
import os
import re
from datetime import datetime
import subprocess

# Set global variables
CONFIG = "/etc/velociraptor/api_client.yaml"
CASES = "/cases"
QUERY="""
    SELECT Timestamp,
        ClientId,
        { SELECT os_info.fqdn AS Hostname 
          FROM clients(client_id=ClientId) 
        } as Hostname,
        FlowId,
        Flow.request.artifacts as Artifact,    
        Flow.request.creator as Creator,
        file_store(path=Flow.urn) as URN,
        Flow.total_expected_uploaded_bytes as Expected_Bytes,
        Flow.total_uploaded_bytes as Uploaded_Bytes,
        { SELECT file_store(path=vfs_path)
          FROM uploads(client_id=ClientId, flow_id=Flow.urn)
        } as Uploads
    FROM watch_monitoring(artifact='System.Flow.Completion')
    WHERE Flow.artifacts_with_results =~ '(?i)KapeFiles|LiveResponse' 
"""
              
def run(config, query):
    creds = grpc.ssl_channel_credentials(
        root_certificates=config["ca_certificate"].encode("utf8"),
        private_key=config["client_private_key"].encode("utf8"),
        certificate_chain=config["client_cert"].encode("utf8"))

    options = (('grpc.ssl_target_name_override', "VelociraptorServer",),)

    with grpc.secure_channel(config["api_connection_string"],
                             creds, options) as channel:
        stub = api_pb2_grpc.APIStub(channel)

        request = api_pb2.VQLCollectorArgs(
            max_wait=1,
            Query=[api_pb2.VQLRequest(
                Name="LiveResponse",
                VQL=query,
            )])

        for response in stub.Query(request):
            rows = json.loads(response.Response)
            for row in rows:

                # Setup variables from flow data
                timestamp       = row['Timestamp']
                client_id       = row['ClientId']
                hostname        = row['Hostname']
                flow_id         = row['FlowId']
                artifact        = row['Artifact']
                creator         = row['Creator']
                urn             = row['URN']
                upload_paths    = row['Uploads']

                # process if there are files in flow
                if len(upload_paths) > 0:
                    print("LiveResponse flow found")
                    print("\tTime     : " + 
                        str(datetime.utcfromtimestamp(timestamp)) + 'Z')
                    print("\tFlowID   : " + flow_id)
                    print("\tClientId : " + client_id)
                    print("\tHostname : " + hostname)
                    print("\tFiles    : " + str(len(upload_paths)))
                    print("\tCreator  : " + creator)

                    case_path = CASES + '/' + hostname
                    timestamp = datetime.utcfromtimestamp(timestamp).\
                                    strftime("%Y-%m-%dT%H%MZ")
                    
                    # run plaso
                    timeliner(case_path, flow_path, hostname, timestamp)
                    
                    # run path specific processing
                    evtx_paths = []

                    for file_path in upload_paths:
                        file_path = str(file_path).rstrip("']").lstrip("['")
                        
                        if file_path.endswith('$MFT'):
                            parse_mft(
                                case_path, hostname, file_path, timestamp)
                        if file_path.endswith('$J'):
                            parse_usnj(
                                case_path, hostname, file_path, timestamp)
                        if file_path.endswith('.evtx'):
                            evtx_paths.append(file_path)

                    if len(evtx_paths) > 0:
                        parse_evtx(
                            case_path, hostname, evtx_paths, timestamp)



def timeliner(case_path, flow_path, hostname, timestamp):
    os.makedirs(case_path + '/plaso_log', exist_ok=True)
    os.chdir(case_path + '/plaso_log')

    plaso_path = case_path + '/' + timestamp + '_' + hostname + '.plaso'
    csv_path = case_path + '/' + timestamp + '_' + hostname + '.csv'
    remove_if_exists(plaso_path)
    remove_if_exists(csv_path)
        
    print("\nGenerating timeline")
    print("\tPlaso dump:\t" + plaso_path)
    print("\tTimeline:\t" + csv_path)
    
    subprocess.check_call(
        ["log2timeline.py","--parsers=!filestat,!mft",plaso_path,flow_path])
    subprocess.check_call(
        ['psort.py','-z','UTC','-w',csv_path,plaso_path])



def parse_evtx(case_path, hostname, evtx_paths, timestamp):
    os.makedirs(os.path.dirname(case_path + '/evtx'), exist_ok=True)
    
    for file_path in evtx_paths:
        process = False
        json_path = case_path + '/evtx/' + timestamp + '_' + hostname + '_' \
                + os.path.splitext(os.path.basename(file_path))[0] + '.json'

        # cover VSS usecase where we expect more than one file
        while True:
            if not os.path.exists(json_path):
                break
            json_path = os.path.splitext(json_path)[0] + '1.json'

        # Currently limiting processing to set evtx. 
        # Will expand in future and add specific EID
        if file_path.endswith('Security.evtx'):
            process = True
        if file_path.endswith('System.evtx'):
            process = True
        if file_path.endswith('Application.evtx'):
            process = True
        if 'TerminalServices' in file_path:
            process = True
        if 'TaskScheduler' in file_path:
            process = True

        if process == True:
            print("\tProcessing:\t" + os.path.basename(file_path))

            subprocess.check_call(
                ['velociraptor','query',
                '"SELECT * FROM parse_evtx(filename=\\"' + file_path + '\\")"',
                 '>',json_path])



def parse_mft(case_path, hostname, file_path, timestamp):
    os.makedirs(os.path.dirname(case_path), exist_ok=True)
    drive = re.search('\/([^\/]*)%3A\/', file_path).group(1)            
    csv_path = case_path + '/' + timestamp + '_' + hostname + '_' \
                + drive + '_mft.csv'
    remove_if_exists(csv_path)
            
    print("\nProcessing MFT")
    print("\tDrive:\t" + drive)
    print("\tInput:\t" + file_path)
    print("\tOutput:\t" + csv_path)
    
    subprocess.check_call(
        ["analyzeMFT.py","-w","--bodyfull","-o",csv_path,"-f",file_path])



def parse_usnj(case_path, hostname, file_path, timestamp):
    os.makedirs(os.path.dirname(case_path), exist_ok=True)
    drive = re.search('\/([^\/]*)%3A\/', file_path).group(1)       
    json_path = case_path + '/' + timestamp + '_' + hostname + '_' \
                + drive + '_usnj.json'
    remove_if_exists(json_path)
    csv_path = case_path + '/' + timestamp + '_' + hostname + '_' \
                + drive + '_usnj.csv'
    remove_if_exists(csv_path)

    print("\nProcessing UsnJrnl:$J")
    print("\tDrive:\t" + drive)
    print("\tInput:\t" + file_path)
    print("\tOutput:\t" + json_path)
    
    subprocess.check_call(
        ['python','/usr/local/bin/usn.py','--csv','-f',
            file_path,'-o',csv_path])
    #subprocess.check_call(
    #    ['python','/usr/local/bin/usn.py','--verbose',
    #        '-f',file_path,'-o',json_path])



def remove_if_exists(filename):
    if os.path.exists(filename):
        os.remove(filename)



if __name__ == '__main__':
    config = yaml.load(open(CONFIG).read(), Loader=yaml.FullLoader)
    run(config, QUERY)
