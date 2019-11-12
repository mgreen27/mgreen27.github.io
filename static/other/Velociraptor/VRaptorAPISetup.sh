#!/bin/bash
# Velociraptor API setup
# Author: @mgreen27

# This script will setup Velociraptor API services
# Assumes wget installed.
# This script will not install forensic tools  on ubuntu...
#
# Variables:
#     BINFOLDER - folder where velociraptor installed
#     CONFIG - folder where server.config.yaml and where to store api_config.yaml
#     API - API IP and port - localhost:8001 default
#     FOLDER - API program folder where to install bindings
#     VUser and VGroup - velociraptor user and group names


BINFOLDER=/usr/local/bin
CONFIG=/etc/velociraptor
API=127.0.0.1:8001
FOLDER=/opt/velociraptor/api
VUSER=velociraptor
VGROUP=velociraptor


# Get Operating System
os=$(sudo cat /etc/os-release | egrep -i "centos|ubuntu" -om 1)

sudo mkdir $FOLDER -p

if [ ${os^^} == "CENTOS" ]; then
    echo -e "\nInstalling CentOS Velociraptor API POC"

    # Python3 and API requirements
    sudo yum -y install python36 python36-pip git
    sudo pip3 install grpcio grpcio-tools pyyml -q

    # Install CERT-tools
    CERT="https://forensics.cert.org/cert-forensics-tools-release-el7.rpm"
    sudo yum -y install epel-release 
    sudo yum -y update epel-release
    sudo yum -y install centos-release-scl-rh
    wget $CERT
    sudo rpm -i $(basename $CERT)
    rm -f $(basename $CERT)

    # install some tools for POC
    yum -y install plaso
    yum -y install analyzeMFT
    wget -P $BINFOLDER https://raw.githubusercontent.com/PoorBillionaire/USN-Journal-Parser/master/usnparser/usn.py
    chmod +x $BINFOLDER/usn.py

elif [ ${os^^} == "UBUNTU" ]; then
    echo -e "\nInstalling CentOS Velociraptor API POC"
    
    # Python3 and API requirements
    sudo apt-get -y install python3 python3-pip git
    sudo pip3 install grpcio grpcio-tools pyyml -q
else
    echo -e "\nVelociraptor API POC - Unsupported OS. Exiting.\n"
    exit
fi



# If no Velocirpator binary/distributed install we need to download for processing evtx
# download latest release
if [ ! -f "$BINFOLDER/velociraptor" ]
then
    # distributed install so download Velociraptor for processing
    LINUX="$(curl -s https://api.github.com/repos/Velocidex/velociraptor/releases/latest  | grep browser_download_url | cut -d '"' -f 4 | grep linux-amd64)"
    wget $LINUX
    chmod +x $(basename $LINUX)
    sudo mv $(basename $LINUX) $BINFOLDER/velociraptor
else
    # Generate API config for local install
    sudo $BINFOLDER/velociraptor --config $CONFIG/server.config.yaml config api_client --name ServerAPI > $CONFIG/api_client.yaml
    sudo sed -i "s|api_connection_string: 127.0.0.1:8001|api_connection_string: $API|g" $CONFIG/api_client.yaml
fi


# download python bindings
sudo mkdir $FOLDER
wget -P $FOLDER https://raw.githubusercontent.com/Velocidex/velociraptor/master/bindings/python/api.proto
wget -P $FOLDER https://raw.githubusercontent.com/Velocidex/velociraptor/master/bindings/python/api_pb2.py
wget -P $FOLDER https://raw.githubusercontent.com/Velocidex/velociraptor/master/bindings/python/api_pb2_grpc.py
sudo touch /usr/local/lib64/python3.6/site-packages/google/__init__.py

# download client latest release
wget -P $FOLDER https://raw.githubusercontent.com/mgreen27/mgreen27.github.io/master/static/other/Velociraptor/processing.py
wget -P $FOLDER https://github.com/Velocidex/velociraptor/blob/master/bindings/python/client_example.py


# build velociraptor processing service
sudo echo "[Unit]" > /etc/systemd/system/velociraptor-processing.service
sudo echo "Description=Velociraptor processing service" >> /etc/systemd/system/velociraptor-processing.service
sudo echo "After=velociraptor.service" >> /etc/systemd/system/velociraptor-processing.service
sudo echo "" >> /etc/systemd/system/velociraptor-processing.service
sudo echo "[Service]" >> /etc/systemd/system/velociraptor-processing.service
sudo echo "User=${VUSER}" >> /etc/systemd/system/velociraptor-processing.service
sudo echo "Group=${VGROUP}" >> /etc/systemd/system/velociraptor-processing.service
sudo echo "Type=simple" >> /etc/systemd/system/velociraptor-processing.service
sudo echo "Restart=always" >> /etc/systemd/system/velociraptor-processing.service
sudo echo "Environment=LANG=en_US.UTF-8" >> /etc/systemd/system/velociraptor-processing.service
sudo echo "ExecStart=/usr/bin/python3 ${FOLDER}/processing.py" >> /etc/systemd/system/velociraptor-processing.service
sudo echo "" >> /etc/systemd/system/velociraptor-processing.service
sudo echo "[Install]" >> /etc/systemd/system/velociraptor-processing.service
sudo echo "WantedBy=multi-user.target" >> /etc/systemd/system/velociraptor-processing.service
sudo echo "" >> /etc/systemd/system/velociraptor-processing.service

sudo systemctl daemon-reload
sudo chown -R ${VUSER}:${VGROUP} $FOLDER

# User message
echo -e "\n***************************************************"
echo -e "Velociraptor API POC install complete\n"
echo -e "\nVelociraptor Processing Service control:"
echo -e "\tsudo systemctl start velociraptor-processing"
echo -e "\tsudo systemctl stop velociraptor-processing"
echo -e "\tsudo systemctl status velociraptor-processing -l\n"
