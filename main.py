from logging import exception
import boto3
import os
import re
import subprocess
import xml.dom.minidom

open_re = re.compile(r"Security\slayer")
closed_re = re.compile(r"^Received\sunhandled\spacket")
status_dict = {}
output_list = []

def readXMLFile(inputfilename):
    DOMTree = xml.dom.minidom.parse(inputfilename)
    return DOMTree

def parseXMLFile(DOMTree):
    try:
        portscan = DOMTree.documentElement
        ports = portscan.getElementsByTagName('ports')[0].getElementsByTagName('port')
        ip_addr = portscan.getElementsByTagName('host')[0].getElementsByTagName('address')[0].getAttribute('addr')
        for port in ports:
            if (port.getAttribute("portid") == "3389"):
                try:
                    script_output = port.getElementsByTagName('script')[0].getAttribute('output')
                except:
                    script_output = ''
        if open_re.search(script_output):
            rdp_status = "Accessible"
        elif closed_re.match(script_output):
            rdp_status = "Inaccessible"
        else:
            rdp_status = "Undetermined"
    except Exception as ex:
        print("[-] Error parsing the output.xml fileL: " + str(ex))
        ip_addr = ""
        rdp_status = "fail"
    status_dict[ip_addr] = rdp_status
    return (ip_addr, rdp_status)

def parse_output():
    ip_addr, rdp_status = parseXMLFile(readXMLFile("output.xml"))
    if not(rdp_status == "fail"):
        print("[+]", str(ip_addr), "-", str(rdp_status))
    
    output_list.append(str(ip_addr) + " - " + str(rdp_status))
    # os.remove("output.xml")

def check_rdp(ip_addr):
    try:
        nmap_command = "nmap -sV -Pn -n -p3389 --script=rdp-enum-encryption -vv -oX output.xml --append-output " + str(ip_addr).strip()
        nmap_process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, shell=True)
        nmap_process.communicate()
        parse_output()
    except Exception as ex:
        print("[-] Error occured while running script: " + str(ex))

ec2client_1 = boto3.client('ec2')
region_response = ec2client_1.describe_regions()

for region in region_response['Regions']:
    ec2client = boto3.client('ec2',region_name=region['RegionName'])
    response = ec2client.describe_instances()
    
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            if instance['State']['Name'] == 'running':
                check_rdp(instance['PublicIpAddress'])

print(output_list)