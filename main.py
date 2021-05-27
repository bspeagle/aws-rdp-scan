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
    try:
        DOMTree = xml.dom.minidom.parse(inputfilename)
        return DOMTree
    except Exception as ex:
        print("[-] Error reading the output.xml file: " + str(ex))

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

        reportFile = xml.dom.minidom.parse("report.xml")
        reportXml = reportFile.documentElement
        reportXml.appendChild(portscan)
        xml_str = reportXml.toprettyxml(indent = '  ').replace("\n\n","")

        with open ("report.xml", "w") as f:
            f.write(xml_str)
        
    except Exception as ex:
        print("[-] Error parsing the output.xml file: " + str(ex))
        ip_addr = ""
        rdp_status = "fail"
    
    status_dict[ip_addr] = rdp_status
    return (ip_addr, rdp_status)

def parse_output():
    try:
        ip_addr, rdp_status = parseXMLFile(readXMLFile("output.xml"))
    except Exception as ex:
        print("[-] Error occured while parsing script: " + str(ex))
    
    output_list.append(str(ip_addr) + " - " + str(rdp_status))
    os.remove("output.xml")

def check_rdp(ip_addr):
    try:
        nmap_command = "nmap -sV -Pn -n -p3389 --script=rdp-enum-encryption -vv -oX output.xml --append-output " + str(ip_addr).strip()
        nmap_process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, shell=True)
        nmap_process.communicate()
        parse_output()
    except Exception as ex:
        print("[-] Error occured while running script: " + str(ex))

if os.path.exists('output.xml'):
    os.remove("output.xml")

if os.path.exists('report.xml'):
    os.remove("report.xml")

if os.path.exists('summary.txt'):
    os.remove("summary.txt")

root = xml.dom.minidom.Document()
xmlRoot = root.createElement('root')
root.appendChild(xmlRoot)
with open("report.xml", "w") as xml_file:
    root.writexml(xml_file)

ec2client_1 = boto3.client('ec2')
region_response = ec2client_1.describe_regions()

for region in region_response['Regions']:
    ec2client = boto3.client('ec2',region_name=region['RegionName'])
    response = ec2client.describe_instances()
    
    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            if instance['State']['Name'] == 'running' and 'PublicIpAddress' in instance:
                check_rdp(instance['PublicIpAddress'])

with open("report.xml") as filehandle:
        lines = filehandle.readlines()

with open("report.xml", 'w') as filehandle:
    lines = filter(lambda x: x.strip(), lines)
    filehandle.writelines(lines)   

with open('summary.txt', mode='wt', encoding='utf-8') as myfile:
    myfile.write('\n'.join(output_list))

print(output_list)