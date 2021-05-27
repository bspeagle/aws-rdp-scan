This script scans all regions for all EC2 instances with a public IP and returns whether port 3389 (used for RDP) is accessible.

There are two output files:
report.xml - Complete details of nmap scan performed on each instance
summary.txt - Simple list of public IPs found and whether the corresponding RDP port is accessible

You need to set up your AWS security credentials before the code is able to connect to AWS.
More info here https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html