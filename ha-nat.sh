#!/bin/bash
#
# This version is from https://github.com/romesh-mccullough/vpc/blob/master/ha-nat.sh
# 
#
# Copyright 2013 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#  http://aws.amazon.com/apache2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
#
# HA NAT User Data Script
# Configures the instance to function as a PAT / NAT device and then
# creates a default NAT route for Route Tables associated to subnets that are:
# 1. tagged with key/value "network=private"
# 2. in the same VPC as the instance running script
# 3. in the same AZ as the instance running script
#
# Prerequisites:
# 
# 1. Instance should be in an Availability Autoscaling group with min/max size of 1
#    Example Autoscaling launch configuration:
#		aws autoscaling create-auto-scaling-group --auto-scaling-group-name ha-nat-asg\
#	    --launch-configuration-name ha-nat-launch --min-size 1 --max-size 1\
#	    --vpc-zone-identifier subnet-xxxxxxxx
#
# 2. AWS CLI version 1.2.2 or higher. By default, script will update instance to the latest version.
# 3. Private subnets must be tagged with tag Name=network and Value=private. Case IS sensitive.
# 4. IAM EC2 Role must be applied to instance:
#
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Effect": "Allow",
#       "Action": [
#     	  "ec2:DescribeInstances",
#   	  "ec2:ModifyInstanceAttribute",
#   	  "ec2:DescribeSubnets",
#   	  "ec2:DescribeRouteTables",
#   	  "ec2:CreateRoute",
#   	  "ec2:ReplaceRoute"
#       ],
#       "Resource": "*"
#     }
#   ]
# }
#
#
# Caveats:
#	If the VPC configuration uses a single Route Table associated to multiple private subnets
#   in multiple AZs, then the HA NAT script would modify private subnets in other AZs. The 
#   recommended HA NAT configuration is 1 NAT per AZ and 1 unique private Route Table per AZ.

# Enable for debugging
# set -x

function log { logger -t "vpc" -- $1; }

function die {
	[ -n "$1" ] && log "$1"
	log "Configuration of HA NAT failed!"
	exit 1
}

# Sanitize PATH
PATH="/usr/sbin:/sbin:/usr/bin:/bin"

# Configure the instance to run as a Port Address Translator (PAT) to provide 
# Internet connectivity to private instances. 

log "Beginning Port Address Translator (PAT) configuration..."
log "Determining the MAC address on eth0..."
ETH0_MAC=$(cat /sys/class/net/eth0/address) ||
    die "Unable to determine MAC address on eth0."
log "Found MAC ${ETH0_MAC} for eth0."

VPC_CIDR_URI="http://169.254.169.254/latest/meta-data/network/interfaces/macs/${ETH0_MAC}/vpc-ipv4-cidr-block"
log "Metadata location for vpc ipv4 range: ${VPC_CIDR_URI}"

VPC_CIDR_RANGE=$(curl --retry 3 --silent --fail ${VPC_CIDR_URI})
if [ $? -ne 0 ]; then
   log "Unable to retrive VPC CIDR range from meta-data, using 0.0.0.0/0 instead. PAT may be insecure!"
   VPC_CIDR_RANGE="0.0.0.0/0"
else
   log "Retrieved VPC CIDR range ${VPC_CIDR_RANGE} from meta-data."
fi

log "Enabling PAT..."
sysctl -q -w net.ipv4.ip_forward=1 net.ipv4.conf.eth0.send_redirects=0 && (
   iptables -t nat -C POSTROUTING -o eth0 -s ${VPC_CIDR_RANGE} -j MASQUERADE 2> /dev/null ||
   iptables -t nat -A POSTROUTING -o eth0 -s ${VPC_CIDR_RANGE} -j MASQUERADE ) ||
       die

sysctl net.ipv4.ip_forward net.ipv4.conf.eth0.send_redirects | log
iptables -n -t nat -L POSTROUTING | log

log "Configuration of NAT/PAT complete."

# Set CLI Output to text
export AWS_DEFAULT_OUTPUT="text"

# Set Instance Identity URI
II_URI="http://169.254.169.254/latest/dynamic/instance-identity/document"

# Set region of NAT instance
REGION=`curl --retry 3 --retry-delay 0 --silent --fail $II_URI | grep region | awk -F\" '{print $4}'`

# Set AWS CLI default Region
export AWS_DEFAULT_REGION=$REGION

# Set AZ of NAT instance
AVAILABILITY_ZONE=`curl --retry 3 --retry-delay 0 --silent --fail $II_URI | grep availabilityZone | awk -F\" '{print $4}'`

# Set Instance ID from metadata
INSTANCE_ID=`curl --retry 3 --retry-delay 0 --silent --fail $II_URI | grep instanceId | awk -F\" '{print $4}'`

# Set VPC_ID of Instance
VPC_ID=`aws ec2 describe-instances --instance-ids $INSTANCE_ID --query 'Reservations[*].Instances[*].VpcId'` ||
	die "Unable to determine VPC ID for instance."

# Determine Main Route Table for the VPC
MAIN_RT=`aws ec2 describe-route-tables --query 'RouteTables[*].RouteTableId' --filters Name=vpc-id,Values=$VPC_ID Name=association.main,Values=true` ||
	die "Unable to determine VPC Main Route Table."

# Optional EIP attachment, file is dropped from user-data
EIP_LIST="/root/eip_alloc.list"
if [ -e "$EIP_LIST" ]; then
	EIP=`grep $AVAILABILITY_ZONE $EIP_LIST | awk '{print $2}'`
        if [ -n "$EIP" ]; then
		log "Associating EIP $EIP"
		aws ec2 associate-address --instance-id $INSTANCE_ID --allocation-id $EIP
	else
		log "No matching EIP found for $AVAILABILITY_ZONE"
		log "eip_alloc.list: `cat $EIP_LIST`"
	fi
fi
	
log "HA NAT configuration parameters: Instance ID=$INSTANCE_ID, Region=$REGION, Availability Zone=$AVAILABILITY_ZONE, VPC=$VPC_ID"

# Get list of private route tables tagged for this subnet, tags primary-az=$AVAILABILITY_ZONE an  network=private
PRIVATE_ROUTE_TABLES="`aws ec2 describe-route-tables --query 'RouteTables[*].RouteTableId' \
--filters Name=vpc-id,Values=$VPC_ID Name=tag:network,Values=private Name=tag:primary-az,Values=$AVAILABILITY_ZONE`"
	# If no private route tables found, exit
	if [ -z "$PRIVATE_ROUTE_TABLES" ]; then
		die "No private route tables found to modify."
	else log "Modifying the following route tables: $PRIVATE_ROUTE_TABLES"
	fi
for table in $PRIVATE_ROUTE_TABLES; do
	if [ "$table" = "$MAIN_RT" ]; then
	       	log "$table is the main route table.  HA NAT script will NOT edit Main Route Table."
	else
               # Modify found private subnet's Routing Table to point to new HA NAT instance id
               aws ec2 create-route --route-table-id $table --destination-cidr-block 0.0.0.0/0 --instance-id $INSTANCE_ID &&
               log "$table has been modified to point default route to $INSTANCE_ID."
               if [ $? -ne 0 ] ; then
                       log "Route already exists, replacing existing route."
                       aws ec2 replace-route --route-table-id $table --destination-cidr-block 0.0.0.0/0 --instance-id $INSTANCE_ID
               fi
	fi
done

if [ $? -ne 0 ] ; then
	die
fi

# Turn off source / destination check
aws ec2 modify-instance-attribute --instance-id $INSTANCE_ID --source-dest-check "{\"Value\": false}" &&
log "Source Destination check disabled for $INSTANCE_ID."

log "Configuration of HA NAT complete."
exit 0
