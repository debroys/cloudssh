#! /usr/bin/env python

import argparse
import httplib
import json
import sys

import boto3
import netaddr

ec2 = boto3.resource("ec2")


MY_IP_URL = 'httpbin.org/ip'
MYSQL_PORT_RANGES = {
    'tcp': (3306, 3306)  # MySQL/Aurora
}


def ssh_port_ranges():
    if sys.platform == 'win32':
        return {
            'tcp': (22, 22)  # SSH
        }
    else:
        return {
            'tcp': (22, 22),  # SSH
            'udp': (60000, 60010)  # MOSH
        }


def get_user_ip(ip_address_url):
    if ip_address_url.startswith('http://'):
        ip_address_url = ip_address_url.split('//', 1)[1]
        cls = httplib.HTTPConnection
    elif ip_address_url.startswith('https://'):
        ip_address_url = ip_address_url.split('//', 1)[1]
        cls = httplib.HTTPSConnection
    else:
        cls = httplib.HTTPSConnection
    if '/' in ip_address_url:
        url_root, url_path = ip_address_url.split('/', 1)
    else:
        url_root = ip_address_url
        url_path = ''
    http_conn = cls(url_root)
    http_conn.request('GET', '/' + url_path)
    response = http_conn.getresponse()
    if response.status >= 300:
        return None
    content_type = response.getheader('Content-Type', 'text/plain')
    if content_type == 'application/json':
        response = json.loads(response.read())
        if isinstance(response, dict) and 'origin' in response:
            ip = response['origin']
        elif isinstance(response, basestring):
            ip = response
        elif isinstance(response, list):
            ip = response[0]
        else:
            return None
    else:
        ip = response.read().strip()
    if ip.startswith('"'):
        ip = ip[1:]
    if ip.endswith('"'):
        ip = ip[:-1]
    if ip:
        return netaddr.IPNetwork(ip)
    return None


def get_security_group(name=None, id=None):
    if id is None:
        if name is not None:
            response = ec2.describe_security_groups(GroupNames=[name])
            for sg in response['SecurityGroups']:
                id = sg['GroupId']
                break
    if id is None:
        return None
    return ec2.SecurityGroup(id)


def whitelist_user_ip(user_ip, sg_ssh, sg_rds):
    tasks = []
    if sg_ssh:
        tasks.append((sg_ssh, ssh_port_ranges()))
    if sg_rds:
        tasks.append((sg_rds, MYSQL_PORT_RANGES))
    for sg, port_ranges in tasks:
        if sg.ip_permissions:
            sg.revoke_ingress(IpPermissions=sg.ip_permissions)
        for protocol, port_range in port_ranges.iteritems():
            sg.authorize_ingress(IpProtocol=protocol, FromPort=port_range[0], ToPort=port_range[1],
                                 CidrIp=str(user_ip.cidr))


def main():
    parser = argparse.ArgumentParser(description='Whitelist user IP address in AWS security groups')
    parser.add_argument('--user-ip',  help='IP address of User')
    parser.add_argument('--ssh-id', help='ID of SSH Security Group')
    parser.add_argument('--rds-id', help='ID of RDS Security Group')
    parser.add_argument('--ip-address-url', help='URL returning user public IP address', default=MY_IP_URL)
    args = parser.parse_args()
    if args.ssh_id:
        sg_ssh = get_security_group(id=args.ssh_id)
    else:
        sg_ssh = None
    if args.rds_id:
        sg_rds = get_security_group(id=args.rds_id)
    else:
        sg_rds = None
    user_ip = args.user_ip
    if user_ip is None:
        user_ip = get_user_ip(args.ip_address_url)
    whitelist_user_ip(user_ip, sg_ssh, sg_rds)


if __name__ == '__main__':
    main()
