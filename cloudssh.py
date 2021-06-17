# Copyright 2016, FittedCloud, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Jim Yang (jim@fittedcloud.com)


from __future__ import print_function
from __future__ import unicode_literals

from builtins import object
import subprocess
import sys
import os.path
import argparse
import getpass
import socket


class Configuration(object):
    def __init__(self, argv):
        self.argv = argv
        self.supported_providers = ["aws"]
        self.user_home = os.path.expanduser("~")
        self.cloud_user = None
        self.cloud_pwd = None

    def log(self, *args, **kwargs):
        if self.verbose:
            print(*args, **kwargs)

    def parse_args(self):
        if "--" in self.argv:
            dash_index = self.argv.index("--")
            cloudssh_params = self.argv[1:dash_index]
            self.client_tool_params = self.argv[dash_index+1:]
        else:
            cloudssh_params = self.argv[1:]
            self.client_tool_params = []

        parser = argparse.ArgumentParser(
            prog="cloudssh",
            description=("A tool to ssh to cloud VM instances based on instance id.\n"
                         "\tExample: cloudssh user@instance_id"),
            epilog=("parameters after \"--\" are passed directly to the underline ssh client."
                    " E.g. cloudssh user@instance_id -- -i c:\\users\\xyz\\mykey.ppk"))
        parser.add_argument("-n", "--no-stop", action='store_false',
                            help="disable the power down feature")
        parser.add_argument("-p", "--use-private-ip", action='store_true',
                            help="use the IP address private to the cloud")
        parser.add_argument("-i", "--ask-credential", action='store_true',
                            help="force the user to enter a cloud credential interactively;"
                                 " ignore pre-configured credentials")
        parser.add_argument("-m", "--use-mosh", action='store_true',
                            help="use mosh as SSH command (linux and darwin only)")
        parser.add_argument("-s", "--start-only", action='store_true',
                            help="only ensure the instance is running, do not connect.")
        parser.add_argument("-q", "--quiet", action='store_true',
                            help="silent mode")
        parser.add_argument("cloud_address", nargs=1, type=str, metavar="<cloud address>",
                            help="cloud ssh address; e.g. user@instance_id.region.aws")
        parser.add_argument("remote_cmd", nargs=argparse.REMAINDER, metavar="[command]", help="command to be executed")
        args = parser.parse_args(cloudssh_params)
        dest = args.cloud_address[0]
        self.stop_on_closing = args.no_stop
        self.use_private_ip = args.use_private_ip
        self.ask_credential = args.ask_credential
        self.use_mosh = args.use_mosh
        self.start_only = args.start_only
        self.remote_cmd = args.remote_cmd
        self.verbose = not args.quiet
        parts = dest.split("@")
        if len(parts) != 2:
            print("Invalid address format.")
            exit(1)
        self.user = parts[0]
        addr_parts = parts[1].split(".")
        self.provider = addr_parts[-1]
        if self.provider not in self.supported_providers:
            # default provider is "aws"
            self.provider = "aws"

        if self.provider == "aws":
            self.log("Cloud provider is AWS.")
            if len(addr_parts) > 3:
                raise Exception("invalid aws address. The address format is <instance_id>[.<region>[.aws]]")
            if len(addr_parts) >= 2:
                self.region = addr_parts[1]
            else:
                self.region = None
                if os.path.exists(os.path.join(self.user_home, '.aws/config')):
                    self.log("Use pre-configured region")
                else:
                    print("AWS region is missing. Please retry with \"<instance_id>.<region_name>\"")
                    exit(1)

            if len(addr_parts) >= 1:
                self.inst_id = addr_parts[0]

            if not self.ask_credential and os.path.exists(os.path.join(self.user_home, '.aws/credentials')):
                self.log("Use pre-configured credentials")
            else:
                self.cloud_user = getpass.getpass("enter AWS access key: ")
                self.cloud_pwd = getpass.getpass("enter AWS secret key: ")


class CloudSsh(object):
    def log(self, *args, **kwargs):
        if self.config.verbose:
            print(*args, **kwargs)

    def __init__(self, configuration):
        self.config = configuration
        if "win32" == sys.platform:
            self.sshuicmd = "putty"
            self.sshinlinecmd = "plink"
        elif "linux" == sys.platform or "linux2" == sys.platform or "darwin" == sys.platform:
            if self.config.use_mosh:
                self.sshuicmd = "mosh"
            else:
                self.sshuicmd = "ssh"
            self.sshinlinecmd = "ssh"
        else:
            print("Unsupported platform {}".format(sys.platform))
            exit(1)

    def do_ssh(self):
        self.ip = self.locate_instance_ip()
        if self.config.start_only:
            return
        cmd = [self.sshinlinecmd if self.config.remote_cmd else self.sshuicmd]
        cmd.extend(self.config.client_tool_params)
        cmd.append("{0}@{1}".format(self.config.user, self.ip))
        cmd.extend(self.config.remote_cmd)
        subprocess.call(cmd)
        if self.config.verbose or self.config.stop_on_closing:
            self.handle_session_close()
        self.log("Cloudssh session closed")

    def handle_session_close(self):
        cmd = [self.sshinlinecmd]
        cmd.extend(self.config.client_tool_params)
        cmd.append("{0}@{1}".format(self.config.user, self.ip))
        cmd.append("who")
        tty_sessions = subprocess.check_output(cmd)
        if len(tty_sessions) == 0:
            if self.config.stop_on_closing:
                self.close_session()
                self.log("No interactive sessions. Stopping the instance.")
            else:
                self.log("No interactive sessions. The instance is still running.")
        else:
            self.log("There are other interactive sessions.")

    def locate_instance_ip(self):
        return None

    def close_session(self):
        pass


class AwsCloudSsh(CloudSsh):
    def __init__(self, configuration):
        super(AwsCloudSsh, self).__init__(configuration)
        import boto3
        if self.config.cloud_user is not None:
            session = boto3.Session(aws_access_key_id=self.config.cloud_user,
                                    aws_secret_access_key=self.config.cloud_pwd)
            if self.config.region is not None:
                self.ec2 = session.resource("ec2", region_name=self.config.region)
            else:
                self.ec2 = session.resource("ec2")
        else:
            if self.config.region is not None:
                self.ec2 = boto3.resource("ec2", region_name=self.config.region)
            else:
                self.ec2 = boto3.resource("ec2")
        self.started_here = False

    def get_running_instance(self):
        inst = self.ec2.Instance(self.config.inst_id)
        if inst is None:
            raise Exception("invalid instance id {0}".format(self.config.inst_id))

        self.started_here = False
        while inst.state['Name'] != "running":
            if inst.state['Name'] == "stopped":
                self.log("Starting instance {0} from \"{1}\" state".format(self.config.inst_id,
                                                                           inst.state['Name']))
                inst.start()
                self.started_here = True
                self.log("Waiting for instance {0} to start".format(self.config.inst_id))
                inst.wait_until_running()
            elif inst.state['Name'] == "pending":
                self.log("Waiting for instance {0} to start".format(self.config.inst_id))
                inst.wait_until_running()
            elif inst.state['Name'] == "stopping":
                self.log("Waiting for instance {0} to stop".format(self.config.inst_id))
                inst.wait_until_stopped()
            else:
                raise Exception("instance {0} is invalid ({1}).".format(self.config.inst_id, inst.state['Name']))
            inst = self.ec2.Instance(self.config.inst_id)
        return inst

    def get_ip_address(self, inst):
        if self.config.use_private_ip:
            if inst.private_ip_address is None:
                raise Exception("instance {0} does not have internal IP".format(self.config.inst_id))
            self.log("Found private IP {0} for instance {1}".format(inst.private_ip_address,
                                                                    self.config.inst_id))
            return inst.private_ip_address
        elif inst.public_ip_address is None:
            raise Exception("instance {0} does not have public IP".format(self.config.inst_id))
        self.log("Found public IP {0} for instance {1}".format(inst.public_ip_address,
                                                               self.config.inst_id))
        return inst.public_ip_address

    def locate_instance_ip(self):
        inst = None
        try:
            inst = self.get_running_instance()
            ip_address = self.get_ip_address(inst)
            if not have_ssh_prompt(ip_address):
                self.log("WARNING: SSH connection not available for {}".format(ip_address))
            return ip_address
        except Exception:
            if self.started_here and inst is not None:
                inst.stop()
            raise

    def close_session(self):
        inst = self.ec2.Instance(self.config.inst_id)
        inst.stop()


def have_ssh_prompt(ip_address):
    try:
        sock = socket.create_connection((ip_address, 22), 300)
        sock.close()
        return True
    except socket.error:
        return False


def main():
    try:
        config = Configuration(sys.argv)
        config.parse_args()
        if config.provider == "aws":
            cloud_ssh = AwsCloudSsh(config)
        cloud_ssh.do_ssh()
    except Exception:
        raise


if __name__ == "__main__":
    main()
