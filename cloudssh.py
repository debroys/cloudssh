#----------------------------------------------------------------------------
# Copyright 2016, FittedCloud, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.
#
#Author: Jim Yang (jim@fittedcloud.com)
#----------------------------------------------------------------------------

import time
import subprocess
import sys
import shlex
import argparse
import boto3

class Configuration(object):
    def __init__(self, argv):
        self.argv = argv
        self.supported_providers = ["aws"]

    def parse_args(self):
        if "--" in self.argv:
            dash_index = self.argv.index("--")
            cloudssh_params = self.argv[1:dash_index]
            self.client_tool_params = " ".join(self.argv[dash_index+1:])
        else:
            cloudssh_params = self.argv[1:]
            self.client_tool_params = ""

        parser = argparse.ArgumentParser(prog="cloudssh",
                                            description="A tool to ssh to cloud VM instances based on instance id.\n"
                                            "\tExample: cloudssh user@instance_id",
                                            usage="%(prog)s [-n --no-stop] [-p --use-private-ip] <cloud address> [command] [-- <parameters passed to the client>]",
                                            epilog="parameters after \"--\" are passed to the underline ssh client."
                                                                                " E.g. cloudssh user@instance_id -- -i c:\\users\\xyz\\mykey.ppk")
        parser.add_argument("-n", "--no-stop", action='store_false', help="normally cloudssh would stop the instance after the session is closed"
                                                                          " if there is no other interactive sessions. This flag disables this feature.")
        parser.add_argument("-p", "--use-private-ip", action='store_true', help="use the IP address private to the cloud.")
        parser.add_argument("cloud_address", nargs=1, type=str, metavar="<cloud address>", help="cloud ssh address. E.g. user@instance_id.")
        parser.add_argument("remote_cmd", nargs=argparse.REMAINDER, metavar="[command]", help="command to be executed")
        args = parser.parse_args(cloudssh_params)
        dest = args.cloud_address[0]
        self.stop_on_closing = args.no_stop
        self.use_private_ip = args.use_private_ip
        self.remote_cmd = " ".join(args.remote_cmd)
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
            if len(addr_parts) > 3:
                raise Exception("invalid aws address. The address format is <instance_id>[.<region>[.aws]]")
            if len(addr_parts) >= 2:
                self.region = addr_parts[1]
            else:
                self.region = None
            if len(addr_parts) >= 1:
                self.inst_id = addr_parts[0]


class CloudSsh(object):
    def __init__(self, configuration):
        self.config = configuration
        if "win" in sys.platform:
            self.sshuicmd = "putty"
            self.sshinlinecmd = "plink"
        elif "linux" in sys.platform:
            self.sshuicmd = "ssh"
            self.sshinlinecmd = "ssh"
        else:
            print("unsupported platform {}".format(sys.platform))
            exit(1)

    def do_ssh(self):
        self.ip = self.locate_instance_public_ip()
        cmd = "{0} {1} {2}@{3} {4}".format(self.sshuicmd, self.config.client_tool_params, self.config.user, self.ip, self.config.remote_cmd)
        subprocess.call(cmd, shell=True)
        self.handle_session_close()
        print("cloudssh session closed")

    def handle_session_close(self):
        cmd = "{0} {1} {2}@{3} who".format(self.sshinlinecmd, self.config.client_tool_params, self.config.user, self.ip)
        tty_sessions = subprocess.check_output(cmd, shell=True)
        if len(tty_sessions) == 0:
            if self.config.stop_on_closing:
                self.close_session()
                print("No interactive sessions. Stopping the instance.")
            else:
                print("No interactive sessions. The instance is still running.")
        else:
            print("There are other interactive sessions.")

    def locate_instance_public_ip(self):
        return None;

    def close_session(self):
        pass

class AwsCloudSsh(CloudSsh):
    def __init__(self, configuration):
        super(AwsCloudSsh, self).__init__(configuration)
        if self.config.region is not None:
            boto3.setup_default_session(region_name=self.config.region)
        self.ec2 = boto3.resource("ec2")

    def locate_instance_public_ip(self):
        started_here = False
        inst = None
        try:
            for i in range(120):
                inst = self.ec2.Instance(self.config.inst_id)
                if inst is None:
                    raise Exception("invalid instance id {0}".format(self.config.inst_id))

                if inst.state['Name'] == "running":
                    if self.config.use_private_ip:
                        if inst.private_ip_address is not None:
                            time.sleep(10)
                            print("Found private IP {0} for instance {1}".format(inst.private_ip_address, self.config.inst_id))
                            return inst.private_ip_address
                        else:
                            raise Exception("instance {0} does not have internal IP".format(self.config.inst_id))
                    else:
                        if inst.public_ip_address is not None:
                            time.sleep(10)
                            print("Found public IP {0} for instance {1}".format(inst.public_ip_address, self.config.inst_id))
                            return inst.public_ip_address
                        else:
                            raise Exception("instance {0} does not have public IP".format(self.config.inst_id))
                elif inst.state['Name'] == "stopped":
                    print("Starting instance {0} from \"{1}\" state".format(self.config.inst_id, inst.state['Name']))
                    inst.start()
                    started_here = True
                elif inst.state['Name'] == "pending" or inst.state['Name'] == "stopping":
                    print("Waiting for instance {0} to start".format(self.config.inst_id))
                else:
                    raise Exception("instance {0} is invalid ({1}).".format(self.config.inst_id, inst.state['Name']))

                time.sleep(5)
            raise Exception("too many tries to locate IP. Give up.")
        except Exception as e:
            if started_here and inst is not None:
                inst.stop()
            raise e

    def close_session(self):
        inst = self.ec2.Instance(self.config.inst_id)
        inst.stop()


def main():
    try:
        config = Configuration(sys.argv)
        config.parse_args()
        if config.provider == "aws":
            cloud_ssh = AwsCloudSsh(config)
        cloud_ssh.do_ssh()
    except Exception as e:
        print("Error: {0}".format(str(e)))


if __name__ == "__main__":
    main()
