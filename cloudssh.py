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
import argparse
import boto3


class CloudSSH(object):
    def __init__(self, argv):
        self.argv = argv
        self.user = ""
        self.inst_id = ""
        self.client_tool_params = ""
        self.remote_cmd = ""
        self.ip = ""
        self.stop_on_closing = False
        if "win" in sys.platform:
            self.sshuicmd = "putty"
            self.sshinlinecmd = "plink"
        elif "linux" in sys.platform:
            self.sshuicmd = "ssh"
            self.sshinlinecmd = "ssh"
        else:
            print("unsupported platform {}".format(sys.platform))
            exit(1)

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
                                            usage="%(prog)s [-n --no-stop] <cloud address> [command] [-- <parameters passed to the client>]",
                                            epilog="parameters after \"--\" are passed to the underline ssh client."
                                                                                " E.g. cloudssh user@instance_id -- -i c:\\users\\xyz\\mykey.ppk")
        parser.add_argument("-n", "--no-stop", action='store_false', help="normally cloudssh would stop the instance after the session is closed"
                                                                          " if there is no other interactive sessions. This flag disables this feature.")
        parser.add_argument("cloud_address", nargs=1, type=str, metavar="<cloud address>", help="cloud ssh address. E.g. user@instance_id.")
        parser.add_argument("remote_cmd", nargs=argparse.REMAINDER, metavar="[command]", help="command to be executed")
        args = parser.parse_args(cloudssh_params)
        dest = args.cloud_address[0]
        self.stop_on_closing = args.no_stop;
        self.remote_cmd = " ".join(args.remote_cmd)
        parts = dest.split("@")
        if len(parts) != 2:
            print("Invalid address format.")
            exit(1)
        self.user = parts[0]
        self.inst_id = parts[1]

    def do_ssh(self):
        self.ec2 = boto3.resource("ec2")
        self.locate_instance_public_ip()
        cmd = "{0} {1} {2}@{3} {4}".format(self.sshuicmd, self.client_tool_params, self.user, self.ip, self.remote_cmd)
        subprocess.call(cmd, shell=True)
        self.handle_session_close()
        print("cloudssh session closed")

    def handle_session_close(self):
        cmd = "{0} {1} {2}@{3} who".format(self.sshinlinecmd, self.client_tool_params, self.user, self.ip)
        tty_sessions = subprocess.check_output(cmd)
        if len(tty_sessions) == 0:
            if self.stop_on_closing:
                inst = self.ec2.Instance(self.inst_id)
                inst.stop()
                print("No interactive sessions at {0}. Stopping the instance.".format(self.inst_id))
            else:
                print("No interactive sessions at {0}. The instance is still running.".format(self.inst_id))
        else:
            print("There are other interactive sessions.")

    def locate_instance_public_ip(self):
        started_here = False
        inst = None
        try:
            for i in range(120):
                inst = self.ec2.Instance(self.inst_id)
                if inst is None:
                    raise Exception("invalid instance id {0}".format(self.inst_id))

                if inst.state['Name'] == "running":
                    if inst.public_ip_address is not None:
                        print("Found public IP {0} for instance {1}".format(inst.public_ip_address, self.inst_id))
                        self.ip = inst.public_ip_address
                        return
                    else:
                        raise Exception("instance {0} does not have public IP".format(self.inst_id))
                elif inst.state['Name'] == "stopped":
                    print("Starting instance {0} from \"{1}\" state".format(self.inst_id, inst.state['Name']))
                    inst.start()
                    started_here = True
                elif inst.state['Name'] == "pending" or inst.state['Name'] == "stopping":
                    print("Waiting for instance {0} to start".format(self.inst_id))
                else:
                    raise Exception("instance {0} is invalid ({1}).".format(self.inst_id, inst.state['Name']))

                time.sleep(5)
        except Exception as e:
            if started_here and inst is not None:
                inst.stop()
            raise e

if __name__ == "__main__":
    try:
        cloud_ssh = CloudSSH(sys.argv)
        cloud_ssh.parse_args()
        cloud_ssh.do_ssh()
    except Exception as e:
        print("e: {0}".format(str(e)))
