cloudssh

A client tool for ssh into a VM in the public cloud using static instance name.
The instance can be in any power state. The tool works even when the instance is in
the power-down state. Main features,

1. ssh to a cloud instance using instance name. E.g.

   $ cloudssh ec2-user@i-0123456789012345

2. Automatically power up the instance. When the ssh session terminates, it may
   automatically power down the instance if the session is the last interactive session.

Initially the tool supports AWS. In the future, we will support other cloud providers.

Requirements:

1. Install python if not already installed.
3. Install aws boto3 for python ("pip install boto3").

On Windows
4. Install PUTTY.

Make sure all installed tools are on the path for command search.

For usage, run "cloudssh -h"
