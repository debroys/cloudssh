Cloudssh

Installation:

1. Install python if not already installed.
2. Install aws boto3 for python.
   Use "pip install boto3" or "sudo pip install boto3".
   On MacOS you may need to use "sudo pip install --ignore-installed six boto3"

Additional step on Windows

1. Install PUTTY.

IMPORTANT - Make sure all installed tools are on
            the PATH for command search.


Quick Start:

cloudssh ec2-user@<your instance id>.<region name>

For example

cloudssh ec2-user@i-0123456789012345.us-west-2

LIMITATIONS:

Currently the supported cloud provider is AWS only.


Author Jim Yang. Contact email: jim@fittedcloud.com or jyang_bos@yahoo.com
