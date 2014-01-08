AWS_Security_Groups
===================

Script that parses all *.json files from current working director and authorizes rules for the security groups found in json.

Example JSON with small explanation of parts:

	{
		"security_group": {
			"name": "example_group",   // Human Readable group name -- Not requirede
			"description": "example description",  // Human readable description -- Not required
			"group_id": "sg-3x4mpl3",  // AWS Security Group ID -- REQUIRED
			"vpc_id": "vpc-3x4mpl3",   // AWS VPC ID that the Security Group belongs to -- Not required
			"inbound": {
				"rules": [
					{
						"source": "192.168.1.1/16",       // Source IP, Subnet, or another security group's ID -- IP/Subnets must be in CIDR format(x.x.x.x/xx)
						"destination_ports": "0..65535",  // Destination Port or Ports.  Must be in NUM..NUM range format, even for singular port opening.  Ex: "443..443"
						"description": "All ports open from local subnet"  // Human readable description of individual rule.
					}
				]
			}
		}
	}
