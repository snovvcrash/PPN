#!/usr/bin/env python3

# Usage:
# mkdir -p services/names
# ./parsenmap.py -i services/alltcp-versions.xml

import argparse
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import PurePosixPath, Path

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--input', type=str, help='input XML file path')


def parsenmap(root):
	names = defaultdict(list)
	for host in root.findall('host'):
		if host.find('status').get('state') == 'up':
			for ports in host.findall('ports'):
				for port in ports.findall('port'):
					if port.find('state').get('state') == 'open':
						try:
							service_name = port.find('service').get('name')
						except AttributeError:
							pass
						else:
							port_id = port.get('portid')
							host_addr = host.find('address').get('addr')
							names[(service_name, port_id)].append(host_addr)

	return names


if __name__ == '__main__':
	args = parser.parse_args()
	report = ET.parse(args.input)
	root = report.getroot()

	for (service_name, port_id), host_addrs in parsenmap(root).items():
		for host_addr in sorted(set(host_addrs)):
			filename = f'{PurePosixPath(args.input).parent}/names/{port_id}-{service_name}.txt'
			if not Path(filename).exists():
				print(f'[+] Created file {filename}')
			with open(filename, 'a') as f:
				f.write(host_addr + '\n')
