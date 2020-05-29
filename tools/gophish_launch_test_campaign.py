#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from argparse import ArgumentParser

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from gophish import Gophish
from gophish.models import *

parser = ArgumentParser()
parser.add_argument('--id', type=int, default=None, help='campaign id (if you want to delete existing campaign first)')

API_KEY = '<API_KEY_HERE>'
HOST = 'https://127.0.0.1:31337'


def start_campaign(api, name='Test_Campaign'):
	groups = [Group(name='Group_Name')]
	template = Template(name='Email_Template_Name')
	page = Page(name='Landing_Page_Name')
	smtp = SMTP(name='Sender_Name')
	url = 'https://example.com'
	campaign = Campaign(name=name, groups=groups, template=template, page=page, url=url, smtp=smtp)
	campaign = api.campaigns.post(campaign)
	return campaign


def delete_campaign(api, campaign_id):
	resp = api.campaigns.delete(campaign_id=campaign_id)
	return resp


api = Gophish(API_KEY, host=HOST, verify=False)

args = parser.parse_args()
if args.id:
	resp = delete_campaign(api, args.id)
	if resp.success:
		print(f'[+] Deleted campaign with id {args.id}')
	else:
		print(f'[-] Failed to delete campaign with id {args.id}')

campaign = start_campaign(api)
if campaign.id:
	print(f'[+] Started new campaign with id {campaign.id}')
else:
	print(f'[-] Failed to start new campaign')
