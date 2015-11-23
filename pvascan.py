#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pvascan.py
# encoding = utf8

"""
Copyright (c) 2015, M Habib - STMIK Akakom, Yogyakarta
All rights reserved.
License : BSD-3-Clause
"""
from __future__ import print_function
from __future__ import absolute_import

import argparse
import csv
import os
import platform
import datetime

try:
	from ConfigParser import ConfigParser
except ImportError:
	from configparser import ConfigParser
try:
	import wget
	from nmap import PortScanner
except ImportError as e:
	print("[-]", e)
	print("| pvascan importing additional library :")
	print("|	python-nmap, wget")
	print("|__ Try: pip install <python-library>\n")
	exit(0)

from io import open
from VulnDetection import VulnDetection

cnfile	= 'config.ini'
dbfile	= 'files.csv'
hosts = None
ports = None
config = ConfigParser()

def create_config():
	"""
	Read cnfile for configuration, if not exist create it first and add Configuration
	section.
	"""
	if not os.path.isfile(cnfile):
		with open(cnfile, 'wb', encoding='utf-8') as configfile:
			config.add_section('Configuration')
			config.set('Configuration', 'database', dbfile)
			config.write(configfile)
			print("[+] New configuration created with default value on file %s.\n" % cnfile)

def load_config():
	global dbfile
	try:
		config.read(cnfile)
		dbfile = config.get('Configuration', 'database')
	except:
		print("[-] Something is wrong while reading configuration file.")
		exit(0)

def update_config(db):
	"""Updating config with db variable."""
	try:
		config.read(cnfile)
		config.set('Configuration', 'database', db)
		with open(cnfile, 'wb', encoding='utf-8') as conf:
			config.write(conf)
			print("[+] Configuration updated on file %s.\n" % cnfile)
	except:
		print("[-] Error while updating configuration file!\n")

def get_db():
	try:
		# Exploit-DB files.csv
		db = wget.download('https://raw.githubusercontent.com/offensive-'
		'security/exploit-database/master/files.csv')
		print()
	except:
		print("[-] Error while downloading database file!")

def validate_db(dbfile):
	if not os.path.isfile(dbfile):
		print("[-] Database is not exist")
		exit(0)

def load_db(dbfile):
	"""
	Reload config and load dbfile.
	Return db object.
	"""
	try:
		f = open(dbfile, 'r', encoding='utf-8')
		db = csv.DictReader(f)
		return db
	except:
		print("[-] Vulnerability database is not loading.")
		print("|__ Please try ./pvascan.py -h\n")
		exit(0)

def opt_menu():
	global hosts, ports
	parser = argparse.ArgumentParser()
	parser.add_argument('-H', '--host', dest='ip',
					help='IP of the target that will be scan for Vulnerability Assessment')
	parser.add_argument('-p', '--port', dest='port',
					help='Scan just the specific TCP port Ex: \'22, 80\'')
	parser.add_argument('--getdb', action='store_true', dest='getdb',
					help='Download Exploit-DB files.csv as vulnerability database and exit')
	parser.add_argument('--dbs', dest='dbs',
					help='Select path where your database file is in with updating pvascan configuration file (default: files.csv)')

	options = parser.parse_args()
	hosts = options.ip
	if options.getdb:
		get_db()
		update_config('files.csv')
	if options.dbs:
		update_config(options.dbs)
		validate_db(options.dbs)
	if (hosts == None):
		parser.print_help()
		exit(0)
	if options.port:
		ports = options.port

def nm_scan(hosts, ports, args='-T4 -A'):
	print("From" , platform.uname()[0], platform.uname()[2])
	print("On",  datetime.datetime.now().ctime())
	print("Scanning for host", hosts)
	try:
		nm = PortScanner()
		result = nm.scan(hosts=hosts, ports=ports, arguments=args, sudo=False)
		return result
	except:
		print("[-] Error!!! Something is wrong,")
		print("| (network trouble / nmap problem) ")
		print("| make sure you have nmap installed ")
		print("|__ Please try ./pvascan.py -h\n")
		exit(0)

def main():
	create_config()
	opt_menu()
	load_config()
	validate_db(dbfile)

	nmap_result = nm_scan(hosts, ports)
	# nmap_result = {'nmap': {'scanstats': {'uphosts': '2', 'timestr': 'Sun Nov 22 23:45:21 2015', 'downhosts': '0', 'totalhosts': '2', 'elapsed': '22.63'}, 'scaninfo': {'tcp': {'services': '22,80', 'method': 'connect'}}, 'command_line': 'nmap -oX - -p 80, 22 -T4 -A 127.0.0.1-2'}, 'scan': {'127.0.0.2': {'status': {'state': 'up', 'reason': 'syn-ack'}, 'hostnames': [], 'vendor': {}, 'addresses': {'ipv4': '127.0.0.2'}, 'tcp': {80: {'product': 'nginx', 'state': 'open', 'version': '1.8.0', 'name': 'http', 'conf': '10', 'script': {'html-title': 'Welcome to nginx!'}, 'extrainfo': '', 'reason': 'syn-ack', 'cpe': ''}, 22: {'product': 'OpenSSH', 'state': 'open', 'version': '5.9p1 Debian 5ubuntu1.7', 'name': 'ssh', 'conf': '10', 'extrainfo': 'protocol 2.0', 'reason': 'syn-ack', 'cpe': ''}}}, '127.0.0.1': {'status': {'state': 'up', 'reason': 'syn-ack'}, 'hostnames': [{'type': 'PTR', 'name': 'localhost'}], 'vendor': {}, 'addresses': {'ipv4': '127.0.0.1'}, 'tcp': {80: {'product': 'nginx', 'state': 'open', 'version': '1.8.0', 'name': 'http', 'conf': '10', 'script': {'html-title': 'Welcome to nginx!'}, 'extrainfo': '', 'reason': 'syn-ack', 'cpe': ''}, 22: {'product': 'OpenSSH', 'state': 'open', 'version': '5.9p1 Debian 5ubuntu1.7', 'name': 'ssh', 'conf': '10', 'script': {'ssh-hostkey': '1024 fe:c6:fe:4f:02:1e:a1:86:23:b0:ea:e4:f0:bb:53:8d (DSA)\n2048 da:4c:cf:2d:84:fa:2c:15:1f:68:74:f6:c6:4a:63:f2 (RSA)'}, 'extrainfo': 'protocol 2.0', 'reason': 'syn-ack', 'cpe': ''}}}}}
	pva = VulnDetection()
	for (host, result) in nmap_result['scan'].items():
		print("==============")
		print("IP : %s" % host)
		pva.db = load_db(dbfile)
		pva.result = result
		pva.os_detect()
		pva.port_info()

if __name__ == '__main__':
	main()
