#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pvascan.py

"""
Copyright (c) 2015, M Habib - STMIK Akakom, Yogyakarta
All rights reserved.
License : BSD-3-Clause
"""

try:
	import argparse, wget, csv, os, platform, datetime
	from ConfigParser import ConfigParser
	from nmap import PortScanner
	from VulnDetection import VulnDetection
except ImportError:
	print '[-] Python error, some library cannot imported.'
	print '| pvascan importing additional library : '
	print '|	python-nmap, wget'
	print '|__ Try: pip install <python-library>\n'
	exit(0)

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
		with open(cnfile, 'wb') as configfile:
			config.add_section('Configuration')
			config.set('Configuration', 'database', dbfile)
			config.write(configfile)
			print '[+] New configuration created with default value on file %s.\n' % cnfile

def load_config():
	global dbfile
	try:
		config.read(cnfile)
		dbfile = config.get('Configuration', 'database')
	except:
		print '[-] Something is wrong while reading configuration file,'
		exit(0)

def update_config(db):
	"""
	Updating config with db variable
	"""
	try:
		config.read(cnfile)
		config.set('Configuration', 'database', db)
		with open(cnfile, 'wb') as conf:
			config.write(conf)
			print '[+] Configuration updated on file %s.\n' % cnfile
	except:
		print '[-] Error while updating configuration file!\n'

def get_db():
	"""
	Download files.csv
	Return filename
	"""
	try:
		db = wget.download('https://raw.githubusercontent.com/offensive-'
		'security/exploit-database/master/files.csv') # Exploit-DB files.csv
		print ''
		update_config('files.csv')
	except:
		print '[-] Error while downloading file database!'

def validate_db(dbfile):
	if not os.path.isfile(dbfile):
		print '[-] Database is not exist'
		exit(0)

def load_db(dbfile):
	"""
	Reload config and load dbfile
	Return db object
	"""
	try:
		db = csv.DictReader(open(dbfile))
		return db
	except:
		print '[-] Vulnerability database is not selected.'
		print '|__ Please try \'./pvascan.py -h\'\n'
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
	if options.dbs:
		update_config(options.dbs)
		validate_db(options.dbs)
	if (hosts == None):
		parser.print_help()
		exit(0)
	if options.port:
		ports = options.port

def nm_scan(hosts, ports, args='-T4 -A'):
	print 'From ' + platform.uname()[0] + ' ' +platform.uname()[2]
	print 'On ' + datetime.datetime.now().ctime()
	print 'Scanning for host ' + hosts
	try:
		nm = PortScanner()
		result = nm.scan(hosts=hosts, ports=ports, arguments=args, sudo=False)
		return result
	except:
		print '[-] Error!!! Something is wrong,'
		print '| (network trouble / nmap problem)'
		print '|__ Please try \'./pvascan.py -h\'\n'
		exit(0)

def main():
	create_config()
	opt_menu()
	load_config()
	validate_db(dbfile)

	nmap_result = nm_scan(hosts, ports)
	pva = VulnDetection()
	for host, result in nmap_result['scan'].iteritems():
		print "=============="
		print 'IP : %s' % host
		pva.db = load_db(dbfile)
		pva.result = result
		pva.os_detect()
		pva.port_info()

if __name__ == '__main__':
	main()
