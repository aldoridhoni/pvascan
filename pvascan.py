#!/usr/bin/env python

"""
Copyright (c) 2015, M Habib - STMIK Akakom, Yogyakarta
All rights reserved.
License : BSD-3-Clause
"""

try:
	import argparse, wget, csv, os
	from ConfigParser import ConfigParser
	from CNmap import CNmap
except ImportError:
	print '[-] Python error, some library cannot imported.'
	print '| pvascan importing additional library : '
	print '|	python-nmap, wget'
	print '|__ Try: pip install <python-library>\n'
	exit(0)

cnfile	= 'config.ini'
dbfile	= 'files.csv'
port = None
config = ConfigParser()

def createconfig():
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

def loadconfig():
	global dbfile
	try:
		config.read(cnfile)
		dbfile = config.get('Configuration', 'database')
	except:
		print '[-] Something is wrong while reading configuration file,'
		exit(0)


def updateconfig(db):
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

def getdb():
	"""
	Download files.csv
	Return filename
	"""
	try:
		db = wget.download('https://raw.githubusercontent.com/offensive-'
		'security/exploit-database/master/files.csv') # Exploit-DB files.csv
		print ''
		updateconfig('files.csv')
	except:
		print '[-] Error while downloading file database!'

def loadb(dbfile):
	"""
	Reload config and load dbfile
	Return db module
	"""
	try:
		db = csv.DictReader(open(dbfile))
		return db
	except:
		print '[-] Vulnerability database is not selected.'
		print '|__ Please try \'./pvascan.py -h\'\n'
		exit(0)

def optmenu():
	global host, port
	parser = argparse.ArgumentParser()	
	parser.add_argument('-H', '--host', dest='ip',
					help='IP of the target that will be scan for Vulnerability Assessment')		 
	parser.add_argument('-p', '--port', dest='port', 
					help='Scan just the specific TCP port (1-65535)')
	parser.add_argument('--getdb', action='store_true', dest='getdb',
					help='Download Exploit-DB files.csv as vulnerability database and exit')
	parser.add_argument('--dbs', dest='dbs',
					help='Select path where your database file is in with updating pvascan configuration file')

	options = parser.parse_args()
	host = options.ip
	if options.getdb:
		getdb()
		exit(0)
	if options.dbs:
		updateconfig(options.dbs)
		loadconfig()
	if (host == None):
		print parser.usage
		exit(0)
	if options.port:
		port = options.port

def main():
	createconfig()
	loadconfig()
	optmenu()

	db = loadb(dbfile)
	cnmap = CNmap(host, db, port)
	cnmap.nmscan()
	
	try:
		if cnmap.result['scan'][host].keys():
			cnmap.osdetect()
			cnmap.portinfo()
	except:
		print '[-] Oh Dear!'
		print '| problem while connect to target host'
		print '|__ Please try \'./pvascan.py -h\'\n'

if __name__ == '__main__':
	main()
