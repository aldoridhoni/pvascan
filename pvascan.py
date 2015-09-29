#!/usr/bin/python

"""
Copyright (c) 2015, M Habib - STMIK Akakom, Yogyakarta
All rights reserved.
License : BSD-3-Clause
"""

try:
	import ConfigParser
	import csv
	import nmap
	import optparse
	import re
	import wget
except ImportError:
	print '[-]Python error, some library cannot imported.'
	print '| pvascan importing library : ConfigParser, csv, python-nmap, optparse, re, wget'
	print '|__ Try to: pip install <python-library>\n'
	exit(0)

reslcan	= None
host	= ''
osinf	= ''
porlis	= []
argu	= '-T4 -A'
dbfile	= ''
cnfile	= 'config.ini'

def loadcnf():
	global cnfile, dbfile
	config = ConfigParser.ConfigParser()
	try:
		config.read(cnfile)
		dbfile = config.get('Configuration', 'database')
	except:
		print '[-]Missing file configuration.'
		print '|__ Please add \''+cnfile+'\'\n'
		exit(0)

def editcnf(db):
	global cnfile, dbfile
	config = ConfigParser.ConfigParser()
	dbfile = db
	try:
		config.read(cnfile)
		config.remove_option('Configuration', 'database')
		config.set('Configuration', 'database', dbfile)
		with open(cnfile, 'wb') as conf:
			config.write(conf)
		print '[+]Configuration changed on file '+cnfile+'\n'
	except:
		print '[-]Error while changing configuration\n'

def getdb():
	try:
		db = wget.download('https://raw.githubusercontent.com/offensive-'
		'security/exploit-database/master/files.csv') # Exploit-DB file.csv
		editcnf(db)
	except:
		print '[-]Error while downloading file database!'
		
def loadb():
	global dbfile
	try:
		db = csv.DictReader(open(dbfile))
		return db
	except:
		print '[-]Vulnerable database not selected.'
		print '|__ Please try \'--help\'\n'
		exit(0)

def vulnscan(banner):
	db = loadb()
	found = 0
	probex = None
	if len(banner)>1:
		s = re.compile(banner, re.IGNORECASE)
		for row in db:
			c = s.findall(row['description'])
			if c:
				found+=1
		if found>3:
			probex = 'HIGH'
		elif found>1:
			probex = 'MEDIUM'
		elif found>0:
			probex = 'LOW'
	if found:
		print '| vulnerable detected,'
		print '| ',found,'exploits found.'
		print '|__ Probability exploitable ['+probex+']\n'
				
def osdetect():
	global osinf
	try:
		os = reslcan['scan'][host]['osclass']
		print 'OS detection accuracy '+os['accuracy']+'% \n'+\
			'Vendor : '+os['vendor']+', '+os['osfamily']+' '+os['osgen']
		osinf = os['osfamily']
	except:
		print 'For OS detection pvascan need root privillage'
		osinf = None
	return osinf

def portinf():
	global porlis
	oprt = reslcan['scan'][host]['tcp']
	print 'Discovered host ports [',len(porlis),']:'
	for port in porlis:
		nserv	= oprt[port]['name']
		banner	= oprt[port]['product']+' '+oprt[port]['version']
		if (oprt[port]['state']=='open'):
			print '[+]PORT',port,'['+nserv+'] '+banner
			vulnscan(banner)
		else:
			print '[-]PORT',port,'[STATE:'+oprt[port]['state']+']'
					
def nmscan():
	global host, argu, reslcan, porlis
	print 'Scanning for host '+host+'...'
	nm = nmap.PortScanner()
	try:
		reslcan = nm.scan(hosts=host, arguments=argu)
		porlis = reslcan['scan'][host]['tcp'].keys()
	except:
		print '[-]Error!!! Somethings wrong,'
		print '| (network trouble / nmap problem)'
		print '|__ Please try \'--help\'\n'
		exit(0)

def optmenu():
	global host, argu
	parser = optparse.OptionParser('usage: ./pvascan.py -h')	
	parser.add_option('-H', '--host', dest='ip', type='string',
					help='IP of the target that will be scan\n'
						'for Vulnerability Assessment')		 
	parser.add_option('-p', '--port', dest='port', type='string', 
					help='Scan just the specific TCP port (1-65535)')
	parser.add_option('--getdb', action='store_true', dest='getdb',
					help='Download Exploit-DB database file\n')
	parser.add_option('--dbs', dest='dbs', type='string',
					help='Select path where your database file is in\n'
						'and change the file configuration')
	
	(options, args) = parser.parse_args()
	host = options.ip
	if options.getdb:
		getdb()
		exit(0)
	if options.dbs:
		editcnf(options.dbs)
	if (host == None):
		print parser.usage
		exit(0)
	if options.port:
		argu = '-p '+options.port+' -T4 -A' #'-p 1-65535 -T4 -A'
	loadb()	# checking vulnerable database

def main():
	loadcnf()
	optmenu()
	nmscan()
	global reslcan
	if reslcan:
		osdetect()
		portinf()
	
if __name__ == '__main__':
	main()
