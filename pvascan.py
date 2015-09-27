#!/usr/bin/python

"""
Copyright (c) 2015, M Habib - STMIK Akakom, Yogyakarta
All rights reserved.
License : BSD-3-Clause
"""

try:
	import csv
	import nmap
	import optparse
	import re
except ImportError:
	print '[-]Python error, some library cannot imported.'
	print '| pvascan importing library : csv, nmap, optparse, re'
	print '|__ Try to: pip install <python-library>\n'
	exit(0)

reslcan	= None
host	= ''
osinf	= ''
porlis	= []
argu	= '-T4 -A'
vulndb	= 'files.csv'

def cekvulndb():
	global vulndb
	try:
		db = csv.DictReader(open(vulndb))
		return db
	except:
		print '[-]Scanning stoped,'
		print '|  vulnerable databases not selected.'
		print '|__ VA Task need Exploit-DB '+vulndb+'\n'
		exit(0)
	
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

def vulnscan(banner):
	db = cekvulndb()
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
			
def nmscan():
	global host, argu, reslcan, porlis
	print 'Scanning for host '+host+'...'
	nm = nmap.PortScanner()
	try:
		reslcan = nm.scan(hosts=host, arguments=argu)
		porlis = reslcan['scan'][host]['tcp'].keys()
		return reslcan
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
	(options, args) = parser.parse_args()		
	host = options.ip
	if (host == None):
		print parser.usage
		exit(0)
	if options.port:
		argu = '-p '+options.port+' -T4 -A' #'-p 1-65535 -T4 -A'

def main():
	global reslcan
	optmenu()	
	nmscan()
	if reslcan:
		osdetect()
		portinf()
	
if __name__ == '__main__':
	main()
