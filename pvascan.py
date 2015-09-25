#!/usr/bin/python
"""
Copyright (c) 2015, M Habib - STMIK Akakom, Yogyakarta
All rights reserved.
License : BSD-3-Clause
"""

import csv
import nmap
import optparse
import re

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
		print '[-]Scanning stoped'
		print '| vulnerable databases not selected'
		print '|__VA Task need Exploit-DB '+vulndb
		exit(0)
	
def osdetect():
	global osinf
	try:
		os = reslcan['scan'][host]['osclass']
		print 'OS detection accuracy '+os['accuracy']+'% \n'+\
			'Vendor : '+os['vendor']+', '+os['osfamily']+' '+os['osgen']
		osinf = os['osfamily']
	except:
		osinf = None
	return osinf

def portinf():
	global porlis
	oprt = reslcan['scan'][host]['tcp']
	print 'Discovered open port [',len(porlis),'ports opened ]'
	for port in porlis:
		nserv	= oprt[port]['name']
		banner	= oprt[port]['product']+' '+\
					oprt[port]['version']
		print '[+]Port',port,'running service '+nserv+' '+banner
		vulnscan(banner)

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
			probex = 'high'
		elif found>1:
			probex = 'medium'
		elif found>0:
			probex = 'low'
	if found:
		print '| vulnerable detected,'
		print '| ',found,'exploits found'
		print '|__ probability exploitable ['+probex+']'
			
def nmscan():
	global host, argu, reslcan, porlis
	print 'Scanning for host '+host+'...'
	nm = nmap.PortScanner()
	try:
		reslcan = nm.scan(hosts=host, arguments=argu)
		porlis = reslcan['scan'][host]['tcp'].keys()
		return reslcan
	except:
		print '[-]Error!!! [nmap problem]'
		exit(0)

def optmenu():
	global host
	parser = optparse.OptionParser('usage: ./pvascan.py -H <ip_target>')
	parser.add_option('-H', '--host', dest='ip', type='string', help='IP Target')
	(options, args) = parser.parse_args()
	host = options.ip
	if (host == None):
		print parser.usage
		exit(0)

def main():
	global reslcan
	optmenu()	
	nmscan()
	if reslcan:
		osdetect()
		portinf()
	
if __name__ == '__main__':
	main()
