#!/usr/bin/env python
# -*- coding: utf-8 -*-
# CNmap.py
"""
nmap wrapper with banner reader.
"""

from nmap import PortScanner
import platform, datetime, re

class CNmap:
	def __init__(self, host, dbfile, ports, args='-T4 -A'):
		self.host = host
		self.args = args
		self.db = dbfile
		self.result = {}
		self.osinf = ''
		self.ports = ports

	def nmscan(self):
		print 'From ' + platform.uname()[0] + ' ' +platform.uname()[2]
		print 'On ' + datetime.datetime.now().ctime()
		print 'Scanning for host ' + self.host
		try:
			nm = PortScanner()
			self.result = nm.scan(hosts=self.host, ports=self.ports, arguments=self.args, sudo=False)
		except:
			print '[-] Error!!! Something is wrong,'
			print '| (network trouble / nmap problem)'
			print '|__ Please try \'./pvascan.py -h\'\n'
			exit(0)

	def osdetect(self):
		"""
		Detect os info from result.
		"""
		try:
			os = self.result['scan'][self.host]['osclass']
			print 'OS detection accuracy '+ os['accuracy'] +'% '
			print 'Vendor : ' + os['vendor'] + ', '+ os['osfamily'] + ' ' + os['osgen']
			self.osinf = os['osfamily']
		except:
			print 'For OS detection pvascan need root privillage'
			self.osinf = None

	def portinfo(self):
		porlis = self.result['scan'][self.host]['tcp'].keys()
		oprt = self.result['scan'][self.host]['tcp']
		print 'Discovered host ports [',len(porlis),']'
		for port in porlis:
			nserv	= oprt[port]['name']
			banner	= oprt[port]['product'] + ' '+ oprt[port]['version']
			if (oprt[port]['state'] == 'open'):
				print '[+] PORT %s [ %s ] %s' % (port, nserv, banner)
				self.vulnscan(banner)
			else:
				print '[-] PORT %s [STATE:%s]' % (port, oprt[port]['state'])

	def vulnscan(self, banner):
		found = 0
		desc = {}
		url = {}
		if len(banner) > 3:
			s = re.compile(banner, re.IGNORECASE)
			for row in self.db:
				c = s.findall(row['description'])
				if c:
					found+=1
					desc[found] = row['description']
					url[found] = row['id']				

		if found:
			print '| VULNERABLE DETECTED!'
			print '|- Description : '
			for x in desc.keys():
				print '|   ', x, '' + desc[x]
				print '|    | For more information please visit url below'
				print '|    |_ https://www.exploit-db.com/exploits/' + url[x] +'/'
			print '|-', found, 'exploits found,'			
			print '|__ Please contact the aplication\'s vendor to patch the vulnerable\n'
