"""
Copyright (c) 2015, M Habib - STMIK Akakom, Yogyakarta
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of STMIK Akakom nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
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
