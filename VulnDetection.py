#!/usr/bin/env python
# -*- coding: utf-8 -*-
# VulnDetection.py
"""
Banner reader.
"""
from __future__ import print_function
import  re

class VulnDetection(object):
	def __init__(self):
		self.db = None
		self.result = None

	def os_detect(self):
		try:
			os = self.result['osclass']
			print("OS detection accuracy %s%" % os['accuracy'])
			print("Vendor :", os['vendor'], os['osfamily'], os['osgen'])
		except KeyError:
			print("For OS detection pvascan need root privillage")

	def port_info(self):
		found_ports = self.result['tcp']
		print("Discovered host ports : %s" % len(found_ports))
		for (number, port) in found_ports.items():
			banner = port['product'] + ' ' + port['version']
			if (port['state'] == 'open'):
				print("[+] PORT %s [%s] %s" % (number, port['name'], banner))
				if len(banner) > 3:
					self.loop_db(banner)
			else:
				print("[-] PORT %s [STATE:%s]" % (number, port['state']))

	def loop_db(self, banner):
		found = {}
		for row in self.db:
			if self.vulner_search(banner, row['description']):
				found.update({row['id'] : row['description']})

		if found:
			print ("| VULNERABILITY DETECTED!")
			print ("|- Description : ")
			for num, id in enumerate(found):
				print("|    %d. %s" % (num + 1, found[id]))
				print("|    | For more information please visit url below")
				print("|    |_ https://www.exploit-db.com/exploits/%s/" % id)
			print("|-", len(found), "exploits found,")
			print("|__ Please contact the aplication's vendor to patch the vulnerability\n")

	def vulner_search(self, banner, string):
		s = re.compile(banner, flags=re.IGNORECASE)
		if s.match(string):
			return True
		else:
			return False
