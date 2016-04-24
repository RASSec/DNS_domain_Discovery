#!/usr/local/bin/python
#-*- coding: utf-8 -*-
#auth=blog.cve.wang
import os
import sys
import re

reObj3 = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
def nmap_demo(ip):
    os.popen('rm -rf open.log&&nmap %s -Pn -T4 -p53 --open >>open.log'% ip) .read()
    for x in reObj3.findall(openfile()):
        print '[+]--ok--'+x+'   '+str(53)+'  open!'
def openfile():
    return open('open.log').read()

def openfiledns():
    return open('dns.txt').read()

def del_log():
    os.popen('rm -rf dns.txt open.log')
def att(url):
    os.popen('rm -rf dns.txt&&perl dnsenum.pl %s >>dns.txt' % url).read()
    for x in reObj3.findall(openfiledns()):
        print 'scaning......'+'.'.join(x.split('.')[:3])+'.1/24'
        nmap_demo('.'.join(x.split('.')[:3])+'.1/24')
if __name__=="__main__":
    if 2 != len(sys.argv):
	print '''

8 888888888o.      b.             8    d888888o.      d888888o.
8 8888    `^888.   888o.          8  .`8888:' `88.  .`8888:' `88.
8 8888        `88. Y88888o.       8  8.`8888.   Y8  8.`8888.   Y8
8 8888         `88 .`Y888888o.    8  `8.`8888.      `8.`8888.
8 8888          88 8o. `Y888888o. 8   `8.`8888.      `8.`8888.
8 8888          88 8`Y8o. `Y88888o8    `8.`8888.      `8.`8888.
8 8888         ,88 8   `Y8o. `Y8888     `8.`8888.      `8.`8888.
8 8888        ,88' 8      `Y8o. `Y8 8b   `8.`8888. 8b   `8.`8888.
8 8888    ,o88P'   8         `Y8o.` `8b.  ;8.`8888 `8b.  ;8.`8888
8 888888888P'      8            `Yo  `Y8888P ,88P'  `Y8888P ,88P'
ver 1.0
By RASSec
blog.cve.wang
Eg: python dns_s.py cert.org.cn
	'''
	exit()
    try:
        att(sys.argv[1])
    except KeyboardInterrupt:
        del_log()
        print 'stop scaning...'
        sys.exit()