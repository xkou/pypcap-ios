import sys

#from ctypes import *
#cap = CDLL("pypcap.dylib")
#print "dosome", cap.some()


import pypcap
print "interface:", pypcap.lookupdev()

pcap = pypcap.pcap()
pcap.setfilter( "tcp and not port 22" )

import dpkt

for t, p in pcap:
	d = dpkt.ethernet.Ethernet( p )
	d = d.data.data.data
	if d.startswith( "GET" ) or d.startswith( "POST" ) or d.startswith("CONNECT"):
		print d.split("\n")[0].strip()

print "hello world", pypcap.version()
print pypcap.lookupdev()



