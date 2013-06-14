#!/usr/bin/python
import sys
from FireTestTransparent import *
from ethernetConfig import *
from scapy import *
from threading import Thread

ListPorts = [20,21,22,23,25,53,69,80,81,110,123,136,137,161,443,445,502,700,2000,2001,2002,2003,3389,3129,3128,5900,8080,8081,8090,8091,11002]
#ListPorts = [22,80, 100, 161]
internetInterface = "eth1"
lanInterface = "eth0"
internetMAC = EthernetConfig.GetMACAddress(internetInterface)
lanMAC = EthernetConfig.GetMACAddress(lanInterface)
honeydConf="""
create default
set default personality "Microsoft Windows XP Home Edition"
set default default tcp action open
set default default udp action reset
set default default icmp action open
"""
#set default default udp action open
#set default default udp action "echo 'UDP Response OK'" #"sh -c 'echo ResponseUDP'"
class GenericTest (Thread):
	def __init__(self, baseIP, routerIP, mask, callBackResponse, useUDP):
		Thread.__init__(self)
		self.callBackResponse = callBackResponse
		self.routerIP = routerIP
		self.baseIP = baseIP
		self.mask = mask
		self.baseNetwork = self.baseIP+"/"+str(self.mask)
		self.firewallIP = self.createFirewallIP()
		self.useUDP = useUDP
		if (self.useUDP == False):
			self.layer4=TCP(dport=ListPorts, sport=12345)
		else:
			print "Going UDP"
			self.layer4=UDP(dport=ListPorts, sport=12345)
	def run(self):
		self.prepareContext()
		self.doTest()
		self.cleanContext()
	def createFirewallIP(self):
		digitsRouterIP = self.routerIP.split('.')
		if (int(digitsRouterIP[3]) %4 == 0 ): #.252
			digitsRouterIP[3]=str(int(digitsRouterIP[3])+1)
		else: #.253, .254, .255
			digitsRouterIP[3]=str(int(digitsRouterIP[3])-1)
		return digitsRouterIP[0]+"."+digitsRouterIP[1]+"."+digitsRouterIP[2]+"."+digitsRouterIP[3]
	def prepareContext(self):
		return
	def doTest(self):
		return
	def cleanContext(self):
		commands.getstatusoutput("killall honeyd")
		commands.getstatusoutput("killall arpd")
		commands.getstatusoutput("route del default")
		commands.getstatusoutput("arp -d 10.0.0.254 ")
		commands.getstatusoutput("arp -d 172.16.1.254 ")
		commands.getstatusoutput("killall -9 honeyd")
		commands.getstatusoutput("killall -9 arpd")

	def poisonFirewallARPCache(self): #internetInterface will have 172.16.1.1/24 and lanInterface 10.0.0.1/24
		print commands.getstatusoutput("ifconfig "+internetInterface+" "+self.routerIP)
		print commands.getstatusoutput("arpd "+self.baseNetwork+ " -i "+lanInterface)
		arping(net=self.baseNetwork, iface=internetInterface)
		commands.getstatusoutput("killall arpd"); 
		print commands.getstatusoutput("ifconfig "+internetInterface+" 172.16.1.1/24") 		
	
		print commands.getstatusoutput("ifconfig "+lanInterface+" "+self.baseIP[:-1]+"3") #le 3 est par example
		print commands.getstatusoutput("arpd "+self.routerIP+ " -i "+internetInterface)
		arping(net=self.routerIP, iface=lanInterface)
		commands.getstatusoutput("killall arpd");
		print commands.getstatusoutput("ifconfig "+lanInterface+" 10.0.0.1/24")
	
	def printResults(self, listOfAnswers):
		resultsOK={}
		for snd,rcv in listOfAnswers:
			ipToUse=""
			if (self.PrintIPSRC==True):
				ipToUse=str(rcv.payload.src)
			else:
				ipToUse=str(rcv.payload.dst)
			if  rcv.payload.payload.flags==18: # Syn ACK
				if resultsOK.has_key(ipToUse) == False:
					resultsOK[ipToUse] = [str(rcv.sport)]
				else:
					resultsOK[ipToUse].append(str(rcv.sport))
			elif  rcv.payload.proto==1 and rcv.payload.payload.type==3 and rcv.payload.payload.code==3:  #rcv (ehter) . payload (=ip) . payload (=udp) .payload (=string)
				originalIPheader= rcv.payload.payload.payload
##				self.callBackResponse(originalIPheader.dst+" at "+str(originalIPheader.payload.dport), "", "OK")
				if resultsOK.has_key(ipToUse) == False:
					resultsOK[ipToUse] = [str(originalIPheader.payload.dport)]
				else:
					resultsOK[ipToUse].append(str(originalIPheader.payload.dport))
			else:
				print "KO "+rcv.payload.summary()
		
		ips=resultsOK.keys()
		ips.sort()
		for ip in ips:
			self.callBackResponse(ip+" at "+str(resultsOK[ip]), "", "OK")

class HATest (GenericTest):
	def __init__(self, baseIP, routerIP, mask, callBackResponse, useUDP):
		GenericTest.__init__(self, baseIP, routerIP, mask, callBackResponse, useUDP)
		self.PrintIPSRC=False
	def prepareContext(self):
		self.poisonFirewallARPCache()
		print commands.getstatusoutput("route add default gw 172.16.1.254") #comme les ip du requetes sont dehors le reseau, il demandera toujours le GW
		print commands.getstatusoutput("arp -s 172.16.1.254 "+lanMAC) #mais le GW est faux, c'est le MAC de l'autre interface (internet)
#START SOCKETS in INTERNET INTERFACE
		f=open("/tmp/honeyd.conf",'w')
		f.write(honeydConf)
		f.close()
		print commands.getstatusoutput("honeyd -f /tmp/honeyd.conf "+self.routerIP+ " -i "+internetInterface)

	def doTest(self):
##srp(Ether(src="00:0A:5E:5E:53:8B", dst="00:12:79:5C:11:78")/IP(dst="192.168.1.254", src="192.168.1.0/24")/ICMP(), iface="eth0", timeout=1)  
		a,u=srp(Ether(src=lanMAC, dst=internetMAC)/IP(dst=self.routerIP, src=self.baseNetwork)/self.layer4, iface=lanInterface, timeout=1)  
		self.printResults(a)

class SATest (GenericTest):
	def __init__(self, baseIP, routerIP, mask, callBackResponse, useUDP):
		GenericTest.__init__(self, baseIP, routerIP, mask, callBackResponse, useUDP)
		self.PrintIPSRC=True
	def prepareContext(self):
		self.poisonFirewallARPCache()
		print commands.getstatusoutput("route add default gw 10.0.0.254") #comme les ip du requetes sont dehors le reseau, il demandera toujours le GW
		print commands.getstatusoutput("arp -s 10.0.0.254 "+internetMAC) #mais le GW est faux, c'est le MAC de l'autre interface (internet)
#START SOCKETS in LAN INTERFACE
		f=open("/tmp/honeyd.conf",'w')
		honeydConfSA = honeydConf
		honeydConfSA+="\n bind "+self.routerIP+" to "+lanInterface
		f.write(honeydConfSA)
		f.close()
		print commands.getstatusoutput("honeyd -f /tmp/honeyd.conf "+self.baseNetwork+ " -i "+lanInterface)

	def doTest(self):
##ssrp(Ether(src="00:12:79:5C:11:78",dst="00:0A:5E:5E:53:8B")/IP(dst="192.168.1.0/24", src="192.168.1.254")/ICMP(), iface="eth1", timeout=1)  
		a,u=srp(Ether(src=internetMAC, dst=lanMAC)/IP(dst=self.baseNetwork, src=self.routerIP)/self.layer4, iface=internetInterface, timeout=1)  
		self.printResults(a)
		
class FireTester_Selection_Impl(FireTester_Selection):
	def __init__(self,parent = None,name = None,fl = 0):
	    FireTester_Selection.__init__(self,parent,name,fl)
	    self.okImage = QPixmap("good.png")
	    self.koImage = QPixmap("error.png")
	    QObject.connect(self.StartButton,SIGNAL("clicked()"), self.StartTest)
	def StartTest(self): 
		baseIP = self.InputBaseIP.text().latin1()
		mask = self.InputMask.text().latin1()
		routerIP = self.InputRouterIP.text().latin1()
		self.tabs.setCurrentPage(1)
		if (self.HATest.isChecked()):
			print "HATest"
			self.resultList.clear()
			self.resultList.insertItem("Starting Hosts Allowed test. Wait some seconds");
			t=HATest(baseIP,routerIP,mask,self.callBackResponse, self.UDPSelect.isChecked())
			t.start()
		elif (self.SATest.isChecked()):
			print "SATest"
			self.resultList.clear()
			self.resultList.insertItem("Starting Servers Accesible test. Wait some seconds");
			t=SATest(baseIP,routerIP,mask,self.callBackResponse, self.UDPSelect.isChecked())
			t.start()	
	def callBackResponse(self, msg, dump, statusIndicator):
		if (statusIndicator == "OK"):
			self.resultList.insertItem(self.okImage, msg + "::"+ dump)		
		elif (statusIndicator == "KO"):		
			self.resultList.insertItem(self.koImage, msg +"::"+ dump)
		self.resultList.update()
if __name__ == "__main__":
	a = QApplication(sys.argv)
	QObject.connect(a,SIGNAL("lastWindowClosed()"),a,SLOT("quit()"))
	win = FireTester_Selection_Impl()
	a.setMainWidget(win) 
	win.show()
	a.exec_loop()
	commands.getstatusoutput("killall -9 honeyd");
	commands.getstatusoutput("killall -9 arpd");
	print "Hemos acabado"
	

##:::::::::Test Hosts Autorises:::::::::::
##src N IP LAN
##dst 1 IP Internet
##LocalNet=>	eth0: 12.1.1.1 (emulates 192.168.1.0/24 except .252, .253, .254 and .255)
##Internet=>	eth1: 192.168.1.254/30
##
##ifconfig eth1 192.168.1.254/30
##route add default gw 192.168.1.253
##arp -s 192.168.1.253 00:0A:5E:5E:53:8B
##(demarrer sockets)
##srp(Ether(src="00:0A:5E:5E:53:8B", dst="00:12:79:5C:11:78")/IP(dst="192.168.1.254", src="192.168.1.0/24")/ICMP(), iface="eth0", timeout=1)  

##::::::::: Test Serveurs Accesibles:::::::::::
##src 1 IP Internet
##dst N IP LAN
##LocalNet=>	eth0: 12.1.1.1 (emulates ALL 192.168.1.0/24 except .254)
##Internet=>	eth1: 172.16.1.1 (emulates 192.168.1.254)
##
##arpd 192.168.1.0/24 -i eth0
##honeyd -f honeyd.conf 192.168.1.0/24 -i eth0
##
##ifconfig eth0 12.1.1.1
##route add default gw 12.1.1.254
##arp -s 12.1.1.254 00:12:79:5C:11:78
##srp(Ether(src="00:12:79:5C:11:78",dst="00:0A:5E:5E:53:8B")/IP(dst="192.168.1.0/24", src="192.168.1.254")/ICMP(), iface="eth1", timeout=1)  
