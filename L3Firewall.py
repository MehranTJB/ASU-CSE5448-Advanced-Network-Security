esfrom pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
''' New imports here ... '''
import csv
import argparse
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp

log = core.getLogger()
priority = 50000

l2config = "l2firewall.config"
l3config = "l3firewall.config"


class Firewall (EventMixin):

	def __init__ (self,l2config,l3config):
		self.listenTo(core.openflow)
                ## I converted this code into a comment
		#self.disbaled_MAC_pair = [] # Shore a tuple of MAC pair which will be installed into the flow table of each switch.
                #self.fwconfig = list()

                self.Tlogs = dict ()    # Python dictionary to keep logs of the source MAC/IP addressess and destination MAC/IP addresses.
                self.TRules = dict ()  # Python dictionary to keep logs of the new firewall rule to avoid duplications.

		'''
		Read the CSV file
		'''
		if l2config == "":
			l2config="l2firewall.config"
		if l3config == "":
			l3config="l3firewall.config" 
		with open(l2config, 'rb') as rules:
			csvreader = csv.DictReader(rules) # Map into a dictionary
			for line in csvreader:
				# Read MAC address. Convert string to Ethernet address using the EthAddr() function.
                                if line['mac_0'] != 'any':
				    mac_0 = EthAddr(line['mac_0'])
                                else:
                                    mac_0 = None

                                if line['mac_1'] != 'any':
        				mac_1 = EthAddr(line['mac_1'])
                                else:
                                    mac_1 = None
				# Append to the array storing all MAC pair.
				self.disbaled_MAC_pair.append((mac_0,mac_1))

		with open(l3config) as csvfile:
			log.debug("Reading log file !")
			self.rules = csv.DictReader(csvfile)
			for row in self.rules:
                                ## I Added this code 
      				prio = row['priority']
				s_mac = row['src_mac']
				d_mac = row['dst_mac']
                                ## ------
				s_ip = row['src_ip']
				d_ip = row['dst_ip']
				s_port = row['src_port']
				d_port = row['dst_port']
                                ## I Added this code
				nw_proto = row['nw_proto']
                                ## ------
				print "src_ip, dst_ip, src_port, dst_port", s_ip,d_ip,s_port,d_port
                                # Add to firewall rules in memory
				log.debug("Keep firewall rules in memory")
                                # I added this code
                                if s_mac != "any" and d_mac == "any" and s_ip == "any" and d_ip != "any" and s_port == "any" and d_port == "any" and nw_proto == "any":
                                    self.Tlogs [s_mac] = [s_ip, d_ip, 'any']
                                if s_mac == "any" and d_mac == "any" and s_ip != "any" and d_ip != "any" and s_port == "any" and d_port == "any" and nw_proto == "any":
                                    self.Tlogs [s_mac] = [s_ip, d_ip, 'any']
                                ## -------

		log.debug("Enabling Firewall Module")

	def replyToARP(self, packet, match, event):
		r = arp()
		r.opcode = arp.REPLY
		r.hwdst = match.dl_src
		r.protosrc = match.nw_dst
		r.protodst = match.nw_src
		r.hwsrc = match.dl_dst
		e = ethernet(type=packet.ARP_TYPE, src = r.hwsrc, dst=r.hwdst)
		e.set_payload(r)
		msg = of.ofp_packet_out()
		msg.data = e.pack()
		msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
		msg.in_port = event.port
		event.connection.send(msg)

	def allowOther(self, event, action=None):
                log.debug ("Execute allowOther")
		msg = of.ofp_flow_mod()
		match = of.ofp_match()
		msg.actions.append(action)
		event.connection.send(msg)

	def installFlow(self, event, offset, srcmac, dstmac, srcip, dstip, sport, dport, nwproto):
                ## -------
                log.debug ("Update firewall's rules in the OVS switch - installFlow")
                ## ------
		msg = of.ofp_flow_mod()
		match = of.ofp_match()
		if(srcip != None):
			match.nw_src = IPAddr(srcip)
		if(dstip != None):
			match.nw_dst = IPAddr(dstip)
                if(nwproto):
                        match.nw_proto = int(nwproto)
		match.dl_src = srcmac
		match.dl_dst = dstmac
		match.tp_src = sport
		match.tp_dst = dport
		match.dl_type = pkt.ethernet.IP_TYPE
		msg.match = match
		msg.hard_timeout = 0
		msg.idle_timeout = 7200
                msg.priority = priority + offset
		event.connection.send(msg)

	def replyToIP(self, packet, match, event):
                log.debug ("Execute replyToIP")
		srcmac = str(match.dl_src)
		dstmac = str(match.dl_src)
		sport = str(match.tp_src)
		dport = str(match.tp_dst)
		nwproto = str(match.nw_proto)

                with open(l3config) as csvfile:
                    log.debug("Reading log file !")
                    self.rules = csv.DictReader(csvfile)
                    for row in self.rules:
                        prio = row['priority']
                        srcmac = row['src_mac']
                        dstmac = row['dst_mac']
                        s_ip = row['src_ip']
                        d_ip = row['dst_ip']
                        s_port = row['src_port']
                        d_port = row['dst_port']
                        nw_proto = row['nw_proto']

                        log.debug("You are in original code block ...")
                        srcmac1 = EthAddr(srcmac) if srcmac != 'any' else None
                        dstmac1 = EthAddr(dstmac) if dstmac != 'any' else None
                        s_ip1 = s_ip if s_ip != 'any' else None
                        d_ip1 = d_ip if d_ip != 'any' else None
                        s_port1 = int(s_port) if s_port != 'any' else None
                        d_port1 = int(d_port) if d_port != 'any' else None
                        prio1 = int(prio) if prio != None else priority
                        if nw_proto == "tcp":
                            nw_proto1 = pkt.ipv4.TCP_PROTOCOL
                        elif nw_proto == "icmp":
                            nw_proto1 = pkt.ipv4.ICMP_PROTOCOL
                            s_port1 = None
                            d_port1 = None
                        elif nw_proto == "udp":
                            nw_proto1 = pkt.ipv4.UDP_PROTOCOL
                        else:
                            #nw_proto1 = None
                            log.debug("PROTOCOL field is mandatory, Choose between ICMP, TCP, UDP")
                        print (prio1, srcmac1, dstmac1, s_ip1, d_ip1, s_port1, d_port1, nw_proto1)
                        self.installFlow(event, prio1, srcmac1, dstmac1, s_ip1, d_ip1, s_port1, d_port1, nw_proto1)

                self.allowOther(event)


	def _handle_ConnectionUp (self, event):
		''' Add your logic here ... '''
                # In this lab I needed to detect DoS traffic from spoofed source MAC or IP addresses.
                # To accomplish this goal I used the following algorithm to detect the source MAC or IP spoofed traffic
                # on every new incomming traffic flow.
		#
		# In order to find spoofed source MAC or IP addresses, I needed to keep track of all source MAC and IP addresses and
		# and save them for further investigations. I also needed to keep the new rules that I created during the lab to avoid
		# duplication.
		# In order to satisfy these requirements, I defined two dictionaries with the following usages:
		# Tlogs: To save all source MAC and IP addresses, destination MAC and IP adresesses.
		# TRules: To save new Firewall rules to avoid duplication.
		#
                # First part - detect spoofed source MAC addresses - BONUS POINTS
		# look for the source MAC address in the Tlogs dictionary
                # if source MAC address is not found in the Tlogs dictionary then
                #      look for the source IP address in the Tlogs dictionary
                #      if a similar source IP address is found in the Tlogs dictionary then
                #          **** Spoofed source MAC address detected   *****
		#	   Create a new rule to block it and if this rule hadn't been added to the TRules dictionary, then added it to
		#          the TRules dictionary.
		#          Append the new rule into the CSV file and resend Firewall rules to the OVS switch.
		#      else
		#          Add source MAC/IP addresses to the Tlogs dictionary for future investigations
		# Second part - detect spoofed source IP addresses
                # else source MAC address is found in the Tlogs dictionary, this traffic needs to be checked for spoofed source IP address
		#      look for the source IP address in the Tlogs dictionary
		#      if similar source IP address is found in the Tlogs dictionary then
		#         *** Spoofed source IP address detected *****
		#         Create a new rule to block it and if this rule hasn't been added to the TRules dictionary, then add it to
		#         the TRules dictionary.
		#         Append the new rule into the CSV file and resend Firewall rules to the OVS switch.
		'''
		Iterate through the disbaled_MAC_pair array, and for each
		pair we install a rule in each OpenFlow switch
		'''
		self.connection = event.connection
                ## I converted this code to comment
		#for (source, destination) in self.disbaled_MAC_pair:
                ## ------
                for spoofedMAC, spoofedIPs in self.Tlogs.items():
                        ## I addedthis code
                        srcmac = spoofedMAC
                        srcip = spoofedIPs[0]
                        dstip = spoofedIPs[1]
                        log.debug ('Retrieving firewall rules: srcmac=%s, srcip=%s, dstip=%s' %
                                (str(srcmac), str(srcip), str(dstip)))
                        ## ------

                        message = of.ofp_flow_mod()     # OpenFlow massage. Instructs a switch to install a flow
			match = of.ofp_match()          # Create a match

                        ## I added this code
                        if srcmac == 'any':
                            match.dl_src = None         # Source MAC
                        else:
                            match.dl_src = srcmac       # Source MAC
                        if srcip == 'any':
                            match.nw_src = None         # Source IP address
                        else:
                            match.nw_src = IPAddr(srcip)    # Source IP address
                        if dstip == 'any':
                            match.nw_dst = None         # Destination IP address
                        else:
                            match.nw_dst = IPAddr(dstip)    # Destination IP address
                        ## ------

                        ## I converted this code to comment
                        #match.dl_src = source # Source address
                        #match.dl_dst = destination  # Destination address
                        ## ------

                        message.priority = 65535 # Set priority (between 0 and 65535)

                        match.dl_type = ethernet.IP_TYPE
			message.match = match
			event.connection.send(message) # Send instruction to the switch

		log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

        ## I added this code
        def UpdateCSV(self, srcmac='any', srcip='any', dstip='any'):

            # In this function I review all rules that were defined previously, if the current rule wasn't saved in the past
            # then I add this rule to the firewall rule and I save the new rule to the CSV file.
            # I use AllowAdd variable to specify the type of action based on the rule's status.

            AllowAdd = True      # Initialize variable, default value allows to add current rule to the firewall
            for spoofedMAC, spoofedIPs in self.TRules.items():
                if spoofedMAC == str(srcmac) and spoofedIPs[0] == str(srcip) and spoofedIPs[1] == str(dstip):
                   # log.debug("No need to write log file - entry already present")
                    AllowAdd = False    # Duplicated rule detected.
                    break

            if AllowAdd:       # Current rule is a new one and I add this rule to the firewall.
                self.TRules [str(srcmac)] = [str(srcip), str(dstip)]
                # Open csv file in append mode and add new rule at the end of CSV file.
                # I use a large number (e.g, 10000) as the priority number because I want this rule executed with the
                # lowest priority.
                # If I want to block DoS traffic from the attacking host then I need to specify the source IP/MAC addresses in the
                # new rule, hence I want to mitigate the DDoS attack against the target host, then I specify the detination IP address
                # to block all traffic from any source to the specific IP address.
                with open(l3config, 'a') as csvfile:

                    csvwriter = csv.DictWriter(csvfile, fieldnames=[
                        'priority','src_mac','dst_mac','src_ip','dst_ip','src_port','dst_port','nw_proto',])
                    csvwriter.writerow({
                        'priority': 10000,
                        'src_mac' : str(srcmac),
                        'dst_mac' : 'any',
                        'src_ip'  : str(srcip),
                        'dst_ip'  : str(dstip),
                        'src_port': 'any',
                        'dst_port': 'any',
                        'nw_proto': 'any',
                        })
                    log.debug("Rule saved in l3firewall.config file: srcip=%s dstip=%s srcmac=%s" % (str(srcip), str(dstip), str(srcmac)))
        ## ------

        ## I added this code
        # This function is responsible for analysing incoming packets to detect spoofed IP/MAC addresses.
        # In the First Part I want to detect spoofed source MAC addresses, to do this I look up the source MAC address
        # In the Tlogs dictionary that I use to hold spoofed MAC/IP addresses. If I can't find this MAC address in the
        # Tlogs dictionary, then I need to check the source IP addresses, If I find another record with the same source IP address
        # and a different source MAC address, this means I've detected spoofed source MAC address.
        # I print out a message at the controller's console, "MAC Spoofing detected" and I create a new rule to block this flow from
        # the source IP address and any source MAC address to the specific destination IP address (h2 container host).
        # In the second Part I want to detect the spoofed source IP address, In order to do this I look up the source IP address
        # in the Tlogs dictionary that I use to hold spoofed MAC/IP addresses. If I don't find this IP address in the
        # Tlogs dictionary, then I need to check the source MAC addreses, If I find another record with the same source MAC address
        # and a different source IP address, this means I've detected a spoofed source IP address.
        # I print out a message at the controller's console, "IP Spoofing Detected" and I create a new rule to block this flow from
        # the source MAC address and any source IP addresses to the specific destination IP address (h2 container host).
        def TrafficAnalyser(self, packet, match=None, event=None):
            srcmac = None
            srcip = None
            dstip = None
            if packet.type == packet.IP_TYPE:
                ip_packet = packet.payload
                # First part - Spoofed MAC address detection
                if packet.src not in self.Tlogs:        # New MAC address, I need to check the source IP address
                    for spoofedMAC, spoofedIPs in self.Tlogs.items():
                        # Duplicate source IP address found, MAC address spoofed.
                        if str(spoofedIPs[0]) == str(ip_packet.srcip):
                            log.debug(" MAC spoofing detected @ Attacker: IP: %s - MAC: %s, Target(Victim): IP: %s, MAC: %s, Port %s ***" %
                                (str(ip_packet.srcip), str(spoofedMAC), str(spoofedIPs[1]), str(packet.src), str(event.port)))
                            # I create a rule to block flow traffic from the source and destination IP addresses with any source MAC addresses
                            # to protect the victim from the DoS attack.
                            srcmac = None
                            srcip = str(ip_packet.srcip)
                            dstip = str(ip_packet.dstip)
                            self.UpdateCSV ('any', srcip, dstip)
                    # If the combination of the source IP and MAC addresses are unique, based on the assumptions in this lab I
                    # consider this traffic legitimate, I add source IP and MAC addresses, destination IP addresses, and
                    # the switch port number to the Tlogs dictionary for future traffic investigations.
                    self.Tlog [packet.src] = [ip_packet.srcip, ip_packet.dstip, event.port]
                    log.debug("Update TSpoofed Table : src_MAC: %s, src_IP: %s, dst_IP: %s, Port: %s" %
                        (str(packet.src), str(ip_packet.srcip), str(ip_packet.dstip), str(event.port)))
                    return True
                # Second part - Spoofed IP address detected.
                else:
                    # Source MAC address already exists in the TSpoofed table. I look up the combination of source IP and MAC
                    # addrersses in the Tlogs dictionary. If I find a similar record with the same source IP and MAc address, based
                    # on the lab's asumptions I conclude the traffic is ligitimate and I write a message at the controller's console
                    # "Duplicate Entry".
                    if self.Tlog.get(packet.src) == [ip_packet.srcip, ip_packet.dstip, event.port]:
                        log.debug("Duplicate Entry: src_MAC: %s, src_IP: %s, dst_IP: %s, Port: %s" %
                            (str(packet.src), str(ip_packet.srcip), str(ip_packet.dstip), str(event.port)))
                        return True
                    else:
                        # If I find a record with the same source MAC address and different source IP address, I can conclude
                        # that the source IP address is spoofed in this traffic.
                        newip = self.Tlog.get(packet.src)[0]
                        if newip != ip_packet.srcip:
                            log.debug("IP spoofing detected @ Attacker: MAC: %s, Spoofed IP: %s,  Target(Victim): IP: %s, Port %s ***" %
                                (str(packet.src), str(newip), str(ip_packet.dstip), str(event.port)))
                            # I create a rule at the firewall with the source MAC address and destination IP address, with any source
                            # source IP addresses to protect the victim from a DoS attack.
                            srcmac = str(packet.src)
                            srcip = None
                            dstip = str(ip_packet.dstip)
                            # I call the UpdateCSV function to add a new rule based on the spoofed MAC or IP address that I detected.
                            self.UpdateCSV (srcmac, 'any', dstip)
                        return True
            srcmac = srcmac
            dstmac = None
            sport = None
            dport = None
            nwproto = str(match.nw_proto)
            # In regular cases, the firewall rules are sent to the switch when the controller is initialized.
            # In this lab we want to add new rules to the switch on the fly based on the content of the TRules dictionary,
            # then we need to recall installFlowc function to resend the latest filrewall rules from the controller to the OVS switch.
            log.debug("Reinstall the firewall rules... ")
            self.installFlow(event, 10000, srcmac, None, srcip, dstip, None, None, nw_proto)

            return False
        ## -------

        # This function on the first packet of every new traffic flow will be called.
        # I modified this function to call the TrafficAnalyser function to find suspicious traffic (DoS traffic with Spoofed-
        # source MAC or IP addressees) by examining the source MAC and IP addresses.
	def _handle_PacketIn(self, event):

		packet = event.parsed
		match = of.ofp_match.from_packet(packet)

		if(match.dl_type == packet.ARP_TYPE and match.nw_proto == arp.REQUEST):

		    self.replyToARP(packet, match, event)

		if(match.dl_type == packet.IP_TYPE):

                    if self.TrafficAnalyser(packet, match, event):
                        log.debug("-- Normal traffic --")
                    else:
                        log.debug("-- Attack detected --")

                    ## I converted this code to comment
		    #ip_packet = packet.payload
		    #if ip_packet.protocol == ip_packet.TCP_PROTOCOL:
		    #   log.debug("TCP it is !")
                    ## ------

                    ## I changed this line of code
		    self.replyToIP(packet, match, event)
                    ## --------

def launch (l2config="l2firewall.config",l3config="l3firewall.config"):
	'''
	Starting the Firewall module
	'''
	parser = argparse.ArgumentParser()
	parser.add_argument('--l2config', action='store', dest='l2config',
					help='Layer 2 config file', default='l2firewall.config')
	parser.add_argument('--l3config', action='store', dest='l3config',
					help='Layer 3 config file', default='l3firewall.config')
	core.registerNew(Firewall,l2config,l3config)

