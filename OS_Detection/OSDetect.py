#!/usr/bin/env python2
# -*- coding: utf-8 -*-   
"""======================================================================"""
"""IDE used: Spyder
   Python 2.7.14 on Anaconda2
   In Scapy v2 use from scapy.all import * instead of from scapy import *.
   """
#============================================================================
"""
Created on Friday April 6 20:18:57 2018

Due Date: Tuesday May 15 23:59 2018

@author: Alem Haddush Fitwi
Email:afitwi1@binghamton.edu
Hardware-Based Security - EECE658
Department of Electrical & Computer Engineering
Watson Graduate School of Engineering & Applied Science
The State University of New York @ Binghamton
"""
#============================================================================
"""
Project 4: Live Network Scan and OS Detection
"""
#============================================================================
#----------------------------------------------------------------------------
"""
Step_1: Importing Required Packages or modules:
    Importing the logging module to suppress all messages that have lower 
    level of severity as compared to error messages. This is mainly to 
    suppress the messages that apper every time we open Scapy
"""
#----------------------------------------------------------------------------
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)
try:
    from scapy.all import *
except ImportError:
    print ("Scapy package for Python is not installed on your system.")
    print ("Get it from https://pypi.python.org/pypi/scapy and try again.")
    sys.exit() 
#============================================================================
#----------------------------------------------------------------------------
"""
Step_2: Define the targets IP & Port addresses, and the exit interface of 
        the host on which this python script will be running.
"""
#----------------------------------------------------------------------------
# You can define as many IP Addresses of Target hosts as you want
targets = ['149.125.24.35', '149.125.24.36', '149.125.24.37']
#You can define the target port numbers or services below
ports = [80,50743, 111, 135, 22, 59178] #specified ports
#Define the exit interface of the host that runs this script
interface = "wlan0" #please check your working interface first 
#============================================================================
#----------------------------------------------------------------------------
"""
Step_3: Define a method called "scanICMP":      
"""
#----------------------------------------------------------------------------
def scanICMP():
    """It checks network hosts by sending an ICMP echo, analyze the 
       reply of the target hosts, and extract the TTL and Window Size 
       in order to determine the type of OS they are running.
    """
    for target in targets:
        ping_reply = srp1(Ether() / IP(dst = target) / ICMP(), 
                          timeout = 5, iface = interface, verbose = 0)
        if str(type(ping_reply)) == "<type 'NoneType'>" or ping_reply.getlayer(ICMP).type == "3":
            print ("\n---> Host with IP %s is down or unreachable."
                       % target)           
        else:
            print ("\n\n---> Host with IP %s and MAC address %s is up."
                        % (target, ping_reply[Ether].src))
            print ("\nTCP Ports:\n")
            open_ports = scanTCP(target, ports)
            if len(open_ports) > 0:
                pkt = sr1(IP(dst = target) / TCP(dport = open_ports[0], 
                            flags = "S"), timeout = 2, iface = interface, 
                              verbose = 0)
                ttl = str(pkt[IP].ttl)
                window = str(pkt[TCP].window)
                if ttl == "64" and window == "5720":
                    print("Detected OS type is Chrome OS/Android.\n")
                elif ttl=="255" and window == "4128":
                    print("Detected OS type is Cisco IOS 12.4.\n")
                elif ttl=="64" and window == "65535":
                    print("Detected OS type is FreeBSD.\n")
                elif ttl == "64" and window == "5840":
                    print("Detected OS type is Linux Kernel 2.x.\n")
                elif ttl == "64" and window == "14600":
                    print("Detected OS type is Linux Kernel 3.x.\n")
                elif ttl == "64" and window == "65535":
                    print("Detected OS type is MAC OS.\n")
                elif ttl == "128" and window == "16384":
                    print("Detected OS type is Windows 2000.\n")
                elif ttl == "128" and window == "8192":
                    print("Detected OS type is Windows 7.\n")
                elif ttl == "128" and window == "65535":
                    print("Detected OS type is Windows XP.\n")
            else:
                print("Cannot detect host OS --> no open ports found.")
#============================================================================
#----------------------------------------------------------------------------
"""
Step_4: Define a method called "scanTCP":      
"""
#----------------------------------------------------------------------------
def scanTCP(target, port):
    """It scans for opened ports and services by sending a SYN pkt
       Input@rgument: target, and port
       Output:open_ports
    """
    open_ports = [] #list of ports
    ans, unans = sr(IP(dst = target) / TCP(sport = RandShort(), 
                       dport = port, flags = "S"), timeout = 5, 
                       iface = interface, verbose = 0)
    for sent, received in ans: #Handles answered packets
        if received.haslayer(TCP) and str(received[TCP].flags) == "18":
            print str(sent[TCP].dport) + " is OPEN!" #syn pkt
            open_ports.append(int(sent[TCP].dport))
        elif received.haslayer(TCP) and str(received[TCP].flags) == "20":
            print str(sent[TCP].dport) + " is closed!" #reset
        elif received.haslayer(ICMP) and str(received[ICMP].type) == "3":
            print str(sent[TCP].dport) + " is filtered!" #unreachable
    for sent in unans:#handles unanswered packets
        print str(sent[TCP].dport) + " is filtered!"
    return open_ports
#============================================================================
#----------------------------------------------------------------------------
"""
Step_5: Call the  "scanICMP" method to perform scanning:      
"""
#----------------------------------------------------------------------------
scanICMP()
#============================================================================
#----------------------------------------------------------------------------
""" ~~~~~~~~~~~~~~~~~~~~~~~~~~~~End of Program ~~~~~~~~~~~~~~~~~~~~~~~~~~~"""
#============================================================================
