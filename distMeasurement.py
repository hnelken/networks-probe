# Harry Nelken (hrn10)
# EECS 325 - Project 2

import socket, select, sys
from struct import *
from timeit import default_timer as timer

# Prepare to open sockets
src_ip = '172.20.120.99'
port = 33434
max_hops = 30
icmp = socket.getprotobyname('icmp')
udp = socket.getprotobyname('udp')
init_ttl = 32

# Read targets.txt
with open('targets.txt', 'r') as targets:
    for target in targets:
        failures = 3
        while failures > 0:
            target = ''.join(target.split())
       
            # Get destination IP of target
            dst_ip = socket.gethostbyname(target)

            print "Measuring distance to target: {0} ( {1} )".format(target, dst_ip)    
        
            # Create receiving and sending sockets
            recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
            send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, init_ttl)
            recv_socket.bind(("", port))

            # Begin RTT measurement
            start_time = timer()

            # Send ICMP Echo request
            send_socket.sendto("", (target, port))
            
            # Perform select on recv socket to recover from blocking
            read_ready, _, _ = select.select([recv_socket], [], [], 1)
            if len(read_ready) > 0:
                try:
                    """ 
                    IP Header Unpacking adapted from 
                    
                    http://www.binarytides.com/python-packet-sniffer-code-linux/
                    
                    """
                    
                    # Read responses
                    packet, curr_addr = recv_socket.recvfrom(65565)

                    # Stop RTT measurement
                    end_time = timer()

                    # Get return address
                    curr_addr = curr_addr[0]

                    # Inspect TTL in IP headers
                    ip_header = packet[0:20]
                    iph = unpack('!BBHHHBBH4s4s' , ip_header)
                    ttl = iph[5]
                   
                    try:
                        curr_name = socket.gethostbyaddr(curr_addr)[0]
                    except socket.error:
                        curr_name = curr_addr
                    
                    print "   Hostname:", curr_name
                    print "   RTT:", (end_time - start_time) * 1000, "ms"
                    print "   Dist:", (64 - ttl), "hops"

                except socket.error:
                    pass
                finally:
                    send_socket.close()
                    recv_socket.close()
                    failures = 0
            else:
                failures -= 1
                print "   FAILURE:", (3 - failures), " of 3"
                if failures > 0:
                    print "   - Retrying..."
                else:
                    print "   - Exceeded failure limit, measurement abandoned"

