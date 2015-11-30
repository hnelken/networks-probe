# Harry Nelken (hrn10)
# EECS 325 - Project 2

import socket, select, sys
from struct import *
from timeit import default_timer as timer

class Probe:

    # Socket preparation info
    src_ip = '172.20.120.99'
    port = 33434
    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')
    max_hops = 32
    max_failures = 3
 
    def main(self):
        # Read targets.txt
        with open('targets.txt', 'r') as targets:
            for target in targets:
                failures = self.max_failures
                while failures > 0:
                    # Clean whitespace
                    target = ''.join(target.split())
       
                    # Get destination IP of target
                    dst_ip = socket.gethostbyname(target)
            
                    print ""
                    print "", "Measuring distance to target:", target, "(", dst_ip, ")"    
        
                    # Create receiving and sending sockets
                    recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, self.icmp)
                    send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, self.udp)
            
                    # Configure the sockets
                    send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, self.max_hops)
                    recv_socket.bind(("", self.port))

                    # Begin RTT measurement
                    send_time = timer()

                    # Send ICMP Echo request
                    send_socket.sendto("", (target, self.port))
            
                    # Perform select on recv socket to recover from blocking
                    read_ready, _, _ = select.select([recv_socket], [], [], 1)
                    if len(read_ready) > 0:
                        try:
                            """ 
                            IP Header Unpacking adapted from 
                    
                            http://www.binarytides.com/python-packet-sniffer-code-linux/
                    
                            """
                    
                            # Read responses
                            packet, curr_addr = recv_socket.recvfrom(2048)

                            # Stop RTT measurement
                            recv_time = timer()

                            # Get return address
                            curr_addr = curr_addr[0]

                            if curr_addr == dst_ip:
                                self.inspect_packet(packet, curr_addr, send_time, recv_time)
                                failures = 0
                            else:
                                failures = self.fail(failures)
                        except socket.error:
                            failures = self.fail(failures)
                        finally:
                            send_socket.close()
                            recv_socket.close()
                    else:
                        failures = self.fail(failures)


    def inspect_packet(self, packet, curr_addr, send_time, recv_time):
        # Inspect TTL in IP headers
        ip_raw = packet[0:20]
        ip_header = unpack('!BBHHHBBH4s4s', ip_raw)

        ttl = ip_header[5]
        init_ttl = 0

        # Estimate initial TTL value of ICMP Echo reply
        if ttl > 64:
            if ttl > 128:
                init_ttl = 255  # Very common initial value
            else:
                init_ttl = 128  # Windows initial value
        else:
            init_ttl = 64   # Very common initial value

        try:
            curr_name = socket.gethostbyaddr(curr_addr)[0]
        except socket.error:
            curr_name = curr_addr
                    
        rtt = (recv_time - send_time) * 1000
        hops = (init_ttl - ttl)

        print "   Hostname:", curr_name
        print "   RTT:", rtt, "ms"
        print "   Dist:", hops, "hops"


    def fail(self, failures):
        failures -= 1
        print "   FAILURE:", (self.max_failures - failures), "of", self.max_failures
        if failures > 0:
            print "   - Retrying..."
        else:
            print "   - Exceeded failure limit, measurement abandoned"
        return failures


if __name__ == '__main__': Probe.main(Probe())
