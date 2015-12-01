# Harry Nelken (hrn10)
# EECS 325 - Project 2

import os, socket, select, sys, struct
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
    timeout = 2

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
                    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            
                    # Begin RTT measurement
                    send_time = timer()

                    packet_id = os.getpid() & 0xFFFF
                    packet = self.get_packet(target, packet_id)

                    # Send ICMP Echo request
                    icmp_socket.sendto(packet, (dst_ip, self.port))
                    
                    delay = self.receive(icmp_socket, packet_id, send_time)
                    print "FINISHED:", delay
                    failures = 0
                    """
                    # Perform select on recv socket to recover from blocking
                    read_ready, _, _ = select.select([icmp_socket], [], [], 2)
                    if len(read_ready) > 0:
                        try:
                             
                            IP Header Unpacking adapted from 
                    
                            http://www.binarytides.com/python-packet-sniffer-code-linux/
                    
                            
                    
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
                    """

    def checksum(self, source_string):
        """
        I'm not too confident that this is right but testing seems
        to suggest that it gives the same answers as in_cksum in ping.c
        """
        sum = 0
        countTo = (len(source_string)/2)*2
        count = 0
        while count<countTo:
            thisVal = ord(source_string[count + 1])*256 + ord(source_string[count])
            sum = sum + thisVal
            sum = sum & 0xffffffff # Necessary?
            count = count + 2
                                                                             
        if countTo<len(source_string):
            sum = sum + ord(source_string[len(source_string) - 1])
            sum = sum & 0xffffffff # Necessary?
                                                                                                      
        sum = (sum >> 16)  +  (sum & 0xffff)
        sum = sum + (sum >> 16)
        answer = ~sum
        answer = answer & 0xffff
                                                                                                                       
        # Swap bytes. Bugger me if I know why.
        answer = answer >> 8 | (answer << 8 & 0xff00)
                                                                                                                                
        return answer
    
    def receive(self, icmp_socket, ID, send_time):
        time_left = self.timeout

        while True:
            sel_start_time = timer()
            readyLists = select.select([icmp_socket], [], [], time_left)
            select_delay  = (timer() - sel_start_time) * 1000
            if readyLists[0] == []:
                return

            recv_time = timer()
            
            response, addr = icmp_socket.recvfrom(1024)
            
            ip_header = struct.unpack("!BBHHHBBH4s4s", response[0:20])
            print "TTL:", ip_header[5]

            icmp_header = struct.unpack("bbHHh", response[20:28])
            packetID = icmp_header[3]
            print "ICMP:", icmp_header
            if packetID == ID:
                bytesInDouble = struct.calcsize("d")
                timeSent = struct.unpack("d", response[28:28 + bytesInDouble])[0]
                return (recv_time - send_time) * 1000
                                                 
            timeLeft = timeLeft - select_delay
            if timeLeft <= 0:
                return
            

    def get_packet(self, dest_addr, ID):
        dest_addr  =  socket.gethostbyname(dest_addr)
        
        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        my_checksum = 0
                  
        # Make a dummy header with a 0 checksum.
        header = struct.pack("bbHHh", 8, 0, my_checksum, ID, 1)
        bytesInDouble = struct.calcsize("d")
        data = (192 - bytesInDouble) * "Q"
        data = struct.pack("d", timer()) + data
                                       
        # Calculate the checksum on the data and the dummy header.
        my_checksum = self.checksum(header + data)
                                                
        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy.
        header = struct.pack(
            "bbHHh", 8, 0, socket.htons(my_checksum), ID, 1)
        packet = header + data
        return packet
       #my_socket.sendto(packet, (dest_addr, 1)) # Don't know about the 1

    def inspect_packet(self, packet, curr_addr, send_time, recv_time):
        # Inspect TTL in IP headers
        ip_raw = packet[0:20]
        ip_header = unpack('!BBHHHBBH4s4s', ip_raw)

        icmp_raw = packet[20:28]
        icmp_header = unpack('!BBHHH', icmp_raw)
    
        print "ICMP:", icmp_header
        
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
