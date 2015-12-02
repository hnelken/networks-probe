# Harry Nelken (hrn10)
# EECS 325 - Project 2

import os, socket, select, sys, struct
from struct import *
from timeit import default_timer as timer

# Socket preparation info
src_ip = '172.20.120.99'
port = 33434
max_hops = 32
max_failures = 3
timeout = 2

"""
Reads the list of targets and measures RTT and hop count to each destination
"""
def main():
    print ""
    # Read targets.txt
    with open('targets.txt', 'r') as targets:
        for target in targets:
            failures = max_failures
            while failures > 0:
                # Clean whitespace
                target = ''.join(target.split())
       
                # Get destination IP of target
                dst_ip = socket.gethostbyname(target)
            
                print "", "Measuring distance to target:", target, "(", dst_ip, ")"    
        
                # Create receiving and sending sockets
                icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

                # Make ICMP Echo Request packet
                packet_id = os.getpid() & 0xFFFF
                packet = make_packet(dst_ip, packet_id)
            
                # Begin RTT measurement
                send_time = timer()

                # Send ICMP Echo Request
                icmp_socket.sendto(packet, (dst_ip, port))
                
                # Receive ICMP Echo Reply
                result = receive_echo(icmp_socket, packet_id, send_time)
                
                # Interpret results
                if result == None:
                    failures = fail(failures)
                else:
                    print_results(result[0], result[1])
                    failures = 0

    print "Measurements complete.\n"

"""
Receives echo replies from the socket used to send the requests
"""
def receive_echo(icmp_socket, packet_id, send_time):
    """
    REPLY PARSING ADAPTED FROM:

    http://www.g-loaded.eu/2009/10/30/python-ping/
    """
    
    time_left = timeout

    while True:
        sel_start_time = timer()
        readyLists = select.select([icmp_socket], [], [], time_left)
        select_delay  = (timer() - sel_start_time) * 1000

        # Check for timeout
        if readyLists[0] == []:
            return

        # Stop RTT timer
        recv_time = timer()
            
        # Read from socket
        response, addr = icmp_socket.recvfrom(1024)
            
        # Parse response contents
        ip_header = struct.unpack("!BBHHHBBH4s4s", response[0:20])

        icmp_header = struct.unpack("bbHHh", response[20:28])
        return_id = icmp_header[3]

        # Check identifier to authenticate packet
        if return_id == packet_id:
            bytesInDouble = struct.calcsize("d")
            timeSent = struct.unpack("d", response[28:28 + bytesInDouble])[0]
            return (recv_time - send_time) * 1000, ip_header[5]

        # Check for timeout again
        timeLeft = timeLeft - select_delay
        if timeLeft <= 0:
            return
 
"""
Makes an ICMP Echo Request packet
"""
def make_packet(dst_ip, packet_id):
    """
    ICMP HEADER CONSTRUCTION ADOPTED FROM:

    http://www.g-loaded.eu/2009/10/30/python-ping/
    """
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    checksum = 0
                  
    # Make a dummy header with a 0 checksum.
    header = struct.pack("bbHHh", 8, 0, checksum, packet_id, 1)
    bytesInDouble = struct.calcsize("d")
    data = (192 - bytesInDouble) * "Q"
    data = struct.pack("d", timer()) + data
                                       
    # Calculate the checksum on the data and the dummy header.
    checksum = get_checksum(header + data)
                                                
    # Make a new header than with the new checksum.
    header = struct.pack("bbHHh", 8, 0, socket.htons(checksum), packet_id, 1)
    
    # Put together the packet
    packet = header + data

    return packet

"""
Calculates the checksum for a given packet
"""
def get_checksum(source_string):
    """
    CHECKSUM FUNCTION ADOPTED FROM:
    
    http://www.g-loaded.eu/2009/10/30/python-ping/
    """
    sum = 0
    countTo = (len(source_string)/2)*2
    count = 0
    while count<countTo:
        thisVal = ord(source_string[count + 1])*256 + ord(source_string[count])
        sum = sum + thisVal
        sum = sum & 0xffffffff
        count = count + 2
                                                                             
    if countTo<len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff 
                                                                                                      
    sum = (sum >> 16)  +  (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff

    answer = answer >> 8 | (answer << 8 & 0xff00)
                                                                                                                                
    return answer
    
"""
Handles a probe failure
"""
def fail(failures):
    failures -= 1
    print "   FAILURE:", (max_failures - failures), "of", max_failures
    if failures > 0:
        print "   - Retrying..."
    else:
        print "   - Exceeded failure limit, measurement abandoned"
    return failures

"""
Prints the results of a successful probe
"""
def print_results(rtt, ttl):
    init_ttl = 0
    if ttl > 64:
        if ttl > 128:
            init_ttl = 255
        else:
            init_ttl = 128
    else:
        init_ttl = 64

    print "    RTT:", rtt, "ms"
    print "    Dist:", (init_ttl - ttl), "hops"
    print ""

if __name__ == '__main__': main()
