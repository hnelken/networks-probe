# networks-probe
Written by Harry Nelken (hrn10@case.edu)

EECS 325 - Networks
Project 2

Measures RTT and estimates number of hops to a list of destinations.
 - Requires root access to send ICMP messages using raw sockets
 - Reads destinations from 'targets.txt'
 
Usage:
```
sudo python distMeasurement.py
```
