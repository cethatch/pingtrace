# PingTrace  

**Author:** Christine Thatcher  
**Course:** CS372 – Intro to Networking  
**Date:** March 11, 2025  

PingTrace is a Python-based tool that implements core functionality of the `ping` and `traceroute` utilities using raw sockets and custom ICMP packet handling. The program constructs, sends, and validates ICMP Echo Requests and Echo Replies, while also supporting hop-by-hop route discovery with increasing TTL values.  

## Features  
- **Ping Functionality:**  
  Sends ICMP Echo Requests to a specified host, collects round-trip times (RTT), and reports packet loss and statistics.  

- **Traceroute Functionality:**  
  Sends ICMP Echo Requests with incrementally increasing TTL values to trace the path packets take to the target host. Provides descriptions of ICMP error messages when encountered.  

- **ICMP Error Handling:**  
  Supports parsing and printing of ICMP error codes such as *Destination Unreachable* and *Time Exceeded*.  

- **RTT Metrics:**  
  Calculates minimum, maximum, and average RTTs in milliseconds, as well as packet loss rate.  

- **Validation of Replies:**  
  Verifies identifiers, sequence numbers, and payload data for received ICMP Echo Replies to ensure response integrity.  

## Implementation Overview  
The program is built around the following classes:  
- **IcmpHelperLibrary:**  
  The main interface, responsible for sending pings, performing traceroute, managing RTT calculations, and reporting statistics.  

- **IcmpPacket:**  
  Handles construction of ICMP packets, including header fields, checksums, data encoding, and sending packets via raw sockets.  

- **IcmpPacket_EchoReply:**  
  Parses and validates received ICMP Echo Reply packets against the original request, printing results to the console.  

## Usage  

### Prerequisites  
- Python 3  
- Administrator/root privileges (required for raw sockets)  

### Running the Program  
The program accepts two command-line arguments:  

```bash
python3 IcmpHelperLibrary.py ping <hostname>
python3 IcmpHelperLibrary.py traceroute <hostname>
