# Advanced Packet Analyzer (APA)

An advanced **Packet Analyzer** written in C that processes **PCAP files** to analyze network traffic in great detail. This tool provides comprehensive information about captured network packets, including Ethernet, IP, TCP, UDP, ICMP, and ARP headers. It is designed for network professionals who need to deeply inspect network traffic captured in PCAP files.

## Features

- **Ethernet Header Parsing**: Extracts MAC addresses and Ethernet type.
- **IP Header Parsing**: Handles IPv4 and IPv6, extracting source/destination IPs, protocol type (TCP, UDP, ICMP, etc.), and more.
- **TCP Header Parsing**: Displays details about source/destination ports, sequence/acknowledgment numbers, flags, window size, and checksum.
- **UDP Header Parsing**: Shows source/destination ports, length, and checksum.
- **ICMP Header Parsing**: Extracts ICMP type, code, checksum, and additional parameters.
- **ARP Header Parsing**: Recognizes ARP requests/replies and extracts sender/target MAC/IP addresses.
- **Comprehensive Packet Information**: Displays timestamp, packet length, and protocol details.
- **Cross-Platform**: Should work on Linux, macOS, and Windows (with minor adjustments for Windows build tools).

## Requirements

- **C Compiler**: `gcc` or compatible C compiler.
- **libpcap**: Required for reading PCAP files. Install using package managers like `apt-get` on Ubuntu or `brew` on macOS.

### Installation

To build and run the project on a Linux-based system:

1. **Install libpcap**:

```bash
sudo apt-get install libpcap-dev
```

2. **Clone the repository**:

```bash
git clone https://github.com/0xAminED/APA.git
cd APA
```
3. **Compile the code**:

```bash
gcc -o APA APA.c -lpcap
```
4. **Run the packet analyzer with a PCAP file**:

```bash
./APA your_pcap_file.pcap
```

## Example Output
```bash
Starting packet analysis...
Packet Length: 66 bytes
Captured at: Thu Sep 15 14:25:35 2022
== Ethernet Header ==
Source MAC: 00:0c:29:8c:5a:6e
Destination MAC: 00:0c:29:71:82:3d
Ethernet Type: 0x0800

== IP Header ==
Source IP: 192.168.1.1
Destination IP: 192.168.1.2
IP Version: 4
Header Length: 20 bytes
Protocol: 6 (TCP)

== TCP Header ==
Source Port: 80
Destination Port: 12345
Sequence Number: 12345678
Acknowledgment Number: 23456789
Flags: 0x18
Window Size: 8192
Checksum: 0x1234
Urgent Pointer: 0

...
```

## How it Works

1. **Ethernet Header**: The program starts by parsing the Ethernet frame, displaying source and destination MAC addresses, and the Ethernet type.
2. **IP Header**: The IP header is parsed to extract the source and destination IP addresses, IP version, protocol type (TCP, UDP, ICMP, etc.), and header length.
3. **TCP Header**: If the packet is TCP, it parses the TCP header to display useful information such as source and destination ports, sequence and acknowledgment numbers, window size, and flags.
4. **UDP Header**: For UDP packets, the program displays source and destination ports, UDP length, and checksum.
5. **ICMP Header**: If the packet is ICMP (such as a ping request/response), it parses and prints the ICMP type, code, checksum, and identifier.
6. **ARP Header**: ARP requests and replies are also handled, and the program displays sender/target MAC and IP addresses.


## Future Enhancements
- **Support for more protocols**: Add support for additional protocols such as IPv6, DNS, HTTP, etc.
- **Packet Filtering**: Allow filtering of packets by IP, protocol, ports, etc.
- **Statistics**: Provide traffic statistics, such as packet counts, byte counts, etc.
- **GUI Interface**: Develop a graphical user interface to visualize packet data and network activity.
- **Export Data**: Export packet analysis results to CSV, JSON, or other formats.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to the contributors for their valuable feedback and improvements.







