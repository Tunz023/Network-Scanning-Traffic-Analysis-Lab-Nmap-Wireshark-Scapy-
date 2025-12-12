# Network-Scanning-Traffic-Analysis-Lab-Nmap-Wireshark-Scapy-
This repository documents my Ethical Hacking lab, covering Nmap host discovery, OS detection, and service enumeration; SMB enumeration via Nmap scripts; packet capture and analysis with tcpdump/Wireshark; and interactive packet crafting, sniffing, and filtering using Scapy, all in a controlled lab environment.

Author: Motunrayo Lawal
Course: Ethical Hacking – ParoCyber Training Network
Lab Environment: Internal isolated subnet 10.6.6.0/24

# Practical Assignment – Nmap & Scapy Lab

This repository contains my completed lab work for the Ethical Hacking practical assignment.  
It documents **Nmap network scanning**, **Scapy packet crafting and sniffing**, and **packet capture/analysis using tcpdump and Wireshark**

---

## Objective

The lab focused on reproducing Nmap and Scapy exercises from class.  
Skills covered include:  
- Host discovery  
- Port & service enumeration  
- OS fingerprinting  
- SMB share enumeration  
- Packet sniffing & protocol analysis  
- Packet capture & traffic inspection

---

## Lab Environment

| Component | Value |
|-----------|-------|
| OS | Kali Linux |
| Network Range | 10.6.6.0/24 |
| Target Host | 10.6.6.23 |
| Interface | br-internal (eth0) |
| Lab | ParoCyber Internal Training Network |
| Tools | Nmap, Scapy, Wireshark, tcpdump |

---

## 🔍 Nmap Lab Documentation

### 1. Nmap Version Verification
```bash
nmap -v
```
Result: Nmap version 7.94 
*This was done to discover the version of the nmap in use.*
https://screenshots/nmap_version_check.png

### 2. Host Discovery (Ping Sweep)
```bash
nmap -sn 10.6.6.0/24
```
**Discovered Hosts:**
- 10.6.6.1 (Gateway)
- 10.6.6.11
- 10.6.6.12
- 10.6.6.13
- 10.6.6.14
- **10.6.6.23 (Target Host)**
- 10.6.6.100

This was performed to know the number of host(s) that are available for use.
View Screenshot (./screenshots/)

### 3. OS Detection & Port Enumeration on Target Host
```bash
sudo nmap -O 10.6.6.23
```
**Findings:**

*OS Detected*: Linux

*Open Ports*

| Port | Protocol | Service      |
| ---- | -------- | ------------ |
| 21   | TCP      | FTP          |
| 22   | TCP      | SSH          |
| 53   | TCP      | DNS          |
| 80   | TCP      | HTTP         |
| 139  | TCP      | NetBIOS-SSN  |
| 445  | TCP      | Microsoft-DS |

*This was run to discover the open ports on the target system*

### 4. Aggressive Service Scanning
**FTP Service Enumeration:**

```bash
nmap -p21 -sV -A -T4 10.6.6.23
```
*This command is used to find...*

**SMB Service Enumeration:**

```bash
nmap -p139,445 -sV 10.6.6.23
```
https://screenshots/service_scan.png

*his command is used to find...*

### 5. SMB Share Enumeration
```bash
nmap --script smb-enum-shares.nse -p445 10.6.6.23
```
Purpose: Identify shared folders, permissions, and anonymous access possibilities.
*An Anonymous access with Read, Write permission was detected.*

https://screenshots/smb_enumeration.png

## 🔍 WireShark Lab Documentation

### 6. Packet Capture with Wireshark/tcpdump
System Configuration Checks:

```bash
pwd               # Confirm working directory
ifconfig          # Verify IP address and interface details
cat /etc/resolv.conf   # Check DNS configuration
ip route          # View routing information
```
Screenshot

Capture Packet Traffic:

```bash
sudo tcpdump -i eth0 -s 0 -w motunrayo.pcap
```

*The command is used to capture all the packets passing through the interface durong the scan. And it was saved to Motunrayo.pcap. Pcap is the extention file
After running the command, I browsed on the internet for few seconds then went back to stop the capture*

*Stop Capture:*
```bash
Ctrl + c
```
*Verify file:*
```bash
ls motunrayo.pcap
```

**Traffic Generation During Capture:**
```bash
wireshark
```
Result:
https://screenshots/packet_capture.png

## 🔍 Scapy Lab Documentation
###  Scapy Packet Manipulation & Analysis
**Launch Scapy Environment (Basic Command):**
```bash
sudo su        # Run as privileged user
man scapy      # View Scapy manual
scapy          # Enter the Scapy interactive environment
```

*Inside Scapy:*
```bash
ls()           # List all available protocols
ls(IP)         # View IP packet header fields
```
https://screenshots/scapy_interface.png

### Sniffing Traffic (Like Wireshark)
**1. Start a basic packet capture**
```bash
sniff()         
```

**2. Generate traffic from another terminal**
```bash
ping google.com
ping -c 4 google.com   # Ping with 4 packets     
```

*Stop Sniff & Ping*
```bash
Ctrl + C 
```

**4. Store and summarize captured packets**
```bash
paro = _              # Store captured packets
paro.summary()        # Display packet summary    
```


### Sniffing on a Specific Network Interface

**1. Start capture on a chosen interface**
```bash
sniff(iface="br-internal")
```

**2. Generate interface specific traffic**
```bash
ping 10.6.6.1
# or open a webpage on the network
http://10.6.6.23

```

**3. Stop the sniff and save the results**
```bash
paro2 = _
paro2.summary()
```
________________________________________
### ICMP Filtered Sniffing
**1. Capture only ICMP packets**
```bash
sniff(iface="br-internal", filter="icmp", count=3)
```
**2. Trigger ICMP traffic**
```bash
ping 10.6.6.23
Stop both the ping and the sniff with Ctrl + C.
```
**3. Store and inspect captured ICMP packets**
```bash
paro3 = _
paro3.summary()
```
**4. Inspect a specific packet**
```bash
paro3[3]
```







