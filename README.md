```ruby
▄▄▄▄▄▄ ▄▄▄▄   ▄▄▄  ▄▄▄▄▄ ▄▄▄▄▄ ▄▄  ▄▄▄▄    ▄▄▄  ▄▄  ▄▄  ▄▄▄  ▄▄  ▄▄ ▄▄ ▄▄▄▄▄ ▄▄▄▄▄ ▄▄▄▄  
  ██   ██▄█▄ ██▀██ ██▄▄  ██▄▄  ██ ██▀▀▀   ██▀██ ███▄██ ██▀██ ██  ▀███▀   ▄█▀ ██▄▄  ██▄█▄ 
  ██   ██ ██ ██▀██ ██    ██    ██ ▀████   ██▀██ ██ ▀██ ██▀██ ██▄▄▄ █   ▄██▄▄ ██▄▄▄ ██ ██ 
                                                                                         
```

>A high-performance CLI network analyzer built with libpcap for raw packet capture and FTXUI for a fully interactive terminal UI.
The application captures packets directly from a network interface, parses protocol headers manually, aggregates statistics in real time

---
![Preview](example.png)

> [!IMPORTANT]
> Packet capture requires elevated privileges.

Run with:

```bash
sudo ./network-traffic-analyzer
```

Or grant capabilities:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./network-traffic-analyzer
```

---

# Features
1) ## Live Packet Capture
- Capture traffic from a selected network interface
- Support for BPF filters (e.g. tcp, port 80, udp)
- Real-time processing using libpcap

2) ## Real-Time Statistics Engine
- Total packets & traffic volume
- Transport protocol distribution (TCP / UDP / ICMP)
- Application-level classification (port-based)
- Top IP addresses
- Top source > destination pairs

3) ## Flexible Capture Modes
- Live capture from selected network interface (-i, --interface)
- Offline analysis from .pcap file (-r, --offline)
- Packet count limit (-c)
- Time limit for capture (-t)
- Interface discovery (--interfaces) 

> [!TIP]
> For the complete list of CLI options, use:
> `--help`

# Technologies
- C++20+
- Boost::program_options
- libpcap
- FTXUI
- CMake

# Usage Example

### Live capture on eth0
```
sudo ./network-traffic-analyzer -i eth0
```
### Filter DNS traffic
```
sudo ./network-traffic-analyzer -i any --filter proto:dns
```
### Capture 100 packets
```
sudo ./network-traffic-analyzer -i wlan0 -c 100
```
### Analyze offline pcap file
```
sudo ./network-traffic-analyzer --offline traffic.pcap
```
### Export results
```
sudo ./network-traffic-analyzer --json result.json

```
