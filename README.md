# Java Packet Analyzer and DPI Engine

This project is implemented in Java and uses only the JDK. It reads classic PCAP captures, decodes Ethernet and IPv4 packets, tracks TCP/UDP connections, classifies visible application traffic, applies blocking rules, and writes permitted packets to an output PCAP.

## Requirements

- JDK 17 or later
- Windows PowerShell for the included build script (or compile the Java sources directly with `javac`)

## Build

From the repository root:

```powershell
.\build.ps1
```

Compiled classes are written to `build\classes`.

## Run the webpage

Start the local web dashboard:

```powershell
java -cp build\classes packetanalyzer.WebMain
```

Then open [http://127.0.0.1:8765](http://127.0.0.1:8765) in your browser. Choose a PCAP file, optionally enter comma-separated source IPs, app names, or domains to block, and select **Analyze karein**. The dashboard shows packet and connection counts, application breakdown, and packet verdicts; use **Filtered PCAP download karein** to save the allowed packets. The server accepts connections only from your computer, and uploaded files are limited to 64 MB. Press `Ctrl+C` in PowerShell to stop it. An alternate port can be selected, for example `java -cp build\classes packetanalyzer.WebMain 9000`.

## Run the DPI engine

```powershell
java -cp build\classes packetanalyzer.DpiMain test_dpi.pcap filtered.pcap
```

Block traffic by source IPv4 address, application, or domain:

```powershell
java -cp build\classes packetanalyzer.DpiMain capture.pcap filtered.pcap --block-ip 192.168.1.50
java -cp build\classes packetanalyzer.DpiMain capture.pcap filtered.pcap --block-app YouTube
java -cp build\classes packetanalyzer.DpiMain capture.pcap filtered.pcap --block-domain "*.example.com"
```

Options:

| Option | Description |
| --- | --- |
| `--block-ip <ip>` | Drop packets whose source IPv4 address matches |
| `--block-app <app>` | Drop traffic classified as the named application |
| `--block-domain <domain>` | Drop traffic for the exact domain or wildcard domain |
| `--rules <file>` | Load rules from a rules file |
| `--lbs <n>` | Number of load-balancer groups (default: 2) |
| `--fps <n>` | Worker threads per group (default: 2) |
| `--queue-size <n>` | Capacity of each bounded packet queue (default: 10000) |
| `--verbose` | Print dropped packet details |
| `--help` | Show command help |

The total number of DPI workers is `--lbs * --fps`; each flow is consistently assigned to a worker so its connection state remains local to that worker. The output PCAP retains the input capture's byte order and global header. Packets not parseable as Ethernet/IPv4 TCP or UDP are excluded from DPI processing.

## Run the packet summary reader

```powershell
java -cp build\classes packetanalyzer.PacketAnalyzerMain test_dpi.pcap
java -cp build\classes packetanalyzer.PacketAnalyzerMain test_dpi.pcap 10
```

This prints packet timestamps, Ethernet and IPv4 details, TCP/UDP headers, and a short payload preview. It reads all packets unless a positive maximum is supplied (`-1` also means unlimited).

## Rules file

Rules use section headers, with one rule per line:

```text
[BLOCKED_IPS]
192.168.1.50

[BLOCKED_APPS]
YouTube

[BLOCKED_DOMAINS]
example.com
*.social.example

[BLOCKED_PORTS]
25
```

Domains are matched case-insensitively. A `*.example.com` rule matches both `example.com` and its subdomains.

## What is classified

The DPI engine tracks connections and packet/byte counts, inspects HTTP Host headers and TLS ClientHello SNI, recognizes DNS queries, and maps known domains to application categories (including Google, YouTube, Facebook, Microsoft, Netflix, and others). Classification cannot identify names hidden by encrypted client hello or encrypted application payloads. This analyzer reads classic PCAP files and currently decodes IPv4 transport headers; it does not decode IPv6 or PCAP-NG.

## Test capture

`test_dpi.pcap` is included. To regenerate it, run:

```powershell
java -cp build\classes packetanalyzer.TestPcapGenerator
```
