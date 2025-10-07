# Analysis of the feasibility of using machine learning for network threat detection and prediction
This README explains repository structure, how to reproduce the environment, how to run telemetry and Snort, how to collect/convert logs, how to produce a merged dataset and basic ML experiments, and tips for generating error conditions / attacks.

# Project overview
You run a small SDN testbed (Mininet linear topology with 2 switches and 2 hosts).

Some things (like `local.rules`) will need to be customized based on your environment and put into mininet vm into snort root directory.

Ryu controller runs a SimpleSwitch13-derived app that:
* Performs L2 learning forwarding
* Polls switches periodically for port stats, flow stats, table stats.
* Logs OpenFlow events (packet_in, flow_mod, flow_removed, port_status) to CSV.

Snort (IDS) runs on a host and writes alerts/logs (CSV / unified2 → CSV) that are parsed and aggregated.

# Main goals:

Produce a reproducible dataset combining switch telemetry + Snort logs.

Evaluate simple ML methods to detect/predict attacks from gathered data.

# Requirements
Use a Linux VM (Ubuntu/Debian). Suggested versions tested with Mininet + OVS supporting OpenFlow 1.3.

Core software:

* Python 3.9
* Ryu controller (installed via pip or from source)
* Mininet (for topology)
* Open vSwitch (default Mininet)
* Snort 2.9.20
* scapy / hping3 / iperf (traffic generators)
* Xming to view Mininet CLI on Windows (optional)

# Quick start
0. Set up Python environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
1. Start Ryu controller:
   ```bash
   ryu-manager --verbose sdn-controller/controller.pu
   ```
2. Start Mininet simulation:
   ```bash
   sudo python3 mininet/topology.py
   ```
3. Run Snort on any port, for example s1-eth1:
   ```bash
   <tbd>
   ```
4. Generate traffic/attacks from h1 or h2:
   ```bash
   <tbd>
   ```
   
# Telemetry output
1. port_stats.csv:
```
ts_utc,switch_dpid,port_no,rx_packets,tx_packets,rx_bytes,tx_bytes,rx_errors,tx_errors,duration_s
```
2. flow_stats.csv:
```
ts_utc,switch_dpid,priority,match,duration_sec,packet_count,byte_count
```
3. port_desc.csv:
```
ts_utc,switch_dpid,port_no,hw_addr,name,config,state
```
4. table_stats.csv:
```
ts_utc,switch_dpid,table_id,active_count,lookup_count,matched_count
```
5. events.csv:
```
ts_utc,switch_dpid,event_type,details
```

# License
This repository is intended for research/educational use.
Based on Ryu SDN framework, Mininet, Snort - check their licenses.