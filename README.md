
# StreamSight

## Network Packet Analysis and Delay Characterization Tool

StreamSight is a comprehensive tool developed during Hackenza for the characterization and analysis of delays in packet transmission across various network protocols.

**Team Rocket:**
- Jayant Choudhary [2023A7PS0404G]
- Swayam Lakhotia [2023A7PS0368G]
- Siddhant Kedia [2023A7PS0375G]
- Pratham Chheda [2023AAPS0138G]

## Table of Contents
1. [Project Overview](#project-overview)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Core Logic](#core-logic)
6. [File Structure](#file-structure)
7. [Testing Methodology](#testing-methodology)

## Project Overview

StreamSight analyzes network traffic captured in `.pcapng` files, focusing on identifying transmission delays across TCP, UDP, and MQTT protocols. Provides performance insights through interactive visualizations.

## Features

- Multi-protocol analysis (TCP, UDP, MQTT)
- Delay characterization and visualization
- Interactive Streamlit frontend
- Protocol-specific performance metrics
- Timeline analysis and packet exploration
- Synthetic data generation for testing
- Root cause Analysis

## Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/StreamSight.git
cd StreamSight
```

2. Install dependencies:
```
pip install -r requirements.txt
```

3. Install Wireshark for PyShark functionality:  
   [Wireshark Download](https://www.wireshark.org/download.html)

## Usage

1. Launch Streamlit interface:
```
streamlit run app.py
```

2. Upload `.pcapng` file or use synthetic data
3. Navigate through analysis tabs:
   - Overview: Project summary
   - Delay Analysis: Protocol-agnostic metrics
   - Protocol-Specific Tabs: Detailed TCP/UDP/MQTT insights
   - Timeline: Chronological packet flow
   - Explorer: Raw packet inspection

## Core Logic

### Packet Processing Pipeline (`pcap_parser.py`)
```
graph TD
    A[PCAPNG File] --> B[PyShark Extraction]
    B --> C{Protocol Detection}
    C -->|TCP| D[Handshake Analysis]
    C -->|UDP| E[Jitter Calculation]
    C -->|MQTT| F[Message Flow Tracking]
    D --> G[Delay Metrics]
    E --> G
    F --> G
    G --> H[Visualization Engine]
    H --> I Root Cause Analysis
```

### MQTT Analysis Implementation
**Packet Processing Logic:**
1. Message Type Identification:
   - CONNECT (1): Client initiation, tracks source as client
   - CONNACK (2): Broker response, identifies broker IP
   - PUBLISH (3): Message transmission timing
   - PUBACK (4): Acknowledgment tracking

2. Entity Identification:
   ```
   if msg_type == '1':  # CONNECT
       clients.add(src_ip)
       brokers.add(dst_ip)
   elif msg_type == '2':  # CONNACK
       brokers.add(src_ip)
   ```

3. Delay Calculations:
   - **Broker-Client Delay**:  
     `broker_ack_time - client_publish_time`
   - **Broker Processing Delay**:  
     `broker_forward_time - broker_ack_time`  

 
    **Key Limitations**
The following elements cannot be directly observed in case of port 8883:

    - Message IDs (msgid)
    - Message types (msgtype)s
    - QoS levels

4. Port Heuristics:
   - 1883: Standard MQTT port
   - 8883: MQTT over SSL (Encrypted: No access to msg)
   ```
   if dst_port == 1883:
       mqtt_messages[msg_id]['client_publish_time'] = timestamp
   elif src_port == 1883:
       mqtt_messages[msg_id]['broker_forward_time'] = timestamp
   ```

### Protocol-Specific Metrics

#### TCP Analysis
- Round Trip Time (RTT)
- ACK Response Delay
- Retransmission Patterns
- Connection Establishment Time

#### UDP Analysis
- Inter-Packet Delay (IPD)
- RFC-Compliant Jitter
- Packet Loss Detection
- Congestion Scoring

#### MQTT Analysis
- Client-Broker Handshake Timing
- Message Publish-Acknowledge Latency
- Broker Processing Efficiency
- Topic-Based Delay Correlation

## File Structure

```
StreamSight/
├── app.py                 # Streamlit application core
├── pcap_parser.py         # Packet processing engine
├── data_generator.py      # Synthetic traffic generation
├── visualizations.py      # Plotly chart generation
├── analysis.py            # Timeline categorization
├── requirements.txt       # Python dependencies
├── proposal.pdf           # Initial project design
├── rootcause_analysis.py  # Performs the root cause analysis
└── tabs/                  # UI components
    ├── overview.py        # Project summary
    ├── delay_analysis.py  # Cross-protocol metrics
    ├── mqtt_analysis.py   # MQTT-specific dashboards
    ├── tcp_analysis.py    # TCP performance insights
    ├── udp_analysis.py    # UDP traffic analysis
    ├── timeline.py        # Chronological view
    ├── explorer.py        # Packet inspection
    ├── search.py          # Filtering interface
    └── rootcause_tab.py   # A helper tab file for displaying root cause analysis  
```

## Testing Methodology

1. **Synthetic Data Validation**
   - `data_generator.py` creates controlled test scenarios
   - Validates metric calculations against known values

2. **Real-World Capture Testing**
   - Wireshark-verified packet captures
   - Cross-checked timing measurements

<!-- 3. **Edge Case Handling**
   - Negative time differences
   - Out-of-order packets
   - Malformed protocol headers -->
