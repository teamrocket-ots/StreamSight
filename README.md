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
7. [Analysis Metrics](#analysis-metrics)
8. [Visualization](#visualization)
9. [Additional Features](#additional-features)

## Project Overview

StreamSight is designed to analyze network traffic captured in `.pcapng` files, with a focus on identifying and characterizing various types of transmission delays across TCP, UDP, and MQTT protocols. The project provides detailed insights into network performance through comprehensive analysis and interactive visualizations.

## Features

- Multi-protocol analysis (TCP, UDP, MQTT)
- Delay characterization and visualization
- Interactive Streamlit frontend
- Protocol-specific performance metrics
- Timeline analysis and packet exploration
- Support for both real and simulated data

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/StreamSight.git
cd StreamSight
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

3. Ensure you have Wireshark installed (required for PyShark functionality)  
    https://www.wireshark.org/download.html

## Usage

1. Run the Streamlit application:
```bash
streamlit run app.py
```

2. Upload a `.pcapng` file or use the provided sample data
3. Navigate through the different tabs to explore various aspects of the analysis

## Core Logic

The core functionality of StreamSight is implemented through several key components:

### 1. Packet Capture and Processing (`pcap_parser.py`)
- Uses PyShark to extract data from `.pcapng` files
- Identifies and categorizes packets by protocol (TCP, UDP, MQTT)
- Calculates timestamps and time differentials between packets
- Associates related packets to track transmission paths

### 2. Protocol-Specific Analysis

#### TCP Analysis
- Tracks handshakes, retransmissions, and acknowledgments
- Calculates RTT, ACK delays, and connection establishment times
- Identifies congestion events and throughput limitations

#### UDP Analysis
- Measures inter-packet delay (IPD) using timestamp differences
- Implements RFC-compliant jitter calculations with exponential moving averages
- Detects packet loss through statistical analysis of timing gaps
- Generates a congestion score based on weighted jitter and loss metrics

#### MQTT Analysis
- Maps the client-broker-cloud communication architecture
- Tracks connection establishment, subscription, and message publishing
- Measures device-to-broker, broker processing, and broker-to-cloud delays

### 3. Data Generation (`data_generator.py`)
- Creates synthetic network traffic data for testing and demonstration
- Simulates realistic delay patterns and protocol behaviors

### 4. Visualization Engine (`visualizations.py`)
- Generates interactive Plotly charts and graphs
- Provides time-series analysis of delay metrics
- Creates heatmaps and distribution plots for pattern identification

## File Structure

```
StreamSight/
├── app.py                 # Main Streamlit application
├── pcap_parser.py         # PCAP file parsing and protocol analysis
├── data_generator.py      # Synthetic data generation
├── visualizations.py      # Visualization functions
├── analysis.py            # Timeline insights and categorization
├── requirements.txt       # Project dependencies
├── proposal.pdf           # Initial project proposal
└── tabs/                  # Streamlit frontend tabs
    ├── overview.py        # Project overview and summary
    ├── delay_analysis.py  # General delay analysis
    ├── mqtt_analysis.py   # MQTT-specific analysis
    ├── tcp_analysis.py    # TCP-specific analysis
    ├── udp_analysis.py    # UDP-specific analysis
    ├── timeline.py        # Chronological packet view
    ├── insights.py        # Key findings and observations
    ├── explorer.py        # Interactive packet explorer
    └── search.py          # Search functionality
`