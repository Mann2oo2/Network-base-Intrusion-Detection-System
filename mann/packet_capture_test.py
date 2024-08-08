from scapy.all import sniff, wrpcap, ICMP, TCP, UDP, DNS, ARP, IP, Ether, Raw
import csv
import os
from collections import deque
import time
import rules
import pickle
import numpy as np
from sklearn.preprocessing import LabelEncoder

# Load the IDS model
with open('ids_model.pkl', 'rb') as model_file:
    ids_model = pickle.load(model_file)

# Prompt the user for the output filenames
output_filename = input("Enter the output filename for the captured packets (with .pcap extension): ")
csv_filename = input("Enter the output filename for the extracted features (with .csv extension): ")

# List to store all captured packets
all_packets = []

# Define CSV header names 15 fills
csv_headers = [
    'eth_src', 'eth_dst', 'eth_type', 'ip_src', 'ip_dst', 'ip_proto', 'ip_flags_frag', 'src_port', 'dst_port',
    'ip_ihl', 'ip_chksum', 'ip_len', 'raw_load', 'packet_rate', 'payloads'
]

# Queue to store packet times for rate calculation
packet_times = deque(maxlen=100)

# Initialize the CSV file with headers
def initialize_csv():
    if not os.path.isfile(csv_filename):
        with open(csv_filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(csv_headers)

# Function to write features to a CSV file
def write_features_to_csv(features):
    with open(csv_filename, 'a', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_headers)
        writer.writerow(features)

# Function to label encode string features
def encode_features(features):
    label_encoders = {}
    for key in features:
        if isinstance(features[key], str):
            if key not in label_encoders:
                label_encoders[key] = LabelEncoder()
                label_encoders[key].fit([features[key]])
            features[key] = label_encoders[key].transform([features[key]])[0]
    return features

# Define the callback function to handle captured packets
def packet_handler(packet):
    global all_packets
    all_packets.append(packet)
    
    # Extract features from the packet
    features = extract_features(packet)
    
    # Apply intrusion detection rules
    for rule in rules.intrusion_rules:
        if rules.apply_rule(features, rule):
            alert_message = rule['alert_message']
            print(f"{alert_message}: {packet.summary()}")

    # Ensure all features are numerical and handle missing values
    for key in features:
        if features[key] is None:
            if key in ['eth_src', 'eth_dst', 'ip_src', 'ip_dst', 'ip_flags_frag']:
                features[key] = "not available"
            else:
                features[key] = 0
        else:
            try:
                if isinstance(features[key], bytes):
                    features[key] = len(features[key])
                elif key == 'ip_flags_frag' and isinstance(features[key], type(packet[IP].flags)):
                    features[key] = int(features[key])
                else:
                    features[key] = float(features[key])
            except ValueError:
                if key in ['eth_src', 'eth_dst', 'ip_src', 'ip_dst', 'ip_flags_frag']:
                    features[key] = "not available"
                else:
                    features[key] = 0

    # Encode string features
    features = encode_features(features)

    # Predict using the IDS model
    try:
        prediction = ids_model.predict([list(features.values())])[0]
        if prediction == 0:  # Assuming 1 indicates a malicious prediction
            print(f"Malicious packet detected: {packet.summary()}")
    except Exception as e:
        print(f"Error making prediction: {e}")

    # Write the features to the CSV file
    write_features_to_csv(features)

# Function to extract features from the packet
def extract_features(packet):
    features = {header: None for header in csv_headers}  # Initialize all features to None
    
    # Timestamp for rate calculation
    current_time = time.time()
    packet_times.append(current_time)
    
    if packet.haslayer(Ether):
        eth_layer = packet[Ether]
        features['eth_src'] = eth_layer.src
        features['eth_dst'] = eth_layer.dst
        features['eth_type'] = eth_layer.type
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        features['ip_src'] = ip_layer.src
        features['ip_dst'] = ip_layer.dst
        features['ip_proto'] = ip_layer.proto
        features['ip_flags_frag'] = ip_layer.flags & 0x1
        features['ip_ihl'] = ip_layer.ihl
        features['ip_chksum'] = ip_layer.chksum
        features['ip_len'] = ip_layer.len
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        features['src_port'] = tcp_layer.sport
        features['dst_port'] = tcp_layer.dport
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        features['src_port'] = udp_layer.sport
        features['dst_port'] = udp_layer.dport
    if packet.haslayer(Raw):
        features['raw_load'] = len(packet[Raw].load)
    
    # Calculate packet rate (packets per second)
    if len(packet_times) > 1:
        time_diff = packet_times[-1] - packet_times[0]
        features['packet_rate'] = len(packet_times) / time_diff if time_diff > 0 else 0
    
    # Calculate payloads (sum of payload lengths)
    payloads = sum(len(p[Raw].load) for p in all_packets if p.haslayer(Raw))
    features['payloads'] = payloads

    return features

# Start capturing packets using Scapy's sniff function
print("Capturing packets on all interfaces... Press Ctrl+C to stop.")
try:
    initialize_csv()
    sniff(prn=packet_handler, store=False)
except KeyboardInterrupt:
    pass
finally:
    # Save all captured packets to a .pcap file
    wrpcap(output_filename, all_packets)
    print(f"All captured packets have been saved to {output_filename}")

