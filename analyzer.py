import subprocess
import collections
import sys
import os

# --- Iteration 2 & 3: Security Threshold Definitions ---
# Threshold for DNS repeated queries to detect potential beaconing or tunneling
THRESHOLD_DNS_REPETITION = 5  
# Threshold for packet rate (pps) to identify potential DoS or heavy traffic
THRESHOLD_PACKET_RATE = 100    
# Threshold for TCP retransmission rate (5% is a standard network health baseline)
THRESHOLD_RETRANSMISSION_RATE = 0.05 

def run_analysis(file_path):
    # Ensure the target pcap file exists before starting the pipeline
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found.")
        return

    print("-" * 50)
    print(f"System: Starting Automated Analysis Pipeline...")
    print(f"File Target: {file_path}")
    print("-" * 50)

    try:
        # --- Stage 1: Traffic Profiling & Protocol Distribution ---
        # Feature 2 from Proposal: Classify packets and summarize distribution
        print("\n[Step 1/3] Profiling Network Traffic...")
        
        # Extract protocol names for percentage calculation using Tshark fields
        cmd_proto = f"tshark -r {file_path} -T fields -e _ws.col.Protocol"
        protocols = subprocess.check_output(cmd_proto, shell=True).decode().splitlines()
        
        # Extract relative timestamps to calculate capture duration and packet velocity
        cmd_rate = f"tshark -r {file_path} -T fields -e frame.time_relative"
        timestamps = subprocess.check_output(cmd_rate, shell=True).decode().splitlines()
        
        is_rate_anomaly = False
        if timestamps:
            duration = float(timestamps[-1])
            packet_count = len(timestamps)
            avg_rate = packet_count / duration if duration > 0 else 0
            
            print(f"Statistics: {packet_count} packets processed in {duration:.2f} seconds.")
            print(f"Result: Average Traffic Rate is {avg_rate:.2f} packets/s.")
            
            # Implementation of Protocol Distribution (Counts & Percentages)
            proto_counts = collections.Counter(protocols)
            print("Protocol Distribution Summary:")
            for proto, count in proto_counts.items():
                percentage = (count / packet_count) * 100
                print(f" - {proto}: {count} packets ({percentage:.1f}%)")

            # Check if current pps exceeds the defined security threshold
            if avg_rate > THRESHOLD_PACKET_RATE:
                print(f"Warning: [High Traffic] Anomaly detected! Exceeds {THRESHOLD_PACKET_RATE} pps.")
                is_rate_anomaly = True

        # --- Stage 2: Deep Inspection (DNS & TCP Anomalies) ---
        # Feature 3 from Proposal: Identification of repeated DNS and TCP retransmissions
        print("\n[Step 2/3] Performing Deep Packet Inspection...")
        
        # DNS Anomaly Detection: Filtering for DNS queries to find suspicious patterns
        cmd_dns = f"tshark -r {file_path} -Y 'dns.flags.response == 0' -T fields -e dns.qry.name"
        dns_queries = subprocess.check_output(cmd_dns, shell=True).decode().splitlines()
        
        dns_counts = collections.Counter(dns_queries)
        is_dns_anomaly = False
        for domain, count in dns_counts.items():
            if count > THRESHOLD_DNS_REPETITION:
                print(f"Warning: [DNS Repetition] Domain [{domain}] requested {count} times.")
                is_dns_anomaly = True

        # TCP Retransmission Analysis: Monitoring for potential packet loss or interference
        cmd_retrans = f"tshark -r {file_path} -Y 'tcp.analysis.retransmission' | wc -l"
        retrans_count = int(subprocess.check_output(cmd_retrans, shell=True).decode().strip())
        
        is_retrans_anomaly = False
        if packet_count > 0:
            retrans_rate = retrans_count / packet_count
            print(f"TCP Analysis: {retrans_count} retransmissions found (Rate: {retrans_rate:.2%})")
            if retrans_rate > THRESHOLD_RETRANSMISSION_RATE:
                print(f"Warning: [TCP Instability] High retransmission rate detected.")
                is_retrans_anomaly = True

        # --- Stage 3: Security Posture Evaluation ---
        print("\n[Step 3/3] Final Security Rule Evaluation...")
        # Consolidate all boolean indicators into a single anomaly score
        anomaly_score = sum([is_rate_anomaly, is_dns_anomaly, is_retrans_anomaly])
        
        print("-" * 50)
        print("Final Analysis Conclusion")
        status = "ANOMALY DETECTED" if anomaly_score > 0 else "NORMAL"
        print(f"Overall Status: {status} (Anomaly Score: {anomaly_score}/3)")
        print("-" * 50)
        print("Ready for Submission.")

    except Exception as e:
        print(f"Critical Error during analysis: {e}")

if __name__ == "__main__":
    # Dynamically handle file path via CLI argument or use a cross-platform default
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        # Automatically resolves user home directory (~/) for local testing
        target = os.path.expanduser("~/CS5700/test.pcap")
    
    run_analysis(target)