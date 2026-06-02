#!/usr/bin/env python3
import sys
import argparse
import time
import random

# Mock database of company nodes/servers
MOCK_NODES = {
    "api-gateway": {"ip": "192.168.1.1", "status": "Online", "region": "ap-south-1"},
    "llm-inference-01": {"ip": "10.0.4.12", "status": "Online", "region": "us-east-1"},
    "llm-inference-02": {"ip": "10.0.4.13", "status": "Offline", "region": "us-east-1"},
    "data-pipeline": {"ip": "172.16.0.5", "status": "Online", "region": "eu-west-1"},
}

def ping_node(node_name):
    print(f"Connecting to Openlake network...")
    time.sleep(0.6)  # Simulate network latency
    
    if node_name not in MOCK_NODES:
        print(f"❌ Error: Node '{node_name}' not found in Openlake registry.")
        print("Available nodes: " + ", ".join(MOCK_NODES.keys()))
        sys.exit(1)
        
    node_info = MOCK_NODES[node_name]
    print(f"Pinging {node_name} [{node_info['ip']}] with 32 bytes of data:")
    
    if node_info["status"] == "Offline":
        for i in range(3):
            time.sleep(0.8)
            print(f"Request timed out for ping packet {i+1}")
        print(f"➔ Status: 🔴 OFFLINE (Failed to reach node in {node_info['region']})")
    else:
        for i in range(3):
            time.sleep(0.4)
            latency = round(random.uniform(12.5, 45.2), 1)
            print(f"Reply from {node_info['ip']}: bytes=32 time={latency}ms TTL=64")
        print(f"➔ Status: 🟢 ONLINE (Node active in {node_info['region']})")

def main():
    parser = argparse.ArgumentParser(description="Openlake Command Line Interface (CLI)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Setup the 'ping' subcommand
    ping_parser = subparsers.add_parser("ping", help="Ping a cluster or service node")
    ping_parser.add_argument("node", help="Name of the node to check")

    args = parser.parse_args()

    if args.command == "ping":
        ping_node(args.node)

if __name__ == "__main__":
    main()
