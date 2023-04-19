from scapy.all import *
print("HostAware IDS")
print("Starting[+]")
print(" Two ports are being monitored [80,443]")
def handle_packet(packet):
    if TCP in packet and packet[TCP].dport == 80:
        print("[ALERT] Port 80 used!")
    elif TCP in packet and packet[TCP].dport == 443:
        print("[ALERT] Port 443 used!")

sniff(prn=handle_packet, filter="tcp")