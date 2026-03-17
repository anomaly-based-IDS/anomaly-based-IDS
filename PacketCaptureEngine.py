from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import queue
import threading
from datetime import datetime
import json

class PacketCaptureEngine:
    def __init__(self, interface = None, packet_queue_maxsize = 10000):
        self.interface = interface
        self.packet_queue = queue.Queue(maxsize=packet_queue_maxsize)
        self.capture_thread = None
        self.stop_event = threading.Event()
        self.packet_stats = defaultdict(int)

    def packet_callback(self, packet): # 
        try:
            if IP not in packet:
                return
            
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto, # 6 for TCP, 17 for UDP
                'ttl': packet[IP].ttl,
                'length': len(packet)
            }

            if TCP in packet:
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['flags'] = packet[TCP].flags
                packet_info['seq'] = packet[TCP].seq

            elif UDP in packet:
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport

            if not self.packet_queue.full():
                self.packet_queue.put(packet_info)
            else:
                try:
                    self.packet_queue.get_nowait()  # 오래된 패킷 제거
                    self.packet_queue.put(packet_info)

                except queue.Empty:
                    pass  # 큐가 비어있을때 발생할 수 있는 예외 처리

            self.packet_stats['captured'] += 1

        except Exception as e:
            self.packet_stats['errors'] += 1
            print(f"Error processing packet: {e}")


    def start_capture(self): 
        self.capture_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.capture_thread.start()
        print(f"Packet capture started on interface: {self.interface}")

    def _sniff_packets(self):
        sniff(iface=self.interface, prn=self.packet_callback, stop_filter=lambda x: self.stop_event.is_set(),
              store=False)
        
    def stop_capture(self):
        self.stop_event.set()
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
            print("Packet capture stopped.")

    def get_captured_packets(self):
        return dict(self.packet_stats), list(self.packet_queue.queue)