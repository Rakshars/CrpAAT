import struct
import time
from datetime import datetime

class PCAPLogger:
    def __init__(self):
        self.packets = []
        self.sessions = {}  # client_port -> {c2s_seq, s2c_seq, c2s_ack, s2c_ack}
        self.keys_history = []  # List of tuples: (timestamp_str, username, key_hex)
        self.start_time = time.time()

    def _internet_checksum(self, data):
        """Calculates 16-bit internet checksum (RFC 1071)."""
        if len(data) % 2 == 1:
            data += b'\x00'
        s = sum(struct.unpack(f"!{len(data)//2}H", data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff

    def log_key(self, username, aes_key_bytes):
        """Logs an established symmetric key to keys history."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        self.keys_history.append((timestamp, username or "ANONYMOUS", aes_key_bytes.hex()))

    def log_packet(self, direction, client_port, payload_bytes):
        """
        Wraps the socket payload bytes in Ethernet, IPv4, and TCP headers, 
        maintaining sequence tracking, and logs it in standard PCAP format.
        
        direction: 'c2s' (client -> server) or 's2c' (server -> client)
        client_port: port number of the client socket
        payload_bytes: raw byte string
        """
        timestamp = time.time()
        sec = int(timestamp)
        usec = int((timestamp - sec) * 1000000)
        
        # Initialize session tracking if not exists
        if client_port not in self.sessions:
            self.sessions[client_port] = {
                'c2s_seq': 1000,
                's2c_seq': 5000,
                'c2s_ack': 5000,
                's2c_ack': 1000
            }
            
        sess = self.sessions[client_port]
        server_port = 9999
        
        # Setup addressing depending on direction
        if direction == 'c2s':
            src_ip = b'\x7f\x00\x00\x01'  # 127.0.0.1
            dst_ip = b'\x7f\x00\x00\x01'
            src_port = client_port
            dst_port = server_port
            seq = sess['c2s_seq']
            ack = sess['c2s_ack']
            # Update sequences
            sess['c2s_seq'] += len(payload_bytes)
            sess['s2c_ack'] = sess['c2s_seq']
        else:
            src_ip = b'\x7f\x00\x00\x01'
            dst_ip = b'\x7f\x00\x00\x01'
            src_port = server_port
            dst_port = client_port
            seq = sess['s2c_seq']
            ack = sess['s2c_ack']
            # Update sequences
            sess['s2c_seq'] += len(payload_bytes)
            sess['c2s_ack'] = sess['s2c_seq']

        # 1. Ethernet Header (14 bytes)
        # Dest MAC, Src MAC, Type (0x0800 = IPv4)
        eth_header = struct.pack("!6s6sH", b"\x00\x00\x00\x00\x00\x02", b"\x00\x00\x00\x00\x00\x01", 0x0800)

        # 2. IPv4 Header (20 bytes)
        version_ihl = 0x45  # Version 4, IHL 5 (20 bytes)
        dscp_ecn = 0x00
        total_len = 20 + 20 + len(payload_bytes)
        ident = (12345 + len(self.packets)) & 0xFFFF
        flags_offset = 0x4000  # Don't Fragment
        ttl = 64
        proto = 6  # TCP
        hdr_checksum = 0
        
        # Pack raw IP header to calculate checksum
        ip_header_pre = struct.pack("!BBHHHBBH4s4s", version_ihl, dscp_ecn, total_len, ident, flags_offset, ttl, proto, hdr_checksum, src_ip, dst_ip)
        hdr_checksum = self._internet_checksum(ip_header_pre)
        ip_header = struct.pack("!BBHHHBBH4s4s", version_ihl, dscp_ecn, total_len, ident, flags_offset, ttl, proto, hdr_checksum, src_ip, dst_ip)

        # 3. TCP Header (20 bytes)
        # Source Port, Dest Port, Seq, Ack, Offset/Flags, Window, Checksum, Urgent
        data_offset_flags = 0x5018  # Data offset 5 (20 bytes), flags PSH | ACK
        window = 65535
        tcp_checksum = 0
        urgent = 0
        
        # Calculate TCP checksum with pseudo-header
        # Pseudo header: src_ip (4B), dst_ip (4B), reserved (1B = 0), protocol (1B = 6), tcp_len (2B)
        tcp_len = 20 + len(payload_bytes)
        pseudo_hdr = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, proto, tcp_len)
        tcp_hdr_pre = struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, data_offset_flags, window, tcp_checksum, urgent)
        tcp_checksum = self._internet_checksum(pseudo_hdr + tcp_hdr_pre + payload_bytes)
        tcp_hdr = struct.pack("!HHIIHHHH", src_port, dst_port, seq, ack, data_offset_flags, window, tcp_checksum, urgent)

        # Construct packet record
        full_packet = eth_header + ip_header + tcp_hdr + payload_bytes
        
        # PCAP Packet Record Header (16 bytes): ts_sec, ts_usec, incl_len, orig_len
        pcap_rec_hdr = struct.pack("<IIII", sec, usec, len(full_packet), len(full_packet))
        
        self.packets.append(pcap_rec_hdr + full_packet)

    def generate_pcap_bytes(self):
        """Returns the full binary PCAP byte stream of the recorded packets."""
        # PCAP Global Header (24 bytes)
        # magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network
        global_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)  # LinkType 1 = Ethernet
        return global_hdr + b"".join(self.packets)

    def generate_keys_txt(self):
        """Generates a text log of session keys mapping timestamps and users to AES keys."""
        lines = [
            "===========================================================",
            "           CRYPTOSHIELD SESSION AES-256 KEYS LOG           ",
            "===========================================================",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "Format: [Timestamp] [User] [Symmetric AES-256 Session Key]",
            "-----------------------------------------------------------"
        ]
        if not self.keys_history:
            lines.append("[!] No established session keys found.")
        else:
            for timestamp, user, key in self.keys_history:
                lines.append(f"[{timestamp}] User '{user}': {key}")
        lines.append("-----------------------------------------------------------")
        lines.append("Use these keys to manually decrypt secure payloads if needed.")
        return "\n".join(lines)
