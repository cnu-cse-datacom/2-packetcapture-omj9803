import socket
import struct

def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s", data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x"+ethernet_header[12].hex()

    print("=======ethernet header=======")
    print("src_mac_address:", ether_src)
    print("dest_mac_address:", ether_dest)
    print("ip_version", ip_header)

def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr


recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

while True:
    data = recv_socket.recvfrom(20000)
    parsing_ethernet_header(data[0][0:14])
    
    ip_header_ = struct.unpack("!B B H H H B B H 4s 4s", data[0][14:34])
    ip_version = (ip_header_[0] & 0b11110000) >> 4
    ip_Length = ip_header_[0] & 0b00001111
    ip_differ = (ip_header_[1] & 0b11111100) >> 2
    ip_explicit = ip_header_[1] & 0b00000011
    ip_total_length = ip_header_[2]
    ip_identification = ip_header_[3]
    ip_flags = ip_header_[4]

    ip_reserved = (ip_header_[4] & 0x8000) >> 15 
    ip_not_fragments = (ip_header_[4] & 0x4000) >> 14
    ip_fragments = (ip_header_[4] & 0x2000) >> 13
    ip_fragments_offset = ip_header_[4] & 0x1fff

    ip_Time_to_live = ip_header_[5]
    ip_protocol = ip_header_[6]
    ip_header_checksum = ip_header_[7]
    ip_source = socket.inet_ntoa(ip_header_[8])
    ip_dest = socket.inet_ntoa(ip_header_[9])
    ip_padding = (ip_Length * 4) - 20


    print("=======ip_header=======")
    print("ip_version: ", ip_version)
    print("ip_Length: ", ip_Length)
    print("differentiated_service_codepoint: ", ip_differ)
    print("explicit_congestion_notification: ", ip_explicit)
    print("total_length: ", ip_total_length)
    print("identification: ", ip_identification)
    print("flags: ", ip_flags)
    print(">>>reserved_bit: ", ip_reserved)
    print(">>>not_fragments: ", ip_not_fragments)
    print(">>>fragments: ", ip_fragments)
    print(">>>fragments_offset: ", ip_fragments_offset)
    print("Time to live: ", ip_Time_to_live)
    print("protocol: ", ip_protocol)
    print("header checksum: ", ip_header_checksum)
    print("source_ip_address: ", ip_source)
    print("dest_ip_address: ", ip_dest)

    
    if ip_protocol == 6:
        tcp_header = struct.unpack("!H H I I B B H H H", data[0][34:54])

        tcp_src = tcp_header[0]
        tcp_dec = tcp_header[1]
        tcp_seq = tcp_header[2]
        tcp_header_length = (tcp_header[4] & 0b11110000) >> 4
        tcp_ack = (tcp_header[5] & 0b00010000) >> 4
        tcp_reserved = (tcp_header[4] & 0b00001110) >> 1
        tcp_nonce = (tcp_header[4] & 0b00000001)
        tcp_cwr = (tcp_header[5] & 0b10000000) >> 7
        tcp_urg = (tcp_header[5] & 0b00100000) >> 5
        tcp_push = (tcp_header[5] & 0b00001000) >> 3
        tcp_reset = (tcp_header[5] & 0b00000100) >> 2
        tcp_syn = (tcp_header[5] & 0b00000010) >> 1
        tcp_fin = tcp_header[5] & 0b00000001
        tcp_win = tcp_header[6]
        tcp_checksum = tcp_header[7]

        if tcp_ack == 1:
            tcp_ack_num = tcp_header[3]
        else :
            tcp_ack_num = 0
    
        if tcp_urg == 1:
            tcp_urgp = tcp_header[8]
        else :
            tcp_urgp = 0

        print("=======TCP_header=======")
        print("src_port: ", tcp_src)
        print("dec_port: ", tcp_dec)
        print("seq_num: ", tcp_seq)
        print("ack_num: ", tcp_ack_num)
        print("header_len: ", tcp_header_length)
        print(">>>reserved: ", tcp_reserved)
        print(">>>nonce: ", tcp_nonce)
        print(">>>cwr: ", tcp_cwr)
        print(">>>urgent: ", tcp_urg)
        print(">>>ack: ", tcp_ack)
        print(">>>push: ", tcp_push)
        print(">>>reset: ", tcp_reset)
        print(">>>syn: ", tcp_syn)
        print(">>>fin: ", tcp_fin)
        print("window_size_value: ", tcp_win)
        print("checksum: ", tcp_checksum)
        print("urgent pointer: ", tcp_urgp)

    elif ip_protocol == 17:
        udp_header = struct.unpack("!H H H H", data[0][34+ip_padding:42+ip_padding])
        udp_src = udp_header[0]
        udp_dst = udp_header[1]
        udp_leng = udp_header[2]
        udp_checksum = udp_header[3]


        print("=======udp_header=======")
        print("src_port: ", udp_src)
        print("dst_port: ", udp_dst)
        print("leng: ", udp_leng)
        print("header checksum: ", udp_checksum)

