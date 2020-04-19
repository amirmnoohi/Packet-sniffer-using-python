import socket
from struct import *
import time
import argparse
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


class Pcap:
    def __init__(self, filename, link_type=1):
        self.pcap_file = open(filename, 'wb')
        self.pcap_file.write(pack('@IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        self.pcap_file.write(pack('@IIII', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()


def main():
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        parser = argparse.ArgumentParser()
        parser.add_argument('-o', '--output', help='name of file to store sniffed data eg: sniffed.pcap', required=True)
        args = parser.parse_args()
        pcap = Pcap(args.output)

        while True:
            print("---------------------------------")
            raw_data, addr = conn.recvfrom(65535)
            pcap.write(raw_data)
            ether_header = ether(raw_data)
            # SHOWING ETHERNET HEADER :
            print("\nEthernet Frame:")
            print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(ether_header[0], ether_header[1],
                                                                             ether_header[2]))
            # SHOWING IPV4 HEADER :
            if ether_header[2] == 8:
                ip_header = ip(ether_header[3])
                print(TAB_1 + 'IPv4 Packet:')
                print(TAB_2 + 'version: {},Header Length: {},Type of Service: {},Total Length: {},Identification: {},'
                              'IP Flags: {},Fragment Offset: {},Time To Live: {},Protocole: {},Header Checksum: {},'
                              'Source Address: {},Destination Addresss: {}'.format(ip_header[0], ip_header[1],
                                                                                   ip_header[2],
                                                                                   ip_header[3], ip_header[4],
                                                                                   ip_header[5],
                                                                                   ip_header[6], ip_header[7],
                                                                                   ip_header[8],
                                                                                   ip_header[9], ip_header[10],
                                                                                   ip_header[11]))
                # ICMP PACKETS
                if ip_header[8] == 1:
                    icmp_header = icmp(ip_header[-1])
                    print(TAB_1 + 'ICMP Packet:')
                    print(
                        TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_header[0], icmp_header[1],
                                                                           icmp_header[2]))
                    print(TAB_2 + 'ICMP Data:')
                    print(format_multi_line(DATA_TAB_3, icmp_header[3]))
                # TCP PACKETS
                elif ip_header[8] == 6:
                    tcp_header = tcp(ip_header[-1])
                    print(TAB_1 + 'TCP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp_header[0], tcp_header[1]))
                    print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp_header[2], tcp_header[3]))
                    print(TAB_2 + 'Offset: {}, Reserved: {}'.format(tcp_header[4], tcp_header[5]))
                    print(TAB_2 + 'Flags:')
                    print(TAB_3 + 'NS: {}, CWR: {}, ECE: {}'.format(tcp_header[6], tcp_header[7], tcp_header[8]))
                    print(TAB_3 + 'URG: {}, ACK: {}, PSH:{}'.format(tcp_header[9], tcp_header[10], tcp_header[11]))
                    print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp_header[12], tcp_header[13], tcp_header[14]))
                    print(TAB_2 + 'Windows Size: {}, Checksum: {}, Urgent Pointer: {}'.format(tcp_header[15],
                                                                                              tcp_header[16],
                                                                                              tcp_header[17]))
                    # HTTP DATA
                    if len(tcp_header[-1]) > 0:
                        if tcp_header[0] == 80 or tcp_header[1] == 80:
                            print(TAB_2 + 'HTTP Data:')
                            try:
                                http_data = http(tcp_header[-1])
                                http_info = str(http_data).split('\n')
                                for line in http_info:
                                    print(DATA_TAB_3 + str(line))
                            except:
                                print(format_multi_line(DATA_TAB_3, tcp_header[-1]))
                        else:
                            print(TAB_2 + 'TCP Data:')
                            print(format_multi_line(DATA_TAB_3, repr(tcp_header[-1])))

                # UDP PACKETS
                if ip_header[8] == 17:
                    udp_header = udp(ip_header[-1])
                    print(TAB_1 + 'UDP Segment:')
                    print(
                        TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}, Checksunm: {}'.format(udp_header[0],
                                                                                                          udp_header[1],
                                                                                                          udp_header[2],
                                                                                                          udp_header[
                                                                                                              3]))
    except KeyboardInterrupt:
        print("\nCtrl+C Pressed!\nAll Data is Saved at : " + args.output)


def ether(data):
    dest_mac, src_mac, proto = unpack('! 6s 6s H', data[:14])
    return [get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]]


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def ip(data):
    maindata = data
    data = unpack('!BBHHHBBH4s4s', data[:20])
    return [(data[0] >> 4), (data[0] & 0xF) * 4, data[1], data[2],
            data[3], data[4] >> 13, data[4] & 0x1FFF, data[5],
            data[6], hex(data[7]), socket.inet_ntoa(data[8]),
            socket.inet_ntoa(data[9]), maindata[((data[0] & 0xF) * 4):]]


def icmp(data):
    type, code, checksum = unpack('!BBH', data[:4])
    return [type, code, hex(checksum), repr(data[4:])]


def tcp(data):
    maindata = data
    data = unpack('!HHLLHHHH', data[:20])
    return [data[0], data[1], data[2], data[3], (data[4] >> 12) * 4, (data[4] >> 9) & 7,
            (data[4] >> 8) & 1, (data[4] & 128) >> 7,
            (data[4] & 64) >> 6, (data[4] & 32) >> 5, (data[4] & 16) >> 4,
            (data[4] & 8) >> 3, (data[4] & 4) >> 2, (data[4] & 2) >> 1, data[4] & 1,
            data[5], hex(data[6]), data[7], maindata[(data[4] >> 12) * 4:]]


def http(data):
    try:
        return data.decode('utf-8')
    except:
        return data


def udp(data):
    data = unpack('!HHHH', data[:8])
    return [data[0], data[1], data[2], hex(data[3])]


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
