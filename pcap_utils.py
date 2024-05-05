import dpkt
from dpkt.compat import compat_ord
import socket
import pyshark
import networkx as nx


def mac_addr(address):
    return ':'.join('%02x' % compat_ord(b) for b in address)


def getIcmpInfo(ip,ipSrc,ipDst):
    # https://dpkt.readthedocs.io/en/latest/print_icmp.html
    icmp = ip.data
    data = 'IP: %s -> %s   (len=%d ttl=%d)' % (ipSrc, ipDst, ip.len, ip.ttl)
    data += 'ICMP: type:%d code:%d checksum:%d data: %s' % (icmp.type, icmp.code, icmp.sum, repr(icmp.data))
    return data

def getDnsInfo(udp):
    dns = dpkt.dns.DNS(udp)
    if dns.qr != dpkt.dns.DNS_R: 
        return 0,0
    if dns.opcode != dpkt.dns.DNS_QUERY: 
        return 0,0
    if dns.rcode != dpkt.dns.DNS_RCODE_NOERR: 
        return 0,0
    if len(dns.an) < 1: 
        return 0,0
    # now we're going to process and spit out responses based on record type
    # ref: http://en.wikipedia.org/wiki/List_of_DNS_record_types
    data = []
    for answer in dns.an:
        if answer.type == dpkt.dns.DNS_CNAME:
            data.appand("CNAME request", answer.name, "\tresponse", answer.cname)
        elif answer.type == dpkt.dns.DNS_A:
            data.appand("A request", answer.name, "\tresponse", socket.inet_ntoa(answer.rdata))
        elif answer.type == dpkt.dns.DNS_PTR:
            data.appand("PTR request", answer.name, "\tresponse", answer.ptrname)
    return data,1

def getArpInfo(eth):
    data = "Src: " + mac_addr(eth.src)
    data += "Dst: " + mac_addr(eth.dst)
    return data
    #ipSrc = socket.inet_ntoa(ip.src)
    #ipDst = socket.inet_ntoa(ip.dst)
    #print ("source protocol address", socket.inet_ntoa(arp.spa))
    #print ("source hardware address",  mac_addr(arp.sha))
    #print ("Target protocol address", socket.inet_ntoa(arp.tpa))      #IPv4 address
    #print ("target hardware address",  mac_addr(arp.tha))


protocolPortTCP = {
    "FTP":    21,
    "SSH":    22,
    "TELNET": 23,
    "SMTP":   25,
    "HTTP":   80,
    "KR5":    88,
    "POP3":   110,
    "NTP":    123,
    "MS-RPC": 135,
    "NetBIOS":139,
    "SNMP":   162,
    "LDAP":   398,
    "HTTPS":  443,
    "SMB":    445,
    "IMAPS":  993,
    "RDP":    3389
}
protocolPortUDP = {
    "DNS":     53,
    "TFTP":    69,
    "DHCP":    [67,68], #  Server = 67 &  client  = 68
    "NTP":     123,
    "NetBIOS": [137,138],
    "SNMP":    [161,162],
    "RDP":     3389,
    "Dropbox": 17500
}


def getPcInfo(macAddress,ipAddress):
    return [ipAddress,macAddress]


def printPcap(pcap):
    HttpHeaders = []
    dnsInfo = []
    icmpData = []
    arpInfo = []

    nbPacket = 1
    nbNodes = 0
    counters = {
        'TELNET': 0, 
        'FTP': 0,
        'TFTP': 0,
        'SSH': 0,
        'HTTP': 0,
        'KR5': 0,
        'HTTPS': 0,
        'DNS': 0,
        'ICMP': 0,
        'ARP': 0,
        
        'MS-RPC': 0,
        'RDP': 0,
        'POP3': 0,
        'SNMP': 0,
        'IMAPS': 0,
        'NetBIOS': 0,
        
        'SMTP': 0,
        'LDAP': 0,
        'SMB': 0,
        'TCP': 0,

        'UDP': 0,
        'DHCP': 0,
        'Dropbox': 0,
        'NTP': 0,

        'IP6': 0
    }

    for (ts,buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except dpkt.dpkt.NeedData as e:
            print(e)
            continue
        
        linkInfo = "UNKN"
        sport = 0
        dport = 0

        if(isinstance(eth.data, dpkt.ip.IP)):
            ip = eth.data
            ipSrc = socket.inet_ntoa(ip.src)
            ipDst = socket.inet_ntoa(ip.dst)
            # print("IP: ", ipSrc, " -> ", ipDst)

            if(isinstance(ip.data, dpkt.tcp.TCP) and len(ip.data.data) > 0):
                tcp = ip.data
                sport = tcp.sport
                dport = tcp.dport
                
                if(tcp.dport == protocolPortTCP["FTP"]):
                    linkInfo = "FTP"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["SSH"]):
                    linkInfo = "SSH"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["TELNET"]):
                    linkInfo = "TELNET"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["SMTP"]):
                    linkInfo = "SMTP"
                    counters[linkInfo] += 1
                elif (tcp.dport == protocolPortTCP["HTTP"]):
                    try:
                        http = dpkt.http.Request(tcp.data)
                        info = "IP:"+ ipSrc + " -> "+ ipDst + "\t" + http.method +" "+ http.uri +" "+ http.headers['user-agent']
                        HttpHeaders.append(info)
                    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                        pass
                    linkInfo = "HTTP"
                    counters[linkInfo] += 1
                elif (tcp.dport == protocolPortTCP["KR5"]):
                    linkInfo = "KR5"
                    counters[linkInfo] += 1
                elif (tcp.dport == protocolPortTCP["POP3"]):
                    linkInfo = "POP3"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["NetBIOS"]):
                    linkInfo = "NetBIOS"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["NTP"]):
                    linkInfo = "NTP"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["MS-RPC"]):
                    linkInfo = "MS-RPC"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["SNMP"]):
                    linkInfo = "SNMP"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["LDAP"]):
                    linkInfo = "LDAP"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["HTTPS"]):
                    linkInfo = "HTTPS"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["SMB"]):
                    linkInfo = "SMB"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["IMAPS"]):
                    linkInfo = "IMAPS"
                    counters[linkInfo] += 1
                elif(tcp.dport == protocolPortTCP["RDP"]):
                    linkInfo = "RDP"
                    counters[linkInfo] += 1
                else:
                    linkInfo = "TCP"
                    counters[linkInfo] += 1

            elif(isinstance(ip.data, dpkt.udp.UDP) and len(ip.data.data) > 0 ):
                udp = ip.data
                sport = udp.sport
                dport = udp.dport
                if (udp.dport == protocolPortUDP["DNS"]):
                    data,ret = getDnsInfo(udp.data)
                    if(ret):
                        dnsInfo.append(data)
                    linkInfo = "DNS"
                    counters[linkInfo] += 1
                elif (udp.dport == protocolPortUDP["TFTP"]):
                    linkInfo = "TFTP"
                    counters[linkInfo] += 1
                elif (udp.dport == protocolPortUDP["DHCP"][0] or udp.dport == protocolPortUDP["DHCP"][1]):
                    linkInfo = "DHCP"
                    counters[linkInfo] += 1
                elif ((udp.dport == protocolPortUDP["NTP"])):
                    linkInfo = "NTP"
                    counters[linkInfo] += 1
                elif (udp.dport == protocolPortUDP["NetBIOS"][0] or udp.dport == protocolPortUDP["NetBIOS"][1]):
                    linkInfo = "NetBIOS"
                    counters[linkInfo] += 1
                elif (udp.dport == protocolPortUDP["SNMP"][0] or udp.dport == protocolPortUDP["SNMP"][1]):
                    linkInfo = "SNMP"
                    counters[linkInfo] += 1
                elif ((udp.dport == protocolPortUDP["Dropbox"])):
                    linkInfo = "Dropbox"
                    counters[linkInfo] += 1
                else:
                    linkInfo = "UDP"
                    counters[linkInfo] += 1

            elif(isinstance(ip.data, dpkt.icmp.ICMP)):
                icmpData.append(getIcmpInfo(ip,ipSrc,ipDst))
                linkInfo = "ICMP"
                counters[linkInfo] += 1

        elif(isinstance(eth.data, dpkt.arp.ARP)):
            linkInfo = "ARP"
            counters[linkInfo] += 1
            arpInfo.append(getArpInfo(eth))
            print("    [X] ARP NOT SUPPORTED !!!    ")

        elif(isinstance(eth.data, dpkt.ip6.IP6)):
            linkInfo = "IP6"
            counters[linkInfo] += 1
            print("    [X] IP6 NOT SUPPORTED !!!     ")

        else:
            print("    [X] UNKNOWN PROTOCOL !!!    ")

        # print("    [*] Packet: ", nbPacket, "Protocol: ", linkInfo, "Src: ", ipSrc, "Dst: ", ipDst, "Sport: ", sport, "Dport: ", dport)
        nbPacket += 1
    print("\n[+] NbPackets: ", nbPacket, "NbNodes:", nbNodes, end="\r")
    
    print("\n\n[-] Network Stat:")
    for key,value in counters.items():
        if(value > 0):
            print("\t" +  key +"\t", value)
    

    # if(counters["DNS"] > 0 and len(dnsInfo) > 0):
    #     pFile = open("dnsInfo.txt", "w")
    #     for queries in dnsInfo:
    #         for query in queries:
    #             pFile.write(query + "\n")
    #     pFile.close
    # if(counters["HTTP"] > 0 and len(HttpHeaders) > 0):
    #     pFile = open("httpInfo.txt", "w")
    #     for HttpHeader in HttpHeaders:
    #         pFile.write(HttpHeader + "\n")
    #         #print("\t", HttpHeader)
    #     pFile.close
    # if(counters["ICMP"] > 0 and len(icmpData) > 0):
    #     pFile = open("icmpInfo.txt", "w")
    #     for icmpReq in icmpData:
    #         pFile.write(icmpReq + "\n")
    #     pFile.close
    # if(counters["ARP"] > 0 and len(arpInfo) > 0):
    #     pFile = open("arpInfo.txt", "w")
    #     for arpReq in arpInfo:
    #         pFile.write(arpReq + "\n")
    #     pFile.close



def analyze_pcap(fileName):
    print("[i] Pcap scan started")
    pFile = open(fileName, 'rb')
    pcap = dpkt.pcap.Reader(pFile)
    printPcap(pcap)
    pFile.close()



def process_pcap_file(G):
    # Open the PCAP file
    pcap_file = pyshark.FileCapture("./pcap/test.pcap", use_ek=True)

    # Process each packet in the PCAP file
    for packet in pcap_file:
        try:
            # Extract the source and destination IP addresses if exists
            if hasattr(packet, "ip"):
                src_ip = str(packet.ip.src.host)
                dst_ip = str(packet.ip.dst.host)
            else:
                # packet.pretty_print()
                continue

            # Extract the source and destination port numbers if exists
            if hasattr(packet, "tcp"):
                src_port = str(packet.tcp.srcport)
                dst_port = str(packet.tcp.dstport)
            elif hasattr(packet, "udp"):
                src_port = str(packet.udp.srcport)
                dst_port = str(packet.udp.dstport)
            else:
                src_port = None
                dst_port = None

            G.add_edge(src_ip, dst_ip) # TODO improve

            # # Create nodes and relationships in Neo4j
            # if src_port and dst_port:
            #     #create_connection_nodes(src_ip, src_port, dst_ip, dst_port)
            # else:
            #     #create_connection_nodes_without_ports(src_ip, dst_ip)

        except Exception as e:
            print(f"Error processing packet: {e}")
            continue

    # Close the PCAP file
    pcap_file.close()
