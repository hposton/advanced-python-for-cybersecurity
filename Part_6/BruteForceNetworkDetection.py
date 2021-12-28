from scapy.all import *

FTPconns = {}
failedFTP = {}
def FTPAnalysis(p):
    vals = p[Raw].load.strip().split()
    src = p[IP].src
    dst = p[IP].dst
    port = p[TCP].sport
    if vals[0] == b"USER":
        key = "%s->%s" % (src,dst)  # Client -> Server
        if not key in FTPconns:
            FTPconns[key] = {}
        FTPconns[key][port] = [vals[1].decode("utf-8"),"login"]
    elif vals[0] == b"PASS":
        key = "%s->%s" % (src,dst)
        if key in FTPconns:
            if port in FTPconns[key]:
                FTPconns[key][port][1] = "pass"
            else:
                print("Anomalous FTP PASS (%s) %s:%s" % (vals[1],key,port))
    elif vals[0] == b"530":
        key = "%s->%s" % (dst,src)  # Server -> Client
        port = p[TCP].dport
        if key in FTPconns:
            if port in FTPconns[key]:
                v = FTPconns[key].pop(port)
                if v[0] in failedFTP:
                    failedFTP[v[0]] += 1
                else:
                    failedFTP[v[0]] = 1

SSHconns = {}
failedSSH = {}
threshold = 5000
def SSHAnalysis(p):
    sIP = p[IP].src
    cIP = p[IP].dst
    key = "%s->%s" % (cIP,sIP)
    port = p[TCP].dport
    l = p[IP].len + 14
    if "F" in p[TCP].flags:
        b = SSHconns[key].pop(port)
        b += l
        if b < threshold:
            if key in failedSSH:
                failedSSH[key] += 1
            else:
                failedSSH[key] = 1
    else:
        if not key in SSHconns:
            SSHconns[key] = {}
        if port in SSHconns[key]:
            SSHconns[key][port] += l
        else:
            if "S" in p[TCP].flags:
                SSHconns[key][port] = l

def analyzePacket(p):
    if p.haslayer(TCP):
        if (p[TCP].sport == 21 or p[TCP].dport == 21) and p.haslayer(Raw):
            FTPAnalysis(p)
        elif (p[TCP].sport == 22):
            SSHAnalysis(p)

def printResults(openConns,failed,protocol):
    print("Open %s Connections: " % protocol)
    for conn in openConns:
        c = openConns[conn]
        if len(c) > 0:
            print(conn)
            for p in c:
                print("\t Port: %s User: " % (p,c[p]))
    print("Failed %s Logins: "% protocol)
    for f in failed:
        print("\t%s: %d" % (f,failed[f]))

#sniff(offline="bruteforce.pcap",prn=analyzePacket)
sniff(offline="ssh.pcapng",prn=analyzePacket)
#printResults(FTPconns,failedFTP,"FTP")
printResults(SSHconns,failedSSH,"SSH")