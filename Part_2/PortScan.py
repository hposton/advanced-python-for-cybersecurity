from scapy.all import *
import requests
ports = [20,21,22,23,25,53,69,80,110,143,161,162,389,443,445,636,8080,8443]

def SynScan(host):
    ans,unans = sr(IP(dst=host)/TCP(dport=ports,flags="S"),timeout=2,verbose=0)
    p = [s[TCP].dport for (s,r,) in ans if s[TCP].dport == r[TCP].sport and r[TCP].flags == "SA"]
    return p

def bannerGrab(ip,port):
    if port in [53,6980,443]:
        return ""
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip,port))
        banner = s.recv(1024)
        return banner.decode("utf-8")
    except:
        return

def HTTPHeaderGrab(ip,port):
    try:
        if port == 443:
            response = requests.head("https://%s:%s"%(ip,port),verify=False)
        else:
            response = requests.head("http://%s:%s"%(ip,port),verify=False)
        return response
    except Exception as e:
        print(e)
        return ""   
