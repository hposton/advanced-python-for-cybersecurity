import dns
import dns.resolver
import socket

dictionary = []
d = "subdomains.txt"
with open(d,"r") as f:
    dictionary = f.read().splitlines()

hosts = {}

def ReverseDNS(ip):
    try:
        result = socket.gethostbyaddr(ip)
        return [result[0]]+result[1]
    except socket.herror:
        return []

def DNSRequest(sub,domain):
    global hosts
    hostname = sub+domain
    try:
        result = dns.resolver.resolve(hostname)
        if result:
            for answer in result:
                ip = answer.to_text()
                hostnames = ReverseDNS(ip)
                subs = [sub]
                for hostname in hostnames:
                    if hostname.endswith(domain):
                        s = hostname.rstrip(domain)
                        subs.append(s)
                if ip in hosts:
                    s = hosts[ip]["subs"]
                    hosts[ip] = list(dict.fromkeys(s+subs))
                else:
                    hosts[ip] = list(dict.fromkeys(subs))
    except:
        return


def SubdomainSearch(domain,nums):
    successes = []
    for word in dictionary:
        DNSRequest(word,domain)
        if nums:
            for i in range(0,10):
                DNSRequest(word+str(i),domain)


def DNSSearch(domain,nums):
    SubdomainSearch(domain,nums)
    return hosts

"""domain = ".google.com"
hosts = DNSSearch(domain,True)
for ip in hosts:
    print(ip,hosts[ip])"""