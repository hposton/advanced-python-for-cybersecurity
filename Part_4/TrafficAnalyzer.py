from scapy.all import *
from scapy.layers.http import *
from pandas import Series
from Entropy import fieldEntropy
from CheckEncoding import checkEncoding

protocols = {}
targetLayers = ("Raw","DNS","HTTP Request","HTTP Response")
def protocolAnalysis(p):
    layers = p.layers()
    protos = [l.name for l in [p.getlayer(i) for i in range(len(layers))] if l.name in targetLayers]
    for proto in protos:
        if proto in protocols:
            protocols[proto] += 1
        else:
            protocols[proto] = 1
    return protos



def getFieldName(p,f):
    name = ""
    l = 0
    while p.getlayer(l).name != f:
        name += "%s:" % p.getlayer(l).name
        l += 1
    name += "%s" % p.getlayer(l).name
    return name

fields = {}
def fieldAnalysis(p,proto):
    x = getFieldName(p,proto)
    for f in p[proto].fields:
        v = p[proto].fields[f]
        e = fieldEntropy(v)
        if e:
            enc = checkEncoding(v)
            n = "%s:%s" % (x,f)
            if n in fields:
                fields[n]["entropy"].append(e)
                fields[n]["length"].append(len(v))
                fields[n]["encoding"].append(enc)
            else:
                fields[n] = {
                    "entropy":[e],
                    "length":[len(v)],
                    "encoding":[enc]}
    for pf in p[proto].packetfields:
        name = pf.name
        if p[proto].getfieldval(name):
            for f in p[proto].getfieldval(name).fields:
                v = p[proto].getfieldval(name).getfieldval(f)
                e = fieldEntropy(v)
                if e:
                    enc = checkEncoding(v)
                    n = "%s:%s:%s" % (x,name,f)
                    if n in fields:
                        fields[n]["entropy"].append(e)
                        fields[n]["length"].append(len(v))
                        fields[n]["encoding"].append(enc)
                    else:
                        fields[n] = {
                            "entropy":[e],
                            "length":[len(v)],
                            "encoding":[enc]}

def analyzeTraffic(p):
    protos = protocolAnalysis(p)
    for proto in protos:
        fieldAnalysis(p,proto)

#sniff(count=100,prn=analyzeTraffic)
sniff(offline="traffic.pcap",prn=analyzeTraffic)

for p in protocols:
    print(p,protocols[p])

for f in fields:
    # Calculate average entropy
    entropies = fields[f]["entropy"]
    e = sum(entropies)/len(entropies)
    
    # Calculate average length
    lengths = fields[f]["length"]
    l = sum(lengths)/len(lengths)
    
    # Calculate counts of each encoding
    s = Series(fields[f]["encoding"])
    #print(s)
    counts = s.value_counts().to_dict()
    url = counts["URL"]/len(lengths) if "URL" in counts else 0.0
    b64 = counts["B64"]/len(lengths) if "B64" in counts else 0.0
    print("%s\n\tCount: %d\n\tAverage Length: %f\n\tAverage Entropy: %f\n\tURL Encoded: %f\n\tBase64 Encoded: %f" % (f,len(lengths),l,e,url,b64))    
