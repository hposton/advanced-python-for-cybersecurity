from scapy.all import *
from scapy.layers.http import *
from pandas import Series

threshold = 10

def calcuateLikelihood(feature):
    counts = Series(feature[:-1]).value_counts().to_dict()
    if feature[-1] in counts:
        return float(counts[feature[-1]])/float(len(feature))
    else:
        return .1/len(feature)

def extractHTTPRequest(p,features):
    features["Method"].append(p[HTTPRequest].Method)
    features["Path"].append(p[HTTPRequest].Path)
    features["Cookie"].append(p[HTTPRequest].Cookie)
    features["Host"].append(p[HTTPRequest].Host)
    features["Referer"].append(p[HTTPRequest].Referer)
    features["UserAgent"].append(p[HTTPRequest].User_Agent)
    if len(features["UserAgent"]) > threshold:
        probability = 1.0
        for feature in features:
            probability *= calcuateLikelihood(features[feature])
    else:
        probability = 1.0
    return [features,probability]

def extractHTTPResponse(p,features):
    features["StatusCode"].append(p[HTTPResponse].Status_Code)
    features["Server"].append(p[HTTPResponse].Server)
    if len(features["Server"]) > threshold:
        probability = 1.0
        for feature in features:
            probability *= calcuateLikelihood(features[feature])
    else:
        probability = 1.0
    return [features,probability]

def extractTCP(p,client,features):
    if client:
        port = p[TCP].dport
    else:
        port = p[TCP].sport
    features["port"].append(port)
    features["flags"].append(p[TCP].flags)
    if len(features["flags"]) > threshold:
        probability = 1.0
        for feature in features:
            probability *= calcuateLikelihood(features[feature])
    else:
        probability = 1.0
    return [features,probability]


def extractUDP(p,client,features):
    if client:
        port = p[UDP].dport
    else:
        port = p[UDP].sport
    features["port"].append(port)
    if len(features["port"]) > threshold:
        probability = 1.0
        for feature in features:
            probability *= calcuateLikelihood(features[feature])
    else:
        probability = 1.0
    return [features,probability]


def extractIP(p,client,features):
    if client:
        cIP = p[IP].src
        sIP = p[IP].dst
    else:
        cIP = p[IP].dst
        sIP = p[IP].src
    features["cIP"].append(cIP)
    features["sIP"].append(sIP)
    features["conn"].append("%s->%s" % (cIP,sIP))
    if len(features["conn"]) > threshold:
        probability = 1.0
        for feature in features:
            probability *= calcuateLikelihood(features[feature])
    else:
        probability = 1.0
    return [features,probability]


features = {}
num = 0
def processPacket(p):
    global features,num
    probs = 1.0
    if p.haslayer(IP):
        if p.haslayer(TCP):
            client = p[TCP].sport >= 49152
            features["TCP"],x = extractTCP(p,client,features["TCP"])
            probs *= x
        elif p.haslayer(UDP):
            client = p[UDP].sport >= 49152
            features["UDP"],x = extractUDP(p,client,features["UDP"])
            probs *= x
        else:
            return
        features["IP"],x = extractIP(p,client,features["IP"])
        probs *= x
        if p.haslayer(HTTPRequest):
            features["HTTPRequest"],x = extractHTTPRequest(p,features["HTTPRequest"])
            probs *= x
        if p.haslayer(HTTPResponse):
            features["HTTPResponse"],x = extractHTTPResponse(p,features["HTTPResponse"])
            probs *= x
    if probs != 1.0:
        print("Packet %d has probability %f" % (num,probs))
    num += 1

protos = {
    "IP": ["cIP","sIP","conn"],
    "TCP": ["port","flags"],
    "UDP": ["port"],
    "HTTPRequest": ["Method","Path","Cookie","Host","Referer","UserAgent"],
    "HTTPResponse": ["StatusCode","Server"]
}
def initDict():
    global features
    for p in protos:
        features[p] = {}
        for x in protos[p]:
            features[p][x] = []

initDict()
sniff(offline="http.cap",prn=processPacket)