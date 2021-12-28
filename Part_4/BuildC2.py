from scapy.all import *
from scapy.layers.http import *

settings = {
    "src": "127.0.0.1",
    "dst": "8.8.8.8"
}
def buildLayers(layers):
    p = Ether()/IP(src=settings["src"],dst=settings["dst"])
    for layer in layers.split(":")[2:]:
        try:
            layer = layer.replace(" ","")
            if layer == "HTTP1":
                layer = "HTTP"
            l = globals()[layer]()
            p.add_payload(l)
        except:
            return p
    return p

def setPayload(packet,layers,data):
    p = packet
    l = layers.split(":")
    for layer in l[:-1]:
        if packet.haslayer(layer):
            p = p[layer]
        else:
            p = getattr(p,layer)
    p.setfieldval(l[-1],data)
    return packet

layers = "Ethernet:IP:TCP:HTTP 1:HTTP Response:Raw:load"
packet = buildLayers(layers)
data = "Hello"
packet = setPayload(packet,layers,data)
packet.show()