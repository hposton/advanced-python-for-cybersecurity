from pandas import Series
from scipy.stats import entropy

def calcEntropy(data):
    s = Series(data)
    counts = s.value_counts()
    return entropy(counts)

minLen = 5
def fieldEntropy(v):
    if type(v) in (str, bytes, bytearray):
        if type(v) is str:
            b = bytearray(v,"utf-8")
        else:
            b = bytearray(v)
        if len(b) >= minLen:
            e = calcEntropy(b)
            return e
        else:
            return None
    else:
        return None

print("%s Entropy: %s" % ("Hello world!",fieldEntropy("Hello world!")))
from random import randbytes
r = randbytes(12)
print("%s Entropy: %s"%(r,fieldEntropy(r)))