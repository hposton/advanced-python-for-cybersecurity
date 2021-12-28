from itertools import product
from timeit import default_timer

def loadWords():
    with open("dictionary3000.txt","r") as f:
        words = f.read().split("\n")
    return words

def genRandomWordPasswords(num):
    words = loadWords()
    passwords = [""]
    for i in range(num):
        p = ["".join(p) for p in list(product(passwords,words))]
        passwords = p
    return passwords

start = default_timer()
genRandomWordPasswords(2)
stop = default_timer()
print("Runtime: %s" % (stop-start))