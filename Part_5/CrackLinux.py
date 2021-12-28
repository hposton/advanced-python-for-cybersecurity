import passlib
from passlib.hash import sha512_crypt as sha512
from GenVariations import genVariations

def crackHash(h, salt, algo, passwords):
    if algo == "6":
        for p in passwords:
            result = sha512.hash(p,salt=salt,rounds=5000)
            vals = result.split("$")
            if h == vals[3]:
                return p

hashes = [
    "user1:$6$KXfkG0Wz$3WhIMhWFhgoYNLSDtkUZ13hoh0zIO0bpAJeJAEzKXKtcfgO9hR5NfjBFhZgiu0dW.aBctp.qDsaa.mWxCQfYW0:18836:0:99999:7:::","user2:$6$cU6D.uwD$gaBGSQq5/CE22AkmHHzOV8X2f4lgAAxMK5P.9t1D7tkfc9Y.OA4gLGcgsGwJfaJPbN18livNfCMk1yG0y4wWT1:18836:0:99999:7:::"]
passwords = genVariations("password")
for h in hashes:
    vals = h.split(":")
    user = vals[0]
    vals = vals[1].split("$")
    p = crackHash(vals[3],vals[2],vals[1],passwords)
    if p:
        print("%s: %s" % (user,p))