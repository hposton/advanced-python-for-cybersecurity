import requests

with open("vuldb_api.txt","r") as f:
    key = f.read()
def VuldbLookup(product,version=None):
    url = "https://vuldb.com/?api"
    if version:
        q = "product:%s,version:%s" % (product,version)
    else:
        q = "product:%s" % product
    query = {
        "apikey":key,
        "advancedsearch":q
    }
    results = requests.post(url,query)
    j = results.json()
    if "result" in j:
        sources = [result["source"] for result in j["result"] if "source" in result]
        return sources
    else:
        return []
