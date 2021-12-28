import shodan

with open("shodan_api.txt","r") as f:
    key = f.read()
api = shodan.Shodan(key)

def queryShodan(query):
    hosts = {}
    try:
        results = api.search(query)
        for service in results["matches"]:
            ip = service["ip_str"]
            ports = service["port"]
            if ip in hosts:
                hosts[ip]["ports"] += ports
            else:
                hosts[ip] = {"ports":ports}
        return hosts
    except Exception as e:
        #print("Error %s" % e)
        return []

def ShodanLookup(ip):
    try:
        results = api.host(ip)
        records = []
        #print(results)
        for item in results["data"]:
            r = {
                "port":item["port"],
                "banner": item["data"]
            }
            if "product" in item:
                r["product"] = item["product"]
            if "version" in item:
                r["version"] = item["version"]
            if "cpe" in item:
                r["cpe"] = item["cpe"]
            records += [r]
        return records
    except Exception as e:
        #print(e)
        return []
