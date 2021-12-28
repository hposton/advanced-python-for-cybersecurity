import winreg

def subkeys(hive,path):
    try:
        key = winreg.OpenKey(hive,path)
    except Exception as e:
        return    
    numSubkeys = winreg.QueryInfoKey(key)[0]
    for i in range(numSubkeys):
        subkey = winreg.EnumKey(key,i)
        yield subkey

def values(hive,path):
    try:
        key = winreg.OpenKey(hive,path)
    except Exception as e:
        return
    numValues = winreg.QueryInfoKey(key)[1]
    for i in range(numValues):
        value = winreg.EnumValue(key,i)
        yield value

matches = {}
stringVals = [winreg.REG_SZ, winreg.REG_MULTI_SZ, winreg.REG_EXPAND_SZ]
def traverseSubkeys(name,hive,regpath,keywords):
    for value in values(hive,regpath):
        match = True in [k in value[0].lower() for k in keywords]
        if match and value[2] in stringVals:
            if len(value[1]) > 0 and not value[1].replace(".","",1).isdigit():
                print("%s\\%s\\%s: %s" % (name,regpath,value[0],value[1]))
    for subkey in subkeys(hive,regpath):
        subpath = "%s\\%s" % (regpath,subkey)
        match = True in [k in subkey.lower() for k in keywords]
        if match:
            val = winreg.QueryValue(hive,subpath)
            if len(val) > 0 and not val.replace(".","",1).isdigit():
                print("%s\\%s: %s" %(name,subpath,val))
            matches[subpath] = val
        traverseSubkeys(name,hive,subpath,keywords)

def searchRegistryKeys(hive,path,keyword):
    traverseSubkeys(hive[0],hive[1],path,keyword)

keywords = ["password","keyfile"]
for hive in [["HKLM",winreg.HKEY_LOCAL_MACHINE], ["HKCU",winreg.HKEY_CURRENT_USER],["HKU",winreg.HKEY_USERS]]:
    searchRegistryKeys(hive,r"SOFTWARE",keywords)