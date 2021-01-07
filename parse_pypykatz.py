#!/usr/bin/env python3.7

import json

class bcolors:
    RED = '\033[1;31m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[94m'
    LIGREEN = '\033[92m'
    GREEN = '\033[0;32m'
    NORMAL = '\033[0m'
    TAN = '\033[0;33;33m'

def displayCreds():
    msvDict = {}
    wdigestDict = {}
    sspDict = {}
    sortedResults = []
    with open ("output.json","r") as file:
        jsonFileData = json.load(file)

        for jsonData in jsonFileData["lsass.DMP"]["logon_sessions"]:

            # Get the unique MSV Information from LSASS
            msvCreds = jsonFileData["lsass.DMP"]["logon_sessions"][jsonData]["msv_creds"]
            for data in msvCreds:
                if data["username"] not in msvDict:
                    msvDict.update({data["username"] : [[data["LMHash"],data["NThash"],data["domainname"]]]})
                else:
                    if [data["LMHash"],data["NThash"],data["domainname"]] not in msvDict[data["username"]]:
                        msvDict[data["username"]].append([data["LMHash"],data["NThash"],data["domainname"]])

            # Get the unique wDigest Information from LSASS
            wdigestCreds = jsonFileData["lsass.DMP"]["logon_sessions"][jsonData]["wdigest_creds"]
            for data in wdigestCreds:
                if data["password"] != None:
                    if data["username"] not in wdigestDict:
                        wdigestDict.update({data["username"] : [[data["password"],data["domainname"]]]})
                    else:
                        wdigestDict[data["username"]].append([data["password"],data["domainname"]])

            # Get the unique SSP Information from LSASS
            sspCreds = jsonFileData["lsass.DMP"]["logon_sessions"][jsonData]["ssp_creds"]
            for data in sspCreds:
                if data["password"] != None:
                    if data["username"] not in sspDict:
                        sspDict.update({data["username"] : [[data["password"],data["domainname"]]]})
                    else:
                        sspDict[data["username"]].append([data["password"],data["domainname"]])

        #print wdigest from LSASS JSON file
        if wdigestDict:    
            print (bcolors.LIGREEN + "[+]" + bcolors.BLUE + " wdigest:" + bcolors.NORMAL)
            for username, userInfo in wdigestDict.items():
                for item in userInfo:
                    print (bcolors.YELLOW + "\t%s\%s:%s" % (item[1],username,item[0]) + bcolors.NORMAL)

        #print credssp from LSASS JSON file
        if sspDict:
            print (bcolors.LIGREEN + "[+]" + bcolors.BLUE + " credssp:" + bcolors.NORMAL)
            for username, userInfo in sspDict.items():
                for item in userInfo:
                    if item[1] == '':
                        print (bcolors.YELLOW + "\t.\%s:%s" % (username,item[0]) + bcolors.NORMAL)
                    else:
                        print (bcolors.YELLOW + "\t%s\%s:%s" % (item[1],username,item[0]) + bcolors.NORMAL)

        #print msv from LSASS JSON file
        if msvDict:
            print (bcolors.LIGREEN + "[+]" + bcolors.BLUE + " msv:" + bcolors.NORMAL)
            for username, userInfo in msvDict.items():
                for item in userInfo:
                    if item[0] == None:
                        print (bcolors.YELLOW + "\t%s\%s:aad3b435b51404eeaad3b435b51404ee:%s" % (item[2],username,item[1]) + bcolors.NORMAL)
                    else:
                        print (bcolors.YELLOW + "\t%s\%s:%s:%s" % (item[2],username,item[0],item[1]) + bcolors.NORMAL)


    file.close()
    return

displayCreds()
print (bcolors.BLUE + "\n[*]" + bcolors.NORMAL + " Done!")
