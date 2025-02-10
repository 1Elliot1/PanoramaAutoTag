import ipaddress
import requests
import pprint
import json
from panos.panorama import Panorama, DeviceGroup
from panos.objects import AddressObject
import xml.etree.ElementTree as ET
import ipaddress
from dotenv import load_dotenv
import os
import getpass
import netaddr
import urllib3
import re
import argparse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def keyGen(addressArg):
    print("Username: ")
    username = input()
    password = getpass.getpass()
    #send a key gen request with specified creds
    query = {'type':'keygen', 'user':username, 'password':password}
    response = requests.get(addressArg, params=query, verify=False)

    # Parse the XML string
    root = ET.fromstring(response.text)

    # Find the key element and grab string
    api_key = root.find(".//key").text
    envPath = '.env'

    #if .env exists, append new pan key
    if os.path.exists(envPath):
        with open(envPath, "a") as envFile:
            envFile.write(f"PAN_KEY={api_key}")
    else:
        #otherwise, create new .env and store key
        with open(envPath, "w") as envFile:
            envFile.write(f"PAN_KEY={api_key}")
    print("Key Successfully Saved To File")

def parseInterfaces(data):
    newData = []
    #check for the expected format of data
    if 'result' in data and 'entry' in data['result']:
        for mainInterface in data['result']['entry']:
            if 'layer3' in mainInterface and 'units' in mainInterface['layer3'] and 'entry' in mainInterface['layer3']['units']:
                for subInterface in mainInterface['layer3']['units']['entry']:
                    extractedInfo = {}
                    #Format map for each interface to append to a list of interface maps
                    extractedInfo['@name'] = subInterface.get('@name', 'N/A')
                    extractedInfo['tag'] = subInterface.get('tag', 'N/A')
                    extractedInfo['ip'] = subInterface['ip']['entry'][0].get('@name', 'N/A')
                    newData.append(extractedInfo)
    return newData

def tagIPObjects(ipObjects, vlanData, zoneData, headers, panHost):
    #(...Code below iterates through each IPObject...)
    tagCache = {}
    #Must iterate through each object in the environment
    for ipObject in ipObjects:
        #(...)
        tempAddr = ipObject.get('ip-netmask')
        ipAddress = ipObject.get('ip-netmask')
        vlanTag = None
        #Finding objects with single ip addr
        if '/32' in ipAddress or not '/' in ipAddress or ':' in ipAddress:
            ipAddress = [ipAddress.split('/')[0]]
        #Convert the range to required format if object is CIDR range
        elif '/' in ipAddress and '.' in ipAddress:
            ipAddress = convertRanges(ipAddress)
        if ipAddress != None and 'N' not in ipAddress:
            #iterate through each vlan in the env
            for vlan in vlanData:
                #compare if objects ip is within vlan range
                if ipInSubnet(ipAddress, vlan['ip']):
                    vlanTag = f"{vlan['tag']}"
                    #break out of loop for efficiency once found
                    break
        extHosts = []
        if not vlanTag:
            if isExternal(ipAddress):
                vlanTag = "External Host"
        if vlanTag:
            #if a tag applies, construct objects url 
            url = f"https://{panHost[0]}/restapi/v{panHost[1]}/Objects/Addresses?location={ipObject['@location']}&name={ipObject['@name']}"
            tagString = f'{vlanTag}'
            #find correlated zone tag if object is an internal host
            assignedZone = "N/A"
            if tagString != 'External Host':
                tagString = f'VLAN{vlanTag}'
                assignedZone = vlanInZone(vlanTag, zoneData)
                #(...Calls createTag below...)
            #create the correlated zone tag if found
            #These only create the tag within the environment, does not yet assign to objects
            if assignedZone is not None and assignedZone != "":
                createTag(assignedZone, headers, panHost, tagCache)
            #if tag can be created or exists construct member array of all object's tags
            if createTag(tagString, headers, panHost, tagCache):
                memberList = []
                if tagString:
                    memberList.append(tagString)
                if assignedZone:
                    memberList.append(str(assignedZone))
                #prexisting tags
                if ipObject.get('prevTags'):
                    memberList.extend(ipObject['prevTags'])
                #constructed object payload
                #Takes object info and applies the constructed tags as items within the tag dict's member list
                newPayload = {
                    'entry': {
                        '@location': ipObject['@location'],
                        '@name': ipObject['@name'],
                        'ip-netmask': ipObject['ip-netmask'],
                        'description': ipObject['description'],
                        'tag': {
                            'member':
                                memberList
                        }
                    }
                }

                #(... New IP Object Payload that appends new tags constructed above...)
                response = requests.request("PUT", url, headers=headers, json=newPayload, verify=False)
                if response.status_code == 200:
                    print(f"Tag '{tagString}' and '{assignedZone}' Added to IP Object {ipObject['@name']} Successfully")
                else:
                    print(f"Error Adding Tag '{tagString}' or '{assignedZone}' to IP Object {ipObject['@name']}: {response.text}\n{response.status_code}")

def convertRanges(objectRange):
    #convert cidr ranges to their lower and upper limits of ip addresses for comparison
    subnet = netaddr.IPNetwork(objectRange)
    lowerLim = subnet.network
    upperLim = subnet.broadcast
    #return limits in arr to compare if items fall within a given range
    return [lowerLim, upperLim]

def isExternal(address):
    privateIps = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '147.129.0.0/16']
    isExt = True
    #catches N/A and nonexistant netmasks
    if address is None or any(char.isalpha() for char in str(address)):
        return False
    #if ip isnt found in arr of private ips, must be external-- return true
    for priv in privateIps:
        if ipInSubnet(address, priv):
            isExt = False
    return isExt

#TODO: Brush up on
def parseZones(data):
    #parsing json for relevant fields
    if 'result' in data and 'entry' in data['result']:
        parsedZoneList = []
        for zone in data['result']['entry']:
            tempVlans = zone.get('network', {}).get('layer3', {}).get('member', [])
            splitVlans = []
            for vlan in tempVlans:
                #Formatting each VLAN before appending to list
                if 'ae' in vlan:
                    splitVlans.append(vlan.split('.')[1])
            #Construct a map of each zone's info and it's respective VLANs
            tempObject = {
                '@name': zone.get('@name'),
                '@location': zone.get('@location'),
                '@template': zone.get('@template'),
                '@vsys': zone.get('@vsys'),
                'vlans': splitVlans
            }
            parsedZoneList.append(tempObject)
        return parsedZoneList

def createTag(tagName, headers, panHost, cache={}):
    url = f"https://{panHost[0]}/restapi/v{panHost[1]}/Objects/Tags?location=shared&name={tagName}"
    payload = {
        'entry': [
            {
                '@name': tagName,
                'disable-override': 'no',
                'color': 'color1'
            }
        ]
    }
    #cache format: 'tagname': 'existsBoolean'
    if tagName in cache and cache[tagName]:
        print(f"Tag '{tagName}' Already Exists. Skipping Creation...")
        return True
    try:
        response = requests.request("POST", url, headers=headers, json=payload, verify=False)
        response.raise_for_status()
        print(f"Tag '{tagName}' Created Successfully")
        cache[tagName] = True
        return True

    except requests.exceptions.RequestException as e:
        if response.status_code == 409:
            #redundancy for catching prexisting tags being created
            print(f"Tag '{tagName}' Already Exists. Skipping Creation...")
            cache[tagName] = True
            return True
        else:
            print(f"Error Creating Tag '{tagName}': {e}")
            return False

#True if given address is in CIDR range
def ipInSubnet(ipAddresses, vlanRange):
    return all(ipaddress.ip_address(ip) in ipaddress.ip_network(vlanRange, strict = False) for ip in ipAddresses)

def vlanInZone(vlanTag, zoneData):
    #iterate through zones, each hold collection of vlans they encompass
    for zone in zoneData:
        if vlanTag in zone['vlans']:
            #Format tag
            return f"ZONE {zone['@name']}"
    return

def parseObjectMap(responseJSON):
    objectList = []
    if 'result' in responseJSON and 'entry' in responseJSON['result']:
        for objectInfo in responseJSON['result']['entry']:
            tempObject = {
                '@name': objectInfo.get('@name', 'N/A'),
                '@location': objectInfo.get('@location', 'N/A'),
                'ip-netmask': objectInfo.get('ip-netmask', 'N/A'),
                'ip-range': objectInfo.get('ip-range', 'N/A'),
                'description': objectInfo.get('description', ''),
                'prevTags': objectInfo.get('tag', {}).get('member', [])
            }
            objectList.append(tempObject)
    return objectList

#TODO Brush up on this function
def consolidateData(panHost, headers, targetTemplates):
    #Grab all vlan objects
    vlanData = []
    for x in targetTemplates:
        #constructed url of pre-acquired system details,
        #loops through each specified template
        url = f"https://{panHost[0]}/restapi/v{panHost[1]}/Network/AggregateEthernetInterfaces?location=template&template={x}"
        response = requests.request("GET", url, headers=headers, verify = False)
        responseDict = json.loads(response.text)
        parsed = parseInterfaces(responseDict)
        #(...Further parsing and formatting- the same is done for zoneData...)
        #loop through each interface map within list
        for item in parsed:
            #Join each template's collected interface maps to one list
            vlanData.append(item)

    zoneData = []
    for x in targetTemplates:
        #TODO: make setting vsys versatile
        vsys = 'vsys1'
        if x == 'IC-datacenter-template':
            vsys = 'IC-datacenter'
        url = f"https://{panHost[0]}/restapi/v{panHost[1]}/Network/Zones?location=template&template={x}&vsys={vsys}"
        response = requests.request('GET', url, headers=headers, verify=False)

        zoneDict = json.loads(response.text)
        parsedData = parseZones(zoneDict)
        #join each template's collected zone maps to one list
        for item in parsedData:
            zoneData.append(item)
    #raw json of all objects
    #TODO: make location and devicegroup parameters into variables for versatility (Make this entire section more versatile)
    url = f"https://{panHost[0]}/restapi/v{panHost[1]}/Objects/Addresses?location=device-group&device-group=IC-datacenter"
    response = requests.request('GET', url, headers=headers, verify=False)
    datacenterResponseDict = json.loads(response.text)

    url = f"https://{panHost[0]}/restapi/v{panHost[1]}/Objects/Addresses?location=shared"
    response = requests.request('GET', url, headers=headers, verify=False)
    sharedResponseDict = json.loads(response.text)
    #parse both location's objects into maps and consolidate into one list
    allObjects = parseObjectMap(sharedResponseDict) + parseObjectMap(datacenterResponseDict)
    #returns 3 collections of formatted data: zones, vlans, and all objects within the specified locations/groups 
    #for further processing and tagging
    return vlanData, zoneData, allObjects

def getSystemData(panHost, headers):
    #Send request to capture system data 
    url = f"https://{panHost[0]}/api?type=version&key={headers['X-PAN-KEY']}"
    response = requests.request("POST", url, headers=headers, verify=False)
    sysDict = {}
    #if request is successful, parse through response for relevant data
    if response.status_code == 200:
        try:
            #Use regex to search for specific lines in response
            vers = re.search(r'<sw-version>(.*?)</sw-version>', response.text)
            if vers:
                #(...further parsing of response and formatting into dictionary...)
                vers = vers.group(1)
                formatVers = vers.split('.')[0:2]
                vers =  '.'.join(formatVers)
                sysDict['vers'] = vers
            multiVsys = re.search(r'<multi-vsys>(.*?)</multi-vsys>', response.text)
            if multiVsys:
                multiVsys = multiVsys.group(1)
                sysDict['multiVsys'] = multiVsys
            model = re.search(r'<model>(.*?)</model>', response.text)
            if model:
                model = model.group(1)
                sysDict['model'] = model
            serialNum = re.search(r'<serial>(.*?)</serial>', response.text)
            if serialNum:
                serialNum = serialNum.group(1)
                sysDict['serialNum'] = serialNum
            return sysDict
        except (KeyError, json.JSONDecodeError) as e:
            print(f"Error Parsing JSON response: {e}")
    else:
        return response.status_code

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--address', help='Panorama address or URL', default='jsr-panorama.campus.ithaca.lan')
    parser.add_argument('-k', '--key', action="store_true", help="Create API Key")
    parser.add_argument('-t', '--templates', help="List of Target Panorama Templates. (Format: ['templateName', 'templateName'])", default=["IC-datacenter-template", "IC-perimeter-template", "PAP-pa820"])

    args = parser.parse_args()

    load_dotenv()
    # Panorama connect details
    panHost = [args.address, "N/A"]
    if args.key:
        keyGen(args.address)

    apiKey = os.getenv("PAN_KEY")
    targetTemplates = args.templates

    #Request headers
    headers = {
        'Content-Type': 'application/json',
        'X-PAN-KEY': apiKey
    }
    #grab system data
    sysData = getSystemData(panHost, headers)
    #assign version number to host details for passing in arguments 
    panHost[1] = sysData['vers']
    print(f"Panorama\tVersion:{sysData['vers']}\tModel:{sysData['model']}\tSerial:{sysData['serialNum']}\tMultiVsys:{sysData['multiVsys']}")

    vlanData, zoneData, objectData = consolidateData(panHost, headers, targetTemplates)
    tagIPObjects(objectData, vlanData, zoneData, headers, panHost)
    # Push changes to panorama (Would not automate this without extensive testing)
    # https://{{panos_host}}:{{port}}/api/?type=commit&key={{api_key}}&cmd=<commit></commit>

main()

