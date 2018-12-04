#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import socket
import io
import json
import sys
import traceback
from lib import DNSPacket

class FuYuanDNS:
    def __init__(self, data):
        self.data = data
        self.DNS = DNSPacket(data) 
        self.dnsType = self.DNS.dnsType
        self.dnsClass = self.DNS.dnsClass
        self.domainName = self.DNS.domainName

    def getRecord(self):
        try:
            rawJson = io.open("zone.json", 'r', encoding='UTF-8')
            jsonFile = rawJson.read()
            rawJson.close()
            data = json.loads(jsonFile)
            records = data["AnswerSection"]
            for item in records:
                if item["Name"] == self.domainName[:-1]:
                    self.address = item["Address"]
                    #print(item["Preference"])
                    try:
                        self.preference = item["Preference"] 
                    except:
                        self.preference = 10
            return True
        except BaseException as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            tb = traceback.extract_tb(exc_tb)[-1]
            print(exc_type, tb[2], tb[1])
            return None
    def server(self):
        try:
#        if self.dnsType == 12:
#            return self.DNS.ptr()
            if self.dnsType == 1: 
                self.getRecord()
                return self.DNS.A(self.address)
            elif self.dnsType == 2:
                self.getRecord()
                return self.DNS.NS(self.address)
            elif self.dnsType == 5: 
                self.getRecord()
                return self.DNS.CNAME(self.address)
            elif self.dnsType == 16:
                self.getRecord()
                return self.DNS.TXT(self.address)
            elif self.dnsType == 28:
                self.getRecord()
                return self.DNS.AAAA(self.address)
            elif self.dnsType == 15:
                self.getRecord()
                return self.DNS.MX(self.preference, self.address)
            else:
                self.address="None"
                return self.DNS.none()
        except:
            return self.DNS.none()
#            pass
if __name__  == "__main__":
    print("FuYuanDNS Server")
    while 1:
        udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udps.bind(('',53))
        data, addr = udps.recvfrom(1024)
        query = FuYuanDNS(data)
        try:
            udps.sendto(query.server(), addr)
            print("Client: ", addr[0], "Port: ", addr[1], "Query Type: ", query.dnsType, "Value: ", query.address)
        except BaseException as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            tb = traceback.extract_tb(exc_tb)[-1]
            print(exc_type, tb[2], tb[1])
 
            pass
