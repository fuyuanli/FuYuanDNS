#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import ipaddress

class DNSPacket:
    def __init__(self, data):
        self.data = data
        self.dnsType = int(str("0x"+str(self.data[-3:-2])[4:6]), 16)
        self.dnsClass = int(str("0x"+str(self.data[-1:])[4:6]), 16)
        self.domainName = self.getDomianName() 
    def PTR(self):
        packet=b''
        packet+=self.data[:2]               # Transcation ID
        packet+=b'\x81\x80'                 # Flags: 0x8180 Standard query response, No error
        packet+=self.data[4:6]              # Questions
        packet+=self.data[4:6]              # Answer RRs
        packet+=b'\x00\x00'                 # Authority RRs
        packet+=b'\x00\x00'                 # Additional RRs
        packet+=self.data[12:]              # Original Domain Name Question
        packet+=b'\xc0\x0c'                 # Pointer to domain name
        packet+=b'\x00\x01'                 # Type
        packet+=b'\x00\x0c'                 # Class
        packet+=b'\x00\x00\x00\x3c'         # TTL
        for item in self.getDataLen(value):
            #print(item)
            tmp = chr(int(item, base=16)).encode('latin-1')
            packet+=tmp                     # Data Length
        packet+= self.domain2hex("dns.nttu.rclab") 
        packet+=b'\x00'
        return packet
    def A(self, ip=None):
        if ip is None:
            ip = "127.0.0.1"
        packet=b''
        packet+=self.data[:2]               # Transcation ID
        packet+=b'\x81\x80'                 # Flags: 0x8180 Standard query response, No error
        packet+=self.data[4:6]              # Questions
        packet+=self.data[4:6]              # Answer RRs
        packet+=b'\x00\x00'                 # Authority RRs
        packet+=b'\x00\x00'                 # Additional RRs
        packet+=self.data[12:]              # Original Domain Name Question
        packet+=b'\xc0\x0c'                 # Pointer to domain name
        packet+=b'\x00\x01'                 # Type
        packet+=b'\x00\x01'                 # Class
        packet+=b'\x00\x00\x00\x3c'         # TTL
        packet+=b'\x00\x04'                 # data length -> 4 bytes
        ip = ip.split('.') # 4bytes of IP
        for item in ip:
            tmp = chr(int(item)).encode('latin-1')
            packet+=tmp
        return packet

    def AAAA(self, ip=None):
        if ip is None:
            ip = "0000:0000:0000:0000:0000:0000:0000:0001"
        packet=b''
        packet+=self.data[:2]               # Transcation ID
        packet+=b'\x81\x80'                 # Flags: 0x8180 Standard query response, No error
        packet+=self.data[4:6]              # Questions
        packet+=self.data[4:6]              # Answer RRs
        packet+=b'\x00\x00'                 # Authority RRs
        packet+=b'\x00\x00'                 # Additional RRs
        packet+=self.data[12:]              # Original Domain Name Question
        packet+=b'\xc0\x0c'                 # Pointer to domain name
        packet+=b'\x00\x1c'                 # Type
        packet+=b'\x00\x01'                 # Class
        packet+=b'\x00\x00\x00\x3c'         # TTL
        packet+=b'\x00\x10'                 # data length -> 16 bytes
        v6List = self.v6ToList(ip)
        for item in v6List:
            tmp = chr(int(item, base=16)).encode('latin-1')
            packet+=tmp
        #print([hex(c) for c in packet])
        return packet
    
    def MX(self, preference=None, value=None):
        if preference is None:
            preference = 0
        if value is None:
            value = ""
        packet=b''
        packet+=self.data[:2]               # Transcation ID
        packet+=b'\x81\x80'                 # Flags: 0x8180 Standard query response, No error
        packet+=self.data[4:6]              # Questions
        packet+=self.data[4:6]              # Answer RRs
        packet+=b'\x00\x00'                 # Authority RRs
        packet+=b'\x00\x00'                 # Additional RRs
        packet+=self.data[12:]              # Original Domain Name Question
        packet+=b'\xc0\x0c'                 # Pointer to domain name
        packet+=b'\x00\x0f'                 # Type
        packet+=b'\x00\x01'                 # Class
        packet+=b'\x00\x00\x00\x3c'         # TTL
        for item in self.dataLen2hex(self.getDataLen(value)+2, 4):
#            print(item)
            tmp = chr(int(item, base=16)).encode('latin-1')
            packet+=tmp                     # Data Length
        #for item in self.preference2hex(preference):
        #    print(item)
        packet += chr(int(self.preference2hex(preference)[0], base=16)).encode('latin-1')
        packet += chr(int(self.preference2hex(preference)[1], base=16)).encode('latin-1')
        packet+=self.domain2hex(value) # Address
        packet+=b'\x00'
        return packet

    def CNAME(self, alias):
        packet=b''
        packet+=self.data[:2]               # Transcation ID
        packet+=b'\x81\x80'                 # Flags: 0x8180 Standard query response, No error
        packet+=self.data[4:6]              # Questions
        packet+=self.data[4:6]              # Answer RRs
        packet+=b'\x00\x00'                 # Authority RRs
        packet+=b'\x00\x00'                 # Additional RRs
        packet+=self.data[12:]              # Original Domain Name Question
        packet+=b'\xc0\x0c'                 # Pointer to domain name
        packet+=b'\x00\x05'                 # Type
        packet+=b'\x00\x01'                 # Class
        packet+=b'\x00\x00\x00\x3c'         # TTL
        for item in self.dataLen2hex(self.getDataLen(alias), 4):
#            print(item)
            tmp = chr(int(item, base=16)).encode('latin-1')
            packet+=tmp                     # Data Length
        #for item in self.preference2hex(preference):
        #    print(item)
        packet+=self.domain2hex(alias) # Address
        packet+=b'\x00'
        return packet

    def NS(self, alias):
        packet=b''
        packet+=self.data[:2]               # Transcation ID
        packet+=b'\x81\x80'                 # Flags: 0x8180 Standard query response, No error
        packet+=self.data[4:6]              # Questions
        packet+=self.data[4:6]              # Answer RRs
        packet+=b'\x00\x00'                 # Authority RRs
        packet+=b'\x00\x00'                 # Additional RRs
        packet+=self.data[12:]              # Original Domain Name Question
        packet+=b'\xc0\x0c'                 # Pointer to domain name
        packet+=b'\x00\x02'                 # Type
        packet+=b'\x00\x01'                 # Class
        packet+=b'\x00\x00\x00\x3c'         # TTL
        for item in self.dataLen2hex(self.getDataLen(alias), 4):
#            print(item)
            tmp = chr(int(item, base=16)).encode('latin-1')
            packet+=tmp                     # Data Length
        #for item in self.preference2hex(preference):
        #    print(item)
        packet+=self.domain2hex(alias) # Address
        packet+=b'\x00'
        return packet

    def TXT(self, content):
        packet=b''
        packet+=self.data[:2]               # Transcation ID
        packet+=b'\x81\x80'                 # Flags: 0x8180 Standard query response, No error
        packet+=self.data[4:6]              # Questions
        packet+=self.data[4:6]              # Answer RRs
        packet+=b'\x00\x00'                 # Authority RRs
        packet+=b'\x00\x00'                 # Additional RRs
        packet+=self.data[12:]              # Original Domain Name Question
        packet+=b'\xc0\x0c'                 # Pointer to domain name
        packet+=b'\x00\x10'                 # Type
        packet+=b'\x00\x01'                 # Class
        packet+=b'\x00\x00\x00\x3c'         # TTL
        for item in self.dataLen2hex(len(content)+1, 4):
#            print(item)
            tmp = chr(int(item, base=16)).encode('latin-1')
            packet+=tmp                     # Data Length

        #packet+=chr(int(len(content))).encode('latin-1') #TXT Length
        packet+=self.domain2hex(content) # TXT
        packet+=b'\x00'
        return packet


    def none(self):
        packet=b''
        packet+=self.data[:2]               # Transcation ID
        packet+=b'\x81\x83'                 # Flags: 0x8180 Standard query response, No error
        packet+=self.data[4:6]              # Questions
        #packet+=self.data[4:6]             # Answer RRs
        packet+=b'\x00\x00'                 # Answer RRs
        packet+=b'\x00\x00'                 # Authority RRs
        packet+=b'\x00\x00'                 # Additional RRs
        packet+=self.data[12:]              # Original Domain Name Question
        packet+=b'\xc0\x0c'                 # Pointer to domain name
        packet+=b'\x00\x01'                 # Type
        packet+=b'\x00\x01'                 # Class
        return packet


    def v6ToList(self, rawIPv6):
        IPv6 = ipaddress.ip_address(rawIPv6)
        IPv6 = IPv6.exploded
        list1 = IPv6.split(":")
        result = []
        for item in list1:
            for num in range(0, 4, 2):
                result.append(item[num:num+2])
        return result

    def getDomianName(self):
        domainName = ""
        data = self.data
        tipo = (data[2] >> 3) & 15   # Opcode bits
        if tipo == 0:                     # Standard query
            ini=12
            lon=data[ini]
            while lon != 0:
                domainName+=(data[ini+1:ini+lon+1].decode())+'.'
                ini+=lon+1
                lon=data[ini]
        return domainName

    def preference2hex(self, preference):
        hexString = hex(int(preference))[2:].zfill(4)
        hexList=[hexString[i:i+2] for i in range(0, 4, 2)]
        #print(hexList)
        return hexList

    def getDataLen(self, domainName):
        result = 0
        domainList = domainName.split(".")
        for item in domainList:
            result += 1
            result += len(item)
        result+=1
        return result
        #print("result", result)

    def dataLen2hex(self, result, digits):
        hexString = hex(int(result))[2:].zfill(digits)
        #print(hexString)
        hexList=[hexString[i:i+2] for i in range(0, digits, 2)]
        #print(hexList)
        return hexList
    def getDataLenNew(self, domainName):
        result = 0
        domainNameList = domainName.split("")


        
    def domain2hex(self, domainName):
        domainList = domainName.split(".")
        packet = b''
        for item in domainList:
            packet+=chr(int(hex(len(item)), base=16)).encode('latin-1')
            packet+=item.encode()
        return packet
