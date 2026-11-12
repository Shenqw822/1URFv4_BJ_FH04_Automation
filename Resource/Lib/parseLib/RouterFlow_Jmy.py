#!/bin/bash/env python
# -*- coding:utf-8 -*-
# Author PeiWenPing
# time:2022/2/25:11:17
# email:peiwenping@finslink.com


from trex_stl_lib.api import *
from scapy.all import *
import binascii
import re
import os
import dpkt
import time
import datetime
import configparser


base = [str(x) for x in range(10)] + [chr(x)
                                      for x in range(ord('A'), ord('A') + 6)]

ID_TO_PRO = {
    132:"SCTP",
    1:"ICMP",
    2:"IGMP",
    6:"TCP",
    8:"EGP",
    9:"IGP",
    17:"UDP",
    42:"IPV6",
    47:"GRE",
    50:"ESP",
    51:"AH",
    58:"ICMPV6",
    89:"OSPF",
   112:"VRRP",
    115:"L2TP",
    253:'UNKNOW',
    0:"NO"
    }

BASE_DIR = os.getcwd()

split = lambda x,sep: str(x).split(sep) if x else x

class netflow:
    def __init__(self,configName):
        self.configName = configName
        self.config = configparser.ConfigParser()
        self.config.read(os.path.join(BASE_DIR, "%s.ini"%configName))

    def getNetflow(self,title='rule'):
        return dict(self.config[title])

class DdevieParsePacket:
    """通过 scapy包提供解析报文功能"""

    def __init__(self):
        self.pkts = ''


    def bj_net_flow(self, configName,pcapfile):
        with  open(pcapfile, 'rb') as fi:
            hello1 = dpkt.pcap.Reader(fi)
            simpleType = {}
            pkt_index = 0
            for timestamp,i in hello1:
                pkt_index += 1
                startwith=0
                flow_info = str(binascii.hexlify(bytes(i)),encoding="utf-8")
                if int(flow_info[124:128],16) == 0:continue
                common = netflow(configName).getNetflow("common")
                flow = netflow(configName).getNetflow("flow_v4") if int(flow_info[124:128], 16) == 350 else netflow(
                    configName).getNetflow("flow_v6")
                gap = 63 if int(flow_info[124:128],16) == 350 else 103
                comvalue = {}
                for key in common:
                    type = None if len(common[key].split(',')) == 2 else common[key].split(',')[2]
                    comvalue[key] =self.formatChange(flow_info[int(common[key].split(',')[0])*2:(int(common[key].split(',')[0])+int(common[key].split(',')[1]))*2],type)
                flow_packet = 0  #单包中所有流的包个数
                flow_bytes = 0   #单包中所有流的字节数
                for flowCnt in range(1,int(comvalue["count"])+1):
                    for flowvaule in flow:
                        typeva = None if len(flow[flowvaule].split(',')) == 2 else flow[flowvaule].split(',')[2]
                        comvalue["{}{}".format(flowvaule, flowCnt)] = self.formatChange(
                            flow_info[(int(flow[flowvaule].split(',')[0]) + startwith) * 2:(int(
                                flow[flowvaule].split(',')[0]) + int(
                                flow[flowvaule].split(',')[1]) + startwith) * 2], typeva)
                    if comvalue.get("{}{}".format("pkts", flowCnt)) :
                        flow_packet += comvalue["{}{}".format("pkts", flowCnt)]
                        #print(flow_packet)
                    if comvalue.get("{}{}".format("bytes", flowCnt)):
                        flow_bytes += comvalue["{}{}".format("bytes", flowCnt)]
                    startwith += gap


                comvalue["total_pkts"] = flow_packet
                comvalue["total_bytes"] = flow_bytes
                simpleType[pkt_index] = comvalue
                # if pkt_index == 27 :break        #提取个数限制

            return simpleType

    def formatChange(self,value,type=None):
        if str(type).lower() == 'ipv4':
            result = ".".join(str(int(value, 16) >> i & 0xFF) for i in (24, 16, 8, 0))
        elif str(type).lower() == 'ipv6':
            result = ":".join(re.findall(r'\w{4}', value))
        elif str(type).lower() == 'dec':
            # print(value)
            result = int(value,16)
        elif str(type).lower() == 'time':
            # print(value)
            time2 = datetime.datetime.fromtimestamp(int(value,16))
            result = time2.strftime("%Y.%m.%d-%H:%M:%S")
        elif str(type).lower() == 'mac':
            result = "-".join(re.findall(r'\w{2}', value))
        elif str(type).lower() == 'pro':
            result = ID_TO_PRO[int(value,16)]
        else:
            result = value
        return result

    def v6JianToQuan(self, v6Address):
        if "::" not in v6Address:
            return v6Address
        v6List = str(v6Address).split("::")
        if "" in v6List:  # 代表在前或后出现::
            befAft = v6List.index("")  # 0或1
            v6value = [x for x in v6List[1].split(':')]
            v6Zero = ['0000' for _ in range(8 - len(v6value))]
            if befAft:
                v6value = ["{:0>4}".format(x) for x in v6List[0].split(':')]
                v6Zero = ['0000' for _ in range(8 - len(v6value))]
                v6All = v6value + v6Zero
            else:
                v6value = ["{:0>4}".format(x) for x in v6List[1].split(':')]
                v6Zero = ['0000' for _ in range(8 - len(v6value))]
                v6All = v6Zero + v6value

        else:
            v6valuePre = ["{:0>4}".format(x) for x in v6List[0].split(':')]
            v6valueSuf = ["{:0>4}".format(x) for x in v6List[1].split(':')]
            v6Zero = ['0000' for _ in range(8 - len(v6valuePre + v6valueSuf))]
            v6All = v6valuePre + v6Zero + v6valueSuf
        return ":".join(v6All)

    def convert_to_xx00(self,input_string):
        byte_array = bytearray(input_string,'utf-8')
        hex_string = byte_array.hex()
        split_hex = [hex_string[i:i+2] for i in range(0,len(hex_string),2)]
        final_result ="\\x" + '\\x'.join(split_hex)
        return final_result

    def mult_bytes_to_one_byte(self, bytecounts, data, is_hex=False):
        """
        针对存在某个值对应的字节数字为多个的时候，需要针对数据实际占有字节数和帧格式中的字节个数不匹配需要考虑用0代替
        :param bytecounts: 帧格式中分配的字节数
        :param data: 实际的数据
        :return: 帧格式中每个字段的值 [a,b,c]
        """
        if is_hex:
            if int(bytecounts) == 1:
                data1 = data if len(data) == 2 else "0" + str(data)
                return data1
            else:
                if isinstance(data, list):
                    tmp = []
                    for i in data:
                        data1 = data if len(data) == 2 else "0" + str(data)
                        tmp.append(data1)
                    data_hex = ''.join(tmp)
                else:
                    # data1 = data if len(data) == bytecounts*2 else "0" + str(data)
                    data_hex = data
                # print(data_hex)
                # 先对实际数据进行处理，使得和其占用字节数进行对其 不足用0填充
                if len(data_hex) < int(bytecounts) * 2:
                    cha = int(bytecounts) * 2 - len(data_hex)
                    # new_data_hex = data_hex + '0' * cha
                    new_data_hex = '0' * cha + data_hex
                else:
                    new_data_hex = data_hex
        else:
            if int(bytecounts) == 1:
                return self.dec_to_hex(data[0])
            # 先转为16进制
            if isinstance(data, list):
                tmp = []
                for i in data:
                    tmp.append(self.dec_to_hex(i))
                data_hex = ''.join(tmp)
            else:
                data_hex = self.dec_to_hex(data)
            # print(data_hex)
            # 先对实际数据进行处理，使得和其占用字节数进行对其 不足用0填充
            if len(data_hex) < int(bytecounts) * 2:
                cha = int(bytecounts) * 2 - len(data_hex)
                # new_data_hex = data_hex + '0' * cha
                new_data_hex = '0' * cha + data_hex
            else:
                new_data_hex = data_hex
            # print(new_data_hex)  # 调试用
            # print(re.findall(r'\w{2}', new_data_hex)) # 调试用
            # 对新的数据进行按长度2进行分割，返回列表
        return re.findall(r'\w{2}', new_data_hex)

    def dec_to_hex(self, data):
        """
        10进制转为16进制，且去掉0x内容,且保证输出的都是两位
        :param data: 普通内容
        :return:
        """

        num = int(data)
        mid = []
        while True:
            if num == 0:
                break
            num, rem = divmod(num, 16)
            mid.append(base[rem])
        a = ''.join([str(x) for x in mid[::-1]])
        if len(a) == 1 and a:
            b = '0' + str(a)
        elif not a:
            b = '00'
        else:
            b = a
        return b



if __name__ == '__main__':

    time1 = time.time()
    hello = DdevieParsePacket()
    total_count = 0  #输出流统计计数
    total_bytes = 0   #输出流总字节数
    total_pkts = 0    #输出流总包个数
    ipfix_packet_count = 0  #输出IPFIX包个数
    s = hello.bj_net_flow("netflow_jmy","./IPFIX_IPv6_100W.pcap")
    # print(s)

    #print(type(s))
    #print(s)
    total_count = sum(entry['count'] for entry in s.values())
    total_bytes  = sum(entry['total_bytes'] for entry in s.values())
    total_pkts = sum(entry['total_pkts'] for entry in s.values())

    print('总流个数:',total_count)
    print('总字节：',total_bytes)
    print('总包个数:',total_pkts)
    time2=time.time()
    print("总共花费时间%ss"%(time2-time1))