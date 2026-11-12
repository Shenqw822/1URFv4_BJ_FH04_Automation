#!/bin/bash/env python
# -*- coding:utf-8 -*-
# Author PeiWenPing
# time:2022/2/25:11:17
# email:peiwenping@finslink.com


from trex_stl_lib.api import *
from scapy.all import *
import binascii
import time
import datetime


class Tc800ParsePacket:
    """通过 scapy包提供解析报文功能"""

    def __init__(self):
        self.pkts = ''
        self.padding = self._padding()

    def parser_pcapfile_padding(self, pcapfile):
        """
        解析pcap文件转为对应的pkts--使用其他外部接口前需要先调用该接口才生效
        :return: pkts
        """
        self.pkts = rdpcap(pcapfile)
        # self.pkts = PcapReader(pcapfile)
        # self.pkts =  RawPcapReader(pcapfile)
        self.padding = self._padding()
        return len(self.pkts)

    def __change_padding_hex_to_bin(self, padding):
        data_bit_tmp = int(str(padding), 16)
        data_bit_48 = '{:048b}'.format(data_bit_tmp)
        return data_bit_48

    def _padding(self):
        """
        2023-02-20新增
        返回padding内容（即finslink打标内容）
        """
        padding_dict = {}
        pkt_index = 0
        for i in self.pkts:
            pkt_index += 1
            if not i.haslayer(Padding):
                padding_dict[pkt_index] = '0' * 48
            else:
                # padding_dict[pkt_index] = self.__change_padding_hex_to_bin(i['Padding'])
                # padding_dict[pkt_index] = str(binascii.hexlify(i['Padding']), encoding="utf-8")
                if str(binascii.hexlify(i['Padding'].load),encoding="utf-8").startswith("46534c4b"):
                    padding_dict[pkt_index] = str(
                    binascii.hexlify(
                        i['Padding'].load),
                    encoding="utf-8")
                else:
                    padding_dict[pkt_index] = str(
                        binascii.hexlify(
                            i['Padding'].load),
                        encoding="utf-8")[8:]
        # print(padding_dict)
        return padding_dict

    def tlv_8808(self):
        """
        输出8808符合要求的打标字段--fpga
        filed_info:/46 53 4c 4b/tlv_class_type 2字节/tlv_class_len 2字节/tlv_type 2字节/tlv_len 2字节/tlv_data tlv_len/tlv_type 2字节/tlv_type 2字节/tlv_len 2字节/tlv_data tlv_len
        tlv_type 2字节/tlv_len 2字节/tlv_data tlv_len/tlv_total_len 2字节/46 53 4c 4b/
        :return {pktindex:filed_info}

        :return:
        """
        tlv_type = {
            17: "L2",
            18: "GTP",
            19: "DNS",
            20: "Radius",
            21: "TLS/SSL",
            22: "Rule IDs",
            23: "OTHER",
            24: "SESSION",
            25: "EMAIL",
            26: "TFTP",
            27: "FTP",
            28: "KERBEROS",
            29: "IPSEC",
            30: "LDAP/CLDAP",
            31: "DIAMETER",
            32: "NTLM",
            33: "SMB",
            34: "FEEDBACK",
            35: "S1AP",
            36: "HNBAP",
            37: "SIP",
            38: "RTP",
            39: "L2TP",
            40: "VXLAN",
            41: "GRE",
            42: "PPTP",
            43: "IPINIP",
            44: "TERDEM",
            45: "CAPWAP",
            46: "ERSPAN",
            47: "DATAGRAM",
            48: "GTP_TUNNEL",
            49: "IPSEC_TUNNEL",
            50: "COUNTRY",
            51: "ESP",
            52: "TCP",
            53: "GSMMAP",
            54: "HTTP",
            257: "CDP",
            258: "UDLD",
            259: "LLDP",
            260: "LACP" }
        tlv_dict = {}
        for i in self.padding:
            tlv1_len = int(self.padding[i][20:24],16)*2 + 24
            tlv2_len = int(self.padding[i][tlv1_len+4:tlv1_len+8],16)*2 + tlv1_len + 8
            tlv3_len =  int(self.padding[i][tlv2_len+4:tlv2_len+8],16)*2 + tlv2_len + 8
            tlv_dict[str(i)] = [self.padding[i][0:8],self.padding[i][8:12],self.padding[i][12:16],self.padding[i][16:20],self.padding[i][20:24],self.padding[i][24:tlv1_len],self.padding[i][tlv1_len:tlv1_len+4],
                                self.padding[i][tlv1_len+4:tlv1_len+8],self.padding[i][tlv1_len+8:tlv2_len],self.padding[i][tlv2_len:tlv2_len+4],
                                self.padding[i][tlv2_len+4:tlv2_len+8],self.padding[i][tlv2_len+8:tlv3_len],self.padding[i][tlv3_len:tlv3_len+4],self.padding[i][tlv3_len+4:tlv3_len+12]
                                ]
        return tlv_dict

    def net_flow_v4(self):
        """
        filed_info = [smac/dmac/sip/dip/protocol/sport/dport//version/flow_len/flow_srcip/flow_dstip/flow_sport/flow_dport/flow_protocol/flow_4/flow_Byte/00/flow_packet/00]
        :return {pktindex:filed_info}
        """
        flow_v4_dict = {}
        pkt_index = 0
        for i in self.pkts:
            pkt_index += 1
            flow_info = str(binascii.hexlify(i["Netflow DataFlowSet V9/10"]["Netflow DataFlowset Record V9/10"].fieldValue),encoding="utf-8")
            # print(flow_info)
            flow_v4_dict[pkt_index] = [i[Ether].src,i[Ether].dst,i[IP].version,i[IP].proto,i[IP].src,i[IP].dst,i[UDP].sport,i[UDP].dport,
                                       i["Netflow Header"].version,i["Netflow DataFlowSet V9/10"].length,flow_info[0:8],flow_info[8:16],
                                       flow_info[16:20],flow_info[20:24],flow_info[24:26],flow_info[26:28],flow_info[28:36],flow_info[36:38],flow_info[38:44],flow_info[44:48]]

        return flow_v4_dict

    def net_flow_v6(self):
        """
        filed_info = [smac/dmac/sip/dip/protocol/sport/dport//version/flow_len/flow_srcip/flow_dstip/flow_sport/flow_dport/flow_protocol/flow_4/flow_Byte/00/flow_packet/00]
        :return {pktindex:filed_info}
        """
        flow_v6_dict = {}
        pkt_index = 0
        for i in self.pkts:
            pkt_index += 1
            flow_info = str(
                binascii.hexlify(i["Netflow DataFlowSet V9/10"]["Netflow DataFlowset Record V9/10"].fieldValue),
                encoding="utf-8")
            # print(flow_info)
            flow_v6_dict[pkt_index] = [i[Ether].src, i[Ether].dst, i[IP].version, i[IP].proto, i[IP].src, i[IP].dst,
                                       i[UDP].sport, i[UDP].dport,
                                       i["Netflow Header"].version, i["Netflow DataFlowSet V9/10"].length,
                                       flow_info[32:64], flow_info[0:32],
                                       flow_info[64:68], flow_info[68:72], flow_info[72:74], flow_info[74:76],
                                       flow_info[76:84], flow_info[84:86], flow_info[86:92], flow_info[92:96]]

        return flow_v6_dict

    def extract_five_tuple_from_pcap(self):

        # 存储提取的五元组的列表
        five_tuple_list = []

        # 遍历每个数据包
        for packet in self.pkts:
            # 检查是否有IP层
            if IP in packet:
                ip_layer = packet[IP]

                # 获取五元组信息
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst

                # 根据协议类型提取端口信息
                if TCP in ip_layer:
                    protocol = 'TCP'
                    src_port = ip_layer[TCP].sport
                    dst_port = ip_layer[TCP].dport
                elif UDP in ip_layer:
                    protocol = 'UDP'
                    src_port = ip_layer[UDP].sport
                    dst_port = ip_layer[UDP].dport
                else:
                    # 如果是其他协议，可以根据实际情况进行处理
                    protocol = 'Other'
                    src_port = 0
                    dst_port = 0

                # 将五元组信息添加到列表中
                five_tuple = (src_ip, src_port, dst_ip, dst_port, protocol)
                five_tuple_list.append(five_tuple)

        return five_tuple_list
    #
    # def bj_make(self,pcapfile,acl_starttime=0,acl_endtime=0):
    #     """
    #     根据pcapfile返回该pcap包含的流量大小，以及首包和尾部报间隔时间、和收报到达时间；当acl相关时间参数不为0也要同步返回对应的距离1970.1.1的s
    #     :param pcapfile:
    #     :param acl_starttime:
    #     :param acl_endstart:
    #     :return:[pcap文件中尾报和首包间隔时长,pcap文件中所有包的字节数相加后M表示,pcap第一个包到达时间unix,传递的规则中starttime转换成unix(未传则为0),传递的规则中endtime转换成unix(未传则为0)]
    #     """
    #     self.parser_pcapfile_padding(pcapfile)
    #     arrive_time_first = self.pkts[0].time
    #     arrive_time_last = self.pkts[-1].time
    #     arrive_interval_time = arrive_time_last - arrive_time_first
    #     all_flow_byte = 0
    #     for i in range(len(self.pkts)):
    #         all_flow_byte += self.pkts[i].__len__()
    #     all_flow_m = all_flow_byte/1024/1024
    #     if acl_starttime:
    #         time_get = datetime.datetime.strptime("%s"%acl_starttime, "%Y.%m.%d-%H:%M:%S")
    #         acl_starttime_unix = time.mktime(time_get.timetuple())
    #     else:
    #         acl_starttime_unix = acl_starttime
    #
    #     if acl_endtime:
    #         time_get = datetime.datetime.strptime("%s"%acl_endtime, "%Y.%m.%d-%H:%M:%S")
    #         acl_endtime_unix = time.mktime(time_get.timetuple())
    #     else:
    #         acl_endtime_unix = acl_endtime
    #
    #     return arrive_interval_time,all_flow_m,arrive_time_first
    #
    # def cli_time_epoc_switch(self,time1,format=0,interval_time=0):
    #     """
    #     设备时间和unix时间相互转换，并且增加上间隔时间
    #     :param time1: 要不unix，要不就是设备系统时间
    #     :param format:0:返回设备时间格式，1返回unix时间
    #     :param interval_time: 以秒为单位，在time1的基础上增加该时长
    #     :return:
    #     """
    #     if '-' in str(time1):
    #         time_get = datetime.datetime.strptime("%s" % time1, "%Y.%m.%d-%H:%M:%S")
    #         time1_unix = time.mktime(time_get.timetuple())
    #         time1_unix_interval = time1_unix + interval_time
    #     else:
    #         time1_unix_interval = time1 + interval_time
    #     if not format:
    #         time2 = datetime.datetime.fromtimestamp(time1_unix_interval)
    #         device_time = time2.strftime("%Y.%m.%d-%H:%M:%S")
    #         return device_time
    #     else:
    #         return time1_unix_interval
    #



if __name__ == '__main__':
    # time_get = datetime.datetime.strptime("2024.02.22-15:00:00","%Y.%m.%d-%H:%M:%S")
    # print(time.mktime(time_get.timetuple()))
    #
    # hsstart = time.time()
    hello = Tc800ParsePacket()
    # hello.parser_pcapfile_padding('sss.pcap')
    # # # hello.parser_pcapfile('origin.pcap')
    # # print(hello.extract_five_tuple_from_pcap())
    # # hello.parser_pcapfile('netflow_ipv4_n100.pcap')
    # # print(hello.net_flow_v4())
    #
    # # print(hello.padding)
    # # print(hello.net_flow_v4())
    # # # print(hello.tlv_8808())
    # # starttime = time.ctime(hello.pkts[0].time)
    # # endtime = time.ctime(hello.pkts[-1].time)
    # starttime = hello.pkts[0].time
    # endtime = hello.pkts[-1].time
    # print("最开始和最后报文时间间隔%ds"%(endtime-starttime))
    # len_all = 0
    # for i in range(len(hello.pkts)):
    #     len_all += hello.pkts[i].__len__()
    # print("流量总大小%dM"%(len_all/1024/1024))
    # hsendtime = time.time()
    # print("耗时%s"%(hsendtime-hsstart))
    # # print(hello.pkts[0].protocols)
    dd = hello.cli_time_epoc_change("2024.02.22-15:00:05",1,5)
    print(dd)