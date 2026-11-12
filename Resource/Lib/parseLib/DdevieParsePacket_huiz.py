#!/bin/bash/env python
# -*- coding:utf-8 -*-
# Author PeiWenPing
# time:2022/2/25:11:17
# email:peiwenping@finslink.com


from trex_stl_lib.api import *
from scapy.all import *
import scapy
import binascii
import re
import os
from scapy.utils import PcapReader

import time
import datetime

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
class DdevieParsePacket:
    """通过 scapy包提供解析报文功能"""

    def __init__(self):
        self.pkts = ''
        self.dst_mac = self._mac("dst")
        self.src_mac = self._mac("src")
        self.vlan_in_vlan = self.__vlan_in_vlan()

    def parser_pcapfile(self, pcapfile):
        """
        解析pcap文件转为对应的pkts
        :return: pkts
        """
        self.pkts = rdpcap(pcapfile)
        # self.pkts = PcapReader(pcapfile)
        # self.pkts =  RawPcapReader(pcapfile)
        self.dst_mac = self._mac("dst")
        self.src_mac = self._mac("src")
        self.vlan_in_vlan = self.__vlan_in_vlan()
        return len(self.pkts)

    def __change_mac_hex_to_bin(self, hex_data):
        """
        把对应的16进制转为2进制，且进行0补全
        :param hex_data 需要转化的16进制
        :return: bit_data
        """
        data_bit_tmp = int(str(hex_data).replace(':', ''), 16)
        data_bit_48 = '{:048b}'.format(data_bit_tmp)
        return data_bit_48

    def __change_dec_to_bin(self, dec_data, bit_len):
        """
        把对应的10进制转为2进制，位数不够进行0填充
        :param dec_data 10进制数据
        :param bit_len: 位数
        :return:
        """
        data_bit_tmp = int(str(dec_data).replace(',', ''), 10)
        c = '{:0%sb}' % bit_len
        data_bit = c.format(data_bit_tmp)
        return data_bit

    def _mac(self, mac_type):
        """
        按照要求提取对应的MACI地址信息
        :param mac_type src,dst
        :return:{pkindex,dst}
        """
        mac_dict = {}
        pkt_index = 0
        for i in self.pkts:
            pkt_index += 1
            if not i.haslayer(Ether):
                mac_dict[pkt_index] = '0' * 48
            else:
                mac = i['Ether'].dst if str(
                    mac_type).lower() == 'dst' else i['Ether'].src
                mac_dict[pkt_index] = self.__change_mac_hex_to_bin(mac)
        return mac_dict

    def __vlan_in_vlan(self):
        """
        按要求提取二层vlan信息
        cfi对那个scapy解析后的id,vid对应vlan,type对应type,pri对应prio
        :return:
        """
        try:
            pkt_index = 0
            vlan_dict = {}
            for pkt in self.pkts:
                pkt_index += 1
                if not pkt.haslayer(Dot1Q):
                    vlan_dict[pkt_index] = '0' * 64
                else:
                    vlan_0_type = self.__change_dec_to_bin(
                        pkt['Dot1Q'][0].type, 16)
                    vlan_0_prio = self.__change_dec_to_bin(
                        pkt['Dot1Q'][0].prio, 3)
                    vlan_0_cfi = self.__change_dec_to_bin(
                        pkt['Dot1Q'][0].id, 1)
                    vlan_0_vid = self.__change_dec_to_bin(
                        pkt['Dot1Q'][0].vlan, 12)
                    vlan_1_type = self.__change_dec_to_bin(
                        pkt['Dot1Q'][1].type, 16)
                    vlan_1_prio = self.__change_dec_to_bin(
                        pkt['Dot1Q'][1].prio, 3)
                    vlan_1_cfi = self.__change_dec_to_bin(
                        pkt['Dot1Q'][1].id, 1)
                    vlan_1_vid = self.__change_dec_to_bin(
                        pkt['Dot1Q'][1].vlan, 12)
                    vlan_dict[str(pkt_index)] = vlan_0_type + vlan_0_prio + vlan_0_cfi + \
                        vlan_0_vid + vlan_1_type + vlan_1_prio + vlan_1_cfi + vlan_1_vid

            return vlan_dict
        except BaseException:
            pass

    def fh8108(self):
        """
        提取需要验证的appid和入端口，且组合成appid和interface输出
        :return {pkindex1:[appid,interface],pkindex2:[appid,interface]...]
        """
        src_dict = {}
        for i in self.src_mac:
            # appid_bin = self.src_mac[i][0:7] + self.src_mac[i][8:24]
            # appid_dec = str(int(appid_bin, 2))
            slot_id_tmp = self.src_mac[i][24:32]
            slot_id = str(int(slot_id_tmp, 2))

            zika_id_tmp = self.src_mac[i][24:32]
            zika_id = str(int(zika_id_tmp, 2))
            device_id_tmp = self.src_mac[i][32:40]
            device_id = str(int(device_id_tmp, 2))
            # interface = str(int(self.src_mac[i][24:32], 2)) + "/" + str(int(self.src_mac[i][32:40], 2))
            interface = str(
                int(self.src_mac[i][8:12], 2)) + "/" + str(int(self.src_mac[i][12:20], 2))
            src_dict[str(i)] = [slot_id, interface, device_id, zika_id]
        return src_dict

    def direct_copy(self, d_g='d'):
        """
        直接复制输出的信息：目的mac、源mac
        目的MAC格式：
        47~41 | 40 | 39~24 |  23~16  | 15~13 |   12        |      11~0      |
        机器号| 0 |   0   | 输出组ID|   0   |D输入端口方向| D设备输入端口号|

        源MAC格式
        47~32 |    31~0       |
         0   | 复制流量ruleid |
         :param d_g d:D携带信息 g:携带信息 默认d
        :return:{pktindex:[src[0~48],dst[0~48]]
        """
        src_dict = {}
        if str(d_g).lower() == 'd':
            for i in self.src_mac:

                src_dict[str(i)] = [self.src_mac[i][0:16], self.src_mac[i][16:48]], [self.dst_mac[i][0:7], self.dst_mac[i][7],
                                                                                     self.dst_mac[i][8:24], self.dst_mac[i][24:32],
                                                                                     self.dst_mac[i][32:35], self.dst_mac[i][35],
                                                                                     self.dst_mac[i][36:48]]
        else:
            for i in self.src_mac:
                src_dict[str(i)] = [self.src_mac[i][0:16], self.src_mac[i][16:48]], [self.dst_mac[i][0:7],
                                                                                     self.dst_mac[i][7],
                                                                                     self.dst_mac[i][8:24],
                                                                                     self.dst_mac[i][24:32],
                                                                                     self.dst_mac[i][32:35],
                                                                                     self.dst_mac[i][35],
                                                                                     self.dst_mac[i][36:40],
                                                                                     self.dst_mac[i][40:48]]
        return src_dict

    def indirect_copy_not_specified(self, d_g='d'):
        """
        间接复制-非指定计算单元输出的信息：目的mac、源mac
        目的MAC格式：
        47~41 | 40 |        39~32     |      31~24   |      23~16    | 15~13 |      12      |      11~0      |
        机器号| 0 |  业务7~0输出标记 | 业务7 ACL组号|  业务6 ACL组号|   0   | D输入端口方向| D设备输入端口号|

        源MAC格式
        |      47~40    |      39~32     |       31~24     |       23~16     |        15~8      |       7~0      |
        | 业务5 ACL组号 |  业务4 ACL组号 |  业务3 ACL组号  |  业务2 ACL组号  |  业务1 ACL组号  |  业务0 ACL组号  |
         :param d_g d:D携带信息 g:携带信息 默认d
        :return: pktindex:[src[0~48],dst[0~48]]
        """
        src_dict = {}
        if str(d_g).lower() == 'd':
            for i in self.src_mac:
                src_dict[str(i)] = [self.src_mac[i][0:8], self.src_mac[i][8:16], self.src_mac[i][16:24], self.src_mac[i][24:32],
                                    self.src_mac[i][32:40], self.src_mac[i][40:48]], [self.dst_mac[i][0:7], self.dst_mac[i][7],
                                                                                      self.dst_mac[i][8:16],
                                                                                      self.dst_mac[i][16:24],
                                                                                      self.dst_mac[i][24:32],
                                                                                      self.dst_mac[i][32:35],
                                                                                      self.dst_mac[i][35],
                                                                                      self.dst_mac[i][36:48]]
        else:
            for i in self.src_mac:
                src_dict[str(i)] = [self.src_mac[i][0:8], self.src_mac[i][8:16], self.src_mac[i][16:24], self.src_mac[i][24:32],
                                    self.src_mac[i][32:40], self.src_mac[i][40:48]], [self.dst_mac[i][0:7], self.dst_mac[i][7],
                                                                                      self.dst_mac[i][8:16],
                                                                                      self.dst_mac[i][16:24],
                                                                                      self.dst_mac[i][24:32],
                                                                                      self.dst_mac[i][32:35],
                                                                                      self.dst_mac[i][35],
                                                                                      self.dst_mac[i][36:40],
                                                                                      self.dst_mac[i][40:48]]

        return src_dict

    def indirect_copy_specified(self, d_g='d'):
        """
        间接复制-指定计算单元输出的信息：vlan_in_vlan、目的mac、源mac
        目的MAC格式：
        |                   47~0           |
        |          业务7~4的计算单元       |

        源MAC格式
        |                   47~0           |
        |          业务3~0的计算单元       |

        802.1Q vlan

         type  |             PRI          |   CFI |       VID        |    TYPE  |       PRI      |  CFI  |             VID                |
        16 bit |            3 bit         | 1 bit |      12 bit      |   16bit  |      3bit     |  1 bit |            12 bit              |
        15~0   |  2~1 |        0          |   0   |      11~0        |   15~0   |      2~0     |    0    |      11~8    |      7~0        |
        0x8100|   0   | D设备输入端口方向 |   0   |  D设备输入端口号 |  0x8100  |  机器号6~4/7 |    0    |  机器号3~0/7 | 某业务的ACL组号 |
         :param d_g d:D携带信息 g:携带信息 默认d
        :return::{pktindex:[src[0~48],dst[0~48],vlan[]
        """
        src_dict = {}
        if str(d_g).lower() == 'd':
            for i in self.src_mac:
                src_dict[str(i)] = [self.src_mac[i][0:48], [self.dst_mac[i][0:48]], [self.vlan_in_vlan[i][0:16],
                                                                                     self.vlan_in_vlan[i][16:18],
                                                                                     self.vlan_in_vlan[i][18],
                                                                                     self.vlan_in_vlan[i][19],
                                                                                     self.vlan_in_vlan[i][20:32],
                                                                                     self.vlan_in_vlan[i][32:48],
                                                                                     self.vlan_in_vlan[i][48:51],
                                                                                     self.vlan_in_vlan[i][51],
                                                                                     self.vlan_in_vlan[i][52:56],
                                                                                     self.vlan_in_vlan[i][56:64]]]
        else:
            for i in self.src_mac:
                src_dict[str(i)] = [self.src_mac[i][0:48], [self.dst_mac[i][0:48]], [self.vlan_in_vlan[i][0:16],
                                                                                     self.vlan_in_vlan[i][16:18],
                                                                                     self.vlan_in_vlan[i][18],
                                                                                     self.vlan_in_vlan[i][19],
                                                                                     self.vlan_in_vlan[i][20:24],
                                                                                     self.vlan_in_vlan[i][24:32],
                                                                                     self.vlan_in_vlan[i][32:48],
                                                                                     self.vlan_in_vlan[i][48:51],
                                                                                     self.vlan_in_vlan[i][51],
                                                                                     self.vlan_in_vlan[i][52:56],
                                                                                     self.vlan_in_vlan[i][56:64]]]

        return src_dict

    def copy_mode_return_info(self, copy_mode, d_g='d', *args):
        """
        根据复制模式不一样返回对应的信息
        :param copy_mode: direction:直接复制模式,indirection_assigned:间接指定模式  indirection_unassigned:间接非指定模式
         :param d_g d:D携带信息 g:携带信息 默认d
        :param args: 可变长
        :return: pktindex:[src[0~48],dst[0~48]] or pktindex:[src[0~48],dst[0~48],vlan[]
        """
        if str(copy_mode).lower() == 'direction':
            return self.direct_copy(d_g)
        elif str(copy_mode).lower() == 'indirection_assigned':
            return self.indirect_copy_specified(d_g)
        else:
            return self.indirect_copy_not_specified(d_g)

    def make_compare_packet_info(
            self, org_pcapfile, d_out_pcapfile, hit_pktindex=0):
        """
        1.把d_out_pcapfile中每个包的smac和dmac换成org_pcapfile中的每个包的smac和dmac
        :param org_pcapfile:
        :param d_out_pcapfile:
        :return:[发送的pkts,修改后pkts]
        """
        change_pkt = []
        self.parser_pcapfile(org_pcapfile)
        org_pkts = self.pkts
        org_pkts_new = []
        self.parser_pcapfile(d_out_pcapfile)
        d_out_pkts = self.pkts
        # print(org_pkts[0].show())
        d_out_pkts_len = len(d_out_pkts)
        if not hit_pktindex:
            for pktindex in range(d_out_pkts_len):
                d_out_pkts[pktindex][Ether].src = org_pkts[pktindex][Ether].src
                d_out_pkts[pktindex][Ether].dst = org_pkts[pktindex][Ether].dst
                try:
                    d_out_pkts[pktindex][Padding] = org_pkts[pktindex][Padding]
                    d_out_pkts[pktindex][TCP].chksum = org_pkts[pktindex][TCP].chksum
                    d_out_pkts[pktindex][UDP].chksum = org_pkts[pktindex][UDP].chksum
                except BaseException:
                    pass
                change_pkt.append(d_out_pkts[pktindex][1:])
                org_pkts_new.append(org_pkts[pktindex][1:])
        else:
            pass
        return org_pkts_new, change_pkt

    def get_vlan_info(self, pcapfile):
        """
        获取pcapfile中包的vlan信息
        :param pcapfile: pcapfile文件
        :return: {pktindex:[vlan_layers,[vid1,vid2,...]]}
        """
        # 解析pcapfile
        self.parser_pcapfile(pcapfile)
        pkts = self.pkts
        return_info = {}
        pkts_len = len(pkts)
        # 以包序列号进行循环
        for pktindex in range(pkts_len):
            ad_count = 0
            q_count = 0
            vlan_id = []
            # 以每个包的layer进行判断是否含有vlan层
            for layer in pkts[pktindex].layers():
                if layer is scapy.layers.l2.Dot1AD:
                    vid = pkts[pktindex]['Dot1AD'][ad_count].vlan
                    vlan_id.append(vid)
                    ad_count += 1
                elif layer is scapy.layers.l2.Dot1Q:
                    vid = pkts[pktindex]['Dot1Q'][q_count].vlan
                    vlan_id.append(vid)
                    q_count += 1
            vlan_layer_count = ad_count + q_count
            if not vlan_id:
                vlan_id = 0
            return_info[pktindex] = [vlan_layer_count, vlan_id]
        return return_info

    def delete_first_vlan(self, pcapfile):
        """删除某一层vlan"""
        self.parser_pcapfile(pcapfile)
        pkts = self.pkts
        new_pkts = []
        for pkt in pkts:
            try:
                pkt.remove_underlayer(Dot1Q)
                print(pkt.show())
                time.sleep(1000)
            except BaseException:
                pass

    def extract_five_tuple_from_pcap(self, pcap_file, list_dict=1):
        """

        :param pcap_file: 解析的pcapfile
        :param list_dict: 1：返回list，0：返回dict
        :return:
        """
        # 读取pcap文件
        pktindex = 0
        packets = rdpcap(pcap_file)
        # 存储提取的五元组的列表
        five_tuple_all = [] if list_dict else {}

        # 遍历每个数据包
        for packet in packets:
            pktindex += 1
            # 检查是否有IP层
            if IP in packet or IPv6 in packet:
                ip_layer = packet[IP] if IP in packet else packet[IPv6]

                # 获取五元组信息
                src_ip = ip_layer.src if IP in packet else self.v6JianToQuan(ip_layer.src)
                dst_ip = ip_layer.dst if IP in packet else self.v6JianToQuan(ip_layer.dst)

                # 根据协议类型提取端口信息
                if TCP in ip_layer:
                    protocol = 'TCP'
                    src_port = ip_layer[TCP].sport
                    dst_port = ip_layer[TCP].dport
                elif UDP in ip_layer:
                    protocol = 'UDP'
                    src_port = ip_layer[UDP].sport
                    dst_port = ip_layer[UDP].dport
                elif SCTP in ip_layer:
                    protocol = 'SCTP'
                    src_port = ip_layer[SCTP].sport
                    dst_port = ip_layer[SCTP].dport
                else:
                    # 如果是其他协议，可以根据实际情况进行处理
                    protocol = 'Other'
                    src_port = 0
                    dst_port = 0

                # 将五元组信息添加到列表中
                five_tuple = [src_ip, src_port, dst_ip, dst_port, protocol]
                # print(five_tuple)
                if list_dict:
                    five_tuple_all.append(five_tuple)
                else:
                    five_tuple_all[pktindex] = five_tuple

        return five_tuple_all

    def extract_smac_from_pcap(self, pcap_file):

        packets = rdpcap(pcap_file)

        smac_list = []

        for packet in packets:
            if Ether in packet and IP in packet:
                smac = packet[Ether].src
                smac_list.append(smac)

        return smac_list

    def hash_and_remove_duplicates(self, path, pcap_file):
        # 读取pcap文件
        pcap_file_list = str(pcap_file).split(',')
        # 存储不重复hash结果的集合
        # unique_hashes = set()
        index = 1
        pktindex_hash = {}
        unique_hashes = []
        for file in pcap_file_list:
            packets = rdpcap(path + file)
            # 遍历每个数据包
            for packet in packets:
                # 获取报文的二进制表示
                packet_bytes = bytes(packet)
                # 计算hash值
                hash_result = hashlib.sha256(packet_bytes).hexdigest()
                # pktindex_hash[index] = hash_result
                # index += 1
                # 添加hash结果到集合中，集合会自动去重
                if hash_result not in unique_hashes:
                    unique_hashes.append(hash_result)

        # 将集合转换为列表
        # unique_hash_list = list(unique_hashes)
        #
        # return unique_hash_list
        return unique_hashes

    def hash_packets_except_smac(self, pcap_file):
        # 读取pcap文件
        packets = rdpcap(pcap_file)

        # 存储hash结果的列表
        hash_list = []

        # 遍历每个数据包
        for packet in packets:
            # 检查是否包含Ether层
            if Ether in packet:
                # 获取除了源MAC地址之外的报文字节
                packet_bytes = bytes(packet[Ether].payload)

                # 计算hash值
                hash_result = hashlib.sha256(packet_bytes).hexdigest()

                # 将hash结果添加到列表中
                hash_list.append(hash_result)

        return hash_list

    def parser_8101_r3(self, pcapfile):
        self.parser_pcapfile(pcapfile)
        """
              2024-01-23新增
              """
        padding_dict = {}
        pkt_index = 0
        for i in self.pkts:
            # print(i.show())
            pkt_index += 1
            if not i.haslayer(Raw):
                # padding_dict[pkt_index] = '0' * 48
                pass
            else:
                if str(binascii.hexlify(i[Raw].load), encoding="utf-8").lower().startswith('d1110201') or str(
                        binascii.hexlify(i[Raw].load), encoding="utf-8").lower().startswith('d1110203') or str(
                        binascii.hexlify(i[Raw].load), encoding="utf-8").lower().startswith('d1110221') or str(
                        binascii.hexlify(i[Raw].load), encoding="utf-8").lower().startswith('d11102fe') or str(
                        binascii.hexlify(i[Raw].load), encoding="utf-8").lower().startswith('d1110301') or str(
                        binascii.hexlify(i[Raw].load), encoding="utf-8").lower().startswith('d1110501'):
                    padding_dict[pkt_index] = i[Raw].load
        return padding_dict

    def bj_make(self, pcapfile, acl_starttime=0, acl_endtime=0):
        """
        根据pcapfile返回该pcap包含的流量大小，以及首包和尾部报间隔时间、和收报到达时间；当acl相关时间参数不为0也要同步返回对应的距离1970.1.1的s
        :param pcapfile:
        :param acl_starttime:
        :param acl_endstart:
        :return:[pcap文件中尾报和首包间隔时长,pcap文件中所有包的字节数相加后M表示,pcap第一个包到达时间unix,传递的规则中starttime转换成unix(未传则为0),传递的规则中endtime转换成unix(未传则为0)]
                ps:当包为空，则返回0,0,0
        """
        self.parser_pcapfile(pcapfile)
        if len(self.pkts) == 0:
            return 0, 0, 0
        arrive_time_first = self.pkts[0].time
        arrive_time_last = self.pkts[-1].time
        arrive_interval_time = arrive_time_last - arrive_time_first
        all_flow_byte = 0
        for i in range(len(self.pkts)):
            all_flow_byte += self.pkts[i].__len__()
        all_flow_m = all_flow_byte / 1024 / 1024
        if acl_starttime:
            time_get = datetime.datetime.strptime(
                "%s" % acl_starttime, "%Y.%m.%d-%H:%M:%S")
            acl_starttime_unix = time.mktime(time_get.timetuple())
        else:
            acl_starttime_unix = acl_starttime

        if acl_endtime:
            time_get = datetime.datetime.strptime(
                "%s" % acl_endtime, "%Y.%m.%d-%H:%M:%S")
            acl_endtime_unix = time.mktime(time_get.timetuple())
        else:
            acl_endtime_unix = acl_endtime

        return arrive_interval_time, all_flow_m, arrive_time_first

    def cli_time_epoc_switch(self, time1, format=0, interval_time=0):
        """
        设备时间和unix时间相互转换，并且增加上间隔时间
        :param time1: 要不unix，要不就是设备系统时间
        :param format:0:返回设备时间格式，1返回unix时间
        :param interval_time: 以秒为单位，在time1的基础上增加该时长
        :return:
        """
        if '-' in str(time1):
            time_get = datetime.datetime.strptime(
                "%s" % time1, "%Y.%m.%d-%H:%M:%S")
            time1_unix = time.mktime(time_get.timetuple())
            time1_unix_interval = time1_unix + int(interval_time)
        else:
            time1_unix_interval = time1 + int(interval_time)
        if not format:
            time2 = datetime.datetime.fromtimestamp(time1_unix_interval)
            device_time = time2.strftime("%Y.%m.%d-%H:%M:%S")
            return device_time
        else:
            return time1_unix_interval

    # def bj_net_flow(self, configName):
    #     simpleType = {}
    #     pkt_index = 0
    #     for i in self.pkts:
    #         common = confignetflow.netflow(configName).getNetflow("common")
    #         netflowv4 = confignetflow.netflow(configName).getNetflow("netflow_v4")
    #         netflowv6 = confignetflow.netflow(configName).getNetflow("netflow_v6")
    #         netflowv4Size = int(netflowv4.pop("size"))
    #         netflowv6Size = int(netflowv6.pop("size"))
    #
    #         pkt_index += 1
    #         flow_info = str(binascii.hexlify(bytes(i)),encoding="utf-8")
    #         # print(len(flow_info))
    #         comvalue = {}
    #         startwith = 0
    #         v4_flw = 0
    #         v6_flw = 0
    #         for key in common:
    #             type = None if len(common[key].split(',')) == 2 else common[key].split(',')[2]
    #             comvalue[key] =self.formatChange(flow_info[int(common[key].split(',')[0])*2:(int(common[key].split(',')[0])+int(common[key].split(',')[1]))*2],type)
    #         for flw_cnt in range(int(comvalue["fl_cnt"])):
    #             comvalue['first_zx_ip_ver'] = self.formatChange(flow_info[(int(netflowv4["zx_ip_ver"].split(',')[0])+startwith) * 2:(int(
    #                         netflowv4["zx_ip_ver"].split(',')[0]) + int(netflowv4["zx_ip_ver"].split(',')[1])+startwith) * 2], "dec")
    #             if comvalue['first_zx_ip_ver'] == 4:
    #                 for netflow in netflowv4:
    #                     typeva = None if len(netflowv4[netflow].split(',')) == 2 else netflowv4[netflow].split(',')[2]
    #                     comvalue["{}{}".format(netflow,flw_cnt)] = self.formatChange(flow_info[(int(netflowv4[netflow].split(',')[0])+startwith) * 2:(int(
    #                         netflowv4[netflow].split(',')[0]) + int(netflowv4[netflow].split(',')[1])+startwith) * 2], typeva)
    #                 startwith += netflowv4Size
    #                 v4_flw += 1
    #             elif comvalue['first_zx_ip_ver'] == 6:
    #                 for netflow in netflowv6:
    #                     typeva = None if len(netflowv6[netflow].split(',')) == 2 else netflowv6[netflow].split(',')[
    #                         2]
    #                     comvalue["{}{}".format(netflow,flw_cnt)] = self.formatChange(flow_info[(int(netflowv6[netflow].split(',')[0])+startwith) * 2:(int(netflowv6[netflow].split(',')[0]) + int(netflowv6[netflow].split(',')[1])+startwith) * 2], typeva)
    #                 startwith += netflowv6Size
    #                 v6_flw += 1
    #             comvalue["v4_flow_count"]=  v4_flw
    #             comvalue["v6_flow_count"] = v6_flw
    #             comvalue["cal_len"] = int(v4_flw)*netflowv4Size + int(v6_flw)*netflowv6Size + 46 +4
    #             simpleType[pkt_index] = comvalue
    #         # if pkt_index == 1 :break
    #     return simpleType

    def formatChange(self,value,type=None):
        if str(type).lower() == 'ipv4':
            result = ".".join(str(int(value, 16) >> i & 0xFF) for i in (24, 16, 8, 0))
        elif str(type).lower() == 'ipv6':
            result = ":".join(re.findall(r'\w{4}', value))
        elif str(type).lower() == 'dec':
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

    def changeVlanType(self,path=None):
        path = "C:\\Users\\peiwe\\Desktop\\1URFv4_SELF\\Resource\\Business\\raw_packets"
        vlanchange = []
        for home, folder, files in os.walk(path):
            if "tcc" in home: continue
            for file in files:
                if ".pcap" not in file or ".bak20240703" in file: continue
                pkindex = 0
                index = []
                value = []
                self.parser_pcapfile(home + "\\" + file)
                for pkt in self.pkts:
                    pkindex += 1
                    if hex(pkt['Ether'].type) == '0x88a8' or hex(pkt['Ether'].type) == '0x9100':
                        index.append(str(pkindex))
                        pkt['Ether'].type = int('0x8100',16)
                    value.append(pkt)
                if index:
                    wrpcap("{}\\{}".format(home, file), value)
                    # os.popen("copy {}\\{} {}\\{}.bak20240703".format(home,file,home,file))
                    vlanchange.append(home + "\\" + file)  # +" index {}".format(",".join(index)))
        return vlanchange

    def changeTcpchksum(self,path=None):
        vlanchange = []
        path = "C:\\Users\\peiwe\\Desktop\\1URFv4_SELF\\Resource\\Business\\raw_packets"
        for home,folder,files in os.walk(path):
            if "tcc" in home:continue
            for file in files:
                if ".pcap" not in file or ".bak20240703" in file: continue
                pkindex = 0
                index = []
                value = []
                self.parser_pcapfile(home+"\\"+file)
                for pkt in self.pkts:
                    pkindex += 1
                    if pkt.haslayer(TCP):
                        if hex(pkt['TCP'].chksum) == '0xffff':
                            index.append(str(pkindex))
                            pkt['TCP'].chksum = int('0x0000',16)
                            print(pkt.show())
                    value.append(pkt)

                if index :
                    print(home + "\\" + file)
                    wrpcap("{}\\{}".format(home, file),value)
                    # os.popen("copy {}\\{} {}\\{}.bak20240703".format(home,file,home,file))
                    vlanchange.append(home+"\\"+file)#+" index {}".format(",".join(index)))
        return vlanchange

    def filter(self, path=None,sep=None):
        vlanchange = []
        sep = '\\' if sep else '/'
        path = "C:{}Users{}peiwe{}Desktop{}test".format(sep,sep,sep,sep)
        for home, folder, files in os.walk(path):
            if "tcc" in home: continue
            for file in files:
                if "223.pcap" not in  file: continue
                print(file)
                pkindex = 0
                index = []
                value = []
                self.pkts = PcapReader(home + sep + file)
                for pkt in self.pkts:
                    # print(pkt.show())
                    # print(pkt.layers())
                    # print(pkt.show())
                    pkindex += 1
                    if pkt.haslayer(Radius):
                        print(pkt.show())
                        # if hex(pkt['TCP'].chksum) == '0xffff':
                        # pkt['UDP'].dport=18
                        # pkt['UDP'].sport=18


                        index.append(str(pkindex))
                        #     pkt['TCP'].chksum = int('0x0000', 16)
                        #     print(pkt.show())
                        value.append(pkt)
                if index:
                    print(home + sep + file)
                    # os.popen("copy {}{}{} {}{}{}.bak20240703".format(home,sep,file,home,sep,file))
                    wrpcap("{}{}{}".format(home,sep, file), value)
                    # os.popen("copy {}\\{} {}\\{}.bak20240703".format(home,file,home,file))
                    vlanchange.append(home + sep+ file)  # +" index {}".format(",".join(index)))
        return vlanchange

if __name__ == '__main__':

    time1 = time.time()
    hello = DdevieParsePacket()
    c = hello.filter()
    # # print(c)
    # # time.sleep(50)
    # d = hello.changeTcpchksum()
    # print(d)
    # time2 = time.time()
    # print("消耗时间{}".format(time2-time1))