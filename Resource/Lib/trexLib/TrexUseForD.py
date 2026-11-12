#!/bin/bash/env python
# Author PeiWenPing
# time:2022/9/25 16:26
# email:peiwenping@finslink.com


import trex_stl_lib.api
from trex_stl_lib.api import *
import time
import math
import scapy


class TrexUseForD:

    def __init__(self, serverip, username, path_to_save_pcap, portid=1):
        self.serverip = serverip
        self.username = username
        self.portid = portid if isinstance(portid, int) else int(portid)
        self.path_to_save_pcap = path_to_save_pcap

    def __connect_server(self):
        conn = trex_stl_lib.api.STLClient(
            server=self.serverip, username=self.username)
        conn.connect()
        return conn

    def __prase_pcapfile(self, filename):
        file_all = len(filename)
        pkts = scapy.all.rdpcap(filename[0])
        filename_new = filename[1:]
        for file in filename_new:
            if file_all >1:
                pkts = pkts + scapy.all.rdpcap(file)
        return pkts

    def __trex_init(self, conn):
        h = conn.get_capture_status()
        active_cap = len(h.keys())
        if active_cap == 0:
            pass
        else:
            for i in h.keys():
                conn.stop_capture(i)
        conn.reset(self.portid)

    def __create_stream(self, filename, conn, is_order=True):
        times = 0
        pkts = self.__prase_pcapfile(filename)

        for pkt in pkts:
            times += 1
            stream = STLStream(packet=STLPktBuilder(pkt=pkt),
                               mode=STLTXSingleBurst(
                total_pkts=1, percentage=100), name=1)
            conn.add_streams(stream)
            if is_order:
                conn.start(force=True)
                conn.wait_on_traffic()
                conn.stop()
                conn.remove_all_streams()
            elif times == len(pkts):
                conn.start(force=True)
                conn.wait_on_traffic()
                conn.stop()
                conn.remove_all_streams()

    def __capture_start(self, conn, packgecount=1669600, bpf_fl=None):
        conn.set_service_mode(ports=self.portid, enabled=True)
        self.capture_rx = conn.start_capture(
            rx_ports=self.portid,
            limit=packgecount,
            mode='fixed',
            bpf_filter=bpf_fl)
        self.capture_tx = conn.start_capture(
            tx_ports=self.portid,
            limit=packgecount,
            mode='fixed',
            bpf_filter=bpf_fl)

    def __capture_stop(self, save_name, conn):
        path_to_save_pcap = str(time.time()) + "__" + save_name
        timestamp_tx = self.path_to_save_pcap + path_to_save_pcap + "tx"
        conn.stop_capture(self.capture_tx['id'], timestamp_tx + ".pcap")
        timestamp_rx = self.path_to_save_pcap + path_to_save_pcap + "rx"
        conn.stop_capture(self.capture_rx['id'], timestamp_rx + ".pcap")
        return timestamp_rx, timestamp_tx

    def Trex_load_pcap_burst(self, *filename, save_name):
        starttime = time.time()
        conn = self.__connect_server()
        try:
            self.__trex_init(conn)
            self.__capture_start(conn)
            conn.clear_stats()
            self.__create_stream(filename, conn=conn,is_order=True)
            rx, tx = self.__capture_stop(''.join(save_name), conn)
            time.sleep(3)
            stats = conn.get_stats()
        finally:
            conn.disconnect()
        endtime = time.time()
        print(endtime - starttime)
        print(stats['total'])
        return rx, tx

    def start_262144(self, *save_name):
        conn = self.__connect_server()
        try:
            self.__trex_init(conn)
            self.__capture_start(conn)
            conn.clear_stats()
            packet = (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00', type=2048) /
                      IP(ihl=5, len=110, id=1234, ttl=127, proto=6, chksum=64694, src='10.0.0.1') /
                      TCP(sport=1025, dport=1025, seq=129018, dataofs=5, reserved=2, flags=192, window=1024, chksum=46051,
                          options=[]) /
                      Raw(
                          load=b'\x00\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'))
            vm = STLVM()
            vm.var(
                name='ip_src',
                op='inc',
                step=1,
                size=4,
                min_value='10.0.0.1',
                max_value='10.4.0.0')
            vm.write(
                fv_name='ip_src',
                pkt_offset=26,
                add_val=0,
                byte_order='big')
            # vm.fix_chksum_hw(l3_offset='IP', l4_offset='TCP', l4_type=17)
            stream = STLStream(packet=STLPktBuilder(pkt=packet, vm=vm),
                               name='262144',
                               stream_id=0,
                               mac_src_override_by_pkt=False,
                               mac_dst_override_mode=0,
                               mode=STLTXSingleBurst(total_pkts=262144, percentage=1.0))

            conn.add_streams(stream)
            conn.start(force=True)
            conn.wait_on_traffic()
            conn.stop()
            conn.remove_all_streams()
            rx, tx = self.__capture_stop(''.join(save_name), conn)
        finally:
            conn.disconnect()
        return rx, tx

    def start_204800(self, *save_name):
        conn = self.__connect_server()
        try:
            self.__trex_init(conn)
            self.__capture_start(conn)
            conn.clear_stats()
            packet = (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00', type=2048) /
                      IP(ihl=5, len=110, id=1234, ttl=127, proto=6, chksum=64694, src='10.0.0.1', dst='192.168.100.1') /
                      TCP(sport=111, dport=222, seq=129018, dataofs=5, reserved=2, flags=192, window=1024, chksum=46051,
                          options=[]) /
                      Raw(
                          load=b'\x00\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'))
            vm = STLVM()
            vm.var(
                name='ip_src',
                op='inc',
                step=1,
                size=4,
                min_value='10.0.0.1',
                max_value='10.4.0.0')
            vm.write(
                fv_name='ip_src',
                pkt_offset=26,
                add_val=0,
                byte_order='big')
            # vm.fix_chksum_hw(l3_offset='IP', l4_offset='TCP', l4_type=17)
            stream = STLStream(packet=STLPktBuilder(pkt=packet, vm=vm),
                               name='262144',
                               stream_id=0,
                               mac_src_override_by_pkt=False,
                               mac_dst_override_mode=0,
                               mode=STLTXSingleBurst(total_pkts=204800, percentage=1.0))

            conn.add_streams(stream)
            conn.start(force=True)
            conn.wait_on_traffic()
            conn.stop()
            conn.remove_all_streams()
            rx, tx = self.__capture_stop(''.join(save_name), conn)
        finally:
            conn.disconnect()
        return rx, tx

    def start_attack(self, *save_name):
        conn = self.__connect_server()
        try:
            self.__trex_init(conn)
            self.__capture_start(conn)
            conn.clear_stats()
            packet = (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00', type=2048) /
                      IP(ihl=5, len=110, id=1234, ttl=127, proto=6, chksum=64694, src='1.1.1.1', dst='2.2.2.2') /
                      TCP(sport=1002, dport=1003, seq=129018, dataofs=5, reserved=2, flags=192, window=1024, chksum=46051,
                          options=[]) /
                      Raw(
                          load=b'\x00\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'))
            vm = STLVM()
            vm.var(
                name='ip_src',
                op='inc',
                step=1,
                size=4,
                min_value='1.1.1.1',
                max_value='255.255.255.255')
            vm.write(
                fv_name='ip_src',
                pkt_offset=26,
                add_val=0,
                byte_order='big')
            # vm.fix_chksum_hw(l3_offset='IP', l4_offset='TCP', l4_type=17)
            stream = STLStream(packet=STLPktBuilder(pkt=packet, vm=vm),
                               name='262144',
                               stream_id=0,
                               mac_src_override_by_pkt=False,
                               mac_dst_override_mode=0,
                               mode=STLTXSingleBurst(total_pkts=8388608, percentage=1.0))

            conn.add_streams(stream)
            conn.start(force=True)
            conn.wait_on_traffic()
            conn.stop()
            conn.remove_all_streams()
            rx, tx = self.__capture_stop(''.join(save_name), conn)
        finally:
            conn.disconnect()
        return rx, tx

    def Trex_capture(self, start_or_stop, capture_id=(0, 0), *save_name):
        conn = self.__connect_server()
        save_name = '' if not save_name else ''.join(save_name)
        try:
            if str(start_or_stop).lower() == 'start':
                self.__trex_init(conn)
                self.__capture_start(conn)
                rx = self.capture_rx
                tx = self.capture_tx
                print(rx, tx)
            elif str(start_or_stop).lower() == 'stop':
                path_to_save_pcap = str(time.time()) + "__" + save_name
                tx = self.path_to_save_pcap + path_to_save_pcap + "tx"
                conn.stop_capture(capture_id[1]['id'], tx + ".pcap")
                rx = self.path_to_save_pcap + path_to_save_pcap + "rx"
                conn.stop_capture(capture_id[0]['id'], rx + ".pcap")
        finally:
            conn.disconnect()
        return rx, tx

    def Trex_load_pcap_burst_no_oreder(self, filename, *save_name):
        starttime = time.time()
        conn = self.__connect_server()
        try:
            self.__trex_init(conn)
            self.__capture_start(conn)
            conn.clear_stats()
            self.__create_stream(filename, conn, is_order=False)
            rx, tx = self.__capture_stop(''.join(save_name), conn)
            time.sleep(3)
            stats = conn.get_stats()
        finally:
            conn.disconnect()
        endtime = time.time()
        print(endtime - starttime)
        print(stats['total'])
        return rx, tx

    def _inc_ipv6(ipv6_addr, count, step):
        """
        为实现ipv6地址递增增加的函数
        :param ipv6_addr:
        :return:
        """
        parts = ipv6_addr.split(':')
        ipv6_list = []
        for time in range(count):
            for i in range(len(parts) - 1, -1, -1):
                if parts[i].lower() == 'ffff':
                    parts[i] = '0'
                else:
                    parts[i] = str(hex(int(parts[i], 16) + int(step)))[2:]
                    break
            ipv6_list.append(':'.join(parts))
        return ipv6_list

    def start_src_dst_inc_dec(self, src_ip, dst_ip, count, step, step_index,
                              src_dst, inc_dec_random, sport=1024, dport=1024, *save_name):
        """

        :param src_ip: 源ip，支持v4/v6
        :param dst_ip: 目的ip，支持v4/v6
        :param count: 发送多少个包
        :param step: inc_dec设置步长,cong开始
        :param step_index: inc_dec设置对应的元素,字节数
        :param src_dst: inc_dec时指定src_ip或dst_ip
        :param inc_dec_random: 指定操作类型inc/dec/random
        :param save_name: 文件保存名
        :return: 返回tx/rx对应的pcap包
        """

        count = int(count)
        step = int(step)
        step_index = int(step_index)

        conn = self.__connect_server()
        try:
            self.__trex_init(conn)
            self.__capture_start(conn)
            conn.clear_stats()
            packet = (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00') / IPv6(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport))\
                if ':' in str(src_ip) \
                else (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00') / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport))
            v4_v6_dict = {'v4': {'src': [29, 28, 27, 26],
                                 'dst': [33, 32, 31, 30]},
                          'v6': {'src': [37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22],
                                 'dst': [53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38]}}
            v4_v6 = v4_v6_dict['v4'] if '.' in str(src_ip) \
                else v4_v6_dict['v6']
            v4_v6_src_dst = v4_v6['src'] if 'src' in str(src_dst).lower() \
                else v4_v6['dst']
            step_size = int(step)
            operation = str(inc_dec_random).lower()
            ip = src_ip if 'src' in str(src_dst) \
                else dst_ip
            iplist = ip.split('.') if '.' in str(src_ip) else ip.split(':')
            if ':' in str(src_ip):
                index = 0
                for item in iplist:
                    if len(item) < 4:
                        item1 = (4 - len(item)) * '0' + item
                        iplist[index] = item1
                        index += 1
                    else:
                        index += 1
                liplist_str = ''.join(iplist)
                iplist = re.findall(r'.{2}', liplist_str)
            iplist.reverse()
            one_byte = 256 // step_size
            for i in [1, 4, 8]:
                if i == 1:
                    if one_byte >= count:
                        byte_size = 1
                        break
                else:
                    if 256**(i - 1) * one_byte >= count:
                        byte_size = i
                        break
            minvalue = 0
            if '.' in str(src_ip):
                index_list = 0
                for value in iplist[int(step_index)
                                        :byte_size + int(step_index)]:
                    if iplist.index(value) == 0:
                        minvalue += int(value)
                        index_list += 1
                    else:
                        minvalue = minvalue + 256**index_list * int(value)
                        index_list += 1
            if ':' in str(src_ip):
                index_list = 0
                for value in iplist[int(step_index)
                                        :byte_size + int(step_index)]:
                    if iplist.index(value) == 0:
                        minvalue += int(value, 16)
                        index_list += 1
                    else:
                        minvalue = minvalue + 256**index_list * int(value, 16)
                        index_list += 1
            pkt_offset = v4_v6_src_dst[int(step_index) + byte_size - 1]
            vm = STLVM()
            vm.var(
                name='ip',
                op=operation,
                step=step_size,
                size=byte_size,
                min_value=minvalue,
                max_value=255**byte_size)
            vm.write(
                fv_name='ip',
                pkt_offset=pkt_offset,
                add_val=0,
                byte_order='big')
            stream = STLStream(packet=STLPktBuilder(pkt=packet, vm=vm),
                               name='ip_step',
                               stream_id=0,
                               mac_src_override_by_pkt=False,
                               mac_dst_override_mode=0,
                               mode=STLTXSingleBurst(total_pkts=count, percentage=30.0))
            conn.add_streams(stream)
            conn.start(force=True)
            conn.wait_on_traffic()
            conn.stop()
            conn.remove_all_streams()
            rx, tx = self.__capture_stop(''.join(save_name), conn)
        finally:
            conn.disconnect()
        return rx, tx

    def start_define(self, src_ip=0, dst_ip=0, sp=0, dp=0,
                     mbps=100000000, start_times=-1, *save_name):
        src_ip = "1.1.1.1" if not src_ip else src_ip
        dst_ip = "2.2.2.2" if not dst_ip else dst_ip
        sp = 1024 if not sp else sp
        dp = 1024 if not dp else dp
        conn = self.__connect_server()

        self.__trex_init(conn)
        self.__capture_start(conn)
        conn.clear_stats()
        packet = (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00', type=2048) /
                  IP(src=src_ip, dst=dst_ip) /
                  TCP(sport=sp, dport=dp, options=[]))
        stream = STLStream(packet=STLPktBuilder(pkt=packet),
                           mode=STLTXCont(percentage=20))

        conn.add_streams(stream)
        if not start_times:
            conn.start(force=True, duration=start_times)
        else:
            conn.start(force=True, duration=start_times)
            conn.wait_on_traffic()
        conn.stop()
        conn.remove_all_streams()
        rx, tx = self.__capture_stop(''.join(save_name), conn)
        # finally:
        conn.disconnect()
        return rx, tx

    def start_src_dst_inc_dec_fin(self, src_ip, dst_ip, count, step, step_index,
                                  src_dst, inc_dec_random, sport=1024, dport=1024, tcp_udp='tcp', *save_name):
        """

        :param src_ip: 源ip，支持v4/v6
        :param dst_ip: 目的ip，支持v4/v6
        :param count: 发送多少个包
        :param step: inc_dec设置步长,cong开始
        :param step_index: inc_dec设置对应的元素,字节数
        :param src_dst: inc_dec时指定src_ip或dst_ip
        :param inc_dec_random: 指定操作类型inc/dec/random
        :param save_name: 文件保存名
        :return: 返回tx/rx对应的pcap包
        """

        count = int(count)
        step = int(step)
        step_index = int(step_index)

        conn = self.__connect_server()
        try:
            self.__trex_init(conn)
            # self.__capture_start(conn)
            conn.clear_stats()
            if str(tcp_udp).lower() == 'tcp':
                packet = (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00') / IPv6(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport))\
                    if ':' in str(src_ip) \
                    else (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00') / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport))
            else:
                packet = (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00') / IPv6(src=src_ip, dst=dst_ip) / UDP(
                    sport=sport, dport=dport)) \
                    if ':' in str(src_ip) \
                    else (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00') / IP(src=src_ip, dst=dst_ip) / UDP(
                        sport=sport, dport=dport))
            v4_v6_dict = {'v4': {'src': [29, 28, 27, 26],
                                 'dst': [33, 32, 31, 30]},
                          'v6': {'src': [37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22],
                                 'dst': [53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38]}}
            v4_v6 = v4_v6_dict['v4'] if '.' in str(src_ip) \
                else v4_v6_dict['v6']
            v4_v6_src_dst = v4_v6['src'] if 'src' in str(src_dst).lower() \
                else v4_v6['dst']
            step_size = int(step)
            operation = str(inc_dec_random).lower()
            ip = src_ip if 'src' in str(src_dst) \
                else dst_ip
            iplist = ip.split('.') if '.' in str(src_ip) else ip.split(':')
            if ':' in str(src_ip):
                index = 0
                for item in iplist:
                    if len(item) < 4:
                        item1 = (4 - len(item)) * '0' + item
                        iplist[index] = item1
                        index += 1
                    else:
                        index += 1
                liplist_str = ''.join(iplist)
                iplist = re.findall(r'.{2}', liplist_str)
            iplist.reverse()
            one_byte = 256 // step_size
            for i in [1, 4, 8]:
                if i == 1:
                    if one_byte >= count:
                        byte_size = 1
                        break
                else:
                    if 256**(i - 1) * one_byte >= count:
                        byte_size = i
                        break
            minvalue = 0
            if '.' in str(src_ip):
                index_list = 0
                for value in iplist[int(step_index)
                                        :byte_size + int(step_index)]:
                    if iplist.index(value) == 0:
                        minvalue += int(value)
                        index_list += 1
                    else:
                        minvalue = minvalue + 256**index_list * int(value)
                        index_list += 1
            if ':' in str(src_ip):
                index_list = 0
                for value in iplist[int(step_index)
                                        :byte_size + int(step_index)]:
                    if iplist.index(value) == 0:
                        minvalue += int(value, 16)
                        index_list += 1
                    else:
                        minvalue = minvalue + 256**index_list * int(value, 16)
                        index_list += 1
            pkt_offset = v4_v6_src_dst[int(step_index) + byte_size - 1]
            vm = STLVM()
            vm.var(
                name='ip',
                op=operation,
                step=step_size,
                size=byte_size,
                min_value=minvalue,
                max_value=255**byte_size)
            vm.write(
                fv_name='ip',
                pkt_offset=pkt_offset,
                add_val=0,
                byte_order='big')
            stream = STLStream(packet=STLPktBuilder(pkt=packet, vm=vm),
                               name='ip_step',
                               stream_id=0,
                               mac_src_override_by_pkt=False,
                               mac_dst_override_mode=0,
                               mode=STLTXSingleBurst(total_pkts=count, percentage=8.0))
            conn.add_streams(stream)
            conn.start(force=True)
            conn.wait_on_traffic()
            conn.stop()
            conn.remove_all_streams()
            # rx, tx = self.__capture_stop(''.join(save_name), conn)
        finally:
            conn.disconnect()
        # return rx, tx
    # #暂时不用该函数，因为只支持sip,dip递增数量一致；后面优化了sip，dip递增数量分开的
    # def start_src_and_dst_inc_dec(self, src_ip, dst_ip, count, step, step_index, step1, step_index1, inc_dec_random_src,
    #                               inc_dec_random_dst, sport=1024, dport=1024, tcp_udp='tcp', *save_name):
    #     """
    #
    #     :param src_ip: 源ip，支持v4/v6
    #     :param dst_ip: 目的ip，支持v4/v6
    #     :param count: 发送多少个包
    #     :param step: src_inc_dec设置步长,cong开始
    #     :param step_index: src_inc_dec设置对应的元素,字节数
    #     :param step1: dst_inc_dec设置步长,cong开始
    #     :param step_index1: dst_inc_dec设置对应的元素,字节数
    #     :param inc_dec_random_src: 指定src操作类型inc/dec/random
    #      :param inc_dec_random_dst: 指定dst操作类型inc/dec/random
    #     :param save_name: 文件保存名
    #     :return: 返回tx/rx对应的pcap包
    #     """
    #
    #     count = int(count)
    #     conn = self.__connect_server()
    #     try:
    #         self.__trex_init(conn)
    #         # self.__capture_start(conn)
    #         conn.clear_stats()
    #         if str(tcp_udp).lower() == 'tcp':
    #             packet = (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00') / IPv6(src=src_ip, dst=dst_ip) / TCP(
    #                 sport=sport, dport=dport)) \
    #                 if ':' in str(src_ip) \
    #                 else (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00') / IP(src=src_ip, dst=dst_ip) / TCP(
    #                     sport=sport, dport=dport))
    #         else:
    #             packet = (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00') / IPv6(src=src_ip, dst=dst_ip) / UDP(
    #                 sport=sport, dport=dport)) \
    #                 if ':' in str(src_ip) \
    #                 else (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00') / IP(src=src_ip, dst=dst_ip) / UDP(
    #                     sport=sport, dport=dport))
    #         v4_v6_dict = {'v4': {'src': [29, 28, 27, 26],
    #                              'dst': [33, 32, 31, 30]},
    #                       'v6': {'src': [37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22],
    #                              'dst': [53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38]}}
    #         v4_v6 = v4_v6_dict['v4'] if '.' in str(src_ip) \
    #             else v4_v6_dict['v6']
    #         # src递增或递减
    #         v4_v6_src = v4_v6['src']
    #         v4_v6_dst = v4_v6['dst']
    #         step_size_src = int(step)
    #         step_size_dst = int(step1)
    #         operation_src = str(inc_dec_random_src).lower()
    #         operation_dst = str(inc_dec_random_dst).lower()
    #         src_iplist = src_ip.split('.') if '.' in str(
    #             src_ip) else src_ip.split(':')
    #         dst_iplist = dst_ip.split('.') if '.' in str(
    #             dst_ip) else dst_ip.split(':')
    #         if ':' in str(src_ip):
    #             index = 0
    #             for item in src_iplist:
    #                 if len(item) < 4:
    #                     item1 = (4 - len(item)) * '0' + item
    #                     src_iplist[index] = item1
    #                     index += 1
    #                 else:
    #                     index += 1
    #             src_iplist_str = ''.join(src_iplist)
    #             src_iplist = re.findall(r'.{2}', src_iplist_str)
    #         src_iplist.reverse()
    #         if ':' in str(dst_ip):
    #             index = 0
    #             for item in dst_iplist:
    #                 if len(item) < 4:
    #                     item1 = (4 - len(item)) * '0' + item
    #                     dst_iplist[index] = item1
    #                     index += 1
    #                 else:
    #                     index += 1
    #             dst_iplist_str = ''.join(dst_iplist)
    #             dst_iplist = re.findall(r'.{2}', dst_iplist_str)
    #         dst_iplist.reverse()
    #         one_byte_src = 256 // step_size_src
    #         one_byte_dst = 256 // step_size_dst
    #
    #         for i in [1, 4, 8]:
    #             if i == 1:
    #                 if one_byte_src >= count:
    #                     byte_size_src = 1
    #                     break
    #             else:
    #                 if 256 ** (i - 1) * one_byte_src >= count:
    #                     byte_size_src = i
    #                     break
    #         for i in [1, 4, 8]:
    #             if i == 1:
    #                 if one_byte_dst >= count:
    #                     byte_size_dst = 1
    #                     break
    #             else:
    #                 if 256 ** (i - 1) * one_byte_dst >= count:
    #                     byte_size_dst = i
    #                     break
    #         minvalue_src = 0
    #         if '.' in str(src_ip):
    #             index_list = 0
    #             for value in src_iplist[int(
    #                     step_index):byte_size_src + int(step_index)]:
    #                 if src_iplist.index(value) == 0:
    #                     minvalue_src += int(value)
    #                     index_list += 1
    #                 else:
    #                     minvalue_src = minvalue_src + \
    #                         256 ** index_list * int(value)
    #                     index_list += 1
    #         if ':' in str(src_ip):
    #             index_list = 0
    #             for value in src_iplist[int(
    #                     step_index):byte_size_src + int(step_index)]:
    #                 if src_iplist.index(value) == 0:
    #                     minvalue_src += int(value, 16)
    #                     index_list += 1
    #                 else:
    #                     minvalue_src = minvalue_src + \
    #                         256 ** index_list * int(value, 16)
    #                     index_list += 1
    #         minvalue_dst = 0
    #         if '.' in str(src_ip):
    #             index_list = 0
    #             for value in dst_iplist[int(
    #                     step_index1):byte_size_dst + int(step_index1)]:
    #                 if dst_iplist.index(value) == 0:
    #                     minvalue_dst += int(value)
    #                     index_list += 1
    #                 else:
    #                     minvalue_dst = minvalue_dst + \
    #                         256 ** index_list * int(value)
    #                     index_list += 1
    #         if ':' in str(src_ip):
    #             index_list = 0
    #             for value in dst_iplist[int(
    #                     step_index1):byte_size_dst + int(step_index1)]:
    #                 if dst_iplist.index(value) == 0:
    #                     minvalue_dst += int(value, 16)
    #                     index_list += 1
    #                 else:
    #                     minvalue_dst = minvalue_dst + \
    #                         256 ** index_list * int(value, 16)
    #                     index_list += 1
    #
    #         pkt_offset_src = v4_v6_src[int(step_index) + byte_size_src - 1]
    #         pkt_offset_dst = v4_v6_dst[int(step_index1) + byte_size_dst - 1]
    #         vm = STLVM()
    #         vm.var(
    #             name='src',
    #             op=operation_src,
    #             step=step_size_src,
    #             size=byte_size_src,
    #             min_value=minvalue_src,
    #             max_value=255 ** byte_size_src)
    #         vm.write(
    #             fv_name='src',
    #             pkt_offset=pkt_offset_src,
    #             add_val=0,
    #             byte_order='big')
    #         vm.var(
    #             name='dst',
    #             op=operation_dst,
    #             step=step_size_dst,
    #             size=byte_size_dst,
    #             min_value=minvalue_dst,
    #             max_value=255 ** byte_size_dst)
    #         vm.write(
    #             fv_name='dst',
    #             pkt_offset=pkt_offset_dst,
    #             add_val=0,
    #             byte_order='big')
    #         stream = STLStream(packet=STLPktBuilder(pkt=packet, vm=vm),
    #                            name='ip_step',
    #                            stream_id=0,
    #                            mac_src_override_by_pkt=False,
    #                            mac_dst_override_mode=0,
    #                            mode=STLTXSingleBurst(total_pkts=count, percentage=8.0))
    #
    #         conn.add_streams(stream)
    #         conn.start(force=True)
    #         conn.wait_on_traffic()
    #         conn.stop()
    #         conn.remove_all_streams()
    #         # rx, tx = self.__capture_stop(''.join(save_name), conn)
    #     finally:
    #         conn.disconnect()
    #     # return rx, tx

    def start_src_and_dst_inc_dec(self, src_ip, dst_ip, count_src, count_dst, step, step_index, step1, step_index1, inc_dec_random_src,
                                  inc_dec_random_dst, sport=1024, dport=1024, tcp_udp='tcp', *save_name):
        """

        :param src_ip: 源ip，支持v4/v6
        :param dst_ip: 目的ip，支持v4/v6
        :param count: 发送多少个包
        :param step: src_inc_dec设置步长,cong开始
        :param step_index: src_inc_dec设置对应的元素,字节数
        :param step1: dst_inc_dec设置步长,cong开始
        :param step_index1: dst_inc_dec设置对应的元素,字节数
        :param inc_dec_random_src: 指定src操作类型inc/dec/random
         :param inc_dec_random_dst: 指定dst操作类型inc/dec/random
        :param save_name: 文件保存名
        :return: 返回tx/rx对应的pcap包
        """

        count_src = int(count_src)
        count_dst = int(count_dst)
        conn = self.__connect_server()
        try:
            self.__trex_init(conn)
            # self.__capture_start(conn)
            conn.clear_stats()
            if str(tcp_udp).lower() == 'tcp':
                packet = (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00') / IPv6(src=src_ip, dst=dst_ip) / TCP(
                    sport=sport, dport=dport)) \
                    if ':' in str(src_ip) \
                    else (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00') / IP(src=src_ip, dst=dst_ip) / TCP(
                        sport=sport, dport=dport))
            else:
                packet = (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00') / IPv6(src=src_ip, dst=dst_ip) / UDP(
                    sport=sport, dport=dport)) \
                    if ':' in str(src_ip) \
                    else (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00') / IP(src=src_ip, dst=dst_ip) / UDP(
                        sport=sport, dport=dport))
            v4_v6_dict = {'v4': {'src': [29, 28, 27, 26],
                                 'dst': [33, 32, 31, 30]},
                          'v6': {'src': [37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22],
                                 'dst': [53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38]}}
            v4_v6 = v4_v6_dict['v4'] if '.' in str(src_ip) \
                else v4_v6_dict['v6']
            # src递增或递减
            v4_v6_src = v4_v6['src']
            v4_v6_dst = v4_v6['dst']
            step_size_src = int(step)
            step_size_dst = int(step1)
            operation_src = str(inc_dec_random_src).lower()
            operation_dst = str(inc_dec_random_dst).lower()
            src_iplist = src_ip.split('.') if '.' in str(
                src_ip) else src_ip.split(':')
            dst_iplist = dst_ip.split('.') if '.' in str(
                dst_ip) else dst_ip.split(':')
            if ':' in str(src_ip):
                index = 0
                for item in src_iplist:
                    if len(item) < 4:
                        item1 = (4 - len(item)) * '0' + item
                        src_iplist[index] = item1
                        index += 1
                    else:
                        index += 1
                src_iplist_str = ''.join(src_iplist)
                src_iplist = re.findall(r'.{2}', src_iplist_str)
            src_iplist.reverse()
            if ':' in str(dst_ip):
                index = 0
                for item in dst_iplist:
                    if len(item) < 4:
                        item1 = (4 - len(item)) * '0' + item
                        dst_iplist[index] = item1
                        index += 1
                    else:
                        index += 1
                dst_iplist_str = ''.join(dst_iplist)
                dst_iplist = re.findall(r'.{2}', dst_iplist_str)
            dst_iplist.reverse()
            one_byte_src = 256 // step_size_src
            one_byte_dst = 256 // step_size_dst

            for i in [1, 4, 8]:
                if i == 1:
                    if one_byte_src >= count_src:
                        byte_size_src = 1
                        break
                else:
                    if 256 ** (i - 1) * one_byte_src >= count_src:
                        byte_size_src = i
                        break
            for i in [1, 4, 8]:
                if i == 1:
                    if one_byte_dst >= count_dst:
                        byte_size_dst = 1
                        break
                else:
                    if 256 ** (i - 1) * one_byte_dst >= count_dst:
                        byte_size_dst = i
                        break
            minvalue_src = 0
            if '.' in str(src_ip):
                index_list = 0
                for value in src_iplist[int(
                        step_index):byte_size_src + int(step_index)]:
                    if src_iplist.index(value) == 0:
                        minvalue_src += int(value)
                        index_list += 1
                    else:
                        minvalue_src = minvalue_src + \
                            256 ** index_list * int(value)
                        index_list += 1
            if ':' in str(src_ip):
                index_list = 0
                for value in src_iplist[int(
                        step_index):byte_size_src + int(step_index)]:
                    if src_iplist.index(value) == 0:
                        minvalue_src += int(value, 16)
                        index_list += 1
                    else:
                        minvalue_src = minvalue_src + \
                            256 ** index_list * int(value, 16)
                        index_list += 1
            minvalue_dst = 0
            if '.' in str(src_ip):
                index_list = 0
                for value in dst_iplist[int(
                        step_index1):byte_size_dst + int(step_index1)]:
                    if dst_iplist.index(value) == 0:
                        minvalue_dst += int(value)
                        index_list += 1
                    else:
                        minvalue_dst = minvalue_dst + \
                            256 ** index_list * int(value)
                        index_list += 1
            if ':' in str(src_ip):
                index_list = 0
                for value in dst_iplist[int(
                        step_index1):byte_size_dst + int(step_index1)]:
                    if dst_iplist.index(value) == 0:
                        minvalue_dst += int(value, 16)
                        index_list += 1
                    else:
                        minvalue_dst = minvalue_dst + \
                            256 ** index_list * int(value, 16)
                        index_list += 1

            count = count_src if count_src >= count_dst else count_dst
            pkt_offset_src = v4_v6_src[int(step_index) + byte_size_src - 1]
            pkt_offset_dst = v4_v6_dst[int(step_index1) + byte_size_dst - 1]
            vm = STLVM()
            vm.var(
                name='src',
                op=operation_src,
                step=step_size_src,
                size=byte_size_src,
                min_value=minvalue_src,
                max_value=count_src + minvalue_src)
            vm.write(
                fv_name='src',
                pkt_offset=pkt_offset_src,
                add_val=0,
                byte_order='big')
            vm.var(
                name='dst',
                op=operation_dst,
                step=step_size_dst,
                size=byte_size_dst,
                min_value=minvalue_dst,
                max_value=count_dst + minvalue_dst)
            vm.write(
                fv_name='dst',
                pkt_offset=pkt_offset_dst,
                add_val=0,
                byte_order='big')
            stream = STLStream(packet=STLPktBuilder(pkt=packet, vm=vm),
                               name='ip_step',
                               stream_id=0,
                               mac_src_override_by_pkt=False,
                               mac_dst_override_mode=0,
                               mode=STLTXSingleBurst(total_pkts=count, percentage=8.0))

            conn.add_streams(stream)
            conn.start(force=True)
            conn.wait_on_traffic()
            conn.stop()
            conn.remove_all_streams()
            # rx, tx = self.__capture_stop(''.join(save_name), conn)
        finally:
            conn.disconnect()
        # return rx, tx

    def case142_1(self):
        # case 142-1
        # V4_LHself
        self.start_src_dst_inc_dec_fin(
            "70.0.0.1", "2.2.2.2", 833200, 1, 0, "src", "inc")
        self.start_src_dst_inc_dec_fin(
            "1.1.1.1", "100.0.0.1", 833200, 1, 0, "dst", "inc")
        self.start_src_dst_inc_dec_fin(
            "20.0.0.1", "110.0.0.1", 833200, 1, 0, "src", "inc")
        self.start_src_dst_inc_dec_fin(
            "50.0.0.1",
            "2.2.2.2",
            833200,
            1,
            0,
            "src",
            "inc",
            sport=5001,
            tcp_udp='udp')
        self.start_src_dst_inc_dec_fin(
            "1.1.1.1",
            "130.0.0.1",
            833200,
            1,
            0,
            "dst",
            "inc",
            dport=25001,
            tcp_udp='tcp')
        self.start_src_dst_inc_dec_fin(
            "100.0.0.1",
            "190.0.0.1",
            833200,
            1,
            0,
            "src",
            "inc",
            dport=25001,
            tcp_udp='udp')
        self.start_src_dst_inc_dec_fin(
            "110.0.0.1",
            "200.0.0.1",
            833200,
            1,
            0,
            "src",
            "inc",
            sport=5001,
            tcp_udp='tcp')
        self.start_src_dst_inc_dec_fin(
            "90.0.0.1",
            "180.0.0.1",
            833200,
            1,
            0,
            "src",
            "inc",
            tcp_udp='udp')
        self.start_src_dst_inc_dec_fin(
            "140.0.0.1",
            "2.2.2.2",
            833200,
            1,
            0,
            "src",
            "inc",
            dport=25001,
            tcp_udp='tcp')
        self.start_src_dst_inc_dec_fin(
            "1.1.1.1",
            "220.0.0.1",
            833200,
            1,
            0,
            "dst",
            "inc",
            sport=5001,
            tcp_udp='udp')
        self.start_src_dst_inc_dec_fin(
            "80.0.0.1",
            "2.2.2.2",
            833200,
            1,
            0,
            "src",
            "inc",
            tcp_udp='tcp')
        self.start_src_dst_inc_dec_fin(
            "1.1.1.1",
            "120.0.0.1",
            834800,
            1,
            0,
            "dst",
            "inc",
            tcp_udp='udp')

        # V4_YM
        self.start_src_dst_inc_dec_fin(
            "11.50.0.0", "2.2.2.2", 13380, 256, 0, "src", "inc")
        self.start_src_dst_inc_dec_fin(
            "1.1.1.1", "101.50.0.0", 13330, 256, 0, "dst", "inc")
        self.start_src_dst_inc_dec_fin(
            "21.50.0.0", "111.50.0.0", 13330, 256, 0, "src", "inc")
        self.start_src_dst_inc_dec_fin(
            "1.1.1.1",
            "121.50.0.0",
            13330,
            256,
            0,
            "dst",
            "inc",
            tcp_udp='tcp')
        self.start_src_dst_inc_dec_fin(
            "41.50.0.0",
            "2.2.2.2",
            13330,
            256,
            0,
            "src",
            "inc",
            tcp_udp='udp')
        self.start_src_dst_inc_dec_fin(
            "51.50.0.0",
            "131.50.0.0",
            13330,
            256,
            0,
            "src",
            "inc",
            tcp_udp='tcp')
        self.start_src_dst_inc_dec_fin(
            "1.1.1.1",
            "141.50.0.0",
            13330,
            256,
            0,
            "dst",
            "inc",
            dport=25001,
            tcp_udp='udp')
        self.start_src_dst_inc_dec_fin(
            "71.50.0.0",
            "2.2.2.2",
            13330,
            256,
            0,
            "src",
            "inc",
            sport=5001,
            tcp_udp='tcp')
        self.start_src_dst_inc_dec_fin(
            "1.1.1.1",
            "151.50.0.0",
            13330,
            256,
            0,
            "dst",
            "inc",
            sport=5001,
            tcp_udp='udp')
        self.start_src_dst_inc_dec_fin(
            "91.50.0.0",
            "2.2.2.2",
            13330,
            256,
            0,
            "src",
            "inc",
            dport=25001,
            tcp_udp='tcp')
        self.start_src_dst_inc_dec_fin(
            "101.50.0.0",
            "161.50.0.0",
            13330,
            256,
            0,
            "src",
            "inc",
            dport=25001,
            tcp_udp='udp')
        self.start_src_dst_inc_dec_fin(
            "111.50.0.0",
            "171.50.0.0",
            13330,
            256,
            0,
            "src",
            "inc",
            sport=5001,
            tcp_udp='tcp')
        self.start_src_dst_inc_dec_fin(
            "121.50.0.0",
            "2.2.2.2",
            13330,
            256,
            0,
            "src",
            "inc",
            sport=5001,
            dport=25001,
            tcp_udp='udp')
        self.start_src_dst_inc_dec_fin(
            "1.1.1.1",
            "181.50.0.0",
            13330,
            256,
            0,
            "dst",
            "inc",
            sport=5001,
            dport=25001,
            tcp_udp='tcp')
        self.start_src_dst_inc_dec_fin(
            "141.50.0.0",
            "191.50.0.0",
            13330,
            256,
            0,
            "src",
            "inc",
            sport=5001,
            dport=25001,
            tcp_udp='udp')

        # V6_LH
        self.start_src_dst_inc_dec_fin(
            '2000:0:0:0:0:0:4600:0001',
            "2:2:2:2:2:2:2:2",
            1666400,
            1,
            0,
            "src",
            "inc")  # 未输出
        self.start_src_dst_inc_dec_fin(
            '1:1:1:1:1:1:1:1',
            "2000:0:0:0:0:0:6400:0001",
            1666400,
            1,
            0,
            "dst",
            "inc")
        self.start_src_dst_inc_dec_fin(
            '2000:0:0:0:0:0:1400:0001',
            "2000:0:0:0:0:0:6E00:0001",
            1666400,
            1,
            0,
            "src",
            "inc")
        self.start_src_dst_inc_dec_fin(
            '2000:0:0:0:0:0:3200:0001',
            "2:2:2:2:2:2:2:2",
            1666400,
            1,
            0,
            "src",
            "inc",
            sport=5001,
            tcp_udp='udp')
        self.start_src_dst_inc_dec_fin(
            '1:1:1:1:1:1:1:1',
            "2000:0:0:0:0:0:8200:0001",
            1666400,
            1,
            0,
            "dst",
            "inc",
            dport=25001,
            tcp_udp='tcp')
        self.start_src_dst_inc_dec_fin(
            '2000:0:0:0:0:0:6400:0001',
            "2000:0:0:0:0:0:BE00:0001",
            1666400,
            1,
            0,
            "src",
            "inc",
            dport=25001,
            tcp_udp='udp')
        self.start_src_dst_inc_dec_fin(
            '2000:0:0:0:0:0:6E00:0001',
            "2000:0:0:0:0:0:C800:0001",
            1666400,
            1,
            0,
            "src",
            "inc",
            sport=5001,
            tcp_udp='tcp')
        self.start_src_dst_inc_dec_fin(
            '2000:0:0:0:0:0:5A00:0001',
            "2000:0:0:0:0:0:B400:0001",
            1666400,
            1,
            0,
            "src",
            "inc",
            tcp_udp='udp')
        self.start_src_dst_inc_dec_fin(
            '2000:0:0:0:0:0:8C00:0001',
            "2:2:2:2:2:2:2:2",
            1666400,
            1,
            0,
            "src",
            "inc",
            dport=25001,
            tcp_udp='tcp')
        self.start_src_dst_inc_dec_fin(
            '1:1:1:1:1:1:1:1',
            "2000:0:0:0:0:0:DC00:0001",
            1666400,
            1,
            0,
            "dst",
            "inc",
            sport=5001,
            tcp_udp='udp')
        self.start_src_dst_inc_dec_fin(
            '2000:0:0:0:0:0:5000:0001',
            "2000:0:0:0:0:0:DC00:0001",
            1666400,
            1,
            0,
            "src",
            "inc",
            tcp_udp='tcp')
        self.start_src_dst_inc_dec_fin(
            '1:1:1:1:1:1:1:1',
            "2000:0:0:0:0:0:7800:0001",
            1669600,
            1,
            0,
            "dst",
            "inc",
            tcp_udp='udp')

        # V6_YMself
        self.start_src_dst_inc_dec_fin(
            '2001:0:0:0:0:0:0A32:0000',
            "2:2:2:2:2:2:2:2",
            9000,
            256,
            0,
            "src",
            "inc")
        self.start_src_dst_inc_dec_fin(
            '1:1:1:1:1:1:1:1',
            "2001:0:0:0:0:0:6432:0000",
            6500,
            256,
            0,
            "dst",
            "inc")
        self.start_src_dst_inc_dec_fin(
            '2001:0:0:0:0:0:1432:0000',
            "2001:0:0:0:0:0:6E32:0000",
            6500,
            256,
            0,
            "src",
            "inc")
        self.start_src_dst_inc_dec_fin(
            '1:1:1:1:1:1:1:1',
            "2001:0:0:0:0:0:7832:0000",
            6500,
            256,
            0,
            "dst",
            "inc",
            tcp_udp='tcp')
        self.start_src_dst_inc_dec_fin(
            '2001:0:0:0:0:0:2832:0000',
            "2:2:2:2:2:2:2:2",
            6500,
            256,
            0,
            "src",
            "inc",
            tcp_udp="udp")
        self.start_src_dst_inc_dec_fin(
            '2001:0:0:0:0:0:3232:0000',
            "2001:0:0:0:0:0:8232:0000",
            6500,
            256,
            0,
            "src",
            "inc",
            tcp_udp="tcp")
        self.start_src_dst_inc_dec_fin(
            '1:1:1:1:1:1:1:1',
            "2001:0:0:0:0:0:8C32:0000",
            6500,
            256,
            0,
            "dst",
            "inc",
            dport=25001,
            tcp_udp='udp')
        self.start_src_dst_inc_dec_fin(
            '2001:0:0:0:0:0:4632:0000',
            "2:2:2:2:2:2:2:2",
            6500,
            256,
            0,
            "src",
            "inc",
            sport=5001,
            tcp_udp="tcp")
        self.start_src_dst_inc_dec_fin(
            '1:1:1:1:1:1:1:1',
            "2001:0:0:0:0:0:9632:0000",
            6500,
            256,
            0,
            "dst",
            "inc",
            sport=5001,
            tcp_udp='udp')
        self.start_src_dst_inc_dec_fin(
            '2001:0:0:0:0:0:5A32:0000',
            "2:2:2:2:2:2:2:2",
            6500,
            256,
            0,
            "src",
            "inc",
            dport=25001,
            tcp_udp="tcp")
        self.start_src_dst_inc_dec_fin(
            '2001:0:0:0:0:0:6432:0000',
            "2001:0:0:0:0:0:A032:0000",
            6500,
            256,
            0,
            "src",
            "inc",
            dport=25001,
            tcp_udp="udp")
        self.start_src_dst_inc_dec_fin(
            '2001:0:0:0:0:0:6E32:0000',
            "2001:0:0:0:0:0:AA32:0000",
            6500,
            256,
            0,
            "src",
            "inc",
            sport=5001,
            tcp_udp="tcp")
        self.start_src_dst_inc_dec_fin(
            '2001:0:0:0:0:0:7832:0000',
            "2:2:2:2:2:2:2:2",
            6500,
            256,
            0,
            "src",
            "inc",
            sport=5001,
            dport=25001,
            tcp_udp="udp")
        self.start_src_dst_inc_dec_fin(
            '1:1:1:1:1:1:1:1',
            "2001:0:0:0:0:0:B432:0000",
            6500,
            256,
            0,
            "dst",
            "inc",
            sport=5001,
            dport=25001,
            tcp_udp='tcp')
        self.start_src_dst_inc_dec_fin(
            '2001:0:0:0:0:0:8C32:0000',
            "2001:0:0:0:0:0:BE32:0000",
            6500,
            256,
            0,
            "src",
            "inc",
            sport=5001,
            dport=25001,
            tcp_udp="udp")

    def case147(self):
        # A1&B127
        self.start_src_and_dst_inc_dec(
            "70.0.0.1", "160.0.0.1", 450000, 450000, 1, 0, 1, 0, "inc", "inc")
        self.start_src_and_dst_inc_dec(
            "50.0.0.1", "160.0.0.1", 450000, 450000, 1, 0, 1, 0, "inc", "inc", 5001, 1024, "udp")
        self.start_src_and_dst_inc_dec(
            "50.0.0.1", "140.0.0.1", 450000, 450000, 1, 0, 1, 0, "inc",
            "inc",
            5001,
            25001,
            "udp")
        self.start_src_and_dst_inc_dec(
            "70.0.0.1",
            "140.0.0.1",
            450000, 450000,
            1, 0, 1, 0,
            "inc",
            "inc",
            1024,
            25001,
            "udp")
        # A2&B126
        self.start_src_and_dst_inc_dec(
            "2000:0:0:0:0:0:4600:0001",
            "2000:0:0:0:0:0:6400:0001",
            834000, 834000,
            1, 0, 1, 0,
            "inc",
            "inc")
        self.start_src_and_dst_inc_dec(
            "2000:0:0:0:0:0:3200:0001",
            "2000:0:0:0:0:0:6400:0001",
            834000, 834000,
            1, 0, 1, 0,
            "inc", "inc",
            5001, 1024, "udp"
        )
        self.start_src_and_dst_inc_dec(
            "2000:0:0:0:0:0:3200:0001",
            "2000:0:0:0:0:0:8200:0001",
            834000, 834000,
            1, 0, 1, 0,
            "inc",
            "inc",
            5001,
            25001,
            "udp")
        self.start_src_and_dst_inc_dec(
            "2000:0:0:0:0:0:4600:0001",
            "2000:0:0:0:0:0:8200:0001",
            834000, 834000,
            1, 0, 1, 0,
            "inc",
            "inc",
            1024,
            25001,
            "udp")
        # A3&b125
        self.start_src_and_dst_inc_dec(
            "11.40.0.1", "101.50.0.0", 1699840, 6640, 1, 0, 256, 0, "inc", "inc")
        self.start_src_and_dst_inc_dec(
            "31.40.0.1",
            "101.50.0.0",
            1699840, 6640,
            1, 0, 256, 0,
            "inc",
            "inc",
            5001,
            1024,
            "udp")
        self.start_src_and_dst_inc_dec(
            "11.40.0.1", "141.50.0.0", 1699840, 6640, 1, 0, 256, 0, "inc", "inc", 1024, 25001, "udp")
        self.start_src_and_dst_inc_dec(
            "31.40.0.1",
            "141.50.0.0",
            1699840, 6640,
            1, 0, 256, 0,
            "inc",
            "inc",
            5001,
            25001,
            "udp")
        # A4&124
        self.start_src_and_dst_inc_dec(
            "2000:0:0:0:0:0:a280:0001",
            "2001:0:0:0:0:0:6432:0000",
            832000, 3250,
            1, 0, 256, 0,
            "inc",
            "inc")
        self.start_src_and_dst_inc_dec("2000:0:0:0:0:0:3232:0001", "2001:0:0:0:0:0:6432:0000", 832000, 3250, 1, 0, 256, 0, "inc", "inc", 5001,
                                       1024, "udp")
        self.start_src_and_dst_inc_dec(
            "2000:0:0:0:0:0:a280:0001",
            "2001:0:0:0:0:0:8c32:0000",
            832000, 3250,
            1, 0, 256, 0,
            "inc",
            "inc", 1024, 25001, "udp")
        self.start_src_and_dst_inc_dec("2000:0:0:0:0:0:3232:0001", "2001:0:0:0:0:0:8c32:0000", 832000, 3250, 1, 0, 256,
                                       0, "inc", "inc", 5001,
                                       25001, "udp")

        # ipv4_LH
        self.start_src_dst_inc_dec_fin(
            "20.0.0.1", "110.0.0.1", 600000, 1, 0, "src", "inc")
        self.start_src_dst_inc_dec_fin(
            "100.0.0.1",
            "190.0.0.1",
            600000,
            1,
            0,
            "src",
            "inc",
            1024,
            25001,
            "udp")
        self.start_src_dst_inc_dec_fin(
            "110.0.0.1",
            "200.0.0.1",
            600000,
            1,
            0,
            "src",
            "inc",
            5001,
            1024,
            "tcp")
        self.start_src_dst_inc_dec_fin(
            "90.0.0.1",
            "180.0.0.1",
            600000,
            1,
            0,
            "src",
            "inc",
            1024,
            1024,
            "udp")
        self.start_src_dst_inc_dec_fin(
            "140.0.0.1",
            "192.168.1.1",
            600000,
            1,
            0,
            "src",
            "inc",
            1024,
            25001,
            "tcp")
        self.start_src_dst_inc_dec_fin(
            "10.0.0.1",
            "220.0.0.1",
            600000,
            1,
            0,
            "dst",
            "inc",
            5001,
            1024,
            "udp")
        self.start_src_dst_inc_dec_fin(
            "80.0.0.1",
            "192.168.1.1",
            600000,
            1,
            0,
            "src",
            "inc",
            1024,
            1024,
            "tcp")
        self.start_src_dst_inc_dec_fin(
            "10.0.0.1",
            "120.0.0.1",
            600000,
            1,
            0,
            "dst",
            "inc",
            1024,
            1024,
            "udp")

        # ipv4_YM
        self.start_src_dst_inc_dec_fin(
            "11.50.0.0", "192.168.1.1", 6640, 256, 0, "src", "inc")
        self.start_src_dst_inc_dec_fin(
            "21.50.0.0", "111.50.0.0", 6640, 256, 0, "src", "inc")
        self.start_src_dst_inc_dec_fin(
            "10.0.0.1", "121.50.0.0", 6640, 256, 0, "dst", "inc")
        self.start_src_dst_inc_dec_fin(
            "41.50.0.0",
            "121.50.0.0",
            6640,
            256,
            0,
            "src",
            "inc",
            1024,
            1024,
            "udp")
        self.start_src_dst_inc_dec_fin(
            "51.50.0.0",
            "131.50.0.0",
            6640,
            256,
            0,
            "src",
            "inc",
            1024,
            1024,
            "tcp")
        self.start_src_dst_inc_dec_fin(
            "71.50.0.0",
            "192.168.1.1",
            6640,
            256,
            0,
            "src",
            "inc",
            5001,
            1024,
            "tcp")
        self.start_src_dst_inc_dec_fin(
            "10.0.0.1",
            "151.50.0.0",
            6640,
            256,
            0,
            "dst",
            "inc",
            5001,
            1024,
            "udp")
        self.start_src_dst_inc_dec_fin(
            "91.50.0.0",
            "152.50.0.0",
            6640,
            256,
            0,
            "src",
            "inc",
            1024,
            25001,
            "tcp")
        self.start_src_dst_inc_dec_fin(
            "101.50.0.0",
            "161.50.0.0",
            6640,
            256,
            0,
            "src",
            "inc",
            1024,
            25001,
            "udp")
        self.start_src_dst_inc_dec_fin(
            "111.50.0.0",
            "171.50.0.0",
            6640,
            256,
            0,
            "src",
            "inc",
            5001,
            1024,
            "tcp")
        self.start_src_dst_inc_dec_fin(
            "121.50.0.0",
            "192.168.1.1",
            6640,
            256,
            0,
            "src",
            "inc",
            5001,
            25001,
            "udp")
        self.start_src_dst_inc_dec_fin(
            "10.0.0.1",
            "181.50.0.0",
            6640,
            256,
            0,
            "dst",
            "inc",
            5001,
            25001,
            "tcp")
        self.start_src_dst_inc_dec_fin(
            "141.50.0.0",
            "191.50.0.0",
            6640,
            256,
            0,
            "src",
            "inc",
            5001,
            25001,
            "udp")

        # ipv6_LH
        self.start_src_dst_inc_dec_fin(
            "2000:0:0:0:0:0:1400:0001",
            "2000:0:0:0:0:0:6e00:1",
            1850000,
            1,
            0,
            "src",
            "inc")
        self.start_src_dst_inc_dec_fin("2000:0:0:0:0:0:6400:0001", "2000:0:0:0:0:0:BE00:1", 1850000, 1, 0, "src", "inc",
                                       1024,
                                       25001, "udp")
        self.start_src_dst_inc_dec_fin(
            "2000:0:0:0:0:0:6E00:0001",
            "2000:0:0:0:0:0:C800:1",
            1850000,
            1,
            0,
            "src",
            "inc",
            5001,
            1024)
        self.start_src_dst_inc_dec_fin("2000:0:0:0:0:0:5A00:0001", "2000:0:0:0:0:0:B400:1", 1850000, 1, 0, "src", "inc", 1024,
                                       1024, "udp")
        self.start_src_dst_inc_dec_fin("2000:0:0:0:0:0:8c00:0001", "1000:0:0:0:0:0:0:1", 1850000, 1, 0, "src", "inc", 1024,
                                       25001)
        self.start_src_dst_inc_dec_fin("2000:0:0:0:0:0:0:1", "2000:0:0:0:0:0:Dc00:0001", 1850000, 1, 0, "dst", "inc", 5001,
                                       1024, "udp")
        self.start_src_dst_inc_dec_fin(
            "2000:0:0:0:0:0:5000:0001",
            "1000:0:0:0:0:0:0:1",
            1850000,
            1,
            0,
            "src",
            "inc")
        self.start_src_dst_inc_dec_fin("2000:0:0:0:0:0:0:1", "2000:0:0:0:0:0:7800:0001", 1850000, 1, 0, "dst", "inc", 1024,
                                       1024, "udp")
        # ipv6_YM
        self.start_src_dst_inc_dec_fin(
            "2001:0:0:0:0:0:0A32:0",
            "1000:0:0:0:0:0:0:1",
            4500,
            256,
            0,
            "src",
            "inc")
        self.start_src_dst_inc_dec_fin(
            "2001:0:0:0:0:0:1432:0",
            "2001:0:0:0:0:0:6E32:0",
            3250,
            256,
            0,
            "src",
            "inc")

        self.start_src_dst_inc_dec_fin(
            "2000:0:0:0:0:0:0:1",
            "2001:0:0:0:0:0:7832:0",
            3250,
            256,
            0,
            "dst",
            "inc")

        self.start_src_dst_inc_dec_fin("2001:0:0:0:0:0:2832:0", "1000:0:0:0:0:0:0:1", 3250, 256, 0, "src", "inc", 1024,
                                       1024, "udp")
        self.start_src_dst_inc_dec_fin(
            "2001:0:0:0:0:0:3232:0",
            "2001:0:0:0:0:0:8232:0",
            3250,
            256,
            0,
            "src",
            "inc")
        self.start_src_dst_inc_dec_fin(
            "2001:0:0:0:0:0:4632:0",
            "1000:0:0:0:0:0:0:1",
            3250,
            256,
            0,
            "src",
            "inc",
            5001)

        self.start_src_dst_inc_dec_fin("2000:0:0:0:0:0:0:1", "2001:0:0:0:0:0:9632:0", 3250, 256, 0, "dst", "inc", 5001,
                                       1024, "udp")
        self.start_src_dst_inc_dec_fin("2001:0:0:0:0:0:5A32:0", "1000:0:0:0:0:0:0:1", 3250, 256, 0, "src", "inc", 1024,
                                       25001)
        self.start_src_dst_inc_dec_fin("2001:0:0:0:0:0:6432:0", "2001:0:0:0:0:0:A032:0", 3250, 256, 0, "src", "inc", 1024,
                                       25001, "udp")

        self.start_src_dst_inc_dec_fin(
            "2001:0:0:0:0:0:6E32:0",
            "2001:0:0:0:0:0:AA32:0",
            3250,
            256,
            0,
            "src",
            "inc",
            5001)
        self.start_src_dst_inc_dec_fin("2001:0:0:0:0:0:7832:0", "1000:0:0:0:0:0:0:1", 3250, 256, 0, "src", "inc", 5001,
                                       25001, "udp")
        self.start_src_dst_inc_dec_fin("2000:0:0:0:0:0:0:1", "2001:0:0:0:0:0:B432:0", 3250, 256, 0, "dst", "inc", 5001,
                                       25001)
        self.start_src_dst_inc_dec_fin("2001:0:0:0:0:0:8C32:0", "2001:0:0:0:0:0:BE32:0", 3250, 256, 0, "src", "inc", 5001,
                                       25001, "udp")

        self.start_src_dst_inc_dec_fin(
            "0:0:0:0:0:0:1000:1",
            "2000:0:0:0:0:0:0:1",
            50000,
            1,
            0,
            "src",
            "inc")
        self.start_src_dst_inc_dec_fin(
            "2000:0:0:0:0:0:0:1",
            "0:0:0:0:0:0:2100:1",
            50000,
            1,
            0,
            "dst",
            "inc")

        self.start_src_dst_inc_dec_fin(
            "2002:1:1:1:0:0:0:0",
            "2000:0:0:0:0:0:0:1",
            50000,
            1,
            0,
            "src",
            "inc")
        self.start_src_dst_inc_dec_fin(
            "2000:0:0:0:0:0:0:1",
            "2003:1:1:1:0:0:0:0",
            50000,
            1,
            0,
            "dst",
            "inc")

    def case147_self(self):
        # A1&B127
        self.start_src_and_dst_inc_dec(
            "170.0.0.1", "60.0.0.1", 100, 100, 1, 0, 1, 0, "inc", "inc")
        self.start_src_and_dst_inc_dec(
            "150.0.0.1", "60.0.0.1", 100, 100, 1, 0, 1, 0, "inc", "inc", 5001, 1024, "udp")
        self.start_src_and_dst_inc_dec(
            "150.0.0.1", "240.0.0.1", 100, 100, 1, 0, 1, 0, "inc",
            "inc",
            5001,
            25001,
            "udp")
        self.start_src_and_dst_inc_dec(
            "170.0.0.1",
            "240.0.0.1",
            100, 100,
            1, 0, 1, 0,
            "inc",
            "inc",
            1024,
            25001,
            "udp")
        # A2&B126
        self.start_src_and_dst_inc_dec(
            "3000:0:0:0:0:0:4600:0001",
            "3000:0:0:0:0:0:6400:0001",
            100, 100,
            1, 0, 1, 0,
            "inc",
            "inc")
        self.start_src_and_dst_inc_dec(
            "3000:0:0:0:0:0:3200:0001",
            "3000:0:0:0:0:0:6400:0001",
            100, 100,
            1, 0, 1, 0,
            "inc", "inc",
            5001, 1024, "udp"
        )
        self.start_src_and_dst_inc_dec(
            "3000:0:0:0:0:0:3200:0001",
            "3000:0:0:0:0:0:8200:0001",
            100, 100,
            1, 0, 1, 0,
            "inc",
            "inc",
            5001,
            25001,
            "udp")
        self.start_src_and_dst_inc_dec(
            "3000:0:0:0:0:0:4600:0001",
            "3000:0:0:0:0:0:8200:0001",
            100, 100,
            1, 0, 1, 0,
            "inc",
            "inc",
            1024,
            25001,
            "udp")
        # A3&b125
        self.start_src_and_dst_inc_dec(
            "111.40.0.1", "101.50.0.0", 100, 100, 1, 0, 256, 0, "inc", "inc")
        self.start_src_and_dst_inc_dec(
            "131.40.0.1",
            "101.50.0.0",
            100, 100,
            1, 0, 256, 0,
            "inc",
            "inc",
            5001,
            1024,
            "udp")
        self.start_src_and_dst_inc_dec(
            "111.40.0.1", "141.50.0.0", 100, 100, 1, 0, 256, 0, "inc", "inc", 1024, 25001, "udp")
        self.start_src_and_dst_inc_dec(
            "131.40.0.1",
            "141.50.0.0",
            100, 100,
            1, 0, 256, 0,
            "inc",
            "inc",
            5001,
            25001,
            "udp")
        # A4&124
        self.start_src_and_dst_inc_dec(
            "3000:0:0:0:0:0:a280:0001",
            "2001:0:0:0:0:0:6432:0000",
            100, 100,
            1, 0, 256, 0,
            "inc",
            "inc")
        self.start_src_and_dst_inc_dec("3000:0:0:0:0:0:3232:0001", "2001:0:0:0:0:0:6432:0000", 100, 100, 1, 0, 256,
                                       0, "inc", "inc", 5001,
                                       1024, "udp")
        self.start_src_and_dst_inc_dec(
            "3000:0:0:0:0:0:a280:0001",
            "2001:0:0:0:0:0:8c32:0000",
            100, 100,
            1, 0, 256, 0,
            "inc",
            "inc", 1024, 25001, "udp")
        self.start_src_and_dst_inc_dec("3000:0:0:0:0:0:3232:0001", "2001:0:0:0:0:0:8c32:0000", 100, 100, 1, 0, 256,
                                       0, "inc", "inc", 5001,
                                       25001, "udp")

        # ipv4_LH
        self.start_src_dst_inc_dec_fin(
            "200.0.0.1", "40.0.0.1", 100, 1, 0, "src", "inc")
        self.start_src_dst_inc_dec_fin(
            "30.0.0.1",
            "90.0.0.1",
            100,
            1,
            0,
            "src",
            "inc",
            1024,
            25001,
            "udp")
        self.start_src_dst_inc_dec_fin(
            "210.0.0.1",
            "20.0.0.1",
            100,
            1,
            0,
            "src",
            "inc",
            5001,
            1024,
            "tcp")
        self.start_src_dst_inc_dec_fin(
            "190.0.0.1",
            "80.0.0.1",
            100,
            1,
            0,
            "src",
            "inc",
            1024,
            1024,
            "udp")
        self.start_src_dst_inc_dec_fin(
            "40.0.0.1",
            "192.168.1.1",
            100,
            1,
            0,
            "src",
            "inc",
            1024,
            25001,
            "tcp")
        self.start_src_dst_inc_dec_fin(
            "10.0.0.1",
            "20.0.0.1",
            100,
            1,
            0,
            "dst",
            "inc",
            5001,
            1024,
            "udp")
        self.start_src_dst_inc_dec_fin(
            "180.0.0.1",
            "192.168.1.1",
            100,
            1,
            0,
            "src",
            "inc",
            1024,
            1024,
            "tcp")
        self.start_src_dst_inc_dec_fin(
            "10.0.0.1",
            "220.0.0.1",
            100,
            1,
            0,
            "dst",
            "inc",
            1024,
            1024,
            "udp")

        # ipv6_LH
        self.start_src_dst_inc_dec_fin(
            "3000:0:0:0:0:0:1400:0001",
            "3000:0:0:0:0:0:6e00:1",
            100,
            1,
            0,
            "src",
            "inc")
        self.start_src_dst_inc_dec_fin("3000:0:0:0:0:0:6400:0001", "3000:0:0:0:0:0:BE00:1", 100, 1, 0, "src", "inc",
                                       1024,
                                       25001, "udp")
        self.start_src_dst_inc_dec_fin(
            "3000:0:0:0:0:0:6E00:0001",
            "3000:0:0:0:0:0:C800:1",
            100,
            1,
            0,
            "src",
            "inc",
            5001,
            1024)
        self.start_src_dst_inc_dec_fin("3000:0:0:0:0:0:5A00:0001", "3000:0:0:0:0:0:B400:1", 100, 1, 0, "src", "inc",
                                       1024,
                                       1024, "udp")
        self.start_src_dst_inc_dec_fin("3000:0:0:0:0:0:8c00:0001", "1000:0:0:0:0:0:0:1", 100, 1, 0, "src", "inc",
                                       1024,
                                       25001)
        self.start_src_dst_inc_dec_fin("2000:0:0:0:0:0:0:1", "3000:0:0:0:0:0:Dc00:0001", 100, 1, 0, "dst", "inc",
                                       5001,
                                       1024, "udp")
        self.start_src_dst_inc_dec_fin(
            "3000:0:0:0:0:0:5000:0001",
            "1000:0:0:0:0:0:0:1",
            100,
            1,
            0,
            "src",
            "inc")
        self.start_src_dst_inc_dec_fin("2000:0:0:0:0:0:0:1", "3000:0:0:0:0:0:7800:0001", 100, 1, 0, "dst", "inc",
                                       1024,
                                       1024, "udp")

        self.start_src_dst_inc_dec_fin(
            "0:0:0:0:0:0:2000:1",
            "2000:0:0:0:0:0:0:1",
            100,
            1,
            0,
            "src",
            "inc")
        self.start_src_dst_inc_dec_fin(
            "2000:0:0:0:0:0:0:1",
            "0:0:0:0:0:0:3100:1",
            100,
            1,
            0,
            "dst",
            "inc")

        self.start_src_dst_inc_dec_fin(
            "3002:1:1:1:0:0:0:0",
            "2000:0:0:0:0:0:0:1",
            100,
            1,
            0,
            "src",
            "inc")
        self.start_src_dst_inc_dec_fin(
            "2000:0:0:0:0:0:0:1",
            "3003:1:1:1:0:0:0:0",
            100,
            1,
            0,
            "dst",
            "inc")

    def case147_self_storage(self):
        # A1&B127
        self.start_src_and_dst_inc_dec(
            "170.0.0.1", "60.0.0.1", 100, 100, 1, 0, 1, 0, "inc", "inc")
        self.start_src_and_dst_inc_dec(
            "150.0.0.1", "60.0.0.1", 100, 100, 1, 0, 1, 0, "inc", "inc", 5001, 1024, "udp")
        self.start_src_and_dst_inc_dec(
            "150.0.0.1", "240.0.0.1", 100, 100, 1, 0, 1, 0, "inc",
            "inc",
            5001,
            25001,
            "udp")
        self.start_src_and_dst_inc_dec(
            "170.0.0.1",
            "240.0.0.1",
            100, 100,
            1, 0, 1, 0,
            "inc",
            "inc",
            1024,
            25001,
            "udp")
        # A2&B126
        self.start_src_and_dst_inc_dec(
            "3000:0:0:0:0:0:4600:0001",
            "3000:0:0:0:0:0:6400:0001",
            100, 100,
            1, 0, 1, 0,
            "inc",
            "inc")
        self.start_src_and_dst_inc_dec(
            "3000:0:0:0:0:0:3200:0001",
            "3000:0:0:0:0:0:6400:0001",
            100, 100,
            1, 0, 1, 0,
            "inc", "inc",
            5001, 1024, "udp"
        )
        self.start_src_and_dst_inc_dec(
            "3000:0:0:0:0:0:3200:0001",
            "3000:0:0:0:0:0:8200:0001",
            100, 100,
            1, 0, 1, 0,
            "inc",
            "inc",
            5001,
            25001,
            "udp")
        self.start_src_and_dst_inc_dec(
            "3000:0:0:0:0:0:4600:0001",
            "3000:0:0:0:0:0:8200:0001",
            100, 100,
            1, 0, 1, 0,
            "inc",
            "inc",
            1024,
            25001,
            "udp")
        # A3&b125
        self.start_src_and_dst_inc_dec(
            "111.40.0.1", "101.50.0.0", 100, 100, 1, 0, 256, 0, "inc", "inc")
        self.start_src_and_dst_inc_dec(
            "131.40.0.1",
            "101.50.0.0",
            100, 100,
            1, 0, 256, 0,
            "inc",
            "inc",
            5001,
            1024,
            "udp")
        self.start_src_and_dst_inc_dec(
            "111.40.0.1", "141.50.0.0", 100, 100, 1, 0, 256, 0, "inc", "inc", 1024, 25001, "udp")
        self.start_src_and_dst_inc_dec(
            "131.40.0.1",
            "141.50.0.0",
            100, 100,
            1, 0, 256, 0,
            "inc",
            "inc",
            5001,
            25001,
            "udp")
        # A4&124
        # self.start_src_and_dst_inc_dec(
        #     "3000:0:0:0:0:0:a280:0001",
        #     "2001:0:0:0:0:0:6432:0000",
        #     100, 100,
        #     1, 0, 256, 0,
        #     "inc",
        #     "inc") #ip 取模a280出现hash冲突，先取消
        self.start_src_and_dst_inc_dec("3000:0:0:0:0:0:3232:0001", "2001:0:0:0:0:0:6432:0000", 100, 100, 1, 0, 256,
                                       0, "inc", "inc", 5001,
                                       1024, "udp")
        # self.start_src_and_dst_inc_dec(
        #     "3000:0:0:0:0:0:a280:0001",
        #     "2001:0:0:0:0:0:8c32:0000",
        #     100, 100,
        #     1, 0, 256, 0,
        #     "inc",
        #     "inc", 1024, 25001, "udp") ##ip 取模a280出现hash冲突，先取消
        self.start_src_and_dst_inc_dec("3000:0:0:0:0:0:3232:0001", "2001:0:0:0:0:0:8c32:0000", 100, 100, 1, 0, 256,
                                       0, "inc", "inc", 5001,
                                       25001, "udp")

        # ipv4_LH
        self.start_src_dst_inc_dec_fin(
            "200.0.0.1", "40.0.0.1", 100, 1, 0, "src", "inc")
        self.start_src_dst_inc_dec_fin(
            "30.0.0.1",
            "90.0.0.1",
            100,
            1,
            0,
            "src",
            "inc",
            1024,
            25001,
            "udp")
        self.start_src_dst_inc_dec_fin(
            "210.0.0.1",
            "20.0.0.1",
            100,
            1,
            0,
            "src",
            "inc",
            5001,
            1024,
            "tcp")
        self.start_src_dst_inc_dec_fin(
            "190.0.0.1",
            "80.0.0.1",
            100,
            1,
            0,
            "src",
            "inc",
            1024,
            1024,
            "udp")
        self.start_src_dst_inc_dec_fin(
            "40.0.0.1",
            "192.168.1.1",
            100,
            1,
            0,
            "src",
            "inc",
            1024,
            25001,
            "tcp")
        self.start_src_dst_inc_dec_fin(
            "10.0.0.1",
            "20.0.0.1",
            100,
            1,
            0,
            "dst",
            "inc",
            5001,
            1024,
            "udp")
        self.start_src_dst_inc_dec_fin(
            "180.0.0.1",
            "192.168.1.1",
            100,
            1,
            0,
            "src",
            "inc",
            1024,
            1024,
            "tcp")
        self.start_src_dst_inc_dec_fin(
            "10.0.0.1",
            "220.0.0.1",
            100,
            1,
            0,
            "dst",
            "inc",
            1024,
            1024,
            "udp")

        # ipv6_LH
        self.start_src_dst_inc_dec_fin(
            "3000:0:0:0:0:0:1400:0001",
            "3000:0:0:0:0:0:6e00:1",
            100,
            1,
            0,
            "src",
            "inc")
        self.start_src_dst_inc_dec_fin("3000:0:0:0:0:0:6400:0001", "3000:0:0:0:0:0:BE00:1", 100, 1, 0, "src", "inc",
                                       1024,
                                       25001, "udp")
        self.start_src_dst_inc_dec_fin(
            "3000:0:0:0:0:0:6E00:0001",
            "3000:0:0:0:0:0:C800:1",
            100,
            1,
            0,
            "src",
            "inc",
            5001,
            1024)
        self.start_src_dst_inc_dec_fin("3000:0:0:0:0:0:5A00:0001", "3000:0:0:0:0:0:B400:1", 100, 1, 0, "src", "inc",
                                       1024,
                                       1024, "udp")
        self.start_src_dst_inc_dec_fin("3000:0:0:0:0:0:8c00:0001", "1000:0:0:0:0:0:0:1", 100, 1, 0, "src", "inc",
                                       1024,
                                       25001)
        self.start_src_dst_inc_dec_fin("2000:0:0:0:0:0:0:1", "3000:0:0:0:0:0:Dc00:0001", 100, 1, 0, "dst", "inc",
                                       5001,
                                       1024, "udp")
        self.start_src_dst_inc_dec_fin(
            "3000:0:0:0:0:0:5000:0001",
            "1000:0:0:0:0:0:0:1",
            100,
            1,
            0,
            "src",
            "inc")
        self.start_src_dst_inc_dec_fin("2000:0:0:0:0:0:0:1", "3000:0:0:0:0:0:7800:0001", 100, 1, 0, "dst", "inc",
                                       1024,
                                       1024, "udp")

        self.start_src_dst_inc_dec_fin(
            "0:0:0:0:0:0:2000:1",
            "2000:0:0:0:0:0:0:1",
            100,
            1,
            0,
            "src",
            "inc")
        self.start_src_dst_inc_dec_fin(
            "2000:0:0:0:0:0:0:1",
            "0:0:0:0:0:0:3100:1",
            100,
            1,
            0,
            "dst",
            "inc")

        self.start_src_dst_inc_dec_fin(
            "3002:1:1:1:0:0:0:0",
            "2000:0:0:0:0:0:0:1",
            100,
            1,
            0,
            "src",
            "inc")
        self.start_src_dst_inc_dec_fin(
            "2000:0:0:0:0:0:0:1",
            "3003:1:1:1:0:0:0:0",
            100,
            1,
            0,
            "dst",
            "inc")

    def Trex_pcapfile_times(self, filename, seconds=1):
        starttime = time.time()
        conn = self.__connect_server()
        try:
            self.__trex_init(conn)
            conn.clear_stats()
            times = 0
            pkts = self.__prase_pcapfile(filename)
            for pkt in pkts:
                times += 1
                stream = STLStream(
                    packet=STLPktBuilder(
                        pkt=pkt), mode=STLTXCont(
                        percentage=10), name=1)
                conn.add_streams(stream)
            conn.start(force=True, mult="4%")
            time.sleep(int(seconds))
            # conn.wait_on_traffic()
            conn.stop()
            conn.remove_all_streams()
        finally:
            conn.disconnect()
        endtime = time.time()
        print(endtime - starttime)



if __name__ == "__main__":
    trex = TrexUseForD(
        "192.168.3.9",
        "D_AutoTest",
        "C:\\Users\\peiwe\\Desktop\\", portid=0)
    a,b = trex.Trex_load_pcap_burst("C:\\Users\\peiwe\\Desktop\\1URFv4_SELF\\Resource\\Business\\raw_packets\\FH\\TCP_tudou.com.pcap","C:\\Users\\peiwe\\Desktop\\1URFv4_SELF\\Resource\\Business\\raw_packets\\FH\\SIP.pcap",save_name="hello")
    print(a,b)

