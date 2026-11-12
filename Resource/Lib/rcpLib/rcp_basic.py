#!/bin/bash/env python
# -*- coding:utf-8 -*-
# Author PeiWenPing
# time:2022/3/3:16:43
# email:peiwenping@finslink.com

"""
提供构建rcp报文相关的基本功能功能函数
"""
import struct
import binascii
import re
import time
import hashlib

base = [str(x) for x in range(10)] + [chr(x) for x in range(ord('A'), ord('A') + 6)]
pro_to_id = {
    "SCTP":132,
    "ICMP": 1,
    "IGMP": 2,
    "TCP": 6,
    "EGP": 8,
    "IGP": 9,
    "UDP": 17,
    "IPV6": 41,
    "GRE": 47,
    "ESP": 50,
    "AH": 51,
    "ICMPV6": 58,
    "OSPF": 89,
    "VRRP": 112,
    "L2TP": 115,
    "0": 0,
    'UNKNOW':253,
    'FF':255}

class RcpBasic:
    """
    提供rcp报文的构建的基础功能
    """
    def __init__(self):
        pass

    def data_format_change(self, data):
        """
        对RCP普通发送数据进行变成符合要求 b'\x25\x99...'
        :param data:需要转化的数据  必须列表,且列表内的数据为去掉0x的16进制数据
        :return:
        """
        new_data = []
        dest_data = b''
        for list_value in data:  # 下面循环主要解决不够两位的进行补全生成新的列表
            list_v = str(list_value) if len(
                str(list_value)) == 2 else '0' + str(list_value)
            new_data.append(list_v)
        for dest in new_data:  # 主要是对字符串转为符合网络传送的bytes格式
            dest_t = int(str(dest), 16)
            dest_data += struct.pack('B', dest_t)
        # print(binascii.hexlify(dest_data))  # 调试专用
        return dest_data

    def str_process(self, data):
        """
        针对字符串内容进行处理，主要是登录用到的用户名,把其转为ASCII
        :param data:
        :return:对应字符的ASCII列表
        """
        a = []
        for i in data:
            # 转为对应的ascii码
            # ascii_value = ord(str(i))
            # 临时处理0不进行转换
            # ascii_value = ord(str(i)) if str(i) != '0' else int(i)
            ascii_value = ord(str(i)) if str(i) != '0' else '48' #为应对ascii 0 对应的ascii的值为48
            ascii_value = ord(str(i)) if str(i) != '0' else '48'  # 为应对ascii 0 对应的ascii的值为48
            a.append(str(ascii_value))
        # print(a) #调试专用
        return a

    def bin_to_hex(self, data):
        """
        二进制码流转为16进制，且去掉0x内容
        :param data: '0b000'
        :return: 返回16进制去掉0x的内容
        """
        a = hex(int(data, 2))
        b = a.replace('0x', '')
        c = str(b) if len(b) == 2 else '0' + str(b)
        return c

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

    def mult_bytes_to_one_byte_old(self, bytecounts, data, is_hex=False):
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

    import re

    def mult_bytes_to_one_byte(self, bytecounts, data, is_hex=False):
        """
        针对存在某个值对应的字节数字为多个的时候，需要处理数据与帧格式字节数不匹配的情况（不足补0，过长截断）
        :param bytecounts: 帧格式中分配的字节数
        :param data: 实际的数据（整数或字符串，根据is_hex判断）
        :return: 帧格式中每个字段的字节列表 [a,b,c]
        """
        target_len = int(bytecounts) * 2  # 目标十六进制字符串总长度（每个字节2个字符）
        data_hex = ""

        if is_hex:
            # 处理十六进制字符串输入
            if isinstance(data, list):
                tmp = []
                for i in data:
                    # 单个元素补0至2位（如"F"→"0F"）
                    tmp.append(i.zfill(2) if len(i) < 2 else i[-2:])
                data_hex = ''.join(tmp)
            else:
                # 确保data是字符串（若传入非字符串则转为字符串）
                data_hex = str(data)
        else:
            # 处理整数输入：先确保data是整数，再转为十六进制
            try:
                # 关键修复：将data强制转换为整数（处理可能的字符串输入）
                data_int = int(data)
            except (ValueError, TypeError):
                # 转换失败时默认用0（可根据实际需求调整）
                data_int = 0

            if isinstance(data, list):
                tmp = []
                for i in data:
                    # 列表元素也需转为整数后再处理
                    i_int = int(i) if isinstance(i, (int, str)) else 0
                    hex_str = self.dec_to_hex(i_int).lstrip('0x').upper()
                    tmp.append(hex_str)
                data_hex = ''.join(tmp)
            else:
                # 计算目标字节数能表示的最大值（如4字节→0xFFFFFFFF）
                max_val = (1 << (int(bytecounts) * 8)) - 1
                # 按位与截断（仅保留目标字节数范围内的数值）
                truncated_data = data_int & max_val
                # 转为十六进制（去除前缀0x，大写）
                data_hex = self.dec_to_hex(truncated_data).lstrip('0x').upper()

        # 统一处理长度：不足补0（前补），过长截断（取末尾target_len位，即低位字节）
        if len(data_hex) < target_len:
            data_hex = data_hex.zfill(target_len)
        else:
            data_hex = data_hex[-target_len:]  # 若需保留高位字节，改为 data_hex[:target_len]

        # 按2个字符分割为字节列表
        return re.findall(r'\w{2}', data_hex)

    def mult_bytes_to_one_byte_sufix_zero(self, bytecounts, data, is_hex=False):
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
                    new_data_hex = data_hex + '0' * cha
                else:
                    new_data_hex = data_hex
        else:
            if int(bytecounts) == 1:
                return self.dec_to_hex(data)
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
                new_data_hex = data_hex + '0' * cha
            else:
                new_data_hex = data_hex
            # print(new_data_hex)  # 调试用
            # print(re.findall(r'\w{2}', new_data_hex)) # 调试用
            # 对新的数据进行按长度2进行分割，返回列表
        return re.findall(r'\w{2}', new_data_hex)

    def rcp_header(self, messType,returnCode, deviceId,packLen,ruleId=0,messId=0):
        """
        :param messType: 2B
            0x0000  新增放行请求
            0x0001  新增放行应答
            0x0100  变更请求
            0x0101  变更应答
            0x0200  删除请求
            0x0201  删除应答
            0x0300  查询请求
            0x0301  查询应答
            0x0400  镜像采样请求
            0x0401  镜像采样应答
            0x0500  告警阈值请求
            0x0501  告警阈值应答
        :param returnCode: 1B 返回码，请求时设置为0
        :param deviceId: 4B 设备ID
        :param packLen: 4B 消息长度(包括消息头)
        :param ruleId:4B 规则ID(变更、响应、删除才需要携带)；默认不携带,值为0
        :return:
        """
        header = []
        header.append(self.dec_to_hex(1)) #版本号
        header += self.mult_bytes_to_one_byte(2,messType,True) #消息类型
        header.append(self.dec_to_hex(returnCode))
        header += self.mult_bytes_to_one_byte(4,deviceId)
        header += self.mult_bytes_to_one_byte(4,messId)
        header += self.mult_bytes_to_one_byte(4, packLen)
        if ruleId :
            header += self.mult_bytes_to_one_byte(4, ruleId)
        return header

    def v6JianToQuan(self,v6Address):
        if "::" not in v6Address:
            return v6Address
        v6List = str(v6Address).split("::")
        if "" in v6List:  # 代表在前或后出现::
            befAft = v6List.index("")  # 0或1
            v6value = [x for x in v6List[1].split(':')]
            v6Zero = ['0' for _ in range(8 - len(v6value))]
            if befAft:
                v6value = [x for x in v6List[0].split(':')]
                v6Zero = ['0' for _ in range(8 - len(v6value))]
                v6All = v6value+ v6Zero
            else:
                v6value = [x for x in v6List[1].split(':')]
                v6Zero = ['0' for _ in range(8 - len(v6value))]
                v6All = v6Zero+ v6value

        else:
            v6valuePre = [x for x in v6List[0].split(':')]
            v6valueSuf = [x for x in v6List[1].split(':')]
            v6Zero = ['0' for _ in range(8-len(v6valuePre + v6valueSuf))]
            v6All = v6valuePre + v6Zero + v6valueSuf
        return ":".join(v6All)

if __name__ == '__main__':
    # md5 = hashlib.md5()
    # md5.update(str("sysadmin").encode('utf-8'))
    # password_md5 = md5.hexdigest()
    # print(password_md5)
    a = RcpBasic()
    c = a.mult_bytes_to_one_byte(2,'0100',True)
    print(c)