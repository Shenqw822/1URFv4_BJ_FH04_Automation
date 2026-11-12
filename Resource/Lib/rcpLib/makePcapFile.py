#!/bin/bash/env python
# -*- coding:utf-8 -*-
# Author PeiWenPing
# time:2024/5/7:13:50
# email:peiwenping@finslink.com
# 生成所需得pcapfile

from scapy.all import *
import configini
import paramiko_client
import time

class MPLS(Packet):
    name = 'MPLS'
    fields_desc = [
        BitField('label',100,20),   #名称,value,bit位(16进制表示)
        BitField('experimental',0,3),
        BitField('stack',1,1),
        BitField('ttl',255,8)
    ]

class GTP(Packet):
    name = 'GTP'
    fields_desc = [
        BitField('version',1,3),   #版本号
        BitField('p',1,1),          #protocol type 1:gtp-c/gtp-u，0:gtp
        BitField('R',0,1),   #保留字段
        BitField('e',1,1), #扩展消息头标志 1:有值 0:无值
        BitField('s', 1, 1), #序列号标志位
        BitField('pn', 0, 1), #N-PDU 标志位
        BitField('message', 255, 8), #GTP消息类型
        BitField('length', 36, 16), #消息总长度，不包括GTP头前8字节
        BitField('teid', 0, 32),  #
        # BitField('sequence number', 0X2712, 16), #当e,s,pn任意一个为1，该字段存在；当s为1，该字段需要被解析
        # BitField('n-pdu number', 1, 8),  # 当e,s,pn任意一个为1，该字段存在；当pn为1，该字段需要被解析
        BitField('next', 0, 8),# 当e,s,pn任意一个为1，该字段存在；当e为1，该字段需要被解析
        # BitField('length', 2, 8),
        # BitField('next', 0, 8),
    ]

class makePcapFile:

    def __init__(self, localPath, remotePath, skip_upload=False):
        self.localPath = localPath
        self.remotePath = remotePath
        self.skip_upload = skip_upload
        self._persistent_ssh = None

    def openSsh(self):
        """开启持久SSH连接，批量生成报文时复用，避免每次_upload都重新握手"""
        if self._persistent_ssh is None and not self.skip_upload:
            self._persistent_ssh = paramiko_client.ParamikoConnection(
                configini.SERVER['server_ip'], user=configini.SERVER['username'],
                pwd=configini.SERVER['password'])

    def closeSsh(self):
        """关闭持久SSH连接"""
        if self._persistent_ssh:
            self._persistent_ssh.close()
            self._persistent_ssh = None

    def _defalutValue(self, **kwargs):
        ipdefault = '192.168.1.1/32' if str(
            kwargs['v4v6']).lower() == 'v4' else "1::1/128"
        portdefault = 1024
        protodefault='tcp'
        kwargs['sip'] = kwargs['sip'] if kwargs['sip'] else ipdefault
        kwargs['sport'] = kwargs['sport'] if kwargs['sport'] else portdefault
        kwargs['dport'] = kwargs['dport'] if kwargs['dport'] else portdefault
        #kwargs['proto'] =  kwargs['proto'] if  kwargs['proto'] else protodefault
        return kwargs

    def _upload(self, localFilePath, remoteFilePath):
        if self.skip_upload:
            return
        if self._persistent_ssh:
            self._persistent_ssh.upload(localFilePath, remoteFilePath)
        else:
            ssh = paramiko_client.ParamikoConnection(configini.SERVER['server_ip'], user=configini.SERVER['username'],
                                                     pwd=configini.SERVER['password'])
            ssh.upload(localFilePath, remoteFilePath)
            ssh.close()

    def makePcap(self,exist,pcapFileName,title):
        saveName=[]
        for titleSingle in str(title).split(','):
            if not title :continue
            kwargs = configini.confPacket(pcapFileName).getPacket(titleSingle)
            opeer = kwargs['pkt_type']
            saveNameSingle = eval("self.%s"%opeer)(exist,**kwargs)
            saveName.append(saveNameSingle)
        return ','.join(saveName)

    def makePcapFromRule(self, exist, ruleConfigName, title, outputDir=None):
        """从RCP规则配置直接生成报文，无需单独的packet .ini
        参数: exist=0新建/1复用, ruleConfigName=规则ini名, title=section名(支持逗号分隔多个), outputDir=输出目录(默认self.localPath)"""
        save_dir = outputDir if outputDir else self.localPath
        if not os.path.exists(save_dir):
            os.makedirs(save_dir)

        # 计算远程子目录：outputDir 相对于 self.localPath 的差额同步到 remotePath
        try:
            rel_dir = os.path.relpath(save_dir, self.localPath)
        except ValueError:
            rel_dir = '.'
        if rel_dir != '.':
            remote_subdir = rel_dir.replace('\\', '/')
            remote_dir = self.remotePath.rstrip('/') + '/' + remote_subdir
            # 确保远程子目录存在
            if self._persistent_ssh:
                try:
                    self._persistent_ssh.sftp.stat(remote_dir)
                except IOError:
                    self._persistent_ssh.mkdir(remote_dir)
        else:
            remote_dir = self.remotePath

        saveName = []
        for titleSingle in str(title).split(','):
            if not titleSingle:
                continue
            rule = configini.R3(ruleConfigName).getR3(titleSingle)

            sipg = rule['sipg']
            dipg = rule['dipg']
            sip = sipg[0][0]
            sport = sipg[0][1] if sipg[0][1] != '0' else '1024'
            proto = sipg[0][3] if sipg[0][3] != '0' else 'tcp'
            dip = dipg[0][0]
            dport = dipg[0][1] if dipg[0][1] != '0' else '1024'

            operate = rule['operate']
            if operate == 'addRule_L2':
                if rule.get('vlang') and rule['vlang']:
                    pkt_type = 'vlan'
                elif rule.get('mplsg') and rule['mplsg']:
                    pkt_type = 'mpls'
                else:
                    pkt_type = 'normal'
            else:
                pkt_type = 'normal'

            kwargs = {
                'v4v6': rule['v4v6'], 'sip': sip, 'dip': dip,
                'sport': sport, 'dport': dport, 'proto': proto,
                'pkt_type': pkt_type, 'pkt_count': 200, 'pkt_len': 300,
                'raw': '', 'raw_offset': 0, 'save_name': titleSingle,
            }
            if pkt_type == 'vlan':
                kwargs['vlanid'] = ','.join(rule['vlang'][0]) if rule['vlang'] else '100,200'
            if pkt_type == 'mpls':
                kwargs['mplslabel'] = ','.join(rule['mplsg'][0]) if rule['mplsg'] else '300,400'

            # 临时切换 localPath 和 remotePath 以写入/上传到指定目录
            orig_local = self.localPath
            orig_remote = self.remotePath
            self.localPath = save_dir
            self.remotePath = remote_dir
            saveNameSingle = eval("self.%s" % kwargs['pkt_type'])(exist, **kwargs)
            self.localPath = orig_local
            self.remotePath = orig_remote
            saveName.append(saveNameSingle)
        return ','.join(saveName)

    def needRegenPcap(self, ruleConfigName, titles, outputDir=None):
        """检查是否需要重新生成pcap
        返回True: 需要重新生成（pcap不存在或ini更新）
        返回False: 可复用已有pcap"""
        save_dir = outputDir if outputDir else self.localPath
        ini_path = os.path.join(configini.BASE_DIR, '%s.ini' % ruleConfigName)
        if not os.path.exists(ini_path):
            return True
        ini_mtime = os.path.getmtime(ini_path)
        for title in str(titles).split(','):
            title = title.strip()
            if not title:
                continue
            pcap_path = os.path.join(save_dir, '%s.pcap' % title)
            if not os.path.exists(pcap_path):
                return True
            if os.path.getmtime(pcap_path) < ini_mtime:
                return True
        return False

    def vlan(self,exist, **kwargs):
        vlan_list = kwargs['vlanid'].split(',')
        if not exist:
            kwargs = self._defalutValue(**kwargs)
            v4v6 = 'IP' if str(kwargs['v4v6']).lower() == 'v4' else 'IPv6'
            if str(kwargs['proto']).upper():
                try:
                    if kwargs['tcpflag']:
                        value = "{}(sport={},dport={},flags='{}')".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                                          kwargs['dport'], "".join(
                                [str(x[0]).upper() for x in kwargs['tcpflag'].split(',')]))
                    else:
                        value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                               kwargs['dport'])
                except:
                    value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                           kwargs['dport'])
                singlePktLen = len(Ether() /
                                   Dot1Q(vlan=int(vlan_list[0])) /
                                   Dot1Q(vlan=int(vlan_list[1])) /
                                   eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) /
                                   eval(value)/
                                   (kwargs['raw']))
                ipList = Ether() / Dot1Q(vlan=int(vlan_list[0])) / Dot1Q(vlan=int(vlan_list[1])) / eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / eval(value) / Raw('0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (
                        kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            else:
                singlePktLen = len(Ether() /
                                   Dot1Q(vlan=int(vlan_list[0])) /
                                   Dot1Q(vlan=int(vlan_list[1])) /
                                   eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) /
                                   (kwargs['raw']))
                ipList = Ether() / Dot1Q(vlan=int(vlan_list[0])) / Dot1Q(vlan=int(vlan_list[1]))/ eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / Raw(
                    '0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            ip = [value for index, value in enumerate(
                ipList) if index < kwargs['pkt_count']]
            if len(ip) == kwargs['pkt_count']:
                wrip = ip
            else:
                wrip1 = ip * kwargs['pkt_count']
                wrip = wrip1[0:kwargs['pkt_count']]
            wrpcap('%s/%s.pcap' % (self.localPath, kwargs['save_name']), wrip)
            self._upload('%s/%s.pcap' % (self.localPath, kwargs['save_name']),'%s/%s.pcap' % (self.remotePath, kwargs['save_name']))
        # return '%s/%s.pcap' % (self.localPath, kwargs['save_name'])
        return '%s.pcap' % (kwargs['save_name'])

    def normal(self,exist, **kwargs):
        """tcpflag=URG, ACK, PSH, RST, SYN, FIN"""
        if not exist:
            kwargs = self._defalutValue(**kwargs)
            v4v6 = 'IP' if str(kwargs['v4v6']).lower() == 'v4' else 'IPv6'
            if str(kwargs['proto']).upper():
                try:
                    if kwargs['tcpflag'] :
                        value = "{}(sport={},dport={},flags='{}')".format(str(kwargs['proto']).upper(),kwargs['sport'],kwargs['dport'],"".join([str(x[0]).upper() for x in kwargs['tcpflag'].split(',')]))
                        # str(kwargs['proto']).upper()+(sport=kwargs['sport'], dport=kwargs['sport'],flags="{}".format("".join([str(x[0]).upper() for x in kwargs['tcpflag'].split(',')]))))
                        # print(value)
                    else:
                        value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                               kwargs['dport'])
                except:
                    value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],kwargs['dport'])
                singlePktLen = len(Ether() / eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / eval(value) / (kwargs['raw']))
                ipList = Ether() / eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / eval(value)/ Raw('0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (
                        kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            else:
                singlePktLen = len(Ether() /
                                   eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) /
                                   (kwargs['raw']))
                ipList = Ether() / eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / Raw(
                    '0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            ip = [value for index, value in enumerate(
                ipList) if index < kwargs['pkt_count']]
            if len(ip) == kwargs['pkt_count']:
                wrip = ip
            else:
                wrip1 = ip * kwargs['pkt_count']
                wrip = wrip1[0:kwargs['pkt_count']]
            wrpcap('%s/%s.pcap' % (self.localPath, kwargs['save_name']), wrip)
            self._upload('%s/%s.pcap' % (self.localPath, kwargs['save_name']),
                          '%s/%s.pcap' % (self.remotePath, kwargs['save_name']))
        # return '%s/%s.pcap' % (self.localPath, kwargs['save_name'])
        return '%s.pcap' % ( kwargs['save_name'])
        
    def build_mpls_packet(self,labels_str):
        """
          根据十进制字符串列表生成 MPLS 栈
          :param labels_str: 十进制标签列表（如 ['100'] 或 ['101', '200']）
          :return: Scapy MPLS 栈对象（最外层为第一层标签）
          :raises ValueError: 标签值无效（非1~1023整数）或列表为空
          """
        mpls_layers = []
        for idx, label_str in enumerate(labels_str):
            # 转换为整数并校验范围
            try:
                label = int(label_str)
            except ValueError:
                raise ValueError(f"无效标签格式: '{label_str}'（需十进制整数）")

            # if not 1 <= label <= 1023:
            #     raise ValueError(f"标签值 {label} 超出范围（1~1023）")

            # 构建单层 MPLS
            is_stack_bottom = (idx == len(labels_str) - 1)
            mpls_layer = MPLS(
                label=label,
                experimental=0,
                stack=is_stack_bottom,  # 最后一层设为栈底
                ttl=64
            )
            mpls_layers.append(mpls_layer)
        # 组合成多层栈
        if not mpls_layers:
            return None
        current_packet = mpls_layers[0]
        for layer in mpls_layers[1:]:
            current_packet = current_packet / layer  # 逐层拼接
        return current_packet


    def mpls(self,exist, **kwargs):
        mpls_labels_list = kwargs['mplslabel'].split(',')
        # if not os.path.exists(self.localPath):
        #     os.makedirs(self.localPath)
        mpls = self.build_mpls_packet(mpls_labels_list)
        if not exist:
            kwargs = self._defalutValue(**kwargs)
            v4v6 = 'IP' if str(kwargs['v4v6']).lower() == 'v4' else 'IPv6'
            if str(kwargs['proto']).upper():
                try:
                    if kwargs['tcpflag']:
                        value = "{}(sport={},dport={},flags='{}')".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                                          kwargs['dport'], "".join(
                                [str(x[0]).upper() for x in kwargs['tcpflag'].split(',')]))
                    else:
                        value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                               kwargs['dport'])
                except:
                    value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                           kwargs['dport'])
                singlePktLen = len(Ether(type=34887) / mpls /eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / eval(value) / (kwargs['raw']))
                ipList = Ether(type=34887) / mpls /eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / eval(value) / Raw('0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (
                        kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            else:
                singlePktLen = len(Ether(type=34887) /mpls/
                                   eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) /
                                   (kwargs['raw']))
                ipList = Ether(type=34887) / mpls / eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / Raw(
                    '0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            ip = [value for index, value in enumerate(
                ipList) if index < kwargs['pkt_count']]
            if len(ip) == kwargs['pkt_count']:
                wrip = ip
            else:
                wrip1 = ip * kwargs['pkt_count']
                wrip = wrip1[0:kwargs['pkt_count']]
            wrpcap('%s/%s.pcap' % (self.localPath, kwargs['save_name']), wrip)
            self._upload('%s/%s.pcap' % (self.localPath, kwargs['save_name']),
                             '%s/%s.pcap' % (self.remotePath, kwargs['save_name']))
                # return '%s/%s.pcap' % (self.localPath, kwargs['save_name'])
        return '%s.pcap' % (kwargs['save_name'])

    def mpls_old(self,exist, **kwargs):
        if not exist:
            kwargs = self._defalutValue(**kwargs)
            v4v6 = 'IP' if str(kwargs['v4v6']).lower() == 'v4' else 'IPv6'
            if str(kwargs['proto']).upper():
                try:
                    if kwargs['tcpflag']:
                        value = "{}(sport={},dport={},flags='{}')".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                                          kwargs['dport'], "".join(
                                [str(x[0]).upper() for x in kwargs['tcpflag'].split(',')]))
                    else:
                        value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                               kwargs['dport'])
                except:
                    value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                           kwargs['dport'])
                singlePktLen = len(Ether(type=34887) / MPLS(stack=0)/MPLS()/eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / eval(value) / (kwargs['raw']))
                ipList = Ether(type=34887) / MPLS(stack=0)/MPLS()/eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / eval(value) / Raw('0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (
                        kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            else:
                singlePktLen = len(Ether(type=34887) /MPLS(stack=0)/MPLS()/
                                   eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) /
                                   (kwargs['raw']))
                ipList = Ether(type=34887) /MPLS(stack=0)/MPLS()/ eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / Raw(
                    '0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            ip = [value for index, value in enumerate(
                ipList) if index < kwargs['pkt_count']]
            if len(ip) == kwargs['pkt_count']:
                wrip = ip
            else:
                wrip1 = ip * kwargs['pkt_count']
                wrip = wrip1[0:kwargs['pkt_count']]
            wrpcap('%s/%s.pcap' % (self.localPath, kwargs['save_name']), wrip)
            self._upload('%s/%s.pcap' % (self.localPath, kwargs['save_name']),
                             '%s/%s.pcap' % (self.remotePath, kwargs['save_name']))
                # return '%s/%s.pcap' % (self.localPath, kwargs['save_name'])
        return '%s.pcap' % (kwargs['save_name'])

    def gre(self, exist, **kwargs):
        if not exist:
            kwargs = self._defalutValue(**kwargs)
            v4v6 = 'IP' if str(kwargs['v4v6']).lower() == 'v4' else 'IPv6'
            out_v4v6 = 'IP' if str(kwargs['out_v4v6']).lower() == 'v4' else 'IPv6'
            if str(kwargs['proto']).upper():
                try:
                    if kwargs['tcpflag']:
                        value = "{}(sport={},dport={},flags='{}')".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                                          kwargs['dport'], "".join(
                                [str(x[0]).upper() for x in kwargs['tcpflag'].split(',')]))
                    else:
                        value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                               kwargs['dport'])
                except:
                    value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                           kwargs['dport'])
                singlePktLen = len(Ether() / eval(out_v4v6)(src=kwargs['out_sip'], dst=kwargs['out_dip']) / GRE()/Ether() / eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip'])/eval(value) / (kwargs['raw']))
                ipList = Ether() / eval(out_v4v6)(src=kwargs['out_sip'], dst=kwargs['out_dip']) / GRE()/Ether() / eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip'])/eval(value) / Raw(
                    '0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (
                            kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            else:
                singlePktLen = len(Ether() /
                                   eval(out_v4v6)(src=kwargs['out_sip'], dst=kwargs['out_dip']) /GRE()/Ether() /
                                   eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip'])/
                                   (kwargs['raw']))
                ipList = Ether() / eval(out_v4v6)(src=kwargs['out_sip'], dst=kwargs['out_dip']) / GRE()/Ether()/ eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip'])/Raw(
                    '0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (
                                kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            ip = [value for index, value in enumerate(
                ipList) if index < kwargs['pkt_count']]
            if len(ip) == kwargs['pkt_count']:
                wrip = ip
            else:
                wrip1 = ip * kwargs['pkt_count']
                wrip = wrip1[0:kwargs['pkt_count']]
            wrpcap('%s/%s.pcap' % (self.localPath, kwargs['save_name']), wrip)
            self._upload('%s/%s.pcap' % (self.localPath, kwargs['save_name']),
                         '%s/%s.pcap' % (self.remotePath, kwargs['save_name']))
        # return '%s/%s.pcap' % (self.localPath, kwargs['save_name'])
        return '%s.pcap' % (kwargs['save_name'])

    def ipinip(self, exist, **kwargs):
        if not exist:
            kwargs = self._defalutValue(**kwargs)
            v4v6 = 'IP' if str(kwargs['v4v6']).lower() == 'v4' else 'IPv6'
            out_v4v6 = 'IP' if str(kwargs['out_v4v6']).lower() == 'v4' else 'IPv6'
            if str(kwargs['proto']).upper():
                try:
                    if kwargs['tcpflag']:
                        value = "{}(sport={},dport={},flags='{}')".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                                          kwargs['dport'], "".join(
                                [str(x[0]).upper() for x in kwargs['tcpflag'].split(',')]))
                    else:
                        value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                               kwargs['dport'])
                except:
                    value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                           kwargs['dport'])
                singlePktLen = len(
                    Ether() / eval(out_v4v6)(src=kwargs['out_sip'], dst=kwargs['out_dip']) / eval(
                        v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / eval(value) / (kwargs['raw']))
                ipList = Ether() / eval(out_v4v6)(src=kwargs['out_sip'],
                                                  dst=kwargs['out_dip']) /eval(v4v6)(
                    src=kwargs['sip'], dst=kwargs['dip']) / eval(value) / Raw(
                    '0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (
                            kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            else:
                singlePktLen = len(Ether() /
                                   eval(out_v4v6)(src=kwargs['out_sip'], dst=kwargs['out_dip'])  /
                                   eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) /
                                   (kwargs['raw']))
                ipList = Ether() / eval(out_v4v6)(src=kwargs['out_sip'],
                                                  dst=kwargs['out_dip']) /  eval(v4v6)(
                    src=kwargs['sip'], dst=kwargs['dip']) / Raw(
                    '0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (
                            kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            ip = [value for index, value in enumerate(
                ipList) if index < kwargs['pkt_count']]
            if len(ip) == kwargs['pkt_count']:
                wrip = ip
            else:
                wrip1 = ip * kwargs['pkt_count']
                wrip = wrip1[0:kwargs['pkt_count']]
            wrpcap('%s/%s.pcap' % (self.localPath, kwargs['save_name']), wrip)
            self._upload('%s/%s.pcap' % (self.localPath, kwargs['save_name']),
                         '%s/%s.pcap' % (self.remotePath, kwargs['save_name']))
        # return '%s/%s.pcap' % (self.localPath, kwargs['save_name'])
        return '%s.pcap' % (kwargs['save_name'])

    def gtp(self, exist, **kwargs):
        if not exist:
            kwargs = self._defalutValue(**kwargs)
            v4v6 = 'IP' if str(kwargs['v4v6']).lower() == 'v4' else 'IPv6'
            out_v4v6 = 'IP' if str(kwargs['out_v4v6']).lower() == 'v4' else 'IPv6'
            if str(kwargs['proto']).upper():
                try:
                    if kwargs['tcpflag']:
                        value = "{}(sport={},dport={},flags='{}')".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                                          kwargs['dport'], "".join(
                                [str(x[0]).upper() for x in kwargs['tcpflag'].split(',')]))
                    else:
                        value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                               kwargs['dport'])
                except:
                    value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                           kwargs['dport'])
                gtp_len = len(
                    Ether() / eval(out_v4v6)(src=kwargs['out_sip'], dst=kwargs['out_dip']) /UDP(sport=2152,dport=1024))
                singlePktLen = len(
                    Ether() / eval(out_v4v6)(src=kwargs['out_sip'], dst=kwargs['out_dip']) /UDP(sport=2152,dport=1024)/GTP(length=kwargs['pkt_len']-gtp_len-8)/ eval(
                        v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / eval(value) / (kwargs['raw']))
                ipList = Ether() / eval(out_v4v6)(src=kwargs['out_sip'],
                                                  dst=kwargs['out_dip']) /UDP(sport=2152,dport=1024)/GTP(length=kwargs['pkt_len']-gtp_len-8)/eval(v4v6)(
                    src=kwargs['sip'], dst=kwargs['dip']) / eval(value) / Raw(
                    '0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (
                            kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            else:
                gtp_len = len(
                    Ether() / eval(out_v4v6)(src=kwargs['out_sip'], dst=kwargs['out_dip']) / UDP(sport=2152,
                                                                                                 dport=1024))
                singlePktLen = len(Ether() /
                                   eval(out_v4v6)(src=kwargs['out_sip'], dst=kwargs['out_dip'])  /UDP(sport=2152,dport=1024)/GTP(length=kwargs['pkt_len']-gtp_len-8)/
                                   eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) /
                                   (kwargs['raw']))
                ipList = Ether() / eval(out_v4v6)(src=kwargs['out_sip'],
                                                  dst=kwargs['out_dip']) /UDP(sport=2152,dport=1024)/GTP(length=kwargs['pkt_len']-gtp_len-8)/eval(v4v6)(
                    src=kwargs['sip'], dst=kwargs['dip']) / Raw(
                    '0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (
                            kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            ip = [value for index, value in enumerate(
                ipList) if index < kwargs['pkt_count']]
            if len(ip) == kwargs['pkt_count']:
                wrip = ip
            else:
                wrip1 = ip * kwargs['pkt_count']
                wrip = wrip1[0:kwargs['pkt_count']]
            wrpcap('%s/%s.pcap' % (self.localPath, kwargs['save_name']), wrip)
            self._upload('%s/%s.pcap' % (self.localPath, kwargs['save_name']),
                         '%s/%s.pcap' % (self.remotePath, kwargs['save_name']))
        # return '%s/%s.pcap' % (self.localPath, kwargs['save_name'])
        return '%s.pcap' % (kwargs['save_name'])

    def icmp(self,exist, **kwargs):
        if not exist:
            kwargs = self._defalutValue(**kwargs)
            v4v6 = 'IP' if str(kwargs['v4v6']).lower() == 'v4' else 'IPv6'
            singlePktLen = len(Ether() / eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / ICMP() / (kwargs['raw']))
            ipList = Ether() / eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / ICMP()/ Raw('0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (
                    kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            ip = [value for index, value in enumerate(
                ipList) if index < kwargs['pkt_count']]
            if len(ip) == kwargs['pkt_count']:
                wrip = ip
            else:
                wrip1 = ip * kwargs['pkt_count']
                wrip = wrip1[0:kwargs['pkt_count']]
            wrpcap('%s/%s.pcap' % (self.localPath, kwargs['save_name']), wrip)
            self._upload('%s/%s.pcap' % (self.localPath, kwargs['save_name']),
                          '%s/%s.pcap' % (self.remotePath, kwargs['save_name']))
        # return '%s/%s.pcap' % (self.localPath, kwargs['save_name'])
        return '%s.pcap' % ( kwargs['save_name'])

    def ah(self,exist, **kwargs):
        if not exist:
            kwargs = self._defalutValue(**kwargs)
            v4v6 = 'IP' if str(kwargs['v4v6']).lower() == 'v4' else 'IPv6'
            if str(kwargs['proto']).upper():
                try:
                    if kwargs['tcpflag']:
                        value = "{}(sport={},dport={},flags='{}')".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                                          kwargs['dport'], "".join(
                                [str(x[0]).upper() for x in kwargs['tcpflag'].split(',')]))
                    else:
                        value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                               kwargs['dport'])
                except:
                    value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                           kwargs['dport'])
                singlePktLen = len(Ether() / eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / AH()/eval(value) / (kwargs['raw']))
                ipList = Ether() / eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / AH()/eval(value) / Raw('0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (
                        kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            else:
                singlePktLen = len(Ether() /
                                   eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) /AH()/
                                   (kwargs['raw']))
                ipList = Ether() / eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / AH()/Raw(
                    '0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            ip = [value for index, value in enumerate(
                ipList) if index < kwargs['pkt_count']]
            if len(ip) == kwargs['pkt_count']:
                wrip = ip
            else:
                wrip1 = ip * kwargs['pkt_count']
                wrip = wrip1[0:kwargs['pkt_count']]
            wrpcap('%s/%s.pcap' % (self.localPath, kwargs['save_name']), wrip)
            self._upload('%s/%s.pcap' % (self.localPath, kwargs['save_name']),
                          '%s/%s.pcap' % (self.remotePath, kwargs['save_name']))
        # return '%s/%s.pcap' % (self.localPath, kwargs['save_name'])
        return '%s.pcap' % ( kwargs['save_name'])

    def l2tp(self, exist, **kwargs):
        if not exist:
            kwargs = self._defalutValue(**kwargs)
            v4v6 = 'IP' if str(kwargs['v4v6']).lower() == 'v4' else 'IPv6'
            out_v4v6 = 'IP' if str(kwargs['out_v4v6']).lower() == 'v4' else 'IPv6'
            if str(kwargs['proto']).upper():
                try:
                    if kwargs['tcpflag']:
                        value = "{}(sport={},dport={},flags='{}')".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                                          kwargs['dport'], "".join(
                                [str(x[0]).upper() for x in kwargs['tcpflag'].split(',')]))
                    else:
                        value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                               kwargs['dport'])
                except:
                    value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                           kwargs['dport'])
                singlePktLen = len(
                    Ether() / eval(out_v4v6)(src=kwargs['out_sip'], dst=kwargs['out_dip']) / UDP() / L2TP() / eval(
                        v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / eval(value) / (kwargs['raw']))
                ipList = Ether() / eval(out_v4v6)(src=kwargs['out_sip'],
                                                  dst=kwargs['out_dip']) / UDP() / L2TP() / eval(v4v6)(
                    src=kwargs['sip'], dst=kwargs['dip']) / eval(value) / Raw(
                    '0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (
                            kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            else:
                singlePktLen = len(Ether() /
                                   eval(out_v4v6)(src=kwargs['out_sip'], dst=kwargs['out_dip']) / UDP() / L2TP(
                    length=kwargs['pkt_len'] - gtp_len - 8) /
                                   eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) /
                                   (kwargs['raw']))
                ipList = Ether() / eval(out_v4v6)(src=kwargs['out_sip'],
                                                  dst=kwargs['out_dip']) / UDP() / L2TP() / eval(v4v6)(
                    src=kwargs['sip'], dst=kwargs['dip']) / Raw(
                    '0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (
                            kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            ip = [value for index, value in enumerate(
                ipList) if index < kwargs['pkt_count']]
            if len(ip) == kwargs['pkt_count']:
                wrip = ip
            else:
                wrip1 = ip * kwargs['pkt_count']
                wrip = wrip1[0:kwargs['pkt_count']]
            wrpcap('%s/%s.pcap' % (self.localPath, kwargs['save_name']), wrip)
            self._upload('%s/%s.pcap' % (self.localPath, kwargs['save_name']),
                         '%s/%s.pcap' % (self.remotePath, kwargs['save_name']))
        # return '%s/%s.pcap' % (self.localPath, kwargs['save_name'])
        return '%s.pcap' % (kwargs['save_name'])

    def pptp(self, exist, **kwargs):
        if not exist:
            kwargs = self._defalutValue(**kwargs)
            v4v6 = 'IP' if str(kwargs['v4v6']).lower() == 'v4' else 'IPv6'
            out_v4v6 = 'IP' if str(kwargs['out_v4v6']).lower() == 'v4' else 'IPv6'
            if str(kwargs['proto']).upper():
                try:
                    if kwargs['tcpflag']:
                        value = "{}(sport={},dport={},flags='{}')".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                                          kwargs['dport'], "".join(
                                [str(x[0]).upper() for x in kwargs['tcpflag'].split(',')]))
                    else:
                        value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                               kwargs['dport'])
                except:
                    value = "{}(sport={},dport={})".format(str(kwargs['proto']).upper(), kwargs['sport'],
                                                           kwargs['dport'])
                singlePktLen = len(
                    Ether() / eval(out_v4v6)(src=kwargs['out_sip'], dst=kwargs['out_dip']) / TCP() / PPTP() / eval(
                        v4v6)(src=kwargs['sip'], dst=kwargs['dip']) / eval(value) / (kwargs['raw']))
                ipList = Ether() / eval(out_v4v6)(src=kwargs['out_sip'],
                                                  dst=kwargs['out_dip']) / UDP() / L2TP() / eval(v4v6)(
                    src=kwargs['sip'], dst=kwargs['dip']) / eval(value) / Raw(
                    '0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (
                            kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            else:
                singlePktLen = len(Ether() /
                                   eval(out_v4v6)(src=kwargs['out_sip'], dst=kwargs['out_dip']) / UDP() / L2TP(
                    length=kwargs['pkt_len'] - gtp_len - 8) /
                                   eval(v4v6)(src=kwargs['sip'], dst=kwargs['dip']) /
                                   (kwargs['raw']))
                ipList = Ether() / eval(out_v4v6)(src=kwargs['out_sip'],
                                                  dst=kwargs['out_dip']) / UDP() / L2TP() / eval(v4v6)(
                    src=kwargs['sip'], dst=kwargs['dip']) / Raw(
                    '0' * kwargs['raw_offset'] + kwargs['raw'] + '0' * (
                            kwargs['pkt_len'] - singlePktLen - kwargs['raw_offset']))
            ip = [value for index, value in enumerate(
                ipList) if index < kwargs['pkt_count']]
            if len(ip) == kwargs['pkt_count']:
                wrip = ip
            else:
                wrip1 = ip * kwargs['pkt_count']
                wrip = wrip1[0:kwargs['pkt_count']]
            wrpcap('%s/%s.pcap' % (self.localPath, kwargs['save_name']), wrip)
            self._upload('%s/%s.pcap' % (self.localPath, kwargs['save_name']),
                         '%s/%s.pcap' % (self.remotePath, kwargs['save_name']))
        # return '%s/%s.pcap' % (self.localPath, kwargs['save_name'])
        return '%s.pcap' % (kwargs['save_name'])

if __name__ == '__main__':
    """
    独立运行模式:
      python makePcapFile.py <config_name> <title> [output_dir]
      python makePcapFile.py <config_name> all       [output_dir]  # 生成所有 section

    示例:
      python makePcapFile.py rcpClearLimit_packet v4_day_fivetuple
      python makePcapFile.py rcpClearLimit_packet all ./output
    """
    import sys, configparser
    if len(sys.argv) < 3:
        print('Usage: python makePcapFile.py <config_name> <title|all> [output_dir]')
        print('  config_name: ini 文件名（不含 .ini 后缀），位于 config/ 目录')
        print('  title:       指定 section 名，或 "all" 生成全部')
        print('  output_dir:  输出目录（默认 ./pcaps）')
        sys.exit(1)

    config_name = sys.argv[1]
    title_arg = sys.argv[2]
    output_dir = sys.argv[3] if len(sys.argv) > 3 else os.path.join(os.path.dirname(__file__), 'pcaps')

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 独立模式: skip_upload=True, remotePath 不使用
    pp = makePcapFile(output_dir, '', skip_upload=True)

    if title_arg == 'all':
        # 读取 ini 文件所有 section 名
        ini_path = os.path.join(os.path.dirname(__file__), 'config', config_name + '.ini')
        cp = configparser.ConfigParser()
        cp.read(ini_path)
        titles = cp.sections()
        print('Generating %d packets from [%s]...' % (len(titles), config_name))
    else:
        titles = title_arg.split(',')

    start_time = time.time()
    for title in titles:
        result = pp.makePcap(0, config_name, title)
        print('  %s -> %s' % (title, result))
    print('Done. Time: %.2fs' % (time.time() - start_time))