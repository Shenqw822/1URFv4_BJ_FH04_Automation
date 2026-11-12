#!/bin/bash/env python
#-*- coding:utf-8 -*-
#Author song

import trex_stl_lib.api
import time
import os
import scapy
from scapy.all import rdpcap


def create_stream_vlan(speed,svlan=200,cvlan=100,ccvlan=300):
    """
    function:
        建流由于otn对五元组之类的不关注，后续需要可以通过参数设置，这里只进行速率的设置
        由于otn项目的流基本也就3种vlan 100,vlan 200,不带vlan
    argument:
        speed : 打流的速率
        *vlan : 接受vlan，返回tuple格式
    return value :
        streams = [vlan100_stream,vlan200_stream,stream]
    """
    speed = int(speed)
    svlan = int(svlan)
    cvlan - int(cvlan)
    ccvlan = int(ccvlan)
    base_pkt = trex_stl_lib.api.Ether(src="70:88:6b:ae:B1:11",dst="70:88:6b:ae:B1:12") /trex_stl_lib.api.Dot1Q(vlan=cvlan)/trex_stl_lib.api.IP(src="16.0.0.1", dst="48.0.0.1") / trex_stl_lib.api.UDP(dport=12, sport=1025)
    base_pkt1 = trex_stl_lib.api.Ether(dst="70:88:6b:ae:B1:11",src="70:88:6b:ae:B1:12") / trex_stl_lib.api.Dot1Q(vlan=svlan)/trex_stl_lib.api.IP(src="16.0.0.2", dst="48.0.0.1") / trex_stl_lib.api.UDP(dport=12, sport=1025)
    base_pkt2 = trex_stl_lib.api.Ether() / trex_stl_lib.api.Dot1Q(vlan=svlan)/trex_stl_lib.api.Dot1Q(vlan=cvlan)/ trex_stl_lib.api.IP(src="16.0.0.2",dst="48.0.0.1") / trex_stl_lib.api.UDP(dport=12, sport=1025)
    base_pkt3 = trex_stl_lib.api.Ether() / trex_stl_lib.api.IP(src="16.0.0.3", dst="48.0.0.1") / trex_stl_lib.api.UDP(dport=12, sport=1025)
    base_pkt4 = trex_stl_lib.api.Ether(dst="70:88:6b:ae:B1:13",src="70:88:6b:ae:B1:14") / trex_stl_lib.api.Dot1Q(vlan=ccvlan)/trex_stl_lib.api.IP(src="16.0.0.3", dst="48.0.0.1") / trex_stl_lib.api.UDP(dport=12, sport=1025)
    return trex_stl_lib.api.STLProfile([trex_stl_lib.api.STLStream(packet=trex_stl_lib.api.STLPktBuilder(pkt=base_pkt),mode=trex_stl_lib.api.STLTXCont(percentage=speed)),
                                        trex_stl_lib.api.STLStream(packet=trex_stl_lib.api.STLPktBuilder(pkt=base_pkt1),mode=trex_stl_lib.api.STLTXCont(percentage=speed)),
                                        trex_stl_lib.api.STLStream(packet=trex_stl_lib.api.STLPktBuilder(pkt=base_pkt2),mode=trex_stl_lib.api.STLTXCont(percentage=speed)),
                                        trex_stl_lib.api.STLStream(packet=trex_stl_lib.api.STLPktBuilder(pkt=base_pkt3),mode=trex_stl_lib.api.STLTXCont(percentage=speed)),
                                        trex_stl_lib.api.STLStream(packet=trex_stl_lib.api.STLPktBuilder(pkt=base_pkt4),mode=trex_stl_lib.api.STLTXCont(percentage=speed))]).get_streams()

def create_speci_stream(speed,payloadsize,svlan=200,cvlan=100,ssvlan=300):
    """
    note payloadsize设置值最大为
        当为udp报文：payloadsize = 包长 - (18(eth)+20(ip)+8(udp))=包长-46
        当为tcp报文：payloadsize = 包长 -(18(eth)+20(ip)+20(tcp))=包长-58
    """
    speed = int(speed)
    payloadsize = int(payloadsize)
    base_pkt = trex_stl_lib.api.Ether(src="70:88:6b:ae:B1:11",dst="70:88:6b:ae:B1:12") / \
               trex_stl_lib.api.Dot1Q(vlan=svlan) /\
               trex_stl_lib.api.IP(src="16.0.0.1",dst="48.0.0.1") / \
               trex_stl_lib.api.UDP(dport=12, sport=1025)/\
               ('\x55'*(payloadsize))
    base_pkt_1 = trex_stl_lib.api.Ether(src="70:88:6b:ae:B1:11",dst="70:88:6b:ae:B1:12") / \
               trex_stl_lib.api.Dot1Q(vlan=cvlan) / \
               trex_stl_lib.api.IP(dst="16.0.0.1", src="48.0.0.1") / \
               trex_stl_lib.api.UDP(dport=12, sport=1025) / \
               ('\x55' * (payloadsize))
    base_pkt_2 = trex_stl_lib.api.Ether() / \
               trex_stl_lib.api.Dot1Q(vlan=svlan) / \
                trex_stl_lib.api.Dot1Q(vlan=cvlan) /\
                trex_stl_lib.api.IP(src="16.0.0.1", dst="48.0.0.1") / \
               trex_stl_lib.api.UDP(dport=12, sport=1025) / \
               ('\x55' * (payloadsize))

    base_pkt_3 = trex_stl_lib.api.Ether(src="70:88:6b:ae:B1:11",dst="70:88:6b:ae:B1:12") / \
                 trex_stl_lib.api.Dot1Q(vlan=ssvlan) / \
                 trex_stl_lib.api.IP(src="16.0.0.1", dst="48.0.0.1") / \
                 trex_stl_lib.api.UDP(dport=12, sport=1025) / \
                 ('\x55' * (payloadsize))

    base_pkt_4 = trex_stl_lib.api.Ether() / \
               trex_stl_lib.api.IP(src="16.0.0.1",dst="48.0.0.1") / \
               trex_stl_lib.api.UDP(dport=12, sport=1025)/\
               ('\x55'*(payloadsize))
    vm = trex_stl_lib.api.STLScVmRaw([trex_stl_lib.api.STLVmFlowVar(name="fv_rand",
                                                                    min_value=64,
                                                                    max_value=len(base_pkt),
                                                                    size=2,
                                                                    op="random"),
                                      trex_stl_lib.api.STLVmTrimPktSize("fv_rand")])
    return trex_stl_lib.api.STLProfile([trex_stl_lib.api.STLStream(packet=trex_stl_lib.api.STLPktBuilder(pkt=base_pkt,vm=vm),mode=trex_stl_lib.api.STLTXCont(percentage=speed)),
                                        trex_stl_lib.api.STLStream(
                                            packet=trex_stl_lib.api.STLPktBuilder(pkt=base_pkt_1, vm=vm),
                                            mode=trex_stl_lib.api.STLTXCont(percentage=speed)),
                                        trex_stl_lib.api.STLStream(
                                            packet=trex_stl_lib.api.STLPktBuilder(pkt=base_pkt_2, vm=vm),
                                            mode=trex_stl_lib.api.STLTXCont(percentage=speed)),
                                        trex_stl_lib.api.STLStream(
                                            packet=trex_stl_lib.api.STLPktBuilder(pkt=base_pkt_3, vm=vm),
                                            mode=trex_stl_lib.api.STLTXCont(percentage=speed)),
                                        trex_stl_lib.api.STLStream(
                                            packet=trex_stl_lib.api.STLPktBuilder(pkt=base_pkt_4, vm=vm),
                                            mode=trex_stl_lib.api.STLTXCont(percentage=speed))]).get_streams()

def connect_trex(serverip,username):
    """
    function:
        建立和trex仪表连接
    argument:
        serverip : trex仪表服务器ip
        username : 登入用户名
    return values:
        conn object :返回连接对象
    """
    conn = trex_stl_lib.api.STLClient(server=serverip, username=username)
    conn.connect()
    return conn

def add_stream_for_port(conn,port,karg):
    """
    function:
        把stream和port进行绑定,以便后面打流
    argument:
        conn : trex连接对象
        port : 对应的端口
        karg : 对应的流
    """
    port = int(port)
    conn.reset(port)
    conn.add_streams(karg,ports=port)
    time.sleep(5)

def get_work_dir(dir_name):
    work_dir_win=os.getcwd()+"\\Resource\\Business"
    #work_dir_win = os.path.abspath(os.path.join(os.getcwd(), ".."))+"\\Resource\\Business"
    work_dir=work_dir_win.replace("\\","/")
    return work_dir+"/"+dir_name+"/"

def ld_pcap(pcapfile):
    pkts = scapy.all.rdpcap(pcapfile)
    return pkts

def create_stream_profile(pkts):
    return trex_stl_lib.api.STLProfile([trex_stl_lib.api.STLStream(packet=trex_stl_lib.api.STLPktBuilder(pkt=pkts))]).get_streams()

def create_stream(pkts):
    pkt=trex_stl_lib.api.STLPktBuilder(pkts)                 #封装成TRex的包结构
    stream = trex_stl_lib.api.STLStream(packet=pkt,mode=trex_stl_lib.api.STLTXCont(percentage=1))    #建TRex流
    #streams.append(stream)
    return stream

def create_stream_burst(pkts,total_burst_pkts):
    # print("start create stream burst")
    pkt=trex_stl_lib.api.STLPktBuilder(pkts)                 #封装成TRex的包结构
    stream = trex_stl_lib.api.STLStream(packet=pkt,mode=trex_stl_lib.api.STLTXSingleBurst(total_pkts=total_burst_pkts,percentage=1))    #建TRex流
    #streams.append(stream)
    return stream

def start_flow(conn,times=0,*ports):
    """
    function:
        端口进行开始打流
    notes:
        关于ports参数，python下需要List形式,robot是字符形式
    argument：
        conn : trex仪表连接对象
        port : 指定的端口
        times : 打流的时长，默认为0，持续打流
    """
    times = int(times)
    port_1=[]
    for i in ports:
        a=int(i)
        port_1.append(a)
    conn.clear_stats()
    conn.start(ports=port_1,duration = times,force=True)
    if times == 0:
        pass
    else:
        conn.wait_on_traffic(ports=port_1)
    time.sleep(5)

def get_count(conn,port):
    """
    function：
        获取指定端口的统计计数
    argument:
        conn : trex连接对象
        port : 指定端口
    return value:
        返回端口计数--字典
         ================== ===============
         key                 Meaning
         =================  ===============
         ibytes             Number of input bytes
         ierrors            Number of input errors
         ipackets           Number of input packets
         obytes             Number of output bytes
         oerrors            Number of output errors
         opackets           Number of output packets
         rx_bps             Receive bits per second rate(L2 layer)
         rx_pps             Receive packet per second rate
         tx_bps             Transmit bits per second rate(L2 layer)
         tx_pps             Transmit packet per second rate
         =================  ===============
    """
    port = int(port)
    stats = conn.get_stats()
    return stats[port]

def capture_port_start(conn,port,packgecount=10000,bpf_fl=None):
    """
    function:
        对端口开始进行抓包
    notice：
        抓包必须在打流之前打开，否则可能抓不到
        port必须在service模式下进行
    argumen:
        conn : trex连接对象
        port : 对应的抓包端口
        packgetcunt : 抓包的个数,默认10000个
        bfp_fl : 抓包的filter条件,例如:"vlan 200","udp adn dst 53","vlan 100 and tcp[tcpflags]  == tcp-syn"等等
    return value:
        返回存包的对象
           'id: <new_id>, 'ts': <starting timestamp>}
                where 'id' is the new capture ID for future commands
                and 'ts' is that server monotonic timestamp when
                the capture was created
    """
    port = int(port)
    packgecount = int(packgecount)
    # print("packgecount = ", packgecount)
    conn.set_service_mode(ports=port,enabled=True)
    capture_rx = conn.start_capture(rx_ports=port,limit=packgecount,mode='fixed',bpf_filter=bpf_fl)
    capture_tx = conn.start_capture(tx_ports=port, limit=packgecount, mode='fixed', bpf_filter=bpf_fl)
    return capture_rx,capture_tx

# def capture_port_stop(conn,capture,port,path_to_save_pcap="1"):
#
#     """
#     funtion:
#         停止抓包，且以file.pcap形式进行保存
#     notice:
#         port必须在service模式下进行
#     argumen:
#         conn : trex连接对象
#         capture : start_capture返回的存包对象
#         port : 对应的端口
#         path_to_save_pcap : 保存抓包结果路径,不传递
#     """
#
#     curr_dir = get_work_dir("ripe_packets")
#     # print(curr_dir)
#     port = int(port)
#     if path_to_save_pcap == None:
#
#         conn.stop_capture(capture['id'])
#     else:
#         path_to_save_pcap=str(time.time())+"_"+path_to_save_pcap
#         conn.stop_capture(capture['id'], curr_dir + path_to_save_pcap+".pcap")
#     # print(str(curr_dir + path_to_save_pcap))
#     return str(curr_dir + path_to_save_pcap)

def capture_port_stop(conn,capture,port,path_to_save_pcap="1"):

    """
    funtion:
        停止抓包，且以file.pcap形式进行保存
    notice:
        port必须在service模式下进行
    argumen:
        conn : trex连接对象
        capture : start_capture返回的存包对象
        port : 对应的端口
        path_to_save_pcap : 保存抓包结果路径,不传递
    """
    #2022-04-19为解决保存包乱序问题

    curr_dir = get_work_dir("ripe_packets")
    # print(curr_dir)
    port = int(port)
    if path_to_save_pcap == None:
        conn.stop_capture(capture['id'])
    else:
        path_to_save_pcap=str(time.time())+"_"+path_to_save_pcap
        conn.stop_capture(capture['id'], curr_dir + path_to_save_pcap+".pcap")
    return str(curr_dir + path_to_save_pcap)

def relase_capture(conn,capture,port,vlan):
    """
    function:
        解析端口收到的包是否包含vlan,判断其他字段可以根据需求后续增加
    argument：
        conn : trex连接对象
        capture : start_capture返回的存包对象
        port : 对应的端口
        vlan : 判断的vlan值
    return value:
        如果包含返回0,不包含返回1
    """
    port = int(port)
    rx_pkg = []
    conn.set_service_mode(ports=port)
    conn.stop_capture(capture['id'],output=rx_pkg)
    conn.set_service_mode(ports=port, enabled=False)
    rx_scapy_pkt = trex_stl_lib.api.Ether(rx_pkg[0]['binary'])
    if rx_scapy_pkt.vlan == vlan:
        return 0
    else:
        return 1
    #print(rx_scapy_pkt.show2())

def close_connect(conn):
    """
    function:
        断开之前停止所占用端口的打流
        断开trex的连接
        释放所有占用的端口
    argumen:
        conn : trex连接对象
    """
    conn.disconnect()

def stop_flow(conn,*ports):
    """
    funtion:
        停止对应端口打流
    argument：
        conn : trex连接对象
        port指定端口
    """
    port_1=[]
    for i in ports:
        a=int(i)
        port_1.append(a)
    conn.stop(ports=port_1)

def get_hit_count(conn,port,capture):
    """
    funtion:
        获取对应的过滤计数
    argument:
        conn : trex连接对象
        port : 对应的端口
        capture : 对应的抓包器对象
    return:
        返回对应的匹配的包计数
    note:
        先打流-->抓包-->获取hit计数-->停止抓包
        且统计出来的计数和start_capture中的bfl条件一致
    """
    port = int(port)
    macth_count = conn.get_capture_status()[capture['id']]["matched"]
    return macth_count

def init_capture(conn):
    """
    function:
        针对trex存在抓包操作未正常关闭的情况下，会导致端口无法占用之类需要关闭抓包
    argument:
        conn : trex连接对象
    """
    h = conn.get_capture_status()
    active_cap = len(h.keys())
    if active_cap == 0:
        pass
    else:
        for i in h.keys():
            conn.stop_capture(i)

if __name__ == "__main__":
    conn = connect_trex("192.168.3.16","songxf")



