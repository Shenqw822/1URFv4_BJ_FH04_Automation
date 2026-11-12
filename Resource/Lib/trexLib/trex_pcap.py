#!/bin/bash/env python
# -*- coding: utf-8 -*-

import trex
import time
import trex_stl_lib.api
from trex_stl_lib.api import *


global serverip
serverip= "192.168.3.9"
global user
user = "D_AutoTest"
global portid
portid = "0"
global conn

def Trex_load_pcap(filename):
    conn = trex.connect_trex(serverip,user)
    pkts = trex.ld_pcap(filename)
    stream_total = []

    for i in range(len(pkts)):
        # print(len(pkts))
        stream = trex.create_stream(pkts[i])
        stream_total.append(stream)

    trex.add_stream_for_port(conn,portid,stream_total)
    trex.init_capture(conn)
    capture = trex.capture_port_start(conn,portid)
    trex.start_flow(conn,1,portid)
    time.sleep(3)
    timestamp = trex.capture_port_stop(conn,capture,portid,"333")
    trex.close_connect(conn)
    return timestamp

def Trex_load_pcap_burst(filename,*packet_name):
    try:
        global conn
        conn = trex.connect_trex(serverip,user)
        pkts = trex.ld_pcap(filename)
        stream_total = []
        for i in range(len(pkts)):
            # print(len(pkts))
            stream = trex.create_stream_burst(pkts[i],1)
            stream_total.append(stream)
        # modify by yangwei: function trex.init_capture() should be put before trex.add_stream_for_port
        trex.init_capture(conn)
        trex.add_stream_for_port(conn,portid,stream_total)
        capture_rx,capture_tx = trex.capture_port_start(conn,portid)
        trex.start_flow(conn,2,portid)
        time.sleep(2)
        if len(packet_name)<=0:
            packet='1'
        else:
            packet=str(packet_name[0])
        timestamp_tx = trex.capture_port_stop(conn, capture_tx, portid, packet+"_tx")
        time.sleep(2)
        timestamp_rx = trex.capture_port_stop(conn,capture_rx,portid,packet+"_rx")

    finally:
        trex.close_connect(conn)
    return  timestamp_rx,timestamp_tx

def Trex_create_stream():
    conn = trex.connect_trex(serverip,user)
    stream = trex.create_stream_vlan(90)
    # print(len(stream))
    trex.add_stream_for_port(conn,portid,stream[4])

    trex.init_capture(conn)
    capture = trex.capture_port_start(conn,portid)
    trex.start_flow(conn,5,portid)
    time.sleep(3)
    timestamp = trex.capture_port_stop(conn,capture,portid,"333")
    trex.close_connect(conn)
    return timestamp

def Trex_load_pcap_burst_onebyone(filename,*packet_name):
    '''
    报文按pacp存放顺序发送
    '''
    try:
        global conn
        conn = trex.connect_trex(serverip,user)
        pkts = trex_stl_lib.api.STLProfile.load_pcap(filename,)
        print(pkts)
        trex.init_capture(conn)
        conn.reset(int(portid))
        capture_rx, capture_tx = trex.capture_port_start(conn, portid)
        streams_list = []
        for i in range(1,len(pkts)+1):
            pkt = trex_stl_lib.api.STLPktBuilder(pkts[-i])
            if i == 1:
                stream_s= trex_stl_lib.api.STLStream(name=i,packet=pkt, mode=trex_stl_lib.api.STLTXSingleBurst(total_pkts=1,percentage=0.001))
            else:
                stream_s = trex_stl_lib.api.STLStream(name=i,packet=pkt,
                                                    mode=trex_stl_lib.api.STLTXSingleBurst(total_pkts=1, percentage=0.001),next=streams_list[-1].get_name())
            streams_list.append(stream_s)

            conn.add_streams(stream_s,ports=int(portid))

        # conn.add_streams(streams,ports=int(portid))
        trex.start_flow(conn,2,portid)
        time.sleep(0.1)

        if len(packet_name)<=0:
            packet='1'
        else:
            packet=str(packet_name[0])
        timestamp_tx = trex.capture_port_stop(conn, capture_tx, portid, packet+"_tx")
        time.sleep(2)
        timestamp_rx = trex.capture_port_stop(conn,capture_rx,portid,packet+"_rx")
    finally:
        trex.close_connect(conn)
    return timestamp_rx, timestamp_tx

def Trex_capture(start_or_stop,capture_id=(0,0),*packet_name):
    try:
        global conn
        conn = trex.connect_trex(serverip, user)
        if len(packet_name) <= 0:
            packet = '1'
        else:
            packet = str(packet_name[0])
        if str(start_or_stop).lower()== 'start':
            trex.init_capture(conn)
            port = int(portid)
            conn.reset(port)
            capture_rx, capture_tx = trex.capture_port_start(conn, portid)
            timestamp_rx,timestamp_tx=capture_rx, capture_tx
        elif str(start_or_stop).lower()== 'stop':
            timestamp_tx = trex.capture_port_stop(conn, capture_id[1], portid, packet + "_tx")
            timestamp_rx = trex.capture_port_stop(conn, capture_id[0], portid, packet + "_rx")
    finally:
        trex.close_connect(conn)
    return  timestamp_rx,timestamp_tx

def start_262144(*packet_name):
    try:
        global conn
        conn = trex.connect_trex(serverip, user)
        streams = []
        packet = (Ether(dst='00:00:00:00:00:00', src='00:00:00:00:00:00', type=2048) /
                  IP(ihl=5, len=110, id=1234, ttl=127, proto=6, chksum=64694, src='10.0.0.1') /
                  TCP(sport=1025, dport=1025, seq=129018, dataofs=5, reserved=2, flags=192, window=1024, chksum=46051,
                      options=[]) /
                  Raw(
                      load=b'\x00\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'))
        vm = STLVM()
        vm.var(name='ip_src', op='inc', step=1, size=4, min_value='10.0.0.1', max_value='10.4.0.0')
        vm.write(fv_name='ip_src', pkt_offset=26, add_val=0, byte_order='big')
        # vm.fix_chksum_hw(l3_offset='IP', l4_offset='TCP', l4_type=17)
        stream = STLStream(packet=STLPktBuilder(pkt=packet, vm=vm),
                           name='262144',
                           stream_id=0,
                           mac_src_override_by_pkt=False,
                           mac_dst_override_mode=0,
                           mode=STLTXSingleBurst(total_pkts=262144, percentage=1.0))
        streams.append(stream)
        trex.init_capture(conn)
        trex.add_stream_for_port(conn, portid, streams)
        capture_rx, capture_tx = trex.capture_port_start(conn, portid)
        trex.start_flow(conn, 2, portid)
        time.sleep(2)
        if len(packet_name) <= 0:
            packet = '1'
        else:
            packet = str(packet_name[0])
        timestamp_tx = trex.capture_port_stop(conn, capture_tx, portid, packet + "_tx")
        time.sleep(2)
        timestamp_rx = trex.capture_port_stop(conn, capture_rx, portid, packet + "_rx")

    finally:
        trex.close_connect(conn)
    return timestamp_rx, timestamp_tx
