#!/bin/bash/env python
# -*- coding: utf-8 -*-

import parsepcap
from scapy.all import *

def eth_parse(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smac = []
    Dmac = []
    padding_eth = []
    packet_length = []
    payload_eth = []

    for i in range(count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        print(p10)
        try:
            p9 = parsepcap.pkt_padding(pp,i) #只包含padding的数据(也即是tlv)，不包含报文的payload
            time.sleep(0.2)
        except IndexError:
            print("No padding")
            p9=""   
        try:
            p11 = parsepcap.pkt_raw_data(pp,i) #只包含报文payload
            time.sleep(0.2)
        except IndexError:
            print("No Raw")
            p11=""

        print(p1,p2)
        print(p9,p10,p11)
        time.sleep(0.2)

        Smac.append(p1)
        Dmac.append(p2)
        padding_eth.append(p9)
        packet_length.append(p10)
        payload_eth.append(p11)

    print(Smac,Dmac)
    print(padding_eth,packet_length,payload_eth)

    return Smac,Dmac,padding_eth,packet_length,payload_eth

def ipv4_tcp_parse(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    Protocolv4 = []
    Sportv4 = []
    Dportv4 = []
    pduv4 = []
    packet_length = []
    pduv4data = []

    for i in range(count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p5 =  parsepcap.pkt_protocol(pp,i)
        p6 = parsepcap.pkt_sporttcp(pp,i)
        p7 =  parsepcap.pkt_dporttcp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-58)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i) #只包含padding的数据，不包含报文的payload
        time.sleep(0.2)
        try:
            p11 = parsepcap.pkt_raw_data(pp,i) #只包含报文payload
            time.sleep(0.2)
        except IndexError:
            print("No Raw")
            p11=""

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10,p11)
        time.sleep(0.2)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        Protocolv4.append(p5)
        Sportv4.append(p6)
        Dportv4.append(p7)
        pduv4.append(p9)
        packet_length.append(p10)
        pduv4data.append(p11)

    print(Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4)
    print(pduv4,packet_length,pduv4data)

    return Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4,pduv4,packet_length,pduv4data


def ipv4_tcp_parse_noipabstract(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    Protocolv4 = []
    Sportv4 = []
    Dportv4 = []
    pduv4 = []
    packet_length = []
    pduv4data = []

    for i in range(count_number-2):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p5 =  parsepcap.pkt_protocol(pp,i)
        p6 = parsepcap.pkt_sporttcp(pp,i)
        p7 =  parsepcap.pkt_dporttcp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-58)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i) #只包含padding的数据，不包含报文的payload
        time.sleep(1)
        p11 = parsepcap.pkt_raw_data(pp,i) #只包含报文payload
        time.sleep(1)

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10,p11)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        Protocolv4.append(p5)
        Sportv4.append(p6)
        Dportv4.append(p7)
        pduv4.append(p9)
        packet_length.append(p10)
        pduv4data.append(p11)

    print(Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4)
    print(pduv4,packet_length,pduv4data)

    return Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4,pduv4,packet_length,pduv4data

def ipv4_tcp_parse_x86(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    Protocolv4 = []
    Sportv4 = []
    Dportv4 = []
    pduv4 = []
    packet_length = []
    pduv4data = []

    for i in range(count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p5 =  parsepcap.pkt_protocol(pp,i)
        p6 = parsepcap.pkt_sporttcp(pp,i)
        p7 =  parsepcap.pkt_dporttcp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-58)
        print(a)
        p9 = parsepcap.pkt_raw_hex(pp,i) #包含报文payload和padding的数据，
        time.sleep(1)
        p11 = parsepcap.pkt_raw_data(pp,i) #只包含报文payload
        time.sleep(1)

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10,p11)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        Protocolv4.append(p5)
        Sportv4.append(p6)
        Dportv4.append(p7)
        pduv4.append(p9)
        packet_length.append(p10)
        pduv4data.append(p11)

    print(Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4)
    print(pduv4,packet_length,pduv4data)

    return Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4,pduv4,packet_length,pduv4data

def ipv4_tcp_parse_nopayload(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    Protocolv4 = []
    Sportv4 = []
    Dportv4 = []
    pduv4 = []
    packet_length = []

    for i in range(count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p5 =  parsepcap.pkt_protocol(pp,i)
        p6 = parsepcap.pkt_sporttcp(pp,i)
        p7 =  parsepcap.pkt_dporttcp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-58)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        Protocolv4.append(p5)
        Sportv4.append(p6)
        Dportv4.append(p7)
        pduv4.append(p9)
        packet_length.append(p10)

    print(Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4)
    print(pduv4,packet_length)

    return Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4,pduv4,packet_length

def ipv4_tcp_parse_nopayload_noipabstract(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    Protocolv4 = []
    Sportv4 = []
    Dportv4 = []
    pduv4 = []
    packet_length = []

    for i in range(count_number-2):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p5 =  parsepcap.pkt_protocol(pp,i)
        p6 = parsepcap.pkt_sporttcp(pp,i)
        p7 =  parsepcap.pkt_dporttcp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-58)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        Protocolv4.append(p5)
        Sportv4.append(p6)
        Dportv4.append(p7)
        pduv4.append(p9)
        packet_length.append(p10)

    print(Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4)
    print(pduv4,packet_length)

    return Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4,pduv4,packet_length

def ipv4_tcp_parse_nopayload_ipabstract(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    Protocolv4 = []
    Sportv4 = []
    Dportv4 = []
    pduv4 = []
    packet_length = []

    for i in range(1,count_number-1):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p5 =  parsepcap.pkt_protocol(pp,i)
        p6 = parsepcap.pkt_sporttcp(pp,i)
        p7 =  parsepcap.pkt_dporttcp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-58)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        Protocolv4.append(p5)
        Sportv4.append(p6)
        Dportv4.append(p7)
        pduv4.append(p9)
        packet_length.append(p10)

    print(Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4)
    print(pduv4,packet_length)

    return Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4,pduv4,packet_length

def ipv4_tcp_parse_nopayload_ipsession(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    Protocolv4 = []
    Sportv4 = []
    Dportv4 = []
    pduv4 = []
    packet_length = []

    for i in range(2,count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p5 =  parsepcap.pkt_protocol(pp,i)
        p6 = parsepcap.pkt_sporttcp(pp,i)
        p7 =  parsepcap.pkt_dporttcp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-58)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        Protocolv4.append(p5)
        Sportv4.append(p6)
        Dportv4.append(p7)
        pduv4.append(p9)
        packet_length.append(p10)

    print(Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4)
    print(pduv4,packet_length)

    return Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4,pduv4,packet_length

def ipv4_tcp_parse_nopayload_x86(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    Protocolv4 = []
    Sportv4 = []
    Dportv4 = []
    pduv4 = []
    packet_length = []

    for i in range(count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p5 =  parsepcap.pkt_protocol(pp,i)
        p6 = parsepcap.pkt_sporttcp(pp,i)
        p7 =  parsepcap.pkt_dporttcp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-58)
        print(a)
        p9 = parsepcap.pkt_raw_hex(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        Protocolv4.append(p5)
        Sportv4.append(p6)
        Dportv4.append(p7)
        pduv4.append(p9)
        packet_length.append(p10)

    print(Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4)
    print(pduv4,packet_length)

    return Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4,pduv4,packet_length


def ipv4_udp_parse(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    Protocolv4 = []
    Sportv4 = []
    Dportv4 = []
    pduv4 = []
    packet_length = []
    pduv4data = []

    for i in range(count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p5 =  parsepcap.pkt_protocol(pp,i)
        p6 = parsepcap.pkt_sportudp(pp,i)
        p7 =  parsepcap.pkt_dportudp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-46)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i)
        time.sleep(1)
        try:
            p11 = parsepcap.pkt_raw_data(pp,i) #只包含报文payload
            time.sleep(1)
        except IndexError:
            print("No Raw")
            p11=""

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10,p11)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        Protocolv4.append(p5)
        Sportv4.append(p6)
        Dportv4.append(p7)
        pduv4.append(p9)
        packet_length.append(p10)
        pduv4data.append(p11)

    print(Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4)
    print(pduv4,packet_length,pduv4data)

    return Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4,pduv4,packet_length,pduv4data

def ipv4_udp_parse_noipabstract(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    Protocolv4 = []
    Sportv4 = []
    Dportv4 = []
    pduv4 = []
    packet_length = []
    pduv4data = []

    for i in range(count_number-2):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p5 =  parsepcap.pkt_protocol(pp,i)
        p6 = parsepcap.pkt_sportudp(pp,i)
        p7 =  parsepcap.pkt_dportudp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-46)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i)
        time.sleep(1)
        p11 = parsepcap.pkt_raw_data(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10,p11)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        Protocolv4.append(p5)
        Sportv4.append(p6)
        Dportv4.append(p7)
        pduv4.append(p9)
        packet_length.append(p10)
        pduv4data.append(p11)

    print(Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4)
    print(pduv4,packet_length,pduv4data)

    return Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4,pduv4,packet_length,pduv4data

def ipv4_udp_parse_nopayload_noipabstract(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    Protocolv4 = []
    Sportv4 = []
    Dportv4 = []
    pduv4 = []
    packet_length = []
    pduv4data = []

    for i in range(count_number-2):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p5 =  parsepcap.pkt_protocol(pp,i)
        p6 = parsepcap.pkt_sportudp(pp,i)
        p7 =  parsepcap.pkt_dportudp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-46)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i)
        try:
            p11 = parsepcap.pkt_raw_data(pp,i) #只包含报文payload
            time.sleep(1)
        except IndexError:
            print("No Raw")
            p11=""

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10,p11)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        Protocolv4.append(p5)
        Sportv4.append(p6)
        Dportv4.append(p7)
        pduv4.append(p9)
        packet_length.append(p10)
        pduv4data.append(p11)

    print(Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4)
    print(pduv4,packet_length,pduv4data)

    return Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4,pduv4,packet_length,pduv4data

def ipv4_udp_parse_x86(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    Protocolv4 = []
    Sportv4 = []
    Dportv4 = []
    pduv4 = []
    packet_length = []
    pduv4data = []

    for i in range(count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p5 =  parsepcap.pkt_protocol(pp,i)
        p6 = parsepcap.pkt_sportudp(pp,i)
        p7 =  parsepcap.pkt_dportudp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-46)
        print(a)
        p9 = parsepcap.pkt_raw_hex(pp,i)
        time.sleep(1)
        p11 = parsepcap.pkt_raw_data(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10,p11)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        Protocolv4.append(p5)
        Sportv4.append(p6)
        Dportv4.append(p7)
        pduv4.append(p9)
        packet_length.append(p10)
        pduv4data.append(p11)

    print(Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4)
    print(pduv4,packet_length,pduv4data)

    return Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4,pduv4,packet_length,pduv4data

def ipv4_udp_parse_nopayload(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    Protocolv4 = []
    Sportv4 = []
    Dportv4 = []
    pduv4 = []
    packet_length = []

    for i in range(count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p5 =  parsepcap.pkt_protocol(pp,i)
        p6 = parsepcap.pkt_sportudp(pp,i)
        p7 =  parsepcap.pkt_dportudp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-46)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        Protocolv4.append(p5)
        Sportv4.append(p6)
        Dportv4.append(p7)
        pduv4.append(p9)
        packet_length.append(p10)

    print(Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4)
    print(pduv4,packet_length)

    return Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4,pduv4,packet_length


def ipv4_udp_parse_nopayload_ipabstract(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    Protocolv4 = []
    Sportv4 = []
    Dportv4 = []
    pduv4 = []
    packet_length = []

    for i in range(1,count_number-1):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p5 =  parsepcap.pkt_protocol(pp,i)
        p6 = parsepcap.pkt_sportudp(pp,i)
        p7 =  parsepcap.pkt_dportudp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-46)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        Protocolv4.append(p5)
        Sportv4.append(p6)
        Dportv4.append(p7)
        pduv4.append(p9)
        packet_length.append(p10)

    print(Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4)
    print(pduv4,packet_length)

    return Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4,pduv4,packet_length

def ipv4_udp_parse_nopayload_ipsession(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    Protocolv4 = []
    Sportv4 = []
    Dportv4 = []
    pduv4 = []
    packet_length = []

    for i in range(2,count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p5 =  parsepcap.pkt_protocol(pp,i)
        p6 = parsepcap.pkt_sportudp(pp,i)
        p7 =  parsepcap.pkt_dportudp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-46)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        Protocolv4.append(p5)
        Sportv4.append(p6)
        Dportv4.append(p7)
        pduv4.append(p9)
        packet_length.append(p10)

    print(Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4)
    print(pduv4,packet_length)

    return Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4,pduv4,packet_length

def ipv4_udp_parse_nopayload_x86(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    Protocolv4 = []
    Sportv4 = []
    Dportv4 = []
    pduv4 = []
    packet_length = []

    for i in range(count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p5 =  parsepcap.pkt_protocol(pp,i)
        p6 = parsepcap.pkt_sportudp(pp,i)
        p7 =  parsepcap.pkt_dportudp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-46)
        print(a)
        p9 = parsepcap.pkt_raw_hex(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        Protocolv4.append(p5)
        Sportv4.append(p6)
        Dportv4.append(p7)
        pduv4.append(p9)
        packet_length.append(p10)

    print(Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4)
    print(pduv4,packet_length)

    return Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4,pduv4,packet_length

def ipv6_tcp_parse(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv6 = []
    Dmacv6 = []
    Sipv6 = []
    Dipv6 = []
    Protocolv6 = []
    Sportv6 = []
    Dportv6 = []
    pduv6 = []
    packet_length = []
    pduv6data = []

    for i in range(count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sipv6(pp,i)
        p4 = parsepcap.pkt_dipv6(pp,i)
        p5 =  parsepcap.pkt_protocolv6(pp,i)
        p6 = parsepcap.pkt_sporttcp(pp,i)
        p7 =  parsepcap.pkt_dporttcp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-78)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i)
        time.sleep(1)
        p11 = parsepcap.pkt_raw_data(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10,p11)
        time.sleep(3)

        Smacv6.append(p1)
        Dmacv6.append(p2)
        Sipv6.append(p3)
        Dipv6.append(p4)
        Protocolv6.append(p5)
        Sportv6.append(p6)
        Dportv6.append(p7)
        pduv6.append(p9)
        packet_length.append(p10)
        pduv6data.append(p11)

    print(Smacv6,Dmacv6,Sipv6,Dipv6,Protocolv6,Sportv6,Dportv6)
    print(pduv6,packet_length,pduv6data)

    return Smacv6,Dmacv6,Sipv6,Dipv6,Protocolv6,Sportv6,Dportv6,pduv6,packet_length,pduv6data

def ipv6_tcp_parse_x86(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv6 = []
    Dmacv6 = []
    Sipv6 = []
    Dipv6 = []
    Protocolv6 = []
    Sportv6 = []
    Dportv6 = []
    pduv6 = []
    packet_length = []
    pduv6data = []

    for i in range(count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sipv6(pp,i)
        p4 = parsepcap.pkt_dipv6(pp,i)
        p5 =  parsepcap.pkt_protocolv6(pp,i)
        p6 = parsepcap.pkt_sporttcp(pp,i)
        p7 =  parsepcap.pkt_dporttcp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-78)
        print(a)
        p9 = parsepcap.pkt_raw_hex(pp,i)
        time.sleep(1)
        p11 = parsepcap.pkt_raw_data(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10,p11)
        time.sleep(3)

        Smacv6.append(p1)
        Dmacv6.append(p2)
        Sipv6.append(p3)
        Dipv6.append(p4)
        Protocolv6.append(p5)
        Sportv6.append(p6)
        Dportv6.append(p7)
        pduv6.append(p9)
        packet_length.append(p10)
        pduv6data.append(p11)

    print(Smacv6,Dmacv6,Sipv6,Dipv6,Protocolv6,Sportv6,Dportv6)
    print(pduv6,packet_length,pduv6data)

    return Smacv6,Dmacv6,Sipv6,Dipv6,Protocolv6,Sportv6,Dportv6,pduv6,packet_length,pduv6data


def ipv6_udp_parse(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv6 = []
    Dmacv6 = []
    Sipv6 = []
    Dipv6 = []
    Protocolv6 = []
    Sportv6 = []
    Dportv6 = []
    pduv6 = []
    packet_length = []
    pduv6data = []

    for i in range(count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sipv6(pp,i)
        p4 = parsepcap.pkt_dipv6(pp,i)
        p5 =  parsepcap.pkt_protocolv6(pp,i)
        p6 = parsepcap.pkt_sportudp(pp,i)
        p7 =  parsepcap.pkt_dportudp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-66)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i)
        time.sleep(1)
        p11 = parsepcap.pkt_raw_data(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10,p11)
        time.sleep(3)

        Smacv6.append(p1)
        Dmacv6.append(p2)
        Sipv6.append(p3)
        Dipv6.append(p4)
        Protocolv6.append(p5)
        Sportv6.append(p6)
        Dportv6.append(p7)
        pduv6.append(p9)
        packet_length.append(p10)
        pduv6data.append(p11)

    print(Smacv6,Dmacv6,Sipv6,Dipv6,Protocolv6,Sportv6,Dportv6)
    print(pduv6,packet_length,pduv6data)

    return Smacv6,Dmacv6,Sipv6,Dipv6,Protocolv6,Sportv6,Dportv6,pduv6,packet_length,pduv6data

def ipv6_udp_parse_x86(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv6 = []
    Dmacv6 = []
    Sipv6 = []
    Dipv6 = []
    Protocolv6 = []
    Sportv6 = []
    Dportv6 = []
    pduv6 = []
    packet_length = []
    pduv6data = []

    for i in range(count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sipv6(pp,i)
        p4 = parsepcap.pkt_dipv6(pp,i)
        p5 =  parsepcap.pkt_protocolv6(pp,i)
        p6 = parsepcap.pkt_sportudp(pp,i)
        p7 =  parsepcap.pkt_dportudp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-66)
        print(a)
        p9 = parsepcap.pkt_raw_hex(pp,i)
        time.sleep(1)
        p11 = parsepcap.pkt_raw_data(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10,p11)
        time.sleep(3)

        Smacv6.append(p1)
        Dmacv6.append(p2)
        Sipv6.append(p3)
        Dipv6.append(p4)
        Protocolv6.append(p5)
        Sportv6.append(p6)
        Dportv6.append(p7)
        pduv6.append(p9)
        packet_length.append(p10)
        pduv6data.append(p11)

    print(Smacv6,Dmacv6,Sipv6,Dipv6,Protocolv6,Sportv6,Dportv6)
    print(pduv6,packet_length,pduv6data)

    return Smacv6,Dmacv6,Sipv6,Dipv6,Protocolv6,Sportv6,Dportv6,pduv6,packet_length,pduv6data


def ipv4_parse(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    pduv4 = []
    packet_length = []
    pduv4data = []

    for i in range(count_number):
        print(pp[i].show())
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-38)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i)
        time.sleep(1)
        try:
            p11 = parsepcap.pkt_raw_data(pp,i) #只包含报文payload
            time.sleep(0.2)
        except IndexError:
            print("No Raw")
            p11=""

        print(p1,p2,p3,p4)
        print(p9,p10,p11)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        pduv4.append(p9)
        packet_length.append(p10)
        pduv4data.append(p11)

    print(Smacv4,Dmacv4,Sipv4,Dipv4)
    print(pduv4,packet_length,pduv4data)

    return Smacv4,Dmacv4,Sipv4,Dipv4,pduv4,packet_length,pduv4data

def ipv4_parse_nopayload(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    pduv4 = []
    packet_length = []

    for i in range(count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-38)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4)
        print(p9,p10)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        pduv4.append(p9)
        packet_length.append(p10)

    print(Smacv4,Dmacv4,Sipv4,Dipv4)
    print(pduv4,packet_length)

    return Smacv4,Dmacv4,Sipv4,Dipv4,pduv4,packet_length

def ipv4_parse_nopayload_noipabstract(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    pduv4 = []
    packet_length = []

    for i in range(count_number-2):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-38)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4)
        print(p9,p10)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        pduv4.append(p9)
        packet_length.append(p10)

    print(Smacv4,Dmacv4,Sipv4,Dipv4)
    print(pduv4,packet_length)

    return Smacv4,Dmacv4,Sipv4,Dipv4,pduv4,packet_length

def ipv4_parse_nopayload_ipabstract(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    pduv4 = []
    packet_length = []

    for i in range(1,count_number-1):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-38)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4)
        print(p9,p10)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        pduv4.append(p9)
        packet_length.append(p10)

    print(Smacv4,Dmacv4,Sipv4,Dipv4)
    print(pduv4,packet_length)

    return Smacv4,Dmacv4,Sipv4,Dipv4,pduv4,packet_length

def ipv4_parse_nopayload_ipsession(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    pduv4 = []
    packet_length = []

    for i in range(2,count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-38)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4)
        print(p9,p10)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        pduv4.append(p9)
        packet_length.append(p10)

    print(Smacv4,Dmacv4,Sipv4,Dipv4)
    print(pduv4,packet_length)

    return Smacv4,Dmacv4,Sipv4,Dipv4,pduv4,packet_length

def ipv4_parse_x86(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    pduv4 = []
    packet_length = []
    pduv4data = []

    for i in range(count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-38)
        print(a)
        p9 = parsepcap.pkt_raw_hex(pp,i)
        time.sleep(1)
        p11 = parsepcap.pkt_raw_data(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4)
        print(p9,p10,p11)
        time.sleep(3)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        pduv4.append(p9)
        packet_length.append(p10)
        pduv4data.append(p11)

    print(Smacv4,Dmacv4,Sipv4,Dipv4)
    print(pduv4,packet_length,pduv4data)

    return Smacv4,Dmacv4,Sipv4,Dipv4,pduv4,packet_length,pduv4data


def ipv6_parse(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv6 = []
    Dmacv6 = []
    Sipv6 = []
    Dipv6 = []
    pduv6 = []
    packet_length = []
    pduv6data = []

    for i in range(count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sipv6(pp,i)
        p4 = parsepcap.pkt_dipv6(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-58)
        print(a)
        try:
             p9 = parsepcap.pkt_padding(pp,i)
        except IndexError:
            print("No padding")
            p9=""
        try:
            if "ICMPv6EchoReply" in pp[i]:
                p11 = scapy.all.hexdump(pp[i][ICMPv6EchoReply].data, dump=True)
            else:
                p11 = parsepcap.pkt_raw_data(pp,i) #只包含报文payload
                time.sleep(0.2)
        except IndexError:
            print("No Raw")
            p11=""

        print(p1,p2,p3,p4)
        print(p9,p10,p11)
        time.sleep(3)

        Smacv6.append(p1)
        Dmacv6.append(p2)
        Sipv6.append(p3)
        Dipv6.append(p4)
        pduv6.append(p9)
        packet_length.append(p10)
        pduv6data.append(p11)

    print(Smacv6,Dmacv6,Sipv6,Dipv6)
    print(pduv6,packet_length,pduv6data)

    return Smacv6,Dmacv6,Sipv6,Dipv6,pduv6,packet_length,pduv6data


def ipv6_parse_x86(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv6 = []
    Dmacv6 = []
    Sipv6 = []
    Dipv6 = []
    pduv6 = []
    packet_length = []
    pduv6data = []

    for i in range(count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sipv6(pp,i)
        p4 = parsepcap.pkt_dipv6(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-58)
        print(a)
        p9 = parsepcap.pkt_raw_hex(pp,i)
        time.sleep(1)
        p11 = parsepcap.pkt_raw_data(pp,i)
        time.sleep(1)

        print(p1,p2,p3,p4)
        print(p9,p10,p11)
        time.sleep(3)

        Smacv6.append(p1)
        Dmacv6.append(p2)
        Sipv6.append(p3)
        Dipv6.append(p4)
        pduv6.append(p9)
        packet_length.append(p10)
        pduv6data.append(p11)

    print(Smacv6,Dmacv6,Sipv6,Dipv6)
    print(pduv6,packet_length,pduv6data)

    return Smacv6,Dmacv6,Sipv6,Dipv6,pduv6,packet_length,pduv6data

def ipv4_ipValueAll_parse(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    pduv4ip = []

    for i in range(count_number):
        ipValueAll = parsepcap.pkt_ip_hex(pp,i)
        time.sleep(1)

        print(ipValueAll)
        time.sleep(3)
        pduv4ip.append(ipValueAll)

    print(pduv4ip)

    return pduv4ip
    
def ipv4_ipDataAll_parse(fpath):
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    pduv4data = []

    for i in range(count_number):
        try:
            ipDataAll = parsepcap.pkt_raw_data(pp,i) #只包含报文payload
            time.sleep(0.2)
        except IndexError:
            print("No Raw")
            ipDataAll = ""
        time.sleep(1)

        print(ipDataAll)
        time.sleep(3)
        pduv4data.append(ipDataAll)

    print(pduv4data)

    return pduv4data

def ipv4_sctp_parse(fpath):
    '''
    eth+ipv4+sctp+raw报文解析

    :param fpath: pcap包路径

    :return: smac,dmac,sip,dip,protocol,sport,dport,pduv,packet_length,pduvdata

    '''
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    Smacv4 = []
    Dmacv4 = []
    Sipv4 = []
    Dipv4 = []
    Protocolv4 = []
    Sportv4 = []
    Dportv4 = []
    pduv4 = []
    packet_length = []
    pduv4data = []

    for i in range(count_number):
        p1 = parsepcap.pkt_smac(pp,i)
        p2 = parsepcap.pkt_dmac(pp,i)
        p3 = parsepcap.pkt_sip(pp,i)
        p4 = parsepcap.pkt_dip(pp,i)
        p5 =  parsepcap.pkt_protocol(pp,i)
        p6 = parsepcap.pkt_sportsctp(pp,i)
        p7 =  parsepcap.pkt_dportsctp(pp,i)
        p10 = parsepcap.pkt_len(pp,i)
        a = int(p10-58)
        print(a)
        p9 = parsepcap.pkt_padding(pp,i) #只包含padding的数据，不包含报文的payload
        try:
            p11 = parsepcap.pkt_raw_data(pp,i) #只包含报文payload
        except IndexError:
            print("No Raw")
            p11=""

        print(p1,p2,p3,p4,p5,p6,p7)
        print(p9,p10,p11)

        Smacv4.append(p1)
        Dmacv4.append(p2)
        Sipv4.append(p3)
        Dipv4.append(p4)
        Protocolv4.append(p5)
        Sportv4.append(p6)
        Dportv4.append(p7)
        pduv4.append(p9)
        packet_length.append(p10)
        pduv4data.append(p11)

    print(Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4)
    print(pduv4,packet_length,pduv4data)

    return Smacv4,Dmacv4,Sipv4,Dipv4,Protocolv4,Sportv4,Dportv4,pduv4,packet_length,pduv4data
    
def packet_parse(packets_hex):
    #packets_hex = ipv4_ipValueAll_parse(fpath)
    #a=len(packets_hex)
    #packets_hex = ipv4_ipValueAll_parse(fpath)
    #a=len(packets_hex)
    packets_hexlist =packets_hex.split('\n')
    packetctotalALL = ''
    for i in range(len(packets_hexlist)):
        packets_hexlist_1 = packets_hexlist[i].split(' ')
        print(packets_hexlist_1)
        packets_hexlist_2 = packets_hexlist_1[2:-2]
        packets_hexlist_3 = ''.join(packets_hexlist_2)
        packetctotalALL  = packetctotalALL + packets_hexlist_3
    print(packetctotalALL)
    return packetctotalALL
    
def IPv4split_parse(pduv4data):
    datatoall = ''
    for i in range(len(pduv4data)):
        data = packet_parse(pduv4data[i])
        datatoall = datatoall + data
    return  datatoall

def packet_split(packetctotalALL):
    p=0
    if '46534C4B' in packetctotalALL:
        p=packetctotalALL.index('46534C4B')
        packetctotalALL=packetctotalALL[0:p]
        print(p)
    packetctotalALL=''.join(packetctotalALL)

    return  packetctotalALL,p
    
def IPv4mulsplit_parse(pduv4data):
    datatoall = []
    for j in range(len(pduv4data)//3):
        i = 0
        k = 3*j
        data3 = ''
        while i < 3:
            data = packet_parse(pduv4data[k])
            data3 = data3 + data
            i+=1
            k+=1
        datatoall.append(data3)
    return  datatoall

def packet_split_tlv(packetctotalALL,p):
    if p!=0:
        tlv=packetctotalALL[p:]
    packetctotalALL = ''.join(tlv)
    print(tlv)
    return  tlv

def getDownUpPacket(fpath,applicationProtocol):
    upPacket = 0
    downPacket = 0
    upBytes = 0
    downBytes = 0
    res ={}
    pp = parsepcap.readdpcap(fpath)
    count_number = parsepcap.pkt_counter(pp)
    for i in range(count_number):
        sport = pp[i][applicationProtocol].sport
        dport = pp[i][applicationProtocol].dport
        if sport>dport:
            upPacket += 1
            upBytes += len(pp[i])
        else:
            downPacket += 1
            downBytes += len(pp[i])
    res['UpPackets'] = hex(upPacket)[2:].rjust(8,'0')
    res['DownPackets'] =  hex(downPacket)[2:].rjust(8,'0')
    res['UpBytes'] = hex(upBytes)[2:0].rjust(32,'0')
    res['DownBytes']= hex(upBytes)[2:0].rjust(32,'0')
    return res
def enct():
    print("parse")
if __name__ == "__main__":
    #Trexpcap("vlan2.pcap")
    #Trex_create_stream()
    #ipv4_tcp_parse("tcp.pcap")
    #ipv4_tcp_parse("F:\智能传感\SmartsensorTrex_1\import\\1.1.1.1.1 urg_tcp4_0.pcap")
    #Smacv4, Dmacv4, Sipv4, Dipv4, Protocolv4, Sportv4, Dportv4, pduv4, packet_length, pduv4data = ipv4_tcp_parse(("F:\智能传感\SmartsensorTrex_1\ccc\\ipv4_tcp.pcap"))
    #print("tlv:\n")
    #print(pduv4)
    print(type(hex(16)[2:]))
    ans= (hex(16)[2:]).rjust(8, '0')
    print(ans)