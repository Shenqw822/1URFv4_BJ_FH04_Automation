#!/usr/bin/python
# -*- coding: utf-8 -*-
from scapy.all import *
#rdpcap

def readdpcap(filepath):
    ppkts = rdpcap(filepath)
    return ppkts

def pkt_smac(ppkts,SeqNumber):
    return ppkts[SeqNumber]["Ether"].src

def pkt_dmac(ppkts,SeqNumber):
    return ppkts[SeqNumber]["Ether"].dst

def pkt_sip(ppkts,SeqNumber):
    return ppkts[SeqNumber]["IP"].src

def pkt_dip(ppkts,SeqNumber):
    return ppkts[SeqNumber]["IP"].dst

def pkt_protocol(ppkts,SeqNumber):
    return ppkts[SeqNumber]["IP"].proto

def pkt_sipv6(ppkts,SeqNumber):
    return ppkts[SeqNumber]["IPv6"].src

def pkt_dipv6(ppkts,SeqNumber):
    return ppkts[SeqNumber]["IPv6"].dst

def pkt_protocolv6(ppkts,SeqNumber):
    return ppkts[SeqNumber]["IPv6"].nh

def pkt_counter(ppkts):
    return len(ppkts)

def pkt_sporttcp(ppkts,SeqNumber):
    return ppkts[SeqNumber]["TCP"].sport

def pkt_dporttcp(ppkts,SeqNumber):
    return ppkts[SeqNumber]["TCP"].dport

def pkt_sportudp(ppkts,SeqNumber):
    return ppkts[SeqNumber]["UDP"].sport

def pkt_dportudp(ppkts,SeqNumber):
    return ppkts[SeqNumber]["UDP"].dport

def pkt_raw(ppkts,SeqNumber):
    return ppkts[SeqNumber]["Raw"][0:9000]

def pkt_raw_data(ppkts,SeqNumber):
    return scapy.all.hexdump(ppkts[SeqNumber]["Raw"].load,dump=True)

def pkt_raw_hex(ppkts,SeqNumber):
    return scapy.all.hexdump(ppkts[SeqNumber]["Raw"][0:9000],dump=True)

def pkt_ip_hex(ppkts,SeqNumber):
    return scapy.all.hexdump(ppkts[SeqNumber],dump=True)

def pkt_padding(ppkts,SeqNumber):
    return scapy.all.hexdump(ppkts[SeqNumber]["Padding"],dump=True)

def pkt_len(ppkts,SeqNumber):
    return int(len(ppkts[SeqNumber]))

def pkt_rawv4tcp(ppkts,SeqNumber):
    return str(ppkts[SeqNumber]["Raw"])[0:6]

def pkt_sipn(ppkts,SeqNumber):
    return ppkts[SeqNumber]["IP"].src

def pkt_sipv6n(ppkts,SeqNumber):
    return ppkts[SeqNumber]["IPv6"].src
def pkt_sportsctp(ppkts,SeqNumber):
    '''
    返回sctp报文源端口
    :param ppkts:
    :param SeqNumber:
    :return:
    '''
    return ppkts[SeqNumber]["SCTP"].sport

def pkt_dportsctp(ppkts,SeqNumber):
    '''
    返回sctp报文目的端口
    :param ppkts:
    :param SeqNumber:
    :return:
    '''
    return ppkts[SeqNumber]["SCTP"].dport