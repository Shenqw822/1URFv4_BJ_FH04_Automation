#!/bin/bash/env python
# -*- coding:utf-8 -*-

import os

# CIDR 文件路径（相对于本文件的 ../../Business/cidr_data/）
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
V4_CIDR_FILE = os.path.join(_BASE_DIR, '..', '..', 'Business', 'cidr_data', 'china_ipv4_cidr.txt')
V6_CIDR_FILE = os.path.join(_BASE_DIR, '..', '..', 'Business', 'cidr_data', 'china_ipv6_cidr.txt')


class RuleImport:

    _DEFAULTS = {
        'expect_code': '01', 'inGroup': 255,
        'total': 0, 'day': 0, 'starttime': 0, 'endtime': 0,
        'expect_cost_total': 0, 'expect_cost_day': 0, 'expect_cost_time': 0,
        'pri': 0, 'limit_type': 10,
        'vlang': [], 'mplsg': [],
    }

    @staticmethod
    def load_cidrs_from_file(filepath, sample_size=None):
        if sample_size is not None and str(sample_size).lower() != 'none':
            sample_size = int(sample_size)
        else:
            sample_size = None
        lines = []
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    lines.append(line)
        if sample_size is not None and sample_size < len(lines):
            lines = lines[:sample_size]
        return lines

    @staticmethod
    def cidr_to_sipg_entry(cidr):
        return [cidr, 0, 0, 0, 0]

    @classmethod
    def _build_kwargs(cls, sip_cidr_list, dip_cidr_list, v4v6, **overrides):
        kwargs = dict(cls._DEFAULTS)
        kwargs['v4v6'] = v4v6
        kwargs['sipg'] = [cls.cidr_to_sipg_entry(c) for c in sip_cidr_list] if sip_cidr_list else []
        kwargs['dipg'] = [cls.cidr_to_sipg_entry(c) for c in dip_cidr_list] if dip_cidr_list else []
        kwargs.update(overrides)
        return kwargs

    @classmethod
    def build_combined_rule_kwargs(cls, cidr_list, v4v6, **overrides):
        return cls._build_kwargs(cidr_list, cidr_list, v4v6, **overrides)

    @classmethod
    def build_five_tuple_rule_kwargs(cls, sip_cidr_list, dip_cidr_list, v4v6, **overrides):
        wildcard = '0.0.0.0/0' if v4v6 == 'v4' else '::/0'
        if not sip_cidr_list:
            sip_cidr_list = [wildcard] * len(dip_cidr_list)
        if not dip_cidr_list:
            dip_cidr_list = [wildcard] * len(sip_cidr_list)
        return cls._build_kwargs(sip_cidr_list, dip_cidr_list, v4v6, **overrides)
