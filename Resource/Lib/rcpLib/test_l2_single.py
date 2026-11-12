#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""最小验证：单条 L2 规则下发，对比不同参数组合的 returnCode"""
import RcpApiNew_2 as R

a = R.RcpApi("192.168.128.235", deviceId=0, sslSwitch=0)

cases = [
    ("原参数 inGroup=[] mplsg=[[1,2]]", dict(inGroup=[], mplsg=[[1, 2]])),
    ("inGroup=127 mplsg=[[1,2]]", dict(inGroup=127, mplsg=[[1, 2]])),
    ("inGroup=127 mplsg=[[1,4294967295]]", dict(inGroup=127, mplsg=[[1, 4294967295]])),
]

for name, extra in cases:
    try:
        request, expectResult, result, ruleid = a.addRule_L2(
            expect_code=1,
            sipg=[['10.0.0.1/24', 0, 0, 0, 255]],
            dipg=[['2.2.2.2/24', 2, 2, "tcp", 255]],
            vlang=[],
            limit_type=0,
            pri=4,
            total=0,
            day=0,
            starttime=0,
            endtime=0,
            serviceType=0,
            v4v6='v4',
            **extra,
        )
        # 提取实际响应的 returnCode（第3组：版本2 + messType4 + returnCode2）
        rc = result[6:8] if len(result) >= 8 else '?'
        ruleid_hex = result[-8:] if len(result) >= 8 else '?'
        print(f"[{name}] returnCode={rc} ruleId={ruleid_hex} 下发ruleid={ruleid}")
    except Exception as e:
        print(f"[{name}] EXCEPTION: {type(e).__name__}: {e}")

a.close()
