*** Settings ***
Documentation     缺陷复现验证（MR#8789、MR#8791）及 ACL 规则循环下发/删除压力测试
Library           ExcelLibrary
Library           Process
Resource          ../Resource/Public/initConfiguration.txt
Resource          ../Resource/Public/sshKeywordSet.txt
Resource          ../Resource/Public/Ddevice.txt
Library           ../Resource/Lib/rcpLib/RcpApiForRf.py

*** Test Cases ***
frequency_updata
    [Tags]    MR
    ${version}    Create List    28    49
    ${times}    Set Variable    100
    @{version_fin}    Evaluate    ${version}*${times}
    FOR    ${version}    IN    @{version_fin}
        ${version_file}    Set Variable    8101v0.2.${version}.tar.gz
        comment    升级设备
        SSHLibrary.Open Connection    ${host_ip}
        SSHLibrary.Login    root    fa
        SSHLibrary.Put File    \\\\192.168.19.216\\1u汇聚过滤（810x）\\version\\v0.2.${version}\\${version_file}    /tmp
        SSHLibrary.Close All Connections
        New Connection Custom
        telnet.write    update version ${version_file}
        ${info}    Telnet.Read Until    please wait
        log    ${info}
        sleep    400
        comment    读取寄存器信息
        SSHLibrary.Open Connection    ${host_ip}    timeout=120
        SSHLibrary.login    root    fa
        SSHLibrary.Write    pwd
        sleep    1
        SSHLibrary.Read
        SSHLibrary.Write    cd /home/
        sleep    1
        SSHLibrary.Read
        SSHLibrary.Write    cat luacmd_cpld.txt |luacmd.lua
        sleep    1
        ${confdb}    SSHLibrary.Read Until    root@
        log    ${confdb}
        ${hello}    Get Regexp Matches    ${confdb}    :([0-9]{4,})H    1
        log    ${hello}
        ${times}    Get Count    ${hello}    0003    #0003为预期值
        log    ${times}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${times}    1    预期值出现的次数不符合预期    #预期该值出现4次
        SSHLibrary.Close All Connections
    END

alarm_time_wrong
    [Documentation]    复现MR#8789
    [Tags]    MR
    New Connection Custom
    telnet.write    interface eth 1/1 admin down
    ${up_down}    create list    up    down
    ${up_down_mult}    Evaluate    ${up_down}*200000
    FOR    ${interface}    IN    @{up_down_mult}
        New Connection Custom
        sleep    1
        telnet.write    interface eth 1/1 admin ${interface}
        check_history_alarm_time    show alarm history | include "Los"
    END

oam_reboot
    [Documentation]    复现MR#8791
    [Tags]    MR
    [Setup]
    log    测试普通的转发业务
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    forwardRcp
    open excel    ${ImportFilepath}/${excelName}
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${totalAppIdList}    Create List
    ${expectRespondCode}    Set Variable    01
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    ps aux | grep oam | grep -v grep | awk '{print $2}'
    sleep    1
    ${oam_pid_org}    SSHLibrary.Read
    SSHLibrary.Close All Connections
    comment    按照excel中的行为单位进行循环测试
    ${a}    Evaluate    [2]*10
    FOR    ${row}    IN    @{a}
        log    第${row}行循环测试
        New Connection Custom
        comment    获取相关内容
        ${configFileName}    read cell data by name    ${sheetName}    A${row}
        ${ruleTitle}    read cell data by name    ${sheetName}    B${row}
        ${packetFileName}    read cell data by name    ${sheetName}    C${row}
        ${hitPcapTile}    read cell data by name    ${sheetName}    D${row}
        ${backPcapTile}    read cell data by name    ${sheetName}    E${row}
        ${savePcapfileFlag}    read cell data by name    ${sheetName}    F${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    G${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    H${row}
        comment    根据配置通过rcp进行acl规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${configFileName}    ${ruleTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        Append To List    ${totalAppIdList}    ${ruleId}
        comment    rcp下发后，在9999下查看规则
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    undo acl stage3_f ipmode ipv4 src_ip 123.11.92.101/255.255.255.255
        ${info}    Telnet.Read Until    ${userName1}(config)#
        telnet.write    acl stage3_f 4302 ipmode ipv4 src_ip 123.11.92.101/255.255.255.255 action drop app_id 1 group_a 1
        ${info}    Telnet.Read Until    ${userName1}(config)#
        telnet.write    undo acl stage3_f ipmode ipv4 \ dst_ip 192.0.0.1/255.255.255.255
        ${info}    Telnet.Read Until    ${userName1}(config)#
        telnet.write    undo acl \ grouped_rule \ 1
        ${info}    Telnet.Read Until    ${userName1}(config)#
        SSHLibrary.Open Connection    ${host_ip}    timeout=120
        SSHLibrary.login    root    fa
        SSHLibrary.Write    pwd
        sleep    1
        SSHLibrary.Read
        SSHLibrary.Write    ps aux | grep oam | grep -v grep | awk '{print $2}'
        sleep    1
        ${oam_pid_now}    SSHLibrary.Read
        SSHLibrary.Close All Connections
        Run Keyword And Continue On Failure    Should Be Equal    ${oam_pid_org}    ${oam_pid_now}
    END
    FOR    ${row}    IN    @{a}
        log    第${row}行循环测试
        New Connection Custom
        comment    获取相关内容
        ${configFileName}    read cell data by name    ${sheetName}    A${row}
        ${ruleTitle}    read cell data by name    ${sheetName}    B${row}
        ${packetFileName}    read cell data by name    ${sheetName}    C${row}
        ${hitPcapTile}    read cell data by name    ${sheetName}    D${row}
        ${backPcapTile}    read cell data by name    ${sheetName}    E${row}
        ${savePcapfileFlag}    read cell data by name    ${sheetName}    F${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    G${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    H${row}
        comment    根据配置通过rcp进行acl规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${configFileName}    ${ruleTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        Append To List    ${totalAppIdList}    ${ruleId}
        comment    rcp下发后，在9999下查看规则
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    undo acl stage3_f ipmode ipv4 \ dst_ip 192.0.0.1/255.255.255.255
        ${info}    Telnet.Read Until    ${userName1}(config)#
        telnet.write    acl stage3_f 4303 ipmode ipv4 dst_ip 192.0.0.1/255.255.255.255 action drop app_id 1 group_b 1
        ${info}    Telnet.Read Until    ${userName1}(config)#
        telnet.write    undo acl stage3_f ipmode ipv4 src_ip 123.11.92.101/255.255.255.255
        ${info}    Telnet.Read Until    ${userName1}(config)#
        telnet.write    undo acl \ grouped_rule \ 1
        ${info}    Telnet.Read Until    ${userName1}(config)#
        SSHLibrary.Open Connection    ${host_ip}    timeout=120
        SSHLibrary.login    root    fa
        SSHLibrary.Write    pwd
        sleep    1
        SSHLibrary.Read
        SSHLibrary.Write    ps aux | grep oam | grep -v grep | awk '{print $2}'
        sleep    1
        ${oam_pid_now}    SSHLibrary.Read
        SSHLibrary.Close All Connections
        Run Keyword And Continue On Failure    Should Be Equal    ${oam_pid_org}    ${oam_pid_now}
    END
    FOR    ${row}    IN    @{a}
        log    第${row}行循环测试
        New Connection Custom
        comment    获取相关内容
        ${configFileName}    read cell data by name    ${sheetName}    A${row}
        ${ruleTitle}    read cell data by name    ${sheetName}    B${row}
        ${packetFileName}    read cell data by name    ${sheetName}    C${row}
        ${hitPcapTile}    read cell data by name    ${sheetName}    D${row}
        ${backPcapTile}    read cell data by name    ${sheetName}    E${row}
        ${savePcapfileFlag}    read cell data by name    ${sheetName}    F${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    G${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    H${row}
        comment    根据配置通过rcp进行acl规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${configFileName}    ${ruleTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        Append To List    ${totalAppIdList}    ${ruleId}
        comment    rcp下发后，在9999下查看规则
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    undo acl stage3_f ipmode ipv4 \ dst_ip 192.0.0.1/255.255.255.255
        ${info}    Telnet.Read Until    ${userName1}(config)#
        telnet.write    acl stage3_f 4303 ipmode ipv4 dst_ip 192.0.0.1/255.255.255.255 action drop app_id 1 group_b 1
        ${info}    Telnet.Read Until    ${userName1}(config)#
        telnet.write    undo acl stage3_f ipmode ipv4 \ src_ip 10.0.0.1/255.255.255.0
        ${info}    Telnet.Read Until    ${userName1}(config)#
        telnet.write    acl stage3_f 4301 ipmode ipv4 src_ip 10.0.0.1/255.255.255.0 action drop app_id 1 group_a 1
        ${info}    Telnet.Read Until    ${userName1}(config)#
        telnet.write    undo acl stage3_f ipmode ipv4 \ src_ip 123.11.92.101/255.255.255.255
        ${info}    Telnet.Read Until    ${userName1}(config)#
        telnet.write    acl stage3_f 4302 ipmode ipv4 src_ip 123.11.92.101/255.255.255.255 action drop app_id 1 group_a 1
        ${info}    Telnet.Read Until    ${userName1}(config)#
        telnet.write    undo acl \ grouped_rule \ 1
        ${info}    Telnet.Read Until    ${userName1}(config)#
        SSHLibrary.Open Connection    ${host_ip}    timeout=120
        SSHLibrary.login    root    fa
        SSHLibrary.Write    pwd
        sleep    1
        SSHLibrary.Read
        SSHLibrary.Write    ps aux | grep oam | grep -v grep | awk '{print $2}'
        sleep    1
        ${oam_pid_now}    SSHLibrary.Read
        SSHLibrary.Close All Connections
        Run Keyword And Continue On Failure    Should Be Equal    ${oam_pid_org}    ${oam_pid_now}
    END
    FOR    ${row}    IN    @{a}
        log    第${row}行循环测试
        New Connection Custom
        comment    获取相关内容
        ${configFileName}    read cell data by name    ${sheetName}    A${row}
        ${ruleTitle}    read cell data by name    ${sheetName}    B${row}
        ${packetFileName}    read cell data by name    ${sheetName}    C${row}
        ${hitPcapTile}    read cell data by name    ${sheetName}    D${row}
        ${backPcapTile}    read cell data by name    ${sheetName}    E${row}
        ${savePcapfileFlag}    read cell data by name    ${sheetName}    F${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    G${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    H${row}
        comment    根据配置通过rcp进行acl规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${configFileName}    ${ruleTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        Append To List    ${totalAppIdList}    ${ruleId}
        comment    rcp下发后，在9999下查看规则
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    undo acl stage3_f ipmode ipv4 \ dst_ip 192.0.0.1/255.255.255.255
        ${info}    Telnet.Read Until    ${userName1}(config)#
        telnet.write    undo acl stage3_f ipmode ipv4 \ src_ip 10.0.0.1/255.255.255.0
        ${info}    Telnet.Read Until    ${userName1}(config)#
        telnet.write    undo acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        SSHLibrary.Open Connection    ${host_ip}    timeout=120
        SSHLibrary.login    root    fa
        SSHLibrary.Write    pwd
        sleep    1
        SSHLibrary.Read
        SSHLibrary.Write    ps aux | grep oam | grep -v grep | awk '{print $2}'
        sleep    1
        ${oam_pid_now}    SSHLibrary.Read
        SSHLibrary.Close All Connections
        Run Keyword And Continue On Failure    Should Be Equal    ${oam_pid_org}    ${oam_pid_now}
    END

loop_acl_undo
    [Documentation]    RCP 下发 4000 条 L2 规则后 undo acl all，循环 500 次记录 show rule number 字段值
    ...    1. 运行 RcpApiNew_2.py 下发 4000 条 L2 规则
    ...    2. telnet show rule number 记录下发后 total/rcptotal/rcpforward
    ...    3. telnet undo acl all
    ...    4. telnet show rule number 记录删除后 total/rcptotal/rcpforward
    [Tags]    MR    acl
    [Setup]    undoAclAll
    ${rcpScript}    Set Variable    ${CURDIR}/../Resource/Lib/rcpLib/RcpApiNew_2.py
    ${rcpLibDir}    Set Variable    ${CURDIR}/../Resource/Lib/rcpLib
    FOR    ${i}    IN RANGE    1    501
        ${result}    Run Process    E:/app/python/python.exe    ${rcpScript}    cwd=${rcpLibDir}    timeout=300    stdout=DEVNULL    stderr=DEVNULL
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${result.rc}    0    第${i}轮 RCP 下发退出码非0
        New Connection Custom
        telnet.write    show rule number
        ${out1}    Telnet.Read Until    ${userName1}(config)#
        ${rcptotal1}    Get Regexp Matches    ${out1}    \\brcptotal\\s*:\\s*(\\d+)    1
        ${total1}    Get Regexp Matches    ${out1}    \\btotal\\s*:\\s*(\\d+)    1
        ${rcpforward1}    Get Regexp Matches    ${out1}    \\brcpforward\\s*:\\s*(\\d+)    1
        Log    第${i}轮 下发后 total=${total1}[0] rcptotal=${rcptotal1}[0] rcpforward=${rcpforward1}[0]
        telnet.write    undo acl all
        Telnet.Read Until    ${userName1}(config)#
        ${totalAfter}    Set Variable    99999
        ${waitSec}    Set Variable    0
        WHILE    ${totalAfter} != 0 and ${waitSec} < 120
            Sleep    5s
            telnet.write    show rule number
            ${tmp}    Telnet.Read Until    ${userName1}(config)#
            ${totalTmp}    Get Regexp Matches    ${tmp}    \\btotal\\s*:\\s*(\\d+)    1
            ${totalAfter}    Convert To Integer    ${totalTmp}[0]
            ${waitSec}    Evaluate    ${waitSec} + 5
        END
        telnet.write    show rule number
        ${out2}    Telnet.Read Until    ${userName1}(config)#
        ${rcptotal2}    Get Regexp Matches    ${out2}    \\brcptotal\\s*:\\s*(\\d+)    1
        ${total2}    Get Regexp Matches    ${out2}    \\btotal\\s*:\\s*(\\d+)    1
        ${rcpforward2}    Get Regexp Matches    ${out2}    \\brcpforward\\s*:\\s*(\\d+)    1
        Log    第${i}轮 undo acl all 后 total=${total2}[0] rcptotal=${rcptotal2}[0] rcpforward=${rcpforward2}[0]
    END
