*** Settings ***
Library           ExcelLibrary
Resource          ../Resource/Public/initConfiguration.txt
Resource          ../Resource/Public/sshKeywordSet.txt
Resource          ../Resource/Public/instrument.txt
Resource          ../Resource/Public/Ddevice.txt
Library           ../Resource/Lib/rcpLib/RcpApiForRf.py
Resource          ../Resource/Business/variable.txt

*** Test Cases ***
ingroup_test
    [Documentation]    入口组隔离验证：ingroup0 背景入口组命中不输出，ingroup127 主入口组命中输出
    ...    遍历rcp和cli下发
    ...    遍历中标统计最大范围，appid最大范围
    [Tags]    ingroup
    [Setup]    undoAclAll
    ${sheetName}    Set Variable    ingroup
    ${ingroupPcapPath}    Set Variable    ${ssh_server_raw_pcap_path}ingroup/
    open excel    ${ImportFilepath}/${excelName}
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${countRow}+1
    comment    ===== 阶段1: RCP 规则（2-13 行）=====
    FOR    ${row}    IN RANGE    2    14
        ${configFileName}    read cell data by name    ${sheetName}    A${row}
        ${ruleTitle}    read cell data by name    ${sheetName}    B${row}
        ${pcapFile}    read cell data by name    ${sheetName}    C${row}
        ${expectOutput}    read cell data by name    ${sheetName}    D${row}
        ${speed}    read cell data by name    ${sheetName}    E${row}
        ${duration}    read cell data by name    ${sheetName}    F${row}
        comment    下发 RCP 规则
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${configFileName}    ${ruleTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发失败: ${ruleTitle}
        comment    查看规则
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打流验证
        ${rx}    ${tx}    tcpreplayAndTcpdump    ingroup_rcp_${row}    ${pcapFile}    ${speed}    ${duration}    tcpreplayPath=${ingroupPcapPath}
        IF    '${expectOutput}' == '0'
            Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    第${row}行 预期不输出但rx!=0
            compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
            ${hitCount}    getAclHitstatistics    ${ruleId}
            Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    第${row}行 不输出但hitCount!=0
        ELSE
            Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    第${row}行 预期输出但rx=0
            ${in_all_pkt}    ${in_all_byte}    ${out_all_pkt}    ${out_all_byte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
            ${hitCount}    getAclHitstatistics    ${ruleId}
            Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${out_all_byte}    第${row}行 hitCount不等于设备输出
        END
    END
    comment    ===== 阶段2: CLI 规则（14-33 行）=====
    FOR    ${row}    IN RANGE    14    ${countRrowAdd}
        ${ruleContent}    read cell data by name    ${sheetName}    B${row}
        ${pcapFile}    read cell data by name    ${sheetName}    C${row}
        ${expectOutput}    read cell data by name    ${sheetName}    D${row}
        ${speed}    read cell data by name    ${sheetName}    E${row}
        ${duration}    read cell data by name    ${sheetName}    F${row}
        ${appId}    read cell data by name    ${sheetName}    G${row}
        ${pri}    read cell data by name    ${sheetName}    H${row}
        ${hitFlag}    read cell data by name    ${sheetName}    I${row}
        comment    拼接 CLI 命令（I=1 带 hit_statistics，I=0 不带）
        ${suffix}    Set Variable If    '${hitFlag}' == '1'    action ${action_info} outgroup_f ${outgroup_fId_1} app_id ${appId} hit_statistics true priority ${pri}    action ${action_info} outgroup_f ${outgroup_fId_1} app_id ${appId} priority ${pri}
        ${acl_all}    Run Keyword If    'temp' in '${ruleContent}'    Replace String    ${ruleContent}    temp    ${suffix}
        ...    ELSE    Catenate    ${ruleContent}    ${suffix}
        comment    下发 CLI 规则
        New Connection Custom
        telnet.write    ${acl_all}
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    should not contain    ${info}    ERROR
        comment    查看规则
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        comment    C=no 时跳过打流
        Continue For Loop If    '${pcapFile}' == 'no'
        comment    打流验证
        ${rx}    ${tx}    tcpreplayAndTcpdump    ingroup_cli_${row}    ${pcapFile}    ${speed}    ${duration}    tcpreplayPath=${ingroupPcapPath}
        IF    '${expectOutput}' == '0'
            Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    第${row}行 预期不输出但rx!=0
            compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
            IF    '${hitFlag}' == '1'
                ${hitCount}    getAclHitstatistics    ${appId}
                Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    第${row}行 不输出但hitCount!=0
            END
        ELSE
            Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    第${row}行 预期输出但rx=0
            ${in_all_pkt}    ${in_all_byte}    ${out_all_pkt}    ${out_all_byte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
            IF    '${hitFlag}' == '1'
                ${hitCount}    getAclHitstatistics    ${appId}
                Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${out_all_byte}    第${row}行 hitCount不等于设备输出
            END
        END
    END
    [Teardown]    undoAclAll
