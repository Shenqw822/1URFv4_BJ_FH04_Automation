*** Settings ***
Documentation     规则优先级验证
...               1. 批量下发48条规则(IPv4+IPv6+L2各16条,priority 0-15)
...               2. 打流验证最高优先级规则命中
...               3. 逐条删除验证优先级依次生效
Library           ExcelLibrary
Resource          ../Resource/Public/initConfiguration.txt
Resource          ../Resource/Public/sshKeywordSet.txt
Resource          ../Resource/Public/instrument.txt
Resource          ../Resource/Public/Ddevice.txt

*** Test Cases ***
priority
    [Documentation]    测试点：规则优先级验证——最高优先级规则命中后，中标统计和输出计数均正确，逐条删除后依次验证
    [Tags]    cli    priority
    [Setup]    undoAclAll
    log    开始规则优先级测试
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    rule_pri
    open excel    ${ImportFilepath}/${excelName}
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${countRow}+1
    ${stream_name_pre}=    set variable    ${ssh_server_raw_pcap_path}Pri/
    comment    ==== Step 1: 批量下发全部48条规则（IPv4 rows 2-17 + IPv6 rows 18-33 + L2 rows 34-49）====
    log    批量下发全部48条规则
    New Connection Custom
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        ${rulePre}    read cell data by name    ${sheetName}    A${row}
        Continue For Loop If    '${rulePre}' == ''
        ${appId}    read cell data by name    ${sheetName}    B${row}
        ${action}    read cell data by name    ${sheetName}    C${row}
        ${priority}    read cell data by name    ${sheetName}    D${row}
        ${ruleSuf}    Run Keyword If    '${action}' == 'block'
        ...    Set Variable    action ${action} app_id ${appId} hit_statistics true priority ${priority}
        ...    ELSE
        ...    Set Variable    action ${action} outgroup_f ${outgroup_fId_1} app_id ${appId} hit_statistics true priority ${priority}
        ${acl_all}    Catenate    SEPARATOR=${SPACE}    ${rulePre}    ${ruleSuf}
        telnet.write    ${acl_all}
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    Should Not Contain    ${info}    ERROR    下发规则失败: ${acl_all}
    END
    telnet.write    show acl all
    ${info}    Telnet.Read Until    ${userName1}(config)#
    log    全部48条规则下发完成
    comment    ==== Step 2: 测试IPv4规则优先级（priority 0→15, Excel rows 2-17）====
    log    开始测试IPv4规则优先级
    FOR    ${row}    IN RANGE    2    18
        ${rulePre}    read cell data by name    ${sheetName}    A${row}
        Continue For Loop If    '${rulePre}' == ''
        ${app_id}    read cell data by name    ${sheetName}    B${row}
        ${action}    read cell data by name    ${sheetName}    C${row}
        ${priority}    read cell data by name    ${sheetName}    D${row}
        ${pcapfile}    read cell data by name    ${sheetName}    E${row}
        ${speed}    read cell data by name    ${sheetName}    F${row}
        ${durationTime}    read cell data by name    ${sheetName}    G${row}
        log    IPv4 priority=${priority} app_id=${app_id} action=${action}
        ${rx}    ${tx}    tcpreplayAndTcpdump    ipv4_pri${priority}    ${pcapfile}    ${speed}    ${durationTime}    tcpreplayPath=${stream_name_pre}
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${app_id}    5
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${hitCount}    0    app_id=${app_id} 中标统计应为>0，实际${hitCount}
        Run Keyword If    '${action}' == 'forward'
        ...    Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    0    app_id=${app_id} forward动作应有输出计数，实际rx=${rx}
        ...    ELSE
        ...    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    0    app_id=${app_id} block动作应无输出计数，实际rx=${rx}
        comment    删除当前最高优先级规则
        New Connection Custom
        telnet.write    undo acl stage3_f app_id ${app_id}
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    Should Not Contain    ${info}    ERROR    删除规则失败: app_id=${app_id}
    END
    log    IPv4规则优先级测试完成
    comment    ==== Step 3: 测试IPv6规则优先级（priority 0→15, Excel rows 18-33）====
    log    开始测试IPv6规则优先级
    FOR    ${row}    IN RANGE    18    34
        ${rulePre}    read cell data by name    ${sheetName}    A${row}
        Continue For Loop If    '${rulePre}' == ''
        ${app_id}    read cell data by name    ${sheetName}    B${row}
        ${action}    read cell data by name    ${sheetName}    C${row}
        ${priority}    read cell data by name    ${sheetName}    D${row}
        ${pcapfile}    read cell data by name    ${sheetName}    E${row}
        ${speed}    read cell data by name    ${sheetName}    F${row}
        ${durationTime}    read cell data by name    ${sheetName}    G${row}
        log    IPv6 priority=${priority} app_id=${app_id} action=${action}
        ${rx}    ${tx}    tcpreplayAndTcpdump    ipv6_pri${priority}    ${pcapfile}    ${speed}    ${durationTime}    tcpreplayPath=${stream_name_pre}
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${app_id}    5
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${hitCount}    0    app_id=${app_id} 中标统计应为>0，实际${hitCount}
        Run Keyword If    '${action}' == 'forward'
        ...    Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    0    app_id=${app_id} forward动作应有输出计数，实际rx=${rx}
        ...    ELSE
        ...    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    0    app_id=${app_id} block动作应无输出计数，实际rx=${rx}
        comment    删除当前最高优先级规则
        New Connection Custom
        telnet.write    undo acl stage3_f app_id ${app_id}
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    Should Not Contain    ${info}    ERROR    删除规则失败: app_id=${app_id}
    END
    log    IPv6规则优先级测试完成
    comment    ==== Step 4: 测试L2规则优先级（priority 0→15, Excel rows 34-49）====
    log    开始测试L2规则优先级
    FOR    ${row}    IN RANGE    34    51
        ${rulePre}    read cell data by name    ${sheetName}    A${row}
        Continue For Loop If    '${rulePre}' == ''
        ${app_id}    read cell data by name    ${sheetName}    B${row}
        ${action}    read cell data by name    ${sheetName}    C${row}
        ${priority}    read cell data by name    ${sheetName}    D${row}
        ${pcapfile}    read cell data by name    ${sheetName}    E${row}
        ${speed}    read cell data by name    ${sheetName}    F${row}
        ${durationTime}    read cell data by name    ${sheetName}    G${row}
        Continue For Loop If    '${pcapfile}' == 'no'
        log    L2 priority=${priority} app_id=${app_id} action=${action}
        ${rx}    ${tx}    tcpreplayAndTcpdump    l2_pri${priority}    ${pcapfile}    ${speed}    ${durationTime}    tcpreplayPath=${stream_name_pre}
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${app_id}    5
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${hitCount}    0    app_id=${app_id} 中标统计应为>0，实际${hitCount}
        Run Keyword If    '${action}' == 'forward'
        ...    Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    0    app_id=${app_id} forward动作应有输出计数，实际rx=${rx}
        ...    ELSE
        ...    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    0    app_id=${app_id} block动作应无输出计数，实际rx=${rx}
        comment    删除当前最高优先级规则
        New Connection Custom
        telnet.write    undo acl l2 app_id ${app_id}
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    Should Not Contain    ${info}    ERROR    删除规则失败: app_id=${app_id}
    END
    log    L2规则优先级测试完成
    [Teardown]    undoAclAll
