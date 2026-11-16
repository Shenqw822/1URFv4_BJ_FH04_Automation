*** Settings ***
Library           ExcelLibrary
Resource          ../Resource/Public/initConfiguration.txt
Resource          ../Resource/Public/sshKeywordSet.txt
Resource          ../Resource/Public/instrument.txt
Resource          ../Resource/Public/Ddevice.txt
Library           ../Resource/Lib/rcpLib/makePcapFile.py    ${localRawPcapPath}    ${ssh_server_raw_pcap_path}
Library           ../Resource/Lib/rcpLib/RcpApiForRf.py
Library           ../Resource/Lib/rcpLib/RuleImport.py
Resource          ../Resource/Business/variable.txt

*** Variables ***
${wuCha}          10
@{packetTitleList}
${restoreWaitTime}    10

*** Test Cases ***
rcp_init
    [Tags]    rcp
    comment    设置rcp的config配置
    log    设备相关配置
    changeConfigOptionValue    config    client    dst_ip    ${host_ip}
    changeConfigOptionValue    config    client    dev_id    0
    changeConfigOptionValue    config    client    ssl_switch    ${ssl_switch}
    log    仪表服务器相关配置
    changeConfigOptionValue    config    netcard    server_ip    ${trex_ip}
    changeConfigOptionValue    config    netcard    username    ${ssh_server_user}
    changeConfigOptionValue    config    netcard    password    ${ssh_server_password}
    changeConfigOptionValue    config    netcard    nic    ${ssh_server_net_port}

forward
    [Documentation]    packet1:sip=10.0.0.1/24 \ \ \ \ \ dip=192.0.0.1 \ \ \ \ \ \ \ \ \ \ \ \ udp
    ...    packet2:sip=123.11.92.101 \ dip=212.134.23.10 \ \ \ \ \ udp
    ...    packet3:sip=2000::2 \ \ \ \ \ \ \ \ \ \ \ dip=2000::1 \ \ \ \ \ \ \ \ \ \ \ \ \ \ tcp
    ...    packet4:sip=1000::1/120 \ \ \ \ dip=2000::1/128 \ \ \ \ \ \ \ \ sctp
    ...    packet5:sip=100.1.1.2 \ \ \ \ \ \ \ \ dip=200.0.0.1 \ \ \ \ \ \ \ \ \ \ \ 场景1：下发packet1+packet2的sip；背景流packet2,业务流packet1（只下发ip)
    ...    场景2：下发packet2+packet1的dip；背景流packet1,业务流packet2（只下发ip)
    ...    场景3：下发packet1+packet2；背景流packet5，业务流packet1+packet2（下发5元组）
    ...    场景4：下发packet3,背景流packet5,业务流packet3(sip=pro+sp,dip=ip+dp+pro)
    ...    场景5：下发packet4,背景流packet5,业务流packet4(sip=ip+pro+sp,dip=ip+dp+pro)
    ...    场景6：下发packet3+packet4的sip,背景流packet4,业务流packet3（packet3的下发pro+port,packet4=ip+pro+port)
    ...    场景7：下发packet1+packet2+packet4,背景流packet3+packet5,业务流packet1+packet2+packet4
    ...
    ...    用例程序步骤：
    ...    0.初始化setup，删除设备上所有acl规则和sni
    ...    1.打开exec了表格
    ...    2.设置初始参数：totalAppIdList,expectRespondCode
    ...    3.按照exceli表格的行数进行循环
    ...    a.获取相关参数：规则配置文件名，规则配置title,包配置文件名，包配置title，保存pcapfile标识，打流速率，打流时间
    ...    b.按照a中获取的信息通过rcp进行规则下发，且根据返回判断规则是否下发成功
    ...    c.把b中的ruleid加入2中的totalAppIdList
    ...    d.通过show acl all获取当前acl信息
    ...    e.根据a中信息，进行背景和业务的pcapfile文件的生成
    ...    f.打e中生成的背景pcapfile
    ...    g.校验仪表的tx=设备rx,设备tx=仪表rx，以及仪表rx=0
    ...    h.获取规则中标统计，且中标统计为0
    ...    i.打e中生成的业务pcapfile，且把设备输出保存outpcapfile
    ...    j.校验仪表的tx=设备rx,设备tx=仪表rx，以及仪表rx!=0
    ...    k.获取规则中标统计，且中标统计=仪表的tx
    ...    l.根据c中的业务pcap和i中的outpcapfile生成hash值，对源和设备输出内容进行比较
    ...    m.通过rcp删除规则
    [Tags]    rcp
    [Setup]    undoAclAll
    comment    测试普通的转发业务
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    forwardRcp
    open excel    ${ImportFilepath}/${excelName}
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${totalAppIdList}    Create List
    ${expectRespondCode}    Set Variable    01
    comment    按照excel中的行为单位进行循环测试
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
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
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    根据配置自动生成pcapfile
        ${hitPcapfileName}    makePcap    ${0}    ${packetFileName}    ${hitPcapTile}
        ${backPcapfileName}    makePcap    ${0}    ${packetFileName}    ${backPcapTile}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    ${savePcapfileFlag}_${row}_back    ${backPcapfileName}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    getAclHitstatistics    ${totalAppIdList}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    ${savePcapfileFlag}_${row}_hit    ${hitPcapfileName}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${in_all_pkt}    ${in_all_byte}    ${out_all_pkt}    ${out_all_byte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${totalAppIdList}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${out_all_byte}    业务流的hitCount不等于设备总输出
        Comment    通过hash校验包的完整性
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}    ${hitPcapfileName}
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    ${savePcapfileFlag}_${row}_hit.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Should Be True    ${hashResult}
        Comment    删除本次循环时下发的acl，进入下一次循环acl下发
        delete    ${ruleId}    ${expectRespondCode}
        ${totalAppIdList}    Create List
    END

totalNumModifyAndAlarm
    [Documentation]    packet1:sip=10.0.0.1/24 \ \ \ \ \ dip=192.0.0.1 \ \ \ \ \ \ \ \ \ \ \ \ udp
    ...    packet2:sip=123.11.92.101 \ dip=212.134.23.10 \ \ \ \ \ udp
    ...    packet5:sip=100.1.1.2 \ \ \ \ \ \ \ \ dip=200.0.0.1 \ \ \ \ \ \ \ \ \ \ \ nopro
    ...
    ...    场景1：下发packet1+packet2的sip；背景流packet2,业务流packet1（只下发ip)
    ...    场景2：下发packet2+packet1的dip；背景流packet1,业务流packet2（只下发ip)
    ...    场景3：下发packet1+packet2；背景流packet5，业务流packet1+packet2（下发5元组）
    ...    场景4：下发packet3,背景流packet5,业务流packet3(sip=pro+sp,dip=ip+dp+pro)
    ...    场景5：下发packet4,背景流packet5,业务流packet4(sip=ip+pro+sp,dip=ip+dp+pro)
    ...    场景6：下发packet3+packet4的sip,背景流packet4,业务流packet3（packet3的下发pro+port,packet4=ip+pro+port)
    ...    场景7：下发packet1+packet2+packet4,背景流packet3+packet5,业务流packet1+packet2+packet4
    ...
    ...    用例程序步骤：
    ...    0.初始化setup，删除设备上所有acl规则和sni
    ...    1.打开exec了表格
    ...    2.设置初始参数：totalAppIdList,expectRespondCode
    ...    3.按照exceli表格的行数进行循环
    ...    a.获取相关参数：规则配置文件名，规则配置title,包配置文件名，包配置title，保存pcapfile标识，打流速率，打流时间
    ...    b.按照a中获取的信息通过rcp进行规则下发，且根据返回判断规则是否下发成功
    ...    c.把b中的ruleid加入2中的totalAppIdList
    ...    d.通过show acl all获取当前acl信息
    ...    e.根据a中信息，进行背景和业务的pcapfile文件的生成
    ...    f.打e中生成的背景pcapfile
    ...    g.校验仪表的tx=设备rx,设备tx=仪表rx，以及仪表rx=0
    ...    h.获取规则中标统计，且中标统计为0
    ...    i.打e中生成的业务pcapfile，且把设备输出保存outpcapfile
    ...    j.校验仪表的tx=设备rx,设备tx=仪表rx，以及仪表rx!=0
    ...    k.获取规则中标统计，且中标统计=仪表的tx
    ...    l.根据c中的业务pcap和i中的outpcapfile生成hash值，对源和设备输出内容进行比较
    ...    m.通过rcp删除规则
    [Tags]    rcp
    [Setup]    undoAclAll
    log    测试放行用例
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    totalNumRcp
    open excel    ${ImportFilepath}/${excelName}
    ${countRow}    get row count    ${sheetName}
    #    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${countRrowAdd}    Set Variable    ${count_row}+1
    ${totalAcl}    Set Variable    0
    ${totalAppIdList}    Create List
    ${backPcafileSuf}    Set Variable    back.pcap
    ${expectRespondCode}    Set Variable    01
    ${ingroup_member}    create list    @{inportId}
    ${ingroup_member_num}    Get Length    ${ingroup_member}
    comment    按照excel中的行为单位进行循环测试
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        log    第${row}行循环测试
        comment    获取相关内容
        ${configFileName}    read cell data by name    ${sheetName}    A${row}
        ${ruleTitle}    read cell data by name    ${sheetName}    B${row}
        ${result}    read cell data by name    ${sheetName}    C${row}
        ${operaType}    read cell data by name    ${sheetName}    D${row}
        ${packetFileName}    read cell data by name    ${sheetName}    E${row}
        ${hitPcapTile}    read cell data by name    ${sheetName}    F${row}
        ${backpcapTitle}    read cell data by name    ${sheetName}    G${row}
        ${savePcapfileFlag}    read cell data by name    ${sheetName}    H${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    I${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    J${row}
        ${expectTotalNum}    read cell data by name    ${sheetName}    K${row}
        ${zuduanValue}    read cell data by name    ${sheetName}    L${row}
        ${operaTypeNext}    Run Keyword If    ${row} == ${countRow}    Set Variable    03
        ...    ELSE    read cell data by name    ${sheetName}    C${${row}+1}
        comment    下发业务配置
        ${expectTotalNumBit}    evaluate    ${expectTotalNum}*1024*1024*${ingroup_member_num}
        changeConfigOptionValue    ${configFileName}    ${ruleTitle}    total    ${expectTotalNumBit}
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword If    "${operaType}"=="04"    alarmSet    ${configFileName}    ${ruleTitle}
        ...    ELSE IF    "${operaType}"=="00" or "${operaType}"=="01" or "${operaType}"=="02" \    addOrModifyOrDrop    ${configFileName}    ${ruleTitle}    ${totalAppIdList}[0]
        ...    ELSE IF    "${operaType}"=="03"    addOrModifyOrDrop    ${configFileName}    ${ruleTitle}
        ...    ELSE    Set Variable    0    0    0    1
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp操作失败
        Continue For Loop If    '${hitPcapTile}' == 'no'
        ${hitPcapfileName}    makePcap    ${0}    ${packetFileName}    ${hitPcapTile}
        ${backPcapfile}    makePcap    ${0}    ${packetFileName}    ${backpcapTitle}
        Append To List    ${totalAppIdList}    ${ruleId}
        Remove Values From List    ${totalAppIdList}    ${0}
        log    ${totalAppIdList}
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    ${savePcapfileFlag}_${row}_back    ${backPcapfile}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    getAclHitstatistics    ${totalAppIdList}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    ${savePcapfileFlag}_${row}_hit    ${hitPcapfileName}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    Run Keyword If    '${result}'=='01'    getAclHitstatistics    ${totalAppIdList}
        ...    ELSE    Set Variable    1
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${hitCount}    ${0}    业务流的hitCount等于0
        Comment    通过hash校验包的完整性
        ${exactTime}    ${exactNum}    ${firstPacketUnixTime}    Bj Make    ${localRipePcapPath}${savePcapfileFlag}_${row}_hit.pcap
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}    ${hitPcapfileName}
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    ${savePcapfileFlag}_${row}_hit.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Run Keyword If    ${rx} !=0    Should Be True    ${hashResult}
        Run Keyword If    '${result}'=='01'    checkNumOrTimeResult    ${savePcapfileFlag}_${row}_hit.pcap    ${zuduanValue}    0    ${startFlowSpeed}    1    ${wuCha}
        Comment    删除本次循环时下发的acl，进入下一次循环acl下发
        ${totalAcl}    Set Variable    0
        ${totalAppIdList}    Run Keyword If    '${operaTypeNext}' == '03'    Create List
        ...    ELSE    Create List    ${ruleId}
        Run Keyword If    '${result}'!='01' and '${zuduanValue}' =='0'    log    此时无告警
        ...    ELSE IF    '${result}'!='01' and '${zuduanValue}' =='1'    log    此时有告警
        Continue For Loop If    '${result}'!='01'
        comment    阻断后查询规则变成drop
        New Connection Custom
        telnet.write    show acl all
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    Should Not Contain    ${info}    action forward    阻断后，规则中包含forward
        ${rx}    ${tx}    tcpreplayAndTcpdump    ${savePcapfileFlag}_${row}_hit_after_drop    ${hitPcapfileName}    0    0
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    阻断后还能输出
    END

totalTime
    [Tags]    rcp    time
    [Setup]    undoAclAll
    log    测试时间阻断用例--未来生效
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    totalTimeRcp
    open excel    ${ImportFilepath}/${excelName}
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${totalAcl}    Set Variable    0
    ${totalAppIdList}    Create List
    ${backPcafileSuf}    Set Variable    back.pcap
    ${expectRespondCode}    Set Variable    01
    comment    按照excel中的行为单位进行循环测试
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        log    第${row}行循环测试
        comment    获取相关内容
        ${configFileName}    read cell data by name    ${sheetName}    A${row}
        ${ruleTitle}    read cell data by name    ${sheetName}    B${row}
        ${packetFileName}    read cell data by name    ${sheetName}    C${row}
        ${hitPcapTile}    read cell data by name    ${sheetName}    D${row}
        ${backPcapTile}    read cell data by name    ${sheetName}    E${row}
        ${savePcapfileFlag}    read cell data by name    ${sheetName}    F${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    G${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    H${row}
        ${expectTotalTime}    read cell data by name    ${sheetName}    I${row}
        ${actionTime}    read cell data by name    ${sheetName}    J${row}
        comment    下发业务配置
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    ${actionTime}
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${expectTotalTime}
        log    ${startTimeSys}
        log    ${endTimeSys}
        changeConfigOptionValue    ${configFileName}    ${ruleTitle}    starttime    ${startTimeSys}
        changeConfigOptionValue    ${configFileName}    ${ruleTitle}    endtime    ${endTimeSys}
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${configFileName}    ${ruleTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        ${hitPcapfileName}    Run Keyword If    "${hitPcapTile}" not in ${packetTitleList}    makePcap    ${0}    ${packetFileName}    ${hitPcapTile}
        ...    ELSE    makePcap    ${1}    ${packetFileName}    ${hitPcapTile}
        Run Keyword If    "${hitPcapTile}" not in ${packetTitleList}    Append To List    ${packetTitleList}    ${hitPcapTile}
        ${backPcapfileName}    Run Keyword If    "${backPcapTile}" not in ${packetTitleList}    makePcap    ${0}    ${packetFileName}    ${backPcapTile}
        ...    ELSE    makePcap    ${1}    ${packetFileName}    ${backPcapTile}
        Run Keyword If    "${backPcapTile}" not in ${packetTitleList}    Append To List    ${packetTitleList}    ${backPcapTile}
        Append To List    ${totalAppIdList}    ${ruleId}
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    ${savePcapfileFlag}_${row}_back    ${backPcapfileName}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    getAclHitstatistics    ${totalAppIdList}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    ${savePcapfileFlag}_${row}_hit    ${hitPcapfileName}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Comment    通过hash校验包的完整性
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}    ${hitPcapfileName}
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    ${savePcapfileFlag}_${row}_hit.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Run Keyword If    ${rx} !=0    Should Be True    ${hashResult}
        checkNumOrTimeResult    ${savePcapfileFlag}_${row}_hit.pcap    0    ${expectTotalTime}    ${startFlowSpeed}    0    ${wuCha}
        comment    新增阻断后校验
        New Connection Custom
        telnet.write    show acl all
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    Should Not Contain    ${info}    action forward    阻断后，规则中包含forward
        ${rx}    ${tx}    tcpreplayAndTcpdump    ${savePcapfileFlag}_${row}_hit_after_drop    ${hitPcapfileName}    0    0
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    阻断后还能输出
        Comment    删除本次循环时下发的acl，进入下一次循环acl下发
        ${totalAcl}    Set Variable    0
        ${totalAppIdList}    Create List
        delete    ${ruleId}    ${expectRespondCode}
    END

rcpAddModifyDel
    [Tags]    rcp
    [Setup]    undo acl all
    log    测试放行用例
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    rcpAddModifyDel
    open excel    ${ImportFilepath}/${excelName}
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${totalAcl}    Set Variable    0
    ${totalAppIdList}    Create List
    ${backPcafileSuf}    Set Variable    back.pcap
    ${expectRespondCode}    Set Variable    01
    comment    按照excel中的行为单位进行循环测试
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        log    第${row}行循环测试
        comment    获取相关内容
        ${configFileName}    read cell data by name    ${sheetName}    A${row}
        ${ruleTitle}    read cell data by name    ${sheetName}    B${row}
        ${addOrModify}    read cell data by name    ${sheetName}    C${row}
        ${pcapfileOrNO}    read cell data by name    ${sheetName}    D${row}
        ${backPcapfile}    read cell data by name    ${sheetName}    E${row}
        ${savePcapfileFlag}    read cell data by name    ${sheetName}    F${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    G${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    H${row}
        ${expectTotalNum}    read cell data by name    ${sheetName}    I${row}
        ${expectDayNum}    read cell data by name    ${sheetName}    J${row}
        ${expectTotalTime}    read cell data by name    ${sheetName}    K${row}
        ${actionTime}    read cell data by name    ${sheetName}    L${row}
        ${addOrModifyNextRow}    Run Keyword If    ${row} == ${countRow}    Set Variable    03
        ...    ELSE    read cell data by name    ${sheetName}    C${${row}+1}
        comment    下发业务配置
        ${expectTotalNumBit}    evaluate    ${expectTotalNum}*1024*1024
        ${expectDayNumBit}    evaluate    ${expectDayNum}*1024*1024
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    ${actionTime}
        ${endTimeSysTmp}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${expectTotalTime}
        ${startTimeSysTmp}    Run Keyword If    "${expectTotalTime}" == "0"    Set Variable    0
        ...    ELSE    Set Variable    ${startTimeSys}
        ${endTimeSys}    Run Keyword If    "${expectTotalTime}" == "0"    Set Variable    0
        ...    ELSE    Set Variable    ${endTimeSysTmp}
        ${expectTotalNumBit}    Run Keyword if    ${row} == 36    Set Variable    64*1024*1024
        ...    ELSE    Set Variable    ${expectTotalNumBit}    #针对之前modify不会保留之前的放行信息改成关联放行信息，增加该条配置
        changeConfigOptionValue    ${configFileName}    ${ruleTitle}    total    ${expectTotalNumBit}
        changeConfigOptionValue    ${configFileName}    ${ruleTitle}    day    ${expectDayNumBit}
        changeConfigOptionValue    ${configFileName}    ${ruleTitle}    starttime    ${startTimeSysTmp}
        changeConfigOptionValue    ${configFileName}    ${ruleTitle}    endtime    ${endTimeSys}
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${configFileName}    ${ruleTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        Append To List    ${totalAppIdList}    ${ruleId}
        comment    通过rcp查询规则是否正常下发
        ${questBody}    ${expectRespond}    ${exactRespond}    ${appid}    Query Rule    ${ruleId}    ${expectRespondCode}    ${requestBody}    0    0    1
        #    Run Keyword And Continue On Failure    Run Keyword If    "${addOrModify}"=='03'    Should Be Equal As Strings    ${expectRespond}[:-16]    ${exactRespond}[:-16]    RCP查询规则异常
        Run Keyword And Continue On Failure    Run Keyword If    "${addOrModify}"=='03'    Should Be Equal As Strings    ${expectRespond}[:-64]    ${exactRespond}[:-64]    RCP查询规则异常
        Run Keyword And Continue On Failure    Run Keyword If    "${addOrModify}"=='03'    Should Be Equal As Strings    ${expectRespond}[-48:]    ${exactRespond}[-48:]    RCP查询规则异常
        ${result}    Run Keyword If    "${addOrModify}"=='03'    Hex To Int    ${exactRespond}[-64:-48]
        Run Keyword And Continue On Failure    Run Keyword If    "${addOrModify}"=='03'    Should Be True    ${result}<=2
        comment    通过命令行查询rcp下发规则是否正常--后续增加
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    ${savePcapfileFlag}_${row}_back    ${backPcapfile}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    Run Keyword If    "${expectTotalTime}" == "0"    getAclHitstatistics    ${totalAppIdList}
        ...    ELSE    Set Variable    0
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    ${savePcapfileFlag}_${row}_hit    ${pcapfileOrNO}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    Run Keyword If    "${expectTotalTime}" == "0" and "${expectTotalNum}" == "0"    getAclHitstatistics    ${totalAppIdList}
        ...    ELSE    Set Variable    1
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${hitCount}    ${0}    业务流的hitCount等于0    #    Run Keyword If    "${expectTotalTime}" != "0"    checkNumOrTimeResult    ${savePcapfileFlag}_${row}_hit.pcap    ${expectTotalNum}    ${expectTotalTime}    ${startFlowSpeed}    0    ${wuCha}    # ELSE IF
        ...    # "${expectTotalNum}" != "0"    checkNumOrTimeResult    ${savePcapfileFlag}_${row}_hit.pcap    ${expectTotalNum}    0    ${startFlowSpeed}    1    ${wuCha}
        comment    校验阻断后的效果（下面6行）
        New Connection Custom
        telnet.write    show acl all
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword If    "${expectTotalTime}" != "0"    Run Keyword And Continue On Failure    Should Not Contain    ${info}    action forward    阻断后，规则中包含forward
        ${rx}    ${tx}    Run Keyword If    "${expectTotalTime}" != "0"    tcpreplayAndTcpdump    ${savePcapfileFlag}_${row}_hit_after_drop    ${pcapfileOrNO}    0    0
        Run Keyword If    "${expectTotalTime}" != "0"    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    阻断后还能输出
        ${totalAppIdList}    Run Keyword If    '${addOrModifyNextRow}' == '03'    Create List
        ...    ELSE    Create List    ${ruleId}
        ${questBody}    ${expectRespond}    ${exactRespond}    ${appid}    Run Keyword If    '${addOrModifyNextRow}' == '03'    delete    ${ruleId}    ${expectRespondCode}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectRespond}    ${exactRespond}    rcp删除规则失败
        ${questBody}    ${expectRespond}    ${exactRespond}    ${appid}    Run Keyword If    '${addOrModifyNextRow}' == '03'    Query Rule    ${ruleId}    04    ${requestBody}    0    0    0
    END

rcp_add
    [Documentation]    1、add_v4
    ...
    ...    2、add_v6
    ...
    ...    3、add_v4v6
    ...
    ...    4、add_mult(sip:2v4+1v6,dip:2v6+1v4)
    ...
    ...    5、add_total(v4+total)
    ...
    ...    6、add_time(v6+time)
    ...
    ...    7、add_startendtime(v4v6+startendtime)
    ...
    ...    8、add_only_sip_v4
    ...
    ...    9、add_only_dip_v4
    ...
    ...    10、add_only_sip_v6
    ...
    ...    11、add_only_dip_v6
    ...
    ...    12、add_only_sip_v4v6
    ...
    ...    13、add_only_dip_v4v6
    ...
    ...    14、add_drop_dip_only（v4v6）阻断规则，以8个地址为单位 800个包阻断100个
    [Tags]    rcp
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    ADD
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    按照excel中的行为单位进行循环测试
    #    ${${countRow}-1}
    FOR    ${row}    IN RANGE    2    ${${countRow}-1}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    H${row}
        ${hitPcapTitle}    read cell data by name    ${sheetName}    I${row}
        ${backPcapTitle}    read cell data by name    ${sheetName}    J${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    K${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    L${row}
        comment    对对应的ini配置文件的限量信息进行设置
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    80
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    生成pcap包
        ${backPcap}    makePcap    ${0}    ${iniPacketFileName}    ${backPcapTitle}
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${hitPcapTitle}
        log    ${backPcap}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_back    ${backPcap}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_hit    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        #    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${tx}[1]    业务流的hitCount不等于仪表的Tx
        Run Keyword And Continue On Failure    Should Be True    ${hitCount}<=${inByte}    业务流的hitCount大等设备总接收
        Run Keyword And Continue On Failure    Should Be True    ${hitCount}>=${outByte}    业务流的hitCount小于设备的txbyte
        Run Keyword If    "${expectOutTotal}" !="0"    checkNumOrTimeResult    interface_add_${row}_hit.pcap    ${expectOutTotal}    0    ${startFlowSpeed}    1    ${wuCha}
        ...    ELSE IF    "${expectOutTime}"!='0'    checkNumOrTimeResult    interface_add_${row}_hit.pcap    0    ${expectOutTime}    ${startFlowSpeed}    0    ${wuCha}
        comment    校验阻断后的效果（下面6行）
        New Connection Custom
        telnet.write    show acl all | include "grouped_rule ${ruleId}"
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword If    "${expectOutTotal}" !="0"    Run Keyword And Continue On Failure    Should not Contain    ${info}    action forward    阻断后，规则中包含forward
        ${rx}    ${tx}    Run Keyword If    "${expectOutTotal}" !="0"    tcpreplayAndTcpdump    interface_add_${row}_hit_after_drop    ${hitPcap}    0    0
        Run Keyword If    "${expectOutTotal}" !="0"    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    阻断后还能输出
    END
    FOR    ${row}    IN RANGE    ${${countRow}-1}    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    H${row}
        ${hitPcapTitle}    read cell data by name    ${sheetName}    I${row}
        ${backPcapTitle}    read cell data by name    ${sheetName}    J${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    K${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    L${row}
        comment    对对应的ini配置文件的限量信息进行设置
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    80
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    生成pcap包
        ${backPcap}    makePcap    ${0}    ${iniPacketFileName}    ${backPcapTitle}
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${hitPcapTitle}
        log    ${backPcap}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_back    ${backPcap}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_hit    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Numbers    ${${tx}[0]//8*7}    ${rx}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${${tx}[1]//8}    业务流的hitCount不等于仪表的Tx
    END

rcp_add_vlan
    [Documentation]    1、add_v4
    ...
    ...    2、add_v6
    ...
    ...    3、add_v4v6
    ...
    ...    4、add_mult(sip:2v4+1v6,dip:2v6+1v4)
    ...
    ...    5、add_total(v4+total)
    ...
    ...    6、add_time(v6+time)
    ...
    ...    7、add_startendtime(v4v6+startendtime)
    ...
    ...    8、add_only_sip_v4
    ...
    ...    9、add_only_dip_v4
    ...
    ...    10、add_only_sip_v6
    ...
    ...    11、add_only_dip_v6
    ...
    ...    12、add_only_sip_v4v6
    ...
    ...    13、add_only_dip_v4v6
    ...
    ...    14、add_drop_dip_only（v4v6）阻断规则，以8个地址为单位 800个包阻断100个
    [Tags]    rcp
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    ADD_VLAN
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    按照excel中的行为单位进行循环测试
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    H${row}
        ${hitPcapTitle}    read cell data by name    ${sheetName}    I${row}
        ${backPcapTitle}    read cell data by name    ${sheetName}    J${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    K${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    L${row}
        comment    对对应的ini配置文件的限量信息进行设置
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    80
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    生成pcap包
        ${backPcap}    makePcap    ${0}    ${iniPacketFileName}    ${backPcapTitle}
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${hitPcapTitle}
        log    ${backPcap}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_back    ${backPcap}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_hit    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        #    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${tx}[1]    业务流的hitCount不等于仪表的Tx
        Run Keyword And Continue On Failure    Should Be True    ${hitCount}<=${inByte}    业务流的hitCount大等设备接收
        Run Keyword And Continue On Failure    Should Be True    ${hitCount}>=${outByte}    业务流的hitCount小于设备的txbyte
        Run Keyword If    "${expectOutTotal}" !="0"    checkNumOrTimeResult    interface_add_${row}_hit.pcap    ${expectOutTotal}    0    ${startFlowSpeed}    1    ${wuCha}
        ...    ELSE IF    "${expectOutTime}"!='0'    checkNumOrTimeResult    interface_add_${row}_hit.pcap    0    ${expectOutTime}    ${startFlowSpeed}    0    ${wuCha}
        comment    校验阻断后的效果（下面6行）
        New Connection Custom
        telnet.write    show acl all
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword If    "${expectOutTotal}" !="0"    Run Keyword And Continue On Failure    Should Not Contain    ${info}    action forward    阻断后，规则中包含forward
        ${rx}    ${tx}    Run Keyword If    "${expectOutTotal}" !="0"    tcpreplayAndTcpdump    interface_add_${row}_hit_after_drop    ${hitPcap}    0    0
        Run Keyword If    "${expectOutTotal}" !="0"    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    阻断后还能输出
        Run Keyword And Continue On Failure    delete    ${ruleId}    01
    END

rcp_add_sni_acl
    [Documentation]    1、下发sni_limit规则，serverType 5,sni_num 6,nohttps 0,radio 0
    ...    2、下发sni_acl 17字节包含问号：tbn?0.gstatic.com，打流看是否正常命中
    ...    3、下发sni_acl 21字节包含井号：pted#tbn0.gstatic.com，打流看是否正常命中
    ...    4、下发sni_acl 27字节包含横线：sencrypted-tbn0.gstatic.com，打流看是否正常命中
    ...    5、下发sni_acl 30字节包含下划线：ww.sen_rypted-tbn0.gstatic.com，打流看是否正常命中
    ...    6、下发sni_acl 18字节包含下竖线：|tbn0.gstatic.com，打流看是否正常命中
    ...    7、下发sni_acl 1字节最后字节为t：包中包含static.doubleclinck.net，打流看是否正常命中
    ...    8、下发sni_acl总共6条(包含上面的6条：打流看是否正常命中全部输出，且进行阻断了
    ...
    ...    2024-10-30 增加第9步骤，验证支持63B
    ...    1，rcp下发的是65B的规则：ac762226756d9a50ab48354b44c6cb910.profile.eze51-c1.cloudfront.net （servername_65.pcap）
    ...    2，到了设备上只能下发64B: c762226756d9a50ab48354b44c6cb910.profile.eze51-c1.cloudfront.net
    ...    3，修改报文是的第64为不符合预期：aa762226756d9a50ab48354b44c6cb910.profile.eze51-c1.cloudfront.net(正常也能命中，因为fpga只支持63B，会从后面开始截取 \ （servername_64_diff.pcap）
    ...    4，为了验证fpga从后截取，则把最后1位修改不符合，预期结果无法命中：c762226756d9a50ab48354b44c6cb910.profile.eze51-c1.cloudfront.neg \ （servername_1_diff.pcap）
    ...    5、为了验证fpga支持63B,修改第63B为f，预期不命中即可：acf62226756d9a50ab48354b44c6cb910.profile.eze51-c1.cloudfront.net （servername_63_diff.pcap）
    [Tags]    A
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    ADD_SNI_ACL
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    按照excel中的行为单位进行循环测试
    ${sni_filename}    create list
    FOR    ${row}    IN RANGE    2    12
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${sni_limit_or_acl}    read cell data by name    ${sheetName}    C${row}    #0代表是limit，1代表acl
        ${serviceType}    read cell data by name    ${sheetName}    D${row}
        ${sni_number}    read cell data by name    ${sheetName}    E${row}
        ${sni_nohttps}    read cell data by name    ${sheetName}    F${row}
        ${sni_not_https_radio}    read cell data by name    ${sheetName}    G${row}
        ${pcap}    read cell data by name    ${sheetName}    H${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    I${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    J${row}
        ${drop_or_no}    read cell data by name    ${sheetName}    K${row}    #1代表阻断，其他代表非阻断
        ${backpcap}    read cell data by name    ${sheetName}    L${row}
        comment    根据serviceType为0进行sni规则
        Run Keyword If    ${sni_limit_or_acl} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    serviceType    ${serviceType}
        Run Keyword If    ${sni_limit_or_acl} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    sniNumber    ${sni_number}
        Run Keyword If    ${sni_limit_or_acl} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    httpsPercent    ${sni_nohttps}
        Run Keyword If    ${sni_limit_or_acl} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    notHttps    ${sni_not_https_radio}
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword If    ${sni_limit_or_acl} == 0    sniSet    ${iniRcpFileName}    ${testTitle}
        Run Keyword If    ${sni_limit_or_acl} == 0    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    SNI下发失败
        Run Keyword If    ${sni_limit_or_acl} == 0    Append To List    ${sni_filename}    ${iniRcpFileName}
        New Connection Custom
        telnet.write    show sni_limit
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Continue For Loop If    ${sni_limit_or_acl} == 0
        comment    根据sni_limit_or_acl}非0进行acl规则
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    servicetype    ${serviceType}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addSniRule    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_sni_${row}_back    ${backpcap}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        New Connection Custom
        telnet.write    show acl hit_statistics \ 1
        ${info}    Telnet.Read Until    sysadmin(config)#
        ${sni_hitCountList}    get regexp matches    ${info}    [0-9]{1,}\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)    3
        Run Keyword And Continue On Failure    Should Be Equal As Integers    0    ${sni_hitCountList}[0]
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_sni_${row}_hit    ${pcap}    ${startFlowSpeed}    ${startFlowTime}
        ${output}    Set Variable If    ${row} == 11    ${3}    ${1}    #第11行应该输出3个，第9行输出6个，其他输出1个
        Run Keyword If    ${drop_or_no}!=1    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${output}    业务流仪表的rx等于0
        ...    ELSE    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${6}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inPkt}    ${outPkt}
        New Connection Custom
        telnet.write    show acl hit_statistics \ 1
        ${info}    Telnet.Read Until    sysadmin(config)#
        ${sni_hitCountList}    get regexp matches    ${info}    [0-9]{1,}\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)    3
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${sni_number}    ${sni_hitCountList}[0]
        Continue For Loop If    ${drop_or_no}!=1
        New Connection Custom
        telnet .write    show acl all | include "server_name"
        ${log}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    Should Contain    ${log}    action drop    阻断后规则未变成drop
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_drop_${row}_hit    ${pcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    未正常阻断，依然有输出
    END

rcp_add_sni_acl_fenpian
    [Documentation]    增加分片报文，命中输出第2片
    [Tags]    A
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    ADD_SNI_ACL
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    按照excel中的行为单位进行循环测试
    ${sni_filename}    create list
    FOR    ${row}    IN RANGE    12    13
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${sni_limit_or_acl}    read cell data by name    ${sheetName}    C${row}    #0代表是limit，1代表acl
        ${serviceType}    read cell data by name    ${sheetName}    D${row}
        ${sni_number}    read cell data by name    ${sheetName}    E${row}
        ${sni_nohttps}    read cell data by name    ${sheetName}    F${row}
        ${sni_not_https_radio}    read cell data by name    ${sheetName}    G${row}
        ${pcap}    read cell data by name    ${sheetName}    H${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    I${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    J${row}
        ${drop_or_no}    read cell data by name    ${sheetName}    K${row}    #1代表阻断，其他代表非阻断
        ${backpcap}    read cell data by name    ${sheetName}    L${row}
        comment    根据serviceType为0进行sni规则
        Run Keyword If    ${sni_limit_or_acl} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    serviceType    ${serviceType}
        Run Keyword If    ${sni_limit_or_acl} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    sniNumber    ${sni_number}
        Run Keyword If    ${sni_limit_or_acl} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    httpsPercent    ${sni_nohttps}
        Run Keyword If    ${sni_limit_or_acl} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    notHttps    ${sni_not_https_radio}
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword If    ${sni_limit_or_acl} == 0    sniSet    ${iniRcpFileName}    ${testTitle}
        Run Keyword If    ${sni_limit_or_acl} == 0    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    SNI下发失败
        Run Keyword If    ${sni_limit_or_acl} == 0    Append To List    ${sni_filename}    ${iniRcpFileName}
        New Connection Custom
        telnet.write    show sni_limit
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Continue For Loop If    ${sni_limit_or_acl} == 0
        comment    根据sni_limit_or_acl}非0进行acl规则
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    servicetype    ${serviceType}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addSniRule    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_sni_${row}_back    ${backpcap}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        New Connection Custom
        telnet.write    show acl hit_statistics \ 1
        ${info}    Telnet.Read Until    sysadmin(config)#
        ${sni_hitCountList}    get regexp matches    ${info}    [0-9]{1,}\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)    3
        Run Keyword And Continue On Failure    Should Be Equal As Integers    0    ${sni_hitCountList}[0]
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_sni_${row}_hit    ${pcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword If    ${drop_or_no}!=1    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${1}    业务流仪表的rx等于0
        ...    ELSE    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${6}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${outByte}    400
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${outPkt}    1
        New Connection Custom
        telnet.write    show acl hit_statistics \ 1
        ${info}    Telnet.Read Until    sysadmin(config)#
        ${sni_hitCountList}    get regexp matches    ${info}    [0-9]{1,}\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)    3
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${sni_number}    ${sni_hitCountList}[0]
        Continue For Loop If    ${drop_or_no}!=1
        New Connection Custom
        telnet .write    show acl all | include "server_name"
        ${log}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    Should Contain    ${log}    action drop    阻断后规则未变成drop
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_drop_${row}_hit    ${pcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    未正常阻断，依然有输出
    END

rcp_modify_rule
    [Documentation]    1、增加规则sipg=4个v4,3个v6；dipg=3个v4,4个v6
    ...
    ...    2、modify_del sipg=1个v6
    ...
    ...    3、modify_del dipg=1个v4，1个v6
    ...
    ...    4、modify_del sipg=1个v6 ;dipg=2个v6
    [Tags]    rcp
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    MODIFY_RULE
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    按照excel中的行为单位进行循环测试
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    H${row}
        ${hitPcapTitle}    read cell data by name    ${sheetName}    I${row}
        ${backPcapTitle}    read cell data by name    ${sheetName}    J${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    K${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    L${row}
        comment    对对应的ini配置文件的限量信息进行设置
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    80
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    生成pcap包
        ${backPcap}    makePcap    ${0}    ${iniPacketFileName}    ${backPcapTitle}
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${hitPcapTitle}
        log    ${backPcap}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_back    ${backPcap}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_hit    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${inByte}    业务流的hitCount不等于设备接收
    END

rcp_modify_rule_vlan
    [Documentation]    1、增加规则sipg=4个v4,3个v6；dipg=3个v4,4个v6
    ...
    ...    2、modify_del sipg=1个v6
    ...
    ...    3、modify_del dipg=1个v4，1个v6
    ...
    ...    4、modify_del sipg=1个v6 ;dipg=2个v6
    [Tags]    rcp
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    MODIFY_RULE_VLAN
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    按照excel中的行为单位进行循环测试
    ${appid_list}    create list    1
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    H${row}
        ${hitPcapTitle}    read cell data by name    ${sheetName}    I${row}
        ${backPcapTitle}    read cell data by name    ${sheetName}    J${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    K${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    L${row}
        comment    对对应的ini配置文件的限量信息进行设置
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    80
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    inGroup    ${ingroupId}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}    ${appid_list}[-1]
        Append To List    ${appid_list}    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    生成pcap包
        ${backPcap}    makePcap    ${0}    ${iniPacketFileName}    ${backPcapTitle}
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${hitPcapTitle}
        log    ${backPcap}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_back    ${backPcap}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_hit    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${inByte}    业务流的hitCount不等于设备接收
    END

rcp_modify_limit
    [Documentation]    1.下发forward_v4规则
    ...
    ...    2.modify不携带任何sipg,dipg信息，增加total,mon,start/endtime信息
    ...
    ...    3.modify add_v6，修改total
    ...
    ...    4.modify del_v4 修改mon
    ...
    ...    5.modify add v4v6 修改start/endtime
    ...
    ...    6.modify readd修改 total,start/end信息
    [Tags]    rcp
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    MODIFY_LIMIT
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${ingroup_member}    create list    @{inportId}
    ${ingroup_member_num}    Get Length    ${ingroup_member}
    comment    按照excel中的行为单位进行循环测试
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    H${row}
        ${hitPcapTitle}    read cell data by name    ${sheetName}    I${row}
        ${backPcapTitle}    read cell data by name    ${sheetName}    J${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    K${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    L${row}
        comment    对对应的ini配置文件的限量信息进行设置
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    85
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024*${ingroup_member_num}}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024*${ingroup_member_num}}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    生成pcap包
        ${backPcap}    makePcap    ${0}    ${iniPacketFileName}    ${backPcapTitle}
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${hitPcapTitle}
        log    ${backPcap}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_back    ${backPcap}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_hit    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be True    ${hitCount}<=${inByte}    业务流的hitCount大等设备总接收
        #    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${tx}[1]    业务流的hitCount不等于仪表的Tx
        comment    Run Keyword If    "${expectOutTotal}" !="0"    checkNumOrTimeResult    interface_add_${row}_hit.pcap    ${expectOutTotal}    0    ${startFlowSpeed}    1    ${wuCha}
        ...    ELSE IF    "${expectOutTime}"!='0'    checkNumOrTimeResult    interface_add_${row}_hit.pcap    0    ${expectOutTime}    ${startFlowSpeed}    0    ${wuCha}
        comment    校验阻断后的效果（下面6行）
        New Connection Custom
        telnet.write    show acl all
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword If    "${expectOutTotal}" !="0"    Run Keyword And Continue On Failure    Should Not Contain    ${info}    action forward    阻断后，规则中包含forward
        ${rx}    ${tx}    Run Keyword If    "${expectOutTotal}" !="0"    tcpreplayAndTcpdump    interface_add_${row}_hit_after_drop    ${hitPcap}    0    0
        Run Keyword If    "${expectOutTotal}" !="0"    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    阻断后还能输出
    END

rcp_modify_limit_vlan
    [Documentation]    1.下发vlan规则
    ...
    ...    2.modify不携带任何信息，增加total,mon,start/endtime信息
    ...
    ...    3.modify add_v6，修改total
    ...
    ...    4.modify del_v4 修改mon
    ...
    ...    5.modify add v4v6 修改start/endtime
    ...
    ...    6.modify readd修改 total,start/end信息
    [Tags]    rcp    debug
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    MODIFY_LIMIT_VLAN
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    按照excel中的行为单位进行循环测试
    ${appid_list}    create list    1
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    H${row}
        ${hitPcapTitle}    read cell data by name    ${sheetName}    I${row}
        ${backPcapTitle}    read cell data by name    ${sheetName}    J${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    K${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    L${row}
        comment    对对应的ini配置文件的限量信息进行设置
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    120
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}    ${appid_list}[-1]
        Append To List    ${appid_list}    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    生成pcap包
        ${backPcap}    makePcap    ${0}    ${iniPacketFileName}    ${backPcapTitle}
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${hitPcapTitle}
        log    ${backPcap}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_back    ${backPcap}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_hit    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be True    ${hitCount}<=${inByte}    业务流的hitCount大等设备总接收
        #    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${tx}[1]    业务流的hitCount不等于仪表的Tx
        Run Keyword If    "${expectOutTotal}" !="0"    checkNumOrTimeResult    interface_add_${row}_hit.pcap    ${expectOutTotal}    0    ${startFlowSpeed}    1    ${wuCha}
        ...    ELSE IF    "${expectOutTime}"!='0'    checkNumOrTimeResult    interface_add_${row}_hit.pcap    0    ${expectOutTime}    ${startFlowSpeed}    0    ${wuCha}
        comment    校验阻断后的效果（下面6行）
        New Connection Custom
        telnet.write    show acl all
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword If    "${expectOutTotal}" !="0"    Run Keyword And Continue On Failure    Should Not Contain    ${info}    action forward    阻断后，规则中包含forward
        ${rx}    ${tx}    Run Keyword If    "${expectOutTotal}" !="0"    tcpreplayAndTcpdump    interface_add_${row}_hit_after_drop    ${hitPcap}    0    0
        Run Keyword If    "${expectOutTotal}" !="0"    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    阻断后还能输出
    END

group_repeat
    [Documentation]    1、新增v4/v6规则
    ...
    ...    2、复用 sip_v4
    ...
    ...    3、复用dip_v4
    ...
    ...    4、复用sip_v6
    ...
    ...    5、复用dip_v6
    ...
    ...    6、复用sip_dip_v4
    ...
    ...    7、复用sip_dip_v6
    [Tags]    rcp
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    GROUP_REPEAT
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    按照excel中的行为单位进行循环测试
    ${total_appid}    Create List
    FOR    ${row}    IN RANGE    2    ${countRow}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    H${row}
        ${hitPcapTitle}    read cell data by name    ${sheetName}    I${row}
        ${backPcapTitle}    read cell data by name    ${sheetName}    J${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    K${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    L${row}
        comment    对对应的ini配置文件的限量信息进行设置
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    80
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        Append To List    ${total_appid}    ${ruleId}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    生成pcap包
        ${backPcap}    makePcap    ${0}    ${iniPacketFileName}    ${backPcapTitle}
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${hitPcapTitle}
        log    ${backPcap}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_back    ${backPcap}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_hit    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${inByte}    业务流的hitCount不等于设备输入
    END
    FOR    ${row}    IN RANGE    ${countRow}    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    H${row}
        ${hitPcapTitle}    read cell data by name    ${sheetName}    I${row}
        ${backPcapTitle}    read cell data by name    ${sheetName}    J${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    K${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    L${row}
        comment    对对应的ini配置文件的限量信息进行设置
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    80
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        Append To List    ${total_appid}    ${ruleId}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    生成pcap包
        ${backPcap}    makePcap    ${0}    ${iniPacketFileName}    ${backPcapTitle}
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${hitPcapTitle}
        log    ${backPcap}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_back    ${backPcap}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_hit    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${total_appid}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${inByte}    业务流的hitCount不等于仪表的Tx
    END

netflow_aging
    [Documentation]    //9s
    ...    mfpga1(0x1041,0x20fa) \ \ mfpga1(0x7ce9,0x20fb)
    ...
    ...    //超时，短包，tcpflag的fin和rst
    ...    mfpga1(1,0x2030)
    ...    //关闭，开启老化
    ...    mfpga1(0x4014,0x2000)、mfpga1(0x6014,0x2000)
    ...    fafb*3.3ns
    ...
    ...    netflow的srcip和报文的srcip不能相同
    [Tags]    rcp
    [Setup]    undo acl all
    ${slot_interface}    Split String    ${inportId}[0]    /
    ${slot_id}    Get From List    ${slot_interface}    0
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    NETFLOW_AGING
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    设置流统计输出端口
    sendMultiCommand    netflow outport ${outgroup_f_portId_1}[0],netflow enable,flow_table aging_accuracy 8M
    comment    设置拼包为9s左右
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /home/
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    echo -n "mfpga${slot_id}(0x1041,0x20fa) mfpga${slot_id}(0x7ce9,0x20fb) mfpga${slot_id}(1,0x2030) \ mfpga${slot_id}(0x3,0x2031)" | luacmd.lua
    sleep    1
    ${info}    SSHLibrary.Read Until    root@
    log    ${info}
    SSHLibrary.Close All Connections
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${source_mac}    read cell data by name    ${sheetName}    A${row}
        ${server_mac}    read cell data by name    ${sheetName}    B${row}
        ${source_ip}    read cell data by name    ${sheetName}    C${row}
        ${server_ip}    read cell data by name    ${sheetName}    D${row}
        ${source_port_str}    read cell data by name    ${sheetName}    E${row}
        ${server_port_str}    read cell data by name    ${sheetName}    F${row}
        ${aging_time}    read cell data by name    ${sheetName}    G${row}
        ${iniRcpFileName}    read cell data by name    ${sheetName}    H${row}
        ${testTitle}    read cell data by name    ${sheetName}    I${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    J${row}
        ${PcapTitle}    read cell data by name    ${sheetName}    K${row}
        ${zxflowFiveTupleTitle}    read cell data by name    ${sheetName}    L${row}
        ${flowCnt_str}    read cell data by name    ${sheetName}    M${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    N${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    O${row}
        ${source_port}    Convert To Integer    ${source_port_str}
        ${server_port}    Convert To Integer    ${server_port_str}
        ${flowCnt}    Convert To Integer    ${flowCnt_str}
        comment    配置对应的netflow和agingtime
        sendMultiCommand    netflow source_mac ${source_mac},netflow server_mac ${server_mac},netflow source_ip ${source_ip},netflow server_ip ${server_ip},netflow source_port ${source_port},netflow server_port ${server_port},
        sendMultiCommand    flow_manage tcp_aging_time ${aging_time},flow_manage udp_aging_time ${aging_time},flow_manage other_aging_time ${aging_time},
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword If    '${testTitle}'!=''    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword If    '${testTitle}'!=''    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        comment    生成pcap包
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${PcapTitle}
        log    ${hitPcap}
        comment    打流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    netfow_${row}    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}    1    1    ${${aging_time}+5}    src host ${source_ip}
        ${zx_postive_bytes}    ${zx_pos_pkts}    ${zx_reverse_bytes}    ${zx_rev_pkts}    get_zxflow_pkts_bytes    ${PcapTitle}    ${tx}
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${${zx_pos_pkts}+${zx_rev_pkts}}    00
        comment    解析对应的
        ${netflowcount}    Parser Pcapfile    ${localRipePcapPath}netfow_${row}.pcap
        Run Keyword And Continue On Failure    Run Keyword If    ${flowCnt} != 0    Should Be Equal As Integers    ${netflowcount}    1
        ...    ELSE    Should Be Equal As Integers    ${netflowcount}    0
        Continue For Loop If    ${flowCnt} == 0
        ${exact_flowinfo}    Bj Net Flow    netflow
        log    ${exact_flowinfo}
        comment    为防止后续执行步骤失败导致导致规则未删除，先删除本次使用的规则
        Run Keyword If    '${testTitle}'!=''    delete    ${ruleId}    01
        comment    生成预期flow信息
        ${pcap}    makePcap    ${0}    ${iniPacketFileName}    ${zxflowFiveTupleTitle}
        ${zxflowFiveTuple}    extract_five_tuple_from_pcap    ${localRawPcapPath}/${pcap}    0
        log    ${zxflowFiveTuple}
        ${zxflow_fivetuple}    Get From Dictionary    ${zxflowFiveTuple}    ${1}
        ${zxflowV4V6}    Set Variable If    "v4" in "${PcapTitle}"    ${4}    ${6}
        ${zx_ip_h}    Run Keyword If    "${testTitle}" ==""    Set Variable    03
        ...    ELSE IF    "Pos" in "${testTitle}"    Set Variable    01
        ...    ELSE IF    "Rev" in "${testTitle}"    Set Variable    02
        ...    ELSE    Set Variable    00
        ${expectResult}    Create Dictionary    source_mac=${source_mac}    server_mac=${server_mac}    protocol=UDP    source_ip=${source_ip}    server_ip=${server_ip}    source_port=${source_port}    server_port=${server_port}    zxf_ver=${1}    fl_cnt=${flowCnt}    zx_pro0=${zxflow_fivetuple}[4]    zx_ip_ver0=${zxflowV4V6}    zx_ip_h0=${zx_ip_h}    zx_sip0=${zxflow_fivetuple}[0]    zx_dip0=${zxflow_fivetuple}[2]
        ...    zx_sport0=${zxflow_fivetuple}[1]    zx_dport0=${zxflow_fivetuple}[3]    zx_postive_bytes0=${zx_postive_bytes}    zx_reverse_bytes0=${zx_reverse_bytes}
        log    ${expectResult}
        ${exact_flowinfo_1}    Get From Dictionary    ${exact_flowinfo}    ${1}
        log    ${exact_flowinfo_1}
        Run Keyword And Continue On Failure    Dictionary Should Contain Sub Dictionary    ${exact_flowinfo_1}    ${expectResult}
    END
    [Teardown]    sendMultiCommand    netflow disable

netflow_rst_fin
    [Documentation]    //9s
    ...    mfpga1(0x1041,0x20fa) \ \ mfpga1(0x7ce9,0x20fb)
    ...
    ...    //超时，短包，tcpflag的fin和rst
    ...    mfpga1(1,0x2030)
    ...
    ...    fafb*3.3ns
    ...
    ...    netflow的srcip和报文的srcip不能相同
    [Tags]    rcp
    [Setup]    undo acl all
    ${slot_interface}    Split String    ${inportId}[0]    /
    ${slot_id}    Get From List    ${slot_interface}    0
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    NETFLOW_FIN_RST
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    设置流统计输出端口
    sendMultiCommand    netflow outport ${outgroup_f_portId_1}[0],netflow enable,flow_table aging_accuracy 8M
    comment    设置拼包为9s左右
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /home/
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    echo -n "mfpga${slot_id}(0x1041,0x20fa) mfpga${slot_id}(0x7ce9,0x20fb) mfpga${slot_id}(1,0x2030) \ mfpga${slot_id}(0x3,0x2031)" | luacmd.lua
    sleep    1
    ${info}    SSHLibrary.Read Until    root@
    log    ${info}
    SSHLibrary.Close All Connections
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${source_mac}    read cell data by name    ${sheetName}    A${row}
        ${server_mac}    read cell data by name    ${sheetName}    B${row}
        ${source_ip}    read cell data by name    ${sheetName}    C${row}
        ${server_ip}    read cell data by name    ${sheetName}    D${row}
        ${source_port_str}    read cell data by name    ${sheetName}    E${row}
        ${server_port_str}    read cell data by name    ${sheetName}    F${row}
        ${aging_time}    read cell data by name    ${sheetName}    G${row}
        ${iniRcpFileName}    read cell data by name    ${sheetName}    H${row}
        ${testTitle}    read cell data by name    ${sheetName}    I${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    J${row}
        ${PcapTitle}    read cell data by name    ${sheetName}    K${row}
        ${zxflowFiveTupleTitle}    read cell data by name    ${sheetName}    L${row}
        ${flowCnt_str}    read cell data by name    ${sheetName}    M${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    N${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    O${row}
        ${source_port}    Convert To Integer    ${source_port_str}
        ${server_port}    Convert To Integer    ${server_port_str}
        ${flowCnt}    Convert To Integer    ${flowCnt_str}
        comment    配置对应的netflow和agingtime
        sendMultiCommand    netflow source_mac ${source_mac},netflow server_mac ${server_mac},netflow source_ip ${source_ip},netflow server_ip ${server_ip},netflow source_port ${source_port},netflow server_port ${server_port},
        sendMultiCommand    flow_manage tcp_aging_time ${aging_time},flow_manage udp_aging_time ${aging_time},flow_manage other_aging_time ${aging_time},
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword If    '${testTitle}'!=''    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword If    '${testTitle}'!=''    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        comment    生成pcap包
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${PcapTitle}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    netfow_${row}    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}    1    1    ${9}    src host ${source_ip}
        ${zx_postive_bytes}    ${zx_postive_pkts}    ${zx_reverse_bytes}    ${zx_reverse_pkts}    get_zxflow_pkts_bytes    ${PcapTitle}    ${tx}
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${${zx_postive_pkts}+${zx_reverse_pkts}}    00
        comment    解析对应的
        ${netflowcount}    Parser Pcapfile    ${localRipePcapPath}netfow_${row}.pcap
        Run Keyword And Continue On Failure    Run Keyword If    ${flowCnt} != 0    Should Be Equal As Integers    ${netflowcount}    1
        ...    ELSE    Should Be Equal As Integers    ${netflowcount}    0
        Continue For Loop If    ${flowCnt} == 0
        ${exact_flowinfo}    Bj Net Flow    netflow
        log    ${exact_flowinfo}
        comment    生成预期flow信息
        ${pcap}    makePcap    ${0}    ${iniPacketFileName}    ${zxflowFiveTupleTitle}
        ${zxflowFiveTuple}    extract_five_tuple_from_pcap    ${localRawPcapPath}/${pcap}    0
        log    ${zxflowFiveTuple}
        ${zxflow_fivetuple}    Get From Dictionary    ${zxflowFiveTuple}    ${1}
        ${zxflowV4V6}    Set Variable If    "v4" in "${PcapTitle}"    ${4}    ${6}
        ${zx_ip_h}    Run Keyword If    "${testTitle}" ==""    Set Variable    03
        ...    ELSE IF    "Pos" in "${testTitle}"    Set Variable    01
        ...    ELSE IF    "Rev" in "${testTitle}"    Set Variable    02
        ...    ELSE    Set Variable    00
        ${PcapTitle_list}    Split String    ${PcapTitle}    ,
        ${expectResult}    Create Dictionary    source_mac=${source_mac}    server_mac=${server_mac}    protocol=UDP    source_ip=${source_ip}    server_ip=${server_ip}    source_port=${source_port}    server_port=${server_port}    zxf_ver=${1}    fl_cnt=${flowCnt}    zx_pro0=${zxflow_fivetuple}[4]    zx_ip_ver0=${zxflowV4V6}    zx_ip_h0=${zx_ip_h}    zx_sip0=${zxflow_fivetuple}[0]    zx_dip0=${zxflow_fivetuple}[2]
        ...    zx_sport0=${zxflow_fivetuple}[1]    zx_dport0=${zxflow_fivetuple}[3]    zx_postive_bytes0=${zx_postive_bytes}    zx_reverse_bytes0=${zx_reverse_bytes}
        log    ${expectResult}
        ${exact_flowinfo_1}    Get From Dictionary    ${exact_flowinfo}    ${1}
        log    ${exact_flowinfo_1}
        Run Keyword And Continue On Failure    Dictionary Should Contain Sub Dictionary    ${exact_flowinfo_1}    ${expectResult}
        Run Keyword If    '${testTitle}'!=''    delete    ${ruleId}    01
    END
    [Teardown]    sendMultiCommand    netflow disable

netflow_joint
    [Documentation]    //9s
    ...    mfpga1(0x1041,0x20fa) \ \ mfpga1(0x7ce9,0x20fb)
    ...
    ...    //超时，短包，tcpflag的fin和rst
    ...    mfpga1(1,0x2030)
    ...
    ...    fafb*3.3ns
    ...
    ...    netflow的srcip和报文的srcip不能相同
    ...
    ...    拼包：46+32(v4netflow)*flwcnt1+56(v6*netflow)*flwcnt2+4(crc)
    [Tags]    rcp
    [Setup]    undo acl all
    ${slot_interface}    Split String    ${inportId}[0]    /
    ${slot_id}    Get From List    ${slot_interface}    0
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    NETFLOW_JOINT
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    设置流统计输出端口
    sendMultiCommand    netflow outport ${outgroup_f_portId_1}[0],netflow enable,flow_table aging_accuracy 8M
    comment    设置拼包为9s左右
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /home/
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    echo -n "mfpga${slot_id}(0x1041,0x20fa) mfpga${slot_id}(0x7ce9,0x20fb) mfpga${slot_id}(1,0x2030) mfpga${slot_id}(0x3,0x2031)" | luacmd.lua
    sleep    1
    ${info}    SSHLibrary.Read Until    root@
    log    ${info}
    SSHLibrary.Close All Connections
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${source_mac}    read cell data by name    ${sheetName}    A${row}
        ${server_mac}    read cell data by name    ${sheetName}    B${row}
        ${source_ip}    read cell data by name    ${sheetName}    C${row}
        ${server_ip}    read cell data by name    ${sheetName}    D${row}
        ${source_port_str}    read cell data by name    ${sheetName}    E${row}
        ${server_port_str}    read cell data by name    ${sheetName}    F${row}
        ${aging_time}    read cell data by name    ${sheetName}    G${row}
        ${iniRcpFileName}    read cell data by name    ${sheetName}    H${row}
        ${testTitle}    read cell data by name    ${sheetName}    I${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    J${row}
        ${PcapTitle}    read cell data by name    ${sheetName}    K${row}
        ${zxflowFiveTupleTitle}    read cell data by name    ${sheetName}    L${row}
        ${flowCnt_str}    read cell data by name    ${sheetName}    M${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    N${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    O${row}
        ${source_port}    Convert To Integer    ${source_port_str}
        ${server_port}    Convert To Integer    ${server_port_str}
        ${flowCnt}    Convert To Integer    ${flowCnt_str}
        comment    配置对应的netflow和agingtime
        sendMultiCommand    netflow source_mac ${source_mac},netflow server_mac ${server_mac},netflow source_ip ${source_ip},netflow server_ip ${server_ip},netflow source_port ${source_port},netflow server_port ${server_port},
        sendMultiCommand    flow_manage tcp_aging_time ${aging_time},flow_manage udp_aging_time ${aging_time},flow_manage other_aging_time ${aging_time},
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword If    '${testTitle}'!=''    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword If    '${testTitle}'!=''    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        comment    生成pcap包
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${PcapTitle}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    netfow_${row}    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}    1    1    ${${aging_time}+5}    src host ${source_ip}
        ${zx_postive_bytes}    ${zx_postive_pkts}    ${zx_reverse_bytes}    ${zx_reverse_pkts}    get_zxflow_pkts_bytes    ${PcapTitle}    ${tx}
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${${zx_postive_pkts}+${zx_reverse_pkts}}    00
        comment    解析对应的
        ${netflowcount}    Parser Pcapfile    ${localRipePcapPath}netfow_${row}.pcap
        Run Keyword And Continue On Failure    Run Keyword If    ${flowCnt} != 0    Should Be Equal As Integers    ${netflowcount}    1
        ...    ELSE    Should Be Equal As Integers    ${netflowcount}    0
        Continue For Loop If    ${flowCnt} == 0
        ${exact_flowinfo}    Bj Net Flow    netflow
        log    ${exact_flowinfo}
        comment    生成预期flow信息
        ${pcap}    makePcap    ${0}    ${iniPacketFileName}    ${zxflowFiveTupleTitle}
        ${zxflowFiveTuple}    extract_five_tuple_from_pcap    ${localRawPcapPath}/${pcap}    1
        log    ${zxflowFiveTuple}
        #    ${zxflow_fivetuple_index1}    Get From Dictionary    ${zxflowFiveTuple}    ${1}
        #    log    ${zxflow_fivetuple}
        ${zxflowV4V6}    Set Variable If    "v4" in "${PcapTitle}"    ${4}    ${6}
        ${zx_ip_h}    Run Keyword If    "${testTitle}" ==""    Set Variable    03
        ...    ELSE IF    "Pos" in "${testTitle}"    Set Variable    01
        ...    ELSE IF    "Rev" in "${testTitle}"    Set Variable    02
        ...    ELSE    Set Variable    00
        ${PcapTitle_list}    Split String    ${PcapTitle}    ,
        ${expectResultComm}    Create Dictionary    source_mac=${source_mac}    server_mac=${server_mac}    protocol=UDP    source_ip=${source_ip}    server_ip=${server_ip}    source_port=${source_port}    server_port=${server_port}    zxf_ver=${1}    fl_cnt=${flowCnt}
        log    ${expectResultComm}
        ${exact_flowinfo_1}    Get From Dictionary    ${exact_flowinfo}    ${1}
        log    ${exact_flowinfo_1}
        comment    通过解析的流表信息，获取sip和key对应关心
        ${flow_sip_key}    Evaluate    list(map(lambda x:"zx_sip{}".format(x),range(${flowcnt})))
        log    ${flow_sip_key}
        ${zxflow_order}    Evaluate    list(map(lambda x:${exact_flowinfo_1}.get(x),${flow_sip_key}))
        log    ${zxflow_order}
        ${fivetuple_order}    evaluate    [y for x in ${zxflow_order} for y in ${zxflowFiveTuple} if x in y ]
        log    ${fivetuple_order}
        ${zxflowV4V6}    Set Variable If    "v4" in "${PcapTitle}"    ${4}    ${6}
        ${zx_ip_h}    Run Keyword If    "${testTitle}" ==""    Set Variable    03
        ...    ELSE IF    "Pos" in "${testTitle}"    Set Variable    01
        ...    ELSE IF    "Rev" in "${testTitle}"    Set Variable    02
        ...    ELSE    Set Variable    00
        ${expect_zxflow_pro}    Evaluate    {"zx_pro%s"%i:${fivetuple_order}\[i\]\[4\] for i in range(${flowCnt})}
        ${expect_zxflow_ip_ver}    Evaluate    {"zx_ip_ver%s"%i:${zxflowV4V6} for i in range(${flowCnt})}
        ${expect_zxflow_ip_h}    Evaluate    {"zx_ip_h%s"%i:"${zx_ip_h}" for i in range(${flowCnt})}
        ${expect_zxflow_sip}    Evaluate    {"zx_sip%s"%i:${fivetuple_order}\[i\]\[0\] for i in range(${flowCnt})}
        ${expect_zxflow_dip}    Evaluate    {"zx_dip%s"%i:${fivetuple_order}\[i\]\[2\] for i in range(${flowCnt})}
        ${expect_zxflow_sport}    Evaluate    {"zx_sport%s"%i:${fivetuple_order}\[i\]\[1\] for i in range(${flowCnt})}
        ${expect_zxflow_dport}    Evaluate    {"zx_dport%s"%i:${fivetuple_order}\[i\]\[3\] for i in range(${flowCnt})}
        ${expect_zxflow_postive_byte}    Evaluate    {"zx_postive_bytes%s"%i:${zx_postive_bytes}//${flowCnt} for i in range(${flowCnt})}
        ${expect_zxflow_reverse_byte}    Evaluate    {"zx_reverse_bytes%s"%i:${zx_reverse_bytes}//${flowCnt} for i in range(${flowCnt})}
        ${expect_zxflow_info}    Evaluate    {**${expect_zxflow_pro},**${expect_zxflow_ip_ver},**${expect_zxflow_ip_h},**${expect_zxflow_sip},**${expect_zxflow_dip},**${expect_zxflow_sport},**${expect_zxflow_dport},**${expect_zxflow_postive_byte},**${expect_zxflow_reverse_byte}}
        log    ${expect_zxflow_info}
        Run Keyword And Continue On Failure    Dictionary Should Contain Sub Dictionary    ${exact_flowinfo_1}    ${expect_zxflow_info}
        comment    校验zxflow公共部分
        Run Keyword And Continue On Failure    Dictionary Should Contain Sub Dictionary    ${exact_flowinfo_1}    ${expectResultComm}
        comment    校验zxflow信息
        Run Keyword And Continue On Failure    Dictionary Should Contain Sub Dictionary    ${exact_flowinfo_1}    ${expect_zxflow_info}
    END
    [Teardown]    sendMultiCommand    netflow disable

netflow_long_session
    [Documentation]    //超时，短包，tcpflag的fin和rst
    ...    mfpga1(1,0x2030)
    ...    mfpga1(0x5050,0x2033) ---配置超长320s
    ...    mfpga1(0,0x2032) //关闭包间隔超过15s销毁会话
    ...
    ...    netflow的srcip和报文的srcip不能相同
    ...
    ...    使用刷新老化，老化时间599s，在7min时候再次打流立马触发长会话输出；长会话是基于包触发的
    [Tags]    rcp
    [Setup]    undo acl all
    ${slot_interface}    Split String    ${inportId}[0]    /
    ${slot_id}    Get From List    ${slot_interface}    0
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    NETFLOW_LONG_SESSION
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    设置流统计输出端口
    sendMultiCommand    netflow outport ${outgroup_f_portId_1}[0],netflow enable,flow_table aging_accuracy 8M,flow_table aging_mode flush_aging
    comment    设置长会话为320s左右
    ${longtime}    Set Variable    ${320}
    ${longtimeHex}    Convert To Hex    ${${longtime}//4}
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /home/
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    echo -n "mfpga${slot_id}(0x${longtimeHex}${longtimeHex},0x2033) mfpga${slot_id}(1,0x2030) mfpga${slot_id}(0x0,0x2032) mfpga${slot_id}(0x3,0x2031)" | luacmd.lua
    sleep    1
    ${info}    SSHLibrary.Read Until    root@
    log    ${info}
    SSHLibrary.Close All Connections
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${source_mac}    read cell data by name    ${sheetName}    A${row}
        ${server_mac}    read cell data by name    ${sheetName}    B${row}
        ${source_ip}    read cell data by name    ${sheetName}    C${row}
        ${server_ip}    read cell data by name    ${sheetName}    D${row}
        ${source_port_str}    read cell data by name    ${sheetName}    E${row}
        ${server_port_str}    read cell data by name    ${sheetName}    F${row}
        ${aging_time}    read cell data by name    ${sheetName}    G${row}
        ${iniRcpFileName}    read cell data by name    ${sheetName}    H${row}
        ${testTitle}    read cell data by name    ${sheetName}    I${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    J${row}
        ${PcapTitle}    read cell data by name    ${sheetName}    K${row}
        ${zxflowFiveTupleTitle}    read cell data by name    ${sheetName}    L${row}
        ${flowCnt_str}    read cell data by name    ${sheetName}    M${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    N${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    O${row}
        ${source_port}    Convert To Integer    ${source_port_str}
        ${server_port}    Convert To Integer    ${server_port_str}
        ${flowCnt}    Convert To Integer    ${flowCnt_str}
        comment    配置对应的netflow和agingtime
        sendMultiCommand    netflow source_mac ${source_mac},netflow server_mac ${server_mac},netflow source_ip ${source_ip},netflow server_ip ${server_ip},netflow source_port ${source_port},netflow server_port ${server_port},
        sendMultiCommand    flow_manage tcp_aging_time ${aging_time},flow_manage udp_aging_time ${aging_time},flow_manage other_aging_time ${aging_time},
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword If    '${testTitle}'!=''    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword If    '${testTitle}'!=''    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        comment    生成pcap包
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${PcapTitle}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx1}    ${tx1}    tcpreplayAndTcpdump    netfow_${row}_first    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}    1    1    ${9}    src host ${source_ip}
        sleep    ${${longtime}+30}
        ${rx2}    ${tx2}    tcpreplayAndTcpdump    netfow_${row}_second    ${hitPcap}    ${startFlowSpeed}    1t    1    0    ${9}    src host ${source_ip}
        ${rx}    Set Variable    ${${rx1}+${rx2}}
        ${tx}    Evaluate    list(map(lambda x,y:int(x)+int(y),${tx1},${tx2}))
        ${zx_postive_bytes}    ${zx_postive_pkts}    ${zx_reverse_bytes}    ${zx_reverse_pkts}    get_zxflow_pkts_bytes    ${PcapTitle}    ${tx}
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${${zx_postive_pkts}+${zx_reverse_pkts}}    00
        comment    解析对应的
        ${netflowcount}    Parser Pcapfile    ${localRipePcapPath}netfow_${row}_second.pcap
        Run Keyword And Continue On Failure    Run Keyword If    ${flowCnt} != 0    Should Be Equal As Integers    ${netflowcount}    1
        ...    ELSE    Should Be Equal As Integers    ${netflowcount}    0
        Continue For Loop If    ${flowCnt} == 0
        ${exact_flowinfo}    Bj Net Flow    netflow
        log    ${exact_flowinfo}
        Run Keyword If    '${testTitle}'!=''    delete    ${ruleId}    01
        comment    生成预期flow信息
        ${pcap}    makePcap    ${0}    ${iniPacketFileName}    ${zxflowFiveTupleTitle}
        ${zxflowFiveTuple}    extract_five_tuple_from_pcap    ${localRawPcapPath}/${pcap}    1
        log    ${zxflowFiveTuple}
        ${zxflowV4V6}    Set Variable If    "v4" in "${PcapTitle}"    ${4}    ${6}
        ${zx_ip_h}    Run Keyword If    "${testTitle}" ==""    Set Variable    03
        ...    ELSE IF    "Pos" in "${testTitle}"    Set Variable    01
        ...    ELSE IF    "Rev" in "${testTitle}"    Set Variable    02
        ...    ELSE    Set Variable    00
        ${PcapTitle_list}    Split String    ${PcapTitle}    ,
        ${expectResultComm}    Create Dictionary    source_mac=${source_mac}    server_mac=${server_mac}    protocol=UDP    source_ip=${source_ip}    server_ip=${server_ip}    source_port=${source_port}    server_port=${server_port}    zxf_ver=${1}    fl_cnt=${flowCnt}
        log    ${expectResultComm}
        ${exact_flowinfo_1}    Get From Dictionary    ${exact_flowinfo}    ${1}
        log    ${exact_flowinfo_1}
        comment    通过解析的流表信息，获取sip和key对应关心
        ${flow_sip_key}    Evaluate    list(map(lambda x:"zx_sip{}".format(x),range(${flowcnt})))
        log    ${flow_sip_key}
        ${zxflow_order}    Evaluate    list(map(lambda x:${exact_flowinfo_1}.get(x),${flow_sip_key}))
        log    ${zxflow_order}
        ${fivetuple_order}    evaluate    [y for x in ${zxflow_order} for y in ${zxflowFiveTuple} if x in y ]
        log    ${fivetuple_order}
        ${zxflowV4V6}    Set Variable If    "v4" in "${PcapTitle}"    ${4}    ${6}
        ${zx_ip_h}    Run Keyword If    "${testTitle}" ==""    Set Variable    03
        ...    ELSE IF    "Pos" in "${testTitle}"    Set Variable    01
        ...    ELSE IF    "Rev" in "${testTitle}"    Set Variable    02
        ...    ELSE    Set Variable    00
        ${expect_zxflow_pro}    Evaluate    {"zx_pro%s"%i:${fivetuple_order}\[i\]\[4\] for i in range(${flowCnt})}
        ${expect_zxflow_ip_ver}    Evaluate    {"zx_ip_ver%s"%i:${zxflowV4V6} for i in range(${flowCnt})}
        ${expect_zxflow_ip_h}    Evaluate    {"zx_ip_h%s"%i:"${zx_ip_h}" for i in range(${flowCnt})}
        ${expect_zxflow_sip}    Evaluate    {"zx_sip%s"%i:${fivetuple_order}\[i\]\[0\] for i in range(${flowCnt})}
        ${expect_zxflow_dip}    Evaluate    {"zx_dip%s"%i:${fivetuple_order}\[i\]\[2\] for i in range(${flowCnt})}
        ${expect_zxflow_sport}    Evaluate    {"zx_sport%s"%i:${fivetuple_order}\[i\]\[1\] for i in range(${flowCnt})}
        ${expect_zxflow_dport}    Evaluate    {"zx_dport%s"%i:${fivetuple_order}\[i\]\[3\] for i in range(${flowCnt})}
        ${expect_zxflow_postive_byte}    Evaluate    {"zx_postive_bytes%s"%i:${zx_postive_bytes}//${flowCnt} for i in range(${flowCnt})}
        ${expect_zxflow_reverse_byte}    Evaluate    {"zx_reverse_bytes%s"%i:${zx_reverse_bytes}//${flowCnt} for i in range(${flowCnt})}
        ${expect_zxflow_info}    Evaluate    {**${expect_zxflow_pro},**${expect_zxflow_ip_ver},**${expect_zxflow_ip_h},**${expect_zxflow_sip},**${expect_zxflow_dip},**${expect_zxflow_sport},**${expect_zxflow_dport},**${expect_zxflow_postive_byte},**${expect_zxflow_reverse_byte}}
        log    ${expect_zxflow_info}
        Run Keyword And Continue On Failure    Dictionary Should Contain Sub Dictionary    ${exact_flowinfo_1}    ${expect_zxflow_info}
        comment    校验zxflow公共部分
        Run Keyword And Continue On Failure    Dictionary Should Contain Sub Dictionary    ${exact_flowinfo_1}    ${expectResultComm}
        comment    校验zxflow信息
        Run Keyword And Continue On Failure    Dictionary Should Contain Sub Dictionary    ${exact_flowinfo_1}    ${expect_zxflow_info}
    END
    [Teardown]    sendMultiCommand    netflow disable

netflow_over_time
    [Documentation]    //9s
    ...    mfpga1(0x1041,0x20fa) \ \ mfpga1(0x7ce9,0x20fb)
    ...
    ...    //超时，短包，tcpflag的fin和rst
    ...    mfpga1(1,0x2030)
    ...    //开启超时15s mfpga1(0x0f0f,0x2032)
    ...    netflow的srcip和报文的srcip不能相同
    ...    //超长设置320s mfpga1(0x5050,0x2033)
    ...
    ...    //老化时间的一半大于超时时间设置
    [Tags]    rcp    debug
    [Setup]    undo acl all
    ${slot_interface}    Split String    ${inportId}[0]    /
    ${slot_id}    Get From List    ${slot_interface}    0
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    NETFLOW_OUT_TIME
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    设置流统计输出端口
    sendMultiCommand    netflow outport ${outgroup_f_portId_1}[0],netflow enable,flow_table aging_accuracy 8M,flow_table aging_mode flush_aging
    comment    设置长会话为320s左右
    ${longtime}    Set Variable    ${320}
    ${longtimeHex}    Convert To Hex    ${${longtime}//4}
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /home/
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    echo -n "mfpga${slot_id}(0x${longtimeHex}${longtimeHex},0x2033) mfpga${slot_id}(1,0x2030) mfpga${slot_id}(0x0F0F,0x2032) mfpga${slot_id}(0x3,0x2031)" | luacmd.lua
    sleep    1
    ${info}    SSHLibrary.Read Until    root@
    log    ${info}
    SSHLibrary.Close All Connections
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${source_mac}    read cell data by name    ${sheetName}    A${row}
        ${server_mac}    read cell data by name    ${sheetName}    B${row}
        ${source_ip}    read cell data by name    ${sheetName}    C${row}
        ${server_ip}    read cell data by name    ${sheetName}    D${row}
        ${source_port_str}    read cell data by name    ${sheetName}    E${row}
        ${server_port_str}    read cell data by name    ${sheetName}    F${row}
        ${aging_time}    read cell data by name    ${sheetName}    G${row}
        ${iniRcpFileName}    read cell data by name    ${sheetName}    H${row}
        ${testTitle}    read cell data by name    ${sheetName}    I${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    J${row}
        ${PcapTitle}    read cell data by name    ${sheetName}    K${row}
        ${zxflowFiveTupleTitle}    read cell data by name    ${sheetName}    L${row}
        ${flowCnt_str}    read cell data by name    ${sheetName}    M${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    N${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    O${row}
        ${source_port}    Convert To Integer    ${source_port_str}
        ${server_port}    Convert To Integer    ${server_port_str}
        ${flowCnt}    Convert To Integer    ${flowCnt_str}
        comment    配置对应的netflow和agingtime
        sendMultiCommand    netflow source_mac ${source_mac},netflow server_mac ${server_mac},netflow source_ip ${source_ip},netflow server_ip ${server_ip},netflow source_port ${source_port},netflow server_port ${server_port},
        sendMultiCommand    flow_manage tcp_aging_time ${aging_time},flow_manage udp_aging_time ${aging_time},flow_manage other_aging_time ${aging_time},
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword If    '${testTitle}'!=''    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword If    '${testTitle}'!=''    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        comment    生成pcap包
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${PcapTitle}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx1}    ${tx1}    tcpreplayAndTcpdump    netfow_${row}_first    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}    1    1    ${9}    src host ${source_ip}
        sleep    ${${aging_time}//2}
        ${rx2}    ${tx2}    tcpreplayAndTcpdump    netfow_${row}_second    ${hitPcap}    ${startFlowSpeed}    1t    1    0    ${9}    src host ${source_ip}
        ${rx}    Set Variable    ${${rx1}+${rx2}}
        ${tx}    Evaluate    list(map(lambda x,y:int(x)+int(y),${tx1},${tx2}))
        ${zx_postive_bytes}    ${zx_postive_pkts}    ${zx_reverse_bytes}    ${zx_reverse_pkts}    get_zxflow_pkts_bytes    ${PcapTitle}    ${tx}
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${${zx_postive_pkts}+${zx_reverse_pkts}}    00
        comment    解析对应的
        ${netflowcount}    Parser Pcapfile    ${localRipePcapPath}netfow_${row}_second.pcap
        Run Keyword And Continue On Failure    Run Keyword If    ${flowCnt} != 0    Should Be Equal As Integers    ${netflowcount}    1
        ...    ELSE    Should Be Equal As Integers    ${netflowcount}    0
        Continue For Loop If    ${flowCnt} == 0
        ${exact_flowinfo}    Bj Net Flow    netflow
        log    ${exact_flowinfo}
        Run Keyword If    '${testTitle}'!=''    delete    ${ruleId}    01
        comment    生成预期flow信息
        ${pcap}    makePcap    ${0}    ${iniPacketFileName}    ${zxflowFiveTupleTitle}
        ${zxflowFiveTuple}    extract_five_tuple_from_pcap    ${localRawPcapPath}/${pcap}    1
        log    ${zxflowFiveTuple}
        ${zxflowV4V6}    Set Variable If    "v4" in "${PcapTitle}"    ${4}    ${6}
        ${zx_ip_h}    Run Keyword If    "${testTitle}" ==""    Set Variable    03
        ...    ELSE IF    "Pos" in "${testTitle}"    Set Variable    01
        ...    ELSE IF    "Rev" in "${testTitle}"    Set Variable    02
        ...    ELSE    Set Variable    00
        ${PcapTitle_list}    Split String    ${PcapTitle}    ,
        ${expectResultComm}    Create Dictionary    source_mac=${source_mac}    server_mac=${server_mac}    protocol=UDP    source_ip=${source_ip}    server_ip=${server_ip}    source_port=${source_port}    server_port=${server_port}    zxf_ver=${1}    fl_cnt=${flowCnt}
        log    ${expectResultComm}
        ${exact_flowinfo_1}    Get From Dictionary    ${exact_flowinfo}    ${1}
        log    ${exact_flowinfo_1}
        comment    通过解析的流表信息，获取sip和key对应关心
        ${flow_sip_key}    Evaluate    list(map(lambda x:"zx_sip{}".format(x),range(${flowcnt})))
        log    ${flow_sip_key}
        ${zxflow_order}    Evaluate    list(map(lambda x:${exact_flowinfo_1}.get(x),${flow_sip_key}))
        log    ${zxflow_order}
        ${fivetuple_order}    evaluate    [y for x in ${zxflow_order} for y in ${zxflowFiveTuple} if x in y ]
        log    ${fivetuple_order}
        ${zxflowV4V6}    Set Variable If    "v4" in "${PcapTitle}"    ${4}    ${6}
        ${zx_ip_h}    Run Keyword If    "${testTitle}" ==""    Set Variable    03
        ...    ELSE IF    "Pos" in "${testTitle}"    Set Variable    01
        ...    ELSE IF    "Rev" in "${testTitle}"    Set Variable    02
        ...    ELSE    Set Variable    00
        ${expect_zxflow_pro}    Evaluate    {"zx_pro%s"%i:${fivetuple_order}\[i\]\[4\] for i in range(${flowCnt})}
        ${expect_zxflow_ip_ver}    Evaluate    {"zx_ip_ver%s"%i:${zxflowV4V6} for i in range(${flowCnt})}
        ${expect_zxflow_ip_h}    Evaluate    {"zx_ip_h%s"%i:"${zx_ip_h}" for i in range(${flowCnt})}
        ${expect_zxflow_sip}    Evaluate    {"zx_sip%s"%i:${fivetuple_order}\[i\]\[0\] for i in range(${flowCnt})}
        ${expect_zxflow_dip}    Evaluate    {"zx_dip%s"%i:${fivetuple_order}\[i\]\[2\] for i in range(${flowCnt})}
        ${expect_zxflow_sport}    Evaluate    {"zx_sport%s"%i:${fivetuple_order}\[i\]\[1\] for i in range(${flowCnt})}
        ${expect_zxflow_dport}    Evaluate    {"zx_dport%s"%i:${fivetuple_order}\[i\]\[3\] for i in range(${flowCnt})}
        ${expect_zxflow_postive_byte}    Evaluate    {"zx_postive_bytes%s"%i:${zx_postive_bytes}//${flowCnt} for i in range(${flowCnt})}
        ${expect_zxflow_reverse_byte}    Evaluate    {"zx_reverse_bytes%s"%i:${zx_reverse_bytes}//${flowCnt} for i in range(${flowCnt})}
        ${expect_zxflow_info}    Evaluate    {**${expect_zxflow_pro},**${expect_zxflow_ip_ver},**${expect_zxflow_ip_h},**${expect_zxflow_sip},**${expect_zxflow_dip},**${expect_zxflow_sport},**${expect_zxflow_dport},**${expect_zxflow_postive_byte},**${expect_zxflow_reverse_byte}}
        log    ${expect_zxflow_info}
        Run Keyword And Continue On Failure    Dictionary Should Contain Sub Dictionary    ${exact_flowinfo_1}    ${expect_zxflow_info}
        comment    校验zxflow公共部分
        Run Keyword And Continue On Failure    Dictionary Should Contain Sub Dictionary    ${exact_flowinfo_1}    ${expectResultComm}
        comment    校验zxflow信息
        Run Keyword And Continue On Failure    Dictionary Should Contain Sub Dictionary    ${exact_flowinfo_1}    ${expect_zxflow_info}
    END
    [Teardown]    sendMultiCommand    netflow disable

netflow_over_bytes
    [Documentation]    //9s
    ...    mfpga1(0x1041,0x20fa) \ \ mfpga1(0x7ce9,0x20fb)
    ...
    ...    mfpga1(0x1,0x203d) ---开启时戳功能；
    ...    mfpga1(0x1,0x2030) ---长短会话，还有SYN,RST,FIN这些生效；默认是0，关闭；
    ...    mfpga1(0x1,0x203c) ---使能流表超限功能
    ...    mfpga1(0x1,0x2199) ---流表8Gddr+ip取模
    ...    mfpga1(0,0x2031) \ \ ---关闭短包
    ...    mfpga1(0,0x2032) \ \ ---关闭超时
    [Tags]    rcp
    [Setup]    undo acl all
    ${slot_interface}    Split String    ${inportId}[0]    /
    ${slot_id}    Get From List    ${slot_interface}    0
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    NETFLOW_OVER_BYTES
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}-1
    comment    设置流统计输出端口
    sendMultiCommand    netflow outport ${outgroup_f_portId_1}[0],netflow enable,flow_table aging_accuracy 8M
    comment    设置拼包为9s左右
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /home/
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    echo -n "mfpga${slot_id}(0x1041,0x20fa) mfpga${slot_id}(0x7ce9,0x20fb) mfpga${slot_id}(1,0x2030) \ mfpga${slot_id}(0x3,0x2031)" | luacmd.lua
    sleep    1
    ${info}    SSHLibrary.Read Until    root@
    log    ${info}
    SSHLibrary.Close All Connections
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${source_mac}    read cell data by name    ${sheetName}    A${row}
        ${server_mac}    read cell data by name    ${sheetName}    B${row}
        ${source_ip}    read cell data by name    ${sheetName}    C${row}
        ${server_ip}    read cell data by name    ${sheetName}    D${row}
        ${source_port_str}    read cell data by name    ${sheetName}    E${row}
        ${server_port_str}    read cell data by name    ${sheetName}    F${row}
        ${aging_time}    read cell data by name    ${sheetName}    G${row}
        ${iniRcpFileName}    read cell data by name    ${sheetName}    H${row}
        ${testTitle}    read cell data by name    ${sheetName}    I${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    J${row}
        ${PcapTitle}    read cell data by name    ${sheetName}    K${row}
        ${zxflowFiveTupleTitle}    read cell data by name    ${sheetName}    L${row}
        ${flowCnt_str}    read cell data by name    ${sheetName}    M${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    N${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    O${row}
        ${source_port}    Convert To Integer    ${source_port_str}
        ${server_port}    Convert To Integer    ${server_port_str}
        ${flowCnt}    Convert To Integer    ${flowCnt_str}
        comment    配置对应的netflow和agingtime
        sendMultiCommand    netflow source_mac ${source_mac},netflow server_mac ${server_mac},netflow source_ip ${source_ip},netflow server_ip ${server_ip},netflow source_port ${source_port},netflow server_port ${server_port},
        sendMultiCommand    flow_manage tcp_aging_time ${aging_time},flow_manage udp_aging_time ${aging_time},flow_manage other_aging_time ${aging_time},
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword If    '${testTitle}'!=''    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword If    '${testTitle}'!=''    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        comment    生成pcap包
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${PcapTitle}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    netfow_${row}    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}    1    1    ${${aging_time}+5}    src host ${source_ip}
        ${zx_postive_bytes}    ${zx_pos_pkts}    ${zx_reverse_bytes}    ${zx_rev_pkts}    get_zxflow_pkts_bytes    ${PcapTitle}    ${tx}
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${${zx_pos_pkts}+${zx_rev_pkts}}    00
        comment    解析对应的
        ${netflowcount}    Parser Pcapfile    ${localRipePcapPath}netfow_${row}.pcap
        Run Keyword And Continue On Failure    Run Keyword If    ${flowCnt} != 0    Should Be true    ${netflowcount}>=2
        ...    ELSE    Should Be Equal As Integers    ${netflowcount}    0
        Continue For Loop If    ${flowCnt} == 0
        ${exact_flowinfo}    Bj Net Flow    netflow
        log    ${exact_flowinfo}
        Run Keyword If    '${testTitle}'!=''    delete    ${ruleId}    01
        comment    生成预期flow信息
        ${pcap}    makePcap    ${0}    ${iniPacketFileName}    ${zxflowFiveTupleTitle}
        ${zxflowFiveTuple}    extract_five_tuple_from_pcap    ${localRawPcapPath}/${pcap}    0
        log    ${zxflowFiveTuple}
        ${zxflow_fivetuple}    Get From Dictionary    ${zxflowFiveTuple}    ${1}
        ${zxflowV4V6}    Set Variable If    "v4" in "${PcapTitle}"    ${4}    ${6}
        ${zx_ip_h}    Run Keyword If    "${testTitle}" ==""    Set Variable    03
        ...    ELSE IF    "Pos" in "${testTitle}"    Set Variable    01
        ...    ELSE IF    "Rev" in "${testTitle}"    Set Variable    02
        ...    ELSE    Set Variable    00
        ${expectResult}    Create Dictionary    source_mac=${source_mac}    server_mac=${server_mac}    protocol=UDP    source_ip=${source_ip}    server_ip=${server_ip}    source_port=${source_port}    server_port=${server_port}    zxf_ver=${1}    fl_cnt=${flowCnt}    zx_pro0=${zxflow_fivetuple}[4]    zx_ip_ver0=${zxflowV4V6}    zx_ip_h0=${zx_ip_h}    zx_sip0=${zxflow_fivetuple}[0]    zx_dip0=${zxflow_fivetuple}[2]
        ...    zx_sport0=${zxflow_fivetuple}[1]    zx_dport0=${zxflow_fivetuple}[3]    zx_postive_bytes0=${zx_postive_bytes}    zx_reverse_bytes0=${zx_reverse_bytes}
        log    ${expectResult}
        ${exact_flowinfo_1}    Get From Dictionary    ${exact_flowinfo}    ${1}
        ${exact_flowinfo_2}    Get From Dictionary    ${exact_flowinfo}    ${2}
        ${exact_flowinfo_3}    Run Keyword If    ${netflowcount}>2    Get From Dictionary    ${exact_flowinfo}    ${3}
        log    ${exact_flowinfo_1}
        log    ${exact_flowinfo_2}
        log    ${exact_flowinfo_3}
        ${zx_post_bytes_dict2}    Pop From Dictionary    ${exact_flowinfo_2}    zx_postive_bytes0
        ${zx_rever_bytes_dict2}    Pop From Dictionary    ${exact_flowinfo_2}    zx_reverse_bytes0
        ${zx_post_bytes_dict3}    Run Keyword If    ${netflowcount}>2    Pop From Dictionary    ${exact_flowinfo_3}    zx_postive_bytes0
        ...    ELSE    Set Variable    0
        ${zx_rever_bytes_dict3}    Run Keyword If    ${netflowcount}>2    Pop From Dictionary    ${exact_flowinfo_3}    zx_reverse_bytes0
        ...    ELSE    Set Variable    0
        ${zx_post_bytes_dict1}    Pop From Dictionary    ${exact_flowinfo_1}    zx_postive_bytes0
        ${zx_rever_bytes_dict1}    Pop From Dictionary    ${exact_flowinfo_1}    zx_reverse_bytes0
        ${zx_endtime0_dict2}    Pop From Dictionary    ${exact_flowinfo_2}    zx_endtime0
        ${zx_starttime0_dict2}    Pop From Dictionary    ${exact_flowinfo_2}    zx_starttime0
        ${zx_endtime0_dict1}    Pop From Dictionary    ${exact_flowinfo_1}    zx_endtime0
        ${zx_starttime0_dict1}    Pop From Dictionary    ${exact_flowinfo_1}    zx_starttime0
        ${zx_endtime0_dict3}    Run Keyword If    ${netflowcount}>2    Pop From Dictionary    ${exact_flowinfo_3}    zx_endtime0
        ${zx_starttime0_dict3}    Run Keyword If    ${netflowcount}>2    Pop From Dictionary    ${exact_flowinfo_3}    zx_starttime0
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${zx_endtime0_dict1}    ${zx_starttime0_dict2}
        Run Keyword And Continue On Failure    Should Not Be Equal As Strings    ${zx_starttime0_dict2}    ${zx_endtime0_dict2}
        Run Keyword And Continue On Failure    Should Not Be Equal As Strings    ${zx_starttime0_dict1}    ${zx_endtime0_dict1}
        ${new_bytes}    Create Dictionary    zx_postive_bytes0=${${zx_post_bytes_dict1}+${zx_post_bytes_dict2}+${zx_post_bytes_dict3}}    zx_reverse_bytes0=${${zx_rever_bytes_dict1}+${zx_rever_bytes_dict2}+${zx_rever_bytes_dict3}}
        Set To Dictionary    ${exact_flowinfo_1}    &{new_bytes}
        log    ${exact_flowinfo_1}
        Run Keyword And Continue On Failure    Dictionary Should Contain Sub Dictionary    ${exact_flowinfo_1}    ${exact_flowinfo_2}
        Run Keyword If    ${netflowcount}>2    Run Keyword And Continue On Failure    Dictionary Should Contain Sub Dictionary    ${exact_flowinfo_1}    ${exact_flowinfo_3}
        Run Keyword And Continue On Failure    Dictionary Should Contain Sub Dictionary    ${exact_flowinfo_1}    ${expectResult}
    END
    [Teardown]    sendMultiCommand    netflow disable

netflow_203f_0
    [Documentation]    只为测试：0x203d=0（去使能时戳，按包统计）是否正常输出zxflow，不校验内容，只校验是否正常输出
    [Tags]    rcp
    [Setup]    undo acl all
    ${slot_interface}    Split String    ${inportId}[0]    /
    ${slot_id}    Get From List    ${slot_interface}    0
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    NETFLOW_AGING
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    设置流统计输出端口
    sendMultiCommand    netflow outport ${outgroup_f_portId_1}[0],netflow enable,flow_table aging_accuracy 8M
    comment    设置拼包为9s左右
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /home/
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    echo -n "mfpga${slot_id}(0x1041,0x20fa) mfpga${slot_id}(0x7ce9,0x20fb) mfpga${slot_id}(1,0x2030) \ mfpga${slot_id}(0x3,0x2031) \ \ mfpga${slot_id}(0x0,0x203d)" | luacmd.lua
    sleep    1
    ${info}    SSHLibrary.Read Until    root@
    log    ${info}
    SSHLibrary.Close All Connections
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${source_mac}    read cell data by name    ${sheetName}    A${row}
        ${server_mac}    read cell data by name    ${sheetName}    B${row}
        ${source_ip}    read cell data by name    ${sheetName}    C${row}
        ${server_ip}    read cell data by name    ${sheetName}    D${row}
        ${source_port_str}    read cell data by name    ${sheetName}    E${row}
        ${server_port_str}    read cell data by name    ${sheetName}    F${row}
        ${aging_time}    read cell data by name    ${sheetName}    G${row}
        ${iniRcpFileName}    read cell data by name    ${sheetName}    H${row}
        ${testTitle}    read cell data by name    ${sheetName}    I${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    J${row}
        ${PcapTitle}    read cell data by name    ${sheetName}    K${row}
        ${zxflowFiveTupleTitle}    read cell data by name    ${sheetName}    L${row}
        ${flowCnt_str}    read cell data by name    ${sheetName}    M${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    N${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    O${row}
        ${source_port}    Convert To Integer    ${source_port_str}
        ${server_port}    Convert To Integer    ${server_port_str}
        ${flowCnt}    Convert To Integer    ${flowCnt_str}
        comment    配置对应的netflow和agingtime
        sendMultiCommand    netflow source_mac ${source_mac},netflow server_mac ${server_mac},netflow source_ip ${source_ip},netflow server_ip ${server_ip},netflow source_port ${source_port},netflow server_port ${server_port},
        sendMultiCommand    flow_manage tcp_aging_time ${aging_time},flow_manage udp_aging_time ${aging_time},flow_manage other_aging_time ${aging_time},
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword If    '${testTitle}'!=''    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword If    '${testTitle}'!=''    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        comment    生成pcap包
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${PcapTitle}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    netfow_${row}    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}    1    1    ${${aging_time}+5}    src host ${source_ip}
        ${zx_postive_bytes}    ${zx_pos_pkts}    ${zx_reverse_bytes}    ${zx_rev_pkts}    get_zxflow_pkts_bytes    ${PcapTitle}    ${tx}
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${${zx_pos_pkts}+${zx_rev_pkts}}    00
        comment    解析对应的
        ${netflowcount}    Parser Pcapfile    ${localRipePcapPath}netfow_${row}.pcap
        ${exact_flowinfo}    Bj Net Flow    netflow_packet
        log    ${exact_flowinfo}
        ${actual_zx_postive_bytes}    ${actual_zx_postive_pkts}    ${actual_zx_reverse_bytes}    ${actual_zx_reverse_pkts}    parser_netflow_packet    ${exact_flowinfo}
        Run Keyword And Continue On Failure    Run Keyword If    ${flowCnt} != 0    Should Be Equal As Integers    ${zx_postive_bytes}    ${actual_zx_postive_bytes}    正向报文字节数不相等
        Run Keyword And Continue On Failure    Run Keyword If    ${flowCnt} != 0    Should Be Equal As Integers    ${zx_pos_pkts}    ${actual_zx_postive_pkts}    正向报文数不相等
        Run Keyword And Continue On Failure    Run Keyword If    ${flowCnt} != 0    Should Be Equal As Integers    ${zx_reverse_bytes}    ${actual_zx_reverse_bytes}    反向报文字节数不相等
        Run Keyword And Continue On Failure    Run Keyword If    ${flowCnt} != 0    Should Be Equal As Integers    ${zx_rev_pkts}    ${actual_zx_reverse_pkts}    反向报文数不相等    #    Run Keyword And Continue On Failure    Run Keyword If    ${flowCnt} != 0    Should Be Equal As Integers    ${netflowcount}    1    # ELSE    Should Be Equal As Integers
        ...    # ${netflowcount}    0
        Continue For Loop If    ${flowCnt} == 0
        Run Keyword If    '${testTitle}'!=''    delete    ${ruleId}    01
    END
    [Teardown]    sendMultiCommand    netflow disable

netflow_203f_0_recover
    [Documentation]    恢复0x203f=1（时戳使能）
    [Tags]    rcp
    [Setup]    undo acl all
    ${slot_interface}    Split String    ${inportId}[0]    /
    ${slot_id}    Get From List    ${slot_interface}    0
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    NETFLOW_AGING
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    设置流统计输出端口
    sendMultiCommand    netflow outport ${outgroup_f_portId_1}[0],netflow enable,flow_table aging_accuracy 8M
    comment    设置拼包为9s左右
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /home/
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    echo -n " mfpga${slot_id}(0x1,0x203d)" | luacmd.lua
    sleep    1
    ${info}    SSHLibrary.Read Until    root@
    log    ${info}
    SSHLibrary.Close All Connections
    [Teardown]    sendMultiCommand    netflow disable

rcp_query
    [Documentation]    根据预期输出进行设置打流次数
    ...    根据是否限量进行规则是否变成drop判断
    ...    根据预期时长是否为0判定打流时间
    ...
    ...    Ps：所有测试行，必须指定预期输出总量或者时间,不能2者同时指定，另外当为时间，就应该是drop
    ...
    ...
    ...    主题思想：
    ...    1.预期输出和预期时间不会同时存在
    ...    2.当时预期时间，则只打流一次，校验时间是否符合预期，规则是否变drop
    ...    3.当预期输出，打流2次，第1次打流全部正常输出，第2次进行阻断
    ...    4.当是阻断，打流速率很慢，非阻断打流速度很快
    [Tags]    rcp
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    QUERY
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    按照excel中的行为单位进行循环测试
    #    ${${countRow}-1}
    ${appid_list}    Create List
    ${id_out}    Create Dictionary
    ${ingroup_member}    create list    @{inportId}
    ${ingroup_member_num}    Get Length    ${ingroup_member}
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    H${row}
        ${hitPcapTitle}    read cell data by name    ${sheetName}    I${row}
        ${backPcapTitle}    read cell data by name    ${sheetName}    J${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    K${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    L${row}
        ${drop_or_no}    read cell data by name    ${sheetName}    M${row}
        comment    对对应的ini配置文件的限量信息进行设置
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    20
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        ${startTimeSys_fin}    Set Variable If    ${startEndTimeGap} == 0    ${EMPTY}    ${startTimeSys}
        ${endTimeSys_fin}    Set Variable If    ${startEndTimeGap} == 0    ${EMPTY}    ${endTimeSys}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys_fin}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys_fin}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024*${ingroup_member_num}}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024*${ingroup_member_num}}
        comment    生成pcap包
        ${backPcap}    makePcap    ${0}    ${iniPacketFileName}    ${backPcapTitle}
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${hitPcapTitle}
        log    ${backPcap}
        log    ${hitPcap}
        ${packet_size_list}    getConfigOptionValue    ${iniPacketFileName}    ${hitPcapTitle}    pkt_len
        ${packet_size}    Evaluate    math.floor(sum(${packet_size_list})/len(${packet_size_list}))    math
        ${packet_count_list}    getConfigOptionValue    ${iniPacketFileName}    ${hitPcapTitle}    pkt_count
        ${packet_count}    Evaluate    sum(${packet_count_list})
        ${time1}    Get Time    epoch
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    根据预期输出总量，计算需要打流次数
        ${times}    evaluate    math.ceil(${expectOutTotal}*1024*1024/((${packet_size}+4)*${packet_count}))    math
        ${rx}    ${tx}    Run Keyword If    ${times} == 0    tcpreplayAndTcpdump    interface_add_${row}_number_1_hit    ${hitPcap}    0.1    ${${expectOutTime}+20}
        ...    ELSE    tcpreplayAndTcpdump    interface_add_${row}_number_1_hit    ${hitPcap}    0    ${${times}-1}t
        sleep    10
        comment    第一次打流进行校验
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inPkt}    ${outPkt}
        Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inByte}    ${outByte}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should \ Be Equal As Integers    ${hitCount}    ${outByte}
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-48:-32]    #SNInumber
        Run Keyword And Continue On Failure    Should Be True    ${result}==0
        ${result}    Hex To Int    ${exactRespond}[-32:-16]    #https流量
        Run Keyword And Continue On Failure    Should Be True    ${result}==0
        #    Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-16:]    #nohttps
        Run Keyword And Continue On Failure    Should Be True    ${result}==0
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all | include "acl grouped_rule"
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Run Keyword If    ${times} == 0    Run Keyword And Continue On Failure    Should Contain    ${info}    action drop    非https的阈值未生效
        ${exactTime}    ${exactNum}    ${firstPacketUnixTime}    Run Keyword If    ${times} == 0    checkNumOrTimeResult    interface_add_${row}_number_1_hit.pcap    0    0    1    2
        ${result}    Run Keyword If    ${times} == 0    Evaluate    abs(${exactTime}-${expectOutTime})
        Run Keyword If    ${times} == 0    Should Be True    0<=${result}<3
        Continue For Loop If    ${times} == 0
        comment    第2次打流，速率要慢
        ${rx1}    ${tx1}    tcpreplayAndTcpdump    interface_add_${row}_number_2_hit    ${hitPcap}    0.1    1t
        comment    内容校验
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx1}    ${0}    业务流仪表的rx等于0
        ${inPkt1}    ${inByte1}    ${outPkt1}    ${outByte1}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx1}[0]    ${rx1}
        Run Keyword If    ${drop_or_no}== 0    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inPkt1}    ${outPkt1}
        ...    ELSE    Run Keyword And Continue On Failure    should be true    ${inPkt1}>=${outPkt1}    阻断打流，输入报个数小于输出报个数
        Run Keyword If    ${drop_or_no}== 0    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inByte1}    ${outByte1}
        ...    ELSE    Run Keyword And Continue On Failure    should be true    ${inByte1}>=${outByte1}    阻断打流，输入字节小于输出输出字节
        ${hitCount1}    getAclHitstatistics    ${ruleId}
        Run Keyword If    ${drop_or_no}== 0    Run Keyword And Continue On Failure    Should \ Be Equal As Integers    ${hitCount1}    ${outByte1}    #    # ELSE    Run Keyword And Continue On Failure    should be true    ${hitCount1}>=${outByte1}    阻断打流，命中字节数小于输出
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword If    ${drop_or_no}== 1    Run Keyword And Continue On Failure    Should Be True    ${${outByte}+${outByte1}-${result}}<=${outByte1}
        ...    ELSE    Run Keyword And Continue On Failure    Should Be True    ${result}==${${hitCount1}+${hitCount}}
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword If    ${drop_or_no}== 1    Run Keyword And Continue On Failure    Should Be True    ${${outByte}+${outByte1}-${result}}<=${outByte1}
        ...    ELSE    Run Keyword And Continue On Failure    Should Be True    ${result}==${${hitCount1}+${hitCount}}
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-48:-32]    #SNInumber
        Run Keyword And Continue On Failure    Should Be True    ${result}==0
        ${result}    Hex To Int    ${exactRespond}[-32:-16]    #https流量
        Run Keyword And Continue On Failure    Should Be True    ${result}==0    #    Run Keyword If    ${drop_or_no}== 1    Run Keyword And Continue On Failure    Should Be True    ${${outByte}+${outByte1}-${result}}<=${outByte1}    # ELSE    Run Keyword And Continue On Failure    Should Be True    ${result}==${${hitCount1}+${hitCount}}
        ${result}    Hex To Int    ${exactRespond}[-16:]    #nohttps
        Run Keyword And Continue On Failure    Should Be True    ${result}==0
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all | include "acl grouped_rule"
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Run Keyword If    ${drop_or_no}== 1    Run Keyword And Continue On Failure    Should Contain    ${info}    action drop
        ...    ELSE    Run Keyword And Continue On Failure    Should \ not Contain    ${info}    action drop
        undo acl all
    END

rcp_add_sni_number
    [Documentation]    4: 'sginput.qq.com'
    ...    6: 'n0.gstatic.com'
    ...    8: 'get.sogou.com'
    ...    12: 'adservices.com'
    ...    17: content-autofill.googleapis.com //超过170，176B
    ...    19: 'ww.youtube.com'
    ...    21: 'lay.google.com'
    ...    24: \ googleads.g.doubleclick.net //超过170，180B
    ...    26: \ static.doubleclinck.net
    ...    32: 'nts.google.com'
    ...
    ...    字节数：
    ...    4: 243
    ...    6: 1794
    ...    8: 238
    ...    9: 238
    ...    10: 451
    ...    12: 1792
    ...    17:1831
    ...    19: 1847
    ...    24: 1827
    ...    26: 1854
    ...    21: 1879
    ...    32: 1787
    ...    =15781
    ...
    ...    0829：新增通过sni-acl规则进行对应的测试
    [Tags]    A
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    ADD_SNI
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    按照excel中的行为单位进行循环测试
    #    ${${countRow}-1}
    ${sni_filename}    create list
    FOR    ${row}    IN RANGE    2    4
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${serviceType}    read cell data by name    ${sheetName}    C${row}
        ${totalLimit}    read cell data by name    ${sheetName}    D${row}
        ${timeLimit}    read cell data by name    ${sheetName}    E${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    G${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    H${row}
        ${expectSniNumber}    read cell data by name    ${sheetName}    I${row}
        ${expectHttps}    read cell data by name    ${sheetName}    J${row}
        ${expectNoHttps}    read cell data by name    ${sheetName}    K${row}
        ${pcap}    read cell data by name    ${sheetName}    L${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    M${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    N${row}
        comment    根据serviceType为0进行sni规则
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    serviceType    ${testTitle}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    sniNumber    ${totalLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    httpsPercent    ${timeLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    notHttps    ${startEndTimeGap}
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword If    ${serviceType} == 0    sniSet    ${iniRcpFileName}    ${testTitle}
        Run Keyword If    ${serviceType} == 0    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    SNI下发失败
        Run Keyword If    ${serviceType} == 0    Append To List    ${sni_filename}    ${iniRcpFileName}
        New Connection Custom
        telnet.write    show sni_limit
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Continue For Loop If    ${serviceType} == 0
        comment    根据serviceType非0进行acl规则
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    80
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    servicetype    ${serviceType}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_sninumber    ${expectSniNumber}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_httpspercent    ${expectHttps}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_nothttps    ${expectNoHttps}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${pcap}    Set Variable    https-dns.alidns.com-64_sni_10.pcap
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_hit    ${pcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-48:-32]    #SNInumber
        Run Keyword And Continue On Failure    Should Be True    ${result}==10
        ${result}    Hex To Int    ${exactRespond}[-32:-16]    #https流量
        Run Keyword And Continue On Failure    Should Be True    ${result}==${expectHttps}
        ${result}    Hex To Int    ${exactRespond}[-16:]    #nohttps
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
    END

rcp_add_sni_https_l2l3
    [Documentation]    通过发送l2,l3层的sni流量：2个包总共3612B
    ...    再次发送 大于l4层的nohttps:5419字节（前2个包加起来3592未满足50%，所以需要第3个包，总共加起来5419B)
    ...    所以预期结果是：SNI=2,SNI流量：3612B，noSNI=5419B；总共输出5个包(由于在进行drop可能还是导致多1个包输出
    [Tags]    A
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    ADD_SNI
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    按照excel中的行为单位进行循环测试
    #    ${${countRow}-1}
    ${sni_filename}    create list
    FOR    ${row}    IN RANGE    4    6
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${serviceType}    read cell data by name    ${sheetName}    C${row}
        ${totalLimit}    read cell data by name    ${sheetName}    D${row}
        ${timeLimit}    read cell data by name    ${sheetName}    E${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    G${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    H${row}
        ${expectSniNumber}    read cell data by name    ${sheetName}    I${row}
        ${expectHttps}    read cell data by name    ${sheetName}    J${row}
        ${expectNoHttps}    read cell data by name    ${sheetName}    K${row}
        ${pcap}    read cell data by name    ${sheetName}    L${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    M${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    N${row}
        comment    根据serviceType为0进行sni规则
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    serviceType    ${testTitle}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    sniNumber    ${totalLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    httpsPercent    ${timeLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    notHttps    ${startEndTimeGap}
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword If    ${serviceType} == 0    sniSet    ${iniRcpFileName}    ${testTitle}
        Run Keyword If    ${serviceType} == 0    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    SNI下发失败
        Run Keyword If    ${serviceType} == 0    Append To List    ${sni_filename}    ${iniRcpFileName}
        New Connection Custom
        telnet.write    show sni_limit
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Continue For Loop If    ${serviceType} == 0
        comment    根据serviceType非0进行acl规则
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    80
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    servicetype    ${serviceType}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_sninumber    ${expectSniNumber}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_httpspercent    ${expectHttps}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_nothttps    ${expectNoHttps}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_hit    ${pcap}    ${startFlowSpeed}    ${startFlowTime}    1
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${${tx}[0]+${tx}[2]+${tx}[4]+${tx}[6]}    ${rx}
        Run Keyword And Continue On Failure    Should Be true    ${rx}>=${5} and ${rx}<=${6}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-48:-32]    #SNInumber
        Run Keyword And Continue On Failure    Should Be True    ${result}==${expectSniNumber}
        ${result}    Hex To Int    ${exactRespond}[-32:-16]    #https流量
        Run Keyword And Continue On Failure    Should Be True    ${result}==${expectHttps}
        ${result}    Hex To Int    ${exactRespond}[-16:]    #nohttps
        Run Keyword And Continue On Failure    Should Be True    ${result}==${expectNoHttps}
    END

rcp_add_sni_https_l3l4
    [Documentation]    通过发送l3,l4层的sni流量：2个包总共1794+1794=3588B
    ...    再次发送 大于l4层的nohttps:5419字节（前2个包加起来3602满足50%)
    ...    所以预期结果是：SNI=2,SNI流量：3588B，noSNI=3602B,总共输出应该是4个包(由于软件变成drop需要时间会导致多输出1个
    ...
    ...    //0813 当前fpga不支持l4的，导致输出的2个包，sni=1,sni流量：1794，noSni=1794
    [Tags]    A
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    ADD_SNI
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    按照excel中的行为单位进行循环测试
    #    ${${countRow}-1}
    ${sni_filename}    create list
    FOR    ${row}    IN RANGE    6    8
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${serviceType}    read cell data by name    ${sheetName}    C${row}
        ${totalLimit}    read cell data by name    ${sheetName}    D${row}
        ${timeLimit}    read cell data by name    ${sheetName}    E${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    G${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    H${row}
        ${expectSniNumber}    read cell data by name    ${sheetName}    I${row}
        ${expectHttps}    read cell data by name    ${sheetName}    J${row}
        ${expectNoHttps}    read cell data by name    ${sheetName}    K${row}
        ${pcap}    read cell data by name    ${sheetName}    L${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    M${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    N${row}
        comment    根据serviceType为0进行sni规则
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    serviceType    ${testTitle}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    sniNumber    ${totalLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    httpsPercent    ${timeLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    notHttps    ${startEndTimeGap}
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword If    ${serviceType} == 0    sniSet    ${iniRcpFileName}    ${testTitle}
        Run Keyword If    ${serviceType} == 0    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    SNI下发失败
        Run Keyword If    ${serviceType} == 0    Append To List    ${sni_filename}    ${iniRcpFileName}
        New Connection Custom
        telnet.write    show sni_limit
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Continue For Loop If    ${serviceType} == 0
        comment    根据serviceType非0进行acl规则
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    80
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    servicetype    ${serviceType}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_sninumber    ${expectSniNumber}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_httpspercent    ${expectHttps}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_nothttps    ${expectNoHttps}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_hit    ${pcap}    ${startFlowSpeed}    ${startFlowTime}    1
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${${tx}[0]+${tx}[2]+${tx}[4]+${tx}[6]}    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${4}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-48:-32]    #SNInumber
        Run Keyword And Continue On Failure    Should Be True    ${result}==${expectSniNumber}
        ${result}    Hex To Int    ${exactRespond}[-32:-16]    #https流量
        Run Keyword And Continue On Failure    Should Be True    ${result}==${expectHttps}
        ${result}    Hex To Int    ${exactRespond}[-16:]    #nohttps
        Run Keyword And Continue On Failure    Should Be True    ${result}==${expectNoHttps}
    END

rcp_add_nosni_threshold
    [Documentation]    1、通过发送l2,l3层的sni流量：2个包总共3612B
    ...    2、再次发送 大于l4层的nohttps:3602字节（前2个包加起来3592满足45%)，总长度5419B
    ...    3、再次打流l1层SNI流量：11个包总共2810B
    ...    ..要是未加入阈值（当前设置阈值为1M)，第2次打流就应该阻断，只输出5个包，所以我们这里需要判断：规则是否drop，输出是否大于11+5=16
    ...    4.打流87，使得还差6568B达到阈值1M
    ...    5，再次打1，2、3的流触发阻断
    ...
    ...    所以，最后SNI数量=13，SNI流量=568748 noSNI=480474
    [Tags]    A
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    ADD_SNI
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    按照excel中的行为单位进行循环测试
    #    ${${countRow}-1}
    ${sni_filename}    create list
    FOR    ${row}    IN RANGE    8    10
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${serviceType}    read cell data by name    ${sheetName}    C${row}
        ${totalLimit}    read cell data by name    ${sheetName}    D${row}
        ${timeLimit}    read cell data by name    ${sheetName}    E${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    G${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    H${row}
        ${expectSniNumber}    read cell data by name    ${sheetName}    I${row}
        ${expectHttps}    read cell data by name    ${sheetName}    J${row}
        ${expectNoHttps}    read cell data by name    ${sheetName}    K${row}
        ${pcap}    read cell data by name    ${sheetName}    L${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    M${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    N${row}
        comment    根据serviceType为0进行sni规则
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    serviceType    ${testTitle}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    sniNumber    ${totalLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    httpsPercent    ${timeLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    notHttps    ${startEndTimeGap}
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword If    ${serviceType} == 0    sniSet    ${iniRcpFileName}    ${testTitle}
        Run Keyword If    ${serviceType} == 0    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    SNI下发失败
        Run Keyword If    ${serviceType} == 0    Append To List    ${sni_filename}    ${iniRcpFileName}
        New Connection Custom
        telnet.write    show sni_limit
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Continue For Loop If    ${serviceType} == 0
        comment    根据serviceType非0进行acl规则
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    80
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    servicetype    ${serviceType}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_sninumber    ${expectSniNumber}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_httpspercent    ${expectHttps}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_nothttps    ${expectNoHttps}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打流一次，要是没有阈值，正常应该是会字节触发阻断
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_hit    ${pcap}    ${startFlowSpeed}    ${startFlowTime}    1
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${16}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        New Connection Custom
        telnet .write    show acl all | include "acl grouped_rule"
        ${log}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    Should Not Contain    ${log}    action drop    非https的阈值未生效
        comment    再次打流90679次，一次是11841B；打完之后，总流量是1,073,730,039B，离1024M，还差11785B
        ${rx1}    ${tx1}    tcpreplayAndTcpdump    interface_add_${row}_90679times_hit    ${pcap}    0    90679t    0    0
        Run Keyword And Continue On Failure    Should \ Be Equal As Integers    ${rx1}    ${1450864}    打流90679次，未完全输出
        New Connection Custom
        telnet .write    show acl all | include "acl grouped_rule"
        ${log}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    Should Contain    ${log}    action drop    非https的阈值未生效
        #    comment    再打一次，会触发阻断(sni=6422,nosin=5419,输出16个包)
        #    ${rx2}    ${tx2}    tcpreplayAndTcpdump    interface_add_${row}_drop_hit    ${pcap}    ${startFlowSpeed}    ${startFlowTime}    1    0
        #    New Connection Custom
        #    telnet .write    show acl all | include "acl grouped_rule"
        #    ${log}    telnet.read until    ${userName1}(config)#
        #    Run Keyword And Continue On Failure    Should Contain    ${log}    action drop    非https的阈值未生效
        #    Run Keyword And Continue On Failure    Should \ Be Equal As Integers    ${rx2}    ${1}    打流第90681次，未阻断
        #    ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${${tx}[0]+${tx}[2]+${tx}[4]+${tx}[6]+${tx2}[0]+${tx2}[2]+${tx2}[4]+${tx2}[6]+${tx1}[0]}    ${${rx}+${rx1}+${rx2}}
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-48:-32]    #SNInumber
        Run Keyword And Continue On Failure    Should Be True    ${result}==${expectSniNumber}
        ${result}    Hex To Int    ${exactRespond}[-32:-16]    #https流量
        Run Keyword And Continue On Failure    Should Be True    ${result}==${expectHttps}
        ${result}    Hex To Int    ${exactRespond}[-16:]    #nohttps
        Run Keyword And Continue On Failure    Should Be True    ${result}==${expectNoHttps}
    END

rcp_add_sni_special
    [Documentation]    特殊操作（testtile为0代表不下发任何规则，只打流;servicetype=0 and 0 in testtile只删除规则）
    ...    0.下发一条业务号为0，设备应该返回07错误码（消息校验错误）//10
    ...    1.配置一条最大255的值SNI值//11
    ...    2.下发规则进行该SNI绑定//12
    ...    3.打流不达到阻断效果//12
    ...    4.重新下发该SNI规则（相当于修改）//13
    ...    5.打流能达到步骤2的阻断值（但依然不进行阻断）//14
    ...    6.此时打流满足步骤4的阻断值//15
    ...    7.通过sni全0删除SNI规则，通过rcp删除该规则//16
    ...    8.删除设备上的规则//17 \ \ \ 9.下发步骤2的规则，//18
    ...    10.打流超过步骤4的阻断（判断SNI删除成功)，以及规则对应的sni不存在不限量//18
    ...    https_servername_10.pcap中的第8个pcap无法识别的（超过170B)
    [Tags]    A
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    ADD_SNI
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    按照excel中的行为单位进行循环测试
    #    ${${countRow}-1}
    ${sni_filename}    create list
    FOR    ${row}    IN RANGE    10    19
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitlezero}    read cell data by name    ${sheetName}    B${row}
        ${serviceType}    read cell data by name    ${sheetName}    C${row}
        ${totalLimit}    read cell data by name    ${sheetName}    D${row}
        ${timeLimit}    read cell data by name    ${sheetName}    E${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    G${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    H${row}
        ${expectSniNumber}    read cell data by name    ${sheetName}    I${row}
        ${expectHttps}    read cell data by name    ${sheetName}    J${row}
        ${expectNoHttps}    read cell data by name    ${sheetName}    K${row}
        ${pcap}    read cell data by name    ${sheetName}    L${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    M${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    N${row}
        ${dropOrno}    read cell data by name    ${sheetName}    O${row}    #1代表阻断
        ${testTitle}    Run Keyword If    "0" in "${testTitlezero}"    Set Variable    ${testTitlezero}[:-1]
        ...    ELSE    Set Variable    ${testTitlezero}
        Run Keyword If    "${serviceType}" == "0" and "0" in "${testTitlezero}"    undo acl all
        Continue For Loop If    "${serviceType}" == "0" and "0" in "${testTitlezero}"
        comment    根据serviceType为0进行sni规则
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    serviceType    ${testTitle}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    sniNumber    ${totalLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    httpsPercent    ${timeLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    notHttps    ${startEndTimeGap}
        ${expectCode}    Run Keyword If    "0" in "${testTitlezero}"    Set Variable    07
        ...    ELSE    Set Variable    01
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword If    ${serviceType} == 0    sniSet    ${iniRcpFileName}    ${testTitle}    ${expectCode}
        Run Keyword If    ${serviceType} == 0    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    SNI下发失败
        Run Keyword If    ${serviceType} == 0    Append To List    ${sni_filename}    ${iniRcpFileName}
        New Connection Custom
        telnet.write    show sni_limit
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Continue For Loop If    ${serviceType} == 0
        comment    根据serviceType非0进行acl规则
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    80
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    servicetype    ${serviceType}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword If    "0" not in "${testTitlezero}"    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        ...    ELSE    Set Variable    0    0    0    1
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        Run Keyword If    "0" not in "${testTitlezero}"    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_sninumber    ${expectSniNumber}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_httpspercent    ${expectHttps}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_nothttps    ${expectNoHttps}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打流一次，要是没有阈值，正常应该是会字节触发阻断
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_hit    ${pcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should not Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        New Connection Custom
        telnet .write    show acl all | include "acl grouped_rule"
        ${log}    telnet.read until    ${userName1}(config)#
        log    ${log}
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Run Keyword If    ${dropOrno} == 0    Should Be True    ${inPkt}==${outPkt}
        Run Keyword And Continue On Failure    Run Keyword If    ${dropOrno} == 1    Should Be True    ${inPkt}>${outPkt}
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0    放行总量不符合预期
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0    月内放行量不符合预期
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0    放行时间等于0
        ${result}    Hex To Int    ${exactRespond}[-48:-32]    #SNInumber
        Run Keyword And Continue On Failure    Should Be True    ${result}==${expectSniNumber}    SNInumber不符合预期
        ${result}    Hex To Int    ${exactRespond}[-32:-16]    #https流量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0    https流量等于0
        ${result}    Hex To Int    ${exactRespond}[-16:]    #nohttps
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0    非https流量等于0
    END

clientHello_mirror
    [Documentation]    1、业务端口和clienthello镜像输出端口不能复用
    ...    2、通过端口设置udp封装的mac和sip,dip,dp；其中sp是通过算法自动生成
    ...    interface eth ${outgroup_f_portId_1}[0] vxlan_smac
    ...    interface eth ${outgroup_f_portId_1}[0] vxlan_dmac
    ...    interface eth ${outgroup_f_portId_1}[0] vxlan_sip
    ...    interface eth ${outgroup_f_portId_1}[0] sni_mirror_dip
    ...    interface eth ${outgroup_f_portId_1}[0] sni_mirror_dport
    ...    sport是通过某种算法，输出的值
    ...    3、42字节后的内容即为client hello报文
    ...    4、自动化校验2部分
    ...    a.smac，dmac，sip，dip,dport，udp
    ...    b.clienthello和原始报文一样
    [Tags]    A
    ${mirro_outgroup_id}    Set Variable    10
    comment    由于linkmap和clienthello镜像输出端口不能复用，所有需要修改linkmap
    Remove Values From List    ${outgroup_f_portId_2}    ${outgroup_f_portId_1}[0]
    sendMultiCommand    linkmap rx ${inportId}[0] tx ${outgroup_f_portId_2}[0]
    comment    设置镜像输出的端口组
    initConfiguration.addGroup    outgroup_f    ${outgroup_f_portId_1}    ${mirro_outgroup_id}
    comment    开启client镜像输出
    sendMultiCommand    sni_mirror enable true outgroup_f ${mirro_outgroup_id}
    ${slot_interface}    Split String    ${inportId}[0]    /
    ${slot_id}    Get From List    ${slot_interface}    0
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    CLIENT_HELLO_MIRROR
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    SSHLibrary.Close All Connections
    FOR    ${row}    IN RANGE    2    6
        comment    读取excel内容
        ${vxlan_smac}    read cell data by name    ${sheetName}    A${row}
        ${vxlan_dmac}    read cell data by name    ${sheetName}    B${row}
        ${vxlan_sip}    read cell data by name    ${sheetName}    C${row}
        ${sni_mirror_dip}    read cell data by name    ${sheetName}    D${row}
        ${sni_mirror_dport_str}    read cell data by name    ${sheetName}    E${row}
        ${backpcap}    read cell data by name    ${sheetName}    F${row}
        ${outpcap}    read cell data by name    ${sheetName}    G${row}
        ${sni_mirror_dport}    Convert To Integer    ${sni_mirror_dport_str}
        comment    配置封装的mac以及sip,dip,dport信息
        sendMultiCommand    interface eth ${outgroup_f_portId_1}[0] vxlan_smac ${vxlan_smac},interface eth ${outgroup_f_portId_1}[0] vxlan_dmac ${vxlan_dmac},interface eth ${outgroup_f_portId_1}[0] vxlan_sip ${vxlan_sip},interface eth ${outgroup_f_portId_1}[0] sni_mirror_dip ${sni_mirror_dip},interface eth ${outgroup_f_portId_1}[0] sni_mirror_dport ${sni_mirror_dport}
        comment    打背景流,不应该有任何输出
        ${rx}    ${tx}    tcpreplayAndTcpdump    clientHelloMirror_${row}_back    ${backpcap}    0    0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${0}    ${outPkt}    背景流，设备的输出不为0
        comment    打输出流，校验封装的镜像报文是否符合预期
        ${rx}    ${tx}    tcpreplayAndTcpdump    clientHelloMirror_${row}_output    ${outpcap}    0    0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inPkt}    ${outPkt}    设备的输出${outPkt}!=设备的输入${inPkt}
        comment    仪表和设备的计数校验
        ${pktCount}    parser_pcapfile    ${localRipePcapPath}clientHelloMirror_${row}_output.pcap
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${pktCount}    ${outPkt}    设备的输出${outPkt}!=仪表的输入${pktCount}
        Run Keyword And Continue On Failure    Should not Be Equal As Integers    ${pktCount}    ${0}    仪表的输入${pktCount} ==0
        comment    7元组信息校验smac,dmac,sip,sp,dip,dp,p
        ${pktindex_seven_tuple}    extract_five_tuple_from_pcap    ${localRipePcapPath}clientHelloMirror_${row}_output.pcap    list_dict=1    have_mac=1
        log    ${pktindex_seven_tuple}
        #    ${expect_six_tuple}    create list    ${vxlan_smac}    ${vxlan_dmac}    ${vxlan_sip}    ${pktindex_seven_tuple}[${1}][3]    ${sni_mirror_dip}    ${sni_mirror_dport}    UDP
        #    ${result}    Evaluate    all([value \ == ${expect_six_tuple} for value in ${pktindex_seven_tuple}.values()])
        ${expect_six_tuple}    Evaluate    [["${vxlan_smac}","${vxlan_dmac}","${vxlan_sip}",value[3],"${sni_mirror_dip}",${sni_mirror_dport},'UDP'] for value in ${pktindex_seven_tuple}]
        log    ${expect_six_tuple}
        Run Keyword And Continue On Failure    Should Be True    ${expect_six_tuple} == ${pktindex_seven_tuple}
        comment    通过hash值对client hello进行校验
        change    ${localRipePcapPath}clientHelloMirror_${row}_output.pcap    ${0}    ${42}    ${0}    mode=inc    #生成新的pcap，在原有名称基础上最前面增加new_
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}    ${outpcap}
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    new_clientHelloMirror_${row}_output.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Should Be True    ${hashResult}
    END
    [Teardown]    sendMultiCommand    linkmap rx ${inportId}[0] tx ${outgroup_f_portId_1}[0],undo outgroup_f \ ${mirro_outgroup_id},sni_mirror enable false

clientHello_mirror_fenpian
    [Documentation]    增加分片报文，镜像输出第2片
    [Tags]    A
    ${mirro_outgroup_id}    Set Variable    10
    comment    由于linkmap和clienthello镜像输出端口不能复用，所有需要修改linkmap
    Remove Values From List    ${outgroup_f_portId_2}    ${outgroup_f_portId_1}[0]
    sendMultiCommand    linkmap rx ${inportId}[0] tx ${outgroup_f_portId_2}[0]
    comment    设置镜像输出的端口组
    initConfiguration.addGroup    outgroup_f    ${outgroup_f_portId_1}    ${mirro_outgroup_id}
    comment    开启client镜像输出
    sendMultiCommand    sni_mirror enable true outgroup_f ${mirro_outgroup_id}
    ${slot_interface}    Split String    ${inportId}[0]    /
    ${slot_id}    Get From List    ${slot_interface}    0
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    CLIENT_HELLO_MIRROR
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    SSHLibrary.Close All Connections
    FOR    ${row}    IN RANGE    6    7
        comment    读取excel内容
        ${vxlan_smac}    read cell data by name    ${sheetName}    A${row}
        ${vxlan_dmac}    read cell data by name    ${sheetName}    B${row}
        ${vxlan_sip}    read cell data by name    ${sheetName}    C${row}
        ${sni_mirror_dip}    read cell data by name    ${sheetName}    D${row}
        ${sni_mirror_dport_str}    read cell data by name    ${sheetName}    E${row}
        ${backpcap}    read cell data by name    ${sheetName}    F${row}
        ${outpcap}    read cell data by name    ${sheetName}    G${row}
        ${outpcap_result_pcap}    read cell data by name    ${sheetName}    H${row}
        ${sni_mirror_dport}    Convert To Integer    ${sni_mirror_dport_str}
        comment    配置封装的mac以及sip,dip,dport信息
        sendMultiCommand    interface eth ${outgroup_f_portId_1}[0] vxlan_smac ${vxlan_smac},interface eth ${outgroup_f_portId_1}[0] vxlan_dmac ${vxlan_dmac},interface eth ${outgroup_f_portId_1}[0] vxlan_sip ${vxlan_sip},interface eth ${outgroup_f_portId_1}[0] sni_mirror_dip ${sni_mirror_dip},interface eth ${outgroup_f_portId_1}[0] sni_mirror_dport ${sni_mirror_dport}
        comment    打背景流,不应该有任何输出
        ${rx}    ${tx}    tcpreplayAndTcpdump    clientHelloMirror_${row}_back    ${backpcap}    0    0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${0}    ${outPkt}    背景流，设备的输出不为0
        comment    打输出流，校验封装的镜像报文是否符合预期
        ${rx}    ${tx}    tcpreplayAndTcpdump    clientHelloMirror_${row}_output    ${outpcap}    0    0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${outByte}    442
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${outPkt}    1
        comment    仪表和设备的计数校验
        ${pktCount}    parser_pcapfile    ${localRipePcapPath}clientHelloMirror_${row}_output.pcap
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${pktCount}    ${outPkt}    设备的输出${outPkt}!=仪表的输入${pktCount}
        Run Keyword And Continue On Failure    Should not Be Equal As Integers    ${pktCount}    ${0}    仪表的输入${pktCount} ==0
        comment    7元组信息校验smac,dmac,sip,sp,dip,dp,p
        ${pktindex_seven_tuple}    extract_five_tuple_from_pcap    ${localRipePcapPath}clientHelloMirror_${row}_output.pcap    list_dict=1    have_mac=1
        log    ${pktindex_seven_tuple}
        #    ${expect_six_tuple}    create list    ${vxlan_smac}    ${vxlan_dmac}    ${vxlan_sip}    ${pktindex_seven_tuple}[${1}][3]    ${sni_mirror_dip}    ${sni_mirror_dport}    UDP
        #    ${result}    Evaluate    all([value \ == ${expect_six_tuple} for value in ${pktindex_seven_tuple}.values()])
        ${expect_six_tuple}    Evaluate    [["${vxlan_smac}","${vxlan_dmac}","${vxlan_sip}",value[3],"${sni_mirror_dip}",${sni_mirror_dport},'UDP'] for value in ${pktindex_seven_tuple}]
        log    ${expect_six_tuple}
        Run Keyword And Continue On Failure    Should Be True    ${expect_six_tuple} == ${pktindex_seven_tuple}
        comment    通过hash值对client hello进行校验
        change    ${localRipePcapPath}clientHelloMirror_${row}_output.pcap    ${0}    ${42}    ${0}    mode=inc    #生成新的pcap，在原有名称基础上最前面增加new_
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}    ${outpcap_result_pcap}
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    new_clientHelloMirror_${row}_output.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Should Be True    ${hashResult}
    END
    [Teardown]    sendMultiCommand    linkmap rx ${inportId}[0] tx ${outgroup_f_portId_1}[0],undo outgroup_f \ ${mirro_outgroup_id},sni_mirror enable false

sni_limit_drop
    [Documentation]    1、通过命令行配置sni_limit 的动作为drop
    ...    2、然后测试sni_number是否正常阻断
    ...    3、测试nosni_threshold是否正常阻断
    [Tags]    A
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    ADD_SNI
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    按照excel中的行为单位进行循环测试
    comment    测试sni_number
    ${sni_filename}    create list
    FOR    ${row}    IN RANGE    2    4
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${serviceType}    read cell data by name    ${sheetName}    C${row}
        ${totalLimit}    read cell data by name    ${sheetName}    D${row}
        ${timeLimit}    read cell data by name    ${sheetName}    E${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    G${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    H${row}
        ${expectSniNumber}    read cell data by name    ${sheetName}    I${row}
        ${expectHttps}    read cell data by name    ${sheetName}    J${row}
        ${expectNoHttps}    read cell data by name    ${sheetName}    K${row}
        ${pcap}    read cell data by name    ${sheetName}    L${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    M${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    N${row}
        comment    根据serviceType为0进行sni规则
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    serviceType    ${testTitle}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    sniNumber    ${totalLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    httpsPercent    ${timeLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    notHttps    ${startEndTimeGap}
        Run Keyword If    ${serviceType} == 0    New Connection Custom
        Run Keyword If    ${serviceType} == 0    sendMultiCommand    sni_limit ${testTitle} number ${totalLimit} not_sni_ratio ${timeLimit} not_sni_ratio_valid_GB ${startEndTimeGap} limit_action drop
        Run Keyword If    ${serviceType} == 0    Append To List    ${sni_filename}    ${iniRcpFileName}
        New Connection Custom
        telnet.write    show sni_limit
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Continue For Loop If    ${serviceType} == 0
        comment    根据serviceType非0进行acl规则
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    80
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    servicetype    ${serviceType}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_sninumber    ${expectSniNumber}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_httpspercent    ${expectHttps}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_nothttps    ${expectNoHttps}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${pcap}    Set Variable    https-dns.alidns.com-64_sni_10.pcap
        ${rx}    ${tx}    tcpreplayAndTcpdump    sni_cli_drop_interface_add_${row}_hit    ${pcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-48:-32]    #SNInumber
        Run Keyword And Continue On Failure    Should Be True    ${result}==10
        ${result}    Hex To Int    ${exactRespond}[-32:-16]    #https流量
        Run Keyword And Continue On Failure    Should Be True    ${result}==${expectHttps}
        ${result}    Hex To Int    ${exactRespond}[-16:]    #nohttps
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
    END
    comment    测试阈值阻断
    undo acl all
    ${sni_filename}    create list
    FOR    ${row}    IN RANGE    8    10
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${serviceType}    read cell data by name    ${sheetName}    C${row}
        ${totalLimit}    read cell data by name    ${sheetName}    D${row}
        ${timeLimit}    read cell data by name    ${sheetName}    E${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    G${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    H${row}
        ${expectSniNumber}    read cell data by name    ${sheetName}    I${row}
        ${expectHttps}    read cell data by name    ${sheetName}    J${row}
        ${expectNoHttps}    read cell data by name    ${sheetName}    K${row}
        ${pcap}    read cell data by name    ${sheetName}    L${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    M${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    N${row}
        comment    根据serviceType为0进行sni规则
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    serviceType    ${testTitle}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    sniNumber    ${totalLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    httpsPercent    ${timeLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    notHttps    ${startEndTimeGap}
        Run Keyword If    ${serviceType} == 0    New Connection Custom
        Run Keyword If    ${serviceType} == 0    sendMultiCommand    sni_limit ${testTitle} number ${totalLimit} not_sni_ratio ${timeLimit} not_sni_ratio_valid_GB ${startEndTimeGap} limit_action drop
        New Connection Custom
        telnet.write    show sni_limit
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Continue For Loop If    ${serviceType} == 0
        comment    根据serviceType非0进行acl规则
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    80
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    servicetype    ${serviceType}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_sninumber    ${expectSniNumber}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_httpspercent    ${expectHttps}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_nothttps    ${expectNoHttps}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打流一次，要是没有阈值，正常应该是会字节触发阻断
        ${rx}    ${tx}    tcpreplayAndTcpdump    sni_cli_drop_interface_add_${row}_hit    ${pcap}    ${startFlowSpeed}    ${startFlowTime}    1
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${16}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        New Connection Custom
        telnet .write    show acl all | include "acl grouped_rule"
        ${log}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    Should Not Contain    ${log}    action drop    非https的阈值未生效
        comment    再次打流90679次，一次是11841B；打完之后，总流量是1,073,730,039B，离1024M，还差11785B
        ${rx1}    ${tx1}    tcpreplayAndTcpdump    sni_cli_drop_interface_add_${row}_90679times_hit    ${pcap}    0    90679t    0    0
        Run Keyword And Continue On Failure    Should \ Be Equal As Integers    ${rx1}    ${1450864}    打流90679次，未完全输出
        New Connection Custom
        telnet .write    show acl all | include "acl grouped_rule"
        ${log}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    Should Contain    ${log}    action drop    非https的阈值未生效
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-48:-32]    #SNInumber
        Run Keyword And Continue On Failure    Should Be True    ${result}==${expectSniNumber}
        ${result}    Hex To Int    ${exactRespond}[-32:-16]    #https流量
        Run Keyword And Continue On Failure    Should Be True    ${result}==${expectHttps}
        ${result}    Hex To Int    ${exactRespond}[-16:]    #nohttps
        Run Keyword And Continue On Failure    Should Be True    ${result}==${expectNoHttps}
    END

sni_limit_alarm
    [Documentation]    1、通过命令行配置sni_limit 的动作为alarm
    ...    2、然后测试sni_number到达阻断值后，是否上报alarm以及对应的规则未变成drop，流量继续输出
    ...    3、测试nosni_threshold道道阻断后，，是否上报alarm以及对应的规则未变成drop，流量继续输出
    [Tags]    A
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    ADD_SNI
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    测试sni_number
    comment    获取最近一次的alarm日志的日期
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /appdisk/log
    sleep    1
    SSHLibrary.Write    grep -i 'threshold' sys.log | tail -n 1
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    grep -i ".*reached [0-9][0-9]\%.*threshold\." sys.log | tail -n 1 | awk -F 'NanoPi' '{print $1}'
    sleep    1
    ${sni_info_org}    SSHLibrary.Read Until    root@
    SSHLibrary.Close All Connections
    ${sni_filename}    create list
    FOR    ${row}    IN RANGE    2    4
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${serviceType}    read cell data by name    ${sheetName}    C${row}
        ${totalLimit}    read cell data by name    ${sheetName}    D${row}
        ${timeLimit}    read cell data by name    ${sheetName}    E${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    G${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    H${row}
        ${expectSniNumber}    read cell data by name    ${sheetName}    I${row}
        ${expectHttps}    read cell data by name    ${sheetName}    J${row}
        ${expectNoHttps}    read cell data by name    ${sheetName}    K${row}
        ${pcap}    read cell data by name    ${sheetName}    L${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    M${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    N${row}
        comment    根据serviceType为0进行sni规则
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    serviceType    ${testTitle}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    sniNumber    ${totalLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    httpsPercent    ${timeLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    notHttps    ${startEndTimeGap}
        Run Keyword If    ${serviceType} == 0    New Connection Custom
        Run Keyword If    ${serviceType} == 0    sendMultiCommand    sni_limit ${testTitle} number ${totalLimit} not_sni_ratio ${timeLimit} not_sni_ratio_valid_GB ${startEndTimeGap} limit_action alarm
        Run Keyword If    ${serviceType} == 0    Append To List    ${sni_filename}    ${iniRcpFileName}
        New Connection Custom
        telnet.write    show sni_limit
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Continue For Loop If    ${serviceType} == 0
        comment    根据serviceType非0进行acl规则
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    80
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    servicetype    ${serviceType}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_sninumber    ${expectSniNumber}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_httpspercent    ${expectHttps}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_nothttps    ${expectNoHttps}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    sni_cli_alarm_interface_add_${row}_hit    ${pcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inPkt}    ${outPkt}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inByte}    ${outByte}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${outByte}    ${hitCount}
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-48:-32]    #SNInumber
        Run Keyword And Continue On Failure    Should Be True    ${result}==104
        ${result1}    Hex To Int    ${exactRespond}[-32:-16]    #https流量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result2}    Hex To Int    ${exactRespond}[-16:]    #nohttps
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${outByte}    ${${result1}+${result2}}
        comment    校验规则不为drop
        New Connection Custom
        telnet.write    show acl all | include "acl grouped_rule"
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Run Keyword And Continue On Failure    Should not Contain    ${info}    action drop    alarm行为规则变未drop
        comment    检查是否上报告警——后续考虑是否加入
        SSHLibrary.Open Connection    ${host_ip}    timeout=120
        SSHLibrary.login    root    fa
        SSHLibrary.Write    pwd
        sleep    1
        SSHLibrary.Read
        SSHLibrary.Write    cd /appdisk/log
        sleep    1
        SSHLibrary.Write    grep -i 'threshold' sys.log | tail -n 1
        sleep    1
        SSHLibrary.Read
        SSHLibrary.Write    grep -i ".*reached [0-9][0-9]\%.*threshold\." sys.log | tail -n 1 | awk -F 'NanoPi' '{print $1}'
        sleep    1
        ${sni_info}    SSHLibrary.Read Until    root@
        SSHLibrary.Close All Connections
        Run Keyword And Continue On Failure    Should Not Be Equal As Strings    ${sni_info}    ${sni_info_org}
    END
    comment    测试阈值阻断
    undo acl all
    comment    获取最近一次的alarm日志的日期
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /appdisk/log
    sleep    1
    SSHLibrary.Write    grep -i 'threshold' sys.log | tail -n 1
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    grep -i ".*reached [0-9][0-9]\%.*threshold\." sys.log | tail -n 1 | awk -F 'NanoPi' '{print $1}'
    sleep    1
    ${sni_info_org}    SSHLibrary.Read Until    root@
    SSHLibrary.Close All Connections
    ${sni_filename}    create list
    FOR    ${row}    IN RANGE    8    10
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${serviceType}    read cell data by name    ${sheetName}    C${row}
        ${totalLimit}    read cell data by name    ${sheetName}    D${row}
        ${timeLimit}    read cell data by name    ${sheetName}    E${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    G${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    H${row}
        ${expectSniNumber}    read cell data by name    ${sheetName}    I${row}
        ${expectHttps}    read cell data by name    ${sheetName}    J${row}
        ${expectNoHttps}    read cell data by name    ${sheetName}    K${row}
        ${pcap}    read cell data by name    ${sheetName}    L${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    M${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    N${row}
        comment    根据serviceType为0进行sni规则
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    serviceType    ${testTitle}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    sniNumber    ${totalLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    httpsPercent    ${timeLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    notHttps    ${startEndTimeGap}
        Run Keyword If    ${serviceType} == 0    New Connection Custom
        Run Keyword If    ${serviceType} == 0    sendMultiCommand    sni_limit ${testTitle} number ${totalLimit} not_sni_ratio ${timeLimit} not_sni_ratio_valid_GB ${startEndTimeGap} limit_action alarm
        New Connection Custom
        telnet.write    show sni_limit
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Continue For Loop If    ${serviceType} == 0
        comment    根据serviceType非0进行acl规则
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    80
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    servicetype    ${serviceType}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_sninumber    ${expectSniNumber}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_httpspercent    ${expectHttps}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_nothttps    ${expectNoHttps}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打流一次，要是没有阈值，正常应该是会字节触发阻断
        ${rx}    ${tx}    tcpreplayAndTcpdump    sni_cli_alarm_interface_add_${row}_hit    ${pcap}    ${startFlowSpeed}    ${startFlowTime}    1
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${16}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        New Connection Custom
        telnet .write    show acl all | include "acl grouped_rule"
        ${log}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    Should Not Contain    ${log}    action drop    非https的阈值未生效
        comment    再次打流90678次，此时不会阻断
        ${rx1}    ${tx1}    tcpreplayAndTcpdump    sni_cli_alarm_interface_add_${row}_90679times_hit    ${pcap}    0    90678t    0    0
        comment    要是阻断生效此时应该会进行正常阻断
        ${rx2}    ${tx2}    tcpreplayAndTcpdump    sni_cli_alarm_interface_add_${row}_90679times_hit    ${pcap}    0.01    1t    0    0
        comment    再次验证阻断不生效
        ${rx3}    ${tx3}    tcpreplayAndTcpdump    sni_cli_alarm_interface_add_${row}_90679times_hit    ${pcap}    100    10    0    0
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx3}    ${0}    设置alarm的行为不生效无流量输出
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${${tx}[0]+${tx}[2]+${tx}[4]+${tx1}[0]+${tx2}[0]+${tx3}[0]}    ${${rx}+${rx1}+${rx2}+${rx3}}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inPkt}    ${outPkt}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inByte}    ${outByte}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-48:-32]    #SNInumber
        Run Keyword And Continue On Failure    Should Be True    ${result}==3
        ${result1}    Hex To Int    ${exactRespond}[-32:-16]    #https流量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result2}    Hex To Int    ${exactRespond}[-16:]    #nohttps
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${outByte}    ${${result1}+${result2}}
        comment    校验规则是否不为drop
        New Connection Custom
        telnet .write    show acl all | include "acl grouped_rule"
        ${log}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    Should not Contain    ${log}    action drop    非https的阈值未生效
        comment    检查是否上报告警——后续考虑是否加入
        SSHLibrary.Open Connection    ${host_ip}    timeout=120
        SSHLibrary.login    root    fa
        SSHLibrary.Write    pwd
        sleep    1
        SSHLibrary.Read
        SSHLibrary.Write    cd /appdisk/log
        sleep    1
        SSHLibrary.Write    grep -i 'threshold' sys.log | tail -n 1
        sleep    1
        SSHLibrary.Read
        SSHLibrary.Write    grep -i ".*reached [0-9][0-9]\%.*threshold\." sys.log | tail -n 1 | awk -F 'NanoPi' '{print $1}'
        sleep    1
        ${sni_info}    SSHLibrary.Read Until    root@
        SSHLibrary.Close All Connections
        Run Keyword And Continue On Failure    Should Not Be Equal As Strings    ${sni_info}    ${sni_info_org}
    END

sni_limit_noop
    [Documentation]    1、通过命令行配置sni_limit 的动作为alarm
    ...    2、然后测试sni_number到达阻断值后，流量继续输出，以及没有alarm
    ...    3、测试nosni_threshold道道阻断后，流量继续输出，以及没有alarm
    [Tags]    A
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    ADD_SNI
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    按照excel中的行为单位进行循环测试
    comment    测试sni_number
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /appdisk/log
    sleep    1
    SSHLibrary.Write    grep -i 'threshold' sys.log | tail -n 1
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    grep -i ".*reached [0-9][0-9]\%.*threshold\." sys.log | tail -n 1 | awk -F 'NanoPi' '{print $1}'
    sleep    1
    ${sni_info_org}    SSHLibrary.Read Until    root@
    SSHLibrary.Close All Connections
    ${sni_filename}    create list
    FOR    ${row}    IN RANGE    2    4
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${serviceType}    read cell data by name    ${sheetName}    C${row}
        ${totalLimit}    read cell data by name    ${sheetName}    D${row}
        ${timeLimit}    read cell data by name    ${sheetName}    E${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    G${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    H${row}
        ${expectSniNumber}    read cell data by name    ${sheetName}    I${row}
        ${expectHttps}    read cell data by name    ${sheetName}    J${row}
        ${expectNoHttps}    read cell data by name    ${sheetName}    K${row}
        ${pcap}    read cell data by name    ${sheetName}    L${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    M${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    N${row}
        comment    根据serviceType为0进行sni规则
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    serviceType    ${testTitle}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    sniNumber    ${totalLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    httpsPercent    ${timeLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    notHttps    ${startEndTimeGap}
        Run Keyword If    ${serviceType} == 0    New Connection Custom
        Run Keyword If    ${serviceType} == 0    sendMultiCommand    sni_limit ${testTitle} number ${totalLimit} not_sni_ratio ${timeLimit} not_sni_ratio_valid_GB ${startEndTimeGap} limit_action noop
        Run Keyword If    ${serviceType} == 0    Append To List    ${sni_filename}    ${iniRcpFileName}
        New Connection Custom
        telnet.write    show sni_limit
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Continue For Loop If    ${serviceType} == 0
        comment    根据serviceType非0进行acl规则
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    80
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    servicetype    ${serviceType}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_sninumber    ${expectSniNumber}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_httpspercent    ${expectHttps}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_nothttps    ${expectNoHttps}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    sni_cli_alarm_interface_add_${row}_hit    ${pcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inPkt}    ${outPkt}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inByte}    ${outByte}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${outByte}    ${hitCount}
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-48:-32]    #SNInumber
        Run Keyword And Continue On Failure    Should Be True    ${result}==104
        ${result1}    Hex To Int    ${exactRespond}[-32:-16]    #https流量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result2}    Hex To Int    ${exactRespond}[-16:]    #nohttps
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${outByte}    ${${result1}+${result2}}
        comment    校验规则不为drop
        New Connection Custom
        telnet.write    show acl all | include "acl grouped_rule"
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Run Keyword And Continue On Failure    Should not Contain    ${info}    action drop    alarm行为规则变未drop
        comment    检查是否没上报告警——后续考虑是否加入
        SSHLibrary.Open Connection    ${host_ip}    timeout=120
        SSHLibrary.login    root    fa
        SSHLibrary.Write    pwd
        sleep    1
        SSHLibrary.Read
        SSHLibrary.Write    cd /appdisk/log
        sleep    1
        SSHLibrary.Write    grep -i 'threshold' sys.log | tail -n 1
        sleep    1
        SSHLibrary.Read
        SSHLibrary.Write    grep -i ".*reached [0-9][0-9]\%.*threshold\." sys.log | tail -n 1 | awk -F 'NanoPi' '{print $1}'
        sleep    1
        ${sni_info}    SSHLibrary.Read Until    root@
        SSHLibrary.Close All Connections
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${sni_info}    ${sni_info_org}
    END
    comment    测试阈值阻断
    undo acl all
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /appdisk/log
    sleep    1
    SSHLibrary.Write    grep -i 'threshold' sys.log | tail -n 1
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    grep -i ".*reached [0-9][0-9]\%.*threshold\." sys.log | tail -n 1 | awk -F 'NanoPi' '{print $1}'
    sleep    1
    ${sni_info_org}    SSHLibrary.Read Until    root@
    SSHLibrary.Close All Connections
    ${sni_filename}    create list
    FOR    ${row}    IN RANGE    8    10
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${serviceType}    read cell data by name    ${sheetName}    C${row}
        ${totalLimit}    read cell data by name    ${sheetName}    D${row}
        ${timeLimit}    read cell data by name    ${sheetName}    E${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    G${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    H${row}
        ${expectSniNumber}    read cell data by name    ${sheetName}    I${row}
        ${expectHttps}    read cell data by name    ${sheetName}    J${row}
        ${expectNoHttps}    read cell data by name    ${sheetName}    K${row}
        ${pcap}    read cell data by name    ${sheetName}    L${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    M${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    N${row}
        comment    根据serviceType为0进行sni规则
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    serviceType    ${testTitle}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    sniNumber    ${totalLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    httpsPercent    ${timeLimit}
        Run Keyword If    ${serviceType} == 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    notHttps    ${startEndTimeGap}
        Run Keyword If    ${serviceType} == 0    New Connection Custom
        Run Keyword If    ${serviceType} == 0    sendMultiCommand    sni_limit ${testTitle} number ${totalLimit} not_sni_ratio ${timeLimit} not_sni_ratio_valid_GB ${startEndTimeGap} limit_action noop
        New Connection Custom
        telnet.write    show sni_limit
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Continue For Loop If    ${serviceType} == 0
        comment    根据serviceType非0进行acl规则
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    80
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys}
        Run Keyword If    ${startTimeSys}!=${endTimeSys}    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    servicetype    ${serviceType}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_sninumber    ${expectSniNumber}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_httpspercent    ${expectHttps}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    expect_nothttps    ${expectNoHttps}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打流一次，要是没有阈值，正常应该是会字节触发阻断
        ${rx}    ${tx}    tcpreplayAndTcpdump    sni_cli_alarm_interface_add_${row}_hit    ${pcap}    ${startFlowSpeed}    ${startFlowTime}    1
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${16}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        New Connection Custom
        telnet .write    show acl all | include "acl grouped_rule"
        ${log}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    Should Not Contain    ${log}    action drop    非https的阈值未生效
        comment    再次打流90678次，此时不会阻断
        ${rx1}    ${tx1}    tcpreplayAndTcpdump    sni_cli_alarm_interface_add_${row}_90679times_hit    ${pcap}    0    90678t    0    0
        comment    要是阻断生效此时应该会进行正常阻断
        ${rx2}    ${tx2}    tcpreplayAndTcpdump    sni_cli_alarm_interface_add_${row}_90679times_hit    ${pcap}    0.01    1t    0    0
        comment    再次验证阻断不生效
        ${rx3}    ${tx3}    tcpreplayAndTcpdump    sni_cli_alarm_interface_add_${row}_90679times_hit    ${pcap}    100    10    0    0
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx3}    ${0}    设置alarm的行为不生效无流量输出
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${${tx}[0]+${tx}[2]+${tx}[4]+${tx1}[0]+${tx2}[0]+${tx3}[0]}    ${${rx}+${rx1}+${rx2}+${rx3}}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inPkt}    ${outPkt}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inByte}    ${outByte}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-48:-32]    #SNInumber
        Run Keyword And Continue On Failure    Should Be True    ${result}==3
        ${result1}    Hex To Int    ${exactRespond}[-32:-16]    #https流量
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result2}    Hex To Int    ${exactRespond}[-16:]    #nohttps
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${outByte}    ${${result1}+${result2}}
        comment    校验规则是否不为drop
        New Connection Custom
        telnet .write    show acl all | include "acl grouped_rule"
        ${log}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    Should not Contain    ${log}    action drop    非https的阈值未生效
        comment    检查是否没上报告警——后续考虑是否加入
        SSHLibrary.Open Connection    ${host_ip}    timeout=120
        SSHLibrary.login    root    fa
        SSHLibrary.Write    pwd
        sleep    1
        SSHLibrary.Read
        SSHLibrary.Write    cd /appdisk/log
        sleep    1
        SSHLibrary.Write    grep -i 'threshold' sys.log | tail -n 1
        sleep    1
        SSHLibrary.Read
        SSHLibrary.Write    grep -i ".*reached [0-9][0-9]\%.*threshold\." sys.log | tail -n 1 | awk -F 'NanoPi' '{print $1}'
        sleep    1
        ${sni_info}    SSHLibrary.Read Until    root@
        SSHLibrary.Close All Connections
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${sni_info}    ${sni_info_org}
    END

sni_unnormal
    [Documentation]    打1.pcap，连续打100次，然后查看寄存器计数
    [Tags]    A
    [Setup]    undo acl all
    ${slot_interface}    Split String    ${inportId}[0]    /
    ${slot_id}    Get From List    ${slot_interface}    0
    comment    报文，靠近eop(相隔5个字节)
    comment    清除寄存器计数
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /appdisk/log
    sleep    1
    SSHLibrary.Write    echo "mfpga${slot_id}(0,0x1c40)" | luacmd.lua
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    echo "dfpga${slot_id}(0x1c58)" | luacmd.lua
    sleep    1
    ${log}    SSHLibrary.Read Until    root@
    log    ${log}
    ${hello}    Get Regexp Matches    ${log}    :([0-9A-Z]{4,})H    1
    log    ${hello}
    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${hello}[0][0:2]    00    1c58清除不掉
    SSHLibrary.Close All Connections
    ${sni_filename}    create list
    comment    打流100次
    New Connection Custom
    telnet.write    clear statistics all
    ${rx1}    ${tx1}    tcpreplayAndTcpdump    sni_nnnormal    1.pcap    100    100000t    0    0
    compareStastics    ${inportId}    ${outgroup_f_portId_1}    100000    00
    comment    检查寄存器-1c58
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /appdisk/log
    sleep    1
    SSHLibrary.Write    echo "dfpga${slot_id}(0x1c58)" | luacmd.lua
    sleep    1
    ${confdb}    SSHLibrary.Read Until    root@
    log    ${confdb}
    ${hello}    Get Regexp Matches    ${confdb}    :([0-9A-Z]{4,})H    1
    log    ${hello}
    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${hello}[0][0:2]    A0    sni识别异常
    SSHLibrary.Close All Connections
    comment    报文，更加靠近eop(相隔1个字节)
    comment    清除寄存器计数
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /appdisk/log
    sleep    1
    SSHLibrary.Write    echo "mfpga${slot_id}(0,0x1c40)" | luacmd.lua
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    echo "dfpga${slot_id}(0x1c58)" | luacmd.lua
    sleep    1
    ${log}    SSHLibrary.Read Until    root@
    log    ${log}
    ${hello}    Get Regexp Matches    ${log}    :([0-9A-Z]{4,})H    1
    log    ${hello}
    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${hello}[0][0:2]    00    1c58清除不掉
    SSHLibrary.Close All Connections
    ${sni_filename}    create list
    comment    打流100次
    New Connection Custom
    telnet.write    clear statistics all
    ${rx1}    ${tx1}    tcpreplayAndTcpdump    sni_nnnormal    1_tc10.pcap    100    100000t    0    0
    compareStastics    ${inportId}    ${outgroup_f_portId_1}    100000    00
    comment    检查寄存器-1c58
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /appdisk/log
    sleep    1
    SSHLibrary.Write    echo "dfpga${slot_id}(0x1c58)" | luacmd.lua
    sleep    1
    ${confdb}    SSHLibrary.Read Until    root@
    log    ${confdb}
    ${hello}    Get Regexp Matches    ${confdb}    :([0-9A-Z]{4,})H    1
    log    ${hello}
    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${hello}[0][0:2]    A0    sni识别异常
    SSHLibrary.Close All Connections

sni_no_clear
    [Documentation]    undo acl all无法清除sni计数，
    ...    步骤：
    ...    1，下发规则
    ...    2，打流，查看sni计数
    ...    3，删除规则，清除计数
    ...    4，重复步骤1-3
    [Tags]    A
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    ADD_SNI
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    按照excel中的行为单位进行循环测试
    comment    清除寄存器计数
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /appdisk/log
    sleep    1
    SSHLibrary.Write    echo "mfpga1(0,0x1c40)" | luacmd.lua
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    echo "dfpga1(0x1c58)" | luacmd.lua
    sleep    1
    ${log}    SSHLibrary.Read Until    root@
    SSHLibrary.Close All Connections
    ${sni_filename}    create list
    comment    打流100次
    FOR    ${i}    IN RANGE    100
        New Connection Custom
        telnet.write    undo acl all
        ${info}    Telnet.Read Until    sysadmin(config)#
        sleep    5
        telnet.write    clear statistics all
        ${info}    Telnet.Read Until    sysadmin(config)#
        telnet.write    acl stage3_f ipmode ipv4 action forward outgroup_f \ 1 bussiness 2 hit_statistics true \ app_id 1
        ${info}    Telnet.Read Until    sysadmin(config)#
        ${rx1}    ${tx1}    tcpreplayAndTcpdump    sni_nnnormal    https-dns.alidns.com_104.pcap    10    0    0    0
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    104    104
        telnet.write    show acl hit_statistics \ 1
        ${info}    Telnet.Read Until    sysadmin(config)#
        ${hitCountList}    get regexp matches    ${info}    [0-9]{1,}\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)    3
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCountList}[0]    104
    END

sni_no_clear_singal
    [Documentation]    针对单挑规则无法清除sni计数，
    ...    步骤：
    ...    1，下发规则
    ...    2，打流，查看sni计数
    ...    3，删除规则，清除计数
    ...    4，重复步骤1-3
    [Tags]    A
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    ADD_SNI
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    按照excel中的行为单位进行循环测试
    comment    清除寄存器计数
    SSHLibrary.Open Connection    ${host_ip}    timeout=120
    SSHLibrary.login    root    fa
    SSHLibrary.Write    pwd
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    cd /appdisk/log
    sleep    1
    SSHLibrary.Write    echo "mfpga1(0,0x1c40)" | luacmd.lua
    sleep    1
    SSHLibrary.Read
    SSHLibrary.Write    echo "dfpga1(0x1c58)" | luacmd.lua
    sleep    1
    ${log}    SSHLibrary.Read Until    root@
    SSHLibrary.Close All Connections
    ${sni_filename}    create list
    comment    打流100次
    FOR    ${i}    IN RANGE    100
        New Connection Custom
        telnet.write    clear statistics all
        ${info}    Telnet.Read Until    sysadmin(config)#
        telnet.write    acl stage3_f ipmode ipv4 action forward outgroup_f \ 1 bussiness 2 hit_statistics true \ app_id 1
        ${info}    Telnet.Read Until    sysadmin(config)#
        ${rx1}    ${tx1}    tcpreplayAndTcpdump    sni_nnnormal    https-dns.alidns.com_104.pcap    10    0    0    0
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    104    104
        telnet.write    show acl hit_statistics \ 1
        ${info}    Telnet.Read Until    sysadmin(config)#
        ${hitCountList}    get regexp matches    ${info}    [0-9]{1,}\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)    3
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCountList}[0]    104
        telnet.write    undo acl stage3_f ipmode ipv4
        Telnet.Read Until    sysadmin(config)#
        sleep    5
        telnet.write    acl stage3_f 4301 ipmode ipv4 src_ip 192.168.8.131/255.255.255.255 action drop app_id 1 group_a 1
        Telnet.Read Until    sysadmin(config)#
        telnet.write    acl grouped_rule 1 group_num_a 1 group_num_b 0 action forward outgroup_f 1 app_id 1 hit_statistics true bussiness 2
        Telnet.Read Until    sysadmin(config)#
        telnet.write    clear statistics all
        sleep    3
        ${info}    Telnet.Read Until    sysadmin(config)#
        ${rx1}    ${tx1}    tcpreplayAndTcpdump    sni_nnnormal_group    https-dns.alidns.com-64_sni_10.pcap    10    0    0    0
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    483    483
        telnet.write    show acl hit_statistics \ 1
        ${info}    Telnet.Read Until    sysadmin(config)#
        ${hitCountList}    get regexp matches    ${info}    [0-9]{1,}\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)    3
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCountList}[0]    101
        telnet.write    undo acl grouped_rule 1
        Telnet.Read Until    sysadmin(config)#
        sleep    5
        telnet.write    acl sni server_name "tbn?0.gstatic.com" action forward outgroup_f 1 app_id 1 hit_statistics true bussiness 5
        Telnet.Read Until    sysadmin(config)#
        telnet.write    clear statistics all
        sleep    3
        ${info}    Telnet.Read Until    sysadmin(config)#
        ${rx1}    ${tx1}    tcpreplayAndTcpdump    sni_nnnormal_sni    wenhao.pcap    10    0    0    0
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    1    1
        telnet.write    show acl hit_statistics \ 1
        ${info}    Telnet.Read Until    sysadmin(config)#
        ${hitCountList}    get regexp matches    ${info}    [0-9]{1,}\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)    3
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCountList}[0]    1
        telnet.write    undo acl sni server_name "tbn?0.gstatic.com" action forward
        Telnet.Read Until    sysadmin(config)#
        sleep    5
    END

rcp_add_del_fivetuple
    [Documentation]    五元组下发遍历以下8种情况：
    ...    纯a、纯b、纯a&纯b、2a&2b、1a&2b、2a&1b、2a、2b
    ...
    ...    用例程序步骤：
    ...
    ...    1.打开exec了表格
    ...    2.设置初始参数：totalAppIdList,expectRespondCode
    ...    3.按照excel中ADD_FiveTuple表格的行数进行循环
    ...    a.获取相关参数：规则配置文件名，规则配置title,包配置文件名，包配置title，保存pcapfile标识，打流速率，打流时间
    ...    b.按照a中获取的信息通过rcp进行规则下发，且根据返回判断规则是否下发成功，获取对应的ruleid
    ...    c.通过show acl all获取当前acl信息
    ...    d.根据a中信息，进行背景和业务的pcapfile文件的生成
    ...    e.打e中生成的背景pcapfile
    ...    f.校验仪表的tx=设备rx,设备tx=仪表rx，以及仪表rx=0
    ...    g.获取规则中标统计，且中标统计为0
    ...    h.打e中生成的业务pcapfile，且把设备输出保存outpcapfile
    ...    i.校验仪表的tx=设备rx,设备tx=仪表rx，以及仪表rx!=0
    ...    j.获取规则中标统计，且中标统计=仪表的tx
    ...    k.根据c中的业务pcap和i中的outpcapfile生成hash值，对源和设备输出内容进行比较
    ...    l.通过rcp删除规则
    ...    n.打流验证规则是否正常删除
    ...    m.通过show acl all获取当前acl信息
    [Tags]    debug
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    ADD_FiveTuple
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${expectRespondCode}    Set Variable    01
    comment    按照excel中的行为单位进行循环测试
    #    ${${countRow}-1}
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    H${row}
        ${hitPcapTitle}    read cell data by name    ${sheetName}    I${row}
        ${backPcapTitle}    read cell data by name    ${sheetName}    J${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    K${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    L${row}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    生成pcap包
        ${backPcap}    makePcap    ${0}    ${iniPacketFileName}    ${backPcapTitle}
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${hitPcapTitle}
        log    ${backPcap}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_fivetuple_${row}_back    ${backPcap}    0    0
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_fivetuple_${row}_hit    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${outByte}    业务流的hitCount不等于设备总发送
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}    ${hitPcap}
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    interface_add_fivetuple_${row}_hit.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Should Be True    ${hashResult}    包内容检查错误，仪表发送报文不等于设备输出的报文内容
        Comment    测试五元组规则删除
        delete_fivetuple    ${ruleId}    ${expectRespondCode}
        comment    打删除前名字流来判断是否无法命中，规则被删除
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_fivetuple_${row}_afterdel    ${hitPcap}    0    0
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    规则删除后仍有命中
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
    END

rcp_modify_rule_fivetuple
    [Tags]    debug
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    MODIFY_FiveTuple
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${expectRespondCode}    Set Variable    01
    ${ruleId}    Set Variable    28412
    comment    按照excel中的行为单位进行循环测试
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    H${row}
        ${hitPcapTitle}    read cell data by name    ${sheetName}    I${row}
        ${backPcapTitle}    read cell data by name    ${sheetName}    J${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    K${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    L${row}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword And Continue On Failure    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        comment    ${length}=    Get Length    ${totalAppIdList}
        comment    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${length}    ${1}    未变更规则，ruleid与变更前不一致
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    生成pcap包
        ${backPcap}    makePcap    ${0}    ${iniPacketFileName}    ${backPcapTitle}
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${hitPcapTitle}
        log    ${backPcap}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_modify_fivetuple_${row}_back    ${backPcap}    0    0
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_modify_fivetuple_${row}_hit    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${outByte}    业务流的hitCount不等于设备总发送
        Comment    通过hash校验包的完整性
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}    ${hitPcap}
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    interface_modify_fivetuple_${row}_hit.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Should Be True    ${hashResult}    包内容检查错误，仪表发送报文不等于设备输出的报文内容
        comment    测试完ipv4后删除规则，继续ipv6测试
        Run Keyword If    ${row} == ${11}    delete_fivetuple    ${ruleId}    ${expectRespondCode}
    END
    Comment    删除设备下发的acl
    delete_fivetuple    ${ruleId}    ${expectRespondCode}

rcp_query_fivetuple
    [Tags]    debug
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    QUERY_FiveTuple
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${expectRespondCode}    Set Variable    01
    comment    按照excel中的行为单位进行循环测试
    #    ${${countRow}-1}
    ${appid_list}    Create List
    ${id_out}    Create Dictionary
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    H${row}
        ${hitPcapTitle}    read cell data by name    ${sheetName}    I${row}
        ${backPcapTitle}    read cell data by name    ${sheetName}    J${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    K${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    L${row}
        ${drop_or_no}    read cell data by name    ${sheetName}    M${row}
        comment    对对应的ini配置文件的限量信息进行设置
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    50
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        ${startTimeSys_fin}    Set Variable If    ${startEndTimeGap} == 0    ${EMPTY}    ${startTimeSys}
        ${endTimeSys_fin}    Set Variable If    ${startEndTimeGap} == 0    ${EMPTY}    ${endTimeSys}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys_fin}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys_fin}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        comment    生成pcap包
        ${backPcap}    makePcap    ${0}    ${iniPacketFileName}    ${backPcapTitle}
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${hitPcapTitle}
        log    ${backPcap}
        log    ${hitPcap}
        ${packet_size_list}    getConfigOptionValue    ${iniPacketFileName}    ${hitPcapTitle}    pkt_len
        ${packet_size}    Evaluate    math.floor(sum(${packet_size_list})/len(${packet_size_list}))    math
        ${packet_count_list}    getConfigOptionValue    ${iniPacketFileName}    ${hitPcapTitle}    pkt_count
        ${packet_count}    Evaluate    sum(${packet_count_list})
        ${time1}    Get Time    epoch
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    根据预期输出总量，计算需要打流次数
        ${times}    evaluate    math.ceil(${expectOutTotal}*1024*1024/((${packet_size}+4)*${packet_count}))    math
        ${rx}    ${tx}    Run Keyword If    ${times} == 0    tcpreplayAndTcpdump    interface_add_${row}_number_1_hit    ${hitPcap}    0.1    ${${expectOutTime}+20}
        ...    ELSE    tcpreplayAndTcpdump    interface_add_${row}_number_1_hit    ${hitPcap}    0    ${${times}-1}t
        sleep    10
        comment    第一次打流进行校验
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inPkt}    ${outPkt}
        Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inByte}    ${outByte}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should \ Be Equal As Integers    ${hitCount}    ${outByte}
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew_fivetuple    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-48:-32]    #SNInumber
        Run Keyword And Continue On Failure    Should Be True    ${result}==0
        ${result}    Hex To Int    ${exactRespond}[-32:-16]    #https流量
        Run Keyword And Continue On Failure    Should Be True    ${result}==0
        #    Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-16:]    #nohttps
        Run Keyword And Continue On Failure    Should Be True    ${result}==0
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Run Keyword If    ${times} == 0    Run Keyword And Continue On Failure    Should Contain    ${info}    action drop    非https的阈值未生效
        ${exactTime}    ${exactNum}    ${firstPacketUnixTime}    Run Keyword If    ${times} == 0    checkNumOrTimeResult    interface_add_${row}_number_1_hit.pcap    0    0    1    2
        ${result}    Run Keyword If    ${times} == 0    Evaluate    abs(${exactTime}-${expectOutTime})
        Run Keyword If    ${times} == 0    Should Be True    0<=${result}<3
        Continue For Loop If    ${times} == 0
        comment    第2次打流，速率要慢
        ${rx1}    ${tx1}    tcpreplayAndTcpdump    interface_add_${row}_number_2_hit    ${hitPcap}    0.1    1t
        comment    内容校验
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx1}    ${0}    业务流仪表的rx等于0
        ${inPkt1}    ${inByte1}    ${outPkt1}    ${outByte1}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx1}[0]    ${rx1}
        Run Keyword If    ${drop_or_no}== 0    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inPkt1}    ${outPkt1}
        ...    ELSE    Run Keyword And Continue On Failure    should be true    ${inPkt1}>=${outPkt1}    阻断打流，输入报个数小于输出报个数
        Run Keyword If    ${drop_or_no}== 0    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inByte1}    ${outByte1}
        ...    ELSE    Run Keyword And Continue On Failure    should be true    ${inByte1}>=${outByte1}    阻断打流，输入字节小于输出输出字节
        ${hitCount1}    getAclHitstatistics    ${ruleId}
        Run Keyword If    ${drop_or_no}== 0    Run Keyword And Continue On Failure    Should \ Be Equal As Integers    ${hitCount1}    ${outByte1}    #    # ELSE    Run Keyword And Continue On Failure    should be true    ${hitCount1}>=${outByte1}    阻断打流，命中字节数小于输出
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew_fivetuple    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword If    ${drop_or_no}== 1    Run Keyword And Continue On Failure    Should Be True    ${${outByte}+${outByte1}-${result}}<=${outByte1}
        ...    ELSE    Run Keyword And Continue On Failure    Should Be True    ${result}==${${hitCount1}+${hitCount}}
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword If    ${drop_or_no}== 1    Run Keyword And Continue On Failure    Should Be True    ${${outByte}+${outByte1}-${result}}<=${outByte1}
        ...    ELSE    Run Keyword And Continue On Failure    Should Be True    ${result}==${${hitCount1}+${hitCount}}
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-48:-32]    #SNInumber
        Run Keyword And Continue On Failure    Should Be True    ${result}==0
        ${result}    Hex To Int    ${exactRespond}[-32:-16]    #https流量
        Run Keyword And Continue On Failure    Should Be True    ${result}==0    #    Run Keyword If    ${drop_or_no}== 1    Run Keyword And Continue On Failure    Should Be True    ${${outByte}+${outByte1}-${result}}<=${outByte1}    # ELSE    Run Keyword And Continue On Failure    Should Be True    ${result}==${${hitCount1}+${hitCount}}
        ${result}    Hex To Int    ${exactRespond}[-16:]    #nohttps
        Run Keyword And Continue On Failure    Should Be True    ${result}==0
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Run Keyword If    ${drop_or_no}== 1    Run Keyword And Continue On Failure    Should Contain    ${info}    action drop
        ...    ELSE    Run Keyword And Continue On Failure    Should \ not Contain    ${info}    action drop
        undo acl all
    #    ${ruleId}    Create List    ${ruleId}
    #    undoFiveTupleByRCP    ${ruleId}
    END

rcp_block_fivetuple
    [Tags]    debug
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    BLOCK_FiveTuple
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${forwardAppIdList}    Create List
    ${expectRespondCode}    Set Variable    01
    comment    按照excel中的前两行下发初始转发规则
    FOR    ${row}    IN RANGE    2    4
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    H${row}
        ${hitPcapTitle}    read cell data by name    ${sheetName}    I${row}
        ${backPcapTitle}    read cell data by name    ${sheetName}    J${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    K${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    L${row}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId_fd}    Run Keyword And Continue On Failure    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        Append To List    ${forwardAppIdList}    ${ruleId_fd}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    生成pcap包
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${hitPcapTitle}
        log    ${hitPcap}
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_block_fivetuple_${row}_hit    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId_fd}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${outByte}    业务流的hitCount不等于设备总发送
    END
    comment    下发阻断规则
    FOR    ${row}    IN RANGE    4    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    H${row}
        ${hitPcapTitle}    read cell data by name    ${sheetName}    I${row}
        ${backPcapTitle}    read cell data by name    ${sheetName}    J${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    K${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    L${row}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword And Continue On Failure    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    生成pcap包
        ${backPcap}    makePcap    ${0}    ${iniPacketFileName}    ${backPcapTitle}
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${hitPcapTitle}
        log    ${backPcap}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计=0)，背景流：不匹配阻断规则但能匹配初始转发规则
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_block_fivetuple_${row}_back    ${backPcap}    0    0
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    阻断规则的背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且tx=0；2、仪表rx=0；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_block_fivetuple_${row}_hit    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    阻断规则的流量有输出
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${tx}[1]    业务流的hitCount不等于仪表的Tx
        Comment    测试阻断五元组规则删除
        delete_fivetuple    ${ruleId}    ${expectRespondCode}
        comment    打删除前命中流来判断是否无法命中，规则被删除
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_fivetuple_${row}_afterdel    ${hitPcap}    0    0
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        comment    cli下规则查看
        ${hitCount}    run keyword if    "v4" in "${testTitle}"    Run Keyword And Continue On Failure    getAclHitstatistics    ${forwardAppIdList}[0]
        ...    ELSE    Run Keyword And Continue On Failure    getAclHitstatistics    ${forwardAppIdList}[1]
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${tx}[1]
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
    END
    Comment    删除初始转发规则
    undoFiveTupleByRCP    ${forwardAppIdList}

mpls_add
    [Documentation]    1、按照excel下发规则，发送相应的背景流+命中流，遍历一层、二层、三层、四层mpls匹配
    ...    2、 将规则绑定入口组，发送不在入口组但是匹配规则的报文测试是否基于入口组
    ...    //
    ...    2026.6.12修改规则appid，已明确一个appid的规则已经阻断后，再下发该appid的规则，不进行限量处理（明确现场不会用该场景）目前vlan和mpls都只识别2层，命令行可以配置4层&3层
    [Tags]    cli
    log    测试放行用例
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    MPLS_ADD
    open excel    ${ImportFilepath}/${excelName}
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    FOR    ${row}    IN RANGE    2    6
        log    第${row}行循环测试
        comment    获取相关内容
        ${rulePre}    read cell data by name    ${sheetName}    A${row}
        ${appId}    read cell data by name    ${sheetName}    B${row}
        ${total}    read cell data by name    ${sheetName}    C${row}
        ${time}    read cell data by name    ${sheetName}    D${row}
        ${startEndGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    H${row}
        ${backPcapFile}    read cell data by name    ${sheetName}    I${row}
        ${hitPcapFile}    read cell data by name    ${sheetName}    J${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    K${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    L${row}
        ${ruleSuf}=    Run Keyword If    ${total} != 0    Set Variable    action ${action_info} outgroup_f ${outgroup_fId_1} app_id ${appId} hit_statistics true total_limit_num ${total}m
        ...    ELSE IF    ${time} != 0    Set Variable    action ${action_info} outgroup_f ${outgroup_fId_1} app_id ${appId} hit_statistics true limit_num ${time}m/1m
        ...    ELSE    ${EMPTY}
        ${acl_all}    catenate    ${rulePre}    ${ruleSuf}
        New Connection Custom
        telnet.write    ${acl_all}
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    should not contain    ${info}    ERROR
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        ${backPcap}    makePcap    ${0}    ${iniPacketFileName}    ${backPcapFile}
        ${hitPcap}    makePcap    ${0}    ${iniPacketFileName}    ${hitPcapFile}
        log    ${backPcap}
        log    ${hitPcap}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    mpls_${row}_back    ${backPcap}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    getAclHitstatistics    ${appId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    mpls_${row}_hit    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${appId}
        Run Keyword And Continue On Failure    Should Be True    ${hitCount}<=${inByte}    业务流的hitCount大等设备总接收
        Run Keyword And Continue On Failure    Should Be True    ${hitCount}>=${outByte}    业务流的hitCount小于设备的txbyte
        comment    校验阻断后的效果（下面6行）
        New Connection Custom
        telnet.write    show acl all
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword If    "${total}" !="0" or "${time}" != "0"    Run Keyword And Continue On Failure    Should not Contain    ${info}    action forward    阻断后，规则中包含forward
        ${rx}    ${tx}    Run Keyword If    "${total}" !="0" or "${time}" != "0"    tcpreplayAndTcpdump    mpls_${row}_hit_after_drop    ${hitPcap}    0    10
        Run Keyword If    "${total}" !="0" or "${time}" != "0"    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    阻断后还能输出
    END
    New Connection Custom
    telnet.write    undo acl all
    ${info}    telnet.read until    ${userName1}(config)#
    comment    测试规则是否支持基于入口组，配置规则基于背景入口组
    FOR    ${row}    IN RANGE    2    6
        log    第${row}行循环测试
        comment    获取相关内容
        ${rulePre}    read cell data by name    ${sheetName}    A${row}
        ${appId}    read cell data by name    ${sheetName}    B${row}
        ${total}    read cell data by name    ${sheetName}    C${row}
        ${time}    read cell data by name    ${sheetName}    D${row}
        ${startEndGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    H${row}
        ${backPcapFile}    read cell data by name    ${sheetName}    I${row}
        ${hitPcapFile}    read cell data by name    ${sheetName}    J${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    K${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    L${row}
        ${ruleSuf}=    Run Keyword If    ${total} != 0    Set Variable    ingroup ${ingroup_back_id} \ \ \ \ action ${action_info} outgroup_f ${outgroup_fId_1} app_id ${appId} hit_statistics true total_limit_num ${total}m
        ...    ELSE IF    ${time} != 0    Set Variable    ingroup ${ingroup_back_id} \ \ action ${action_info} outgroup_f ${outgroup_fId_1} app_id ${appId} hit_statistics true limit_num ${time}m/1m
        ...    ELSE    ${EMPTY}
        ${acl_all}    catenate    ${rulePre}    ${ruleSuf}
        New Connection Custom
        telnet.write    ${acl_all}
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    should not contain    ${info}    ERROR
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打背景流（匹配规则但是不在入口组内)、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${hitPcap}    makePcap    ${1}    ${iniPacketFileName}    ${hitPcapFile}
        ${rx}    ${tx}    tcpreplayAndTcpdump    mpls_${row}_back    ${hitPcap}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    不匹配入口组但匹配规则有输出
        ${hitCount}    getAclHitstatistics    ${appId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
    END
    New Connection Custom
    telnet.write    undo acl all
    ${info}    telnet.read until    ${userName1}(config)#
    [Teardown]

mpls_modify
    [Tags]    cli
    log    测试放行用例
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    MPLS_MODIFY
    open excel    ${ImportFilepath}/${excelName}
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${rx_before}    Set Variable    ${0}
    ${tx_before}=    create list    0    ${0}
    ${ingroup_member}    create list    @{inportId}
    ${ingroup_member_num}    Get Length    ${ingroup_member}    #计算串接时倍数
    comment    测试前清楚计数，后续打流均未清除计数
    New Connection Custom
    telnet.write    clear statistics all
    ${info}    telnet.read until    ${userName1}(config)#
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        log    第${row}行循环测试
        comment    获取相关内容
        ${rulePre}    read cell data by name    ${sheetName}    A${row}
        ${appId}    read cell data by name    ${sheetName}    B${row}
        ${total}    read cell data by name    ${sheetName}    C${row}
        ${time}    read cell data by name    ${sheetName}    D${row}
        ${startEndGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${Next}    read cell data by name    ${sheetName}    H${row}
        ${iniPacketFileName}    read cell data by name    ${sheetName}    I${row}
        ${hitPcapFile}    read cell data by name    ${sheetName}    J${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    K${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    L${row}
        ${total}    Evaluate    ${total}*${ingroup_member_num}
        ${time}    Evaluate    ${time}*${ingroup_member_num}
        ${ruleSuf}=    Run Keyword If    ${total} != 0    Set Variable    ingroup ${ingroupId} \ action ${action_info} outgroup_f ${outgroup_fId_1} app_id ${appId} hit_statistics true total_limit_num ${total}m
        ...    ELSE IF    ${time} != 0    Set Variable    ingroup ${ingroupId} \ action ${action_info} outgroup_f ${outgroup_fId_1} app_id ${appId} hit_statistics true limit_num ${time}m/1m
        ...    ELSE    ${EMPTY}
        ${acl_all}    catenate    ${rulePre}    ${ruleSuf}
        New Connection Custom
        telnet.write    ${acl_all}
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword And Continue On Failure    should not contain    ${info}    ERROR
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        ${hitPcap}    Run Keyword If    "${hitPcapFile}" != ""    makePcap    ${0}    ${iniPacketFileName}    ${hitPcapFile}
        log    ${hitPcap}
        ${rx}    ${tx}    Run Keyword If    "${hitPcapFile}" != ""    tcpreplayAndTcpdump    mpls_${row}_modify_hit    ${hitPcap}    ${startFlowSpeed}    ${startFlowTime}    0    0
        ${rx_before}    Run Keyword If    "${Next}" == "yes"    Evaluate    ${rx_before} + ${rx}
        ...    ELSE    Set Variable    ${rx_before}
        ${tx_before}    Run Keyword If    "${Next}" == "yes"    Evaluate    [int(x) + int(y) for x, y in zip(${tx_before}, ${tx})]
        ...    ELSE    Set Variable    ${tx_before}
        Continue For Loop If    "${Next}" != ""
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${${tx}[0]+${tx_before}[0]}    ${${rx}+${rx_before}}
        ${hitCount}    getAclHitstatistics    ${appId}
        Run Keyword And Continue On Failure    Should Be True    ${hitCount}<=${inByte}    业务流的hitCount大等设备总接收
        #    Run Keyword And Continue On Failure    Should Be True    ${hitCount}>=${outByte}    业务流的hitCount小于设备的txbyte
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${tx}[0]
        New Connection Custom
        telnet.write    show acl all
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword If    "${total}" !="0" or "${time}" != "0"    Run Keyword And Continue On Failure    Should not Contain    ${info}    action forward    阻断后，规则中包含forward
        telnet.write    undo acl all
        ${info}    telnet.read until    ${userName1}(config)#
        ${rx_before}    Set Variable    ${0}
        ${tx_before}=    create list    0    ${0}
        telnet.write    clear statistics all
    END

rcp_add_del_fivetuple_new
    [Documentation]    五元组下发遍历以下8种情况：
    ...    纯a、纯b、纯a&纯b、2a&2b、1a&2b、2a&1b、2a、2b
    ...
    ...    用例程序步骤：
    ...
    ...    1.打开exec了表格
    ...    2.设置初始参数：totalAppIdList,expectRespondCode
    ...    3.按照excel中ADD_FiveTuple表格的行数进行循环
    ...    a.获取相关参数：规则配置文件名，规则配置title,包配置文件名，包配置title，保存pcapfile标识，打流速率，打流时间
    ...    b.按照a中获取的信息通过rcp进行规则下发，且根据返回判断规则是否下发成功，获取对应的ruleid
    ...    c.通过show acl all获取当前acl信息
    ...    d.根据a中信息，进行背景和业务的pcapfile文件的生成
    ...    e.打e中生成的背景pcapfile
    ...    f.校验仪表的tx=设备rx,设备tx=仪表rx，以及仪表rx=0
    ...    g.获取规则中标统计，且中标统计为0
    ...    h.打e中生成的业务pcapfile，且把设备输出保存outpcapfile
    ...    i.校验仪表的tx=设备rx,设备tx=仪表rx，以及仪表rx!=0
    ...    j.获取规则中标统计，且中标统计=仪表的tx
    ...    k.根据c中的业务pcap和i中的outpcapfile生成hash值，对源和设备输出内容进行比较
    ...    l.通过rcp删除规则
    ...    n.打流验证规则是否正常删除
    ...    m.通过show acl all获取当前acl信息
    [Tags]    rcp
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    ADD_FiveTuple_NEW
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${expectRespondCode}    Set Variable    01
    ${stream_name_pre}=    set variable    ${ssh_server_raw_pcap_path}FiveTuple_packet/
    comment    按照excel中的行为单位进行循环测试
    #    ${${countRow}-1}
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${hitpacket}    read cell data by name    ${sheetName}    H${row}
        ${backpacket}    read cell data by name    ${sheetName}    I${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    J${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    K${row}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_del_fivetuple_${row}_back    ${stream_name_pre}${backpacket}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_fivetuple_${row}_hit    ${stream_name_pre}${hitpacket}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${inByte}    业务流的hitCount不等于设备总输入
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}    FiveTuple_packet/${hitpacket}
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    interface_add_fivetuple_${row}_hit.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Should Be True    ${hashResult}    包内容检查错误，仪表发送报文不等于设备输出的报文内容
        Comment    测试五元组规则删除
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    delete_fivetuple    ${ruleId}    ${expectRespondCode}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        comment    打删除前名字流来判断是否无法命中，规则被删除
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_fivetuple_${row}_afterdel    FiveTuple_packet/${hitpacket}    0    0
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    规则删除后仍有命中
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
    END

rcp_modify_rule_fivetuple_new
    [Tags]    rcp
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    MODIFY_FiveTuple_NEW
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${expectRespondCode}    Set Variable    01
    ${AppIdList}    Create List
    ${ruleId}    Set Variable    89628
    ${stream_name_pre}=    set variable    ${ssh_server_raw_pcap_path}FiveTuple_packet/
    comment    按照excel中的行为单位进行循环测试
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${hitpacket}    read cell data by name    ${sheetName}    H${row}
        ${backpacket}    read cell data by name    ${sheetName}    I${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    J${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    K${row}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword And Continue On Failure    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        Run Keyword If    '${hitpacket}' == 'no'    Append To List    ${AppIdList}    ${ruleId}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Continue For Loop If    '${hitpacket}' == 'no'
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_modify_fivetuple_${row}_back    ${stream_name_pre}${backpacket}    0    10
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_modify_fivetuple_${row}_hit    ${stream_name_pre}${hitpacket}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${outByte}    业务流的hitCount不等于设备总发送
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}    FiveTuple_packet/${hitpacket}
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    interface_modify_fivetuple_${row}_hit.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Should Be True    ${hashResult}    包内容检查错误，仪表发送报文不等于设备输出的报文内容
    END
    Comment    删除规则
    undoFiveTupleByRCP    ${AppIdList}

rcp_modify_rule_fivetuple_addfd
    [Documentation]    五元组v4/v6累积放行量测试（bj现场用例）：
    ...    1、下发规则
    ...    2、修改元组
    ...    3、修改限量
    ...    4、修改限时
    ...
    ...    注意：
    ...    1、修改后不清除计数，通过比较设备计数=放行量表示累加
    ...    2、addOrModify标识2时，保存appid，通过修改同一appid累加放行量
    [Tags]    rcp
    log    测试放行用例
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    MODIFY_FiveTuple_addfd
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${totalAcl}    Set Variable    0
    ${totalAppIdList}    Create List
    ${expectRespondCode}    Set Variable    01
    ${ruleId}    Set Variable    ${EMPTY}
    ${stream_name_pre}=    set variable    ${ssh_server_raw_pcap_path}FiveTuple_packet/
    comment    按照excel中的行为单位进行循环测试
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        log    第${row}行循环测试
        comment    获取相关内容
        ${configFileName}    read cell data by name    ${sheetName}    A${row}
        ${ruleTitle}    read cell data by name    ${sheetName}    B${row}
        ${addOrModify}    read cell data by name    ${sheetName}    C${row}
        ${hitpacket}    read cell data by name    ${sheetName}    D${row}
        ${savePcapfileFlag}    read cell data by name    ${sheetName}    E${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    F${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    G${row}
        ${expectTotalNum}    read cell data by name    ${sheetName}    H${row}
        ${expectDayNum}    read cell data by name    ${sheetName}    I${row}
        ${expectTotalTime}    read cell data by name    ${sheetName}    J${row}
        ${actionTime}    read cell data by name    ${sheetName}    K${row}
        ${clearStatistics}    read cell data by name    ${sheetName}    L${row}
        ${addOrModifyNextRow}    Run Keyword If    ${row} == ${countRow}    Set Variable    03
        ...    ELSE    read cell data by name    ${sheetName}    C${${row}+1}
        comment    下发业务配置
        ${expectTotalNumBit}    evaluate    ${expectTotalNum}*1024*1024
        ${expectDayNumBit}    evaluate    ${expectDayNum}*1024*1024
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    ${actionTime}
        ${endTimeSysTmp}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${expectTotalTime}
        ${startTimeSysTmp}    Run Keyword If    "${expectTotalTime}" == "0"    Set Variable    0
        ...    ELSE    Set Variable    ${startTimeSys}
        ${endTimeSys}    Run Keyword If    "${expectTotalTime}" == "0"    Set Variable    0
        ...    ELSE    Set Variable    ${endTimeSysTmp}
        changeConfigOptionValue    ${configFileName}    ${ruleTitle}    total    ${expectTotalNumBit}
        changeConfigOptionValue    ${configFileName}    ${ruleTitle}    day    ${expectDayNumBit}
        changeConfigOptionValue    ${configFileName}    ${ruleTitle}    starttime    ${startTimeSysTmp}
        changeConfigOptionValue    ${configFileName}    ${ruleTitle}    endtime    ${endTimeSys}
        ${savedRuleId}    Run Keyword If    "${addOrModify}"=="02"    Set Variable    ${ruleId}
        ...    ELSE    Set Variable    ${EMPTY}
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}
        ...    Run Keyword If    "${addOrModify}"=="02"
        ...    addOrModifyOrDrop    ${configFileName}    ${ruleTitle}    ruleId=${savedRuleId}
        ...    ELSE
        ...    addOrModifyOrDrop    ${configFileName}    ${ruleTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${configFileName}    ${ruleTitle}    request    ${requestBody}
        Append To List    ${totalAppIdList}    ${ruleId}
        comment    通过rcp查询规则是否正常下发
        ${queryRuleId}    Set Variable If    "${addOrModify}"=="02"    ${savedRuleId}    ${ruleId}
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew_fivetuple    ${queryRuleId}    ${configFileName}    ${ruleTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Run Keyword If    "${addOrModify}"=='01'    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP新增规则查询异常
        Run Keyword And Continue On Failure    Run Keyword If    "${addOrModify}"=='01'    Should Be Equal As Strings    ${expect_respond}[-96:-80]    ${exactRespond}[-96:-80]    RCP新增规则应答码异常
        Run Keyword And Continue On Failure    Run Keyword If    "${addOrModify}"=='02'    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP修改规则查询异常
        Run Keyword And Continue On Failure    Run Keyword If    "${addOrModify}"=='02'    Should Be Equal As Strings    ${expect_respond}[-48:]    ${exactRespond}[-48:]    RCP修改规则查询异常
        ${result}    Run Keyword If    "${addOrModify}"=='02'    Hex To Int    ${exactRespond}[-64:-48]
        Run Keyword And Continue On Failure    Run Keyword If    "${addOrModify}"=='02'    Should Be True    ${result}<=2
        comment    通过命令行查询rcp下发规则是否正常
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    ${savePcapfileFlag}_${row}_hit    ${stream_name_pre}${hitpacket}    ${startFlowSpeed}    ${startFlowTime}    clearStatistics=${clearStatistics}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    00    00
        ${hitCount}    Run Keyword If    "${expectTotalTime}" == "0" and "${expectTotalNum}" == "0"    getAclHitstatistics    ${totalAppIdList}
        ...    ELSE    Set Variable    1
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${hitCount}    ${0}    业务流的hitCount等于0    #    Run Keyword If    "${expectTotalTime}" != "0"    checkNumOrTimeResult    ${savePcapfileFlag}_${row}_hit.pcap    ${expectTotalNum}    ${expectTotalTime}    ${startFlowSpeed}    0    ${wuCha}    # ELSE IF
        ...    # "${expectTotalNum}" != "0"    checkNumOrTimeResult    ${savePcapfileFlag}_${row}_hit.pcap    ${expectTotalNum}    0    ${startFlowSpeed}    1    ${wuCha}
        comment    打流后查询规则计数
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew_fivetuple    ${queryruleId}    ${configFileName}    ${ruleTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    打流后RCP查询规则异常
        ${result_total}    Hex To Int    ${exactRespond}[-96:-80]
        Run Keyword If    "${expectTotalNum}" != "0"    Run Keyword And Continue On Failure    Should Be True    ${result_total}==${outByte}    放行总量与设备输出字节数不匹配
        ${result_day}    Hex To Int    ${exactRespond}[-80:-64]
        Run Keyword If    "${expectTotalNum}" != "0"    Run Keyword And Continue On Failure    Should Be True    ${result_day}==${outByte}    月内放行量与设备输出字节数不匹配
        ${result_time}    Hex To Int    ${exactRespond}[-64:-48]
        Run Keyword And Continue On Failure    Should Be True    ${result_time}!=0    放行时间为0
        comment    校验阻断后的效果（下面6行）
        New Connection Custom
        telnet.write    show acl all
        ${info}    telnet.read until    ${userName1}(config)#
        Run Keyword If    "${expectTotalTime}" != "0"    Run Keyword And Continue On Failure    Should Not Contain    ${info}    action forward    阻断后，规则中包含forward
        ${rx}    ${tx}    Run Keyword If    "${expectTotalTime}" != "0"    tcpreplayAndTcpdump    ${savePcapfileFlag}_${row}_hit_after_drop    ${stream_name_pre}${hitpacket}    0    0    clearStatistics=${clearStatistics}
        Run Keyword If    "${expectTotalTime}" != "0"    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    阻断后还能输出
        ${totalAppIdList}    Run Keyword If    '${addOrModifyNextRow}' == '03' or ${row} == 5    Create List
        ...    ELSE    Create List    ${ruleId}
        ${questBody}    ${expectRespond}    ${exactRespond}    ${appid}    Run Keyword If    '${addOrModifyNextRow}' == '03' or ${row} == 5    delete    ${ruleId}    ${expectRespondCode}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectRespond}    ${exactRespond}    rcp删除规则失败
    END

rcp_block_fivetuple_new
    [Tags]    rcp
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    BLOCK_FiveTuple_NEW
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${forwardAppIdList}    Create List
    ${expectRespondCode}    Set Variable    01
    ${stream_name_pre}=    set variable    ${ssh_server_raw_pcap_path}FiveTuple_packet/
    comment    按照excel中的行为单位进行循环测试
    FOR    ${row}    IN RANGE    4    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${hitpacket}    read cell data by name    ${sheetName}    H${row}
        ${backpacket}    read cell data by name    ${sheetName}    I${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    J${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    K${row}
        comment    规则下发
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword And Continue On Failure    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        New Connection Custom
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打背景流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计=0)，背景流：不匹配阻断规则但能匹配初始转发规则
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_block_fivetuple_${row}_back    ${stream_name_pre}${backpacket}    0    0
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}[0]
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    阻断规则的背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且tx=0；2、仪表rx=0；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_block_fivetuple_${row}_hit    ${stream_name_pre}${hitpacket}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    阻断规则的流量有输出
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${inByte}    业务流的hitCount不等于设备总接收
        Comment    测试阻断五元组规则删除
        delete_fivetuple    ${ruleId}    ${expectRespondCode}
        comment    打删除前命中流来判断是否无法命中，规则被删除
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_fivetuple_${row}_afterdel    ${stream_name_pre}${hitpacket}    0    0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
    END
    Comment    删除初始转发规则
    undoFiveTupleByRCP    ${forwardAppIdList}

rcp_query_fivetuple_new
    [Tags]    rcp
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    QUERY_FiveTuple _NEW
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${expectRespondCode}    Set Variable    01
    comment    按照excel中的行为单位进行循环测试
    #    ${${countRow}-1}
    ${appid_list}    Create List
    ${id_out}    Create Dictionary
    ${stream_name_pre}=    set variable    ${ssh_server_raw_pcap_path}FiveTuple_packet/
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${hitPcapname}    read cell data by name    ${sheetName}    H${row}
        ${backPcapname}    read cell data by name    ${sheetName}    I${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    J${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    K${row}
        ${drop_or_no}    read cell data by name    ${sheetName}    L${row}
        ${packet_size}    read cell data by name    ${sheetName}    M${row}
        comment    对对应的ini配置文件的限量信息进行设置
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    50
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        ${startTimeSys_fin}    Set Variable If    ${startEndTimeGap} == 0    ${EMPTY}    ${startTimeSys}
        ${endTimeSys_fin}    Set Variable If    ${startEndTimeGap} == 0    ${EMPTY}    ${endTimeSys}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys_fin}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys_fin}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        ${packet_count}    parser_pcapfile    ${localRawPcapPath}FiveTuple_packet/${hitPcapname}
        log    ${packet_count}
        comment    根据预期输出总量，计算需要打流次数
        ${times}    evaluate    math.ceil(${expectOutTotal}*1024*1024/((${packet_size}+4)*${packet_count}))    math
        comment    第一次打流进行校验
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_${row}_number_1_hit    ${stream_name_pre}/${hitPcapname}    0    ${${times}-1}t
        sleep    10
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should \ Be Equal As Integers    ${hitCount}    ${outByte}
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew_fivetuple    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-48:-32]    #SNInumber
        Run Keyword And Continue On Failure    Should Be True    ${result}==0
        ${result}    Hex To Int    ${exactRespond}[-32:-16]    #https流量
        Run Keyword And Continue On Failure    Should Be True    ${result}==0
        #    Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-16:]    #nohttps
        Run Keyword And Continue On Failure    Should Be True    ${result}==0
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Run Keyword If    ${times} == 0    Run Keyword And Continue On Failure    Should Contain    ${info}    action drop    非https的阈值未生效
        ${exactTime}    ${exactNum}    ${firstPacketUnixTime}    Run Keyword If    ${times} == 0    checkNumOrTimeResult    interface_add_${row}_number_1_hit.pcap    0    0    1    2
        ${result}    Run Keyword If    ${times} == 0    Evaluate    abs(${exactTime}-${expectOutTime})
        Run Keyword If    ${times} == 0    Should Be True    0<=${result}<3
        Continue For Loop If    ${times} == 0
        comment    第2次打流，速率要慢
        ${rx1}    ${tx1}    tcpreplayAndTcpdump    interface_add_${row}_number_2_hit    ${stream_name_pre}/${hitPcapname}    0.1    1t
        comment    内容校验
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx1}    ${0}    业务流仪表的rx等于0
        ${inPkt1}    ${inByte1}    ${outPkt1}    ${outByte1}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx1}[0]    ${rx1}
        Run Keyword If    ${drop_or_no}== 0    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inPkt1}    ${outPkt1}
        ...    ELSE    Run Keyword And Continue On Failure    should be true    ${inPkt1}>=${outPkt1}    阻断打流，输入报个数小于输出报个数
        Run Keyword If    ${drop_or_no}== 0    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inByte1}    ${outByte1}
        ...    ELSE    Run Keyword And Continue On Failure    should be true    ${inByte1}>=${outByte1}    阻断打流，输入字节小于输出输出字节
        ${hitCount1}    getAclHitstatistics    ${ruleId}
        Run Keyword If    ${drop_or_no}== 0    Run Keyword And Continue On Failure    Should \ Be Equal As Integers    ${hitCount1}    ${outByte1}    #    # ELSE    Run Keyword And Continue On Failure    should be true    ${hitCount1}>=${outByte1}    阻断打流，命中字节数小于输出
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRuleNew_fivetuple    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword If    ${drop_or_no}== 1    Run Keyword And Continue On Failure    Should Be True    ${${outByte}+${outByte1}-${result}}<=${outByte1}
        ...    ELSE    Run Keyword And Continue On Failure    Should Be True    ${result}==${${hitCount1}+${hitCount}}
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword If    ${drop_or_no}== 1    Run Keyword And Continue On Failure    Should Be True    ${${outByte}+${outByte1}-${result}}<=${outByte1}
        ...    ELSE    Run Keyword And Continue On Failure    Should Be True    ${result}==${${hitCount1}+${hitCount}}
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-48:-32]    #SNInumber
        Run Keyword And Continue On Failure    Should Be True    ${result}==0
        ${result}    Hex To Int    ${exactRespond}[-32:-16]    #https流量
        Run Keyword And Continue On Failure    Should Be True    ${result}==0    #    Run Keyword If    ${drop_or_no}== 1    Run Keyword And Continue On Failure    Should Be True    ${${outByte}+${outByte1}-${result}}<=${outByte1}    # ELSE    Run Keyword And Continue On Failure    Should Be True    ${result}==${${hitCount1}+${hitCount}}
        ${result}    Hex To Int    ${exactRespond}[-16:]    #nohttps
        Run Keyword And Continue On Failure    Should Be True    ${result}==0
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Run Keyword If    ${drop_or_no}== 1    Run Keyword And Continue On Failure    Should Contain    ${info}    action drop
        ...    ELSE    Run Keyword And Continue On Failure    Should \ not Contain    ${info}    action drop
        undo acl all
    #    ${ruleId}    Create List    ${ruleId}
    #    undoFiveTupleByRCP    ${ruleId}
    END

rcp_add_del_L2
    [Tags]    rcp
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    ADD_L2
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${expectRespondCode}    Set Variable    01
    ${stream_name_pre}=    set variable    ${ssh_server_raw_pcap_path}L2/
    comment    按照excel中的行为单位进行循环测试
    #    ${${countRow}-1}
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${hitpacket}    read cell data by name    ${sheetName}    H${row}
        ${backpacket}    read cell data by name    ${sheetName}    I${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    J${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    K${row}
        ${packet_size}    read cell data by name    ${sheetName}    M${row}
        comment    规则下发
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    inGroup    ${ingroupId}
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_del_L2_${row}_back    ${stream_name_pre}${backpacket}    0    0
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_del_L2_${row}_hit    ${stream_name_pre}${hitpacket}    0    0
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${inByte}    业务流的hitCount不等于设备总输入
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}    L2/${hitpacket}
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    interface_add_del_L2_${row}_hit.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Should Be True    ${hashResult}    包内容检查错误，仪表发送报文不等于设备输出的报文内容
        Comment    测试L2规则删除
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    delete_L2    ${ruleId}    ${expectRespondCode}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp删除规则失败
        comment    打删除前名字流来判断是否无法命中，规则被删除
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_add_L2_${row}_afterdel    L2/${hitpacket}    0    0
        compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    规则删除后仍有命中
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
    END

rcp_modify_L2
    [Tags]    rcp
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    MODIFY_L2
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${expectRespondCode}    Set Variable    01
    ${AppIdList}    Create List
    ${ruleId}    Set Variable    89628
    ${stream_name_pre}=    set variable    ${ssh_server_raw_pcap_path}L2/
    comment    按照excel中的行为单位进行循环测试
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${hitpacket}    read cell data by name    ${sheetName}    H${row}
        ${backpacket}    read cell data by name    ${sheetName}    I${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    J${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    K${row}
        ${dropFlag}    read cell data by name    ${sheetName}    L${row}
        comment    规则下发
        Run Keyword If    ${totalLimit}!= 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        Run Keyword If    ${timeLimit}!= 0    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword If    'add' in '${testTitle}'    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}    ${ruleId}
        ...    ELSE    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}    ${AppIdList}[0]
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        Run Keyword If    'add' in '${testTitle}'    Append To List    ${AppIdList}    ${ruleId}
        log    ${AppIdList}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        #    Continue For Loop If    '${hitpacket}' == 'no'
        comment    打背景流、校验结果(1、设备rx不为0，tx为0；2、仪表rx为0；3、中标统计为0)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_modify_L2_${row}_back    ${stream_name_pre}${backpacket}    0    10
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword If    'del' not in '${testTitle}'    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}
        ...    ELSE    Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}
        ${hitCount}    Run Keyword If    'del' not in '${testTitle}'    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        ...    ELSE    Run Keyword And Continue On Failure    getAclHitstatistics    ${AppIdList}[1]
        Run Keyword If    'del' not in '${testTitle}'    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流有hitCount计数
        ...    ELSE    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${outByte}
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_modify_L2_${row}_hit    ${hitpacket}    ${startFlowSpeed}    ${startFlowTime}    tcpreplayPath=${stream_name_pre}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        Run Keyword If    ${dropFlag}== 0    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${outByte}    业务流的hitCount不等于设备总发送
        ...    ELSE    Run Keyword And Continue On Failure    should be true    ${inByte}>=${hitCount}
        Run Keyword If    ${dropFlag}== 0    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inByte}    ${outByte}    业务流的输入不等于设备总发送
        ...    ELSE    Run Keyword And Continue On Failure    should be true    ${inByte}>${outByte}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Run Keyword If    ${dropFlag}== 1    Run Keyword And Continue On Failure    Should Contain    ${info}    action drop
        ...    ELSE    Run Keyword And Continue On Failure    Should \ not Contain    ${info}    action drop
        Continue For Loop If    ${dropFlag}== 1
        comment    检测报文内容
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}L2/    ${hitpacket}
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    interface_modify_L2_${row}_hit.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Should Be True    ${hashResult}    包内容检查错误，仪表发送报文不等于设备输出的报文内容
    END
    Comment    删除规则
    undoFiveTupleByRCP    ${AppIdList}

rcp_block_L2
    [Tags]    rcp
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    BLOCK_L2
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${forwardAppIdList}    Create List
    ${expectRespondCode}    Set Variable    01
    ${stream_name_pre}=    set variable    ${ssh_server_raw_pcap_path}L2/
    comment    按照excel中的前两行下发初始转发规则
    FOR    ${row}    IN RANGE    2    5
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${hitpacket}    read cell data by name    ${sheetName}    H${row}
        ${backpacket}    read cell data by name    ${sheetName}    I${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    J${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    K${row}
        comment    规则下发
        Run Keyword If    'L2' in '${testTitle}'    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    inGroup    ${ingroupId}
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId_fd}    Run Keyword And Continue On Failure    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        Append To List    ${forwardAppIdList}    ${ruleId_fd}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打业务流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_block_L2_${row}_fd    ${hitpacket}    ${startFlowSpeed}    ${startFlowTime}    tcpreplayPath=${stream_name_pre}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId_fd}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${outByte}    业务流的hitCount不等于设备总发送
    END
    comment    按照excel中的行为单位进行循环测试
    FOR    ${row}    IN RANGE    5    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${hitpacket}    read cell data by name    ${sheetName}    H${row}
        ${backpacket}    read cell data by name    ${sheetName}    I${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    J${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    K${row}
        comment    规则下发
        Run Keyword If    'L2' in '${testTitle}'    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    inGroup    ${ingroupId}
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    Run Keyword If    'changePri' not in '${testTitle}'    Run Keyword And Continue On Failure    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        ...    ELSE    Run Keyword And Continue On Failure    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}    ${ruleId}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        comment    打背景流、校验结果(1、设备rx不为0，且rx=tx；2、仪表rx=设备tx；3，中标统计=0)，背景流：不匹配阻断规则但能匹配初始转发规则
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_block_L2_${row}_back    ${backpacket}    ${startFlowSpeed}    ${startFlowTime}    tcpreplayPath=${stream_name_pre}
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${hitCount}    Run Keyword If    'v4' in '${backpacket}'    getAclHitstatistics    ${forwardAppIdList}[2]
        ...    ELSE    getAclHitstatistics    ${forwardAppIdList}[1]
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${inByte}    L2阻断规则的背景流(匹配组合或五元组)异常
        comment    打业务流、校验结果(1、设备rx不为0，且tx=0；2、仪表rx=0；3，中标统计等于rx)
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_block_L2_${row}_hit    ${hitpacket}    ${startFlowSpeed}    ${startFlowTime}    tcpreplayPath=${stream_name_pre}
        Run Keyword If    'changePri' not in '${testTitle}'    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    阻断规则的流量有输出
        ...    ELSE    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${tx}[0]    未命中或匹配异常，高优先级L2放行规则
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    Run Keyword If    'changePri' not in '${testTitle}'    Run Keyword And Continue On Failure    getAclHitstatistics    ${ruleId}
        ...    ELSE    Run Keyword And Continue On Failure    getAclHitstatistics    ${forwardAppIdList}[0]
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${inByte}    业务流的hitCount不等于设备总接收
        Continue For Loop If    'changePri' not in '${testTitle}'
        Comment    测试阻断l2规则删除
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    delete_L2    ${ruleId}    ${expectRespondCode}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp删除规则失败
    END
    Comment    删除初始转发规则
    undoFiveTupleByRCP    ${forwardAppIdList}

rcp_query_L2
    [Tags]    rcp
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    ADD_L2
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${expectRespondCode}    Set Variable    01
    ${stream_name_pre}=    set variable    ${ssh_server_raw_pcap_path}L2/
    comment    按照excel中的行为单位进行循环测试
    #    ${${countRow}-1}
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        ${totalLimit}    read cell data by name    ${sheetName}    C${row}
        ${timeLimit}    read cell data by name    ${sheetName}    D${row}
        ${startEndTimeGap}    read cell data by name    ${sheetName}    E${row}
        ${expectOutTotal}    read cell data by name    ${sheetName}    F${row}
        ${expectOutTime}    read cell data by name    ${sheetName}    G${row}
        ${hitpacket}    read cell data by name    ${sheetName}    H${row}
        ${backpacket}    read cell data by name    ${sheetName}    I${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    J${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    K${row}
        ${packet_size}    read cell data by name    ${sheetName}    L${row}
        ${drop_or_no}    read cell data by name    ${sheetName}    M${row}
        comment    规则下发
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    inGroup    ${ingroupId}
        ${systemTime}    get_cli_time
        ${startTimeSys}    cli_time_epoc_switchRcp    ${systemTime}    1    50
        ${endTimeSys}    cli_time_epoc_switchRcp    ${startTimeSys}    1    ${startEndTimeGap}
        ${startTimeSys_fin}    Set Variable If    ${startEndTimeGap} == 0    ${EMPTY}    ${startTimeSys}
        ${endTimeSys_fin}    Set Variable If    ${startEndTimeGap} == 0    ${EMPTY}    ${endTimeSys}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    starttime    ${startTimeSys_fin}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    endtime    ${endTimeSys_fin}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    total    ${${totalLimit}*1024*1024}
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    day    ${${timeLimit}*1024*1024}
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        ${packet_count}    parser_pcapfile    ${localRawPcapPath}L2/${hitpacket}
        log    ${packet_count}
        comment    根据预期输出总量，计算需要打流次数
        ${times}    evaluate    math.ceil(${expectOutTotal}*1024*1024/((${packet_size}+4)*${packet_count}))    math
        comment    第一次打流进行校验
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_query_L2_${row}num_1_hit    ${stream_name_pre}${hitpacket}    0    ${${times}-1}t
        sleep    10
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${ruleId}
        Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should \ Be Equal As Integers    ${hitCount}    ${outByte}
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRulenew_L2    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword If    ${times} != 0    Run Keyword And Continue On Failure    Should Be True    ${result}==${outByte}
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-48:]    #备用
        Run Keyword And Continue On Failure    Should Be True    ${result}==0
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Run Keyword If    ${times} == 0    Run Keyword And Continue On Failure    Should Contain    ${info}    action drop    非https的阈值未生效
        ${exactTime}    ${exactNum}    ${firstPacketUnixTime}    Run Keyword If    ${times} == 0    checkNumOrTimeResult    interface_query_${row}num__1_hit.pcap    0    0    1    2
        ${result}    Run Keyword If    ${times} == 0    Evaluate    abs(${exactTime}-${expectOutTime})
        Run Keyword If    ${times} == 0    Should Be True    0<=${result}<3
        Continue For Loop If    ${times} == 0
        comment    第2次打流，速率要慢
        ${rx1}    ${tx1}    tcpreplayAndTcpdump    interface_add_${row}_number_2_hit    ${stream_name_pre}${hitpacket}    0.1    1t
        comment    内容校验
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx1}    ${0}    业务流仪表的rx等于0
        ${inPkt1}    ${inByte1}    ${outPkt1}    ${outByte1}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx1}[0]    ${rx1}
        Run Keyword If    ${drop_or_no}== 0    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inPkt1}    ${outPkt1}
        ...    ELSE    Run Keyword And Continue On Failure    should be true    ${inPkt1}>=${outPkt1}    阻断打流，输入报个数小于输出报个数
        Run Keyword If    ${drop_or_no}== 0    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${inByte1}    ${outByte1}
        ...    ELSE    Run Keyword And Continue On Failure    should be true    ${inByte1}>=${outByte1}    阻断打流，输入字节小于输出输出字节
        ${hitCount1}    getAclHitstatistics    ${ruleId}
        Run Keyword If    ${drop_or_no}== 0    Run Keyword And Continue On Failure    Should \ Be Equal As Integers    ${hitCount1}    ${outByte1}    #    # ELSE    Run Keyword And Continue On Failure    should be true    ${hitCount1}>=${outByte1}    阻断打流，命中字节数小于输出
        ${request}    ${expect_respond}    ${exactRespond}    ${ruleid}    queryRulenew_L2    ${ruleId}    ${iniRcpFileName}    ${testTitle}
        log    ${expect_respond}
        log    ${exactRespond}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect_respond}[:-96]    ${exactRespond}[:-96]    RCP查询规则异常
        ${result}    Hex To Int    ${exactRespond}[-96:-80]    #放行总量
        Run Keyword If    ${drop_or_no}== 1    Run Keyword And Continue On Failure    Should Be True    ${${outByte}+${outByte1}-${result}}<=${outByte1}
        ...    ELSE    Run Keyword And Continue On Failure    Should Be True    ${result}==${${hitCount1}+${hitCount}}
        ${result}    Hex To Int    ${exactRespond}[-80:-64]    #月内放行量
        Run Keyword If    ${drop_or_no}== 1    Run Keyword And Continue On Failure    Should Be True    ${${outByte}+${outByte1}-${result}}<=${outByte1}
        ...    ELSE    Run Keyword And Continue On Failure    Should Be True    ${result}==${${hitCount1}+${hitCount}}
        ${result}    Hex To Int    ${exactRespond}[-64:-48]    #放行时间
        Run Keyword And Continue On Failure    Should Be True    ${result}!=0
        ${result}    Hex To Int    ${exactRespond}[-48:]    #备用
        Run Keyword And Continue On Failure    Should Be True    ${result}==0
        comment    cli下规则查看
        New Connection Custom
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        Run Keyword If    ${drop_or_no}== 1    Run Keyword And Continue On Failure    Should Contain    ${info}    action drop
        ...    ELSE    Run Keyword And Continue On Failure    Should \ not Contain    ${info}    action drop
        ${ruleId}    Create List    ${ruleId}
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    delete_L2    ${ruleId}    ${expectRespondCode}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp删除规则失败
    END

rcp_clear_limit
    [Documentation]    验证放行量清零的两种机制：
    ...    1. CLI主动清除：undo acl <规则类型> <内部id> reset_all_limit_num true
    ...    2. 时间边界自动清零：修改设备时间到日初/周初/月初 00:00
    ...    3.覆盖：3种规则类型(stage3_f/l2/grouped_rule) × 2种IP版本(v4/v6) × 3种限量周期(day/week/month) = 18条规则
    ...    4.每条规则的每个报文200包×300字节=60800bytes(含CRC)，总量远小于limit 5242880，不会触发阻断
    [Tags]    rcp
    [Setup]    undoAclAll
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    CLEAR_LIMIT
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    comment    初始化存储列表(对应Excel A-I列)
    @{ruleIdList}    Create List
    @{cliTypeList}    Create List
    @{testTitleList}    Create List
    @{limitTypeList}    Create List
    @{internalIdList}    Create List
    @{speedList}    Create List
    @{timeList}    Create List
    ${rcpClearLimitPcapPath}    Set Variable    ${localRawPcapPath}rcpclearlimit/
    ${sshClearLimitPath}    Set Variable    ${ssh_server_raw_pcap_path}rcpclearlimit/
    comment    记录原始时间并关闭NTP
    New Connection Custom
    ${originalTime}    getCliTime
    log    原始系统时间: ${originalTime}
    telnet.write    interface mgmt 1/1 ntpserver 0.0.0.0
    ${ntpInfo}    Telnet.Read Until    ${userName1}(config)#
    log    已关闭NTP
    comment    ===== 阶段1: 批量下发18条规则 =====
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        Continue For Loop If    '${testTitle}' == ''
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${limitType}    read cell data by name    ${sheetName}    C${row}
        ${cliType}    read cell data by name    ${sheetName}    D${row}
        ${internalId}    read cell data by name    ${sheetName}    E${row}
        ${speed}    read cell data by name    ${sheetName}    H${row}
        ${timeVal}    read cell data by name    ${sheetName}    I${row}
        log    下发规则: ${testTitle} (${cliType}/${limitType})
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    request    ${requestBody}
        Append To List    ${ruleIdList}    ${ruleId}
        Append To List    ${cliTypeList}    ${cliType}
        Append To List    ${testTitleList}    ${testTitle}
        Append To List    ${limitTypeList}    ${limitType}
        Append To List    ${internalIdList}    ${internalId}
        Append To List    ${speedList}    ${speed}
        Append To List    ${timeList}    ${timeVal}
    END
    ${ruleCount}    Get Length    ${ruleIdList}
    log    共下发${ruleCount}条规则
    comment    cli下规则查看
    telnet.write    show acl all
    ${info}    Telnet.Read Until    ${userName1}(config)#
    comment    检查是否需要重新生成pcap（pcap不存在或ini有更新）
    ${titleListStr}    Catenate    SEPARATOR=,    @{testTitleList}
    ${needRegen}    needRegenPcap    rcpClearLimit    ${titleListStr}    ${rcpClearLimitPcapPath}
    ${existFlag}    Set Variable If    ${needRegen}    0    1
    log    是否需重新生成pcap: ${needRegen} (exist=${existFlag})
    comment    生成/复用pcap（复用单个SSH连接加速上传）
    openSsh
    @{allPcaps}    Create List
    FOR    ${i}    IN RANGE    0    ${ruleCount}
        ${pcap}    makePcapFromRule    ${existFlag}    rcpClearLimit    ${testTitleList}[${i}]    ${rcpClearLimitPcapPath}
        Append To List    ${allPcaps}    ${pcap}
    END
    closeSsh
    ${pcapList}    Catenate    SEPARATOR=,    @{allPcaps}
    log    已准备全部pcap: ${pcapList}
    comment    ===== 阶段2: CLI主动清除放行量 =====
    log    ===== CLI清除阶段开始 =====
    comment    复用已生成的pcap直接打流
    ${rx}    ${tx}    tcpreplayAndTcpdump    clear_limit_cli    ${pcapList}    ${speedList}[0]    ${timeList}[0]    tcpreplayPath=${sshClearLimitPath}
    Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${tx}[0]    ${rx}    tcpreplay发送包数与tcpdump接收包数不相等
    ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
    comment    查询每条规则，验证放行量>0
    FOR    ${i}    IN RANGE    0    ${ruleCount}
        ${totalPass}    ${periodPass}    queryRcpLimit    ${ruleIdList}[${i}]    ${testTitleList}[${i}]    ${cliTypeList}[${i}]
        Run Keyword And Continue On Failure    Should Be True    ${totalPass}>0    规则${testTitleList}[${i}]放行总量应为>0，实际${totalPass}
        Run Keyword And Continue On Failure    Should Be True    ${periodPass}>0    规则${testTitleList}[${i}]周期放行量应为>0，实际${periodPass}
    END
    comment    CLI清除每条规则的放行量
    New Connection Custom
    FOR    ${i}    IN RANGE    0    ${ruleCount}
        ${cliType}    Set Variable    ${cliTypeList}[${i}]
        ${internalId}    Set Variable    ${internalIdList}[${i}]
        telnet.write    undo acl ${cliType} ${internalId} reset_all_limit_num true
        ${clearResp}    Telnet.Read Until    ${userName1}(config)#
        log    CLI清除 ${cliType} ${internalId}: ${clearResp}
    END
    Sleep    5s
    comment    再次查询，验证放行量已清零
    FOR    ${i}    IN RANGE    0    ${ruleCount}
        ${totalPass}    ${periodPass}    queryRcpLimit    ${ruleIdList}[${i}]    ${testTitleList}[${i}]    ${cliTypeList}[${i}]
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${totalPass}    ${0}    规则${testTitleList}[${i}]CLI清除后放行总量应为0，实际${totalPass}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${periodPass}    ${0}    规则${testTitleList}[${i}]CLI清除后周期放行量应为0，实际${periodPass}
    END
    log    ===== CLI清除阶段完成 =====
    comment    ===== 阶段3: 时间边界-日初清零 =====
    log    ===== 日初清零阶段开始 =====
    comment    复用pcap重新打流
    ${rx}    ${tx}    tcpreplayAndTcpdump    clear_limit_day    ${pcapList}    ${speedList}[0]    ${timeList}[0]    tcpreplayPath=${sshClearLimitPath}
    Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${tx}[0]    ${rx}    tcpreplay发送包数与tcpdump接收包数不相等
    ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
    comment    跳到明天0点
    ${currentTime}    getCliTime
    ${targetDay}    get_next_time_boundary_rcp    ${currentTime}    day
    log    当前时间: ${currentTime}, 跳到: ${targetDay}
    setSystemTime    ${targetDay}
    Sleep    3s
    comment    判断明天0点是否也是周一/月初
    &{dayBoundary}    get_date_boundary_info    ${targetDay}
    ${dayIsMonday}    Set Variable    ${dayBoundary.is_monday}
    ${dayIsMonthFirst}    Set Variable    ${dayBoundary.is_month_first}
    log    日初边界日期=${targetDay}, 是否周一=${dayIsMonday}, 是否月初=${dayIsMonthFirst}
    comment    查询验证：日限量必清零；若同时为周一则周限量清零；若同时为1号则月限量清零
    FOR    ${i}    IN RANGE    0    ${ruleCount}
        ${totalPass}    ${periodPass}    queryRcpLimit    ${ruleIdList}[${i}]    ${testTitleList}[${i}]    ${cliTypeList}[${i}]
        Run Keyword If    '${limitTypeList}[${i}]'=='day'
        ...    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${periodPass}    ${0}    日限量规则${testTitleList}[${i}]日初周期量应为0，实际${periodPass}
        ...    ELSE IF    '${limitTypeList}[${i}]'=='week' and ${dayIsMonday}==${True}
        ...    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${periodPass}    ${0}    周限量规则${testTitleList}[${i}]日初(周一)周期量应为0，实际${periodPass}
        ...    ELSE IF    '${limitTypeList}[${i}]'=='week'
        ...    Run Keyword And Continue On Failure    Should Be True    ${periodPass}>0    周限量规则${testTitleList}[${i}]日初(非周一)周期量应>0，实际${periodPass}
        ...    ELSE IF    '${limitTypeList}[${i}]'=='month' and ${dayIsMonthFirst}==${True}
        ...    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${periodPass}    ${0}    月限量规则${testTitleList}[${i}]日初(月初)周期量应为0，实际${periodPass}
        ...    ELSE
        ...    Run Keyword And Continue On Failure    Should Be True    ${periodPass}>0    月限量规则${testTitleList}[${i}]日初(非月初)周期量应>0，实际${periodPass}
    END
    comment    复用pcap再次打流，验证日限量规则重新计数
    ${rx}    ${tx}    tcpreplayAndTcpdump    clear_limit_day2    ${pcapList}    ${speedList}[0]    ${timeList}[0]    tcpreplayPath=${sshClearLimitPath}
    Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${tx}[0]    ${rx}    tcpreplay发送包数与tcpdump接收包数不相等
    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
    FOR    ${i}    IN RANGE    0    ${ruleCount}
        ${totalPass}    ${periodPass}    queryRcpLimit    ${ruleIdList}[${i}]    ${testTitleList}[${i}]    ${cliTypeList}[${i}]
        Run Keyword And Continue On Failure    Should Be True    ${periodPass}>0    日初后重新打流，规则${testTitleList}[${i}]周期量应>0，实际${periodPass}
    END
    log    ===== 日初清零阶段完成 =====
    comment    ===== 阶段4: 时间边界-周初清零 =====
    log    ===== 周初清零阶段开始 =====
    comment    复用pcap重新打流
    ${rx}    ${tx}    tcpreplayAndTcpdump    clear_limit_week    ${pcapList}    ${speedList}[0]    ${timeList}[0]    tcpreplayPath=${sshClearLimitPath}
    Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${tx}[0]    ${rx}    tcpreplay发送包数与tcpdump接收包数不相等
    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
    comment    跳到下周一0点
    ${currentTime}    getCliTime
    ${targetWeek}    get_next_time_boundary_rcp    ${currentTime}    week
    log    当前时间: ${currentTime}, 跳到: ${targetWeek}
    setSystemTime    ${targetWeek}
    Sleep    3s
    comment    判断下周一是否同时也是下月1号
    &{weekBoundary}    get_date_boundary_info    ${targetWeek}
    ${weekIsMonthFirst}    Set Variable    ${weekBoundary.is_month_first}
    log    周初边界日期=${targetWeek}, 是否月初=${weekIsMonthFirst}
    comment    查询验证：日+周限量规则清零；若周一=1号则月限量也清零，否则月限量保持
    FOR    ${i}    IN RANGE    0    ${ruleCount}
        ${totalPass}    ${periodPass}    queryRcpLimit    ${ruleIdList}[${i}]    ${testTitleList}[${i}]    ${cliTypeList}[${i}]
        Run Keyword If    ${weekIsMonthFirst}==${True}    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${periodPass}    ${0}    周初+月初规则${testTitleList}[${i}]周期量应为0，实际${periodPass}
        ...    ELSE IF    '${limitTypeList}[${i}]'=='month'
        ...    Run Keyword And Continue On Failure    Should Be True    ${periodPass}>0    月限量规则${testTitleList}[${i}]周期量应>0，实际${periodPass}
        ...    ELSE
        ...    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${periodPass}    ${0}    非月限量规则${testTitleList}[${i}]周初后周期量应为0，实际${periodPass}
    END
    comment    复用pcap再次打流，验证清零的规则重新计数
    ${rx}    ${tx}    tcpreplayAndTcpdump    clear_limit_week2    ${pcapList}    ${speedList}[0]    ${timeList}[0]    tcpreplayPath=${sshClearLimitPath}
    Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${tx}[0]    ${rx}    tcpreplay发送包数与tcpdump接收包数不相等
    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
    FOR    ${i}    IN RANGE    0    ${ruleCount}
        ${totalPass}    ${periodPass}    queryRcpLimit    ${ruleIdList}[${i}]    ${testTitleList}[${i}]    ${cliTypeList}[${i}]
        Run Keyword And Continue On Failure    Should Be True    ${periodPass}>0    周初后重新打流，规则${testTitleList}[${i}]周期量应>0，实际${periodPass}
    END
    log    ===== 周初清零阶段完成 =====
    comment    ===== 阶段5: 时间边界-月初清零 =====
    log    ===== 月初清零阶段开始 =====
    comment    复用pcap重新打流
    ${rx}    ${tx}    tcpreplayAndTcpdump    clear_limit_month    ${pcapList}    ${speedList}[0]    ${timeList}[0]    tcpreplayPath=${sshClearLimitPath}
    Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${tx}[0]    ${rx}    tcpreplay发送包数与tcpdump接收包数不相等
    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
    comment    跳到下月1号0点
    ${currentTime}    getCliTime
    ${targetMonth}    get_next_time_boundary_rcp    ${currentTime}    month
    log    当前时间: ${currentTime}, 跳到: ${targetMonth}
    setSystemTime    ${targetMonth}
    Sleep    3s
    comment    判断下月1号是否为周一
    &{monthBoundary}    get_date_boundary_info    ${targetMonth}
    ${monthIsMonday}    Set Variable    ${monthBoundary.is_monday}
    log    月初边界日期=${targetMonth}, 是否周一=${monthIsMonday}
    comment    查询验证：日+月限量规则清零；若1号=周一则周限量也清零，否则周限量保持
    FOR    ${i}    IN RANGE    0    ${ruleCount}
        ${totalPass}    ${periodPass}    queryRcpLimit    ${ruleIdList}[${i}]    ${testTitleList}[${i}]    ${cliTypeList}[${i}]
        Run Keyword If    ${monthIsMonday}==${True}    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${periodPass}    ${0}    月初+周初规则${testTitleList}[${i}]周期量应为0，实际${periodPass}
        ...    ELSE IF    '${limitTypeList}[${i}]'=='week'
        ...    Run Keyword And Continue On Failure    Should Be True    ${periodPass}>0    月初(非周一)周限量规则${testTitleList}[${i}]周期量应>0，实际${periodPass}
        ...    ELSE
        ...    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${periodPass}    ${0}    月初规则${testTitleList}[${i}]周期量应为0，实际${periodPass}
    END
    comment    复用pcap再次打流，验证清零的规则重新计数
    ${rx}    ${tx}    tcpreplayAndTcpdump    clear_limit_month2    ${pcapList}    ${speedList}[0]    ${timeList}[0]    tcpreplayPath=${sshClearLimitPath}
    Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    ${0}    业务流仪表的rx等于0
    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${tx}[0]    ${rx}    tcpreplay发送包数与tcpdump接收包数不相等
    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
    FOR    ${i}    IN RANGE    0    ${ruleCount}
        ${totalPass}    ${periodPass}    queryRcpLimit    ${ruleIdList}[${i}]    ${testTitleList}[${i}]    ${cliTypeList}[${i}]
        Run Keyword And Continue On Failure    Should Be True    ${periodPass}>0    月初后重新打流，规则${testTitleList}[${i}]周期量应>0，实际${periodPass}
    END
    log    ===== 月初清零阶段完成 =====
    comment    ===== 阶段6: 删除规则+恢复时间 =====
    log    ===== 清理阶段 =====
    comment    恢复原始时间
    New Connection Custom
    telnet.write    systemtime ${originalTime}
    ${restoreResp}    Telnet.Read Until    ${userName1}(config)#
    log    恢复系统时间: ${originalTime}
    comment    恢复NTP
    telnet.write    interface mgmt 1/1 ntpserver 192.168.4.147
    ${ntpRestore}    Telnet.Read Until    ${userName1}(config)#
    log    已恢复NTP
    Sleep    30s
    ${newTime}    getCliTime
    log    原始系统时间: ${newTime}
    [Teardown]    undoAclAll

rcp_priority
    [Documentation]    典型应用场景的优先级
    [Tags]    rcp
    [Setup]    undo acl all
    comment    打开对应的excel配置表
    ${sheetName}    Set Variable    PRIORITY
    open excel    ${ImportFilepath}/interface.xls
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${count_row}+1
    ${forwardAppIdList}    Create List
    ${expectRespondCode}    Set Variable    01
    ${stream_name_pre}=    set variable    ${ssh_server_raw_pcap_path}Pri/
    comment    配置全局优先级2内外层匹配
    New Connection Custom
    telnet.write    global priority_for_tunnel 2
    ${info}    Telnet.Read Until    ${userName1}(config)#
    log    ${info}
    comment    按照excel中下发各类优先级规则
    FOR    ${row}    IN RANGE    2    21
        comment    读取excel内容
        ${iniRcpFileName}    read cell data by name    ${sheetName}    A${row}
        ${testTitle}    read cell data by name    ${sheetName}    B${row}
        comment    规则下发
        Run Keyword If    'vlan' in '${testTitle}'    changeConfigOptionValue    ${iniRcpFileName}    ${testTitle}    inGroup    ${ingroupId}
        ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId_fd}    Run Keyword And Continue On Failure    addOrModifyOrDrop    ${iniRcpFileName}    ${testTitle}
        Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    rcp下发规则失败
        Append To List    ${forwardAppIdList}    ${ruleId_fd}
        comment    cli下规则查看
        telnet.write    show acl all
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
        telnet.write    show acl rcp
        ${info}    Telnet.Read Until    ${userName1}(config)#
        log    ${info}
    END
    comment    依次打流，验证报文匹配情况
    FOR    ${row}    IN RANGE    21    ${countRrowAdd}
        comment    读取excel内容
        ${hitpacket}    read cell data by name    ${sheetName}    C${row}
        ${rule_index}    read cell data by name    ${sheetName}    D${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    E${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    F${row}
        ${DropFlag}    read cell data by name    ${sheetName}    G${row}
        comment    打业务流、校验结果(1、设备rx不为0，且tx=0；2、仪表rx=0；3，中标统计等于rx)
        Continue For Loop If    '${hitpacket}'== ''
        ${rx}    ${tx}    tcpreplayAndTcpdump    interface_pri_${row}_hit    ${hitpacket}    ${startFlowSpeed}    ${startFlowTime}    tcpreplayPath=${stream_name_pre}
        Run Keyword If    'deny' in '${hitpacket}'    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${0}    阻断规则的流量有输出
        ...    ELSE    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${tx}[0]    未命中或匹配异常，高优先级L2放行规则
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    Run Keyword If    'no' not in '${rule_index}'    Run Keyword And Continue On Failure    getAclHitstatistics    ${forwardAppIdList}[${rule_index}]
        ...    ELSE    Run Keyword And Continue On Failure    getAclHitstatistics    ${forwardAppIdList}
        Run Keyword If    'no' not in '${rule_index}'    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${inByte}    业务流的hitCount不等于设备总接收
        ...    ELSE    Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${0}    背景流（不匹配规则）的hitCount不等于0
        Continue For Loop If    ${DropFlag} == 1
        Comment    检验输出报文内容
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}    Pri/${hitpacket}
        log    ${src_hash_list}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    interface_pri_${row}_hit.pcap
        log    ${dst_hash_list}
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Should Be True    ${hashResult}    包内容检查错误，仪表发送报文不等于设备输出的报文内容
    END
    Comment    删除初始转发规则
    undoFiveTupleByRCP    ${forwardAppIdList}
    telnet.write    undo global priority_for_tunnel
    ${info}    Telnet.Read Until    ${userName1}(config)#
    log    ${info}

Repeat_grouped&five_tuple
    [Documentation]    验证组合规则和五元组规则的内容可重复（规则共存验证）
    ...    1、下发v4组合规则（sip+dip=china_ipv4_cidr.txt）
    ...    2、下发v6组合规则（sip+dip=china_ipv6_cidr.txt）
    ...    3、下发v4五元组规则（sip=v4全量8790, dip为空）
    ...    4、下发v4五元组规则（sip为空, dip=v4全量8790）
    ...    5、下发v6五元组规则（sip=v6全量2039, dip为空）
    ...    6、下发v6五元组规则（sip为空, dip=v6全量2039）
    ...
    ...    注：新增导入大量ip的用法（cidr）
    [Tags]    rcp
    [Setup]    undoAclAll
    ${sampleSize}    Set Variable    ${None}
    comment    === 阶段1: 加载CIDR数据 ===
    ${v4_cidrs}    Load Cidrs From File    ${CURDIR}/../Resource/Business/cidr_data/china_ipv4_cidr.txt    ${sampleSize}
    ${v6_cidrs}    Load Cidrs From File    ${CURDIR}/../Resource/Business/cidr_data/china_ipv6_cidr.txt    ${sampleSize}
    ${v4Count}    Get Length    ${v4_cidrs}
    ${v6Count}    Get Length    ${v6_cidrs}
    log    v4_cidrs: ${v4Count}, v6_cidrs: ${v6Count}
    comment    === 阶段2: 下发v4组合规则 ===
    &{kwargs1}    Build Combined Rule Kwargs    ${v4_cidrs}    v4
    ${req}    ${expect}    ${actual}    ${ruleId_1}    Add Rule Direct    &{kwargs1}
    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect}    ${actual}
    log    v4 grouped rule id: ${ruleId_1}
    telnet.write    show rule number
    ${info}    Telnet.Read Until    ${userName1}(config)#
    log    ${info}
    comment    === 阶段3: 下发v6组合规则 ===
    &{kwargs2}    Build Combined Rule Kwargs    ${v6_cidrs}    v6
    ${req}    ${expect}    ${actual}    ${ruleId_2}    Add Rule Direct    &{kwargs2}
    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect}    ${actual}
    log    v6 grouped rule id: ${ruleId_2}
    telnet.write    show rule number
    ${info}    Telnet.Read Until    ${userName1}(config)#
    log    ${info}
    comment    === 阶段4: 下发五元组规则(4条,一边全量CIDR,另一边为空)===
    @{empty}    Create List
    &{kwargs3}    Build Five Tuple Rule Kwargs    ${v4_cidrs}    ${empty}    v4
    ${req}    ${expect}    ${actual}    ${ruleId_3}    Add Rule Direct Five Tuple    &{kwargs3}
    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect}    ${actual}
    log    v4 five-tuple rule3(sip=v4_all,dip=empty) id: ${ruleId_3}
    &{kwargs4}    Build Five Tuple Rule Kwargs    ${empty}    ${v4_cidrs}    v4
    ${req}    ${expect}    ${actual}    ${ruleId_4}    Add Rule Direct Five Tuple    &{kwargs4}
    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect}    ${actual}
    log    v4 five-tuple rule4(sip=empty,dip=v4_all) id: ${ruleId_4}
    &{kwargs5}    Build Five Tuple Rule Kwargs    ${v6_cidrs}    ${empty}    v6
    ${req}    ${expect}    ${actual}    ${ruleId_5}    Add Rule Direct Five Tuple    &{kwargs5}
    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect}    ${actual}
    log    v6 five-tuple rule5(sip=v6_all,dip=empty) id: ${ruleId_5}
    &{kwargs6}    Build Five Tuple Rule Kwargs    ${empty}    ${v6_cidrs}    v6
    ${req}    ${expect}    ${actual}    ${ruleId_6}    Add Rule Direct Five Tuple    &{kwargs6}
    Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expect}    ${actual}
    log    v6 five-tuple rule6(sip=empty,dip=v6_all) id: ${ruleId_6}
    comment    === 阶段5: 验证规则共存 ===
    New Connection Custom
    telnet.write    show acl all
    ${info}    Telnet.Read Until    ${userName1}(config)#
    log    ${info}
    telnet.write    show acl rcp
    ${info}    Telnet.Read Until    ${userName1}(config)#
    log    ${info}
    telnet.write    show rule number
    ${info}    Telnet.Read Until    ${userName1}(config)#
    log    ${info}
    [Teardown]    undoAclAll
