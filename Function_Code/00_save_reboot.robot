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
${restoreWaitTime}    10

*** Test Cases ***
reboot_rule_persistence
    [Documentation]    设备带流量冷重启后规则持久化和有效性验
    ...    1. 逐行下发RCP/CLI规则并打流验
    ...    2. 后台打流+保存重启+停流+验证规则持久
    ...    3. 重启后逐行打流验证规则仍生效
    [Tags]    reboot    persistence
    [Setup]    undoAclAll
    # ===== 阶段A: 逐行下发规则+打流验证 + 记录状态=====
    # A1. 打开 Excel，初始化
    ${sheetName}    Set Variable    save&reboot
    open excel    ${ImportFilepath}/${excelName}
    ${countRow}    get row count    ${sheetName}
    ${countRrowAdd}    Evaluate    ${countRow}+1
    # A2. 逐行: 下发规则 → 立即打流验证
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        ${configFileName}    read cell data by name    ${sheetName}    A${row}
        ${ruleTitle}    read cell data by name    ${sheetName}    B${row}
        ${packetFileName}    read cell data by name    ${sheetName}    C${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    D${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    E${row}
        ${appId}    read cell data by name    ${sheetName}    F${row}
        ${appId}    Convert To Integer    ${appId}
        # --- 下发规则 ---
        IF    '${configFileName}' == 'no'
            # CLI规则 (行9-12, colA="no")
            New Connection Custom
            ${ruleSuf}    Set Variable    action ${action_info} outgroup_f ${outgroup_fId_1} app_id ${appId} hit_statistics true
            ${acl_all}    Catenate    ${ruleTitle}    ${ruleSuf}
            telnet.write    ${acl_all}
            ${info}    Telnet.Read Until    ${userName1}(config)#
            Run Keyword And Continue On Failure    Should Not Contain    ${info}    ERROR
        ELSE
            # RCP规则 (行2-8, colA="allrulesave")
            ${requestBody}    ${expectResponse}    ${actualResponse}    ${ruleId}    addOrModifyOrDrop    ${configFileName}    ${ruleTitle}
            Run Keyword And Continue On Failure    Should Be Equal As Strings    ${expectResponse}    ${actualResponse}    RCP下发失败: ${ruleTitle}
        END
        # --- 打流验证 ---
        ${rx}    ${tx}    tcpreplayAndTcpdump    reboot_before_${row}    ${packetFileName}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    0    第${row}行 重启前打流rx=0: ${packetFileName}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${tx}[0]    第${row}行 重启前rx!=tx: ${packetFileName}
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${appId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${outByte}    第${row}行 重启前hitCount!=tx字节: ${packetFileName}
        Comment    报文hash校验
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}    ${packetFileName}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    reboot_before_${row}.pcap
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Should Be True    ${hashResult}    第${row}行 重启前报文hash不一致: ${packetFileName}
    END
    # A3. 记录重启前状态
    New Connection Custom
    telnet.write    show acl all
    ${acl_before}    Telnet.Read Until    ${userName1}(config)#
    telnet.write    show acl rcp
    ${rcp_before}    Telnet.Read Until    ${userName1}(config)#
    Log    ${rcp_before}
    telnet.write    show rule number
    ${ruleCount_before}    Telnet.Read Until    ${userName1}(config)#
    Log    ${ruleCount_before}
    # ===== 阶段B: 后台打流 + 保存重启 + 停流 + 验证持久=====
    # B1. 同一 telnet 清零统计
    telnet.write    clear statistics all
    sleep    2s
    compareStastics    ${inportId}    ${outgroup_f_portId_1}    0    0
    # B2. SSH 后台启动 tcpreplay
    OpenConnectionAndLogin    alias=tcpreplay_bg
    SSHLibrary.Write    cd ${ssh_server_raw_pcap_path}
    SSHLibrary.Read Until    \#
    SSHLibrary.Write    nohup tcpreplay -l0 -t -i ${ssh_server_net_port} Default_stp.pcap Default_icmp.pcap Default_ICMPv6_echos.pcap Default_arp.pcap Default_lacp.pcap > /tmp/tcpreplay_bg.log 2>/dev/null &
    SSHLibrary.Read Until    \#
    SSHLibrary.Close All Connections
    # B3. 同一 telnet: save + reboot
    telnet.write    save
    ${saveResp}    Telnet.Read Until    ${userName1}(config)#
    telnet.write    reboot cold
    # B4. 等待设备上线（轮询重连，成功后复用此连接）
    Wait Device Reboot    max_wait=900
    # B5. SSH 停流
    OpenConnectionAndLogin    alias=tcpreplay_bg
    SSHLibrary.Write    pkill -9 tcpreplay; sleep 1; tail -n 5 /tmp/tcpreplay_bg.log
    ${txInfo}    SSHLibrary.Read Until    \#
    Log    ${txInfo}
    SSHLibrary.Close All Connections
    # B6. 重新建立telnet连接(B5 SSH期间可能已空闲超时), 读端口 + 清统计 + 验证规则持久
    New Connection Custom
    telnet.write    show statistics interface ${inportId}
    ${stats}    Telnet.Read Until    ${userName1}(config)#
    Log    ${stats}
    telnet.write    clear statistics all
    sleep    2s
    compareStastics    ${inportId}    ${outgroup_f_portId_1}    0    0
    telnet.write    show acl all
    ${acl_after}    Telnet.Read Until    ${userName1}(config)#
    Run Keyword And Continue On Failure    Should Be Equal    ${acl_before}    ${acl_after}    重启后show acl all不一致
    telnet.write    show acl rcp
    ${rcp_after}    Telnet.Read Until    ${userName1}(config)#
    Log    ${rcp_after}
    telnet.write    show rule number
    ${ruleCount_after}    Telnet.Read Until    ${userName1}(config)#
    Run Keyword And Continue On Failure    Should Be Equal    ${ruleCount_before}    ${ruleCount_after}    重启后规则数量不一致
    # ===== 阶段C: 重启后打流验证规则仍生效 =====
    FOR    ${row}    IN RANGE    2    ${countRrowAdd}
        ${packetFileName}    read cell data by name    ${sheetName}    C${row}
        ${startFlowSpeed}    read cell data by name    ${sheetName}    D${row}
        ${startFlowTime}    read cell data by name    ${sheetName}    E${row}
        ${appId}    read cell data by name    ${sheetName}    F${row}
        ${appId}    Convert To Integer    ${appId}
        ${rx}    ${tx}    tcpreplayAndTcpdump    reboot_after_${row}    ${packetFileName}    ${startFlowSpeed}    ${startFlowTime}
        Run Keyword And Continue On Failure    Should Not Be Equal As Integers    ${rx}    0    第${row}行 重启后打流rx=0: ${packetFileName}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${rx}    ${tx}[0]    第${row}行 重启后rx!=tx: ${packetFileName}
        ${inPkt}    ${inByte}    ${outPkt}    ${outByte}    compareStastics    ${inportId}    ${outgroup_f_portId_1}    ${tx}[0]    ${rx}
        ${hitCount}    getAclHitstatistics    ${appId}
        Run Keyword And Continue On Failure    Should Be Equal As Integers    ${hitCount}    ${outByte}    第${row}行 重启后hitCount!=tx字节: ${packetFileName}
        Comment    通过hash校验包的完整性
        ${src_hash_list}=    hash_and_remove_duplicates    ${localRawPcapPath}    ${packetFileName}
        ${dst_hash_list}=    hash_and_remove_duplicates    ${localRipePcapPath}    reboot_after_${row}.pcap
        ${hashResult}    compare_hash_lists    ${src_hash_list}    ${dst_hash_list}
        Run Keyword And Continue On Failure    Should Be True    ${hashResult}    第${row}行 重启后报文hash不一致: ${packetFileName}
    END
    [Teardown]    undoAclAll
