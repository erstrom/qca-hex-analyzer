from enum import Enum, unique


@unique
class WmiUnifiedCmdGrpId(Enum):

    WMI_UNIFIED_GRP_SCAN = 3
    WMI_UNIFIED_GRP_PDEV = 4
    WMI_UNIFIED_GRP_VDEV = 5
    WMI_UNIFIED_GRP_PEER = 6
    WMI_UNIFIED_GRP_MGMT = 7
    WMI_UNIFIED_GRP_BA_NEG = 8
    WMI_UNIFIED_GRP_STA_PS = 9
    WMI_UNIFIED_GRP_DFS = 10
    WMI_UNIFIED_GRP_ROAM = 11
    WMI_UNIFIED_GRP_OFL_SCAN = 12
    WMI_UNIFIED_GRP_P2P = 13
    WMI_UNIFIED_GRP_AP_PS = 14
    WMI_UNIFIED_GRP_RATE_CTRL = 15
    WMI_UNIFIED_GRP_PROFILE = 16
    WMI_UNIFIED_GRP_SUSPEND = 17
    WMI_UNIFIED_GRP_BCN_FILTER = 18
    WMI_UNIFIED_GRP_WOW = 19
    WMI_UNIFIED_GRP_RTT = 20
    WMI_UNIFIED_GRP_SPECTRAL = 21
    WMI_UNIFIED_GRP_STATS = 22
    WMI_UNIFIED_GRP_ARP_NS_OFL = 23
    WMI_UNIFIED_GRP_NLO_OFL = 24
    WMI_UNIFIED_GRP_GTK_OFL = 25
    WMI_UNIFIED_GRP_CSA_OFL = 26
    WMI_UNIFIED_GRP_CHATTER = 27
    WMI_UNIFIED_GRP_TID_ADDBA = 28
    WMI_UNIFIED_GRP_MISC = 29
    WMI_UNIFIED_GRP_GPIO = 30
    WMI_UNIFIED_GRP_FWTEST = 31
    WMI_UNIFIED_GRP_TDLS = 32
    WMI_UNIFIED_GRP_RESMGR = 33
    WMI_UNIFIED_GRP_STA_SMPS = 34
    WMI_UNIFIED_GRP_WLAN_HB = 35
    WMI_UNIFIED_GRP_RMC = 36
    WMI_UNIFIED_GRP_MHF_OFL = 37
    WMI_UNIFIED_GRP_LOCATION_SCAN = 38
    WMI_UNIFIED_GRP_OEM = 39
    WMI_UNIFIED_GRP_NAN = 40
    WMI_UNIFIED_GRP_COEX = 41
    WMI_UNIFIED_GRP_OBSS_OFL = 42
    WMI_UNIFIED_GRP_LPI = 43
    WMI_UNIFIED_GRP_EXTSCAN = 44
    WMI_UNIFIED_GRP_DHCP_OFL = 45
    WMI_UNIFIED_GRP_IPA = 46
    WMI_UNIFIED_GRP_MDNS_OFL = 47
    WMI_UNIFIED_GRP_SAP_OFL = 48
    WMI_UNIFIED_GRP_OCB = 49
    WMI_UNIFIED_GRP_SOC = 50
    WMI_UNIFIED_GRP_PKT_FILTER = 51
    WMI_UNIFIED_GRP_MAWC = 52
    WMI_UNIFIED_GRP_PMF_OFFLOAD = 53


@unique
class WmiUnifiedCmd(Enum):

    WMI_UNIFIED_INIT_CMDID = 0x1

    WMI_UNIFIED_START_SCAN_CMDID = 0x3001
    WMI_UNIFIED_STOP_SCAN_CMDID = 0x3002
    WMI_UNIFIED_SCAN_CHAN_LIST_CMDID = 0x3003
    WMI_UNIFIED_SCAN_SCH_PRIO_TBL_CMDID = 0x3004
    WMI_UNIFIED_SCAN_UPDATE_REQUEST_CMDID = 0x3005
    WMI_UNIFIED_SCAN_PROB_REQ_OUI_CMDID = 0x3006

    WMI_UNIFIED_PDEV_SET_REGDOMAIN_CMDID = 0x4001
    WMI_UNIFIED_PDEV_SET_CHANNEL_CMDID = 0x4002
    WMI_UNIFIED_PDEV_SET_PARAM_CMDID = 0x4003
    WMI_UNIFIED_PDEV_PKTLOG_ENABLE_CMDID = 0x4004
    WMI_UNIFIED_PDEV_PKTLOG_DISABLE_CMDID = 0x4005
    WMI_UNIFIED_PDEV_SET_WMM_PARAMS_CMDID = 0x4006
    WMI_UNIFIED_PDEV_SET_HT_CAP_IE_CMDID = 0x4007
    WMI_UNIFIED_PDEV_SET_VHT_CAP_IE_CMDID = 0x4008
    WMI_UNIFIED_PDEV_SET_DSCP_TID_MAP_CMDID = 0x4009
    WMI_UNIFIED_PDEV_SET_QUIET_MODE_CMDID = 0x400a
    WMI_UNIFIED_PDEV_GREEN_AP_PS_ENABLE_CMDID = 0x400b
    WMI_UNIFIED_PDEV_GET_TPC_CONFIG_CMDID = 0x400c
    WMI_UNIFIED_PDEV_SET_BASE_MACADDR_CMDID = 0x400d
    WMI_UNIFIED_PDEV_DUMP_CMDID = 0x400e
    WMI_UNIFIED_PDEV_SET_LED_CONFIG_CMDID = 0x400f
    WMI_UNIFIED_PDEV_GET_TEMPERATURE_CMDID = 0x4010
    WMI_UNIFIED_PDEV_SET_LED_FLASHING_CMDID = 0x4011

    WMI_UNIFIED_VDEV_CREATE_CMDID = 0x5001
    WMI_UNIFIED_VDEV_DELETE_CMDID = 0x5002
    WMI_UNIFIED_VDEV_START_REQUEST_CMDID = 0x5003
    WMI_UNIFIED_VDEV_RESTART_REQUEST_CMDID = 0x5004
    WMI_UNIFIED_VDEV_UP_CMDID = 0x5005
    WMI_UNIFIED_VDEV_STOP_CMDID = 0x5006
    WMI_UNIFIED_VDEV_DOWN_CMDID = 0x5007
    WMI_UNIFIED_VDEV_SET_PARAM_CMDID = 0x5008
    WMI_UNIFIED_VDEV_INSTALL_KEY_CMDID = 0x5009
    WMI_UNIFIED_VDEV_WNM_SLEEPMODE_CMDID = 0x500a
    WMI_UNIFIED_VDEV_WMM_ADDTS_CMDID = 0x500b
    WMI_UNIFIED_VDEV_WMM_DELTS_CMDID = 0x500c
    WMI_UNIFIED_VDEV_SET_WMM_PARAMS_CMDID = 0x500d
    WMI_UNIFIED_VDEV_SET_GTX_PARAMS_CMDID = 0x500e
    WMI_UNIFIED_VDEV_IPSEC_NATKEEPALIVE_FILTER_CMDID = 0x500f
    WMI_UNIFIED_VDEV_PLMREQ_START_CMDID = 0x5010
    WMI_UNIFIED_VDEV_PLMREQ_STOP_CMDID = 0x5011
    WMI_UNIFIED_VDEV_TSF_TSTAMP_ACTION_CMDID = 0x5012
    WMI_UNIFIED_VDEV_SET_IE_CMDID = 0x5013

    WMI_UNIFIED_PEER_CREATE_CMDID = 0x6001
    WMI_UNIFIED_PEER_DELETE_CMDID = 0x6002
    WMI_UNIFIED_PEER_FLUSH_TIDS_CMDID = 0x6003
    WMI_UNIFIED_PEER_SET_PARAM_CMDID = 0x6004
    WMI_UNIFIED_PEER_ASSOC_CMDID = 0x6005
    WMI_UNIFIED_PEER_ADD_WDS_ENTRY_CMDID = 0x6006
    WMI_UNIFIED_PEER_REMOVE_WDS_ENTRY_CMDID = 0x6007
    WMI_UNIFIED_PEER_MCAST_GROUP_CMDID = 0x6008
    WMI_UNIFIED_PEER_INFO_REQ_CMDID = 0x6009
    WMI_UNIFIED_PEER_GET_ESTIMATED_LINKSPEED_CMDID = 0x600a
    WMI_UNIFIED_PEER_SET_RATE_REPORT_CONDITION_CMDID = 0x600b

    WMI_UNIFIED_BCN_TX_CMDID = 0x7001
    WMI_UNIFIED_PDEV_SEND_BCN_CMDID = 0x7002
    WMI_UNIFIED_BCN_TMPL_CMDID = 0x7003
    WMI_UNIFIED_BCN_FILTER_RX_CMDID = 0x7004
    WMI_UNIFIED_PRB_REQ_FILTER_RX_CMDID = 0x7005
    WMI_UNIFIED_MGMT_TX_CMDID = 0x7006
    WMI_UNIFIED_PRB_TMPL_CMDID = 0x7007
    WMI_UNIFIED_MGMT_TX_SEND_CMDID = 0x7008

    WMI_UNIFIED_ADDBA_CLEAR_RESP_CMDID = 0x8001
    WMI_UNIFIED_ADDBA_SEND_CMDID = 0x8002
    WMI_UNIFIED_ADDBA_STATUS_CMDID = 0x8003
    WMI_UNIFIED_DELBA_SEND_CMDID = 0x8004
    WMI_UNIFIED_ADDBA_SET_RESP_CMDID = 0x8005
    WMI_UNIFIED_SEND_SINGLEAMSDU_CMDID = 0x8006

    WMI_UNIFIED_STA_POWERSAVE_MODE_CMDID = 0x9001
    WMI_UNIFIED_STA_POWERSAVE_PARAM_CMDID = 0x9002
    WMI_UNIFIED_STA_MIMO_PS_MODE_CMDID = 0x9003

    WMI_UNIFIED_PDEV_DFS_ENABLE_CMDID = 0xa001
    WMI_UNIFIED_PDEV_DFS_DISABLE_CMDID = 0xa002
    WMI_UNIFIED_DFS_PHYERR_FILTER_ENA_CMDID = 0xa003
    WMI_UNIFIED_DFS_PHYERR_FILTER_DIS_CMDID = 0xa004

    WMI_UNIFIED_ROAM_SCAN_MODE = 0xb001
    WMI_UNIFIED_ROAM_SCAN_RSSI_THRESHOLD = 0xb002
    WMI_UNIFIED_ROAM_SCAN_PERIOD = 0xb003
    WMI_UNIFIED_ROAM_SCAN_RSSI_CHANGE_THRESHOLD = 0xb004
    WMI_UNIFIED_ROAM_AP_PROFILE = 0xb005
    WMI_UNIFIED_ROAM_CHAN_LIST = 0xb006
    WMI_UNIFIED_ROAM_SCAN_CMD = 0xb007
    WMI_UNIFIED_ROAM_SYNCH_COMPLETE = 0xb008
    WMI_UNIFIED_ROAM_SET_RIC_REQUEST_CMDID = 0xb009
    WMI_UNIFIED_ROAM_INVOKE_CMDID = 0xb00a
    WMI_UNIFIED_ROAM_FILTER_CMDID = 0xb00b
    WMI_UNIFIED_ROAM_SUBNET_CHANGE_CONFIG_CMDID = 0xb00c
    WMI_UNIFIED_ROAM_CONFIGURE_MAWC_CMDID = 0xb00d

    WMI_UNIFIED_OFL_SCAN_ADD_AP_PROFILE = 0xc001
    WMI_UNIFIED_OFL_SCAN_REMOVE_AP_PROFILE = 0xc002
    WMI_UNIFIED_OFL_SCAN_PERIOD = 0xc003

    WMI_UNIFIED_P2P_DEV_SET_DEVICE_INFO = 0xd001
    WMI_UNIFIED_P2P_DEV_SET_DISCOVERABILITY = 0xd002
    WMI_UNIFIED_P2P_GO_SET_BEACON_IE = 0xd003
    WMI_UNIFIED_P2P_GO_SET_PROBE_RESP_IE = 0xd004
    WMI_UNIFIED_P2P_SET_VENDOR_IE_DATA_CMDID = 0xd005
    WMI_UNIFIED_P2P_DISC_OFFLOAD_CONFIG_CMDID = 0xd006
    WMI_UNIFIED_P2P_DISC_OFFLOAD_APPIE_CMDID = 0xd007
    WMI_UNIFIED_P2P_DISC_OFFLOAD_PATTERN_CMDID = 0xd008
    WMI_UNIFIED_P2P_SET_OPPPS_PARAM_CMDID = 0xd009

    WMI_UNIFIED_AP_PS_PEER_PARAM_CMDID = 0xe001
    WMI_UNIFIED_AP_PS_PEER_UAPSD_COEX_CMDID = 0xe002
    WMI_UNIFIED_AP_PS_EGAP_PARAM_CMDID = 0xe003

    WMI_UNIFIED_PEER_RATE_RETRY_SCHED_CMDID = 0xf001

    WMI_UNIFIED_WLAN_PROFILE_TRIGGER_CMDID = 0x10001
    WMI_UNIFIED_WLAN_PROFILE_SET_HIST_INTVL_CMDID = 0x10002
    WMI_UNIFIED_WLAN_PROFILE_GET_PROFILE_DATA_CMDID = 0x10003
    WMI_UNIFIED_WLAN_PROFILE_ENABLE_PROFILE_ID_CMDID = 0x10004
    WMI_UNIFIED_WLAN_PROFILE_LIST_PROFILE_ID_CMDID = 0x10005

    WMI_UNIFIED_PDEV_SUSPEND_CMDID = 0x11001
    WMI_UNIFIED_PDEV_RESUME_CMDID = 0x11002

    WMI_UNIFIED_ADD_BCN_FILTER_CMDID = 0x12001
    WMI_UNIFIED_RMV_BCN_FILTER_CMDID = 0x12002

    WMI_UNIFIED_WOW_ADD_WAKE_PATTERN_CMDID = 0x13001
    WMI_UNIFIED_WOW_DEL_WAKE_PATTERN_CMDID = 0x13002
    WMI_UNIFIED_WOW_ENABLE_DISABLE_WAKE_EVENT_CMDID = 0x13003
    WMI_UNIFIED_WOW_ENABLE_CMDID = 0x13004
    WMI_UNIFIED_WOW_HOSTWAKEUP_FROM_SLEEP_CMDID = 0x13005
    WMI_UNIFIED_WOW_IOAC_ADD_KEEPALIVE_CMDID = 0x13006
    WMI_UNIFIED_WOW_IOAC_DEL_KEEPALIVE_CMDID = 0x13007
    WMI_UNIFIED_WOW_IOAC_ADD_WAKE_PATTERN_CMDID = 0x13008
    WMI_UNIFIED_WOW_IOAC_DEL_WAKE_PATTERN_CMDID = 0x13009
    WMI_UNIFIED_D0_WOW_ENABLE_DISABLE_CMDID = 0x1300a
    WMI_UNIFIED_EXTWOW_ENABLE_CMDID = 0x1300b
    WMI_UNIFIED_EXTWOW_SET_APP_TYPE1_PARAMS_CMDID = 0x1300c
    WMI_UNIFIED_EXTWOW_SET_APP_TYPE2_PARAMS_CMDID = 0x1300d
    WMI_UNIFIED_WOW_ENABLE_ICMPV6_NA_FLT_CMDID = 0x1300e
    WMI_UNIFIED_WOW_UDP_SVC_OFLD_CMDID = 0x1300f
    WMI_UNIFIED_WOW_HOSTWAKEUP_GPIO_PIN_PATTERN_CONFIG_CMDID = 0x13010

    WMI_UNIFIED_RTT_MEASREQ_CMDID = 0x14001
    WMI_UNIFIED_RTT_TSF_CMDID = 0x14002

    WMI_UNIFIED_VDEV_SPECTRAL_SCAN_CONFIGURE_CMDID = 0x15001
    WMI_UNIFIED_VDEV_SPECTRAL_SCAN_ENABLE_CMDID = 0x15002

    WMI_UNIFIED_REQUEST_STATS_CMDID = 0x16001
    WMI_UNIFIED_MCC_SCHED_TRAFFIC_STATS_CMDID = 0x16002
    WMI_UNIFIED_REQUEST_STATS_EXT_CMDID = 0x16003
    WMI_UNIFIED_REQUEST_LINK_STATS_CMDID = 0x16004
    WMI_UNIFIED_START_LINK_STATS_CMDID = 0x16005
    WMI_UNIFIED_CLEAR_LINK_STATS_CMDID = 0x16006
    WMI_UNIFIED_GET_FW_MEM_DUMP_CMDID = 0x16007
    WMI_UNIFIED_DEBUG_MESG_FLUSH_CMDID = 0x16008
    WMI_UNIFIED_DIAG_EVENT_LOG_CONFIG_CMDID = 0x16009

    WMI_UNIFIED_SET_ARP_NS_OFFLOAD_CMDID = 0x17001
    WMI_UNIFIED_ADD_PROACTIVE_ARP_RSP_PATTERN_CMDID = 0x17002
    WMI_UNIFIED_DEL_PROACTIVE_ARP_RSP_PATTERN_CMDID = 0x17003

    WMI_UNIFIED_NETWORK_LIST_OFFLOAD_CONFIG_CMDID = 0x18001
    WMI_UNIFIED_APFIND_CMDID = 0x18002
    WMI_UNIFIED_PASSPOINT_LIST_CONFIG_CMDID = 0x18003
    WMI_UNIFIED_NLO_CONFIGURE_MAWC_CMDID = 0x18004

    WMI_UNIFIED_GTK_OFFLOAD_CMDID = 0x19001

    WMI_UNIFIED_CSA_OFFLOAD_ENABLE_CMDID = 0x1a001
    WMI_UNIFIED_CSA_OFFLOAD_CHANSWITCH_CMDID = 0x1a002

    WMI_UNIFIED_CHATTER_SET_MODE_CMDID = 0x1b001
    WMI_UNIFIED_CHATTER_ADD_COALESCING_FILTER_CMDID = 0x1b002
    WMI_UNIFIED_CHATTER_DELETE_COALESCING_FILTER_CMDID = 0x1b003
    WMI_UNIFIED_CHATTER_COALESCING_QUERY_CMDID = 0x1b004

    WMI_UNIFIED_PEER_TID_ADDBA_CMDID = 0x1c001
    WMI_UNIFIED_PEER_TID_DELBA_CMDID = 0x1c002
    WMI_UNIFIED_STA_DTIM_PS_METHOD_CMDID = 0x1c003
    WMI_UNIFIED_STA_UAPSD_AUTO_TRIG_CMDID = 0x1c004
    WMI_UNIFIED_STA_KEEPALIVE_CMDID = 0x1c005
    WMI_UNIFIED_BA_REQ_SSN_CMDID = 0x1c006

    WMI_UNIFIED_ECHO_CMDID = 0x1d001
    WMI_UNIFIED_PDEV_UTF_CMDID = 0x1d002
    WMI_UNIFIED_DBGLOG_CFG_CMDID = 0x1d003
    WMI_UNIFIED_PDEV_QVIT_CMDID = 0x1d004
    WMI_UNIFIED_PDEV_FTM_INTG_CMDID = 0x1d005
    WMI_UNIFIED_VDEV_SET_KEEPALIVE_CMDID = 0x1d006
    WMI_UNIFIED_VDEV_GET_KEEPALIVE_CMDID = 0x1d007
    WMI_UNIFIED_FORCE_FW_HANG_CMDID = 0x1d008
    WMI_UNIFIED_SET_MCASTBCAST_FILTER_CMDID = 0x1d009
    WMI_UNIFIED_THERMAL_MGMT_CMDID = 0x1d00a
    WMI_UNIFIED_HOST_AUTO_SHUTDOWN_CFG_CMDID = 0x1d00b
    WMI_UNIFIED_TPC_CHAINMASK_CONFIG_CMDID = 0x1d00c
    WMI_UNIFIED_SET_ANTENNA_DIVERSITY_CMDID = 0x1d00d
    WMI_UNIFIED_OCB_SET_SCHED_CMDID = 0x1d00e
    WMI_UNIFIED_RSSI_BREACH_MONITOR_CONFIG_CMDID = 0x1d00f
    WMI_UNIFIED_LRO_CONFIG_CMDID = 0x1d010
    WMI_UNIFIED_TRANSFER_DATA_TO_FLASH_CMDID = 0x1d011

    WMI_UNIFIED_GPIO_CONFIG_CMDID = 0x1e001
    WMI_UNIFIED_GPIO_OUTPUT_CMDID = 0x1e002
    WMI_UNIFIED_TXBF_CMDID = 0x1e003

    WMI_UNIFIED_FWTEST_VDEV_MCC_SET_TBTT_MODE_CMDID = 0x1f001
    WMI_UNIFIED_FWTEST_P2P_SET_NOA_PARAM_CMDID = 0x1f002
    WMI_UNIFIED_UNIT_TEST_CMDID = 0x1f003

    WMI_UNIFIED_TDLS_SET_STATE_CMDID = 0x20001
    WMI_UNIFIED_TDLS_PEER_UPDATE_CMDID = 0x20002
    WMI_UNIFIED_TDLS_SET_OFFCHAN_MODE_CMDID = 0x20003

    WMI_UNIFIED_RESMGR_ADAPTIVE_OCS_ENABLE_DISABLE_CMDID = 0x21001
    WMI_UNIFIED_RESMGR_SET_CHAN_TIME_QUOTA_CMDID = 0x21002
    WMI_UNIFIED_RESMGR_SET_CHAN_LATENCY_CMDID = 0x21003

    WMI_UNIFIED_STA_SMPS_FORCE_MODE_CMDID = 0x22001
    WMI_UNIFIED_STA_SMPS_PARAM_CMDID = 0x22002

    WMI_UNIFIED_HB_SET_ENABLE_CMDID = 0x23001
    WMI_UNIFIED_HB_SET_TCP_PARAMS_CMDID = 0x23002
    WMI_UNIFIED_HB_SET_TCP_PKT_FILTER_CMDID = 0x23003
    WMI_UNIFIED_HB_SET_UDP_PARAMS_CMDID = 0x23004
    WMI_UNIFIED_HB_SET_UDP_PKT_FILTER_CMDID = 0x23005

    WMI_UNIFIED_RMC_SET_MODE_CMDID = 0x24001
    WMI_UNIFIED_RMC_SET_ACTION_PERIOD_CMDID = 0x24002
    WMI_UNIFIED_RMC_CONFIG_CMDID = 0x24003

    WMI_UNIFIED_MHF_OFFLOAD_SET_MODE_CMDID = 0x25001
    WMI_UNIFIED_MHF_OFFLOAD_PLUMB_ROUTING_TBL_CMDID = 0x25002

    WMI_UNIFIED_BATCH_SCAN_ENABLE_CMDID = 0x26001
    WMI_UNIFIED_BATCH_SCAN_DISABLE_CMDI = 0x26002
    WMI_UNIFIED_BATCH_SCAN_TRIGGER_RESULT_CMDID = 0x26003

    WMI_UNIFIED_OEM_REQ_CMDID = 0x27001
    WMI_UNIFIED_OEM_REQUEST_CMDID = 0x27002

    WMI_UNIFIED_NAN_CMDID = 0x28001

    WMI_UNIFIED_MODEM_POWER_STATE_CMDID = 0x29001
    WMI_UNIFIED_CHAN_AVOID_UPDATE_CMDID = 0x29002

    WMI_UNIFIED_OBSS_SCAN_ENABLE_CMDID = 0x2a001
    WMI_UNIFIED_OBSS_SCAN_DISABLE_CMDID = 0x2a002

    WMI_UNIFIED_LPI_MGMT_SNOOPING_CONFIG_CMDID = 0x2b001
    WMI_UNIFIED_LPI_START_SCAN_CMDID = 0x2b002
    WMI_UNIFIED_LPI_STOP_SCAN_CMDID = 0x2b003

    WMI_UNIFIED_EXTSCAN_START_CMDID = 0x2c001
    WMI_UNIFIED_EXTSCAN_STOP_CMDID = 0x2c002
    WMI_UNIFIED_EXTSCAN_CONFIGURE_WLAN_CHANGE_MONITOR_CMDID = 0x2c003
    WMI_UNIFIED_EXTSCAN_CONFIGURE_HOTLIST_MONITOR_CMDID = 0x2c004
    WMI_UNIFIED_EXTSCAN_GET_CACHED_RESULTS_CMDID = 0x2c005
    WMI_UNIFIED_EXTSCAN_GET_WLAN_CHANGE_RESULTS_CMDID = 0x2c006
    WMI_UNIFIED_EXTSCAN_SET_CAPABILITIES_CMDID = 0x2c007
    WMI_UNIFIED_EXTSCAN_GET_CAPABILITIES_CMDID = 0x2c008
    WMI_UNIFIED_EXTSCAN_CONFIGURE_HOTLIST_SSID_MONITOR_CMDID = 0x2c009
    WMI_UNIFIED_EXTSCAN_CONFIGURE_MAWC_CMDID = 0x2c00A

    WMI_UNIFIED_SET_DHCP_SERVER_OFFLOAD_CMDID = 0x2d001

    WMI_UNIFIED_IPA_OFFLOAD_ENABLE_DISABLE_CMDID = 0x2e001

    WMI_UNIFIED_MDNS_OFFLOAD_ENABLE_CMDID = 0x2f001
    WMI_UNIFIED_MDNS_SET_FQDN_CMDID = 0x2f002
    WMI_UNIFIED_MDNS_SET_RESPONSE_CMDID = 0x2f003
    WMI_UNIFIED_MDNS_GET_STATS_CMDID = 0x2f004

    WMI_UNIFIED_SAP_OFL_ENABLE_CMDID = 0x30001
    WMI_UNIFIED_SAP_SET_BLACKLIST_PARAM_CMDID = 0x30002

    WMI_UNIFIED_OCB_SET_CONFIG_CMDID = 0x31001
    WMI_UNIFIED_OCB_SET_UTC_TIME_CMDID = 0x31002
    WMI_UNIFIED_OCB_START_TIMING_ADVERT_CMDID = 0x31003
    WMI_UNIFIED_OCB_STOP_TIMING_ADVERT_CMDID = 0x31004
    WMI_UNIFIED_OCB_GET_TSF_TIMER_CMDID = 0x31005
    WMI_UNIFIED_DCC_GET_STATS_CMDID = 0x31006
    WMI_UNIFIED_DCC_CLEAR_STATS_CMDID = 0x31007
    WMI_UNIFIED_DCC_UPDATE_NDL_CMDID = 0x31008

    WMI_UNIFIED_SOC_SET_PCL_CMDID = 0x32001
    WMI_UNIFIED_SOC_SET_HW_MODE_CMDID = 0x32002
    WMI_UNIFIED_SOC_SET_DUAL_MAC_CONFIG_CMDID = 0x32003
    WMI_UNIFIED_SOC_SET_ANTENNA_MODE_CMDID = 0x32004

    WMI_UNIFIED_PACKET_FILTER_CONFIG_CMDID = 0x33001
    WMI_UNIFIED_PACKET_FILTER_ENABLE_CMDID = 0x33002

    WMI_UNIFIED_MAWC_SENSOR_REPORT_IND_CMDID = 0x34001

    WMI_UNIFIED_PMF_OFFLOAD_SET_SA_QUERY_CMDID = 0x35001


@unique
class WmiUnifiedEvt(Enum):

    # TODO: Add event codes...
    WMI_SERVICE_READY_EVENTID = 0x1
    WMI_READY_EVENTID = 0x2

    # Scan specific events
    WMI_SCAN_EVENTID = 0x3001

    # PDEV specific events
    WMI_PDEV_TPC_CONFIG_EVENTID = 0x4001
    WMI_CHAN_INFO_EVENTID = 0x4002
    WMI_PHYERR_EVENTID = 0x4003

    # VDEV specific events
    WMI_VDEV_START_RESP_EVENTID = 0x5001
    WMI_VDEV_STOPPED_EVENTID = 0x5002
    WMI_VDEV_INSTALL_KEY_COMPLETE_EVENTID = 0x5003

    # peer specific events
    WMI_PEER_STA_KICKOUT_EVENTID = 0x6001

    # beacon/mgmt specific events
    WMI_MGMT_RX_EVENTID = 0x7001
    WMI_HOST_SWBA_EVENTID = 0x7002
    WMI_TBTTOFFSET_UPDATE_EVENTID = 0x7003

    # ADDBA Related WMI Events*/
    WMI_TX_DELBA_COMPLETE_EVENTID = 0x8001
    WMI_TX_ADDBA_COMPLETE_EVENTID = 0x8002

    # Roam event to trigger roaming on host
    WMI_ROAM_EVENTID = 0xb001
    WMI_PROFILE_MATCH = 0xb002

    # WoW
    WMI_WOW_WAKEUP_HOST_EVENTID = 0x13001

    # RTT
    WMI_RTT_MEASUREMENT_REPORT_EVENTID = 0x14001
    WMI_TSF_MEASUREMENT_REPORT_EVENTID = 0x14002
    WMI_RTT_ERROR_REPORT_EVENTID = 0x14003

    # GTK offload
    WMI_GTK_OFFLOAD_STATUS_EVENTID = 0x19001
    WMI_GTK_REKEY_FAIL_EVENTID = 0x19002

    # CSA IE received event
    WMI_CSA_HANDLING_EVENTID = 0x1a001

    # Misc events
    WMI_ECHO_EVENTID = 0x1d001
    WMI_PDEV_UTF_EVENTID = 0x1d002
    WMI_DEBUG_MESG_EVENTID = 0x1d003
    WMI_UPDATE_STATS_EVENTID = 0x1d004
    WMI_DEBUG_PRINT_EVENTID = 0x1d005
    WMI_DCS_INTERFERENCE_EVENTID = 0x1d006
    WMI_PDEV_QVIT_EVENTID = 0x1d007
    WMI_WLAN_PROFILE_DATA_EVENTID = 0x1d008
    WMI_PDEV_FTM_INTG_EVENTID = 0x1d009
    WMI_WLAN_FREQ_AVOID_EVENTID = 0x1d00a
    WMI_VDEV_GET_KEEPALIVE_EVENTID = 0x1d00b
    WMI_DIAG_EVENTID = 0x1d011

    # GPIO Event
    WMI_GPIO_INPUT_EVENTID = 0x1e001


class WmiUnified:

    @staticmethod
    def get_cmd_group(cmd_id):

        grp_id = (cmd_id >> 12) & 0xfff

        try:
            return WmiUnifiedCmdGrpId(grp_id)
        except ValueError:
            return None

    @staticmethod
    def get_cmd_enum(cmd_id):

        try:
            return WmiUnifiedCmd(cmd_id)
        except ValueError:
            return None

    @staticmethod
    def get_evt_enum(evt_id):

        try:
            return WmiUnifiedEvt(evt_id)
        except ValueError:
            return None
