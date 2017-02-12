from collections import namedtuple
from abc import ABCMeta, abstractmethod
from enum import Enum, unique


TlvHeader = namedtuple('TlvHeader',
                       ['length', 'tag'],
                       verbose=False)

PdevSetParamMsg = namedtuple('PdevSetParamMsg',
                             ['tlv_hdr', 'param', 'value'],
                             verbose=False)

VdevCreateMsg = namedtuple('VdevCreateMsg',
                           ['tlv_hdr', 'vdev_id', 'vdev_type',
                            'vdev_subtype', 'mac_addr'],
                           verbose=False)

WmiChannel = namedtuple('WmiChannel',
                        ['tlv_hdr', 'mhz', 'band_center_freq1',
                         'band_center_freq2', 'mode', 'min_power',
                         'max_power', 'reg_power', 'reg_classid',
                         'antenna_max', 'max_tx_power'],
                        verbose=False)

VdevStartReqMsg = namedtuple('VdevStartReqMsg',
                             ['tlv_hdr', 'vdev_id', 'requestor_id',
                              'bcn_intval', 'dtim_period', 'flags',
                              'ssid_len', 'ssid', 'bcn_tx_rate',
                              'bcn_tx_power', 'num_noa_descr',
                              'disable_hw_ack', 'wmi_chan'],
                             verbose=False)

VdevSetParamMsg = namedtuple('VdevSetParamMsg',
                             ['tlv_hdr', 'vdev_id', 'param_id',
                              'param_value'],
                             verbose=False)

PdevSetRegDomainMsg = namedtuple('PdevSetRegDomainMsg',
                                 ['tlv_hdr', 'pdev_id', 'regd',
                                  'regd_2ghz', 'regd_5ghz',
                                  'conform_limit_2ghz',
                                  'conform_limit_5ghz'],
                                 verbose=False)

PeerCreateMsg = namedtuple('PeerCreateMsg',
                           ['tlv_hdr', 'vdev_id', 'peer_addr',
                            'peer_type'],
                           verbose=False)

PeerSetParamMsg = namedtuple('PeerSetParamMsg',
                             ['tlv_hdr', 'vdev_id', 'peer_macaddr',
                              'param_id', 'param_value'],
                             verbose=False)


def _create_le32(data):

    le32_val1 = int(data[0], 16)
    le32_val2 = int(data[1], 16)
    le32_val3 = int(data[2], 16)
    le32_val4 = int(data[3], 16)
    le32_val = ((le32_val4 << 24) & 0xFF000000) | \
               ((le32_val3 << 16) & 0xFF0000) | \
               ((le32_val2 << 8) & 0xFF00) | \
               (le32_val1 & 0xFF)
    return le32_val


def _create_le16(data):

    le16_val1 = int(data[0], 16)
    le16_val2 = int(data[1], 16)
    le16_val = ((le16_val2 << 8) & 0xFF00) | (le16_val1 & 0xFF)
    return le16_val


def _create_tlv_hdr(data):

    tlv_len = _create_le16(data[0:2])
    tlv_tag = _create_le16(data[2:4])
    try:
        tlv_tag_enum = WmiTlvTag(tlv_tag)
    except ValueError:
        tlv_tag_enum = WmiTlvTag.WMI_TLV_TAG_UNKNOWN

    hdr = TlvHeader(length=tlv_len, tag=tlv_tag_enum)
    return hdr


def _isnamedtupleinstance(x):

    t = type(x)
    b = t.__bases__
    if len(b) != 1 or b[0] != tuple:
        return False
    f = getattr(t, '_fields', None)
    if not isinstance(f, tuple):
        return False
    return all(type(n) == str for n in f)


def _print_named_tuple(ntup, fp, pre_string=""):

    fp.write("%s%s:\n" % (pre_string, type(ntup).__name__))
    for name, value in ntup._asdict().iteritems():
        if _isnamedtupleinstance(value):
            _print_named_tuple(value, fp, pre_string + "  ")
        elif isinstance(value, Enum):
            fp.write("%s  %s: 0x%x (%s)\n" %
                     (pre_string, name, value.value, value.name))
        elif isinstance(value, (int, long)):
            fp.write("%s  %s: 0x%x\n" % (pre_string, name, value))
        else:
            fp.write("%s  %s: %s\n" % (pre_string, name, value))


class WmiTlvMsg:

    @abstractmethod
    def print_data(self, fp):

        pass


class WmiTlvMsgPdevSetParam(WmiTlvMsg):

    def __init__(self, data):

        tlv_hdr = _create_tlv_hdr(data)
        if tlv_hdr.length < 12:
            return None

        param = _create_le32(data[8:12])
        value = _create_le32(data[12:16])

        try:
            param_id_enum = WmiTlvPdevParam(param)
        except ValueError:
            param_id_enum = WmiTlvPdevParam.WMI_TLV_PDEV_PARAM_UNKNOWN

        self.tlv_msg = PdevSetParamMsg(tlv_hdr=tlv_hdr,
                                       param=param_id_enum,
                                       value=value)

    def print_data(self, fp):

        _print_named_tuple(self.tlv_msg, fp)


class WmiTlvMsgPdevSetRegDomain(WmiTlvMsg):

    def __init__(self, data):

        tlv_hdr = _create_tlv_hdr(data)
        if tlv_hdr.length < 24:
            return None

        pdev_id = _create_le32(data[4:8])
        regd = _create_le32(data[8:12])
        regd_2ghz = _create_le32(data[12:16])
        regd_5ghz = _create_le32(data[16:20])
        conform_limit_2ghz = _create_le32(data[20:24])
        conform_limit_5ghz = _create_le32(data[24:28])

        self.tlv_msg = PdevSetRegDomainMsg(tlv_hdr=tlv_hdr,
                                           pdev_id=pdev_id,
                                           regd=regd,
                                           regd_2ghz=regd_2ghz,
                                           regd_5ghz=regd_5ghz,
                                           conform_limit_2ghz=conform_limit_2ghz,
                                           conform_limit_5ghz=conform_limit_5ghz)

    def print_data(self, fp):

        _print_named_tuple(self.tlv_msg, fp)


class WmiTlvMsgVdevCreate(WmiTlvMsg):

    def __init__(self, data):

        tlv_hdr = _create_tlv_hdr(data)
        if tlv_hdr.length < 20:
            return None

        vdev_id = _create_le32(data[4:8])
        vdev_type = _create_le32(data[8:12])
        vdev_subtype = _create_le32(data[12:16])
        mac_addr = data[16:24]

        self.tlv_msg = VdevCreateMsg(tlv_hdr=tlv_hdr,
                                     vdev_id=vdev_id,
                                     vdev_type=vdev_type,
                                     vdev_subtype=vdev_subtype,
                                     mac_addr=mac_addr)

    def print_data(self, fp):

        _print_named_tuple(self.tlv_msg, fp)


class WmiTlvMsgVdevStartReq(WmiTlvMsg):

    def __init__(self, data):

        tlv_hdr = _create_tlv_hdr(data)
        if tlv_hdr.length < 72:
            return None

        vdev_id = _create_le32(data[4:8])
        requestor_id = _create_le32(data[8:12])
        bcn_intval = _create_le32(data[12:16])
        dtim_period = _create_le32(data[16:20])
        flags = _create_le32(data[20:24])
        ssid_len = _create_le32(data[24:28])
        ssid = data[28:60]
        bcn_tx_rate = _create_le32(data[60:64])
        bcn_tx_power = _create_le32(data[64:68])
        num_noa_descr = _create_le32(data[68:72])
        disable_hw_ack = _create_le32(data[72:76])

        wmi_chan = None
        next_tlv_offset = tlv_hdr.length + 4
        tlv_hdr2 = _create_tlv_hdr(data[next_tlv_offset:])
        if len(data) >= tlv_hdr.length + tlv_hdr2.length:
            ch_data = data[next_tlv_offset + 4:]
            mhz = _create_le32(ch_data[0:4])
            band_center_freq1 = _create_le32(ch_data[4:8])
            band_center_freq2 = _create_le32(ch_data[8:12])
            mode = int(ch_data[12], 16)
            min_power = int(ch_data[16], 16)
            max_power = int(ch_data[17], 16)
            reg_power = int(ch_data[18], 16)
            reg_classid = int(ch_data[19], 16)
            antenna_max = int(ch_data[20], 16)
            max_tx_power = int(ch_data[21], 16)

            wmi_chan = WmiChannel(tlv_hdr=tlv_hdr2,
                                  mhz=mhz,
                                  band_center_freq1=band_center_freq1,
                                  band_center_freq2=band_center_freq2,
                                  mode=mode,
                                  min_power=min_power,
                                  max_power=max_power,
                                  reg_power=reg_power,
                                  reg_classid=reg_classid,
                                  antenna_max=antenna_max,
                                  max_tx_power=max_tx_power)

        self.tlv_msg = VdevStartReqMsg(tlv_hdr=tlv_hdr,
                                       vdev_id=vdev_id,
                                       requestor_id=requestor_id,
                                       bcn_intval=bcn_intval,
                                       dtim_period=dtim_period,
                                       flags=flags,
                                       ssid_len=ssid_len,
                                       ssid=ssid,
                                       bcn_tx_rate=bcn_tx_rate,
                                       bcn_tx_power=bcn_tx_power,
                                       num_noa_descr=num_noa_descr,
                                       disable_hw_ack=disable_hw_ack,
                                       wmi_chan=wmi_chan)

    def print_data(self, fp):

        _print_named_tuple(self.tlv_msg, fp)


class WmiTlvMsgVdevSetParam(WmiTlvMsg):

    def __init__(self, data):

        tlv_hdr = _create_tlv_hdr(data)
        if tlv_hdr.length < 12:
            return None

        vdev_id = _create_le32(data[4:8])
        param_id = _create_le32(data[8:12])
        param_value = _create_le32(data[12:16])

        try:
            param_id_enum = WmiTlvVdevParam(param_id)
        except ValueError:
            param_id_enum = WmiTlvVdevParam.WMI_TLV_VDEV_PARAM_UNKNOWN

        self.tlv_msg = VdevSetParamMsg(tlv_hdr=tlv_hdr,
                                       vdev_id=vdev_id,
                                       param_id=param_id_enum,
                                       param_value=param_value)

    def print_data(self, fp):

        _print_named_tuple(self.tlv_msg, fp)


class WmiTlvMsgPeerCreate(WmiTlvMsg):

    def __init__(self, data):

        tlv_hdr = _create_tlv_hdr(data)
        if tlv_hdr.length < 16:
            return None

        vdev_id = _create_le32(data[4:])
        peer_addr = data[8:16]
        peer_type = _create_le32(data[16:])

        try:
            peer_type_enum = WmiTlvPeerType(peer_type)
        except ValueError:
            peer_type_enum = WmiTlvPeerType.WMI_PEER_TYPE_UNKNOWN

        self.tlv_msg = PeerCreateMsg(tlv_hdr=tlv_hdr,
                                     vdev_id=vdev_id,
                                     peer_addr=peer_addr,
                                     peer_type=peer_type_enum)

    def print_data(self, fp):

        _print_named_tuple(self.tlv_msg, fp)


class WmiTlvMsgPeerSetParam(WmiTlvMsg):

    def __init__(self, data):

        tlv_hdr = _create_tlv_hdr(data)
        if tlv_hdr.length < 20:
            return None

        vdev_id = _create_le32(data[4:])
        peer_macaddr = data[8:16]
        param_id = _create_le32(data[16:])
        param_value = _create_le32(data[20:])

        try:
            param_id_enum = WmiTlvPeerParam(param_id)
        except ValueError:
            param_id_enum = WmiTlvPeerParam.WMI_PEER_PARAM_UNKNOWN

        self.tlv_msg = PeerSetParamMsg(tlv_hdr=tlv_hdr,
                                       vdev_id=vdev_id,
                                       peer_macaddr=peer_macaddr,
                                       param_id=param_id_enum,
                                       param_value=param_value)

    def print_data(self, fp):

        _print_named_tuple(self.tlv_msg, fp)


@unique
class WmiTlvTag(Enum):
    WMI_TLV_TAG_LAST_RESERVED = 15

    WMI_TLV_TAG_ARRAY_UINT32 = 16
    WMI_TLV_TAG_ARRAY_BYTE = 17
    WMI_TLV_TAG_ARRAY_STRUCT = 18
    WMI_TLV_TAG_ARRAY_FIXED_STRUCT = 19
    WMI_TLV_TAG_LAST_ARRAY_ENUM = 31

    WMI_TLV_TAG_STRUCT_SERVICE_READY_EVENT = 32
    WMI_TLV_TAG_STRUCT_HAL_REG_CAPABILITIES = 33
    WMI_TLV_TAG_STRUCT_WLAN_HOST_MEM_REQ = 34
    WMI_TLV_TAG_STRUCT_READY_EVENT = 35
    WMI_TLV_TAG_STRUCT_SCAN_EVENT = 36
    WMI_TLV_TAG_STRUCT_PDEV_TPC_CONFIG_EVENT = 37
    WMI_TLV_TAG_STRUCT_CHAN_INFO_EVENT = 38
    WMI_TLV_TAG_STRUCT_COMB_PHYERR_RX_HDR = 39
    WMI_TLV_TAG_STRUCT_VDEV_START_RESPONSE_EVENT = 40
    WMI_TLV_TAG_STRUCT_VDEV_STOPPED_EVENT = 41
    WMI_TLV_TAG_STRUCT_VDEV_INSTALL_KEY_COMPLETE_EVENT = 42
    WMI_TLV_TAG_STRUCT_PEER_STA_KICKOUT_EVENT = 43
    WMI_TLV_TAG_STRUCT_MGMT_RX_HDR = 44
    WMI_TLV_TAG_STRUCT_TBTT_OFFSET_EVENT = 45
    WMI_TLV_TAG_STRUCT_TX_DELBA_COMPLETE_EVENT = 46
    WMI_TLV_TAG_STRUCT_TX_ADDBA_COMPLETE_EVENT = 47
    WMI_TLV_TAG_STRUCT_ROAM_EVENT = 48
    WMI_TLV_TAG_STRUCT_WOW_EVENT_INFO = 49
    WMI_TLV_TAG_STRUCT_WOW_EVENT_INFO_SECTION_BITMAP = 50
    WMI_TLV_TAG_STRUCT_RTT_EVENT_HEADER = 51
    WMI_TLV_TAG_STRUCT_RTT_ERROR_REPORT_EVENT = 52
    WMI_TLV_TAG_STRUCT_RTT_MEAS_EVENT = 53
    WMI_TLV_TAG_STRUCT_ECHO_EVENT = 54
    WMI_TLV_TAG_STRUCT_FTM_INTG_EVENT = 55
    WMI_TLV_TAG_STRUCT_VDEV_GET_KEEPALIVE_EVENT = 56
    WMI_TLV_TAG_STRUCT_GPIO_INPUT_EVENT = 57
    WMI_TLV_TAG_STRUCT_CSA_EVENT = 58
    WMI_TLV_TAG_STRUCT_GTK_OFFLOAD_STATUS_EVENT = 59
    WMI_TLV_TAG_STRUCT_IGTK_INFO = 60
    WMI_TLV_TAG_STRUCT_DCS_INTERFERENCE_EVENT = 61
    WMI_TLV_TAG_STRUCT_ATH_DCS_CW_INT = 62
    WMI_TLV_TAG_STRUCT_ATH_DCS_WLAN_INT_STAT = 63
    WMI_TLV_TAG_STRUCT_WLAN_PROFILE_CTX_T = 64
    WMI_TLV_TAG_STRUCT_WLAN_PROFILE_T = 65
    WMI_TLV_TAG_STRUCT_PDEV_QVIT_EVENT = 66
    WMI_TLV_TAG_STRUCT_HOST_SWBA_EVENT = 67
    WMI_TLV_TAG_STRUCT_TIM_INFO = 68
    WMI_TLV_TAG_STRUCT_P2P_NOA_INFO = 69
    WMI_TLV_TAG_STRUCT_STATS_EVENT = 70
    WMI_TLV_TAG_STRUCT_AVOID_FREQ_RANGES_EVENT = 71
    WMI_TLV_TAG_STRUCT_AVOID_FREQ_RANGE_DESC = 72
    WMI_TLV_TAG_STRUCT_GTK_REKEY_FAIL_EVENT = 73
    WMI_TLV_TAG_STRUCT_INIT_CMD = 74
    WMI_TLV_TAG_STRUCT_RESOURCE_CONFIG = 75
    WMI_TLV_TAG_STRUCT_WLAN_HOST_MEMORY_CHUNK = 76
    WMI_TLV_TAG_STRUCT_START_SCAN_CMD = 77
    WMI_TLV_TAG_STRUCT_STOP_SCAN_CMD = 78
    WMI_TLV_TAG_STRUCT_SCAN_CHAN_LIST_CMD = 79
    WMI_TLV_TAG_STRUCT_CHANNEL = 80
    WMI_TLV_TAG_STRUCT_PDEV_SET_REGDOMAIN_CMD = 81
    WMI_TLV_TAG_STRUCT_PDEV_SET_PARAM_CMD = 82
    WMI_TLV_TAG_STRUCT_PDEV_SET_WMM_PARAMS_CMD = 83
    WMI_TLV_TAG_STRUCT_WMM_PARAMS = 84
    WMI_TLV_TAG_STRUCT_PDEV_SET_QUIET_CMD = 85
    WMI_TLV_TAG_STRUCT_VDEV_CREATE_CMD = 86
    WMI_TLV_TAG_STRUCT_VDEV_DELETE_CMD = 87
    WMI_TLV_TAG_STRUCT_VDEV_START_REQUEST_CMD = 88
    WMI_TLV_TAG_STRUCT_P2P_NOA_DESCRIPTOR = 89
    WMI_TLV_TAG_STRUCT_P2P_GO_SET_BEACON_IE = 90
    WMI_TLV_TAG_STRUCT_GTK_OFFLOAD_CMD = 91
    WMI_TLV_TAG_STRUCT_VDEV_UP_CMD = 92
    WMI_TLV_TAG_STRUCT_VDEV_STOP_CMD = 93
    WMI_TLV_TAG_STRUCT_VDEV_DOWN_CMD = 94
    WMI_TLV_TAG_STRUCT_VDEV_SET_PARAM_CMD = 95
    WMI_TLV_TAG_STRUCT_VDEV_INSTALL_KEY_CMD = 96
    WMI_TLV_TAG_STRUCT_PEER_CREATE_CMD = 97
    WMI_TLV_TAG_STRUCT_PEER_DELETE_CMD = 98
    WMI_TLV_TAG_STRUCT_PEER_FLUSH_TIDS_CMD = 99
    WMI_TLV_TAG_STRUCT_PEER_SET_PARAM_CMD = 100
    WMI_TLV_TAG_STRUCT_PEER_ASSOC_COMPLETE_CMD = 101
    WMI_TLV_TAG_STRUCT_VHT_RATE_SET = 102
    WMI_TLV_TAG_STRUCT_BCN_TMPL_CMD = 103
    WMI_TLV_TAG_STRUCT_PRB_TMPL_CMD = 104
    WMI_TLV_TAG_STRUCT_BCN_PRB_INFO = 105
    WMI_TLV_TAG_STRUCT_PEER_TID_ADDBA_CMD = 106
    WMI_TLV_TAG_STRUCT_PEER_TID_DELBA_CMD = 107
    WMI_TLV_TAG_STRUCT_STA_POWERSAVE_MODE_CMD = 108
    WMI_TLV_TAG_STRUCT_STA_POWERSAVE_PARAM_CMD = 109
    WMI_TLV_TAG_STRUCT_STA_DTIM_PS_METHOD_CMD = 110
    WMI_TLV_TAG_STRUCT_ROAM_SCAN_MODE = 111
    WMI_TLV_TAG_STRUCT_ROAM_SCAN_RSSI_THRESHOLD = 112
    WMI_TLV_TAG_STRUCT_ROAM_SCAN_PERIOD = 113
    WMI_TLV_TAG_STRUCT_ROAM_SCAN_RSSI_CHANGE_THRESHOLD = 114
    WMI_TLV_TAG_STRUCT_PDEV_SUSPEND_CMD = 115
    WMI_TLV_TAG_STRUCT_PDEV_RESUME_CMD = 116
    WMI_TLV_TAG_STRUCT_ADD_BCN_FILTER_CMD = 117
    WMI_TLV_TAG_STRUCT_RMV_BCN_FILTER_CMD = 118
    WMI_TLV_TAG_STRUCT_WOW_ENABLE_CMD = 119
    WMI_TLV_TAG_STRUCT_WOW_HOSTWAKEUP_FROM_SLEEP_CMD = 120
    WMI_TLV_TAG_STRUCT_STA_UAPSD_AUTO_TRIG_CMD = 121
    WMI_TLV_TAG_STRUCT_STA_UAPSD_AUTO_TRIG_PARAM = 122
    WMI_TLV_TAG_STRUCT_SET_ARP_NS_OFFLOAD_CMD = 123
    WMI_TLV_TAG_STRUCT_ARP_OFFLOAD_TUPLE = 124
    WMI_TLV_TAG_STRUCT_NS_OFFLOAD_TUPLE = 125
    WMI_TLV_TAG_STRUCT_FTM_INTG_CMD = 126
    WMI_TLV_TAG_STRUCT_STA_KEEPALIVE_CMD = 127
    WMI_TLV_TAG_STRUCT_STA_KEEPALVE_ARP_RESPONSE = 128
    WMI_TLV_TAG_STRUCT_P2P_SET_VENDOR_IE_DATA_CMD = 129
    WMI_TLV_TAG_STRUCT_AP_PS_PEER_CMD = 130
    WMI_TLV_TAG_STRUCT_PEER_RATE_RETRY_SCHED_CMD = 131
    WMI_TLV_TAG_STRUCT_WLAN_PROFILE_TRIGGER_CMD = 132
    WMI_TLV_TAG_STRUCT_WLAN_PROFILE_SET_HIST_INTVL_CMD = 133
    WMI_TLV_TAG_STRUCT_WLAN_PROFILE_GET_PROF_DATA_CMD = 134
    WMI_TLV_TAG_STRUCT_WLAN_PROFILE_ENABLE_PROFILE_ID_CMD = 135
    WMI_TLV_TAG_STRUCT_WOW_DEL_PATTERN_CMD = 136
    WMI_TLV_TAG_STRUCT_WOW_ADD_DEL_EVT_CMD = 137
    WMI_TLV_TAG_STRUCT_RTT_MEASREQ_HEAD = 138
    WMI_TLV_TAG_STRUCT_RTT_MEASREQ_BODY = 139
    WMI_TLV_TAG_STRUCT_RTT_TSF_CMD = 140
    WMI_TLV_TAG_STRUCT_VDEV_SPECTRAL_CONFIGURE_CMD = 141
    WMI_TLV_TAG_STRUCT_VDEV_SPECTRAL_ENABLE_CMD = 142
    WMI_TLV_TAG_STRUCT_REQUEST_STATS_CMD = 143
    WMI_TLV_TAG_STRUCT_NLO_CONFIG_CMD = 144
    WMI_TLV_TAG_STRUCT_NLO_CONFIGURED_PARAMETERS = 145
    WMI_TLV_TAG_STRUCT_CSA_OFFLOAD_ENABLE_CMD = 146
    WMI_TLV_TAG_STRUCT_CSA_OFFLOAD_CHANSWITCH_CMD = 147
    WMI_TLV_TAG_STRUCT_CHATTER_SET_MODE_CMD = 148
    WMI_TLV_TAG_STRUCT_ECHO_CMD = 149
    WMI_TLV_TAG_STRUCT_VDEV_SET_KEEPALIVE_CMD = 150
    WMI_TLV_TAG_STRUCT_VDEV_GET_KEEPALIVE_CMD = 151
    WMI_TLV_TAG_STRUCT_FORCE_FW_HANG_CMD = 152
    WMI_TLV_TAG_STRUCT_GPIO_CONFIG_CMD = 153
    WMI_TLV_TAG_STRUCT_GPIO_OUTPUT_CMD = 154
    WMI_TLV_TAG_STRUCT_PEER_ADD_WDS_ENTRY_CMD = 155
    WMI_TLV_TAG_STRUCT_PEER_REMOVE_WDS_ENTRY_CMD = 156
    WMI_TLV_TAG_STRUCT_BCN_TX_HDR = 157
    WMI_TLV_TAG_STRUCT_BCN_SEND_FROM_HOST_CMD = 158
    WMI_TLV_TAG_STRUCT_MGMT_TX_HDR = 159
    WMI_TLV_TAG_STRUCT_ADDBA_CLEAR_RESP_CMD = 160
    WMI_TLV_TAG_STRUCT_ADDBA_SEND_CMD = 161
    WMI_TLV_TAG_STRUCT_DELBA_SEND_CMD = 162
    WMI_TLV_TAG_STRUCT_ADDBA_SETRESPONSE_CMD = 163
    WMI_TLV_TAG_STRUCT_SEND_SINGLEAMSDU_CMD = 164
    WMI_TLV_TAG_STRUCT_PDEV_PKTLOG_ENABLE_CMD = 165
    WMI_TLV_TAG_STRUCT_PDEV_PKTLOG_DISABLE_CMD = 166
    WMI_TLV_TAG_STRUCT_PDEV_SET_HT_IE_CMD = 167
    WMI_TLV_TAG_STRUCT_PDEV_SET_VHT_IE_CMD = 168
    WMI_TLV_TAG_STRUCT_PDEV_SET_DSCP_TID_MAP_CMD = 169
    WMI_TLV_TAG_STRUCT_PDEV_GREEN_AP_PS_ENABLE_CMD = 170
    WMI_TLV_TAG_STRUCT_PDEV_GET_TPC_CONFIG_CMD = 171
    WMI_TLV_TAG_STRUCT_PDEV_SET_BASE_MACADDR_CMD = 172
    WMI_TLV_TAG_STRUCT_PEER_MCAST_GROUP_CMD = 173
    WMI_TLV_TAG_STRUCT_ROAM_AP_PROFILE = 174
    WMI_TLV_TAG_STRUCT_AP_PROFILE = 175
    WMI_TLV_TAG_STRUCT_SCAN_SCH_PRIORITY_TABLE_CMD = 176
    WMI_TLV_TAG_STRUCT_PDEV_DFS_ENABLE_CMD = 177
    WMI_TLV_TAG_STRUCT_PDEV_DFS_DISABLE_CMD = 178
    WMI_TLV_TAG_STRUCT_WOW_ADD_PATTERN_CMD = 179
    WMI_TLV_TAG_STRUCT_WOW_BITMAP_PATTERN_T = 180
    WMI_TLV_TAG_STRUCT_WOW_IPV4_SYNC_PATTERN_T = 181
    WMI_TLV_TAG_STRUCT_WOW_IPV6_SYNC_PATTERN_T = 182
    WMI_TLV_TAG_STRUCT_WOW_MAGIC_PATTERN_CMD = 183
    WMI_TLV_TAG_STRUCT_SCAN_UPDATE_REQUEST_CMD = 184
    WMI_TLV_TAG_STRUCT_CHATTER_PKT_COALESCING_FILTER = 185
    WMI_TLV_TAG_STRUCT_CHATTER_COALESCING_ADD_FILTER_CMD = 186
    WMI_TLV_TAG_STRUCT_CHATTER_COALESCING_DELETE_FILTER_CMD = 187
    WMI_TLV_TAG_STRUCT_CHATTER_COALESCING_QUERY_CMD = 188
    WMI_TLV_TAG_STRUCT_TXBF_CMD = 189
    WMI_TLV_TAG_STRUCT_DEBUG_LOG_CONFIG_CMD = 190
    WMI_TLV_TAG_STRUCT_NLO_EVENT = 191
    WMI_TLV_TAG_STRUCT_CHATTER_QUERY_REPLY_EVENT = 192
    WMI_TLV_TAG_STRUCT_UPLOAD_H_HDR = 193
    WMI_TLV_TAG_STRUCT_CAPTURE_H_EVENT_HDR = 194
    WMI_TLV_TAG_STRUCT_VDEV_WNM_SLEEPMODE_CMD = 195
    WMI_TLV_TAG_STRUCT_VDEV_IPSEC_NATKEEPALIVE_FILTER_CMD = 196
    WMI_TLV_TAG_STRUCT_VDEV_WMM_ADDTS_CMD = 197
    WMI_TLV_TAG_STRUCT_VDEV_WMM_DELTS_CMD = 198
    WMI_TLV_TAG_STRUCT_VDEV_SET_WMM_PARAMS_CMD = 199
    WMI_TLV_TAG_STRUCT_TDLS_SET_STATE_CMD = 200
    WMI_TLV_TAG_STRUCT_TDLS_PEER_UPDATE_CMD = 201
    WMI_TLV_TAG_STRUCT_TDLS_PEER_EVENT = 202
    WMI_TLV_TAG_STRUCT_TDLS_PEER_CAPABILITIES = 203
    WMI_TLV_TAG_STRUCT_VDEV_MCC_SET_TBTT_MODE_CMD = 204
    WMI_TLV_TAG_STRUCT_ROAM_CHAN_LIST = 205
    WMI_TLV_TAG_STRUCT_VDEV_MCC_BCN_INTVL_CHANGE_EVENT = 206
    WMI_TLV_TAG_STRUCT_RESMGR_ADAPTIVE_OCS_CMD = 207
    WMI_TLV_TAG_STRUCT_RESMGR_SET_CHAN_TIME_QUOTA_CMD = 208
    WMI_TLV_TAG_STRUCT_RESMGR_SET_CHAN_LATENCY_CMD = 209
    WMI_TLV_TAG_STRUCT_BA_REQ_SSN_CMD = 210
    WMI_TLV_TAG_STRUCT_BA_RSP_SSN_EVENT = 211
    WMI_TLV_TAG_STRUCT_STA_SMPS_FORCE_MODE_CMD = 212
    WMI_TLV_TAG_STRUCT_SET_MCASTBCAST_FILTER_CMD = 213
    WMI_TLV_TAG_STRUCT_P2P_SET_OPPPS_CMD = 214
    WMI_TLV_TAG_STRUCT_P2P_SET_NOA_CMD = 215
    WMI_TLV_TAG_STRUCT_BA_REQ_SSN_CMD_SUB_STRUCT_PARAM = 216
    WMI_TLV_TAG_STRUCT_BA_REQ_SSN_EVENT_SUB_STRUCT_PARAM = 217
    WMI_TLV_TAG_STRUCT_STA_SMPS_PARAM_CMD = 218
    WMI_TLV_TAG_STRUCT_VDEV_SET_GTX_PARAMS_CMD = 219
    WMI_TLV_TAG_STRUCT_MCC_SCHED_TRAFFIC_STATS_CMD = 220
    WMI_TLV_TAG_STRUCT_MCC_SCHED_STA_TRAFFIC_STATS = 221
    WMI_TLV_TAG_STRUCT_OFFLOAD_BCN_TX_STATUS_EVENT = 222
    WMI_TLV_TAG_STRUCT_P2P_NOA_EVENT = 223
    WMI_TLV_TAG_STRUCT_HB_SET_ENABLE_CMD = 224
    WMI_TLV_TAG_STRUCT_HB_SET_TCP_PARAMS_CMD = 225
    WMI_TLV_TAG_STRUCT_HB_SET_TCP_PKT_FILTER_CMD = 226
    WMI_TLV_TAG_STRUCT_HB_SET_UDP_PARAMS_CMD = 227
    WMI_TLV_TAG_STRUCT_HB_SET_UDP_PKT_FILTER_CMD = 228
    WMI_TLV_TAG_STRUCT_HB_IND_EVENT = 229
    WMI_TLV_TAG_STRUCT_TX_PAUSE_EVENT = 230
    WMI_TLV_TAG_STRUCT_RFKILL_EVENT = 231
    WMI_TLV_TAG_STRUCT_DFS_RADAR_EVENT = 232
    WMI_TLV_TAG_STRUCT_DFS_PHYERR_FILTER_ENA_CMD = 233
    WMI_TLV_TAG_STRUCT_DFS_PHYERR_FILTER_DIS_CMD = 234
    WMI_TLV_TAG_STRUCT_BATCH_SCAN_RESULT_SCAN_LIST = 235
    WMI_TLV_TAG_STRUCT_BATCH_SCAN_RESULT_NETWORK_INFO = 236
    WMI_TLV_TAG_STRUCT_BATCH_SCAN_ENABLE_CMD = 237
    WMI_TLV_TAG_STRUCT_BATCH_SCAN_DISABLE_CMD = 238
    WMI_TLV_TAG_STRUCT_BATCH_SCAN_TRIGGER_RESULT_CMD = 239
    WMI_TLV_TAG_STRUCT_BATCH_SCAN_ENABLED_EVENT = 240
    WMI_TLV_TAG_STRUCT_BATCH_SCAN_RESULT_EVENT = 241
    WMI_TLV_TAG_STRUCT_VDEV_PLMREQ_START_CMD = 242
    WMI_TLV_TAG_STRUCT_VDEV_PLMREQ_STOP_CMD = 243
    WMI_TLV_TAG_STRUCT_THERMAL_MGMT_CMD = 244
    WMI_TLV_TAG_STRUCT_THERMAL_MGMT_EVENT = 245
    WMI_TLV_TAG_STRUCT_PEER_INFO_REQ_CMD = 246
    WMI_TLV_TAG_STRUCT_PEER_INFO_EVENT = 247
    WMI_TLV_TAG_STRUCT_PEER_INFO = 248
    WMI_TLV_TAG_STRUCT_PEER_TX_FAIL_CNT_THR_EVENT = 249
    WMI_TLV_TAG_STRUCT_RMC_SET_MODE_CMD = 250
    WMI_TLV_TAG_STRUCT_RMC_SET_ACTION_PERIOD_CMD = 251
    WMI_TLV_TAG_STRUCT_RMC_CONFIG_CMD = 252
    WMI_TLV_TAG_STRUCT_MHF_OFFLOAD_SET_MODE_CMD = 253
    WMI_TLV_TAG_STRUCT_MHF_OFFLOAD_PLUMB_ROUTING_TABLE_CMD = 254
    WMI_TLV_TAG_STRUCT_ADD_PROACTIVE_ARP_RSP_PATTERN_CMD = 255
    WMI_TLV_TAG_STRUCT_DEL_PROACTIVE_ARP_RSP_PATTERN_CMD = 256
    WMI_TLV_TAG_STRUCT_NAN_CMD_PARAM = 257
    WMI_TLV_TAG_STRUCT_NAN_EVENT_HDR = 258
    WMI_TLV_TAG_STRUCT_PDEV_L1SS_TRACK_EVENT = 259
    WMI_TLV_TAG_STRUCT_DIAG_DATA_CONTAINER_EVENT = 260
    WMI_TLV_TAG_STRUCT_MODEM_POWER_STATE_CMD_PARAM = 261
    WMI_TLV_TAG_STRUCT_PEER_GET_ESTIMATED_LINKSPEED_CMD = 262
    WMI_TLV_TAG_STRUCT_PEER_ESTIMATED_LINKSPEED_EVENT = 263
    WMI_TLV_TAG_STRUCT_AGGR_STATE_TRIG_EVENT = 264
    WMI_TLV_TAG_STRUCT_MHF_OFFLOAD_ROUTING_TABLE_ENTRY = 265
    WMI_TLV_TAG_STRUCT_ROAM_SCAN_CMD = 266
    WMI_TLV_TAG_STRUCT_REQ_STATS_EXT_CMD = 267
    WMI_TLV_TAG_STRUCT_STATS_EXT_EVENT = 268
    WMI_TLV_TAG_STRUCT_OBSS_SCAN_ENABLE_CMD = 269
    WMI_TLV_TAG_STRUCT_OBSS_SCAN_DISABLE_CMD = 270
    WMI_TLV_TAG_STRUCT_OFFLOAD_PRB_RSP_TX_STATUS_EVENT = 271
    WMI_TLV_TAG_STRUCT_PDEV_SET_LED_CONFIG_CMD = 272
    WMI_TLV_TAG_STRUCT_HOST_AUTO_SHUTDOWN_CFG_CMD = 273
    WMI_TLV_TAG_STRUCT_HOST_AUTO_SHUTDOWN_EVENT = 274
    WMI_TLV_TAG_STRUCT_UPDATE_WHAL_MIB_STATS_EVENT = 275
    WMI_TLV_TAG_STRUCT_CHAN_AVOID_UPDATE_CMD_PARAM = 276
    WMI_TLV_TAG_STRUCT_WOW_ACER_IOAC_PKT_PATTERN_T = 277
    WMI_TLV_TAG_STRUCT_WOW_ACER_IOAC_TMR_PATTERN_T = 278
    WMI_TLV_TAG_STRUCT_WOW_IOAC_ADD_KEEPALIVE_CMD = 279
    WMI_TLV_TAG_STRUCT_WOW_IOAC_DEL_KEEPALIVE_CMD = 280
    WMI_TLV_TAG_STRUCT_WOW_IOAC_KEEPALIVE_T = 281
    WMI_TLV_TAG_STRUCT_WOW_ACER_IOAC_ADD_PATTERN_CMD = 282
    WMI_TLV_TAG_STRUCT_WOW_ACER_IOAC_DEL_PATTERN_CMD = 283
    WMI_TLV_TAG_STRUCT_START_LINK_STATS_CMD = 284
    WMI_TLV_TAG_STRUCT_CLEAR_LINK_STATS_CMD = 285
    WMI_TLV_TAG_STRUCT_REQUEST_LINK_STATS_CMD = 286
    WMI_TLV_TAG_STRUCT_IFACE_LINK_STATS_EVENT = 287
    WMI_TLV_TAG_STRUCT_RADIO_LINK_STATS_EVENT = 288
    WMI_TLV_TAG_STRUCT_PEER_STATS_EVENT = 289
    WMI_TLV_TAG_STRUCT_CHANNEL_STATS = 290
    WMI_TLV_TAG_STRUCT_RADIO_LINK_STATS = 291
    WMI_TLV_TAG_STRUCT_RATE_STATS = 292
    WMI_TLV_TAG_STRUCT_PEER_LINK_STATS = 293
    WMI_TLV_TAG_STRUCT_WMM_AC_STATS = 294
    WMI_TLV_TAG_STRUCT_IFACE_LINK_STATS = 295
    WMI_TLV_TAG_STRUCT_LPI_MGMT_SNOOPING_CONFIG_CMD = 296
    WMI_TLV_TAG_STRUCT_LPI_START_SCAN_CMD = 297
    WMI_TLV_TAG_STRUCT_LPI_STOP_SCAN_CMD = 298
    WMI_TLV_TAG_STRUCT_LPI_RESULT_EVENT = 299
    WMI_TLV_TAG_STRUCT_PEER_STATE_EVENT = 300
    WMI_TLV_TAG_STRUCT_EXTSCAN_BUCKET_CMD = 301
    WMI_TLV_TAG_STRUCT_EXTSCAN_BUCKET_CHANNEL_EVENT = 302
    WMI_TLV_TAG_STRUCT_EXTSCAN_START_CMD = 303
    WMI_TLV_TAG_STRUCT_EXTSCAN_STOP_CMD = 304
    WMI_TLV_TAG_STRUCT_EXTSCAN_CONFIGURE_WLAN_CHANGE_MONITOR_CMD = 305
    WMI_TLV_TAG_STRUCT_EXTSCAN_WLAN_CHANGE_BSSID_PARAM_CMD = 306
    WMI_TLV_TAG_STRUCT_EXTSCAN_CONFIGURE_HOTLIST_MONITOR_CMD = 307
    WMI_TLV_TAG_STRUCT_EXTSCAN_GET_CACHED_RESULTS_CMD = 308
    WMI_TLV_TAG_STRUCT_EXTSCAN_GET_WLAN_CHANGE_RESULTS_CMD = 309
    WMI_TLV_TAG_STRUCT_EXTSCAN_SET_CAPABILITIES_CMD = 310
    WMI_TLV_TAG_STRUCT_EXTSCAN_GET_CAPABILITIES_CMD = 311
    WMI_TLV_TAG_STRUCT_EXTSCAN_OPERATION_EVENT = 312
    WMI_TLV_TAG_STRUCT_EXTSCAN_START_STOP_EVENT = 313
    WMI_TLV_TAG_STRUCT_EXTSCAN_TABLE_USAGE_EVENT = 314
    WMI_TLV_TAG_STRUCT_EXTSCAN_WLAN_DESCRIPTOR_EVENT = 315
    WMI_TLV_TAG_STRUCT_EXTSCAN_RSSI_INFO_EVENT = 316
    WMI_TLV_TAG_STRUCT_EXTSCAN_CACHED_RESULTS_EVENT = 317
    WMI_TLV_TAG_STRUCT_EXTSCAN_WLAN_CHANGE_RESULTS_EVENT = 318
    WMI_TLV_TAG_STRUCT_EXTSCAN_WLAN_CHANGE_RESULT_BSSID_EVENT = 319
    WMI_TLV_TAG_STRUCT_EXTSCAN_HOTLIST_MATCH_EVENT = 320
    WMI_TLV_TAG_STRUCT_EXTSCAN_CAPABILITIES_EVENT = 321
    WMI_TLV_TAG_STRUCT_EXTSCAN_CACHE_CAPABILITIES_EVENT = 322
    WMI_TLV_TAG_STRUCT_EXTSCAN_WLAN_CHANGE_MONITOR_CAPABILITIES_EVENT = 323
    WMI_TLV_TAG_STRUCT_EXTSCAN_HOTLIST_MONITOR_CAPABILITIES_EVENT = 324
    WMI_TLV_TAG_STRUCT_D0_WOW_ENABLE_DISABLE_CMD = 325
    WMI_TLV_TAG_STRUCT_D0_WOW_DISABLE_ACK_EVENT = 326
    WMI_TLV_TAG_STRUCT_UNIT_TEST_CMD = 327
    WMI_TLV_TAG_STRUCT_ROAM_OFFLOAD_TLV_PARAM = 328
    WMI_TLV_TAG_STRUCT_ROAM_11I_OFFLOAD_TLV_PARAM = 329
    WMI_TLV_TAG_STRUCT_ROAM_11R_OFFLOAD_TLV_PARAM = 330
    WMI_TLV_TAG_STRUCT_ROAM_ESE_OFFLOAD_TLV_PARAM = 331
    WMI_TLV_TAG_STRUCT_ROAM_SYNCH_EVENT = 332
    WMI_TLV_TAG_STRUCT_ROAM_SYNCH_COMPLETE = 333
    WMI_TLV_TAG_STRUCT_EXTWOW_ENABLE_CMD = 334
    WMI_TLV_TAG_STRUCT_EXTWOW_SET_APP_TYPE1_PARAMS_CMD = 335
    WMI_TLV_TAG_STRUCT_EXTWOW_SET_APP_TYPE2_PARAMS_CMD = 336
    WMI_TLV_TAG_STRUCT_LPI_STATUS_EVENT = 337
    WMI_TLV_TAG_STRUCT_LPI_HANDOFF_EVENT = 338
    WMI_TLV_TAG_STRUCT_VDEV_RATE_STATS_EVENT = 339
    WMI_TLV_TAG_STRUCT_VDEV_RATE_HT_INFO = 340
    WMI_TLV_TAG_STRUCT_RIC_REQUEST = 341
    WMI_TLV_TAG_STRUCT_PDEV_GET_TEMPERATURE_CMD = 342
    WMI_TLV_TAG_STRUCT_PDEV_TEMPERATURE_EVENT = 343
    WMI_TLV_TAG_STRUCT_SET_DHCP_SERVER_OFFLOAD_CMD = 344
    WMI_TLV_TAG_STRUCT_TPC_CHAINMASK_CONFIG_CMD = 345
    WMI_TLV_TAG_STRUCT_RIC_TSPEC = 346
    WMI_TLV_TAG_STRUCT_TPC_CHAINMASK_CONFIG = 347
    WMI_TLV_TAG_STRUCT_IPA_OFFLOAD_CMD = 348
    WMI_TLV_TAG_STRUCT_SCAN_PROB_REQ_OUI_CMD = 349
    WMI_TLV_TAG_STRUCT_KEY_MATERIAL = 350
    WMI_TLV_TAG_STRUCT_TDLS_SET_OFFCHAN_MODE_CMD = 351
    WMI_TLV_TAG_STRUCT_SET_LED_FLASHING_CMD = 352
    WMI_TLV_TAG_STRUCT_MDNS_OFFLOAD_CMD = 353
    WMI_TLV_TAG_STRUCT_MDNS_SET_FQDN_CMD = 354
    WMI_TLV_TAG_STRUCT_MDNS_SET_RESP_CMD = 355
    WMI_TLV_TAG_STRUCT_MDNS_GET_STATS_CMD = 356
    WMI_TLV_TAG_STRUCT_MDNS_STATS_EVENT = 357
    WMI_TLV_TAG_STRUCT_ROAM_INVOKE_CMD = 358
    WMI_TLV_TAG_STRUCT_PDEV_RESUME_EVENT = 359
    WMI_TLV_TAG_STRUCT_PDEV_SET_ANTENNA_DIVERSITY_CMD = 360
    WMI_TLV_TAG_STRUCT_SAP_OFL_ENABLE_CMD = 361
    WMI_TLV_TAG_STRUCT_SAP_OFL_ADD_STA_EVENT = 362
    WMI_TLV_TAG_STRUCT_SAP_OFL_DEL_STA_EVENT = 363
    WMI_TLV_TAG_STRUCT_APFIND_CMD_PARAM = 364
    WMI_TLV_TAG_STRUCT_APFIND_EVENT_HDR = 365

    WMI_TLV_TAG_MAX = 366
    WMI_TLV_TAG_UNKNOWN = 0xFFFF


@unique
class WmiTlvPdevParam(Enum):

    WMI_TLV_PDEV_PARAM_TX_CHAIN_MASK = 1
    WMI_TLV_PDEV_PARAM_RX_CHAIN_MASK = 2
    WMI_TLV_PDEV_PARAM_TXPOWER_LIMIT2G = 3
    WMI_TLV_PDEV_PARAM_TXPOWER_LIMIT5G = 4
    WMI_TLV_PDEV_PARAM_TXPOWER_SCALE = 5
    WMI_TLV_PDEV_PARAM_BEACON_GEN_MODE = 6
    WMI_TLV_PDEV_PARAM_BEACON_TX_MODE = 7
    WMI_TLV_PDEV_PARAM_RESMGR_OFFCHAN_MODE = 8
    WMI_TLV_PDEV_PARAM_PROTECTION_MODE = 9
    WMI_TLV_PDEV_PARAM_DYNAMIC_BW = 10
    WMI_TLV_PDEV_PARAM_NON_AGG_SW_RETRY_TH = 11
    WMI_TLV_PDEV_PARAM_AGG_SW_RETRY_TH = 12
    WMI_TLV_PDEV_PARAM_STA_KICKOUT_TH = 13
    WMI_TLV_PDEV_PARAM_AC_AGGRSIZE_SCALING = 14
    WMI_TLV_PDEV_PARAM_LTR_ENABLE = 15
    WMI_TLV_PDEV_PARAM_LTR_AC_LATENCY_BE = 16
    WMI_TLV_PDEV_PARAM_LTR_AC_LATENCY_BK = 17
    WMI_TLV_PDEV_PARAM_LTR_AC_LATENCY_VI = 18
    WMI_TLV_PDEV_PARAM_LTR_AC_LATENCY_VO = 19
    WMI_TLV_PDEV_PARAM_LTR_AC_LATENCY_TIMEOUT = 20
    WMI_TLV_PDEV_PARAM_LTR_SLEEP_OVERRIDE = 21
    WMI_TLV_PDEV_PARAM_LTR_RX_OVERRIDE = 22
    WMI_TLV_PDEV_PARAM_LTR_TX_ACTIVITY_TIMEOUT = 23
    WMI_TLV_PDEV_PARAM_L1SS_ENABLE = 24
    WMI_TLV_PDEV_PARAM_DSLEEP_ENABLE = 25
    WMI_TLV_PDEV_PARAM_PCIELP_TXBUF_FLUSH = 26
    WMI_TLV_PDEV_PARAM_PCIELP_TXBUF_WATERMARK = 27
    WMI_TLV_PDEV_PARAM_PCIELP_TXBUF_TMO_EN = 28
    WMI_TLV_PDEV_PARAM_PCIELP_TXBUF_TMO_VALUE = 29
    WMI_TLV_PDEV_PARAM_PDEV_STATS_UPDATE_PERIOD = 30
    WMI_TLV_PDEV_PARAM_VDEV_STATS_UPDATE_PERIOD = 31
    WMI_TLV_PDEV_PARAM_PEER_STATS_UPDATE_PERIOD = 32
    WMI_TLV_PDEV_PARAM_BCNFLT_STATS_UPDATE_PERIOD = 33
    WMI_TLV_PDEV_PARAM_PMF_QOS = 34
    WMI_TLV_PDEV_PARAM_ARP_AC_OVERRIDE = 35
    WMI_TLV_PDEV_PARAM_DCS = 36
    WMI_TLV_PDEV_PARAM_ANI_ENABLE = 37
    WMI_TLV_PDEV_PARAM_ANI_POLL_PERIOD = 38
    WMI_TLV_PDEV_PARAM_ANI_LISTEN_PERIOD = 39
    WMI_TLV_PDEV_PARAM_ANI_OFDM_LEVEL = 40
    WMI_TLV_PDEV_PARAM_ANI_CCK_LEVEL = 41
    WMI_TLV_PDEV_PARAM_DYNTXCHAIN = 42
    WMI_TLV_PDEV_PARAM_PROXY_STA = 43
    WMI_TLV_PDEV_PARAM_IDLE_PS_CONFIG = 44
    WMI_TLV_PDEV_PARAM_POWER_GATING_SLEEP = 45
    WMI_TLV_PDEV_PARAM_RFKILL_ENABLE = 46
    WMI_TLV_PDEV_PARAM_BURST_DUR = 47
    WMI_TLV_PDEV_PARAM_BURST_ENABLE = 48
    WMI_TLV_PDEV_PARAM_HW_RFKILL_CONFIG = 49
    WMI_TLV_PDEV_PARAM_LOW_POWER_RF_ENABLE = 50
    WMI_TLV_PDEV_PARAM_L1SS_TRACK = 51
    WMI_TLV_PDEV_PARAM_HYST_EN = 52
    WMI_TLV_PDEV_PARAM_POWER_COLLAPSE_ENABLE = 53
    WMI_TLV_PDEV_PARAM_LED_SYS_STATE = 54
    WMI_TLV_PDEV_PARAM_LED_ENABLE = 55
    WMI_TLV_PDEV_PARAM_AUDIO_OVER_WLAN_LATENCY = 56
    WMI_TLV_PDEV_PARAM_AUDIO_OVER_WLAN_ENABLE = 57
    WMI_TLV_PDEV_PARAM_WHAL_MIB_STATS_UPDATE_ENABLE = 58
    WMI_TLV_PDEV_PARAM_VDEV_RATE_STATS_UPDATE_PERIOD = 59
    WMI_TLV_PDEV_PARAM_TXPOWER_REASON_NONE = 60
    WMI_TLV_PDEV_PARAM_TXPOWER_REASON_SAR = 61
    WMI_TLV_PDEV_PARAM_TXPOWER_REASON_MAX = 62
    WMI_TLV_PDEV_PARAM_UNKNOWN = 0xFFFF


@unique
class WmiTlvVdevParam(Enum):
    WMI_TLV_VDEV_PARAM_RTS_THRESHOLD = 1
    WMI_TLV_VDEV_PARAM_FRAGMENTATION_THRESHOLD = 2
    WMI_TLV_VDEV_PARAM_BEACON_INTERVAL = 3
    WMI_TLV_VDEV_PARAM_LISTEN_INTERVAL = 4
    WMI_TLV_VDEV_PARAM_MULTICAST_RATE = 5
    WMI_TLV_VDEV_PARAM_MGMT_TX_RATE = 6
    WMI_TLV_VDEV_PARAM_SLOT_TIME = 7
    WMI_TLV_VDEV_PARAM_PREAMBLE = 8
    WMI_TLV_VDEV_PARAM_SWBA_TIME = 9
    WMI_TLV_VDEV_STATS_UPDATE_PERIOD = 10
    WMI_TLV_VDEV_PWRSAVE_AGEOUT_TIME = 11
    WMI_TLV_VDEV_HOST_SWBA_INTERVAL = 12
    WMI_TLV_VDEV_PARAM_DTIM_PERIOD = 13
    WMI_TLV_VDEV_OC_SCHEDULER_AIR_TIME_LIMIT = 14
    WMI_TLV_VDEV_PARAM_WDS = 15
    WMI_TLV_VDEV_PARAM_ATIM_WINDOW = 16
    WMI_TLV_VDEV_PARAM_BMISS_COUNT_MAX = 17
    WMI_TLV_VDEV_PARAM_BMISS_FIRST_BCNT = 18
    WMI_TLV_VDEV_PARAM_BMISS_FINAL_BCNT = 19
    WMI_TLV_VDEV_PARAM_FEATURE_WMM = 20
    WMI_TLV_VDEV_PARAM_CHWIDTH = 21
    WMI_TLV_VDEV_PARAM_CHEXTOFFSET = 22
    WMI_TLV_VDEV_PARAM_DISABLE_HTPROTECTION = 23
    WMI_TLV_VDEV_PARAM_STA_QUICKKICKOUT = 24
    WMI_TLV_VDEV_PARAM_MGMT_RATE = 25
    WMI_TLV_VDEV_PARAM_PROTECTION_MODE = 26
    WMI_TLV_VDEV_PARAM_FIXED_RATE = 27
    WMI_TLV_VDEV_PARAM_SGI = 28
    WMI_TLV_VDEV_PARAM_LDPC = 29
    WMI_TLV_VDEV_PARAM_TX_STBC = 30
    WMI_TLV_VDEV_PARAM_RX_STBC = 31
    WMI_TLV_VDEV_PARAM_INTRA_BSS_FWD = 32
    WMI_TLV_VDEV_PARAM_DEF_KEYID = 33
    WMI_TLV_VDEV_PARAM_NSS = 34
    WMI_TLV_VDEV_PARAM_BCAST_DATA_RATE = 35
    WMI_TLV_VDEV_PARAM_MCAST_DATA_RATE = 36
    WMI_TLV_VDEV_PARAM_MCAST_INDICATE = 37
    WMI_TLV_VDEV_PARAM_DHCP_INDICATE = 38
    WMI_TLV_VDEV_PARAM_UNKNOWN_DEST_INDICATE = 39
    WMI_TLV_VDEV_PARAM_AP_KEEPALIVE_MIN_IDLE_INACTIVE_TIME_SECS = 40
    WMI_TLV_VDEV_PARAM_AP_KEEPALIVE_MAX_IDLE_INACTIVE_TIME_SECS = 41
    WMI_TLV_VDEV_PARAM_AP_KEEPALIVE_MAX_UNRESPONSIVE_TIME_SECS = 42
    WMI_TLV_VDEV_PARAM_AP_ENABLE_NAWDS = 43
    WMI_TLV_VDEV_PARAM_ENABLE_RTSCTS = 44
    WMI_TLV_VDEV_PARAM_TXBF = 45
    WMI_TLV_VDEV_PARAM_PACKET_POWERSAVE = 46
    WMI_TLV_VDEV_PARAM_DROP_UNENCRY = 47
    WMI_TLV_VDEV_PARAM_TX_ENCAP_TYPE = 48
    WMI_TLV_VDEV_PARAM_AP_DETECT_OUT_OF_SYNC_SLEEPING_STA_TIME_SECS = 49
    WMI_TLV_VDEV_PARAM_EARLY_RX_ADJUST_ENABLE = 50
    WMI_TLV_VDEV_PARAM_EARLY_RX_TGT_BMISS_NUM = 51
    WMI_TLV_VDEV_PARAM_EARLY_RX_BMISS_SAMPLE_CYCLE = 52
    WMI_TLV_VDEV_PARAM_EARLY_RX_SLOP_STEP = 53
    WMI_TLV_VDEV_PARAM_EARLY_RX_INIT_SLOP = 54
    WMI_TLV_VDEV_PARAM_EARLY_RX_ADJUST_PAUSE = 55
    WMI_TLV_VDEV_PARAM_TX_PWRLIMIT = 56
    WMI_TLV_VDEV_PARAM_SNR_NUM_FOR_CAL = 57
    WMI_TLV_VDEV_PARAM_ROAM_FW_OFFLOAD = 58
    WMI_TLV_VDEV_PARAM_ENABLE_RMC = 59
    WMI_TLV_VDEV_PARAM_IBSS_MAX_BCN_LOST_MS = 60
    WMI_TLV_VDEV_PARAM_MAX_RATE = 61
    WMI_TLV_VDEV_PARAM_EARLY_RX_DRIFT_SAMPLE = 62
    WMI_TLV_VDEV_PARAM_SET_IBSS_TX_FAIL_CNT_THR = 63
    WMI_TLV_VDEV_PARAM_EBT_RESYNC_TIMEOUT = 64
    WMI_TLV_VDEV_PARAM_AGGR_TRIG_EVENT_ENABLE = 65
    WMI_TLV_VDEV_PARAM_IS_IBSS_POWER_SAVE_ALLOWED = 66
    WMI_TLV_VDEV_PARAM_IS_POWER_COLLAPSE_ALLOWED = 67
    WMI_TLV_VDEV_PARAM_IS_AWAKE_ON_TXRX_ENABLED = 68
    WMI_TLV_VDEV_PARAM_INACTIVITY_CNT = 69
    WMI_TLV_VDEV_PARAM_TXSP_END_INACTIVITY_TIME_MS = 70
    WMI_TLV_VDEV_PARAM_DTIM_POLICY = 71
    WMI_TLV_VDEV_PARAM_IBSS_PS_WARMUP_TIME_SECS = 72
    WMI_TLV_VDEV_PARAM_IBSS_PS_1RX_CHAIN_IN_ATIM_WINDOW_ENABLE = 73
    WMI_TLV_VDEV_PARAM_UNKNOWN = 0xFFFF


@unique
class WmiTlvPeerParam(Enum):

    WMI_PEER_SMPS_STATE = 0x1
    WMI_PEER_AMPDU = 0x2
    WMI_PEER_AUTHORIZE = 0x3
    WMI_PEER_CHAN_WIDTH = 0x4
    WMI_PEER_NSS = 0x5
    WMI_PEER_USE_4ADDR = 0x6
    WMI_PEER_DUMMY_VAR = 0xFF
    WMI_PEER_PARAM_UNKNOWN = 0xFFFF


@unique
class WmiTlvPeerType(Enum):

    WMI_TLV_PEER_TYPE_DEFAULT = 0
    WMI_TLV_PEER_TYPE_BSS = 1
    WMI_TLV_PEER_TYPE_TDLS = 2
    WMI_TLV_PEER_TYPE_HOST_MAX = 127
    WMI_TLV_PEER_TYPE_ROAMOFFLOAD_TMP = 128
