from enum import Enum, unique


class HttH2tMsgType(Enum):

    HTT_H2T_MSG_TYPE_VERSION_REQ = 0x0
    HTT_H2T_MSG_TYPE_TX_FRM = 0x1
    HTT_H2T_MSG_TYPE_RX_RING_CFG = 0x2
    HTT_H2T_MSG_TYPE_STATS_REQ = 0x3
    HTT_H2T_MSG_TYPE_SYNC = 0x4
    HTT_H2T_MSG_TYPE_AGGR_CFG = 0x5
    HTT_H2T_MSG_TYPE_FRAG_DESC_BANK_CFG = 0x6
    DEPRECATED_HTT_H2T_MSG_TYPE_MGMT_TX = 0x7
    HTT_H2T_MSG_TYPE_WDI_IPA_CFG = 0x8
    HTT_H2T_MSG_TYPE_WDI_IPA_OP_REQ = 0x9
    HTT_H2T_MSG_TYPE_AGGR_CFG_EX = 0xa


class HttT2hMsgType(Enum):

    HTT_T2H_MSG_TYPE_VERSION_CONF = 0x0
    HTT_T2H_MSG_TYPE_RX_IND = 0x1
    HTT_T2H_MSG_TYPE_RX_FLUSH = 0x2
    HTT_T2H_MSG_TYPE_PEER_MAP = 0x3
    HTT_T2H_MSG_TYPE_PEER_UNMAP = 0x4
    HTT_T2H_MSG_TYPE_RX_ADDBA = 0x5
    HTT_T2H_MSG_TYPE_RX_DELBA = 0x6
    HTT_T2H_MSG_TYPE_TX_COMPL_IND = 0x7
    HTT_T2H_MSG_TYPE_PKTLOG = 0x8
    HTT_T2H_MSG_TYPE_STATS_CONF = 0x9
    HTT_T2H_MSG_TYPE_RX_FRAG_IND = 0xa
    HTT_T2H_MSG_TYPE_SEC_IND = 0xb
    DEPRECATED_HTT_T2H_MSG_TYPE_RC_UPDATE_IND = 0xc
    HTT_T2H_MSG_TYPE_TX_INSPECT_IND = 0xd
    HTT_T2H_MSG_TYPE_MGMT_TX_COMPL_IND = 0xe
    HTT_T2H_MSG_TYPE_TX_CREDIT_UPDATE_IND = 0xf
    HTT_T2H_MSG_TYPE_RX_PN_IND = 0x10
    HTT_T2H_MSG_TYPE_RX_OFFLOAD_DELIVER_IND = 0x11
    HTT_T2H_MSG_TYPE_RX_IN_ORD_PADDR_IND = 0x12
    HTT_T2H_MSG_TYPE_WDI_IPA_OP_RESPONSE = 0x14
    HTT_T2H_MSG_TYPE_CHAN_CHANGE = 0x15
    HTT_T2H_MSG_TYPE_RX_OFLD_PKT_ERR = 0x16
    HTT_T2H_MSG_TYPE_RATE_REPORT = 0x17
    HTT_T2H_MSG_TYPE_FLOW_POOL_MAP = 0x18
    HTT_T2H_MSG_TYPE_FLOW_POOL_UNMAP = 0x19
    HTT_T2H_MSG_TYPE_TEST = 0x20


class Htt:

    @staticmethod
    def get_h2t_enum(h2t_id):

        try:
            return HttH2tMsgType(h2t_id)
        except ValueError:
            return None

    @staticmethod
    def get_t2h_enum(t2h_id):

        try:
            return HttT2hMsgType(t2h_id)
        except ValueError:
            return None
