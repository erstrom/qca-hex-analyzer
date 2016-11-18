from enum import Enum, unique


@unique
class HtcCtrlMsgId(Enum):

    HTC_MSG_READY_ID = 1
    HTC_MSG_CONNECT_SERVICE_ID = 2
    HTC_MSG_CONNECT_SERVICE_RESP_ID = 3
    HTC_MSG_SETUP_COMPLETE_ID = 4
    HTC_MSG_SETUP_COMPLETE_EX_ID = 5
    HTC_MSG_SEND_SUSPEND_COMPLETE = 6
    # Special command enum: Trailer only
    HTC_MSG_TRAILER_ONLY = 0xffff


class HtcCtrl:

    @staticmethod
    def get_msg_id_enum(msg_id):

        try:
            return HtcCtrlMsgId(msg_id)
        except ValueError:
            return None
