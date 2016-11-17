from collections import namedtuple
from .analyzer import Analyzer, HtcHeader
from .htc_ctrl import HtcCtrl


HtcCtrlHeader = namedtuple('HtcCtrlHeader',
                           ['msg_id'],
                           verbose=False)


class HtcCtrlAnalyzer(Analyzer):

    def __init__(self, short_htc_hdr=False, timestamps=False):

        Analyzer.__init__(self,
                          short_htc_hdr=short_htc_hdr,
                          timestamps=timestamps)

        # eid is always 0 for HTC control
        self.eid = 0
        self.hdr_len = 2
        self.htc_ctrl_hdr = None

    def __create_htc_ctrl_hdr(self, hexdata):

        if len(hexdata) < self.hdr_len:
            return None

        id1 = int(hexdata[0], 16)
        id2 = int(hexdata[1], 16)
        msg_id = ((id2 << 8) & 0xFF00) | (id1 & 0xFF)

        hdr = HtcCtrlHeader(msg_id=msg_id)
        return hdr

    def __begin_new_frame(self, hexdata):

        # Verify that the hexdump has enough data for the HTC hdr
        # and HTC ctrl hdr.
        # A linux hexdump has 16 values = 15 spaces in one line at most
        hexdata_a = hexdata.split(' ', 15)

        self.cur_data = []
        self.cur_trailer = []
        self.valid_msg = False
        self.full_msg = False
        htc_hdr = self.create_htc_hdr(hexdata_a)
        if not htc_hdr:
            return False

        if htc_hdr.eid != self.eid:
            return False

        self.htc_hdr = htc_hdr

        # Examine the HTC header and check if it is a "trailer only"
        # message. A "trailer only" message is a message with no data,
        # just trailer.
        data_len = self.get_data_len()
        if data_len == 0:
            return self.append_msg_data(hexdata_a[self.htc_hdr_len:16])

        htc_ctrl_hdr = self.__create_htc_ctrl_hdr(hexdata_a[self.htc_hdr_len:])
        if not htc_ctrl_hdr:
            return False

        self.htc_ctrl_hdr = htc_ctrl_hdr
        self.htc_ctrl_enum = HtcCtrl.get_msg_id_enum(self.htc_ctrl_hdr.msg_id)

        # Append the last bytes to the saved data array
        self.valid_msg = True
        return self.append_msg_data(hexdata_a[self.htc_hdr_len:16])

    def __continue_frame(self, hexdata):

        if not self.valid_msg or self.full_msg:
            return False

        hexdata_a = hexdata.split(' ', 15)

        full_msg = self.append_msg_data(hexdata_a)

        return full_msg

    def parse_hexdata(self, hexdata):

        (ts, hexdata) = self.parse_timestamp(hexdata)

        # Read the dump address. Address = 0 means a new msg
        hexdata_split1 = hexdata.split(': ', 1)
        addr = int(hexdata_split1[0], 16)
        if addr == 0:
            self.ts = ts
            return self.__begin_new_frame(hexdata_split1[1])
        else:
            return self.__continue_frame(hexdata_split1[1])

    def get_id(self):

        if not self.htc_ctrl_hdr:
            return None

        return self.htc_ctrl_hdr.msg_id

    def get_enums(self):

        return (self.htc_ctrl_enum, self.htc_ctrl_enum)

    def get_id_str(self):

        if not self.htc_ctrl_hdr:
            return ''

        str = ''
        if self.timestamps:
            str = '[{}]'.format(self.ts)
            str = str.ljust(16)
        str = '{}HTC ctrl msg id: {:6x}'.format(str, self.htc_ctrl_hdr.msg_id)
        if self.htc_ctrl_enum:
            str = '{}  string: {}'.format(str, self.htc_ctrl_enum.name)
            str = str.ljust(70)
        str = '{}\n'.format(str)
        return str
