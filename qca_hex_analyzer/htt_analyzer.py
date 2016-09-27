from collections import namedtuple
from .htt import Htt


HtcHeader = namedtuple('HtcHeader',
                       ['eid', 'flags', 'length', 'ctrl0', 'ctrl1'],
                       verbose=False)


class HttAnalyzer:

    def __init__(self, eid=2, short_htc_hdr=False, timestamps=False):

        self.eid = eid
        self.timestamps = timestamps

        if short_htc_hdr:
            self.htc_hdr_len = 6
        else:
            self.htc_hdr_len = 8

        self.cur_htt_data = []
        self.valid_htt_msg = False
        self.full_msg = False
        self.htc_hdr = None
        self.h2t_enum = None
        self.t2h_enum = None
        self.htt_id = None

    def __create_htc_hdr(self, hexdata):

        if len(hexdata) < self.htc_hdr_len:
            return None

        eid = int(hexdata[0], 16)
        flags = int(hexdata[1], 16)
        len1 = int(hexdata[2], 16)
        len2 = int(hexdata[3], 16)
        ctrl0 = int(hexdata[4], 16)
        ctrl1 = int(hexdata[5], 16)
        # HTC header lengths is 2 bytes LE
        hdr_len = ((len2 << 8) & 0xFF00) | len1
        hdr = HtcHeader(eid=eid, flags=flags, length=hdr_len, ctrl0=ctrl0,
                        ctrl1=ctrl1)
        return hdr

    def __begin_new_frame(self, hexdata):

        # Verify that the hexdump has enough data for the HTC hdr
        # and WMI hdr.
        # A linux hexdump has 16 values = 15 spaces in one line at most
        hexdata_a = hexdata.split(' ', 15)

        self.cur_htt_data = []
        self.valid_htt_msg = False
        self.full_msg = False
        htc_hdr = self.__create_htc_hdr(hexdata_a)
        if not htc_hdr:
            return False

        if htc_hdr.eid != self.eid:
            return False

        if len(hexdata_a) < self.htc_hdr_len + 1:
            return False

        self.htt_id = int(hexdata_a[self.htc_hdr_len], 16)
        self.h2t_enum = Htt.get_h2t_enum(self.htt_id)
        self.t2h_enum = Htt.get_t2h_enum(self.htt_id)
        self.htc_hdr = htc_hdr

        # Append the last bytes to the saved data array
        self.cur_htt_data = hexdata_a[self.htc_hdr_len:16]
        self.valid_htt_msg = True
        return False

    def __continue_frame(self, hexdata):

        if not self.valid_htt_msg or self.full_msg:
            return False

        hexdata_a = hexdata.split(' ', 15)

        if len(self.cur_htt_data) + len(hexdata_a) >= self.htc_hdr.length:
            # The data must not exceed the HTC hdr length.
            # The HTC header length is the length of the payload
            # Since there will be padding of the SDIO messages it
            # is not unlikely that there will be exceeding bytes.
            exceeding_bytes = \
                len(self.cur_htt_data) + len(hexdata_a) - self.htc_hdr.length
            remaining_bytes = len(hexdata_a) - exceeding_bytes
            self.cur_htt_data += hexdata_a[0:remaining_bytes]
            # We now have a full message
            self.full_msg = True
            return True

        self.cur_htt_data += hexdata_a
        # Not a full message, more data needed...
        return False

    def parse_hexdata(self, hexdata):

        if self.timestamps:
            hexdata_split1 = hexdata.split('] ', 1)
            ts = hexdata_split1[0][1:]
        else:
            hexdata_split1 = [None, hexdata]
            ts = None

        # Read the dump address. Address = 0 means a new msg
        hexdata_split2 = hexdata_split1[1].split(': ', 1)
        addr = int(hexdata_split2[0], 16)
        if addr == 0:
            self.ts = ts
            return self.__begin_new_frame(hexdata_split2[1])
        else:
            return self.__continue_frame(hexdata_split2[1])

    def get_id(self):

        return self.htt_id

    def get_enums(self):

        return (self.h2t_enum, self.t2h_enum)

    def get_timestamp(self):

        if self.timestamps:
            return self.ts
        else:
            return None

    def get_data(self):

        if not self.valid_htt_msg:
            return None

        return self.cur_htt_data

    def get_data_str(self):

        if not self.valid_htt_msg:
            return None

        str = '\n'
        no_of_lines = len(self.cur_htt_data) // 16
        iter_a = self.cur_htt_data
        for i in range(0, no_of_lines + 1):
            if len(iter_a) == 0:
                break
            str = '{0}{1:08x}:  '.format(str, i * 16)
            iter_len = min(16, len(iter_a))
            for j in range(0, iter_len):
                str = '{0}{1} '.format(str, iter_a[j])
            str = '{}\n'.format(str)
            iter_a = iter_a[iter_len:]

        return str
