from collections import namedtuple
from abc import ABCMeta, abstractmethod


HtcHeader = namedtuple('HtcHeader',
                       ['eid', 'flags', 'length', 'ctrl0', 'ctrl1'],
                       verbose=False)


##
# Analyzer abstract base class.
# All analyzers are expected to inherit this class
class Analyzer:
    __metaclass__ = ABCMeta

    def __init__(self, short_htc_hdr=False, timestamps=False):

        self.timestamps = timestamps

        if short_htc_hdr:
            self.htc_hdr_len = 6
        else:
            self.htc_hdr_len = 8

        self.valid_msg = False
        self.full_msg = False
        self.htc_hdr = None
        self.cur_data = []
        self.ts = None

    def create_htc_hdr(self, hexdata):

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

    def parse_timestamp(self, hexdata):

        if self.timestamps:
            hexdata_split1 = hexdata.split('] ', 1)
            return (hexdata_split1[0][1:], hexdata_split1[1])
        else:
            return (None, hexdata)

    @abstractmethod
    def parse_hexdata(self, hexdata):

        pass

    @abstractmethod
    def get_id(self):

        pass

    @abstractmethod
    def get_id_str(self):

        pass

    @abstractmethod
    def get_enums(self):

        pass

    def get_timestamp(self):

        if self.timestamps:
            return self.ts
        else:
            return None

    def get_data(self):

        if not self.valid_msg:
            return None

        return self.cur_data

    def get_data_str(self):

        if not self.valid_msg:
            return None

        str = '\n'
        no_of_lines = len(self.cur_data) // 16
        iter_a = self.cur_data
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
