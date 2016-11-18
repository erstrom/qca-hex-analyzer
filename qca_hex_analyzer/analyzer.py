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
        self.htc_hdr_data = []
        self.cur_data = []
        self.cur_trailer = []
        self.full_data = False
        self.ts = None

    def clear(self):

        self.cur_data = []
        self.cur_trailer = []
        self.valid_msg = False
        self.full_msg = False

    def create_htc_hdr(self, hexdata):

        if len(hexdata) < self.htc_hdr_len:
            return False

        eid = int(hexdata[0], 16)
        flags = int(hexdata[1], 16)
        len1 = int(hexdata[2], 16)
        len2 = int(hexdata[3], 16)
        ctrl0 = int(hexdata[4], 16)
        ctrl1 = int(hexdata[5], 16)
        # HTC header lengths is 2 bytes LE
        hdr_len = ((len2 << 8) & 0xFF00) | len1
        self.htc_hdr = HtcHeader(eid=eid, flags=flags, length=hdr_len,
                                 ctrl0=ctrl0, ctrl1=ctrl1)
        self.htc_hdr_data = hexdata[0:self.htc_hdr_len]
        return True

    def get_data_len(self):

        # Data length is defined as: total length - trailer length
        return self.htc_hdr.length - self.htc_hdr.ctrl0

    def append_msg_data(self, hexdata_a):

        cur_data_len = self.get_data_len()
        cur_trailer_len = self.htc_hdr.ctrl0
        cur_tot_len = self.htc_hdr.length

        bytes_left_full_data = cur_data_len - len(self.cur_data)
        exceeding_data_bytes = len(hexdata_a) - bytes_left_full_data

        if not self.full_data and exceeding_data_bytes >= 0:
            self.full_data = True
            self.cur_data += hexdata_a[0:bytes_left_full_data]
            if cur_trailer_len == 0:
                # We don't expect any trailer for this message so we
                # consider it full
                self.full_msg = True
                self.full_data = False
                return True
            elif cur_trailer_len > exceeding_data_bytes:
                self.cur_trailer += hexdata_a[bytes_left_full_data:]
            else:
                # Trailer is now full
                end = bytes_left_full_data + \
                      exceeding_data_bytes - cur_trailer_len
                self.cur_trailer += hexdata_a[bytes_left_full_data:end]
                self.full_msg = True
                self.full_data = False
                return True

        bytes_left_full_trailer = cur_trailer_len - len(self.cur_trailer)
        exceeding_trailer_bytes = len(hexdata_a) - bytes_left_full_trailer

        if self.full_data and exceeding_trailer_bytes >= 0:
            self.cur_trailer += hexdata_a[0:bytes_left_full_trailer]
            self.full_msg = True
            self.full_data = False
            return True

        if self.full_data:
            self.cur_trailer += hexdata_a
        else:
            self.cur_data += hexdata_a

        # Not a full message, more data needed...
        return False

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

    def get_htc_hdr_str(self):

        if not self.valid_msg:
            return None

        str = ''
        str = '{0}00000000:  '.format(str)
        iter_a = self.htc_hdr_data
        for j in range(0, len(iter_a)):
            str = '{0}{1} '.format(str, iter_a[j])
        str = '{}\n'.format(str)

        return str

    def get_data_str(self):

        if not self.valid_msg:
            return None

        str = ''
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

    def get_trailer_str(self):

        if not self.valid_msg:
            return None

        str = ''
        no_of_lines = len(self.cur_trailer) // 16
        iter_a = self.cur_trailer
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
