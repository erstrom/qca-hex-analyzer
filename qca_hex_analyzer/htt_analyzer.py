from collections import namedtuple
from .htt import Htt
from .analyzer import Analyzer, HtcHeader


class HttAnalyzer(Analyzer):

    def __init__(self, eid=2, short_htc_hdr=False, timestamps=False,
                 t2h=False):

        Analyzer.__init__(self,
                          short_htc_hdr=short_htc_hdr,
                          timestamps=timestamps,
                          t2h=t2h)

        self.eid = eid
        self.enum = None
        self.htt_id = None

    def __begin_new_frame(self, hexdata):

        # Verify that the hexdump has enough data for the HTC hdr
        # and a HTT message id.
        # A linux hexdump has 16 values = 15 spaces in one line at most
        hexdata_a = hexdata.split(' ', 15)

        self.clear()
        valid_htc_hdr = self.create_htc_hdr(hexdata_a)
        if not valid_htc_hdr:
            return False

        if self.htc_hdr.eid != self.eid:
            return False

        if len(hexdata_a) < self.htc_hdr_len + 1:
            return False

        self.htt_id = int(hexdata_a[self.htc_hdr_len], 16)
        if self.t2h:
            self.enum = Htt.get_t2h_enum(self.htt_id)
        else:
            self.enum = Htt.get_h2t_enum(self.htt_id)

        # Append the last bytes to the saved data array
        self.valid_msg = True
        return self.append_msg_data(hexdata_a[self.htc_hdr_len:16])

    def __continue_frame(self, hexdata):

        if not self.valid_msg or self.full_msg:
            return False

        hexdata_a = hexdata.split(' ', 15)

        return self.append_msg_data(hexdata_a)

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

    def get_id_str(self):

        if self.htt_id is None:
            return ''

        str = ''
        if self.timestamps:
            str = '[{}]'.format(self.ts)
            str = str.ljust(16)
        str = '{}HTT msg id: {:6x}'.format(str, self.htt_id)
        if self.enum:
            str = '{},  {}'.format(str, self.enum.name)
        str = '{}\n'.format(str)
        return str
