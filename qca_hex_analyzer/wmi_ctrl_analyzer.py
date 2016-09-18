from collections import namedtuple

HtcHeader = namedtuple('HtcHeader',
                       ['eid', 'flags', 'length', 'ctrl0', 'ctrl1'],
                       verbose=False)

WmiHeader = namedtuple('WmiHeader',
                       ['msg_id', 'if_idx'],
                       verbose=False)


class WmiCtrlAnalyzer:

    def __init__(self, ctrl_svc_eid=1, short_htc_hdr=False, wmi_unified=True):

        self.ctrl_svc_eid = ctrl_svc_eid
        self.wmi_unified = wmi_unified

        if short_htc_hdr:
            self.htc_hdr_len = 6
        else:
            self.htc_hdr_len = 8

        if wmi_unified:
            self.wmi_hdr_len = 4
        else:
            self.wmi_hdr_len = 6

        self.cur_wmi_data = []
        self.valid_wmi_hdr = False
        self.full_wmi_msg = False
        self.htc_hdr = None
        self.wmi_hdr = None

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

    def __create_wmi_hdr(self, hexdata):

        if len(hexdata) < self.wmi_hdr_len:
            return None

        if self.wmi_unified:
            # WMI unified uses 24 bit ID LE
            id1 = int(hexdata[0], 16)
            id2 = int(hexdata[1], 16)
            id3 = int(hexdata[2], 16)
            msg_id = ((id3 << 16) & 0xFF0000) | \
                     ((id2 << 8) & 0xFF00) | (id1 & 0xFF)
            if_idx = int(hexdata[3], 16)
        else:
            # "Old" WMI uses 16 bit ID LE
            id1 = int(hexdata[0], 16)
            id2 = int(hexdata[1], 16)
            msg_id = ((id2 << 8) & 0xFF00) | (id1 & 0xFF)
            if_idx = int(hexdata[3], 16)

        hdr = WmiHeader(msg_id=msg_id, if_idx=if_idx)
        return hdr

    def __begin_new_frame(self, hexdata):

        # Verify that the hexdump has enough data for the HTC hdr
        # and WMI hdr.
        # A linux hexdump has 16 values = 15 spaces in one line at most
        hexdata_a = hexdata.split(' ', 15)

        self.cur_wmi_data = []
        self.valid_wmi_hdr = False
        self.full_wmi_msg = False
        htc_hdr = self.__create_htc_hdr(hexdata_a)
        if not htc_hdr:
            return False

        if htc_hdr.eid != self.ctrl_svc_eid:
            return False

        wmi_hdr = self.__create_wmi_hdr(hexdata_a[self.htc_hdr_len:])
        if not wmi_hdr:
            return False

        self.htc_hdr = htc_hdr
        self.wmi_hdr = wmi_hdr
        # Append the last bytes (4 bytes in the case of wmi unified)
        # to the saved wmi data array
        self.cur_wmi_data = hexdata_a[self.htc_hdr_len + self.wmi_hdr_len:16]
        self.valid_wmi_hdr = True
        return False

    def __continue_frame(self, hexdata):

        if not self.valid_wmi_hdr or self.full_wmi_msg:
            return False

        hexdata_a = hexdata.split(' ', 15)

        if len(self.cur_wmi_data) + len(hexdata_a) >= self.htc_hdr.length:
            # The wmi data must not exceed the HTC hdr length.
            # The HTC header length is the length of the payload
            # (wmi data in this case).
            # Since there will be padding of the SDIO messages it
            # is not unlikely that there will be exceeding bytes (padding).
            exceeding_bytes = \
                len(self.cur_wmi_data) + len(hexdata_a) - self.htc_hdr.length
            remaining_bytes = len(hexdata_a) - exceeding_bytes
            self.cur_wmi_data += hexdata_a[0:remaining_bytes]
            # We now have a full WMI message
            self.full_wmi_msg = True
            return True

        self.cur_wmi_data += hexdata_a
        # Not a full wmi message, more data needed...
        return False

    def parse_hexdata(self, hexdata):

        # Read the dump address. Address = 0 means a new msg
        hexdata_split1 = hexdata.split(': ', 1)
        addr = int(hexdata_split1[0], 16)
        if addr == 0:
            return self.__begin_new_frame(hexdata_split1[1])
        else:
            return self.__continue_frame(hexdata_split1[1])

    def get_wmi_id(self):

        if not self.wmi_hdr:
            return None

        return self.wmi_hdr.msg_id

    def get_wmi_data(self):

        if not self.valid_wmi_hdr:
            return None

        return self.cur_wmi_data

    def get_wmi_data_str(self):

        if not self.valid_wmi_hdr:
            return None

        str = '\n'
        no_of_lines = len(self.cur_wmi_data) // 16
        iter_a = self.cur_wmi_data
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
