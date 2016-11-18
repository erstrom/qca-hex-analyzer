from collections import namedtuple
from .wmi_unified import WmiUnified, WmiUnifiedCmd, WmiUnifiedCmdGrpId
from .analyzer import Analyzer, HtcHeader


WmiHeader = namedtuple('WmiHeader',
                       ['msg_id', 'if_idx'],
                       verbose=False)


class WmiCtrlAnalyzer(Analyzer):

    def __init__(self, eid=1, short_htc_hdr=False, wmi_unified=True,
                 timestamps=False):

        Analyzer.__init__(self,
                          short_htc_hdr=short_htc_hdr,
                          timestamps=timestamps)

        self.eid = eid
        self.wmi_unified = wmi_unified

        if wmi_unified:
            self.wmi_hdr_len = 4
        else:
            self.wmi_hdr_len = 6

        self.wmi_hdr = None
        self.wmi_cmd_enum = None
        self.wmi_evt_enum = None

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

        self.clear()
        valid_htc_hdr = self.create_htc_hdr(hexdata_a)
        if not valid_htc_hdr:
            return False

        if self.htc_hdr.eid != self.eid:
            return False

        wmi_hdr = self.__create_wmi_hdr(hexdata_a[self.htc_hdr_len:])
        if not wmi_hdr:
            return False

        self.wmi_hdr = wmi_hdr
        if self.wmi_unified:
            self.wmi_cmd_enum = WmiUnified.get_cmd_enum(self.wmi_hdr.msg_id)
            self.wmi_evt_enum = WmiUnified.get_evt_enum(self.wmi_hdr.msg_id)
            if not self.wmi_cmd_enum and not self.wmi_evt_enum:
                # The id was not a valid command or event id, so this can't be
                # a valid WMI header
                return False

        # Append the last bytes (4 bytes in the case of wmi unified)
        # to the saved wmi data array
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

    def get_id(self):

        if not self.wmi_hdr:
            return None

        return self.wmi_hdr.msg_id

    def get_enums(self):

        return (self.wmi_cmd_enum, self.wmi_evt_enum)

    def get_id_grp(self):

        if not self.wmi_hdr:
            return None

        return WmiUnified.get_cmd_group(self.wmi_hdr.msg_id)

    def get_id_str(self):

        if not self.wmi_hdr:
            return ''

        str = ''
        if self.timestamps:
            str = '[{}]'.format(self.ts)
            str = str.ljust(16)
        str = '{}WMI msg id: {:6x}'.format(str, self.wmi_hdr.msg_id)
        if self.wmi_cmd_enum:
            str = '{}  cmd: {}'.format(str, self.wmi_cmd_enum.name)
            str = str.ljust(70)
        if self.wmi_evt_enum:
            str = '{}  evt: {}'.format(str, self.wmi_evt_enum.name)
        str = '{}\n'.format(str)
        return str
