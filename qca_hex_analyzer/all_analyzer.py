from collections import namedtuple
from .analyzer import Analyzer, HtcHeader
from .wmi_ctrl_analyzer import WmiCtrlAnalyzer
from .htc_ctrl_analyzer import HtcCtrlAnalyzer
from .htt_analyzer import HttAnalyzer


class AllAnalyzer(Analyzer):

    def __init__(self, wmi_ctrl_eid=1, htt_eid=2, short_htc_hdr=False,
                 wmi_unified=True, timestamps=False):

        Analyzer.__init__(self,
                          short_htc_hdr=short_htc_hdr,
                          timestamps=timestamps)

        self.wmi_ctrl_analyzer = WmiCtrlAnalyzer(eid=wmi_ctrl_eid,
                                                 short_htc_hdr=short_htc_hdr,
                                                 wmi_unified=wmi_unified,
                                                 timestamps=timestamps)

        self.htc_ctrl_analyzer = HtcCtrlAnalyzer(short_htc_hdr=short_htc_hdr,
                                                 timestamps=timestamps)

        self.htt_analyzer = HttAnalyzer(eid=htt_eid,
                                        short_htc_hdr=short_htc_hdr,
                                        timestamps=timestamps)

        self.cur_analyzer = None

        self.wmi_ctrl_eid = wmi_ctrl_eid
        self.htt_eid = htt_eid
        self.htc_ctrl_eid = 0

    def __set_cur_analyzer(self, hexdata):

        hexdata_a = hexdata.split(' ', 15)
        eid = int(hexdata_a[0], 16)
        if eid == self.wmi_ctrl_eid:
            self.cur_analyzer = self.wmi_ctrl_analyzer
        elif eid == self.htt_eid:
            self.cur_analyzer = self.htt_analyzer
        elif eid == self.htc_ctrl_eid:
            self.cur_analyzer = self.htc_ctrl_analyzer
        else:
            self.cur_analyzer = None

    def parse_hexdata(self, hexdata):

        (ts, hexdata_no_ts) = self.parse_timestamp(hexdata)

        hexdata_split1 = hexdata_no_ts.split(': ', 1)
        addr = int(hexdata_split1[0], 16)
        if addr == 0:
            # Address = 0 means a new msg and thus, a new HTC
            # header. We use the eid from the HTC header to
            # decide which of our analyzers we should use
            self.__set_cur_analyzer(hexdata_split1[1])

        if self.cur_analyzer:
            return self.cur_analyzer.parse_hexdata(hexdata)
        else:
            return False

    def get_id_str(self):

        if not self.cur_analyzer:
            return ''

        return self.cur_analyzer.get_id_str()

    def get_htc_hdr_str(self):

        if not self.cur_analyzer:
                return None

        return self.cur_analyzer.get_htc_hdr_str()

    def get_data_str(self):

        if not self.cur_analyzer:
            return None

        return self.cur_analyzer.get_data_str()

    def get_trailer_str(self):

        if not self.cur_analyzer:
            return None

        return self.cur_analyzer.get_trailer_str()
