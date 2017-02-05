from collections import namedtuple

import argparse
import pdb
import traceback
import sys
import os
from qca_hex_analyzer import WmiCtrlAnalyzer, HtcCtrlAnalyzer, HttAnalyzer, AllAnalyzer
import hexfilter

description = \
    "Tool used to analyze hexdumps produced by a qca wireless kernel " \
    "driver (such as ath6kl, ath10k or qcacld2.0). " \
    "The hexdumps are assumed to contain dumps of the traffic " \
    "between the driver and the target. " \
    "No special preprocessing of the log files is required. " \
    "Filter strings (description strings) can be used to limit the output " \
    "(only RX or TX etc.). " \
    "The driver must of course be configured to log all necessary debug " \
    "data (for ath6kl and ath10k this means a proper debug mask). "

wmi_ctrl_help = \
    "Subcommand for WMI control message parsing. " \
    "This subcommand is used to extract WMI control messages from the input. "

wmi_ctrl_description = \
    "Extracts WMI control message hexdata from an input (--input-file). " \
    "The extracted messages will be printed to the output (--output -file). " \
    "--ep-id is used to determine from which HTC endpoint the data will " \
    "be extracted (see description of that option below). " \
    "All valid WMI control message ID's will be printed together with the " \
    "message enum string (from ath6kl source code). " \
    "The --wmi-old option must be used if the driver does not use the WMI " \
    "unified protocol (ath6kl). " \
    "The WMI control message payload will also be printed together with " \
    "message ID's if the --print-data option is used."

htc_ctrl_help = \
    "Subcommand for HTC control message parsing. " \
    "This subcommand is used to extract HTC control messages from the input. "

htc_ctrl_description = \
    "Extracts HTC control message hexdata from an input (--input-file). " \
    "The extracted messages will be printed to the output (--output -file). " \
    "All valid HTC control message ID's will be printed together with the " \
    "message enum string (from ath6kl source code). " \
    "The message payload will also be printed together with the " \
    "message ID's if the --print-data option is used. " \
    "HTC control messages will always be extracted from endpoint 0."

htt_help = \
    "Subcommand for HTT message parsing. " \
    "This subcommand is used to extract HTT messages from the input. "

htt_description = \
    "Extracts HTT message hexdata from an input (--input-file). " \
    "The extracted messages will be printed to the output (--output -file). " \
    "--ep-id is used to determine from which HTC endpoint the data will " \
    "be extracted (see description of that option below). " \
    "All valid HTT message ID's will be printed together with the " \
    "message enum string (from ath10k source code). " \
    "The message payload will also be printed together with " \
    "message ID's if the --print-data option is used."

all_help = \
    "Subcommand for parsing of all supported message types. " \
    "This subcommand is used to extract both WMI control, " \
    "HTC control and HTT messages from the input. "

all_description = \
    "Extracts message hexdata from an input (--input-file). " \
    "The extracted messages will be printed to the output (--output-file). " \
    "The messages can be any of the supported message types " \
    "(currently only WMI controli, HTC control and HTT). " \
    "--wmi-ctrl-ep-id and --htt-ep-id is used to determine from which " \
    "endpoints WMI and HTT data will be extracted " \
    "(see description of those options below). " \
    "HTC control messages will always be extracted from ep 0. " \
    "All valid message ID's will be printed together " \
    "with a corresponding message enum string. " \
    "The message payload will also be printed together with " \
    "message ID's if the --print-data option is used."


def auto_int(x):

    return int(x, 0)


def load_options():

    global parsed_args
    base_parser = argparse.ArgumentParser(add_help=False)

    base_parser.add_argument('-i', '--input-file',
                             help="Input (log) file. If omitted, "
                                  "stdin will be read.")
    base_parser.add_argument('-o', '--output-file',
                             help="Output file. If omitted, "
                                  "the output will be written to stdout.")
    base_parser.add_argument('-n', '--no-timestamps', action="store_true",
                             help="Specifies whether or not the input file "
                                  "contains timestamps. ")
    base_parser.add_argument('-d', '--desc-str', nargs='+', type=str,
                             help="Description string(s) of the dumps. "
                                  "Only dumps with a prefix "
                                  "matching any of the provided desc strings "
                                  "will be analyzed. "
                                  "If no --desc-str option is given, no "
                                  "description filtering will be performed. "
                                  "The prefix of a hexdump is the short "
                                  "description string before the address "
                                  "in each line of the dump, i.e the hexdump "
                                  "prefix. "
                                  "--desc-str is normally used to select "
                                  "between RX and TX logs and should be "
                                  "combined with a proper --data-direction "
                                  "option.")
    base_parser.add_argument('-a', '--data-direction', nargs=1, type=str,
                             help="This option is used to specify how the "
                                  "hexdata should be interpreted. "
                                  "Valid values are: "
                                  "t2h (target to host) or h2t (host to target). "
                                  "With t2h, RX trailers will be printed if "
                                  "--print-data is used. h2t is default. "
                                  "This option should be combined with an "
                                  "applicable --desc-str option. ")
    base_parser.add_argument('-v', '--desc-str-invert', nargs='+', type=str,
                             help="Description string(s) of the dumps to be. "
                                  "excluded. Similar to --desc-str, but all "
                                  "matching prefixes will be excluded from "
                                  "the analysis.")
    base_parser.add_argument('-s', '--short-htc-header', action="store_true",
                             help="Use 6 byte HTC header (\"old\" format) "
                                  "instead of 8 bytes.")
    base_parser.add_argument('-t', '--keep-timestamps', action="store_true",
                             help="Keep the timestamps associated with each "
                                  "hexdump in the output. "
                                  "This option will only have effect if the "
                                  "log file contains timestamps.")

    parser = argparse.ArgumentParser(prog="qca_hex_analyzer",
                                     description=description,
                                     parents=[base_parser])

    subparsers = parser.add_subparsers(dest="subparser_name")
    parser_wmi_ctrl = subparsers.add_parser('wmi-ctrl',
                                            help=wmi_ctrl_help,
                                            description=wmi_ctrl_description,
                                            parents=[base_parser])
    parser_wmi_ctrl.add_argument('--wmi-old', action="store_true",
                                 help="Specifies whether or not the WMI messages "
                                      "are according to the \"old\" WMI protocol. "
                                      "If not set, the messages will be interpreted "
                                      "according to the unified WMI format")
    parser_wmi_ctrl.add_argument('-p', '--print-data', action="store_true",
                                 help="Print WMI data message payload (and not just "
                                      "WMI message ID) for all encountered messages. ")
    parser_wmi_ctrl.add_argument('-e', '--ep-id', metavar='ID', nargs=1,
                                 type=int, default=[2],
                                 help="WMI control service endpoint ID. "
                                      "This is the endpoint where the WMI control data is "
                                      "expected to be present. Make sure the endpoint "
                                      "matches the endpoint id associated with the "
                                      "control service endpoint (service id 0x100) "
                                      "of the driver (the endpoint received from the "
                                      "target in the HTC service connect response). "
                                      "If this option is omitted a default value of 2 "
                                      "will be used.")
    parser_wmi_ctrl.add_argument('--tlv', action="store_true",
                                 help="TLV analysis."
                                      "Each WMI message will be interpreted as a TLV "
                                      "message and the content of the message will be. "
                                      "written out in text (instead of hexdump). "
                                      "If the encountered message is not supported by "
                                      "the parser, the hex data will be printed instead.")
    parser_wmi_ctrl.add_argument('--id', '--msg-id', metavar='ID',
                                 nargs='+', type=auto_int,
                                 help="WMI message id filter. "
                                      "Only WMI messages with an id matching any of the "
                                      "provided id's will be included in the output. "
                                      "If no --id | --msg-id option is given, no "
                                      "filtering will be performed. ")
    parser_wmi_ctrl.add_argument('--skip-id', '--skip-msg-id', metavar='ID',
                                 nargs='+', type=auto_int,
                                 help="WMI message id exclude filter. "
                                      "Similar to --id | --msg-id, but all matching "
                                      "id's will be excluded from the output. ")
    parser_htc_ctrl = subparsers.add_parser('htc-ctrl',
                                            help=htc_ctrl_help,
                                            description=htc_ctrl_description,
                                            parents=[base_parser])
    parser_htc_ctrl.add_argument('-p', '--print-data', action="store_true",
                                 help="Print HTC ctrl data message payload (and not just "
                                      "message ID) for all encountered messages. ")
    parser_htt = subparsers.add_parser('htt',
                                       help=htt_help,
                                       description=htt_description,
                                       parents=[base_parser])
    parser_htt.add_argument('-p', '--print-data', action="store_true",
                            help="Print HTT data message payload (and not just "
                                 "HTT message ID) for all encountered messages. ")
    parser_htt.add_argument('-e', '--ep-id', metavar='ID', nargs=1,
                            type=int, default=[1],
                            help="HTT service endpoint ID. "
                                 "This is the endpoint where the HTT data is "
                                 "expected to be present. Make sure the endpoint "
                                 "matches the endpoint id associated with the "
                                 "HTT endpoint (service id 0x300) "
                                 "of the driver (the endpoint received from the "
                                 "target in the HTC service connect response). "
                                 "If this option is omitted a default value of 1 "
                                 "will be used.")
    parser_all = subparsers.add_parser('all',
                                       help=all_help,
                                       description=all_description,
                                       parents=[base_parser])
    parser_all.add_argument('-p', '--print-data', action="store_true",
                            help="Print message payload (and not just "
                                 "message ID) for all encountered messages. ")
    parser_all.add_argument('--wmi-old', action="store_true",
                            help="Specifies whether or not the WMI messages "
                                 "are according to the \"old\" WMI protocol. "
                                 "If not set, the messages will be interpreted "
                                 "according to the unified WMI format")
    parser_all.add_argument('--htt-ep-id', metavar='ID', nargs=1,
                            type=int, default=[1],
                            help="HTT service endpoint ID. "
                                 "This is the endpoint where the HTT data is "
                                 "expected to be present. Make sure the endpoint "
                                 "matches the endpoint id associated with the "
                                 "HTT endpoint (service id 0x300) "
                                 "of the driver (the endpoint received from the "
                                 "target in the HTC service connect response). "
                                 "If this option is omitted a default value of 1 "
                                 "will be used.")
    parser_all.add_argument('--wmi-ctrl-ep-id', metavar='ID', nargs=1,
                            type=int, default=[2],
                            help="WMI control service endpoint ID. "
                                 "This is the endpoint where the WMI control data is "
                                 "expected to be present. Make sure the endpoint "
                                 "matches the endpoint id associated with the "
                                 "control service endpoint (service id 0x100) "
                                 "of the driver (the endpoint received from the "
                                 "target in the HTC service connect response). "
                                 "If this option is omitted a default value of 2 "
                                 "will be used.")
    parsed_args = parser.parse_args()


def main():
    global parsed_args
    load_options()

    try:
        if parsed_args.input_file:
            infp = open(parsed_args.input_file, "r")
        else:
            infp = sys.stdin
        if parsed_args.output_file:
            outfp = open(parsed_args.output_file, "w")
        else:
            outfp = sys.stdout

        if parsed_args.data_direction:
            if parsed_args.data_direction[0] == 't2h':
                t2h = True
            elif parsed_args.data_direction[0] == 'h2t':
                t2h = False
            else:
                sys.stderr.write('Unsupported data direction: {}\n'.format(parsed_args.data_direction[0]))
                exit(1)
        else:
            # Interpret the data as host -> target is the default behaviour
            t2h = False

        hf = hexfilter.HexFilterLinux(skip_timestamps=(not parsed_args.keep_timestamps),
                                      abs_timestamps=True,
                                      dump_desc=parsed_args.desc_str,
                                      dump_desc_invert=parsed_args.desc_str_invert,
                                      log_has_timestamps=(not parsed_args.no_timestamps),
                                      include_dump_desc_in_output=False,
                                      remove_ascii_part=True)

        if parsed_args.subparser_name == 'wmi-ctrl':
            analyzer = WmiCtrlAnalyzer(eid=parsed_args.ep_id[0],
                                       wmi_unified=(not parsed_args.wmi_old),
                                       short_htc_hdr=parsed_args.short_htc_header,
                                       timestamps=parsed_args.keep_timestamps,
                                       t2h=t2h,
                                       tlv_analysis=parsed_args.tlv,
                                       msg_id_filter=parsed_args.id,
                                       msg_id_exclude_filter=parsed_args.skip_id)
            if parsed_args.tlv:
                parsed_args.print_data = True
        elif parsed_args.subparser_name == 'htc-ctrl':
            analyzer = HtcCtrlAnalyzer(short_htc_hdr=parsed_args.short_htc_header,
                                       timestamps=parsed_args.keep_timestamps,
                                       t2h=t2h)
        elif parsed_args.subparser_name == 'htt':
            analyzer = HttAnalyzer(eid=parsed_args.ep_id[0],
                                   short_htc_hdr=parsed_args.short_htc_header,
                                   timestamps=parsed_args.keep_timestamps,
                                   t2h=t2h)
        elif parsed_args.subparser_name == 'all':
            analyzer = AllAnalyzer(wmi_ctrl_eid=parsed_args.wmi_ctrl_ep_id[0],
                                   htt_eid=parsed_args.htt_ep_id[0],
                                   wmi_unified=(not parsed_args.wmi_old),
                                   short_htc_hdr=parsed_args.short_htc_header,
                                   timestamps=parsed_args.keep_timestamps,
                                   t2h=t2h)
        else:
            sys.stderr.write('Unsupported subcommand: {}\n'.format(parsed_args.subparser_name))

        for line in infp:
            if hf.parse_line(line):
                hexdata = hf.get_hex()
                if analyzer.parse_hexdata(hexdata):
                    str = analyzer.get_id_str()
                    outfp.write(str)
                    if parsed_args.print_data:
                        analyzer.print_data(outfp)

    except IOError as err:
        sys.stderr.write('{}\n'.format(err))
    except:
        type, value, tb = sys.exc_info()
        traceback.print_exc()
        pdb.post_mortem(tb)

if __name__ == "__main__":
    main()
