#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
import random
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper


def writeStaticTable(p4info_helper, switch):

    hosts = [('10.0.1.1', "00:00:00:00:01:01", 1), (('10.0.1.2', "00:00:00:00:01:02", 2)), (('10.0.1.3', "00:00:00:00:01:03", 3))]

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        default_action=True,
        action_name="MyIngress.drop",
        action_params={ }
        )
    switch.WriteTableEntry(table_entry)

    for h in hosts:
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": (h[0], 32)
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "dstAddr": h[1],
                "port": h[2]
            })
        switch.WriteTableEntry(table_entry)

    # zip_codes = np.random.randint(99999, size = 100)
    # ages = np.random.randint(100, size = 100)
    zip_codes = [random.randrange(10000,70000) for i in xrange(10)]
    ages = random.sample(range(0, 100), 10)
    rows = zip(ages, zip_codes)
    # rows = [(1, 20728), (2, 51876), (3,345), (4,54),(5,756),(6,45231),(7, 58984), (71, 59619), (32, 31734), (20, 22514), (35, 26063), (33, 68108), (14, 69741), (66, 27639), (24, 31739), (92, 42949), (19, 55206), (21, 43695)]
    # rows = [(8, 20728), (56, 51876)]

    for r in rows:
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyEgress.join_exact",
            match_fields={
                "hdr.tupleVal.age": r[0]
            },
            action_name="MyEgress.update_headers",
            action_params={
                "z": r[1]
            })
        switch.WriteTableEntry(table_entry)


def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.
    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            # TODO For extra credit, you can use the p4info_helper to translate
            #      the IDs in the entry to names
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
            for m in entry.match:
                print p4info_helper.get_match_field_name(table_name, m.field_id),
                print '%r' % (p4info_helper.get_match_field_value(m),),
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
            for p in action.params:
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
            print


def printGrpcError(e):
    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    # Create a switch connection object for s1
    # this is backed by a P4Runtime gRPC connection.
    # Also, dump all P4Runtime messages sent to switch to given txt files.
    s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='s1',
        address='127.0.0.1:50051',
        device_id=0,
        proto_dump_file='logs/s1-p4runtime-requests.txt')

    # Send master arbitration update message to establish this controller as
    # master (required by P4Runtime before performing any other write operation)
    s1.MasterArbitrationUpdate()

    # Install the P4 program on the switch
    s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                   bmv2_json_file_path=bmv2_file_path)
    print "Installed P4 Program using SetForwardingPipelineConfig on s1"

    # write match rows into table
    writeStaticTable(p4info_helper, switch=s1)

    # read table entries from s1
    readTableRules(p4info_helper, s1)
    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/static_join.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/static_join.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
