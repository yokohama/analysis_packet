import sys
import json

#file_path = './http_1request.json'

if not '-f' in sys.argv:
    print('Usage: python analysis_packet.py -f path/to/your/json/file')
    exit()

file_index = sys.argv.index('-f') + 1

file_path = sys.argv[file_index]

with open(file_path) as f:
    data = json.loads(f.read())

array = []
for d in data:
    array.append(d['_source']['layers'])

origin_ip = ''

sorted_array = sorted(array, key=lambda x: x['frame']['frame.time'])
for i, sa in enumerate(sorted_array):
    #
    # IP Layner
    #
    if origin_ip == '':
        origin_ip = sa['ip']['ip.src']

    if sa['ip']['ip.src'] == origin_ip:
        src_ip = origin_ip
        dst_ip = sa['ip']['ip.dst']
        allow = '>>>'
    else:
        src_ip = origin_ip
        dst_ip = sa['ip']['ip.src']
        allow = '<<<'

    #
    # Transport Layner
    #
    src_port = 'null'
    dst_port = 'null'

    if 'tcp' in sa.keys():
        protocol = 'tcp'
    elif 'udp' in sa.keys():
        protocol = 'udp'

    if protocol in sa.keys():
        if sa['ip']['ip.src'] == origin_ip:
            src_port = sa[protocol][protocol + '.srcport']
            dst_port = sa[protocol][protocol + '.dstport']
        else:
            src_port = sa[protocol][protocol + '.dstport']
            dst_port = sa[protocol][protocol + '.srcport']

    #
    # Application Layner
    #
    sammary = ''
    if 'http' in sa.keys():
        sammary = list(sa['http'].keys())[0]
    if 'smb' in sa.keys():
        sammaries = list(sa['smb'].keys())
        sammary = sammaries[0] + ', ' + sammaries[1]
    if 'smb2' in sa.keys():
        sammaries = list(sa['smb2'].keys())
        sammary = sammaries[0] + ', ' + sammaries[1]

    print(str(i).zfill(3) + ', ' +  
          src_ip + ':' + src_port + ', ' +
          allow + ', ' +
          dst_ip + ':' + dst_port + ', ' +
          sa['tcp']['tcp.flags_tree']['tcp.flags.str'] + ', ' +
          sa['tcp']['tcp.seq_raw'] + ', ' +
          sa['tcp']['tcp.ack_raw'] + ', ' +
          sammary) 
