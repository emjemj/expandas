import argparse
import sys
import os.path
import expandas.loader
import jinja2


parser = argparse.ArgumentParser(description='Command line interface for explandas.')
parser.add_argument('-a', '--as_macro', type=str, help='AS macro')
parser.add_argument('-A', '--as_number', type=int, help='AS number')
parser.add_argument('-t', '--template', help='Jinja2 template')
parser.add_argument('-O', '--output', default='all', choices=['all', 'ipv4', 'ipv6'], help='Specify output without template')
parser.add_argument('-o', '--output-file', help='Save to file')
loadargs = parser.add_argument_group(description='Loader arguments:')
loadargs.add_argument('-l', '--loader', default='rest', choices=['rest', 'dump', 'bpgq3'], help='Defaults to RIPE Rest method.')
args = parser.parse_args()

if args.loader == "rest":
    l = expandas.loader.RIPERESTLoader()
elif args.loader == "dump":
    l = expandas.loader.RIPEDumpLoader()
elif args.loader == "bgpq3":
    l = expandas.loader.BGPQ3Loader()
else:
    l = expandas.loader.RIPERESTLoader()

if args.template is not None:
    if os.path.isfile(args.template):
        path, filename = os.path.split(args.template)
        mode = 'template'
    else:
        sys.exit("File not found.")
elif args.output is not None:
    mode = 'output'

if args.as_macro is not None:
    data = l.load_asset(args.as_macro)
elif args.as_number is not None:
    data = l.load_asn(args.as_number)
else:
    sys.exit("AS macro or AS number must be provided.")

if mode == 'template':
    result = jinja2.Environment(loader=jinja2.FileSystemLoader(path or './')).get_template(args.template).render({"asset": data})
elif mode == 'output':
    if args.output == 'ipv4':
        result = data.inet
    elif args.output == 'ipv6':
        result = data.inet6
    else:
        result = data.inet + data.inet6

    result = '\n'.join(str(ip) for ip in result)

if args.output_file is not None:
    f = open(args.output_file, 'w')
    f.write(result)
    f.close
else:
    print(result)
