#!/usr/bin/env python3

#
# Reverse resolve a range of network-addresses against a specific nameserver. 
# Basically "dig -x" in a loop.
# Written by @c0dmtr1x (info@codemetrix.net)
# 


import sys, ipaddress, dns, dns.resolver, dns.reversename, argparse
from time import sleep

results = {1:"FOUND",2:"NO_ENTRY",3:"REFUSED", 4:"NO_ANSWER", 5:"TIMEOUT"}
private_networks=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","fc00::/7","fd00::/8"]

# resolve an ip against given resolver
def resolve(resolver,ip, quiet=False):
    try:
        answer = resolver.query(ip.reverse_pointer,'ptr')
        if not quiet:
            print("[+] " + str(ip) + " : " + str(answer[0]))
        return 1, str(answer[0])
    except dns.resolver.NXDOMAIN:
        if not quiet:
            print("[.] Resolved but no entry for " + str(ip))
        return 2, None
    except dns.resolver.NoNameservers:
        if not quiet:
            print("[-] Answer refused for " + str(ip))
        return 3, None
    except dns.resolver.NoAnswer:
        if not quiet:
            print("[-] No answer section for " + str(ip))
        return 4, None
    except dns.exception.Timeout:
        if not quiet:
            print("[-] Timeout")
        return 5, None

# log output to file
def write_file(outfile,nameserver,ip,result, answer = None):
    outfile.write(str(nameserver) + "," + str(ip) + "," + results[result] + "," + str(answer) + "\n")


# check range of network addresses
def quickcheck(resolver):
    for cidr in private_networks:
        network = ipaddress.ip_network(str(cidr))
        hosts = network.hosts()
        ip = hosts.__next__()
        print("[*] Checking network " + cidr)
        result, answer = resolve(resolver,ip,True)
        if args.outfile:
            write_file(outfile,custom_ns,ip,result)
        if result in (1,2,3,4): #skip timeouts
            print("    * Nameserver responded, further checks ")
            if result == 1:
                print("[+] Entry found in nameserver " + str(custom_ns) + " for " + str(ip) + " : " + answer)
            for i in range(1,args.max_queries):
                ip = hosts.__next__()
                result, answer = resolve(resolver,ip,True)
                if args.outfile:
                    write_file(outfile,custom_ns,ip,result,answer)
                if result == 1:
                    print("[+] Entry found in nameserver " + str(custom_ns) + " for " + str(ip) + " : " + answer)
        else:
            print("    - No response, timeout or denied")
            if args.outfile:
                write_file(outfile,custom_ns,ip,result,answer)


# Resolve nameserver
def get_nameserver(nameserver):
    custom_ns = None
    try:
        custom_ns = str(ipaddress.ip_address(nameserver))
    except ValueError:
        # no ip, so we try to resolve it as hostname.
        import socket
        custom_ns = socket.gethostbyname(nameserver)
    
    return custom_ns


# configure a resolver with a specific nameserver
def get_resolver(nameserver):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.timeout = args.timeout
    resolver.lifetime = args.timeout
    return resolver

# argparse
parser = argparse.ArgumentParser()
parser.add_argument('--quickcheck', '-q', help='Quick check: Use for batch testing. Scans the first entries of each private network and returns results in one line.', action='store_true')
parser.add_argument('--timeout', '-t', help="Manually adjust timout in seconds. Default is 5", nargs="?", type=int, default=5)
parser.add_argument('--max-queries','-m', help="Maximal number of queries for a network. In quickcheck mode each private network will be called with the first number of ips specified here. Default 15.", type=int, default=15)
parser.add_argument('nameserver', help="nameserver IP or hostname",nargs="?")
parser.add_argument('network', help="network range in CIDR notation to check, e.g. 10.0.0.0/8", nargs="?")
parser.add_argument('--outfile', '-o', help="write results in file", nargs="?")
parser.add_argument('--infile', '-i', help="Read nameservers from here, 1 per line", nargs="?")
args = parser.parse_args()


if not args.nameserver and not args.network:
    print("Please specifiy either nameserver or network")
    parser.print_help()
    exit(0)


maxips = args.max_queries

# Set outfile
outfile = None
if args.outfile:
    outfile = open(args.outfile,'w')

# default global values
custom_ns = None
resolver = None
if args.nameserver:
    custom_ns = get_nameserver(args.nameserver)
    resolver = get_resolver(custom_ns)
    print ("[*] Checking nameserver " + str(custom_ns))

# try to resolve the first ip of each network
if not args.network and not args.quickcheck:
    for cidr in private_networks:
        network = ipaddress.ip_network(str(cidr))
        ip = network.hosts().__next__()
        result,answer = resolve(resolver,ip)
        if args.outfile:
            write_file(outfile,custom_ns,ip,result,answer)

# check whole network
if args.network:
    network = ipaddress.ip_network(args.network)
    for ip in network.hosts():
        result,answer = resolve(resolver,ip)
        if args.outfile:
            write_file(outfile,custom_ns,ip,result,answer)
        # stay quit - more or less
        sleep(0.03)

# check each network up to max_queries ips
if args.quickcheck:
    if not args.infile:
        quickcheck(resolver)
    else:
        infile = open(args.infile,"r")
        if not infile:
            print("Could not open input file. Exiting.")
            exit(0)

        for line in infile:
            custom_ns = get_nameserver(line.strip())
            resolver = get_resolver(custom_ns)
            print ("[*] Checking nameserver " + str(custom_ns))
            quickcheck(resolver)

        
