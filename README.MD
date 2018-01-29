# Privdns.py Private IP DNS check

## What does it do?
You can use it to check if your nameserver resolves private IPs to external clients. Reverse quering nameservers for private IP addresses might give an result, sometimes unexpectedly leaking infrastructure dominas and ips.

It's basically a reverse DNS query in a loop directed at a specific nameserver. You can do the same thing with dig -x but privdns automates some things.

## Requirements

* Python3
* ipaddress package (pip3 install ipaddress)
* dns python (pip3 install dnspython)

## How to run it

```
michael@seventysix ~/privdns % python3 privdns.py 
Please specifiy either nameserver or network
usage: privdns.py [-h] [--quickcheck] [--timeout [TIMEOUT]]
                  [--max-queries MAX_QUERIES] [--outfile [OUTFILE]]
                  [--infile [INFILE]]
                  [nameserver] [network]

positional arguments:
  nameserver            nameserver IP or hostname
  network               network range in CIDR notation to check, e.g.
                        10.0.0.0/8

optional arguments:
  -h, --help            show this help message and exit
  --quickcheck, -q      Quick check: Use for batch testing. Scans the first
                        entries of each private network and returns results in
                        one line.
  --timeout [TIMEOUT], -t [TIMEOUT]
                        Manually adjust timout in seconds. Default is 5
  --max-queries MAX_QUERIES, -m MAX_QUERIES
                        Maximal number of queries for a network. In quickcheck
                        mode each private network will be called with the
                        first number of ips specified here. Default 15.
  --outfile [OUTFILE], -o [OUTFILE]
                        write results in file
  --infile [INFILE], -i [INFILE]
                        Read nameservers from here, 1 per line

```

## Example

Scan the beginning of each private network (I know that fd00::1 is in range of fc00::1 but it still makes sense to check both)

```
michael@seventysix ~/privdns % ./privdns.py 8.8.8.8
[*] Checking nameserver 8.8.8.8
[.] Resolved but no entry for 10.0.0.1
[.] Resolved but no entry for 172.16.0.1
[.] Resolved but no entry for 192.168.0.1
[.] Resolved but no entry for fc00::1
[.] Resolved but no entry for fd00::1
```

Scan a specific network range in a given dnsserver
```
michael@seventysix ~/privdns % ./privdns.py 8.8.8.8 10.0.0.0/8
[*] Checking nameserver 8.8.8.8
[.] Resolved but no entry for 10.0.0.1
[.] Resolved but no entry for 10.0.0.2
[.] Resolved but no entry for 10.0.0.3
[.] Resolved but no entry for 10.0.0.4
[.] Resolved but no entry for 10.0.0.5

```

Do a quickcheck, i.e. scan the first servers for each private network range (10.0.0.1 - 10.0.0.15, 172.16.0.1 - 172.16.0.15 etc.)
```
michael@seventysix ~/privdns % ./privdns.py -q 8.8.8.8
[*] Checking nameserver 8.8.8.8
[*] Checking network 10.0.0.0/8
    * Nameserver responded, further checks 
[*] Checking network 172.16.0.0/12
    * Nameserver responded, further checks 
[*] Checking network 192.168.0.0/16
    * Nameserver responded, further checks 
[*] Checking network fc00::/7
    * Nameserver responded, further checks 
[*] Checking network fd00::/8
    * Nameserver responded, further checks 
```

## Troubleshooting

1. I'm geting a "host bit set" error

Specify your network correctly, it should match your CIDR notation and all "free" bits need to be zero. So you can tell it to scan 10.0.0.0/8 but not 10.0.1.0/8. You would have to specify 10.0.1.0/24 then.

2. How can I scan a single private ip?

You can't do that with this tool. Use dig or something else.

3. Is it fast?

No, it's slow and not threaded or optimized for speed. It still should be usable for standard usecases.

## Additional notes

I scanned around 30K german and US nameservers for this. It doesn't seem to be a too common problem. Mostly servers belonging to the same companies showed up in the hits, as well as some private routers (mostly broadcom). You can read more on this here: https://www.codemetrix.net/...
