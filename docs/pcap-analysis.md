# PCAP analysis: two public sample captures

Purpose: practice reading network traffic with Wireshark and tshark, and write down
what the evidence shows, keeping facts and assumptions apart.

## Scope and safety

- Only public sample captures from the official Wireshark sample page
  (https://wiki.wireshark.org/SampleCaptures) were analyzed. No traffic from my own
  machine or network was captured.
- The capture files are not stored in this repository: their redistribution terms are
  not stated, and *.cap, *.pcap and *.pcapng are git-ignored. Anyone can download
  them from the page above and check the SHA256 values below.
- The captures are old (the browser string in http.cap carries a 2004 build date).
  Their addresses are historical and are not threat indicators.

## Files

| File | Size (bytes) | SHA256 |
|---|---|---|
| http.cap | 25803 | 25A72BDF10339F2C29916920C8B9501D294923108DE8F29B19ABA7CC001AB60D |
| dns.cap | 4338 | 041EEB6F98BB398F1EE8B09651B5B5A84F6A62639F95BF226F9E7B77355D9F28 |

## Method

All commands use tshark (installed with Wireshark) and only read the files:

    tshark -r http.cap -q -z io,phs
    tshark -r http.cap -Y "dns or http"
    tshark -r http.cap -q -z conv,tcp
    tshark -r http.cap -Y "http.request" -T fields -e frame.number -e http.host -e http.user_agent
    tshark -r http.cap -Y "http" -T fields -e frame.number -e http.request_in -e http.response_in -e http.response.code -e http.content_type
    tshark -r dns.cap -T fields -e frame.number -e ip.src -e ip.dst -e dns.flags.response -e dns.qry.name -e dns.qry.type -e dns.flags.rcode
    tshark -r dns.cap -Y "dns.flags.rcode != 0" -T fields -e frame.number -e ip.src -e ip.dst -e dns.qry.name -e dns.qry.type -e dns.flags.rcode

## http.cap

### Facts

- 43 frames, 25,091 bytes: 41 TCP frames and 2 UDP frames (one DNS query and its response).
- Two TCP conversations from one client to two web servers on port 80:

| Conversation | Frames | Size | Duration |
|---|---|---|---|
| client:3372 to 65.208.228.223:80 | 34 | about 20 kB | 30.39 s |
| client:3371 to 216.239.59.99:80 | 7 | 4,119 bytes | 1.79 s |

- Timeline:

| Frame | Time (s) | Event |
|---|---|---|
| 4 | 0.91 | GET /download.html, Host www.ethereal.com |
| 13 | 2.55 | DNS query (A) for pagead2.googlesyndication.com |
| 17 | 2.91 | DNS response: a CNAME chain and two A records |
| 18 | 2.98 | GET /pagead/ads?... to 216.239.59.99, Host pagead2.googlesyndication.com |
| 27 | 3.96 | 200 OK, text/html (answers frame 18) |
| 38 | 4.85 | 200 OK, text/html (answers frame 4) |

- Request and response pairing comes from Wireshark's HTTP analysis (http.request_in).
- All traffic is plain HTTP and DNS: URLs, query parameters and headers are readable
  by anyone on the network path.
- Both requests carry the same User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6) Gecko/20040113.

### Reading (interpretation, not proof)

- The pattern fits a browser loading a page and then an embedded advertising resource:
  the name is resolved first, then the request follows.
- Host and User-Agent are text written by the client and can be forged, so they are
  weak evidence on their own.
- tshark labels the body of frame 38 as xml. That is a heuristic; the declared
  Content-Type is text/html.
- Not determined by this capture: who the user was, what the page showed, and whether
  65.208.228.223 really belongs to the host named in the Host header (the capture has
  no DNS lookup for that name).

## dns.cap

### Facts

- 38 DNS messages (queries and responses) in two groups.
- Group A: 192.168.170.8 asks 192.168.170.20 about public names using many record types
  (TXT, MX, LOC, A, AAAA, ANY, NS and reverse PTR lookups).
- Group B: 192.168.170.56 asks 217.13.4.24 for SRV records named like
  _ldap._tcp.dc._msdcs.[internal domain] and for the A record of one host name,
  which it asked twice.
- Six responses carry an error. All six are rcode 3 (NXDOMAIN, the name does not exist):

| Frame | From | To | Name | Type |
|---|---|---|---|---|
| 22 | 192.168.170.20 | 192.168.170.8 | www.example.notginh | AAAA |
| 30 | 217.13.4.24 | 192.168.170.56 | _ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.[internal domain] | SRV |
| 32 | 217.13.4.24 | 192.168.170.56 | _ldap._tcp.dc._msdcs.[internal domain] | SRV |
| 34 | 217.13.4.24 | 192.168.170.56 | _ldap._tcp.[GUID].domains._msdcs.[internal domain] | SRV |
| 36 | 217.13.4.24 | 192.168.170.56 | [host].[internal domain] | A |
| 38 | 217.13.4.24 | 192.168.170.56 | [host].[internal domain] | A |

### Reading (interpretation, not proof)

- Group A looks like manual DNS testing with a tool such as dig or nslookup: many record
  types for one name, a deliberately invalid name, and a reverse lookup of 127.0.0.1.
  The capture does not say which tool was used.
- Group B matches the standard way Windows clients locate Active Directory domain
  controllers (SRV lookups under _msdcs). Every answer from 217.13.4.24 was NXDOMAIN.
  That address is not a private one, so an internal domain name may be leaking to an
  external resolver, which usually points to a DNS configuration mistake. The capture
  cannot show whether that server was the resolver the client was meant to use.
- DNS errors alone are not an attack indicator. In other settings a burst of NXDOMAIN
  answers can come from reconnaissance, so source, destination and frequency must be
  checked before drawing conclusions.

## Limits of this analysis

- Two small public teaching captures: no claim about detection accuracy or about any
  real network.
- Every finding comes only from the commands listed above.
- This work is separate from the Windows event log analyzer in src/. Correlating
  network and endpoint evidence is possible future work, not something done here.
