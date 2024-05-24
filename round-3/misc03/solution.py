from scapy.all import rdpcap, TCP
from collections import namedtuple
import sys

if len(sys.argv) != 2:
	print(f"Usage: {sys.argv[0]} <pcap>")
	sys.exit(1)

pcap = rdpcap(sys.argv[1])

# filter for frames containing enc
pcap = [p for p in pcap if b'enc' in bytes(p)]
assert len(pcap) == 2

# marker for tuple of two elements (tuple=68, len=02)
tuple_of_two = bytes.fromhex("6802")

# erlang data is encoded as TLV
TLV = namedtuple('TLV', ['t', 'l', 'v'])
parsed = []
for p in pcap:
	tlv_bytes = p[TCP].load.split(tuple_of_two)[-1]

	tlvs = []
	for i in range(2):
		t = tlv_bytes[:2] # tag
		tlv_bytes = tlv_bytes[2:]
		l = tlv_bytes[0] # len
		tlv_bytes = tlv_bytes[1:]
		v = tlv_bytes[:l] # val
		tlv_bytes = tlv_bytes[l:]
		# print(t,l,v)
		tlvs.append(TLV(t,l,v))
	
	parsed.append(tlvs)
	
# print(parsed)

p0 = parsed[0][0].v
c0 = parsed[0][1].v

p1 = parsed[1][0].v
c1 = parsed[1][1].v

# check that p1 is a rotation of p0
assert p1[:-1] == p0[1:] and p1[-1] == p0[0] and sorted(p0) == list(range(len(p0)))
c = [c0[i] ^ c1[i] for i in range(len(c0))]

"""
we have two expressions:
```
x[p0] ^ k0 = c0
x[p1] ^ k1 = c1
...
x[pn] ^ kn = cn
```

and 
```
x[p1] ^ k0 = d0
x[p2] ^ k1 = d1
...
x[pn] ^ k{n-1} = d{n-1}
x[0] ^ kn = dn
```

if we xor first row of the first expression with first row of the second etc we get:
```
x[p0] ^ x[p1] = c0 ^ d0
x[p1] ^ x[p2] = c1 ^ d1
...
x[pi] ^ x[p{i+1}] = ci ^ di
...
x[pn] ^ x[p0] = cn ^ dn
```

since we know the p vector and we know x[n] = '}' we can start from the row where pi = n and solve for x[p{i+1}] and so on
"""

L = len(p0)
x = [None] * L

x[L-1] = ord('}')

i = p0.index(L-1)

for _ in range(L):
	x[p0[(i+1) % L]] = c[i] ^ x[p0[i]]
	i = (i+1) % L

print(bytes(x).decode())


