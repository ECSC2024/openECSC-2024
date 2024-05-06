import pyshark
import requests

ENDPOINT = "http://localhost:5000/maze"

cap = pyshark.FileCapture("../../attachments/capture.pcap", display_filter="http")

moves = []

for pkt in cap:
    if hasattr(pkt.http, "request_method"):
        moves.append(pkt.http.request_uri_query.split("=")[1])
    if hasattr(pkt.http, "response"):
        if "FAILED" in pkt.http.file_data:
            moves.pop()


s = requests.Session()

i = 0
while i < len(moves):
    move = moves[i]
    r = s.get(ENDPOINT, params={"direction": move})
    if "FAILED" not in r.text:
        i += 1

print(r.text)
