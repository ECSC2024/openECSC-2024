from minidump import minidumpfile
import json
import base64
import struct

out = []

with open("ssh.exe.dmp", "rb") as f:
    file_bin = f.read()
    mdf = minidumpfile.MinidumpFile.parse_bytes(file_bin)

    for segment in mdf.memory_segments_64.memory_segments:
        out.append({
            "base_address": struct.pack(">Q", segment.start_virtual_address).hex(),
            "data": base64.b64encode(file_bin[segment.start_file_address : segment.start_file_address + segment.size]).decode()
        })

with open("ssh.exe.maxidump", "w") as f:
    f.write(json.dumps(out, indent=2))
