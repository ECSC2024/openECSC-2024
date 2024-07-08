# TeamItaly Preselection CTF 2024

## [misc] ssh.exe (0 solves)

Our forensics team managed to capture a SSH connection and dump the process memory (while it was connected) but they've no clue how to read the communication. Can you help them?

Author: Luca Massarelli (ACN), Bruno Taricco (ACN), Lorenzo Zarfati (ACN), Giovanni Minotti <@Giotino>

## Overview

We are given a PCAP file and a memory dump of the `ssh.exe` process. The goal is to extract the encryption keys used during the SSH connection and read the communication.

## Solution

### Network traffic analysis

To analyze network traffic, we can use `Wireshark`.  
Upon opening the PCAP file, we see that there is an SSH connection. The client is using the software `SSH-2.0-OpenSSH_for_Windows_8.6`, the source code of which is available on GitHub (<https://github.com/PowerShell/openssh-portable/releases/tag/v8.6.0.0>). The encryption used is `aes128-ctr`. This information will be useful later on.

### Memory analysis

The file `ssh.exe.maxidump` is a file that contains various segments of the memory of the `ssh.exe` process in JSON format.

```JSON
[
  {
    "base_address": 2147352576,
    "data": "AQAAAAAAA..."
  },
  {
    "base_address": 2147356672,
    "data": "AQAAAAAAA..."
  }
]
```

To retrieve the symmetric keys (there are two because one exists for Client->Server and one for Server->Client) of the SSH communication, it is necessary to analyze the memory of the `ssh.exe` process at the time of capture.
Without source code and symbols, memory analysis is very complex and requires manual analysis. What we can do is use references to known strings and characteristics of the data structures to search for the keys in the memory (we actually have the source code and symbols, but the maxidump format prevents us from loading everything into Visual Studio).

Specifically, this is the data structure that contains the keys:

```C
struct sshenc {
 char *name;
 const struct sshcipher *cipher;
 int enabled;
 u_int key_len;
 u_int iv_len;
 u_int block_size;
 u_char *key;
 u_char *iv;
};
```

We can use `name` (which is the cipher name) to locate instances of the data structure in memory, match some parametets (for example `key_len` must be 16, due to `aes128-ctr`) and then read the encryption keys (and other parameters).

See `extract-keys.py`  (output in `extracted-keys.txt`).

I haven't investigated much into the order in which the two structures are instantiated in the code, but I noticed that the first structure contains the key for client->server and the second one for server->client.

### Decryption of the traffic

To reconstruct the traffic and extract the data exchanged between the two machines using `tshark`, we can use the following command:

```bash
tshark -r capture.pcapng -q -z follow,tcp,raw,0 > comm.txt
```

After running this command, `comm.txt` will contain hexadecimal data representing the exchanged data between the client and server. Lines that begin with `\t` contain server->client data, while lines that start directly with hexadecimal characters contain client->server data. We should ignore any non-hexadecimal content, such as headers at the top and a line at the bottom.

Following the SSH protocol, we need to extract all frames of communication, which may include multiple frames within the same TCP packet. Therefore, it's crucial to read the data correctly rather than relying on individual TCP packets.

Next, we'll need to decrypt the data using the keys (and IVs) found earlier. These keys and IVs should be placed at the beginning of the `decrypt-traffic.py` script.

See `decrypt-traffic.py` to perform the decryption (output in `decrypted-traffic.txt`).

Running `decrypt-traffic.py` will provide us with all the decrypted traffic. This process allows us to analyze the SSH communication and access the plaintext exchanged between the client and server.

We don't need to proceed with decoding SSH frames since the flag is visible.

`S->C ENC b'\x05^\x00\x00\x00\x00\x00\x00\x001TeamItaly{ssh_decryption_successfully_achieved}\r\na\t\xa9\xd6Y'`
