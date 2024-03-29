import struct


def parse_field_number_and_type(byte):
    field_number = byte >> 3
    wire_type = byte & 0x07
    return field_number, wire_type


def parse_varint_field(data):
    result = 0
    shift = 0
    length = 0
    for byte in data:
        length += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return (length, result)
        shift += 7
    raise ValueError("Malformed varint")


def parse_fixed64_field(data):
    return struct.unpack("<Q", data)[0]


def parse_fixed32_field(data):
    return struct.unpack("<I", data)[0]


def parse_length_delimited_field(data):
    [length_len, length] = parse_varint_field(data)
    return data[length_len : length_len + length]


def parse_message(buffer):
    fields = {}
    while buffer:
        [tag_len, tag] = parse_varint_field(buffer)

        field_number, wire_type = parse_field_number_and_type(tag)

        buffer = buffer[tag_len:]

        if wire_type == 0:  # Varint
            [value_len, value] = parse_varint_field(buffer)
            if field_number not in fields or fields[field_number]["type"] == "varint":
                fields[field_number] = {"type": "varint", "value": value}
            buffer = buffer[value_len:]

        elif wire_type == 1:  # Fixed64
            value = parse_fixed64_field(buffer[:8])
            if field_number not in fields or fields[field_number]["type"] == "fixed64":
                fields[field_number] = {
                    "type": "fixed64",
                    "value": value,
                }
            buffer = buffer[8:]

        elif wire_type == 2:  # Length-delimited
            [length_len, length] = parse_varint_field(buffer)
            value = buffer[length_len : length_len + length]
            if (
                field_number not in fields
                or fields[field_number]["type"] == "length-delimited"
            ):
                fields[field_number] = {
                    "type": "length-delimited",
                    "value": value,
                }
            buffer = buffer[length_len + length :]

        elif wire_type == 5:  # Fixed32
            value = parse_fixed32_field(buffer[:4])
            if field_number not in fields or fields[field_number]["type"] == "fixed32":
                fields[field_number] = {
                    "type": "fixed32",
                    "value": value,
                }
            buffer = buffer[4:]

        else:
            raise ValueError(f"Unsupported wire type: {wire_type}")

    return fields
