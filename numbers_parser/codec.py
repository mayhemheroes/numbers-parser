from builtins import zip
from builtins import str
from builtins import object

import sys
import struct
import snappy
import traceback
from functools import partial

from numbers_parser.mapping import ID_NAME_MAP, NAME_CLASS_MAP

from google.protobuf.internal.encoder import _VarintBytes
from google.protobuf.internal.decoder import _DecodeVarint32
from google.protobuf.json_format import MessageToDict, ParseDict
from google.protobuf.message import EncodeError

from numbers_parser.generated.TSPArchiveMessages_pb2 import ArchiveInfo


MAX_FLOAT = 340282346638528859811704183484516925440.000000000000000000


class IWAFile(object):
    def __init__(self, chunks, filename=None):
        self.chunks = chunks
        self.filename = filename

    @classmethod
    def from_buffer(cls, data, filename=None):
        try:
            chunks = []
            while data:
                chunk, data = IWACompressedChunk.from_buffer(data, filename)
                chunks.append(chunk)

            return cls(chunks, filename)
        except Exception as e:
            if filename:
                raise ValueError("Failed to deserialize " + filename) from e
            else:
                raise

    @classmethod
    def from_dict(cls, _dict):
        return cls([IWACompressedChunk.from_dict(chunk) for chunk in _dict["chunks"]])

    def to_dict(self):
        try:
            return {"chunks": [chunk.to_dict() for chunk in self.chunks]}
        except Exception as e:
            if self.filename:
                raise ValueError("Failed to serialize " + self.filename) from e
            else:
                raise

    def to_buffer(self):
        return b"".join([chunk.to_buffer() for chunk in self.chunks])


class IWACompressedChunk(object):
    def __init__(self, archives):
        self.archives = archives

    def __eq__(self, other):
        return self.archives == other.archives

    @classmethod
    def _decompress_all(cls, data):
        while data:
            header = data[:4]

            first_byte = header[0]
            if not isinstance(first_byte, int):
                first_byte = ord(first_byte)

            if first_byte != 0x00:
                raise ValueError(
                    "IWA chunk does not start with 0x00! (found %x)" % first_byte
                )

            unpacked = struct.unpack_from("<I", bytes(header[1:]) + b"\x00")
            length = unpacked[0]
            chunk = data[4 : 4 + length]
            data = data[4 + length :]

            try:
                yield snappy.uncompress(chunk)
            except Exception:
                # Try to see if this data isn't compressed in the first place.
                # If this data is still compressed, parsing it as Protobuf
                # will almost definitely fail anyways.
                yield chunk

    @classmethod
    def from_buffer(cls, data, filename=None):
        data = b"".join(cls._decompress_all(data))
        archives = []
        while data:
            archive, data = IWAArchiveSegment.from_buffer(data, filename)
            archives.append(archive)
        return cls(archives), None

    @classmethod
    def from_dict(cls, _dict):
        return cls([IWAArchiveSegment.from_dict(d) for d in _dict["archives"]])

    def to_dict(self):
        return {"archives": [archive.to_dict() for archive in self.archives]}

    def to_buffer(self):
        uncompressed = b"".join([archive.to_buffer() for archive in self.archives])
        payloads = []
        while uncompressed:
            payloads.append(snappy.compress(uncompressed[:65536]))
            uncompressed = uncompressed[65536:]
        return b"".join(
            [
                b"\x00" + struct.pack("<I", len(payload))[:3] + payload
                for payload in payloads
            ]
        )


class ProtobufPatch(object):
    def __init__(self, data):
        self.data = data

    def __eq__(self, other):
        return self.data == other.data

#    def __repr__(self):
#        return "<%s %s>" % (self.__class__.__name__, self.data)

    def to_dict(self):
        return message_to_dict(self.data)

    @classmethod
    def FromString(cls, message_info, proto_klass, data):
        if len(message_info.diff_field_path.path) != 1:
            print(
                str(proto_klass)
                + ": can't process diff_field_path = "
                + str(len(message_info.diff_field_path.path)),
                file=sys.stderr,
            )
            return cls(proto_klass.FromString(data))

        if message_info.fields_to_remove:
            print(
                str(proto_klass) + ": can't process fields_to_remove", file=sys.stderr
            )
            return cls(proto_klass.FromString(data))

        for diff_path in message_info.diff_field_path.path:
            if diff_path not in proto_klass.DESCRIPTOR.fields_by_number:
                print(str(proto_klass) + ": " + str(diff_path) + " path not found", file=sys.stderr)
                return cls(proto_klass.FromString(data))
            else:
                patched_field = proto_klass.DESCRIPTOR.fields_by_number[diff_path]
                print(str(proto_klass) + ": patching", str(patched_field), file=sys.stderr)
                field_message_class = NAME_CLASS_MAP[patched_field.message_type.full_name]
                return cls(field_message_class.FromString(data))

    def SerializeToString(self):
        return self.data.SerializePartialToString()


class IWAArchiveSegment(object):
    def __init__(self, header, objects):
        self.header = header
        self.objects = objects

    def __eq__(self, other):
        return self.header == other.header and self.objects == other.objects

#    def __repr__(self):
#        return "<%s identifier=%s objects=%s>" % (
#            self.__class__.__name__,
#            self.header.identifier,
#            repr(self.objects).replace("\n", " ").replace("  ", " "),
#        )

    @classmethod
    def from_buffer(cls, buf, filename=None):
        archive_info, payload = get_archive_info_and_remainder(buf)
        if not repr(archive_info):
            raise ValueError("Segment doesn't seem to start with an ArchiveInfo!")

        payloads = []

        n = 0
        for message_info in archive_info.message_infos:
            try:
                if message_info.type == 0 and archive_info.should_merge and payloads:
                    base_message = archive_info.message_infos[
                        message_info.base_message_index
                    ]
                    klass = partial(
                        ProtobufPatch.FromString,
                        message_info,
                        ID_NAME_MAP[base_message.type],
                    )
                else:
                    klass = ID_NAME_MAP[message_info.type]
            except KeyError:
                raise NotImplementedError(
                    "Don't know how to parse Protobuf message type "
                    + str(message_info.type)
                )
            try:
                message_payload = payload[n : n + message_info.length]
                if hasattr(klass, "FromString"):
                    output = klass.FromString(message_payload)
                else:
                    output = klass(message_payload)
            except Exception as e:
                raise ValueError(
                    "Failed to deserialize %s payload of length %d: %s"
                    % (klass, message_info.length, e)
                )
            payloads.append(output)
            n += message_info.length

        return cls(archive_info, payloads), payload[n:]

    @classmethod
    def from_dict(cls, _dict):
        header = dict_to_header(_dict["header"])
        objects = []
        for message_info, o in zip(header.message_infos, _dict["objects"]):
            if message_info.diff_field_path and "_pbtype" not in o:
                base_message_info = header.message_infos[
                    message_info.base_message_index
                ]
                message_class = ID_NAME_MAP[base_message_info.type]
                objects.append(ProtobufPatch(message_class, o))
            else:
                objects.append(dict_to_message(o))
        return cls(header, objects)

    def to_dict(self):
        return {
            "header": header_to_dict(self.header),
            "objects": [message_to_dict(message) for message in self.objects],
        }

    def to_buffer(self):
        # Each message_info as part of the header needs to be updated
        # so that its length matches the object contained within.
        for obj, message_info in zip(self.objects, self.header.message_infos):
            try:
                object_length = len(obj.SerializeToString())
                provided_length = message_info.length
                if object_length != provided_length:
                    message_info.length = object_length
            except EncodeError as e:
                raise ValueError(
                    "Failed to encode object: %s\nObject: '%s'\nMessage info: %s"
                    % (e, repr(obj), message_info)
                )
        return b"".join(
            [_VarintBytes(self.header.ByteSize()), self.header.SerializeToString()]
            + [obj.SerializeToString() for obj in self.objects]
        )


def message_to_dict(message):
    if hasattr(message, "to_dict"):
        return message.to_dict()
    output = MessageToDict(message)
    output["_pbtype"] = type(message).DESCRIPTOR.full_name
    return output


def header_to_dict(message):
    output = message_to_dict(message)
    for message_info in output["messageInfos"]:
        del message_info["length"]
    return output


def _work_around_protobuf_max_float_handling(_dict):
    """
    protobuf==3.13.0 includes a check to make sure that any `float` value
    parsed from a Python dictionary must be less than FLOAT_MAX. Unfortunately,
    when parsing from YAML, serialized FLOAT_MAX values round to slightly over FLOAT_MAX.
    This is a nasty hack to fix that.
    """
    for k, v in _dict.items():
        if isinstance(v, dict):
            _work_around_protobuf_max_float_handling(v)
        elif isinstance(v, float):
            if v > MAX_FLOAT:
                _dict[k] = MAX_FLOAT
    return _dict


def dict_to_message(_dict):
    _type = _dict["_pbtype"]
    del _dict["_pbtype"]
    _dict = _work_around_protobuf_max_float_handling(_dict)
    return ParseDict(_dict, NAME_CLASS_MAP[_type](), ignore_unknown_fields=True)


def dict_to_header(_dict):
    for message_info in _dict["messageInfos"]:
        # set a dummy length value that we'll overwrite later
        message_info["length"] = 0
    return dict_to_message(_dict)


def get_archive_info_and_remainder(buf):
    msg_len, new_pos = _DecodeVarint32(buf, 0)
    n = new_pos
    msg_buf = buf[n : n + msg_len]
    n += msg_len
    return ArchiveInfo.FromString(msg_buf), buf[n:]
