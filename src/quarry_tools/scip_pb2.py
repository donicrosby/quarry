"""Minimal SCIP protobuf Python bindings for quarry-tools.

Manually crafted from the SCIP protobuf schema (https://github.com/sourcegraph/scip).
Only the subset needed for call-graph extraction is included.
"""

from __future__ import annotations

from google.protobuf import descriptor_pb2 as _descriptor_pb2
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

_sym_db = _symbol_database.Default()

_OPTIONAL = _descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
_REPEATED = _descriptor_pb2.FieldDescriptorProto.LABEL_REPEATED
_STRING = _descriptor_pb2.FieldDescriptorProto.TYPE_STRING
_INT32 = _descriptor_pb2.FieldDescriptorProto.TYPE_INT32
_BOOL = _descriptor_pb2.FieldDescriptorProto.TYPE_BOOL
_ENUM = _descriptor_pb2.FieldDescriptorProto.TYPE_ENUM
_MESSAGE = _descriptor_pb2.FieldDescriptorProto.TYPE_MESSAGE


def _field(
    msg: _descriptor_pb2.DescriptorProto,
    name: str,
    number: int,
    ftype: int,
    label: int = _OPTIONAL,
    type_name: str | None = None,
) -> None:
    f = msg.field.add()
    f.name = name
    f.number = number
    f.type = ftype  # type: ignore[assignment]
    f.label = label  # type: ignore[assignment]
    if type_name is not None:
        f.type_name = type_name


def _build_file_descriptor():
    fp = _descriptor_pb2.FileDescriptorProto()
    fp.name = "scip.proto"
    fp.package = "scip"
    fp.syntax = "proto3"

    ev = fp.enum_type.add()
    ev.name = "ProtocolVersion"
    v = ev.value.add()
    v.name = "UnspecifiedProtocolVersion"
    v.number = 0

    ev = fp.enum_type.add()
    ev.name = "TextEncoding"
    for nm, num in [("UnspecifiedTextEncoding", 0), ("UTF8", 1), ("UTF16", 2)]:
        v = ev.value.add()
        v.name = nm
        v.number = num

    ev = fp.enum_type.add()
    ev.name = "SymbolRole"
    for nm, num in [
        ("UnspecifiedSymbolRole", 0),
        ("Definition", 1),
        ("Import", 2),
        ("WriteAccess", 4),
        ("ReadAccess", 8),
        ("Generated", 16),
        ("Test", 32),
        ("ForwardDefinition", 64),
    ]:
        v = ev.value.add()
        v.name = nm
        v.number = num

    ev = fp.enum_type.add()
    ev.name = "SyntaxKind"
    for nm, num in [("UnspecifiedSyntaxKind", 0), ("Comment", 1), ("IdentifierModule", 7)]:
        v = ev.value.add()
        v.name = nm
        v.number = num

    ev = fp.enum_type.add()
    ev.name = "SymbolKind"
    v = ev.value.add()
    v.name = "UnspecifiedKind"
    v.number = 0

    msg = fp.message_type.add()
    msg.name = "ToolInfo"
    _field(msg, "name", 1, _STRING)
    _field(msg, "version", 2, _STRING)
    _field(msg, "arguments", 3, _STRING, _REPEATED)

    msg = fp.message_type.add()
    msg.name = "Metadata"
    _field(msg, "version", 1, _ENUM, type_name=".scip.ProtocolVersion")
    _field(msg, "tool_info", 2, _MESSAGE, type_name=".scip.ToolInfo")
    _field(msg, "project_root", 3, _STRING)
    _field(msg, "text_document_encoding", 4, _ENUM, type_name=".scip.TextEncoding")

    msg = fp.message_type.add()
    msg.name = "Relationship"
    _field(msg, "symbol", 1, _STRING)
    _field(msg, "is_reference", 2, _BOOL)
    _field(msg, "is_implementation", 3, _BOOL)
    _field(msg, "is_type_definition", 4, _BOOL)
    _field(msg, "is_definition", 5, _BOOL)

    msg = fp.message_type.add()
    msg.name = "SymbolInformation"
    _field(msg, "symbol", 1, _STRING)
    _field(msg, "documentation", 3, _STRING, _REPEATED)
    _field(msg, "relationships", 4, _MESSAGE, _REPEATED, type_name=".scip.Relationship")
    _field(msg, "kind", 5, _ENUM, type_name=".scip.SymbolKind")
    _field(msg, "display_name", 6, _STRING)
    _field(msg, "enclosing_symbol", 8, _STRING)

    msg = fp.message_type.add()
    msg.name = "Occurrence"
    _field(msg, "range", 1, _INT32, _REPEATED)
    _field(msg, "symbol", 2, _STRING)
    _field(msg, "symbol_roles", 3, _INT32)
    _field(msg, "override_documentation", 4, _STRING, _REPEATED)
    _field(msg, "syntax_kind", 5, _ENUM, type_name=".scip.SyntaxKind")

    msg = fp.message_type.add()
    msg.name = "Document"
    _field(msg, "relative_path", 1, _STRING)
    _field(msg, "occurrences", 2, _MESSAGE, _REPEATED, type_name=".scip.Occurrence")
    _field(msg, "symbols", 3, _MESSAGE, _REPEATED, type_name=".scip.SymbolInformation")
    _field(msg, "language", 4, _STRING)

    msg = fp.message_type.add()
    msg.name = "Index"
    _field(msg, "metadata", 1, _MESSAGE, type_name=".scip.Metadata")
    _field(msg, "documents", 2, _MESSAGE, _REPEATED, type_name=".scip.Document")
    _field(msg, "external_symbols", 3, _MESSAGE, _REPEATED, type_name=".scip.SymbolInformation")

    return fp


DESCRIPTOR = _descriptor_pool.Default().Add(_build_file_descriptor())  # type: ignore[assignment]

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())  # type: ignore[arg-type]
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, __name__, globals())  # type: ignore[arg-type]
