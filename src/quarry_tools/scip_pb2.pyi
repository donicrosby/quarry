from google.protobuf.internal.containers import (
    RepeatedCompositeFieldContainer,
    RepeatedScalarFieldContainer,
)
from google.protobuf.message import Message

class SymbolInformation(Message):
    symbol: str
    display_name: str
    enclosing_symbol: str
    def __init__(
        self,
        *,
        symbol: str = ...,
        display_name: str = ...,
        enclosing_symbol: str = ...,
    ) -> None: ...

class Occurrence(Message):
    symbol: str
    symbol_roles: int
    range: RepeatedScalarFieldContainer[int]
    def __init__(self, *, symbol: str = ..., symbol_roles: int = ...) -> None: ...

class Document(Message):
    relative_path: str
    language: str
    symbols: RepeatedCompositeFieldContainer[SymbolInformation]
    occurrences: RepeatedCompositeFieldContainer[Occurrence]
    def __init__(self, *, relative_path: str = ..., language: str = ...) -> None: ...

class Index(Message):
    documents: RepeatedCompositeFieldContainer[Document]
    external_symbols: RepeatedCompositeFieldContainer[SymbolInformation]
    def __init__(self) -> None: ...
