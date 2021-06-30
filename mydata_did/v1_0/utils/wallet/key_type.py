"""Key type enum."""

from enum import Enum
from typing import NamedTuple, Optional

# Define keys
KeySpec = NamedTuple(
    "KeySpec",
    [("key_type", str), ("multicodec_name", str), ("multicodec_prefix", int)],
)


class KeyTypeException(BaseException):
    """Key type exception."""


class KeyType(Enum):
    """KeyType Enum specifying key types with multicodec name."""

    # NOTE: the py_multicodec library is outdated. We use hardcoded prefixes here
    # until this PR gets released: https://github.com/multiformats/py-multicodec/pull/14
    # multicodec is also not used now, but may be used again if py_multicodec is updated
    ED25519 = KeySpec("ed25519", "ed25519-pub", b"\xed\x01")

    @property
    def key_type(self) -> str:
        """Getter for key type identifier."""
        return self.value.key_type

    @property
    def multicodec_name(self) -> str:
        """Getter for multicodec name."""
        return self.value.multicodec_name

    @property
    def multicodec_prefix(self) -> bytes:
        """Getter for multicodec prefix."""
        return self.value.multicodec_prefix

    @classmethod
    def from_multicodec_name(cls, multicodec_name: str) -> Optional["KeyType"]:
        """Get KeyType instance based on multicodec name. Returns None if not found."""
        for key_type in KeyType:
            if key_type.multicodec_name == multicodec_name:
                return key_type

        return None

    @classmethod
    def from_multicodec_prefix(cls, multicodec_prefix: bytes) -> Optional["KeyType"]:
        """Get KeyType instance based on multicodec prefix. Returns None if not found."""
        for key_type in KeyType:
            if key_type.multicodec_prefix == multicodec_prefix:
                return key_type

        return None

    @classmethod
    def from_prefixed_bytes(cls, prefixed_bytes: bytes) -> Optional["KeyType"]:
        """Get KeyType instance based on prefix in bytes. Returns None if not found."""
        for key_type in KeyType:
            if prefixed_bytes.startswith(key_type.multicodec_prefix):
                return key_type

        return None

    @classmethod
    def from_key_type(cls, key_type: str) -> Optional["KeyType"]:
        """Get KeyType instance from the key type identifier."""
        for _key_type in KeyType:
            if _key_type.key_type == key_type:
                return _key_type

        return None
