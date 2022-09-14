"""
DIDDoc utility methods.

Copyright 2017-2019 Government of Canada
Public Services and Procurement Canada - buyandsell.gc.ca

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import datetime
from urllib.parse import urlparse

import semver
from multibase import decode

if __name__ == "__main__":
    from mydata_did.v1_0.utils.regex import MYDATA_DID_PATTERN
else:
    from .regex import MYDATA_DID_PATTERN


def resource(ref: str, delimiter: str = None) -> str:
    """
    Extract the resource for an identifier.

    Given a (URI) reference, return up to its delimiter (exclusively), or all of it if
    there is none.

    Args:
        ref: reference
        delimiter: delimiter character
            (default None maps to '#', or ';' introduces identifiers)
    """

    return ref.split(delimiter if delimiter else "#")[0]


def derive_did_type(uri: str) -> str:
    mydata_did_pattern_match = MYDATA_DID_PATTERN.match(uri)
    if mydata_did_pattern_match:
        return mydata_did_pattern_match.group("did_type")
    return None


def canon_did(uri: str) -> str:
    """
    Convert a URI into a DID if need be, left-stripping 'did:mydata:' if present.

    Args:
        uri: input URI or DID

    Raises:
        ValueError: for invalid input.

    """

    if ok_did(uri):
        return uri

    if uri.startswith("did:mydata:"):
        mydata_did_pattern_match = MYDATA_DID_PATTERN.match(uri)
        if mydata_did_pattern_match:
            prefix_end = 13 if mydata_did_pattern_match.group("did_type") else 11
            rv = uri[prefix_end:]
            if ok_did(rv):
                return rv
    raise ValueError(
        "Bad specification {} does not correspond to a MyData DID".format(uri)
    )


def canon_ref(did: str, ref: str, delimiter: str = None, did_type: str = None):
    """
    Given a reference in a DID document, return it in its canonical form of a URI.

    Args:
        did: DID acting as the identifier of the DID document
        ref: reference to canonicalize, either a DID or a fragment pointing to a
            location in the DID doc
        delimiter: delimiter character marking fragment (default '#') or
            introducing identifier (';') against DID resource
    """

    if not ok_did(did):
        raise ValueError("Bad DID {} cannot act as DID document identifier".format(did))

    if ok_did(ref):  # e.g., LjgpST2rjsoxYegQDRm7EL
        return (
            "did:mydata:{}".format(did)
            if not did_type
            else "did:mydata:{}:{}".format(did_type, did)
        )

    if ok_did(resource(ref, delimiter)):  # e.g., LjgpST2rjsoxYegQDRm7EL#keys-1
        return (
            "did:mydata:{}".format(ref)
            if not did_type
            else "did:mydata:{}:{}".format(did_type, did)
        )

    if ref.startswith(
        "did:mydata:"
    ):  # e.g., did:mydata:LjgpST2rjsoxYegQDRm7EL, did:mydata:LjgpST2rjsoxYegQDRm7EL#3
        mydata_did_pattern_match = MYDATA_DID_PATTERN.match(resource(ref, delimiter))
        if mydata_did_pattern_match:
            prefix_end = 13 if mydata_did_pattern_match.group("did_type") else 11
            rv = ref[prefix_end:]
            if ok_did(resource(rv, delimiter)):
                return ref
        raise ValueError("Bad URI {} does not correspond to a MyData DID".format(ref))

    if urlparse(ref).scheme:  # e.g., https://example.com/messages/8377464
        return ref

    return (
        "did:mydata:{}{}{}".format(did, delimiter if delimiter else "#", ref)
        if not did_type
        else "did:mydata:{}:{}{}{}".format(
            did_type, did, delimiter if delimiter else "#", ref
        )
    )


def ok_did(token: str) -> bool:
    """
    Whether input token looks like a valid decentralized identifier.

    Args:
        token: candidate string

    Returns: whether input token looks like a valid schema identifier

    """
    try:
        return len(decode(token)) == 34 if token else False
    except ValueError:
        return False


def current_datetime_in_iso8601() -> str:
    """
    Return current datetime in ISO8601 format.
    """
    return str(
        datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc).isoformat()
    )


def str_to_bool(s: str) -> bool:
    """
    Convert a string to a boolean.

    Args:
        s: string to convert

    Returns: boolean value

    """

    if not isinstance(s, str):
        return False

    if s.lower() in ["true", "t", "1"]:
        return True
    elif s.lower() in ["false", "f", "0"]:
        return False
    else:
        raise ValueError("Cannot convert string to boolean: {}".format(s))


def bool_to_str(b: bool) -> str:
    """
    Convert a boolean to a string.

    Args:
        b: boolean to convert

    Returns: string value

    """
    return "true" if b else "false"


def int_to_semver_str(int_version: int) -> str:
    """
    Convert integer version to semver string.
    """
    return str(semver.VersionInfo(str(int_version)))


def comma_separated_str_to_list(s: str) -> list:
    """
    Convert a comma separated string to a list.

    Args:
        s: string to convert

    Returns: list value

    """
    return s.split(",")


def get_slices(page, page_size=10):
    """
    Get the start and end indices for the given page and page size.

    Args:
        page: page number
        page_size: page size

    Returns: start and end indices

    """
    start = (page - 1) * page_size

    end = start + page_size

    return start, end


if __name__ == "__main__":
    print(canon_did("did:mydata:0:z6MkfiSdYhnLnS6jfwSf2yS2CiwwjZGmFUFL5QbyL2Xu8z2E"))
