"""Sign and verify functions for json-ld based data agreements."""

import json
import typing

from aries_cloudagent.wallet.base import BaseWallet
from aries_cloudagent.wallet.util import (
    b58_to_bytes,
    b64_to_bytes,
    b64_to_str,
    bytes_to_b58,
    bytes_to_b64,
    str_to_b64,
)
from mydata_did.v1_0.utils.jsonld.create_verify_data import create_verify_data

MULTIBASE_B58_BTC = "z"
MULTICODEC_ED25519_PUB = b"\xed"


def did_mydata(verkey: str) -> str:
    """Qualify verkey into DID MyData if need be."""

    if verkey.startswith(f"did:mydata:{MULTIBASE_B58_BTC}"):
        return verkey

    return f"did:mydata:{MULTIBASE_B58_BTC}" + bytes_to_b58(
        MULTICODEC_ED25519_PUB + b58_to_bytes(verkey)
    )


def b64encode(str):
    """Url Safe B64 Encode."""
    return str_to_b64(str, urlsafe=True, pad=False)


def b64decode(bytes):
    """Url Safe B64 Decode."""
    return b64_to_str(bytes, urlsafe=True)


def create_jws(encoded_header, verify_data):
    """Compose JWS."""
    return (encoded_header + ".").encode("utf-8") + verify_data


async def jws_sign(verify_data, verkey, wallet):
    """Sign JWS."""

    header = {"alg": "EdDSA", "b64": False, "crit": ["b64"]}

    encoded_header = b64encode(json.dumps(header))

    jws_to_sign = create_jws(encoded_header, verify_data)

    signature = await wallet.sign_message(jws_to_sign, verkey)

    encoded_signature = bytes_to_b64(signature, urlsafe=True, pad=False)

    return encoded_header + ".." + encoded_signature


def verify_jws_header(header):
    """Check header requirements."""

    if (
        not (
            header["alg"] == "EdDSA"
            and header["b64"] is False
            and isinstance(header["crit"], list)
            and len(header["crit"]) == 1
            and header["crit"][0] == "b64"
        )
        and len(header) == 3
    ):
        raise Exception("Invalid JWS header parameters for Ed25519Signature2018.")


async def jws_verify(verify_data, signature, public_key, wallet):
    """Detatched jws verify handling."""

    encoded_header, _, encoded_signature = signature.partition("..")
    decoded_header = json.loads(b64decode(encoded_header))

    verify_jws_header(decoded_header)

    decoded_signature = b64_to_bytes(encoded_signature, urlsafe=True)

    jws_to_verify = create_jws(encoded_header, verify_data)

    verified = await wallet.verify_message(jws_to_verify, decoded_signature, public_key)

    return verified


async def sign_data_agreement(data_agreement, signature_options, verkey, wallet):
    """Sign data agreement."""

    proof_chain = False
    if "proof" in data_agreement:
        # Detected the document is being signed more than once,
        # therefore expected output is a proof chain of 2 elements.

        proof_chain = True

    framed, verify_data_hex_string = create_verify_data(
        data_agreement, signature_options, proof_chain
    )

    verify_data_bytes = bytes.fromhex(verify_data_hex_string)

    jws = await jws_sign(verify_data_bytes, verkey, wallet)

    if "proofChain" not in data_agreement:
        if not proof_chain:
            # For single proof

            document_with_proof = {
                **data_agreement,
                "proof": {**signature_options, "proofValue": jws},
            }
        else:
            # For proof chain with 2 elements

            old_proof = data_agreement.pop("proof", None)
            new_proof = {**signature_options, "proofValue": jws}
            document_with_proof = {
                **data_agreement,
                "proofChain": [old_proof, new_proof],
            }
    else:

        # For proof chain with more than 2 elements

        document_with_proof = {**data_agreement}
        document_with_proof["proofChain"].append(
            {**signature_options, "proofValue": jws}
        )

    return document_with_proof


async def verify_data_agreement(doc, verkey, wallet, drop_proof_chain: bool = True):
    """Verify data agreement."""

    proof_chain = False
    old_proof = None
    new_proof = None
    if "proofChain" in doc:
        # Detected the document is being signed more than once, therefore it is a proof chain.
        proof_chain = True

        if drop_proof_chain:
            # For proof chain with 2 elements

            old_proof = doc["proofChain"][0]
            new_proof = doc["proofChain"][1]

            doc.pop("proofChain", None)

            doc["proof"] = old_proof
        else:
            # For proof chain with more than 2 elements

            new_proof = doc["proofChain"][-1]

            doc["proofChain"] = doc["proofChain"][:-1]

    framed, verify_data_hex_string = create_verify_data(
        doc, doc["proof"] if not proof_chain else new_proof, proof_chain
    )

    verify_data_bytes = bytes.fromhex(verify_data_hex_string)

    valid = await jws_verify(
        verify_data_bytes,
        framed["proof"]["proofValue"] if not proof_chain else new_proof["proofValue"],
        verkey,
        wallet,
    )

    return valid


async def verify_data_agreement_with_proof_chain(
    doc: dict = None, verkeys: typing.List[str] = None, wallet: BaseWallet = None
) -> bool:

    proof_chain = doc.pop("proofChain", None)
    genesis_proof = proof_chain[0]

    genesis_doc = {**doc, "proof": genesis_proof}
    genesis_doc["event"] = genesis_doc["event"][0]

    current_doc = {**doc, "proofChain": proof_chain}

    genesis_valid = await verify_data_agreement(genesis_doc.copy(), verkeys[0], wallet)

    current_valid = await verify_data_agreement(current_doc.copy(), verkeys[1], wallet)

    return genesis_valid and current_valid
