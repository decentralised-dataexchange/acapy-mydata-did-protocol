"""Message and inner object type identifiers for Connections."""

from aries_cloudagent.protocols.didcomm_prefix import DIDCommPrefix

SPEC_URI = (
    "https://github.com/hyperledger/aries-rfcs/tree/"
    "bb42a6c35e0d5543718fb36dd099551ab192f7b0/features/0036-issue-credential"
)

# Message types
CREDENTIAL_PROPOSAL = f"issue-credential/1.0/propose-credential"
CREDENTIAL_OFFER = f"issue-credential/1.0/offer-credential"
CREDENTIAL_REQUEST = f"issue-credential/1.0/request-credential"
CREDENTIAL_ISSUE = f"issue-credential/1.0/issue-credential"
CREDENTIAL_ACK = f"issue-credential/1.0/ack"

PROTOCOL_PACKAGE = "mydata_did.patched_protocols.issue_credential.v1_0"

MESSAGE_TYPES = DIDCommPrefix.qualify_all(
    {
        CREDENTIAL_PROPOSAL: (
            f"{PROTOCOL_PACKAGE}.messages.credential_proposal.CredentialProposal"
        ),
        CREDENTIAL_OFFER: (
            f"{PROTOCOL_PACKAGE}.messages.credential_offer.CredentialOffer"
        ),
        CREDENTIAL_REQUEST: (
            f"{PROTOCOL_PACKAGE}.messages.credential_request.CredentialRequest"
        ),
        CREDENTIAL_ISSUE: (
            f"{PROTOCOL_PACKAGE}.messages.credential_issue.CredentialIssue"
        ),
        CREDENTIAL_ACK: f"{PROTOCOL_PACKAGE}.messages.credential_ack.CredentialAck",
    }
)

# Inner object types
CREDENTIAL_PREVIEW = f"issue-credential/1.0/credential-preview"

# Identifiers to use in attachment decorators
ATTACH_DECO_IDS = {
    CREDENTIAL_OFFER: "libindy-cred-offer-0",
    CREDENTIAL_REQUEST: "libindy-cred-request-0",
    CREDENTIAL_ISSUE: "libindy-cred-0",
}
