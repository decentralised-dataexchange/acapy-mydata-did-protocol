from aries_cloudagent.protocols.didcomm_prefix import DIDCommPrefix

# DIDComm protocol specification URL
SPEC_URI = (
    "https://github.com/decentralised-dataexchange/automated-data-agreements/blob/"
    "main/docs/did-spec.md"
)

# Message types
CREATE_DID = f"mydata-did/1.0/create-did"
CREATE_DID_RESPONSE = f"mydata-did/1.0/create-did-response"

READ_DID = f"mydata-did/1.0/read-did"
READ_DID_RESPONSE = f"mydata_did/1.0/read-did-response"

DELETE_DID = f"mydata-did/1.0/delete-did"
DELETE_DID_RESPONSE = f"mydata-did/1.0/delete-did-response"

PROBLEM_REPORT = f"mydata-did/1.0/problem-report"

PROTOCOL_PACKAGE = "mydata_did.v1_0"

MESSAGE_TYPES = DIDCommPrefix.qualify_all(
    {
        CREATE_DID: (
            f"{PROTOCOL_PACKAGE}.messages.create_did.CreateDID"
        ),
        CREATE_DID_RESPONSE: (
            f"{PROTOCOL_PACKAGE}.messages.create_did_response.CreateDIDResponse"
        ),
        READ_DID: (
            f"{PROTOCOL_PACKAGE}.messages.read_did.ReadDID"
        ),
        READ_DID_RESPONSE: (
            f"{PROTOCOL_PACKAGE}.messages.read_did_response.ReadDIDResponse"
        ),
        DELETE_DID: (
            f"{PROTOCOL_PACKAGE}.messages.delete_did.DeleteDID"
        ),
        DELETE_DID_RESPONSE: (
            f"{PROTOCOL_PACKAGE}.messages.delete_did_response.DeleteDIDResponse"
        ),
        PROBLEM_REPORT: (
            f"{PROTOCOL_PACKAGE}.messages.problem_report.ProblemReport"
        )
    },
)
