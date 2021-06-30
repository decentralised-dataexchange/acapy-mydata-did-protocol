from aries_cloudagent.protocols.didcomm_prefix import DIDCommPrefix

# DIDComm protocol specification URL for MyData DID CRUD operations
SPEC_URI = (
    "https://github.com/decentralised-dataexchange/automated-data-agreements/blob/"
    "main/docs/did-spec.md"
)

# DIDComm protocol specification URL for Data Agreement lifecycle
DATA_AGREEMENT_SPEC_URI = (
    "https://github.com/decentralised-dataexchange/automated-data-agreements/blob/"
    "main/docs/didcomm-protocol-spec.md"
)

# Message types

# Message types for MyDATA DID CRUD operations (ADA RFC 0001 - MyData DID Protocol 1.0)
CREATE_DID = f"mydata-did/1.0/create-did"
CREATE_DID_RESPONSE = f"mydata-did/1.0/create-did-response"
READ_DID = f"mydata-did/1.0/read-did"
READ_DID_RESPONSE = f"mydata_did/1.0/read-did-response"
DELETE_DID = f"mydata-did/1.0/delete-did"
DELETE_DID_RESPONSE = f"mydata-did/1.0/delete-did-response"
MYDATA_DID_PROBLEM_REPORT = f"mydata-did/1.0/problem-report"

# Message types for Data Agreement CRUD operations (ADA RFC 0002 - Data Agreement Protocol 1.0)
READ_DATA_AGREEMENT = f"data-agreements/1.0/read-data-agreement"
READ_DATA_AGREEMENT_RESPONSE = f"data-agreements/1.0/read-data-agreement-response"
DATA_AGREEMENT_PROBLEM_REPORT = f"data-agreements/1.0/problem-report"

# Patched message types (Existing message types from Aries RFC are patched to support ADA RFC(s))
CONNECTION_REQUEST = f"connections/1.0/request"

# Protocol package path
PROTOCOL_PACKAGE = "mydata_did.v1_0"

# Message type mappings to their corresponding class
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
        MYDATA_DID_PROBLEM_REPORT: (
            f"{PROTOCOL_PACKAGE}.messages.problem_report.ProblemReport"
        ),
        # CONNECTION_REQUEST: (
        #     f"{PROTOCOL_PACKAGE}.messages.connection_request.ConnectionRequest"
        # ),
        READ_DATA_AGREEMENT: (
            f"{PROTOCOL_PACKAGE}.messages.read_data_agreement.ReadDataAgreement"
        ),
        READ_DATA_AGREEMENT_RESPONSE: (
            f"{PROTOCOL_PACKAGE}.messages.read_data_agreement_response.ReadDataAgreementResponse"
        ),
        DATA_AGREEMENT_PROBLEM_REPORT: (
            f"{PROTOCOL_PACKAGE}.messages.problem_report.DataAgreementProblemReport"
        ),
    },
)
