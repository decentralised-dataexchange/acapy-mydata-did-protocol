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

# Message type for reading all data agreement templates available in an organisation.
READ_ALL_DATA_AGREEMENT_TEMPLATE = f"data-agreements/1.0/read-all-template"
READ_ALL_DATA_AGREEMENT_TEMPLATE_RESPONSE = f"data-agreements/1.0/read-all-template-response"

# Message types for ADA RFC 0003 - Data Agreement Negotiation Protocol 1.0
DATA_AGREEMENT_NEGOTIATION_OFFER = f"data-agreement-negotiation/1.0/offer"
DATA_AGREEMENT_NEGOTIATION_REJECT = f"data-agreement-negotiation/1.0/reject"
DATA_AGREEMENT_NEGOTIATION_ACCEPT = f"data-agreement-negotiation/1.0/accept"
DATA_AGREEMENT_NEGOTIATION_PROBLEM_REPORT = f"data-agreement-negotiation/1.0/problem-report"

# Message types for ADA RFC 0005 - Data Agreement Termination Protocol 1.0
DATA_AGREEMENT_TERMINATION_TERMINATE = f"data-agreement-termination/1.0/terminate"
DATA_AGREEMENT_TERMINATION_TERMINATE_ACK = f"data-agreement-termination/1.0/terminate-ack"
DATA_AGREEMENT_TERMINATION_PROBLEM_REPORT = f"data-agreement-termination/1.0/problem-report"

# Message types for ADA RFC 0004 - Data Agreement Proofs Protocol 1.0
DATA_AGREEMENT_PROOFS_VERIFY = f"data-agreement-proofs/1.0/verify-request"
DATA_AGREEMENT_PROOFS_VERIFY_RESPONSE = f"data-agreement-proofs/1.0/verify-response"

# Message types for iGrant.io specific messages.

# Data agreement QR code workflow initiate message.
DATA_AGREEMENT_QR_CODE_WORKFLOW_INITIATE = f"data-agreement-qr-code/1.0/initiate"
DATA_AGREEMENT_QR_CODE_WORKFLOW_PROBLEM_REPORT = f"data-agreement-qr-code/1.0/problem-report"

# JSON-LD functions protocol.
JSON_LD_PROCESSED_DATA = f"json-ld/1.0/processed-data"
JSON_LD_PROCESSED_RESPONSE_DATA = f"json-ld/1.0/processed-data-response"
JSON_LD_PROBLEM_REPORT = f"json-ld/1.0/problem-report"

# Data controller protocol
DATA_CONTROLLER_DETAILS = f"data-controller/1.0/details"
DATA_CONTROLLER_DETAILS_RESPONSE = f"data-controller/1.0/details-response"

# Existing connections protocol.
EXISTING_CONNECTIONS = f"connections/1.0/exists"

# Protocol package path
PROTOCOL_PACKAGE = "mydata_did.v1_0"

# Message type mappings to their corresponding class
MESSAGE_TYPES = DIDCommPrefix.qualify_all(
    {
        CREATE_DID: (
            f"{PROTOCOL_PACKAGE}.messages.create_did.CreateDIDMessage"
        ),
        CREATE_DID_RESPONSE: (
            f"{PROTOCOL_PACKAGE}.messages.create_did_response.CreateDIDResponseMessage"
        ),
        READ_DID: (
            f"{PROTOCOL_PACKAGE}.messages.read_did.ReadDIDMessage"
        ),
        READ_DID_RESPONSE: (
            f"{PROTOCOL_PACKAGE}.messages.read_did_response.ReadDIDResponseMessage"
        ),
        DELETE_DID: (
            f"{PROTOCOL_PACKAGE}.messages.delete_did.DeleteDIDMessage"
        ),
        DELETE_DID_RESPONSE: (
            f"{PROTOCOL_PACKAGE}.messages.delete_did_response.DeleteDIDResponseMessage"
        ),
        MYDATA_DID_PROBLEM_REPORT: (
            f"{PROTOCOL_PACKAGE}.messages.problem_report.MyDataDIDProblemReportMessage"
        ),
        READ_DATA_AGREEMENT: (
            f"{PROTOCOL_PACKAGE}.messages.read_data_agreement.ReadDataAgreement"
        ),
        READ_DATA_AGREEMENT_RESPONSE: (
            f"{PROTOCOL_PACKAGE}.messages.read_data_agreement_response.ReadDataAgreementResponse"
        ),
        DATA_AGREEMENT_PROBLEM_REPORT: (
            f"{PROTOCOL_PACKAGE}.messages.problem_report.DataAgreementProblemReport"
        ),
        DATA_AGREEMENT_NEGOTIATION_REJECT: (
            f"{PROTOCOL_PACKAGE}.messages.data_agreement_reject.DataAgreementNegotiationRejectMessage"
        ),
        DATA_AGREEMENT_NEGOTIATION_PROBLEM_REPORT: (
            f"{PROTOCOL_PACKAGE}.messages.problem_report.DataAgreementNegotiationProblemReport"
        ),
        DATA_AGREEMENT_TERMINATION_TERMINATE: (
            f"{PROTOCOL_PACKAGE}.messages.data_agreement_terminate.DataAgreementTerminationTerminateMessage"
        ),
        DATA_AGREEMENT_TERMINATION_TERMINATE_ACK: (
            f"{PROTOCOL_PACKAGE}.messages.data_agreement_terminate_ack.DataAgreementTerminationAck"
        ),
        DATA_AGREEMENT_TERMINATION_PROBLEM_REPORT: (
            f"{PROTOCOL_PACKAGE}.messages.problem_report.DataAgreementTerminationProblemReport"
        ),
        DATA_AGREEMENT_PROOFS_VERIFY: (
            f"{PROTOCOL_PACKAGE}.messages.data_agreement_verify.DataAgreementVerify"
        ),
        DATA_AGREEMENT_PROOFS_VERIFY_RESPONSE: (
            f"{PROTOCOL_PACKAGE}.messages.data_agreement_verify_response.DataAgreementVerifyResponse"
        ),
        DATA_AGREEMENT_QR_CODE_WORKFLOW_INITIATE: (
            f"{PROTOCOL_PACKAGE}.messages.data_agreement_qr_code_initiate.DataAgreementQrCodeInitiateMessage"
        ),
        DATA_AGREEMENT_QR_CODE_WORKFLOW_PROBLEM_REPORT: (
            f"{PROTOCOL_PACKAGE}.messages.data_agreement_qr_code_problem_report.DataAgreementQrCodeProblemReport"
        ),
        JSON_LD_PROCESSED_DATA: (
            f"{PROTOCOL_PACKAGE}.messages.json_ld_processed.JSONLDProcessedMessage"
        ),
        JSON_LD_PROCESSED_RESPONSE_DATA: (
            f"{PROTOCOL_PACKAGE}.messages.json_ld_processed_response.JSONLDProcessedResponseMessage"
        ),
        JSON_LD_PROBLEM_REPORT: (
            f"{PROTOCOL_PACKAGE}.messages.json_ld_problem_report.JSONLDProblemReport"
        ),
        READ_ALL_DATA_AGREEMENT_TEMPLATE: (
            f"{PROTOCOL_PACKAGE}.messages.read_all_data_agreement_template.ReadAllDataAgreementTemplateMessage"
        ),
        READ_ALL_DATA_AGREEMENT_TEMPLATE_RESPONSE: (
            f"{PROTOCOL_PACKAGE}.messages.read_all_data_agreement_template_response.ReadAllDataAgreementTemplateResponseMessage"
        ),
        DATA_CONTROLLER_DETAILS: (
            f"{PROTOCOL_PACKAGE}.messages.data_controller_details.DataControllerDetailsMessage"
        ),
        DATA_CONTROLLER_DETAILS_RESPONSE: (
            f"{PROTOCOL_PACKAGE}.messages.data_controller_details_response.DataControllerDetailsResponseMessage"
        ),
        EXISTING_CONNECTIONS: (
            f"{PROTOCOL_PACKAGE}.messages.existing_connections.ExistingConnectionsMessage"
        ),
    },
)
