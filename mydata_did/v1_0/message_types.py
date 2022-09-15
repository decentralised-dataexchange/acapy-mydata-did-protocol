# flake8: noqa
from aries_cloudagent.protocols.didcomm_prefix import DIDCommPrefix

# DIDComm protocol specification for Automated Data Agreements
SPEC_URI = "https://github.com/decentralised-dataexchange/automated-data-agreements"

# Message types

# Message types for MyDATA DID CRUD operations (ADA RFC 0001 - MyData DID Protocol 1.0)
READ_DID = f"mydata-did/1.0/read-did"
READ_DID_RESPONSE = f"mydata_did/1.0/read-did-response"
MYDATA_DID_PROBLEM_REPORT = f"mydata-did/1.0/problem-report"

# Message types for Data Agreement CRUD operations (ADA RFC 0002 - Data Agreement Protocol 1.0)
READ_DATA_AGREEMENT = f"data-agreements/1.0/read-data-agreement"
READ_DATA_AGREEMENT_RESPONSE = f"data-agreements/1.0/read-data-agreement-response"
DATA_AGREEMENT_PROBLEM_REPORT = f"data-agreements/1.0/problem-report"

# Message types for ADA RFC 0003 - Data Agreement Negotiation Protocol 1.0
DATA_AGREEMENT_NEGOTIATION_OFFER = f"data-agreement-negotiation/1.0/offer"
DATA_AGREEMENT_NEGOTIATION_REJECT = f"data-agreement-negotiation/1.0/reject"
DATA_AGREEMENT_NEGOTIATION_ACCEPT = f"data-agreement-negotiation/1.0/accept"
DATA_AGREEMENT_NEGOTIATION_RECEIPT = f"data-agreement-negotiation/1.0/receipt"
DATA_AGREEMENT_NEGOTIATION_PROBLEM_REPORT = (
    f"data-agreement-negotiation/1.0/problem-report"
)

THIRDPARTY_DATA_SHARING_FETCH_PREFERENCES = (
    f"third-party-data-sharing/1.0/fetch-preferences"
)
THIRDPARTY_DATA_SHARING_FETCH_PREFERENCES_RESPONSE = (
    f"third-party-data-sharing/1.0/fetch-preferences-response"
)
THIRDPARTY_DATA_SHARING_UPDATE_PREFERENCES = (
    f"third-party-data-sharing/1.0/update-preferences"
)

DA_PERMISSIONS = f"data-agreement/1.0/permissions"

# Message types for ADA RFC 0005 - Data Agreement Termination Protocol 1.0
DATA_AGREEMENT_TERMINATION_TERMINATE = f"data-agreement-termination/1.0/terminate"
DATA_AGREEMENT_TERMINATION_TERMINATE_ACK = (
    f"data-agreement-termination/1.0/terminate-ack"
)
DATA_AGREEMENT_TERMINATION_PROBLEM_REPORT = (
    f"data-agreement-termination/1.0/problem-report"
)

# Message types for iGrant.io specific messages.

# Data agreement QR code workflow initiate message.
DATA_AGREEMENT_QR_CODE_WORKFLOW_INITIATE = f"data-agreement-qr-code/1.0/initiate"
DATA_AGREEMENT_QR_CODE_WORKFLOW_PROBLEM_REPORT = (
    f"data-agreement-qr-code/1.0/problem-report"
)

# JSON-LD functions protocol.
JSON_LD_PROCESSED_DATA = f"json-ld/1.0/processed-data"
JSON_LD_PROCESSED_RESPONSE_DATA = f"json-ld/1.0/processed-data-response"

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
        READ_DID: (f"{PROTOCOL_PACKAGE}.messages.read_did.ReadDIDMessage"),
        READ_DID_RESPONSE: (
            f"{PROTOCOL_PACKAGE}.messages.read_did_response.ReadDIDResponseMessage"
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
        DATA_AGREEMENT_NEGOTIATION_RECEIPT: (
            f"{PROTOCOL_PACKAGE}.messages.da_negotiation_receipt.DataAgreementNegotiationReceiptMessage"
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
        DATA_CONTROLLER_DETAILS: (
            f"{PROTOCOL_PACKAGE}.messages.data_controller_details.DataControllerDetailsMessage"
        ),
        DATA_CONTROLLER_DETAILS_RESPONSE: (
            f"{PROTOCOL_PACKAGE}.messages.data_controller_details_response.DataControllerDetailsResponseMessage"
        ),
        EXISTING_CONNECTIONS: (
            f"{PROTOCOL_PACKAGE}.messages.existing_connections.ExistingConnectionsMessage"
        ),
        DA_PERMISSIONS: (
            f"{PROTOCOL_PACKAGE}.messages.da_permissions.DAPermissionsMessage"
        ),
        THIRDPARTY_DATA_SHARING_FETCH_PREFERENCES: (
            f"{PROTOCOL_PACKAGE}.messages.fetch_preferences.FetchPreferencesMessage"
        ),
        THIRDPARTY_DATA_SHARING_FETCH_PREFERENCES_RESPONSE: (
            f"{PROTOCOL_PACKAGE}.messages.fetch_preferences_response.FetchPreferencesResponseMessage"
        ),
    },
)
