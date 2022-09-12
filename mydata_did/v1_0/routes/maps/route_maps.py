from aiohttp import web
from ..data_agreement_auditor_functions_routes import (
    query_data_agreement_instances
)
from ..data_agreement_core_functions_routes import (
    create_and_store_data_agreement_in_wallet_v2,
    publish_data_agreement_handler,
    query_data_agreements_in_wallet,
    update_data_agreement_in_wallet_v2,
    delete_data_agreement_in_wallet,
    query_da_personal_data_in_wallet,
    update_da_personal_data_in_wallet,
    delete_da_personal_data_in_wallet,
    generate_data_agreement_qr_code_payload,
    query_data_agreement_qr_code_metadata_records_handler,
    remove_data_agreement_qr_code_metadata_record_handler,
    send_data_agreements_qr_code_workflow_initiate_handler,
    fetch_customer_identification_da_handler,
    configure_customer_identification_da_handler
)

from ..data_controller_functions_routes import (
    send_data_controller_details_message_handler,
    update_data_controller_details
)

from ..jsonld_routes import (
    send_json_ld_didcomm_processed_data_message_handler,
)

from ..mydata_did_operations_routes import (
    send_read_did_message_to_mydata_did_registry,
    mydata_did_remote_records_list,
)


from ..connection_routes import (
    wellknown_connection_handler,
    v2_connections_create_invitation,
    send_existing_connections_message_handler,
    get_existing_connections_handler,
    connections_list_v2,
    generate_firebase_dynamic_link_for_connection_invitation_handler
)

# Routes defined in ADA
ROUTES_ADA = [
    web.post(
        "/v1/mydata-did/didcomm/read-did/{did}",
        send_read_did_message_to_mydata_did_registry,
    ),
    web.get(
        "/v1/mydata-did/remote",
        mydata_did_remote_records_list,
        allow_head=False,
    ),
    web.post(
        "/v1/data-agreements",
        create_and_store_data_agreement_in_wallet_v2,
    ),
    web.post(
        "/v1/data-agreements/{template_id}/publish",
        publish_data_agreement_handler,
    ),
    web.get(
        "/v1/data-agreements", query_data_agreements_in_wallet, allow_head=False
    ),
    web.put(
        "/v1/data-agreements/{template_id}",
        update_data_agreement_in_wallet_v2,
    ),
    web.delete(
        "/v1/data-agreements/{template_id}",
        delete_data_agreement_in_wallet,
    ),
    web.get(
        "/v1/data-agreements/personal-data",
        query_da_personal_data_in_wallet,
        allow_head=False,
    ),
    web.put(
        "/v1/data-agreements/personal-data/{attribute_id}",
        update_da_personal_data_in_wallet,
    ),
    web.delete(
        "/v1/data-agreements/personal-data/{attribute_id}",
        delete_da_personal_data_in_wallet,
    ),
    web.get(
        "/v1/auditor/data-agreements/instances",
        query_data_agreement_instances,
        allow_head=False,
    ),
    web.post(
        "/v1/data-agreements/{template_id}/customer-identification",
        configure_customer_identification_da_handler
    ),
    web.get(
        "/v1/data-agreements/customer-identification",
        fetch_customer_identification_da_handler,
        allow_head=False,
    ),
    web.get(
        "/v1/.well-known/did-configuration.json",
        wellknown_connection_handler,
        allow_head=False,
    ),
    web.post(
        "/v1/data-agreements/{template_id}/qr",
        generate_data_agreement_qr_code_payload,
    ),
    web.get(
        "/v1/data-agreements/{template_id}/qr",
        query_data_agreement_qr_code_metadata_records_handler,
        allow_head=False,
    ),
    web.delete(
        "/v1/data-agreements/{template_id}/qr/{qr_id}",
        remove_data_agreement_qr_code_metadata_record_handler,
    ),
    web.post(
        "/v1/data-agreements/qr/{qr_id}/workflow-initiate/connections/{connection_id}",
        send_data_agreements_qr_code_workflow_initiate_handler,
    ),
    web.post(
        "/v1/json-ld/didcomm/processed-data/connections/{connection_id}",
        send_json_ld_didcomm_processed_data_message_handler,
    ),
    web.post(
        "/v2/connections/create-invitation", v2_connections_create_invitation
    ),
    web.post(
        "/v1/connections/{conn_id}/invitation/firebase",
        generate_firebase_dynamic_link_for_connection_invitation_handler,
    ),
    web.post(
        "/v1/data-controller/didcomm/details/connections/{connection_id}",
        send_data_controller_details_message_handler,
    ),
    web.post(
        "/v1/connections/{conn_id}/existing",
        send_existing_connections_message_handler,
    ),
    web.get(
        "/v1/connections/{conn_id}/existing",
        get_existing_connections_handler,
        allow_head=False,
    ),
    web.get(
        "/v2/connections",
        connections_list_v2,
        allow_head=False
    ),
    web.post(
        "/v1/data-controller",
        update_data_controller_details
    )
]
