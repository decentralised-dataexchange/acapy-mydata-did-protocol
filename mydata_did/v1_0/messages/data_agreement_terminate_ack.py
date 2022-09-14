from aries_cloudagent.messaging.ack.message import Ack, AckSchema
from marshmallow import EXCLUDE
from mydata_did.v1_0.message_types import (
    DATA_AGREEMENT_TERMINATION_TERMINATE_ACK,
    PROTOCOL_PACKAGE,
)

HANDLER_CLASS = f"{PROTOCOL_PACKAGE}.handlers.data_agreement_termination_ack_handler.DataAgreementTerminationAckHandler"


class DataAgreementTerminationAck(Ack):
    """Base class representing an explicit ack message for data agreement termination protocol."""

    class Meta:
        """DataAgreementTerminationAck metadata."""

        handler_class = HANDLER_CLASS
        message_type = DATA_AGREEMENT_TERMINATION_TERMINATE_ACK
        schema_class = "DataAgreementTerminationAckSchema"

    def __init__(self, status: str = None, **kwargs):
        """
        Initialize an explicit ack message instance.

        Args:
            status: Status (default OK)

        """
        super().__init__(status, **kwargs)


class DataAgreementTerminationAckSchema(AckSchema):
    """Schema for DataAgreementTerminationAck class."""

    class Meta:
        """DataAgreementTerminationAck schema metadata."""

        model_class = DataAgreementTerminationAck
        unknown = EXCLUDE
