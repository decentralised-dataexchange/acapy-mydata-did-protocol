from os import environ
from typing import Any

from marshmallow import fields, validate

from aries_cloudagent.messaging.models.base_record import BaseExchangeRecord, BaseExchangeSchema
from aries_cloudagent.messaging.valid import UUIDFour

from ..utils.regex import MYDATA_DID


class MyDataDIDRecord(BaseExchangeRecord):
    class Meta:
        schema_class = "MyDataDIDRecordSchema"

    RECORD_TYPE = "mydata_did_record_v10"
    RECORD_ID_NAME = "mydata_did_record_id"
    WEBHOOK_TOPIC = None
    TAG_NAMES = {"~did"}

    STATE_DID_VERIFIED = "verified"
    STATE_DID_REVOKED = "revoked"

    def __init__(
        self,
        *,
        mydata_did_record_id: str = None,
        did: str = None,
        state: str = None,
        **kwargs
    ):
        super().__init__(mydata_did_record_id, state, **kwargs)
        self.did = did

    @property
    def mydata_did_record_id(self) -> str:
        return self._id

    @property
    def record_value(self) -> dict:
        """Accessor for JSON record value generated for this transaction record."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "did",
                "state",
            )
        }

    def __eq__(self, other: Any) -> bool:
        """Comparison between records."""
        return super().__eq__(other)


class MyDataDIDRecordSchema(BaseExchangeSchema):

    class Meta:

        model_class = MyDataDIDRecord

    mydata_did_record_id = fields.Str(
        required=False,
        description="MyData DID record",
        example=UUIDFour.EXAMPLE,
    )
    state = fields.Str(
        required=False,
        description="MyData DID record state",
        example=MyDataDIDRecord.STATE_DID_VERIFIED,
    )

    did = fields.Str(required=False, description="MyData decentralised identifier", **MYDATA_DID)
