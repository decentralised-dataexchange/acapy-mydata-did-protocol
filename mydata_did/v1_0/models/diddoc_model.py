import typing

from aries_cloudagent.messaging.models.base import BaseModel, BaseModelSchema
from marshmallow import EXCLUDE, fields
from marshmallow.exceptions import ValidationError
from mydata_did.v1_0.utils.diddoc import DIDDoc
from mydata_did.v1_0.utils.regex import MyDataDID
from mydata_did.v1_0.utils.verification_method import PublicKeyType


class DIDDocWrapper(fields.Field):
    """Field that loads and serializes DIDDoc."""

    def _serialize(self, value, attr, obj, **kwargs):
        """
        Serialize the DIDDoc.

        Args:
            value: The value to serialize

        Returns:
            The serialized DIDDoc

        """
        return value.serialize()

    def _deserialize(self, value, attr, data, **kwargs):
        """
        Deserialize a value into a DIDDoc.

        Args:
            value: The value to deserialize

        Returns:
            The deserialized value

        """
        return DIDDoc.deserialize(value)

    def _validate(self, value: DIDDoc):
        if not value.validate():
            raise ValidationError("MyData DIDDoc is not valid.")


class MyDataDIDBody(BaseModel):
    class Meta:
        schema_class = "MyDataDIDBodySchema"

    def __init__(self, *, did_doc: DIDDoc, **kwargs):
        super().__init__(**kwargs)
        self.did_doc = did_doc


class MyDataDIDBodySchema(BaseModelSchema):
    class Meta:
        model_class = MyDataDIDBody
        unknown = EXCLUDE

    did_doc = DIDDocWrapper(data_key="did", required=False)


class MyDataDIDDocService(BaseModel):
    """
    Service information for a DID Document.
    """

    class Meta:
        # Schema class
        schema_class = "MyDataDIDDocServiceSchema"

    def __init__(
        self,
        *,
        service_id: str = None,
        service_type: str = None,
        service_priority: int = 0,
        recipient_keys: typing.List[str] = None,
        service_endpoint: str = None,
        **kwargs,
    ):
        """
        Initialize a DID Document Service object.

        Args:
            service_id: The service ID
            service_type: The service type
            service_priority: The service priority
            recipient_keys: The recipient keys
            service_endpoint: The service endpoint
        """

        super().__init__(**kwargs)

        # Service ID
        self.service_id = service_id

        # Service type
        self.service_type = service_type

        # Service priority
        self.service_priority = service_priority

        # Recipient keys
        self.recipient_keys = recipient_keys

        # Service endpoint
        self.service_endpoint = service_endpoint


class MyDataDIDDocServiceSchema(BaseModelSchema):
    """
    Schema for DID Document Service.
    """

    class Meta:

        # Model class
        model_class = MyDataDIDDocService

        # Unknown fields are excluded.
        unknown = EXCLUDE

    # Service ID
    service_id = fields.Str(
        data_key="id", required=True, example=f"did:mydata:{MyDataDID.EXAMPLE};didcomm"
    )

    # Service type
    service_type = fields.Str(data_key="type", required=True, example="DIDComm")

    # Service priority
    service_priority = fields.Int(data_key="priority", required=True, example=1)

    # Recipient keys
    recipient_keys = fields.List(
        fields.Str(required=True, example=MyDataDID.EXAMPLE),
        data_key="recipientKeys",
        required=True,
    )

    # Service endpoint
    service_endpoint = fields.Str(
        data_key="serviceEndpoint", required=True, example="https://didcomm.org"
    )


class MyDataDIDDocAuthentication(BaseModel):
    """
    Authentication information for a DID Document.
    """

    class Meta:
        # Schema class
        schema_class = "MyDataDIDDocAuthenticationSchema"

    def __init__(
        self, *, authentication_type: str = None, public_key: str = None, **kwargs
    ):
        """
        Initialize a DID Document Authentication object.

        Args:
            authentication_type: The authentication type
            public_key: The public key
        """
        super().__init__(**kwargs)

        # Set attributes
        self.authentication_type = authentication_type
        self.public_key = public_key


class MyDataDIDDocAuthenticationSchema(BaseModelSchema):
    """
    Schema for DID Document Authentication.

    """

    class Meta:

        # Model class
        model_class = MyDataDIDDocAuthentication

        # Unknown fields are excluded.
        unknown = EXCLUDE

    # The authentication type
    authentication_type = fields.Str(
        data_key="type",
        required=True,
        example=PublicKeyType.ED25519_SIG_2018.authn_type,
    )

    # The public key
    public_key = fields.Str(
        data_key="publicKey",
        required=True,
        example=f"did:mydata:f{MyDataDID.EXAMPLE}#1",
    )


class MyDataDIDDocVerificationMethod(BaseModel):
    """
    A DID Document Verification Method.
    """

    class Meta:
        # Schema class
        schema_class = "MyDataDIDDocVerificationMethodSchema"

    def __init__(
        self,
        *,
        verification_method_id: str = None,
        verification_method_type: str = None,
        controller: str = None,
        public_key_base58: str = None,
        **kwargs,
    ):
        """
        Initialize a DID Document Verification Method.

        Args:
            verification_method_id: The verification method id
            verification_method_type: The verification method type
            controller: The controller
            public_key_base58: The public key base58
        """

        # Initialize the super class
        super().__init__(**kwargs)

        # Set attributes
        self.verification_method_id = verification_method_id
        self.verification_method_type = verification_method_type
        self.controller = controller
        self.public_key_base58 = public_key_base58


class MyDataDIDDocVerificationMethodSchema(BaseModelSchema):
    """
    A DID Document Verification Method Schema.
    """

    class Meta:
        # Schema class
        model_class = MyDataDIDDocVerificationMethod

    # Verification method id
    verification_method_id = fields.Str(
        data_key="id", required=True, example=f"did:mydata:{MyDataDID.EXAMPLE}#1"
    )

    # Verification method type
    verification_method_type = fields.Str(
        data_key="type", required=True, example=PublicKeyType.ED25519_SIG_2018.ver_type
    )

    # Controller
    controller = fields.Str(
        data_key="controller", required=True, example=f"did:mydata:{MyDataDID.EXAMPLE}"
    )

    # Public key base58
    public_key_base58 = fields.Str(
        data_key="publicKeyBase58", required=True, example=f"{MyDataDID.EXAMPLE}"
    )


class MyDataDIDDoc(BaseModel):
    """
    MyData DIDDoc model
    """

    class Meta:
        # Schema class
        schema_class = "MyDataDIDDocSchema"

    def __init__(
        self,
        *,
        context: str = None,
        diddoc_id: str = None,
        verification_method: typing.List[MyDataDIDDocVerificationMethod] = None,
        authentication: typing.List[MyDataDIDDocAuthentication] = None,
        service: typing.List[MyDataDIDDocService] = None,
        **kwargs,
    ):
        """
        Initialize a MyData DIDDoc model.

        Args:
            context: The DIDDoc context
            diddoc_id: The DIDDoc id
            verification_method: The verification method
            authentication: The authentication method
            service: The service
            kwargs: The extra arguments

        """

        # Call parent constructor
        super().__init__(**kwargs)

        # Set attributes
        self.context = context
        self.diddoc_id = diddoc_id
        self.verification_method = verification_method
        self.authentication = authentication
        self.service = service


class MyDataDIDDocSchema(BaseModelSchema):
    """
    MyData DIDDoc schema
    """

    class Meta:
        # Model class
        model_class = MyDataDIDDoc

        # Unknown fields are excluded
        unknown = EXCLUDE

    # The DIDDoc context
    context = fields.Str(
        required=True,
        data_key="@context",
        example=DIDDoc.CONTEXT,
        description="The DIDDoc context",
    )

    # The DIDDoc id
    diddoc_id = fields.Str(
        required=True,
        data_key="id",
        example=f"did:mydata:{MyDataDID.EXAMPLE}",
    )

    # The verification method
    verification_method = fields.List(
        fields.Nested(MyDataDIDDocVerificationMethodSchema), required=True
    )

    # The authentication method
    authentication = fields.List(
        fields.Nested(MyDataDIDDocAuthenticationSchema), required=True
    )

    # The service
    service = fields.List(fields.Nested(MyDataDIDDocServiceSchema), required=True)


class MyDataDIDResponseBody(BaseModel):
    """
    MyData DID response body model
    """

    class Meta:

        # Schema class
        schema_class = "MyDataDIDResponseBodySchema"

    def __init__(
        self,
        *,
        did_doc: MyDataDIDDoc = None,
        version: str = None,
        status: str = None,
        **kwargs,
    ):
        """
        Initialize a MyData DID response body model.

        Args:
            did_doc: The DIDDoc
            version: The version
        """
        super().__init__(**kwargs)

        # Set attributes
        self.did_doc = did_doc
        self.version = version
        self.status = status


class MyDataDIDResponseBodySchema(BaseModelSchema):
    """
    MyData DID response body schema
    """

    class Meta:

        # Model class
        model_class = MyDataDIDResponseBody

        # Unknown fields are excluded
        unknown = EXCLUDE

    # The DIDDoc
    did_doc = fields.Nested(MyDataDIDDocSchema, required=True)

    # The version
    version = fields.Str(data_key="version")

    # The status
    status = fields.Str(data_key="status")
