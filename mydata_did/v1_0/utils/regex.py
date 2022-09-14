import re

from marshmallow.validate import Regexp

MYDATA_DID_REGEX = (
    "did:mydata(:?(?P<did_type>0|1|2|3|4))?:(?P<identifier>z[a-km-zA-HJ-NP-Z1-9]+)"
)
MYDATA_DID_PATTERN = re.compile(f"^{MYDATA_DID_REGEX}$")


class MyDataDID(Regexp):
    """Validate value against MyData DID."""

    EXAMPLE = "z6MkfiSdYhnLnS6jfwSf2yS2CiwwjZGmFUFL5QbyL2Xu8z2E"
    PATTERN = rf"^did:mydata(:?(?P<did_type>0|1|2|3|4))?:(?P<identifier>z[a-km-zA-HJ-NP-Z1-9]+)"

    def __init__(self):
        """Initializer."""

        super().__init__(
            MyDataDID.PATTERN,
            error="Value {input} is not an mydata decentralized identifier (DID)",
        )


MYDATA_DID = {"validate": MyDataDID(), "example": MyDataDID.EXAMPLE}


if __name__ == "__main__":
    print(
        MYDATA_DID_PATTERN.match(
            "did:mydata:0:z6MkfiSdYhnLnS6jfwSf2yS2CiwwjZGmFUFL5QbyL2Xu8z2E"
        ).group("did_type")
    )
    print(
        MYDATA_DID_PATTERN.match(
            "did:mydata:z6MkfiSdYhnLnS6jfwSf2yS2CiwwjZGmFUFL5QbyL2Xu8z2E"
        ).group("did_type")
    )
