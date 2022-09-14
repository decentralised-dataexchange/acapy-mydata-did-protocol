from aries_cloudagent.messaging.decorators.base import BaseDecoratorSet
from aries_cloudagent.messaging.decorators.localization_decorator import (
    LocalizationDecorator,
)
from aries_cloudagent.messaging.decorators.signature_decorator import SignatureDecorator
from aries_cloudagent.messaging.decorators.thread_decorator import ThreadDecorator
from aries_cloudagent.messaging.decorators.timing_decorator import TimingDecorator
from aries_cloudagent.messaging.decorators.trace_decorator import TraceDecorator
from aries_cloudagent.messaging.decorators.transport_decorator import TransportDecorator
from mydata_did.v1_0.decorators.data_agreement_context_decorator import (
    DataAgreementContextDecorator,
)

PATCHED_DECORATOR_MODELS = {
    "l10n": LocalizationDecorator,
    "sig": SignatureDecorator,
    "thread": ThreadDecorator,
    "trace": TraceDecorator,
    "timing": TimingDecorator,
    "transport": TransportDecorator,
    "data-agreement-context": DataAgreementContextDecorator,
}


class PatchedDecoratorSet(BaseDecoratorSet):
    """Patched decorator set implementation."""

    def __init__(self, models: dict = None):
        """Initialize the decorator set."""
        super().__init__(PATCHED_DECORATOR_MODELS if models is None else models)
