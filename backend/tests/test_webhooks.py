from unittest.mock import patch

from app.api.v1.webhooks import _build_signature, deliver_webhook
from app.models.webhook import WebhookConfig


class DummyQuery:
    def __init__(self, webhooks):
        self.webhooks = webhooks

    def filter(self, *args):
        return self

    def all(self):
        return self.webhooks


class DummyDB:
    def __init__(self, webhooks):
        self.webhooks = webhooks

    def query(self, model):
        return DummyQuery(self.webhooks)


def test_build_signature_generates_hmac_sha256():
    signature = _build_signature("secret", b'{"decision":"block"}')

    assert isinstance(signature, str)
    assert len(signature) == 64


@patch("app.api.v1.webhooks._post_webhook")
def test_deliver_webhook_calls_matching_active_webhook(mock_post):
    webhook = WebhookConfig(
        user_id=1,
        url="https://example.com/webhook",
        secret="secret",
        is_active=True,
        events=["guard_block"],
    )

    deliver_webhook(
        db=DummyDB([webhook]),
        user_id=1,
        event="guard_block",
        payload={"decision": "block"},
    )

    mock_post.assert_called_once_with(
        url="https://example.com/webhook",
        event="guard_block",
        payload={"decision": "block"},
        secret="secret",
    )


@patch("app.api.v1.webhooks._post_webhook")
def test_deliver_webhook_ignores_unsubscribed_event(mock_post):
    webhook = WebhookConfig(
        user_id=1,
        url="https://example.com/webhook",
        secret="secret",
        is_active=True,
        events=["compliance_drift"],
    )

    deliver_webhook(
        db=DummyDB([webhook]),
        user_id=1,
        event="guard_block",
        payload={"decision": "block"},
    )

    mock_post.assert_not_called()
