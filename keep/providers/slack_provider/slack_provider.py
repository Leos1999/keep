"""
Slack provider is an interface for Slack messages.
"""

import dataclasses
import json
import os
from typing import OrderedDict

import pydantic
import requests

from keep.api.models.alert import AlertDto, AlertSeverity, AlertStatus
from keep.contextmanager.contextmanager import ContextManager
from keep.exceptions.provider_exception import ProviderException
from keep.functions import utcnowtimestamp
from keep.providers.base.base_provider import BaseProvider
from keep.providers.models.provider_config import ProviderConfig, ProviderScope
from keep.providers.models.provider_method import ProviderMethod


@pydantic.dataclasses.dataclass
class SlackProviderAuthConfig:
    """Slack authentication configuration."""

    webhook_url: str = dataclasses.field(
        metadata={
            "required": True,
            "description": "Slack Webhook Url",
            "sensitive": True,
        },
        default="",
    )
    access_token: str = dataclasses.field(
        metadata={
            "description": "For access token installation flow, use Keep UI",
            "required": False,
            "sensitive": True,
            "hidden": True,
        },
        default="",
    )


class SlackProvider(BaseProvider):
    """Send alert message to Slack."""

    PROVIDER_DISPLAY_NAME = "Slack"
    OAUTH2_URL = os.environ.get("SLACK_OAUTH2_URL")
    SLACK_CLIENT_ID = os.environ.get("SLACK_CLIENT_ID")
    SLACK_CLIENT_SECRET = os.environ.get("SLACK_CLIENT_SECRET")
    SLACK_API = "https://slack.com/api"
    PROVIDER_CATEGORY = ["Collaboration"]

    # Update PROVIDER_SCOPES to include required permissions
    PROVIDER_SCOPES = [
        ProviderScope(
            name="channels:read",
            description="Required to list available channels",
            mandatory=True,
            documentation_url="https://api.slack.com/scopes/channels:read", 
        ),
        ProviderScope(
            name="channels:history",
            description="Required to read messages from channels",
            mandatory=True,
            documentation_url="https://api.slack.com/scopes/channels:history",
        )
    ]

    # Add provider method configuration
    PROVIDER_METHODS = [
        ProviderMethod(
            name="get_messages",
            description="Get messages from a Slack channel",
            type="view",
            func_name="get_messages",
            scopes=["channels:history", "channels:read"],
            params={
                "channel": "str",
                "oldest": "int",
                "limit": "int"
            }
        )
    ]

    def __init__(
        self, context_manager: ContextManager, provider_id: str, config: ProviderConfig
    ):
        super().__init__(context_manager, provider_id, config)
        # Track latest message timestamp per channel
        self.last_message_ts = {}

    def validate_config(self):
        self.authentication_config = SlackProviderAuthConfig(
            **self.config.authentication
        )
        if (
            not self.authentication_config.webhook_url
            and not self.authentication_config.access_token
        ):
            raise Exception("Slack webhook url OR Slack access token is required")

    def dispose(self):
        """
        No need to dispose of anything, so just do nothing.
        """
        pass

    @staticmethod
    def oauth2_logic(**payload) -> dict:
        """
        Logic for handling oauth2 callback.

        Args:
            payload (dict): The payload from the oauth2 callback.

        Returns:
            dict: The provider configuration.
        """
        code = payload.get("code")
        if not code:
            raise Exception("No code provided")
        exchange_request_payload = {
            **payload,
            "client_id": SlackProvider.SLACK_CLIENT_ID,
            "client_secret": SlackProvider.SLACK_CLIENT_SECRET,
        }
        response = requests.post(
            f"{SlackProvider.SLACK_API}/oauth.v2.access",
            data=exchange_request_payload,
        )
        response_json = response.json()
        if not response.ok or not response_json.get("ok"):
            raise Exception(
                response_json.get("error"),
            )
        new_provider_info = {"access_token": response_json.get("access_token")}

        team_name = response_json.get("team", {}).get("name")
        if team_name:
            # replacing dots to prevent problems in workflows
            new_provider_info["provider_name"] = team_name.replace(".", "")

        return new_provider_info

    def _notify_reaction(self, channel: str, emoji: str, timestamp: str):
        if not self.authentication_config.access_token:
            raise ProviderException("Access token is required to notify reaction")

        self.logger.info(
            "Notifying reaction to Slack using",
            extra={
                "emoji": emoji,
                "channel": channel,
                "timestamp": timestamp,
            },
        )
        payload = {
            "channel": channel,
            "token": self.authentication_config.access_token,
            "name": emoji,
            "timestamp": timestamp,
        }
        response = requests.post(
            f"{SlackProvider.SLACK_API}/reactions.add",
            data=payload,
        )
        if not response.ok:
            raise ProviderException(
                f"Failed to notify reaction to Slack: {response.text}"
            )
        self.logger.info("Reaction notified to Slack")
        return response.json()

    def _notify(
        self,
        message="",
        blocks=[],
        channel="",
        slack_timestamp="",
        thread_timestamp="",
        attachments=[],
        username="",
        notification_type="message",
        **kwargs: dict,
    ):
        """
        Notify alert message to Slack using the Slack Incoming Webhook API
        https://api.slack.com/messaging/webhooks

        Args:
            message (str): The content of the message.
            blocks (list): The blocks of the message.
            channel (str): The channel to send the message
            slack_timestamp (str): The timestamp of the message to update
            thread_timestamp (str): The timestamp of the thread to send the message
            attachments (list): The attachments of the message.
            username (str): The username of the message.
            notification_type (str): The type of notification.
        """
        if notification_type == "reaction":
            return self._notify_reaction(
                channel=channel,
                emoji=message,
                timestamp=thread_timestamp,
            )

        notify_data = None
        self.logger.info(
            f"Notifying message to Slack using {'webhook' if self.authentication_config.webhook_url else 'access token'}",
            extra={
                "slack_message": message,
                "blocks": blocks,
                "channel": channel,
            },
        )
        if not message:
            if not blocks and not attachments:
                raise ProviderException(
                    "Message is required - see for example https://github.com/keephq/keep/blob/main/examples/workflows/slack_basic.yml#L16"
                )
        payload = OrderedDict(
            {
                "channel": channel,
            }
        )
        if message:
            payload["text"] = message
        if blocks:
            payload["blocks"] = (
                json.dumps(blocks)
                if isinstance(blocks, dict) or isinstance(blocks, list)
                else blocks
            )
        if attachments:
            payload["attachments"] = (
                json.dumps(attachments)
                if isinstance(attachments, dict) or isinstance(attachments, list)
                else blocks
            )
        if username:
            payload["username"] = username

        if self.authentication_config.webhook_url:
            # If attachments are present, we need to send them as the payload with nothing else
            # Also, do not encode the payload as json, but as x-www-form-urlencoded
            # Only reference I found for it is: https://getkeep.slack.com/services/B082F60L9GX?added=1 and
            # https://stackoverflow.com/questions/42993602/slack-chat-postmessage-attachment-gives-no-text
            if payload.get("attachments", None):
                payload["attachments"] = attachments
                response = requests.post(
                    self.authentication_config.webhook_url,
                    data={"payload": json.dumps(payload)},
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
            else:
                response = requests.post(
                    self.authentication_config.webhook_url,
                    json=payload,
                )
            if not response.ok:
                raise ProviderException(
                    f"{self.__class__.__name__} failed to notify alert message to Slack: {response.text}"
                )
            notify_data = {"slack_timestamp": utcnowtimestamp()}
        elif self.authentication_config.access_token:
            if not channel:
                raise ProviderException("Channel is required (E.g. C12345)")
            self.logger.info(
                "Adding access token to payload",
                extra={
                    "tenant_id": self.context_manager.tenant_id,
                    "workflow_id": self.context_manager.workflow_id,
                    "provider_id": self.provider_id,
                    "access_token_truncated": self.authentication_config.access_token[
                        :5
                    ],
                },
            )
            payload["token"] = self.authentication_config.access_token
            if slack_timestamp == "" and thread_timestamp == "":
                self.logger.info("Sending a new message to Slack")
                method = "chat.postMessage"
            else:
                self.logger.info(f"Updating Slack message with ts: {slack_timestamp}")
                if slack_timestamp:
                    payload["ts"] = slack_timestamp
                    method = "chat.update"
                else:
                    method = "chat.postMessage"
                    payload["thread_ts"] = thread_timestamp

            if payload.get("attachments", None):
                payload["attachments"] = attachments
                if "token" not in payload:
                    self.logger.warning(
                        "Token is not in payload, adding it",
                        extra={
                            "tenant_id": self.context_manager.tenant_id,
                            "workflow_id": self.context_manager.workflow_id,
                            "provider_id": self.provider_id,
                        },
                    )
                    payload["token"] = self.authentication_config.access_token

            response = requests.post(
                f"{SlackProvider.SLACK_API}/{method}", json=payload,
                headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {self.authentication_config.access_token}",
                },
            )

            response_json = response.json()
            if not response.ok or not response_json.get("ok"):
                raise ProviderException(
                    f"Failed to notify alert message to Slack: {response_json.get('error')}"
                )
            notify_data = {"slack_timestamp": response_json["ts"]}
        self.logger.info("Message notified to Slack")
        return notify_data

    def _get_alerts(self) -> list[AlertDto]:
        """
        Get new alerts from configured Slack channels since last check.
        Only returns messages that arrived after the previous call.
        """
        if not self.authentication_config.access_token:
            raise ProviderException("Access token is required to get messages from channels")

        alerts = []
        channels = self.config.get("channels", [])

        for channel in channels:
            # Get messages since last check
            oldest = self.last_message_ts.get(channel)
            messages = self._get_messages(
                channel=channel,
                oldest=oldest,
                limit=1  # Adjust limit as needed
            )

            if not messages:
                continue

            # Update latest message timestamp for this channel
            latest_msg = messages[0]  # Messages are returned in reverse chronological order
            self.last_message_ts[channel] = latest_msg["ts"]

            # Convert messages to alerts
            for msg in messages:
                # Skip messages we've already seen
                if oldest and float(msg["ts"]) <= float(oldest):
                    continue
                    
                alert = AlertDto(
                    id=msg["ts"],
                    name=f"Slack Message from {channel}",
                    description=msg.get("text", ""),
                    message=msg.get("text", ""),
                    lastReceived=msg["ts"],
                    source=["slack"],
                    url=msg.get("permalink"),
                    severity=AlertSeverity.INFO,
                    status=AlertStatus.FIRING,
                    channel=channel,
                    user=msg.get("user", ""),
                    thread_ts=msg.get("thread_ts", "")
                )
                alerts.append(alert)

        return alerts

    def _get_messages(self, channel: str, oldest: int = None, limit: int = 100):
        """Get messages from a Slack channel.

        Args:
            channel: Channel ID or name
            oldest: Start of time range in epoch seconds
            limit: Maximum number of messages to return
        """
        params = {
            "channel": channel,
            "limit": limit
        }
        if oldest:
            params["oldest"] = oldest

        response = requests.get(
            f"{self.SLACK_API}/conversations.history",
            headers={
                "Authorization": f"Bearer {self.authentication_config.access_token}"
            },
            params=params
        )

        if not response.ok:
            raise ProviderException(f"Failed to get messages: {response.text}")

        data = response.json()
        if not data.get("ok"):
            raise ProviderException(f"Slack API error: {data.get('error')}")

        messages = data["messages"]

        # Get permalinks for messages
        for msg in messages:
            permalink_response = requests.get(
                f"{self.SLACK_API}/chat.getPermalink",
                headers={
                    "Authorization": f"Bearer {self.authentication_config.access_token}"
                },
                params={
                    "channel": channel,
                    "message_ts": msg["ts"]
                }
            )
            if permalink_response.ok:
                permalink_data = permalink_response.json()
                if permalink_data.get("ok"):
                    msg["permalink"] = permalink_data["permalink"]

        return messages


if __name__ == "__main__":
    # Output debug messages
    import logging

    from keep.providers.providers_factory import ProvidersFactory

    logging.basicConfig(level=logging.DEBUG, handlers=[logging.StreamHandler()])
    context_manager = ContextManager(
        tenant_id="singletenant",
        workflow_id="test",
    )
    # Load environment variables
    import os

    slack_webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

    # Initalize the provider and provider config
    context_manager = ContextManager(
        tenant_id="singletenant",
        workflow_id="test",
    )
    access_token = os.environ.get("SLACK_ACCESS_TOKEN")
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

    if access_token:
        config = {
            "authentication": {"access_token": access_token},
        }
    elif webhook_url:
        config = {
            "authentication": {"webhook_url": webhook_url},
        }
    # you need some creds
    else:
        raise Exception("please provide either access token or webhook url")

    provider = ProvidersFactory.get_provider(
        context_manager,
        provider_id="slack-keephq",
        provider_type="slack",
        provider_config=config,
    )
    provider.notify(
        channel="C04P7QSG692",
        attachments=[
            {
                "fallback": "Plain-text summary of the attachment.",
                "color": "#2eb886",
                "title": "Slack API Documentation",
                "title_link": "https://api.slack.com/",
                "text": "Optional text that appears within the attachment",
                "footer": "Slack API",
                "footer_icon": "https://platform.slack-edge.com/img/default_application_icon.png",
            }
        ],
    )
