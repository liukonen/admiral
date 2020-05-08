#!/usr/bin/env python3

import re
from slack import WebClient
import time
import os
import certifi
import ssl
from slack import RTMClient
from slack.errors import SlackApiError
from admiral.interfaces import Interface

#Slack 2 interface uses the newer WebSocket Connection and is an upgrade to V2 of the Slackbot Python plugin.
# Version build on RTM platform
class Slack2rtmInterface(Interface):

    def name(self):
        """Return the name of this interface."""
        return "Slack2rtm"

    def setup(self, config):
        self.log.info("Set up Slack2 rtm interface: {}".format(config.id))
        self.last_ping = 0
        self.token = config.api_token
        self.username = config.username
        self.client = None
        self.webClient = None
        # Internal mappings.
        self.channel_by_uid = dict()  # User ID => channel ID
        self.thread_by_uid = dict()

    def connect(self):
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        self.client  = RTMClient(token=self.token, ssl=ssl_context)
        self.client.run_on(event='message')(self.GetMessage)
        self.client.start()
        
    def do_one_loop(self):
        """Look for new messages."""
        time.sleep(1) #Loop does nothing in V2.since it doesnt currently get hit, but saw large IO / CPU on older version

    def GetMessage(self, **payload):
        print(payload)
        message = payload['data']
        self.webClient = payload['web_client']
        print(message)
        self.handle_api_message(message)


    def handle_api_message(self, message):
        """Handle an incoming message from Slack."""
        #if "type" in message:
        if 'text' in message and 'subtype' not in message:
            self.handle_message(message)

    def handle_message(self, message, in_channel=False):
        """Handle a message that will actually elicit a response."""
        # Store their channel ID for the response.
        print("handle Message")
        self.channel_by_uid[message["user"]] = message["channel"]
        self.thread_by_uid[message["user"]] = message['ts']
        # User name no longer returned on new platform
        username = message["user"]

        # Format the message.
        message_data = message
        message = re.sub(
            r'^{username}\s*|<?@{username}>?'.format(username=self.username),
            '',
            message["text"]
        )
        if len(message.strip()) > 0:
            # Handle commands.
            if not self.slack_commands(username, message, message_data, in_channel):
                self.on_message(
                    username=username,
                    message=message,
                )

    def send_message(self, username, message):
        """Send a message to the user."""
        self.log.debug("Send Slack message to [{}] {}".format(
            username, message,
        ))
        print(message)
        try:
            self.webClient.chat_postMessage(channel=self.channel_by_uid[username],text= message,thread_ts=self.thread_by_uid[username])
        except SlackApiError as e:
            # You will get a SlackApiError if "ok" is False
            assert e.response["ok"] is False
            assert e.response["error"]  # str like 'invalid_auth', 'channel_not_found'
            print(f"Got an error: {e.response['error']}")


    def slack_commands(self, username, message, data, in_channel):
        if in_channel:
            if message.startswith("!leave"):
                # Leaving a channel.
                channel = data["channel"]
                self.log.info("Asked to leave channel {} by {}".format(channel, username)) 
                self.log.debug("Slack API:{}".format(self.webClient.api_call("channels.leave", channel=channel)))
                return True
        return False