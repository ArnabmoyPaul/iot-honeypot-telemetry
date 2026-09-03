#!/usr/bin/env python3
"""
MQTT Protocol Handler for Dionaea Honeypot
Emulates IoT MQTT broker to capture Mirai-variant botnet probes.

MQTT is the primary C2 protocol for modern IoT botnets including:
- Mirai (evolved variants)
- Mozi
- Hajime

This handler captures:
- Connection attempts with credentials
- Topic subscriptions (often C2 command channels)
- Published messages (frequently DDoS target lists)
"""

import json
import logging
import struct
from datetime import datetime

logger = logging.getLogger('dionaea.mqtt')

# Common IoT MQTT default credentials targeted by botnets
DEFAULT_CREDENTIALS = [
    ('admin', 'admin'),
    ('root', 'root'),
    ('user', 'user'),
    ('guest', 'guest'),
    ('pi', 'raspberry'),
    ('admin', '123456'),
    ('root', '123456'),
]

# Known malicious MQTT topics used by botnets
SUSPICIOUS_TOPICS = [
    'botnet',
    'c2',
    'command',
    'ddos',
    'shell',
    'exec',
    'download',
    'update',
    'miner',
    'xmr',
]


class MQTTConnection:
    """Handles a single MQTT client connection."""

    def __init__(self, conn):
        self.conn = conn
        self.client_id = None
        self.username = None
        self.password = None
        self.connected = False

    def handle_connect(self, payload: bytes) -> None:
        """Process MQTT CONNECT packet and extract credentials."""
        try:
            # Parse variable header
            proto_len = struct.unpack('!H', payload[:2])[0]
            proto_name = payload[2:2+proto_len].decode('utf-8', errors='ignore')
            proto_level = payload[2+proto_len]
            flags = payload[3+proto_len]
            keep_alive = struct.unpack('!H', payload[4+proto_len:6+proto_len])[0]

            idx = 6 + proto_len

            # Client ID
            client_id_len = struct.unpack('!H', payload[idx:idx+2])[0]
            self.client_id = payload[idx+2:idx+2+client_id_len].decode('utf-8', errors='ignore')
            idx += 2 + client_id_len

            # Username (if present)
            if flags & 0x80:
                username_len = struct.unpack('!H', payload[idx:idx+2])[0]
                self.username = payload[idx+2:idx+2+username_len].decode('utf-8', errors='ignore')
                idx += 2 + username_len

            # Password (if present)
            if flags & 0x40:
                password_len = struct.unpack('!H', payload[idx:idx+2])[0]
                self.password = payload[idx+2:idx+2+password_len].decode('utf-8', errors='ignore')

            # Log structured event
            event = {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'event_type': 'mqtt_connect',
                'src_ip': self.conn.remote.host,
                'src_port': self.conn.remote.port,
                'protocol': 'mqtt',
                'client_id': self.client_id,
                'username': self.username,
                'password': self.password,
                'proto_name': proto_name,
                'proto_level': proto_level,
                'keep_alive': keep_alive,
                'suspicious': self._is_suspicious()
            }
            logger.info(json.dumps(event))

            # Send CONNACK (accept connection for deeper telemetry)
            self.conn.send(b'\x20\x02\x00\x00')
            self.connected = True

        except Exception as e:
            logger.error(f"MQTT connect parse error: {e}")

    def _is_suspicious(self) -> bool:
        """Check if credentials or client ID match known botnet patterns."""
        if (self.username, self.password) in DEFAULT_CREDENTIALS:
            return True
        if self.client_id and any(s in self.client_id.lower() for s in ['bot', 'mirai', 'mozi']):
            return True
        return False

    def handle_publish(self, payload: bytes) -> None:
        """Process MQTT PUBLISH packet for C2 command extraction."""
        try:
            topic_len = struct.unpack('!H', payload[:2])[0]
            topic = payload[2:2+topic_len].decode('utf-8', errors='ignore')
            message = payload[2+topic_len:]

            event = {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'event_type': 'mqtt_publish',
                'src_ip': self.conn.remote.host,
                'topic': topic,
                'message_length': len(message),
                'message_preview': message[:200].hex(),
                'suspicious_topic': any(s in topic.lower() for s in SUSPICIOUS_TOPICS)
            }
            logger.info(json.dumps(event))

        except Exception as e:
            logger.error(f"MQTT publish parse error: {e}")

    def handle_subscribe(self, payload: bytes) -> None:
        """Process MQTT SUBSCRIBE packet."""
        try:
            topics = []
            idx = 2  # Skip packet identifier

            while idx < len(payload):
                topic_len = struct.unpack('!H', payload[idx:idx+2])[0]
                topic = payload[idx+2:idx+2+topic_len].decode('utf-8', errors='ignore')
                qos = payload[idx+2+topic_len]
                topics.append({'topic': topic, 'qos': qos})
                idx += 3 + topic_len

            event = {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'event_type': 'mqtt_subscribe',
                'src_ip': self.conn.remote.host,
                'topics': topics,
                'suspicious': any(
                    any(s in t['topic'].lower() for s in SUSPICIOUS_TOPICS)
                    for t in topics
                )
            }
            logger.info(json.dumps(event))

            # Send SUBACK
            self.conn.send(b'\x90\x03\x00\x01\x00')

        except Exception as e:
            logger.error(f"MQTT subscribe parse error: {e}")
