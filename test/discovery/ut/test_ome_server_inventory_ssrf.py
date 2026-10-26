# Copyright 2026 Dell Inc. or its subsidiaries. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for SSRF protection in ome_server_inventory module.

Tests the _is_same_origin method to ensure it properly validates URLs
and prevents Server-Side Request Forgery (SSRF) attacks.
"""

import pytest

# Import the OMEClient class from the module
import sys
from pathlib import Path

# Add the src directory to the path
src_path = Path(__file__).parent.parent.parent.parent / "src" / "discovery" / "plugins" / "modules"
sys.path.insert(0, str(src_path))

from ome_server_inventory import OMEClient


class TestSSRFProtection:
    """Test SSRF protection in OMEClient._is_same_origin method."""

    @pytest.fixture
    def client(self):
        """Create an OMEClient instance for testing."""
        return OMEClient(
            ip="192.168.1.100",
            username="test",
            password="test",
            verify_ssl=False
        )

    def test_relative_path_accepted(self, client):
        """Test that relative paths are accepted as same-origin."""
        assert client._is_same_origin("/api/GroupService/Groups(1)/Devices") is True
        assert client._is_same_origin("/api/DeviceService/Devices") is True
        assert client._is_same_origin("/some/path") is True

    def test_absolute_same_host_link_accepted(self, client):
        """Test that absolute links to same host are accepted."""
        assert client._is_same_origin("https://192.168.1.100/api/GroupService/Groups(1)/Devices") is True
        assert client._is_same_origin("https://192.168.1.100/api/DeviceService/Devices") is True

    def test_absolute_same_host_with_port_accepted(self, client):
        """Test that absolute links to same host with explicit port are accepted."""
        assert client._is_same_origin("https://192.168.1.100:443/api/GroupService/Groups(1)/Devices") is True

    def test_absolute_foreign_host_rejected(self, client):
        """Test that absolute links to foreign hosts are rejected."""
        assert client._is_same_origin("https://attacker.com/steal") is False
        assert client._is_same_origin("https://evil.com/api/Devices") is False
        assert client._is_same_origin("http://192.168.1.200/api/Devices") is False

    def test_absolute_foreign_host_with_port_rejected(self, client):
        """Test that absolute links to foreign hosts with different ports are rejected."""
        assert client._is_same_origin("https://192.168.1.100:8443/api/Devices") is False
        assert client._is_same_origin("https://attacker.com:443/steal") is False

    def test_metadata_service_blocked(self, client):
        """Test that metadata service URLs are blocked."""
        assert client._is_same_origin("http://169.254.169.254/latest/meta-data/") is False
        assert client._is_same_origin("https://169.254.169.254/latest/meta-data/") is False
        assert client._is_same_origin("https://metadata.google.internal/computeMetadata/v1/") is False

    def test_http_scheme_rejected(self, client):
        """Test that HTTP (non-HTTPS) scheme is rejected."""
        assert client._is_same_origin("http://192.168.1.100/api/Devices") is False
        assert client._is_same_origin("http://192.168.1.100:443/api/Devices") is False

    def test_empty_string_rejected(self, client):
        """Test that empty string is rejected."""
        assert client._is_same_origin("") is False

    def test_localhost_rejected(self, client):
        """Test that localhost is rejected (different from configured IP)."""
        assert client._is_same_origin("https://localhost/api/Devices") is False
        assert client._is_same_origin("https://127.0.0.1/api/Devices") is False

    def test_dns_rebinding_prevented(self, client):
        """Test that DNS rebinding is prevented by hostname check."""
        # Even if attacker controls DNS, hostname must match exactly
        assert client._is_same_origin("https://192.168.1.100.attacker.com/api/Devices") is False

    def test_urljoin_with_relative_path(self, client):
        """Test that urllib.parse.urljoin works correctly with relative paths."""
        import urllib.parse
        base_url = "https://192.168.1.100"
        relative = "/api/GroupService/Groups(1)/Devices"
        resolved = urllib.parse.urljoin(base_url, relative)
        assert resolved == "https://192.168.1.100/api/GroupService/Groups(1)/Devices"

    def test_urljoin_with_absolute_same_host(self, client):
        """Test that urllib.parse.urljoin works with absolute same-host URLs."""
        import urllib.parse
        base_url = "https://192.168.1.100"
        absolute = "https://192.168.1.100/api/GroupService/Groups(1)/Devices"
        resolved = urllib.parse.urljoin(base_url, absolute)
        assert resolved == "https://192.168.1.100/api/GroupService/Groups(1)/Devices"

    def test_urljoin_with_absolute_foreign_host(self, client):
        """Test that urllib.parse.urljoin preserves foreign host URLs."""
        import urllib.parse
        base_url = "https://192.168.1.100"
        foreign = "https://attacker.com/steal"
        resolved = urllib.parse.urljoin(base_url, foreign)
        assert resolved == "https://attacker.com/steal"
        # This is why we need _is_same_origin validation


class TestSessionConfiguration:
    """Test session configuration for SSRF protection."""

    @pytest.fixture
    def client(self):
        """Create an OMEClient instance for testing."""
        return OMEClient(
            ip="192.168.1.100",
            username="test",
            password="test",
            verify_ssl=False
        )

    def test_allow_redirects_disabled(self, client):
        """Test that allow_redirects is disabled to prevent redirect-based SSRF."""
        assert client.session.allow_redirects is False

    def test_session_verify_ssl_configured(self, client):
        """Test that SSL verification is configured."""
        assert client.session.verify is False  # As configured in fixture


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
