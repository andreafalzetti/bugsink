import unittest
from unittest.mock import Mock, patch

from django.core.exceptions import DisallowedHost
from django.test import TestCase, RequestFactory
from django.conf import settings

from .cidr_utils import parse_cidr, is_ip_in_cidr, is_host_allowed
from .wsgi import CustomWSGIRequest


class CIDRUtilsTestCase(unittest.TestCase):
    """Test CIDR utility functions."""
    
    def test_parse_cidr_ipv4(self):
        """Test parsing IPv4 CIDR notation."""
        network = parse_cidr('10.0.0.0/8')
        self.assertEqual(str(network), '10.0.0.0/8')
        
        network = parse_cidr('172.31.0.0/16')
        self.assertEqual(str(network), '172.31.0.0/16')
        
        network = parse_cidr('192.168.1.0/24')
        self.assertEqual(str(network), '192.168.1.0/24')
    
    def test_parse_cidr_ipv6(self):
        """Test parsing IPv6 CIDR notation."""
        network = parse_cidr('2001:db8::/32')
        self.assertEqual(str(network), '2001:db8::/32')
        
        # With brackets
        network = parse_cidr('[2001:db8::/32]')
        self.assertEqual(str(network), '2001:db8::/32')
    
    def test_parse_cidr_invalid(self):
        """Test parsing invalid CIDR notation."""
        with self.assertRaises(ValueError):
            parse_cidr('invalid')
        
        with self.assertRaises(ValueError):
            parse_cidr('10.0.0.0/33')  # Invalid prefix length
    
    def test_is_ip_in_cidr_ipv4(self):
        """Test checking if IPv4 address is in CIDR range."""
        # Positive cases
        self.assertTrue(is_ip_in_cidr('10.0.0.1', '10.0.0.0/8'))
        self.assertTrue(is_ip_in_cidr('10.255.255.255', '10.0.0.0/8'))
        self.assertTrue(is_ip_in_cidr('172.31.0.1', '172.31.0.0/16'))
        self.assertTrue(is_ip_in_cidr('192.168.1.100', '192.168.1.0/24'))
        
        # Negative cases
        self.assertFalse(is_ip_in_cidr('11.0.0.1', '10.0.0.0/8'))
        self.assertFalse(is_ip_in_cidr('172.30.0.1', '172.31.0.0/16'))
        self.assertFalse(is_ip_in_cidr('192.168.2.1', '192.168.1.0/24'))
    
    def test_is_ip_in_cidr_ipv6(self):
        """Test checking if IPv6 address is in CIDR range."""
        # Positive cases
        self.assertTrue(is_ip_in_cidr('2001:db8::1', '2001:db8::/32'))
        self.assertTrue(is_ip_in_cidr('[2001:db8::1]', '[2001:db8::/32]'))
        
        # Negative cases
        self.assertFalse(is_ip_in_cidr('2001:db9::1', '2001:db8::/32'))
        
        # Mixed versions should return False
        self.assertFalse(is_ip_in_cidr('10.0.0.1', '2001:db8::/32'))
        self.assertFalse(is_ip_in_cidr('2001:db8::1', '10.0.0.0/8'))
    
    def test_is_host_allowed_wildcard(self):
        """Test wildcard in ALLOWED_HOSTS."""
        self.assertTrue(is_host_allowed('example.com', ['*']))
        self.assertTrue(is_host_allowed('10.0.0.1', ['*']))
    
    def test_is_host_allowed_direct_match(self):
        """Test direct hostname matching."""
        allowed = ['example.com', 'test.com']
        
        self.assertTrue(is_host_allowed('example.com', allowed))
        self.assertTrue(is_host_allowed('EXAMPLE.COM', allowed))  # Case insensitive
        self.assertFalse(is_host_allowed('other.com', allowed))
        
        # Test IP addresses as direct matches
        allowed_ips = ['192.168.1.1', '[::1]']
        self.assertTrue(is_host_allowed('192.168.1.1', allowed_ips))
        self.assertTrue(is_host_allowed('[::1]', allowed_ips))
        self.assertFalse(is_host_allowed('192.168.1.2', allowed_ips))
    
    def test_is_host_allowed_subdomain_wildcard(self):
        """Test subdomain wildcard matching."""
        allowed = ['.example.com']
        
        self.assertTrue(is_host_allowed('sub.example.com', allowed))
        self.assertTrue(is_host_allowed('deep.sub.example.com', allowed))
        self.assertTrue(is_host_allowed('example.com', allowed))
        self.assertFalse(is_host_allowed('notexample.com', allowed))
        
        # Edge case: ensure '.com' doesn't match just 'com'
        allowed_tld = ['.com']
        self.assertFalse(is_host_allowed('com', allowed_tld))
        self.assertTrue(is_host_allowed('example.com', allowed_tld))
    
    def test_is_host_allowed_cidr(self):
        """Test CIDR range matching."""
        allowed = ['example.com', '10.0.0.0/8', '172.31.0.0/16', '[2001:db8::/32]']
        
        # Domain names
        self.assertTrue(is_host_allowed('example.com', allowed))
        self.assertFalse(is_host_allowed('other.com', allowed))
        
        # IPv4 addresses
        self.assertTrue(is_host_allowed('10.0.0.1', allowed))
        self.assertTrue(is_host_allowed('10.255.255.255', allowed))
        self.assertTrue(is_host_allowed('172.31.0.1', allowed))
        self.assertFalse(is_host_allowed('11.0.0.1', allowed))
        self.assertFalse(is_host_allowed('192.168.1.1', allowed))
        
        # IPv6 addresses
        self.assertTrue(is_host_allowed('[2001:db8::1]', allowed))
        self.assertFalse(is_host_allowed('[2001:db9::1]', allowed))


class CustomWSGIRequestTestCase(TestCase):
    """Test CIDR support in CustomWSGIRequest."""
    
    def _make_environ(self, host):
        """Helper to create WSGI environ with a specific host."""
        return {
            'REQUEST_METHOD': 'GET',
            'PATH_INFO': '/',
            'HTTP_HOST': host,
            'wsgi.input': Mock(),
            'wsgi.url_scheme': 'http',
        }
    
    @patch('bugsink.wsgi.settings')
    def test_allowed_host_passes(self, mock_settings):
        """Test that allowed hosts pass through."""
        mock_settings.ALLOWED_HOSTS = ['example.com', '10.0.0.0/8']
        mock_settings.DEBUG = False
        
        # Domain name
        environ = self._make_environ('example.com')
        request = CustomWSGIRequest(environ)
        self.assertEqual(request.get_host(), 'example.com')
        
        # IP in CIDR range
        environ = self._make_environ('10.0.0.1')
        request = CustomWSGIRequest(environ)
        self.assertEqual(request.get_host(), '10.0.0.1')
    
    @patch('bugsink.wsgi.settings')
    def test_disallowed_host_raises(self, mock_settings):
        """Test that disallowed hosts raise DisallowedHost."""
        mock_settings.ALLOWED_HOSTS = ['example.com', '10.0.0.0/8']
        mock_settings.DEBUG = False
        
        # Different domain
        environ = self._make_environ('evil.com')
        request = CustomWSGIRequest(environ)
        with self.assertRaises(DisallowedHost):
            request.get_host()
        
        # IP outside CIDR range
        environ = self._make_environ('192.168.1.1')
        request = CustomWSGIRequest(environ)
        with self.assertRaises(DisallowedHost):
            request.get_host()
    
    @patch('bugsink.wsgi.settings')
    def test_host_with_port(self, mock_settings):
        """Test host validation with port numbers."""
        mock_settings.ALLOWED_HOSTS = ['example.com', '10.0.0.0/8']
        mock_settings.DEBUG = False
        
        # Domain with port
        environ = self._make_environ('example.com:8000')
        request = CustomWSGIRequest(environ)
        self.assertEqual(request.get_host(), 'example.com:8000')
        
        # IP with port in CIDR range
        environ = self._make_environ('10.0.0.1:8000')
        request = CustomWSGIRequest(environ)
        self.assertEqual(request.get_host(), '10.0.0.1:8000')
        
        # Disallowed host with port
        environ = self._make_environ('evil.com:8000')
        request = CustomWSGIRequest(environ)
        with self.assertRaises(DisallowedHost):
            request.get_host()
    
    @patch('bugsink.wsgi.settings')
    def test_cidr_ipv6(self, mock_settings):
        """Test IPv6 CIDR ranges."""
        mock_settings.ALLOWED_HOSTS = ['[2001:db8::/32]']
        mock_settings.DEBUG = False
        
        # IPv6 in range
        environ = self._make_environ('[2001:db8::1]')
        request = CustomWSGIRequest(environ)
        self.assertEqual(request.get_host(), '[2001:db8::1]')
        
        # IPv6 outside range
        environ = self._make_environ('[2001:db9::1]')
        request = CustomWSGIRequest(environ)
        with self.assertRaises(DisallowedHost):
            request.get_host()