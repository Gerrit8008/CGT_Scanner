import unittest
from security_scanner import SecurityScanner

class TestSecurityScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = SecurityScanner()
        
    def test_network_scan(self):
        result = self.scanner.scan('example.com', {'network': True})
        self.assertIn('network', result)
        self.assertIn('open_ports', result['network'])
        
    def test_web_scan(self):
        result = self.scanner.scan('example.com', {'web': True})
        self.assertIn('web', result)
        self.assertIn('vulnerabilities', result['web'])
