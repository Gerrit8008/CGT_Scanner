
class SecurityScanner:
    def __init__(self):
        self.scanners = {
            'network': NetworkScanner(),
            'web': WebScanner(),
            'ssl': SSLScanner(),
            'dns': DNSScanner(),
            'system': SystemScanner()
        }

    def scan(self, target, options):
        results = {}
        for scanner_type, enabled in options.items():
            if enabled and scanner_type in self.scanners:
                results[scanner_type] = self.scanners[scanner_type].scan(target)
        return results
