import ssl
import socket
from datetime import datetime

class SSLChecker:
    def __init__(self, host, port=443):
        self.host = host
        self.port = port
        self.context = ssl.create_default_context()

    def check_certificate(self):
        try:
            with socket.create_connection((self.host, self.port)) as sock:
                with self.context.wrap_socket(sock, server_hostname=self.host) as ssl_sock:
                    cert = ssl_sock.getpeercert()
                    return cert
        except Exception as e:
            return str(e)

    def validate_certificate(self, cert):
        current_time = datetime.utcnow()
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        recommendations = []

        if current_time < not_before:
            recommendations.append("Certificate is not yet valid.")
        if current_time > not_after:
            recommendations.append("Certificate has expired.")

        return recommendations

    def analyze(self):
        cert = self.check_certificate()
        if isinstance(cert, str):
            return {'error': cert}
        recommendations = self.validate_certificate(cert)
        return {'certificate': cert, 'recommendations': recommendations}

# Usage Example:
# ssl_checker = SSLChecker('example.com')
# findings = ssl_checker.analyze()
# print(findings)