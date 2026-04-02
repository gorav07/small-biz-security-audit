import requests

class WebVulnerabilityScanner:
    def __init__(self, url):
        self.url = url

    def check_sql_injection(self):
        payload = "' OR '1'='1'"
        response = requests.get(self.url + payload)
        if "error" in response.text.lower():
            return False
        return True

    def check_xss(self):
        payload = "<script>alert('XSS')</script>"
        response = requests.get(self.url + payload)
        if payload in response.text:
            return True
        return False

    def run_tests(self):
        results = {
            'SQL Injection': self.check_sql_injection(),
            'Cross Site Scripting (XSS)': self.check_xss(),
        }
        return results

if __name__ == '__main__':
    url = input("Enter the target URL: ")
    scanner = WebVulnerabilityScanner(url)
    results = scanner.run_tests()
    for vulnerability, is_vulnerable in results.items():
        print(f'{vulnerability}: {'Vulnerable' if is_vulnerable else 'Not Vulnerable'}')
