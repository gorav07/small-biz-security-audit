"""
HTTP Security Headers validation module
"""
import requests
import logging

logger = logging.getLogger(__name__)

class HeaderChecker:
    """Check for presence and correctness of security headers"""
    
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "description": "Forces HTTPS connections",
            "example": "max-age=31536000; includeSubDomains"
        },
        "Content-Security-Policy": {
            "description": "Prevents cross-site scripting (XSS) attacks",
            "example": "default-src 'self'; script-src 'self'"
        },
        "X-Content-Type-Options": {
            "description": "Prevents MIME type sniffing",
            "example": "nosniff"
        },
        "X-Frame-Options": {
            "description": "Prevents clickjacking attacks",
            "example": "DENY or SAMEORIGIN"
        },
        "X-XSS-Protection": {
            "description": "Enables browser XSS filtering",
            "example": "1; mode=block"
        },
        "Referrer-Policy": {
            "description": "Controls referrer information",
            "example": "strict-origin-when-cross-origin"
        }
    }
    
    def __init__(self, url):
        """Initialize with URL to check"""
        self.url = url
        self.headers = None
        self.get_headers()
    
    def get_headers(self):
        """Fetch headers from the URL"""
        try:
            response = requests.get(self.url, timeout=10)
            self.headers = response.headers
            logger.info(f"Successfully fetched headers from {self.url}")
        except Exception as e:
            logger.error(f"Failed to fetch headers: {str(e)}")
            self.headers = {}
    
    def validate_headers(self):
        """
        Validate security headers
        
        Returns:
            tuple: (missing_headers, recommendations)
        """
        if not self.headers:
            return [], ["Unable to fetch headers from the URL"]
        
        missing_headers = []
        recommendations = []
        
        for header, info in self.SECURITY_HEADERS.items():
            if header not in self.headers:
                missing_headers.append(header)
                recommendation = (
                    f"Add '{header}' header - {info['description']}. "
                    f"Example: {header}: {info['example']}"
                )
                recommendations.append(recommendation)
        
        return missing_headers, recommendations


if __name__ == "__main__":
    # Example usage
    url = "https://example.com"
    checker = HeaderChecker(url)
    missing, advice = checker.validate_headers()
    print("Missing Headers:", missing)
    print("Recommendations:")
    for rec in advice:
        print(f"  - {rec}")
