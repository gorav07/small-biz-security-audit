class Settings:
    def __init__(self):
        self.api_keys = {
            'service_name': 'your-api-key',  # replace with actual API keys
            'another_service': 'another-api-key'
        }
        self.email_settings = {
            'smtp_server': 'smtp.your-email.com',
            'port': 587,
            'username': 'your-email@example.com',
            'password': 'your-email-password'
        }
        self.scanning_config = {
            'scan_interval': 'daily',
            'timeout': 300  # in seconds
        }
        self.frontend_url = 'https://your-frontend-url.com'
        self.database_url = 'postgresql://user:password@localhost:5432/yourdatabase'
