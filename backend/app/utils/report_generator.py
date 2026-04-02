import os
from datetime import datetime

class ReportGenerator:
    def __init__(self, title="Report"):
        self.title = title
        self.content = ""

    def add_section(self, heading, body):
        self.content += f'<h2>{heading}</h2><p>{body}</p>'

    def generate_html(self):
        current_time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        report = f'<!DOCTYPE html>\n<html lang="en">\n<head>\n    <meta charset="UTF-8">\n    <meta name="viewport" content="width=device-width, initial-scale=1.0">\n    <title>{self.title}</title>\n</head>\n<body>\n    <h1>{self.title}</h1>\n    <p>Report generated on: {current_time} UTC</p>\n    {self.content}\n</body>\n</html>'
        return report

    def save_report(self, filename):
        with open(filename, 'w') as file:
            file.write(self.generate_html())
        print(f'Report saved to {filename}')

# Usage:
# report = ReportGenerator("Annual Security Audit")
# report.add_section("Summary", "This is the summary of the audit.")
# report.save_report("audit_report.html")
