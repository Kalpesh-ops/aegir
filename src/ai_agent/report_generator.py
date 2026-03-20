# Logic to format AI output
import os
import logging
from datetime import datetime


class ReportGenerator:
    def __init__(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.reports_dir = os.path.join(base_dir, "..", "..", "logs", "reports")
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)

    def save_report(self, ai_text, target_ip, scan_data=None):
        """
        Saves the AI analysis to a Markdown file.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"Report_{target_ip}_{timestamp}.md"
        filepath = os.path.join(self.reports_dir, filename)

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                # Add a header with metadata
                f.write(f"# Security Assessment Report\n")
                f.write(f"**Target:** {target_ip}\n")
                f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("---\n\n")

                # Write the AI Content
                f.write(ai_text)

                # Optional: Append raw technical data at the end
                if scan_data:
                    f.write("\n\n---\n## Appendix: Raw Technical Data\n")
                    f.write("```json\n")
                    # Convert dict to string if needed, limited to first 2000 chars to save space
                    import json

                    f.write(
                        json.dumps(scan_data, indent=2)[:2000] + "\n... (truncated)"
                    )
                    f.write("\n```")

            logging.info(f"Report saved locally to {filepath}")
            return filepath

        except Exception as e:
            logging.error(f"Failed to save report: {e}")
            return None

    def generate_pdf(self, markdown_text):
        """
        Placeholder for future PDF generation (e.g., using 'markdown-pdf' or 'weasyprint').
        For the Hackathon, returning the Markdown path is usually sufficient.
        """
        pass
