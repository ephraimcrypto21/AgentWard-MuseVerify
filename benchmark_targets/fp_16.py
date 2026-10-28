"""False Positive 16: Secure temporary file creation using tempfile.NamedTemporaryFile."""
import tempfile


def write_temp_report(report_text: str) -> str:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as tmp:
        tmp.write(report_text)
        return tmp.name
