"""False Positive 19: Safe XML parsing with standard ElementTree."""
import xml.etree.ElementTree as ET


def parse_simple_note(xml_string: str) -> dict:
    root = ET.fromstring(xml_string)
    return {child.tag: (child.text or "") for child in root}
