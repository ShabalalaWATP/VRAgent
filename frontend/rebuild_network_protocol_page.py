#!/usr/bin/env python3
"""
Script to redesign NetworkProtocolExploitationPage.tsx to match ArpDnsPoisoningPage.tsx structure
- Converts from tab-based to section-based layout
- Adds sidebar navigation
- Implements scroll tracking
- Preserves ALL existing content
"""

import re

def extract_data_objects(content):
    """Extract all the data object definitions that need to be preserved"""
    # Find all const declarations
    const_pattern = r'(const \w+(?::\s*\w+\[\])?\s*=\s*(?:\[|{)[\s\S]*?^  \];?$)'
    matches = re.findall(const_pattern, content, re.MULTILINE)
    return matches

def main():
    # Read the original file
    with open(r'C:\AlexDev\VRAgent\frontend\src\pages\NetworkProtocolExploitationPage.tsx', 'r', encoding='utf-8') as f:
        original_content = f.read()

    # Find where TabPanel sections start and end
    tab_sections = []
    tab_pattern = r'<TabPanel value=\{tabValue\} index=(\d+)>([\s\S]*?)</TabPanel>'
    for match in re.finditer(tab_pattern, original_content):
        tab_index = int(match.group(1))
        tab_content = match.group(2)
        tab_sections.append((tab_index, tab_content))

    print(f"Found {len(tab_sections)} tab sections")

    # Extract tab labels
    tab_labels = []
    tab_label_pattern = r'<Tab icon=\{<\w+Icon />\} label="([^"]+)"'
    for match in re.finditer(tab_label_pattern, original_content):
        tab_labels.append(match.group(1))

    print(f"Found {len(tab_labels)} tab labels: {tab_labels}")

    # Map tab labels to section IDs
    section_mapping = [
        ("Fundamentals", "fundamentals", "SchoolIcon"),
        ("Overview", "overview", "SecurityIcon"),
        ("Protocol Map", "protocol-map", "StorageIcon"),
        ("Exploitation Patterns", "exploitation-patterns", "TuneIcon"),
        ("Detection", "detection", "SearchIcon"),
        ("Hardening", "hardening", "ShieldIcon"),
        ("Safe Lab", "safe-lab", "BuildIcon"),
    ]

    print("\nSection mapping:")
    for label, id, icon in section_mapping:
        print(f"  {label} -> {id} ({icon})")

if __name__ == "__main__":
    main()
