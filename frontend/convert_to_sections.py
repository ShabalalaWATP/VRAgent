#!/usr/bin/env python3
"""
Converts NetworkProtocolExploitationPage.tsx from tab-based to section-based layout
matching the ArpDnsPoisoningPage.tsx structure.
"""

import re

def main():
    # Read the original file
    with open(r'C:\AlexDev\VRAgent\frontend\src\pages\NetworkProtocolExploitationPage.tsx', 'r', encoding='utf-8') as f:
        content = f.read()

    # Remove TabPanel interface and function (no longer needed)
    content = re.sub(r'interface TabPanelProps \{[\s\S]*?\}\n\nfunction TabPanel\(props: TabPanelProps\) \{[\s\S]*?\}\n\n', '', content)

    # Remove Tabs and Tab from imports
    content = content.replace('  Tabs,\n', '')
    content = content.replace('  Tab,\n', '')

    # Add missing imports for section-based layout
    imports_to_add = ['LinearProgress', 'ListAltIcon', 'CloseIcon']
    for imp in imports_to_add:
        if imp not in content:
            # Add to MUI imports
            content = content.replace('} from "@mui/material";', f'  {imp},\n}} from "@mui/material";')

    # Add additional icon imports if missing
    icon_imports = {
        'ListAltIcon': '@mui/icons-material/ListAlt',
        'CloseIcon': '@mui/icons-material/Close',
        'KeyboardArrowUpIcon': '@mui/icons-material/KeyboardArrowUp'
    }

    for icon, import_path in icon_imports.items():
        if icon not in content and import_path not in content:
            # Add after other icon imports
            content = content.replace('import { Link, useNavigate } from "react-router-dom";',
                                    f'import {icon} from "{import_path}";\nimport {{ Link, useNavigate }} from "react-router-dom";')

    # Replace state management
    content = re.sub(r'  const \[tabValue, setTabValue\] = useState\(0\);',
                    '  const [activeSection, setActiveSection] = useState("");',
                    content)

    # Add navigation drawer state
    content = re.sub(r'(  const \[tocOpen, setTocOpen\] = useState\(false\);)',
                    r'\1\n  const [navDrawerOpen, setNavDrawerOpen] = useState(false);',
                    content)

    # Update scroll effect to track active section
    scroll_effect = '''  // Track active section on scroll
  useEffect(() => {
    const handleScroll = () => {
      const sections = sectionNavItems.map((item) => item.id);
      let currentSection = "";

      for (const sectionId of sections) {
        const element = document.getElementById(sectionId);
        if (element) {
          const rect = element.getBoundingClientRect();
          if (rect.top <= 150) {
            currentSection = sectionId;
          }
        }
      }
      setActiveSection(currentSection);
      setShowScrollTop(window.scrollY > 400);
    };

    window.addEventListener("scroll", handleScroll);
    handleScroll();
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);'''

    content = re.sub(r'  useEffect\(\(\) => \{[\s\S]*?return \(\) => window\.removeEventListener\(\'scroll\', handleScroll\);\s+\}, \[\]\);',
                    scroll_effect,
                    content)

    # Add sectionNavItems array after const scrollToTop
    section_nav = '''
  // Section navigation items
  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <SchoolIcon /> },
    { id: "fundamentals", label: "Networking Fundamentals", icon: <LanIcon /> },
    { id: "overview", label: "Learning Overview", icon: <SecurityIcon /> },
    { id: "protocol-map", label: "Protocol Map", icon: <StorageIcon /> },
    { id: "exploitation-patterns", label: "Exploitation Patterns", icon: <TuneIcon /> },
    { id: "detection", label: "Detection Methods", icon: <SearchIcon /> },
    { id: "hardening", label: "Hardening Guide", icon: <ShieldIcon /> },
    { id: "safe-lab", label: "Safe Lab Setup", icon: <BuildIcon /> },
  ];

  // Scroll to section
  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      const yOffset = -80;
      const y = element.getBoundingClientRect().top + window.pageYOffset + yOffset;
      window.scrollTo({ top: y, behavior: "smooth" });
      setNavDrawerOpen(false);
    }
  };

  // Progress calculation
  const currentIndex = sectionNavItems.findIndex((item) => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / sectionNavItems.length) * 100 : 0;
'''

    content = re.sub(r'(  const scrollToTop = \(\) => \{[\s\S]*?\};)',
                    r'\1' + section_nav,
                    content)

    # Save to new file
    output_path = r'C:\AlexDev\VRAgent\frontend\src\pages\NetworkProtocolExploitationPage_NEW.tsx'
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"[OK] Converted file saved to: {output_path}")
    print(f"[OK] File size: {len(content)} characters")
    print("\nNext steps:")
    print("1. Manually replace the Tab/TabPanel JSX with section-based layout")
    print("2. Add sidebar navigation component")
    print("3. Add nav drawer for mobile")
    print("4. Add scroll-to-top FAB")
    print("5. Convert each TabPanel to a section with proper ID")

if __name__ == "__main__":
    main()
