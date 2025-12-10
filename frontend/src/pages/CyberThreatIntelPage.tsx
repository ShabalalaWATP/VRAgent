import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  IconButton,
  Chip,
  Grid,
  Tabs,
  Tab,
  TextField,
  InputAdornment,
  Link,
  Card,
  CardContent,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from "@mui/material";
import { useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import SearchIcon from "@mui/icons-material/Search";
import LaunchIcon from "@mui/icons-material/Launch";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";

interface ThreatActor {
  name: string;
  aliases: string[];
  origin: string;
  type: string;
  targets: string[];
  description: string;
  notableCampaigns?: string[];
  ttps?: string[];
}

interface ActorCategory {
  id: string;
  name: string;
  icon: string;
  color: string;
  description: string;
  actors: ThreatActor[];
}

// Organized by allegiance/type
const actorCategories: ActorCategory[] = [
  {
    id: "western-govt",
    name: "Western Government & Allied",
    icon: "🏛️",
    color: "#3b82f6",
    description: "Intelligence agencies and cyber commands from NATO/Five Eyes nations",
    actors: [
      { 
        name: "Equation Group", 
        aliases: ["EQGRP", "Longhorn"], 
        origin: "USA (NSA/TAO)", 
        type: "Intelligence", 
        targets: ["Global Governments", "Telecom", "Encryption"], 
        description: "NSA's elite hacking unit, creators of Stuxnet components.",
        notableCampaigns: ["Stuxnet (Centrifuges)", "Duqu", "Flame"],
        ttps: ["Zero-day exploits", "Firmware persistence", "Air-gap jumping"]
      },
      { 
        name: "Tailored Access Operations (TAO)", 
        aliases: ["Office of TAO"], 
        origin: "USA (NSA)", 
        type: "Intelligence", 
        targets: ["Global"], 
        description: "NSA's offensive cyber operations unit.",
        notableCampaigns: ["Shadow Brokers Leaks (Victim)", "Quantum Insert"],
        ttps: ["Supply chain interdiction", "Hardware implants", "QUANTUM suite"]
      },
      { name: "CIA Special Activities Center", aliases: ["SAC", "Vault 7"], origin: "USA (CIA)", type: "Intelligence", targets: ["Global"], description: "CIA's covert cyber operations division" },
      { name: "USCYBERCOM", aliases: ["Cyber National Mission Force"], origin: "USA", type: "Military", targets: ["State Actors"], description: "Unified combatant command for cyberspace operations" },
      { name: "National Cyber Force (NCF)", aliases: [], origin: "UK (GCHQ/MOD)", type: "Military/Intelligence", targets: ["State Actors", "Terrorists"], description: "UK's offensive cyber capability, joint GCHQ-MOD" },
      { name: "GCHQ", aliases: ["Government Communications HQ"], origin: "UK", type: "Intelligence", targets: ["Global"], description: "UK signals intelligence and cyber security agency" },
      { name: "DGSE", aliases: ["Direction Générale de la Sécurité Extérieure"], origin: "France", type: "Intelligence", targets: ["Global"], description: "French external intelligence service" },
      { name: "BND", aliases: ["Bundesnachrichtendienst"], origin: "Germany", type: "Intelligence", targets: ["Global"], description: "German federal intelligence service" },
      { name: "CSE", aliases: ["Communications Security Establishment"], origin: "Canada", type: "Intelligence", targets: ["Global"], description: "Canada's signals intelligence agency" },
      { name: "ASD", aliases: ["Australian Signals Directorate"], origin: "Australia", type: "Intelligence", targets: ["Asia-Pacific"], description: "Australia's signals intelligence and cyber security agency" },
      { name: "GCSB", aliases: ["Government Communications Security Bureau"], origin: "New Zealand", type: "Intelligence", targets: ["Asia-Pacific"], description: "New Zealand's signals intelligence agency" },
      { name: "Unit 8200", aliases: [], origin: "Israel (IDF)", type: "Military Intelligence", targets: ["Middle East"], description: "Israeli signals intelligence unit, elite cyber capabilities" },
      { name: "Mossad", aliases: [], origin: "Israel", type: "Intelligence", targets: ["Middle East", "Global"], description: "Israeli national intelligence agency" },
    ],
  },
  {
    id: "russian",
    name: "Russian State Actors",
    icon: "🐻",
    color: "#dc2626",
    description: "Russian intelligence services and military cyber units",
    actors: [
      { 
        name: "APT28", 
        aliases: ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM", "Forest Blizzard"], 
        origin: "Russia (GRU)", 
        type: "Military Intelligence", 
        targets: ["NATO", "Ukraine", "Elections"], 
        description: "GRU Unit 26165, responsible for DNC hack, Olympic attacks.",
        notableCampaigns: ["DNC Hack (2016)", "Olympic Destroyer", "Bundestag Hack"],
        ttps: ["X-Agent", "X-Tunnel", "Credential Harvesting", "VPNFilter"]
      },
      { 
        name: "APT29", 
        aliases: ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard"], 
        origin: "Russia (SVR)", 
        type: "Intelligence", 
        targets: ["Government", "Think Tanks"], 
        description: "SVR foreign intelligence, SolarWinds supply chain attack.",
        notableCampaigns: ["SolarWinds (Sunburst)", "DNC Hack (2016)", "COVID-19 Vaccine Theft"],
        ttps: ["Supply Chain Compromise", "Cloud Persistence", "Token Theft"]
      },
      { 
        name: "Sandworm", 
        aliases: ["Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "Unit 74455"], 
        origin: "Russia (GRU)", 
        type: "Military Intelligence", 
        targets: ["Ukraine", "Infrastructure"], 
        description: "GRU Unit 74455, NotPetya, Ukraine power grid attacks.",
        notableCampaigns: ["NotPetya", "Ukraine Power Grid (2015/2016)", "Olympic Destroyer"],
        ttps: ["Destructive Malware (Wiper)", "Living off the Land", "Industroyer"]
      },
      { 
        name: "Turla", 
        aliases: ["Snake", "Venomous Bear", "KRYPTON", "Secret Blizzard"], 
        origin: "Russia (FSB)", 
        type: "Intelligence", 
        targets: ["Government", "Military"], 
        description: "FSB Center 16, one of most sophisticated Russian APTs.",
        notableCampaigns: ["Agent.btz", "Moonlight Maze", "Satellite Hijacking"],
        ttps: ["Satellite C2", "Rootkits", "Watering Holes"]
      },
      { name: "Gamaredon", aliases: ["Primitive Bear", "ACTINIUM", "Aqua Blizzard"], origin: "Russia (FSB)", type: "Intelligence", targets: ["Ukraine"], description: "FSB-linked, focused on Ukrainian government" },
      { name: "Star Blizzard", aliases: ["SEABORGIUM", "Callisto", "Cold River"], origin: "Russia (FSB)", type: "Intelligence", targets: ["NATO", "UK", "NGOs"], description: "Credential phishing campaigns against Western targets" },
      { name: "Ember Bear", aliases: ["UAC-0056", "Lorec53"], origin: "Russia (GRU)", type: "Military Intelligence", targets: ["Ukraine", "NATO"], description: "GRU-linked destructive attacks on Ukraine" },
    ],
  },
  {
    id: "chinese",
    name: "Chinese State Actors",
    icon: "🐉",
    color: "#ef4444",
    description: "PLA, MSS, and affiliated Chinese cyber operations",
    actors: [
      { 
        name: "APT1", 
        aliases: ["Comment Crew", "Unit 61398"], 
        origin: "China (PLA)", 
        type: "Military", 
        targets: ["US Defense", "Industry"], 
        description: "PLA Unit 61398, first APT publicly attributed by Mandiant.",
        notableCampaigns: ["Operation Aurora", "Shady RAT"],
        ttps: ["Spearphishing", "Custom Backdoors", "Pass-the-Hash"]
      },
      { 
        name: "APT10", 
        aliases: ["Stone Panda", "menuPass", "Red Apollo"], 
        origin: "China (MSS)", 
        type: "Intelligence", 
        targets: ["MSPs", "Healthcare"], 
        description: "MSS Tianjin bureau, Operation Cloud Hopper.",
        notableCampaigns: ["Operation Cloud Hopper", "Visallo"],
        ttps: ["MSP Compromise", "DLL Side-Loading", "Quasar RAT"]
      },
      { name: "APT40", aliases: ["Leviathan", "TEMP.Periscope", "Gingham Typhoon"], origin: "China (MSS)", type: "Intelligence", targets: ["Maritime", "Defense"], description: "MSS Hainan, maritime and naval intelligence" },
      { 
        name: "APT41", 
        aliases: ["Winnti", "Wicked Panda", "Brass Typhoon"], 
        origin: "China (MSS)", 
        type: "Intelligence/Criminal", 
        targets: ["Gaming", "Tech", "Healthcare"], 
        description: "Dual espionage and financially motivated operations.",
        notableCampaigns: ["Supply Chain Attacks (CCleaner)", "Game Currency Theft"],
        ttps: ["Software Supply Chain", "Bootkits", "ShadowPad"]
      },
      { 
        name: "Volt Typhoon", 
        aliases: ["VANGUARD PANDA", "Bronze Silhouette"], 
        origin: "China", 
        type: "State", 
        targets: ["US Critical Infrastructure"], 
        description: "Pre-positioning for infrastructure disruption.",
        notableCampaigns: ["Guam Infrastructure", "US Ports"],
        ttps: ["Living off the Land (LOTL)", "SOHO Router Exploitation", "Web Shells"]
      },
      { name: "Salt Typhoon", aliases: [], origin: "China", type: "State", targets: ["Telecom", "ISPs"], description: "2024 telecom intrusions, access to wiretap systems" },
      { name: "Flax Typhoon", aliases: ["Ethereal Panda"], origin: "China", type: "State", targets: ["Taiwan", "US"], description: "Taiwan-focused, IoT botnet operations" },
      { name: "Mustang Panda", aliases: ["Bronze President", "RedDelta"], origin: "China", type: "State", targets: ["Southeast Asia", "EU"], description: "Southeast Asian government espionage" },
      { name: "APT31", aliases: ["Zirconium", "Violet Typhoon"], origin: "China (MSS)", type: "Intelligence", targets: ["Government", "Elections"], description: "MSS Hubei, election interference operations" },
    ],
  },
  {
    id: "north-korean",
    name: "North Korean State Actors",
    icon: "🇰🇵",
    color: "#a855f7",
    description: "RGB and affiliated DPRK cyber operations",
    actors: [
      { 
        name: "Lazarus Group", 
        aliases: ["HIDDEN COBRA", "Zinc", "Diamond Sleet"], 
        origin: "DPRK (RGB)", 
        type: "State", 
        targets: ["Finance", "Crypto", "Defense"], 
        description: "Sony hack, WannaCry, $2B+ crypto theft.",
        notableCampaigns: ["WannaCry Ransomware", "Sony Pictures Hack", "Harmony Bridge Theft"],
        ttps: ["SMB Exploits", "Man-in-the-Middle", "Trojanized Applications"]
      },
      { 
        name: "APT38", 
        aliases: ["BlueNoroff", "Stardust Chollima"], 
        origin: "DPRK (RGB)", 
        type: "State", 
        targets: ["Banks", "SWIFT"], 
        description: "Financial theft unit, Bangladesh Bank heist.",
        notableCampaigns: ["Bangladesh Bank Heist", "ATM Cashouts"],
        ttps: ["SWIFT Manipulation", "File Deletion (Wiping)", "Custom Malware"]
      },
      { name: "Kimsuky", aliases: ["Velvet Chollima", "Emerald Sleet", "APT43"], origin: "DPRK (RGB)", type: "State", targets: ["Think Tanks", "Nuclear"], description: "Intelligence gathering on foreign policy" },
      { name: "Andariel", aliases: ["Silent Chollima", "Onyx Sleet"], origin: "DPRK (RGB)", type: "State", targets: ["Defense", "Aerospace"], description: "Defense sector espionage and ransomware" },
      { name: "Bureau 121", aliases: [], origin: "DPRK", type: "State", targets: ["South Korea", "US"], description: "Primary cyber warfare unit, 6000+ operators" },
      { name: "ScarCruft", aliases: ["APT37", "Reaper", "Ruby Sleet"], origin: "DPRK", type: "State", targets: ["South Korea", "Japan"], description: "Regional espionage operations" },
    ],
  },
  {
    id: "iranian",
    name: "Iranian State Actors",
    icon: "🇮🇷",
    color: "#f59e0b",
    description: "IRGC and MOIS affiliated cyber operations",
    actors: [
      { 
        name: "APT33", 
        aliases: ["Elfin", "Refined Kitten", "Peach Sandstorm"], 
        origin: "Iran (IRGC)", 
        type: "State", 
        targets: ["Aviation", "Energy", "Saudi"], 
        description: "Shamoon destructive attacks, aerospace espionage.",
        notableCampaigns: ["Shamoon 2.0", "StoneDrill"],
        ttps: ["Disk Wipers", "Password Spraying", "Web Shells"]
      },
      { name: "APT34", aliases: ["OilRig", "Helix Kitten", "Hazel Sandstorm"], origin: "Iran (MOIS)", type: "Intelligence", targets: ["Middle East", "Finance"], description: "Middle Eastern government and financial sector" },
      { name: "APT35", aliases: ["Charming Kitten", "Phosphorus", "Mint Sandstorm"], origin: "Iran (IRGC)", type: "State", targets: ["Dissidents", "Media", "US"], description: "Social engineering, journalist targeting" },
      { name: "APT39", aliases: ["Chafer", "Cotton Sandstorm"], origin: "Iran (MOIS)", type: "Intelligence", targets: ["Telecom", "Travel"], description: "Telecom and travel industry surveillance" },
      { name: "MuddyWater", aliases: ["Mercury", "Mango Sandstorm"], origin: "Iran (MOIS)", type: "Intelligence", targets: ["Middle East", "Asia"], description: "Government and telecom espionage" },
      { name: "CyberAv3ngers", aliases: [], origin: "Iran (IRGC)", type: "Hacktivist", targets: ["Israel", "US Infrastructure"], description: "ICS/SCADA attacks, water utility compromises" },
      { name: "Tortoiseshell", aliases: ["Imperial Kitten", "Crimson Sandstorm"], origin: "Iran", type: "State", targets: ["Defense", "IT"], description: "Supply chain and IT provider targeting" },
    ],
  },
  {
    id: "cybercrime",
    name: "Cybercriminal Organizations",
    icon: "💀",
    color: "#6366f1",
    description: "Financially motivated ransomware and eCrime groups",
    actors: [
      { 
        name: "LockBit", 
        aliases: ["LockBit 3.0", "LockBit Black"], 
        origin: "Russia-linked", 
        type: "Ransomware", 
        targets: ["Global", "Healthcare", "Government"], 
        description: "Largest RaaS operation 2022-2024, disrupted Feb 2024.",
        notableCampaigns: ["Royal Mail", "Boeing", "ICBC"],
        ttps: ["Double Extortion", "Affiliate Model", "Stealbit"]
      },
      { 
        name: "BlackCat/ALPHV", 
        aliases: ["Noberus"], 
        origin: "Russia-linked", 
        type: "Ransomware", 
        targets: ["Healthcare", "Finance"], 
        description: "Rust-based ransomware, Change Healthcare attack.",
        notableCampaigns: ["Change Healthcare", "MGM Resorts"],
        ttps: ["Rust Payload", "Triple Extortion", "Access Brokers"]
      },
      { 
        name: "Cl0p", 
        aliases: ["TA505", "FIN11"], 
        origin: "Russia-linked", 
        type: "Ransomware", 
        targets: ["File Transfer"], 
        description: "MOVEit, GoAnywhere mass exploitation campaigns.",
        notableCampaigns: ["MOVEit Transfer", "GoAnywhere MFT", "Accellion"],
        ttps: ["Zero-day Exploitation", "Mass Extortion", "Web Shells"]
      },
      { 
        name: "Scattered Spider", 
        aliases: ["Octo Tempest", "UNC3944", "0ktapus"], 
        origin: "US/UK", 
        type: "eCrime", 
        targets: ["Telecom", "Tech", "Casinos"], 
        description: "Social engineering experts, MGM/Caesars attacks.",
        notableCampaigns: ["MGM Resorts", "Caesars Entertainment", "Okta"],
        ttps: ["SIM Swapping", "Help Desk Social Engineering", "BYOVD"]
      },
      { name: "FIN7", aliases: ["Carbanak", "Carbon Spider"], origin: "Russia", type: "eCrime", targets: ["Retail", "Hospitality"], description: "Carbanak banking trojan, point-of-sale malware" },
      { name: "Evil Corp", aliases: ["Indrik Spider", "Dridex"], origin: "Russia", type: "eCrime", targets: ["Finance", "Global"], description: "Dridex, WastedLocker, sanctioned by US Treasury" },
      { name: "REvil", aliases: ["Sodinokibi", "Pinchy Spider"], origin: "Russia", type: "Ransomware", targets: ["MSPs", "Supply Chain"], description: "Kaseya attack, $70M ransom demands, disrupted 2022" },
      { name: "Conti", aliases: ["Wizard Spider"], origin: "Russia", type: "Ransomware", targets: ["Healthcare", "Government"], description: "$180M+ extorted, disbanded after Ukraine leaks 2022" },
      { name: "Black Basta", aliases: [], origin: "Russia-linked", type: "Ransomware", targets: ["Manufacturing", "Tech"], description: "Former Conti members, emerged 2022" },
      { name: "Play", aliases: ["PlayCrypt"], origin: "Unknown", type: "Ransomware", targets: ["Latin America", "Global"], description: "Double extortion, emerged 2022" },
      { name: "8Base", aliases: [], origin: "Unknown", type: "Ransomware", targets: ["SMBs"], description: "SMB-focused ransomware operation" },
      { name: "Akira", aliases: [], origin: "Unknown", type: "Ransomware", targets: ["Education", "Finance"], description: "Emerged 2023, Linux variant" },
      { name: "Rhysida", aliases: [], origin: "Unknown", type: "Ransomware", targets: ["Healthcare", "Education"], description: "British Library attack, emerged 2023" },
    ],
  },
  {
    id: "other-state",
    name: "Other State Actors",
    icon: "🌍",
    color: "#10b981",
    description: "Other nation-state cyber operations",
    actors: [
      { name: "APT32", aliases: ["OceanLotus", "SeaLotus", "Canvas Cyclone"], origin: "Vietnam", type: "State", targets: ["ASEAN", "Dissidents", "Automotive"], description: "Vietnamese state espionage, regional focus" },
      { name: "Domestic Kitten", aliases: ["APT-C-50"], origin: "Iran", type: "State", targets: ["Dissidents", "Kurds"], description: "Surveillance of Iranian diaspora" },
      { name: "SideWinder", aliases: ["Rattlesnake", "APT-Q-39"], origin: "India", type: "State", targets: ["Pakistan", "China", "Nepal"], description: "South Asian regional espionage" },
      { name: "Bitter", aliases: ["APT-Q-37", "T-APT-17"], origin: "India", type: "State", targets: ["Pakistan", "Bangladesh"], description: "South Asian government targeting" },
      { name: "Dark Basin", aliases: ["BellTroX"], origin: "India", type: "Hack-for-Hire", targets: ["Global"], description: "Indian hack-for-hire targeting journalists, activists" },
      { name: "Polonium", aliases: [], origin: "Lebanon", type: "State", targets: ["Israel"], description: "Lebanese targeting of Israeli organizations" },
      { name: "Agrius", aliases: ["DEV-0227", "Pink Sandstorm"], origin: "Iran", type: "State", targets: ["Israel"], description: "Destructive operations against Israel" },
    ],
  },
  {
    id: "hacktivism",
    name: "Hacktivist Groups",
    icon: "✊",
    color: "#ec4899",
    description: "Politically motivated hacking collectives",
    actors: [
      { name: "Anonymous", aliases: [], origin: "Global", type: "Hacktivist", targets: ["Various"], description: "Decentralized collective, anti-Russia ops post-Ukraine" },
      { name: "IT Army of Ukraine", aliases: [], origin: "Ukraine", type: "Hacktivist", targets: ["Russia"], description: "Volunteer DDoS and hack operations against Russia" },
      { name: "Killnet", aliases: [], origin: "Russia", type: "Hacktivist", targets: ["NATO", "Ukraine Allies"], description: "Pro-Russian DDoS attacks on Western targets" },
      { name: "NoName057(16)", aliases: [], origin: "Russia", type: "Hacktivist", targets: ["NATO", "EU"], description: "Pro-Russian DDoS attacks, DDoSia tool" },
      { name: "Anonymous Sudan", aliases: [], origin: "Russia-linked", type: "Hacktivist", targets: ["US", "NATO"], description: "Likely Russian false flag, major DDoS campaigns" },
      { name: "GhostSec", aliases: [], origin: "Global", type: "Hacktivist", targets: ["ISIS", "Russia"], description: "Counter-terrorism, anti-Russia operations" },
      { name: "SiegedSec", aliases: [], origin: "Unknown", type: "Hacktivist", targets: ["Government"], description: "NATO, US government data leaks" },
    ],
  },
];

// CTI Methodology sections
const ctiMethodology = [
  {
    title: "Intelligence Lifecycle",
    icon: "🔄",
    color: "#3b82f6",
    steps: [
      "Planning & Direction - Define intelligence requirements (PIRs)",
      "Collection - Gather data from sources (OSINT, HUMINT, SIGINT, technical)",
      "Processing - Convert raw data into usable format",
      "Analysis - Evaluate, correlate, interpret information",
      "Dissemination - Distribute finished intelligence to stakeholders",
      "Feedback - Assess value and refine requirements",
    ],
  },
  {
    title: "Attribution Framework",
    icon: "🎯",
    color: "#ef4444",
    steps: [
      "Infrastructure Analysis - Domains, IPs, hosting patterns",
      "Malware Analysis - Code similarities, compiler artifacts, language",
      "TTPs - Tactics, techniques mapped to MITRE ATT&CK",
      "Victimology - Target selection patterns and motivations",
      "Operational Security - Mistakes revealing origin",
      "Geopolitical Context - Cui bono? Who benefits?",
    ],
  },
  {
    title: "Indicator Types (Pyramid of Pain)",
    icon: "📊",
    color: "#f59e0b",
    steps: [
      "Hash Values (Trivial) - File hashes, easily changed",
      "IP Addresses (Easy) - C2 servers, proxies",
      "Domain Names (Simple) - Attacker infrastructure",
      "Network/Host Artifacts (Annoying) - User-agents, registry keys",
      "Tools (Challenging) - Custom malware, exploit kits",
      "TTPs (Tough!) - Behavioral patterns, hardest to change",
    ],
  },
  {
    title: "Intelligence Sources",
    icon: "📡",
    color: "#8b5cf6",
    steps: [
      "OSINT - Social media, paste sites, forums, news",
      "Commercial Feeds - Recorded Future, Mandiant, CrowdStrike",
      "Government Sharing - CISA, FBI, NCSC advisories",
      "ISACs - Industry-specific sharing communities",
      "Dark Web - Forums, markets, ransomware blogs",
      "Internal Telemetry - Logs, alerts, incident data",
    ],
  },
];

const tlpLevels = [
  { level: "TLP:RED", color: "#dc2626", desc: "Not for disclosure, restricted to participants only." },
  { level: "TLP:AMBER", color: "#f59e0b", desc: "Limited disclosure, restricted to organization and clients." },
  { level: "TLP:AMBER+STRICT", color: "#d97706", desc: "Restricted to organization only." },
  { level: "TLP:GREEN", color: "#10b981", desc: "Limited disclosure, community wide." },
  { level: "TLP:CLEAR", color: "#9ca3af", desc: "Unlimited disclosure, public information." },
];

const biases = [
  { name: "Confirmation Bias", desc: "Seeking information that supports pre-existing beliefs." },
  { name: "Anchoring", desc: "Relying too heavily on the first piece of information offered." },
  { name: "Mirror Imaging", desc: "Assuming the adversary thinks and acts like you do." },
  { name: "Availability Heuristic", desc: "Overestimating the importance of information that is easy to recall." },
];

// Tracking methodology
const trackingMethods = [
  { method: "Infrastructure Tracking", description: "Monitor domain registrations, SSL certificates, IP ranges, hosting patterns", tools: "PassiveTotal, DomainTools, Shodan, Censys" },
  { method: "Malware Tracking", description: "Track malware families, code evolution, C2 protocols", tools: "VirusTotal, MalwareBazaar, Any.Run, Joe Sandbox" },
  { method: "Campaign Tracking", description: "Monitor active campaigns, victimology, phishing infrastructure", tools: "PhishTank, URLhaus, MISP, OpenCTI" },
  { method: "Actor Tracking", description: "Build profiles on threat actors, TTPs, tooling preferences", tools: "MITRE ATT&CK, Threat Actor Libraries, MISP Galaxies" },
  { method: "Vulnerability Tracking", description: "Track exploitation of CVEs, PoC releases, in-the-wild exploitation", tools: "VulnDB, KEV Catalog, Exploit-DB, NVD" },
  { method: "Underground Monitoring", description: "Monitor dark web forums, ransomware blogs, leak sites", tools: "Tor, Flare, DarkOwl, Intel471" },
];

const pivotTechniques = [
  { name: "Email Address", pivots: ["Domain Registration", "Social Media", "GitHub/Forums", "Breach Data"] },
  { name: "IP Address", pivots: ["Passive DNS (Domains)", "SSL Certificates", "Open Ports/Services", "Geo-location"] },
  { name: "Domain Name", pivots: ["Whois Data", "Subdomains", "Associated Emails", "File Downloads"] },
  { name: "SSL Certificate", pivots: ["Subject/Issuer Name", "Serial Number", "JARM Fingerprint", "Other Domains"] },
  { name: "Malware Hash", pivots: ["Imphash", "Rich Header", "String Reuse", "Compilation Time"] },
];

export default function CyberThreatIntelPage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [selectedCategory, setSelectedCategory] = useState(0);
  const [searchQuery, setSearchQuery] = useState("");
  const [tabValue, setTabValue] = useState(0);

  const filteredActors = useMemo(() => {
    if (!searchQuery.trim()) return actorCategories[selectedCategory].actors;
    const query = searchQuery.toLowerCase();
    return actorCategories[selectedCategory].actors.filter(
      (a) =>
        a.name.toLowerCase().includes(query) ||
        a.aliases.some((al) => al.toLowerCase().includes(query)) ||
        a.origin.toLowerCase().includes(query) ||
        a.description.toLowerCase().includes(query)
    );
  }, [selectedCategory, searchQuery]);

  const allActors = useMemo(() => {
    return actorCategories.flatMap((c) => c.actors);
  }, []);

  const globalSearch = useMemo(() => {
    if (!searchQuery.trim()) return [];
    const query = searchQuery.toLowerCase();
    return allActors.filter(
      (a) =>
        a.name.toLowerCase().includes(query) ||
        a.aliases.some((al) => al.toLowerCase().includes(query)) ||
        a.origin.toLowerCase().includes(query)
    );
  }, [searchQuery, allActors]);

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Back Button */}
      <IconButton onClick={() => navigate("/learn")} sx={{ mb: 2 }}>
        <ArrowBackIcon />
      </IconButton>

      {/* Header */}
      <Box sx={{ mb: 5 }}>
        <Typography
          variant="h3"
          sx={{
            fontWeight: 800,
            mb: 2,
            background: `linear-gradient(135deg, #dc2626, #f59e0b, #3b82f6)`,
            backgroundClip: "text",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}
        >
          🕵️ Cyber Threat Intelligence
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 900 }}>
          Understanding threat actors, attribution methods, and intelligence tradecraft for defensive and offensive security operations.
        </Typography>
      </Box>

      {/* Main Tabs */}
      <Tabs value={tabValue} onChange={(_, v) => setTabValue(v)} sx={{ mb: 4 }}>
        <Tab label="🎭 Threat Actors" />
        <Tab label="🔬 CTI Methodology" />
        <Tab label="📡 Tracking & Tools" />
      </Tabs>

      {/* TAB 0: Threat Actors */}
      {tabValue === 0 && (
        <>
          {/* Stats */}
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3, background: `linear-gradient(135deg, ${alpha("#dc2626", 0.05)}, ${alpha("#3b82f6", 0.05)})` }}>
            <Grid container spacing={3} justifyContent="center">
              <Grid item xs={6} sm={3}>
                <Box sx={{ textAlign: "center" }}>
                  <Typography variant="h4" sx={{ fontWeight: 800, color: "error.main" }}>{allActors.length}+</Typography>
                  <Typography variant="body2" color="text.secondary">Threat Actors</Typography>
                </Box>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Box sx={{ textAlign: "center" }}>
                  <Typography variant="h4" sx={{ fontWeight: 800, color: "warning.main" }}>{actorCategories.length}</Typography>
                  <Typography variant="body2" color="text.secondary">Categories</Typography>
                </Box>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Box sx={{ textAlign: "center" }}>
                  <Typography variant="h4" sx={{ fontWeight: 800, color: "info.main" }}>15+</Typography>
                  <Typography variant="body2" color="text.secondary">Nations</Typography>
                </Box>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Box sx={{ textAlign: "center" }}>
                  <Typography variant="h4" sx={{ fontWeight: 800, color: "success.main" }}>2024</Typography>
                  <Typography variant="body2" color="text.secondary">Updated</Typography>
                </Box>
              </Grid>
            </Grid>
          </Paper>

          {/* Search */}
          <TextField
            fullWidth
            size="small"
            placeholder="Search actors, aliases, origins..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            InputProps={{
              startAdornment: <InputAdornment position="start"><SearchIcon color="action" /></InputAdornment>,
            }}
            sx={{ mb: 3, maxWidth: 500 }}
          />

          {/* Global Search Results */}
          {searchQuery.trim() && globalSearch.length > 0 && (
            <Alert severity="info" sx={{ mb: 3 }}>
              Found {globalSearch.length} actors matching "{searchQuery}" across all categories
            </Alert>
          )}

          {/* Category Cards */}
          <Box sx={{ display: "flex", overflowX: "auto", gap: 1.5, mb: 4, pb: 2 }}>
            {actorCategories.map((cat, index) => (
              <Card
                key={cat.id}
                onClick={() => { setSelectedCategory(index); setSearchQuery(""); }}
                sx={{
                  minWidth: 130,
                  flexShrink: 0,
                  cursor: "pointer",
                  border: `2px solid ${selectedCategory === index ? cat.color : "transparent"}`,
                  bgcolor: selectedCategory === index ? alpha(cat.color, 0.1) : "background.paper",
                  transition: "all 0.2s",
                  "&:hover": { bgcolor: alpha(cat.color, 0.05), transform: "translateY(-2px)" },
                }}
              >
                <CardContent sx={{ textAlign: "center", p: 2, "&:last-child": { pb: 2 } }}>
                  <Typography variant="h5" sx={{ mb: 0.5 }}>{cat.icon}</Typography>
                  <Typography variant="caption" sx={{ fontWeight: 600, color: cat.color, display: "block", fontSize: "0.7rem" }}>
                    {cat.name.split(" ")[0]}
                  </Typography>
                  <Typography variant="caption" color="text.disabled" sx={{ fontSize: "0.65rem" }}>
                    {cat.actors.length} actors
                  </Typography>
                </CardContent>
              </Card>
            ))}
          </Box>

          {/* Selected Category Detail */}
          <Paper sx={{ mb: 4, borderRadius: 3, overflow: "hidden" }}>
            <Box sx={{ p: 3, bgcolor: alpha(actorCategories[selectedCategory].color, 0.05), borderBottom: `3px solid ${actorCategories[selectedCategory].color}` }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                <Typography variant="h4">{actorCategories[selectedCategory].icon}</Typography>
                <Typography variant="h5" sx={{ fontWeight: 700 }}>{actorCategories[selectedCategory].name}</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary">{actorCategories[selectedCategory].description}</Typography>
            </Box>

            {/* Actor List */}
            <Box sx={{ p: 3 }}>
              {filteredActors.length === 0 ? (
                <Alert severity="info">No actors match your search.</Alert>
              ) : (
                <Grid container spacing={2}>
                  {filteredActors.map((actor) => (
                    <Grid item xs={12} md={6} key={actor.name}>
                      <Paper
                        sx={{
                          p: 2,
                          height: "100%",
                          border: `1px solid ${alpha(actorCategories[selectedCategory].color, 0.2)}`,
                          transition: "all 0.2s",
                          "&:hover": { borderColor: actorCategories[selectedCategory].color, bgcolor: alpha(actorCategories[selectedCategory].color, 0.02) },
                        }}
                      >
                        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                          <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{actor.name}</Typography>
                          <Chip label={actor.type} size="small" sx={{ fontSize: "0.65rem", bgcolor: alpha(actorCategories[selectedCategory].color, 0.1), color: actorCategories[selectedCategory].color }} />
                        </Box>
                        {actor.aliases.length > 0 && (
                          <Typography variant="caption" color="text.disabled" sx={{ display: "block", mb: 1 }}>
                            aka: {actor.aliases.slice(0, 3).join(", ")}{actor.aliases.length > 3 ? "..." : ""}
                          </Typography>
                        )}
                        <Box sx={{ display: "flex", gap: 0.5, mb: 1, flexWrap: "wrap" }}>
                          <Chip label={actor.origin} size="small" variant="outlined" sx={{ fontSize: "0.6rem", height: 20 }} />
                          {actor.targets.slice(0, 2).map((t) => (
                            <Chip key={t} label={t} size="small" variant="outlined" sx={{ fontSize: "0.6rem", height: 20 }} />
                          ))}
                        </Box>
                        <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem", lineHeight: 1.5 }}>
                          {actor.description}
                        </Typography>
                        {actor.notableCampaigns && (
                          <Box sx={{ mt: 1.5 }}>
                            <Typography variant="caption" sx={{ fontWeight: 700, display: "block", fontSize: "0.7rem", color: "text.primary" }}>Notable Campaigns:</Typography>
                            <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.7rem" }}>{actor.notableCampaigns.join(", ")}</Typography>
                          </Box>
                        )}
                        {actor.ttps && (
                          <Box sx={{ mt: 1 }}>
                            <Typography variant="caption" sx={{ fontWeight: 700, display: "block", fontSize: "0.7rem", color: "text.primary" }}>Key TTPs:</Typography>
                            <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.7rem" }}>{actor.ttps.join(", ")}</Typography>
                          </Box>
                        )}
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              )}
            </Box>
          </Paper>
        </>
      )}

      {/* TAB 1: CTI Methodology */}
      {tabValue === 1 && (
        <>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🔬 CTI Methodology & Frameworks</Typography>

          <Grid container spacing={3} sx={{ mb: 4 }}>
            {ctiMethodology.map((section) => (
              <Grid item xs={12} md={6} key={section.title}>
                <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha(section.color, 0.2)}` }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                    <Typography variant="h4">{section.icon}</Typography>
                    <Typography variant="h6" sx={{ fontWeight: 700 }}>{section.title}</Typography>
                  </Box>
                  {section.steps.map((step, i) => (
                    <Box key={i} sx={{ display: "flex", gap: 1.5, mb: 1.5 }}>
                      <Typography variant="body2" sx={{ color: section.color, fontWeight: 700, minWidth: 20 }}>{i + 1}.</Typography>
                      <Typography variant="body2" color="text.secondary">{step}</Typography>
                    </Box>
                  ))}
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* Diamond Model */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>💎 Diamond Model of Intrusion Analysis</Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Box sx={{ textAlign: "center", mb: 3 }}>
                  <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
                    Four core features connected by relationships:
                  </Typography>
                  <Box sx={{ display: "flex", justifyContent: "center", gap: 3, flexWrap: "wrap" }}>
                    {[
                      { label: "Adversary", color: "#ef4444", desc: "Threat actor" },
                      { label: "Infrastructure", color: "#f59e0b", desc: "C2, domains, IPs" },
                      { label: "Capability", color: "#3b82f6", desc: "Tools, malware" },
                      { label: "Victim", color: "#10b981", desc: "Target org/system" },
                    ].map((node) => (
                      <Box key={node.label} sx={{ textAlign: "center" }}>
                        <Box sx={{ width: 80, height: 80, borderRadius: 2, bgcolor: alpha(node.color, 0.1), border: `2px solid ${node.color}`, display: "flex", alignItems: "center", justifyContent: "center", mb: 1 }}>
                          <Typography variant="body2" sx={{ fontWeight: 700, color: node.color }}>{node.label}</Typography>
                        </Box>
                        <Typography variant="caption" color="text.secondary">{node.desc}</Typography>
                      </Box>
                    ))}
                  </Box>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Meta-Features</Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  {[
                    "Timestamp - When activity occurred",
                    "Phase - Kill chain stage",
                    "Result - Success/failure",
                    "Direction - Adversary→Victim or bidirectional",
                    "Methodology - How capability was deployed",
                    "Resources - What adversary needed",
                  ].map((meta) => (
                    <Typography key={meta} variant="body2" color="text.secondary">• {meta}</Typography>
                  ))}
                </Box>
              </Grid>
            </Grid>
          </Paper>

          {/* STIX/TAXII */}
          <Paper sx={{ p: 4, borderRadius: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>📋 STIX & TAXII Standards</Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>STIX (Structured Threat Information eXpression)</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Standardized language for describing cyber threat information:
                </Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                  {["Attack Pattern", "Campaign", "Course of Action", "Identity", "Indicator", "Intrusion Set", "Malware", "Observed Data", "Report", "Threat Actor", "Tool", "Vulnerability"].map((obj) => (
                    <Chip key={obj} label={obj} size="small" sx={{ fontSize: "0.65rem" }} />
                  ))}
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>TAXII (Trusted Automated eXchange of Intelligence Information)</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Transport protocol for exchanging STIX data:
                </Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                  {[
                    "Collections - Sets of CTI objects",
                    "Channels - Publish/subscribe feeds",
                    "API Roots - Service endpoints",
                  ].map((item) => (
                    <Typography key={item} variant="body2" color="text.secondary">• {item}</Typography>
                  ))}
                </Box>
              </Grid>
            </Grid>
          </Paper>

          {/* TLP & Biases */}
          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🚦 Traffic Light Protocol (TLP)</Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                  {tlpLevels.map((tlp) => (
                    <Box key={tlp.level} sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <Chip label={tlp.level} size="small" sx={{ bgcolor: tlp.color, color: tlp.level === "TLP:CLEAR" ? "black" : "white", fontWeight: 700, minWidth: 100 }} />
                      <Typography variant="caption" color="text.secondary">{tlp.desc}</Typography>
                    </Box>
                  ))}
                </Box>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🧠 Cognitive Biases in Analysis</Typography>
                <Box sx={{ display: "flex", flexDirection: "column", gap: 1.5 }}>
                  {biases.map((bias) => (
                    <Box key={bias.name}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "error.main" }}>{bias.name}</Typography>
                      <Typography variant="caption" color="text.secondary">{bias.desc}</Typography>
                    </Box>
                  ))}
                </Box>
              </Paper>
            </Grid>
          </Grid>
        </>
      )}

      {/* TAB 2: Tracking & Tools */}
      {tabValue === 2 && (
        <>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>📡 Tracking Methods & Tools</Typography>

          {/* Tracking Methods Table */}
          <TableContainer component={Paper} sx={{ mb: 4, borderRadius: 3 }}>
            <Table>
              <TableHead>
                <TableRow sx={{ bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Method</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Tools</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {trackingMethods.map((row) => (
                  <TableRow key={row.method}>
                    <TableCell sx={{ fontWeight: 600 }}>{row.method}</TableCell>
                    <TableCell>{row.description}</TableCell>
                    <TableCell>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                        {row.tools.split(", ").map((tool) => (
                          <Chip key={tool} label={tool} size="small" variant="outlined" sx={{ fontSize: "0.65rem" }} />
                        ))}
                      </Box>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          {/* Pivot Searching */}
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🔍 Pivot Searching Techniques</Typography>
            <Grid container spacing={2}>
              {pivotTechniques.map((tech) => (
                <Grid item xs={12} sm={6} md={4} key={tech.name}>
                  <Box sx={{ p: 2, border: "1px solid", borderColor: "divider", borderRadius: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "primary.main", mb: 1 }}>{tech.name}</Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {tech.pivots.map((p) => (
                        <Chip key={p} label={p} size="small" sx={{ fontSize: "0.65rem" }} />
                      ))}
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Key Platforms */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>🛠️ CTI Platforms & Resources</Typography>
          <Grid container spacing={2}>
            {[
              { name: "MISP", url: "https://www.misp-project.org/", desc: "Open source threat intelligence platform" },
              { name: "OpenCTI", url: "https://www.opencti.io/", desc: "Open cyber threat intelligence platform" },
              { name: "MITRE ATT&CK", url: "https://attack.mitre.org/", desc: "Adversary TTPs knowledge base" },
              { name: "VirusTotal", url: "https://www.virustotal.com/", desc: "Malware and URL analysis" },
              { name: "Shodan", url: "https://www.shodan.io/", desc: "Internet-connected device search" },
              { name: "Censys", url: "https://censys.io/", desc: "Internet-wide scanning and data" },
              { name: "URLhaus", url: "https://urlhaus.abuse.ch/", desc: "Malicious URL tracking" },
              { name: "MalwareBazaar", url: "https://bazaar.abuse.ch/", desc: "Malware sample sharing" },
              { name: "AlienVault OTX", url: "https://otx.alienvault.com/", desc: "Open threat exchange" },
              { name: "Recorded Future", url: "https://www.recordedfuture.com/", desc: "Commercial threat intelligence" },
              { name: "Mandiant", url: "https://www.mandiant.com/", desc: "Threat research and IR" },
              { name: "CrowdStrike Falcon", url: "https://www.crowdstrike.com/", desc: "Threat intelligence and EDR" },
            ].map((platform) => (
              <Grid item xs={12} sm={6} md={4} key={platform.name}>
                <Link href={platform.url} target="_blank" rel="noopener" underline="none">
                  <Paper sx={{ p: 2, height: "100%", transition: "all 0.2s", "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05) } }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "primary.main" }}>{platform.name}</Typography>
                      <LaunchIcon fontSize="small" color="action" sx={{ fontSize: 14 }} />
                    </Box>
                    <Typography variant="caption" color="text.secondary">{platform.desc}</Typography>
                  </Paper>
                </Link>
              </Grid>
            ))}
          </Grid>

          {/* Government Resources */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 3 }}>🏛️ Government CTI Resources</Typography>
          <Grid container spacing={2}>
            {[
              { name: "CISA Known Exploited Vulnerabilities", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", country: "🇺🇸" },
              { name: "FBI IC3", url: "https://www.ic3.gov/", country: "🇺🇸" },
              { name: "NCSC UK Advisories", url: "https://www.ncsc.gov.uk/section/keep-up-to-date/threat-reports", country: "🇬🇧" },
              { name: "ANSSI France", url: "https://www.cert.ssi.gouv.fr/", country: "🇫🇷" },
              { name: "BSI Germany", url: "https://www.bsi.bund.de/", country: "🇩🇪" },
              { name: "ACSC Australia", url: "https://www.cyber.gov.au/", country: "🇦🇺" },
            ].map((resource) => (
              <Grid item xs={12} sm={6} md={4} key={resource.name}>
                <Link href={resource.url} target="_blank" rel="noopener" underline="none">
                  <Paper sx={{ p: 2, transition: "all 0.2s", "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05) } }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <Typography variant="body1">{resource.country}</Typography>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>{resource.name}</Typography>
                      <LaunchIcon fontSize="small" color="action" sx={{ fontSize: 14, ml: "auto" }} />
                    </Box>
                  </Paper>
                </Link>
              </Grid>
            ))}
          </Grid>
        </>
      )}
    </Container>
  );
}
