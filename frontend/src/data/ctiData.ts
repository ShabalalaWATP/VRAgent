export interface ThreatActor {
  name: string;
  aliases: string[];
  origin: string;
  type: string;
  targets: string[];
  description: string;
  notableCampaigns?: string[];
  ttps?: string[];
  tools?: string[];
}

export interface ActorCategory {
  id: string;
  name: string;
  icon: string;
  color: string;
  description: string;
  actors: ThreatActor[];
}

// Organized by allegiance/type
export const actorCategories: ActorCategory[] = [
  {
    id: "western-govt",
    name: "Western Government & Allied",
    icon: "🏛️",
    color: "#3b82f6",
    description: "Intelligence agencies and cyber commands from NATO/Five Eyes nations",
    actors: [
      { 
        name: "Equation Group", 
        aliases: ["EQGRP", "Longhorn", "Tilded Team"], 
        origin: "USA (NSA/TAO)", 
        type: "Intelligence", 
        targets: ["Global Governments", "Telecom", "Encryption", "Energy"], 
        description: "NSA's elite hacking unit, creators of Stuxnet components. Known for extremely sophisticated implants and zero-days.",
        notableCampaigns: ["Stuxnet (Centrifuges)", "Duqu", "Flame", "Fanny"],
        ttps: ["Zero-day exploits", "Firmware persistence", "Air-gap jumping", "Encrypted payloads"],
        tools: ["EternalBlue", "DoublePulsar", "FuzzBunch", "DanderSpritz", "Groks"]
      },
      { 
        name: "Tailored Access Operations (TAO)", 
        aliases: ["Office of TAO", "S32"], 
        origin: "USA (NSA)", 
        type: "Intelligence", 
        targets: ["Global"], 
        description: "NSA's offensive cyber operations unit. Specializes in interdiction and hardware implants.",
        notableCampaigns: ["Shadow Brokers Leaks (Victim)", "Quantum Insert", "Operation Shotgiant"],
        ttps: ["Supply chain interdiction", "Hardware implants", "QUANTUM suite", "Man-on-the-side"],
        tools: ["FOXACID", "QUANTUMINSERT", "JETPLOW", "HEADWATER"]
      },
      { 
        name: "CIA Special Activities Center", 
        aliases: ["SAC", "Vault 7", "Center for Cyber Intelligence (CCI)"], 
        origin: "USA (CIA)", 
        type: "Intelligence", 
        targets: ["Global", "Counter-Terrorism"], 
        description: "CIA's covert cyber operations division. Focused on physical access and close-access operations.",
        notableCampaigns: ["Vault 7 Leaks", "Weeping Angel"],
        ttps: ["Physical Access", "USB Exfiltration", "Smart TV Compromise"],
        tools: ["Marble Framework", "Weeping Angel", "AfterMidnight", "Hive"]
      },
      { 
        name: "USCYBERCOM", 
        aliases: ["Cyber National Mission Force (CNMF)"], 
        origin: "USA", 
        type: "Military", 
        targets: ["State Actors", "Ransomware Groups"], 
        description: "Unified combatant command for cyberspace operations. Conducts 'Hunt Forward' operations.",
        notableCampaigns: ["Operation Glowing Symphony (ISIS)", "Hunt Forward Missions (Ukraine, etc.)"],
        ttps: ["Defend Forward", "Persistent Engagement", "Infrastructure Disruption"],
        tools: ["Classified Military Cyber Tools"]
      },
      { 
        name: "National Cyber Force (NCF)", 
        aliases: [], 
        origin: "UK (GCHQ/MOD)", 
        type: "Military/Intelligence", 
        targets: ["State Actors", "Terrorists", "Serious Crime"], 
        description: "UK's offensive cyber capability, joint GCHQ-MOD partnership.",
        notableCampaigns: ["Counter-Disinformation", "Counter-Terrorism Ops"],
        ttps: ["CNE (Computer Network Exploitation)", "CNA (Computer Network Attack)"],
        tools: ["GCHQ Toolset"]
      },
      { 
        name: "GCHQ", 
        aliases: ["Government Communications HQ"], 
        origin: "UK", 
        type: "Intelligence", 
        targets: ["Global"], 
        description: "UK signals intelligence and cyber security agency. Close partner of NSA.",
        notableCampaigns: ["Operation Socialist (Belgacom)", "Karma Police", "Tempora"],
        ttps: ["Quantum Insert", "Cable Tapping", "CNE", "Traffic Analysis"],
        tools: ["Smurf Suite", "Hacienda", "Tempora"]
      },
      { 
        name: "DGSE", 
        aliases: ["Direction Générale de la Sécurité Extérieure"], 
        origin: "France", 
        type: "Intelligence", 
        targets: ["Global", "Africa", "Middle East"], 
        description: "French external intelligence service. Active in economic and political espionage.",
        notableCampaigns: ["Animal Farm (suspected)", "Babar", "Casper"],
        ttps: ["Custom Malware", "Spearphishing"],
        tools: ["Babar", "Casper", "Dino"]
      },
      { name: "BND", aliases: ["Bundesnachrichtendienst"], origin: "Germany", type: "Intelligence", targets: ["Global"], description: "German federal intelligence service. Focus on SIGINT and foreign intelligence." },
      { name: "CSE", aliases: ["Communications Security Establishment"], origin: "Canada", type: "Intelligence", targets: ["Global"], description: "Canada's signals intelligence agency. Five Eyes member." },
      { name: "ASD", aliases: ["Australian Signals Directorate"], origin: "Australia", type: "Intelligence", targets: ["Asia-Pacific"], description: "Australia's signals intelligence and cyber security agency. Five Eyes member." },
      { name: "GCSB", aliases: ["Government Communications Security Bureau"], origin: "New Zealand", type: "Intelligence", targets: ["Asia-Pacific"], description: "New Zealand's signals intelligence agency. Five Eyes member." },
      { 
        name: "Unit 8200", 
        aliases: [], 
        origin: "Israel (IDF)", 
        type: "Military Intelligence", 
        targets: ["Middle East"], 
        description: "Israeli signals intelligence unit, elite cyber capabilities. Comparable to NSA.",
        notableCampaigns: ["Stuxnet (Joint)", "Duqu 2.0", "Olympic Games"],
        ttps: ["Advanced Malware", "Supply Chain", "Zero-days", "Signal Interception"],
        tools: ["Duqu 2.0", "Gauss", "Flame"]
      },
      { 
        name: "Mossad", 
        aliases: [], 
        origin: "Israel", 
        type: "Intelligence", 
        targets: ["Middle East", "Global"], 
        description: "Israeli national intelligence agency. Focus on covert ops and HUMINT.",
        notableCampaigns: ["Natanz Sabotage", "Targeted Operations"],
        ttps: ["HUMINT-enabled Cyber", "Physical Access", "Supply Chain"],
        tools: ["Pegasus (User/Client)", "Custom Implants"]
      },
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
        aliases: ["Fancy Bear", "Sofacy", "Sednit", "STRONTIUM", "Forest Blizzard", "Tsar Team", "Pawn Storm"], 
        origin: "Russia (GRU Unit 26165)", 
        type: "Military Intelligence", 
        targets: ["NATO", "Ukraine", "Elections", "Journalists"], 
        description: "GRU 85th Main Special Service Center (GTsSS). DNC hack, Olympic attacks. Highly aggressive.",
        notableCampaigns: ["DNC Hack (2016)", "Olympic Destroyer", "Bundestag Hack", "WADA Hack"],
        ttps: ["X-Agent", "X-Tunnel", "Credential Harvesting", "VPNFilter", "Spearphishing"],
        tools: ["X-Agent", "X-Tunnel", "Zebrocy", "DealersChoice", "Drovorub"]
      },
      { 
        name: "APT29", 
        aliases: ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard", "Yttrium", "Cloaked Ursa"], 
        origin: "Russia (SVR)", 
        type: "Intelligence", 
        targets: ["Government", "Think Tanks", "Pharma", "Energy"], 
        description: "SVR Foreign Intelligence Service. SolarWinds supply chain attack. Stealthy and persistent.",
        notableCampaigns: ["SolarWinds (Sunburst)", "DNC Hack (2016)", "COVID-19 Vaccine Theft", "Operation Ghost"],
        ttps: ["Supply Chain Compromise", "Cloud Persistence", "Token Theft", "Pass-the-Ticket"],
        tools: ["Sunburst", "Teardrop", "Raindrop", "GoldMax", "WellMess", "MagicWeb"]
      },
      { 
        name: "Sandworm", 
        aliases: ["Voodoo Bear", "IRIDIUM", "Seashell Blizzard", "Unit 74455", "Telebots", "BlackEnergy Group"], 
        origin: "Russia (GRU Unit 74455)", 
        type: "Military Intelligence", 
        targets: ["Ukraine", "Infrastructure", "Media"], 
        description: "GRU Main Center for Special Technologies (GTsST). NotPetya, Power Grid. Destructive focus.",
        notableCampaigns: ["NotPetya", "Ukraine Power Grid (2015/2016)", "Olympic Destroyer", "Georgia Cyberattack"],
        ttps: ["Destructive Malware (Wiper)", "Living off the Land", "Industroyer", "Supply Chain"],
        tools: ["BlackEnergy", "Industroyer/CrashOverride", "NotPetya", "Cyclops Blink", "KillDisk"]
      },
      { 
        name: "Turla", 
        aliases: ["Snake", "Venomous Bear", "KRYPTON", "Secret Blizzard", "Waterbug", "Uroburos"], 
        origin: "Russia (FSB Center 16)", 
        type: "Intelligence", 
        targets: ["Government", "Military", "Diplomatic"], 
        description: "FSB Center 16 (Radio-Electronic Intelligence). Sophisticated espionage, satellite hijacking.",
        notableCampaigns: ["Agent.btz", "Moonlight Maze", "Satellite Hijacking", "Mosquito"],
        ttps: ["Satellite C2", "Rootkits", "Watering Holes", "ComLoJack"],
        tools: ["Snake", "Carbon", "Kazuar", "ComRAT", "TinyTurla"]
      },
      { 
        name: "Gamaredon", 
        aliases: ["Primitive Bear", "ACTINIUM", "Aqua Blizzard", "Shuckworm", "Armageddon"], 
        origin: "Russia (FSB Center 18)", 
        type: "Intelligence", 
        targets: ["Ukraine"], 
        description: "FSB Center 18 (Information Security). Focused on Ukrainian government. High volume, low sophistication.",
        notableCampaigns: ["Continuous Ukraine Ops"],
        ttps: ["Template Injection", "VBScript", "Spearphishing"],
        tools: ["Pterodo", "GammaLoad", "GammaSteel"]
      },
      { 
        name: "Star Blizzard", 
        aliases: ["SEABORGIUM", "Callisto", "Cold River", "TA446"], 
        origin: "Russia (FSB Center 18)", 
        type: "Intelligence", 
        targets: ["NATO", "UK", "NGOs", "Nuclear Labs"], 
        description: "FSB Center 18. Credential phishing campaigns against Western targets.",
        notableCampaigns: ["UK Political Interference", "Nuclear Lab Targeting"],
        ttps: ["Credential Harvesting", "EvilGinx", "Social Engineering"],
        tools: ["EvilGinx2", "Gophish"]
      },
      { 
        name: "Ember Bear", 
        aliases: ["UAC-0056", "Lorec53", "Bleeding Bear", "DEV-0586"], 
        origin: "Russia (GRU)", 
        type: "Military Intelligence", 
        targets: ["Ukraine", "NATO"], 
        description: "GRU-linked destructive attacks on Ukraine. WhisperGate wiper.",
        notableCampaigns: ["WhisperGate", "SaintBot"],
        ttps: ["Wipers", "Website Defacement"],
        tools: ["WhisperGate", "SaintBot", "OutSteel"]
      },
      { 
        name: "Dragonfly", 
        aliases: ["Energetic Bear", "Crouching Yeti", "Koala", "Berserk Bear"], 
        origin: "Russia (FSB Center 16)", 
        type: "Intelligence", 
        targets: ["Energy", "Aviation", "Manufacturing"], 
        description: "FSB Center 16. Targeting energy sector and industrial control systems.",
        notableCampaigns: ["Havex", "Dragonfly 2.0", "US Energy Grid Probing"],
        ttps: ["Watering Holes", "Trojanized Software", "Credential Harvesting", "SMB Harvesting"],
        tools: ["Havex", "Karagany", "Oldrea"]
      },
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
        aliases: ["Comment Crew", "Unit 61398", "Byzantine Candor"], 
        origin: "China (PLA)", 
        type: "Military", 
        targets: ["US Defense", "Industry", "Tech"], 
        description: "PLA Unit 61398, first APT publicly attributed by Mandiant. Massive IP theft.",
        notableCampaigns: ["Operation Aurora", "Shady RAT"],
        ttps: ["Spearphishing", "Custom Backdoors", "Pass-the-Hash"],
        tools: ["PoisonIvy", "PlugX", "Mimikatz"]
      },
      { 
        name: "APT10", 
        aliases: ["Stone Panda", "menuPass", "Red Apollo", "CVNX", "Potassium"], 
        origin: "China (MSS)", 
        type: "Intelligence", 
        targets: ["MSPs", "Healthcare", "Manufacturing"], 
        description: "MSS Tianjin bureau, Operation Cloud Hopper. Targeting Managed Service Providers.",
        notableCampaigns: ["Operation Cloud Hopper", "Visallo"],
        ttps: ["MSP Compromise", "DLL Side-Loading", "Quasar RAT", "Living off the Land"],
        tools: ["PlugX", "Quasar RAT", "RedLeaves", "Chocmilk"]
      },
      { 
        name: "APT40", 
        aliases: ["Leviathan", "TEMP.Periscope", "Gingham Typhoon", "Kryptonite Panda", "Mudcarp"], 
        origin: "China (MSS)", 
        type: "Intelligence", 
        targets: ["Maritime", "Defense", "Engineering"], 
        description: "MSS Hainan, maritime and naval intelligence. South China Sea focus.",
        notableCampaigns: ["Naval Research Theft", "Belt and Road Espionage"],
        ttps: ["Web Shells", "Spearphishing", "Compromised Web Servers"],
        tools: ["China Chopper", "BADFLICK", "Scanbox"]
      },
      { 
        name: "APT41", 
        aliases: ["Winnti", "Wicked Panda", "Brass Typhoon", "Barium", "Double Dragon"], 
        origin: "China (MSS)", 
        type: "Intelligence/Criminal", 
        targets: ["Gaming", "Tech", "Healthcare", "Telecom"], 
        description: "Dual espionage and financially motivated operations. Supply chain attacks.",
        notableCampaigns: ["Supply Chain Attacks (CCleaner, ASUS)", "Game Currency Theft"],
        ttps: ["Software Supply Chain", "Bootkits", "ShadowPad", "SQL Injection"],
        tools: ["ShadowPad", "Winnti", "Cobalt Strike", "PlugX"]
      },
      { 
        name: "Volt Typhoon", 
        aliases: ["VANGUARD PANDA", "Bronze Silhouette", "Insidious Taurus"], 
        origin: "China", 
        type: "State", 
        targets: ["US Critical Infrastructure", "Guam"], 
        description: "Pre-positioning for infrastructure disruption. Stealthy LOTL operations.",
        notableCampaigns: ["Guam Infrastructure", "US Ports"],
        ttps: ["Living off the Land (LOTL)", "SOHO Router Exploitation", "Web Shells", "Proxy Chaining"],
        tools: ["KV Botnet", "Earthworm", "Fscan", "Fast Reverse Proxy"]
      },
      { name: "Salt Typhoon", aliases: ["GhostEmperor"], origin: "China", type: "State", targets: ["Telecom", "ISPs"], description: "2024 telecom intrusions, access to wiretap systems.", tools: ["GhostEmperor Rootkit"] },
      { name: "Flax Typhoon", aliases: ["Ethereal Panda"], origin: "China", type: "State", targets: ["Taiwan", "US"], description: "Taiwan-focused, IoT botnet operations.", tools: ["Raptor Train Botnet"] },
      { name: "Mustang Panda", aliases: ["Bronze President", "RedDelta", "HoneyMyte"], origin: "China", type: "State", targets: ["Southeast Asia", "EU", "Vatican"], description: "Southeast Asian government espionage. USB propagation.", tools: ["PlugX", "Cobalt Strike"] },
      { name: "APT31", aliases: ["Zirconium", "Violet Typhoon", "Judgment Panda"], origin: "China (MSS)", type: "Intelligence", targets: ["Government", "Elections"], description: "MSS Hubei, election interference operations.", tools: ["Zippyshare", "RawDisk"] },
      { 
        name: "APT27", 
        aliases: ["Emissary Panda", "LuckyMouse", "Bronze Union", "Iron Tiger"], 
        origin: "China (MSS)", 
        type: "Intelligence", 
        targets: ["Aerospace", "Government", "Defense"], 
        description: "Long-running espionage campaigns using custom malware.",
        notableCampaigns: ["Operation Iron Tiger", "SharePoint Exploits"],
        ttps: ["Watering Holes", "HyperBro", "PlugX", "Strategic Web Compromise"],
        tools: ["HyperBro", "PlugX", "SysUpdate"]
      },
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
        aliases: ["HIDDEN COBRA", "Zinc", "Diamond Sleet", "Guardians of Peace"], 
        origin: "DPRK (RGB)", 
        type: "State", 
        targets: ["Finance", "Crypto", "Defense", "Media"], 
        description: "Sony hack, WannaCry, $2B+ crypto theft. Highly aggressive and versatile.",
        notableCampaigns: ["WannaCry Ransomware", "Sony Pictures Hack", "Harmony Bridge Theft", "Operation Troy"],
        ttps: ["SMB Exploits", "Man-in-the-Middle", "Trojanized Applications", "DLL Side-Loading"],
        tools: ["WannaCry", "Manuscrypt", "Bankshot", "Dtrack", "MimiKatz"]
      },
      { 
        name: "APT38", 
        aliases: ["BlueNoroff", "Stardust Chollima", "Nickel Glagolite"], 
        origin: "DPRK (RGB)", 
        type: "State", 
        targets: ["Banks", "SWIFT", "Crypto Exchanges"], 
        description: "Financial theft unit, Bangladesh Bank heist. Specialized in SWIFT fraud.",
        notableCampaigns: ["Bangladesh Bank Heist", "ATM Cashouts", "Chile Bank Heist"],
        ttps: ["SWIFT Manipulation", "File Deletion (Wiping)", "Custom Malware", "Anti-Forensics"],
        tools: ["Banswift", "Wingbird", "AuditWiper"]
      },
      { 
        name: "Kimsuky", 
        aliases: ["Velvet Chollima", "Emerald Sleet", "APT43", "Black Banshee"], 
        origin: "DPRK (RGB)", 
        type: "State", 
        targets: ["Think Tanks", "Nuclear", "South Korea"], 
        description: "Intelligence gathering on foreign policy and nuclear technology.",
        notableCampaigns: ["Nuclear Reactor Espionage", "Academic Phishing"],
        ttps: ["Spearphishing", "Malicious Documents", "Social Engineering"],
        tools: ["AppleSeed", "BabyShark", "FlowerPower"]
      },
      { 
        name: "Andariel", 
        aliases: ["Silent Chollima", "Onyx Sleet", "Stonefish"], 
        origin: "DPRK (RGB)", 
        type: "State", 
        targets: ["Defense", "Aerospace", "Finance"], 
        description: "Defense sector espionage and ransomware for funding.",
        notableCampaigns: ["Defense Contractor Hacks", "Maui Ransomware"],
        ttps: ["Log4j Exploitation", "Ransomware", "Web Shells"],
        tools: ["Maui Ransomware", "Dtrack", "TigerRAT"]
      },
      { name: "Bureau 121", aliases: [], origin: "DPRK", type: "State", targets: ["South Korea", "US"], description: "Primary cyber warfare unit, 6000+ operators. General cyber operations." },
      { name: "ScarCruft", aliases: ["APT37", "Reaper", "Ruby Sleet", "Ricochet Chollima"], origin: "DPRK", type: "State", targets: ["South Korea", "Japan", "Defectors"], description: "Regional espionage operations. Focus on dissidents.", tools: ["ROKRAT", "Dolphin"] },
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
        aliases: ["Elfin", "Refined Kitten", "Peach Sandstorm", "Holmium"], 
        origin: "Iran (IRGC)", 
        type: "State", 
        targets: ["Aviation", "Energy", "Saudi Arabia", "US"], 
        description: "Shamoon destructive attacks, aerospace espionage.",
        notableCampaigns: ["Shamoon 2.0", "StoneDrill", "Oberlin"],
        ttps: ["Disk Wipers", "Password Spraying", "Web Shells", "Spearphishing"],
        tools: ["Shamoon", "StoneDrill", "ShapeShift", "DropShot"]
      },
      { 
        name: "APT34", 
        aliases: ["OilRig", "Helix Kitten", "Hazel Sandstorm", "Cobalt Gypsy"], 
        origin: "Iran (MOIS)", 
        type: "Intelligence", 
        targets: ["Middle East", "Finance", "Energy", "Telecom"], 
        description: "Middle Eastern government and financial sector espionage.",
        notableCampaigns: ["Leak of Tools (2019)", "Bondat"],
        ttps: ["DNS Tunneling", "Social Engineering", "Web Shells"],
        tools: ["PoisonFrog", "Glimpse", "Bondat", "Karkoff"]
      },
      { 
        name: "APT35", 
        aliases: ["Charming Kitten", "Phosphorus", "Mint Sandstorm", "NewsBeef"], 
        origin: "Iran (IRGC)", 
        type: "State", 
        targets: ["Dissidents", "Media", "US", "Israel"], 
        description: "Social engineering, journalist targeting, interference.",
        notableCampaigns: ["HBO Hack", "US Election Interference"],
        ttps: ["Social Engineering", "Account Takeover", "SMS Phishing"],
        tools: ["PowerShell Backdoors", "CharmPower"]
      },
      { name: "APT39", aliases: ["Chafer", "Cotton Sandstorm", "Remix Kitten"], origin: "Iran (MOIS)", type: "Intelligence", targets: ["Telecom", "Travel"], description: "Telecom and travel industry surveillance to track individuals.", tools: ["Remexi", "Seaweed"] },
      { name: "MuddyWater", aliases: ["Mercury", "Mango Sandstorm", "Static Kitten"], origin: "Iran (MOIS)", type: "Intelligence", targets: ["Middle East", "Asia"], description: "Government and telecom espionage. Destructive capability.", tools: ["POWERSTATS", "MuddyRot"] },
      { name: "CyberAv3ngers", aliases: [], origin: "Iran (IRGC)", type: "Hacktivist", targets: ["Israel", "US Infrastructure"], description: "ICS/SCADA attacks, water utility compromises. Unit 700.", tools: ["PLC Exploits"] },
      { name: "Tortoiseshell", aliases: ["Imperial Kitten", "Crimson Sandstorm", "TA456"], origin: "Iran", type: "State", targets: ["Defense", "IT"], description: "Supply chain and IT provider targeting. Facebook fake profiles.", tools: ["Syskit", "Liderc"] },
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
        aliases: ["LockBit 3.0", "LockBit Black", "ABCD"], 
        origin: "Russia-linked", 
        type: "Ransomware", 
        targets: ["Global", "Healthcare", "Government", "Manufacturing"], 
        description: "Largest RaaS operation 2022-2024, disrupted Feb 2024. Highly professionalized.",
        notableCampaigns: ["Royal Mail", "Boeing", "ICBC", "Accenture"],
        ttps: ["Double Extortion", "Affiliate Model", "Stealbit", "PrintNightmare"],
        tools: ["StealBit", "LockBit 3.0", "Mimikatz"]
      },
      { 
        name: "BlackCat/ALPHV", 
        aliases: ["Noberus", "DarkSide (Successor)"], 
        origin: "Russia-linked", 
        type: "Ransomware", 
        targets: ["Healthcare", "Finance", "Critical Infrastructure"], 
        description: "Rust-based ransomware, Change Healthcare attack. Rebrand of DarkSide/BlackMatter.",
        notableCampaigns: ["Change Healthcare", "MGM Resorts", "Colonial Pipeline (as DarkSide)"],
        ttps: ["Rust Payload", "Triple Extortion", "Access Brokers", "SEO Poisoning"],
        tools: ["Exmatter", "Munchkin", "Sphynx"]
      },
      { 
        name: "Cl0p", 
        aliases: ["TA505", "FIN11", "Lace Tempest"], 
        origin: "Russia-linked", 
        type: "Ransomware", 
        targets: ["File Transfer", "Global"], 
        description: "MOVEit, GoAnywhere mass exploitation campaigns. Zero-day focused.",
        notableCampaigns: ["MOVEit Transfer", "GoAnywhere MFT", "Accellion", "PaperCut"],
        ttps: ["Zero-day Exploitation", "Mass Extortion", "Web Shells", "Torrent Distribution"],
        tools: ["Dewmode", "Lemurloo", "TrueBot", "FlawedAmmyy"]
      },
      { 
        name: "Scattered Spider", 
        aliases: ["Octo Tempest", "UNC3944", "0ktapus", "Scatter Swine"], 
        origin: "US/UK", 
        type: "eCrime", 
        targets: ["Telecom", "Tech", "Casinos", "BPO"], 
        description: "Social engineering experts, MGM/Caesars attacks. Native English speakers.",
        notableCampaigns: ["MGM Resorts", "Caesars Entertainment", "Okta", "Twilio"],
        ttps: ["SIM Swapping", "Help Desk Social Engineering", "BYOVD", "MFA Fatigue"],
        tools: ["BlackCat Ransomware", "AveMaria", "Raccoon Stealer"]
      },
      { name: "FIN7", aliases: ["Carbanak", "Carbon Spider", "Sangria Tempest"], origin: "Russia", type: "eCrime", targets: ["Retail", "Hospitality"], description: "Carbanak banking trojan, point-of-sale malware. Front companies.", tools: ["Carbanak", "GRIFFON", "Pillowmint"] },
      { name: "Evil Corp", aliases: ["Indrik Spider", "Dridex", "Gold Drake"], origin: "Russia", type: "eCrime", targets: ["Finance", "Global"], description: "Dridex, WastedLocker, sanctioned by US Treasury. Maksim Yakubets.", tools: ["Dridex", "WastedLocker", "Hades", "BitPaymer"] },
      { name: "REvil", aliases: ["Sodinokibi", "Pinchy Spider", "Gold Southfield"], origin: "Russia", type: "Ransomware", targets: ["MSPs", "Supply Chain"], description: "Kaseya attack, $70M ransom demands, disrupted 2022.", tools: ["Sodinokibi", "QakBot"] },
      { name: "Conti", aliases: ["Wizard Spider", "Gold Blackburn"], origin: "Russia", type: "Ransomware", targets: ["Healthcare", "Government"], description: "$180M+ extorted, disbanded after Ukraine leaks 2022. Supported Russian war effort.", tools: ["Conti", "TrickBot", "BazarLoader", "Anchor"] },
      { name: "Black Basta", aliases: ["Cardinal", "Storm-1180"], origin: "Russia-linked", type: "Ransomware", targets: ["Manufacturing", "Tech"], description: "Former Conti members, emerged 2022. Fast encryption.", tools: ["QakBot", "Cobalt Strike"] },
      { name: "Play", aliases: ["PlayCrypt", "Balloonfly"], origin: "Unknown", type: "Ransomware", targets: ["Latin America", "Global"], description: "Double extortion, emerged 2022. Exploits ProxyNotShell.", tools: ["Play Ransomware", "Cobalt Strike"] },
      { name: "8Base", aliases: [], origin: "Unknown", type: "Ransomware", targets: ["SMBs"], description: "SMB-focused ransomware operation. High volume.", tools: ["Phobos"] },
      { name: "Akira", aliases: ["Storm-1567"], origin: "Unknown", type: "Ransomware", targets: ["Education", "Finance"], description: "Emerged 2023, Linux variant. Exploits Cisco VPNs.", tools: ["Akira", "AnyDesk"] },
      { name: "Rhysida", aliases: ["Vice Society (suspected)"], origin: "Unknown", type: "Ransomware", targets: ["Healthcare", "Education"], description: "British Library attack, emerged 2023. Targets education/healthcare.", tools: ["Rhysida", "PortStarter"] },
      { 
        name: "Hive", 
        aliases: [], 
        origin: "Multinational", 
        type: "Ransomware", 
        targets: ["Healthcare", "Energy"], 
        description: "Aggressive RaaS, disrupted by FBI in 2023.",
        notableCampaigns: ["Costa Rica Government", "Memorial Health System"],
        ttps: ["Ransomware-as-a-Service", "Double Extortion", "Cobalt Strike"],
        tools: ["Hive Ransomware"]
      },
      { 
        name: "Royal", 
        aliases: ["DEV-0569", "Storm-0569"], 
        origin: "Russia-linked", 
        type: "Ransomware", 
        targets: ["Critical Infrastructure"], 
        description: "Private group (no affiliates), evolved from Conti.",
        notableCampaigns: ["Dallas City Government", "Silverstone Circuit"],
        ttps: ["Callback Phishing", "BatLoader", "Partial Encryption"],
        tools: ["Royal Ransomware", "BatLoader"]
      },
    ],
  },
  {
    id: "other-state",
    name: "Other State Actors",
    icon: "🌍",
    color: "#10b981",
    description: "Other nation-state cyber operations",
    actors: [
      { name: "APT32", aliases: ["OceanLotus", "SeaLotus", "Canvas Cyclone"], origin: "Vietnam", type: "State", targets: ["ASEAN", "Dissidents", "Automotive"], description: "Vietnamese state espionage, regional focus.", tools: ["Cobalt Strike", "KerrDown"] },
      { name: "Domestic Kitten", aliases: ["APT-C-50"], origin: "Iran", type: "State", targets: ["Dissidents", "Kurds"], description: "Surveillance of Iranian diaspora via mobile malware.", tools: ["FurBall"] },
      { name: "SideWinder", aliases: ["Rattlesnake", "APT-Q-39", "T-APT-04"], origin: "India", type: "State", targets: ["Pakistan", "China", "Nepal"], description: "South Asian regional espionage. Prolific use of exploits.", tools: ["WarHawk"] },
      { name: "Bitter", aliases: ["APT-Q-37", "T-APT-17"], origin: "India", type: "State", targets: ["Pakistan", "Bangladesh"], description: "South Asian government targeting.", tools: ["ArtraDownloader"] },
      { name: "Dark Basin", aliases: ["BellTroX"], origin: "India", type: "Hack-for-Hire", targets: ["Global"], description: "Indian hack-for-hire targeting journalists, activists.", tools: ["Phishing Kits"] },
      { name: "Polonium", aliases: ["Cornflower Sleet"], origin: "Lebanon", type: "State", targets: ["Israel"], description: "Lebanese targeting of Israeli organizations. Coordinated with MOIS.", tools: ["CreepyDrive"] },
      { name: "Agrius", aliases: ["DEV-0227", "Pink Sandstorm"], origin: "Iran", type: "State", targets: ["Israel"], description: "Destructive operations against Israel disguised as ransomware.", tools: ["Apostle", "Deadwood"] },
      { 
        name: "Transparent Tribe", 
        aliases: ["APT36", "Mythic Leopard", "ProjectM"], 
        origin: "Pakistan", 
        type: "State", 
        targets: ["India", "Military"], 
        description: "Espionage against Indian government and military.",
        notableCampaigns: ["Operation C-Major", "Honey Traps"],
        ttps: ["Social Engineering", "Crimson RAT", "Obfuscated VBA"],
        tools: ["Crimson RAT", "ObliqueRAT"]
      },
      { 
        name: "Patchwork", 
        aliases: ["Dropping Elephant", "Chinastrats", "Monsoon"], 
        origin: "India", 
        type: "State", 
        targets: ["China", "Pakistan"], 
        description: "Cyber espionage against neighboring rivals.",
        notableCampaigns: ["Operation Hangover"],
        ttps: ["Spearphishing", "BadNews RAT", "Exploit Documents"],
        tools: ["BadNews", "Badge"]
      },
    ],
  },
  {
    id: "hacktivism",
    name: "Hacktivist Groups",
    icon: "✊",
    color: "#ec4899",
    description: "Politically motivated hacking collectives",
    actors: [
      { name: "Anonymous", aliases: [], origin: "Global", type: "Hacktivist", targets: ["Various"], description: "Decentralized collective, anti-Russia ops post-Ukraine.", tools: ["LOIC", "HOIC"] },
      { name: "IT Army of Ukraine", aliases: [], origin: "Ukraine", type: "Hacktivist", targets: ["Russia"], description: "Volunteer DDoS and hack operations against Russia.", tools: ["DDoS Tools"] },
      { name: "Killnet", aliases: [], origin: "Russia", type: "Hacktivist", targets: ["NATO", "Ukraine Allies"], description: "Pro-Russian DDoS attacks on Western targets.", tools: ["DDoS Scripts"] },
      { name: "NoName057(16)", aliases: [], origin: "Russia", type: "Hacktivist", targets: ["NATO", "EU"], description: "Pro-Russian DDoS attacks, DDoSia tool.", tools: ["DDoSia"] },
      { name: "Anonymous Sudan", aliases: ["Storm-1359"], origin: "Russia-linked", type: "Hacktivist", targets: ["US", "NATO"], description: "Likely Russian false flag, major DDoS campaigns (Microsoft, X).", tools: ["Layer 7 DDoS"] },
      { name: "GhostSec", aliases: [], origin: "Global", type: "Hacktivist", targets: ["ISIS", "Russia"], description: "Counter-terrorism, anti-Russia operations.", tools: ["GhostLocker"] },
      { name: "SiegedSec", aliases: [], origin: "Unknown", type: "Hacktivist", targets: ["Government"], description: "NATO, US government data leaks.", tools: ["SQL Injection"] },
      { 
        name: "Lapsus$", 
        aliases: ["DEV-0537", "Strawberry Fields"], 
        origin: "UK/Brazil", 
        type: "Criminal/Hacktivist", 
        targets: ["Tech Giants", "Telecom"], 
        description: "Teenage group targeting major tech companies for notoriety.",
        notableCampaigns: ["NVIDIA", "Samsung", "Microsoft", "Okta"],
        ttps: ["Insider Threat Recruitment", "SIM Swapping", "Telegram Coordination"],
        tools: ["Purchased Infostealers", "AD Explorer"]
      },
    ],
  },
];

// CTI Methodology sections
export const ctiMethodology = [
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
  {
    title: "Cyber Kill Chain (Lockheed Martin)",
    icon: "⛓️",
    color: "#ef4444",
    steps: [
      "Reconnaissance - Harvesting email addresses, conference info, etc.",
      "Weaponization - Coupling exploit with backdoor into deliverable payload",
      "Delivery - Delivering weaponized bundle to the victim via email, web, USB",
      "Exploitation - Exploiting a vulnerability to execute code on victim's system",
      "Installation - Installing malware on the asset",
      "Command & Control (C2) - Command channel for remote manipulation",
      "Actions on Objectives - With 'Hands on Keyboard' intruder accomplishes their original goals",
    ],
  },
];

export const tlpLevels = [
  { level: "TLP:RED", color: "#dc2626", desc: "Not for disclosure, restricted to participants only." },
  { level: "TLP:AMBER", color: "#f59e0b", desc: "Limited disclosure, restricted to organization and clients." },
  { level: "TLP:AMBER+STRICT", color: "#d97706", desc: "Restricted to organization only." },
  { level: "TLP:GREEN", color: "#10b981", desc: "Limited disclosure, community wide." },
  { level: "TLP:CLEAR", color: "#9ca3af", desc: "Unlimited disclosure, public information." },
];

export const admiraltyCode = {
  reliability: [
    { grade: "A", label: "Completely Reliable", desc: "No doubt of authenticity, trustworthiness, or competency." },
    { grade: "B", label: "Usually Reliable", desc: "Minor doubt about history of reliability." },
    { grade: "C", label: "Fairly Reliable", desc: "Doubt of authenticity, trustworthiness, or competency but has provided valid info in past." },
    { grade: "D", label: "Not Usually Reliable", desc: "Significant doubt about history of reliability." },
    { grade: "E", label: "Unreliable", desc: "Lacking in authenticity, trustworthiness, and competency." },
    { grade: "F", label: "Reliability Cannot Be Judged", desc: "No basis exists for evaluating the reliability of the source." },
  ],
  credibility: [
    { grade: "1", label: "Confirmed by Other Sources", desc: "Logical, consistent with other information, confirmed by independent sources." },
    { grade: "2", label: "Probably True", desc: "Logical, consistent with other information, not confirmed." },
    { grade: "3", label: "Possibly True", desc: "Reasonably logical, agrees with some information, not confirmed." },
    { grade: "4", label: "Doubtful", desc: "Not logical, contradicted by other information." },
    { grade: "5", label: "Improbable", desc: "Not logical, contradicted by other information." },
    { grade: "6", label: "Truth Cannot Be Judged", desc: "The validity of the information cannot be determined." },
  ]
};

export const biases = [
  { name: "Confirmation Bias", desc: "Seeking information that supports pre-existing beliefs." },
  { name: "Anchoring", desc: "Relying too heavily on the first piece of information offered." },
  { name: "Mirror Imaging", desc: "Assuming the adversary thinks and acts like you do." },
  { name: "Availability Heuristic", desc: "Overestimating the importance of information that is easy to recall." },
];

// Tracking methodology
export const trackingMethods = [
  { method: "Infrastructure Tracking", description: "Monitor domain registrations, SSL certificates, IP ranges, hosting patterns", tools: "PassiveTotal, DomainTools, Shodan, Censys" },
  { method: "Malware Tracking", description: "Track malware families, code evolution, C2 protocols", tools: "VirusTotal, MalwareBazaar, Any.Run, Joe Sandbox" },
  { method: "Campaign Tracking", description: "Monitor active campaigns, victimology, phishing infrastructure", tools: "PhishTank, URLhaus, MISP, OpenCTI" },
  { method: "Actor Tracking", description: "Build profiles on threat actors, TTPs, tooling preferences", tools: "MITRE ATT&CK, Threat Actor Libraries, MISP Galaxies" },
  { method: "Vulnerability Tracking", description: "Track exploitation of CVEs, PoC releases, in-the-wild exploitation", tools: "VulnDB, KEV Catalog, Exploit-DB, NVD" },
  { method: "Underground Monitoring", description: "Monitor dark web forums, ransomware blogs, leak sites", tools: "Tor, Flare, DarkOwl, Intel471" },
];

export const pivotTechniques = [
  { name: "Email Address", pivots: ["Domain Registration", "Social Media", "GitHub/Forums", "Breach Data"] },
  { name: "IP Address", pivots: ["Passive DNS (Domains)", "SSL Certificates", "Open Ports/Services", "Geo-location"] },
  { name: "Domain Name", pivots: ["Whois Data", "Subdomains", "Associated Emails", "File Downloads"] },
  { name: "SSL Certificate", pivots: ["Subject/Issuer Name", "Serial Number", "JARM Fingerprint", "Other Domains"] },
  { name: "Malware Hash", pivots: ["Imphash", "Rich Header", "String Reuse", "Compilation Time"] },
];
