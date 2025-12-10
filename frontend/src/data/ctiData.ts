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
  firstSeen?: string;
  active?: boolean;
}

export interface ActorCategory {
  id: string;
  name: string;
  icon: string;
  color: string;
  description: string;
  actors: ThreatActor[];
}

export interface IOCType {
  name: string;
  description: string;
  examples: string[];
  detectionMethods: string[];
  icon: string;
}

export interface MITREtactic {
  id: string;
  name: string;
  description: string;
  techniques: number;
  color: string;
}

export interface IntelSource {
  name: string;
  type: string;
  url: string;
  description: string;
  free: boolean;
  category: string;
}

export interface AnalysisTechnique {
  name: string;
  description: string;
  steps: string[];
  tools: string[];
  difficulty: "Beginner" | "Intermediate" | "Advanced";
}

export interface ThreatLandscape {
  category: string;
  trend: "increasing" | "stable" | "decreasing";
  description: string;
  keyStats: string[];
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
      { 
        name: "BND", 
        aliases: ["Bundesnachrichtendienst"], 
        origin: "Germany", 
        type: "Intelligence", 
        targets: ["Global", "Russia", "Middle East"], 
        description: "German federal intelligence service. Focus on SIGINT and foreign intelligence. Post-Cold War pivot to terrorism and cyber.",
        notableCampaigns: ["Eikonal Program (NSA cooperation)", "Operation Rubicon/Thesaurus (Crypto AG)"],
        ttps: ["SIGINT Collection", "HUMINT Operations", "Satellite Interception"],
        tools: ["Classified German Tools"],
        firstSeen: "1956",
        active: true
      },
      { 
        name: "CSE", 
        aliases: ["Communications Security Establishment", "CSEC"], 
        origin: "Canada", 
        type: "Intelligence", 
        targets: ["Global", "Arctic Region", "Asia-Pacific"], 
        description: "Canada's signals intelligence agency. Five Eyes member. Operates defensive (CSE) and offensive (CCCS) capabilities.",
        notableCampaigns: ["LANDMARK (Brazilian Ministry)", "Five Eyes Joint Operations"],
        ttps: ["SIGINT Collection", "CNE Operations", "Metadata Analysis"],
        tools: ["Classified Five Eyes Tools"],
        firstSeen: "1946",
        active: true
      },
      { 
        name: "ASD", 
        aliases: ["Australian Signals Directorate", "DSD"], 
        origin: "Australia", 
        type: "Intelligence", 
        targets: ["Asia-Pacific", "China", "Indonesia"], 
        description: "Australia's signals intelligence and cyber security agency. Five Eyes member. Operates ACSC for defensive cyber.",
        notableCampaigns: ["Five Eyes Joint Operations", "Asia-Pacific SIGINT"],
        ttps: ["SIGINT Collection", "Offensive Cyber", "Cable Interception"],
        tools: ["Classified", "Joint Five Eyes Capabilities"],
        firstSeen: "1947",
        active: true
      },
      { 
        name: "GCSB", 
        aliases: ["Government Communications Security Bureau"], 
        origin: "New Zealand", 
        type: "Intelligence", 
        targets: ["Asia-Pacific", "South Pacific"], 
        description: "New Zealand's signals intelligence agency. Five Eyes member. Focus on Pacific Island region.",
        notableCampaigns: ["Waihopai Station Operations", "Pacific SIGINT"],
        ttps: ["SIGINT Collection", "Satellite Interception"],
        tools: ["XKeyscore Access", "Five Eyes Shared Tools"],
        firstSeen: "1977",
        active: true
      },
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
      { 
        name: "NSO Group", 
        aliases: ["Q Cyber Technologies"], 
        origin: "Israel", 
        type: "Private Sector Offensive", 
        targets: ["Global (via clients)"], 
        description: "Commercial spyware vendor. Pegasus used by governments worldwide for surveillance.",
        notableCampaigns: ["Pegasus Project", "Zero-Click iPhone Exploits", "WhatsApp Exploits"],
        ttps: ["Zero-Click Exploits", "Mobile Implants", "iMessage Exploits", "Network Injection"],
        tools: ["Pegasus", "Phantom", "Circles"]
      },
      { 
        name: "Shin Bet (ISA)", 
        aliases: ["Shabak", "Israel Security Agency"], 
        origin: "Israel", 
        type: "Intelligence", 
        targets: ["Palestinians", "Domestic Threats"], 
        description: "Israeli internal security service with significant cyber capabilities.",
        ttps: ["Mobile Surveillance", "Social Media Monitoring", "SIGINT"],
        tools: ["Custom Surveillance Tools"]
      },
      { 
        name: "ANSSI", 
        aliases: ["Agence nationale de la sécurité des systèmes d'information"], 
        origin: "France", 
        type: "Defensive/Offensive", 
        targets: ["Threats to France"], 
        description: "French cybersecurity agency with both defensive and offensive mandates.",
        ttps: ["Incident Response", "Threat Hunting", "CNE"],
        tools: ["CLIP OS", "Custom Tools"]
      },
      { 
        name: "AIVD", 
        aliases: ["Algemene Inlichtingen- en Veiligheidsdienst"], 
        origin: "Netherlands", 
        type: "Intelligence", 
        targets: ["Russia", "China", "Counter-Terrorism"], 
        description: "Dutch intelligence service. Reportedly compromised APT29 and provided early warning.",
        notableCampaigns: ["APT29 Compromise (Cozy Bear watching)", "Counter-Intelligence Ops"],
        ttps: ["Counter-Intelligence", "Offensive Cyber"],
        tools: ["Classified"]
      },
      { 
        name: "MIVD", 
        aliases: ["Militaire Inlichtingen- en Veiligheidsdienst"], 
        origin: "Netherlands", 
        type: "Military Intelligence", 
        targets: ["State Actors", "Military Targets"], 
        description: "Dutch military intelligence with significant cyber capabilities.",
        notableCampaigns: ["GRU Operations Exposure"],
        ttps: ["Military CNE", "Counter-Intelligence"],
        tools: ["Classified"]
      },
      { 
        name: "NIS", 
        aliases: ["National Intelligence Service"], 
        origin: "South Korea", 
        type: "Intelligence", 
        targets: ["North Korea", "Regional"], 
        description: "South Korean intelligence agency focused on DPRK and regional threats.",
        ttps: ["SIGINT", "HUMINT", "Cyber Operations"],
        tools: ["Custom Tools"]
      },
      { 
        name: "JSDF Cyber Defense Group", 
        aliases: ["Self-Defense Force Cyber"], 
        origin: "Japan", 
        type: "Military", 
        targets: ["China", "North Korea", "Russia"], 
        description: "Japan Self-Defense Forces cyber unit, expanded significantly since 2022.",
        ttps: ["Defensive Operations", "Network Defense"],
        tools: ["Military Tools"]
      },
      { 
        name: "ASIS", 
        aliases: ["Australian Secret Intelligence Service"], 
        origin: "Australia", 
        type: "Intelligence", 
        targets: ["Asia-Pacific", "Global", "Indonesia", "China"], 
        description: "Australia's foreign intelligence service with cyber capabilities. HUMINT focus with cyber augmentation.",
        notableCampaigns: ["East Timor Operations", "Asia-Pacific Intelligence"],
        ttps: ["HUMINT Operations", "Cyber-enabled Intelligence", "Embassy Operations"],
        tools: ["Classified Australian Tools"],
        firstSeen: "1952",
        active: true
      },
      { 
        name: "SIS/MI6", 
        aliases: ["Secret Intelligence Service", "MI6"], 
        origin: "UK", 
        type: "Intelligence", 
        targets: ["Global", "Russia", "Middle East", "China"], 
        description: "UK's foreign intelligence service. Works closely with GCHQ on cyber operations. HUMINT with cyber integration.",
        notableCampaigns: ["Joint Operations with GCHQ", "Russia Desk Operations"],
        ttps: ["HUMINT", "Cyber-HUMINT Integration", "Agent Handling"],
        tools: ["Joint GCHQ/SIS Capabilities"],
        firstSeen: "1909",
        active: true
      },
      { 
        name: "DIA", 
        aliases: ["Defense Intelligence Agency"], 
        origin: "USA", 
        type: "Military Intelligence", 
        targets: ["Global Military", "State Actors", "WMD Proliferation"], 
        description: "US military intelligence agency with significant cyber capabilities. Supports DoD cyber operations.",
        notableCampaigns: ["Military Intelligence Support", "Combatant Command Support"],
        ttps: ["Military Intelligence", "Defense Attaché Network", "Technical Intelligence"],
        tools: ["JWICS Access", "DoD Cyber Tools"],
        firstSeen: "1961",
        active: true
      },
      { 
        name: "FBI Cyber Division", 
        aliases: ["FBI CD", "IC3"], 
        origin: "USA", 
        type: "Law Enforcement", 
        targets: ["Cybercriminals", "Nation-States", "Ransomware Groups"], 
        description: "FBI's cyber investigative arm. Conducts offensive operations against ransomware. Operates IC3 and CISA partnerships.",
        notableCampaigns: ["Hive Takedown", "QakBot Disruption", "LockBit Disruption", "Volt Typhoon Investigation"],
        ttps: ["Criminal Investigation", "Infrastructure Seizure", "Malware Disruption", "International Cooperation"],
        tools: ["Legal Process", "Technical Operations", "Victim Notification"],
        firstSeen: "2002",
        active: true
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
      { 
        name: "Cadet Blizzard", 
        aliases: ["DEV-0586", "FROZENLAKE"], 
        origin: "Russia (GRU)", 
        type: "Military Intelligence", 
        targets: ["Ukraine", "NATO"], 
        description: "GRU unit conducting destructive operations against Ukraine since 2022.",
        notableCampaigns: ["WhisperGate", "Ukrainian Government Targeting"],
        ttps: ["Wipers", "Web Defacement", "Credential Theft"],
        tools: ["WhisperGate", "CaddyWiper", "DesertBlade"]
      },
      { 
        name: "Gossamer Bear", 
        aliases: ["UNC4210"], 
        origin: "Russia", 
        type: "Intelligence", 
        targets: ["Ukraine", "NATO"], 
        description: "Russian threat actor targeting Ukrainian and NATO entities via phishing.",
        ttps: ["Spearphishing", "Credential Harvesting"],
        tools: ["Custom Phishing Kits"]
      },
      { 
        name: "Void Blizzard", 
        aliases: ["Laundry Bear"], 
        origin: "Russia", 
        type: "State", 
        targets: ["NATO", "Government"], 
        description: "Recently identified Russian actor targeting Western government and defense sectors.",
        notableCampaigns: ["NATO Member Targeting (2024)"],
        ttps: ["Cloud Exploitation", "Credential Theft", "Exchange Exploitation"],
        tools: ["Custom Backdoors"]
      },
      { 
        name: "Nodaria", 
        aliases: ["UAC-0056", "SaintBear"], 
        origin: "Russia (GRU)", 
        type: "Military Intelligence", 
        targets: ["Ukraine"], 
        description: "GRU-linked group conducting espionage operations against Ukraine.",
        ttps: ["GraphSteel", "GrimPlant", "Elephant Framework"],
        tools: ["GraphSteel", "GrimPlant", "Cobalt Strike"]
      },
      { 
        name: "Winter Vivern", 
        aliases: ["UAC-0114", "TA473"], 
        origin: "Russia/Belarus", 
        type: "State", 
        targets: ["NATO", "EU Government"], 
        description: "Targets European government and military. Exploits Zimbra and Roundcube.",
        notableCampaigns: ["European Government Email Compromise", "NATO-aligned Targeting"],
        ttps: ["Webmail Exploitation", "XSS Attacks", "Credential Harvesting"],
        tools: ["Zimbra Exploits", "Custom Scripts"]
      },
      { 
        name: "Romcom", 
        aliases: ["Storm-0978", "Tropical Scorpius", "UNC2596"], 
        origin: "Russia", 
        type: "Espionage/Criminal", 
        targets: ["Ukraine", "NATO", "Government"], 
        description: "Russian group blending espionage with financially-motivated attacks. Cuba ransomware links.",
        notableCampaigns: ["Ukraine Government Targeting", "NATO Summit Phishing"],
        ttps: ["Trojanized Software", "Ransomware", "MS Office Exploits"],
        tools: ["RomCom RAT", "Cuba Ransomware", "Underground Ransomware"]
      },
      { 
        name: "Doppel Spider", 
        aliases: ["TA547", "Scully Spider"], 
        origin: "Russia", 
        type: "eCrime/Espionage", 
        targets: ["Europe", "Financial"], 
        description: "Russian-speaking threat actor with access broker and espionage capabilities.",
        ttps: ["Malspam", "JavaScript Loaders", "Info Stealers"],
        tools: ["ZLoader", "Ursnif", "Rhadamanthys"]
      },
      { 
        name: "Blue Charlie", 
        aliases: ["TAG-53"], 
        origin: "Russia", 
        type: "State", 
        targets: ["NGOs", "Media", "Think Tanks"], 
        description: "Credential phishing campaigns targeting civil society and researchers.",
        ttps: ["Credential Phishing", "Impersonation", "Social Engineering"],
        tools: ["Evilginx", "Custom Phishing"]
      },
      { 
        name: "InvisiMole", 
        aliases: ["Gamaredon Linked"], 
        origin: "Russia", 
        type: "Intelligence", 
        targets: ["Ukraine", "Eastern Europe", "Diplomatic"], 
        description: "Sophisticated espionage group with Gamaredon ties. Highly targeted operations. Advanced backdoors with modular architecture.",
        notableCampaigns: ["Diplomatic Espionage", "Ukrainian Government Targeting"],
        ttps: ["RC2FM Backdoor", "DNS Tunneling", "Modular Malware", "Rootkit Capabilities"],
        tools: ["InvisiMole", "RC2FM", "RC2CL"],
        firstSeen: "2013",
        active: true
      },
      { 
        name: "XakNet", 
        aliases: ["CyberArmyofRussia", "Cyber Army of Russia Reborn"], 
        origin: "Russia", 
        type: "Hacktivist/State", 
        targets: ["Ukraine", "NATO", "US Infrastructure"], 
        description: "Pro-Russian hacktivist group with suspected GRU ties. Conducts DDoS and claims ICS attacks. Telegram coordination.",
        notableCampaigns: ["US Water Utility Claims", "European DDoS Campaigns"],
        ttps: ["DDoS Attacks", "HMI Screenshot Leaks", "Telegram Propaganda", "Claimed ICS Access"],
        tools: ["DDoS Tools", "Wipers", "Custom Scripts"],
        firstSeen: "2022",
        active: true
      },
      { 
        name: "Lorec53", 
        aliases: ["UAC-0056", "SaintBear", "TA471"], 
        origin: "Russia", 
        type: "State", 
        targets: ["Ukraine", "Georgian Government"], 
        description: "Russian group targeting Ukrainian government with various malware. Also targets Georgia and Poland.",
        notableCampaigns: ["Ukrainian Government Phishing", "Elephant Framework Deployment"],
        ttps: ["Spearphishing", "Macro Documents", "GraphSteel/GrimPlant Deployment"],
        tools: ["GraphSteel", "GrimPlant", "Elephant Implant", "Cobalt Strike"],
        firstSeen: "2021",
        active: true
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
      { 
        name: "Salt Typhoon", 
        aliases: ["GhostEmperor", "FamousSparrow"], 
        origin: "China", 
        type: "State", 
        targets: ["Telecom", "ISPs", "Wiretap Systems"], 
        description: "2024 telecom intrusions compromising US ISPs and accessing lawful intercept systems. Major national security concern.",
        notableCampaigns: ["US ISP Compromise (2024)", "Wiretap System Access", "AT&T/Verizon/Lumen Intrusions"],
        ttps: ["Kernel-mode Rootkit", "Exchange Exploitation", "Long-term Persistence", "SIGINT Collection"],
        tools: ["GhostEmperor Rootkit", "Demodex Rootkit", "Custom Implants"],
        firstSeen: "2021",
        active: true
      },
      { 
        name: "Flax Typhoon", 
        aliases: ["Ethereal Panda", "Storm-0919"], 
        origin: "China", 
        type: "State", 
        targets: ["Taiwan", "US", "IoT Devices"], 
        description: "Taiwan-focused espionage with massive IoT botnet (Raptor Train). 200,000+ compromised devices globally.",
        notableCampaigns: ["Taiwan Government Targeting", "Raptor Train Botnet", "SOHO Router Compromise"],
        ttps: ["Living off the Land", "IoT Exploitation", "Minimal Malware", "Web Shells"],
        tools: ["Raptor Train Botnet", "SoftEther VPN", "China Chopper"],
        firstSeen: "2021",
        active: true
      },
      { 
        name: "Mustang Panda", 
        aliases: ["Bronze President", "RedDelta", "HoneyMyte", "TA416", "Earth Preta"], 
        origin: "China", 
        type: "State", 
        targets: ["Southeast Asia", "EU", "Vatican", "Mongolia", "Myanmar"], 
        description: "Southeast Asian government espionage. USB propagation. Known for targeting NGOs and religious organizations.",
        notableCampaigns: ["Vatican Targeting", "Myanmar Coup Intelligence", "EU Diplomatic Targeting"],
        ttps: ["USB Propagation", "DLL Sideloading", "Korplug/PlugX", "Spearphishing"],
        tools: ["PlugX", "Cobalt Strike", "Korplug", "TONESHELL"],
        firstSeen: "2017",
        active: true
      },
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
      { 
        name: "APT3", 
        aliases: ["Gothic Panda", "Buckeye", "UPS Team", "TG-0110"], 
        origin: "China (MSS)", 
        type: "Intelligence", 
        targets: ["Aerospace", "Defense", "Technology"], 
        description: "MSS Guangdong contractor. Sophisticated espionage targeting Western technology.",
        notableCampaigns: ["Double Tap", "Clandestine Wolf"],
        ttps: ["Zero-Days", "Browser Exploitation", "Watering Holes"],
        tools: ["Pirpi", "DoublePulsar (Stolen)", "PlugX"]
      },
      { 
        name: "APT17", 
        aliases: ["Tailgater Team", "Deputy Dog", "Elderwood"], 
        origin: "China", 
        type: "State", 
        targets: ["Government", "Legal", "IT"], 
        description: "Chinese espionage group targeting government and legal sectors.",
        notableCampaigns: ["Operation Aurora Ties", "Deputy Dog Campaign"],
        ttps: ["Watering Holes", "IE Exploits", "Zero-Days"],
        tools: ["Blackcoffee", "HiKit", "Derusbi"]
      },
      { 
        name: "APT19", 
        aliases: ["Codoso Team", "C0d0so0", "Deep Panda"], 
        origin: "China", 
        type: "State", 
        targets: ["Legal", "Investment", "Think Tanks"], 
        description: "Targets legal and investment firms for insider information.",
        ttps: ["Spearphishing", "Strategic Web Compromise"],
        tools: ["Derusbi", "Sakula", "Cobalt Strike"]
      },
      { 
        name: "Aquatic Panda", 
        aliases: ["RedHotel", "Earth Lusca"], 
        origin: "China", 
        type: "State", 
        targets: ["Telecom", "Government", "Technology"], 
        description: "Aggressive Chinese espionage group with wide target scope.",
        notableCampaigns: ["Log4Shell Exploitation", "Exchange Exploitation"],
        ttps: ["Vulnerability Exploitation", "Cobalt Strike", "Web Shells"],
        tools: ["Cobalt Strike", "ShadowPad", "SpiderPig"]
      },
      { 
        name: "Granite Typhoon", 
        aliases: ["Gallium", "GADOLINIUM", "Softcell"], 
        origin: "China", 
        type: "State", 
        targets: ["Telecom", "Finance", "Government"], 
        description: "Targets telecommunications providers for intelligence access.",
        notableCampaigns: ["Operation Soft Cell", "Telecom Targeting"],
        ttps: ["Web Shells", "PoisonIvy", "Mimikatz", "Custom Malware"],
        tools: ["China Chopper", "PoisonIvy", "QuasarRAT"]
      },
      { 
        name: "Charcoal Typhoon", 
        aliases: ["CHROMIUM", "ControlX"], 
        origin: "China", 
        type: "State", 
        targets: ["Government", "Technology", "Education"], 
        description: "Targets education and government sectors in Taiwan and globally.",
        ttps: ["Spearphishing", "Web Shells", "Credential Harvesting"],
        tools: ["Cobalt Strike", "ShadowPad"]
      },
      { 
        name: "Raspberry Typhoon", 
        aliases: ["TAG-22", "Bronze Riverside"], 
        origin: "China", 
        type: "State", 
        targets: ["Southeast Asia", "Australia", "Japan"], 
        description: "Targets ASEAN countries and Pacific allies for political intelligence.",
        ttps: ["ShadowPad", "PlugX", "Spearphishing"],
        tools: ["ShadowPad", "PlugX", "FunnySwitch"]
      },
      { 
        name: "Circle Typhoon", 
        aliases: [], 
        origin: "China", 
        type: "State", 
        targets: ["US Infrastructure", "IT"], 
        description: "2024 identified actor targeting US critical infrastructure like Volt Typhoon.",
        ttps: ["LOTL", "SOHO Device Exploitation"],
        tools: ["Legitimate Tools"]
      },
      { 
        name: "Silk Typhoon", 
        aliases: ["HAFNIUM"], 
        origin: "China", 
        type: "State", 
        targets: ["Government", "NGOs", "Defense"], 
        description: "Responsible for mass Exchange Server exploitation via ProxyLogon.",
        notableCampaigns: ["ProxyLogon Mass Exploitation (2021)", "Exchange Zero-Days"],
        ttps: ["Web Shells", "Exchange Exploitation", "Credential Dumping"],
        tools: ["China Chopper", "Covenant", "Nishang"]
      },
      { 
        name: "APT5", 
        aliases: ["Keyhole Panda", "MANGANESE", "Bronze Fleetwood"], 
        origin: "China", 
        type: "State", 
        targets: ["Telecom", "Technology", "Aerospace"], 
        description: "Long-running Chinese espionage group targeting tech and telecom.",
        notableCampaigns: ["Citrix ADC Exploitation"],
        ttps: ["VPN Exploitation", "Watering Holes"],
        tools: ["LEOUNCIA", "Sesamepudding"]
      },
      { 
        name: "Naikon", 
        aliases: ["APT30", "Lotus Panda", "Override Panda"], 
        origin: "China (PLA)", 
        type: "Military", 
        targets: ["ASEAN", "South China Sea Nations"], 
        description: "PLA-linked group focused on South China Sea territorial intelligence.",
        notableCampaigns: ["ASEAN Targeting", "Philippines Government"],
        ttps: ["Spearphishing", "Decoy Documents", "RoyalRoad"],
        tools: ["Aria-body", "Nebulae", "RainyDay"]
      },
      { 
        name: "Tick", 
        aliases: ["Bronze Butler", "RedBaldKnight", "STALKER PANDA"], 
        origin: "China", 
        type: "State", 
        targets: ["Japan", "South Korea", "Aerospace"], 
        description: "Targeting Japanese and Korean aerospace and defense sectors.",
        ttps: ["Spearphishing", "Watering Holes", "USB Malware"],
        tools: ["Daserf", "xxmm", "Datper"]
      },
      { 
        name: "Tonto Team", 
        aliases: ["CactusPete", "Earth Akhlut", "KARMA PANDA"], 
        origin: "China (PLA)", 
        type: "Military", 
        targets: ["Russia", "Eastern Europe", "ASEAN"], 
        description: "Chinese military espionage group uniquely targeting Russia alongside others.",
        ttps: ["RoyalRoad", "Bisonal", "RTF Exploits"],
        tools: ["Bisonal", "Dexbia", "ShadowPad"]
      },
      { 
        name: "APT15", 
        aliases: ["Vixen Panda", "Nickel", "Ke3Chang", "Playful Dragon", "Mirage"], 
        origin: "China (MSS)", 
        type: "Intelligence", 
        targets: ["Government", "Diplomatic", "Think Tanks", "NGOs"], 
        description: "MSS-linked targeting government and diplomatic entities globally. Long-running operations since 2010.",
        notableCampaigns: ["UK Government Targeting", "Latin American Diplomatic Espionage", "African Union Targeting"],
        ttps: ["Spearphishing", "Watering Holes", "Custom Backdoors", "Living off the Land"],
        tools: ["Ketrum", "Okrum", "Ketrican", "RoyalCli", "BS2005"],
        firstSeen: "2010",
        active: true
      },
      { 
        name: "APT20", 
        aliases: ["Violin Panda", "TH3bug", "TEMP.Zealot"], 
        origin: "China", 
        type: "State", 
        targets: ["Government", "Aviation", "Energy", "Defense"], 
        description: "Chinese espionage targeting aviation and energy sectors. Bypassed 2FA in documented intrusions.",
        notableCampaigns: ["Operation Wocao", "MFA Bypass Intrusions"],
        ttps: ["Web Server Exploitation", "Credential Theft", "2FA Bypass", "Living off the Land"],
        tools: ["PlugX variants", "Custom Web Shells", "Impacket"],
        firstSeen: "2011",
        active: true
      },
      { 
        name: "Blacktech", 
        aliases: ["Palmerworm", "Circuit Panda", "Temp.Overboard", "Radio Panda"], 
        origin: "China", 
        type: "State", 
        targets: ["Taiwan", "Japan", "US", "Hong Kong"], 
        description: "Targets Taiwan and allies, known for router firmware implants. Modified Cisco router firmware for persistence.",
        notableCampaigns: ["Cisco Router Firmware Modification", "Taiwan Government Targeting", "Japan Defense Sector"],
        ttps: ["Router Compromise", "Firmware Modification", "Supply Chain", "GRE Tunneling"],
        tools: ["Waterbear", "PLEAD", "TSCookie", "BendyBear", "FlagPro"],
        firstSeen: "2010",
        active: true
      },
      { 
        name: "Earth Estries", 
        aliases: ["Salt Typhoon related", "FamousSparrow"], 
        origin: "China", 
        type: "State", 
        targets: ["Telecom", "Government", "Hotels", "Engineering"], 
        description: "Sophisticated Chinese actor targeting telecom and government sectors. Uses custom backdoors and rootkits.",
        notableCampaigns: ["Global Telecom Campaign", "Southeast Asian Government Targeting"],
        ttps: ["ProxyLogon Exploitation", "DLL Sideloading", "Custom Backdoors", "Kernel Rootkits"],
        tools: ["GhostSpider", "Snappybee", "HemiGate", "Crowdoor", "Zingdoor"],
        firstSeen: "2020",
        active: true
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
      { 
        name: "Bureau 121", 
        aliases: ["Lab 110", "Unit 180", "Office 91"], 
        origin: "DPRK", 
        type: "State", 
        targets: ["South Korea", "US", "Global Financial"], 
        description: "Primary cyber warfare unit under RGB, 6000+ operators. Headquarters in Pyongyang with satellite offices in China and Southeast Asia.",
        notableCampaigns: ["DarkSeoul (2013)", "Various Lazarus Operations"],
        ttps: ["Offensive Cyber Operations", "Financial Theft", "Destructive Attacks", "Espionage"],
        tools: ["Various tools across sub-units"],
        firstSeen: "1998",
        active: true
      },
      { 
        name: "ScarCruft", 
        aliases: ["APT37", "Reaper", "Ruby Sleet", "Ricochet Chollima", "Group123", "Venus 121"], 
        origin: "DPRK", 
        type: "State", 
        targets: ["South Korea", "Japan", "Defectors", "Journalists", "Human Rights"], 
        description: "Regional espionage operations focused on Korean Peninsula. Targets defectors, journalists, and human rights activists.",
        notableCampaigns: ["Operation Daybreak", "Operation Erebus", "Defector Surveillance"],
        ttps: ["Watering Holes", "HWP Exploits", "Zero-Days", "Mobile Malware"],
        tools: ["ROKRAT", "Dolphin", "Konni", "Goldbackdoor", "Chinotto"],
        firstSeen: "2012",
        active: true
      },
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
      { 
        name: "APT42", 
        aliases: ["Damselfly", "UNC788", "Yellow Garuda"], 
        origin: "Iran (IRGC-IO)", 
        type: "Intelligence", 
        targets: ["Dissidents", "Journalists", "Policy Makers"], 
        description: "IRGC Intelligence Organization. Highly focused on surveillance of individuals.",
        notableCampaigns: ["Journalist Targeting", "Think Tank Espionage", "2024 US Election Interference"],
        ttps: ["Social Engineering", "Credential Harvesting", "Mobile Malware"],
        tools: ["NICECURL", "TAMECAT", "PowerShell Backdoors"]
      },
      { 
        name: "Pioneer Kitten", 
        aliases: ["Fox Kitten", "Parisite", "Lemon Sandstorm", "UNC757"], 
        origin: "Iran", 
        type: "State/Criminal", 
        targets: ["Global", "VPN Infrastructure"], 
        description: "Initial access broker selling access to ransomware groups. VPN exploitation focus.",
        notableCampaigns: ["Pulse Secure Exploitation", "F5 BIG-IP Exploitation", "Ransomware Partnerships"],
        ttps: ["VPN Exploitation", "Web Shells", "Access Brokering"],
        tools: ["Fox Panel", "Pay2Key", "Custom Web Shells"]
      },
      { 
        name: "Scarred Manticore", 
        aliases: ["Storm-0861"], 
        origin: "Iran (MOIS)", 
        type: "Intelligence", 
        targets: ["Middle East", "Government"], 
        description: "Sophisticated MOIS group targeting Middle Eastern governments.",
        notableCampaigns: ["Albanian Government Attacks"],
        ttps: ["Exchange Exploitation", "Web Shells", "Custom Malware"],
        tools: ["LIONTAIL", "FoxShell", "ScarShell"]
      },
      { 
        name: "Dune", 
        aliases: ["Storm-0842"], 
        origin: "Iran (MOIS)", 
        type: "Intelligence", 
        targets: ["Israel", "Albania"], 
        description: "Destructive operations disguised as ransomware. Albanian government attack.",
        notableCampaigns: ["Albania Government Attack (2022)"],
        ttps: ["Wipers", "Ransomware Facade", "Data Destruction"],
        tools: ["ZeroCleare", "Dustman"]
      },
      { 
        name: "Emennet Pasargad", 
        aliases: ["Cotton Sandstorm", "DEV-0842", "Vice Leaker"], 
        origin: "Iran", 
        type: "Contractor", 
        targets: ["Israel", "US", "Elections"], 
        description: "Iranian contractor conducting hack-and-leak and disinformation operations.",
        notableCampaigns: ["Proud Boys Impersonation (2020)", "Israeli Dating Site Hack"],
        ttps: ["Hack-and-Leak", "Disinformation", "Website Defacement"],
        tools: ["Custom Tools", "SMS Spam"]
      },
      { 
        name: "Lyceum", 
        aliases: ["Hexane", "Spirlin", "Siamesekitten"], 
        origin: "Iran", 
        type: "State", 
        targets: ["Energy", "Telecom", "Africa"], 
        description: "Targeting oil and gas, telecommunications across Middle East and Africa.",
        ttps: ["DNS Tunneling", "Spearphishing", "Credential Harvesting"],
        tools: ["DanBot", "Milan", "Shark"]
      },
      { 
        name: "Nemesis Kitten", 
        aliases: ["TunnelVision", "UNC2448", "DEV-0270"], 
        origin: "Iran", 
        type: "State/Criminal", 
        targets: ["Global", "VMware"], 
        description: "Exploiting Log4j and VMware for both espionage and ransomware operations.",
        notableCampaigns: ["Log4Shell Exploitation"],
        ttps: ["VMware Exploitation", "Log4j", "Fast Flux DNS"],
        tools: ["BitLocker Abuse", "DiskCryptor", "Reverse SSH Tunnels"]
      },
      { 
        name: "Magic Hound", 
        aliases: ["APT35 Related", "Newscaster", "Cobalt Illusion"], 
        origin: "Iran (IRGC)", 
        type: "State", 
        targets: ["US", "Israel", "Saudi Arabia"], 
        description: "Long-running IRGC operation using social engineering and fake personas.",
        ttps: ["Fake Social Media Profiles", "Watering Holes", "Spearphishing"],
        tools: ["HYPERSCRAPE", "PowerShell Tools"]
      },
      { 
        name: "PHOSPHORUS", 
        aliases: ["Charming Kitten variant", "TA453", "ITG18"], 
        origin: "Iran (IRGC)", 
        type: "State", 
        targets: ["Medical Research", "Academia", "Policy"], 
        description: "Targets medical research and academic institutions worldwide.",
        ttps: ["Credential Phishing", "Conference Lures", "Medical Research Targeting"],
        tools: ["CharmPower", "GhostEcho", "SpoofedScholars"]
      },
      { 
        name: "Lemon Sandstorm", 
        aliases: ["RUBIDIUM", "FOXKITTEN"], 
        origin: "Iran", 
        type: "State", 
        targets: ["Aerospace", "Defense"], 
        description: "Targets aerospace and defense contractors. VPN exploitation specialty.",
        notableCampaigns: ["VPN Vulnerability Exploitation"],
        ttps: ["VPN Exploitation", "Web Application Attacks"],
        tools: ["Web Shells", "Tunnel Tools"]
      },
      { 
        name: "Void Manticore", 
        aliases: ["Storm-0842"], 
        origin: "Iran (MOIS)", 
        type: "Intelligence", 
        targets: ["Israel", "Middle East"], 
        description: "Wiper malware operations targeting Israel, coordination with Scarred Manticore.",
        ttps: ["Wiper Deployment", "Coordination with Other Groups"],
        tools: ["Cl Wiper", "No-Justice Wiper", "BiBi Wiper"]
      },
      { 
        name: "OilAlpha", 
        aliases: ["Houthi Cyber", "DarkHydrus Related"], 
        origin: "Iran/Yemen", 
        type: "State", 
        targets: ["Saudi Arabia", "UAE", "Yemen Opposition"], 
        description: "Iran-backed Houthi cyber operations targeting Gulf states. Mobile surveillance focus on humanitarian and media organizations.",
        notableCampaigns: ["Gulf State Targeting", "Humanitarian Organization Surveillance"],
        ttps: ["Android Malware", "Spearphishing", "Fake Apps", "Social Engineering"],
        tools: ["SpyNote", "Custom Android Malware", "SpyMax"],
        firstSeen: "2022",
        active: true
      },
      { 
        name: "Moses Staff", 
        aliases: ["Marigold Sandstorm"], 
        origin: "Iran", 
        type: "Hacktivist", 
        targets: ["Israel", "Israeli Companies"], 
        description: "Anti-Israel hacktivist group conducting hack-and-leak operations. Destructive malware disguised as ransomware.",
        notableCampaigns: ["Israeli Company Data Leaks", "Destructive Operations"],
        ttps: ["Hack-and-Leak", "Wiper Malware", "Website Defacement", "Data Destruction"],
        tools: ["DCSrv", "PyDCrypt", "StrifeWater", "DriveGuard"],
        firstSeen: "2021",
        active: true
      },
      { 
        name: "Homeland Justice", 
        aliases: [], 
        origin: "Iran", 
        type: "Hacktivist", 
        targets: ["Albania", "MEK"], 
        description: "Claimed responsibility for Albanian government attacks. Likely persona for Iranian state operations targeting MEK.",
        notableCampaigns: ["Albanian Government Attack (2022)", "E-Albania Portal Destruction"],
        ttps: ["Wiper Malware", "Ransomware Facade", "Website Defacement", "Data Exfiltration"],
        tools: ["ROADSWEEP", "Chimneysweep", "ZeroCleare"],
        firstSeen: "2022",
        active: true
      },
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
      { 
        name: "FIN7", 
        aliases: ["Carbanak", "Carbon Spider", "Sangria Tempest", "ELBRUS"], 
        origin: "Russia", 
        type: "eCrime", 
        targets: ["Retail", "Hospitality", "Restaurant Chains"], 
        description: "Carbanak banking trojan, point-of-sale malware. Operated front companies (Combi Security) for recruitment. Multiple arrests.",
        notableCampaigns: ["US Restaurant Chain Breaches", "Carbanak Banking Attacks", "Combi Security Front"],
        ttps: ["Spearphishing", "POS Malware", "Social Engineering", "Fake Security Company"],
        tools: ["Carbanak", "GRIFFON", "Pillowmint", "POWERTRASH", "Lizar"],
        firstSeen: "2013",
        active: true
      },
      { 
        name: "Evil Corp", 
        aliases: ["Indrik Spider", "Dridex", "Gold Drake", "UNC2165"], 
        origin: "Russia", 
        type: "eCrime", 
        targets: ["Finance", "Global", "US Companies"], 
        description: "Dridex banking trojan, WastedLocker ransomware. OFAC sanctioned. Led by Maksim Yakubets, allegedly works with FSB.",
        notableCampaigns: ["Dridex Banking Fraud ($100M+)", "WastedLocker Campaign", "Garmin Attack"],
        ttps: ["Banking Trojans", "Ransomware", "Affiliate Evasion", "Rebranding"],
        tools: ["Dridex", "WastedLocker", "Hades", "BitPaymer", "PhoenixLocker", "PayloadBIN"],
        firstSeen: "2014",
        active: true
      },
      { 
        name: "REvil", 
        aliases: ["Sodinokibi", "Pinchy Spider", "Gold Southfield"], 
        origin: "Russia", 
        type: "Ransomware", 
        targets: ["MSPs", "Supply Chain", "Large Enterprises"], 
        description: "Kaseya supply chain attack, $70M ransom demands. Disrupted by Russian FSB arrests in 2022. GandCrab successor.",
        notableCampaigns: ["Kaseya VSA Attack", "JBS Foods", "Travelex", "Acer"],
        ttps: ["Ransomware-as-a-Service", "Supply Chain Attacks", "Double Extortion", "MSP Targeting"],
        tools: ["Sodinokibi Ransomware", "QakBot", "IcedID"],
        firstSeen: "2019",
        active: false
      },
      { 
        name: "Conti", 
        aliases: ["Wizard Spider", "Gold Blackburn", "DEV-0193"], 
        origin: "Russia", 
        type: "Ransomware", 
        targets: ["Healthcare", "Government", "Education"], 
        description: "$180M+ extorted, disbanded after Ukraine chat leaks in 2022. Pro-Russia stance led to internal conflict. Members formed new groups.",
        notableCampaigns: ["Costa Rica Government", "Ireland HSE", "US Healthcare Attacks"],
        ttps: ["Double Extortion", "TrickBot Distribution", "Manual Hacking", "Data Leak Site"],
        tools: ["Conti Ransomware", "TrickBot", "BazarLoader", "Anchor", "Cobalt Strike"],
        firstSeen: "2020",
        active: false
      },
      { 
        name: "Black Basta", 
        aliases: ["Cardinal", "Storm-1180"], 
        origin: "Russia-linked", 
        type: "Ransomware", 
        targets: ["Manufacturing", "Tech", "Healthcare"], 
        description: "Former Conti members, emerged April 2022. Fast encryption with ChaCha20. 500+ victims in first 2 years.",
        notableCampaigns: ["ABB", "Capita", "American Dental Association", "Dish Network"],
        ttps: ["QakBot/DarkGate Initial Access", "Double Extortion", "Vishing for Credentials", "Cobalt Strike"],
        tools: ["QakBot", "DarkGate", "Cobalt Strike", "Mimikatz", "Black Basta Encryptor"],
        firstSeen: "2022",
        active: true
      },
      { 
        name: "Play", 
        aliases: ["PlayCrypt", "Balloonfly"], 
        origin: "Unknown", 
        type: "Ransomware", 
        targets: ["Latin America", "Global", "Government"], 
        description: "Double extortion, emerged 2022. Exploits ProxyNotShell, FortiOS vulnerabilities. Closed group (no affiliates).",
        notableCampaigns: ["City of Oakland", "Arnold Clark", "Latin American Governments"],
        ttps: ["ProxyNotShell Exploitation", "FortiOS Exploitation", "AdFind Reconnaissance", "Intermittent Encryption"],
        tools: ["Play Ransomware", "Cobalt Strike", "SystemBC", "Grixba"],
        firstSeen: "2022",
        active: true
      },
      { 
        name: "8Base", 
        aliases: ["RansomHouse Related"], 
        origin: "Unknown", 
        type: "Ransomware", 
        targets: ["SMBs", "Professional Services", "Manufacturing"], 
        description: "SMB-focused ransomware operation using Phobos variant. High volume with aggressive leak site. Claims 350+ victims.",
        notableCampaigns: ["Mass SMB Targeting", "UN Support Claim"],
        ttps: ["Phobos Ransomware", "Double Extortion", "SMB Focus", "Aggressive Naming/Shaming"],
        tools: ["Phobos", "SmokeLoader", "SystemBC"],
        firstSeen: "2022",
        active: true
      },
      { 
        name: "Akira", 
        aliases: ["Storm-1567"], 
        origin: "Unknown", 
        type: "Ransomware", 
        targets: ["Education", "Finance", "Manufacturing"], 
        description: "Emerged 2023, has Linux/VMware ESXi variant. Exploits Cisco VPNs (CVE-2023-20269). Possible Conti links.",
        notableCampaigns: ["Stanford University", "Nissan Oceania", "Cisco VPN Campaign"],
        ttps: ["Cisco VPN Exploitation", "VMware ESXi Targeting", "Double Extortion", "RDP Abuse"],
        tools: ["Akira Ransomware", "AnyDesk", "WinRAR", "Cloudflare Tunnel"],
        firstSeen: "2023",
        active: true
      },
      { 
        name: "Rhysida", 
        aliases: ["Vice Society (suspected)"], 
        origin: "Unknown", 
        type: "Ransomware", 
        targets: ["Healthcare", "Education", "Government"], 
        description: "British Library attack, emerged May 2023. Targets education, healthcare, government. Possible Vice Society rebrand.",
        notableCampaigns: ["British Library", "Chilean Army", "Prospect Medical Holdings", "Prince George's County"],
        ttps: ["Phishing", "Zerologon Exploitation", "Double Extortion", "Living off the Land"],
        tools: ["Rhysida Ransomware", "PortStarter", "Cobalt Strike", "PsExec"],
        firstSeen: "2023",
        active: true
      },
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
      { 
        name: "Medusa", 
        aliases: ["Medusa Locker"], 
        origin: "Unknown", 
        type: "Ransomware", 
        targets: ["Healthcare", "Education", "Manufacturing"], 
        description: "Rapidly growing RaaS operation with aggressive data leak site.",
        notableCampaigns: ["Minneapolis Public Schools", "Toyota Financial Services"],
        ttps: ["RDP Brute Force", "Webshells", "PowerShell", "Double Extortion"],
        tools: ["Medusa Ransomware", "ConnectWise"]
      },
      { 
        name: "RansomHub", 
        aliases: ["Cyclops"], 
        origin: "Unknown", 
        type: "Ransomware", 
        targets: ["Global", "Healthcare"], 
        description: "Emerged 2024, rapidly recruited affiliates from disrupted groups.",
        notableCampaigns: ["Patelco Credit Union", "Frontier Communications"],
        ttps: ["VPN Exploitation", "Citrix Bleed", "ESXi Targeting", "Affiliate Model"],
        tools: ["RansomHub Encryptor", "EDR Killers"]
      },
      { 
        name: "BianLian", 
        aliases: [], 
        origin: "Unknown", 
        type: "Ransomware", 
        targets: ["Healthcare", "Professional Services", "Manufacturing"], 
        description: "Shifted to pure extortion without encryption in 2024.",
        notableCampaigns: ["Save the Children", "Air Canada"],
        ttps: ["ProxyShell Exploitation", "Data Exfiltration Only", "Golang Malware"],
        tools: ["BianLian Backdoor", "WinSCP", "Rclone"]
      },
      { 
        name: "INC Ransom", 
        aliases: ["INC"], 
        origin: "Unknown", 
        type: "Ransomware", 
        targets: ["Healthcare", "Government"], 
        description: "2023-2024 operation targeting critical infrastructure.",
        notableCampaigns: ["Xerox", "NHS Scotland", "Various healthcare orgs"],
        ttps: ["Citrix Bleed Exploitation", "Valid Credentials", "MEGA Upload"],
        tools: ["INC Encryptor", "MEGAsync"]
      },
      { 
        name: "Hunters International", 
        aliases: ["Hive Rebrand"], 
        origin: "Unknown", 
        type: "Ransomware", 
        targets: ["Global", "Manufacturing"], 
        description: "Suspected Hive rebrand, emerged late 2023.",
        notableCampaigns: ["Multiple global victims post-Hive takedown"],
        ttps: ["Rust-based Ransomware", "VMware ESXi Targeting"],
        tools: ["Hunters Ransomware"]
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
      { 
        name: "APT32", 
        aliases: ["OceanLotus", "SeaLotus", "Canvas Cyclone", "APT-C-00"], 
        origin: "Vietnam", 
        type: "State", 
        targets: ["ASEAN", "Dissidents", "Automotive", "Media"], 
        description: "Vietnamese state espionage, regional focus. Targets dissidents, foreign governments, and automotive companies. Sophisticated tradecraft.",
        notableCampaigns: ["BMW/Hyundai Intrusions", "Dissident Surveillance", "ASEAN Government Targeting"],
        ttps: ["Watering Holes", "Spearphishing", "Macros", "Custom Backdoors"],
        tools: ["Cobalt Strike", "KerrDown", "Denis", "Ratsnif", "PhantomLance"],
        firstSeen: "2014",
        active: true
      },
      { 
        name: "Domestic Kitten", 
        aliases: ["APT-C-50", "Flying Kitten"], 
        origin: "Iran", 
        type: "State", 
        targets: ["Dissidents", "Kurds", "ISIS Members", "Iranian Citizens Abroad"], 
        description: "Surveillance of Iranian diaspora via mobile malware. Internal security focus targeting Kurds, ISIS supporters, and dissidents.",
        notableCampaigns: ["Mobile Surveillance Campaigns", "Dissident Tracking"],
        ttps: ["Android Malware", "Fake Apps", "Social Engineering", "Telegram Lures"],
        tools: ["FurBall", "Custom Android Spyware"],
        firstSeen: "2016",
        active: true
      },
      { 
        name: "SideWinder", 
        aliases: ["Rattlesnake", "APT-Q-39", "T-APT-04", "Hardcore Nationalist"], 
        origin: "India", 
        type: "State", 
        targets: ["Pakistan", "China", "Nepal", "Sri Lanka"], 
        description: "South Asian regional espionage. Prolific use of exploits. Very high attack volume with thousands of attacks documented.",
        notableCampaigns: ["Pakistan Military Targeting", "Chinese Entity Targeting", "Nepal Government"],
        ttps: ["Spearphishing", "LNK Files", "DLL Sideloading", "RTF Exploits"],
        tools: ["WarHawk", "SideWinder.RAT", "StealerBot"],
        firstSeen: "2012",
        active: true
      },
      { 
        name: "Bitter", 
        aliases: ["APT-Q-37", "T-APT-17", "BITTER APT"], 
        origin: "India", 
        type: "State", 
        targets: ["Pakistan", "Bangladesh", "China"], 
        description: "South Asian government targeting. Focus on Pakistan military and government. Uses mobile malware.",
        notableCampaigns: ["Pakistan Government Targeting", "Bangladesh Espionage"],
        ttps: ["Spearphishing", "Office Exploits", "Android Malware", "InPage Exploits"],
        tools: ["ArtraDownloader", "BitterRAT", "Almond RAT"],
        firstSeen: "2013",
        active: true
      },
      { 
        name: "Dark Basin", 
        aliases: ["BellTroX InfoTech Services"], 
        origin: "India", 
        type: "Hack-for-Hire", 
        targets: ["Global", "Journalists", "Activists", "Executives"], 
        description: "Indian hack-for-hire service (BellTroX) targeting journalists, activists, and executives on behalf of clients worldwide.",
        notableCampaigns: ["#ExxonKnew Campaign Targeting", "Journalist Targeting", "Corporate Espionage"],
        ttps: ["Phishing", "Credential Harvesting", "Impersonation"],
        tools: ["Phishing Kits", "Custom Infrastructure"],
        firstSeen: "2013",
        active: true
      },
      { 
        name: "Polonium", 
        aliases: ["Cornflower Sleet"], 
        origin: "Lebanon", 
        type: "State", 
        targets: ["Israel", "Israeli IT Companies"], 
        description: "Lebanese targeting of Israeli organizations. Coordinated with Iranian MOIS. Uses cloud services for C2.",
        notableCampaigns: ["Israeli IT Company Targeting", "OneDrive Abuse"],
        ttps: ["Cloud Service Abuse", "OneDrive C2", "Custom Backdoors"],
        tools: ["CreepyDrive", "CreepySnail", "FlipCreep", "TechnoCreep"],
        firstSeen: "2022",
        active: true
      },
      { 
        name: "Agrius", 
        aliases: ["DEV-0227", "Pink Sandstorm", "AmericanExpress APT"], 
        origin: "Iran", 
        type: "State", 
        targets: ["Israel", "UAE", "South Africa"], 
        description: "Destructive operations against Israel disguised as ransomware. Known for Apostle/Fantasy wiper operations.",
        notableCampaigns: ["Israeli Targets (2020-2022)", "South African Diamond Industry"],
        ttps: ["Wipers", "Ransomware Facade", "Web Shells", "Supply Chain"],
        tools: ["Apostle", "Deadwood", "Fantasy Wiper", "IPsec Helper"],
        firstSeen: "2020",
        active: true
      },
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
      { 
        name: "Anonymous", 
        aliases: ["Anon"], 
        origin: "Global", 
        type: "Hacktivist", 
        targets: ["Various", "Russia", "Corporations"], 
        description: "Decentralized collective, major anti-Russia ops post-Ukraine invasion. No central leadership or membership.",
        notableCampaigns: ["OpRussia", "OpISIS", "HBGary Hack", "PlayStation Network"],
        ttps: ["DDoS Attacks", "Data Leaks", "Website Defacement", "Doxing"],
        tools: ["LOIC", "HOIC", "Various Leaked Tools"],
        firstSeen: "2003",
        active: true
      },
      { 
        name: "IT Army of Ukraine", 
        aliases: [], 
        origin: "Ukraine", 
        type: "Hacktivist", 
        targets: ["Russia", "Belarus", "Russian Companies"], 
        description: "Government-coordinated volunteer cyber force conducting DDoS and hack operations against Russia since Feb 2022.",
        notableCampaigns: ["Russian Bank DDoS", "Russian Government Sites", "Propaganda Targeting"],
        ttps: ["Coordinated DDoS", "Telegram Coordination", "Data Leaks", "Defacement"],
        tools: ["DDoS Tools", "Custom Attack Tools"],
        firstSeen: "2022",
        active: true
      },
      { 
        name: "Killnet", 
        aliases: [], 
        origin: "Russia", 
        type: "Hacktivist", 
        targets: ["NATO", "Ukraine Allies", "Critical Infrastructure"], 
        description: "Pro-Russian hacktivist group conducting DDoS attacks on Western targets. Suspected state ties. High media profile.",
        notableCampaigns: ["US Airport DDoS", "Lithuania Government", "Italian Government"],
        ttps: ["Layer 7 DDoS", "Telegram Propaganda", "Crowdsourced Attacks"],
        tools: ["DDoS Scripts", "CC Attack Tools"],
        firstSeen: "2022",
        active: true
      },
      { 
        name: "NoName057(16)", 
        aliases: [], 
        origin: "Russia", 
        type: "Hacktivist", 
        targets: ["NATO", "EU", "Ukraine Supporters"], 
        description: "Pro-Russian DDoS attacks using distributed volunteer tool DDoSia. Rewards volunteers with cryptocurrency.",
        notableCampaigns: ["European Government DDoS", "NATO Ally Targeting", "Swiss Government"],
        ttps: ["DDoSia Platform", "Volunteer Recruitment", "Cryptocurrency Rewards"],
        tools: ["DDoSia", "Custom DDoS Platform"],
        firstSeen: "2022",
        active: true
      },
      { 
        name: "Anonymous Sudan", 
        aliases: ["Storm-1359"], 
        origin: "Russia-linked", 
        type: "Hacktivist", 
        targets: ["US", "NATO", "Tech Companies"], 
        description: "Likely Russian false flag despite Islamic branding. Major DDoS campaigns against Microsoft, X, and Telegram.",
        notableCampaigns: ["Microsoft Azure/Outlook DDoS", "X (Twitter) DDoS", "ChatGPT DDoS"],
        ttps: ["Layer 7 DDoS", "API Abuse", "Telegram Coordination", "Media Amplification"],
        tools: ["Layer 7 DDoS", "Skynet Botnet", "InfraShutdown"],
        firstSeen: "2023",
        active: true
      },
      { 
        name: "GhostSec", 
        aliases: [], 
        origin: "Global", 
        type: "Hacktivist", 
        targets: ["ISIS", "Russia", "Authoritarian Regimes"], 
        description: "Counter-terrorism hacktivist group, anti-ISIS operations. Pivoted to anti-Russia ops. Created GhostLocker ransomware.",
        notableCampaigns: ["OpISIS", "Russian Industrial Control Systems", "Iranian Targets"],
        ttps: ["ICS/SCADA Targeting", "Website Defacement", "Data Leaks", "Ransomware Development"],
        tools: ["GhostLocker", "Custom Tools"],
        firstSeen: "2015",
        active: true
      },
      { 
        name: "SiegedSec", 
        aliases: ["SiegedSecurity"], 
        origin: "Unknown", 
        type: "Hacktivist", 
        targets: ["Government", "Anti-LGBTQ States"], 
        description: "Hacktivist group targeting governments. NATO COI Portal breach. Targets US states with anti-LGBTQ legislation.",
        notableCampaigns: ["NATO COI Portal", "Texas Government", "US State Targeting"],
        ttps: ["SQL Injection", "Data Exfiltration", "Website Defacement"],
        tools: ["SQL Injection", "Common Web Exploits"],
        firstSeen: "2022",
        active: true
      },
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
  { name: "Attribution Bias", desc: "Attributing actions to known actors without sufficient evidence." },
  { name: "Groupthink", desc: "Conforming to team consensus rather than independent analysis." },
  { name: "Recency Bias", desc: "Giving more weight to recent events over historical patterns." },
  { name: "Survivorship Bias", desc: "Focusing only on successful attacks while ignoring failed attempts." },
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

// IOC Types and Detection Methods
export const iocTypes: IOCType[] = [
  {
    name: "File Hashes",
    description: "Cryptographic fingerprints of malicious files (MD5, SHA1, SHA256)",
    examples: ["MD5: d41d8cd98f00b204e9800998ecf8427e", "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    detectionMethods: ["EDR file scanning", "YARA rules", "Antivirus signatures", "Hash lookups"],
    icon: "🔐"
  },
  {
    name: "IP Addresses",
    description: "Command & Control servers, scanning infrastructure, and malicious hosts",
    examples: ["185.220.101.xxx (Tor exit)", "45.155.205.xxx (bulletproof hosting)"],
    detectionMethods: ["Firewall rules", "Network flow analysis", "Threat intelligence feeds", "DNS sinkholing"],
    icon: "🌐"
  },
  {
    name: "Domain Names",
    description: "Malicious domains used for phishing, C2, and payload delivery",
    examples: ["*.ru domains", "DGA-generated domains", "Typosquatted domains"],
    detectionMethods: ["DNS monitoring", "Domain reputation", "WHOIS analysis", "Passive DNS"],
    icon: "🔗"
  },
  {
    name: "URLs",
    description: "Specific malicious URLs for payload delivery or credential harvesting",
    examples: ["hxxp://malicious[.]com/payload.exe", "Shortened URLs (bit.ly)"],
    detectionMethods: ["URL filtering", "Web proxy inspection", "Sandboxing", "URL reputation"],
    icon: "🔍"
  },
  {
    name: "Email Addresses",
    description: "Attacker email addresses used in phishing or registration",
    examples: ["attacker@protonmail.com", "compromised legitimate accounts"],
    detectionMethods: ["Email gateway rules", "Sender reputation", "SPF/DKIM/DMARC", "Header analysis"],
    icon: "📧"
  },
  {
    name: "Registry Keys",
    description: "Windows registry modifications for persistence and configuration",
    examples: ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Software\\Classes\\CLSID"],
    detectionMethods: ["Registry monitoring", "Autoruns analysis", "Baseline comparison", "EDR telemetry"],
    icon: "📝"
  },
  {
    name: "File Paths",
    description: "Common locations where malware resides or drops payloads",
    examples: ["%APPDATA%\\Microsoft\\Windows\\", "%TEMP%\\", "C:\\ProgramData\\"],
    detectionMethods: ["File integrity monitoring", "Behavior analysis", "Directory scanning", "Forensic imaging"],
    icon: "📁"
  },
  {
    name: "Mutex Names",
    description: "Mutual exclusion objects created by malware to prevent multiple instances",
    examples: ["Global\\MalwareMutex123", "UNIQUE_ID_DO_NOT_DELETE"],
    detectionMethods: ["Process analysis", "Handle enumeration", "Sandbox detection", "Memory forensics"],
    icon: "🔒"
  },
  {
    name: "User Agents",
    description: "HTTP User-Agent strings used by malware for C2 communication",
    examples: ["Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (unusual variant)", "Python-urllib/2.7"],
    detectionMethods: ["Web proxy logs", "Network traffic analysis", "Anomaly detection", "HTTP header inspection"],
    icon: "🤖"
  },
  {
    name: "YARA Rules",
    description: "Pattern matching rules to identify malware families and behaviors",
    examples: ["rule Emotet { strings: $a = \"emotet\" condition: $a }"],
    detectionMethods: ["Scanning tools", "YARA generators", "Community rulesets", "Custom development"],
    icon: "📜"
  },
];

// MITRE ATT&CK Tactics
export const mitreTactics: MITREtactic[] = [
  { id: "TA0043", name: "Reconnaissance", description: "Gathering information to plan future operations", techniques: 10, color: "#6366f1" },
  { id: "TA0042", name: "Resource Development", description: "Establishing resources to support operations", techniques: 8, color: "#8b5cf6" },
  { id: "TA0001", name: "Initial Access", description: "Trying to get into your network", techniques: 9, color: "#ec4899" },
  { id: "TA0002", name: "Execution", description: "Trying to run malicious code", techniques: 14, color: "#ef4444" },
  { id: "TA0003", name: "Persistence", description: "Trying to maintain their foothold", techniques: 19, color: "#f97316" },
  { id: "TA0004", name: "Privilege Escalation", description: "Trying to gain higher-level permissions", techniques: 13, color: "#f59e0b" },
  { id: "TA0005", name: "Defense Evasion", description: "Trying to avoid being detected", techniques: 42, color: "#eab308" },
  { id: "TA0006", name: "Credential Access", description: "Stealing credentials like passwords", techniques: 17, color: "#84cc16" },
  { id: "TA0007", name: "Discovery", description: "Trying to figure out your environment", techniques: 31, color: "#22c55e" },
  { id: "TA0008", name: "Lateral Movement", description: "Moving through your environment", techniques: 9, color: "#10b981" },
  { id: "TA0009", name: "Collection", description: "Gathering data of interest", techniques: 17, color: "#14b8a6" },
  { id: "TA0011", name: "Command and Control", description: "Communicating with compromised systems", techniques: 16, color: "#06b6d4" },
  { id: "TA0010", name: "Exfiltration", description: "Stealing data", techniques: 9, color: "#0ea5e9" },
  { id: "TA0040", name: "Impact", description: "Manipulate, interrupt, or destroy systems", techniques: 14, color: "#3b82f6" },
];

// Intelligence Sources Database
export const intelligenceSources: IntelSource[] = [
  // Free & Open Source
  { name: "MITRE ATT&CK", type: "Framework", url: "https://attack.mitre.org/", description: "Knowledge base of adversary tactics and techniques", free: true, category: "Framework" },
  { name: "VirusTotal", type: "Analysis", url: "https://www.virustotal.com/", description: "Multi-scanner malware analysis platform", free: true, category: "Malware Analysis" },
  { name: "AlienVault OTX", type: "Threat Feed", url: "https://otx.alienvault.com/", description: "Open threat exchange with community indicators", free: true, category: "Threat Feed" },
  { name: "AbuseIPDB", type: "Reputation", url: "https://www.abuseipdb.com/", description: "IP address abuse reports and blacklist", free: true, category: "Reputation" },
  { name: "URLhaus", type: "Threat Feed", url: "https://urlhaus.abuse.ch/", description: "Malicious URL tracking by abuse.ch", free: true, category: "Threat Feed" },
  { name: "MalwareBazaar", type: "Samples", url: "https://bazaar.abuse.ch/", description: "Malware sample sharing platform", free: true, category: "Malware Analysis" },
  { name: "Shodan", type: "Reconnaissance", url: "https://www.shodan.io/", description: "Search engine for Internet-connected devices", free: true, category: "OSINT" },
  { name: "Censys", type: "Reconnaissance", url: "https://censys.io/", description: "Internet-wide scanning and search", free: true, category: "OSINT" },
  { name: "GreyNoise", type: "Reconnaissance", url: "https://www.greynoise.io/", description: "Internet background noise analysis", free: true, category: "OSINT" },
  { name: "MISP Project", type: "Platform", url: "https://www.misp-project.org/", description: "Open source threat intelligence platform", free: true, category: "Platform" },
  { name: "OpenCTI", type: "Platform", url: "https://www.opencti.io/", description: "Open source CTI platform for knowledge management", free: true, category: "Platform" },
  { name: "PhishTank", type: "Threat Feed", url: "https://phishtank.org/", description: "Community-driven phishing URL verification", free: true, category: "Phishing" },
  { name: "ThreatFox", type: "Threat Feed", url: "https://threatfox.abuse.ch/", description: "IOC sharing platform by abuse.ch", free: true, category: "Threat Feed" },
  { name: "Feodo Tracker", type: "Threat Feed", url: "https://feodotracker.abuse.ch/", description: "Botnet C2 tracker (Dridex, Emotet, TrickBot)", free: true, category: "Threat Feed" },
  { name: "SSL Blacklist", type: "Threat Feed", url: "https://sslbl.abuse.ch/", description: "Malicious SSL certificate fingerprints", free: true, category: "Threat Feed" },
  { name: "Pulsedive", type: "Analysis", url: "https://pulsedive.com/", description: "Community threat intelligence with API", free: true, category: "Analysis" },
  { name: "ANY.RUN", type: "Sandbox", url: "https://any.run/", description: "Interactive malware sandbox", free: true, category: "Malware Analysis" },
  { name: "Hybrid Analysis", type: "Sandbox", url: "https://www.hybrid-analysis.com/", description: "Free malware analysis service", free: true, category: "Malware Analysis" },
  { name: "Joe Sandbox", type: "Sandbox", url: "https://www.joesandbox.com/", description: "Deep malware analysis platform", free: true, category: "Malware Analysis" },
  
  // Commercial
  { name: "Recorded Future", type: "Platform", url: "https://www.recordedfuture.com/", description: "AI-powered threat intelligence platform", free: false, category: "Platform" },
  { name: "Mandiant", type: "Services", url: "https://www.mandiant.com/", description: "Threat intelligence and incident response", free: false, category: "Services" },
  { name: "CrowdStrike Falcon", type: "Platform", url: "https://www.crowdstrike.com/", description: "EDR with integrated threat intelligence", free: false, category: "Platform" },
  { name: "ThreatConnect", type: "Platform", url: "https://www.threatconnect.com/", description: "Threat intelligence operations platform", free: false, category: "Platform" },
  { name: "Intel 471", type: "Dark Web", url: "https://intel471.com/", description: "Underground and dark web intelligence", free: false, category: "Dark Web" },
  { name: "Flashpoint", type: "Dark Web", url: "https://www.flashpoint.io/", description: "Deep and dark web threat intelligence", free: false, category: "Dark Web" },
  { name: "Digital Shadows", type: "Platform", url: "https://www.digitalshadows.com/", description: "Digital risk protection and intelligence", free: false, category: "Platform" },
  { name: "RiskIQ", type: "Platform", url: "https://www.riskiq.com/", description: "External threat intelligence platform", free: false, category: "Platform" },
  { name: "Domain Tools", type: "OSINT", url: "https://www.domaintools.com/", description: "Domain and DNS intelligence", free: false, category: "OSINT" },
  { name: "Team Cymru", type: "Network", url: "https://www.team-cymru.com/", description: "Network security and threat intelligence", free: false, category: "Network" },
];

// Advanced Analysis Techniques
export const analysisTechniques: AnalysisTechnique[] = [
  {
    name: "Malware Reverse Engineering",
    description: "Disassembling and analyzing malware to understand functionality and extract IOCs",
    steps: [
      "Safely obtain and quarantine the sample",
      "Perform static analysis (strings, imports, PE headers)",
      "Set up isolated analysis environment (VM/sandbox)",
      "Perform dynamic analysis (execution, network traffic)",
      "Disassemble with IDA Pro or Ghidra",
      "Document C2 infrastructure, capabilities, and IOCs"
    ],
    tools: ["IDA Pro", "Ghidra", "x64dbg", "OllyDbg", "PE-Bear", "CFF Explorer"],
    difficulty: "Advanced"
  },
  {
    name: "Infrastructure Analysis",
    description: "Mapping attacker infrastructure through passive DNS, WHOIS, and certificate analysis",
    steps: [
      "Collect initial IOCs (domains, IPs)",
      "Query passive DNS for historical resolutions",
      "Analyze WHOIS records for registrant patterns",
      "Extract SSL/TLS certificate information",
      "Identify hosting patterns and ASN relationships",
      "Build infrastructure graph and identify clusters"
    ],
    tools: ["PassiveTotal", "DomainTools", "Censys", "Shodan", "Maltego", "urlscan.io"],
    difficulty: "Intermediate"
  },
  {
    name: "Memory Forensics",
    description: "Analyzing RAM dumps to identify malicious processes, injected code, and artifacts",
    steps: [
      "Acquire memory dump from compromised system",
      "Identify suspicious processes and network connections",
      "Analyze process memory for injected code",
      "Extract strings, URLs, and potential C2",
      "Identify rootkit hooks and hidden processes",
      "Recover encryption keys and credentials"
    ],
    tools: ["Volatility 3", "Rekall", "MemProcFS", "WinDbg", "YARA"],
    difficulty: "Advanced"
  },
  {
    name: "Network Traffic Analysis",
    description: "Examining PCAP files to identify C2 communication and data exfiltration",
    steps: [
      "Capture or obtain network traffic",
      "Filter for suspicious protocols and destinations",
      "Analyze DNS queries for DGA patterns",
      "Examine HTTP/HTTPS traffic (with TLS inspection)",
      "Identify beaconing behavior",
      "Extract transferred files and data"
    ],
    tools: ["Wireshark", "Zeek", "NetworkMiner", "tcpdump", "Arkime", "Suricata"],
    difficulty: "Intermediate"
  },
  {
    name: "Threat Hunting",
    description: "Proactively searching for undetected threats using hypothesis-driven investigation",
    steps: [
      "Develop hypothesis based on threat intelligence",
      "Define hunting scope and data sources",
      "Build detection queries (SIEM, EDR)",
      "Execute hunt and analyze results",
      "Investigate anomalies and validate findings",
      "Document and create detections for findings"
    ],
    tools: ["Splunk", "Elastic SIEM", "CrowdStrike Falcon", "Microsoft Sentinel", "Carbon Black"],
    difficulty: "Advanced"
  },
  {
    name: "OSINT Collection",
    description: "Gathering publicly available information about threat actors and campaigns",
    steps: [
      "Define intelligence requirements",
      "Identify relevant sources (social media, forums, paste sites)",
      "Set up monitoring and alerts",
      "Collect and normalize data",
      "Analyze for patterns and connections",
      "Validate and cross-reference findings"
    ],
    tools: ["Maltego", "SpiderFoot", "theHarvester", "Shodan", "Google Dorks", "Social media APIs"],
    difficulty: "Beginner"
  },
  {
    name: "Indicator Enrichment",
    description: "Adding context and confidence scoring to raw IOCs",
    steps: [
      "Collect raw indicators from incident",
      "Query reputation services (VT, AbuseIPDB)",
      "Lookup passive DNS and WHOIS",
      "Check against known threat actor infrastructure",
      "Add MITRE ATT&CK mapping",
      "Assign confidence and severity scores"
    ],
    tools: ["MISP", "OpenCTI", "Cortex Analyzers", "VirusTotal API", "Shodan API"],
    difficulty: "Beginner"
  },
  {
    name: "Campaign Tracking",
    description: "Monitoring ongoing threat campaigns and their evolution over time",
    steps: [
      "Establish baseline of known campaign IOCs and TTPs",
      "Set up alerting for new related activity",
      "Track infrastructure changes and new domains",
      "Monitor for malware updates and variants",
      "Document victimology and targeting patterns",
      "Predict future activity based on patterns"
    ],
    tools: ["MISP", "OpenCTI", "Splunk ES", "Recorded Future", "Custom scripts"],
    difficulty: "Intermediate"
  },
];

// Threat Landscape Trends
export const threatLandscape: ThreatLandscape[] = [
  {
    category: "Ransomware",
    trend: "increasing",
    description: "Ransomware attacks continue to surge with more sophisticated double/triple extortion tactics",
    keyStats: ["Average ransom: $1.5M (2024)", "Recovery time: 22 days avg", "85% target backups first", "RaaS models dominate"]
  },
  {
    category: "Supply Chain Attacks",
    trend: "increasing",
    description: "Attacks targeting software supply chains and third-party vendors",
    keyStats: ["742% increase since 2019", "MOVEit affected 2,600+ orgs", "Average 3rd party per breach: 4", "Open source targeting up 250%"]
  },
  {
    category: "AI-Enabled Attacks",
    trend: "increasing",
    description: "Threat actors leveraging AI for phishing, deepfakes, and malware development",
    keyStats: ["Deepfake fraud up 3000%", "AI phishing 40% more effective", "Automated recon tools", "LLM-generated malware emerging"]
  },
  {
    category: "State-Sponsored Espionage",
    trend: "stable",
    description: "Nation-state actors maintain consistent espionage operations targeting critical infrastructure",
    keyStats: ["China: Most active nation-state", "Russia: Destructive capabilities", "Iran: Increased aggression", "DPRK: $3B crypto theft"]
  },
  {
    category: "Credential Attacks",
    trend: "increasing",
    description: "Password spraying, credential stuffing, and infostealer malware on the rise",
    keyStats: ["24B credentials exposed", "Infostealers: 266% increase", "MFA bypass techniques evolving", "Session hijacking common"]
  },
  {
    category: "Cloud Targeting",
    trend: "increasing",
    description: "Attackers increasingly focus on cloud infrastructure misconfigurations",
    keyStats: ["82% breaches involve cloud", "IAM attacks up 200%", "Exposed storage: #1 issue", "Kubernetes attacks emerging"]
  },
  {
    category: "Mobile Threats",
    trend: "increasing",
    description: "Mobile malware and spyware targeting iOS and Android devices",
    keyStats: ["Pegasus-like tools proliferating", "Banking trojans dominant", "SMS phishing (smishing) up 328%", "MDM bypass techniques evolving"]
  },
  {
    category: "IoT/OT Targeting",
    trend: "increasing",
    description: "Attacks on Internet of Things and Operational Technology systems",
    keyStats: ["ICS malware families: 50+", "Healthcare IoT targeted", "SOHO router botnets", "Volt Typhoon pre-positioning"]
  },
];

// Attribution Confidence Levels
export const attributionConfidence = [
  {
    level: "High Confidence",
    percentage: "90%+",
    indicators: [
      "Direct government attribution",
      "Operational security failures revealing identity",
      "Captured infrastructure with forensic evidence",
      "HUMINT confirmation"
    ],
    color: "#22c55e"
  },
  {
    level: "Moderate Confidence",
    percentage: "60-89%",
    indicators: [
      "Consistent TTP overlap with known actors",
      "Infrastructure linked to previous campaigns",
      "Victimology aligns with state interests",
      "Code and tooling similarities"
    ],
    color: "#f59e0b"
  },
  {
    level: "Low Confidence",
    percentage: "30-59%",
    indicators: [
      "Limited TTP overlap",
      "False flag indicators present",
      "New actor or significant evolution",
      "Possible contractor/proxy relationship"
    ],
    color: "#ef4444"
  },
  {
    level: "Unknown/Unattributed",
    percentage: "<30%",
    indicators: [
      "Novel TTPs with no historical match",
      "Clean operational security",
      "Contradictory indicators",
      "Insufficient data for analysis"
    ],
    color: "#6b7280"
  }
];

// Common Malware Families
export const malwareFamilies = [
  {
    name: "Cobalt Strike",
    type: "Post-Exploitation Framework",
    description: "Commercial adversary simulation tool heavily abused by threat actors",
    capabilities: ["Beacon implant", "Lateral movement", "Credential harvesting", "C2 flexibility"],
    usedBy: ["APT29", "APT41", "FIN7", "Multiple ransomware groups"],
    detection: ["YARA rules", "Network signatures", "Memory analysis", "Beacon config extraction"]
  },
  {
    name: "Mimikatz",
    type: "Credential Harvester",
    description: "Windows credential extraction tool for pass-the-hash and Kerberos attacks",
    capabilities: ["LSASS dumping", "Pass-the-hash", "Golden/Silver tickets", "DCSync"],
    usedBy: ["Nearly all threat actors post-exploitation"],
    detection: ["LSASS access monitoring", "Command line logging", "AMSI integration", "Memory protection"]
  },
  {
    name: "Emotet",
    type: "Botnet/Loader",
    description: "Modular botnet that evolved into major malware distribution platform",
    capabilities: ["Email harvesting", "Spam distribution", "Module loading", "Lateral movement"],
    usedBy: ["TA542 (Mummy Spider)", "Sold access to ransomware crews"],
    detection: ["Email indicators", "Network C2 patterns", "Document analysis", "Behavior analysis"]
  },
  {
    name: "QakBot/QBot",
    type: "Banking Trojan/Loader",
    description: "Long-running banking trojan evolved into ransomware access broker",
    capabilities: ["Credential theft", "Email harvesting", "Module system", "Ransomware delivery"],
    usedBy: ["Black Basta", "Royal", "Various RaaS affiliates"],
    detection: ["Scheduled task persistence", "DLL sideloading", "Network patterns", "Registry artifacts"]
  },
  {
    name: "PlugX",
    type: "Remote Access Trojan",
    description: "Chinese-origin RAT used extensively by APT groups",
    capabilities: ["Keylogging", "Screen capture", "File operations", "Process injection"],
    usedBy: ["APT10", "APT27", "APT41", "Mustang Panda"],
    detection: ["DLL sideloading", "Persistence mechanisms", "Network C2", "Memory artifacts"]
  },
  {
    name: "ShadowPad",
    type: "Modular Backdoor",
    description: "Sophisticated backdoor shared among Chinese threat actors",
    capabilities: ["Modular plugins", "Kernel rootkit", "Anti-analysis", "Encrypted C2"],
    usedBy: ["APT41", "APT27", "Multiple Chinese groups"],
    detection: ["Memory forensics", "Kernel driver analysis", "Network decryption", "Behavioral analysis"]
  },
  {
    name: "Sliver",
    type: "C2 Framework",
    description: "Open-source adversary emulation framework gaining threat actor adoption",
    capabilities: ["Cross-platform implants", "mTLS/WireGuard C2", "Staged/stageless payloads", "Process injection"],
    usedBy: ["APT29", "Various criminal groups"],
    detection: ["Network signatures", "Implant configuration", "Process hollowing", "Memory analysis"]
  },
  {
    name: "BruteRatel",
    type: "C2 Framework",
    description: "Red team tool designed to evade EDR, increasingly abused by attackers",
    capabilities: ["EDR evasion", "Syscall execution", "Token manipulation", "Encrypted C2"],
    usedBy: ["Black Basta", "Various ransomware affiliates"],
    detection: ["Memory analysis", "Badger implant signatures", "Network artifacts", "Behavioral patterns"]
  },
];

// Defensive Recommendations by Actor Type
export const defensiveRecommendations = {
  "nation-state": {
    priority: "Critical",
    recommendations: [
      "Implement zero-trust architecture",
      "Deploy advanced EDR with behavioral analysis",
      "Segment networks with strict access controls",
      "Enable comprehensive logging (1 year retention)",
      "Conduct regular threat hunting",
      "Implement hardware security keys for MFA",
      "Monitor for living-off-the-land techniques",
      "Subscribe to government threat advisories"
    ]
  },
  "ransomware": {
    priority: "Critical",
    recommendations: [
      "Maintain offline, immutable backups (3-2-1 rule)",
      "Implement privileged access management (PAM)",
      "Deploy email security with attachment sandboxing",
      "Disable RDP or require VPN + MFA",
      "Patch known exploited vulnerabilities (KEV)",
      "Train users on phishing identification",
      "Develop and test incident response plan",
      "Consider cyber insurance coverage"
    ]
  },
  "hacktivist": {
    priority: "Medium",
    recommendations: [
      "Deploy DDoS mitigation services",
      "Monitor social media for targeting mentions",
      "Secure external-facing applications",
      "Implement web application firewall (WAF)",
      "Regular vulnerability scanning",
      "Incident communication plan",
      "Document and log defacement recovery",
      "Monitor paste sites for data leaks"
    ]
  },
  "ecrime": {
    priority: "High",
    recommendations: [
      "Implement strong email authentication (DMARC)",
      "Deploy credential monitoring services",
      "Use password managers enterprise-wide",
      "Implement conditional access policies",
      "Monitor dark web for credential exposure",
      "Train users on business email compromise",
      "Verify payment changes through secondary channel",
      "Regular phishing simulations"
    ]
  }
};

// Report Writing Templates
export const reportTemplates = {
  threatBrief: {
    name: "Threat Brief",
    sections: [
      "Executive Summary (1 paragraph)",
      "Key Findings (bullet points)",
      "Threat Actor Profile",
      "Technical Analysis",
      "Indicators of Compromise",
      "Defensive Recommendations",
      "References"
    ],
    audience: "Security leadership, SOC teams",
    frequency: "As needed, within 24-48 hours"
  },
  campaignReport: {
    name: "Campaign Analysis",
    sections: [
      "Executive Summary",
      "Campaign Timeline",
      "Victimology",
      "Attack Chain Analysis",
      "Infrastructure Mapping",
      "Malware Analysis",
      "Attribution Assessment",
      "IOCs (Appendix)",
      "MITRE ATT&CK Mapping"
    ],
    audience: "CTI analysts, incident responders",
    frequency: "Per campaign, 1-2 weeks"
  },
  actorProfile: {
    name: "Threat Actor Profile",
    sections: [
      "Actor Overview",
      "Aliases and Naming",
      "Attribution Confidence",
      "Motivation and Objectives",
      "Historical Activity",
      "Target Industries/Regions",
      "TTPs (MITRE ATT&CK)",
      "Tools and Malware",
      "Infrastructure Patterns",
      "Detection Opportunities"
    ],
    audience: "CTI teams, security architects",
    frequency: "Annual update or major change"
  },
  weeklyIntelSummary: {
    name: "Weekly Intelligence Summary",
    sections: [
      "Notable Incidents This Week",
      "New Vulnerabilities (Prioritized)",
      "Threat Actor Activity",
      "Industry-Specific Threats",
      "Recommended Actions",
      "Looking Ahead"
    ],
    audience: "Security teams, leadership",
    frequency: "Weekly"
  }
};
