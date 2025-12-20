import React from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Container,
  Typography,
  Paper,
  Chip,
  Button,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  alpha,
  useTheme,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import FolderSpecialIcon from "@mui/icons-material/FolderSpecial";
import GitHubIcon from "@mui/icons-material/GitHub";
import CreateIcon from "@mui/icons-material/Create";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import BugReportIcon from "@mui/icons-material/BugReport";
import PublicIcon from "@mui/icons-material/Public";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import StarIcon from "@mui/icons-material/Star";
import { useNavigate } from "react-router-dom";

interface PortfolioSection {
  title: string;
  icon: React.ReactNode;
  color: string;
  description: string;
  items: string[];
  tip: string;
}

const portfolioSections: PortfolioSection[] = [
  {
    title: "GitHub Projects",
    icon: <GitHubIcon sx={{ fontSize: 36 }} />,
    color: "#6366f1",
    description: "Showcase your technical skills with public repositories.",
    items: [
      "Security tools (scanners, fuzzers, analyzers)",
      "CTF writeups and solution scripts",
      "Home lab automation (IaC configs)",
      "Vulnerability research/PoCs (responsibly disclosed)",
      "Contributions to open-source security projects",
    ],
    tip: "Keep repos organized with clear READMEs, documentation, and commit history.",
  },
  {
    title: "Blog / Technical Writing",
    icon: <CreateIcon sx={{ fontSize: 36 }} />,
    color: "#ec4899",
    description: "Demonstrate expertise and communication skills through writing.",
    items: [
      "CTF walkthroughs and challenge explanations",
      "Vulnerability analysis and research",
      "Tool tutorials and how-to guides",
      "Career reflections and lessons learned",
      "News commentary and trend analysis",
    ],
    tip: "Platforms: Medium, DEV.to, Hashnode, personal site, or GitHub Pages.",
  },
  {
    title: "CTF Achievements",
    icon: <EmojiEventsIcon sx={{ fontSize: 36 }} />,
    color: "#f59e0b",
    description: "Prove your hands-on skills through competitions.",
    items: [
      "HackTheBox rank and machine completions",
      "TryHackMe badges and learning paths",
      "CTFtime profile with event history",
      "Notable placements in competitions",
      "Specialization areas (web, pwn, crypto, forensics)",
    ],
    tip: "Document your journey with screenshots and writeups (after events end).",
  },
  {
    title: "Bug Bounty / Research",
    icon: <BugReportIcon sx={{ fontSize: 36 }} />,
    color: "#ef4444",
    description: "Show real-world impact through responsible disclosure.",
    items: [
      "Hall of Fame listings from companies",
      "CVEs you've discovered and reported",
      "HackerOne / Bugcrowd reputation and stats",
      "Detailed case studies (with permission)",
      "Methodology documentation",
    ],
    tip: "Focus on quality findings over quantity. One impactful bug beats many dupes.",
  },
];

const presenceTips = [
  "LinkedIn profile optimized with keywords and certifications",
  "Twitter/X for engaging with the security community",
  "Conference talks, even at local meetups, boost credibility",
  "Podcast appearances or YouTube content",
  "Newsletter or community involvement",
];

const portfolioMistakes = [
  "Empty GitHub with no commits or activity",
  "Claiming skills you can't demonstrate",
  "Sharing tools without context or documentation",
  "Exposing sensitive info (API keys, real targets)",
  "Not updating portfolio for months/years",
];

const roleTracks = [
  {
    role: "Application Security",
    focus: "Secure code review, web testing, SDLC controls",
    examples: ["OWASP Top 10 labs", "SAST/DAST findings", "secure PR reviews"],
  },
  {
    role: "Cloud / DevSecOps",
    focus: "IaC security, CI/CD hardening, cloud posture",
    examples: ["Terraform guardrails", "CSPM findings", "container build pipelines"],
  },
  {
    role: "Penetration Testing",
    focus: "End-to-end engagements and reporting",
    examples: ["Network lab report", "AD attack path map", "scoping + evidence"],
  },
  {
    role: "Threat Detection",
    focus: "Logs, telemetry, and detection engineering",
    examples: ["Sigma rules", "SIEM queries", "detection coverage matrix"],
  },
];

const caseStudyTemplate = [
  "Title + 1-line impact statement",
  "Scope and rules of engagement (lab or authorized target)",
  "Methodology (recon, testing, validation)",
  "Finding details (root cause, impact, severity)",
  "Fix and verification steps",
  "Artifacts (PoC, screenshots, logs)",
  "Lessons learned and next steps",
];

const qualityChecklist = [
  "Clear README with setup, usage, and screenshots",
  "Repro steps that work on a clean machine",
  "Dependencies pinned and documented",
  "License and contribution guidance",
  "Clean commit history and meaningful messages",
  "Security considerations and safe usage notes",
];

const evidenceArtifacts = [
  "PoC scripts or payloads (sanitized)",
  "Architecture or threat model diagrams",
  "Scan reports or findings summaries",
  "Before/after remediation evidence",
  "Writeups linked to repo tags or releases",
  "Short demo videos or GIFs",
];

const metricsThatMatter = [
  "Impact: severity, affected scope, and business risk",
  "Coverage: what was tested and what was out of scope",
  "Repro: steps and environment required",
  "Signal quality: false positives vs. true positives",
  "Performance: runtime, latency, or scale (if tool-based)",
];

const safetyGuidelines = [
  "Use labs or targets with explicit permission",
  "Redact tokens, IPs, and sensitive data",
  "Avoid publishing exploit code for active systems",
  "Follow responsible disclosure timelines",
  "Call out assumptions and limitations clearly",
];

const maintenanceCadence = [
  "Ship a meaningful update every 4-6 weeks",
  "Archive outdated projects with a short note",
  "Track a public roadmap or backlog",
  "Refresh screenshots after major changes",
];

const portfolioBlueprint = [
  { section: "Homepage", detail: "Who you are, focus areas, and 2-3 featured projects." },
  { section: "Projects", detail: "Case studies with scope, impact, and artifacts." },
  { section: "Writing", detail: "Technical posts and research summaries." },
  { section: "Talks", detail: "Slides, recordings, and abstracts." },
  { section: "Resume", detail: "One-page PDF with keywords and links." },
  { section: "Contact", detail: "Clear ways to reach you and social links." },
];

const projectIdeasByLevel = [
  {
    level: "Beginner",
    ideas: [
      "Home lab report with asset inventory and risk findings",
      "Simple web scanner or log parser with README and tests",
      "CTF writeups focused on one category",
      "Threat model for a common app (login, API, admin)",
    ],
  },
  {
    level: "Intermediate",
    ideas: [
      "Mini pentest report with scope, evidence, and fixes",
      "CI/CD security checks for a demo app",
      "Container hardening guide with benchmarks",
      "Detection rules mapped to ATT&CK techniques",
    ],
  },
  {
    level: "Advanced",
    ideas: [
      "Original tool with performance benchmarks",
      "Vulnerability research writeup with responsible disclosure",
      "Cloud posture assessment for a sample environment",
      "Purple team exercise with detection and response plan",
    ],
  },
];

const reviewerChecklist = [
  "Is the project goal clear in 1-2 sentences?",
  "Can I reproduce the results quickly?",
  "Do you show impact and how you validated it?",
  "Is the work scoped and ethical?",
  "Are results organized and easy to skim?",
];

const interviewHooks = [
  "Top 3 stories you can demo live",
  "One failure and how you fixed it",
  "A project that shows teamwork or collaboration",
  "A project that shows automation or efficiency",
];

const storytellingFramework = [
  "Situation: the environment or target",
  "Task: what you set out to accomplish",
  "Action: steps, tools, and decisions",
  "Result: impact and evidence",
  "Reflection: lessons and improvements",
];

const signalToEmployers = [
  "Clarity: easy to understand and navigate",
  "Depth: not just outputs, but reasoning",
  "Safety: ethical scope and data handling",
  "Rigor: validation steps and reproducibility",
  "Communication: concise, professional writing",
];

export default function SecurityPortfolioPage() {
  const navigate = useNavigate();
  const theme = useTheme();

  const pageContext = `Building a Security Portfolio Guide - How to build an impressive cybersecurity portfolio including GitHub projects (security tools, CTF writeups, home lab configs), technical blog writing (walkthroughs, tutorials, research), CTF achievements (HackTheBox, TryHackMe, CTFtime), and bug bounty/research (CVEs, hall of fame, case studies). Covers role-focused strategy, case study templates, evidence artifacts, metrics that matter, safety guidelines, maintenance cadence, online presence, and common portfolio mistakes to avoid.`;

  return (
    <LearnPageLayout pageTitle="Building a Security Portfolio" pageContext={pageContext}>
      <Container maxWidth="lg" sx={{ py: 4 }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Button
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{ mb: 2 }}
          >
            Back to Learning Hub
          </Button>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <Box
              sx={{
                width: 64,
                height: 64,
                borderRadius: 2,
                bgcolor: alpha("#6366f1", 0.1),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <FolderSpecialIcon sx={{ fontSize: 36, color: "#6366f1" }} />
            </Box>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Building a Security Portfolio
              </Typography>
              <Typography variant="body1" color="text.secondary">
                Stand out to employers with a compelling portfolio
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip label="Career" color="primary" size="small" />
            <Chip label="GitHub" size="small" sx={{ bgcolor: alpha("#6366f1", 0.1), color: "#6366f1" }} />
            <Chip label="CTF" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.1), color: "#f59e0b" }} />
            <Chip label="Blog" size="small" sx={{ bgcolor: alpha("#ec4899", 0.1), color: "#ec4899" }} />
          </Box>
        </Box>

        {/* Intro */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TipsAndUpdatesIcon color="primary" /> Why Build a Portfolio?
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8 }}>
            In cybersecurity, demonstrating practical skills matters more than degrees alone. A strong portfolio shows 
            employers what you can actually do—not just what you claim. It differentiates you from other candidates, 
            especially when breaking into the field. Think of it as proof-of-work for your security skills.
          </Typography>
        </Paper>

        {/* Portfolio Sections Grid */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          🎯 Portfolio Components
        </Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          {portfolioSections.map((section) => (
            <Grid item xs={12} md={6} key={section.title}>
              <Paper
                sx={{
                  p: 3,
                  height: "100%",
                  borderRadius: 3,
                  border: `1px solid ${alpha(section.color, 0.2)}`,
                  transition: "all 0.3s ease",
                  "&:hover": {
                    borderColor: section.color,
                    boxShadow: `0 8px 30px ${alpha(section.color, 0.15)}`,
                  },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                  <Box
                    sx={{
                      width: 56,
                      height: 56,
                      borderRadius: 2,
                      bgcolor: alpha(section.color, 0.1),
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      color: section.color,
                    }}
                  >
                    {section.icon}
                  </Box>
                  <Typography variant="h6" sx={{ fontWeight: 700 }}>
                    {section.title}
                  </Typography>
                </Box>
                
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  {section.description}
                </Typography>

                {/* Items */}
                <List dense sx={{ mb: 2 }}>
                  {section.items.map((item, i) => (
                    <ListItem key={i} sx={{ py: 0.25, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: section.color }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={item}
                        primaryTypographyProps={{ variant: "body2" }}
                      />
                    </ListItem>
                  ))}
                </List>

                {/* Tip */}
                <Paper
                  sx={{
                    p: 1.5,
                    borderRadius: 2,
                    bgcolor: alpha(section.color, 0.05),
                    border: `1px solid ${alpha(section.color, 0.1)}`,
                  }}
                >
                  <Typography variant="caption" sx={{ fontWeight: 600, color: section.color }}>
                    💡 Tip: {section.tip}
                  </Typography>
                </Paper>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Role Focus */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          ?? Focus Your Portfolio by Role
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {roleTracks.map((track) => (
            <Grid item xs={12} md={6} key={track.role}>
              <Paper
                sx={{
                  p: 3,
                  height: "100%",
                  borderRadius: 3,
                  border: `1px solid ${alpha(theme.palette.primary.main, 0.15)}`,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
                  {track.role}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Focus: {track.focus}
                </Typography>
                <List dense>
                  {track.examples.map((example) => (
                    <ListItem key={example} sx={{ py: 0.25, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: theme.palette.primary.main }} />
                      </ListItemIcon>
                      <ListItemText primary={example} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Portfolio Blueprint */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#6366f1", 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            ?? Portfolio Layout Blueprint
          </Typography>
          <Grid container spacing={2}>
            {portfolioBlueprint.map((item) => (
              <Grid item xs={12} md={6} key={item.section}>
                <Box sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#6366f1", 0.15)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
                    {item.section}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {item.detail}
                  </Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Project Ideas */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          ?? Project Ideas by Level
        </Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {projectIdeasByLevel.map((group) => (
            <Grid item xs={12} md={4} key={group.level}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 3 }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
                  {group.level}
                </Typography>
                <List dense>
                  {group.ideas.map((idea) => (
                    <ListItem key={idea} sx={{ py: 0.25, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ fontSize: 16, color: theme.palette.primary.main }} />
                      </ListItemIcon>
                      <ListItemText primary={idea} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Case Study + Quality Checklist */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                ?? Case Study Template
              </Typography>
              <List dense>
                {caseStudyTemplate.map((step) => (
                  <ListItem key={step} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <StarIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={step} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#10b981", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                ?? Quality Checklist
              </Typography>
              <List dense>
                {qualityChecklist.map((item) => (
                  <ListItem key={item} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Storytelling and Review Signals */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                ?? Storytelling Framework
              </Typography>
              <List dense>
                {storytellingFramework.map((item) => (
                  <ListItem key={item} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <StarIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#10b981", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                ?? What Reviewers Look For
              </Typography>
              <List dense>
                {signalToEmployers.map((item) => (
                  <ListItem key={item} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#10b981" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Evidence Artifacts */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#6366f1", 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            ?? Evidence and Artifacts
          </Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {evidenceArtifacts.map((artifact) => (
              <Chip key={artifact} label={artifact} variant="outlined" size="small" />
            ))}
          </Box>
        </Paper>

        {/* Reviewer Checklist and Interview Hooks */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                ?? Reviewer Checklist
              </Typography>
              <List dense>
                {reviewerChecklist.map((item) => (
                  <ListItem key={item} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#f59e0b", 0.05) }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                ?? Interview Hooks
              </Typography>
              <List dense>
                {interviewHooks.map((item) => (
                  <ListItem key={item} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <StarIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Metrics */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.04) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            ?? Metrics That Matter
          </Typography>
          <List dense>
            {metricsThatMatter.map((metric) => (
              <ListItem key={metric} sx={{ py: 0.5 }}>
                <ListItemIcon sx={{ minWidth: 32 }}>
                  <StarIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                </ListItemIcon>
                <ListItemText primary={metric} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* Safety and Ethics */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#ef4444", 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
            ?? Safety and Ethics
          </Typography>
          <List dense>
            {safetyGuidelines.map((item) => (
              <ListItem key={item} sx={{ py: 0.5 }}>
                <ListItemIcon sx={{ minWidth: 32 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                </ListItemIcon>
                <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* Maintenance */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.05) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TipsAndUpdatesIcon sx={{ color: "#f59e0b" }} /> Maintenance Cadence
          </Typography>
          <List dense>
            {maintenanceCadence.map((item) => (
              <ListItem key={item} sx={{ py: 0.5 }}>
                <ListItemIcon sx={{ minWidth: 32 }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#f59e0b" }} />
                </ListItemIcon>
                <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* Online Presence */}
        <Paper
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#3b82f6", 0.05)}, ${alpha("#6366f1", 0.05)})`,
            border: `1px solid ${alpha("#3b82f6", 0.2)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <PublicIcon sx={{ color: "#3b82f6" }} /> Building Online Presence
          </Typography>
          <List dense>
            {presenceTips.map((tip, i) => (
              <ListItem key={i} sx={{ py: 0.5 }}>
                <ListItemIcon sx={{ minWidth: 32 }}>
                  <StarIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                </ListItemIcon>
                <ListItemText primary={tip} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* Common Mistakes */}
        <Paper
          sx={{
            p: 3,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#ef4444", 0.03)}, ${alpha("#f59e0b", 0.03)})`,
            border: `1px solid ${alpha("#ef4444", 0.15)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
            ⚠️ Portfolio Mistakes to Avoid
          </Typography>
          <List dense>
            {portfolioMistakes.map((mistake, i) => (
              <ListItem key={i} sx={{ py: 0.5 }}>
                <ListItemIcon sx={{ minWidth: 32 }}>
                  <Box
                    sx={{
                      width: 8,
                      height: 8,
                      borderRadius: "50%",
                      bgcolor: "#ef4444",
                    }}
                  />
                </ListItemIcon>
                <ListItemText primary={mistake} primaryTypographyProps={{ variant: "body2" }} />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* Related Pages */}
        <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha(theme.palette.primary.main, 0.03) }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            📚 Related Learning
          </Typography>
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
            <Chip
              label="Career Paths →"
              clickable
              onClick={() => navigate("/learn/career-paths")}
              sx={{ fontWeight: 600 }}
            />
            <Chip
              label="Security Certifications →"
              clickable
              onClick={() => navigate("/learn/certifications")}
              sx={{ fontWeight: 600 }}
            />
          </Box>
        </Paper>
      </Container>
    </LearnPageLayout>
  );
}
