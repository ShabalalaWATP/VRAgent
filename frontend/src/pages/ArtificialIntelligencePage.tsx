import {
  Typography,
  Paper,
  Box,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  alpha,
  Button,
  Container,
} from "@mui/material";
import LearnPageLayout from "../components/LearnPageLayout";
import PsychologyIcon from "@mui/icons-material/Psychology";
import StorageIcon from "@mui/icons-material/Storage";
import FunctionsIcon from "@mui/icons-material/Functions";
import CodeIcon from "@mui/icons-material/Code";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import CategoryIcon from "@mui/icons-material/Category";
import LayersIcon from "@mui/icons-material/Layers";
import TextFieldsIcon from "@mui/icons-material/TextFields";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import VisibilityIcon from "@mui/icons-material/Visibility";
import RecordVoiceOverIcon from "@mui/icons-material/RecordVoiceOver";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import AssessmentIcon from "@mui/icons-material/Assessment";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import CloudIcon from "@mui/icons-material/Cloud";
import SecurityIcon from "@mui/icons-material/Security";
import ShieldIcon from "@mui/icons-material/Shield";
import BugReportIcon from "@mui/icons-material/BugReport";
import BuildIcon from "@mui/icons-material/Build";
import GavelIcon from "@mui/icons-material/Gavel";
import WorkIcon from "@mui/icons-material/Work";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import TimelineIcon from "@mui/icons-material/Timeline";
import SchoolIcon from "@mui/icons-material/School";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import { useNavigate } from "react-router-dom";

const outlineSections = [
  {
    id: "foundations",
    title: "Foundations",
    icon: <PsychologyIcon />,
    color: "#8b5cf6",
    status: "Complete",
    description: "AI terminology, core concepts, history, milestones, and project lifecycle",
  },
  {
    id: "data",
    title: "Data",
    icon: <StorageIcon />,
    color: "#3b82f6",
    status: "Complete",
    description: "Collection, labelling, quality, governance, preprocessing, feature engineering, augmentation, bias",
  },
  {
    id: "maths-theory",
    title: "Maths and Theory",
    icon: <FunctionsIcon />,
    color: "#ef4444",
    status: "Complete",
    description: "Statistics, linear algebra, probability, calculus, optimisation, information theory",
  },
  {
    id: "programming-compute",
    title: "Programming and Compute",
    icon: <CodeIcon />,
    color: "#f59e0b",
    status: "Complete",
    description: "Python for AI, version control, CPU/GPU/TPU, performance fundamentals",
  },
  {
    id: "core-ml",
    title: "Core Machine Learning",
    icon: <AccountTreeIcon />,
    color: "#22c55e",
    status: "Complete",
    description: "Supervised, unsupervised, semi-supervised, self-supervised, reinforcement, online, active learning",
  },
  {
    id: "classical-ml",
    title: "Classical ML Models and Techniques",
    icon: <CategoryIcon />,
    color: "#06b6d4",
    status: "Complete",
    description: "Regression, trees, ensembles, SVM, kNN, time series, anomaly detection, recommenders, causal ML, GNNs",
  },
  {
    id: "deep-learning",
    title: "Deep Learning",
    icon: <LayersIcon />,
    color: "#ec4899",
    status: "Complete",
    description: "Neural networks, backpropagation, regularisation, CNNs, RNNs, Transformers, embeddings, transfer learning",
  },
  {
    id: "nlp",
    title: "Natural Language Processing",
    icon: <TextFieldsIcon />,
    color: "#14b8a6",
    status: "Complete",
    description: "Tokenisation, embeddings, classification, NER, summarisation, question answering",
  },
  {
    id: "llm-agents",
    title: "Large Language Models and Agents",
    icon: <SmartToyIcon />,
    color: "#a855f7",
    status: "Complete",
    description: "Pretraining, fine-tuning, alignment, prompting, RAG, tool use, agents, orchestration, evaluation",
  },
  {
    id: "computer-vision",
    title: "Computer Vision",
    icon: <VisibilityIcon />,
    color: "#0ea5e9",
    status: "Complete",
    description: "Classification, detection, segmentation, pose, OCR, video, ViT, generative vision, robustness",
  },
  {
    id: "speech-audio",
    title: "Speech and Audio AI",
    icon: <RecordVoiceOverIcon />,
    color: "#f97316",
    status: "Complete",
    description: "ASR, TTS, speaker recognition, audio classification, signal processing",
  },
  {
    id: "generative-ai",
    title: "Generative AI",
    icon: <AutoAwesomeIcon />,
    color: "#d946ef",
    status: "Complete",
    description: "Generative modelling, diffusion models, GANs, VAEs, code generation",
  },
  {
    id: "evaluation-testing",
    title: "Evaluation and Testing",
    icon: <AssessmentIcon />,
    color: "#84cc16",
    status: "Complete",
    description: "Metrics, validation, calibration, uncertainty, interpretability, XAI, robustness testing",
  },
  {
    id: "mlops-deployment",
    title: "MLOps and Deployment",
    icon: <RocketLaunchIcon />,
    color: "#6366f1",
    status: "Complete",
    description: "Pipelines, CI/CD, serving, edge deployment, optimisation, monitoring, incident response, FinOps",
  },
  {
    id: "platforms-infra",
    title: "Platforms and Infrastructure",
    icon: <CloudIcon />,
    color: "#0891b2",
    status: "Complete",
    description: "Cloud AI (AWS/Azure/GCP), on-prem stacks, vector databases, data engineering for AI",
  },
  {
    id: "ai-security",
    title: "AI Security",
    icon: <SecurityIcon />,
    color: "#dc2626",
    status: "Complete",
    description: "Threat modelling, adversarial ML, privacy attacks, prompt injection, RAG security, supply chain, red teaming",
  },
  {
    id: "ai-cyber-defence",
    title: "AI in Cyber Defence",
    icon: <ShieldIcon />,
    color: "#16a34a",
    status: "Complete",
    description: "SOC triage, ML detection, UEBA, threat intel, phishing/fraud/malware detection, incident response copilots",
  },
  {
    id: "ai-offensive-security",
    title: "AI in Offensive Security",
    icon: <BugReportIcon />,
    color: "#ea580c",
    status: "Complete",
    description: "Recon, attack surface analysis, exploit research, adversary emulation, social engineering controls",
  },
  {
    id: "ai-secure-dev",
    title: "AI for Secure Software Development",
    icon: <BuildIcon />,
    color: "#7c3aed",
    status: "Complete",
    description: "AI code review, AI-enhanced SAST, threat modelling, SBOM and dependency analysis",
  },
  {
    id: "ethics-governance",
    title: "Ethics, Safety, and Governance",
    icon: <GavelIcon />,
    color: "#be185d",
    status: "Complete",
    description: "Bias, fairness, privacy, transparency, accountability, human-in-the-loop, misuse prevention, governance",
  },
  {
    id: "product-practice",
    title: "Product and Professional Practice",
    icon: <WorkIcon />,
    color: "#0d9488",
    status: "Complete",
    description: "AI product management, research literacy, role pathways, portfolio projects, capstones",
  },
];

export default function ArtificialIntelligencePage() {
  const navigate = useNavigate();

  return (
    <LearnPageLayout
      pageTitle="Artificial Intelligence"
      pageContext="This is the Artificial Intelligence learning page covering AI/ML fundamentals, deep learning, NLP, computer vision, LLMs, MLOps, AI security, and AI applications in cybersecurity. Help users understand AI concepts, techniques, and practical applications."
    >
      <Box sx={{ maxWidth: 1200, mx: "auto", p: { xs: 2, md: 4 } }}>
        {/* Header */}
        <Box sx={{ mb: 4, display: "flex", alignItems: "center", gap: 2, flexWrap: "wrap" }}>
          <Chip
            icon={<ArrowBackIcon />}
            label="Back to Learning Hub"
            onClick={() => navigate("/learn")}
            sx={{ cursor: "pointer" }}
          />
          <Chip
            icon={<SchoolIcon />}
            label="IT Fundamentals"
            color="primary"
            variant="outlined"
          />
        </Box>

        <Typography variant="h3" sx={{ fontWeight: 900, mb: 1 }}>
          🤖 Artificial Intelligence
        </Typography>
        <Typography variant="h6" color="text.secondary" sx={{ mb: 4 }}>
          From fundamentals to frontier: understanding and applying AI/ML in the real world
        </Typography>

        {/* Quick Navigation */}
        <Paper sx={{ p: 2, mb: 4, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.1)}` }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "#8b5cf6" }}>
            Quick Navigation
          </Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {[
              { label: "Foundations", id: "foundations" },
              { label: "Data", id: "data" },
              { label: "Maths & Theory", id: "maths-theory" },
              { label: "Programming", id: "programming-compute" },
              { label: "Core ML", id: "core-ml" },
              { label: "Classical ML", id: "classical-ml" },
              { label: "Deep Learning", id: "deep-learning" },
              { label: "NLP", id: "nlp" },
              { label: "LLMs & Agents", id: "llm-agents" },
              { label: "Computer Vision", id: "computer-vision" },
              { label: "Speech & Audio", id: "speech-audio" },
              { label: "Generative AI", id: "generative-ai" },
              { label: "Evaluation", id: "evaluation-testing" },
              { label: "MLOps", id: "mlops-deployment" },
              { label: "Platforms", id: "platforms-infra" },
              { label: "AI Security", id: "ai-security" },
              { label: "AI Defence", id: "ai-cyber-defence" },
              { label: "AI Offensive", id: "ai-offensive-security" },
              { label: "AI Secure Dev", id: "ai-secure-dev" },
              { label: "Ethics", id: "ethics-governance" },
              { label: "Practice", id: "product-practice" },
              { label: "Course Outline", id: "outline" },
            ].map((nav) => (
              <Chip
                key={nav.id}
                label={nav.label}
                size="small"
                onClick={() => document.getElementById(nav.id)?.scrollIntoView({ behavior: "smooth" })}
                sx={{ cursor: "pointer", "&:hover": { bgcolor: alpha("#8b5cf6", 0.1) } }}
              />
            ))}
          </Box>
        </Paper>

        {/* ==================== SECTION 1: FOUNDATIONS ==================== */}
        <Typography id="foundations" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🧠 Foundations
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Understanding what AI is, where it came from, and how AI projects work
        </Typography>

        {/* What is AI - Introduction */}
        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Artificial Intelligence (AI)</strong> is the science of creating systems that can perform tasks 
            that typically require human intelligence — learning from experience, recognizing patterns, understanding 
            language, making decisions, and even generating creative content. It's not magic, and it's not science 
            fiction anymore. AI is the technology powering the recommendations on your streaming service, the spam 
            filter in your email, the voice assistant on your phone, and increasingly, the tools we use for security.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Machine Learning (ML)</strong> is the dominant approach to building AI today. Instead of writing 
            explicit rules ("if email contains 'Nigerian prince', mark as spam"), we show the system thousands of 
            examples and let it learn the patterns itself. The system builds a <strong>model</strong> — a mathematical 
            representation of those patterns — that can then make predictions on new, unseen data.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Deep Learning</strong> is a subset of ML using neural networks with many layers. These architectures 
            excel at learning complex patterns from large amounts of data. Deep learning powers modern breakthroughs: 
            image recognition that rivals humans, language models that write coherent text, and systems that generate 
            photorealistic images from descriptions.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Why does this matter for security professionals?</strong> AI is transforming both attack and 
            defence. Attackers use AI for phishing at scale, automated vulnerability discovery, and evasion. Defenders 
            use AI for anomaly detection, threat hunting, and automating the analyst's workflow. Understanding how 
            these systems work — their capabilities <em>and</em> their limitations — is essential for both building 
            secure AI systems and defending against AI-powered threats.
          </Typography>
        </Paper>

        {/* Core Terminology */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Core Terminology</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { term: "Model", def: "A mathematical function learned from data that makes predictions or decisions", color: "#8b5cf6" },
            { term: "Training", def: "The process of learning patterns from data to build a model", color: "#3b82f6" },
            { term: "Inference", def: "Using a trained model to make predictions on new data", color: "#22c55e" },
            { term: "Dataset", def: "A collection of examples used for training, validation, or testing", color: "#f59e0b" },
            { term: "Features", def: "The input variables/attributes the model uses to make predictions", color: "#ef4444" },
            { term: "Labels", def: "The target outputs/answers in supervised learning", color: "#ec4899" },
            { term: "Parameters", def: "The internal values a model learns during training (weights, biases)", color: "#06b6d4" },
            { term: "Hyperparameters", def: "Configuration choices set before training (learning rate, layers)", color: "#84cc16" },
            { term: "Loss Function", def: "Measures how wrong the model's predictions are — what training minimises", color: "#a855f7" },
            { term: "Overfitting", def: "Model memorises training data but fails on new data", color: "#dc2626" },
            { term: "Generalisation", def: "Model's ability to perform well on unseen data", color: "#0891b2" },
            { term: "Embedding", def: "A learned dense vector representation of data (words, images, etc.)", color: "#d946ef" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.term}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha(item.color, 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>{item.term}</Typography>
                <Typography variant="caption" color="text.secondary">{item.def}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* AI vs ML vs DL */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>AI vs ML vs Deep Learning</Typography>
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <Box sx={{ textAlign: "center", p: 2 }}>
                <Box sx={{ 
                  width: 120, height: 120, borderRadius: "50%", mx: "auto", mb: 2,
                  bgcolor: alpha("#8b5cf6", 0.1), border: `3px solid ${alpha("#8b5cf6", 0.3)}`,
                  display: "flex", alignItems: "center", justifyContent: "center"
                }}>
                  <Typography variant="h4">🤖</Typography>
                </Box>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6" }}>Artificial Intelligence</Typography>
                <Typography variant="caption" color="text.secondary">
                  The broadest term. Any system exhibiting intelligent behaviour. Includes rule-based systems, 
                  expert systems, and machine learning.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ textAlign: "center", p: 2 }}>
                <Box sx={{ 
                  width: 100, height: 100, borderRadius: "50%", mx: "auto", mb: 2,
                  bgcolor: alpha("#3b82f6", 0.1), border: `3px solid ${alpha("#3b82f6", 0.3)}`,
                  display: "flex", alignItems: "center", justifyContent: "center"
                }}>
                  <Typography variant="h4">📊</Typography>
                </Box>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6" }}>Machine Learning</Typography>
                <Typography variant="caption" color="text.secondary">
                  Subset of AI. Systems that learn patterns from data rather than following explicit rules. 
                  Includes classical ML and deep learning.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ textAlign: "center", p: 2 }}>
                <Box sx={{ 
                  width: 80, height: 80, borderRadius: "50%", mx: "auto", mb: 2,
                  bgcolor: alpha("#22c55e", 0.1), border: `3px solid ${alpha("#22c55e", 0.3)}`,
                  display: "flex", alignItems: "center", justifyContent: "center"
                }}>
                  <Typography variant="h4">🧬</Typography>
                </Box>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e" }}>Deep Learning</Typography>
                <Typography variant="caption" color="text.secondary">
                  Subset of ML. Neural networks with many layers that learn hierarchical representations. 
                  Powers modern AI breakthroughs.
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </Paper>

        {/* History and Milestones */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>History and Milestones</Typography>
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
          <Box sx={{ position: "relative" }}>
            {[
              { year: "1950", event: "Turing Test proposed", desc: "Alan Turing asks 'Can machines think?'" },
              { year: "1956", event: "AI term coined", desc: "Dartmouth workshop — AI becomes a field" },
              { year: "1957", event: "Perceptron invented", desc: "First neural network — hype begins" },
              { year: "1969", event: "First AI Winter", desc: "Limitations exposed, funding dries up" },
              { year: "1986", event: "Backpropagation", desc: "Enables training deep networks" },
              { year: "1997", event: "Deep Blue beats Kasparov", desc: "Chess — brute force + heuristics" },
              { year: "2012", event: "AlexNet / ImageNet", desc: "Deep learning revolution begins" },
              { year: "2016", event: "AlphaGo beats Lee Sedol", desc: "Go — deep RL achieves superhuman play" },
              { year: "2017", event: "Transformer architecture", desc: "'Attention Is All You Need' — enables LLMs" },
              { year: "2020", event: "GPT-3 released", desc: "175B parameters — emergent capabilities" },
              { year: "2022", event: "ChatGPT launches", desc: "AI goes mainstream — 100M users in 2 months" },
              { year: "2023+", event: "Multimodal AI / Agents", desc: "GPT-4V, Claude, Gemini — vision + reasoning + tools" },
            ].map((item, index) => (
              <Box key={item.year} sx={{ display: "flex", mb: 2 }}>
                <Box sx={{ width: 70, flexShrink: 0 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>{item.year}</Typography>
                </Box>
                <Box sx={{ 
                  width: 12, height: 12, borderRadius: "50%", bgcolor: "#f59e0b", 
                  flexShrink: 0, mt: 0.5, mr: 2,
                  boxShadow: index === 11 ? `0 0 0 4px ${alpha("#f59e0b", 0.2)}` : "none"
                }} />
                <Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>{item.event}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                </Box>
              </Box>
            ))}
          </Box>
        </Paper>

        {/* AI Lifecycle */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>AI Lifecycle and Project Workflow</Typography>
        <Grid container spacing={2} sx={{ mb: 5 }}>
          {[
            { phase: "1. Problem Definition", tasks: ["Define business objective", "Determine if AI is appropriate", "Define success metrics"], color: "#8b5cf6" },
            { phase: "2. Data Collection", tasks: ["Identify data sources", "Collect and label data", "Assess data quality and bias"], color: "#3b82f6" },
            { phase: "3. Data Preparation", tasks: ["Clean and preprocess", "Feature engineering", "Train/val/test splits"], color: "#22c55e" },
            { phase: "4. Model Development", tasks: ["Select algorithms", "Train models", "Hyperparameter tuning"], color: "#f59e0b" },
            { phase: "5. Evaluation", tasks: ["Measure performance", "Test for bias/fairness", "Validate on held-out data"], color: "#ef4444" },
            { phase: "6. Deployment", tasks: ["Package model", "Deploy to production", "Set up serving infrastructure"], color: "#ec4899" },
            { phase: "7. Monitoring", tasks: ["Track performance drift", "Monitor data quality", "Alert on anomalies"], color: "#06b6d4" },
            { phase: "8. Iteration", tasks: ["Collect feedback", "Retrain with new data", "Improve continuously"], color: "#84cc16" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={3} key={item.phase}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha(item.color, 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, mb: 1 }}>{item.phase}</Typography>
                <List dense disablePadding>
                  {item.tasks.map((task) => (
                    <ListItem key={task} sx={{ py: 0.1, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 16 }}>
                        <CheckCircleIcon sx={{ fontSize: 10, color: item.color }} />
                      </ListItemIcon>
                      <ListItemText primary={task} primaryTypographyProps={{ variant: "caption" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Key Insight */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#10b981", 0.03), border: `1px solid ${alpha("#10b981", 0.15)}` }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
            <TipsAndUpdatesIcon /> Key Insight
          </Typography>
          <Typography variant="body2" color="text.secondary">
            <strong>AI is not a magic solution</strong> — it's a tool with specific strengths and limitations. 
            The most common failure mode isn't the algorithm; it's the data. Garbage in, garbage out. Before 
            reaching for complex deep learning, ask: Do I have enough quality data? Is the problem well-defined? 
            Would a simpler approach work? Understanding these fundamentals will serve you far better than 
            chasing the latest model architecture.
          </Typography>
        </Paper>

        {/* ==================== SECTION 2: DATA ==================== */}
        <Typography id="data" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          📊 Data
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The foundation of every AI system — where quality matters more than quantity
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>"Data is the new oil"</strong> — but like oil, raw data needs refining before it's useful. 
            The quality of your AI system is fundamentally limited by the quality of your data. A sophisticated 
            model trained on poor data will underperform a simple model trained on excellent data. This is why 
            data engineering often consumes 80% of an ML project's time.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Data collection</strong> is more than just gathering examples — it's about capturing the 
            right distribution of cases your model will encounter in production. <strong>Data labelling</strong> 
            transforms raw data into training examples by adding ground truth. For a spam classifier, that means 
            human annotators marking emails as "spam" or "not spam". Labelling is expensive, time-consuming, and 
            error-prone — yet model quality depends on label quality.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Data governance</strong> ensures data is collected ethically, stored securely, and used 
            appropriately. This includes consent, privacy regulations (GDPR, CCPA), retention policies, and 
            access controls. In security contexts, data governance is critical — training data may contain 
            sensitive information, and model outputs can leak training data.
          </Typography>
        </Paper>

        {/* Data Pipeline */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>The Data Pipeline</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { stage: "1. Collection", desc: "Gather raw data from sources (logs, APIs, sensors, user input, scraping)", color: "#3b82f6", icon: "📥" },
            { stage: "2. Storage", desc: "Store in appropriate format (data lake, warehouse, database, object storage)", color: "#8b5cf6", icon: "💾" },
            { stage: "3. Cleaning", desc: "Remove duplicates, fix errors, handle missing values, standardise formats", color: "#22c55e", icon: "🧹" },
            { stage: "4. Labelling", desc: "Add ground truth annotations (manual, semi-automated, or programmatic)", color: "#f59e0b", icon: "🏷️" },
            { stage: "5. Preprocessing", desc: "Transform for ML (normalisation, encoding, tokenisation, resizing)", color: "#ef4444", icon: "⚙️" },
            { stage: "6. Splitting", desc: "Divide into train/validation/test sets (typically 70/15/15 or 80/10/10)", color: "#ec4899", icon: "✂️" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.stage}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha(item.color, 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>
                  {item.icon} {item.stage}
                </Typography>
                <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Data Quality & Feature Engineering */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>⚠️ Data Quality Issues</Typography>
              <List dense>
                {[
                  { issue: "Missing values", fix: "Imputation, deletion, or model-based handling" },
                  { issue: "Outliers", fix: "Detection (IQR, Z-score), removal or capping" },
                  { issue: "Duplicates", fix: "Deduplication based on key fields or fuzzy matching" },
                  { issue: "Inconsistent formats", fix: "Standardisation (dates, currencies, units)" },
                  { issue: "Label noise", fix: "Multiple annotators, consensus, quality checks" },
                  { issue: "Data drift", fix: "Monitoring distributions over time" },
                ].map((item) => (
                  <ListItem key={item.issue} sx={{ py: 0.5, px: 0 }}>
                    <ListItemText 
                      primary={item.issue}
                      secondary={item.fix}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>🔧 Feature Engineering</Typography>
              <List dense>
                {[
                  { technique: "Numerical scaling", example: "Min-max normalisation, standardisation (z-score)" },
                  { technique: "Categorical encoding", example: "One-hot, label encoding, target encoding" },
                  { technique: "Text vectorisation", example: "TF-IDF, word embeddings, tokenisation" },
                  { technique: "Date/time features", example: "Day of week, hour, is_weekend, time since event" },
                  { technique: "Aggregations", example: "Rolling means, counts, ratios, percentiles" },
                  { technique: "Domain features", example: "Log transforms, polynomial features, interactions" },
                ].map((item) => (
                  <ListItem key={item.technique} sx={{ py: 0.5, px: 0 }}>
                    <ListItemText 
                      primary={item.technique}
                      secondary={item.example}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Data Augmentation & Bias */}
        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>🔄 Data Augmentation</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Artificially expanding training data by creating modified versions of existing examples.
              </Typography>
              <Grid container spacing={1}>
                {[
                  { type: "Images", methods: "Rotation, flip, crop, colour jitter, cutout" },
                  { type: "Text", methods: "Synonym replacement, back-translation, paraphrasing" },
                  { type: "Audio", methods: "Time stretch, pitch shift, noise injection" },
                  { type: "Tabular", methods: "SMOTE for imbalanced classes, noise injection" },
                ].map((item) => (
                  <Grid item xs={12} key={item.type}>
                    <Box sx={{ display: "flex", gap: 1 }}>
                      <Chip label={item.type} size="small" sx={{ fontWeight: 600, minWidth: 60 }} />
                      <Typography variant="caption" color="text.secondary">{item.methods}</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>⚖️ Dataset Bias</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Systematic errors in data that lead to unfair or inaccurate models.
              </Typography>
              <List dense>
                {[
                  { bias: "Selection bias", desc: "Training data doesn't represent production distribution" },
                  { bias: "Label bias", desc: "Annotators' prejudices encoded in labels" },
                  { bias: "Historical bias", desc: "Past discrimination reflected in historical data" },
                  { bias: "Measurement bias", desc: "Systematic errors in data collection" },
                ].map((item) => (
                  <ListItem key={item.bias} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.bias}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600, color: "#dc2626" }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== SECTION 3: MATHS AND THEORY ==================== */}
        <Typography id="maths-theory" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          📐 Maths and Theory
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The mathematical foundations that make machine learning work
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>You don't need a PhD in mathematics to use ML</strong>, but understanding the fundamentals 
            helps you debug models, interpret results, and make informed decisions. Modern frameworks abstract 
            away much of the math, but it's still there under the hood. When things go wrong, mathematical 
            intuition helps you diagnose the problem.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Linear algebra</strong> is the language of data — vectors, matrices, and tensors represent 
            everything from images to embeddings. <strong>Calculus</strong> enables learning through gradients — 
            how to adjust parameters to reduce error. <strong>Probability and statistics</strong> handle uncertainty 
            — the foundation of prediction, inference, and model evaluation.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Optimisation</strong> is how models learn — finding parameter values that minimise a loss 
            function. Gradient descent and its variants (SGD, Adam, RMSprop) are the workhorses of deep learning. 
            Understanding loss landscapes helps explain why some models train well and others don't.
          </Typography>
        </Paper>

        {/* Core Math Areas */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>📊 Statistics for AI</Typography>
              <List dense>
                {[
                  { concept: "Descriptive stats", desc: "Mean, median, mode, variance, standard deviation" },
                  { concept: "Distributions", desc: "Normal, uniform, Bernoulli, Poisson, exponential" },
                  { concept: "Correlation", desc: "Pearson, Spearman — measuring relationships" },
                  { concept: "Hypothesis testing", desc: "p-values, confidence intervals, significance" },
                  { concept: "Bayesian vs Frequentist", desc: "Prior beliefs vs long-run frequencies" },
                  { concept: "Sampling", desc: "Random, stratified, bootstrap — representative subsets" },
                ].map((item) => (
                  <ListItem key={item.concept} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.concept}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>🔢 Linear Algebra for AI</Typography>
              <List dense>
                {[
                  { concept: "Vectors", desc: "1D arrays — features, embeddings, directions" },
                  { concept: "Matrices", desc: "2D arrays — transformations, datasets, weights" },
                  { concept: "Tensors", desc: "N-dimensional arrays — images, batches, sequences" },
                  { concept: "Matrix multiplication", desc: "Core operation in neural networks" },
                  { concept: "Eigenvalues/vectors", desc: "PCA, spectral methods, matrix decomposition" },
                  { concept: "Norms", desc: "L1, L2 — measuring magnitude, regularisation" },
                ].map((item) => (
                  <ListItem key={item.concept} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.concept}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Probability, Calculus, Optimisation */}
        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>🎲 Probability</Typography>
              <List dense>
                {[
                  "Conditional probability P(A|B)",
                  "Bayes' theorem",
                  "Independence & joint distributions",
                  "Expectation & variance",
                  "Maximum likelihood estimation",
                  "Probability density functions",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#22c55e" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>📈 Calculus</Typography>
              <List dense>
                {[
                  "Derivatives — rate of change",
                  "Partial derivatives — multivariate",
                  "Chain rule — composition of functions",
                  "Gradients — direction of steepest ascent",
                  "Jacobians & Hessians",
                  "Automatic differentiation",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ec4899", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>⚡ Optimisation</Typography>
              <List dense>
                {[
                  "Gradient descent (batch, mini-batch, SGD)",
                  "Learning rate & scheduling",
                  "Momentum & adaptive methods",
                  "Adam, RMSprop, AdaGrad",
                  "Loss landscapes & local minima",
                  "Convex vs non-convex optimisation",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.2, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 20 }}>
                      <CheckCircleIcon sx={{ fontSize: 12, color: "#ec4899" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== SECTION 4: PROGRAMMING AND COMPUTE ==================== */}
        <Typography id="programming-compute" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          💻 Programming and Compute
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The tools and infrastructure that bring AI systems to life
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Python dominates AI/ML</strong> for good reasons: a rich ecosystem of libraries (NumPy, Pandas, 
            scikit-learn, PyTorch, TensorFlow), readable syntax, and a massive community. Jupyter notebooks enable 
            interactive exploration and documentation. But production systems often require more — proper software 
            engineering practices, version control, testing, and reproducibility.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Compute is the engine of modern AI</strong>. Training large models requires massive parallelism. 
            GPUs (Graphics Processing Units) excel at the matrix operations fundamental to neural networks. TPUs 
            (Tensor Processing Units) are custom chips designed specifically for ML. Cloud providers offer both 
            on-demand, democratising access to powerful hardware.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Performance matters</strong> — both for training (time to iterate on experiments) and inference 
            (latency and cost in production). Understanding bottlenecks (CPU vs GPU, memory vs compute, I/O vs 
            processing) helps you optimise where it counts. Batch size, data loading, and model architecture all 
            affect performance.
          </Typography>
        </Paper>

        {/* Python Ecosystem */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Python AI/ML Ecosystem</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { name: "NumPy", desc: "Numerical computing, arrays, linear algebra", color: "#4dabcf", category: "Core" },
            { name: "Pandas", desc: "Data manipulation, DataFrames, analysis", color: "#150458", category: "Core" },
            { name: "scikit-learn", desc: "Classical ML algorithms, preprocessing, metrics", color: "#f89939", category: "ML" },
            { name: "PyTorch", desc: "Deep learning, dynamic graphs, research-friendly", color: "#ee4c2c", category: "DL" },
            { name: "TensorFlow", desc: "Deep learning, production-ready, Keras API", color: "#ff6f00", category: "DL" },
            { name: "Hugging Face", desc: "Transformers, pretrained models, datasets", color: "#ffcc00", category: "LLM" },
            { name: "Matplotlib/Seaborn", desc: "Data visualisation, plots, charts", color: "#11557c", category: "Viz" },
            { name: "Jupyter", desc: "Interactive notebooks, exploration, documentation", color: "#f37726", category: "Dev" },
          ].map((item) => (
            <Grid item xs={6} sm={4} md={3} key={item.name}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha(item.color, 0.3)}` }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.name}</Typography>
                  <Chip label={item.category} size="small" sx={{ fontSize: "0.6rem", height: 16 }} />
                </Box>
                <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Compute Types */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Compute Hardware</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#3b82f6" }}>🖥️ CPU</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Central Processing Unit — general-purpose computing
              </Typography>
              <List dense>
                {[
                  "Good for: small models, inference, data preprocessing",
                  "Sequential processing, few cores (8-64)",
                  "High per-core performance",
                  "Lower power consumption",
                  "Widely available, cheaper",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>🎮 GPU</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Graphics Processing Unit — parallel computing powerhouse
              </Typography>
              <List dense>
                {[
                  "Good for: deep learning training & inference",
                  "Massively parallel (thousands of cores)",
                  "Optimised for matrix operations",
                  "NVIDIA dominates (CUDA ecosystem)",
                  "A100, H100, RTX 4090 for ML",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#8b5cf6" }}>⚡ TPU</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Tensor Processing Unit — Google's custom AI chip
              </Typography>
              <List dense>
                {[
                  "Good for: large-scale training, transformers",
                  "Custom silicon for tensor operations",
                  "Available via Google Cloud",
                  "Excellent for JAX/TensorFlow",
                  "TPU v4/v5 for cutting-edge models",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Best Practices */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#06b6d4", 0.03), border: `1px solid ${alpha("#06b6d4", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>🔧 Best Practices for AI Development</Typography>
          <Grid container spacing={2}>
            {[
              { practice: "Version Control", desc: "Git for code, DVC for data, MLflow for experiments" },
              { practice: "Reproducibility", desc: "Fixed seeds, pinned dependencies, containerisation (Docker)" },
              { practice: "Testing", desc: "Unit tests, data validation, model regression tests" },
              { practice: "Documentation", desc: "Docstrings, READMEs, experiment logs, model cards" },
            ].map((item) => (
              <Grid item xs={12} sm={6} key={item.practice}>
                <Box sx={{ display: "flex", gap: 1, alignItems: "flex-start" }}>
                  <CheckCircleIcon sx={{ fontSize: 16, color: "#06b6d4", mt: 0.3 }} />
                  <Box>
                    <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>{item.practice}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Box>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== SECTION 5: CORE MACHINE LEARNING ==================== */}
        <Typography id="core-ml" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🎯 Core Machine Learning
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The fundamental learning paradigms that power AI systems
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Machine learning algorithms learn from data</strong> rather than following explicit rules. 
            But "learning" takes many forms. The type of learning depends on what information is available 
            during training — labelled examples, unlabelled data, rewards, or some combination. Each paradigm 
            has different strengths, requirements, and use cases.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Supervised learning</strong> is the most common — you have inputs and known outputs, and 
            the model learns the mapping. <strong>Unsupervised learning</strong> finds structure in data without 
            labels. <strong>Reinforcement learning</strong> learns through trial and error, maximising rewards. 
            <strong>Self-supervised learning</strong> creates its own labels from the data structure itself — 
            the key to modern LLMs.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            Understanding these paradigms helps you frame problems correctly. Not every problem needs deep learning. 
            Not every problem has labelled data. Choosing the right paradigm is often more important than choosing 
            the right algorithm.
          </Typography>
        </Paper>

        {/* Learning Paradigms */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>📚 Supervised Learning</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Learning from labelled examples — input-output pairs
              </Typography>
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 0.5 }}>Classification</Typography>
                <Typography variant="caption" color="text.secondary">
                  Predicting discrete categories: spam/not spam, cat/dog, malware/benign
                </Typography>
              </Box>
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 0.5 }}>Regression</Typography>
                <Typography variant="caption" color="text.secondary">
                  Predicting continuous values: price, temperature, risk score
                </Typography>
              </Box>
              <Chip label="Requires labelled data" size="small" sx={{ bgcolor: alpha("#3b82f6", 0.1) }} />
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>🔍 Unsupervised Learning</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Finding structure in unlabelled data
              </Typography>
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 0.5 }}>Clustering</Typography>
                <Typography variant="caption" color="text.secondary">
                  Grouping similar items: customer segments, malware families
                </Typography>
              </Box>
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 0.5 }}>Dimensionality Reduction</Typography>
                <Typography variant="caption" color="text.secondary">
                  Compressing features: PCA, t-SNE, UMAP for visualisation
                </Typography>
              </Box>
              <Chip label="No labels needed" size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.1) }} />
            </Paper>
          </Grid>
        </Grid>

        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>🎮 Reinforcement Learning</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Learning through interaction — maximise cumulative reward
              </Typography>
              <List dense>
                {[
                  "Agent takes actions in environment",
                  "Receives rewards/penalties",
                  "Learns policy: state → action",
                  "Games, robotics, trading, RLHF",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 16 }}>
                      <CheckCircleIcon sx={{ fontSize: 10, color: "#22c55e" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>🔄 Self-Supervised Learning</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Creating labels from data structure itself
              </Typography>
              <List dense>
                {[
                  "Predict masked words (BERT)",
                  "Predict next token (GPT)",
                  "Contrastive learning (SimCLR)",
                  "Powers modern LLMs & vision models",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 16 }}>
                      <CheckCircleIcon sx={{ fontSize: 10, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ec4899", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>🏷️ Semi-Supervised</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Using both labelled and unlabelled data
              </Typography>
              <List dense>
                {[
                  "Small labelled + large unlabelled",
                  "Pseudo-labelling",
                  "Consistency regularisation",
                  "Reduces labelling cost significantly",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 16 }}>
                      <CheckCircleIcon sx={{ fontSize: 10, color: "#ec4899" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Other Paradigms */}
        <Grid container spacing={2} sx={{ mb: 5 }}>
          {[
            { name: "Online Learning", desc: "Model updates continuously as new data arrives — streaming, real-time adaptation", color: "#06b6d4" },
            { name: "Active Learning", desc: "Model queries for labels on most informative examples — efficient labelling", color: "#84cc16" },
            { name: "Transfer Learning", desc: "Leverage knowledge from one task/domain to another — pretrained models", color: "#a855f7" },
            { name: "Meta-Learning", desc: "Learning to learn — few-shot adaptation, model-agnostic approaches", color: "#f97316" },
          ].map((item) => (
            <Grid item xs={12} sm={6} key={item.name}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha(item.color, 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>{item.name}</Typography>
                <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== SECTION 6: CLASSICAL ML MODELS ==================== */}
        <Typography id="classical-ml" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          📊 Classical ML Models and Techniques
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The foundational algorithms that still power much of production ML
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#06b6d4", 0.03), border: `1px solid ${alpha("#06b6d4", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Deep learning isn't always the answer</strong>. Classical ML algorithms remain the workhorses 
            of production systems for many reasons: they're interpretable, fast to train, work well with tabular 
            data, and don't require massive datasets or GPU clusters. A gradient boosted tree often beats a neural 
            network on structured data — and you can explain why it made a prediction.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Start simple</strong>. Logistic regression is a powerful baseline for classification. Linear 
            regression for continuous targets. Decision trees for interpretability. Ensemble methods (Random Forest, 
            XGBoost) for predictive power. Only reach for deep learning when simpler methods fail or when you have 
            unstructured data (images, text, audio).
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            These algorithms also form the foundation for more advanced techniques. Understanding how a decision 
            tree works helps you understand Random Forests and gradient boosting. Understanding linear models 
            helps you understand neural networks. The fundamentals matter.
          </Typography>
        </Paper>

        {/* Core Algorithms */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Core Algorithms</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>📈 Linear Models</Typography>
              <List dense>
                {[
                  { algo: "Linear Regression", use: "Continuous target, baseline, interpretable coefficients" },
                  { algo: "Logistic Regression", use: "Binary classification, probability outputs, feature importance" },
                  { algo: "Ridge / Lasso", use: "Regularised regression — L2 (Ridge) shrinks, L1 (Lasso) sparsifies" },
                  { algo: "Elastic Net", use: "Combines L1 + L2 regularisation" },
                ].map((item) => (
                  <ListItem key={item.algo} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.algo}
                      secondary={item.use}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>🌳 Tree-Based Models</Typography>
              <List dense>
                {[
                  { algo: "Decision Tree", use: "Interpretable, handles non-linear, prone to overfitting" },
                  { algo: "Random Forest", use: "Ensemble of trees, reduces variance, robust" },
                  { algo: "XGBoost", use: "Gradient boosting, top performance on tabular data" },
                  { algo: "LightGBM", use: "Faster XGBoost, leaf-wise growth, large datasets" },
                  { algo: "CatBoost", use: "Handles categorical features natively" },
                ].map((item) => (
                  <ListItem key={item.algo} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.algo}
                      secondary={item.use}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Other Algorithms */}
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { algo: "SVM", desc: "Support Vector Machine — finds optimal hyperplane, kernel trick for non-linear", color: "#8b5cf6" },
            { algo: "kNN", desc: "k-Nearest Neighbours — instance-based, no training, distance-based classification", color: "#f59e0b" },
            { algo: "Naive Bayes", desc: "Probabilistic classifier — assumes feature independence, fast, text classification", color: "#ec4899" },
            { algo: "k-Means", desc: "Clustering — partition into k groups, iterative centroid updates", color: "#06b6d4" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={3} key={item.algo}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha(item.color, 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>{item.algo}</Typography>
                <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Specialised Techniques */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Specialised Techniques</Typography>
        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>📉 Time Series</Typography>
              <List dense>
                {[
                  "ARIMA — autoregressive integrated moving average",
                  "Exponential smoothing — trend and seasonality",
                  "Prophet — Facebook's forecasting library",
                  "LSTM/Transformers — deep learning approaches",
                  "Feature engineering: lags, rolling stats, calendrical",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f97316", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>🚨 Anomaly Detection</Typography>
              <List dense>
                {[
                  "Isolation Forest — isolate anomalies, not normal points",
                  "One-Class SVM — learn boundary of normal class",
                  "Autoencoders — reconstruction error as anomaly score",
                  "Statistical methods — z-score, IQR, Grubbs",
                  "Security use: intrusion detection, fraud, malware",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#a855f7", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>🎯 Recommender Systems</Typography>
              <List dense>
                {[
                  "Collaborative filtering — user-item interactions",
                  "Content-based — item features, user preferences",
                  "Matrix factorisation — SVD, ALS",
                  "Hybrid approaches — combine multiple signals",
                  "Deep learning — neural collaborative filtering",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== SECTION 7: DEEP LEARNING ==================== */}
        <Typography id="deep-learning" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🧬 Deep Learning
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Neural networks that learn hierarchical representations from data
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#ec4899", 0.03), border: `1px solid ${alpha("#ec4899", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Deep learning</strong> is a subset of machine learning using neural networks with multiple layers. 
            These "deep" architectures can learn increasingly abstract representations — from pixels to edges to 
            shapes to objects to scenes. This hierarchical feature learning is what makes deep learning powerful 
            for complex tasks like image recognition, language understanding, and speech synthesis.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Neural networks</strong> are inspired by biological neurons but are fundamentally mathematical 
            functions. Each layer transforms its input through weighted connections, adds a bias, and applies a 
            non-linear activation function. <strong>Backpropagation</strong> enables learning by computing gradients 
            of the loss with respect to every parameter, then updating weights to reduce error.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            The deep learning revolution began around 2012 with AlexNet's ImageNet victory. Since then, architectures 
            have evolved dramatically: <strong>CNNs</strong> for images, <strong>RNNs/LSTMs</strong> for sequences, 
            and <strong>Transformers</strong> that now dominate both NLP and vision. Understanding these building 
            blocks is essential for working with modern AI.
          </Typography>
        </Paper>

        {/* Neural Network Fundamentals */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Neural Network Fundamentals</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ec4899", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>🔗 Core Components</Typography>
              <List dense>
                {[
                  { component: "Neurons/Units", desc: "Basic computation: weighted sum + bias + activation" },
                  { component: "Layers", desc: "Groups of neurons: input, hidden, output" },
                  { component: "Weights", desc: "Learnable parameters connecting neurons" },
                  { component: "Biases", desc: "Learnable offsets added to weighted sums" },
                  { component: "Activations", desc: "Non-linearities: ReLU, sigmoid, tanh, softmax" },
                  { component: "Loss Function", desc: "Measures prediction error (cross-entropy, MSE)" },
                ].map((item) => (
                  <ListItem key={item.component} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.component}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>⚡ Training Dynamics</Typography>
              <List dense>
                {[
                  { concept: "Forward Pass", desc: "Input → predictions through network layers" },
                  { concept: "Loss Computation", desc: "Compare predictions to targets" },
                  { concept: "Backward Pass", desc: "Compute gradients via backpropagation" },
                  { concept: "Weight Update", desc: "Adjust parameters using optimizer (SGD, Adam)" },
                  { concept: "Epoch", desc: "One complete pass through training data" },
                  { concept: "Batch Size", desc: "Samples processed before weight update" },
                ].map((item) => (
                  <ListItem key={item.concept} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.concept}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Key Architectures */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Key Architectures</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>🖼️ CNNs</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Convolutional Neural Networks — designed for grid-like data (images)
              </Typography>
              <List dense>
                {[
                  "Convolutional layers — local pattern detection",
                  "Pooling layers — spatial downsampling",
                  "Translation invariance — detect anywhere",
                  "Parameter sharing — efficient",
                  "ResNet, VGG, EfficientNet, ConvNeXt",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 16 }}>
                      <CheckCircleIcon sx={{ fontSize: 10, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>📝 RNNs/LSTMs</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Recurrent Neural Networks — designed for sequential data
              </Typography>
              <List dense>
                {[
                  "Hidden state — memory of past inputs",
                  "Vanishing gradients — long sequences hard",
                  "LSTM — gated memory cells solve this",
                  "GRU — simplified gating mechanism",
                  "Largely replaced by Transformers",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 16 }}>
                      <CheckCircleIcon sx={{ fontSize: 10, color: "#22c55e" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>🔮 Transformers</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Attention-based architecture — state of the art
              </Typography>
              <List dense>
                {[
                  "Self-attention — relate all positions",
                  "Parallel processing — faster training",
                  "Positional encoding — sequence order",
                  "Encoder-decoder or decoder-only",
                  "GPT, BERT, T5, LLaMA, ViT",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 16 }}>
                      <CheckCircleIcon sx={{ fontSize: 10, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Regularisation & Transfer Learning */}
        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>🛡️ Regularisation</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Techniques to prevent overfitting and improve generalisation
              </Typography>
              <Grid container spacing={1}>
                {[
                  { tech: "Dropout", desc: "Randomly zero activations during training" },
                  { tech: "Weight Decay", desc: "L2 penalty on weights (regularisation)" },
                  { tech: "Batch Norm", desc: "Normalise layer inputs, stabilise training" },
                  { tech: "Layer Norm", desc: "Normalise across features (Transformers)" },
                  { tech: "Data Augmentation", desc: "Artificially expand training data" },
                  { tech: "Early Stopping", desc: "Stop when validation loss increases" },
                ].map((item) => (
                  <Grid item xs={12} key={item.tech}>
                    <Box sx={{ display: "flex", gap: 1 }}>
                      <Chip label={item.tech} size="small" sx={{ fontWeight: 600, minWidth: 90, fontSize: "0.65rem" }} />
                      <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#a855f7", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>🔄 Transfer & Multi-task Learning</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Leveraging knowledge across tasks and domains
              </Typography>
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 0.5 }}>Transfer Learning</Typography>
                <Typography variant="caption" color="text.secondary">
                  Pretrain on large dataset, fine-tune on smaller target task. ImageNet → custom classifier. 
                  GPT → domain chatbot. Dramatically reduces data requirements.
                </Typography>
              </Box>
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 0.5 }}>Multi-task Learning</Typography>
                <Typography variant="caption" color="text.secondary">
                  Train single model on multiple related tasks simultaneously. Shared representations improve 
                  generalisation. T5, FLAN-T5 — unified text-to-text format.
                </Typography>
              </Box>
              <Box>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 0.5 }}>Multi-modal Learning</Typography>
                <Typography variant="caption" color="text.secondary">
                  Learn from multiple data types (text + images + audio). CLIP, GPT-4V, Gemini — unified 
                  understanding across modalities.
                </Typography>
              </Box>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== SECTION 8: NATURAL LANGUAGE PROCESSING ==================== */}
        <Typography id="nlp" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          📝 Natural Language Processing
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Teaching machines to understand, generate, and work with human language
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#14b8a6", 0.03), border: `1px solid ${alpha("#14b8a6", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Natural Language Processing (NLP)</strong> is the intersection of linguistics and AI. Language 
            is humanity's most powerful tool for communication, but it's messy, ambiguous, and context-dependent. 
            NLP tackles challenges from basic text processing (tokenisation, part-of-speech tagging) to complex 
            reasoning (question answering, summarisation, dialogue).
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            The field transformed dramatically with <strong>word embeddings</strong> (Word2Vec, GloVe) that captured 
            semantic relationships in vector space. Then came <strong>contextual embeddings</strong> (ELMo, BERT) 
            where word representations depend on surrounding context. Now <strong>large language models</strong> 
            (GPT-4, Claude, LLaMA) achieve remarkable performance across nearly all NLP tasks.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            For security applications, NLP powers phishing detection, threat intelligence extraction, log analysis, 
            vulnerability report parsing, and security chatbots. Understanding NLP fundamentals helps you leverage 
            these capabilities and understand their limitations.
          </Typography>
        </Paper>

        {/* Text Processing Pipeline */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Text Processing Pipeline</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { step: "1. Tokenisation", desc: "Split text into tokens (words, subwords, characters). BPE, WordPiece, SentencePiece", color: "#14b8a6" },
            { step: "2. Normalisation", desc: "Lowercase, remove punctuation, handle Unicode, expand contractions", color: "#3b82f6" },
            { step: "3. Stop Words", desc: "Remove common words (the, is, at) or keep for context", color: "#8b5cf6" },
            { step: "4. Stemming/Lemma", desc: "Reduce to root form: running→run. Stemming (crude) vs Lemmatisation (linguistic)", color: "#f59e0b" },
            { step: "5. Vectorisation", desc: "Convert to numbers: BoW, TF-IDF, or embeddings", color: "#ef4444" },
            { step: "6. Encoding", desc: "Create model inputs: attention masks, position IDs, special tokens", color: "#ec4899" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.step}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha(item.color, 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>{item.step}</Typography>
                <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* NLP Tasks */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Core NLP Tasks</Typography>
        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>🏷️ Classification & NER</Typography>
              <List dense>
                {[
                  { task: "Text Classification", ex: "Sentiment, spam, topic, intent" },
                  { task: "Named Entity Recognition", ex: "Extract people, orgs, locations, dates" },
                  { task: "Part-of-Speech Tagging", ex: "Noun, verb, adjective labels" },
                  { task: "Relation Extraction", ex: "Entity relationships in text" },
                ].map((item) => (
                  <ListItem key={item.task} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.task}
                      secondary={item.ex}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>📄 Generation & Summarisation</Typography>
              <List dense>
                {[
                  { task: "Text Summarisation", ex: "Extractive (select) or abstractive (generate)" },
                  { task: "Text Generation", ex: "Continue text, complete prompts" },
                  { task: "Machine Translation", ex: "Convert between languages" },
                  { task: "Paraphrasing", ex: "Rewrite preserving meaning" },
                ].map((item) => (
                  <ListItem key={item.task} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.task}
                      secondary={item.ex}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>❓ Understanding & QA</Typography>
              <List dense>
                {[
                  { task: "Question Answering", ex: "Extractive, generative, retrieval-augmented" },
                  { task: "Reading Comprehension", ex: "Answer questions about passages" },
                  { task: "Semantic Similarity", ex: "How similar are two texts?" },
                  { task: "Natural Language Inference", ex: "Entailment, contradiction, neutral" },
                ].map((item) => (
                  <ListItem key={item.task} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.task}
                      secondary={item.ex}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== SECTION 9: LARGE LANGUAGE MODELS AND AGENTS ==================== */}
        <Typography id="llm-agents" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🤖 Large Language Models and Agents
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The frontier of AI: from text generators to reasoning systems with tools
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#a855f7", 0.03), border: `1px solid ${alpha("#a855f7", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Large Language Models (LLMs)</strong> are transformer-based models trained on massive text 
            corpora to predict the next token. Despite this simple objective, scaling up revealed emergent 
            capabilities: in-context learning, chain-of-thought reasoning, and instruction following. Models 
            like GPT-4, Claude, Gemini, and LLaMA demonstrate remarkable versatility across tasks.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>The training pipeline</strong> typically involves: (1) <strong>Pretraining</strong> on web-scale 
            text to learn language patterns, (2) <strong>Instruction tuning</strong> on curated task demonstrations, 
            and (3) <strong>RLHF/DPO</strong> alignment to make outputs helpful, harmless, and honest. Each stage 
            shapes the model's behaviour.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>AI Agents</strong> extend LLMs beyond text generation. By giving models access to tools 
            (code execution, web search, APIs, databases), they can take actions in the world. RAG (Retrieval 
            Augmented Generation) grounds responses in external knowledge. Agent orchestration frameworks 
            (LangChain, AutoGPT, CrewAI) enable complex multi-step workflows.
          </Typography>
        </Paper>

        {/* LLM Concepts */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>LLM Core Concepts</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { concept: "Pretraining", desc: "Train on massive text corpus (web, books, code) to predict next token. Learns language structure and world knowledge.", color: "#a855f7" },
            { concept: "Fine-tuning", desc: "Continue training on task-specific data. Adapt general model to specific domain or capability.", color: "#3b82f6" },
            { concept: "Instruction Tuning", desc: "Train on (instruction, response) pairs. Teaches model to follow user requests.", color: "#22c55e" },
            { concept: "RLHF", desc: "Reinforcement Learning from Human Feedback. Train reward model on preferences, optimise for helpfulness.", color: "#f59e0b" },
            { concept: "Context Window", desc: "Maximum tokens model can process at once. GPT-4: 128k, Claude: 200k, Gemini: 1M+", color: "#ef4444" },
            { concept: "Temperature", desc: "Controls randomness. Low = deterministic, high = creative. Affects sampling distribution.", color: "#ec4899" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.concept}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha(item.color, 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>{item.concept}</Typography>
                <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Prompting & RAG */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>💬 Prompt Engineering</Typography>
              <List dense>
                {[
                  { pattern: "Zero-shot", desc: "Direct instruction, no examples" },
                  { pattern: "Few-shot", desc: "Include examples in prompt" },
                  { pattern: "Chain-of-Thought", desc: "\"Let's think step by step\"" },
                  { pattern: "Self-Consistency", desc: "Multiple reasoning paths, vote" },
                  { pattern: "ReAct", desc: "Reasoning + Acting interleaved" },
                  { pattern: "System Prompts", desc: "Persistent instructions, persona, constraints" },
                ].map((item) => (
                  <ListItem key={item.pattern} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.pattern}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>📚 RAG (Retrieval Augmented Generation)</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Ground LLM responses in external knowledge to reduce hallucinations and enable domain-specific answers.
              </Typography>
              <List dense>
                {[
                  "1. Index documents → embeddings → vector DB",
                  "2. User query → embed → similarity search",
                  "3. Retrieve top-k relevant chunks",
                  "4. Inject context into prompt",
                  "5. LLM generates grounded response",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 16 }}>
                      <CheckCircleIcon sx={{ fontSize: 10, color: "#06b6d4" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Agents & Tools */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>🛠️ Agents, Tools & Function Calling</Typography>
          <Grid container spacing={2}>
            {[
              { area: "Function Calling", desc: "LLM outputs structured tool invocations. Model decides when/how to call functions.", tools: "OpenAI functions, Anthropic tools" },
              { area: "Code Execution", desc: "Run code in sandboxed environment. Data analysis, calculations, file operations.", tools: "Code Interpreter, Jupyter, E2B" },
              { area: "Web Search", desc: "Retrieve real-time information. Ground responses in current data.", tools: "Bing, Google, Tavily, Perplexity" },
              { area: "Agent Frameworks", desc: "Orchestrate multi-step reasoning and tool use. Plan → Act → Observe → Reflect.", tools: "LangChain, LlamaIndex, AutoGen, CrewAI" },
            ].map((item) => (
              <Grid item xs={12} sm={6} key={item.area}>
                <Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 0.5 }}>{item.area}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.5 }}>{item.desc}</Typography>
                  <Chip label={item.tools} size="small" sx={{ fontSize: "0.6rem", height: 18 }} />
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== SECTION 10: COMPUTER VISION ==================== */}
        <Typography id="computer-vision" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          👁️ Computer Vision
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Teaching machines to see and understand visual information
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#0ea5e9", 0.03), border: `1px solid ${alpha("#0ea5e9", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Computer Vision (CV)</strong> enables machines to extract meaning from images and videos. 
            From recognising faces to detecting tumours to guiding autonomous vehicles, CV powers countless 
            applications. The field was revolutionised by deep learning — CNNs and now Vision Transformers 
            achieve superhuman performance on many visual tasks.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            Images are represented as tensors: height × width × channels (RGB). <strong>Convolutional layers</strong> 
            detect local patterns (edges, textures, shapes) that compose into higher-level features. Modern 
            architectures like <strong>Vision Transformers (ViT)</strong> apply attention mechanisms to image 
            patches, achieving state-of-the-art results especially with large-scale pretraining.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            For security, CV enables malware visualisation (binary-to-image analysis), document fraud detection, 
            CAPTCHA solving research, deepfake detection, and physical security systems. Understanding CV 
            fundamentals helps you both leverage these capabilities and assess their vulnerabilities.
          </Typography>
        </Paper>

        {/* CV Tasks */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Core Computer Vision Tasks</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#0ea5e9", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>🏷️ Classification</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Assign label(s) to entire image
              </Typography>
              <List dense>
                {[
                  "Single-label: cat, dog, car",
                  "Multi-label: beach + sunset + people",
                  "ImageNet: 1000 classes, 1M+ images",
                  "Models: ResNet, EfficientNet, ViT",
                  "Transfer learning is standard",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>📦 Object Detection</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Locate and classify objects with bounding boxes
              </Typography>
              <List dense>
                {[
                  "Output: boxes + classes + confidence",
                  "Two-stage: R-CNN, Faster R-CNN",
                  "One-stage: YOLO, SSD, RetinaNet",
                  "Transformers: DETR, DINO",
                  "COCO: 80 classes, 330k images",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>🎨 Segmentation</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Pixel-level classification
              </Typography>
              <List dense>
                {[
                  "Semantic: class per pixel (sky, road)",
                  "Instance: distinguish object instances",
                  "Panoptic: semantic + instance combined",
                  "Models: U-Net, Mask R-CNN, SAM",
                  "Medical imaging, autonomous driving",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* More CV Tasks */}
        <Grid container spacing={2} sx={{ mb: 5 }}>
          {[
            { task: "Pose Estimation", desc: "Detect body/hand/face keypoints. OpenPose, MediaPipe. Action recognition, fitness apps.", color: "#8b5cf6" },
            { task: "OCR", desc: "Extract text from images. Document digitisation, license plates. Tesseract, PaddleOCR, cloud APIs.", color: "#ec4899" },
            { task: "Video Understanding", desc: "Tracking, action recognition, temporal reasoning. Object tracking, anomaly detection in surveillance.", color: "#06b6d4" },
            { task: "Vision Transformers", desc: "ViT: patch embeddings + transformer. DINOv2, SAM — foundation models for vision.", color: "#ef4444" },
            { task: "Generative Vision", desc: "Create images from text/noise. Diffusion (Stable Diffusion, DALL-E), GANs. Deepfakes.", color: "#d946ef" },
            { task: "Domain Robustness", desc: "Handle distribution shift, adversarial examples, real-world conditions. Critical for deployment.", color: "#f97316" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.task}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha(item.color, 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>{item.task}</Typography>
                <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== SECTION 11: SPEECH AND AUDIO AI ==================== */}
        <Typography id="speech-audio" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🎤 Speech and Audio AI
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Converting between speech and text, and understanding audio signals
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Speech and audio AI</strong> enables voice assistants, transcription services, voice cloning, 
            and audio analysis. The core challenges are converting acoustic signals to text (ASR), generating 
            natural speech from text (TTS), and extracting meaning from audio (classification, speaker ID).
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            Audio is typically represented as <strong>waveforms</strong> (amplitude over time) or 
            <strong>spectrograms</strong> (frequency content over time). Modern approaches often use 
            end-to-end deep learning — transformers like <strong>Whisper</strong> for ASR achieve 
            remarkable accuracy across languages and accents.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            Security applications include voice biometrics, deepfake audio detection, call centre analytics, 
            and audio forensics. The rise of realistic voice cloning creates new social engineering risks 
            that security professionals must understand.
          </Typography>
        </Paper>

        {/* Speech Tasks */}
        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f97316", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>🎙️ Speech Tasks</Typography>
              <List dense>
                {[
                  { task: "ASR (Speech-to-Text)", desc: "Whisper, DeepSpeech, Google STT, Azure Speech" },
                  { task: "TTS (Text-to-Speech)", desc: "Tacotron, VITS, ElevenLabs, Azure Neural TTS" },
                  { task: "Voice Cloning", desc: "Generate speech in target voice from samples" },
                  { task: "Speaker Recognition", desc: "Verify identity (verification) or identify (identification)" },
                  { task: "Speaker Diarisation", desc: "Who spoke when in multi-speaker audio" },
                  { task: "Speech Enhancement", desc: "Noise reduction, echo cancellation" },
                ].map((item) => (
                  <ListItem key={item.task} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.task}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>🔊 Audio Understanding</Typography>
              <List dense>
                {[
                  { task: "Audio Classification", desc: "Environmental sounds, music genre, emotion" },
                  { task: "Music Information Retrieval", desc: "Beat detection, chord recognition, similarity" },
                  { task: "Sound Event Detection", desc: "Detect and localise sounds in time" },
                  { task: "Audio Tagging", desc: "Multi-label classification of audio clips" },
                ].map((item) => (
                  <ListItem key={item.task} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.task}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
              <Box sx={{ mt: 2, p: 1.5, borderRadius: 1, bgcolor: alpha("#8b5cf6", 0.05) }}>
                <Typography variant="caption" sx={{ fontWeight: 600 }}>Signal Processing Basics</Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                  Sampling rate, Fourier transform, MFCCs, mel spectrograms, windowing, filtering
                </Typography>
              </Box>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== SECTION 12: GENERATIVE AI ==================== */}
        <Typography id="generative-ai" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          ✨ Generative AI
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Models that create new content: images, text, audio, video, and code
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#d946ef", 0.03), border: `1px solid ${alpha("#d946ef", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Generative AI</strong> creates new content rather than just analysing or classifying existing 
            data. This includes text (LLMs), images (diffusion models, GANs), audio (voice synthesis, music), 
            video (Sora, Runway), and code (Copilot, Claude). The ability to generate human-like content has 
            profound implications for creativity, productivity, and security.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Diffusion models</strong> have largely replaced GANs for image generation. They work by 
            learning to reverse a gradual noising process — start with noise, iteratively denoise to create 
            images. Stable Diffusion, DALL-E 3, and Midjourney produce stunning results from text prompts.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            For security, generative AI enables sophisticated phishing, deepfakes, and automated attack content. 
            But it also powers security tools — code generation, threat report writing, security copilots. 
            Understanding generative models helps you both leverage and defend against these capabilities.
          </Typography>
        </Paper>

        {/* Generative Model Types */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Generative Model Architectures</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#d946ef", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#d946ef" }}>🌊 Diffusion Models</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Learn to denoise — current state of the art for images
              </Typography>
              <List dense>
                {[
                  "Forward: gradually add noise to data",
                  "Reverse: learn to remove noise",
                  "Guidance: condition on text (CLIP)",
                  "Stable Diffusion, DALL-E 3, Imagen",
                  "Also: video, audio, 3D generation",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 16 }}>
                      <CheckCircleIcon sx={{ fontSize: 10, color: "#d946ef" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>⚔️ GANs</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Generator vs Discriminator adversarial training
              </Typography>
              <List dense>
                {[
                  "Generator creates fake samples",
                  "Discriminator distinguishes real/fake",
                  "Minimax game → equilibrium",
                  "StyleGAN — photorealistic faces",
                  "Training can be unstable (mode collapse)",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 16 }}>
                      <CheckCircleIcon sx={{ fontSize: 10, color: "#22c55e" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>🔮 VAEs</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Variational Autoencoders — probabilistic latent space
              </Typography>
              <List dense>
                {[
                  "Encoder: data → latent distribution",
                  "Decoder: sample → reconstruction",
                  "Regularised latent space",
                  "Smooth interpolation possible",
                  "Often used in combination (VAE-GAN)",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 16 }}>
                      <CheckCircleIcon sx={{ fontSize: 10, color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Code Generation */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>💻 Code Generation Models</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            LLMs trained or fine-tuned on code — transforming software development
          </Typography>
          <Grid container spacing={2}>
            {[
              { model: "GitHub Copilot", desc: "Code completion, chat, inline suggestions. Based on OpenAI Codex/GPT-4." },
              { model: "Claude", desc: "Strong coding capabilities, 200k context. Excels at code review and explanation." },
              { model: "GPT-4", desc: "General-purpose but excellent at code. Powers many coding assistants." },
              { model: "Code Llama", desc: "Meta's open-source code model. Fine-tuned from LLaMA 2." },
              { model: "StarCoder", desc: "BigCode open-source. Trained on permissively licensed code." },
              { model: "DeepSeek Coder", desc: "Strong open-source alternative. Competitive with proprietary models." },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.model}>
                <Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 0.3 }}>{item.model}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== SECTION 13: EVALUATION AND TESTING ==================== */}
        <Typography id="evaluation-testing" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          📊 Evaluation and Testing
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Measuring model performance, understanding predictions, and ensuring reliability
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#84cc16", 0.03), border: `1px solid ${alpha("#84cc16", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Evaluation</strong> is how we know if our models actually work. It's not just about accuracy — 
            we need metrics that capture what matters for our use case, validation strategies that estimate 
            real-world performance, and interpretability tools that explain why models make predictions.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Good evaluation is harder than it looks.</strong> Train/test splits can leak information. 
            Accuracy hides class imbalance issues. Models confident in wrong predictions are dangerous. 
            Understanding these pitfalls separates production ML from Kaggle competitions.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            For security applications, evaluation is critical. A malware detector with 99% accuracy but 50% 
            false positive rate is useless. Understanding model uncertainty helps know when to trust predictions. 
            Interpretability reveals if models learn spurious correlations or actual patterns.
          </Typography>
        </Paper>

        {/* Metrics */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Key Metrics</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#84cc16", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#84cc16" }}>🎯 Classification</Typography>
              <List dense>
                {[
                  { metric: "Accuracy", desc: "Correct / Total — misleading with imbalance" },
                  { metric: "Precision", desc: "TP / (TP+FP) — when FP costly" },
                  { metric: "Recall", desc: "TP / (TP+FN) — when FN costly" },
                  { metric: "F1 Score", desc: "Harmonic mean of precision/recall" },
                  { metric: "AUC-ROC", desc: "Area under ROC curve — threshold independent" },
                  { metric: "PR-AUC", desc: "Precision-Recall curve — better for imbalanced" },
                ].map((item) => (
                  <ListItem key={item.metric} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.metric}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>📈 Regression</Typography>
              <List dense>
                {[
                  { metric: "MSE/RMSE", desc: "Mean Squared Error — penalises large errors" },
                  { metric: "MAE", desc: "Mean Absolute Error — robust to outliers" },
                  { metric: "R² Score", desc: "Variance explained (0-1)" },
                  { metric: "MAPE", desc: "Mean Absolute Percentage Error" },
                ].map((item) => (
                  <ListItem key={item.metric} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.metric}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>📝 NLP/Generation</Typography>
              <List dense>
                {[
                  { metric: "BLEU", desc: "N-gram overlap — machine translation" },
                  { metric: "ROUGE", desc: "Recall-oriented — summarisation" },
                  { metric: "Perplexity", desc: "How surprised by test data" },
                  { metric: "BERTScore", desc: "Semantic similarity via embeddings" },
                  { metric: "Human Eval", desc: "Gold standard but expensive" },
                ].map((item) => (
                  <ListItem key={item.metric} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.metric}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Validation & Interpretability */}
        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>🔄 Validation Strategies</Typography>
              <List dense>
                {[
                  { strategy: "Train/Val/Test Split", desc: "Simple but wastes data. 70/15/15 typical." },
                  { strategy: "K-Fold Cross-Validation", desc: "K models, each tested on 1/K data. More robust." },
                  { strategy: "Stratified K-Fold", desc: "Preserve class distribution in each fold." },
                  { strategy: "Time Series Split", desc: "Train on past, test on future. No leakage." },
                  { strategy: "Group K-Fold", desc: "Keep groups together (users, sessions)." },
                  { strategy: "Nested CV", desc: "Hyperparameter tuning + evaluation. Unbiased." },
                ].map((item) => (
                  <ListItem key={item.strategy} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.strategy}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ec4899", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>🔍 Interpretability & XAI</Typography>
              <List dense>
                {[
                  { method: "Feature Importance", desc: "Which features matter most? Permutation, SHAP." },
                  { method: "SHAP Values", desc: "Game theory — contribution of each feature." },
                  { method: "LIME", desc: "Local interpretable model-agnostic explanations." },
                  { method: "Attention Visualisation", desc: "What tokens/regions model attends to." },
                  { method: "Integrated Gradients", desc: "Attribution via gradient integration." },
                  { method: "Counterfactuals", desc: "What minimal change flips prediction?" },
                ].map((item) => (
                  <ListItem key={item.method} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.method}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== SECTION 14: MLOPS AND DEPLOYMENT ==================== */}
        <Typography id="mlops-deployment" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🚀 MLOps and Deployment
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Taking models from notebooks to production at scale
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#6366f1", 0.03), border: `1px solid ${alpha("#6366f1", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>MLOps</strong> (Machine Learning Operations) applies DevOps principles to ML systems. 
            Training a model is maybe 10% of the work — the rest is data pipelines, training infrastructure, 
            deployment, monitoring, and continuous improvement. MLOps makes this sustainable and reproducible.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>ML systems have unique challenges:</strong> data drift (input distribution changes), 
            concept drift (relationship between inputs and outputs changes), model staleness, and the need 
            for continuous retraining. Traditional software doesn't deal with these — MLOps does.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            The MLOps stack includes experiment tracking (MLflow, W&B), feature stores (Feast, Tecton), 
            model registries, serving infrastructure (TorchServe, Triton, BentoML), and monitoring solutions. 
            Understanding this ecosystem is essential for production ML.
          </Typography>
        </Paper>

        {/* MLOps Components */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>MLOps Stack</Typography>
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {[
            { component: "Data Pipelines", desc: "ETL, data validation, feature engineering. Airflow, Prefect, Dagster.", color: "#6366f1" },
            { component: "Experiment Tracking", desc: "Log params, metrics, artifacts. MLflow, Weights & Biases, Neptune.", color: "#3b82f6" },
            { component: "Feature Store", desc: "Centralised feature computation and serving. Feast, Tecton, Hopsworks.", color: "#22c55e" },
            { component: "Model Registry", desc: "Version models, track lineage, manage lifecycle. MLflow, Vertex AI.", color: "#f59e0b" },
            { component: "Training Orchestration", desc: "Distributed training, hyperparameter tuning. Kubeflow, Ray, SageMaker.", color: "#ef4444" },
            { component: "Model Serving", desc: "Deploy models as APIs. TorchServe, Triton, BentoML, TensorFlow Serving.", color: "#ec4899" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.component}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha(item.color, 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>{item.component}</Typography>
                <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Deployment & Monitoring */}
        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#0ea5e9", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>📦 Deployment Patterns</Typography>
              <List dense>
                {[
                  { pattern: "REST API", desc: "Synchronous request/response. FastAPI, Flask." },
                  { pattern: "Batch Inference", desc: "Process large datasets offline. Spark, Dataflow." },
                  { pattern: "Streaming", desc: "Real-time predictions. Kafka, Flink integration." },
                  { pattern: "Edge Deployment", desc: "On-device inference. ONNX, TensorRT, CoreML." },
                  { pattern: "Serverless", desc: "Auto-scaling, pay-per-use. Lambda, Cloud Functions." },
                  { pattern: "Shadow Deployment", desc: "Run new model alongside old, compare." },
                ].map((item) => (
                  <ListItem key={item.pattern} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.pattern}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f97316", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>📊 Monitoring & Drift</Typography>
              <List dense>
                {[
                  { aspect: "Data Drift", desc: "Input distribution changes. Monitor feature statistics." },
                  { aspect: "Concept Drift", desc: "Input-output relationship changes. Performance drops." },
                  { aspect: "Model Performance", desc: "Track metrics on live data (when labels available)." },
                  { aspect: "Latency & Throughput", desc: "Response time, requests/second, error rates." },
                  { aspect: "Resource Usage", desc: "CPU, GPU, memory, cost per inference." },
                  { aspect: "Alerts & Triggers", desc: "Automated retraining when drift detected." },
                ].map((item) => (
                  <ListItem key={item.aspect} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.aspect}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== SECTION 15: PLATFORMS AND INFRASTRUCTURE ==================== */}
        <Typography id="platforms-infra" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          ☁️ Platforms and Infrastructure
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Cloud AI services, on-premises stacks, and the infrastructure powering modern AI
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#0891b2", 0.03), border: `1px solid ${alpha("#0891b2", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>AI infrastructure</strong> has evolved from "rent some GPUs" to sophisticated platforms 
            offering managed services for training, serving, and everything in between. The major clouds 
            (AWS, Azure, GCP) provide comprehensive AI/ML platforms, while specialised providers offer 
            targeted solutions for specific needs.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Vector databases</strong> have become critical infrastructure for AI applications. They 
            enable similarity search at scale — essential for RAG, recommendation systems, and semantic search. 
            Options range from purpose-built solutions (Pinecone, Weaviate) to extensions of existing databases.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            Choosing infrastructure involves trade-offs: managed vs. self-hosted, cost vs. flexibility, 
            vendor lock-in vs. best-of-breed. Understanding the landscape helps make informed decisions 
            for your specific requirements.
          </Typography>
        </Paper>

        {/* Cloud Platforms */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Cloud AI Platforms</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>🟠 AWS</Typography>
              <List dense>
                {[
                  "SageMaker — end-to-end ML platform",
                  "Bedrock — managed foundation models",
                  "EC2 P4d/P5 — GPU instances",
                  "Inferentia/Trainium — custom chips",
                  "S3 + Glue — data infrastructure",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 16 }}>
                      <CheckCircleIcon sx={{ fontSize: 10, color: "#f59e0b" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#0ea5e9", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>🔵 Azure</Typography>
              <List dense>
                {[
                  "Azure ML — managed ML workspace",
                  "Azure OpenAI Service — GPT models",
                  "NC/ND series — GPU VMs",
                  "Cognitive Services — prebuilt AI",
                  "Cosmos DB — vector search built-in",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 16 }}>
                      <CheckCircleIcon sx={{ fontSize: 10, color: "#0ea5e9" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>🟢 GCP</Typography>
              <List dense>
                {[
                  "Vertex AI — unified ML platform",
                  "TPUs — tensor processing units",
                  "BigQuery ML — SQL-based ML",
                  "Gemini API — foundation models",
                  "AlloyDB — vector search + SQL",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 16 }}>
                      <CheckCircleIcon sx={{ fontSize: 10, color: "#22c55e" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Vector DBs & Infra */}
        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#a855f7", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>🗄️ Vector Databases</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Store and search embeddings at scale — essential for RAG and semantic search
              </Typography>
              <Grid container spacing={1}>
                {[
                  { db: "Pinecone", desc: "Managed, serverless, fast" },
                  { db: "Weaviate", desc: "Open-source, hybrid search" },
                  { db: "Milvus", desc: "Open-source, scalable" },
                  { db: "Chroma", desc: "Simple, developer-friendly" },
                  { db: "Qdrant", desc: "Rust-based, fast filtering" },
                  { db: "pgvector", desc: "Postgres extension" },
                ].map((item) => (
                  <Grid item xs={6} key={item.db}>
                    <Box>
                      <Typography variant="caption" sx={{ fontWeight: 600 }}>{item.db}</Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>{item.desc}</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ec4899", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>🖥️ Compute & Providers</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                GPU providers and specialised AI compute
              </Typography>
              <Grid container spacing={1}>
                {[
                  { provider: "Lambda Labs", desc: "On-demand A100/H100" },
                  { provider: "CoreWeave", desc: "Cloud-native GPU" },
                  { provider: "RunPod", desc: "Affordable GPU rental" },
                  { provider: "Modal", desc: "Serverless GPU compute" },
                  { provider: "Together AI", desc: "Inference + fine-tuning" },
                  { provider: "Replicate", desc: "Run models via API" },
                ].map((item) => (
                  <Grid item xs={6} key={item.provider}>
                    <Box>
                      <Typography variant="caption" sx={{ fontWeight: 600 }}>{item.provider}</Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>{item.desc}</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== SECTION 16: AI SECURITY ==================== */}
        <Typography id="ai-security" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🔐 AI Security
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Threats against AI systems and how to defend them
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#dc2626", 0.03), border: `1px solid ${alpha("#dc2626", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>AI Security</strong> addresses the unique vulnerabilities of machine learning systems. 
            Unlike traditional software, ML models can be attacked through their training data, manipulated 
            with adversarial inputs, and exploited to leak sensitive information. As AI becomes critical 
            infrastructure, securing these systems is paramount.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>The attack surface is broad:</strong> data poisoning corrupts training, adversarial examples 
            fool inference, model extraction steals intellectual property, and prompt injection hijacks LLMs. 
            Each attack class requires different defences — there's no single security solution.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>LLM security</strong> has emerged as a critical focus area. Prompt injection, jailbreaks, 
            RAG poisoning, and indirect prompt injection via retrieved content create novel attack vectors. 
            Frameworks like OWASP LLM Top 10 help structure the threat landscape.
          </Typography>
        </Paper>

        {/* AI Threat Categories */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>AI/ML Threat Taxonomy</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>⚠️ Training-time Attacks</Typography>
              <List dense>
                {[
                  { attack: "Data Poisoning", desc: "Corrupt training data to manipulate model" },
                  { attack: "Backdoor Attacks", desc: "Insert trigger patterns for targeted misclassification" },
                  { attack: "Label Flipping", desc: "Mislabel data to degrade performance" },
                  { attack: "Model Trojans", desc: "Hidden behaviours activated by triggers" },
                ].map((item) => (
                  <ListItem key={item.attack} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.attack}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>🎯 Inference-time Attacks</Typography>
              <List dense>
                {[
                  { attack: "Adversarial Examples", desc: "Imperceptible perturbations cause misclassification" },
                  { attack: "Evasion Attacks", desc: "Modify malicious inputs to bypass detection" },
                  { attack: "Model Extraction", desc: "Query model to steal functionality" },
                  { attack: "Membership Inference", desc: "Determine if sample was in training data" },
                ].map((item) => (
                  <ListItem key={item.attack} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.attack}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>🔓 Privacy Attacks</Typography>
              <List dense>
                {[
                  { attack: "Model Inversion", desc: "Reconstruct training data from model" },
                  { attack: "Attribute Inference", desc: "Infer sensitive attributes from predictions" },
                  { attack: "Training Data Extraction", desc: "LLMs memorise and leak training data" },
                  { attack: "Gradient Leakage", desc: "Reconstruct data from federated learning" },
                ].map((item) => (
                  <ListItem key={item.attack} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.attack}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* LLM Security */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>🤖 LLM-Specific Security (OWASP LLM Top 10)</Typography>
          <Grid container spacing={2}>
            {[
              { vuln: "Prompt Injection", desc: "Attacker instructions override system prompt" },
              { vuln: "Insecure Output Handling", desc: "Downstream code execution, XSS, SSRF" },
              { vuln: "Training Data Poisoning", desc: "Corrupt fine-tuning or RAG data" },
              { vuln: "Model Denial of Service", desc: "Resource exhaustion via crafted inputs" },
              { vuln: "Supply Chain Vulnerabilities", desc: "Compromised models, datasets, libraries" },
              { vuln: "Sensitive Info Disclosure", desc: "PII, credentials leaked in responses" },
              { vuln: "Insecure Plugin Design", desc: "Over-permissioned tools, lack of validation" },
              { vuln: "Excessive Agency", desc: "Autonomous actions without proper controls" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.vuln}>
                <Box>
                  <Typography variant="caption" sx={{ fontWeight: 600, color: "#ef4444" }}>{item.vuln}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>{item.desc}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== SECTION 17: AI IN CYBER DEFENCE ==================== */}
        <Typography id="ai-cyber-defence" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🛡️ AI in Cyber Defence
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Using AI/ML to detect threats, automate response, and enhance security operations
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#16a34a", 0.03), border: `1px solid ${alpha("#16a34a", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>AI-powered defence</strong> has become essential for modern security operations. The volume 
            of alerts, the speed of attacks, and the sophistication of threats exceed human capacity. ML models 
            detect anomalies, classify threats, prioritise incidents, and even automate initial response actions.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Key applications include:</strong> SIEM/SOAR enrichment, network traffic analysis (NTA), 
            user and entity behaviour analytics (UEBA), endpoint detection and response (EDR), email security, 
            and fraud detection. Each domain has specific ML approaches tuned to its data and threat landscape.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>LLM-powered security tools</strong> are emerging rapidly — copilots for threat hunting, 
            natural language query interfaces for SIEM, automated incident summarisation, and conversational 
            threat intelligence. These augment human analysts rather than replacing them.
          </Typography>
        </Paper>

        {/* Defence Applications */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>AI Defence Applications</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#16a34a", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#16a34a" }}>🔍 Detection & Monitoring</Typography>
              <List dense>
                {[
                  { app: "Malware Classification", desc: "Static/dynamic analysis features → classifier" },
                  { app: "Network Anomaly Detection", desc: "Baseline traffic, detect deviations" },
                  { app: "UEBA", desc: "User behaviour baselines, insider threat detection" },
                  { app: "Log Anomaly Detection", desc: "Identify unusual patterns in logs" },
                  { app: "DGA Detection", desc: "Classify algorithmically generated domains" },
                ].map((item) => (
                  <ListItem key={item.app} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.app}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>📧 Email & Phishing</Typography>
              <List dense>
                {[
                  { app: "Phishing Detection", desc: "URL, content, sender reputation analysis" },
                  { app: "BEC Detection", desc: "Impersonation, urgency, financial requests" },
                  { app: "Spam Filtering", desc: "Classic ML success story" },
                  { app: "Attachment Analysis", desc: "Sandbox + ML classification" },
                  { app: "Brand Impersonation", desc: "Logo detection, domain similarity" },
                ].map((item) => (
                  <ListItem key={item.app} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.app}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>🤖 SOC & Automation</Typography>
              <List dense>
                {[
                  { app: "Alert Triage", desc: "Prioritise, deduplicate, correlate alerts" },
                  { app: "Incident Summarisation", desc: "LLM-generated incident reports" },
                  { app: "Threat Intel Enrichment", desc: "Automate IOC lookup and context" },
                  { app: "Playbook Automation", desc: "SOAR with ML-driven decisions" },
                  { app: "Security Copilots", desc: "Natural language threat hunting" },
                ].map((item) => (
                  <ListItem key={item.app} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.app}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Threat Intel & Fraud */}
        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>📊 Threat Intelligence</Typography>
              <List dense>
                {[
                  { use: "Report Parsing", desc: "NER extraction of IOCs, TTPs, actors from reports" },
                  { use: "Dark Web Monitoring", desc: "NLP analysis of forums, marketplaces" },
                  { use: "Campaign Clustering", desc: "Group related attacks via similarity" },
                  { use: "Attribution", desc: "Behavioural patterns → threat actor linkage" },
                ].map((item) => (
                  <ListItem key={item.use} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.use}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ec4899", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>💳 Fraud Detection</Typography>
              <List dense>
                {[
                  { use: "Transaction Fraud", desc: "Real-time scoring, anomaly detection" },
                  { use: "Account Takeover", desc: "Login behaviour, device fingerprinting" },
                  { use: "Synthetic Identity", desc: "Detect fabricated identity patterns" },
                  { use: "Money Laundering (AML)", desc: "Graph analysis, suspicious patterns" },
                ].map((item) => (
                  <ListItem key={item.use} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.use}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== SECTION 18: AI IN OFFENSIVE SECURITY ==================== */}
        <Typography id="ai-offensive-security" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🐛 AI in Offensive Security
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Using AI/ML to enhance penetration testing, red teaming, and security research
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#ea580c", 0.03), border: `1px solid ${alpha("#ea580c", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>AI-augmented offensive security</strong> enhances the capabilities of penetration testers and 
            red teams. From automated reconnaissance to intelligent fuzzing, AI helps identify vulnerabilities 
            faster and more comprehensively than manual approaches alone.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Key applications include:</strong> attack surface discovery, vulnerability pattern recognition, 
            exploit generation assistance, social engineering simulation, and adversary emulation. These tools 
            augment human expertise rather than replacing the creativity and judgement of skilled operators.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Ethical considerations are paramount.</strong> The same techniques that help defenders can 
            empower attackers. Responsible disclosure, authorisation, and scope control remain essential. 
            Understanding these tools helps security professionals anticipate how adversaries might use AI.
          </Typography>
        </Paper>

        {/* Offensive AI Applications */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>AI-Enhanced Offensive Techniques</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ea580c", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ea580c" }}>🔍 Reconnaissance</Typography>
              <List dense>
                {[
                  { tech: "OSINT Automation", desc: "Scrape, correlate, and analyse public data" },
                  { tech: "Attack Surface Mapping", desc: "Discover assets, subdomains, services" },
                  { tech: "Social Graph Analysis", desc: "Map relationships for social engineering" },
                  { tech: "Technology Fingerprinting", desc: "Identify stack from responses" },
                ].map((item) => (
                  <ListItem key={item.tech} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.tech}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>💥 Vulnerability Research</Typography>
              <List dense>
                {[
                  { tech: "ML-Guided Fuzzing", desc: "Intelligent input generation, coverage guidance" },
                  { tech: "Pattern Recognition", desc: "Identify vuln patterns in code/binaries" },
                  { tech: "Exploit Generation", desc: "LLM-assisted payload crafting" },
                  { tech: "Binary Analysis", desc: "Reverse engineering assistance" },
                ].map((item) => (
                  <ListItem key={item.tech} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.tech}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>🎭 Social Engineering</Typography>
              <List dense>
                {[
                  { tech: "Phishing Generation", desc: "LLM-crafted convincing pretexts" },
                  { tech: "Voice Cloning", desc: "Deepfake audio for vishing tests" },
                  { tech: "Persona Development", desc: "AI-generated fake profiles" },
                  { tech: "Response Simulation", desc: "Chatbots for engagement" },
                ].map((item) => (
                  <ListItem key={item.tech} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.tech}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Red Team & Tools */}
        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>🎯 Red Team Automation</Typography>
              <List dense>
                {[
                  { use: "Adversary Emulation", desc: "Simulate TTPs of known threat actors" },
                  { use: "C2 Optimisation", desc: "Evade detection, adapt to defences" },
                  { use: "Lateral Movement", desc: "Intelligent path finding through networks" },
                  { use: "Persistence", desc: "Identify and exploit persistence mechanisms" },
                  { use: "Reporting", desc: "Automated finding documentation" },
                ].map((item) => (
                  <ListItem key={item.use} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.use}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>🛠️ Tools & Frameworks</Typography>
              <Grid container spacing={1}>
                {[
                  { tool: "PentestGPT", desc: "LLM-guided penetration testing" },
                  { tool: "AutoGPT for Security", desc: "Autonomous security research" },
                  { tool: "Nuclei + AI", desc: "Intelligent template generation" },
                  { tool: "Burp + ML", desc: "AI-enhanced web testing" },
                  { tool: "CALDERA", desc: "Automated adversary emulation" },
                  { tool: "Atomic Red Team", desc: "TTP testing with ML analysis" },
                ].map((item) => (
                  <Grid item xs={6} key={item.tool}>
                    <Box>
                      <Typography variant="caption" sx={{ fontWeight: 600 }}>{item.tool}</Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>{item.desc}</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== SECTION 19: AI FOR SECURE SOFTWARE DEVELOPMENT ==================== */}
        <Typography id="ai-secure-dev" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🛠️ AI for Secure Software Development
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Integrating AI into the secure development lifecycle
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#7c3aed", 0.03), border: `1px solid ${alpha("#7c3aed", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>AI-enhanced secure development</strong> shifts security left by integrating intelligent 
            analysis throughout the software development lifecycle. From code completion that suggests secure 
            patterns to automated vulnerability detection in pull requests, AI makes security more accessible 
            to developers.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Key capabilities include:</strong> AI-assisted code review that spots security issues, 
            intelligent SAST that reduces false positives, automated threat modelling from architecture diagrams, 
            and smart dependency analysis that prioritises real risks over noise.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>The challenge is trust.</strong> Developers need to understand AI suggestions, not blindly 
            accept them. AI can introduce vulnerabilities too — insecure code suggestions, hallucinated APIs, 
            or outdated patterns. Effective use requires AI literacy alongside security knowledge.
          </Typography>
        </Paper>

        {/* Secure Dev AI Applications */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>AI in the Secure SDLC</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#7c3aed", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#7c3aed" }}>📝 Code Analysis</Typography>
              <List dense>
                {[
                  { app: "AI Code Review", desc: "Security-focused PR review, CWE detection" },
                  { app: "Secure Code Completion", desc: "Suggest secure patterns, flag issues" },
                  { app: "Vulnerability Explanation", desc: "LLM explains findings in context" },
                  { app: "Fix Suggestions", desc: "Generate secure code alternatives" },
                ].map((item) => (
                  <ListItem key={item.app} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.app}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>🔍 SAST Enhancement</Typography>
              <List dense>
                {[
                  { app: "False Positive Reduction", desc: "ML classifies true vs false findings" },
                  { app: "Reachability Analysis", desc: "AI determines exploitability" },
                  { app: "Priority Scoring", desc: "Risk-based triage of findings" },
                  { app: "Cross-tool Correlation", desc: "Deduplicate across scanners" },
                ].map((item) => (
                  <ListItem key={item.app} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.app}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>📦 Dependencies & SBOM</Typography>
              <List dense>
                {[
                  { app: "Risk Assessment", desc: "Prioritise CVEs by actual usage" },
                  { app: "License Analysis", desc: "Identify compliance issues" },
                  { app: "Malicious Package Detection", desc: "Spot supply chain attacks" },
                  { app: "Upgrade Path Analysis", desc: "Safe dependency updates" },
                ].map((item) => (
                  <ListItem key={item.app} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.app}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Threat Modelling & Tools */}
        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ec4899", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>🎯 AI-Assisted Threat Modelling</Typography>
              <List dense>
                {[
                  { aspect: "Architecture Analysis", desc: "Parse diagrams, identify components" },
                  { aspect: "Threat Generation", desc: "STRIDE/PASTA threats from architecture" },
                  { aspect: "Attack Tree Generation", desc: "Automated attack path enumeration" },
                  { aspect: "Mitigation Suggestions", desc: "Context-aware security controls" },
                  { aspect: "Documentation", desc: "Generate threat model reports" },
                ].map((item) => (
                  <ListItem key={item.aspect} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.aspect}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>🛠️ Tools & Platforms</Typography>
              <Grid container spacing={1}>
                {[
                  { tool: "GitHub Copilot", desc: "Code completion with security awareness" },
                  { tool: "Snyk DeepCode AI", desc: "ML-powered code analysis" },
                  { tool: "Amazon CodeGuru", desc: "Security recommendations" },
                  { tool: "SonarQube AI", desc: "Enhanced SAST with ML" },
                  { tool: "Semgrep Pro", desc: "AI-assisted rule writing" },
                  { tool: "Socket.dev", desc: "Supply chain risk analysis" },
                ].map((item) => (
                  <Grid item xs={6} key={item.tool}>
                    <Box>
                      <Typography variant="caption" sx={{ fontWeight: 600 }}>{item.tool}</Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>{item.desc}</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== SECTION 20: ETHICS, SAFETY, AND GOVERNANCE ==================== */}
        <Typography id="ethics-governance" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          ⚖️ Ethics, Safety, and Governance
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Responsible AI development, deployment, and oversight
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#be185d", 0.03), border: `1px solid ${alpha("#be185d", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>AI ethics and governance</strong> ensure that AI systems are developed and deployed responsibly. 
            As AI becomes more powerful and pervasive, the potential for harm increases — biased decisions, 
            privacy violations, job displacement, and misuse for surveillance or manipulation.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Key concerns include:</strong> algorithmic bias and fairness, privacy and data protection, 
            transparency and explainability, accountability for AI decisions, and the balance between innovation 
            and safety. Frameworks like the EU AI Act are establishing regulatory requirements.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>For security professionals,</strong> AI governance intersects with security governance. 
            AI systems process sensitive data, make access decisions, and can be weaponised. Understanding 
            ethical frameworks helps navigate the dual-use nature of security AI tools.
          </Typography>
        </Paper>

        {/* Ethics Topics */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Core Ethics Concepts</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#be185d", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#be185d" }}>⚖️ Fairness & Bias</Typography>
              <List dense>
                {[
                  { topic: "Sources of Bias", desc: "Training data, labelling, feature selection" },
                  { topic: "Types of Fairness", desc: "Demographic parity, equalised odds, individual" },
                  { topic: "Bias Detection", desc: "Audit models across protected groups" },
                  { topic: "Mitigation Strategies", desc: "Pre/in/post-processing techniques" },
                ].map((item) => (
                  <ListItem key={item.topic} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.topic}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>🔒 Privacy & Data</Typography>
              <List dense>
                {[
                  { topic: "Data Minimisation", desc: "Collect only what's needed" },
                  { topic: "Differential Privacy", desc: "Provable privacy guarantees" },
                  { topic: "Federated Learning", desc: "Train without centralising data" },
                  { topic: "Right to Explanation", desc: "GDPR requirements for automated decisions" },
                ].map((item) => (
                  <ListItem key={item.topic} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.topic}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>👁️ Transparency</Typography>
              <List dense>
                {[
                  { topic: "Explainability", desc: "Why did the model decide this?" },
                  { topic: "Model Cards", desc: "Document capabilities and limitations" },
                  { topic: "Datasheets", desc: "Document training data provenance" },
                  { topic: "Audit Trails", desc: "Log decisions for accountability" },
                ].map((item) => (
                  <ListItem key={item.topic} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.topic}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Governance & Regulation */}
        <Grid container spacing={3} sx={{ mb: 5 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>📜 Regulation & Frameworks</Typography>
              <List dense>
                {[
                  { reg: "EU AI Act", desc: "Risk-based regulation, prohibited uses, requirements" },
                  { reg: "NIST AI RMF", desc: "US framework for AI risk management" },
                  { reg: "ISO 42001", desc: "AI management system standard" },
                  { reg: "IEEE 7000", desc: "Ethical design process standard" },
                  { reg: "GDPR Art. 22", desc: "Rights regarding automated decisions" },
                ].map((item) => (
                  <ListItem key={item.reg} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.reg}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>👤 Human-in-the-Loop</Typography>
              <List dense>
                {[
                  { concept: "Human Oversight", desc: "Meaningful control over AI decisions" },
                  { concept: "Escalation Paths", desc: "When AI defers to humans" },
                  { concept: "Override Mechanisms", desc: "Ability to correct AI decisions" },
                  { concept: "Continuous Monitoring", desc: "Human review of AI behaviour" },
                  { concept: "Feedback Loops", desc: "Learn from human corrections" },
                ].map((item) => (
                  <ListItem key={item.concept} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.concept}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* ==================== SECTION 21: PRODUCT AND PROFESSIONAL PRACTICE ==================== */}
        <Typography id="product-practice" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          💼 Product and Professional Practice
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Applying AI knowledge in real-world roles and building your career
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#0d9488", 0.03), border: `1px solid ${alpha("#0d9488", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>AI product management</strong> bridges technical capabilities and business value. It requires 
            understanding what AI can and cannot do, how to evaluate AI systems, and how to communicate 
            AI capabilities and limitations to stakeholders.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Research literacy</strong> is essential for staying current. The field moves fast — reading 
            papers, understanding benchmarks, and evaluating claims critically separates informed practitioners 
            from those chasing hype. ArXiv, conference proceedings, and technical blogs are key sources.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Career paths in AI</strong> are diverse: ML engineer, data scientist, AI researcher, 
            MLOps engineer, AI security specialist, AI product manager, and more. Understanding these roles 
            helps you chart your path and build relevant skills.
          </Typography>
        </Paper>

        {/* Professional Skills */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Professional Skills</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#0d9488", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0d9488" }}>📊 AI Product Management</Typography>
              <List dense>
                {[
                  { skill: "Requirements Gathering", desc: "Translate business needs to AI specs" },
                  { skill: "Evaluation Design", desc: "Define success metrics, test plans" },
                  { skill: "Stakeholder Communication", desc: "Explain AI to non-technical audiences" },
                  { skill: "Risk Assessment", desc: "Identify failure modes, edge cases" },
                ].map((item) => (
                  <ListItem key={item.skill} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.skill}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>📚 Research Literacy</Typography>
              <List dense>
                {[
                  { skill: "Paper Reading", desc: "Extract key insights efficiently" },
                  { skill: "Benchmark Understanding", desc: "What metrics mean, limitations" },
                  { skill: "Reproducibility", desc: "Replicate results, validate claims" },
                  { skill: "Trend Analysis", desc: "Distinguish signal from noise" },
                ].map((item) => (
                  <ListItem key={item.skill} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.skill}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>🌟 Portfolio Building</Typography>
              <List dense>
                {[
                  { skill: "Project Selection", desc: "Demonstrate relevant skills" },
                  { skill: "Documentation", desc: "Clear READMEs, notebooks, write-ups" },
                  { skill: "Open Source", desc: "Contribute to AI/ML projects" },
                  { skill: "Blogging/Teaching", desc: "Solidify knowledge by explaining" },
                ].map((item) => (
                  <ListItem key={item.skill} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.skill}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600 }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        {/* Career Paths */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>🚀 AI Career Paths</Typography>
          <Grid container spacing={2}>
            {[
              { role: "ML Engineer", desc: "Build, deploy, and maintain ML systems in production" },
              { role: "Data Scientist", desc: "Extract insights, build models, communicate findings" },
              { role: "AI Researcher", desc: "Push frontiers, publish papers, develop new methods" },
              { role: "MLOps Engineer", desc: "Infrastructure, pipelines, deployment, monitoring" },
              { role: "AI Security Specialist", desc: "Secure AI systems, red team, governance" },
              { role: "AI Product Manager", desc: "Define requirements, prioritise, ship AI products" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.role}>
                <Box>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 0.3 }}>{item.role}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== COURSE OUTLINE ==================== */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Typography id="outline" variant="h4" sx={{ fontWeight: 800, scrollMarginTop: 180 }}>
            📚 Course Outline
          </Typography>
          <Chip label={`${outlineSections.length} Sections`} size="small" color="primary" variant="outlined" />
        </Box>

        <Grid container spacing={2}>
          {outlineSections.map((section, index) => (
            <Grid item xs={12} sm={6} md={4} key={section.id}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 3,
                  border: `1px solid ${alpha(section.color, 0.2)}`,
                  cursor: section.status === "Complete" ? "pointer" : "default",
                  transition: "all 0.2s",
                  "&:hover": section.status === "Complete" ? {
                    borderColor: section.color,
                    transform: "translateY(-2px)",
                    boxShadow: `0 4px 12px ${alpha(section.color, 0.15)}`,
                  } : {},
                }}
                onClick={() => {
                  if (section.status === "Complete") {
                    document.getElementById(section.id)?.scrollIntoView({ behavior: "smooth" });
                  }
                }}
              >
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5 }}>
                  <Box sx={{ 
                    p: 1, 
                    borderRadius: 2, 
                    bgcolor: alpha(section.color, 0.1),
                    color: section.color,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}>
                    {section.icon}
                  </Box>
                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5, flexWrap: "wrap" }}>
                      <Typography variant="caption" sx={{ fontWeight: 600, color: "text.secondary" }}>
                        {String(index + 1).padStart(2, "0")}
                      </Typography>
                      <Chip
                        label={section.status}
                        size="small"
                        sx={{
                          height: 18,
                          fontSize: "0.65rem",
                          bgcolor: section.status === "Complete" ? alpha("#22c55e", 0.1) : alpha("#f59e0b", 0.1),
                          color: section.status === "Complete" ? "#22c55e" : "#f59e0b",
                        }}
                      />
                    </Box>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
                      {section.title}
                    </Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ 
                      display: "-webkit-box",
                      WebkitLineClamp: 2,
                      WebkitBoxOrient: "vertical",
                      overflow: "hidden",
                    }}>
                      {section.description}
                    </Typography>
                  </Box>
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Detailed Section Outlines */}
        <Typography variant="h5" sx={{ fontWeight: 800, mt: 6, mb: 3 }}>
          📋 Detailed Section Topics
        </Typography>

        {/* Data Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <StorageIcon sx={{ color: "#3b82f6" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6" }}>Data</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Data collection and labelling", "Data quality and governance", "Cleaning and preprocessing", 
              "Feature engineering", "Data augmentation", "Dataset bias and representativeness"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* Maths and Theory Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#ef4444", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <FunctionsIcon sx={{ color: "#ef4444" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444" }}>Maths and Theory</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Statistics for AI", "Linear algebra for AI", "Probability basics", "Calculus basics",
              "Optimisation (gradient descent, loss landscapes)", "Information theory basics"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* Programming and Compute Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <CodeIcon sx={{ color: "#f59e0b" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b" }}>Programming and Compute</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Python for AI (notebooks, packages, testing)", "Version control and reproducibility",
              "Compute fundamentals (CPU/GPU/TPU)", "Performance basics (latency, throughput, memory)"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* Core Machine Learning Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <AccountTreeIcon sx={{ color: "#22c55e" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>Core Machine Learning</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Supervised learning", "Unsupervised learning", "Semi-supervised learning", "Self-supervised learning",
              "Reinforcement learning", "Online learning and streaming ML", "Active learning"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* Classical ML Models Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#06b6d4", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <CategoryIcon sx={{ color: "#06b6d4" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#06b6d4" }}>Classical ML Models and Techniques</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Linear and logistic regression", "Decision trees and ensembles (random forest, boosting)",
              "SVM, kNN, Naive Bayes", "Time series forecasting", "Anomaly detection", "Recommender systems",
              "Causal inference and causal ML", "Graph machine learning (GNNs, link prediction)"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* Deep Learning Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#ec4899", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <LayersIcon sx={{ color: "#ec4899" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#ec4899" }}>Deep Learning</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Neural network fundamentals", "Backpropagation and training dynamics", "Regularisation (dropout, weight decay)",
              "CNNs", "RNNs and sequence models", "Transformers", "Embeddings and representation learning",
              "Transfer learning", "Multi-task learning", "Multi-modal learning"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* NLP Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#14b8a6", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <TextFieldsIcon sx={{ color: "#14b8a6" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#14b8a6" }}>Natural Language Processing</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Tokenisation and embeddings", "Text classification", "Named entity recognition",
              "Summarisation", "Question answering"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* LLM and Agents Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#a855f7", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <SmartToyIcon sx={{ color: "#a855f7" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#a855f7" }}>Large Language Models and Agents</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["LLM pretraining and fine-tuning concepts", "Instruction tuning and alignment basics",
              "Prompt engineering and prompt patterns", "Retrieval Augmented Generation (RAG)",
              "Tool use and function calling", "Agents and orchestration patterns",
              "LLM evaluation (benchmarks, rubrics, human eval)"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* Computer Vision Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#0ea5e9", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <VisibilityIcon sx={{ color: "#0ea5e9" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#0ea5e9" }}>Computer Vision</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["CV fundamentals (images, augmentation, datasets)", "Image classification", "Object detection",
              "Segmentation (semantic, instance)", "Pose estimation", "OCR", "Video understanding (tracking, action recognition)",
              "Vision Transformers (ViT)", "Generative vision (diffusion, GANs)", "Domain shift and robustness in real-world vision"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* Speech and Audio Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#f97316", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <RecordVoiceOverIcon sx={{ color: "#f97316" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#f97316" }}>Speech and Audio AI</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Automatic speech recognition (ASR)", "Text-to-speech (TTS)", "Speaker recognition",
              "Audio classification", "Signal processing essentials"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* Generative AI Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#d946ef", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <AutoAwesomeIcon sx={{ color: "#d946ef" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#d946ef" }}>Generative AI</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Generative modelling overview", "Diffusion models", "GANs", "VAEs", "Code generation models"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* Evaluation and Testing Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#84cc16", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <AssessmentIcon sx={{ color: "#84cc16" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#84cc16" }}>Evaluation and Testing</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Metrics for classification, regression, ranking", "Validation methods and leakage prevention",
              "Calibration and uncertainty", "Interpretability and explainability (XAI)", "Robustness testing"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* MLOps and Deployment Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#6366f1", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <RocketLaunchIcon sx={{ color: "#6366f1" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#6366f1" }}>MLOps and Deployment</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["ML pipelines and CI/CD", "Model serving (batch vs real-time)", "Edge deployment",
              "Inference optimisation (quantisation, pruning, distillation)", "Monitoring and observability (drift, performance, data quality)",
              "Model incident response", "Cost management (FinOps for AI)"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* Platforms and Infrastructure Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#0891b2", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <CloudIcon sx={{ color: "#0891b2" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#0891b2" }}>Platforms and Infrastructure</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Cloud AI fundamentals (AWS/Azure/GCP patterns)", "On-prem and private AI stacks",
              "Vector databases and embedding stores", "Data engineering for AI (logs, ETL/ELT, schemas)"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* AI Security Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#dc2626", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <SecurityIcon sx={{ color: "#dc2626" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#dc2626" }}>AI Security</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Threat modelling for AI/LLMs", "Adversarial ML (evasion, poisoning, backdoors)",
              "Model privacy attacks (inference, inversion)", "Prompt injection and indirect prompt injection",
              "RAG security (data poisoning, retrieval manipulation, leakage)", "Model supply chain security (datasets, checkpoints, dependencies)",
              "Secure deployment (secrets, isolation, access control)", "Red teaming and safety testing"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* AI in Cyber Defence Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#16a34a", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <ShieldIcon sx={{ color: "#16a34a" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#16a34a" }}>AI in Cyber Defence</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["SOC triage and alert enrichment", "Detection using ML (EDR/NDR, anomaly detection)",
              "UEBA and behavioural analytics", "Threat intelligence augmentation", "Phishing and fraud detection",
              "Malware detection with ML (static, dynamic, behavioural)", "Vulnerability management with AI (prioritisation, remediation support)",
              "Incident response copilots and automation", "Detection engineering with AI (rule generation, tuning, validation)"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* AI in Offensive Security Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#ea580c", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <BugReportIcon sx={{ color: "#ea580c" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#ea580c" }}>AI in Offensive Security</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Reconnaissance and OSINT augmentation", "Attack surface analysis and target prioritisation",
              "Exploit research assistance (pattern discovery, code reasoning)", "Adversary emulation support (TTP mapping, playbooks)",
              "Social engineering risk and controls (awareness, simulation ethics)",
              "Offensive tool risk management (safe lab use, approvals, ethics)"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* AI for Secure Software Development Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#7c3aed", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <BuildIcon sx={{ color: "#7c3aed" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#7c3aed" }}>AI for Secure Software Development</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["AI-assisted code review and secure coding", "AI-enhanced SAST and triage",
              "AI-assisted threat modelling", "SBOM and dependency risk analysis"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* Ethics, Safety, and Governance Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#be185d", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <GavelIcon sx={{ color: "#be185d" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#be185d" }}>Ethics, Safety, and Governance</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Bias, fairness, and harm", "Privacy and data protection", "Transparency and accountability",
              "Human-in-the-loop design", "Misuse prevention and dual-use handling",
              "Governance, auditability, and documentation"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* Product and Professional Practice Section Outline */}
        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, border: `1px solid ${alpha("#0d9488", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <WorkIcon sx={{ color: "#0d9488" }} />
            <Typography variant="h6" sx={{ fontWeight: 700, color: "#0d9488" }}>Product and Professional Practice</Typography>
          </Box>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["AI product management (requirements, evaluation plans)", "Research literacy (papers, benchmarks, reproducibility)",
              "Role-based pathways (developer, security, research, leadership)", "Portfolio projects and capstones"].map((topic) => (
              <Chip key={topic} label={topic} size="small" variant="outlined" />
            ))}
          </Box>
        </Paper>

        {/* Footer */}
        <Paper sx={{ p: 3, mt: 5, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.1)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            <TimelineIcon sx={{ color: "#8b5cf6", fontSize: 32 }} />
            <Box>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6" }}>
                Comprehensive AI Education
              </Typography>
              <Typography variant="body2" color="text.secondary">
                This course covers the full spectrum of AI knowledge — from mathematical foundations to practical 
                deployment, from core ML theory to cutting-edge LLMs, and from building AI systems to securing them. 
                Content is continuously updated as the field evolves.
              </Typography>
            </Box>
          </Box>
        </Paper>

        {/* Footer Navigation */}
        <Box sx={{ display: "flex", justifyContent: "center", mt: 4 }}>
          <Button
            variant="outlined"
            size="large"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{
              borderRadius: 2,
              px: 4,
              py: 1.5,
              fontWeight: 600,
              borderColor: alpha("#8b5cf6", 0.3),
              color: "#8b5cf6",
              "&:hover": {
                borderColor: "#8b5cf6",
                bgcolor: alpha("#8b5cf6", 0.05),
              },
            }}
          >
            Return to Learning Hub
          </Button>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
