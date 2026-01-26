import React, { useState, useEffect } from "react";
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
  Divider,
  Fab,
  Drawer,
  IconButton,
  Tooltip,
  useMediaQuery,
  useTheme,
  LinearProgress,
} from "@mui/material";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
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
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import QuizIcon from "@mui/icons-material/Quiz";
import { Link, useNavigate } from "react-router-dom";

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

const ACCENT_COLOR = "#8b5cf6";
const QUIZ_QUESTION_COUNT = 10;

const selectRandomQuestions = (questions: QuizQuestion[], count: number) =>
  [...questions].sort(() => Math.random() - 0.5).slice(0, count);

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "AI is best described as:",
    options: [
      "Systems that perform tasks requiring human intelligence",
      "Only robotics",
      "Only data storage",
      "Only rule-based scripts",
    ],
    correctAnswer: 0,
    explanation: "AI covers systems that can perform tasks requiring intelligence.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "Machine learning is:",
    options: [
      "A subset of AI that learns from data",
      "A type of database",
      "A network protocol",
      "Only hand-written rules",
    ],
    correctAnswer: 0,
    explanation: "ML is a subset of AI focused on learning from data.",
  },
  {
    id: 3,
    topic: "Fundamentals",
    question: "Deep learning refers to:",
    options: [
      "Neural networks with many layers",
      "Any statistical test",
      "A single decision tree",
      "Manual feature coding only",
    ],
    correctAnswer: 0,
    explanation: "Deep learning uses multi-layer neural networks.",
  },
  {
    id: 4,
    topic: "Learning Types",
    question: "Supervised learning uses:",
    options: ["Labeled data", "No data", "Only reinforcement signals", "Only random outputs"],
    correctAnswer: 0,
    explanation: "Supervised learning learns from labeled examples.",
  },
  {
    id: 5,
    topic: "Learning Types",
    question: "Unsupervised learning aims to:",
    options: ["Find patterns without labels", "Predict labels from labeled data", "Receive rewards", "Encrypt data"],
    correctAnswer: 0,
    explanation: "Unsupervised learning discovers structure in unlabeled data.",
  },
  {
    id: 6,
    topic: "Learning Types",
    question: "Reinforcement learning learns by:",
    options: ["Maximizing rewards through actions", "Reading labeled files", "Clustering text", "Copying outputs"],
    correctAnswer: 0,
    explanation: "RL learns through actions and reward signals.",
  },
  {
    id: 7,
    topic: "Data",
    question: "The test set is primarily used to:",
    options: ["Evaluate final model performance", "Tune hyperparameters", "Train the model", "Store backups"],
    correctAnswer: 0,
    explanation: "The test set provides a final unbiased evaluation.",
  },
  {
    id: 8,
    topic: "Fundamentals",
    question: "Overfitting occurs when a model:",
    options: [
      "Performs well on training data but poorly on new data",
      "Performs poorly on training data only",
      "Is too simple",
      "Has no features",
    ],
    correctAnswer: 0,
    explanation: "Overfitting hurts generalization to new data.",
  },
  {
    id: 9,
    topic: "Fundamentals",
    question: "Underfitting occurs when a model:",
    options: [
      "Is too simple and performs poorly on both train and test",
      "Memorizes training data",
      "Has too many layers",
      "Uses too much data",
    ],
    correctAnswer: 0,
    explanation: "Underfitting means the model is too simple to learn patterns.",
  },
  {
    id: 10,
    topic: "Data",
    question: "A feature is:",
    options: ["An input variable used by the model", "The model output", "The loss value", "A training epoch"],
    correctAnswer: 0,
    explanation: "Features are the input variables used for prediction.",
  },
  {
    id: 11,
    topic: "Data",
    question: "A label is:",
    options: ["The target output for supervised learning", "An input feature", "A hyperparameter", "A GPU setting"],
    correctAnswer: 0,
    explanation: "Labels are the ground-truth outputs in supervised learning.",
  },
  {
    id: 12,
    topic: "Training",
    question: "A hyperparameter is:",
    options: ["A setting chosen before training", "A weight learned during training", "An output label", "A data record"],
    correctAnswer: 0,
    explanation: "Hyperparameters are set before training begins.",
  },
  {
    id: 13,
    topic: "Training",
    question: "A loss function:",
    options: ["Measures model error to minimize", "Stores data", "Encrypts inputs", "Schedules jobs"],
    correctAnswer: 0,
    explanation: "Loss quantifies error that training minimizes.",
  },
  {
    id: 14,
    topic: "Training",
    question: "Gradient descent is:",
    options: ["An optimization method to minimize loss", "A data storage format", "A logging tool", "A database index"],
    correctAnswer: 0,
    explanation: "Gradient descent updates parameters to reduce loss.",
  },
  {
    id: 15,
    topic: "Training",
    question: "Regularization helps by:",
    options: ["Reducing overfitting", "Increasing label noise", "Deleting data", "Guaranteeing accuracy"],
    correctAnswer: 0,
    explanation: "Regularization discourages overly complex models.",
  },
  {
    id: 16,
    topic: "Training",
    question: "Cross-validation is used to:",
    options: ["Estimate performance more reliably", "Increase training data size only", "Replace test sets", "Avoid evaluation"],
    correctAnswer: 0,
    explanation: "Cross-validation provides a more robust performance estimate.",
  },
  {
    id: 17,
    topic: "Metrics",
    question: "Which metric focuses on catching positives and reducing false negatives?",
    options: ["Recall", "Precision", "Accuracy", "Specificity"],
    correctAnswer: 0,
    explanation: "Recall measures how many true positives are captured.",
  },
  {
    id: 18,
    topic: "Metrics",
    question: "Which metric focuses on reducing false positives?",
    options: ["Precision", "Recall", "Accuracy", "RMSE"],
    correctAnswer: 0,
    explanation: "Precision improves when false positives are reduced.",
  },
  {
    id: 19,
    topic: "Metrics",
    question: "F1 score is:",
    options: ["The harmonic mean of precision and recall", "Average of accuracy and loss", "Only recall", "Only precision"],
    correctAnswer: 0,
    explanation: "F1 balances precision and recall.",
  },
  {
    id: 20,
    topic: "Metrics",
    question: "A confusion matrix counts:",
    options: ["True/false positives and negatives", "CPU usage", "Model size", "Token lengths"],
    correctAnswer: 0,
    explanation: "Confusion matrices summarize classification outcomes.",
  },
  {
    id: 21,
    topic: "Models",
    question: "Classification models output:",
    options: ["Categories or class labels", "Continuous values only", "Random strings", "Disk usage"],
    correctAnswer: 0,
    explanation: "Classification predicts discrete classes.",
  },
  {
    id: 22,
    topic: "Models",
    question: "Linear regression is used to:",
    options: ["Predict continuous values", "Cluster data", "Sort arrays only", "Encrypt messages"],
    correctAnswer: 0,
    explanation: "Linear regression predicts continuous targets.",
  },
  {
    id: 23,
    topic: "Models",
    question: "Logistic regression is commonly used for:",
    options: ["Binary classification", "Time synchronization", "Image compression", "Backup scheduling"],
    correctAnswer: 0,
    explanation: "Logistic regression models class probabilities.",
  },
  {
    id: 24,
    topic: "Models",
    question: "Decision trees work by:",
    options: ["Splitting data based on feature tests", "Performing matrix inversion only", "Randomly guessing outputs", "Encrypting features"],
    correctAnswer: 0,
    explanation: "Decision trees split on features to make decisions.",
  },
  {
    id: 25,
    topic: "Models",
    question: "Random forests are:",
    options: ["Ensembles of decision trees", "Single large tree", "Neural networks", "Clustering algorithms"],
    correctAnswer: 0,
    explanation: "Random forests combine many trees for robustness.",
  },
  {
    id: 26,
    topic: "Models",
    question: "kNN predicts by:",
    options: ["Looking at the nearest neighbors", "Maximizing reward", "Applying gradient descent directly", "Generating random labels"],
    correctAnswer: 0,
    explanation: "kNN uses the closest points to classify or regress.",
  },
  {
    id: 27,
    topic: "Models",
    question: "SVM aims to:",
    options: ["Find the maximum-margin separating hyperplane", "Minimize disk usage", "Encode images", "Balance network load"],
    correctAnswer: 0,
    explanation: "SVMs maximize the margin between classes.",
  },
  {
    id: 28,
    topic: "Models",
    question: "K-means is used for:",
    options: ["Clustering unlabeled data", "Supervised classification", "Sequence prediction", "Model serving"],
    correctAnswer: 0,
    explanation: "K-means groups data into clusters.",
  },
  {
    id: 29,
    topic: "Models",
    question: "PCA is primarily used for:",
    options: ["Dimensionality reduction", "Label encoding", "Data encryption", "Web scraping"],
    correctAnswer: 0,
    explanation: "PCA reduces dimensionality while preserving variance.",
  },
  {
    id: 30,
    topic: "Deep Learning",
    question: "CNNs are well suited for:",
    options: ["Image and spatial data", "Database indexing", "Time sync", "Disk backups"],
    correctAnswer: 0,
    explanation: "CNNs exploit spatial structure in images.",
  },
  {
    id: 31,
    topic: "Deep Learning",
    question: "RNNs are well suited for:",
    options: ["Sequences and time series", "Static images only", "Sorting logs", "Firewall rules"],
    correctAnswer: 0,
    explanation: "RNNs model sequential dependencies.",
  },
  {
    id: 32,
    topic: "Deep Learning",
    question: "LSTMs help with:",
    options: ["Long-range dependencies in sequences", "Disk encryption", "Vector search", "OS scheduling"],
    correctAnswer: 0,
    explanation: "LSTMs mitigate vanishing gradients in sequences.",
  },
  {
    id: 33,
    topic: "Deep Learning",
    question: "Transformers are built around:",
    options: ["Self-attention mechanisms", "Decision trees", "K-means clustering", "Only recurrence"],
    correctAnswer: 0,
    explanation: "Transformers use self-attention to model context.",
  },
  {
    id: 34,
    topic: "Deep Learning",
    question: "Attention lets a model:",
    options: ["Weight relevant tokens differently", "Skip training", "Ignore input order entirely", "Use only the last token"],
    correctAnswer: 0,
    explanation: "Attention focuses on the most relevant parts of the input.",
  },
  {
    id: 35,
    topic: "NLP",
    question: "An embedding is:",
    options: ["A dense vector representation of data", "A raw text string", "A backup file", "A cache miss"],
    correctAnswer: 0,
    explanation: "Embeddings encode data into vectors for ML.",
  },
  {
    id: 36,
    topic: "NLP",
    question: "Tokenization is:",
    options: ["Splitting text into smaller units", "Encrypting text", "Compressing images", "Normalizing data by label"],
    correctAnswer: 0,
    explanation: "Tokenization breaks text into tokens.",
  },
  {
    id: 37,
    topic: "NLP",
    question: "NER stands for and does what?",
    options: [
      "Named Entity Recognition identifies entities in text",
      "Neural Error Reduction compresses models",
      "Network Endpoint Routing forwards packets",
      "New Embedding Registry stores models",
    ],
    correctAnswer: 0,
    explanation: "NER labels entities like names, places, and organizations.",
  },
  {
    id: 38,
    topic: "NLP",
    question: "A language model primarily predicts:",
    options: ["Next token in a sequence", "Only sentiment", "Image labels", "Database rows"],
    correctAnswer: 0,
    explanation: "Language models are trained to predict the next token.",
  },
  {
    id: 39,
    topic: "LLMs",
    question: "Pretraining typically uses:",
    options: ["Large general datasets", "Only labeled task data", "No data", "Only test sets"],
    correctAnswer: 0,
    explanation: "Pretraining uses large-scale data to learn general patterns.",
  },
  {
    id: 40,
    topic: "LLMs",
    question: "Fine-tuning is:",
    options: ["Adapting a pretrained model to a specific task", "Training from scratch", "Only evaluation", "Only compressing model"],
    correctAnswer: 0,
    explanation: "Fine-tuning adapts a model to a target task or domain.",
  },
  {
    id: 41,
    topic: "LLMs",
    question: "RLHF is used to:",
    options: ["Align model behavior with human feedback", "Speed up GPUs", "Encrypt datasets", "Reduce tokenization"],
    correctAnswer: 0,
    explanation: "RLHF aligns outputs to human preferences and safety goals.",
  },
  {
    id: 42,
    topic: "LLMs",
    question: "Prompt engineering is:",
    options: ["Crafting inputs to guide model outputs", "Compiling code", "Creating datasets only", "Replacing training"],
    correctAnswer: 0,
    explanation: "Prompting shapes how models respond to inputs.",
  },
  {
    id: 43,
    topic: "LLMs",
    question: "Temperature controls:",
    options: ["Randomness in generation", "Training dataset size", "GPU clock speed", "Number of parameters"],
    correctAnswer: 0,
    explanation: "Higher temperature increases output randomness.",
  },
  {
    id: 44,
    topic: "LLMs",
    question: "Top-k sampling means:",
    options: ["Sampling from the top k probable tokens", "Using top k datasets", "Keeping k layers only", "Top k metrics only"],
    correctAnswer: 0,
    explanation: "Top-k sampling limits choices to the k most likely tokens.",
  },
  {
    id: 45,
    topic: "RAG",
    question: "RAG is best described as:",
    options: ["Retrieval augmented generation combining search with generation", "A database backup tool", "A training optimizer", "A GPU driver"],
    correctAnswer: 0,
    explanation: "RAG retrieves relevant context before generating responses.",
  },
  {
    id: 46,
    topic: "RAG",
    question: "A vector database stores:",
    options: ["Embeddings for similarity search", "Only text logs", "Only SQL tables", "Only backups"],
    correctAnswer: 0,
    explanation: "Vector databases store embeddings for nearest-neighbor search.",
  },
  {
    id: 47,
    topic: "MLOps",
    question: "Model drift occurs when:",
    options: ["Input data distribution changes over time", "Model size increases", "Logs rotate", "GPU overheats"],
    correctAnswer: 0,
    explanation: "Drift happens when data changes and performance degrades.",
  },
  {
    id: 48,
    topic: "MLOps",
    question: "Data leakage means:",
    options: ["Training data contains information from the test set", "Model is too small", "Data is encrypted", "GPU is idle"],
    correctAnswer: 0,
    explanation: "Leakage makes evaluation overly optimistic.",
  },
  {
    id: 49,
    topic: "MLOps",
    question: "MLOps typically includes:",
    options: ["CI/CD for models and pipelines", "Only model research", "Only data labeling", "Only UI design"],
    correctAnswer: 0,
    explanation: "MLOps operationalizes models with CI/CD and monitoring.",
  },
  {
    id: 50,
    topic: "MLOps",
    question: "Model monitoring is used to:",
    options: ["Track performance and detect issues in production", "Train models", "Label data", "Store passwords"],
    correctAnswer: 0,
    explanation: "Monitoring detects drift and performance regressions.",
  },
  {
    id: 51,
    topic: "MLOps",
    question: "A/B testing is used to:",
    options: ["Compare two model versions", "Encrypt datasets", "Reduce training time", "Pick hardware"],
    correctAnswer: 0,
    explanation: "A/B tests compare model variants in production.",
  },
  {
    id: 52,
    topic: "Security",
    question: "An adversarial example is:",
    options: ["An input modified to fool the model", "A normal training sample", "A data backup", "A network scan"],
    correctAnswer: 0,
    explanation: "Adversarial examples intentionally mislead models.",
  },
  {
    id: 53,
    topic: "Security",
    question: "Data poisoning is:",
    options: ["Maliciously altering training data", "Encrypting datasets", "Reducing batch size", "Cleaning logs"],
    correctAnswer: 0,
    explanation: "Poisoning injects malicious data to manipulate training.",
  },
  {
    id: 54,
    topic: "Security",
    question: "Prompt injection is:",
    options: ["Input designed to override model instructions", "A GPU driver update", "A dataset split", "A logging format"],
    correctAnswer: 0,
    explanation: "Prompt injection tries to bypass or alter instructions.",
  },
  {
    id: 55,
    topic: "Privacy",
    question: "Model memorization risk refers to:",
    options: ["Leaking training data from outputs", "Slow inference", "Low accuracy", "High latency"],
    correctAnswer: 0,
    explanation: "Models can unintentionally reveal training data.",
  },
  {
    id: 56,
    topic: "Privacy",
    question: "Differential privacy works by:",
    options: ["Adding noise to protect individuals", "Encrypting all data", "Removing all features", "Only using public data"],
    correctAnswer: 0,
    explanation: "Differential privacy adds noise to limit individual exposure.",
  },
  {
    id: 57,
    topic: "Ethics",
    question: "Bias in datasets can lead to:",
    options: ["Unfair or discriminatory outcomes", "Higher storage use only", "Faster training", "Better privacy by default"],
    correctAnswer: 0,
    explanation: "Biased data can cause unfair model behavior.",
  },
  {
    id: 58,
    topic: "Explainability",
    question: "Explainability methods help to:",
    options: ["Understand model decisions", "Increase GPU speed", "Replace labels", "Avoid testing"],
    correctAnswer: 0,
    explanation: "Explainability improves transparency and trust.",
  },
  {
    id: 59,
    topic: "Deployment",
    question: "Inference latency matters most for:",
    options: ["Real-time applications", "Offline batch jobs", "Data labeling", "Model training"],
    correctAnswer: 0,
    explanation: "Real-time use cases require low latency.",
  },
  {
    id: 60,
    topic: "Deployment",
    question: "Batch inference is best for:",
    options: ["Offline processing of large datasets", "Real-time chat", "Interactive search", "Streaming control"],
    correctAnswer: 0,
    explanation: "Batch inference suits offline, high-volume jobs.",
  },
  {
    id: 61,
    topic: "Compute",
    question: "GPUs are useful because they:",
    options: ["Perform parallel computations efficiently", "Store databases", "Run DNS services", "Replace CPUs"],
    correctAnswer: 0,
    explanation: "GPUs accelerate parallel ML workloads.",
  },
  {
    id: 62,
    topic: "Compute",
    question: "TPUs are designed for:",
    options: ["Tensor operations in ML workloads", "File storage", "Network routing", "Audio playback"],
    correctAnswer: 0,
    explanation: "TPUs are specialized hardware for tensor math.",
  },
  {
    id: 63,
    topic: "Training",
    question: "Grid search is used for:",
    options: ["Hyperparameter tuning", "Data encryption", "Vector search", "Database indexing"],
    correctAnswer: 0,
    explanation: "Grid search tries combinations of hyperparameters.",
  },
  {
    id: 64,
    topic: "Training",
    question: "Early stopping helps to:",
    options: ["Prevent overfitting", "Increase model size", "Avoid validation", "Skip deployment"],
    correctAnswer: 0,
    explanation: "Early stopping halts training when validation degrades.",
  },
  {
    id: 65,
    topic: "Training",
    question: "Dropout works by:",
    options: ["Randomly disabling neurons during training", "Adding more layers", "Duplicating data", "Changing labels"],
    correctAnswer: 0,
    explanation: "Dropout reduces overfitting by random neuron removal.",
  },
  {
    id: 66,
    topic: "Training",
    question: "Batch size refers to:",
    options: ["Number of samples per training update", "Total number of features", "Training epochs", "Number of GPUs"],
    correctAnswer: 0,
    explanation: "Batch size controls how many samples update weights at once.",
  },
  {
    id: 67,
    topic: "Training",
    question: "An epoch is:",
    options: ["One full pass through the training data", "A single batch", "A data label", "A deployment"],
    correctAnswer: 0,
    explanation: "An epoch is one complete pass through the dataset.",
  },
  {
    id: 68,
    topic: "Training",
    question: "Learning rate controls:",
    options: ["Step size of parameter updates", "Number of layers", "Dataset size", "Label quality"],
    correctAnswer: 0,
    explanation: "Learning rate sets update step sizes during training.",
  },
  {
    id: 69,
    topic: "Metrics",
    question: "For imbalanced classes, a good metric is:",
    options: ["F1 score", "Accuracy", "MSE", "MAE"],
    correctAnswer: 0,
    explanation: "F1 balances precision and recall for imbalanced data.",
  },
  {
    id: 70,
    topic: "Metrics",
    question: "To reduce false positives, you usually optimize for:",
    options: ["Higher precision", "Higher recall", "Higher loss", "Higher variance"],
    correctAnswer: 0,
    explanation: "Precision improves when false positives drop.",
  },
  {
    id: 71,
    topic: "Metrics",
    question: "ROC-AUC measures:",
    options: ["Ranking performance across thresholds", "Training speed", "Memory usage", "Token count"],
    correctAnswer: 0,
    explanation: "ROC-AUC summarizes ranking quality over thresholds.",
  },
  {
    id: 72,
    topic: "Metrics",
    question: "Calibration means:",
    options: ["Predicted probabilities match observed outcomes", "Predictions are random", "Loss is zero", "Data is encrypted"],
    correctAnswer: 0,
    explanation: "Calibration aligns predicted probabilities with reality.",
  },
  {
    id: 73,
    topic: "Transfer Learning",
    question: "Transfer learning means:",
    options: ["Reusing a pretrained model for a new task", "Training from scratch always", "Only using unlabeled data", "Ignoring prior knowledge"],
    correctAnswer: 0,
    explanation: "Transfer learning reuses learned representations.",
  },
  {
    id: 74,
    topic: "Transfer Learning",
    question: "Zero-shot learning means:",
    options: ["Performing a task without task-specific training examples", "Training with 1000 examples", "Only using labeled data", "Only using images"],
    correctAnswer: 0,
    explanation: "Zero-shot performs tasks without labeled examples for that task.",
  },
  {
    id: 75,
    topic: "Transfer Learning",
    question: "Few-shot learning means:",
    options: ["Using a small number of examples to adapt", "Never using examples", "Only training on millions of samples", "Only using unsupervised data"],
    correctAnswer: 0,
    explanation: "Few-shot adapts with a small set of examples.",
  },
];


export default function ArtificialIntelligencePage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("lg"));
  
  const [quizPool] = useState<QuizQuestion[]>(() =>
    selectRandomQuestions(quizQuestions, QUIZ_QUESTION_COUNT)
  );

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");

  // Module navigation items
  const moduleNavItems = [
    { id: "outline", label: "Course Outline", icon: "📚" },
    { id: "foundations", label: "Foundations", icon: "🧠" },
    { id: "data", label: "Data", icon: "📊" },
    { id: "maths-theory", label: "Maths & Theory", icon: "📐" },
    { id: "programming-compute", label: "Programming", icon: "💻" },
    { id: "core-ml", label: "Core ML", icon: "🎯" },
    { id: "classical-ml", label: "Classical ML", icon: "📊" },
    { id: "deep-learning", label: "Deep Learning", icon: "🧬" },
    { id: "nlp", label: "NLP", icon: "📝" },
    { id: "llm-agents", label: "LLMs & Agents", icon: "🤖" },
    { id: "computer-vision", label: "Computer Vision", icon: "👁️" },
    { id: "speech-audio", label: "Speech & Audio", icon: "🎤" },
    { id: "generative-ai", label: "Generative AI", icon: "✨" },
    { id: "evaluation-testing", label: "Evaluation", icon: "📈" },
    { id: "mlops-deployment", label: "MLOps", icon: "🚀" },
    { id: "platforms-infra", label: "Platforms", icon: "☁️" },
    { id: "ai-security", label: "AI Security", icon: "🔒" },
    { id: "ai-cyber-defence", label: "AI Defence", icon: "🛡️" },
    { id: "ai-offensive-security", label: "AI Offensive", icon: "🐛" },
    { id: "ai-secure-dev", label: "AI Secure Dev", icon: "🔧" },
    { id: "ethics-governance", label: "Ethics", icon: "⚖️" },
    { id: "product-practice", label: "Practice", icon: "💼" },
    { id: "quiz", label: "Quiz", icon: "❓" },
  ];

  // Scroll to section
  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
      setNavDrawerOpen(false);
    }
  };

  // Track active section on scroll
  useEffect(() => {
    const handleScroll = () => {
      const sections = moduleNavItems.map(item => item.id);
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
    };

    window.addEventListener("scroll", handleScroll);
    handleScroll(); // Initial check
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  // Scroll to top helper
  const scrollToTop = () => window.scrollTo({ top: 0, behavior: "smooth" });

  // Calculate progress based on active section
  const currentIndex = moduleNavItems.findIndex(item => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / moduleNavItems.length) * 100 : 0;

  // Desktop sidebar navigation component
  const sidebarNav = (
    <Paper
      elevation={0}
      sx={{
        width: 220,
        flexShrink: 0,
        position: "sticky",
        top: 80,
        maxHeight: "calc(100vh - 100px)",
        overflowY: "auto",
        borderRadius: 3,
        border: `1px solid ${alpha(ACCENT_COLOR, 0.15)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        display: { xs: "none", lg: "block" },
        "&::-webkit-scrollbar": {
          width: 6,
        },
        "&::-webkit-scrollbar-thumb": {
          bgcolor: alpha(ACCENT_COLOR, 0.3),
          borderRadius: 3,
        },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: ACCENT_COLOR, display: "flex", alignItems: "center", gap: 1 }}>
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">Progress</Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: ACCENT_COLOR }}>{Math.round(progressPercent)}%</Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha(ACCENT_COLOR, 0.1),
              "& .MuiLinearProgress-bar": {
                bgcolor: ACCENT_COLOR,
                borderRadius: 3,
              },
            }}
          />
        </Box>
        <Divider sx={{ mb: 1 }} />
        <List dense sx={{ mx: -1 }}>
          {moduleNavItems.map((item) => (
            <ListItem
              key={item.id}
              onClick={() => scrollToSection(item.id)}
              sx={{
                borderRadius: 1.5,
                mb: 0.25,
                py: 0.5,
                cursor: "pointer",
                bgcolor: activeSection === item.id ? alpha(ACCENT_COLOR, 0.15) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid ${ACCENT_COLOR}` : "3px solid transparent",
                "&:hover": {
                  bgcolor: alpha(ACCENT_COLOR, 0.08),
                },
                transition: "all 0.15s ease",
              }}
            >
              <ListItemIcon sx={{ minWidth: 24, fontSize: "0.9rem" }}>
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={
                  <Typography
                    variant="caption"
                    sx={{
                      fontWeight: activeSection === item.id ? 700 : 500,
                      color: activeSection === item.id ? ACCENT_COLOR : "text.secondary",
                      fontSize: "0.75rem",
                    }}
                  >
                    {item.label}
                  </Typography>
                }
              />
            </ListItem>
          ))}
        </List>
      </Box>
    </Paper>
  );

  return (
    <LearnPageLayout
      pageTitle="Artificial Intelligence"
      pageContext="This is the Artificial Intelligence learning page covering AI/ML fundamentals, deep learning, NLP, computer vision, LLMs, MLOps, AI security, and AI applications in cybersecurity. Help users understand AI concepts, techniques, and practical applications."
    >
      {/* Floating Navigation Button - Mobile Only */}
      <Tooltip title="Navigate Sections" placement="left">
        <Fab
          color="primary"
          onClick={() => setNavDrawerOpen(true)}
          sx={{
            position: "fixed",
            bottom: 90,
            right: 24,
            zIndex: 1000,
            bgcolor: ACCENT_COLOR,
            "&:hover": { bgcolor: "#7c3aed" },
            boxShadow: `0 4px 20px ${alpha(ACCENT_COLOR, 0.4)}`,
            display: { xs: "flex", lg: "none" },
          }}
        >
          <ListAltIcon />
        </Fab>
      </Tooltip>

      {/* Scroll to Top Button - Mobile Only */}
      <Tooltip title="Scroll to Top" placement="left">
        <Fab
          size="small"
          onClick={scrollToTop}
          sx={{
            position: "fixed",
            bottom: 32,
            right: 28,
            zIndex: 1000,
            bgcolor: alpha(ACCENT_COLOR, 0.15),
            color: ACCENT_COLOR,
            "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.25) },
            display: { xs: "flex", lg: "none" },
          }}
        >
          <KeyboardArrowUpIcon />
        </Fab>
      </Tooltip>

      {/* Navigation Drawer - Mobile */}
      <Drawer
        anchor="right"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        PaperProps={{
          sx: {
            width: isMobile ? "85%" : 320,
            bgcolor: theme.palette.background.paper,
            backgroundImage: "none",
          },
        }}
      >
        <Box sx={{ p: 2 }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
              <ListAltIcon sx={{ color: ACCENT_COLOR }} />
              Course Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} size="small">
              <CloseIcon />
            </IconButton>
          </Box>
          
          <Divider sx={{ mb: 2 }} />

          {/* Progress indicator */}
          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha(ACCENT_COLOR, 0.05) }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">Progress</Typography>
              <Typography variant="caption" sx={{ fontWeight: 600, color: ACCENT_COLOR }}>{Math.round(progressPercent)}%</Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{
                height: 6,
                borderRadius: 3,
                bgcolor: alpha(ACCENT_COLOR, 0.1),
                "& .MuiLinearProgress-bar": {
                  bgcolor: ACCENT_COLOR,
                  borderRadius: 3,
                },
              }}
            />
          </Box>

          {/* Navigation List */}
          <List dense sx={{ mx: -1 }}>
            {moduleNavItems.map((item) => (
              <ListItem
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                sx={{
                  borderRadius: 2,
                  mb: 0.5,
                  cursor: "pointer",
                  bgcolor: activeSection === item.id ? alpha(ACCENT_COLOR, 0.15) : "transparent",
                  borderLeft: activeSection === item.id ? `3px solid ${ACCENT_COLOR}` : "3px solid transparent",
                  "&:hover": {
                    bgcolor: alpha(ACCENT_COLOR, 0.1),
                  },
                  transition: "all 0.2s ease",
                }}
              >
                <ListItemIcon sx={{ minWidth: 32, fontSize: "1.1rem" }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Typography
                      variant="body2"
                      sx={{
                        fontWeight: activeSection === item.id ? 700 : 500,
                        color: activeSection === item.id ? ACCENT_COLOR : "text.primary",
                      }}
                    >
                      {item.label}
                    </Typography>
                  }
                />
                {activeSection === item.id && (
                  <Chip
                    label="Current"
                    size="small"
                    sx={{
                      height: 20,
                      fontSize: "0.65rem",
                      bgcolor: alpha(ACCENT_COLOR, 0.2),
                      color: ACCENT_COLOR,
                    }}
                  />
                )}
              </ListItem>
            ))}
          </List>

          <Divider sx={{ my: 2 }} />

          {/* Quick Actions */}
          <Box sx={{ display: "flex", gap: 1 }}>
            <Button
              size="small"
              variant="outlined"
              onClick={scrollToTop}
              startIcon={<KeyboardArrowUpIcon />}
              sx={{ flex: 1, borderColor: alpha(ACCENT_COLOR, 0.3), color: ACCENT_COLOR }}
            >
              Top
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => scrollToSection("quiz")}
              startIcon={<QuizIcon />}
              sx={{ flex: 1, borderColor: alpha(ACCENT_COLOR, 0.3), color: ACCENT_COLOR }}
            >
              Quiz
            </Button>
          </Box>
        </Box>
      </Drawer>

      {/* Main Layout with Sidebar */}
      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, sm: 3 }, py: 4 }}>
        {/* Desktop Sidebar */}
        {sidebarNav}

        {/* Main Content */}
        <Box sx={{ flex: 1, minWidth: 0 }}>
        {/* Header */}
        <Box sx={{ mb: 4, display: "flex", alignItems: "center", gap: 2, flexWrap: "wrap" }}>
          <Chip
            component={Link}
            to="/learn"
            icon={<ArrowBackIcon />}
            label="Back to Learning Hub"
            clickable
            variant="outlined"
            sx={{ borderRadius: 2 }}
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
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#0ea5e9", 0.04), border: `1px solid ${alpha("#0ea5e9", 0.2)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 800, mb: 1 }}>
            How to Navigate This Page
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
            This page is intentionally long and layered. Each section builds on the previous one, moving from
            foundational concepts to advanced systems and real-world applications. If you are new, read in order.
            If you are experienced, jump to the section that matches your immediate goal, then backfill the basics.
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>
            The goal is practical understanding, not memorization. Every topic includes plain language summaries,
            reasons it matters, and how it connects to deployment, risk, or security. Treat this as a living
            reference you return to as your work evolves.
          </Typography>
        </Paper>

        {/* ==================== COURSE OUTLINE (Moved to top) ==================== */}
        <Box id="outline" sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, scrollMarginTop: 80 }}>
          <Typography variant="h4" sx={{ fontWeight: 800 }}>
            📚 Course Outline
          </Typography>
          <Chip label={`${outlineSections.length} Sections`} size="small" color="primary" variant="outlined" />
        </Box>

        <Grid container spacing={2} sx={{ mb: 5 }}>
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

        {/* ==================== SECTION 1: FOUNDATIONS ==================== */}
        <Typography id="foundations" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          🧠 Foundations
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Understanding what AI is, where it came from, and how AI projects work
        </Typography>
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Foundations in Practice
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          Foundations are about building intuition. You will see repeated themes: data quality, clear objectives,
          and honest evaluation. These themes matter more than any single model family, because they determine
          whether AI adds real value or just complexity.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          As you read, keep asking: What is the input? What is the output? How will we know if the system helps?
          The answers guide model choice, deployment architecture, and even staffing requirements.
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Data as a Product
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          Treat data like a product with owners, documentation, and quality standards. Most ML failures are not
          algorithmic; they are caused by missing coverage, drifting distributions, or ambiguous labels. Good data
          practices reduce incident response and shorten model iteration cycles.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          For security and operational teams, data quality is a risk control. It prevents misleading alerts,
          reduces false positives, and makes model outputs defensible in audits or incident reviews.
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Math for Decision Making
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          You do not need to derive proofs, but you do need to understand what the math is trying to optimize.
          Concepts like gradients, distributions, and variance explain why models behave the way they do under
          change, noise, or adversarial inputs.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          Strong mathematical intuition helps you ask better questions: Is the data separable? Are we overfitting?
          Does the loss function match the business objective? These questions lead to better models and safer
          deployments.
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Engineering Reality
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          AI work quickly becomes a software engineering problem. Experiments are exploratory, but production
          systems require reproducibility, monitoring, and clear ownership. That means thinking about tests,
          versioning, and rollback strategies from day one.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          Compute choices influence cost and speed. A model that trains in hours instead of days enables faster
          iteration, better debugging, and more reliable outcomes. Infrastructure is not just a detail; it is a
          core part of the product.
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Choosing the Right Paradigm
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          The learning paradigm you choose drives data needs, evaluation metrics, and deployment complexity. A
          supervised classifier can be straightforward to operate, while reinforcement learning might require a
          simulation environment and continuous tuning.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          Practical teams start with the simplest approach that meets requirements, then add complexity only
          when it yields measurable improvements. This saves time and reduces operational risk.
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Why Classical Models Still Win
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          Classical models are fast, explainable, and often more reliable for structured data. They are easier to
          debug, cheaper to serve, and more transparent to stakeholders who need to understand decisions.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          Even when you deploy deep learning, classical baselines remain essential. They provide a sanity check
          and help quantify whether the added complexity is truly justified.
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Why Depth Changes the Game
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          Deep learning excels when the raw input is complex and high dimensional, like images, text, or audio.
          It reduces the need for handcrafted features by learning representations directly from data, but it also
          demands more compute, more data, and more careful evaluation.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          Understanding the strengths and limits of deep learning helps you decide when to use it and when to keep
          a simpler model. Depth is powerful, but it is not always the most practical choice.
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Language is Hard for Machines
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          Human language is full of ambiguity, implied meaning, and cultural context. NLP systems must deal with
          sarcasm, domain jargon, and shifting definitions over time. That is why evaluation often requires domain
          experts, not just benchmark scores.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          In practice, NLP success depends on careful data curation and clear intent. A model that performs well
          in a lab can still fail in the field if it does not match real user language or operational constraints.
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          From Text Prediction to Systems
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          LLMs are powerful, but they are not databases or search engines. They generate likely sequences based on
          patterns, which means they can be persuasive even when wrong. This makes grounding, verification, and
          tool-based retrieval essential for reliable applications.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          Agents add orchestration and memory, enabling multi-step workflows. That also increases risk: more tools
          means more attack surface, and more autonomy means stricter safeguards are required.
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

        {/* LLM History Timeline */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>📜 LLM History & Evolution</Typography>
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#6366f1", 0.03), border: `1px solid ${alpha("#6366f1", 0.15)}` }}>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            The rapid evolution from statistical models to trillion-parameter reasoning systems
          </Typography>
          <Box sx={{ position: "relative", pl: 3, borderLeft: `3px solid ${alpha("#6366f1", 0.3)}` }}>
            {[
              { year: "2017", event: "Attention Is All You Need", desc: "Google introduces the Transformer architecture, replacing RNNs with self-attention. Foundation of modern LLMs.", color: "#ef4444" },
              { year: "2018", event: "GPT-1 & BERT", desc: "OpenAI's GPT-1 (117M params) shows generative pretraining works. Google's BERT revolutionises NLU with bidirectional attention.", color: "#f59e0b" },
              { year: "2019", event: "GPT-2", desc: "1.5B parameters. 'Too dangerous to release' — first viral AI safety moment. Zero-shot capabilities emerge.", color: "#22c55e" },
              { year: "2020", event: "GPT-3 & Scaling Laws", desc: "175B parameters. Few-shot learning, emergent abilities. Kaplan scaling laws published. API-first business model.", color: "#3b82f6" },
              { year: "2021", event: "Codex & GitHub Copilot", desc: "Code-trained models. InstructGPT introduces RLHF alignment. Anthropic founded (Constitutional AI).", color: "#8b5cf6" },
              { year: "2022", event: "ChatGPT & Diffusion", desc: "ChatGPT reaches 100M users in 2 months. Stable Diffusion open-sourced. AI winter ends definitively.", color: "#ec4899" },
              { year: "2023", event: "GPT-4 & Open Source Surge", desc: "Multimodal GPT-4. LLaMA leaked, spawning Alpaca, Vicuna, etc. Claude 2, Gemini announced. Mixtral MoE.", color: "#06b6d4" },
              { year: "2024", event: "Reasoning & Agents", desc: "Claude 3/3.5, GPT-4o, Gemini 1.5 (1M context). o1/o3 reasoning models. Open weights: LLaMA 3, Qwen 2.5. MCP protocol.", color: "#10b981" },
              { year: "2025", event: "GPT-5 & Gemini 3 Era", desc: "GPT-5.x series, Claude Opus 4.5, Gemini 3 Pro/Flash. Grok 4, DeepSeek V3.2. 400K-1M contexts standard. Chinese models surge.", color: "#a855f7" },
            ].map((item, idx) => (
              <Box key={idx} sx={{ mb: 2.5, position: "relative" }}>
                <Box sx={{ position: "absolute", left: -19, top: 4, width: 12, height: 12, borderRadius: "50%", bgcolor: item.color, border: "2px solid white" }} />
                <Box sx={{ display: "flex", alignItems: "baseline", gap: 1.5, mb: 0.5 }}>
                  <Chip label={item.year} size="small" sx={{ bgcolor: alpha(item.color, 0.15), color: item.color, fontWeight: 700, fontSize: "0.7rem", height: 20 }} />
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.event}</Typography>
                </Box>
                <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
              </Box>
            ))}
          </Box>
        </Paper>

        {/* Transformer Architecture Deep Dive */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🔬 The Transformer Architecture</Typography>
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#0ea5e9", 0.03), border: `1px solid ${alpha("#0ea5e9", 0.15)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            The <strong>Transformer</strong> (Vaswani et al., 2017) replaced recurrence with <strong>self-attention</strong>, 
            enabling parallel processing and capturing long-range dependencies. Every modern LLM is built on this foundation.
          </Typography>
          
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#0ea5e9", 0.05) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#0ea5e9", mb: 1 }}>🧩 Core Components</Typography>
                <List dense>
                  {[
                    { name: "Token Embeddings", desc: "Convert tokens to dense vectors (d=4096+)" },
                    { name: "Positional Encoding", desc: "Inject sequence order (sinusoidal or learned, RoPE)" },
                    { name: "Multi-Head Attention", desc: "Parallel attention heads capture different relationships" },
                    { name: "Feed-Forward Network", desc: "Two linear layers with activation (usually SwiGLU now)" },
                    { name: "Layer Normalization", desc: "Stabilise training (Pre-LN is now standard)" },
                    { name: "Residual Connections", desc: "Skip connections enable deep networks" },
                  ].map((item) => (
                    <ListItem key={item.name} sx={{ py: 0.3, px: 0 }}>
                      <ListItemText 
                        primary={item.name}
                        secondary={item.desc}
                        primaryTypographyProps={{ variant: "caption", fontWeight: 600 }}
                        secondaryTypographyProps={{ variant: "caption", fontSize: "0.65rem" }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>⚡ Self-Attention Mechanism</Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                  Attention(Q, K, V) = softmax(QK<sup>T</sup> / √d<sub>k</sub>) × V
                </Typography>
                <List dense>
                  {[
                    { name: "Query (Q)", desc: "What am I looking for?" },
                    { name: "Key (K)", desc: "What do I contain?" },
                    { name: "Value (V)", desc: "What information do I provide?" },
                    { name: "Scaling (√d)", desc: "Prevent softmax saturation" },
                    { name: "Causal Mask", desc: "Decoder-only: can't see future tokens" },
                  ].map((item) => (
                    <ListItem key={item.name} sx={{ py: 0.3, px: 0 }}>
                      <ListItemText 
                        primary={item.name}
                        secondary={item.desc}
                        primaryTypographyProps={{ variant: "caption", fontWeight: 600 }}
                        secondaryTypographyProps={{ variant: "caption", fontSize: "0.65rem" }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Grid container spacing={2}>
            {[
              { variant: "Encoder-Only", desc: "Bidirectional attention. BERT, RoBERTa. Best for classification, NER, embeddings.", color: "#3b82f6" },
              { variant: "Decoder-Only", desc: "Causal (left-to-right) attention. GPT, LLaMA, Claude. Best for generation.", color: "#a855f7" },
              { variant: "Encoder-Decoder", desc: "Cross-attention between encoder/decoder. T5, BART. Best for translation, summarisation.", color: "#f59e0b" },
              { variant: "Mixture of Experts (MoE)", desc: "Sparse activation — route tokens to subset of experts. Mixtral, GPT-4(?). More params, same compute.", color: "#ef4444" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.variant}>
                <Paper sx={{ p: 1.5, borderRadius: 2, height: "100%", border: `1px solid ${alpha(item.color, 0.2)}` }}>
                  <Typography variant="caption" sx={{ fontWeight: 700, color: item.color, display: "block", mb: 0.5 }}>{item.variant}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.65rem" }}>{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Pre-training Deep Dive */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>📊 Pre-training: Building the Foundation</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>📚 Training Data</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                LLMs are trained on <strong>trillions of tokens</strong> from diverse sources. Data quality dramatically impacts model capability.
              </Typography>
              <List dense>
                {[
                  { source: "Common Crawl", desc: "Web scrapes. ~60% of training data. Heavy filtering needed." },
                  { source: "Books & Academic", desc: "Books3, PubMed, arXiv. Higher quality, structured knowledge." },
                  { source: "Code", desc: "GitHub, Stack Overflow. Enables code generation, structured reasoning." },
                  { source: "Wikipedia", desc: "Factual, well-structured. Often upweighted." },
                  { source: "Curated/Synthetic", desc: "Human-written, AI-generated. Quality over quantity trend." },
                ].map((item) => (
                  <ListItem key={item.source} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.source}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600, fontSize: "0.75rem" }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
              <Box sx={{ mt: 2, p: 1.5, bgcolor: alpha("#f59e0b", 0.08), borderRadius: 1 }}>
                <Typography variant="caption" sx={{ fontWeight: 600 }}>Data Processing Pipeline:</Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                  Crawl → Dedupe → Filter (quality, safety) → Tokenize → Shuffle → Train
                </Typography>
              </Box>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>🔤 Tokenization</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Convert text to integer sequences. Tokenizer choice significantly impacts model behaviour and efficiency.
              </Typography>
              <List dense>
                {[
                  { method: "BPE (Byte-Pair Encoding)", desc: "GPT series. Iteratively merge frequent pairs. ~50k vocab." },
                  { method: "WordPiece", desc: "BERT. Similar to BPE, likelihood-based merging." },
                  { method: "SentencePiece", desc: "Language-agnostic. Treats text as raw bytes. LLaMA, T5." },
                  { method: "Tiktoken", desc: "OpenAI's fast BPE. cl100k_base for GPT-4." },
                ].map((item) => (
                  <ListItem key={item.method} sx={{ py: 0.3, px: 0 }}>
                    <ListItemText 
                      primary={item.method}
                      secondary={item.desc}
                      primaryTypographyProps={{ variant: "subtitle2", fontWeight: 600, fontSize: "0.75rem" }}
                      secondaryTypographyProps={{ variant: "caption" }}
                    />
                  </ListItem>
                ))}
              </List>
              <Box sx={{ mt: 2, p: 1.5, bgcolor: alpha("#8b5cf6", 0.08), borderRadius: 1 }}>
                <Typography variant="caption" sx={{ fontWeight: 600 }}>Token Economics:</Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                  1 token ≈ 4 chars (English) ≈ 0.75 words. Code/math use more tokens.
                </Typography>
              </Box>
            </Paper>
          </Grid>
        </Grid>

        {/* Scaling Laws & Compute */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>📈 Scaling Laws & Compute</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            <strong>Chinchilla scaling laws</strong> (Hoffmann et al., 2022) showed optimal compute allocation: train smaller models on more data. 
            For compute budget C, optimal model size N and data D scale as: N ∝ C<sup>0.5</sup>, D ∝ C<sup>0.5</sup>
          </Typography>
          <Grid container spacing={2}>
            {[
              { metric: "GPT-3", params: "175B", tokens: "300B", compute: "~3.6×10²³ FLOPs", note: "Undertrained by Chinchilla standards" },
              { metric: "Chinchilla", params: "70B", tokens: "1.4T", compute: "~5×10²³ FLOPs", note: "Optimal ratio: 20 tokens/param" },
              { metric: "LLaMA 2 70B", params: "70B", tokens: "2T", compute: "~10²⁴ FLOPs", note: "Overtrained for inference efficiency" },
              { metric: "GPT-4 (est.)", params: "~1.8T MoE", tokens: "~13T", compute: "~10²⁵ FLOPs", note: "Mixture of Experts architecture" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.metric}>
                <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha("#ef4444", 0.05), textAlign: "center" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>{item.metric}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>{item.params} params</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>{item.tokens} tokens</Typography>
                  <Typography variant="caption" sx={{ fontSize: "0.6rem", color: "#ef4444" }}>{item.note}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
          <Box sx={{ mt: 3, p: 2, bgcolor: alpha("#ef4444", 0.08), borderRadius: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>💰 Training Cost Estimates (2024)</Typography>
            <Grid container spacing={2}>
              {[
                { model: "7B model", cost: "$100K - $500K", gpus: "64-256 A100s, 1-2 weeks" },
                { model: "70B model", cost: "$2M - $10M", gpus: "512-2048 A100s, 2-4 weeks" },
                { model: "GPT-4 class", cost: "$50M - $100M+", gpus: "25,000+ A100s/H100s, months" },
              ].map((item) => (
                <Grid item xs={12} sm={4} key={item.model}>
                  <Typography variant="caption" sx={{ fontWeight: 600, display: "block" }}>{item.model}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.cost}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block", fontSize: "0.6rem" }}>{item.gpus}</Typography>
                </Grid>
              ))}
            </Grid>
          </Box>
        </Paper>

        {/* Pre-training Objectives */}
        <Grid container spacing={2} sx={{ mb: 5 }}>
          {[
            { objective: "Causal LM (CLM)", desc: "Predict next token. GPT-style. Autoregressive generation. Most common for chat/generation models.", color: "#a855f7" },
            { objective: "Masked LM (MLM)", desc: "Predict masked tokens bidirectionally. BERT-style. Better for understanding/embeddings.", color: "#3b82f6" },
            { objective: "Prefix LM", desc: "Bidirectional on prefix, autoregressive on rest. T5, PaLM. Good for conditional generation.", color: "#22c55e" },
            { objective: "Denoising", desc: "Reconstruct corrupted input. BART, T5. Span corruption, sentence permutation.", color: "#f59e0b" },
            { objective: "Contrastive", desc: "Learn by comparing similar/dissimilar pairs. Used in embedding models (E5, BGE).", color: "#ec4899" },
            { objective: "Multimodal", desc: "Align text with images/audio. CLIP, LLaVA, Whisper. Cross-modal understanding.", color: "#06b6d4" },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.objective}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha(item.color, 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>{item.objective}</Typography>
                <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Post-Training & Alignment */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🎯 Post-Training: Alignment & Fine-Tuning</Typography>
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Post-training</strong> transforms a raw pretrained model into a helpful assistant. This multi-stage 
            process aligns the model with human preferences, teaches instruction-following, and adds safety guardrails.
          </Typography>
          
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>1️⃣ Supervised Fine-Tuning (SFT)</Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                  Train on high-quality (instruction, response) pairs. Human-written demonstrations of ideal behaviour.
                </Typography>
                <List dense>
                  {[
                    "10K-100K curated examples",
                    "Diverse tasks & formats",
                    "Quality >> quantity",
                    "Often contractor-written",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 16 }}>
                        <CheckCircleIcon sx={{ fontSize: 10, color: "#3b82f6" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "caption", fontSize: "0.65rem" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>2️⃣ RLHF (Reinforcement Learning from Human Feedback)</Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                  Train reward model on human preferences, then optimise policy via PPO.
                </Typography>
                <List dense>
                  {[
                    "Collect comparison data (A vs B)",
                    "Train reward model",
                    "PPO to maximise reward",
                    "KL penalty prevents drift",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 16 }}>
                        <CheckCircleIcon sx={{ fontSize: 10, color: "#f59e0b" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "caption", fontSize: "0.65rem" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#a855f7", 0.05), height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#a855f7", mb: 1 }}>3️⃣ DPO (Direct Preference Optimization)</Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                  Skip reward model — directly optimise on preferences. Simpler, often comparable results.
                </Typography>
                <List dense>
                  {[
                    "No separate reward model",
                    "Single-stage training",
                    "More stable than PPO",
                    "Used by LLaMA 2, Zephyr",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 16 }}>
                        <CheckCircleIcon sx={{ fontSize: 10, color: "#a855f7" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "caption", fontSize: "0.65rem" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Grid container spacing={2}>
            {[
              { method: "Constitutional AI", desc: "Self-critique against principles. Claude's approach. AI feedback at scale.", color: "#ec4899" },
              { method: "RLAIF", desc: "RL from AI Feedback. Use stronger model to label preferences. Scales better than humans.", color: "#06b6d4" },
              { method: "Rejection Sampling", desc: "Generate many responses, keep best. Simple but effective. Used in LLaMA 2.", color: "#22c55e" },
              { method: "Iterative DPO", desc: "Multiple rounds of DPO with fresh preferences. Continuous improvement.", color: "#f97316" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.method}>
                <Paper sx={{ p: 1.5, borderRadius: 2, height: "100%", border: `1px solid ${alpha(item.color, 0.2)}` }}>
                  <Typography variant="caption" sx={{ fontWeight: 700, color: item.color, display: "block", mb: 0.5 }}>{item.method}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.65rem" }}>{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Thinking/Reasoning Models */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🧠 Thinking Models & Reasoning</Typography>
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#d946ef", 0.03), border: `1px solid ${alpha("#d946ef", 0.15)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>Reasoning models</strong> (like OpenAI's o1, o3) represent a paradigm shift: instead of generating answers 
            immediately, they perform extended "thinking" — exploring solution paths, backtracking, and verifying before 
            responding. This trades latency and compute for dramatically improved performance on complex tasks.
          </Typography>
          
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#d946ef", 0.05) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#d946ef", mb: 1 }}>⚙️ How Thinking Models Work</Typography>
                <List dense>
                  {[
                    { step: "Extended Generation", desc: "Model generates long chain-of-thought (often hidden from user)" },
                    { step: "Search & Backtrack", desc: "Explore multiple reasoning paths, abandon dead ends" },
                    { step: "Self-Verification", desc: "Check intermediate steps, catch errors before output" },
                    { step: "Test-Time Compute", desc: "More thinking = better answers (within limits)" },
                    { step: "Reinforcement Learning", desc: "Trained to produce correct final answers via RL" },
                  ].map((item) => (
                    <ListItem key={item.step} sx={{ py: 0.3, px: 0 }}>
                      <ListItemText 
                        primary={item.step}
                        secondary={item.desc}
                        primaryTypographyProps={{ variant: "caption", fontWeight: 600 }}
                        secondaryTypographyProps={{ variant: "caption", fontSize: "0.65rem" }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#10b981", 0.05) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>📊 When to Use Thinking Models</Typography>
                <List dense>
                  {[
                    { use: "✅ Math & Logic", desc: "Competition math, proofs, puzzles" },
                    { use: "✅ Code & Debugging", desc: "Complex algorithms, finding subtle bugs" },
                    { use: "✅ Science Problems", desc: "Physics, chemistry, research questions" },
                    { use: "✅ Multi-step Planning", desc: "Strategy, complex analysis" },
                    { use: "❌ Simple Q&A", desc: "Overkill for basic questions" },
                    { use: "❌ Creative Writing", desc: "Standard models often better" },
                  ].map((item) => (
                    <ListItem key={item.use} sx={{ py: 0.3, px: 0 }}>
                      <ListItemText 
                        primary={item.use}
                        secondary={item.desc}
                        primaryTypographyProps={{ variant: "caption", fontWeight: 600 }}
                        secondaryTypographyProps={{ variant: "caption", fontSize: "0.65rem" }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Box sx={{ p: 2, bgcolor: alpha("#d946ef", 0.08), borderRadius: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>🏆 Reasoning & Thinking Models (December 2025)</Typography>
            <Grid container spacing={2}>
              {[
                { model: "OpenAI o3", status: "Released", notes: "Latest reasoning model. Strong ARC-AGI scores. Intelligence Index 65." },
                { model: "Kimi K2 Thinking", status: "Released", notes: "Chinese reasoning model. 256K context. Ultra-low 0.64s latency." },
                { model: "Claude Opus 4.5", status: "Released", notes: "Anthropic's flagship. Extended thinking. Top-tier code/analysis." },
                { model: "Gemini 3 Flash Thinking", status: "Released", notes: "Google's fast reasoning. 1M context. 219 tok/s speed." },
                { model: "DeepSeek V3.2", status: "Released", notes: "Open weights. $0.32/1M tokens. Competitive intelligence." },
                { model: "GPT-5.1 Codex", status: "Released", notes: "Specialised reasoning for code. 246 tok/s. Intelligence 67." },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.model}>
                  <Box>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                      <Typography variant="caption" sx={{ fontWeight: 700 }}>{item.model}</Typography>
                      <Chip label={item.status} size="small" sx={{ fontSize: "0.55rem", height: 16, bgcolor: item.status === "Released" ? alpha("#22c55e", 0.2) : alpha("#f59e0b", 0.2) }} />
                    </Box>
                    <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.6rem" }}>{item.notes}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Box>
        </Paper>

        {/* Benchmarking & Evaluation */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>📏 Benchmarking & Model Evaluation</Typography>
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#0ea5e9", 0.03), border: `1px solid ${alpha("#0ea5e9", 0.15)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            Evaluating LLMs is notoriously difficult. Models can "teach to the test" via data contamination, benchmarks 
            saturate quickly, and real-world usefulness doesn't always correlate with scores. Multiple evaluation 
            approaches are essential for understanding model capabilities.
          </Typography>
          
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>📊 Key Benchmarks</Typography>
                <List dense>
                  {[
                    { name: "MMLU", desc: "57 subjects, high school to expert. General knowledge." },
                    { name: "HumanEval / MBPP", desc: "Code generation. Function completion from docstring." },
                    { name: "GSM8K / MATH", desc: "Grade school to competition math. Reasoning required." },
                    { name: "HellaSwag / ARC", desc: "Common sense reasoning. Physical world understanding." },
                    { name: "TruthfulQA", desc: "Resistance to common misconceptions." },
                    { name: "MT-Bench", desc: "Multi-turn conversation quality. GPT-4 as judge." },
                    { name: "GPQA", desc: "Graduate-level science questions. Expert-written." },
                    { name: "ARC-AGI", desc: "Abstract reasoning. Pattern completion puzzles." },
                  ].map((item) => (
                    <ListItem key={item.name} sx={{ py: 0.2, px: 0 }}>
                      <ListItemText 
                        primary={item.name}
                        secondary={item.desc}
                        primaryTypographyProps={{ variant: "caption", fontWeight: 600 }}
                        secondaryTypographyProps={{ variant: "caption", fontSize: "0.6rem" }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>🏟️ Leaderboards & Arenas</Typography>
                <List dense>
                  {[
                    { name: "LMSYS Chatbot Arena", desc: "Blind human preference voting. ELO ratings. Gold standard." },
                    { name: "Artificial Analysis", desc: "Speed, cost, quality comparisons. API pricing tracker." },
                    { name: "Open LLM Leaderboard", desc: "HuggingFace hosted. Open models benchmarked consistently." },
                    { name: "LiveBench", desc: "Continuously updated. Avoids data contamination." },
                    { name: "AlpacaEval", desc: "Automated evaluation. GPT-4 as judge. Win rate vs GPT-4." },
                    { name: "Big Code Models", desc: "Code-specific leaderboard. Multiple coding benchmarks." },
                  ].map((item) => (
                    <ListItem key={item.name} sx={{ py: 0.2, px: 0 }}>
                      <ListItemText 
                        primary={item.name}
                        secondary={item.desc}
                        primaryTypographyProps={{ variant: "caption", fontWeight: 600 }}
                        secondaryTypographyProps={{ variant: "caption", fontSize: "0.6rem" }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Box sx={{ p: 2, bgcolor: alpha("#ef4444", 0.08), borderRadius: 2, mb: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>⚠️ Benchmark Pitfalls</Typography>
            <Grid container spacing={2}>
              {[
                { issue: "Data Contamination", desc: "Test data leaked into training. Inflated scores." },
                { issue: "Teaching to Test", desc: "Models optimised for specific benchmarks, not general capability." },
                { issue: "Saturation", desc: "Benchmarks become too easy. Need harder tests constantly." },
                { issue: "Vibes vs Scores", desc: "High benchmark ≠ good UX. Real usage differs." },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={3} key={item.issue}>
                  <Typography variant="caption" sx={{ fontWeight: 600, display: "block" }}>{item.issue}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.6rem" }}>{item.desc}</Typography>
                </Grid>
              ))}
            </Grid>
          </Box>

          <Typography variant="caption" color="text.secondary">
            <strong>Pro tip:</strong> Check LMSYS Arena for real human preferences, Artificial Analysis for pricing/speed, 
            and run your own evals on tasks that match your use case. Don't trust any single benchmark.
          </Typography>
        </Paper>

        {/* Model Comparison Table */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🏆 Frontier Model Comparison (December 2025)</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Data from Artificial Analysis — Intelligence Index measures general capability, but <strong>domain-specific performance varies significantly</strong>
        </Typography>
        
        {/* Domain Leaders Callout */}
        <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.08), border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "#d97706" }}>⚠️ Important: General Benchmarks Don't Tell The Whole Story</Typography>
          <Grid container spacing={2}>
            {[
              { domain: "Coding & Agentic Work", leader: "Claude Opus 4.5", note: "Ranked #4 on Intelligence Index but widely considered the best for complex coding, tool use, and agentic tasks. The 'vibe' leader." },
              { domain: "Reasoning & Math", leader: "o3 / GPT-5.1 Codex", note: "OpenAI's reasoning models excel at competition math, logic puzzles, and multi-step problem solving." },
              { domain: "Long Context", leader: "Gemini 3 Pro/Flash", note: "1M+ token context. Best for analysing large codebases, long documents, or entire repos." },
              { domain: "Speed & Cost", leader: "MiMo-V2-Flash / DeepSeek V3.2", note: "Open models at fraction of the cost. MiMo at $0.15/1M, DeepSeek at $0.32/1M tokens." },
              { domain: "Real-time Data", leader: "Grok 4", note: "xAI's model with live X/Twitter integration. 2M context on Grok 4.1 Fast." },
              { domain: "Enterprise/EU", leader: "Claude 4.5 Sonnet", note: "Balance of capability, safety, and compliance. 1M context at $6/1M tokens." },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.domain}>
                <Box>
                  <Typography variant="caption" sx={{ fontWeight: 700, color: "#d97706", display: "block" }}>{item.domain}</Typography>
                  <Typography variant="caption" sx={{ fontWeight: 600, display: "block" }}>{item.leader}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.6rem" }}>{item.note}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        <Paper sx={{ p: 2, mb: 4, borderRadius: 3, overflow: "auto" }}>
          <Box sx={{ minWidth: 900 }}>
            <Grid container sx={{ bgcolor: alpha("#6366f1", 0.1), p: 1, borderRadius: 1, mb: 1 }}>
              <Grid item xs={2}><Typography variant="caption" sx={{ fontWeight: 700 }}>Model</Typography></Grid>
              <Grid item xs={1.1}><Typography variant="caption" sx={{ fontWeight: 700 }}>Provider</Typography></Grid>
              <Grid item xs={0.8}><Typography variant="caption" sx={{ fontWeight: 700 }}>Context</Typography></Grid>
              <Grid item xs={0.9}><Typography variant="caption" sx={{ fontWeight: 700 }}>Intel.</Typography></Grid>
              <Grid item xs={1}><Typography variant="caption" sx={{ fontWeight: 700 }}>Price/1M</Typography></Grid>
              <Grid item xs={0.8}><Typography variant="caption" sx={{ fontWeight: 700 }}>Speed</Typography></Grid>
              <Grid item xs={0.8}><Typography variant="caption" sx={{ fontWeight: 700 }}>Latency</Typography></Grid>
              <Grid item xs={2.1}><Typography variant="caption" sx={{ fontWeight: 700 }}>Domain Strength</Typography></Grid>
              <Grid item xs={0.7}><Typography variant="caption" sx={{ fontWeight: 700 }}>Open?</Typography></Grid>
            </Grid>
            {[
              { model: "Gemini 3 Pro Preview", provider: "Google", context: "1M", intelligence: 73, price: "$4.50", speed: "129", latency: "32.6s", domain: "Long context, multimodal", open: "No" },
              { model: "GPT-5.2 (xhigh)", provider: "OpenAI", context: "400K", intelligence: 73, price: "$4.81", speed: "101", latency: "33.4s", domain: "General frontier", open: "No" },
              { model: "Gemini 3 Flash", provider: "Google", context: "1M", intelligence: 71, price: "$1.13", speed: "219", latency: "11.9s", domain: "Fast + long context", open: "No" },
              { model: "Claude Opus 4.5", provider: "Anthropic", context: "200K", intelligence: 70, price: "$10.00", speed: "57", latency: "1.7s", domain: "🏆 CODING & AGENTS", open: "No" },
              { model: "GPT-5.1 (high)", provider: "OpenAI", context: "400K", intelligence: 70, price: "$3.44", speed: "182", latency: "22.8s", domain: "General, balanced", open: "No" },
              { model: "GLM-4.7", provider: "Zhipu AI", context: "200K", intelligence: 68, price: "$0.88", speed: "95", latency: "0.75s", domain: "Chinese, low latency", open: "No" },
              { model: "Kimi K2 Thinking", provider: "Kimi", context: "256K", intelligence: 67, price: "$1.07", speed: "100", latency: "0.64s", domain: "Reasoning, ultra-fast", open: "No" },
              { model: "GPT-5.1 Codex (high)", provider: "OpenAI", context: "400K", intelligence: 67, price: "$3.44", speed: "246", latency: "10.0s", domain: "Code generation", open: "No" },
              { model: "MiMo-V2-Flash", provider: "Xiaomi", context: "256K", intelligence: 66, price: "$0.15", speed: "134", latency: "2.0s", domain: "🏆 ULTRA BUDGET", open: "Yes" },
              { model: "DeepSeek V3.2", provider: "DeepSeek", context: "128K", intelligence: 66, price: "$0.32", speed: "30", latency: "1.3s", domain: "Open, affordable", open: "Yes" },
              { model: "o3", provider: "OpenAI", context: "200K", intelligence: 65, price: "$3.50", speed: "331", latency: "9.2s", domain: "🏆 HARD REASONING", open: "No" },
              { model: "Grok 4", provider: "xAI", context: "256K", intelligence: 65, price: "$6.00", speed: "45", latency: "7.3s", domain: "Real-time X data", open: "No" },
              { model: "Gemini 3 Pro (low)", provider: "Google", context: "1M", intelligence: 65, price: "$4.50", speed: "131", latency: "4.1s", domain: "Cost-effective Pro", open: "No" },
              { model: "GPT-5 mini (high)", provider: "OpenAI", context: "400K", intelligence: 64, price: "$0.69", speed: "67", latency: "110.8s", domain: "Budget GPT-5", open: "No" },
              { model: "Grok 4.1 Fast", provider: "xAI", context: "2M", intelligence: 64, price: "$0.28", speed: "146", latency: "5.1s", domain: "🏆 2M CONTEXT", open: "No" },
              { model: "MiniMax-M2.1", provider: "MiniMax", context: "205K", intelligence: 64, price: "$0.53", speed: "84", latency: "1.5s", domain: "Chinese, balanced", open: "No" },
              { model: "KAT-Coder-Pro V1", provider: "KwaiKAT", context: "256K", intelligence: 64, price: "FREE", speed: "65", latency: "1.0s", domain: "Free code model", open: "Yes" },
              { model: "Claude 4.5 Sonnet", provider: "Anthropic", context: "1M", intelligence: 63, price: "$6.00", speed: "63", latency: "1.9s", domain: "Enterprise, safe", open: "No" },
              { model: "Nova 2.0 Pro Preview", provider: "Amazon", context: "256K", intelligence: 62, price: "$3.44", speed: "132", latency: "21.7s", domain: "AWS ecosystem", open: "No" },
              { model: "GPT-5.1 Codex mini", provider: "OpenAI", context: "400K", intelligence: 62, price: "$0.69", speed: "158", latency: "7.9s", domain: "Budget code", open: "No" },
              { model: "gpt-o55-120B", provider: "OpenAI", context: "131K", intelligence: 61, price: "$0.26", speed: "342", latency: "0.41s", domain: "🏆 FASTEST", open: "No" },
              { model: "Grok 4 Fast", provider: "xAI", context: "2M", intelligence: 60, price: "$0.28", speed: "182", latency: "5.0s", domain: "Fast + huge context", open: "No" },
            ].map((item) => (
              <Grid container key={item.model} sx={{ p: 0.8, borderBottom: `1px solid ${alpha("#000", 0.05)}`, "&:hover": { bgcolor: alpha("#6366f1", 0.03) } }}>
                <Grid item xs={2}><Typography variant="caption" sx={{ fontWeight: 600, fontSize: "0.7rem" }}>{item.model}</Typography></Grid>
                <Grid item xs={1.1}><Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.65rem" }}>{item.provider}</Typography></Grid>
                <Grid item xs={0.8}><Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.65rem" }}>{item.context}</Typography></Grid>
                <Grid item xs={0.9}>
                  <Chip 
                    label={item.intelligence} 
                    size="small" 
                    sx={{ 
                      fontSize: "0.55rem", 
                      height: 16, 
                      fontWeight: 700,
                      bgcolor: item.intelligence >= 70 ? alpha("#22c55e", 0.2) : item.intelligence >= 65 ? alpha("#3b82f6", 0.15) : alpha("#f59e0b", 0.15),
                      color: item.intelligence >= 70 ? "#16a34a" : item.intelligence >= 65 ? "#2563eb" : "#d97706"
                    }} 
                  />
                </Grid>
                <Grid item xs={1}><Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.65rem" }}>{item.price}</Typography></Grid>
                <Grid item xs={0.8}><Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.6rem" }}>{item.speed} t/s</Typography></Grid>
                <Grid item xs={0.8}><Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.6rem" }}>{item.latency}</Typography></Grid>
                <Grid item xs={2.1}>
                  <Typography 
                    variant="caption" 
                    sx={{ 
                      fontSize: "0.58rem", 
                      fontWeight: item.domain.includes("🏆") ? 700 : 400,
                      color: item.domain.includes("🏆") ? "#d97706" : "text.secondary"
                    }}
                  >
                    {item.domain}
                  </Typography>
                </Grid>
                <Grid item xs={0.7}><Chip label={item.open} size="small" sx={{ fontSize: "0.45rem", height: 14, bgcolor: item.open === "Yes" ? alpha("#22c55e", 0.2) : alpha("#ef4444", 0.1) }} /></Grid>
              </Grid>
            ))}
          </Box>
          <Box sx={{ mt: 2, p: 1.5, bgcolor: alpha("#6366f1", 0.05), borderRadius: 1 }}>
            <Typography variant="caption" color="text.secondary">
              <strong>Intelligence:</strong> Artificial Analysis composite score • 
              <strong> Price:</strong> Blended USD/1M tokens • 
              <strong> Speed:</strong> Median tok/s • 
              <strong> Latency:</strong> Time to first chunk •
              <strong> 🏆:</strong> Domain leader
            </Typography>
          </Box>
        </Paper>

        {/* Local LLMs & Self-Hosting */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🏠 Local LLMs & Self-Hosting</Typography>
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#10b981", 0.03), border: `1px solid ${alpha("#10b981", 0.15)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            Run <strong>open-weight models locally</strong> for privacy, cost savings, customisation, and offline use. 
            Modern quantisation techniques (GGUF, AWQ, GPTQ) enable running 70B+ models on consumer hardware.
          </Typography>
          
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#10b981", 0.05) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>🔧 Local LLM Infrastructure</Typography>
                <List dense>
                  {[
                    { tool: "Ollama", desc: "One-line install. Pull models like Docker images. REST API. Best for beginners.", url: "ollama.ai" },
                    { tool: "LM Studio", desc: "GUI app. Browse/download models. Chat interface. GGUF format.", url: "lmstudio.ai" },
                    { tool: "llama.cpp", desc: "C++ inference. Maximum performance. CLI and server modes.", url: "github" },
                    { tool: "vLLM", desc: "High-throughput serving. PagedAttention. Production deployments.", url: "vllm.ai" },
                    { tool: "text-generation-webui", desc: "Full-featured web UI. Multiple backends. Extensions.", url: "oobabooga" },
                    { tool: "LocalAI", desc: "OpenAI-compatible API. Drop-in replacement. Docker-based.", url: "localai.io" },
                  ].map((item) => (
                    <ListItem key={item.tool} sx={{ py: 0.3, px: 0 }}>
                      <ListItemText 
                        primary={item.tool}
                        secondary={item.desc}
                        primaryTypographyProps={{ variant: "caption", fontWeight: 600 }}
                        secondaryTypographyProps={{ variant: "caption", fontSize: "0.65rem" }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>🖥️ Open WebUI</Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1.5 }}>
                  ChatGPT-like interface for local models. Feature-rich, extensible, Docker-based.
                </Typography>
                <List dense>
                  {[
                    "Multi-model support (Ollama, OpenAI, etc.)",
                    "RAG with document upload",
                    "Web search integration",
                    "User management & auth",
                    "Custom model presets",
                    "Voice input/output",
                    "Image generation (SD)",
                    "Plugin/function system",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 16 }}>
                        <CheckCircleIcon sx={{ fontSize: 10, color: "#3b82f6" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "caption", fontSize: "0.65rem" }} />
                    </ListItem>
                  ))}
                </List>
                <Box sx={{ mt: 1, p: 1, bgcolor: alpha("#3b82f6", 0.1), borderRadius: 1, fontFamily: "monospace" }}>
                  <Typography variant="caption" sx={{ fontSize: "0.6rem" }}>
                    docker run -d -p 3000:8080 --add-host=host.docker.internal:host-gateway -v open-webui:/app/backend/data --name open-webui ghcr.io/open-webui/open-webui:main
                  </Typography>
                </Box>
              </Paper>
            </Grid>
          </Grid>

          <Box sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.08), borderRadius: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>💻 Hardware Requirements (Rough Guide)</Typography>
            <Grid container spacing={2}>
              {[
                { size: "7B (Q4)", ram: "8GB+ VRAM", hw: "RTX 3060 12GB, M1 Mac 16GB", speed: "~30 tok/s" },
                { size: "13B (Q4)", ram: "12GB+ VRAM", hw: "RTX 3080/4070, M2 Pro 32GB", speed: "~20 tok/s" },
                { size: "34B (Q4)", ram: "24GB+ VRAM", hw: "RTX 4090, M2 Max 64GB", speed: "~15 tok/s" },
                { size: "70B (Q4)", ram: "48GB+ VRAM", hw: "2x RTX 4090, M3 Max 128GB", speed: "~8 tok/s" },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={3} key={item.size}>
                  <Typography variant="caption" sx={{ fontWeight: 700, display: "block" }}>{item.size}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block", fontSize: "0.6rem" }}>{item.ram}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block", fontSize: "0.6rem" }}>{item.hw}</Typography>
                  <Typography variant="caption" sx={{ color: "#10b981", fontSize: "0.6rem" }}>{item.speed}</Typography>
                </Grid>
              ))}
            </Grid>
          </Box>
        </Paper>

        {/* n8n Workflow Automation */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>⚡ n8n: AI Workflow Automation</Typography>
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#ff6d5a", 0.03), border: `1px solid ${alpha("#ff6d5a", 0.15)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>n8n</strong> is an open-source workflow automation platform with powerful AI capabilities. Build 
            complex LLM pipelines visually — connect models, tools, databases, and APIs without code.
          </Typography>
          
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ff6d5a", 0.05) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ff6d5a", mb: 1 }}>🤖 AI Features in n8n</Typography>
                <List dense>
                  {[
                    "AI Agent node — ReAct-style tool use",
                    "RAG with vector stores (Pinecone, Qdrant, etc.)",
                    "LLM nodes for OpenAI, Anthropic, Ollama, etc.",
                    "Document loaders (PDF, CSV, web scraping)",
                    "Memory for multi-turn conversations",
                    "Chain nodes for complex pipelines",
                    "Code execution for custom logic",
                    "400+ integrations (Slack, Gmail, DB, APIs)",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 16 }}>
                        <CheckCircleIcon sx={{ fontSize: 10, color: "#ff6d5a" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "caption", fontSize: "0.65rem" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>🛠️ Example Use Cases</Typography>
                <List dense>
                  {[
                    { use: "Email Assistant", desc: "Auto-categorise, draft responses, extract action items" },
                    { use: "Content Pipeline", desc: "Research → Write → Edit → Post to CMS/social" },
                    { use: "Support Bot", desc: "RAG over docs, escalate to human, log tickets" },
                    { use: "Data Enrichment", desc: "Scrape → Extract → Validate → Store" },
                    { use: "Code Review", desc: "PR webhook → AI review → Post comments" },
                  ].map((item) => (
                    <ListItem key={item.use} sx={{ py: 0.3, px: 0 }}>
                      <ListItemText 
                        primary={item.use}
                        secondary={item.desc}
                        primaryTypographyProps={{ variant: "caption", fontWeight: 600 }}
                        secondaryTypographyProps={{ variant: "caption", fontSize: "0.65rem" }}
                      />
                    </ListItem>
                  ))}
                </List>
                <Box sx={{ mt: 1, p: 1, bgcolor: alpha("#8b5cf6", 0.1), borderRadius: 1, fontFamily: "monospace" }}>
                  <Typography variant="caption" sx={{ fontSize: "0.6rem" }}>
                    docker run -it --rm -p 5678:5678 -v n8n_data:/home/node/.n8n n8nio/n8n
                  </Typography>
                </Box>
              </Paper>
            </Grid>
          </Grid>
        </Paper>

        {/* MCP (Model Context Protocol) */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🔌 MCP: Model Context Protocol</Typography>
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#06b6d4", 0.03), border: `1px solid ${alpha("#06b6d4", 0.15)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>MCP (Model Context Protocol)</strong> is an open standard for connecting AI models to external 
            tools and data sources. Developed by Anthropic, it standardises how LLMs interact with the world — 
            like USB-C for AI tools.
          </Typography>
          
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.05), height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>🎯 What MCP Provides</Typography>
                <List dense>
                  {[
                    "Standardised tool definitions",
                    "Resources (files, DB, APIs)",
                    "Prompts (reusable templates)",
                    "Two-way communication",
                    "Local & remote servers",
                    "Security boundaries",
                  ].map((item) => (
                    <ListItem key={item} sx={{ py: 0, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 16 }}>
                        <CheckCircleIcon sx={{ fontSize: 10, color: "#06b6d4" }} />
                      </ListItemIcon>
                      <ListItemText primary={item} primaryTypographyProps={{ variant: "caption", fontSize: "0.65rem" }} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>🧩 MCP Servers (Examples)</Typography>
                <List dense>
                  {[
                    { name: "Filesystem", desc: "Read/write local files" },
                    { name: "GitHub", desc: "PRs, issues, code search" },
                    { name: "Postgres/SQLite", desc: "Query databases" },
                    { name: "Brave Search", desc: "Web search" },
                    { name: "Puppeteer", desc: "Browser automation" },
                    { name: "Slack", desc: "Messages, channels" },
                  ].map((item) => (
                    <ListItem key={item.name} sx={{ py: 0.2, px: 0 }}>
                      <ListItemText 
                        primary={item.name}
                        secondary={item.desc}
                        primaryTypographyProps={{ variant: "caption", fontWeight: 600, fontSize: "0.65rem" }}
                        secondaryTypographyProps={{ variant: "caption", fontSize: "0.6rem" }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>💡 Supported Clients</Typography>
                <List dense>
                  {[
                    { client: "Claude Desktop", status: "Native support" },
                    { client: "VS Code (Copilot)", status: "Via extension" },
                    { client: "Cursor", status: "Native support" },
                    { client: "Cline", status: "Native support" },
                    { client: "Continue.dev", status: "Native support" },
                    { client: "Zed", status: "Native support" },
                  ].map((item) => (
                    <ListItem key={item.client} sx={{ py: 0.2, px: 0 }}>
                      <ListItemText 
                        primary={item.client}
                        secondary={item.status}
                        primaryTypographyProps={{ variant: "caption", fontWeight: 600, fontSize: "0.65rem" }}
                        secondaryTypographyProps={{ variant: "caption", fontSize: "0.6rem" }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Box sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.08), borderRadius: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>🔧 MCP vs Function Calling</Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <Typography variant="caption" sx={{ fontWeight: 600, color: "#06b6d4", display: "block" }}>MCP</Typography>
                <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.65rem" }}>
                  Open standard • Reusable across clients • Persistent servers • Rich resource model • 
                  Two-way communication • Growing ecosystem
                </Typography>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Typography variant="caption" sx={{ fontWeight: 600, color: "#a855f7", display: "block" }}>Function Calling</Typography>
                <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.65rem" }}>
                  Provider-specific • Per-request definitions • One-shot execution • Simpler mental model • 
                  Wider LLM support • More mature
                </Typography>
              </Grid>
            </Grid>
          </Box>
        </Paper>

        {/* Agentic AI Patterns */}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>🤖 Agentic AI & Advanced Patterns</Typography>
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#a855f7", 0.03), border: `1px solid ${alpha("#a855f7", 0.15)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.9, fontSize: "1.05rem", mb: 3 }}>
            <strong>AI Agents</strong> combine LLMs with planning, memory, and tool use to autonomously accomplish 
            complex tasks. From simple ReAct loops to multi-agent systems, agentic AI is the frontier of practical AI.
          </Typography>
          
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { pattern: "ReAct", desc: "Reason + Act interleaved. Think → Tool → Observe → Think. Foundation of most agents.", color: "#ef4444" },
              { pattern: "Plan-and-Execute", desc: "Create full plan first, then execute steps. Better for complex multi-step tasks.", color: "#f59e0b" },
              { pattern: "Reflection", desc: "Agent critiques own output, improves iteratively. Self-debugging code agents.", color: "#22c55e" },
              { pattern: "Multi-Agent", desc: "Specialised agents collaborate. Researcher + Writer + Critic. CrewAI, AutoGen.", color: "#3b82f6" },
              { pattern: "Hierarchical", desc: "Manager agent delegates to worker agents. Complex project decomposition.", color: "#8b5cf6" },
              { pattern: "Tool-Use", desc: "LLM decides when/how to call functions. Code execution, search, APIs.", color: "#ec4899" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.pattern}>
                <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha(item.color, 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>{item.pattern}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.65rem" }}>{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#6366f1", 0.05) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#6366f1", mb: 1 }}>🛠️ Agent Frameworks</Typography>
                <List dense>
                  {[
                    { name: "LangChain/LangGraph", desc: "Most popular. Graph-based workflows. Extensive integrations." },
                    { name: "LlamaIndex", desc: "RAG-focused. Data connectors. Query engines." },
                    { name: "AutoGen", desc: "Microsoft. Multi-agent conversations. Code execution." },
                    { name: "CrewAI", desc: "Role-based agents. Simple multi-agent setup." },
                    { name: "Semantic Kernel", desc: "Microsoft. Enterprise-focused. .NET/Python." },
                    { name: "Haystack", desc: "deepset. Production RAG. Pipeline architecture." },
                  ].map((item) => (
                    <ListItem key={item.name} sx={{ py: 0.2, px: 0 }}>
                      <ListItemText 
                        primary={item.name}
                        secondary={item.desc}
                        primaryTypographyProps={{ variant: "caption", fontWeight: 600 }}
                        secondaryTypographyProps={{ variant: "caption", fontSize: "0.6rem" }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#10b981", 0.05) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#10b981", mb: 1 }}>🧠 Memory & State</Typography>
                <List dense>
                  {[
                    { type: "Short-term (Context)", desc: "Conversation history in prompt. Limited by context window." },
                    { type: "Working Memory", desc: "Scratchpad for current task. Plans, intermediate results." },
                    { type: "Long-term (Vector DB)", desc: "Persistent knowledge. RAG retrieval. Embeddings." },
                    { type: "Episodic", desc: "Past interactions. Learn from experience. Personalisation." },
                    { type: "Procedural", desc: "Learned skills. Successful tool sequences. Cached strategies." },
                  ].map((item) => (
                    <ListItem key={item.type} sx={{ py: 0.2, px: 0 }}>
                      <ListItemText 
                        primary={item.type}
                        secondary={item.desc}
                        primaryTypographyProps={{ variant: "caption", fontWeight: 600 }}
                        secondaryTypographyProps={{ variant: "caption", fontSize: "0.6rem" }}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Box sx={{ p: 2, bgcolor: alpha("#ef4444", 0.08), borderRadius: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>⚠️ Agent Challenges</Typography>
            <Grid container spacing={2}>
              {[
                { issue: "Reliability", desc: "Agents fail silently, loop infinitely, or hallucinate tool calls." },
                { issue: "Cost", desc: "Multi-step reasoning uses many tokens. Can be 10-100x single call." },
                { issue: "Latency", desc: "Sequential tool calls add up. User waits for each step." },
                { issue: "Debugging", desc: "Complex traces hard to follow. Non-deterministic behaviour." },
                { issue: "Security", desc: "Tool access = attack surface. Prompt injection risks." },
                { issue: "Evaluation", desc: "Hard to measure. Success criteria often fuzzy." },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.issue}>
                  <Typography variant="caption" sx={{ fontWeight: 600, display: "block" }}>{item.issue}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.6rem" }}>{item.desc}</Typography>
                </Grid>
              ))}
            </Grid>
          </Box>
        </Paper>

        {/* ==================== SECTION 10: COMPUTER VISION ==================== */}
        <Typography id="computer-vision" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 180 }}>
          👁️ Computer Vision
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Teaching machines to see and understand visual information
        </Typography>
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Seeing is Not Understanding
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          Vision models are powerful pattern recognizers, but they can still fail under distribution shift,
          lighting changes, or adversarial inputs. Real-world deployment requires careful validation with
          data that matches the target environment.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          In security and safety contexts, false positives and false negatives have real costs. That makes
          robust evaluation, calibrated confidence scores, and human oversight essential.
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

        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Vision Theory Essentials</Typography>
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha("#0ea5e9", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>🧠 Inductive Biases</Typography>
              <List dense>
                {[
                  "Locality + shared weights (convolutions)",
                  "Receptive field grows with depth and stride",
                  "Translation equivariance; pooling adds invariance",
                  "Multi-scale features (FPN, pyramids)",
                  "Positional encoding for ViT patches",
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
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>📐 Objectives & Losses</Typography>
              <List dense>
                {[
                  "Cross-entropy for classification",
                  "Focal loss for class imbalance",
                  "IoU/GIoU/DIoU for box regression",
                  "Dice or IoU loss for segmentation",
                  "Contrastive/self-supervised losses (SimCLR, DINO)",
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
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>🧪 Evaluation & Robustness</Typography>
              <List dense>
                {[
                  "mAP for detection, mIoU for segmentation",
                  "Calibration and confidence thresholds",
                  "NMS or Soft-NMS to merge overlaps",
                  "Augmentations: crop, flip, color jitter, mixup",
                  "Domain shift tests: lighting, occlusion, blur",
                ].map((item) => (
                  <ListItem key={item} sx={{ py: 0.1, px: 0 }}>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "caption" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>

        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Open Source Vision Models</Typography>
        <Grid container spacing={2} sx={{ mb: 5 }}>
          {[
            {
              title: "Backbone Networks",
              desc: "Feature extractors for most CV pipelines",
              models: "ResNet, EfficientNet, ConvNeXt, MobileNet, ViT, Swin",
              color: "#0ea5e9",
            },
            {
              title: "Detection Models",
              desc: "Bounding boxes + classes at scale",
              models: "Faster R-CNN, RetinaNet, YOLOv5/YOLOv8, DETR, Deformable DETR",
              color: "#22c55e",
            },
            {
              title: "Segmentation Models",
              desc: "Pixel-accurate scene understanding",
              models: "U-Net, Mask R-CNN, DeepLabv3+, SegFormer, Segment Anything (SAM)",
              color: "#f59e0b",
            },
            {
              title: "Foundation & Self-Supervised",
              desc: "General-purpose representations",
              models: "DINOv2, MAE, MoCo, CLIP, BLIP-2",
              color: "#8b5cf6",
            },
            {
              title: "Pose, Tracking, OCR",
              desc: "Keypoints, motion, and text extraction",
              models: "OpenPose, MediaPipe BlazePose/Hands, ByteTrack, Tesseract, PaddleOCR",
              color: "#ec4899",
            },
            {
              title: "Video Understanding",
              desc: "Temporal reasoning in video streams",
              models: "SlowFast, TimeSformer, VideoMAE, X3D",
              color: "#06b6d4",
            },
          ].map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.title}>
              <Paper sx={{ p: 2.5, borderRadius: 2, height: "100%", border: `1px solid ${alpha(item.color, 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>{item.title}</Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                  {item.desc}
                </Typography>
                <Typography variant="caption" sx={{ fontWeight: 600, display: "block" }}>Examples</Typography>
                <Typography variant="caption" color="text.secondary">{item.models}</Typography>
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Audio is Temporal and Contextual
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          Speech systems must handle accents, background noise, overlapping speakers, and domain-specific
          vocabulary. Success often depends on careful dataset selection and post-processing, not just model size.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          In regulated environments, audio data raises privacy concerns. Consent, retention policies, and
          secure storage are as important as recognition accuracy.
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Creativity Meets Risk
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          Generative models can compress expertise into accessible tools, but they also raise issues like
          attribution, originality, and misuse. Organizations need clear policies on acceptable use and
          human review for sensitive outputs.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          Quality control is critical. Generative systems are probabilistic and can produce confident errors,
          so outputs should be validated when used for decisions, security, or public-facing content.
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Beyond Accuracy
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          Good evaluation aligns metrics to real-world risk. In security, a small increase in false positives can
          overwhelm analysts, while a small increase in false negatives can create blind spots. Testing should
          reflect operational constraints, not just benchmark scores.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          Reliable systems also require robustness checks: stress tests, adversarial inputs, and drift monitoring.
          If a model fails quietly, the downstream impact can be larger than a traditional software bug.
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Production is a Different World
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          Deployment introduces latency, cost, and reliability constraints that rarely appear in research. A model
          that is accurate but slow can fail a product requirement. MLOps is about making trade-offs explicit and
          keeping them measurable over time.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          The most successful teams treat ML systems as continuously evolving products. Monitoring, retraining,
          and versioned rollouts are core practices, not optional extras.
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Choosing the Right Stack
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          Platform choices influence speed, cost, and compliance. Managed platforms simplify operations but can
          limit flexibility, while self-hosted stacks require more expertise and maintenance.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          For security teams, infrastructure decisions also affect threat models. Data residency, access controls,
          and auditability should be considered alongside performance and budget.
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Security Starts at Design
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          AI security is not an add-on. It requires threat modeling, data governance, access control, and
          monitoring across the entire lifecycle. Decisions made in data collection or model hosting can
          create long-lived security risks.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          Treat models as production services with unique failure modes. Build guardrails, validate inputs,
          and assume adversarial pressure when models are exposed to untrusted users or data sources.
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Augmentation, Not Replacement
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          The most effective defensive systems use AI to triage, summarize, and correlate events while keeping
          humans in control of critical decisions. This improves speed without sacrificing accountability.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          Successful adoption requires clear feedback loops. Analysts should be able to correct false positives,
          report missed detections, and see improvements reflected in model updates.
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Responsible Use and Scope
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          Offensive applications must stay within explicit authorization and scope. The value of AI here is in
          faster analysis, better reporting, and more thorough coverage, not in bypassing safeguards.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          Keep outputs reviewable and auditable. Human oversight is essential to ensure safe execution and to
          translate AI findings into actionable defensive improvements.
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Security by Default
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          AI can lower the barrier to secure coding, but only if its guidance is contextual and verified. The best
          outcomes happen when AI suggestions are paired with secure defaults, code review standards, and clear
          ownership of risk.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          Treat AI as a collaborator rather than an authority. Encourage developers to inspect, test, and explain
          changes before merging, especially when security is involved.
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          Governance is Operational
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          Ethics becomes real when it is embedded into process: review gates, documented decisions, and measurable
          accountability. Governance is not just policy language; it is how teams build, test, and ship AI systems.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          Mature governance helps teams avoid reputational harm and compliance risk. It also improves trust with
          users and stakeholders by making trade-offs transparent and auditable.
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
        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
          From Skills to Impact
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 2 }}>
          AI work is collaborative. It requires clear communication, alignment on goals, and the ability to
          explain model behavior to non-technical stakeholders. The ability to translate between technical and
          business language is a career accelerator.
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8, mb: 3 }}>
          Focus on outcomes and evidence. Demonstrate how your work improves reliability, reduces risk, or
          accelerates decision making, and document those results in a way others can verify.
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

        {/* Quiz Section */}
        <Box id="quiz" sx={{ mt: 5 }}>
          <QuizSection
            questions={quizPool}
            accentColor={ACCENT_COLOR}
            title="Artificial Intelligence Knowledge Check"
            description="Random 10-question quiz drawn from a 75-question bank each time the page loads."
            questionsPerQuiz={QUIZ_QUESTION_COUNT}
          />
        </Box>

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
      </Box>
    </LearnPageLayout>
  );
}
