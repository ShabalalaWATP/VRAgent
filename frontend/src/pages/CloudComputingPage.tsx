import React from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Container,
  Typography,
  Paper,
  Grid,
  Chip,
  alpha,
  useTheme,
  Divider,
  Button,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from "@mui/material";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import CloudIcon from "@mui/icons-material/Cloud";
import CloudQueueIcon from "@mui/icons-material/CloudQueue";
import StorageIcon from "@mui/icons-material/Storage";
import SecurityIcon from "@mui/icons-material/Security";
import SpeedIcon from "@mui/icons-material/Speed";
import SavingsIcon from "@mui/icons-material/Savings";
import PublicIcon from "@mui/icons-material/Public";
import DevicesIcon from "@mui/icons-material/Devices";
import SettingsIcon from "@mui/icons-material/Settings";
import LockIcon from "@mui/icons-material/Lock";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import CloudDownloadIcon from "@mui/icons-material/CloudDownload";
import DataUsageIcon from "@mui/icons-material/DataUsage";
import BuildIcon from "@mui/icons-material/Build";
import BusinessIcon from "@mui/icons-material/Business";
import HomeIcon from "@mui/icons-material/Home";
import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutline";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import InfoIcon from "@mui/icons-material/Info";
import WarningIcon from "@mui/icons-material/Warning";
import { useNavigate } from "react-router-dom";

// ========== CLOUD SERVICE MODELS ==========
const serviceModels = [
  {
    name: "IaaS",
    fullName: "Infrastructure as a Service",
    description: "Rent virtual machines, storage, and networks. You manage the OS and applications.",
    analogy: "Like renting an empty apartment — you get the space but furnish it yourself",
    examples: "AWS EC2, Azure VMs, Google Compute Engine",
    youManage: "OS, Runtime, Apps, Data",
    providerManages: "Virtualization, Servers, Storage, Networking",
    color: "#3b82f6",
  },
  {
    name: "PaaS",
    fullName: "Platform as a Service",
    description: "Develop and deploy apps without managing infrastructure. Focus on your code.",
    analogy: "Like a furnished apartment — move in and start living, no setup needed",
    examples: "Heroku, Azure App Service, Google App Engine",
    youManage: "Apps, Data",
    providerManages: "OS, Runtime, Virtualization, Servers",
    color: "#8b5cf6",
  },
  {
    name: "SaaS",
    fullName: "Software as a Service",
    description: "Use ready-made applications over the internet. No installation required.",
    analogy: "Like staying at a hotel — everything is done for you, just show up",
    examples: "Gmail, Salesforce, Microsoft 365, Dropbox",
    youManage: "Just your data and settings",
    providerManages: "Everything else",
    color: "#22c55e",
  },
];

// ========== DEPLOYMENT MODELS ==========
const deploymentModels = [
  {
    name: "Public Cloud",
    description: "Resources shared among multiple customers, owned and operated by third-party providers",
    pros: "Cost-effective, scalable, no maintenance",
    cons: "Less control, shared resources, compliance concerns",
    bestFor: "Startups, web apps, development/testing",
    icon: <PublicIcon />,
    color: "#0ea5e9",
  },
  {
    name: "Private Cloud",
    description: "Dedicated infrastructure for a single organization, either on-premises or hosted",
    pros: "Full control, enhanced security, compliance-friendly",
    cons: "Higher costs, requires expertise, less scalable",
    bestFor: "Banks, healthcare, government agencies",
    icon: <LockIcon />,
    color: "#ef4444",
  },
  {
    name: "Hybrid Cloud",
    description: "Combination of public and private clouds, with data and apps moving between them",
    pros: "Flexibility, optimized costs, burst capacity",
    cons: "Complex to manage, integration challenges",
    bestFor: "Enterprises with varying workloads",
    icon: <DevicesIcon />,
    color: "#f59e0b",
  },
  {
    name: "Multi-Cloud",
    description: "Using multiple cloud providers simultaneously to avoid vendor lock-in",
    pros: "No vendor lock-in, best-of-breed services, redundancy",
    cons: "Management complexity, skill requirements",
    bestFor: "Large enterprises, disaster recovery",
    icon: <CloudQueueIcon />,
    color: "#8b5cf6",
  },
];

// ========== MAJOR CLOUD PROVIDERS ==========
const cloudProviders = [
  { name: "AWS", fullName: "Amazon Web Services", marketShare: "~32%", strengths: "Widest service offering, mature ecosystem, largest community", flagship: "EC2, S3, Lambda, RDS", color: "#ff9900" },
  { name: "Azure", fullName: "Microsoft Azure", marketShare: "~23%", strengths: "Enterprise integration, hybrid cloud, Microsoft ecosystem", flagship: "VMs, Blob Storage, Functions, Active Directory", color: "#0078d4" },
  { name: "GCP", fullName: "Google Cloud Platform", marketShare: "~10%", strengths: "Data analytics, ML/AI, Kubernetes (invented it)", flagship: "Compute Engine, BigQuery, GKE, Cloud Functions", color: "#4285f4" },
  { name: "Others", fullName: "IBM, Oracle, Alibaba, etc.", marketShare: "~35%", strengths: "Specialized offerings, regional presence, niche markets", flagship: "Various specialized services", color: "#6b7280" },
];

// ========== CORE CLOUD SERVICES ==========
const coreServices = [
  { category: "Compute", description: "Virtual machines, containers, serverless functions", awsExample: "EC2, Lambda, ECS", azureExample: "VMs, Functions, AKS", gcpExample: "Compute Engine, Cloud Run", icon: <SettingsIcon /> },
  { category: "Storage", description: "Object storage, block storage, file storage, archives", awsExample: "S3, EBS, EFS", azureExample: "Blob, Disk, Files", gcpExample: "Cloud Storage, Persistent Disk", icon: <StorageIcon /> },
  { category: "Database", description: "Managed relational and NoSQL databases", awsExample: "RDS, DynamoDB", azureExample: "SQL Database, Cosmos DB", gcpExample: "Cloud SQL, Firestore", icon: <DataUsageIcon /> },
  { category: "Networking", description: "Virtual networks, load balancers, CDN, DNS", awsExample: "VPC, ELB, CloudFront", azureExample: "VNet, Load Balancer, CDN", gcpExample: "VPC, Cloud Load Balancing", icon: <PublicIcon /> },
  { category: "Security", description: "Identity management, encryption, compliance tools", awsExample: "IAM, KMS, Shield", azureExample: "Active Directory, Key Vault", gcpExample: "IAM, Cloud KMS", icon: <SecurityIcon /> },
];

// ========== CLOUD BENEFITS ==========
const cloudBenefits = [
  { benefit: "Scalability", description: "Scale resources up or down instantly based on demand", icon: <SpeedIcon />, color: "#22c55e" },
  { benefit: "Cost Efficiency", description: "Pay only for what you use, no upfront hardware costs", icon: <SavingsIcon />, color: "#3b82f6" },
  { benefit: "Global Reach", description: "Deploy applications worldwide in minutes", icon: <PublicIcon />, color: "#8b5cf6" },
  { benefit: "Reliability", description: "Built-in redundancy, backups, and disaster recovery", icon: <SecurityIcon />, color: "#f59e0b" },
  { benefit: "Speed & Agility", description: "Provision resources in minutes instead of weeks", icon: <CloudUploadIcon />, color: "#ec4899" },
  { benefit: "Innovation", description: "Access to cutting-edge AI, ML, and analytics services", icon: <TipsAndUpdatesIcon />, color: "#14b8a6" },
];

// ========== SECURITY CONSIDERATIONS ==========
const securityConsiderations = [
  { topic: "Shared Responsibility Model", description: "Cloud provider secures infrastructure; you secure your data and apps", importance: "Critical" },
  { topic: "Identity & Access Management", description: "Control who can access what resources using IAM policies", importance: "Critical" },
  { topic: "Data Encryption", description: "Encrypt data at rest and in transit using provider tools", importance: "High" },
  { topic: "Network Security", description: "Configure security groups, firewalls, and VPCs properly", importance: "High" },
  { topic: "Compliance", description: "Ensure cloud setup meets regulatory requirements (HIPAA, GDPR, etc.)", importance: "High" },
  { topic: "Monitoring & Logging", description: "Track all activities for security auditing and incident response", importance: "High" },
];

// ========== VIRTUALIZATION CONCEPTS ==========
const virtualizationConcepts = [
  { term: "Virtual Machine (VM)", description: "A software-based computer that runs on physical hardware, with its own OS and resources", example: "Running Windows on a Mac using VMware, or EC2 instances on AWS", icon: "🖥️" },
  { term: "Hypervisor", description: "Software that creates and manages VMs by abstracting hardware resources", example: "Type 1: VMware ESXi, Hyper-V | Type 2: VirtualBox, VMware Workstation", icon: "⚙️" },
  { term: "Host vs Guest", description: "Host is the physical machine/OS running the hypervisor; Guest is the VM running on top", example: "Your laptop (host) running a Linux VM (guest)", icon: "🏠" },
  { term: "Snapshot", description: "Point-in-time copy of a VM's state, allowing rollback if something goes wrong", example: "Take snapshot before updates, restore if they break something", icon: "📸" },
  { term: "Live Migration", description: "Moving a running VM between physical hosts without downtime", example: "AWS uses this for maintenance without affecting your instances", icon: "🔄" },
  { term: "Resource Pooling", description: "Combining physical resources from multiple servers into shared pools", example: "100 physical servers pooled to create thousands of VMs", icon: "🎱" },
];

// ========== CONTAINER CONCEPTS ==========
const containerConcepts = [
  { term: "Container", description: "Lightweight, standalone package containing code and all dependencies to run an application", difference: "Shares host OS kernel, unlike VMs which have their own OS", icon: "📦" },
  { term: "Docker", description: "Most popular containerization platform for building, shipping, and running containers", usage: "docker run, docker build, Dockerfile, Docker Hub", icon: "🐳" },
  { term: "Container Image", description: "Read-only template with instructions for creating a container", analogy: "Like a recipe — the image is the recipe, the container is the cooked meal", icon: "📋" },
  { term: "Container Registry", description: "Repository for storing and distributing container images", examples: "Docker Hub, AWS ECR, Azure ACR, Google GCR", icon: "🗄️" },
  { term: "Kubernetes (K8s)", description: "Open-source platform for automating deployment, scaling, and management of containerized apps", features: "Self-healing, load balancing, rolling updates, secret management", icon: "☸️" },
  { term: "Pod", description: "Smallest deployable unit in Kubernetes, containing one or more containers", purpose: "Containers in a pod share network and storage, scheduled together", icon: "🫛" },
];

// ========== SERVERLESS CONCEPTS ==========
const serverlessConcepts = [
  { name: "Function as a Service (FaaS)", description: "Run code without managing servers — just upload your function and it runs when triggered", examples: "AWS Lambda, Azure Functions, Google Cloud Functions", pricing: "Pay per execution (often free tier includes millions of requests)", color: "#f59e0b" },
  { name: "Event-Driven Architecture", description: "Functions triggered by events: HTTP requests, file uploads, database changes, schedules", examples: "Image uploaded → resize function runs → thumbnail saved", useCase: "Webhooks, data processing, automation", color: "#8b5cf6" },
  { name: "Cold Start", description: "Delay when a function runs for the first time (container initialization)", impact: "Can add 100ms-few seconds latency on first request", mitigation: "Provisioned concurrency, keep-warm pings", color: "#ef4444" },
  { name: "Backend as a Service (BaaS)", description: "Pre-built backend features: authentication, databases, push notifications, file storage", examples: "Firebase, AWS Amplify, Supabase", benefit: "Build apps without writing backend code", color: "#22c55e" },
];

// ========== STORAGE TYPES ==========
const storageTypes = [
  { type: "Object Storage", description: "Store files as objects with metadata, accessed via HTTP/API. Infinitely scalable.", awsService: "S3", azureService: "Blob Storage", gcpService: "Cloud Storage", bestFor: "Images, videos, backups, static websites, data lakes", icon: "🪣" },
  { type: "Block Storage", description: "Raw storage volumes attached to VMs, like virtual hard drives. High performance.", awsService: "EBS", azureService: "Managed Disks", gcpService: "Persistent Disk", bestFor: "Databases, boot volumes, applications requiring low latency", icon: "💾" },
  { type: "File Storage", description: "Managed file systems accessible by multiple instances simultaneously (NFS/SMB).", awsService: "EFS", azureService: "Azure Files", gcpService: "Filestore", bestFor: "Shared file systems, content management, legacy apps", icon: "📁" },
  { type: "Archive Storage", description: "Ultra-low-cost storage for rarely accessed data. Retrieval takes hours.", awsService: "S3 Glacier", azureService: "Archive Storage", gcpService: "Archive Storage", bestFor: "Compliance archives, long-term backups, historical data", icon: "🗃️" },
];

// ========== NETWORKING CONCEPTS ==========
const networkingConcepts = [
  { concept: "VPC (Virtual Private Cloud)", description: "Your own isolated network in the cloud with complete control over IP ranges, subnets, routing", purpose: "Network isolation, security boundaries, hybrid connectivity", icon: "🏰" },
  { concept: "Subnet", description: "Subdivision of a VPC. Public subnets have internet access; private subnets don't", example: "Web servers in public subnet, databases in private subnet", icon: "🔲" },
  { concept: "Security Group", description: "Virtual firewall controlling inbound/outbound traffic at the instance level", example: "Allow port 443 from anywhere, allow port 22 only from your IP", icon: "🛡️" },
  { concept: "Load Balancer", description: "Distributes incoming traffic across multiple instances for high availability", types: "Application LB (HTTP/HTTPS), Network LB (TCP/UDP), Gateway LB", icon: "⚖️" },
  { concept: "CDN (Content Delivery Network)", description: "Global network of edge servers caching content closer to users", benefit: "Faster load times, reduced origin server load, DDoS protection", icon: "🌐" },
  { concept: "VPN/Direct Connect", description: "Secure connection between your on-premises network and cloud VPC", useCase: "Hybrid cloud, secure data transfer, extending corporate network", icon: "🔗" },
];

// ========== PRICING MODELS ==========
const pricingModels = [
  { model: "On-Demand", description: "Pay by the hour or second with no commitment. Most flexible but most expensive.", discount: "0%", bestFor: "Development, testing, unpredictable workloads, short-term projects", color: "#ef4444" },
  { model: "Reserved Instances", description: "Commit to 1-3 years for significant discount. Pay upfront or monthly.", discount: "30-72%", bestFor: "Steady-state workloads, production databases, always-on applications", color: "#22c55e" },
  { model: "Spot/Preemptible", description: "Bid on unused capacity at steep discounts. Can be terminated with 2-min warning.", discount: "60-90%", bestFor: "Batch processing, fault-tolerant workloads, big data, CI/CD", color: "#3b82f6" },
  { model: "Savings Plans", description: "Commit to consistent usage amount ($/hour) across services for discounts.", discount: "20-66%", bestFor: "Flexible commitment, multiple instance types, compute-heavy workloads", color: "#8b5cf6" },
];

// ========== COMMON MISCONFIGURATIONS ==========
const commonMisconfigs = [
  { issue: "Public S3 Buckets", description: "Leaving storage buckets publicly accessible exposes sensitive data", impact: "Data breaches, compliance violations, reputation damage", prevention: "Enable Block Public Access, use bucket policies, audit regularly", severity: "Critical" },
  { issue: "Overly Permissive IAM", description: "Giving users/roles more permissions than needed (violating least privilege)", impact: "Lateral movement, privilege escalation, unauthorized access", prevention: "Use IAM Access Analyzer, implement least privilege, regular reviews", severity: "Critical" },
  { issue: "Unencrypted Data", description: "Storing sensitive data without encryption at rest or in transit", impact: "Data exposure if storage is compromised", prevention: "Enable default encryption, use KMS, enforce HTTPS", severity: "High" },
  { issue: "Open Security Groups", description: "Allowing 0.0.0.0/0 access to sensitive ports (SSH, RDP, databases)", impact: "Brute force attacks, unauthorized access, cryptomining", prevention: "Restrict to specific IPs/ranges, use bastion hosts, VPN", severity: "High" },
  { issue: "Disabled Logging", description: "Not enabling CloudTrail, VPC Flow Logs, or access logging", impact: "No visibility into attacks, unable to investigate incidents", prevention: "Enable all logging, centralize logs, set up alerts", severity: "High" },
  { issue: "Hardcoded Credentials", description: "Storing API keys, passwords in code or environment variables", impact: "Credential theft, account compromise", prevention: "Use secrets managers, IAM roles, rotate credentials", severity: "Critical" },
];

// ========== CLOUD TERMINOLOGY ==========
const cloudTerminology = [
  { term: "Region", definition: "Geographic area containing multiple data centers (Availability Zones)", example: "us-east-1 (N. Virginia), eu-west-1 (Ireland), ap-southeast-1 (Singapore)" },
  { term: "Availability Zone (AZ)", definition: "Isolated data center within a region, connected by low-latency links", example: "us-east-1a, us-east-1b — deploy across AZs for high availability" },
  { term: "Edge Location", definition: "CDN endpoint for caching content closer to users", example: "CloudFront has 400+ edge locations globally" },
  { term: "Elasticity", definition: "Ability to automatically scale resources up/down based on demand", example: "Auto Scaling group adds servers during traffic spikes" },
  { term: "High Availability (HA)", definition: "System design ensuring minimal downtime through redundancy", example: "Multi-AZ database deployments, load-balanced web servers" },
  { term: "Fault Tolerance", definition: "Ability to continue operating despite component failures", example: "If one AZ fails, traffic routes to healthy AZs" },
  { term: "Latency", definition: "Time delay between request and response", example: "Deploy in regions closest to your users to reduce latency" },
  { term: "Throughput", definition: "Amount of data transferred in a given time period", example: "S3 can handle thousands of requests per second" },
  { term: "IOPS", definition: "Input/Output Operations Per Second — measure of storage performance", example: "gp3 EBS volumes offer 3,000 baseline IOPS" },
  { term: "Egress", definition: "Data transfer OUT of the cloud (typically charged)", example: "Downloading from S3 to your computer incurs egress fees" },
];

// ========== DETAILED SERVICE COMPARISON ==========
const detailedServiceComparison = [
  { service: "Compute - VMs", aws: "EC2 (Elastic Compute Cloud)", azure: "Virtual Machines", gcp: "Compute Engine", notes: "All offer similar instance types: general, compute, memory, GPU optimized" },
  { service: "Compute - Containers", aws: "ECS, EKS, Fargate", azure: "AKS, Container Instances", gcp: "GKE, Cloud Run", notes: "GKE considered most mature (Google invented Kubernetes)" },
  { service: "Compute - Serverless", aws: "Lambda", azure: "Functions", gcp: "Cloud Functions, Cloud Run", notes: "Lambda most mature, Cloud Run offers container-based serverless" },
  { service: "Object Storage", aws: "S3", azure: "Blob Storage", gcp: "Cloud Storage", notes: "S3 is industry standard, all offer similar durability (11 9's)" },
  { service: "Block Storage", aws: "EBS", azure: "Managed Disks", gcp: "Persistent Disk", notes: "Attach to VMs like hard drives, various performance tiers" },
  { service: "Relational DB", aws: "RDS, Aurora", azure: "SQL Database, MySQL/PostgreSQL", gcp: "Cloud SQL, AlloyDB", notes: "Aurora/AlloyDB offer enhanced performance for MySQL/PostgreSQL" },
  { service: "NoSQL DB", aws: "DynamoDB", azure: "Cosmos DB", gcp: "Firestore, Bigtable", notes: "Cosmos DB offers multiple APIs (SQL, MongoDB, Cassandra)" },
  { service: "Data Warehouse", aws: "Redshift", azure: "Synapse Analytics", gcp: "BigQuery", notes: "BigQuery pioneered serverless data warehousing" },
  { service: "Message Queue", aws: "SQS, SNS", azure: "Service Bus, Event Grid", gcp: "Pub/Sub, Cloud Tasks", notes: "Decouple services, async processing, event-driven architectures" },
  { service: "CDN", aws: "CloudFront", azure: "CDN, Front Door", gcp: "Cloud CDN", notes: "Global edge caching, DDoS protection, SSL termination" },
  { service: "DNS", aws: "Route 53", azure: "DNS", gcp: "Cloud DNS", notes: "Route 53 offers advanced routing (geo, latency, weighted)" },
  { service: "Identity", aws: "IAM, Cognito", azure: "Azure AD, B2C", gcp: "IAM, Identity Platform", notes: "Azure AD most enterprise-ready with SSO, MFA" },
  { service: "Secrets", aws: "Secrets Manager, Parameter Store", azure: "Key Vault", gcp: "Secret Manager", notes: "Store API keys, passwords, certificates securely" },
  { service: "Monitoring", aws: "CloudWatch", azure: "Monitor, App Insights", gcp: "Cloud Monitoring, Logging", notes: "All offer metrics, logs, alerts, dashboards" },
  { service: "ML/AI", aws: "SageMaker, Bedrock", azure: "Azure ML, OpenAI Service", gcp: "Vertex AI, Gemini", notes: "Azure has exclusive OpenAI partnership" },
];

// ========== IAM CONCEPTS ==========
const iamConcepts = [
  { concept: "User", description: "Human identity with credentials (username/password, access keys)", bestPractice: "Use for humans, enable MFA, avoid sharing", icon: "👤" },
  { concept: "Group", description: "Collection of users that share the same permissions", bestPractice: "Organize users by job function (Admins, Developers, Auditors)", icon: "👥" },
  { concept: "Role", description: "Identity assumed by services, apps, or users temporarily", bestPractice: "Use for services and cross-account access, not long-term credentials", icon: "🎭" },
  { concept: "Policy", description: "JSON document defining what actions are allowed or denied", bestPractice: "Use AWS-managed policies, create custom for specific needs", icon: "📜" },
  { concept: "Least Privilege", description: "Grant only the minimum permissions needed to perform a task", bestPractice: "Start with no permissions, add only what's needed, audit regularly", icon: "🔐" },
  { concept: "MFA", description: "Multi-Factor Authentication adds second verification step", bestPractice: "Require for all humans, especially privileged accounts", icon: "📱" },
  { concept: "Access Keys", description: "Programmatic credentials for CLI/SDK access", bestPractice: "Rotate regularly, use roles instead when possible, never commit to Git", icon: "🔑" },
  { concept: "Service Account", description: "Identity for applications and services to authenticate", bestPractice: "Use managed identities where possible, scope permissions tightly", icon: "🤖" },
];

// ========== CLOUD ARCHITECTURE PATTERNS ==========
const architecturePatterns = [
  { pattern: "Three-Tier Architecture", description: "Presentation (web), Logic (app), Data (database) layers separated", useCases: "Traditional web apps, enterprise applications", pros: "Clear separation, easy to understand, proven pattern", cons: "Can be monolithic, scaling challenges", color: "#3b82f6" },
  { pattern: "Microservices", description: "Small, independent services communicating via APIs", useCases: "Large applications, teams working independently, frequent deployments", pros: "Independent scaling, technology flexibility, fault isolation", cons: "Complexity, distributed system challenges, operational overhead", color: "#8b5cf6" },
  { pattern: "Serverless", description: "Event-driven functions with no server management", useCases: "APIs, data processing, automation, sporadic workloads", pros: "No infrastructure management, pay-per-use, auto-scaling", cons: "Cold starts, vendor lock-in, debugging challenges", color: "#f59e0b" },
  { pattern: "Event-Driven", description: "Components communicate through events/messages asynchronously", useCases: "Real-time processing, IoT, workflow orchestration", pros: "Loose coupling, scalability, resilience", cons: "Eventual consistency, complex debugging, ordering challenges", color: "#22c55e" },
  { pattern: "CQRS", description: "Command Query Responsibility Segregation — separate read/write models", useCases: "High-performance reads, complex domains, event sourcing", pros: "Optimized read/write paths, scalability", cons: "Complexity, eventual consistency", color: "#ef4444" },
  { pattern: "Multi-Region", description: "Deploy across multiple geographic regions for HA and performance", useCases: "Global applications, disaster recovery, low-latency requirements", pros: "High availability, better user experience, regulatory compliance", cons: "Data synchronization, cost, complexity", color: "#14b8a6" },
];

// ========== DEVOPS & CI/CD ==========
const devOpsConcepts = [
  { concept: "Infrastructure as Code (IaC)", description: "Define infrastructure using code files instead of manual setup", tools: "Terraform, CloudFormation, ARM, Pulumi, CDK", benefit: "Version control, reproducibility, automation" },
  { concept: "CI/CD Pipeline", description: "Automated workflow for building, testing, and deploying code", tools: "GitHub Actions, GitLab CI, Jenkins, Azure DevOps", benefit: "Faster releases, fewer errors, consistent deployments" },
  { concept: "GitOps", description: "Git as single source of truth for declarative infrastructure and apps", tools: "ArgoCD, Flux, GitLab", benefit: "Audit trail, rollback capability, collaborative changes" },
  { concept: "Container Orchestration", description: "Automated management of containerized applications at scale", tools: "Kubernetes (EKS/AKS/GKE), Docker Swarm, Nomad", benefit: "Self-healing, scaling, rolling updates" },
  { concept: "Service Mesh", description: "Infrastructure layer for service-to-service communication", tools: "Istio, Linkerd, AWS App Mesh", benefit: "mTLS, observability, traffic management" },
  { concept: "Observability", description: "Ability to understand system state from external outputs", tools: "Prometheus, Grafana, Datadog, New Relic", benefit: "Faster debugging, proactive monitoring, SLO tracking" },
];

// ========== CLI TOOLS ==========
const cliTools = [
  { name: "AWS CLI", command: "aws", example: "aws s3 ls", description: "Official AWS command-line interface for all AWS services", install: "pip install awscli or brew install awscli" },
  { name: "Azure CLI", command: "az", example: "az vm list", description: "Cross-platform CLI for managing Azure resources", install: "pip install azure-cli or brew install azure-cli" },
  { name: "Google Cloud CLI", command: "gcloud", example: "gcloud compute instances list", description: "CLI for GCP with gsutil for storage and bq for BigQuery", install: "Download from cloud.google.com/sdk" },
  { name: "Terraform", command: "terraform", example: "terraform apply", description: "Multi-cloud IaC tool for defining infrastructure", install: "brew install terraform or download binary" },
  { name: "kubectl", command: "kubectl", example: "kubectl get pods", description: "Kubernetes CLI for managing clusters and workloads", install: "Bundled with Docker Desktop or install separately" },
  { name: "Docker", command: "docker", example: "docker run nginx", description: "Container runtime CLI for building and running containers", install: "Docker Desktop or docker-ce package" },
];

// ========== REAL WORLD EXAMPLES ==========
const realWorldExamples = [
  { company: "Netflix", useCase: "Streaming infrastructure", details: "Runs entirely on AWS. Uses thousands of EC2 instances, S3 for content storage, CloudFront CDN for delivery. Pioneered chaos engineering (Chaos Monkey).", services: "EC2, S3, CloudFront, DynamoDB" },
  { company: "Spotify", useCase: "Music streaming platform", details: "Migrated from on-premises to GCP. Uses GKE for container orchestration, BigQuery for analytics, Pub/Sub for event streaming.", services: "GKE, BigQuery, Pub/Sub, Cloud Storage" },
  { company: "Airbnb", useCase: "Hospitality marketplace", details: "Uses AWS for core infrastructure. Developed and open-sourced many tools (Airflow, Superset). Heavy use of EMR for data processing.", services: "EC2, S3, RDS, EMR, Redshift" },
  { company: "Capital One", useCase: "Banking services", details: "All-in on AWS, closed all data centers. First US bank fully in the cloud. Strong focus on security and compliance automation.", services: "EC2, Lambda, DynamoDB, Step Functions" },
  { company: "Coca-Cola", useCase: "Enterprise applications", details: "Uses Azure for SAP workloads, Office 365 integration, and AI initiatives. Hybrid cloud with on-premises connections.", services: "Azure VMs, Azure AD, Cognitive Services" },
];

// ========== CLOUD SECURITY TOOLS ==========
const cloudSecurityTools = [
  { tool: "Cloud Security Posture Management (CSPM)", purpose: "Continuously monitor for misconfigurations and compliance violations", examples: "AWS Security Hub, Azure Defender for Cloud, Prisma Cloud, Wiz", importance: "Critical" },
  { tool: "Cloud Workload Protection (CWPP)", purpose: "Protect workloads (VMs, containers, serverless) from threats", examples: "CrowdStrike, Aqua Security, Lacework", importance: "High" },
  { tool: "Cloud Access Security Broker (CASB)", purpose: "Monitor and control cloud service usage, enforce policies", examples: "Netskope, Microsoft Defender for Cloud Apps, Zscaler", importance: "High" },
  { tool: "Cloud Infrastructure Entitlement Management (CIEM)", purpose: "Manage and audit cloud permissions to prevent excessive access", examples: "Ermetic, CloudKnox (Microsoft), Sonrai", importance: "High" },
  { tool: "Secrets Management", purpose: "Securely store and rotate credentials, API keys, certificates", examples: "HashiCorp Vault, AWS Secrets Manager, Azure Key Vault", importance: "Critical" },
  { tool: "Web Application Firewall (WAF)", purpose: "Protect web applications from common attacks (SQLi, XSS)", examples: "AWS WAF, Azure WAF, Cloudflare WAF", importance: "High" },
];

// ========== OUTLINE SECTIONS (Placeholders for future content) ==========
const outlineSections = [
  { title: "Disaster Recovery Strategies", description: "RPO/RTO, backup strategies, multi-region failover", status: "Coming Soon" },
  { title: "Cloud Cost Optimization", description: "FinOps practices, rightsizing, reserved capacity planning", status: "Coming Soon" },
  { title: "Cloud Certifications Guide", description: "AWS, Azure, and GCP certification paths and study tips", status: "Coming Soon" },
];

const CloudComputingPage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();

  const pageContext = `This page covers cloud computing fundamentals for beginners. Topics include:
- What is cloud computing and why it matters (utility model analogy)
- Cloud service models: IaaS (Infrastructure as a Service), PaaS (Platform as a Service), SaaS (Software as a Service)
- Cloud deployment models: Public, Private, Hybrid, and Multi-cloud
- Major cloud providers: AWS, Azure, GCP and their flagship services
- Core cloud services: Compute, Storage, Database, Networking, Security
- Virtualization fundamentals: VMs, hypervisors, snapshots, live migration
- Containers and Kubernetes: Docker, images, registries, pods, orchestration
- Serverless computing: FaaS, event-driven architecture, cold starts, BaaS
- Cloud storage types: Object, Block, File, Archive storage with provider examples
- Cloud networking: VPCs, subnets, security groups, load balancers, CDN
- Pricing models: On-demand, Reserved, Spot/Preemptible, Savings Plans
- Benefits of cloud computing: Scalability, Cost Efficiency, Global Reach, Reliability
- Cloud security: Shared Responsibility Model, IAM, encryption, compliance
- Common misconfigurations: Public buckets, overly permissive IAM, hardcoded credentials
- Cloud terminology: Regions, AZs, edge locations, elasticity, HA, fault tolerance`;

  return (
    <LearnPageLayout pageTitle="Cloud Computing Fundamentals" pageContext={pageContext}>
      <Container maxWidth="lg" sx={{ py: 4 }}>
        {/* Hero Banner */}
        <Paper
          elevation={0}
          sx={{
            p: 5,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#0ea5e9", 0.15)} 0%, ${alpha("#8b5cf6", 0.15)} 100%)`,
            border: `1px solid ${alpha("#0ea5e9", 0.2)}`,
            position: "relative",
            overflow: "hidden",
          }}
        >
          <Box sx={{ position: "absolute", right: -20, top: -20, opacity: 0.1 }}>
            <CloudIcon sx={{ fontSize: 250, color: "#0ea5e9" }} />
          </Box>
          <Box sx={{ position: "relative", zIndex: 1 }}>
            <Chip label="IT Fundamentals" size="small" sx={{ mb: 1, fontWeight: 600, bgcolor: alpha("#0ea5e9", 0.1), color: "#0ea5e9" }} />
            <Typography variant="h3" sx={{ fontWeight: 800, mb: 2, background: `linear-gradient(135deg, #0ea5e9 0%, #8b5cf6 100%)`, WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
              ☁️ Cloud Computing Fundamentals
            </Typography>
            <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 700 }}>
              Understanding on-demand computing resources, cloud service models, major providers, and how the cloud is transforming IT infrastructure.
            </Typography>
          </Box>
        </Paper>

        {/* Quick Navigation */}
        <Paper
          elevation={0}
          sx={{
            p: 2,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            position: "sticky",
            top: 64,
            zIndex: 100,
            backdropFilter: "blur(10px)",
          }}
        >
          <Typography variant="overline" sx={{ fontWeight: 700, color: "text.secondary", mb: 1, display: "block" }}>
            Quick Navigation
          </Typography>
          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {[
              { label: "Introduction", id: "intro" },
              { label: "Service Models", id: "service-models" },
              { label: "Deployment", id: "deployment" },
              { label: "Providers", id: "providers" },
              { label: "Service Comparison", id: "service-comparison" },
              { label: "Virtualization", id: "virtualization" },
              { label: "Containers", id: "containers" },
              { label: "Serverless", id: "serverless" },
              { label: "Storage", id: "storage" },
              { label: "Networking", id: "networking" },
              { label: "IAM", id: "iam" },
              { label: "Architecture", id: "architecture" },
              { label: "DevOps", id: "devops" },
              { label: "CLI Tools", id: "cli" },
              { label: "Pricing", id: "pricing" },
              { label: "Security", id: "security" },
              { label: "Security Tools", id: "security-tools" },
              { label: "Misconfigs", id: "misconfigs" },
              { label: "Real World", id: "real-world" },
              { label: "Terminology", id: "terminology" },
            ].map((nav) => (
              <Chip
                key={nav.id}
                label={nav.label}
                clickable
                component="a"
                href={`#${nav.id}`}
                size="small"
                sx={{
                  fontWeight: 600,
                  "&:hover": { bgcolor: alpha("#0ea5e9", 0.15), color: "#0ea5e9" },
                }}
              />
            ))}
          </Box>
        </Paper>

        {/* ==================== INTRODUCTION SECTION ==================== */}
        <Paper
          id="intro"
          elevation={0}
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            bgcolor: alpha("#0ea5e9", 0.03),
            border: `1px solid ${alpha("#0ea5e9", 0.1)}`,
            scrollMarginTop: 80,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
            <InfoIcon sx={{ color: "#0ea5e9" }} />
            What is Cloud Computing?
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            <strong>Cloud computing</strong> is like renting a supercomputer over the internet instead of buying one. 
            Imagine you need a car — you could buy one outright (expensive, requires maintenance, sits idle most of the time), 
            or you could use a ride-sharing service where you pay only when you need a ride. Cloud computing works the same way 
            for computer resources like servers, storage, and software.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Instead of companies buying expensive servers, setting them up in air-conditioned rooms, hiring staff to maintain them, 
            and upgrading them every few years, they can simply <strong>"rent" computing power from cloud providers</strong> like 
            Amazon (AWS), Microsoft (Azure), or Google (GCP). These providers have massive data centers around the world with 
            thousands of servers, and they let anyone use a portion of that power over the internet.
          </Typography>

          <Box sx={{ bgcolor: alpha("#0ea5e9", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#0ea5e9", 0.2)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0ea5e9" }}>
              🏠 The "Utility" Analogy
            </Typography>
            <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
              Think about electricity. You don't have a power plant in your backyard — you plug into the electrical grid and pay 
              for what you use. Cloud computing is the same concept for computing power. Need more processing? Just ask for it. 
              Need less? Scale down and stop paying. This is called the <strong>"utility computing"</strong> model, and it's 
              revolutionized how businesses operate.
            </Typography>
          </Box>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, mt: 4 }}>
            Why Does Cloud Computing Matter?
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>
                  🚀 For Startups & Small Business
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Start a global web application with $0 upfront investment. No need to buy servers — just use what you need 
                  and pay as you grow. A startup can now compete with enterprises on technical capabilities.
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>
                  🏢 For Enterprises
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Handle sudden traffic spikes (like Black Friday sales) without buying servers that sit idle the rest of 
                  the year. Deploy globally in minutes. Focus on business, not infrastructure management.
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>
                  👨‍💻 For Developers
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Spin up development environments in seconds. Test on different configurations without buying hardware. 
                  Access powerful AI and machine learning tools without expensive GPUs.
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha("#ec4899", 0.2)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ec4899", mb: 1 }}>
                  🔒 For Security Professionals
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Cloud security is one of the most in-demand skills. Understanding cloud architecture is essential for 
                  penetration testing, compliance auditing, and incident response in modern environments.
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, mt: 4 }}>
            Key Characteristics of Cloud Computing
          </Typography>

          <List>
            {[
              { primary: "On-Demand Self-Service", secondary: "Get computing resources instantly without human interaction — just click and deploy" },
              { primary: "Broad Network Access", secondary: "Access your resources from anywhere with an internet connection — laptop, phone, tablet" },
              { primary: "Resource Pooling", secondary: "Provider's resources serve multiple customers, dynamically assigned based on demand" },
              { primary: "Rapid Elasticity", secondary: "Scale up or down automatically to match your workload — pay only for what you use" },
              { primary: "Measured Service", secondary: "Usage is monitored, controlled, and billed — like a utility meter for computing" },
            ].map((item, index) => (
              <ListItem key={index} sx={{ py: 1 }}>
                <ListItemIcon>
                  <CheckCircleOutlineIcon sx={{ color: "#22c55e" }} />
                </ListItemIcon>
                <ListItemText
                  primary={<Typography sx={{ fontWeight: 600 }}>{item.primary}</Typography>}
                  secondary={item.secondary}
                />
              </ListItem>
            ))}
          </List>

          <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, mt: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b", display: "flex", alignItems: "center", gap: 1 }}>
              <TipsAndUpdatesIcon />
              Before vs. After Cloud Computing
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>❌ Traditional (On-Premises)</Typography>
                <Typography variant="body2" color="text.secondary">
                  Buy servers → Wait weeks for delivery → Set up data center → Hire IT staff → Maintain & upgrade → 
                  Estimate capacity years in advance → Pay regardless of usage
                </Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>✅ Cloud Computing</Typography>
                <Typography variant="body2" color="text.secondary">
                  Sign up → Deploy in minutes → Scale instantly → No maintenance → Pay per use → 
                  Access global infrastructure → Focus on your business
                </Typography>
              </Grid>
            </Grid>
          </Box>
        </Paper>

        {/* ==================== SERVICE MODELS ==================== */}
        <Typography id="service-models" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          📦 Cloud Service Models
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The three main ways cloud services are delivered — each with different levels of control and responsibility
        </Typography>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          {serviceModels.map((model) => (
            <Grid item xs={12} md={4} key={model.name}>
              <Paper
                sx={{
                  p: 3,
                  borderRadius: 3,
                  height: "100%",
                  border: `2px solid ${alpha(model.color, 0.3)}`,
                  bgcolor: alpha(model.color, 0.03),
                }}
              >
                <Chip label={model.name} sx={{ fontWeight: 800, bgcolor: model.color, color: "white", fontSize: "1rem", mb: 2 }} />
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>{model.fullName}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{model.description}</Typography>
                
                <Box sx={{ bgcolor: alpha(model.color, 0.1), p: 2, borderRadius: 2, mb: 2 }}>
                  <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 0.5 }}>💡 Analogy:</Typography>
                  <Typography variant="body2">{model.analogy}</Typography>
                </Box>
                
                <Typography variant="caption" sx={{ display: "block", mb: 0.5 }}>
                  <strong>Examples:</strong> {model.examples}
                </Typography>
                <Typography variant="caption" sx={{ display: "block", mb: 0.5, color: "#22c55e" }}>
                  <strong>You manage:</strong> {model.youManage}
                </Typography>
                <Typography variant="caption" sx={{ display: "block", color: "#3b82f6" }}>
                  <strong>Provider manages:</strong> {model.providerManages}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== DEPLOYMENT MODELS ==================== */}
        <Typography id="deployment" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🏗️ Cloud Deployment Models
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Different ways to deploy cloud infrastructure based on ownership and access
        </Typography>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {deploymentModels.map((model) => (
            <Grid item xs={12} sm={6} key={model.name}>
              <Paper sx={{ p: 3, borderRadius: 2, height: "100%", border: `1px solid ${alpha(model.color, 0.2)}` }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                  <Box sx={{ color: model.color }}>{model.icon}</Box>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: model.color }}>{model.name}</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{model.description}</Typography>
                <Typography variant="caption" sx={{ display: "block", color: "#22c55e" }}>✅ Pros: {model.pros}</Typography>
                <Typography variant="caption" sx={{ display: "block", color: "#ef4444", mb: 1 }}>⚠️ Cons: {model.cons}</Typography>
                <Chip label={`Best for: ${model.bestFor}`} size="small" variant="outlined" />
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== MAJOR PROVIDERS ==================== */}
        <Typography id="providers" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🏢 Major Cloud Providers
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The "Big Three" control most of the cloud market, each with unique strengths
        </Typography>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table>
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#0ea5e9", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Provider</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Market Share</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Strengths</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Flagship Services</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {cloudProviders.map((provider) => (
                <TableRow key={provider.name}>
                  <TableCell>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <Chip label={provider.name} size="small" sx={{ fontWeight: 700, bgcolor: provider.color, color: "white" }} />
                      <Typography variant="caption" color="text.secondary">{provider.fullName}</Typography>
                    </Box>
                  </TableCell>
                  <TableCell sx={{ fontWeight: 600 }}>{provider.marketShare}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem" }}>{provider.strengths}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{provider.flagship}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* ==================== CORE SERVICES ==================== */}
        <Typography id="core-services" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🔧 Core Cloud Services
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The fundamental building blocks available from all major cloud providers
        </Typography>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Category</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>AWS</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Azure</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>GCP</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {coreServices.map((service) => (
                <TableRow key={service.category}>
                  <TableCell sx={{ fontWeight: 600 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      {service.icon}
                      {service.category}
                    </Box>
                  </TableCell>
                  <TableCell sx={{ fontSize: "0.85rem" }}>{service.description}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#ff9900" }}>{service.awsExample}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#0078d4" }}>{service.azureExample}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#4285f4" }}>{service.gcpExample}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* ==================== VIRTUALIZATION ==================== */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 5 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>CLOUD TECHNOLOGIES</Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        <Typography id="virtualization" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🖥️ Virtualization Fundamentals
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The foundation technology that makes cloud computing possible
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#6366f1", 0.03), border: `1px solid ${alpha("#6366f1", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            <strong>Virtualization</strong> is the technology that allows multiple virtual computers to run on a single physical machine. 
            Before virtualization, if you needed 10 servers, you bought 10 physical machines (each using maybe 10% of their capacity). 
            With virtualization, you can run 10 virtual machines on fewer physical servers, dramatically improving efficiency. 
            This is the foundation of cloud computing — providers use virtualization to divide their massive data centers 
            into smaller, rentable units.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {virtualizationConcepts.map((concept) => (
            <Grid item xs={12} sm={6} key={concept.term}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha("#6366f1", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5 }}>
                  {concept.icon} {concept.term}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{concept.description}</Typography>
                <Typography variant="caption" sx={{ bgcolor: alpha("#6366f1", 0.08), px: 1, py: 0.5, borderRadius: 1 }}>
                  {concept.example}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== CONTAINERS ==================== */}
        <Typography id="containers" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          📦 Containers & Kubernetes
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Lightweight alternatives to VMs for running applications
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#0ea5e9", 0.03), border: `1px solid ${alpha("#0ea5e9", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8, mb: 2 }}>
            <strong>Containers</strong> are like lightweight VMs that share the host operating system's kernel. While a VM includes 
            a full operating system (gigabytes in size, minutes to start), a container only includes your application and its 
            dependencies (megabytes in size, seconds to start). This makes containers perfect for microservices architecture 
            where you might run hundreds of small services.
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>Virtual Machines</Typography>
              <Typography variant="body2" color="text.secondary">
                Full OS per VM • Gigabytes in size • Minutes to boot • Strong isolation • Higher overhead
              </Typography>
            </Grid>
            <Grid item xs={12} sm={6}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Containers</Typography>
              <Typography variant="body2" color="text.secondary">
                Share host OS kernel • Megabytes in size • Seconds to start • Process isolation • Minimal overhead
              </Typography>
            </Grid>
          </Grid>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {containerConcepts.map((concept) => (
            <Grid item xs={12} sm={6} key={concept.term}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha("#0ea5e9", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5, color: "#0ea5e9" }}>
                  {concept.icon} {concept.term}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{concept.description}</Typography>
                <Typography variant="caption" sx={{ bgcolor: alpha("#0ea5e9", 0.08), px: 1, py: 0.5, borderRadius: 1, display: "inline-block" }}>
                  {concept.difference || concept.usage || concept.analogy || concept.examples || concept.features || concept.purpose}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== SERVERLESS ==================== */}
        <Typography id="serverless" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          ⚡ Serverless Computing
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Run code without managing any infrastructure
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            <strong>"Serverless" doesn't mean no servers</strong> — it means YOU don't manage them. You just write code, 
            upload it, and the cloud provider handles everything: provisioning servers, scaling, patching, and load balancing. 
            You're charged only when your code runs (often measured in milliseconds), making it extremely cost-effective for 
            sporadic workloads. The trade-off is less control and potential "cold start" delays.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {serverlessConcepts.map((concept) => (
            <Grid item xs={12} sm={6} key={concept.name}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `2px solid ${alpha(concept.color, 0.2)}`, bgcolor: alpha(concept.color, 0.02) }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, color: concept.color }}>{concept.name}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{concept.description}</Typography>
                <Typography variant="caption" sx={{ display: "block", mb: 0.5 }}>
                  <strong>Examples:</strong> {concept.examples}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {concept.pricing || concept.useCase || concept.impact || concept.benefit}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== STORAGE TYPES ==================== */}
        <Typography id="storage" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          💾 Cloud Storage Types
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Different storage solutions for different use cases
        </Typography>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#22c55e", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>AWS</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Azure</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>GCP</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Best For</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {storageTypes.map((storage) => (
                <TableRow key={storage.type}>
                  <TableCell sx={{ fontWeight: 600 }}>{storage.icon} {storage.type}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem" }}>{storage.description}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#ff9900" }}>{storage.awsService}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#0078d4" }}>{storage.azureService}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#4285f4" }}>{storage.gcpService}</TableCell>
                  <TableCell sx={{ fontSize: "0.75rem", color: "text.secondary" }}>{storage.bestFor}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* ==================== NETWORKING ==================== */}
        <Typography id="networking" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🌐 Cloud Networking
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Building secure, scalable network infrastructure in the cloud
        </Typography>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {networkingConcepts.map((concept) => (
            <Grid item xs={12} sm={6} key={concept.concept}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5, color: "#8b5cf6" }}>
                  {concept.icon} {concept.concept}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{concept.description}</Typography>
                <Typography variant="caption" sx={{ bgcolor: alpha("#8b5cf6", 0.08), px: 1, py: 0.5, borderRadius: 1 }}>
                  {concept.purpose || concept.example || concept.types || concept.benefit || concept.useCase}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== PRICING ==================== */}
        <Typography id="pricing" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          💰 Cloud Pricing Models
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Understanding how cloud costs work and how to optimize spending
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            Cloud pricing can be complex, but understanding it is crucial for cost management. The key principle is 
            <strong> "pay for what you use"</strong>, but providers offer significant discounts for commitments. 
            A well-optimized cloud deployment might use on-demand for development, reserved instances for production 
            baselines, and spot instances for batch processing — potentially saving 50-70% compared to all on-demand.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {pricingModels.map((model) => (
            <Grid item xs={12} sm={6} key={model.model}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `2px solid ${alpha(model.color, 0.2)}` }}>
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: model.color }}>{model.model}</Typography>
                  <Chip label={`${model.discount} off`} size="small" sx={{ fontWeight: 700, bgcolor: alpha(model.color, 0.1), color: model.color }} />
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{model.description}</Typography>
                <Typography variant="caption" sx={{ display: "block" }}>
                  <strong>Best for:</strong> {model.bestFor}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== BENEFITS ==================== */}
        <Typography id="benefits" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          ✨ Benefits of Cloud Computing
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Why organizations are moving to the cloud
        </Typography>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {cloudBenefits.map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.benefit}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha(item.color, 0.2)}` }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <Box sx={{ color: item.color }}>{item.icon}</Box>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color }}>{item.benefit}</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary">{item.description}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== SECURITY ==================== */}
        <Typography id="security" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🔐 Cloud Security Considerations
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Security is a shared responsibility between you and the cloud provider
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.1)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444", display: "flex", alignItems: "center", gap: 1 }}>
            <WarningIcon />
            The Shared Responsibility Model
          </Typography>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            Cloud providers secure the underlying infrastructure (physical security, network, hypervisors), but 
            <strong> YOU are responsible for securing your data, applications, and configurations</strong>. 
            Many cloud breaches happen not because of provider failures, but because of customer misconfigurations 
            — like leaving S3 buckets publicly accessible or using weak IAM policies.
          </Typography>
        </Paper>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#ef4444", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Security Topic</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Importance</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {securityConsiderations.map((item) => (
                <TableRow key={item.topic}>
                  <TableCell sx={{ fontWeight: 600 }}>{item.topic}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem" }}>{item.description}</TableCell>
                  <TableCell>
                    <Chip 
                      label={item.importance} 
                      size="small" 
                      sx={{ 
                        fontWeight: 600, 
                        bgcolor: item.importance === "Critical" ? alpha("#ef4444", 0.1) : alpha("#f59e0b", 0.1),
                        color: item.importance === "Critical" ? "#ef4444" : "#f59e0b",
                      }} 
                    />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* ==================== COMMON MISCONFIGURATIONS ==================== */}
        <Typography id="misconfigs" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          ⚠️ Common Cloud Misconfigurations
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Security issues that cause most cloud breaches — learn to avoid and detect them
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            According to Gartner, through 2025, <strong>99% of cloud security failures will be the customer's fault</strong>. 
            Most breaches aren't sophisticated attacks — they're simple misconfigurations that expose data or grant excessive 
            access. Understanding these common mistakes is crucial for anyone working with cloud infrastructure.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {commonMisconfigs.map((item) => (
            <Grid item xs={12} sm={6} key={item.issue}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha(item.severity === "Critical" ? "#ef4444" : "#f59e0b", 0.2)}` }}>
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{item.issue}</Typography>
                  <Chip 
                    label={item.severity} 
                    size="small" 
                    sx={{ 
                      fontWeight: 600,
                      bgcolor: alpha(item.severity === "Critical" ? "#ef4444" : "#f59e0b", 0.1),
                      color: item.severity === "Critical" ? "#ef4444" : "#f59e0b",
                    }} 
                  />
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.description}</Typography>
                <Typography variant="caption" sx={{ display: "block", mb: 0.5, color: "#ef4444" }}>
                  <strong>Impact:</strong> {item.impact}
                </Typography>
                <Typography variant="caption" sx={{ display: "block", color: "#22c55e" }}>
                  <strong>Prevention:</strong> {item.prevention}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== TERMINOLOGY ==================== */}
        <Typography id="terminology" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          📖 Cloud Terminology
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Essential terms you'll encounter when working with cloud services
        </Typography>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#0ea5e9", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Term</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Definition</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {cloudTerminology.map((item) => (
                <TableRow key={item.term}>
                  <TableCell sx={{ fontWeight: 600, color: "#0ea5e9" }}>{item.term}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem" }}>{item.definition}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary", fontFamily: "monospace" }}>{item.example}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* ==================== DETAILED SERVICE COMPARISON ==================== */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 5 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>ADVANCED TOPICS</Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        <Typography id="service-comparison" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🔄 Detailed Service Comparison
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Complete mapping of equivalent services across major cloud providers
        </Typography>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Service Category</TableCell>
                <TableCell sx={{ fontWeight: 700, color: "#ff9900" }}>AWS</TableCell>
                <TableCell sx={{ fontWeight: 700, color: "#0078d4" }}>Azure</TableCell>
                <TableCell sx={{ fontWeight: 700, color: "#4285f4" }}>GCP</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {detailedServiceComparison.map((service) => (
                <TableRow key={service.service} sx={{ "&:hover": { bgcolor: alpha("#8b5cf6", 0.02) } }}>
                  <TableCell sx={{ fontWeight: 600 }}>{service.service}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#ff9900" }}>{service.aws}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#0078d4" }}>{service.azure}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#4285f4" }}>{service.gcp}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{service.notes}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* ==================== IAM DEEP DIVE ==================== */}
        <Typography id="iam" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🔐 Identity & Access Management (IAM)
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The cornerstone of cloud security — controlling who can access what
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            <strong>IAM is the #1 security priority in cloud</strong>. It controls who (identity) can do what (actions) 
            on which resources. Misconfigured IAM policies are responsible for many of the largest cloud breaches. 
            Always follow the <strong>Principle of Least Privilege</strong>: grant only the minimum permissions needed 
            for a task, and nothing more.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {iamConcepts.map((concept) => (
            <Grid item xs={12} sm={6} key={concept.concept}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha("#ef4444", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5, color: "#ef4444" }}>
                  {concept.icon} {concept.concept}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{concept.description}</Typography>
                <Typography variant="caption" sx={{ display: "block", color: "#22c55e" }}>
                  <strong>Best Practice:</strong> {concept.bestPractice}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== ARCHITECTURE PATTERNS ==================== */}
        <Typography id="architecture" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🏗️ Cloud Architecture Patterns
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Proven design patterns for building reliable, scalable cloud applications
        </Typography>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {architecturePatterns.map((pattern) => (
            <Grid item xs={12} sm={6} key={pattern.pattern}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha("#6366f1", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5, color: "#6366f1" }}>
                  {pattern.pattern}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{pattern.description}</Typography>
                <Typography variant="caption" sx={{ display: "block", mb: 0.5 }}>
                  <strong>Use Cases:</strong> {pattern.useCases}
                </Typography>
                <Typography variant="caption" sx={{ display: "block", mb: 0.5, color: "#22c55e" }}>
                  <strong>Pros:</strong> {pattern.pros}
                </Typography>
                <Typography variant="caption" sx={{ display: "block", color: "#ef4444" }}>
                  <strong>Cons:</strong> {pattern.cons}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== DEVOPS & CI/CD ==================== */}
        <Typography id="devops" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🔧 DevOps & CI/CD in the Cloud
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Automate your software delivery pipeline with cloud-native tools
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            <strong>DevOps</strong> is a culture and set of practices that combines software development (Dev) and IT operations (Ops). 
            <strong> CI/CD</strong> (Continuous Integration/Continuous Deployment) automates the process of building, testing, and deploying code. 
            Cloud providers offer integrated tools to implement these practices, enabling teams to ship code faster and more reliably.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {devOpsConcepts.map((concept) => (
            <Grid item xs={12} sm={6} key={concept.concept}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5, color: "#f59e0b" }}>
                  {concept.concept}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{concept.description}</Typography>
                <Typography variant="caption" sx={{ display: "block", mb: 0.5 }}>
                  <strong>Tools:</strong> {concept.tools}
                </Typography>
                <Typography variant="caption" sx={{ display: "block", color: "#22c55e" }}>
                  <strong>Benefit:</strong> {concept.benefit}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== CLI TOOLS ==================== */}
        <Typography id="cli" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          💻 Cloud CLI Tools
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Command-line interfaces for managing cloud resources efficiently
        </Typography>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#10b981", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Tool</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Command</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {cliTools.map((tool) => (
                <TableRow key={tool.name} sx={{ "&:hover": { bgcolor: alpha("#10b981", 0.02) } }}>
                  <TableCell sx={{ fontWeight: 600, color: "#10b981" }}>{tool.name}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>{tool.command}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.7rem", bgcolor: alpha("#000", 0.03), borderRadius: 1 }}>
                    {tool.example}
                  </TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{tool.description}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* ==================== SECURITY TOOLS ==================== */}
        <Typography id="security-tools" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🛡️ Cloud Security Tools
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Built-in and third-party tools for securing your cloud environment
        </Typography>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#ef4444", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Tool / Category</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Examples</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {cloudSecurityTools.map((tool) => (
                <TableRow key={tool.tool} sx={{ "&:hover": { bgcolor: alpha("#ef4444", 0.02) } }}>
                  <TableCell sx={{ fontWeight: 600, color: "#ef4444" }}>{tool.tool}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{tool.purpose}</TableCell>
                  <TableCell sx={{ fontSize: "0.75rem" }}>{tool.examples}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* ==================== REAL WORLD EXAMPLES ==================== */}
        <Typography id="real-world" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🌍 Real World Cloud Implementations
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          How major companies use cloud computing to power their services
        </Typography>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {realWorldExamples.map((example) => (
            <Grid item xs={12} md={6} key={example.company}>
              <Paper sx={{ p: 3, borderRadius: 2, height: "100%", border: `1px solid ${alpha("#8b5cf6", 0.2)}`, bgcolor: alpha("#8b5cf6", 0.02) }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>{example.company}</Typography>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 0.5 }}>{example.useCase}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{example.details}</Typography>
                <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>Key Services:</Typography>
                <Typography variant="caption" color="text.secondary">{example.services}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== COMING SOON OUTLINE ==================== */}
        <Typography id="outline" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          📋 Coming Soon
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          More in-depth content will be added in future updates
        </Typography>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {outlineSections.map((section) => (
            <Grid item xs={12} sm={6} md={4} key={section.title}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px dashed ${alpha("#6b7280", 0.3)}`, bgcolor: alpha("#6b7280", 0.03) }}>
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{section.title}</Typography>
                  <Chip label={section.status} size="small" sx={{ fontSize: "0.65rem", bgcolor: alpha("#6b7280", 0.1) }} />
                </Box>
                <Typography variant="body2" color="text.secondary">{section.description}</Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Key Takeaways */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
            <TipsAndUpdatesIcon sx={{ color: "#22c55e" }} />
            Key Takeaways
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Cloud = Renting Computing</Typography>
              <Typography variant="body2" color="text.secondary">
                Instead of buying servers, rent computing resources from providers and pay for what you use. 
                Virtualization and containers make this efficient division possible.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Know the Service Models</Typography>
              <Typography variant="body2" color="text.secondary">
                IaaS (infrastructure), PaaS (platform), SaaS (software). Containers and serverless add more options. 
                Choose based on how much control vs. convenience you need.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Security is YOUR Job</Typography>
              <Typography variant="body2" color="text.secondary">
                Providers secure infrastructure, but you secure your data and configs. 99% of cloud breaches are 
                from misconfigurations — learn the common pitfalls.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Optimize Your Costs</Typography>
              <Typography variant="body2" color="text.secondary">
                Don't just use on-demand pricing. Reserved instances, spot pricing, and savings plans can cut 
                costs by 50-70%. Know your workload patterns.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>VMs vs Containers vs Serverless</Typography>
              <Typography variant="body2" color="text.secondary">
                VMs offer isolation, containers offer portability, serverless offers simplicity. Many workloads 
                use a combination. Match the tool to the job.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Multi-Provider Reality</Typography>
              <Typography variant="body2" color="text.secondary">
                AWS, Azure, and GCP have similar core services with different names. Learn concepts, not just 
                one provider — skills transfer across platforms.
              </Typography>
            </Grid>
          </Grid>
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
              borderColor: alpha("#0ea5e9", 0.3),
              color: "#0ea5e9",
              "&:hover": {
                borderColor: "#0ea5e9",
                bgcolor: alpha("#0ea5e9", 0.05),
              },
            }}
          >
            Return to Learning Hub
          </Button>
        </Box>
      </Container>
    </LearnPageLayout>
  );
};

export default CloudComputingPage;
