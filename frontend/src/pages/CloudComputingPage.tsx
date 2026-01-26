import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import { Link } from "react-router-dom";
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
  Drawer,
  Fab,
  IconButton,
  Tooltip,
  LinearProgress,
  useMediaQuery,
  Slider,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Tabs,
  Tab,
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
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import QuizIcon from "@mui/icons-material/Quiz";
import SchoolIcon from "@mui/icons-material/School";
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

// ========== AWS DEEP DIVE ==========
const awsServiceCategories = [
  {
    category: "Compute",
    color: "#ff9900",
    icon: "🖥️",
    services: [
      { name: "EC2", fullName: "Elastic Compute Cloud", description: "Resizable virtual servers in the cloud. Choose from 400+ instance types optimized for different workloads.", keyFeatures: "Auto Scaling, Spot Instances (90% discount), Dedicated Hosts, Graviton (ARM) processors", useCase: "Web servers, application hosting, batch processing, HPC" },
      { name: "Lambda", fullName: "AWS Lambda", description: "Run code without provisioning servers. Pay only for compute time consumed.", keyFeatures: "Event-driven, 15-min max execution, 10GB memory, supports Python/Node/Java/Go/C#/.NET", useCase: "APIs, data processing, automation, real-time file processing" },
      { name: "ECS/EKS", fullName: "Container Services", description: "Run Docker containers at scale. ECS is AWS-native, EKS is managed Kubernetes.", keyFeatures: "Fargate (serverless containers), deep AWS integration, service discovery", useCase: "Microservices, batch jobs, ML workloads, CI/CD pipelines" },
      { name: "Lightsail", fullName: "Amazon Lightsail", description: "Simple virtual private servers with predictable pricing. Easy for beginners.", keyFeatures: "Fixed monthly pricing, pre-configured apps (WordPress, LAMP), managed databases", useCase: "Simple websites, dev/test environments, small business apps" },
      { name: "Batch", fullName: "AWS Batch", description: "Run batch computing workloads at any scale without managing infrastructure.", keyFeatures: "Automatic scaling, spot integration, job queues, multi-node parallel jobs", useCase: "Financial modeling, drug discovery, genomics, rendering" },
      { name: "Outposts", fullName: "AWS Outposts", description: "Run AWS infrastructure on-premises for hybrid workloads.", keyFeatures: "Same APIs as AWS, local data processing, low latency", useCase: "Data residency, low-latency local processing, hybrid apps" },
    ]
  },
  {
    category: "Storage",
    color: "#22c55e",
    icon: "💾",
    services: [
      { name: "S3", fullName: "Simple Storage Service", description: "Object storage with industry-leading durability (99.999999999%). The backbone of AWS.", keyFeatures: "Storage classes (Standard/IA/Glacier), versioning, lifecycle policies, event notifications", useCase: "Data lakes, backups, static websites, content distribution" },
      { name: "EBS", fullName: "Elastic Block Store", description: "Persistent block storage for EC2. Like a virtual hard drive.", keyFeatures: "SSD/HDD options, snapshots, encryption, up to 64TB volumes, multi-attach", useCase: "Databases, boot volumes, throughput-intensive workloads" },
      { name: "EFS", fullName: "Elastic File System", description: "Managed NFS file system that scales automatically.", keyFeatures: "Petabyte scale, multi-AZ, POSIX-compliant, lifecycle management", useCase: "Content management, web serving, shared home directories" },
      { name: "S3 Glacier", fullName: "S3 Glacier & Deep Archive", description: "Ultra-low cost archive storage. Retrieval from minutes to hours.", keyFeatures: "Vault Lock for compliance, retrieval tiers, 99.999999999% durability", useCase: "Compliance archives, digital preservation, long-term backups" },
      { name: "FSx", fullName: "Amazon FSx", description: "Fully managed file systems: Windows File Server, Lustre, NetApp ONTAP, OpenZFS.", keyFeatures: "Native protocol support, high performance, AWS integration", useCase: "Windows workloads, HPC, machine learning, financial analytics" },
      { name: "Storage Gateway", fullName: "AWS Storage Gateway", description: "Hybrid storage connecting on-premises to AWS cloud storage.", keyFeatures: "File/Volume/Tape gateways, local caching, seamless integration", useCase: "Backup to cloud, disaster recovery, data migration" },
    ]
  },
  {
    category: "Database",
    color: "#3b82f6",
    icon: "🗄️",
    services: [
      { name: "RDS", fullName: "Relational Database Service", description: "Managed relational databases: MySQL, PostgreSQL, MariaDB, Oracle, SQL Server.", keyFeatures: "Automated backups, Multi-AZ, read replicas, auto-scaling storage", useCase: "Traditional applications, e-commerce, content management" },
      { name: "Aurora", fullName: "Amazon Aurora", description: "MySQL/PostgreSQL-compatible with 5x performance, 1/10th the cost of commercial DBs.", keyFeatures: "Auto-scaling storage to 128TB, 15 read replicas, serverless option, global database", useCase: "Enterprise apps, SaaS, gaming, high-availability workloads" },
      { name: "DynamoDB", fullName: "Amazon DynamoDB", description: "Fully managed NoSQL database with single-digit millisecond performance.", keyFeatures: "Serverless, auto-scaling, global tables, ACID transactions, on-demand mode", useCase: "Gaming, IoT, mobile backends, real-time analytics" },
      { name: "ElastiCache", fullName: "Amazon ElastiCache", description: "Managed Redis and Memcached for in-memory caching.", keyFeatures: "Sub-millisecond latency, cluster mode, data tiering", useCase: "Session management, caching, real-time analytics, leaderboards" },
      { name: "Redshift", fullName: "Amazon Redshift", description: "Petabyte-scale data warehouse. Fast analytics on structured data.", keyFeatures: "Columnar storage, Redshift Serverless, ML integration, data sharing", useCase: "Business intelligence, data warehousing, log analytics" },
      { name: "DocumentDB", fullName: "Amazon DocumentDB", description: "MongoDB-compatible document database for JSON workloads.", keyFeatures: "Fully managed, auto-scaling, MongoDB compatibility", useCase: "Content management, catalogs, user profiles" },
    ]
  },
  {
    category: "Networking",
    color: "#8b5cf6",
    icon: "🌐",
    services: [
      { name: "VPC", fullName: "Virtual Private Cloud", description: "Isolated virtual network where you launch AWS resources.", keyFeatures: "Subnets, route tables, security groups, NACLs, VPC peering, Transit Gateway", useCase: "All workloads — foundation of AWS networking" },
      { name: "CloudFront", fullName: "Amazon CloudFront", description: "Global CDN with 400+ edge locations for low-latency content delivery.", keyFeatures: "Origin Shield, real-time logs, Lambda@Edge, WebSocket support", useCase: "Websites, APIs, video streaming, software distribution" },
      { name: "Route 53", fullName: "Amazon Route 53", description: "Highly available DNS service with advanced routing policies.", keyFeatures: "Health checks, geo routing, latency routing, weighted routing, failover", useCase: "Domain registration, DNS management, traffic routing" },
      { name: "ELB", fullName: "Elastic Load Balancing", description: "Distribute traffic across targets. ALB (Layer 7), NLB (Layer 4), GLB (Layer 3).", keyFeatures: "Auto-scaling, health checks, SSL termination, sticky sessions", useCase: "High availability, fault tolerance, scaling" },
      { name: "Direct Connect", fullName: "AWS Direct Connect", description: "Dedicated private network connection from your premises to AWS.", keyFeatures: "Consistent network performance, reduced bandwidth costs, private connectivity", useCase: "Hybrid cloud, data migration, compliance workloads" },
      { name: "API Gateway", fullName: "Amazon API Gateway", description: "Create, publish, and manage APIs at any scale.", keyFeatures: "REST/WebSocket APIs, throttling, caching, authorization, monitoring", useCase: "Serverless backends, mobile backends, microservices APIs" },
    ]
  },
  {
    category: "Security & Identity",
    color: "#ef4444",
    icon: "🔐",
    services: [
      { name: "IAM", fullName: "Identity and Access Management", description: "Control access to AWS resources. Foundation of AWS security.", keyFeatures: "Users, groups, roles, policies, MFA, identity federation, access analyzer", useCase: "All workloads — required for security" },
      { name: "Cognito", fullName: "Amazon Cognito", description: "Add user sign-up, sign-in, and access control to apps.", keyFeatures: "User pools, identity pools, social login, SAML, OAuth 2.0", useCase: "Mobile apps, web apps, API authentication" },
      { name: "KMS", fullName: "Key Management Service", description: "Create and manage encryption keys for your data.", keyFeatures: "AWS-managed keys, customer-managed keys, automatic rotation, audit via CloudTrail", useCase: "Encryption at rest, envelope encryption, digital signing" },
      { name: "Secrets Manager", fullName: "AWS Secrets Manager", description: "Securely store, rotate, and retrieve secrets like API keys and passwords.", keyFeatures: "Automatic rotation, fine-grained access control, cross-account sharing", useCase: "Database credentials, API keys, certificates" },
      { name: "WAF", fullName: "Web Application Firewall", description: "Protect web apps from common exploits like SQL injection and XSS.", keyFeatures: "Managed rules, custom rules, bot control, rate limiting, integration with CloudFront/ALB", useCase: "Web application security, DDoS mitigation" },
      { name: "GuardDuty", fullName: "Amazon GuardDuty", description: "Intelligent threat detection using ML to analyze AWS account activity.", keyFeatures: "Anomaly detection, VPC flow logs analysis, DNS logs, malware protection", useCase: "Threat detection, security monitoring, compliance" },
      { name: "Security Hub", fullName: "AWS Security Hub", description: "Centralized security findings and compliance checks across AWS accounts.", keyFeatures: "Aggregated findings, compliance standards (CIS, PCI-DSS), automated remediation", useCase: "Security posture management, compliance reporting" },
    ]
  },
  {
    category: "AI & Machine Learning",
    color: "#ec4899",
    icon: "🤖",
    services: [
      { name: "SageMaker", fullName: "Amazon SageMaker", description: "Build, train, and deploy ML models at scale.", keyFeatures: "Jupyter notebooks, built-in algorithms, AutoML, model monitoring, MLOps", useCase: "Custom ML models, MLOps pipelines, model training" },
      { name: "Bedrock", fullName: "Amazon Bedrock", description: "Access foundation models (Claude, Llama, Titan) via API.", keyFeatures: "Multiple FMs, fine-tuning, RAG, guardrails, agents", useCase: "Generative AI apps, chatbots, content generation" },
      { name: "Rekognition", fullName: "Amazon Rekognition", description: "Image and video analysis using deep learning.", keyFeatures: "Object detection, facial analysis, content moderation, celebrity recognition", useCase: "Security, media analysis, content moderation" },
      { name: "Comprehend", fullName: "Amazon Comprehend", description: "Natural language processing to extract insights from text.", keyFeatures: "Sentiment analysis, entity recognition, key phrases, language detection", useCase: "Customer feedback analysis, document processing" },
      { name: "Transcribe", fullName: "Amazon Transcribe", description: "Automatic speech recognition (speech-to-text).", keyFeatures: "Real-time/batch, speaker identification, custom vocabulary, medical transcription", useCase: "Call center analytics, meeting transcription, subtitles" },
      { name: "Polly", fullName: "Amazon Polly", description: "Turn text into lifelike speech with neural voices.", keyFeatures: "60+ languages, SSML support, neural TTS, custom lexicons", useCase: "Voice assistants, e-learning, accessibility" },
    ]
  },
  {
    category: "DevOps & Management",
    color: "#14b8a6",
    icon: "⚙️",
    services: [
      { name: "CloudFormation", fullName: "AWS CloudFormation", description: "Infrastructure as Code — define AWS resources using templates.", keyFeatures: "Stacks, change sets, drift detection, nested stacks, StackSets", useCase: "IaC, environment replication, disaster recovery" },
      { name: "CloudWatch", fullName: "Amazon CloudWatch", description: "Monitoring and observability for AWS resources and applications.", keyFeatures: "Metrics, logs, alarms, dashboards, insights, anomaly detection", useCase: "Monitoring, alerting, troubleshooting, capacity planning" },
      { name: "CloudTrail", fullName: "AWS CloudTrail", description: "Audit all API calls made in your AWS account.", keyFeatures: "Event history, trails, insights, Lake (query engine), organization trails", useCase: "Compliance auditing, security analysis, troubleshooting" },
      { name: "Systems Manager", fullName: "AWS Systems Manager", description: "Operational hub for managing AWS and on-premises resources.", keyFeatures: "Session Manager, Patch Manager, Parameter Store, Run Command, Automation", useCase: "Operations management, patching, automation, compliance" },
      { name: "CodePipeline", fullName: "AWS CodePipeline", description: "Continuous delivery service for fast and reliable application updates.", keyFeatures: "Visual workflow, integration with CodeBuild/CodeDeploy, third-party tools", useCase: "CI/CD pipelines, automated deployments" },
      { name: "Config", fullName: "AWS Config", description: "Track resource configuration changes and compliance.", keyFeatures: "Configuration history, compliance rules, remediation, aggregators", useCase: "Compliance auditing, security analysis, change management" },
    ]
  },
];

const awsGlobalInfrastructure = {
  regions: "33+ regions worldwide",
  azs: "105+ Availability Zones",
  edgeLocations: "400+ CloudFront edge locations",
  localZones: "30+ Local Zones for ultra-low latency",
  wavelengthZones: "29+ Wavelength Zones for 5G edge",
  outposts: "On-premises AWS infrastructure",
};

const awsFreeTierHighlights = [
  { service: "EC2", offer: "750 hours/month t2.micro or t3.micro", duration: "12 months" },
  { service: "S3", offer: "5 GB standard storage", duration: "12 months" },
  { service: "RDS", offer: "750 hours/month db.t2.micro", duration: "12 months" },
  { service: "Lambda", offer: "1 million requests/month", duration: "Always free" },
  { service: "DynamoDB", offer: "25 GB storage, 25 WCU/RCU", duration: "Always free" },
  { service: "CloudWatch", offer: "10 custom metrics, 10 alarms", duration: "Always free" },
  { service: "SNS", offer: "1 million publishes/month", duration: "Always free" },
  { service: "SQS", offer: "1 million requests/month", duration: "Always free" },
];

// ========== AZURE DEEP DIVE ==========
const azureServiceCategories = [
  {
    category: "Compute",
    color: "#0078d4",
    icon: "🖥️",
    services: [
      { name: "Virtual Machines", fullName: "Azure Virtual Machines", description: "On-demand, scalable computing with 700+ VM sizes and types.", keyFeatures: "Spot VMs (90% discount), Reserved Instances, Azure Hybrid Benefit, Confidential VMs", useCase: "Windows/Linux workloads, lift-and-shift, dev/test, enterprise apps" },
      { name: "Functions", fullName: "Azure Functions", description: "Event-driven serverless compute. Pay only when code runs.", keyFeatures: "Durable Functions (stateful), Premium plan (no cold start), Consumption plan", useCase: "APIs, webhooks, scheduled tasks, event processing" },
      { name: "AKS", fullName: "Azure Kubernetes Service", description: "Fully managed Kubernetes cluster with automated upgrades and scaling.", keyFeatures: "Azure AD integration, Azure Policy, GitOps with Flux, virtual nodes (ACI)", useCase: "Microservices, CI/CD, ML workloads, multi-cloud with Arc" },
      { name: "Container Instances", fullName: "Azure Container Instances", description: "Run containers without managing servers. Fastest way to run a container.", keyFeatures: "Per-second billing, GPU support, virtual network deployment", useCase: "Simple containers, batch jobs, burstable workloads" },
      { name: "App Service", fullName: "Azure App Service", description: "Fully managed PaaS for web apps, APIs, and mobile backends.", keyFeatures: "Auto-scale, deployment slots, custom domains, managed certificates, WebJobs", useCase: "Web apps, REST APIs, mobile backends" },
      { name: "Azure Arc", fullName: "Azure Arc", description: "Extend Azure management to any infrastructure (on-prem, multi-cloud, edge).", keyFeatures: "Unified management, Azure Policy, GitOps, Azure services anywhere", useCase: "Hybrid cloud, multi-cloud, edge computing" },
    ]
  },
  {
    category: "Storage",
    color: "#22c55e",
    icon: "💾",
    services: [
      { name: "Blob Storage", fullName: "Azure Blob Storage", description: "Object storage for unstructured data. Hot/Cool/Archive tiers.", keyFeatures: "Immutable storage, lifecycle management, blob versioning, data lake integration", useCase: "Backups, big data, static websites, media storage" },
      { name: "Managed Disks", fullName: "Azure Managed Disks", description: "Block storage for VMs with automatic management and redundancy.", keyFeatures: "Premium SSD v2, Ultra Disk, shared disks, disk encryption, snapshots", useCase: "VM disks, databases, high-performance workloads" },
      { name: "Azure Files", fullName: "Azure Files", description: "Fully managed SMB and NFS file shares in the cloud.", keyFeatures: "SMB 3.0, NFS 4.1, Azure File Sync, identity-based authentication", useCase: "Lift-and-shift, shared application settings, dev/test" },
      { name: "Data Lake Storage", fullName: "Azure Data Lake Storage Gen2", description: "Massively scalable data lake with hierarchical namespace on Blob.", keyFeatures: "HDFS compatibility, fine-grained ACLs, analytics integration", useCase: "Big data analytics, data lakes, machine learning" },
      { name: "NetApp Files", fullName: "Azure NetApp Files", description: "Enterprise-grade file storage powered by NetApp.", keyFeatures: "Ultra-low latency, snapshots, cross-region replication", useCase: "SAP, HPC, VDI, enterprise file shares" },
      { name: "StorSimple", fullName: "Azure StorSimple", description: "Hybrid cloud storage solution for data tiering.", keyFeatures: "Automatic tiering, local caching, backup integration", useCase: "Hybrid storage, disaster recovery" },
    ]
  },
  {
    category: "Database",
    color: "#3b82f6",
    icon: "🗄️",
    services: [
      { name: "SQL Database", fullName: "Azure SQL Database", description: "Intelligent, fully managed SQL database with AI-powered features.", keyFeatures: "Hyperscale (100TB+), serverless, auto-tuning, intelligent insights, geo-replication", useCase: "Modern cloud apps, SaaS, data-driven apps" },
      { name: "Cosmos DB", fullName: "Azure Cosmos DB", description: "Globally distributed, multi-model database with guaranteed single-digit ms latency.", keyFeatures: "5 consistency levels, 5 APIs (SQL, MongoDB, Cassandra, Gremlin, Table), turnkey global distribution", useCase: "Global apps, IoT, gaming, personalization, real-time analytics" },
      { name: "SQL Managed Instance", fullName: "Azure SQL Managed Instance", description: "100% SQL Server compatibility with PaaS benefits.", keyFeatures: "Native VNet, SQL Agent, cross-database queries, link feature", useCase: "SQL Server migration, lift-and-shift" },
      { name: "Database for PostgreSQL", fullName: "Azure Database for PostgreSQL", description: "Fully managed PostgreSQL with Flexible Server and Hyperscale (Citus).", keyFeatures: "Built-in HA, intelligent performance, pgvector for AI", useCase: "Web/mobile apps, geospatial, time-series, AI apps" },
      { name: "Cache for Redis", fullName: "Azure Cache for Redis", description: "Fully managed Redis cache for lightning-fast data access.", keyFeatures: "Redis 6.0, active geo-replication, Enterprise tier with RediSearch/RedisBloom", useCase: "Caching, session store, messaging, leaderboards" },
      { name: "Synapse Analytics", fullName: "Azure Synapse Analytics", description: "Limitless analytics service combining data integration, warehousing, and big data.", keyFeatures: "Serverless SQL, Spark pools, Data Explorer pools, Power BI integration", useCase: "Data warehousing, big data analytics, machine learning" },
    ]
  },
  {
    category: "Networking",
    color: "#8b5cf6",
    icon: "🌐",
    services: [
      { name: "Virtual Network", fullName: "Azure Virtual Network", description: "Private network in Azure for secure resource communication.", keyFeatures: "Subnets, NSGs, peering, private endpoints, service endpoints, NAT Gateway", useCase: "All Azure workloads — networking foundation" },
      { name: "CDN", fullName: "Azure CDN", description: "Global content delivery network with multiple providers.", keyFeatures: "Microsoft, Verizon, Akamai options, rules engine, real-time analytics", useCase: "Web content, streaming, software distribution" },
      { name: "Front Door", fullName: "Azure Front Door", description: "Global load balancer with WAF, caching, and SSL termination.", keyFeatures: "Anycast, intelligent routing, URL-based routing, WAF integration", useCase: "Global web apps, API acceleration, multi-region failover" },
      { name: "Load Balancer", fullName: "Azure Load Balancer", description: "Layer 4 load balancing for VMs with high availability.", keyFeatures: "Public/internal LB, health probes, HA ports, zone redundancy", useCase: "VM scaling, high availability, network traffic distribution" },
      { name: "ExpressRoute", fullName: "Azure ExpressRoute", description: "Private, dedicated connection between on-premises and Azure.", keyFeatures: "Up to 100 Gbps, Global Reach, direct peering, ExpressRoute Direct", useCase: "Hybrid connectivity, large data transfers, compliance" },
      { name: "Private Link", fullName: "Azure Private Link", description: "Access Azure services over a private endpoint in your VNet.", keyFeatures: "No public internet exposure, private IP connectivity, cross-region access", useCase: "Secure access to PaaS services, data exfiltration prevention" },
    ]
  },
  {
    category: "Security & Identity",
    color: "#ef4444",
    icon: "🔐",
    services: [
      { name: "Entra ID", fullName: "Microsoft Entra ID (Azure AD)", description: "Cloud-based identity and access management. Foundation of Azure security.", keyFeatures: "SSO, MFA, Conditional Access, Privileged Identity Management, B2B/B2C", useCase: "All Azure workloads, Microsoft 365, third-party SaaS" },
      { name: "Key Vault", fullName: "Azure Key Vault", description: "Securely store and manage keys, secrets, and certificates.", keyFeatures: "HSM-backed keys, secret rotation, certificate management, RBAC", useCase: "Encryption keys, application secrets, certificates" },
      { name: "Defender for Cloud", fullName: "Microsoft Defender for Cloud", description: "Cloud security posture management and workload protection.", keyFeatures: "Secure Score, compliance dashboards, threat protection, vulnerability scanning", useCase: "Security posture, compliance, threat protection" },
      { name: "Sentinel", fullName: "Microsoft Sentinel", description: "Cloud-native SIEM and SOAR powered by AI.", keyFeatures: "200+ connectors, KQL queries, automated playbooks, threat hunting", useCase: "Security monitoring, threat detection, incident response" },
      { name: "DDoS Protection", fullName: "Azure DDoS Protection", description: "Protection against volumetric, protocol, and application layer attacks.", keyFeatures: "Always-on monitoring, adaptive tuning, attack analytics, SLA credit", useCase: "Web applications, public-facing workloads" },
      { name: "Firewall", fullName: "Azure Firewall", description: "Cloud-native network firewall with built-in high availability.", keyFeatures: "Threat intelligence, FQDN filtering, network/application rules, Premium SKU with IDS/IPS", useCase: "Network security, compliance, threat prevention" },
    ]
  },
  {
    category: "AI & Machine Learning",
    color: "#ec4899",
    icon: "🤖",
    services: [
      { name: "Azure OpenAI", fullName: "Azure OpenAI Service", description: "Access to GPT-4, GPT-4o, DALL-E, Whisper with enterprise security.", keyFeatures: "Private networking, content filtering, fine-tuning, Azure AI Search integration", useCase: "Chatbots, content generation, code assistance, document analysis" },
      { name: "Machine Learning", fullName: "Azure Machine Learning", description: "End-to-end ML platform for building, training, and deploying models.", keyFeatures: "AutoML, designer (no-code), MLOps, responsible AI dashboard, managed endpoints", useCase: "Custom ML models, MLOps, model management" },
      { name: "Cognitive Services", fullName: "Azure AI Services", description: "Pre-built AI capabilities for vision, speech, language, and decision.", keyFeatures: "Vision, Speech, Language, Decision APIs, custom models", useCase: "Image analysis, speech recognition, translation, content moderation" },
      { name: "AI Search", fullName: "Azure AI Search", description: "AI-powered search service with vector search and semantic ranking.", keyFeatures: "Vector search, semantic search, hybrid search, knowledge mining, RAG", useCase: "Enterprise search, RAG applications, e-commerce" },
      { name: "Bot Service", fullName: "Azure Bot Service", description: "Build and connect intelligent bots across multiple channels.", keyFeatures: "Bot Framework SDK, Power Virtual Agents, multiple channels", useCase: "Customer service bots, virtual assistants" },
      { name: "Document Intelligence", fullName: "Azure AI Document Intelligence", description: "Extract information from documents using AI.", keyFeatures: "Pre-built models (invoices, receipts), custom models, layout analysis", useCase: "Invoice processing, form extraction, document automation" },
    ]
  },
  {
    category: "DevOps & Management",
    color: "#14b8a6",
    icon: "⚙️",
    services: [
      { name: "Azure DevOps", fullName: "Azure DevOps Services", description: "Complete DevOps toolchain: repos, pipelines, boards, artifacts, test plans.", keyFeatures: "Git repos, YAML pipelines, Kanban boards, package management", useCase: "CI/CD, project management, source control" },
      { name: "Monitor", fullName: "Azure Monitor", description: "Full-stack monitoring for applications, infrastructure, and network.", keyFeatures: "Metrics, logs, Application Insights, Log Analytics, alerts, workbooks", useCase: "Observability, troubleshooting, capacity planning" },
      { name: "Resource Manager", fullName: "Azure Resource Manager (ARM)", description: "Deploy and manage Azure resources using templates and Bicep.", keyFeatures: "ARM templates, Bicep, deployment stacks, what-if, rollback", useCase: "IaC, environment replication, governance" },
      { name: "Policy", fullName: "Azure Policy", description: "Enforce organizational standards and assess compliance at scale.", keyFeatures: "Built-in policies, custom policies, initiatives, remediation tasks", useCase: "Governance, compliance, cost management" },
      { name: "Automation", fullName: "Azure Automation", description: "Process automation and configuration management.", keyFeatures: "Runbooks, DSC, Update Management, Start/Stop VMs", useCase: "Automation, patching, configuration management" },
      { name: "Blueprints", fullName: "Azure Blueprints", description: "Package ARM templates, policies, and RBAC for repeatable deployments.", keyFeatures: "Versioned blueprints, locking, audit trail", useCase: "Landing zones, compliance, governance" },
    ]
  },
];

const azureGlobalInfrastructure = {
  regions: "60+ regions worldwide (more than any cloud)",
  azs: "Availability Zones in 50+ regions",
  edgeLocations: "190+ Azure CDN edge locations",
  edgeZones: "Azure Edge Zones for low-latency",
  stack: "Azure Stack for on-premises/edge",
  expressRoute: "ExpressRoute in 60+ peering locations",
};

const azureFreeTierHighlights = [
  { service: "Virtual Machines", offer: "B1S VM 750 hours/month (Linux), B1S 750 hours/month (Windows)", duration: "12 months" },
  { service: "Blob Storage", offer: "5 GB LRS hot block blob storage", duration: "12 months" },
  { service: "SQL Database", offer: "250 GB S0 database", duration: "12 months" },
  { service: "Functions", offer: "1 million requests/month", duration: "Always free" },
  { service: "Cosmos DB", offer: "1000 RU/s, 25 GB storage", duration: "Always free" },
  { service: "Azure DevOps", offer: "5 users, unlimited private repos", duration: "Always free" },
  { service: "App Service", offer: "10 web/mobile/API apps, 1 GB storage", duration: "Always free" },
  { service: "Cognitive Services", offer: "Various free tiers per service", duration: "Always free" },
];

const azureEnterpriseIntegration = [
  { feature: "Microsoft 365 Integration", description: "Seamless integration with Office 365, Teams, SharePoint, and Outlook" },
  { feature: "Active Directory", description: "Azure AD syncs with on-premises AD for hybrid identity" },
  { feature: "Windows Server", description: "Azure Hybrid Benefit: use existing Windows licenses in Azure" },
  { feature: "SQL Server", description: "Azure Hybrid Benefit for SQL, plus easy migration paths" },
  { feature: "Power Platform", description: "Power BI, Power Apps, Power Automate integrate with Azure" },
  { feature: "Dynamics 365", description: "Enterprise apps running on Azure infrastructure" },
  { feature: "GitHub", description: "Microsoft owns GitHub — deep integration with Azure DevOps" },
  { feature: "Visual Studio", description: "First-class Azure tooling in Visual Studio and VS Code" },
];

// ========== GCP DEEP DIVE ==========
const gcpServiceCategories = [
  {
    category: "Compute",
    color: "#4285f4",
    icon: "🖥️",
    services: [
      { name: "Compute Engine", fullName: "Google Compute Engine", description: "Virtual machines running on Google's infrastructure with custom machine types.", keyFeatures: "Preemptible VMs (80% discount), custom machine types, live migration, confidential VMs", useCase: "Web servers, batch processing, ML training, Windows/Linux workloads" },
      { name: "Cloud Functions", fullName: "Google Cloud Functions", description: "Event-driven serverless compute for building and connecting cloud services.", keyFeatures: "2nd gen (Cloud Run-based), event triggers, 60-min timeout, VPC connector", useCase: "Webhooks, real-time data processing, IoT backends, microservices" },
      { name: "GKE", fullName: "Google Kubernetes Engine", description: "Managed Kubernetes — GCP invented Kubernetes, so GKE is the gold standard.", keyFeatures: "Autopilot mode, multi-cluster management, Anthos, release channels", useCase: "Microservices, ML pipelines, CI/CD, multi-cloud with Anthos" },
      { name: "Cloud Run", fullName: "Google Cloud Run", description: "Fully managed serverless containers — deploy containers without managing infrastructure.", keyFeatures: "Scale to zero, any language/library, request-based billing, Cloud Run Jobs", useCase: "APIs, web apps, background jobs, event-driven processing" },
      { name: "App Engine", fullName: "Google App Engine", description: "Fully managed PaaS for building scalable web applications.", keyFeatures: "Standard (sandbox) & Flexible (Docker) environments, auto-scaling, traffic splitting", useCase: "Web applications, mobile backends, APIs" },
      { name: "Cloud Batch", fullName: "Google Cloud Batch", description: "Fully managed batch processing at any scale.", keyFeatures: "Job scheduling, GPU support, Spot VMs integration, container support", useCase: "Scientific computing, VFX rendering, genomics, financial modeling" },
    ]
  },
  {
    category: "Storage",
    color: "#34a853",
    icon: "💾",
    services: [
      { name: "Cloud Storage", fullName: "Google Cloud Storage", description: "Object storage with global edge-caching and multiple storage classes.", keyFeatures: "Multi-regional/Regional/Nearline/Coldline/Archive classes, signed URLs, versioning", useCase: "Data lakes, backups, content distribution, ML training data" },
      { name: "Persistent Disk", fullName: "Google Persistent Disk", description: "Block storage for VMs with automatic encryption and snapshots.", keyFeatures: "SSD/HDD options, regional disks (HA), snapshots, resize online", useCase: "VM boot disks, databases, enterprise applications" },
      { name: "Filestore", fullName: "Google Cloud Filestore", description: "Managed NFS file storage for applications requiring a file system interface.", keyFeatures: "Basic/High Scale/Enterprise tiers, multi-share support, snapshots", useCase: "Content management, web serving, shared storage for GKE" },
      { name: "Cloud Storage Nearline/Coldline", fullName: "Archive Storage Classes", description: "Low-cost archive storage for infrequently accessed data.", keyFeatures: "Nearline (monthly), Coldline (quarterly), Archive (yearly) access patterns", useCase: "Long-term backups, compliance archives, disaster recovery" },
      { name: "Transfer Service", fullName: "Storage Transfer Service", description: "Transfer data from AWS S3, Azure, or other sources to Cloud Storage.", keyFeatures: "Scheduled transfers, bandwidth management, integrity validation", useCase: "Cloud migration, data synchronization, multi-cloud workflows" },
    ]
  },
  {
    category: "Database",
    color: "#ea4335",
    icon: "🗄️",
    services: [
      { name: "Cloud SQL", fullName: "Google Cloud SQL", description: "Fully managed MySQL, PostgreSQL, and SQL Server databases.", keyFeatures: "Automated backups, read replicas, high availability, Cloud SQL Auth Proxy", useCase: "Web applications, CMS, traditional SQL workloads" },
      { name: "Cloud Spanner", fullName: "Google Cloud Spanner", description: "Globally distributed, horizontally scalable relational database with strong consistency.", keyFeatures: "99.999% SLA, automatic sharding, SQL + ACID at scale", useCase: "Global financial systems, gaming, inventory management" },
      { name: "Firestore", fullName: "Google Cloud Firestore", description: "NoSQL document database with real-time sync and offline support.", keyFeatures: "Real-time listeners, offline mode, automatic scaling, Firebase integration", useCase: "Mobile apps, real-time collaboration, user profiles" },
      { name: "Bigtable", fullName: "Google Cloud Bigtable", description: "Petabyte-scale, low-latency NoSQL database for analytical and operational workloads.", keyFeatures: "Single-digit ms latency, HBase compatible, autoscaling", useCase: "IoT time-series, ad tech, financial data, personalization" },
      { name: "BigQuery", fullName: "Google BigQuery", description: "Serverless, highly scalable data warehouse with built-in ML capabilities.", keyFeatures: "Serverless, separation of storage/compute, BigQuery ML, BI Engine", useCase: "Data warehousing, analytics, ML, real-time dashboards" },
      { name: "Memorystore", fullName: "Google Cloud Memorystore", description: "Fully managed Redis and Memcached for in-memory data store.", keyFeatures: "Sub-millisecond latency, 300GB capacity, automatic failover", useCase: "Caching, session management, gaming leaderboards" },
    ]
  },
  {
    category: "Networking",
    color: "#fbbc04",
    icon: "🌐",
    services: [
      { name: "VPC", fullName: "Virtual Private Cloud", description: "Global virtual network spanning all regions without cross-region charges.", keyFeatures: "Global by default, Shared VPC, VPC peering, Private Google Access", useCase: "All workloads — foundation of GCP networking" },
      { name: "Cloud CDN", fullName: "Google Cloud CDN", description: "Content delivery network using Google's global edge network.", keyFeatures: "Same network as YouTube/Gmail, signed URLs, cache invalidation", useCase: "Web acceleration, video streaming, API caching" },
      { name: "Cloud DNS", fullName: "Google Cloud DNS", description: "Scalable, reliable DNS serving from Google's global network.", keyFeatures: "100% SLA, DNSSEC, private zones, DNS policies", useCase: "Domain management, private DNS, hybrid connectivity" },
      { name: "Cloud Load Balancing", fullName: "Google Cloud Load Balancing", description: "Global load balancing with single anycast IP — no pre-warming needed.", keyFeatures: "Global external (HTTP/TCP), regional, internal, traffic management", useCase: "High availability, global apps, auto-scaling, traffic steering" },
      { name: "Cloud Interconnect", fullName: "Google Cloud Interconnect", description: "Dedicated or partner connections to GCP for hybrid cloud.", keyFeatures: "Dedicated (10-200 Gbps), Partner (50 Mbps-10 Gbps), lower egress costs", useCase: "Hybrid connectivity, data migration, low-latency access" },
      { name: "Cloud Armor", fullName: "Google Cloud Armor", description: "DDoS protection and WAF for applications using global load balancing.", keyFeatures: "Managed rules (OWASP), custom rules, rate limiting, adaptive protection", useCase: "DDoS mitigation, WAF, bot management, geo-blocking" },
    ]
  },
  {
    category: "Security & Identity",
    color: "#ea4335",
    icon: "🔐",
    services: [
      { name: "IAM", fullName: "Identity and Access Management", description: "Fine-grained access control for GCP resources.", keyFeatures: "Predefined roles, custom roles, conditions, recommender, policy analyzer", useCase: "Access control, least privilege, compliance" },
      { name: "Identity Platform", fullName: "Google Identity Platform", description: "Add authentication to apps with support for multiple identity providers.", keyFeatures: "Multi-factor auth, social login, SAML/OIDC, blocking functions", useCase: "User authentication, B2C apps, migration from Firebase Auth" },
      { name: "Cloud KMS", fullName: "Cloud Key Management Service", description: "Manage cryptographic keys for cloud services.", keyFeatures: "HSM-backed keys, external key manager, automatic rotation, Cloud EKM", useCase: "Encryption key management, BYOK, regulatory compliance" },
      { name: "Secret Manager", fullName: "Google Secret Manager", description: "Store and manage sensitive data like API keys, passwords, and certificates.", keyFeatures: "Versioning, automatic rotation, IAM integration, audit logging", useCase: "Secrets management, configuration, certificate storage" },
      { name: "Security Command Center", fullName: "Security Command Center", description: "Centralized security and risk management platform for GCP.", keyFeatures: "Asset discovery, vulnerability scanning, threat detection, compliance", useCase: "Security posture management, compliance reporting, threat detection" },
      { name: "BeyondCorp Enterprise", fullName: "BeyondCorp Enterprise", description: "Zero-trust access solution based on Google's internal security model.", keyFeatures: "Context-aware access, threat protection, data protection, VPN-less access", useCase: "Zero-trust security, remote workforce, secure app access" },
    ]
  },
  {
    category: "AI & Machine Learning",
    color: "#673ab7",
    icon: "🤖",
    services: [
      { name: "Vertex AI", fullName: "Google Vertex AI", description: "Unified ML platform to build, deploy, and scale ML models.", keyFeatures: "AutoML, custom training, model registry, feature store, MLOps", useCase: "Custom ML models, MLOps pipelines, enterprise AI" },
      { name: "Gemini", fullName: "Google Gemini", description: "Google's most capable AI model family for multimodal understanding.", keyFeatures: "Multimodal (text, images, video, audio), 1M+ token context, function calling", useCase: "Generative AI apps, chatbots, content generation, code assistance" },
      { name: "Document AI", fullName: "Google Document AI", description: "Extract structured data from documents using pre-trained or custom models.", keyFeatures: "Invoice, receipt, contract processors, custom models, human-in-the-loop", useCase: "Document processing, invoice automation, contract analysis" },
      { name: "Vision AI", fullName: "Google Cloud Vision", description: "Image analysis with pre-trained models for object detection, OCR, and more.", keyFeatures: "Label detection, OCR, face detection, SafeSearch, product search", useCase: "Image classification, content moderation, visual search" },
      { name: "Speech-to-Text/Text-to-Speech", fullName: "Cloud Speech & TTS", description: "Convert audio to text and text to natural speech.", keyFeatures: "125+ languages, real-time streaming, speaker diarization, WaveNet voices", useCase: "Transcription, voice assistants, accessibility, call analytics" },
      { name: "Translation AI", fullName: "Cloud Translation", description: "Dynamic translation supporting 130+ languages.", keyFeatures: "AutoML Translation (custom), glossaries, batch translation, adaptive translation", useCase: "Website localization, document translation, customer support" },
    ]
  },
  {
    category: "DevOps & Management",
    color: "#0097a7",
    icon: "⚙️",
    services: [
      { name: "Cloud Build", fullName: "Google Cloud Build", description: "Serverless CI/CD platform for building, testing, and deploying.", keyFeatures: "120 free build-minutes/day, custom workers, private pools, triggers", useCase: "CI/CD pipelines, container builds, automated testing" },
      { name: "Cloud Deploy", fullName: "Google Cloud Deploy", description: "Managed continuous delivery to GKE and Cloud Run.", keyFeatures: "Delivery pipelines, canary deployments, rollbacks, approval gates", useCase: "CD for Kubernetes, progressive delivery, release management" },
      { name: "Cloud Monitoring", fullName: "Google Cloud Monitoring", description: "Full-stack monitoring with metrics, dashboards, and alerting.", keyFeatures: "Custom metrics, uptime checks, SLO monitoring, MQL query language", useCase: "Infrastructure monitoring, application monitoring, SLI/SLO tracking" },
      { name: "Cloud Logging", fullName: "Google Cloud Logging", description: "Real-time log management and analysis at scale.", keyFeatures: "Log Explorer, log-based metrics, log sinks, Error Reporting integration", useCase: "Centralized logging, debugging, compliance, audit trails" },
      { name: "Terraform on GCP", fullName: "Terraform / Deployment Manager", description: "Infrastructure as Code using Terraform (recommended) or Deployment Manager.", keyFeatures: "GCP provider, Cloud Foundation Toolkit, blueprints, modules", useCase: "IaC, environment replication, compliance as code" },
      { name: "Cloud Trace", fullName: "Google Cloud Trace", description: "Distributed tracing for applications to find latency bottlenecks.", keyFeatures: "Automatic instrumentation, latency analysis, integration with OpenTelemetry", useCase: "Performance debugging, microservices tracing, latency optimization" },
    ]
  },
  {
    category: "Data Analytics",
    color: "#ff5722",
    icon: "📊",
    services: [
      { name: "BigQuery", fullName: "Google BigQuery", description: "Serverless enterprise data warehouse with built-in ML and BI.", keyFeatures: "Serverless, real-time analytics, BigQuery ML, BI Engine, data sharing", useCase: "Data warehousing, analytics, dashboards, ML on data" },
      { name: "Dataflow", fullName: "Google Cloud Dataflow", description: "Unified stream and batch data processing based on Apache Beam.", keyFeatures: "Autoscaling, exactly-once processing, templates, Dataflow Prime", useCase: "ETL, real-time analytics, event processing, ML pipelines" },
      { name: "Dataproc", fullName: "Google Cloud Dataproc", description: "Managed Spark and Hadoop for big data processing.", keyFeatures: "90-second cluster spin-up, preemptible VMs, autoscaling, Dataproc Serverless", useCase: "Spark/Hadoop workloads, data science, migration from on-prem Hadoop" },
      { name: "Pub/Sub", fullName: "Google Cloud Pub/Sub", description: "Real-time messaging service for event-driven architectures.", keyFeatures: "Global by default, exactly-once delivery, push/pull, dead-letter queues", useCase: "Event streaming, microservices integration, data ingestion" },
      { name: "Looker", fullName: "Google Looker", description: "Enterprise BI and embedded analytics with semantic modeling.", keyFeatures: "LookML modeling, embedded analytics, data actions, Looker Studio integration", useCase: "Business intelligence, embedded analytics, data apps" },
      { name: "Dataplex", fullName: "Google Dataplex", description: "Intelligent data fabric for unified data management and governance.", keyFeatures: "Data lakes, data mesh, data quality, data lineage, data catalog", useCase: "Data governance, data mesh, unified analytics" },
    ]
  },
];

const gcpGlobalInfrastructure = {
  regions: "40+ regions worldwide",
  zones: "120+ zones across all regions",
  edgeLocations: "187+ network edge locations",
  submarineCables: "Private global fiber network with 20+ subsea cables",
  premiumNetwork: "Premium tier uses Google's private backbone",
  carbonNeutral: "Carbon neutral since 2007, 100% renewable energy",
};

const gcpFreeTierHighlights = [
  { service: "Compute Engine", offer: "1 e2-micro instance/month (US regions)", duration: "Always free" },
  { service: "Cloud Storage", offer: "5 GB Regional Storage", duration: "Always free" },
  { service: "BigQuery", offer: "1 TB queries/month, 10 GB storage", duration: "Always free" },
  { service: "Cloud Functions", offer: "2 million invocations/month", duration: "Always free" },
  { service: "Firestore", offer: "1 GB storage, 50K reads/day", duration: "Always free" },
  { service: "Cloud Run", offer: "2 million requests/month", duration: "Always free" },
  { service: "Vision AI", offer: "1,000 units/month", duration: "Always free" },
  { service: "Cloud Build", offer: "120 build-minutes/day", duration: "Always free" },
];

const gcpDifferentiators = [
  { feature: "Data & Analytics Leadership", description: "BigQuery pioneered serverless data warehouses; GCP excels at analytics and ML" },
  { feature: "Kubernetes Originator", description: "Google created Kubernetes — GKE is considered the best managed K8s service" },
  { feature: "Global Network", description: "Premium tier uses Google's private fiber backbone (same as Google Search/YouTube)" },
  { feature: "AI/ML Innovation", description: "TensorFlow, JAX, Gemini — Google leads in AI research and tooling" },
  { feature: "Sustainability", description: "Carbon neutral since 2007, matches 100% energy with renewable sources" },
  { feature: "Pricing Innovation", description: "Sustained use discounts (automatic), committed use discounts, preemptible VMs" },
  { feature: "Live Migration", description: "VMs can be moved between hosts with zero downtime during maintenance" },
  { feature: "Open Source Friendly", description: "Strong support for open source: Kubernetes, TensorFlow, gRPC, Istio" },
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

// ========== OBSERVABILITY & SRE ==========
const observabilitySignals = [
  { signal: "Metrics", description: "Numeric time-series measurements of system behavior", examples: "Latency, error rate, CPU, queue depth", value: "Capacity planning, SLO tracking, trend analysis" },
  { signal: "Logs", description: "Structured records of events and state changes", examples: "HTTP access logs, audit logs, application events", value: "Forensics, debugging, compliance trails" },
  { signal: "Traces", description: "End-to-end request paths across distributed systems", examples: "Trace IDs across API gateway, services, and databases", value: "Bottleneck detection and latency root cause" },
  { signal: "Profiles", description: "Low-level performance samples for CPU, memory, and I/O", examples: "CPU flame graphs, heap profiles, eBPF traces", value: "Optimization of hot paths and resource usage" },
];

const availabilityTargets = [
  { tier: "99.5%", downtime: "3h 39m / month", useCase: "Internal tools, low-risk workloads", guidance: "Single region with good backup practices" },
  { tier: "99.9%", downtime: "43m 49s / month", useCase: "Customer-facing apps, SaaS MVPs", guidance: "Multi-AZ design, automated failover" },
  { tier: "99.95%", downtime: "21m 54s / month", useCase: "Payments, critical services", guidance: "Multi-AZ + active monitoring + playbooks" },
  { tier: "99.99%", downtime: "4m 23s / month", useCase: "Global platforms, regulated systems", guidance: "Multi-region, active-active or hot standby" },
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

// ========== DATA GOVERNANCE & LIFECYCLE ==========
const dataGovernancePractices = [
  { practice: "Classification & Tagging", description: "Label data by sensitivity (public, internal, confidential, regulated)", tools: "AWS Macie, Azure Purview, Google Cloud DLP", outcome: "Drives access control and retention policies" },
  { practice: "Data Residency", description: "Keep data in specific regions for legal or contractual reasons", tools: "Region policies, org-level constraints, data zoning", outcome: "Meets regulatory and customer requirements" },
  { practice: "Access Governance", description: "Enforce least privilege with periodic reviews and approvals", tools: "IAM, Access Analyzer, PIM/PAM workflows", outcome: "Reduces unauthorized access risk" },
  { practice: "Encryption & Key Management", description: "Encrypt at rest/in transit and control keys centrally", tools: "KMS, HSMs, customer-managed keys", outcome: "Protects data from exposure and theft" },
  { practice: "Retention & Disposal", description: "Define how long data is kept and how it is deleted", tools: "Lifecycle policies, legal holds, secure wipe", outcome: "Avoids compliance and storage cost issues" },
  { practice: "Auditability", description: "Track who accessed data and when, with tamper-evident logs", tools: "CloudTrail, Azure Monitor, Cloud Logging", outcome: "Supports incident response and compliance audits" },
];

const dataLifecycleStages = [
  { stage: "Ingest", goal: "Validate, sanitize, and encrypt data on entry", controls: "Schema checks, rate limits, TLS", services: "API Gateway, Event Hub, Pub/Sub" },
  { stage: "Store", goal: "Protect data at rest with access control", controls: "KMS, bucket policies, private endpoints", services: "S3, Blob Storage, Cloud Storage" },
  { stage: "Process", goal: "Use isolated compute with minimal permissions", controls: "IAM roles, network segmentation, temp data hygiene", services: "EMR, Dataproc, Databricks" },
  { stage: "Share", goal: "Control distribution and reduce data exposure", controls: "Tokenization, data contracts, row-level security", services: "Lake Formation, BigQuery, Synapse" },
  { stage: "Archive", goal: "Store long-term data cheaply with policy controls", controls: "Retention rules, legal holds, immutable storage", services: "Glacier, Archive Storage" },
  { stage: "Dispose", goal: "Remove data safely when retention ends", controls: "Secure delete, key revocation, audit trails", services: "Object lock expiration, lifecycle delete" },
];

// ========== WELL-ARCHITECTED FRAMEWORK ========== 
const wellArchitectedPillars = [
  {
    pillar: "Operational Excellence",
    description: "Run and monitor systems to deliver business value and continually improve processes",
    keyPrinciples: ["Perform operations as code", "Make frequent, small, reversible changes", "Anticipate failure", "Learn from operational events"],
    awsTools: "CloudWatch, CloudFormation, Systems Manager, X-Ray",
    questions: "How do you manage and automate changes? How do you respond to unplanned events?",
    color: "#3b82f6",
    icon: "⚙️"
  },
  {
    pillar: "Security",
    description: "Protect information, systems, and assets while delivering business value through risk assessment",
    keyPrinciples: ["Implement strong identity foundation", "Enable traceability", "Apply security at all layers", "Automate security best practices", "Protect data in transit and at rest"],
    awsTools: "IAM, KMS, CloudTrail, Security Hub, GuardDuty, WAF",
    questions: "How do you manage identities? How do you detect and investigate security events?",
    color: "#ef4444",
    icon: "🔒"
  },
  {
    pillar: "Reliability",
    description: "Ensure a workload performs its intended function correctly and consistently",
    keyPrinciples: ["Automatically recover from failure", "Test recovery procedures", "Scale horizontally", "Stop guessing capacity", "Manage change through automation"],
    awsTools: "Auto Scaling, Multi-AZ, Route 53, Backup, Elastic Load Balancing",
    questions: "How do you manage service quotas and constraints? How do you implement change management?",
    color: "#22c55e",
    icon: "🛡️"
  },
  {
    pillar: "Performance Efficiency",
    description: "Use computing resources efficiently to meet requirements and maintain that efficiency as demand changes",
    keyPrinciples: ["Democratize advanced technologies", "Go global in minutes", "Use serverless architectures", "Experiment more often", "Consider mechanical sympathy"],
    awsTools: "Lambda, CloudFront, ElastiCache, Auto Scaling, Compute Optimizer",
    questions: "How do you select appropriate resource types? How do you monitor resources to ensure performance?",
    color: "#f59e0b",
    icon: "⚡"
  },
  {
    pillar: "Cost Optimization",
    description: "Avoid unnecessary costs and run systems to deliver business value at the lowest price point",
    keyPrinciples: ["Implement cloud financial management", "Adopt a consumption model", "Measure overall efficiency", "Stop spending on undifferentiated heavy lifting", "Analyze and attribute expenditure"],
    awsTools: "Cost Explorer, Budgets, Savings Plans, Reserved Instances, Compute Optimizer",
    questions: "How do you implement cloud financial management? How do you monitor usage and cost?",
    color: "#8b5cf6",
    icon: "💰"
  },
  {
    pillar: "Sustainability",
    description: "Minimize environmental impacts of running cloud workloads",
    keyPrinciples: ["Understand your impact", "Establish sustainability goals", "Maximize utilization", "Use efficient hardware and software", "Reduce downstream impact"],
    awsTools: "Customer Carbon Footprint Tool, Graviton processors, Spot Instances",
    questions: "How do you select regions to support your sustainability goals? How do you take advantage of user behavior patterns?",
    color: "#14b8a6",
    icon: "🌱"
  },
];

// ========== CLOUD MIGRATION STRATEGIES (6 Rs) ==========
const migrationStrategies = [
  {
    strategy: "Rehost",
    nickname: "Lift and Shift",
    description: "Move applications to the cloud without changes. Fastest migration path.",
    effort: "Low",
    cloudBenefit: "Low-Medium",
    bestFor: "Legacy apps, tight deadlines, large-scale migrations",
    tools: "AWS Migration Hub, Azure Migrate, Google Migrate for Compute Engine",
    example: "Move on-prem VMs directly to EC2 instances",
    color: "#3b82f6"
  },
  {
    strategy: "Replatform",
    nickname: "Lift, Tinker, and Shift",
    description: "Make a few cloud optimizations without changing core architecture. Balance speed and optimization.",
    effort: "Low-Medium",
    cloudBenefit: "Medium",
    bestFor: "Apps that can benefit from managed services with minimal changes",
    tools: "AWS Elastic Beanstalk, Azure App Service, Google App Engine",
    example: "Migrate database to RDS instead of managing your own MySQL on EC2",
    color: "#8b5cf6"
  },
  {
    strategy: "Repurchase",
    nickname: "Drop and Shop",
    description: "Move to a different product, typically SaaS. Replace custom software with commercial solutions.",
    effort: "Medium",
    cloudBenefit: "Medium-High",
    bestFor: "Commodity applications where SaaS alternatives exist",
    tools: "Salesforce, Workday, ServiceNow, Microsoft 365",
    example: "Replace on-prem email server with Microsoft 365 or Google Workspace",
    color: "#22c55e"
  },
  {
    strategy: "Refactor",
    nickname: "Re-architect",
    description: "Re-imagine how the application is architected using cloud-native features. Most effort, most benefit.",
    effort: "High",
    cloudBenefit: "High",
    bestFor: "Apps needing scalability, new features, or modernization",
    tools: "Containers (EKS/AKS/GKE), Serverless (Lambda), Microservices",
    example: "Break monolith into microservices running on Kubernetes",
    color: "#f59e0b"
  },
  {
    strategy: "Retire",
    nickname: "Decommission",
    description: "Identify IT assets that are no longer useful and can be turned off. Reduce portfolio complexity.",
    effort: "Low",
    cloudBenefit: "Cost savings",
    bestFor: "Redundant, outdated, or unused applications",
    tools: "Application portfolio analysis, dependency mapping",
    example: "Shut down legacy reporting system replaced by modern BI tool",
    color: "#6b7280"
  },
  {
    strategy: "Retain",
    nickname: "Revisit Later",
    description: "Keep certain applications on-premises. Not everything needs to move to cloud.",
    effort: "None",
    cloudBenefit: "N/A",
    bestFor: "Recently upgraded apps, compliance restrictions, low ROI migrations",
    tools: "Hybrid connectivity (Direct Connect, ExpressRoute, VPN)",
    example: "Keep mainframe systems on-prem with hybrid connectivity",
    color: "#ef4444"
  },
];

// ========== DISASTER RECOVERY STRATEGIES ==========
const drStrategies = [
  {
    strategy: "Backup & Restore",
    rpo: "Hours",
    rto: "24+ hours",
    cost: "💰",
    description: "Backup data to cloud storage. Restore infrastructure from scratch when needed.",
    implementation: "Regular backups to S3/Blob, AMIs for quick instance recreation",
    bestFor: "Non-critical systems, cost-sensitive workloads",
    color: "#6b7280"
  },
  {
    strategy: "Pilot Light",
    rpo: "Minutes",
    rto: "Hours",
    cost: "💰💰",
    description: "Keep core components running at minimum capacity. Scale up when disaster occurs.",
    implementation: "Database replication running, AMIs ready, minimal compute running",
    bestFor: "Critical databases, applications with some downtime tolerance",
    color: "#3b82f6"
  },
  {
    strategy: "Warm Standby",
    rpo: "Minutes",
    rto: "Minutes",
    cost: "💰💰💰",
    description: "Scaled-down but fully functional copy of production environment always running.",
    implementation: "Reduced capacity in DR region, ready to scale up immediately",
    bestFor: "Business-critical applications requiring faster recovery",
    color: "#f59e0b"
  },
  {
    strategy: "Multi-Site Active/Active",
    rpo: "Near Zero",
    rto: "Near Zero",
    cost: "💰💰💰💰",
    description: "Full production environment in multiple regions, traffic split between them.",
    implementation: "Global load balancing, real-time data synchronization, both sites active",
    bestFor: "Mission-critical applications with zero-downtime requirements",
    color: "#22c55e"
  },
];

// ========== CLOUD CERTIFICATIONS ==========
const cloudCertifications = [
  {
    provider: "AWS",
    color: "#ff9900",
    certs: [
      { name: "Cloud Practitioner", level: "Foundational", duration: "1-2 months", prereq: "None", focus: "Cloud concepts, billing, support" },
      { name: "Solutions Architect Associate", level: "Associate", duration: "2-3 months", prereq: "Cloud Practitioner recommended", focus: "Designing distributed systems" },
      { name: "Developer Associate", level: "Associate", duration: "2-3 months", prereq: "Cloud Practitioner recommended", focus: "Building cloud applications" },
      { name: "SysOps Administrator Associate", level: "Associate", duration: "2-3 months", prereq: "Cloud Practitioner recommended", focus: "Operations and deployment" },
      { name: "Solutions Architect Professional", level: "Professional", duration: "3-6 months", prereq: "SA Associate", focus: "Complex architectures" },
      { name: "Security Specialty", level: "Specialty", duration: "2-4 months", prereq: "Associate cert", focus: "Security controls and compliance" },
    ]
  },
  {
    provider: "Azure",
    color: "#0078d4",
    certs: [
      { name: "AZ-900 Fundamentals", level: "Foundational", duration: "1-2 months", prereq: "None", focus: "Cloud concepts, Azure services" },
      { name: "AZ-104 Administrator", level: "Associate", duration: "2-3 months", prereq: "AZ-900 recommended", focus: "Managing Azure resources" },
      { name: "AZ-204 Developer", level: "Associate", duration: "2-3 months", prereq: "AZ-900 recommended", focus: "Developing Azure solutions" },
      { name: "AZ-305 Solutions Architect", level: "Expert", duration: "3-6 months", prereq: "AZ-104", focus: "Designing Azure solutions" },
      { name: "AZ-500 Security Engineer", level: "Associate", duration: "2-4 months", prereq: "AZ-104 recommended", focus: "Security operations" },
      { name: "SC-900 Security Fundamentals", level: "Foundational", duration: "1-2 months", prereq: "None", focus: "Security, compliance, identity" },
    ]
  },
  {
    provider: "GCP",
    color: "#4285f4",
    certs: [
      { name: "Cloud Digital Leader", level: "Foundational", duration: "1-2 months", prereq: "None", focus: "Cloud concepts, GCP overview" },
      { name: "Associate Cloud Engineer", level: "Associate", duration: "2-3 months", prereq: "CDL recommended", focus: "Deploying applications, monitoring" },
      { name: "Professional Cloud Architect", level: "Professional", duration: "3-6 months", prereq: "ACE recommended", focus: "Designing enterprise solutions" },
      { name: "Professional Cloud Developer", level: "Professional", duration: "2-4 months", prereq: "ACE recommended", focus: "Building scalable applications" },
      { name: "Professional Cloud Security Engineer", level: "Professional", duration: "2-4 months", prereq: "ACE recommended", focus: "Security controls and policies" },
      { name: "Professional Cloud DevOps Engineer", level: "Professional", duration: "2-4 months", prereq: "ACE recommended", focus: "CI/CD and SRE practices" },
    ]
  },
];

// ========== FINOPS / COST OPTIMIZATION PRACTICES ==========
const costOptimizationPractices = [
  { practice: "Right-sizing", description: "Match instance types to actual workload requirements, not peak capacity", savings: "20-40%", tools: "AWS Compute Optimizer, Azure Advisor, GCP Recommender", implementation: "Review utilization metrics, downsize over-provisioned instances" },
  { practice: "Reserved Capacity", description: "Commit to 1-3 year terms for predictable workloads", savings: "30-72%", tools: "AWS Reserved Instances, Azure Reservations, GCP Committed Use", implementation: "Analyze usage patterns, commit for steady-state workloads" },
  { practice: "Spot/Preemptible Instances", description: "Use spare capacity at steep discounts for fault-tolerant workloads", savings: "60-90%", tools: "AWS Spot, Azure Spot VMs, GCP Preemptible/Spot VMs", implementation: "Design for interruption, use for batch processing, CI/CD" },
  { practice: "Auto Scaling", description: "Automatically adjust capacity based on demand", savings: "Variable", tools: "AWS Auto Scaling, Azure VMSS, GCP MIGs", implementation: "Set scaling policies based on metrics, schedule for known patterns" },
  { practice: "Storage Tiering", description: "Move infrequently accessed data to cheaper storage classes", savings: "40-80%", tools: "S3 Intelligent-Tiering, Azure Cool/Archive, GCP Nearline/Coldline", implementation: "Implement lifecycle policies, use intelligent tiering" },
  { practice: "Idle Resource Cleanup", description: "Identify and terminate unused resources", savings: "15-30%", tools: "AWS Trusted Advisor, Azure Advisor, custom scripts", implementation: "Regular audits, automated cleanup, dev environment schedules" },
  { practice: "Savings Plans", description: "Flexible commitment model for compute usage", savings: "20-66%", tools: "AWS Savings Plans, Azure Savings Plans for Compute", implementation: "Analyze compute spend, commit to hourly spend level" },
  { practice: "FinOps Culture", description: "Make cloud costs visible and accountable to engineering teams", savings: "Organization-wide", tools: "AWS Cost Explorer, Azure Cost Management, GCP Billing", implementation: "Cost allocation tags, team budgets, regular reviews" },
];

// ========== INSTANCE TYPE CATEGORIES ==========
const instanceCategories = [
  { category: "General Purpose", awsTypes: "t3, t4g, m5, m6i, m7g", azureTypes: "B, D, Dv5", gcpTypes: "e2, n2, n2d", useCase: "Web servers, small databases, dev/test environments", characteristics: "Balanced compute, memory, networking" },
  { category: "Compute Optimized", awsTypes: "c5, c6i, c7g", azureTypes: "F, Fsv2", gcpTypes: "c2, c2d, h3", useCase: "High-performance computing, batch processing, gaming servers", characteristics: "High CPU-to-memory ratio, best compute price/performance" },
  { category: "Memory Optimized", awsTypes: "r5, r6i, x2idn", azureTypes: "E, Ev5, M", gcpTypes: "m2, m3", useCase: "In-memory databases, real-time analytics, SAP HANA", characteristics: "High memory-to-CPU ratio, up to 24TB RAM" },
  { category: "Storage Optimized", awsTypes: "i3, i4i, d3", azureTypes: "L", gcpTypes: "z3", useCase: "Data warehousing, distributed file systems, log processing", characteristics: "High sequential read/write, NVMe SSD storage" },
  { category: "Accelerated Computing", awsTypes: "p4, p5, g5, inf2", azureTypes: "NC, ND, NV", gcpTypes: "a2, g2", useCase: "Machine learning, graphics rendering, video encoding", characteristics: "GPU/TPU attached, CUDA/tensor cores" },
  { category: "ARM-based", awsTypes: "t4g, m6g, c7g, r7g", azureTypes: "Dpsv5, Epsv5", gcpTypes: "t2a", useCase: "Cost-effective workloads, containerized apps, web servers", characteristics: "Up to 40% better price/performance, energy efficient" },
];

// ========== KUBERNETES CONCEPTS (EXPANDED) ==========
const kubernetesConcepts = [
  { concept: "Pod", description: "Smallest deployable unit containing one or more containers that share storage and network", keyPoints: "Ephemeral, scheduled on nodes, share localhost", icon: "🫛" },
  { concept: "Deployment", description: "Manages ReplicaSets and provides declarative updates for Pods", keyPoints: "Rolling updates, rollbacks, scaling", icon: "🚀" },
  { concept: "Service", description: "Stable network endpoint to access a set of Pods", keyPoints: "ClusterIP, NodePort, LoadBalancer types", icon: "🔗" },
  { concept: "Ingress", description: "Manages external access to services, typically HTTP/HTTPS", keyPoints: "Path-based routing, TLS termination, virtual hosts", icon: "🚪" },
  { concept: "ConfigMap", description: "Store non-confidential configuration data as key-value pairs", keyPoints: "Decouple config from images, mount as volumes or env vars", icon: "📋" },
  { concept: "Secret", description: "Store sensitive information like passwords, tokens, keys", keyPoints: "Base64 encoded, can be encrypted at rest", icon: "🔐" },
  { concept: "Namespace", description: "Virtual cluster within a physical cluster for resource isolation", keyPoints: "Separate environments, resource quotas, RBAC", icon: "📁" },
  { concept: "Persistent Volume", description: "Storage resource in the cluster with lifecycle independent of Pods", keyPoints: "PV, PVC, StorageClass, dynamic provisioning", icon: "💾" },
  { concept: "DaemonSet", description: "Ensures a copy of a Pod runs on all (or selected) nodes", keyPoints: "Logging agents, monitoring, node-level services", icon: "👻" },
  { concept: "StatefulSet", description: "Manages stateful applications with persistent storage and stable identities", keyPoints: "Ordered deployment, stable network IDs, persistent storage", icon: "📊" },
  { concept: "Horizontal Pod Autoscaler", description: "Automatically scales Pod count based on CPU/memory or custom metrics", keyPoints: "Target utilization, min/max replicas, cooldown", icon: "📈" },
  { concept: "Network Policy", description: "Firewall rules for Pods controlling ingress/egress traffic", keyPoints: "Pod selectors, namespace selectors, port rules", icon: "🛡️" },
];

const ACCENT_COLOR = "#0ea5e9";
const QUIZ_QUESTION_COUNT = 10;

const selectRandomQuestions = (questions: QuizQuestion[], count: number) =>
  [...questions].sort(() => Math.random() - 0.5).slice(0, count);

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Fundamentals",
    question: "Cloud computing is best described as:",
    options: [
      "On-demand access to shared computing resources over the internet",
      "Buying and owning physical servers",
      "Running only desktop applications",
      "A single private data center",
    ],
    correctAnswer: 0,
    explanation: "Cloud provides on-demand resources delivered over the internet.",
  },
  {
    id: 2,
    topic: "Fundamentals",
    question: "Elasticity refers to:",
    options: [
      "Automatically scaling resources up and down",
      "Using only one server",
      "Encrypting all data",
      "Buying hardware upfront",
    ],
    correctAnswer: 0,
    explanation: "Elasticity is the ability to scale resources based on demand.",
  },
  {
    id: 3,
    topic: "Fundamentals",
    question: "Scalability focuses on:",
    options: [
      "Handling growth by adding resources",
      "Reducing latency only",
      "Using one region only",
      "Encrypting traffic",
    ],
    correctAnswer: 0,
    explanation: "Scalability is the ability to grow capacity as demand increases.",
  },
  {
    id: 4,
    topic: "Service Models",
    question: "Which model provides virtual machines and networking?",
    options: ["IaaS", "PaaS", "SaaS", "FaaS"],
    correctAnswer: 0,
    explanation: "IaaS provides infrastructure like VMs and networking.",
  },
  {
    id: 5,
    topic: "Service Models",
    question: "Which model lets you deploy code without managing servers?",
    options: ["PaaS", "IaaS", "SaaS", "Colocation"],
    correctAnswer: 0,
    explanation: "PaaS handles the platform so you focus on code.",
  },
  {
    id: 6,
    topic: "Service Models",
    question: "Which model delivers full applications to end users?",
    options: ["SaaS", "IaaS", "PaaS", "Bare metal"],
    correctAnswer: 0,
    explanation: "SaaS provides ready-to-use applications.",
  },
  {
    id: 7,
    topic: "Service Models",
    question: "Serverless computing is often referred to as:",
    options: ["FaaS", "IaaS", "SaaS", "DaaS"],
    correctAnswer: 0,
    explanation: "Serverless is commonly called Function as a Service (FaaS).",
  },
  {
    id: 8,
    topic: "Deployment Models",
    question: "A public cloud is:",
    options: [
      "Shared infrastructure operated by a provider",
      "Dedicated to a single organization only",
      "Always on-premises",
      "Air-gapped by default",
    ],
    correctAnswer: 0,
    explanation: "Public clouds are multi-tenant and provider-operated.",
  },
  {
    id: 9,
    topic: "Deployment Models",
    question: "A private cloud is:",
    options: [
      "Dedicated to one organization",
      "Shared across unrelated customers",
      "Always free to use",
      "Only for SaaS apps",
    ],
    correctAnswer: 0,
    explanation: "Private clouds are dedicated to a single organization.",
  },
  {
    id: 10,
    topic: "Deployment Models",
    question: "Hybrid cloud combines:",
    options: ["Public and private clouds", "Only public clouds", "Only private clouds", "Only edge locations"],
    correctAnswer: 0,
    explanation: "Hybrid uses both public and private environments.",
  },
  {
    id: 11,
    topic: "Deployment Models",
    question: "Multi-cloud means:",
    options: ["Using multiple cloud providers", "Using multiple regions in one provider", "Using only SaaS", "Using only on-prem"],
    correctAnswer: 0,
    explanation: "Multi-cloud spreads workloads across providers.",
  },
  {
    id: 12,
    topic: "Regions and AZs",
    question: "A cloud region is:",
    options: ["A geographic area with multiple data centers", "A single server", "A single rack", "A single VM"],
    correctAnswer: 0,
    explanation: "Regions group multiple data centers in a geographic area.",
  },
  {
    id: 13,
    topic: "Regions and AZs",
    question: "An Availability Zone (AZ) is:",
    options: ["An isolated data center within a region", "A cloud provider logo", "A single database", "A billing plan"],
    correctAnswer: 0,
    explanation: "AZs are isolated data centers within a region.",
  },
  {
    id: 14,
    topic: "Regions and AZs",
    question: "Using multiple AZs improves:",
    options: ["Availability", "Local disk speed", "Monitor resolution", "Keyboard latency"],
    correctAnswer: 0,
    explanation: "Multi-AZ setups improve resilience and availability.",
  },
  {
    id: 15,
    topic: "Shared Responsibility",
    question: "In the shared responsibility model, the provider is responsible for:",
    options: ["Infrastructure security", "Customer data classification", "Application code", "User access policy"],
    correctAnswer: 0,
    explanation: "Providers secure the infrastructure; customers secure their data and configs.",
  },
  {
    id: 16,
    topic: "Shared Responsibility",
    question: "Customers are responsible for:",
    options: ["Configuring access controls and data security", "Physical data center security", "Power and cooling", "Provider hardware"],
    correctAnswer: 0,
    explanation: "Customers manage access controls and data protections.",
  },
  {
    id: 17,
    topic: "Security",
    question: "IAM is used for:",
    options: ["Identity and access management", "Image rendering", "Network routing", "Storage replication"],
    correctAnswer: 0,
    explanation: "IAM controls identities, roles, and permissions.",
  },
  {
    id: 18,
    topic: "Security",
    question: "MFA provides:",
    options: ["Additional authentication factor", "Automatic scaling", "Network encryption only", "Disk defragmentation"],
    correctAnswer: 0,
    explanation: "MFA adds an extra authentication step.",
  },
  {
    id: 19,
    topic: "Security",
    question: "Least privilege means:",
    options: ["Grant only necessary permissions", "Grant admin to all users", "Disable logging", "Ignore audits"],
    correctAnswer: 0,
    explanation: "Least privilege limits access to what is required.",
  },
  {
    id: 20,
    topic: "Security",
    question: "Encryption at rest protects:",
    options: ["Stored data", "Network traffic only", "CPU caches only", "User sessions only"],
    correctAnswer: 0,
    explanation: "Encryption at rest secures stored data.",
  },
  {
    id: 21,
    topic: "Security",
    question: "Encryption in transit protects:",
    options: ["Data moving over networks", "Only backups", "Only disks", "Only CPU registers"],
    correctAnswer: 0,
    explanation: "In-transit encryption protects network data.",
  },
  {
    id: 22,
    topic: "Storage",
    question: "Object storage is best for:",
    options: ["Unstructured data like images and backups", "Boot disks only", "Databases only", "CPU registers"],
    correctAnswer: 0,
    explanation: "Object storage is ideal for unstructured data.",
  },
  {
    id: 23,
    topic: "Storage",
    question: "Block storage is typically used for:",
    options: ["VM disks and databases", "Static websites only", "DNS records", "Email routing"],
    correctAnswer: 0,
    explanation: "Block storage is used for VM volumes and databases.",
  },
  {
    id: 24,
    topic: "Storage",
    question: "File storage provides:",
    options: ["Shared file systems", "Object buckets only", "TCP load balancing", "User authentication"],
    correctAnswer: 0,
    explanation: "File storage provides shared file systems.",
  },
  {
    id: 25,
    topic: "Networking",
    question: "A CDN primarily improves:",
    options: ["Content delivery latency", "Database writes", "CPU frequency", "RAM speed"],
    correctAnswer: 0,
    explanation: "CDNs cache content closer to users to reduce latency.",
  },
  {
    id: 26,
    topic: "Networking",
    question: "A load balancer distributes:",
    options: ["Traffic across multiple servers", "Disk storage across volumes", "Power across racks", "Keys across users"],
    correctAnswer: 0,
    explanation: "Load balancers distribute traffic to multiple targets.",
  },
  {
    id: 27,
    topic: "Networking",
    question: "A VPC is:",
    options: ["A logically isolated virtual network", "A hardware firewall only", "A storage bucket", "A DNS record"],
    correctAnswer: 0,
    explanation: "A VPC provides a private virtual network in the cloud.",
  },
  {
    id: 28,
    topic: "Networking",
    question: "Security groups typically act as:",
    options: ["Stateful firewalls for instances", "Routing tables", "DNS resolvers", "WAF rules only"],
    correctAnswer: 0,
    explanation: "Security groups are stateful firewalls for resources.",
  },
  {
    id: 29,
    topic: "Networking",
    question: "NAT gateways are used to:",
    options: ["Allow private subnets to access the internet", "Encrypt storage", "Manage IAM users", "Monitor logs"],
    correctAnswer: 0,
    explanation: "NAT gateways provide outbound internet for private subnets.",
  },
  {
    id: 30,
    topic: "Compute",
    question: "A virtual machine is:",
    options: ["A software emulation of a physical server", "A physical rack", "A storage bucket", "A load balancer"],
    correctAnswer: 0,
    explanation: "VMs are software-based servers running on hardware.",
  },
  {
    id: 31,
    topic: "Compute",
    question: "A hypervisor is used to:",
    options: ["Host multiple VMs on one server", "Route network traffic", "Store backups", "Manage DNS zones"],
    correctAnswer: 0,
    explanation: "Hypervisors create and run virtual machines.",
  },
  {
    id: 32,
    topic: "Containers",
    question: "Containers are best described as:",
    options: ["Lightweight app packaging using shared OS kernels", "Full virtual machines", "Physical servers", "Database clusters only"],
    correctAnswer: 0,
    explanation: "Containers share the host OS kernel and package apps.",
  },
  {
    id: 33,
    topic: "Containers",
    question: "Kubernetes is used for:",
    options: ["Container orchestration", "Object storage", "Email delivery", "DNS resolution"],
    correctAnswer: 0,
    explanation: "Kubernetes manages containerized workloads.",
  },
  {
    id: 34,
    topic: "Serverless",
    question: "A common serverless concern is:",
    options: ["Cold start latency", "Lack of encryption", "No internet access", "No scalability"],
    correctAnswer: 0,
    explanation: "Serverless can introduce cold starts.",
  },
  {
    id: 35,
    topic: "Scaling",
    question: "Horizontal scaling means:",
    options: ["Adding more instances", "Increasing CPU on one instance", "Buying a bigger server only", "Reducing instances to one"],
    correctAnswer: 0,
    explanation: "Horizontal scaling adds more instances.",
  },
  {
    id: 36,
    topic: "Scaling",
    question: "Vertical scaling means:",
    options: ["Increasing resources on one instance", "Adding more instances", "Reducing memory", "Removing redundancy"],
    correctAnswer: 0,
    explanation: "Vertical scaling increases CPU/RAM on a single instance.",
  },
  {
    id: 37,
    topic: "Pricing",
    question: "On-demand pricing means:",
    options: ["Pay as you go with no long-term commitment", "Pay for a year upfront only", "Free usage", "Use only reserved capacity"],
    correctAnswer: 0,
    explanation: "On-demand is pay-as-you-go without long-term commitment.",
  },
  {
    id: 38,
    topic: "Pricing",
    question: "Reserved instances provide:",
    options: ["Discounts for commitment", "Free internet", "Free storage", "Free support always"],
    correctAnswer: 0,
    explanation: "Reservations lower cost in exchange for commitment.",
  },
  {
    id: 39,
    topic: "Pricing",
    question: "Spot instances are best for:",
    options: ["Interruptible workloads", "Mission-critical databases", "Legacy mainframes", "Single points of failure"],
    correctAnswer: 0,
    explanation: "Spot instances are low-cost but can be interrupted.",
  },
  {
    id: 40,
    topic: "Pricing",
    question: "Cloud spending is typically considered:",
    options: ["Operational expenditure (OpEx)", "Capital expenditure (CapEx)", "Fixed assets only", "Depreciation only"],
    correctAnswer: 0,
    explanation: "Cloud is usually OpEx because you pay for usage.",
  },
  {
    id: 41,
    topic: "Reliability",
    question: "RPO stands for:",
    options: ["Recovery Point Objective", "Real-time Processing Output", "Regional Provider Option", "Resource Planning Order"],
    correctAnswer: 0,
    explanation: "RPO is the maximum acceptable data loss.",
  },
  {
    id: 42,
    topic: "Reliability",
    question: "RTO stands for:",
    options: ["Recovery Time Objective", "Real-time Transfer Output", "Region Target Order", "Resource Tracking Option"],
    correctAnswer: 0,
    explanation: "RTO is the target time to restore service.",
  },
  {
    id: 43,
    topic: "Reliability",
    question: "Active-active DR means:",
    options: ["Multiple sites serving traffic simultaneously", "Only one site running", "No backups required", "Single AZ only"],
    correctAnswer: 0,
    explanation: "Active-active uses multiple sites at the same time.",
  },
  {
    id: 44,
    topic: "Reliability",
    question: "Active-passive DR means:",
    options: ["Primary site active, secondary on standby", "Both sites active always", "No failover needed", "Only local backups"],
    correctAnswer: 0,
    explanation: "Active-passive keeps a standby site ready.",
  },
  {
    id: 45,
    topic: "Security",
    question: "A WAF is used to:",
    options: ["Protect web apps from common attacks", "Store files", "Run containers", "Manage DNS"],
    correctAnswer: 0,
    explanation: "WAFs block common web attacks like SQLi and XSS.",
  },
  {
    id: 46,
    topic: "Security",
    question: "CSPM tools focus on:",
    options: ["Detecting misconfigurations", "Replacing databases", "Running containers", "Routing traffic"],
    correctAnswer: 0,
    explanation: "CSPM tools identify misconfigurations and compliance issues.",
  },
  {
    id: 47,
    topic: "Security",
    question: "CASB tools help with:",
    options: ["Controlling cloud app usage", "Encrypting CPU caches", "Replacing VPCs", "Managing GPUs"],
    correctAnswer: 0,
    explanation: "CASB tools provide visibility and control of cloud apps.",
  },
  {
    id: 48,
    topic: "Identity",
    question: "Identity federation allows:",
    options: ["Using existing identity providers for cloud access", "Disabling MFA", "Sharing root keys", "Bypassing logging"],
    correctAnswer: 0,
    explanation: "Federation integrates external identity providers.",
  },
  {
    id: 49,
    topic: "Operations",
    question: "Infrastructure as Code (IaC) enables:",
    options: ["Provisioning infrastructure using code", "Manual server setup only", "Only spreadsheets", "No version control"],
    correctAnswer: 0,
    explanation: "IaC defines infrastructure using code and automation.",
  },
  {
    id: 50,
    topic: "Operations",
    question: "CI/CD pipelines are used for:",
    options: ["Automated build, test, and deploy", "Manual patching only", "Stopping deployments", "Tracking invoices"],
    correctAnswer: 0,
    explanation: "CI/CD automates build and deployment workflows.",
  },
  {
    id: 51,
    topic: "Observability",
    question: "Observability includes:",
    options: ["Logs, metrics, and traces", "Only CPU usage", "Only storage size", "Only billing data"],
    correctAnswer: 0,
    explanation: "Observability uses logs, metrics, and traces to understand systems.",
  },
  {
    id: 52,
    topic: "Monitoring",
    question: "Cloud monitoring services are used to:",
    options: ["Collect metrics and alerts", "Run databases", "Encrypt disks", "Provision VMs only"],
    correctAnswer: 0,
    explanation: "Monitoring collects metrics and triggers alerts.",
  },
  {
    id: 53,
    topic: "Storage",
    question: "Object storage durability is typically described as:",
    options: ["Very high with multiple replicas", "Low and unreliable", "Only single copy", "Depends on client only"],
    correctAnswer: 0,
    explanation: "Object storage usually replicates data for durability.",
  },
  {
    id: 54,
    topic: "Databases",
    question: "Managed databases help by:",
    options: ["Handling backups, patching, and scaling", "Removing all costs", "Disabling encryption", "Eliminating latency"],
    correctAnswer: 0,
    explanation: "Managed databases reduce operational burden.",
  },
  {
    id: 55,
    topic: "Messaging",
    question: "A message queue is used to:",
    options: ["Decouple producers and consumers", "Store files long-term", "Provide DNS", "Replace load balancers"],
    correctAnswer: 0,
    explanation: "Queues decouple components and smooth workloads.",
  },
  {
    id: 56,
    topic: "Networking",
    question: "A VPN connection to the cloud provides:",
    options: ["Encrypted tunnel from on-prem to cloud", "Public internet access only", "Disk encryption", "Container scheduling"],
    correctAnswer: 0,
    explanation: "VPNs provide encrypted connectivity to cloud networks.",
  },
  {
    id: 57,
    topic: "Networking",
    question: "Dedicated private connectivity is often called:",
    options: ["Direct Connect or ExpressRoute", "WAF", "CSPM", "SaaS"],
    correctAnswer: 0,
    explanation: "Providers offer direct private links for low latency.",
  },
  {
    id: 58,
    topic: "Compliance",
    question: "Data residency refers to:",
    options: ["Where data is stored geographically", "How fast data moves", "Which CPU is used", "Which browser is used"],
    correctAnswer: 0,
    explanation: "Residency specifies geographic storage location.",
  },
  {
    id: 59,
    topic: "Compliance",
    question: "PCI DSS is related to:",
    options: ["Payment card data security", "Medical data", "Government only", "Browser cookies"],
    correctAnswer: 0,
    explanation: "PCI DSS applies to payment card data security.",
  },
  {
    id: 60,
    topic: "Compliance",
    question: "HIPAA is related to:",
    options: ["Healthcare data protection", "Video streaming", "Gaming", "Retail pricing"],
    correctAnswer: 0,
    explanation: "HIPAA governs protected health information.",
  },
  {
    id: 61,
    topic: "Cost",
    question: "Rightsizing means:",
    options: ["Selecting appropriate instance sizes", "Always choosing the largest instance", "Disabling monitoring", "Avoiding tags"],
    correctAnswer: 0,
    explanation: "Rightsizing matches resources to actual needs.",
  },
  {
    id: 62,
    topic: "Cost",
    question: "Tagging resources helps with:",
    options: ["Cost allocation and organization", "Encrypting storage", "Improving CPU speed", "Reducing bandwidth"],
    correctAnswer: 0,
    explanation: "Tags help track ownership and costs.",
  },
  {
    id: 63,
    topic: "Cloud Providers",
    question: "Which is a major cloud provider?",
    options: ["AWS", "Windows 7", "Photoshop", "Ubuntu"],
    correctAnswer: 0,
    explanation: "AWS is a major cloud provider.",
  },
  {
    id: 64,
    topic: "Cloud Providers",
    question: "Which is a major cloud provider?",
    options: ["Microsoft Azure", "LibreOffice", "Notepad", "WinRAR"],
    correctAnswer: 0,
    explanation: "Azure is a major cloud provider.",
  },
  {
    id: 65,
    topic: "Cloud Providers",
    question: "Which is a major cloud provider?",
    options: ["Google Cloud Platform", "GIMP", "VLC", "Firefox"],
    correctAnswer: 0,
    explanation: "Google Cloud Platform is a major cloud provider.",
  },
  {
    id: 66,
    topic: "Networking",
    question: "A security group is typically:",
    options: ["Stateful", "Stateless", "A DNS record", "A storage class"],
    correctAnswer: 0,
    explanation: "Security groups are stateful firewalls in many clouds.",
  },
  {
    id: 67,
    topic: "Networking",
    question: "A network ACL is typically:",
    options: ["Stateless", "Stateful", "A CPU scheduler", "An IAM role"],
    correctAnswer: 0,
    explanation: "Network ACLs are often stateless.",
  },
  {
    id: 68,
    topic: "Reliability",
    question: "An SLA defines:",
    options: ["Service availability commitments", "CPU clock speed", "Disk size", "IP address format"],
    correctAnswer: 0,
    explanation: "SLAs outline availability and service commitments.",
  },
  {
    id: 69,
    topic: "Security",
    question: "A common cloud breach cause is:",
    options: ["Misconfiguration", "Too many regions", "Too much memory", "Too much redundancy"],
    correctAnswer: 0,
    explanation: "Misconfigurations are a leading cause of cloud incidents.",
  },
  {
    id: 70,
    topic: "Operations",
    question: "Logs for API activity are commonly stored in:",
    options: ["Audit logs like CloudTrail", "CPU cache", "Local browser storage", "USB devices"],
    correctAnswer: 0,
    explanation: "Audit logs capture API activity.",
  },
  {
    id: 71,
    topic: "Storage",
    question: "Archive storage is best for:",
    options: ["Long-term, infrequently accessed data", "High IOPS databases", "Real-time streaming", "Cache data only"],
    correctAnswer: 0,
    explanation: "Archive storage is low cost for infrequent access.",
  },
  {
    id: 72,
    topic: "Serverless",
    question: "Serverless billing is usually based on:",
    options: ["Execution time and requests", "Fixed monthly cost only", "CPU model", "Physical rack space"],
    correctAnswer: 0,
    explanation: "Serverless costs depend on invocations and duration.",
  },
  {
    id: 73,
    topic: "Containers",
    question: "Container images are typically stored in:",
    options: ["Registries", "DNS servers", "Load balancers", "Key vaults only"],
    correctAnswer: 0,
    explanation: "Registries store and distribute container images.",
  },
  {
    id: 74,
    topic: "Architecture",
    question: "Cloud bursting means:",
    options: ["Using cloud resources to handle peak demand", "Deleting all resources", "Avoiding autoscaling", "Turning off backups"],
    correctAnswer: 0,
    explanation: "Cloud bursting uses cloud capacity for spikes.",
  },
  {
    id: 75,
    topic: "Architecture",
    question: "A well-architected cloud design emphasizes:",
    options: ["Reliability, security, and cost efficiency", "Single points of failure", "Manual scaling only", "No monitoring"],
    correctAnswer: 0,
    explanation: "Good architectures prioritize reliability, security, and cost.",
  },
];

const CloudComputingPage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const [quizPool] = useState<QuizQuestion[]>(() =>
    selectRandomQuestions(quizQuestions, QUIZ_QUESTION_COUNT)
  );

  // Navigation state
  const accent = "#06b6d4"; // Cyan for Cloud Computing
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <SchoolIcon /> },
    { id: "service-models", label: "Service Models", icon: <CloudIcon /> },
    { id: "deployment", label: "Deployment", icon: <DevicesIcon /> },
    { id: "providers", label: "Providers", icon: <BusinessIcon /> },
    { id: "aws-deepdive", label: "AWS Deep Dive", icon: <CloudIcon /> },
    { id: "azure-deepdive", label: "Azure Deep Dive", icon: <CloudIcon /> },
    { id: "gcp-deepdive", label: "GCP Deep Dive", icon: <CloudIcon /> },
    { id: "core-services", label: "Core Services", icon: <SettingsIcon /> },
    { id: "virtualization", label: "Virtualization", icon: <DataUsageIcon /> },
    { id: "containers", label: "Containers", icon: <StorageIcon /> },
    { id: "serverless", label: "Serverless", icon: <CloudUploadIcon /> },
    { id: "storage", label: "Storage", icon: <StorageIcon /> },
    { id: "networking", label: "Networking", icon: <PublicIcon /> },
    { id: "pricing", label: "Pricing", icon: <SavingsIcon /> },
    { id: "benefits", label: "Benefits", icon: <CheckCircleOutlineIcon /> },
    { id: "security", label: "Security", icon: <SecurityIcon /> },
    { id: "misconfigs", label: "Misconfigs", icon: <WarningIcon /> },
    { id: "terminology", label: "Terminology", icon: <InfoIcon /> },
    { id: "service-comparison", label: "Comparison", icon: <CloudQueueIcon /> },
    { id: "iam", label: "IAM", icon: <LockIcon /> },
    { id: "architecture", label: "Architecture", icon: <BuildIcon /> },
    { id: "devops", label: "DevOps", icon: <SpeedIcon /> },
    { id: "observability", label: "Observability", icon: <SpeedIcon /> },
    { id: "cli", label: "CLI Tools", icon: <BuildIcon /> },
    { id: "security-tools", label: "Security Tools", icon: <SecurityIcon /> },
    { id: "data-governance", label: "Data Governance", icon: <StorageIcon /> },
    { id: "real-world", label: "Real World", icon: <TipsAndUpdatesIcon /> },
    { id: "outline", label: "Outline", icon: <ListAltIcon /> },
    { id: "quiz", label: "Quiz", icon: <QuizIcon /> },
  ];

  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
      setNavDrawerOpen(false);
    }
  };

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
    };

    window.addEventListener("scroll", handleScroll);
    handleScroll();
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const scrollToTop = () => window.scrollTo({ top: 0, behavior: "smooth" });

  const currentIndex = sectionNavItems.findIndex((item) => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / sectionNavItems.length) * 100 : 0;

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
        border: `1px solid ${alpha(accent, 0.15)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        display: { xs: "none", lg: "block" },
        "&::-webkit-scrollbar": {
          width: 6,
        },
        "&::-webkit-scrollbar-thumb": {
          bgcolor: alpha(accent, 0.3),
          borderRadius: 3,
        },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography
          variant="subtitle2"
          sx={{ fontWeight: 700, mb: 1, color: accent, display: "flex", alignItems: "center", gap: 1 }}
        >
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">
              Progress
            </Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>
              {Math.round(progressPercent)}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha(accent, 0.1),
              "& .MuiLinearProgress-bar": {
                bgcolor: accent,
                borderRadius: 3,
              },
            }}
          />
        </Box>
        <Divider sx={{ mb: 1 }} />
        <List dense sx={{ mx: -1 }}>
          {sectionNavItems.map((item) => (
            <ListItem
              key={item.id}
              onClick={() => scrollToSection(item.id)}
              sx={{
                borderRadius: 1.5,
                mb: 0.25,
                py: 0.5,
                cursor: "pointer",
                bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                "&:hover": {
                  bgcolor: alpha(accent, 0.08),
                },
                transition: "all 0.15s ease",
              }}
            >
              <ListItemIcon sx={{ minWidth: 24, fontSize: "0.9rem" }}>{item.icon}</ListItemIcon>
              <ListItemText
                primary={
                  <Typography
                    variant="caption"
                    sx={{
                      fontWeight: activeSection === item.id ? 700 : 500,
                      color: activeSection === item.id ? accent : "text.secondary",
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
- Cloud terminology: Regions, AZs, edge locations, elasticity, HA, fault tolerance
- Observability and SRE basics: metrics, logs, traces, SLOs
- Data governance and lifecycle: classification, retention, access controls`;

  return (
    <LearnPageLayout pageTitle="Cloud Computing Fundamentals" pageContext={pageContext}>
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
            bgcolor: accent,
            "&:hover": { bgcolor: "#0891b2" },
            boxShadow: `0 4px 20px ${alpha(accent, 0.4)}`,
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
            bgcolor: alpha(accent, 0.15),
            color: accent,
            "&:hover": { bgcolor: alpha(accent, 0.25) },
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
              <ListAltIcon sx={{ color: accent }} />
              Course Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} size="small">
              <CloseIcon />
            </IconButton>
          </Box>

          <Divider sx={{ mb: 2 }} />

          {/* Progress indicator */}
          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">
                Progress
              </Typography>
              <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>
                {Math.round(progressPercent)}%
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{
                height: 6,
                borderRadius: 3,
                bgcolor: alpha(accent, 0.1),
                "& .MuiLinearProgress-bar": {
                  bgcolor: accent,
                  borderRadius: 3,
                },
              }}
            />
          </Box>

          <List>
            {sectionNavItems.map((item) => (
              <ListItem
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                sx={{
                  borderRadius: 2,
                  mb: 0.5,
                  cursor: "pointer",
                  bgcolor: activeSection === item.id ? alpha(accent, 0.12) : "transparent",
                  "&:hover": {
                    bgcolor: alpha(accent, 0.08),
                  },
                }}
              >
                <ListItemIcon sx={{ color: activeSection === item.id ? accent : "inherit", minWidth: 36 }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={item.label}
                  primaryTypographyProps={{
                    fontWeight: activeSection === item.id ? 600 : 400,
                    color: activeSection === item.id ? accent : "inherit",
                  }}
                />
                {activeSection === item.id && (
                  <Chip
                    label="Current"
                    size="small"
                    sx={{
                      height: 20,
                      fontSize: "0.65rem",
                      bgcolor: alpha(accent, 0.2),
                      color: accent,
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
              sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}
            >
              Top
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => scrollToSection("quiz")}
              startIcon={<QuizIcon />}
              sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}
            >
              Quiz
            </Button>
          </Box>
        </Box>
      </Drawer>

      {/* Main Layout with Sidebar */}
      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, sm: 3 }, py: 4 }}>
        {sidebarNav}

        <Box sx={{ flex: 1, minWidth: 0 }}>
          {/* Back Button */}
          <Chip
            component={Link}
            to="/learn"
            icon={<ArrowBackIcon />}
            label="Back to Learning Hub"
            clickable
            variant="outlined"
            sx={{ borderRadius: 2, mb: 3 }}
          />

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

        {/* ==================== AWS DEEP DIVE ==================== */}
        <Box id="aws-deepdive" sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 5, scrollMarginTop: 80 }}>
          <Divider sx={{ flex: 1, borderColor: "#ff9900" }} />
          <Typography variant="overline" sx={{ fontWeight: 700, color: "#ff9900", fontSize: "0.9rem" }}>☁️ AMAZON WEB SERVICES (AWS)</Typography>
          <Divider sx={{ flex: 1, borderColor: "#ff9900" }} />
        </Box>

        <Paper
          elevation={0}
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#ff9900", 0.08)} 0%, ${alpha("#ff9900", 0.02)} 100%)`,
            border: `2px solid ${alpha("#ff9900", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box sx={{ 
              width: 60, 
              height: 60, 
              borderRadius: 2, 
              bgcolor: "#ff9900", 
              display: "flex", 
              alignItems: "center", 
              justifyContent: "center",
              fontSize: "1.8rem"
            }}>
              ☁️
            </Box>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#ff9900" }}>
                Amazon Web Services
              </Typography>
              <Typography variant="body1" color="text.secondary">
                The pioneer and market leader in cloud computing since 2006
              </Typography>
            </Box>
          </Box>

          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            <strong>AWS</strong> launched with S3 and EC2 in 2006 and has been the dominant cloud provider ever since. 
            With <strong>200+ services</strong> across compute, storage, database, analytics, machine learning, IoT, and more, 
            AWS offers the most comprehensive and mature cloud platform. It's the default choice for many startups and 
            enterprises, with the largest community, most extensive documentation, and widest talent pool.
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#ff9900", 0.05), border: `1px solid ${alpha("#ff9900", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#ff9900" }}>{awsGlobalInfrastructure.regions.split(" ")[0]}</Typography>
                <Typography variant="caption" color="text.secondary">Regions</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#ff9900", 0.05), border: `1px solid ${alpha("#ff9900", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#ff9900" }}>{awsGlobalInfrastructure.azs.split(" ")[0]}</Typography>
                <Typography variant="caption" color="text.secondary">AZs</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#ff9900", 0.05), border: `1px solid ${alpha("#ff9900", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#ff9900" }}>{awsGlobalInfrastructure.edgeLocations.split(" ")[0]}</Typography>
                <Typography variant="caption" color="text.secondary">Edge Locations</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#ff9900", 0.05), border: `1px solid ${alpha("#ff9900", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#ff9900" }}>200+</Typography>
                <Typography variant="caption" color="text.secondary">Services</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#ff9900", 0.05), border: `1px solid ${alpha("#ff9900", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#ff9900" }}>~32%</Typography>
                <Typography variant="caption" color="text.secondary">Market Share</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#ff9900", 0.05), border: `1px solid ${alpha("#ff9900", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#ff9900" }}>#1</Typography>
                <Typography variant="caption" color="text.secondary">Since 2006</Typography>
              </Paper>
            </Grid>
          </Grid>

          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Widest service offering", "Most mature ecosystem", "Largest community", "Best documentation", "Most certifications", "Global infrastructure leader"].map((strength) => (
              <Chip key={strength} label={strength} size="small" sx={{ bgcolor: alpha("#ff9900", 0.1), color: "#ff9900", fontWeight: 600 }} />
            ))}
          </Box>
        </Paper>

        {/* AWS Service Categories */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#ff9900" }}>
          AWS Service Categories
        </Typography>

        {awsServiceCategories.map((category) => (
          <Accordion key={category.category} sx={{ mb: 2, borderRadius: 2, "&:before": { display: "none" }, border: `1px solid ${alpha(category.color, 0.2)}` }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ bgcolor: alpha(category.color, 0.03) }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                <Typography sx={{ fontSize: "1.5rem" }}>{category.icon}</Typography>
                <Typography variant="h6" sx={{ fontWeight: 700, color: category.color }}>{category.category}</Typography>
                <Chip label={`${category.services.length} services`} size="small" sx={{ bgcolor: alpha(category.color, 0.1), fontSize: "0.7rem" }} />
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                {category.services.map((service) => (
                  <Grid item xs={12} md={6} key={service.name}>
                    <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha(category.color, 0.15)}`, bgcolor: alpha(category.color, 0.01) }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                        <Chip label={service.name} size="small" sx={{ fontWeight: 700, bgcolor: category.color, color: "white" }} />
                        <Typography variant="caption" color="text.secondary">{service.fullName}</Typography>
                      </Box>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5, lineHeight: 1.7 }}>{service.description}</Typography>
                      <Typography variant="caption" sx={{ display: "block", mb: 0.5 }}>
                        <strong>Key Features:</strong> {service.keyFeatures}
                      </Typography>
                      <Typography variant="caption" sx={{ display: "block", color: category.color }}>
                        <strong>Use Cases:</strong> {service.useCase}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </AccordionDetails>
          </Accordion>
        ))}

        {/* AWS Free Tier */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#22c55e" }}>
            🎁 AWS Free Tier Highlights
          </Typography>
          <Grid container spacing={2}>
            {awsFreeTierHighlights.map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.service}>
                <Box sx={{ p: 1.5, borderRadius: 1, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.1)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ff9900" }}>{item.service}</Typography>
                  <Typography variant="caption" sx={{ display: "block", color: "text.secondary" }}>{item.offer}</Typography>
                  <Chip label={item.duration} size="small" sx={{ mt: 0.5, height: 18, fontSize: "0.65rem", bgcolor: item.duration === "Always free" ? alpha("#22c55e", 0.2) : alpha("#3b82f6", 0.2) }} />
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== AZURE DEEP DIVE ==================== */}
        <Box id="azure-deepdive" sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 5, scrollMarginTop: 80 }}>
          <Divider sx={{ flex: 1, borderColor: "#0078d4" }} />
          <Typography variant="overline" sx={{ fontWeight: 700, color: "#0078d4", fontSize: "0.9rem" }}>☁️ MICROSOFT AZURE</Typography>
          <Divider sx={{ flex: 1, borderColor: "#0078d4" }} />
        </Box>

        <Paper
          elevation={0}
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#0078d4", 0.08)} 0%, ${alpha("#0078d4", 0.02)} 100%)`,
            border: `2px solid ${alpha("#0078d4", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box sx={{ 
              width: 60, 
              height: 60, 
              borderRadius: 2, 
              bgcolor: "#0078d4", 
              display: "flex", 
              alignItems: "center", 
              justifyContent: "center",
              fontSize: "1.8rem"
            }}>
              ☁️
            </Box>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#0078d4" }}>
                Microsoft Azure
              </Typography>
              <Typography variant="body1" color="text.secondary">
                Enterprise cloud leader with deep Microsoft ecosystem integration
              </Typography>
            </Box>
          </Box>

          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            <strong>Microsoft Azure</strong> launched in 2010 and has grown to become the #2 cloud provider with 
            <strong> 200+ services</strong>. Azure's key differentiator is its seamless integration with the Microsoft ecosystem — 
            Windows Server, SQL Server, Active Directory, Microsoft 365, Dynamics 365, and Power Platform. For enterprises 
            already invested in Microsoft, Azure provides the smoothest hybrid cloud experience with Azure Arc, Azure Stack, 
            and the Azure Hybrid Benefit for Windows and SQL Server licenses.
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#0078d4", 0.05), border: `1px solid ${alpha("#0078d4", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#0078d4" }}>{azureGlobalInfrastructure.regions.split(" ")[0]}</Typography>
                <Typography variant="caption" color="text.secondary">Regions</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#0078d4", 0.05), border: `1px solid ${alpha("#0078d4", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#0078d4" }}>50+</Typography>
                <Typography variant="caption" color="text.secondary">AZ Regions</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#0078d4", 0.05), border: `1px solid ${alpha("#0078d4", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#0078d4" }}>190+</Typography>
                <Typography variant="caption" color="text.secondary">Edge Locations</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#0078d4", 0.05), border: `1px solid ${alpha("#0078d4", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#0078d4" }}>200+</Typography>
                <Typography variant="caption" color="text.secondary">Services</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#0078d4", 0.05), border: `1px solid ${alpha("#0078d4", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#0078d4" }}>~23%</Typography>
                <Typography variant="caption" color="text.secondary">Market Share</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#0078d4", 0.05), border: `1px solid ${alpha("#0078d4", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#0078d4" }}>#2</Typography>
                <Typography variant="caption" color="text.secondary">Growing Fast</Typography>
              </Paper>
            </Grid>
          </Grid>

          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Microsoft ecosystem", "Enterprise leader", "Hybrid cloud", "Azure AD", "OpenAI partnership", "Most regions worldwide"].map((strength) => (
              <Chip key={strength} label={strength} size="small" sx={{ bgcolor: alpha("#0078d4", 0.1), color: "#0078d4", fontWeight: 600 }} />
            ))}
          </Box>
        </Paper>

        {/* Azure Enterprise Integration */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#0078d4", 0.02), border: `1px solid ${alpha("#0078d4", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0078d4", display: "flex", alignItems: "center", gap: 1 }}>
            🏢 Microsoft Ecosystem Integration
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Azure's killer feature for enterprises is its native integration with the entire Microsoft stack:
          </Typography>
          <Grid container spacing={2}>
            {azureEnterpriseIntegration.map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.feature}>
                <Box sx={{ p: 1.5, borderRadius: 1, bgcolor: "background.paper", border: `1px solid ${alpha("#0078d4", 0.1)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#0078d4", mb: 0.5 }}>{item.feature}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.description}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Azure Service Categories */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#0078d4" }}>
          Azure Service Categories
        </Typography>

        {azureServiceCategories.map((category) => (
          <Accordion key={category.category} sx={{ mb: 2, borderRadius: 2, "&:before": { display: "none" }, border: `1px solid ${alpha(category.color, 0.2)}` }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ bgcolor: alpha(category.color, 0.03) }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                <Typography sx={{ fontSize: "1.5rem" }}>{category.icon}</Typography>
                <Typography variant="h6" sx={{ fontWeight: 700, color: category.color }}>{category.category}</Typography>
                <Chip label={`${category.services.length} services`} size="small" sx={{ bgcolor: alpha(category.color, 0.1), fontSize: "0.7rem" }} />
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                {category.services.map((service) => (
                  <Grid item xs={12} md={6} key={service.name}>
                    <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha(category.color, 0.15)}`, bgcolor: alpha(category.color, 0.01) }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                        <Chip label={service.name} size="small" sx={{ fontWeight: 700, bgcolor: category.color, color: "white" }} />
                        <Typography variant="caption" color="text.secondary">{service.fullName}</Typography>
                      </Box>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5, lineHeight: 1.7 }}>{service.description}</Typography>
                      <Typography variant="caption" sx={{ display: "block", mb: 0.5 }}>
                        <strong>Key Features:</strong> {service.keyFeatures}
                      </Typography>
                      <Typography variant="caption" sx={{ display: "block", color: category.color }}>
                        <strong>Use Cases:</strong> {service.useCase}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </AccordionDetails>
          </Accordion>
        ))}

        {/* Azure Free Tier */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#22c55e" }}>
            🎁 Azure Free Tier Highlights
          </Typography>
          <Grid container spacing={2}>
            {azureFreeTierHighlights.map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.service}>
                <Box sx={{ p: 1.5, borderRadius: 1, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.1)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#0078d4" }}>{item.service}</Typography>
                  <Typography variant="caption" sx={{ display: "block", color: "text.secondary" }}>{item.offer}</Typography>
                  <Chip label={item.duration} size="small" sx={{ mt: 0.5, height: 18, fontSize: "0.65rem", bgcolor: item.duration === "Always free" ? alpha("#22c55e", 0.2) : alpha("#3b82f6", 0.2) }} />
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== GCP DEEP DIVE ==================== */}
        <Box id="gcp-deepdive" sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 5, scrollMarginTop: 80 }}>
          <Divider sx={{ flex: 1, borderColor: "#4285f4" }} />
          <Typography variant="overline" sx={{ fontWeight: 700, color: "#4285f4", fontSize: "0.9rem" }}>☁️ GOOGLE CLOUD PLATFORM (GCP)</Typography>
          <Divider sx={{ flex: 1, borderColor: "#4285f4" }} />
        </Box>

        <Paper
          elevation={0}
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 3,
            background: `linear-gradient(135deg, ${alpha("#4285f4", 0.08)} 0%, ${alpha("#4285f4", 0.02)} 100%)`,
            border: `2px solid ${alpha("#4285f4", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Box sx={{ 
              width: 60, 
              height: 60, 
              borderRadius: 2, 
              bgcolor: "#4285f4", 
              display: "flex", 
              alignItems: "center", 
              justifyContent: "center",
              fontSize: "1.8rem"
            }}>
              ☁️
            </Box>
            <Box>
              <Typography variant="h4" sx={{ fontWeight: 800, color: "#4285f4" }}>
                Google Cloud Platform
              </Typography>
              <Typography variant="body1" color="text.secondary">
                Data analytics powerhouse and Kubernetes originator
              </Typography>
            </Box>
          </Box>

          <Typography variant="body1" sx={{ lineHeight: 1.9, mb: 3 }}>
            <strong>Google Cloud Platform</strong> (launched 2008) leverages Google's decades of experience running 
            global-scale services like Search, Gmail, and YouTube. GCP is known for <strong>data analytics excellence</strong> (BigQuery 
            pioneered serverless data warehouses), <strong>AI/ML leadership</strong> (TensorFlow, Gemini), and 
            <strong> Kubernetes mastery</strong> — Google created Kubernetes and GKE is considered the gold standard. 
            While smaller in market share (~10%), GCP leads in innovation, sustainability, and is often the choice for 
            data-heavy and ML-focused workloads.
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#4285f4", 0.05), border: `1px solid ${alpha("#4285f4", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#4285f4" }}>{gcpGlobalInfrastructure.regions.split(" ")[0]}</Typography>
                <Typography variant="caption" color="text.secondary">Regions</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#4285f4", 0.05), border: `1px solid ${alpha("#4285f4", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#4285f4" }}>{gcpGlobalInfrastructure.zones.split(" ")[0]}</Typography>
                <Typography variant="caption" color="text.secondary">Zones</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#4285f4", 0.05), border: `1px solid ${alpha("#4285f4", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#4285f4" }}>{gcpGlobalInfrastructure.edgeLocations.split(" ")[0]}</Typography>
                <Typography variant="caption" color="text.secondary">Edge Locations</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#4285f4", 0.05), border: `1px solid ${alpha("#4285f4", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#4285f4" }}>200+</Typography>
                <Typography variant="caption" color="text.secondary">Services</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#4285f4", 0.05), border: `1px solid ${alpha("#4285f4", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#4285f4" }}>~10%</Typography>
                <Typography variant="caption" color="text.secondary">Market Share</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha("#34a853", 0.05), border: `1px solid ${alpha("#34a853", 0.2)}` }}>
                <Typography variant="h5" sx={{ fontWeight: 800, color: "#34a853" }}>100%</Typography>
                <Typography variant="caption" color="text.secondary">Renewable Energy</Typography>
              </Paper>
            </Grid>
          </Grid>

          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
            {["Kubernetes originator", "BigQuery leader", "AI/ML innovation", "Global private network", "Carbon neutral", "Sustained use discounts", "Live VM migration", "Open source friendly"].map((strength) => (
              <Chip key={strength} label={strength} size="small" sx={{ bgcolor: alpha("#4285f4", 0.1), color: "#4285f4", fontWeight: 600 }} />
            ))}
          </Box>
        </Paper>

        {/* GCP Differentiators */}
        <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#4285f4", 0.02), border: `1px solid ${alpha("#4285f4", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4285f4", display: "flex", alignItems: "center", gap: 1 }}>
            🚀 What Makes GCP Different
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            GCP's unique advantages come from Google's infrastructure and innovation culture:
          </Typography>
          <Grid container spacing={2}>
            {gcpDifferentiators.map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.feature}>
                <Box sx={{ p: 1.5, borderRadius: 1, bgcolor: "background.paper", border: `1px solid ${alpha("#4285f4", 0.1)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#4285f4", mb: 0.5 }}>{item.feature}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.description}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* GCP Service Categories */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#4285f4" }}>
          GCP Service Categories
        </Typography>

        {gcpServiceCategories.map((category) => (
          <Accordion key={category.category} sx={{ mb: 2, borderRadius: 2, "&:before": { display: "none" }, border: `1px solid ${alpha(category.color, 0.2)}` }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ bgcolor: alpha(category.color, 0.03) }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                <Typography sx={{ fontSize: "1.5rem" }}>{category.icon}</Typography>
                <Typography variant="h6" sx={{ fontWeight: 700, color: category.color }}>{category.category}</Typography>
                <Chip label={`${category.services.length} services`} size="small" sx={{ bgcolor: alpha(category.color, 0.1), fontSize: "0.7rem" }} />
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={2}>
                {category.services.map((service) => (
                  <Grid item xs={12} md={6} key={service.name}>
                    <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha(category.color, 0.15)}`, bgcolor: alpha(category.color, 0.01) }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                        <Chip label={service.name} size="small" sx={{ fontWeight: 700, bgcolor: category.color, color: "white" }} />
                        <Typography variant="caption" color="text.secondary">{service.fullName}</Typography>
                      </Box>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5, lineHeight: 1.7 }}>{service.description}</Typography>
                      <Typography variant="caption" sx={{ display: "block", mb: 0.5 }}>
                        <strong>Key Features:</strong> {service.keyFeatures}
                      </Typography>
                      <Typography variant="caption" sx={{ display: "block", color: category.color }}>
                        <strong>Use Cases:</strong> {service.useCase}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </AccordionDetails>
          </Accordion>
        ))}

        {/* GCP Free Tier */}
        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#22c55e" }}>
            🎁 GCP Free Tier Highlights
          </Typography>
          <Grid container spacing={2}>
            {gcpFreeTierHighlights.map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.service}>
                <Box sx={{ p: 1.5, borderRadius: 1, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.1)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#4285f4" }}>{item.service}</Typography>
                  <Typography variant="caption" sx={{ display: "block", color: "text.secondary" }}>{item.offer}</Typography>
                  <Chip label={item.duration} size="small" sx={{ mt: 0.5, height: 18, fontSize: "0.65rem", bgcolor: item.duration === "Always free" ? alpha("#22c55e", 0.2) : alpha("#3b82f6", 0.2) }} />
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* AWS vs Azure vs GCP Comparison */}
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          🔄 AWS vs Azure vs GCP: Quick Comparison
        </Typography>
        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Aspect</TableCell>
                <TableCell sx={{ fontWeight: 700, color: "#ff9900" }}>AWS</TableCell>
                <TableCell sx={{ fontWeight: 700, color: "#0078d4" }}>Azure</TableCell>
                <TableCell sx={{ fontWeight: 700, color: "#4285f4" }}>GCP</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {[
                { aspect: "Market Position", aws: "Leader since 2006, ~32% share", azure: "Strong #2, ~23% share", gcp: "Growing #3, ~10% share" },
                { aspect: "Best For", aws: "Startups, web-native, broadest needs", azure: "Microsoft shops, enterprise, hybrid", gcp: "Data/ML workloads, K8s, analytics" },
                { aspect: "Compute", aws: "EC2, Lambda, ECS/EKS", azure: "VMs, Functions, AKS", gcp: "Compute Engine, Cloud Run, GKE" },
                { aspect: "Storage", aws: "S3, EBS, EFS", azure: "Blob, Managed Disks, Files", gcp: "Cloud Storage, Persistent Disk" },
                { aspect: "Database", aws: "RDS, Aurora, DynamoDB", azure: "SQL Database, Cosmos DB", gcp: "Cloud SQL, Spanner, BigQuery" },
                { aspect: "Identity", aws: "IAM + Cognito for users", azure: "Entra ID (Azure AD) — SSO leader", gcp: "Cloud IAM, Identity Platform" },
                { aspect: "AI/ML", aws: "SageMaker, Bedrock (Claude)", azure: "Azure OpenAI (GPT-4)", gcp: "Vertex AI, Gemini, TensorFlow" },
                { aspect: "Hybrid Cloud", aws: "Outposts, EKS Anywhere", azure: "Arc, Stack — deep on-prem", gcp: "Anthos for multi/hybrid cloud" },
                { aspect: "DevOps", aws: "CodePipeline, CodeBuild", azure: "Azure DevOps, GitHub Actions", gcp: "Cloud Build, Cloud Deploy" },
                { aspect: "Enterprise", aws: "Partner integrations", azure: "Native M365, Dynamics, Power", gcp: "Google Workspace, Looker" },
                { aspect: "Pricing", aws: "More granular, complex", azure: "Hybrid Benefit savings", gcp: "Sustained/committed discounts" },
                { aspect: "Regions", aws: "33+ regions", azure: "60+ regions (most)", gcp: "40+ regions, premium network" },
              ].map((row) => (
                <TableRow key={row.aspect} sx={{ "&:hover": { bgcolor: alpha("#8b5cf6", 0.02) } }}>
                  <TableCell sx={{ fontWeight: 600 }}>{row.aspect}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem" }}>{row.aws}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem" }}>{row.azure}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem" }}>{row.gcp}</TableCell>
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

        {/* ==================== OBSERVABILITY & SRE ==================== */}
        <Typography id="observability" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          ?? Observability & SRE Essentials
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          How teams measure reliability, detect incidents, and improve user experience
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#06b6d4", 0.03), border: `1px solid ${alpha("#06b6d4", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            Observability connects what users feel to what systems do. Start with the <strong>golden signals</strong>:
            latency (speed), traffic (load), errors (quality), and saturation (capacity). Use these signals to set
            clear SLOs and manage risk with error budgets.
          </Typography>
        </Paper>

        <TableContainer component={Paper} sx={{ mb: 3, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#06b6d4", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Signal</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>What It Is</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Examples</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Why It Matters</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {observabilitySignals.map((signal) => (
                <TableRow key={signal.signal} sx={{ "&:hover": { bgcolor: alpha("#06b6d4", 0.03) } }}>
                  <TableCell sx={{ fontWeight: 700, color: "#06b6d4" }}>{signal.signal}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem" }}>{signal.description}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{signal.examples}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem" }}>{signal.value}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#06b6d4", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Availability Target</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Allowed Downtime</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Typical Use</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Architecture Guidance</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {availabilityTargets.map((tier) => (
                <TableRow key={tier.tier} sx={{ "&:hover": { bgcolor: alpha("#06b6d4", 0.03) } }}>
                  <TableCell sx={{ fontWeight: 700, color: "#06b6d4" }}>{tier.tier}</TableCell>
                  <TableCell>{tier.downtime}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{tier.useCase}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem" }}>{tier.guidance}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

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

        {/* ==================== DATA GOVERNANCE ==================== */}
        <Typography id="data-governance" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          ?? Data Governance & Lifecycle
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Keep data secure, compliant, and useful from ingestion to disposal
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            Data governance defines who can access data, where it can live, and how long it can be retained. In the cloud,
            governance is enforced through tagging, policies, encryption, and audit logs that travel with your data everywhere.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 4 }}>
          {dataGovernancePractices.map((practice) => (
            <Grid item xs={12} sm={6} md={4} key={practice.practice}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5, color: "#3b82f6" }}>
                  {practice.practice}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  {practice.description}
                </Typography>
                <Typography variant="caption" sx={{ display: "block", mb: 0.5 }}>
                  <strong>Tools:</strong> {practice.tools}
                </Typography>
                <Typography variant="caption" sx={{ display: "block", color: "text.secondary" }}>
                  <strong>Outcome:</strong> {practice.outcome}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#3b82f6", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Stage</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Goal</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Controls</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Examples</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {dataLifecycleStages.map((stage) => (
                <TableRow key={stage.stage} sx={{ "&:hover": { bgcolor: alpha("#3b82f6", 0.03) } }}>
                  <TableCell sx={{ fontWeight: 700, color: "#3b82f6" }}>{stage.stage}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem" }}>{stage.goal}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{stage.controls}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem" }}>{stage.services}</TableCell>
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

        {/* ==================== WELL-ARCHITECTED FRAMEWORK ==================== */}
        <Typography id="well-architected" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🏛️ AWS Well-Architected Framework
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The six pillars of building secure, high-performing, resilient, and efficient infrastructure
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#0ea5e9", 0.03), border: `1px solid ${alpha("#0ea5e9", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            The <strong>Well-Architected Framework</strong> provides a consistent approach to evaluate architectures and implement designs that scale over time.
            While developed by AWS, these principles apply to all cloud providers. Use these pillars to review workloads before going to production.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {wellArchitectedPillars.map((pillar) => (
            <Grid item xs={12} md={6} key={pillar.pillar}>
              <Paper sx={{ p: 3, borderRadius: 2, height: "100%", borderLeft: `4px solid ${pillar.color}`, bgcolor: alpha(pillar.color, 0.02) }}>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                  <span>{pillar.icon}</span>
                  <span style={{ color: pillar.color }}>{pillar.pillar}</span>
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{pillar.description}</Typography>
                <Typography variant="caption" sx={{ display: "block", mb: 1, fontWeight: 600 }}>Key Principles:</Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                  {pillar.keyPrinciples.map((p, i) => (
                    <Chip key={i} label={p} size="small" sx={{ fontSize: "0.65rem", bgcolor: alpha(pillar.color, 0.1) }} />
                  ))}
                </Box>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                  <strong>AWS Tools:</strong> {pillar.awsTools}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== CLOUD MIGRATION STRATEGIES ==================== */}
        <Typography id="migration" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🚀 Cloud Migration Strategies (The 6 Rs)
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Six approaches to migrating applications to the cloud, from simple lift-and-shift to full re-architecture
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            Not every application should be migrated the same way. The <strong>6 Rs</strong> framework helps you choose the right strategy based on
            business requirements, timeline, and available resources. Start with an application portfolio assessment to categorize workloads.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {migrationStrategies.map((strat) => (
            <Grid item xs={12} sm={6} md={4} key={strat.strategy}>
              <Paper sx={{ p: 3, borderRadius: 2, height: "100%", border: `2px solid ${alpha(strat.color, 0.3)}`, bgcolor: alpha(strat.color, 0.02) }}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 1 }}>
                  <Typography variant="h6" sx={{ fontWeight: 800, color: strat.color }}>{strat.strategy}</Typography>
                  <Chip label={strat.effort} size="small" sx={{ fontSize: "0.65rem" }} />
                </Box>
                <Typography variant="caption" sx={{ display: "block", mb: 1, fontStyle: "italic", color: "text.secondary" }}>
                  "{strat.nickname}"
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>{strat.description}</Typography>
                <Typography variant="caption" sx={{ display: "block", mb: 0.5 }}>
                  <strong>Best For:</strong> {strat.bestFor}
                </Typography>
                <Typography variant="caption" sx={{ display: "block", mb: 0.5 }}>
                  <strong>Example:</strong> {strat.example}
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                  <strong>Tools:</strong> {strat.tools}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== DISASTER RECOVERY ==================== */}
        <Typography id="disaster-recovery" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🔄 Disaster Recovery Strategies
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Plan for failures with the right balance of cost and recovery time
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.1)}` }}>
          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>RPO (Recovery Point Objective)</Typography>
              <Typography variant="body2" color="text.secondary">
                Maximum acceptable data loss measured in time. How much data can you afford to lose?
                A 1-hour RPO means backups must be taken at least hourly.
              </Typography>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, color: "#f59e0b" }}>RTO (Recovery Time Objective)</Typography>
              <Typography variant="body2" color="text.secondary">
                Maximum acceptable downtime. How quickly must systems be restored?
                A 4-hour RTO means systems must be operational within 4 hours of failure.
              </Typography>
            </Grid>
          </Grid>
        </Paper>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#ef4444", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Strategy</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>RPO</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>RTO</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Cost</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Best For</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {drStrategies.map((dr) => (
                <TableRow key={dr.strategy} sx={{ "&:hover": { bgcolor: alpha(dr.color, 0.05) } }}>
                  <TableCell sx={{ fontWeight: 700, color: dr.color }}>{dr.strategy}</TableCell>
                  <TableCell>{dr.rpo}</TableCell>
                  <TableCell>{dr.rto}</TableCell>
                  <TableCell>{dr.cost}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{dr.description}</TableCell>
                  <TableCell sx={{ fontSize: "0.75rem" }}>{dr.bestFor}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* ==================== COST OPTIMIZATION ==================== */}
        <Typography id="cost-optimization" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          💰 Cloud Cost Optimization & FinOps
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Best practices for optimizing cloud spending without sacrificing performance
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            <strong>FinOps</strong> (Cloud Financial Operations) is a cultural practice and discipline that brings financial accountability to the variable
            spend model of cloud. It involves cross-functional teams from finance, engineering, and business working together to optimize cloud costs.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {costOptimizationPractices.map((cop) => (
            <Grid item xs={12} sm={6} md={4} key={cop.practice}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e" }}>{cop.practice}</Typography>
                  <Chip label={cop.savings} size="small" sx={{ bgcolor: alpha("#22c55e", 0.1), color: "#22c55e", fontWeight: 700, fontSize: "0.7rem" }} />
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1, fontSize: "0.8rem" }}>{cop.description}</Typography>
                <Typography variant="caption" sx={{ display: "block", color: "text.secondary" }}>
                  <strong>Tools:</strong> {cop.tools}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== INSTANCE TYPES ==================== */}
        <Typography id="instance-types" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🖥️ Instance Type Categories
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Understanding compute instance families across AWS, Azure, and GCP
        </Typography>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#3b82f6", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Category</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>AWS</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Azure</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>GCP</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Use Cases</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {instanceCategories.map((ic) => (
                <TableRow key={ic.category} sx={{ "&:hover": { bgcolor: alpha("#3b82f6", 0.02) } }}>
                  <TableCell sx={{ fontWeight: 700, color: "#3b82f6" }}>{ic.category}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>{ic.awsTypes}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>{ic.azureTypes}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>{ic.gcpTypes}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{ic.useCase}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* ==================== KUBERNETES DEEP DIVE ==================== */}
        <Typography id="kubernetes" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          ☸️ Kubernetes Deep Dive
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Essential Kubernetes concepts for container orchestration
        </Typography>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {kubernetesConcepts.map((kc) => (
            <Grid item xs={12} sm={6} md={4} key={kc.concept}>
              <Paper sx={{ p: 2, borderRadius: 2, height: "100%", border: `1px solid ${alpha("#326ce5", 0.2)}`, bgcolor: alpha("#326ce5", 0.02) }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5, display: "flex", alignItems: "center", gap: 1 }}>
                  <span>{kc.icon}</span>
                  <span style={{ color: "#326ce5" }}>{kc.concept}</span>
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1, fontSize: "0.85rem" }}>{kc.description}</Typography>
                <Typography variant="caption" sx={{ color: "#326ce5" }}>
                  {kc.keyPoints}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== CLOUD CERTIFICATIONS ==================== */}
        <Typography id="certifications" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          📜 Cloud Certifications Guide
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Certification paths for AWS, Azure, and GCP to validate your cloud skills
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            Cloud certifications demonstrate your knowledge and can significantly boost your career. Start with foundational certs to understand concepts,
            then progress to associate and professional levels. <strong>Security certifications</strong> are especially valuable for cybersecurity professionals.
          </Typography>
        </Paper>

        {cloudCertifications.map((provider) => (
          <Box key={provider.provider} sx={{ mb: 4 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: provider.color }}>
              {provider.provider} Certifications
            </Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, border: `2px solid ${alpha(provider.color, 0.2)}` }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha(provider.color, 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Certification</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Level</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Study Time</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Prerequisites</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Focus Areas</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {provider.certs.map((cert) => (
                    <TableRow key={cert.name} sx={{ "&:hover": { bgcolor: alpha(provider.color, 0.02) } }}>
                      <TableCell sx={{ fontWeight: 600 }}>{cert.name}</TableCell>
                      <TableCell>
                        <Chip
                          label={cert.level}
                          size="small"
                          sx={{
                            fontSize: "0.65rem",
                            bgcolor: cert.level === "Foundational" ? alpha("#22c55e", 0.1) :
                                     cert.level === "Associate" ? alpha("#3b82f6", 0.1) :
                                     cert.level === "Professional" || cert.level === "Expert" ? alpha("#8b5cf6", 0.1) :
                                     alpha("#f59e0b", 0.1),
                            color: cert.level === "Foundational" ? "#22c55e" :
                                   cert.level === "Associate" ? "#3b82f6" :
                                   cert.level === "Professional" || cert.level === "Expert" ? "#8b5cf6" :
                                   "#f59e0b"
                          }}
                        />
                      </TableCell>
                      <TableCell sx={{ fontSize: "0.8rem" }}>{cert.duration}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem", color: "text.secondary" }}>{cert.prereq}</TableCell>
                      <TableCell sx={{ fontSize: "0.75rem" }}>{cert.focus}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        ))}

        <Paper sx={{ p: 3, mb: 5, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TipsAndUpdatesIcon sx={{ color: "#22c55e" }} />
            Certification Tips
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 0.5 }}>Start with Fundamentals</Typography>
              <Typography variant="body2" color="text.secondary">
                Foundation certs (Cloud Practitioner, AZ-900, Cloud Digital Leader) build essential knowledge and are quick to earn.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 0.5 }}>Hands-On Practice</Typography>
              <Typography variant="body2" color="text.secondary">
                Use free tiers and sandboxes. AWS, Azure, and GCP all offer free credits for learning. Labs are essential for passing exams.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 0.5 }}>Cross-Cloud Value</Typography>
              <Typography variant="body2" color="text.secondary">
                Concepts transfer between providers. Learning one cloud well makes learning others much easier. Focus on understanding why, not just how.
              </Typography>
            </Grid>
          </Grid>
        </Paper>

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

        {/* Quiz Section */}
        <Box id="quiz" sx={{ mt: 5 }}>
          <QuizSection
            questions={quizPool}
            accentColor={ACCENT_COLOR}
            title="Cloud Computing Fundamentals Knowledge Check"
            description="Random 10-question quiz drawn from a 75-question bank each time the page loads."
            questionsPerQuiz={QUIZ_QUESTION_COUNT}
          />
        </Box>

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
        </Box>
      </Box>
    </LearnPageLayout>
  );
};

export default CloudComputingPage;
