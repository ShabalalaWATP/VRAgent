import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Box,
  Typography,
  Paper,
  Avatar,
  Chip,
  Grid,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  alpha,
  useTheme,
  useMediaQuery,
  Drawer,
  Fab,
  Button,
  Divider,
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
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ArrowRightIcon from "@mui/icons-material/ArrowRight";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import MenuIcon from "@mui/icons-material/Menu";
import SupportAgentIcon from "@mui/icons-material/SupportAgent";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import SettingsIcon from "@mui/icons-material/Settings";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import LoopIcon from "@mui/icons-material/Loop";
import BuildIcon from "@mui/icons-material/Build";
import SecurityIcon from "@mui/icons-material/Security";
import GroupsIcon from "@mui/icons-material/Groups";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import WorkspacePremiumIcon from "@mui/icons-material/WorkspacePremium";
import HubIcon from "@mui/icons-material/Hub";
import ViewInArIcon from "@mui/icons-material/ViewInAr";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";

const ACCENT_COLOR = "#059669"; // Emerald for ITIL

// ========== QUIZ BANK (75 questions, 5 topics) ==========
const quizQuestions: QuizQuestion[] = [
  // Topic 1: ITIL 4 Fundamentals (15 questions)
  {
    id: 1,
    topic: "ITIL 4 Fundamentals",
    question: "What does ITIL stand for?",
    options: ["Information Technology Infrastructure Library", "Integrated Technology Information Library", "Information Technology Integration Library", "Infrastructure Technology Information Library"],
    correctAnswer: 0,
    explanation: "ITIL stands for Information Technology Infrastructure Library, a framework for IT service management."
  },
  {
    id: 2,
    topic: "ITIL 4 Fundamentals",
    question: "What is the definition of a 'service' in ITIL 4?",
    options: ["A software application", "A means of enabling value co-creation", "A technical infrastructure component", "A support team function"],
    correctAnswer: 1,
    explanation: "In ITIL 4, a service is defined as a means of enabling value co-creation by facilitating outcomes customers want to achieve."
  },
  {
    id: 3,
    topic: "ITIL 4 Fundamentals",
    question: "What is the core component of the ITIL 4 framework?",
    options: ["Service Lifecycle", "Service Value System (SVS)", "ITIL Processes", "Service Catalog"],
    correctAnswer: 1,
    explanation: "The Service Value System (SVS) is the core component of ITIL 4, representing how all components work together to create value."
  },
  {
    id: 4,
    topic: "ITIL 4 Fundamentals",
    question: "How many guiding principles does ITIL 4 define?",
    options: ["5", "6", "7", "8"],
    correctAnswer: 2,
    explanation: "ITIL 4 defines 7 guiding principles that provide universal guidance for organizations."
  },
  {
    id: 5,
    topic: "ITIL 4 Fundamentals",
    question: "What is 'value' in ITIL 4?",
    options: ["The cost of a service", "The perceived benefits, usefulness, and importance of something", "The SLA metrics", "The number of users"],
    correctAnswer: 1,
    explanation: "Value is the perceived benefits, usefulness, and importance of something. It is co-created between provider and consumer."
  },
  {
    id: 6,
    topic: "ITIL 4 Fundamentals",
    question: "What organization owns ITIL?",
    options: ["PMI", "AXELOS", "ISO", "ISACA"],
    correctAnswer: 1,
    explanation: "ITIL is owned by AXELOS, a joint venture company that also owns PRINCE2 and other best practice frameworks."
  },
  {
    id: 7,
    topic: "ITIL 4 Fundamentals",
    question: "What are the four dimensions of service management in ITIL 4?",
    options: ["People, Process, Technology, Partners", "Organizations & People, Information & Technology, Partners & Suppliers, Value Streams & Processes", "Strategy, Design, Transition, Operations", "Plan, Build, Run, Improve"],
    correctAnswer: 1,
    explanation: "The four dimensions are: Organizations & People, Information & Technology, Partners & Suppliers, and Value Streams & Processes."
  },
  {
    id: 8,
    topic: "ITIL 4 Fundamentals",
    question: "What is the difference between 'utility' and 'warranty'?",
    options: ["They are the same", "Utility is fitness for purpose, warranty is fitness for use", "Utility is cost, warranty is quality", "Utility is speed, warranty is reliability"],
    correctAnswer: 1,
    explanation: "Utility is fitness for purpose (what the service does), while warranty is fitness for use (how the service performs)."
  },
  {
    id: 9,
    topic: "ITIL 4 Fundamentals",
    question: "What is an 'outcome' in ITIL 4?",
    options: ["The same as an output", "A result for a stakeholder enabled by outputs", "A service level target", "A process metric"],
    correctAnswer: 1,
    explanation: "An outcome is a result for a stakeholder enabled by one or more outputs. Outputs are deliverables; outcomes are results."
  },
  {
    id: 10,
    topic: "ITIL 4 Fundamentals",
    question: "What replaced the 'Service Lifecycle' from ITIL v3?",
    options: ["Service Pipeline", "Service Value System", "Service Catalog", "Service Portfolio"],
    correctAnswer: 1,
    explanation: "ITIL 4 replaced the Service Lifecycle with the Service Value System (SVS), a more flexible, holistic approach."
  },
  {
    id: 11,
    topic: "ITIL 4 Fundamentals",
    question: "What is a 'service offering' in ITIL 4?",
    options: ["A single service", "A description of services designed for a particular consumer group", "A service catalog", "A service request"],
    correctAnswer: 1,
    explanation: "A service offering is a description of one or more services designed to address the needs of a target consumer group."
  },
  {
    id: 12,
    topic: "ITIL 4 Fundamentals",
    question: "What is 'value co-creation'?",
    options: ["Provider creates all value", "Consumer creates all value", "Value is created jointly by provider and consumer", "Value is created by technology"],
    correctAnswer: 2,
    explanation: "Value co-creation recognizes that value is created through an active collaboration between providers and consumers."
  },
  {
    id: 13,
    topic: "ITIL 4 Fundamentals",
    question: "What is a 'service relationship'?",
    options: ["The SLA between parties", "A cooperation between a service provider and service consumer", "A contract", "A support ticket"],
    correctAnswer: 1,
    explanation: "A service relationship is a cooperation between a service provider and service consumer, including service provision, consumption, and management."
  },
  {
    id: 14,
    topic: "ITIL 4 Fundamentals",
    question: "How many practices does ITIL 4 define?",
    options: ["26", "30", "34", "40"],
    correctAnswer: 2,
    explanation: "ITIL 4 defines 34 practices, divided into General Management, Service Management, and Technical Management practices."
  },
  {
    id: 15,
    topic: "ITIL 4 Fundamentals",
    question: "What is the purpose of the Service Value System?",
    options: ["To define SLAs", "To ensure the organization continually co-creates value", "To manage incidents", "To control changes"],
    correctAnswer: 1,
    explanation: "The SVS ensures that the organization continually co-creates value with all stakeholders through the use and management of products and services."
  },

  // Topic 2: Guiding Principles (15 questions)
  {
    id: 16,
    topic: "Guiding Principles",
    question: "Which guiding principle emphasizes understanding the current state before making changes?",
    options: ["Focus on value", "Start where you are", "Progress iteratively with feedback", "Keep it simple and practical"],
    correctAnswer: 1,
    explanation: "'Start where you are' emphasizes understanding and assessing the current state before making improvements."
  },
  {
    id: 17,
    topic: "Guiding Principles",
    question: "Which guiding principle encourages breaking work into smaller, manageable sections?",
    options: ["Focus on value", "Think and work holistically", "Progress iteratively with feedback", "Optimize and automate"],
    correctAnswer: 2,
    explanation: "'Progress iteratively with feedback' encourages working in iterations, getting feedback, and making improvements."
  },
  {
    id: 18,
    topic: "Guiding Principles",
    question: "Which guiding principle reminds us to consider the end-to-end delivery of value?",
    options: ["Focus on value", "Think and work holistically", "Collaborate and promote visibility", "Keep it simple and practical"],
    correctAnswer: 1,
    explanation: "'Think and work holistically' reminds us that no service or component stands alone; consider the whole system."
  },
  {
    id: 19,
    topic: "Guiding Principles",
    question: "What is the first guiding principle in ITIL 4?",
    options: ["Start where you are", "Focus on value", "Progress iteratively", "Collaborate"],
    correctAnswer: 1,
    explanation: "'Focus on value' is the first guiding principle, emphasizing that everything should link back to value for stakeholders."
  },
  {
    id: 20,
    topic: "Guiding Principles",
    question: "Which principle promotes transparency and good communication?",
    options: ["Focus on value", "Think and work holistically", "Collaborate and promote visibility", "Keep it simple and practical"],
    correctAnswer: 2,
    explanation: "'Collaborate and promote visibility' promotes working together across boundaries with transparency."
  },
  {
    id: 21,
    topic: "Guiding Principles",
    question: "Which principle advises against adding unnecessary complexity?",
    options: ["Focus on value", "Optimize and automate", "Keep it simple and practical", "Start where you are"],
    correctAnswer: 2,
    explanation: "'Keep it simple and practical' advises using the minimum number of steps and avoiding unnecessary complexity."
  },
  {
    id: 22,
    topic: "Guiding Principles",
    question: "Which principle should be applied AFTER 'keep it simple and practical'?",
    options: ["Focus on value", "Optimize and automate", "Think and work holistically", "Start where you are"],
    correctAnswer: 1,
    explanation: "'Optimize and automate' should be applied after simplifying. First simplify, then optimize and automate where appropriate."
  },
  {
    id: 23,
    topic: "Guiding Principles",
    question: "What does 'Focus on value' mean for IT services?",
    options: ["Reduce costs at all costs", "Everything should contribute to value for stakeholders", "Focus only on technology", "Maximize automation"],
    correctAnswer: 1,
    explanation: "'Focus on value' means every activity should contribute directly or indirectly to value for stakeholders."
  },
  {
    id: 24,
    topic: "Guiding Principles",
    question: "When applying 'Start where you are', what should you do first?",
    options: ["Discard everything and start fresh", "Assess and understand the current state", "Implement new tools immediately", "Hire new staff"],
    correctAnswer: 1,
    explanation: "Before improving, you should assess and understand what currently exists and what value it provides."
  },
  {
    id: 25,
    topic: "Guiding Principles",
    question: "What is the benefit of 'Progress iteratively with feedback'?",
    options: ["Faster project completion", "Early value delivery and course correction", "Less documentation", "Fewer meetings"],
    correctAnswer: 1,
    explanation: "Iterative progress allows for early delivery of value and the ability to correct course based on feedback."
  },
  {
    id: 26,
    topic: "Guiding Principles",
    question: "What does 'Collaborate and promote visibility' discourage?",
    options: ["Team meetings", "Silos and hidden agendas", "Documentation", "Automation"],
    correctAnswer: 1,
    explanation: "This principle discourages working in silos and having hidden agendas that reduce transparency."
  },
  {
    id: 27,
    topic: "Guiding Principles",
    question: "How should the guiding principles be applied?",
    options: ["Only one at a time", "All together, considering each in context", "Only during implementation", "Only by management"],
    correctAnswer: 1,
    explanation: "The guiding principles should be applied together, with each principle considered in the context of the situation."
  },
  {
    id: 28,
    topic: "Guiding Principles",
    question: "Which principle helps prevent 'analysis paralysis'?",
    options: ["Focus on value", "Start where you are", "Progress iteratively with feedback", "Think and work holistically"],
    correctAnswer: 2,
    explanation: "'Progress iteratively with feedback' helps prevent over-analysis by encouraging small, iterative improvements."
  },
  {
    id: 29,
    topic: "Guiding Principles",
    question: "What should be optimized before automating?",
    options: ["Nothing", "The workflow or process", "The technology", "The budget"],
    correctAnswer: 1,
    explanation: "You should simplify and optimize workflows before automating them. Automating a bad process just makes it faster."
  },
  {
    id: 30,
    topic: "Guiding Principles",
    question: "Who defines what 'value' means?",
    options: ["The IT department", "The service consumer", "The CEO", "The vendor"],
    correctAnswer: 1,
    explanation: "Value is always defined from the perspective of the service consumer, not the provider."
  },

  // Topic 3: Service Value Chain (15 questions)
  {
    id: 31,
    topic: "Service Value Chain",
    question: "How many activities are in the Service Value Chain?",
    options: ["4", "5", "6", "7"],
    correctAnswer: 2,
    explanation: "The Service Value Chain has 6 activities: Plan, Improve, Engage, Design & Transition, Obtain/Build, and Deliver & Support."
  },
  {
    id: 32,
    topic: "Service Value Chain",
    question: "What is the purpose of the 'Plan' activity?",
    options: ["To deploy services", "To ensure shared understanding of vision and improvement direction", "To handle incidents", "To manage suppliers"],
    correctAnswer: 1,
    explanation: "Plan ensures a shared understanding of the vision, current status, and improvement direction for all four dimensions."
  },
  {
    id: 33,
    topic: "Service Value Chain",
    question: "Which activity provides good understanding of stakeholder needs?",
    options: ["Plan", "Engage", "Design & Transition", "Deliver & Support"],
    correctAnswer: 1,
    explanation: "Engage provides good understanding of stakeholder needs, transparency, and continual engagement."
  },
  {
    id: 34,
    topic: "Service Value Chain",
    question: "What does the 'Design & Transition' activity ensure?",
    options: ["Services are deployed only", "Products and services meet stakeholder expectations", "Incidents are resolved", "Changes are rejected"],
    correctAnswer: 1,
    explanation: "Design & Transition ensures products and services continually meet stakeholder expectations for quality, costs, and time."
  },
  {
    id: 35,
    topic: "Service Value Chain",
    question: "Which activity ensures service components are available when needed?",
    options: ["Plan", "Engage", "Obtain/Build", "Improve"],
    correctAnswer: 2,
    explanation: "Obtain/Build ensures service components are available when and where they are needed and meet specifications."
  },
  {
    id: 36,
    topic: "Service Value Chain",
    question: "What is the purpose of 'Deliver & Support'?",
    options: ["Plan new services", "Ensure services are delivered and supported according to specifications", "Improve all activities", "Engage stakeholders"],
    correctAnswer: 1,
    explanation: "Deliver & Support ensures services are delivered and supported according to agreed specifications and expectations."
  },
  {
    id: 37,
    topic: "Service Value Chain",
    question: "Which activity ensures continual improvement of products, services, and practices?",
    options: ["Plan", "Engage", "Design & Transition", "Improve"],
    correctAnswer: 3,
    explanation: "Improve ensures continual improvement of products, services, and practices across all value chain activities."
  },
  {
    id: 38,
    topic: "Service Value Chain",
    question: "What is a 'value stream' in ITIL 4?",
    options: ["A single process", "A series of steps to create and deliver products and services", "A financial metric", "A service catalog entry"],
    correctAnswer: 1,
    explanation: "A value stream is a series of steps an organization takes to create and deliver products and services to consumers."
  },
  {
    id: 39,
    topic: "Service Value Chain",
    question: "Can value chain activities be combined?",
    options: ["Never", "Yes, to create value streams for specific scenarios", "Only during emergencies", "Only for small organizations"],
    correctAnswer: 1,
    explanation: "Value chain activities can be combined in various ways to create value streams tailored to specific scenarios."
  },
  {
    id: 40,
    topic: "Service Value Chain",
    question: "What is the input to the Service Value Chain?",
    options: ["Incidents", "Demand and opportunities", "Changes", "Problems"],
    correctAnswer: 1,
    explanation: "Demand (for products and services) and opportunities (to improve) are the inputs to the Service Value Chain."
  },
  {
    id: 41,
    topic: "Service Value Chain",
    question: "What is the output of the Service Value Chain?",
    options: ["Incidents resolved", "Value for the organization and stakeholders", "Reports", "Service requests fulfilled"],
    correctAnswer: 1,
    explanation: "The output of the Service Value Chain is value for the organization, its customers, and other stakeholders."
  },
  {
    id: 42,
    topic: "Service Value Chain",
    question: "Which activity transforms demand into value?",
    options: ["Only Plan", "Only Deliver & Support", "All six activities working together", "Only Improve"],
    correctAnswer: 2,
    explanation: "All six activities work together to transform demand and opportunities into value for stakeholders."
  },
  {
    id: 43,
    topic: "Service Value Chain",
    question: "Is the Service Value Chain linear?",
    options: ["Yes, always sequential", "No, activities can occur in any order", "Yes, but with exceptions", "No, it's purely random"],
    correctAnswer: 1,
    explanation: "The Service Value Chain is NOT linear. Activities can occur in any order based on the specific value stream."
  },
  {
    id: 44,
    topic: "Service Value Chain",
    question: "What does 'Engage' help establish?",
    options: ["Technical infrastructure", "Good relationships with and between stakeholders", "Financial budgets", "Service levels"],
    correctAnswer: 1,
    explanation: "Engage helps establish good relationships with and between all stakeholders at strategic and tactical levels."
  },
  {
    id: 45,
    topic: "Service Value Chain",
    question: "How does 'Improve' relate to other activities?",
    options: ["It runs separately", "It applies to all other activities and the entire SVS", "It only applies to technology", "It only runs annually"],
    correctAnswer: 1,
    explanation: "Improve applies to all value chain activities, practices, products, services, and the entire Service Value System."
  },

  // Topic 4: ITIL Practices (15 questions)
  {
    id: 46,
    topic: "ITIL Practices",
    question: "How are ITIL 4 practices categorized?",
    options: ["By size", "General Management, Service Management, Technical Management", "By complexity", "By cost"],
    correctAnswer: 1,
    explanation: "ITIL 4 practices are categorized as: General Management (14), Service Management (17), and Technical Management (3)."
  },
  {
    id: 47,
    topic: "ITIL Practices",
    question: "What is the purpose of the 'Incident Management' practice?",
    options: ["Prevent future incidents", "Minimize negative impact by restoring service as quickly as possible", "Investigate root causes", "Approve changes"],
    correctAnswer: 1,
    explanation: "Incident Management minimizes the negative impact of incidents by restoring normal service operation as quickly as possible."
  },
  {
    id: 48,
    topic: "ITIL Practices",
    question: "What is the purpose of 'Problem Management'?",
    options: ["Restore services quickly", "Reduce likelihood and impact of incidents by identifying causes and managing workarounds", "Deploy changes", "Handle service requests"],
    correctAnswer: 1,
    explanation: "Problem Management reduces the likelihood and impact of incidents by identifying root causes and managing workarounds."
  },
  {
    id: 49,
    topic: "ITIL Practices",
    question: "What is the purpose of 'Change Enablement'?",
    options: ["Block all changes", "Maximize successful changes by proper assessment and authorization", "Only approve emergency changes", "Document changes after the fact"],
    correctAnswer: 1,
    explanation: "Change Enablement maximizes the number of successful IT changes by ensuring proper risk assessment and authorization."
  },
  {
    id: 50,
    topic: "ITIL Practices",
    question: "What is a 'Service Request'?",
    options: ["An incident report", "A request for information, advice, or a standard change", "A problem ticket", "A change proposal"],
    correctAnswer: 1,
    explanation: "A service request is a request from a user for information, advice, a standard change, or access to a service."
  },
  {
    id: 51,
    topic: "ITIL Practices",
    question: "Which practice manages the full lifecycle of IT assets?",
    options: ["Incident Management", "IT Asset Management", "Change Enablement", "Problem Management"],
    correctAnswer: 1,
    explanation: "IT Asset Management manages the full lifecycle of IT assets to maximize value and control costs."
  },
  {
    id: 52,
    topic: "ITIL Practices",
    question: "What is the purpose of 'Service Level Management'?",
    options: ["Manage incidents", "Set clear business-based targets for service performance", "Deploy changes", "Manage problems"],
    correctAnswer: 1,
    explanation: "Service Level Management sets clear targets for service performance and enables monitoring against these targets."
  },
  {
    id: 53,
    topic: "ITIL Practices",
    question: "Which practice ensures accurate information about services is available?",
    options: ["Incident Management", "Service Catalog Management", "Change Enablement", "Problem Management"],
    correctAnswer: 1,
    explanation: "Service Catalog Management ensures accurate and consistent information about services is available to those who need it."
  },
  {
    id: 54,
    topic: "ITIL Practices",
    question: "What is the purpose of 'Continual Improvement'?",
    options: ["One-time improvement projects", "Align practices and services with changing business needs", "Annual reviews only", "Technology upgrades only"],
    correctAnswer: 1,
    explanation: "Continual Improvement aligns the organization's practices and services with changing business needs through ongoing improvement."
  },
  {
    id: 55,
    topic: "ITIL Practices",
    question: "Which practice controls access to services?",
    options: ["Incident Management", "Service Request Management", "Access Management", "Change Enablement"],
    correctAnswer: 2,
    explanation: "Access Management controls access to services by granting authorized users rights to use services."
  },
  {
    id: 56,
    topic: "ITIL Practices",
    question: "What is 'Release Management' responsible for?",
    options: ["Coding software", "Making new and changed services available for use", "Testing only", "Incident resolution"],
    correctAnswer: 1,
    explanation: "Release Management makes new and changed services and features available for use."
  },
  {
    id: 57,
    topic: "ITIL Practices",
    question: "Which practice manages risks to confidentiality, integrity, and availability?",
    options: ["Risk Management", "Information Security Management", "Incident Management", "Change Enablement"],
    correctAnswer: 1,
    explanation: "Information Security Management protects information needed by the organization by managing risks to confidentiality, integrity, and availability."
  },
  {
    id: 58,
    topic: "ITIL Practices",
    question: "What is a 'known error' in Problem Management?",
    options: ["An undiagnosed problem", "A problem with documented root cause and workaround", "An incident", "A service request"],
    correctAnswer: 1,
    explanation: "A known error is a problem with a documented root cause and workaround, awaiting a permanent fix."
  },
  {
    id: 59,
    topic: "ITIL Practices",
    question: "Which practice is responsible for 'deployment'?",
    options: ["Release Management", "Deployment Management", "Change Enablement", "Incident Management"],
    correctAnswer: 1,
    explanation: "Deployment Management moves new or changed components to live environments. Release makes them available; Deployment moves them."
  },
  {
    id: 60,
    topic: "ITIL Practices",
    question: "What type of change is 'pre-authorized' with low risk?",
    options: ["Emergency change", "Normal change", "Standard change", "Major change"],
    correctAnswer: 2,
    explanation: "A standard change is pre-authorized, low-risk, well-understood, and follows a documented procedure."
  },

  // Topic 5: SVS Components & Certifications (15 questions)
  {
    id: 61,
    topic: "SVS & Certifications",
    question: "What are the five components of the Service Value System?",
    options: ["Plan, Build, Run, Monitor, Improve", "Guiding Principles, Governance, Service Value Chain, Practices, Continual Improvement", "Strategy, Design, Transition, Operation, Improvement", "Demand, Engage, Deliver, Support, Improve"],
    correctAnswer: 1,
    explanation: "The SVS has five components: Guiding Principles, Governance, Service Value Chain, Practices, and Continual Improvement."
  },
  {
    id: 62,
    topic: "SVS & Certifications",
    question: "What is the role of 'Governance' in the SVS?",
    options: ["Day-to-day operations", "Directs and controls the organization", "Technical implementation", "Incident handling"],
    correctAnswer: 1,
    explanation: "Governance directs and controls the organization through policies, procedures, and defined roles and responsibilities."
  },
  {
    id: 63,
    topic: "SVS & Certifications",
    question: "How many General Management Practices are there in ITIL 4?",
    options: ["10", "14", "17", "20"],
    correctAnswer: 1,
    explanation: "ITIL 4 defines 14 General Management Practices that apply broadly across organizations."
  },
  {
    id: 64,
    topic: "SVS & Certifications",
    question: "How many Service Management Practices are there?",
    options: ["14", "17", "20", "26"],
    correctAnswer: 1,
    explanation: "ITIL 4 defines 17 Service Management Practices specific to IT service management."
  },
  {
    id: 65,
    topic: "SVS & Certifications",
    question: "How many Technical Management Practices are there?",
    options: ["2", "3", "4", "5"],
    correctAnswer: 1,
    explanation: "ITIL 4 defines 3 Technical Management Practices: Deployment Management, Infrastructure & Platform Management, and Software Development & Management."
  },
  {
    id: 66,
    topic: "SVS & Certifications",
    question: "What is the entry-level ITIL 4 certification?",
    options: ["ITIL Practitioner", "ITIL Foundation", "ITIL Specialist", "ITIL Expert"],
    correctAnswer: 1,
    explanation: "ITIL 4 Foundation is the entry-level certification, covering key concepts and terminology."
  },
  {
    id: 67,
    topic: "SVS & Certifications",
    question: "What certification follows ITIL Foundation in the Managing Professional stream?",
    options: ["ITIL Master", "ITIL Specialist modules", "ITIL Strategist", "ITIL Leader"],
    correctAnswer: 1,
    explanation: "After Foundation, the Managing Professional stream includes Specialist modules like CDS, DSV, HVIT, and DPI."
  },
  {
    id: 68,
    topic: "SVS & Certifications",
    question: "What does CDS stand for in ITIL 4 certification?",
    options: ["Create, Deliver, Support", "Configure, Deploy, Support", "Change, Design, Service", "Continual Delivery Service"],
    correctAnswer: 0,
    explanation: "CDS stands for Create, Deliver and Support - one of the ITIL 4 Specialist modules."
  },
  {
    id: 69,
    topic: "SVS & Certifications",
    question: "What is the highest ITIL designation?",
    options: ["ITIL Expert", "ITIL Master", "ITIL Strategist", "ITIL Managing Professional"],
    correctAnswer: 1,
    explanation: "ITIL Master is the highest designation, demonstrating the ability to apply ITIL in diverse situations."
  },
  {
    id: 70,
    topic: "SVS & Certifications",
    question: "What is the Continual Improvement Model?",
    options: ["A single step", "A structured approach for implementing improvements", "An annual review", "A technology upgrade"],
    correctAnswer: 1,
    explanation: "The Continual Improvement Model is a structured approach to implementing improvements using iterative steps."
  },
  {
    id: 71,
    topic: "SVS & Certifications",
    question: "What question does the Continual Improvement Model start with?",
    options: ["How do we get there?", "What is the vision?", "Where are we now?", "Did we get there?"],
    correctAnswer: 1,
    explanation: "The model starts with 'What is the vision?' to establish the improvement direction aligned with objectives."
  },
  {
    id: 72,
    topic: "SVS & Certifications",
    question: "What external factor should be considered alongside the four dimensions?",
    options: ["Technology only", "PESTLE factors (Political, Economic, Social, Technological, Legal, Environmental)", "Vendors only", "Budgets only"],
    correctAnswer: 1,
    explanation: "PESTLE factors are external factors that constrain or influence how service providers operate."
  },
  {
    id: 73,
    topic: "SVS & Certifications",
    question: "What does 'DPI' stand for in ITIL 4 certification?",
    options: ["Design, Plan, Implement", "Direct, Plan and Improve", "Deliver, Provide, Improve", "Define, Process, Iterate"],
    correctAnswer: 1,
    explanation: "DPI stands for Direct, Plan and Improve - one of the ITIL 4 Strategist modules."
  },
  {
    id: 74,
    topic: "SVS & Certifications",
    question: "Which certification stream focuses on strategic and business direction?",
    options: ["Managing Professional", "Strategic Leader", "Technical Practitioner", "Service Operator"],
    correctAnswer: 1,
    explanation: "The Strategic Leader stream focuses on strategic direction and business alignment with ITIL."
  },
  {
    id: 75,
    topic: "SVS & Certifications",
    question: "What is the purpose of the 'Monitoring and Event Management' practice?",
    options: ["Manage incidents", "Systematically observe services and record events", "Deploy changes", "Create reports"],
    correctAnswer: 1,
    explanation: "Monitoring and Event Management systematically observes services and components, recording and reporting state changes as events."
  },
];

// ========== SIDEBAR SECTIONS ==========
const sections = [
  { id: "introduction", label: "Introduction" },
  { id: "key-concepts", label: "Key Concepts" },
  { id: "four-dimensions", label: "Four Dimensions" },
  { id: "svs-overview", label: "Service Value System" },
  { id: "guiding-principles", label: "Guiding Principles" },
  { id: "governance", label: "Governance" },
  { id: "service-value-chain", label: "Service Value Chain" },
  { id: "practices-overview", label: "Practices Overview" },
  { id: "general-practices", label: "General Practices" },
  { id: "service-practices", label: "Service Practices" },
  { id: "technical-practices", label: "Technical Practices" },
  { id: "continual-improvement", label: "Continual Improvement" },
  { id: "certifications", label: "Certifications" },
  { id: "quiz", label: "Knowledge Check" },
];

export default function ITILv4GuidePage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const [activeSection, setActiveSection] = useState("introduction");
  const [mobileDrawerOpen, setMobileDrawerOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      const sectionElements = sections.map(({ id }) => ({
        id,
        el: document.getElementById(id),
      }));
      const scrollPosition = window.scrollY + 120;
      for (let i = sectionElements.length - 1; i >= 0; i--) {
        const { id, el } = sectionElements[i];
        if (el && el.offsetTop <= scrollPosition) {
          setActiveSection(id);
          break;
        }
      }
    };
    window.addEventListener("scroll", handleScroll, { passive: true });
    handleScroll();
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const scrollToSection = (id: string) => {
    const el = document.getElementById(id);
    if (el) {
      const yOffset = -80;
      const y = el.getBoundingClientRect().top + window.pageYOffset + yOffset;
      window.scrollTo({ top: y, behavior: "smooth" });
    }
    setMobileDrawerOpen(false);
  };

  const completedSections = sections.findIndex((s) => s.id === activeSection) + 1;
  const progressPercent = Math.round((completedSections / sections.length) * 100);

  const sidebarContent = (
    <Box sx={{ p: 2 }}>
      <Box sx={{ mb: 2 }}>
        <Typography variant="caption" color="text.secondary">
          Progress: {progressPercent}%
        </Typography>
        <Box
          sx={{
            height: 4,
            borderRadius: 2,
            bgcolor: alpha(ACCENT_COLOR, 0.2),
            mt: 0.5,
          }}
        >
          <Box
            sx={{
              height: "100%",
              borderRadius: 2,
              bgcolor: ACCENT_COLOR,
              width: `${progressPercent}%`,
              transition: "width 0.3s ease",
            }}
          />
        </Box>
      </Box>
      {sections.map((section, idx) => {
        const isActive = activeSection === section.id;
        const isCompleted = idx < sections.findIndex((s) => s.id === activeSection);
        return (
          <Box
            key={section.id}
            onClick={() => scrollToSection(section.id)}
            sx={{
              display: "flex",
              alignItems: "center",
              gap: 1,
              p: 1,
              borderRadius: 1,
              cursor: "pointer",
              bgcolor: isActive ? alpha(ACCENT_COLOR, 0.15) : "transparent",
              borderLeft: isActive ? `3px solid ${ACCENT_COLOR}` : "3px solid transparent",
              "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.08) },
              transition: "all 0.2s ease",
            }}
          >
            {isCompleted ? (
              <CheckCircleIcon sx={{ fontSize: 16, color: ACCENT_COLOR }} />
            ) : (
              <ArrowRightIcon sx={{ fontSize: 16, color: isActive ? ACCENT_COLOR : "text.disabled" }} />
            )}
            <Typography
              variant="body2"
              sx={{
                fontWeight: isActive ? 600 : 400,
                color: isActive ? ACCENT_COLOR : "text.secondary",
                fontSize: "0.8rem",
              }}
            >
              {section.label}
            </Typography>
          </Box>
        );
      })}
    </Box>
  );

  const pageContext = `ITIL 4 Guide - Comprehensive guide to IT Service Management covering the Service Value System, 7 Guiding Principles, Service Value Chain, 34 Practices, Four Dimensions, Continual Improvement, and certification paths.`;

  return (
    <LearnPageLayout pageTitle="ITIL 4 Guide" pageContext={pageContext}>
      <Box sx={{ display: "flex", minHeight: "100vh" }}>
        {/* Desktop Sidebar */}
        {!isMobile && (
          <Box
            sx={{
              width: 260,
              flexShrink: 0,
              position: "sticky",
              top: 80,
              height: "calc(100vh - 100px)",
              overflowY: "auto",
              borderRight: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            }}
          >
            {sidebarContent}
          </Box>
        )}

        {/* Mobile Drawer */}
        {isMobile && (
          <>
            <Drawer
              anchor="left"
              open={mobileDrawerOpen}
              onClose={() => setMobileDrawerOpen(false)}
              PaperProps={{ sx: { width: 260 } }}
            >
              {sidebarContent}
            </Drawer>
            <Fab
              size="small"
              onClick={() => setMobileDrawerOpen(true)}
              sx={{
                position: "fixed",
                bottom: 80,
                left: 16,
                zIndex: 1000,
                bgcolor: ACCENT_COLOR,
                color: "white",
                "&:hover": { bgcolor: alpha(ACCENT_COLOR, 0.9) },
              }}
            >
              <MenuIcon />
            </Fab>
          </>
        )}

        {/* Main Content */}
        <Box sx={{ flex: 1, maxWidth: 900, mx: "auto", p: { xs: 2, md: 4 } }}>
          <Chip
            component={Link}
            to="/learn"
            icon={<ArrowBackIcon />}
            label="Back to Learning Hub"
            clickable
            variant="outlined"
            sx={{ borderRadius: 2, mb: 3 }}
          />

          {/* Hero Section */}
          <Paper
            id="introduction"
            elevation={0}
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              background: `linear-gradient(135deg, ${alpha(ACCENT_COLOR, 0.1)} 0%, ${alpha("#10b981", 0.05)} 100%)`,
              border: `1px solid ${alpha(ACCENT_COLOR, 0.2)}`,
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: ACCENT_COLOR, width: 64, height: 64 }}>
                <SupportAgentIcon sx={{ fontSize: 36 }} />
              </Avatar>
              <Box>
                <Typography variant="h3" sx={{ fontWeight: 800 }}>
                  ITIL 4 Guide
                </Typography>
                <Typography variant="h6" color="text.secondary">
                  IT Service Management Best Practices
                </Typography>
              </Box>
            </Box>
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              ITIL 4 (Information Technology Infrastructure Library) is the most widely adopted framework for IT
              service management. It provides comprehensive guidance for establishing, improving, and optimizing IT
              services to meet business needs and deliver value.
            </Typography>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
              {["ITSM", "Service Value", "Best Practice", "AXELOS", "Practices"].map((tag) => (
                <Chip
                  key={tag}
                  label={tag}
                  size="small"
                  sx={{ bgcolor: alpha(ACCENT_COLOR, 0.1), color: ACCENT_COLOR, fontWeight: 500 }}
                />
              ))}
            </Box>
          </Paper>

          {/* Key Concepts */}
          <Paper id="key-concepts" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <TipsAndUpdatesIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Key Concepts
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              ITIL 4 introduces fundamental concepts that underpin the entire framework. Understanding these is
              essential for effective IT service management.
            </Typography>
            <Grid container spacing={2}>
              {[
                { term: "Service", definition: "A means of enabling value co-creation by facilitating outcomes customers want to achieve", icon: "🎯" },
                { term: "Value", definition: "The perceived benefits, usefulness, and importance of something", icon: "💎" },
                { term: "Value Co-Creation", definition: "Value is created through active collaboration between providers and consumers", icon: "🤝" },
                { term: "Utility", definition: "The functionality offered by a product or service (fitness for purpose)", icon: "⚡" },
                { term: "Warranty", definition: "Assurance that a product or service will meet agreed requirements (fitness for use)", icon: "✅" },
                { term: "Outcome", definition: "A result for a stakeholder enabled by one or more outputs", icon: "🏆" },
              ].map((item) => (
                <Grid item xs={12} md={6} key={item.term}>
                  <Card sx={{ height: "100%", bgcolor: alpha(ACCENT_COLOR, 0.03) }}>
                    <CardContent>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                        <Typography variant="h5">{item.icon}</Typography>
                        <Typography variant="subtitle1" sx={{ fontWeight: 700, color: ACCENT_COLOR }}>
                          {item.term}
                        </Typography>
                      </Box>
                      <Typography variant="body2" color="text.secondary">
                        {item.definition}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Four Dimensions */}
          <Paper id="four-dimensions" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <ViewInArIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                The Four Dimensions
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              ITIL 4 defines four dimensions that must be considered for effective service management. All four
              dimensions must be balanced to ensure holistic value creation.
            </Typography>
            <Grid container spacing={2}>
              {[
                {
                  dimension: "Organizations & People",
                  description: "Structure, culture, roles, competencies, and how people collaborate",
                  examples: "Roles, responsibilities, skills, culture, communication",
                  color: "#3b82f6",
                },
                {
                  dimension: "Information & Technology",
                  description: "Information and knowledge, technologies, and relationships between them",
                  examples: "Tools, databases, knowledge bases, automation, AI/ML",
                  color: "#8b5cf6",
                },
                {
                  dimension: "Partners & Suppliers",
                  description: "Relationships with other organizations involved in service delivery",
                  examples: "Vendors, contracts, outsourcing, partnerships, service integration",
                  color: "#f59e0b",
                },
                {
                  dimension: "Value Streams & Processes",
                  description: "How activities and workflows convert inputs into outputs",
                  examples: "Workflows, procedures, controls, value streams, automation",
                  color: "#22c55e",
                },
              ].map((d) => (
                <Grid item xs={12} md={6} key={d.dimension}>
                  <Card sx={{ height: "100%", borderTop: `4px solid ${d.color}` }}>
                    <CardContent>
                      <Typography variant="h6" sx={{ fontWeight: 700, color: d.color, mb: 1 }}>
                        {d.dimension}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                        {d.description}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        <strong>Examples:</strong> {d.examples}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
            <Box sx={{ bgcolor: alpha(ACCENT_COLOR, 0.05), p: 2, borderRadius: 2, mt: 3 }}>
              <Typography variant="body2">
                <strong>External Factors:</strong> PESTLE factors (Political, Economic, Social, Technological, Legal,
                Environmental) influence all four dimensions and should be considered in service design and delivery.
              </Typography>
            </Box>
          </Paper>

          {/* Service Value System Overview */}
          <Paper id="svs-overview" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <HubIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Service Value System (SVS)
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Service Value System is the core of ITIL 4, describing how all components and activities work
              together to enable value creation. It takes demand and opportunities as inputs and outputs value.
            </Typography>
            <Box sx={{ bgcolor: "#1a1a2e", p: 3, borderRadius: 2, mb: 3, fontFamily: "monospace" }}>
              <Typography variant="subtitle2" sx={{ color: ACCENT_COLOR, mb: 2 }}>
                SVS Components:
              </Typography>
              <Typography variant="body2" component="pre" sx={{ color: "#e0e0e0", fontSize: "0.85rem" }}>
{`┌─────────────────────────────────────────────────────────────┐
│                  SERVICE VALUE SYSTEM                        │
│                                                              │
│  Inputs: Demand + Opportunities                              │
│                      ↓                                       │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │               GUIDING PRINCIPLES                        │ │
│  └─────────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                  GOVERNANCE                             │ │
│  └─────────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              SERVICE VALUE CHAIN                        │ │
│  │    Plan → Engage → Design/Transition → Obtain/Build     │ │
│  │              → Deliver/Support → Improve                │ │
│  └─────────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                   PRACTICES                             │ │
│  └─────────────────────────────────────────────────────────┘ │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │             CONTINUAL IMPROVEMENT                       │ │
│  └─────────────────────────────────────────────────────────┘ │
│                      ↓                                       │
│  Output: VALUE                                               │
└─────────────────────────────────────────────────────────────┘`}
              </Typography>
            </Box>
          </Paper>

          {/* Guiding Principles */}
          <Paper id="guiding-principles" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <TipsAndUpdatesIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                7 Guiding Principles
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The guiding principles are recommendations that guide an organization in all circumstances, regardless
              of changes in goals, strategies, or structure. They are universal and enduring.
            </Typography>
            <Grid container spacing={2}>
              {[
                { num: "1", principle: "Focus on Value", description: "Everything should link back to value, directly or indirectly. Value is defined by the consumer.", color: "#dc2626" },
                { num: "2", principle: "Start Where You Are", description: "Don't start from scratch. Assess the current state, understand what exists, and build on it.", color: "#f59e0b" },
                { num: "3", principle: "Progress Iteratively with Feedback", description: "Work in small iterations, get feedback, and improve. Avoid 'big bang' approaches.", color: "#22c55e" },
                { num: "4", principle: "Collaborate and Promote Visibility", description: "Work together across boundaries. Be transparent. Avoid silos and hidden agendas.", color: "#3b82f6" },
                { num: "5", principle: "Think and Work Holistically", description: "No service stands alone. Consider the whole system and all four dimensions.", color: "#8b5cf6" },
                { num: "6", principle: "Keep It Simple and Practical", description: "Use minimum steps. Avoid unnecessary complexity. Outcome-based thinking.", color: "#0891b2" },
                { num: "7", principle: "Optimize and Automate", description: "After simplifying, optimize workflows. Then automate where it adds value.", color: "#ec4899" },
              ].map((p) => (
                <Grid item xs={12} key={p.principle}>
                  <Card sx={{ display: "flex", alignItems: "center", gap: 2, p: 2, bgcolor: alpha(p.color, 0.03) }}>
                    <Box
                      sx={{
                        width: 40,
                        height: 40,
                        borderRadius: "50%",
                        bgcolor: p.color,
                        color: "white",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        fontWeight: 700,
                        flexShrink: 0,
                      }}
                    >
                      {p.num}
                    </Box>
                    <Box>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: p.color }}>
                        {p.principle}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {p.description}
                      </Typography>
                    </Box>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Governance */}
          <Paper id="governance" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <SecurityIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Governance
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Governance is the means by which an organization is directed and controlled. It ensures the organization's
              activities are aligned with the overall strategy and that policies are followed.
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={4}>
                <Card sx={{ height: "100%", textAlign: "center", p: 3, bgcolor: alpha(ACCENT_COLOR, 0.05) }}>
                  <Typography variant="h3">📋</Typography>
                  <Typography variant="h6" sx={{ fontWeight: 600, mt: 1 }}>
                    Evaluate
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Assess organizational strategy and portfolio against stakeholder needs
                  </Typography>
                </Card>
              </Grid>
              <Grid item xs={12} md={4}>
                <Card sx={{ height: "100%", textAlign: "center", p: 3, bgcolor: alpha(ACCENT_COLOR, 0.05) }}>
                  <Typography variant="h3">🎯</Typography>
                  <Typography variant="h6" sx={{ fontWeight: 600, mt: 1 }}>
                    Direct
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Set policies and priorities to guide organizational activities
                  </Typography>
                </Card>
              </Grid>
              <Grid item xs={12} md={4}>
                <Card sx={{ height: "100%", textAlign: "center", p: 3, bgcolor: alpha(ACCENT_COLOR, 0.05) }}>
                  <Typography variant="h3">📊</Typography>
                  <Typography variant="h6" sx={{ fontWeight: 600, mt: 1 }}>
                    Monitor
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Oversee performance and compliance with policies and direction
                  </Typography>
                </Card>
              </Grid>
            </Grid>
          </Paper>

          {/* Service Value Chain */}
          <Paper id="service-value-chain" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <AccountTreeIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Service Value Chain
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Service Value Chain is an operating model for service providers that outlines the key activities
              required to respond to demand and facilitate value realization. It is NOT linear.
            </Typography>
            <Grid container spacing={2}>
              {[
                { activity: "Plan", purpose: "Ensure shared understanding of vision, current status, and direction for all four dimensions", color: "#3b82f6" },
                { activity: "Improve", purpose: "Ensure continual improvement of products, services, and practices across all activities", color: "#22c55e" },
                { activity: "Engage", purpose: "Provide good understanding of stakeholder needs, transparency, and continual engagement", color: "#8b5cf6" },
                { activity: "Design & Transition", purpose: "Ensure products and services meet stakeholder expectations for quality, costs, and time-to-market", color: "#f59e0b" },
                { activity: "Obtain/Build", purpose: "Ensure service components are available when and where needed, meeting specifications", color: "#dc2626" },
                { activity: "Deliver & Support", purpose: "Ensure services are delivered and supported according to agreed specifications and expectations", color: "#0891b2" },
              ].map((a) => (
                <Grid item xs={12} md={6} key={a.activity}>
                  <Card sx={{ height: "100%", borderLeft: `4px solid ${a.color}` }}>
                    <CardContent>
                      <Typography variant="h6" sx={{ fontWeight: 700, color: a.color }}>
                        {a.activity}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {a.purpose}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Practices Overview */}
          <Paper id="practices-overview" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <BuildIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                ITIL 4 Practices
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              ITIL 4 defines 34 practices (replacing ITIL v3's processes) organized into three categories.
              Each practice is a set of organizational resources designed for performing work.
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha(ACCENT_COLOR, 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Category</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Count</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Focus</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 600 }}>General Management Practices</TableCell>
                    <TableCell>14</TableCell>
                    <TableCell>Applicable across all parts of an organization</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 600 }}>Service Management Practices</TableCell>
                    <TableCell>17</TableCell>
                    <TableCell>Specific to IT service management</TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell sx={{ fontWeight: 600 }}>Technical Management Practices</TableCell>
                    <TableCell>3</TableCell>
                    <TableCell>Adapted from technology management domains</TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          {/* General Management Practices */}
          <Paper id="general-practices" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <SettingsIcon sx={{ color: "#3b82f6" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                General Management Practices (14)
              </Typography>
            </Box>
            <Grid container spacing={1}>
              {[
                "Architecture Management",
                "Continual Improvement",
                "Information Security Management",
                "Knowledge Management",
                "Measurement and Reporting",
                "Organizational Change Management",
                "Portfolio Management",
                "Project Management",
                "Relationship Management",
                "Risk Management",
                "Service Financial Management",
                "Strategy Management",
                "Supplier Management",
                "Workforce and Talent Management",
              ].map((p, i) => (
                <Grid item xs={12} sm={6} md={4} key={p}>
                  <Chip
                    label={p}
                    sx={{
                      width: "100%",
                      justifyContent: "flex-start",
                      bgcolor: alpha("#3b82f6", 0.1),
                      color: "#3b82f6",
                      fontWeight: 500,
                    }}
                  />
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Service Management Practices */}
          <Paper id="service-practices" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <SupportAgentIcon sx={{ color: "#22c55e" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Service Management Practices (17)
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              These are the core IT service management practices that most organizations focus on.
            </Typography>
            <Accordion defaultExpanded>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontWeight: 600 }}>Key Service Practices</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  {[
                    { practice: "Incident Management", purpose: "Minimize negative impact by restoring service quickly" },
                    { practice: "Problem Management", purpose: "Reduce incidents by identifying root causes" },
                    { practice: "Change Enablement", purpose: "Maximize successful changes with proper assessment" },
                    { practice: "Service Request Management", purpose: "Handle user requests for services and information" },
                    { practice: "Service Desk", purpose: "Single point of contact for users and IT" },
                    { practice: "Service Level Management", purpose: "Set and monitor service performance targets" },
                  ].map((p) => (
                    <Grid item xs={12} md={6} key={p.practice}>
                      <Box sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                          {p.practice}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          {p.purpose}
                        </Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </AccordionDetails>
            </Accordion>
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontWeight: 600 }}>All 17 Service Management Practices</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={1}>
                  {[
                    "Availability Management",
                    "Business Analysis",
                    "Capacity and Performance Management",
                    "Change Enablement",
                    "Incident Management",
                    "IT Asset Management",
                    "Monitoring and Event Management",
                    "Problem Management",
                    "Release Management",
                    "Service Catalog Management",
                    "Service Configuration Management",
                    "Service Continuity Management",
                    "Service Design",
                    "Service Desk",
                    "Service Level Management",
                    "Service Request Management",
                    "Service Validation and Testing",
                  ].map((p) => (
                    <Grid item xs={12} sm={6} md={4} key={p}>
                      <Chip
                        label={p}
                        size="small"
                        sx={{
                          width: "100%",
                          justifyContent: "flex-start",
                          bgcolor: alpha("#22c55e", 0.1),
                          fontSize: "0.75rem",
                        }}
                      />
                    </Grid>
                  ))}
                </Grid>
              </AccordionDetails>
            </Accordion>
          </Paper>

          {/* Technical Management Practices */}
          <Paper id="technical-practices" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <BuildIcon sx={{ color: "#8b5cf6" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Technical Management Practices (3)
              </Typography>
            </Box>
            <Grid container spacing={2}>
              {[
                {
                  practice: "Deployment Management",
                  purpose: "Move new or changed hardware, software, or other components to live environments",
                },
                {
                  practice: "Infrastructure and Platform Management",
                  purpose: "Oversee infrastructure and platforms used by an organization",
                },
                {
                  practice: "Software Development and Management",
                  purpose: "Ensure applications meet stakeholder needs in functionality, reliability, and maintainability",
                },
              ].map((p) => (
                <Grid item xs={12} key={p.practice}>
                  <Card sx={{ bgcolor: alpha("#8b5cf6", 0.03) }}>
                    <CardContent>
                      <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6" }}>
                        {p.practice}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {p.purpose}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Continual Improvement */}
          <Paper id="continual-improvement" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <LoopIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Continual Improvement
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Continual improvement is embedded throughout the entire SVS. The Continual Improvement Model provides
              a structured approach to implementing improvements.
            </Typography>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              The Continual Improvement Model:
            </Typography>
            <Grid container spacing={1}>
              {[
                { step: "1", question: "What is the vision?", description: "Define the improvement direction aligned with objectives" },
                { step: "2", question: "Where are we now?", description: "Assess the current state as a starting point" },
                { step: "3", question: "Where do we want to be?", description: "Define measurable targets and goals" },
                { step: "4", question: "How do we get there?", description: "Create an improvement plan" },
                { step: "5", question: "Take action", description: "Execute the improvement plan" },
                { step: "6", question: "Did we get there?", description: "Evaluate results against targets" },
                { step: "7", question: "How do we keep the momentum going?", description: "Embed changes and identify next improvements" },
              ].map((s) => (
                <Grid item xs={12} key={s.step}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, p: 2, bgcolor: alpha(ACCENT_COLOR, 0.05), borderRadius: 2 }}>
                    <Box
                      sx={{
                        width: 36,
                        height: 36,
                        borderRadius: "50%",
                        bgcolor: ACCENT_COLOR,
                        color: "white",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        fontWeight: 700,
                        flexShrink: 0,
                      }}
                    >
                      {s.step}
                    </Box>
                    <Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                        {s.question}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {s.description}
                      </Typography>
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Certifications */}
          <Paper id="certifications" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <WorkspacePremiumIcon sx={{ color: "#f59e0b" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                ITIL 4 Certifications
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              ITIL 4 offers a modular certification scheme with two main streams: Managing Professional and
              Strategic Leader, culminating in the ITIL Master designation.
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <Card sx={{ p: 3, bgcolor: alpha("#22c55e", 0.05), borderLeft: `4px solid #22c55e` }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>
                    ITIL 4 Foundation
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Entry-level certification covering key concepts, guiding principles, and the four dimensions.
                    Required before taking any other ITIL 4 module.
                  </Typography>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card sx={{ height: "100%", p: 3, bgcolor: alpha("#3b82f6", 0.05) }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6", mb: 2 }}>
                    Managing Professional (MP) Stream
                  </Typography>
                  <List dense>
                    {[
                      "CDS - Create, Deliver and Support",
                      "DSV - Drive Stakeholder Value",
                      "HVIT - High-Velocity IT",
                      "DPI - Direct, Plan and Improve",
                    ].map((m) => (
                      <ListItem key={m} sx={{ py: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} />
                        </ListItemIcon>
                        <ListItemText primary={m} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                    Complete all 4 modules for <strong>ITIL Managing Professional</strong> designation.
                  </Typography>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card sx={{ height: "100%", p: 3, bgcolor: alpha("#8b5cf6", 0.05) }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 2 }}>
                    Strategic Leader (SL) Stream
                  </Typography>
                  <List dense>
                    {[
                      "DPI - Direct, Plan and Improve (shared with MP)",
                      "DITS - Digital and IT Strategy",
                    ].map((m) => (
                      <ListItem key={m} sx={{ py: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                        </ListItemIcon>
                        <ListItemText primary={m} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                    Complete both modules for <strong>ITIL Strategic Leader</strong> designation.
                  </Typography>
                </Card>
              </Grid>
              <Grid item xs={12}>
                <Card sx={{ p: 3, bgcolor: alpha("#f59e0b", 0.05), borderLeft: `4px solid #f59e0b` }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b" }}>
                    ITIL Master
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    The highest ITIL designation. Requires both MP and SL designations plus demonstrated ability
                    to apply ITIL concepts in real-world situations through a work-based submission.
                  </Typography>
                </Card>
              </Grid>
            </Grid>
          </Paper>

          {/* Quiz Section */}
          <Box id="quiz">
            <QuizSection
              questions={quizQuestions}
              accentColor={ACCENT_COLOR}
              title="ITIL 4 Knowledge Check"
              description="Test your understanding of ITIL 4 with these questions covering fundamentals, guiding principles, service value chain, practices, and certifications."
            />
          </Box>

          <Divider sx={{ my: 4 }} />

          <Box sx={{ display: "flex", justifyContent: "center" }}>
            <Button
              variant="contained"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate("/learn")}
              sx={{ bgcolor: ACCENT_COLOR, "&:hover": { bgcolor: "#047857" }, px: 4, py: 1.5, fontWeight: 700 }}
            >
              Back to Learning Hub
            </Button>
          </Box>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
