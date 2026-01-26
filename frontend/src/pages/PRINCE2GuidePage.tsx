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
import MenuBookIcon from "@mui/icons-material/MenuBook";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ArrowRightIcon from "@mui/icons-material/ArrowRight";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import MenuIcon from "@mui/icons-material/Menu";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import GroupsIcon from "@mui/icons-material/Groups";
import PersonIcon from "@mui/icons-material/Person";
import AssignmentIcon from "@mui/icons-material/Assignment";
import SettingsIcon from "@mui/icons-material/Settings";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import WarningIcon from "@mui/icons-material/Warning";
import VerifiedIcon from "@mui/icons-material/Verified";
import SchoolIcon from "@mui/icons-material/School";
import CompareArrowsIcon from "@mui/icons-material/CompareArrows";
import WorkspacePremiumIcon from "@mui/icons-material/WorkspacePremium";
import DescriptionIcon from "@mui/icons-material/Description";
import TimelineIcon from "@mui/icons-material/Timeline";
import SecurityIcon from "@mui/icons-material/Security";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";

const ACCENT_COLOR = "#7c3aed"; // Purple for PRINCE2

// ========== QUIZ BANK (75 questions, 5 topics) ==========
const quizQuestions: QuizQuestion[] = [
  // Topic 1: PRINCE2 Fundamentals (15 questions)
  {
    id: 1,
    topic: "PRINCE2 Fundamentals",
    question: "What does PRINCE2 stand for?",
    options: ["Projects in Controlled Environments", "Project Management in Controlled Enterprises", "Professional Project Management Environment", "Projects in Corporate Environments"],
    correctAnswer: 0,
    explanation: "PRINCE2 stands for PRojects IN Controlled Environments, version 2."
  },
  {
    id: 2,
    topic: "PRINCE2 Fundamentals",
    question: "How many principles does PRINCE2 have?",
    options: ["5", "6", "7", "8"],
    correctAnswer: 2,
    explanation: "PRINCE2 has 7 principles that provide the framework's foundation and guide all project decisions."
  },
  {
    id: 3,
    topic: "PRINCE2 Fundamentals",
    question: "How many themes does PRINCE2 define?",
    options: ["5", "6", "7", "8"],
    correctAnswer: 2,
    explanation: "PRINCE2 defines 7 themes that describe aspects of project management that must be addressed continuously."
  },
  {
    id: 4,
    topic: "PRINCE2 Fundamentals",
    question: "How many processes does PRINCE2 have?",
    options: ["5", "6", "7", "8"],
    correctAnswer: 2,
    explanation: "PRINCE2 has 7 processes that describe the steps required to manage and deliver a project."
  },
  {
    id: 5,
    topic: "PRINCE2 Fundamentals",
    question: "What organization owns PRINCE2?",
    options: ["PMI", "AXELOS", "APM", "IPMA"],
    correctAnswer: 1,
    explanation: "PRINCE2 is owned by AXELOS, a joint venture company created by the UK government and Capita."
  },
  {
    id: 6,
    topic: "PRINCE2 Fundamentals",
    question: "What is a key characteristic of PRINCE2?",
    options: ["It is prescriptive", "It is tailorable to any project", "It only works for IT projects", "It requires specific tools"],
    correctAnswer: 1,
    explanation: "PRINCE2 is designed to be tailored to suit the particular needs of each project."
  },
  {
    id: 7,
    topic: "PRINCE2 Fundamentals",
    question: "What does PRINCE2 focus on primarily?",
    options: ["Technical delivery", "Project management", "Resource management", "Financial accounting"],
    correctAnswer: 1,
    explanation: "PRINCE2 focuses on project management, not the specialist work of creating deliverables."
  },
  {
    id: 8,
    topic: "PRINCE2 Fundamentals",
    question: "What is the relationship between principles and themes in PRINCE2?",
    options: ["Principles guide themes", "Themes guide principles", "They are unrelated", "They are the same thing"],
    correctAnswer: 0,
    explanation: "The principles provide guidance for all aspects of PRINCE2, including how themes should be applied."
  },
  {
    id: 9,
    topic: "PRINCE2 Fundamentals",
    question: "Which is NOT a PRINCE2 principle?",
    options: ["Continued business justification", "Learn from experience", "Maximize resources", "Manage by stages"],
    correctAnswer: 2,
    explanation: "'Maximize resources' is not a PRINCE2 principle. The 7 principles are: Continued business justification, Learn from experience, Defined roles and responsibilities, Manage by stages, Manage by exception, Focus on products, and Tailor to suit the project."
  },
  {
    id: 10,
    topic: "PRINCE2 Fundamentals",
    question: "What is meant by 'management by exception' in PRINCE2?",
    options: ["Only exceptions are managed", "Senior management only intervenes when tolerances are exceeded", "Exceptions must always be reported", "All decisions require escalation"],
    correctAnswer: 1,
    explanation: "Management by exception means higher levels of management only need to be involved when forecasts suggest tolerances will be exceeded."
  },
  {
    id: 11,
    topic: "PRINCE2 Fundamentals",
    question: "What is the minimum requirement for a project to be PRINCE2 compliant?",
    options: ["Using all 26 management products", "Following all 7 principles", "Having a Project Board", "Using PRINCE2 software"],
    correctAnswer: 1,
    explanation: "A project must follow all 7 principles to be considered PRINCE2 compliant. Themes and processes can be tailored."
  },
  {
    id: 12,
    topic: "PRINCE2 Fundamentals",
    question: "What type of methodology is PRINCE2?",
    options: ["Agile only", "Waterfall only", "Can be used with both", "Neither"],
    correctAnswer: 2,
    explanation: "PRINCE2 can be used with both waterfall and agile approaches. PRINCE2 Agile specifically addresses agile integration."
  },
  {
    id: 13,
    topic: "PRINCE2 Fundamentals",
    question: "What is the primary input to starting a PRINCE2 project?",
    options: ["Business Case", "Project Brief", "Project Mandate", "Project Initiation Document"],
    correctAnswer: 2,
    explanation: "The Project Mandate is the trigger for the project and provides the initial information needed to start."
  },
  {
    id: 14,
    topic: "PRINCE2 Fundamentals",
    question: "What does 'focus on products' mean in PRINCE2?",
    options: ["Only physical products matter", "Define what will be delivered before planning activities", "Products are more important than processes", "Marketing products is key"],
    correctAnswer: 1,
    explanation: "Focus on products means clearly defining and agreeing the project's products before planning how to deliver them."
  },
  {
    id: 15,
    topic: "PRINCE2 Fundamentals",
    question: "What is tailoring in PRINCE2?",
    options: ["Making custom reports", "Adapting PRINCE2 to suit the project context", "Reducing documentation", "Changing the principles"],
    correctAnswer: 1,
    explanation: "Tailoring means adapting PRINCE2 to suit the project's environment, size, complexity, and risk."
  },

  // Topic 2: PRINCE2 Themes (15 questions)
  {
    id: 16,
    topic: "PRINCE2 Themes",
    question: "Which theme answers the question 'Why?'",
    options: ["Organization", "Business Case", "Plans", "Progress"],
    correctAnswer: 1,
    explanation: "The Business Case theme answers why the project is needed and whether it remains viable."
  },
  {
    id: 17,
    topic: "PRINCE2 Themes",
    question: "Which theme answers the question 'Who?'",
    options: ["Organization", "Business Case", "Quality", "Risk"],
    correctAnswer: 0,
    explanation: "The Organization theme defines the project's accountabilities and responsibilities - who is involved."
  },
  {
    id: 18,
    topic: "PRINCE2 Themes",
    question: "Which theme answers the question 'What?'",
    options: ["Plans", "Quality", "Risk", "Change"],
    correctAnswer: 1,
    explanation: "The Quality theme defines what products will be delivered and their quality criteria."
  },
  {
    id: 19,
    topic: "PRINCE2 Themes",
    question: "Which theme addresses 'What if?'",
    options: ["Plans", "Quality", "Risk", "Change"],
    correctAnswer: 2,
    explanation: "The Risk theme addresses 'What if?' by identifying and managing uncertainties."
  },
  {
    id: 20,
    topic: "PRINCE2 Themes",
    question: "What document is central to the Business Case theme?",
    options: ["Project Brief", "Business Case document", "Benefits Review Plan", "All of the above"],
    correctAnswer: 3,
    explanation: "The Business Case theme uses the Project Brief, Business Case document, and Benefits Review Plan."
  },
  {
    id: 21,
    topic: "PRINCE2 Themes",
    question: "What are the three project interests in the Organization theme?",
    options: ["Time, Cost, Quality", "Business, User, Supplier", "Project, Programme, Portfolio", "Customer, Vendor, Team"],
    correctAnswer: 1,
    explanation: "The three project interests are Business (commercial viability), User (those who will use the products), and Supplier (those who provide resources)."
  },
  {
    id: 22,
    topic: "PRINCE2 Themes",
    question: "What is the Quality theme's approach to defining quality?",
    options: ["Define quality at the end", "Define quality criteria before work begins", "Let users define quality", "Use industry standards only"],
    correctAnswer: 1,
    explanation: "PRINCE2 requires quality to be defined upfront through Product Descriptions and quality criteria."
  },
  {
    id: 23,
    topic: "PRINCE2 Themes",
    question: "What does the Plans theme cover?",
    options: ["Only the project plan", "Only stage plans", "All levels of planning from project to team", "Only work packages"],
    correctAnswer: 2,
    explanation: "The Plans theme covers all levels of planning: Project Plan, Stage Plans, Team Plans, and Exception Plans."
  },
  {
    id: 24,
    topic: "PRINCE2 Themes",
    question: "What is the recommended risk management procedure in PRINCE2?",
    options: ["Identify, Assess, Control", "Identify, Assess, Plan, Implement, Communicate", "Plan, Identify, Review", "Monitor, Control, Close"],
    correctAnswer: 1,
    explanation: "The risk management procedure includes: Identify, Assess, Plan, Implement, and Communicate."
  },
  {
    id: 25,
    topic: "PRINCE2 Themes",
    question: "What are the types of issues in the Change theme?",
    options: ["High, Medium, Low", "Request for change, Off-specification, Problem/Concern", "Critical, Major, Minor", "Urgent, Normal, Low"],
    correctAnswer: 1,
    explanation: "PRINCE2 categorizes issues as: Request for Change (RFC), Off-specification, and Problem/Concern."
  },
  {
    id: 26,
    topic: "PRINCE2 Themes",
    question: "What is the purpose of the Progress theme?",
    options: ["To measure team productivity", "To monitor and control project performance against plans", "To report to stakeholders only", "To track time only"],
    correctAnswer: 1,
    explanation: "The Progress theme establishes mechanisms to monitor and control the project against its plans."
  },
  {
    id: 27,
    topic: "PRINCE2 Themes",
    question: "What are tolerances in PRINCE2?",
    options: ["Acceptable levels of quality", "Permissible deviation from plans before escalation is needed", "Time buffers only", "Budget reserves"],
    correctAnswer: 1,
    explanation: "Tolerances are the permissible deviation from a plan without requiring escalation to the next management level."
  },
  {
    id: 28,
    topic: "PRINCE2 Themes",
    question: "What six aspects can tolerances be set for?",
    options: ["Time, Cost, Quality, Scope, Benefits, Risk", "Time, Cost, Quality, Resources, Scope, Risk", "Time, Cost, Quality, Scope, Value, Risk", "Time, Budget, Quality, Scope, Benefits, Risk"],
    correctAnswer: 0,
    explanation: "Tolerances can be set for: Time, Cost, Quality, Scope, Benefits, and Risk."
  },
  {
    id: 29,
    topic: "PRINCE2 Themes",
    question: "What is a Product Description in PRINCE2?",
    options: ["Marketing material", "A specification of a product's purpose, composition, and quality criteria", "A user manual", "A technical design document"],
    correctAnswer: 1,
    explanation: "A Product Description defines a product's purpose, composition, derivation, quality criteria, and quality method."
  },
  {
    id: 30,
    topic: "PRINCE2 Themes",
    question: "Who is responsible for the Business Case throughout the project?",
    options: ["Project Manager", "Executive", "Project Board", "Senior User"],
    correctAnswer: 1,
    explanation: "The Executive is responsible for the Business Case throughout the project lifecycle."
  },

  // Topic 3: PRINCE2 Processes (15 questions)
  {
    id: 31,
    topic: "PRINCE2 Processes",
    question: "What is the first PRINCE2 process?",
    options: ["Initiating a Project", "Starting up a Project", "Directing a Project", "Managing a Stage Boundary"],
    correctAnswer: 1,
    explanation: "Starting up a Project (SU) is the first process, triggered by the Project Mandate."
  },
  {
    id: 32,
    topic: "PRINCE2 Processes",
    question: "Which process runs throughout the entire project?",
    options: ["Starting up a Project", "Initiating a Project", "Directing a Project", "Managing Product Delivery"],
    correctAnswer: 2,
    explanation: "Directing a Project (DP) runs from project start-up to closure and is used by the Project Board."
  },
  {
    id: 33,
    topic: "PRINCE2 Processes",
    question: "What is the output of 'Starting up a Project'?",
    options: ["Business Case", "Project Initiation Documentation", "Project Brief", "Stage Plan"],
    correctAnswer: 2,
    explanation: "The main output of Starting up a Project is the Project Brief, which provides enough information to decide whether to proceed to initiation."
  },
  {
    id: 34,
    topic: "PRINCE2 Processes",
    question: "What does the 'Initiating a Project' process produce?",
    options: ["Project Mandate", "Project Brief", "Project Initiation Documentation (PID)", "End Project Report"],
    correctAnswer: 2,
    explanation: "Initiating a Project produces the Project Initiation Documentation (PID), which is the foundation for the project."
  },
  {
    id: 35,
    topic: "PRINCE2 Processes",
    question: "Who performs the 'Directing a Project' process?",
    options: ["Project Manager", "Team Manager", "Project Board", "Corporate Management"],
    correctAnswer: 2,
    explanation: "The Directing a Project process is performed by the Project Board to authorize and control the project."
  },
  {
    id: 36,
    topic: "PRINCE2 Processes",
    question: "What is the purpose of 'Controlling a Stage'?",
    options: ["To authorize the project", "To assign and monitor work within a stage", "To close the project", "To create the project plan"],
    correctAnswer: 1,
    explanation: "Controlling a Stage enables the Project Manager to assign work, monitor progress, and take corrective action."
  },
  {
    id: 37,
    topic: "PRINCE2 Processes",
    question: "What happens in 'Managing a Stage Boundary'?",
    options: ["The project starts", "The current stage is reviewed and next stage planned", "Products are delivered", "The project closes"],
    correctAnswer: 1,
    explanation: "Managing a Stage Boundary reviews the current stage, updates plans, and prepares for the next stage."
  },
  {
    id: 38,
    topic: "PRINCE2 Processes",
    question: "Who performs 'Managing Product Delivery'?",
    options: ["Project Manager", "Team Manager", "Project Board", "Executive"],
    correctAnswer: 1,
    explanation: "The Team Manager performs Managing Product Delivery to coordinate work and deliver products."
  },
  {
    id: 39,
    topic: "PRINCE2 Processes",
    question: "What is a Work Package?",
    options: ["A document for the Project Board", "An agreement between Project Manager and Team Manager about work to be done", "A financial document", "A risk assessment"],
    correctAnswer: 1,
    explanation: "A Work Package is an agreement between the Project Manager and Team Manager defining what work is to be done."
  },
  {
    id: 40,
    topic: "PRINCE2 Processes",
    question: "What does 'Closing a Project' process ensure?",
    options: ["Products are abandoned", "Orderly completion and handover of the project", "Next project is started", "Team is disbanded immediately"],
    correctAnswer: 1,
    explanation: "Closing a Project ensures orderly completion, handover of products, and evaluation of the project."
  },
  {
    id: 41,
    topic: "PRINCE2 Processes",
    question: "What are the two types of project closure?",
    options: ["Fast and slow", "Planned and premature", "Full and partial", "Formal and informal"],
    correctAnswer: 1,
    explanation: "Projects can have planned closure (successful completion) or premature closure (early termination)."
  },
  {
    id: 42,
    topic: "PRINCE2 Processes",
    question: "What authorization does 'Directing a Project' provide at stage boundaries?",
    options: ["Work Package authorization", "Stage authorization", "Team authorization", "Change authorization"],
    correctAnswer: 1,
    explanation: "At stage boundaries, the Project Board authorizes the next stage through Directing a Project."
  },
  {
    id: 43,
    topic: "PRINCE2 Processes",
    question: "When is an Exception Plan created?",
    options: ["At project start", "When tolerances are forecast to be exceeded", "At every stage end", "During project closure"],
    correctAnswer: 1,
    explanation: "An Exception Plan is created when forecasts show that stage tolerances will be exceeded."
  },
  {
    id: 44,
    topic: "PRINCE2 Processes",
    question: "What minimum number of stages must a PRINCE2 project have?",
    options: ["1", "2", "3", "4"],
    correctAnswer: 1,
    explanation: "A PRINCE2 project must have at least 2 stages: an Initiation Stage and at least one Delivery Stage."
  },
  {
    id: 45,
    topic: "PRINCE2 Processes",
    question: "What is the relationship between Controlling a Stage and Managing Product Delivery?",
    options: ["They are the same process", "CS assigns work via Work Packages to MPD", "MPD controls CS", "They run at different times"],
    correctAnswer: 1,
    explanation: "Controlling a Stage (Project Manager) assigns work via Work Packages to Managing Product Delivery (Team Manager)."
  },

  // Topic 4: PRINCE2 Roles (15 questions)
  {
    id: 46,
    topic: "PRINCE2 Roles",
    question: "Who chairs the Project Board?",
    options: ["Project Manager", "Executive", "Senior User", "Senior Supplier"],
    correctAnswer: 1,
    explanation: "The Executive chairs the Project Board and is ultimately accountable for the project."
  },
  {
    id: 47,
    topic: "PRINCE2 Roles",
    question: "What are the three Project Board roles?",
    options: ["Manager, Leader, Sponsor", "Executive, Senior User, Senior Supplier", "Director, Manager, Coordinator", "Owner, User, Supplier"],
    correctAnswer: 1,
    explanation: "The Project Board consists of the Executive, Senior User(s), and Senior Supplier(s)."
  },
  {
    id: 48,
    topic: "PRINCE2 Roles",
    question: "Who represents the business interests on the Project Board?",
    options: ["Senior User", "Senior Supplier", "Executive", "Project Manager"],
    correctAnswer: 2,
    explanation: "The Executive represents the business interests and owns the Business Case."
  },
  {
    id: 49,
    topic: "PRINCE2 Roles",
    question: "Who represents the interests of those who will use the project's products?",
    options: ["Executive", "Senior User", "Senior Supplier", "Team Manager"],
    correctAnswer: 1,
    explanation: "The Senior User represents the interests of those who will use the products and specifies requirements."
  },
  {
    id: 50,
    topic: "PRINCE2 Roles",
    question: "Who represents the interests of those designing and building the products?",
    options: ["Executive", "Senior User", "Senior Supplier", "Project Manager"],
    correctAnswer: 2,
    explanation: "The Senior Supplier represents the interests of those designing, developing, and implementing the products."
  },
  {
    id: 51,
    topic: "PRINCE2 Roles",
    question: "Who is responsible for day-to-day project management?",
    options: ["Executive", "Project Manager", "Team Manager", "Project Board"],
    correctAnswer: 1,
    explanation: "The Project Manager is responsible for day-to-day management of the project on behalf of the Project Board."
  },
  {
    id: 52,
    topic: "PRINCE2 Roles",
    question: "What is the role of Project Assurance?",
    options: ["To manage the project", "To deliver products", "To provide independent oversight of project performance", "To close the project"],
    correctAnswer: 2,
    explanation: "Project Assurance provides independent oversight to ensure the project remains viable and is being run properly."
  },
  {
    id: 53,
    topic: "PRINCE2 Roles",
    question: "Who can Project Assurance NOT be delegated to?",
    options: ["External consultants", "The Project Manager", "PMO staff", "Senior User delegates"],
    correctAnswer: 1,
    explanation: "Project Assurance cannot be delegated to the Project Manager as it must remain independent."
  },
  {
    id: 54,
    topic: "PRINCE2 Roles",
    question: "What is the purpose of Change Authority?",
    options: ["To approve all changes", "To handle changes within delegated limits", "To reject all changes", "To create change requests"],
    correctAnswer: 1,
    explanation: "The Change Authority handles changes and off-specifications within limits delegated by the Project Board."
  },
  {
    id: 55,
    topic: "PRINCE2 Roles",
    question: "What is Project Support responsible for?",
    options: ["Making decisions", "Providing administrative support to the Project Manager", "Approving stages", "Defining requirements"],
    correctAnswer: 1,
    explanation: "Project Support provides administrative assistance to the Project Manager and team."
  },
  {
    id: 56,
    topic: "PRINCE2 Roles",
    question: "Who appoints the Project Manager?",
    options: ["Executive", "Senior User", "Senior Supplier", "Corporate Management"],
    correctAnswer: 0,
    explanation: "The Executive appoints the Project Manager during the Starting up a Project process."
  },
  {
    id: 57,
    topic: "PRINCE2 Roles",
    question: "Who is accountable for user acceptance?",
    options: ["Project Manager", "Executive", "Senior User", "Team Manager"],
    correctAnswer: 2,
    explanation: "The Senior User is accountable for user acceptance and confirming that products meet requirements."
  },
  {
    id: 58,
    topic: "PRINCE2 Roles",
    question: "Can Project Board roles be shared?",
    options: ["Never", "Yes, but accountability cannot be shared", "Always", "Only in small projects"],
    correctAnswer: 1,
    explanation: "Roles can be shared or combined, but the accountability for each role must remain clear."
  },
  {
    id: 59,
    topic: "PRINCE2 Roles",
    question: "Who authorizes project closure?",
    options: ["Project Manager", "Executive alone", "Project Board", "Corporate Management"],
    correctAnswer: 2,
    explanation: "The Project Board authorizes project closure through the Directing a Project process."
  },
  {
    id: 60,
    topic: "PRINCE2 Roles",
    question: "What is the Team Manager's primary responsibility?",
    options: ["Creating the Business Case", "Producing the products assigned by Work Packages", "Approving stages", "Managing the Project Board"],
    correctAnswer: 1,
    explanation: "The Team Manager is responsible for producing the products assigned in Work Packages."
  },

  // Topic 5: Management Products & Tailoring (15 questions)
  {
    id: 61,
    topic: "Management Products",
    question: "How many management products does PRINCE2 define?",
    options: ["16", "20", "26", "30"],
    correctAnswer: 2,
    explanation: "PRINCE2 defines 26 management products divided into baselines, records, and reports."
  },
  {
    id: 62,
    topic: "Management Products",
    question: "What are the three categories of management products?",
    options: ["Plans, Reports, Logs", "Baselines, Records, Reports", "Documents, Logs, Registers", "Primary, Secondary, Tertiary"],
    correctAnswer: 1,
    explanation: "Management products are categorized as: Baselines (define aspects of the project), Records (dynamic information), and Reports (snapshots of status)."
  },
  {
    id: 63,
    topic: "Management Products",
    question: "What is the Project Initiation Documentation (PID)?",
    options: ["A single document", "A collection of baseline documents that define the project", "An optional report", "A closure document"],
    correctAnswer: 1,
    explanation: "The PID is a collection of documents that together define the project and form the basis for management."
  },
  {
    id: 64,
    topic: "Management Products",
    question: "What is the purpose of the Daily Log?",
    options: ["To track time", "To record informal issues, actions, and events", "To log attendance", "To record approvals"],
    correctAnswer: 1,
    explanation: "The Daily Log is used by the Project Manager to record informal issues, actions, and events."
  },
  {
    id: 65,
    topic: "Management Products",
    question: "What is recorded in the Issue Register?",
    options: ["Only change requests", "All raised issues, their analysis, and status", "Only problems", "Only risks"],
    correctAnswer: 1,
    explanation: "The Issue Register captures all issues (RFCs, off-specifications, problems/concerns) and their status."
  },
  {
    id: 66,
    topic: "Management Products",
    question: "What is the Risk Register used for?",
    options: ["Recording all project risks and their management", "Recording issues only", "Financial tracking", "Resource allocation"],
    correctAnswer: 0,
    explanation: "The Risk Register records all identified risks, their assessment, and planned responses."
  },
  {
    id: 67,
    topic: "Management Products",
    question: "What is the purpose of the Lessons Log?",
    options: ["To record training needs", "To capture lessons learned for current and future projects", "To log mistakes", "To record team performance"],
    correctAnswer: 1,
    explanation: "The Lessons Log captures lessons learned that can benefit the current project and future projects."
  },
  {
    id: 68,
    topic: "Management Products",
    question: "What report provides regular status updates to the Project Board?",
    options: ["End Stage Report", "Highlight Report", "Exception Report", "Checkpoint Report"],
    correctAnswer: 1,
    explanation: "The Highlight Report provides regular updates to the Project Board on stage progress."
  },
  {
    id: 69,
    topic: "Management Products",
    question: "When is an Exception Report required?",
    options: ["At every stage end", "When tolerances are forecast to be exceeded", "At project start", "Never"],
    correctAnswer: 1,
    explanation: "An Exception Report is produced when tolerances are forecast to be exceeded, alerting the Project Board."
  },
  {
    id: 70,
    topic: "Management Products",
    question: "What is the purpose of the End Project Report?",
    options: ["To start a new project", "To review project performance and capture lessons", "To calculate final costs", "To assign blame"],
    correctAnswer: 1,
    explanation: "The End Project Report reviews overall project performance against the PID and captures lessons learned."
  },
  {
    id: 71,
    topic: "Management Products",
    question: "What does a Product Status Account show?",
    options: ["Financial status", "The status of products at a given time", "Team status", "Risk status"],
    correctAnswer: 1,
    explanation: "A Product Status Account provides information about the status of products at any given time."
  },
  {
    id: 72,
    topic: "Management Products",
    question: "What is the Benefits Review Plan?",
    options: ["A financial report", "A plan for measuring benefits realization after the project", "A stage plan", "A risk plan"],
    correctAnswer: 1,
    explanation: "The Benefits Review Plan defines how and when benefits will be measured after the project ends."
  },
  {
    id: 73,
    topic: "Management Products",
    question: "What must NOT be compromised when tailoring PRINCE2?",
    options: ["Documentation", "The 7 principles", "Meeting frequency", "Report formats"],
    correctAnswer: 1,
    explanation: "When tailoring, the 7 principles must not be compromised; they are mandatory for PRINCE2 compliance."
  },
  {
    id: 74,
    topic: "Management Products",
    question: "What factors influence how PRINCE2 should be tailored?",
    options: ["Only project size", "Project environment, size, complexity, risk, and organizational maturity", "Only budget", "Only timeline"],
    correctAnswer: 1,
    explanation: "Tailoring considers project environment, size, complexity, risk, team capability, and organizational maturity."
  },
  {
    id: 75,
    topic: "Management Products",
    question: "What is the Communication Management Strategy?",
    options: ["A marketing plan", "A plan for how project communications will be managed", "An email policy", "A meeting schedule"],
    correctAnswer: 1,
    explanation: "The Communication Management Strategy defines how communications with stakeholders will be managed."
  },
];

// ========== SIDEBAR SECTIONS ==========
const sections = [
  { id: "introduction", label: "Introduction" },
  { id: "road-trip-analogy", label: "Road Trip Analogy" },
  { id: "why-prince2-matters", label: "Why PRINCE2 Matters" },
  { id: "history", label: "History & Evolution" },
  { id: "principles", label: "7 Principles" },
  { id: "themes", label: "7 Themes" },
  { id: "theme-business-case", label: "Business Case Theme" },
  { id: "theme-organization", label: "Organization Theme" },
  { id: "theme-quality", label: "Quality Theme" },
  { id: "theme-plans", label: "Plans Theme" },
  { id: "theme-risk", label: "Risk Theme" },
  { id: "theme-change", label: "Change Theme" },
  { id: "theme-progress", label: "Progress Theme" },
  { id: "processes", label: "7 Processes" },
  { id: "day-in-the-life", label: "Day in the Life" },
  { id: "roles", label: "Roles & Responsibilities" },
  { id: "management-products", label: "Management Products" },
  { id: "pm-tools", label: "PM Tools Landscape" },
  { id: "tailoring", label: "Tailoring PRINCE2" },
  { id: "prince2-agile", label: "PRINCE2 Agile" },
  { id: "career-paths", label: "Career Paths & Salaries" },
  { id: "certifications", label: "Certifications" },
  { id: "exam-tips", label: "Exam Tips" },
  { id: "quiz", label: "Knowledge Check" },
];

export default function PRINCE2GuidePage() {
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

  const pageContext = `PRINCE2 Guide - Comprehensive guide to the PRINCE2 project management methodology covering the 7 principles, 7 themes, 7 processes, roles and responsibilities, management products, tailoring, PRINCE2 Agile, and certification paths.`;

  return (
    <LearnPageLayout pageTitle="PRINCE2 Guide" pageContext={pageContext}>
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
              background: `linear-gradient(135deg, ${alpha(ACCENT_COLOR, 0.1)} 0%, ${alpha("#8b5cf6", 0.05)} 100%)`,
              border: `1px solid ${alpha(ACCENT_COLOR, 0.2)}`,
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: ACCENT_COLOR, width: 64, height: 64 }}>
                <AccountTreeIcon sx={{ fontSize: 36 }} />
              </Avatar>
              <Box>
                <Typography variant="h3" sx={{ fontWeight: 800 }}>
                  PRINCE2 Guide
                </Typography>
                <Typography variant="h6" color="text.secondary">
                  PRojects IN Controlled Environments
                </Typography>
              </Box>
            </Box>
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              PRINCE2 is a structured project management methodology widely used globally. It provides a flexible,
              scalable approach that can be tailored to any project size or type. Based on seven principles, seven
              themes, and seven processes, PRINCE2 delivers a common vocabulary and proven best practices.
            </Typography>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
              {["Methodology", "Best Practice", "Tailorable", "Process-Based", "AXELOS"].map((tag) => (
                <Chip
                  key={tag}
                  label={tag}
                  size="small"
                  sx={{ bgcolor: alpha(ACCENT_COLOR, 0.1), color: ACCENT_COLOR, fontWeight: 500 }}
                />
              ))}
            </Box>
          </Paper>

          {/* Road Trip Analogy for Beginners */}
          <Paper
            id="road-trip-analogy"
            elevation={0}
            sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.3)}`, bgcolor: alpha("#22c55e", 0.02) }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <TipsAndUpdatesIcon sx={{ color: "#22c55e" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                🚗 PRINCE2 Explained: The Road Trip Analogy
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Imagine you're planning a <strong>cross-country road trip</strong> with friends. PRINCE2 is like having
              a proven travel planning system that's been perfected by millions of travelers before you.
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#22c55e", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Road Trip Element</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>PRINCE2 Equivalent</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>What It Does</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { trip: "🎯 Destination & Why", prince2: "Business Case", does: "Why are we going? Is it worth the time and money?" },
                    { trip: "👥 Who's Coming & Roles", prince2: "Organization", does: "Who drives? Who navigates? Who handles money?" },
                    { trip: "🗺️ Route & Schedule", prince2: "Plans", does: "Which roads? How many days? Where do we stop?" },
                    { trip: "📸 Attractions to Visit", prince2: "Products", does: "Specific places and experiences we want to have" },
                    { trip: "⛽ Checkpoints/Gas Stops", prince2: "Stages", does: "Breaking the journey into manageable legs" },
                    { trip: "🌧️ Weather & Traffic Issues", prince2: "Risks", does: "What could go wrong? What's our backup?" },
                    { trip: "🔄 Detours & Changes", prince2: "Change Control", does: "New attraction found - do we change the plan?" },
                    { trip: "📍 GPS Progress Checks", prince2: "Progress", does: "Are we on track? Do we need to adjust?" },
                  ].map((row) => (
                    <TableRow key={row.trip}>
                      <TableCell sx={{ fontWeight: 500 }}>{row.trip}</TableCell>
                      <TableCell sx={{ color: ACCENT_COLOR, fontWeight: 600 }}>{row.prince2}</TableCell>
                      <TableCell>{row.does}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
            <Box sx={{ mt: 3, p: 2, bgcolor: alpha("#22c55e", 0.1), borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <TipsAndUpdatesIcon sx={{ fontSize: 20, color: "#22c55e" }} />
                The 7-7-7 Memory Trick
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                PRINCE2 is built on <strong>7-7-7</strong>: 7 Principles, 7 Themes, 7 Processes
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Box sx={{ textAlign: "center", p: 1, bgcolor: "background.paper", borderRadius: 1 }}>
                    <Typography variant="h4" sx={{ fontWeight: 800, color: ACCENT_COLOR }}>7</Typography>
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>Principles</Typography>
                    <Typography variant="caption" color="text.secondary">Rules you MUST follow</Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Box sx={{ textAlign: "center", p: 1, bgcolor: "background.paper", borderRadius: 1 }}>
                    <Typography variant="h4" sx={{ fontWeight: 800, color: "#3b82f6" }}>7</Typography>
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>Themes</Typography>
                    <Typography variant="caption" color="text.secondary">Areas to manage constantly</Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Box sx={{ textAlign: "center", p: 1, bgcolor: "background.paper", borderRadius: 1 }}>
                    <Typography variant="h4" sx={{ fontWeight: 800, color: "#22c55e" }}>7</Typography>
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>Processes</Typography>
                    <Typography variant="caption" color="text.secondary">Steps from start to finish</Typography>
                  </Box>
                </Grid>
              </Grid>
            </Box>
          </Paper>

          {/* Why PRINCE2 Matters */}
          <Paper
            id="why-prince2-matters"
            elevation={0}
            sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <VerifiedIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Why PRINCE2 Matters
              </Typography>
            </Box>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { stat: "1M+", label: "Certified Professionals", color: ACCENT_COLOR },
                { stat: "150+", label: "Countries Using PRINCE2", color: "#3b82f6" },
                { stat: "30+", label: "Years of Best Practices", color: "#22c55e" },
                { stat: "70%", label: "UK Government Projects", color: "#f59e0b" },
              ].map((item) => (
                <Grid item xs={6} md={3} key={item.label}>
                  <Box sx={{ textAlign: "center", p: 2, bgcolor: alpha(item.color, 0.1), borderRadius: 2 }}>
                    <Typography variant="h4" sx={{ fontWeight: 800, color: item.color }}>{item.stat}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.label}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Box sx={{ p: 2, bgcolor: alpha("#dc2626", 0.05), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#dc2626", mb: 2 }}>
                    😰 Without PRINCE2:
                  </Typography>
                  <List dense>
                    {[
                      "Projects start without clear justification",
                      "No one knows who's responsible for what",
                      "Scope creep runs unchecked",
                      "Issues discovered too late to fix",
                      "Projects 'complete' but benefits never realized",
                      "Same mistakes repeated on every project",
                    ].map((item, i) => (
                      <ListItem key={i} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 24 }}>
                          <WarningIcon sx={{ fontSize: 16, color: "#dc2626" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Box sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#22c55e", mb: 2 }}>
                    ✅ With PRINCE2:
                  </Typography>
                  <List dense>
                    {[
                      "Business justification reviewed at every stage",
                      "Clear roles and decision-making authority",
                      "Controlled changes through proper governance",
                      "Early warning systems through management by exception",
                      "Focus on benefits realization post-project",
                      "Lessons captured and applied to future projects",
                    ].map((item, i) => (
                      <ListItem key={i} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 24 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: "#22c55e" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              </Grid>
            </Grid>
            <Box sx={{ mt: 3, p: 2, bgcolor: alpha(ACCENT_COLOR, 0.05), borderRadius: 2 }}>
              <Typography variant="body2" sx={{ fontStyle: "italic", textAlign: "center" }}>
                "68% of IT projects fail. PRINCE2 provides the governance framework to be in the successful 32%."
                <br />
                <Typography component="span" variant="caption" color="text.secondary">
                  — Based on industry research from Standish Group CHAOS Report
                </Typography>
              </Typography>
            </Box>
          </Paper>

          {/* PRINCE2 History & Evolution */}
          <Paper
            id="history"
            elevation={0}
            sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <TimelineIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                PRINCE2 History & Evolution
              </Typography>
            </Box>
            <Box sx={{ position: "relative" }}>
              {[
                { year: "1975", title: "PROMPTII Created", desc: "UK Government's CCTA develops PROMPTII for IT project management", color: "#6b7280" },
                { year: "1989", title: "PRINCE is Born", desc: "PROMPTII evolves into PRINCE (PRojects IN Controlled Environments)", color: "#8b5cf6" },
                { year: "1996", title: "PRINCE2 Released", desc: "Major revision adds themes, becomes methodology for all project types", color: ACCENT_COLOR },
                { year: "2009", title: "PRINCE2:2009", desc: "Simplified, 7 principles introduced, more flexible and practical", color: "#3b82f6" },
                { year: "2013", title: "AXELOS Formed", desc: "Joint venture takes ownership, globalizes the methodology", color: "#0891b2" },
                { year: "2017", title: "PRINCE2:2017", desc: "Current version with updated guidance and improved alignment", color: "#22c55e" },
                { year: "2015-Now", title: "PRINCE2 Agile", desc: "Combines PRINCE2 governance with agile flexibility", color: "#f59e0b" },
              ].map((milestone, i) => (
                <Box key={milestone.year} sx={{ display: "flex", mb: 2 }}>
                  <Box sx={{ width: 80, flexShrink: 0, textAlign: "right", pr: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: milestone.color }}>
                      {milestone.year}
                    </Typography>
                  </Box>
                  <Box sx={{ position: "relative", pr: 2 }}>
                    <Box sx={{ width: 12, height: 12, borderRadius: "50%", bgcolor: milestone.color, position: "absolute", left: -6, top: 4 }} />
                    {i < 6 && <Box sx={{ position: "absolute", left: -1, top: 16, width: 2, height: "calc(100% + 8px)", bgcolor: alpha(milestone.color, 0.3) }} />}
                  </Box>
                  <Box sx={{ flex: 1, pb: 2 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>{milestone.title}</Typography>
                    <Typography variant="body2" color="text.secondary">{milestone.desc}</Typography>
                  </Box>
                </Box>
              ))}
            </Box>
          </Paper>

          {/* 7 Principles Section */}
          <Paper id="principles" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <TipsAndUpdatesIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                The 7 Principles
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The principles are the guiding obligations that determine whether a project is genuinely being managed
              using PRINCE2. They are universal, self-validating, and empowering. All seven must be applied for a
              project to be PRINCE2 compliant.
            </Typography>
            
            {/* Visual: Project Control Equation */}
            <Box sx={{ mb: 4, p: 3, bgcolor: alpha(ACCENT_COLOR, 0.05), borderRadius: 2, textAlign: "center" }}>
              <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 2 }}>
                The PRINCE2 Control Equation:
              </Typography>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 2, flexWrap: "wrap" }}>
                <Box sx={{ p: 2, bgcolor: "background.paper", borderRadius: 2, minWidth: 120 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#dc2626" }}>7 Principles</Typography>
                  <Typography variant="caption" color="text.secondary">Foundation</Typography>
                </Box>
                <Typography variant="h4" sx={{ color: "text.secondary" }}>+</Typography>
                <Box sx={{ p: 2, bgcolor: "background.paper", borderRadius: 2, minWidth: 120 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6" }}>7 Themes</Typography>
                  <Typography variant="caption" color="text.secondary">What to Manage</Typography>
                </Box>
                <Typography variant="h4" sx={{ color: "text.secondary" }}>+</Typography>
                <Box sx={{ p: 2, bgcolor: "background.paper", borderRadius: 2, minWidth: 120 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>7 Processes</Typography>
                  <Typography variant="caption" color="text.secondary">How to Do It</Typography>
                </Box>
                <Typography variant="h4" sx={{ color: "text.secondary" }}>=</Typography>
                <Box sx={{ p: 2, bgcolor: ACCENT_COLOR, borderRadius: 2, minWidth: 140 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "white" }}>Controlled Project</Typography>
                  <Typography variant="caption" sx={{ color: alpha("#fff", 0.8) }}>Success!</Typography>
                </Box>
              </Box>
            </Box>

            <Grid container spacing={2}>
              {[
                {
                  principle: "Continued Business Justification",
                  description: "A valid business reason must exist throughout the project. If justification disappears, the project should be stopped.",
                  number: "1",
                },
                {
                  principle: "Learn from Experience",
                  description: "Teams should seek, record, and act on lessons learned from previous projects and throughout the current project.",
                  number: "2",
                },
                {
                  principle: "Defined Roles & Responsibilities",
                  description: "Clear and agreed structure of accountability covering business, user, and supplier stakeholder interests.",
                  number: "3",
                },
                {
                  principle: "Manage by Stages",
                  description: "Projects are planned, monitored, and controlled on a stage-by-stage basis with decision points.",
                  number: "4",
                },
                {
                  principle: "Manage by Exception",
                  description: "Tolerances are set for objectives. Issues are escalated only when tolerances are forecast to be exceeded.",
                  number: "5",
                },
                {
                  principle: "Focus on Products",
                  description: "Successful projects are output-oriented. Product descriptions define quality expectations upfront.",
                  number: "6",
                },
                {
                  principle: "Tailor to Suit the Project",
                  description: "PRINCE2 must be tailored to the project's environment, size, complexity, importance, and risk.",
                  number: "7",
                },
              ].map((item) => (
                <Grid item xs={12} md={6} key={item.principle}>
                  <Card sx={{ height: "100%", position: "relative", overflow: "visible" }}>
                    <Box
                      sx={{
                        position: "absolute",
                        top: -12,
                        left: 16,
                        width: 28,
                        height: 28,
                        borderRadius: "50%",
                        bgcolor: ACCENT_COLOR,
                        color: "white",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        fontWeight: 700,
                        fontSize: "0.9rem",
                      }}
                    >
                      {item.number}
                    </Box>
                    <CardContent sx={{ pt: 3 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
                        {item.principle}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {item.description}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* 7 Themes Overview */}
          <Paper id="themes" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <SettingsIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                The 7 Themes
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Themes describe aspects of project management that must be addressed continuously throughout the project.
              Each theme answers a fundamental project management question.
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha(ACCENT_COLOR, 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Theme</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Question</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { theme: "Business Case", question: "Why?", purpose: "Establishes mechanisms to judge viability" },
                    { theme: "Organization", question: "Who?", purpose: "Defines accountabilities and responsibilities" },
                    { theme: "Quality", question: "What?", purpose: "Defines and implements quality requirements" },
                    { theme: "Plans", question: "How? How much?", purpose: "Facilitates communication and control" },
                    { theme: "Risk", question: "What if?", purpose: "Identifies and manages uncertainty" },
                    { theme: "Change", question: "What's the impact?", purpose: "Manages changes and issues" },
                    { theme: "Progress", question: "Where are we?", purpose: "Monitors and controls performance" },
                  ].map((row) => (
                    <TableRow key={row.theme}>
                      <TableCell sx={{ fontWeight: 600 }}>{row.theme}</TableCell>
                      <TableCell>{row.question}</TableCell>
                      <TableCell>{row.purpose}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          {/* Business Case Theme */}
          <Paper id="theme-business-case" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <AssignmentIcon sx={{ color: "#22c55e" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Business Case Theme
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Business Case theme establishes mechanisms to judge whether the project is (and remains) desirable,
              viable, and achievable. It supports the principle of continued business justification.
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Box sx={{ bgcolor: alpha("#22c55e", 0.05), p: 2, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2 }}>
                    Key Documents
                  </Typography>
                  <List dense>
                    {[
                      "Project Mandate (input)",
                      "Business Case (main document)",
                      "Benefits Review Plan",
                      "Project Brief",
                    ].map((item, i) => (
                      <ListItem key={i}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: "#22c55e" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Box sx={{ bgcolor: alpha("#22c55e", 0.05), p: 2, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2 }}>
                    Business Case Contents
                  </Typography>
                  <List dense>
                    {[
                      "Executive summary",
                      "Reasons for the project",
                      "Options considered",
                      "Expected benefits & dis-benefits",
                      "Costs, timescales, risks",
                      "Investment appraisal",
                    ].map((item, i) => (
                      <ListItem key={i}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <ArrowRightIcon sx={{ color: "#22c55e" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              </Grid>
            </Grid>
          </Paper>

          {/* Organization Theme */}
          <Paper id="theme-organization" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <GroupsIcon sx={{ color: "#3b82f6" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Organization Theme
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Organization theme defines the project's accountabilities and responsibilities. It addresses the
              "Who?" question and ensures the three stakeholder interests are represented.
            </Typography>
            <Box sx={{ bgcolor: alpha("#3b82f6", 0.05), p: 3, borderRadius: 2, mb: 3 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2 }}>
                Three Stakeholder Interests:
              </Typography>
              <Grid container spacing={2}>
                {[
                  { interest: "Business", description: "Ensures project remains viable and delivers value", role: "Executive" },
                  { interest: "User", description: "Specifies needs and uses the products", role: "Senior User" },
                  { interest: "Supplier", description: "Provides resources and expertise to build products", role: "Senior Supplier" },
                ].map((item) => (
                  <Grid item xs={12} md={4} key={item.interest}>
                    <Card sx={{ height: "100%", textAlign: "center" }}>
                      <CardContent>
                        <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6" }}>
                          {item.interest}
                        </Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                          {item.description}
                        </Typography>
                        <Chip label={item.role} size="small" sx={{ bgcolor: alpha("#3b82f6", 0.1) }} />
                      </CardContent>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Box>
          </Paper>

          {/* Quality Theme */}
          <Paper id="theme-quality" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <VerifiedIcon sx={{ color: "#f59e0b" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Quality Theme
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Quality theme defines and implements the means by which the project will verify that products are
              fit for purpose. It answers "What?" and ensures products meet stakeholder expectations.
            </Typography>
            <Box sx={{ bgcolor: "#1a1a2e", p: 3, borderRadius: 2, mb: 3, fontFamily: "monospace" }}>
              <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 2 }}>
                Product Description Structure:
              </Typography>
              <Typography variant="body2" component="pre" sx={{ color: "#e0e0e0", fontSize: "0.85rem" }}>
{`Product Description
├── Identifier
├── Title
├── Purpose
├── Composition (what it contains)
├── Derivation (source materials)
├── Format and Presentation
├── Development Skills Required
├── Quality Criteria
├── Quality Tolerance
├── Quality Method (how to check)
└── Quality Responsibilities`}
              </Typography>
            </Box>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              Quality Activities:
            </Typography>
            <List>
              {[
                "Quality Planning - defining quality requirements upfront",
                "Quality Control - checking products meet requirements (reviews, testing)",
                "Quality Assurance - independent verification of quality processes",
              ].map((item, i) => (
                <ListItem key={i}>
                  <ListItemIcon sx={{ minWidth: 32 }}>
                    <CheckCircleIcon sx={{ fontSize: 18, color: "#f59e0b" }} />
                  </ListItemIcon>
                  <ListItemText primary={item} />
                </ListItem>
              ))}
            </List>
          </Paper>

          {/* Plans Theme */}
          <Paper id="theme-plans" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <TimelineIcon sx={{ color: "#8b5cf6" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Plans Theme
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Plans theme facilitates communication and control by defining the means of delivering products.
              It answers "How?" and "How much?" across multiple planning levels.
            </Typography>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              Levels of Plans:
            </Typography>
            <Grid container spacing={2}>
              {[
                { level: "Project Plan", owner: "Project Manager", approver: "Project Board", purpose: "High-level view of entire project" },
                { level: "Stage Plan", owner: "Project Manager", approver: "Project Board", purpose: "Detailed plan for current stage" },
                { level: "Team Plan", owner: "Team Manager", approver: "Project Manager", purpose: "Detail for work assigned in Work Packages" },
                { level: "Exception Plan", owner: "Project Manager", approver: "Project Board", purpose: "Replaces plan when tolerances exceeded" },
              ].map((plan) => (
                <Grid item xs={12} sm={6} key={plan.level}>
                  <Card sx={{ height: "100%", borderLeft: `4px solid ${ACCENT_COLOR}` }}>
                    <CardContent>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                        {plan.level}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        {plan.purpose}
                      </Typography>
                      <Box sx={{ display: "flex", gap: 1 }}>
                        <Chip label={`Owner: ${plan.owner}`} size="small" sx={{ fontSize: "0.7rem" }} />
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Risk Theme */}
          <Paper id="theme-risk" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <SecurityIcon sx={{ color: "#dc2626" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Risk Theme
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Risk theme identifies, assesses, and controls uncertainty to improve the ability of the project to
              succeed. It answers "What if?" and manages both threats and opportunities.
            </Typography>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              Risk Management Procedure:
            </Typography>
            <Grid container spacing={1} sx={{ mb: 3 }}>
              {[
                { step: "Identify", description: "Identify risks using techniques like brainstorming, checklists" },
                { step: "Assess", description: "Estimate probability and impact, prioritize risks" },
                { step: "Plan", description: "Select and plan risk responses" },
                { step: "Implement", description: "Execute planned responses" },
                { step: "Communicate", description: "Report risk status to stakeholders" },
              ].map((item, i) => (
                <Grid item xs={12} key={item.step}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, p: 1.5, bgcolor: alpha("#dc2626", 0.05), borderRadius: 1 }}>
                    <Box
                      sx={{
                        width: 28,
                        height: 28,
                        borderRadius: "50%",
                        bgcolor: "#dc2626",
                        color: "white",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        fontWeight: 700,
                        fontSize: "0.8rem",
                      }}
                    >
                      {i + 1}
                    </Box>
                    <Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                        {item.step}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {item.description}
                      </Typography>
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              Risk Responses:
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Box sx={{ bgcolor: alpha("#dc2626", 0.05), p: 2, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#dc2626", mb: 1 }}>
                    For Threats
                  </Typography>
                  <List dense>
                    {["Avoid", "Reduce", "Fallback", "Transfer", "Accept", "Share"].map((r) => (
                      <ListItem key={r} sx={{ py: 0 }}>
                        <ListItemText primary={r} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Box sx={{ bgcolor: alpha("#22c55e", 0.05), p: 2, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#22c55e", mb: 1 }}>
                    For Opportunities
                  </Typography>
                  <List dense>
                    {["Exploit", "Enhance", "Share", "Accept", "Reject"].map((r) => (
                      <ListItem key={r} sx={{ py: 0 }}>
                        <ListItemText primary={r} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              </Grid>
            </Grid>
          </Paper>

          {/* Change Theme */}
          <Paper id="theme-change" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <CompareArrowsIcon sx={{ color: "#0891b2" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Change Theme
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Change theme identifies, assesses, and controls any potential and approved changes to the baseline.
              It answers "What's the impact?" and manages all types of issues.
            </Typography>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              Types of Issues:
            </Typography>
            <Grid container spacing={2}>
              {[
                { type: "Request for Change (RFC)", description: "Proposal to change a baseline product", color: "#3b82f6" },
                { type: "Off-Specification", description: "Current or forecast deviation from specification", color: "#f59e0b" },
                { type: "Problem/Concern", description: "Any other issue requiring resolution", color: "#8b5cf6" },
              ].map((issue) => (
                <Grid item xs={12} md={4} key={issue.type}>
                  <Card sx={{ height: "100%", borderTop: `4px solid ${issue.color}` }}>
                    <CardContent>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: issue.color }}>
                        {issue.type}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {issue.description}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Progress Theme */}
          <Paper id="theme-progress" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <TimelineIcon sx={{ color: "#22c55e" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Progress Theme
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Progress theme establishes mechanisms to monitor and compare actual against planned achievements,
              provide a forecast of objectives, and control deviations. It answers "Where are we now?"
            </Typography>
            <Box sx={{ bgcolor: alpha("#22c55e", 0.05), p: 3, borderRadius: 2, mb: 3 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2 }}>
                Tolerance Dimensions (6 aspects):
              </Typography>
              <Grid container spacing={1}>
                {["Time", "Cost", "Quality", "Scope", "Benefits", "Risk"].map((t) => (
                  <Grid item xs={4} md={2} key={t}>
                    <Chip label={t} sx={{ width: "100%", bgcolor: "#22c55e", color: "white" }} />
                  </Grid>
                ))}
              </Grid>
            </Box>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              Progress Reports:
            </Typography>
            <List>
              {[
                "Checkpoint Report - Team Manager to Project Manager",
                "Highlight Report - Project Manager to Project Board",
                "End Stage Report - Review of stage performance",
                "End Project Report - Review of project performance",
              ].map((item, i) => (
                <ListItem key={i}>
                  <ListItemIcon sx={{ minWidth: 32 }}>
                    <ArrowRightIcon sx={{ color: "#22c55e" }} />
                  </ListItemIcon>
                  <ListItemText primary={item} />
                </ListItem>
              ))}
            </List>
          </Paper>

          {/* 7 Processes */}
          <Paper id="processes" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <AccountTreeIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                The 7 Processes
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              PRINCE2 processes provide a set of activities to direct, manage, and deliver a project. They span from
              pre-project through delivery to post-project.
            </Typography>
            <Grid container spacing={2}>
              {[
                { abbr: "SU", name: "Starting up a Project", purpose: "Ensure prerequisites are in place before initiation", owner: "PM/Exec" },
                { abbr: "DP", name: "Directing a Project", purpose: "Enable Project Board to authorize and control", owner: "Project Board" },
                { abbr: "IP", name: "Initiating a Project", purpose: "Establish solid foundations for the project", owner: "Project Manager" },
                { abbr: "CS", name: "Controlling a Stage", purpose: "Assign work, monitor progress, take action", owner: "Project Manager" },
                { abbr: "MP", name: "Managing Product Delivery", purpose: "Ensure products are created and delivered", owner: "Team Manager" },
                { abbr: "SB", name: "Managing a Stage Boundary", purpose: "Review stage, plan next, report to Board", owner: "Project Manager" },
                { abbr: "CP", name: "Closing a Project", purpose: "Confirm acceptance, handover, close project", owner: "Project Manager" },
              ].map((process) => (
                <Grid item xs={12} key={process.abbr}>
                  <Card sx={{ bgcolor: alpha(ACCENT_COLOR, 0.03) }}>
                    <CardContent sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <Box
                        sx={{
                          width: 50,
                          height: 50,
                          borderRadius: 2,
                          bgcolor: ACCENT_COLOR,
                          color: "white",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          fontWeight: 700,
                          flexShrink: 0,
                        }}
                      >
                        {process.abbr}
                      </Box>
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                          {process.name}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          {process.purpose}
                        </Typography>
                      </Box>
                      <Chip label={process.owner} size="small" sx={{ bgcolor: alpha(ACCENT_COLOR, 0.1) }} />
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Day in the Life: PRINCE2 in Action */}
          <Paper
            id="day-in-the-life"
            elevation={0}
            sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#0891b2", 0.3)}`, bgcolor: alpha("#0891b2", 0.02) }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <PersonIcon sx={{ color: "#0891b2" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                📅 Day in the Life: PRINCE2 in Action
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              See how PRINCE2 processes and products work in real project scenarios throughout a typical day:
            </Typography>
            <Grid container spacing={2}>
              {[
                {
                  time: "8:00 AM",
                  event: "Daily Stand-up",
                  scenario: "Team Manager reviews yesterday's Work Package progress. One task is behind schedule.",
                  prince2: "Managing Product Delivery (MP) - monitoring work assigned",
                  color: "#3b82f6",
                },
                {
                  time: "9:30 AM",
                  event: "Issue Escalation",
                  scenario: "A supplier can't deliver a critical component on time. This will exceed stage tolerance.",
                  prince2: "Exception Report prepared, Controlling a Stage (CS) - escalate to Project Board",
                  color: "#dc2626",
                },
                {
                  time: "10:30 AM",
                  event: "Project Board Meeting",
                  scenario: "Board reviews Exception Report. Decides to extend timeline by 2 weeks within project tolerance.",
                  prince2: "Directing a Project (DP) - ad hoc direction, authorizing exception",
                  color: "#8b5cf6",
                },
                {
                  time: "12:00 PM",
                  event: "Quality Review",
                  scenario: "Team conducts quality review of completed deliverable against Product Description.",
                  prince2: "Quality Theme - Quality Control, updating Quality Register",
                  color: "#f59e0b",
                },
                {
                  time: "2:00 PM",
                  event: "Change Request",
                  scenario: "User requests new feature. PM assesses impact using Issue Register, logs as RFC.",
                  prince2: "Change Theme - Request for Change evaluated against baseline",
                  color: "#0891b2",
                },
                {
                  time: "3:30 PM",
                  event: "Risk Review",
                  scenario: "Weekly risk review identifies new threat. Team updates Risk Register with response plan.",
                  prince2: "Risk Theme - Assess, Plan responses, Communicate to stakeholders",
                  color: "#22c55e",
                },
                {
                  time: "4:30 PM",
                  event: "Highlight Report",
                  scenario: "PM prepares weekly Highlight Report summarizing progress, issues, and risks for Project Board.",
                  prince2: "Progress Theme - Controlling a Stage (CS), regular reporting",
                  color: ACCENT_COLOR,
                },
                {
                  time: "5:00 PM",
                  event: "Lessons Captured",
                  scenario: "Team debriefs on supplier issue. PM adds lesson to Lessons Log for future reference.",
                  prince2: "Learn from Experience principle - continuous improvement",
                  color: "#64748b",
                },
              ].map((item) => (
                <Grid item xs={12} md={6} key={item.time}>
                  <Card sx={{ height: "100%", borderLeft: `4px solid ${item.color}` }}>
                    <CardContent>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                        <Chip label={item.time} size="small" sx={{ bgcolor: item.color, color: "white", fontWeight: 600 }} />
                        <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{item.event}</Typography>
                      </Box>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                        {item.scenario}
                      </Typography>
                      <Box sx={{ bgcolor: alpha(item.color, 0.1), p: 1, borderRadius: 1 }}>
                        <Typography variant="caption" sx={{ fontWeight: 600, color: item.color }}>
                          PRINCE2: {item.prince2}
                        </Typography>
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Roles & Responsibilities */}
          <Paper id="roles" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <GroupsIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Roles & Responsibilities
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              PRINCE2 defines clear roles within a project management team structure. Each role has specific
              responsibilities aligned with the three stakeholder interests.
            </Typography>
            <Accordion defaultExpanded>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontWeight: 600 }}>Project Board</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  {[
                    { role: "Executive", responsibilities: ["Owns Business Case", "Chairs Project Board", "Appoints PM", "Final decision authority"], color: "#dc2626" },
                    { role: "Senior User", responsibilities: ["Specifies user needs", "Ensures fitness for purpose", "User acceptance", "Benefits realization"], color: "#3b82f6" },
                    { role: "Senior Supplier", responsibilities: ["Supplier resources", "Technical integrity", "Supplier commitments", "Quality of products"], color: "#22c55e" },
                  ].map((r) => (
                    <Grid item xs={12} md={4} key={r.role}>
                      <Box sx={{ p: 2, bgcolor: alpha(r.color, 0.05), borderRadius: 2, height: "100%" }}>
                        <Typography variant="subtitle1" sx={{ fontWeight: 600, color: r.color, mb: 1 }}>
                          {r.role}
                        </Typography>
                        <List dense>
                          {r.responsibilities.map((resp, i) => (
                            <ListItem key={i} sx={{ py: 0 }}>
                              <ListItemText primary={resp} primaryTypographyProps={{ variant: "body2" }} />
                            </ListItem>
                          ))}
                        </List>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </AccordionDetails>
            </Accordion>
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontWeight: 600 }}>Project Manager</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <List>
                  {[
                    "Day-to-day management of the project",
                    "Produces key management products (PID, plans, reports)",
                    "Manages stage delivery and controls work",
                    "Escalates issues and exceptions to Project Board",
                    "Manages risks and issues within tolerances",
                  ].map((item, i) => (
                    <ListItem key={i}>
                      <ListItemIcon sx={{ minWidth: 32 }}>
                        <CheckCircleIcon sx={{ fontSize: 18, color: ACCENT_COLOR }} />
                      </ListItemIcon>
                      <ListItemText primary={item} />
                    </ListItem>
                  ))}
                </List>
              </AccordionDetails>
            </Accordion>
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontWeight: 600 }}>Other Roles</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  {[
                    { role: "Team Manager", desc: "Produces products assigned via Work Packages" },
                    { role: "Project Assurance", desc: "Independent oversight of project health" },
                    { role: "Change Authority", desc: "Handles changes within delegated limits" },
                    { role: "Project Support", desc: "Administrative support to PM and team" },
                  ].map((r) => (
                    <Grid item xs={12} sm={6} key={r.role}>
                      <Box sx={{ p: 2, bgcolor: alpha(ACCENT_COLOR, 0.03), borderRadius: 2 }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                          {r.role}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          {r.desc}
                        </Typography>
                      </Box>
                    </Grid>
                  ))}
                </Grid>
              </AccordionDetails>
            </Accordion>
          </Paper>

          {/* Management Products */}
          <Paper id="management-products" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <DescriptionIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Management Products
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              PRINCE2 defines 26 management products categorized into three types: Baselines, Records, and Reports.
              These products support project control and communication.
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={4}>
                <Card sx={{ height: "100%", borderTop: `4px solid #dc2626` }}>
                  <CardContent>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: "#dc2626", mb: 2 }}>
                      Baselines
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      Define aspects of the project and are subject to change control.
                    </Typography>
                    <List dense>
                      {["Business Case", "Project Brief", "PID", "Product Descriptions", "Plans", "Work Packages"].map((p) => (
                        <ListItem key={p} sx={{ py: 0 }}>
                          <ListItemText primary={p} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={4}>
                <Card sx={{ height: "100%", borderTop: `4px solid #f59e0b` }}>
                  <CardContent>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b", mb: 2 }}>
                      Records
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      Dynamic information that builds up during the project.
                    </Typography>
                    <List dense>
                      {["Daily Log", "Issue Register", "Risk Register", "Lessons Log", "Quality Register", "Configuration Item Records"].map((p) => (
                        <ListItem key={p} sx={{ py: 0 }}>
                          <ListItemText primary={p} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={4}>
                <Card sx={{ height: "100%", borderTop: `4px solid #22c55e` }}>
                  <CardContent>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>
                      Reports
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      Snapshots of project status at points in time.
                    </Typography>
                    <List dense>
                      {["Checkpoint Report", "Highlight Report", "End Stage Report", "End Project Report", "Exception Report", "Lessons Report"].map((p) => (
                        <ListItem key={p} sx={{ py: 0 }}>
                          <ListItemText primary={p} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          </Paper>

          {/* PM Tools Landscape */}
          <Paper
            id="pm-tools"
            elevation={0}
            sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <SettingsIcon sx={{ color: "#0891b2" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Project Management Tools Landscape
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              While PRINCE2 is methodology-agnostic regarding tools, many organizations use software to manage
              PRINCE2 projects. Here's how popular tools align with PRINCE2:
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#0891b2", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Tool</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Best For</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>PRINCE2 Alignment</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Pricing</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { tool: "Microsoft Project", bestFor: "Traditional waterfall projects", alignment: "⭐⭐⭐⭐⭐ Excellent - built for stage-gate", pricing: "£££" },
                    { tool: "Jira", bestFor: "Agile/PRINCE2 Agile hybrid", alignment: "⭐⭐⭐⭐ Good - with configuration", pricing: "££" },
                    { tool: "Monday.com", bestFor: "Visual project tracking", alignment: "⭐⭐⭐ Moderate - flexible templates", pricing: "££" },
                    { tool: "Asana", bestFor: "Task management & collaboration", alignment: "⭐⭐⭐ Moderate - needs customization", pricing: "££" },
                    { tool: "Smartsheet", bestFor: "Enterprise PMO", alignment: "⭐⭐⭐⭐ Good - strong governance features", pricing: "£££" },
                    { tool: "Wrike", bestFor: "Cross-functional teams", alignment: "⭐⭐⭐⭐ Good - customizable workflows", pricing: "££" },
                    { tool: "Planview", bestFor: "Enterprise portfolio management", alignment: "⭐⭐⭐⭐⭐ Excellent - built for governance", pricing: "££££" },
                    { tool: "OpenProject", bestFor: "Open source alternative", alignment: "⭐⭐⭐⭐ Good - free PRINCE2 templates", pricing: "Free/£" },
                  ].map((row) => (
                    <TableRow key={row.tool}>
                      <TableCell sx={{ fontWeight: 600 }}>{row.tool}</TableCell>
                      <TableCell>{row.bestFor}</TableCell>
                      <TableCell>{row.alignment}</TableCell>
                      <TableCell>{row.pricing}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
            <Box sx={{ mt: 3, p: 2, bgcolor: alpha("#0891b2", 0.05), borderRadius: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                💡 Tool Selection Tip:
              </Typography>
              <Typography variant="body2">
                Choose tools that support your tailored PRINCE2 approach. A simple project might only need a
                spreadsheet for the Daily Log and Issue Register, while enterprise projects may need integrated
                PPM (Project Portfolio Management) suites. <strong>The method comes first, then the tool.</strong>
              </Typography>
            </Box>
            <Box sx={{ mt: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                PRINCE2 Management Products You Can Track in Tools:
              </Typography>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                {["Risk Register", "Issue Register", "Lessons Log", "Daily Log", "Quality Register", "Highlight Reports", "Stage Plans", "Work Packages"].map((product) => (
                  <Chip key={product} label={product} size="small" sx={{ bgcolor: alpha("#0891b2", 0.1) }} />
                ))}
              </Box>
            </Box>
          </Paper>

          {/* Tailoring PRINCE2 */}
          <Paper id="tailoring" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <SettingsIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Tailoring PRINCE2
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Tailoring means adapting PRINCE2 to suit the project environment, while maintaining the principles.
              It ensures the methodology is appropriate without becoming burdensome.
            </Typography>
            <Box sx={{ bgcolor: alpha("#dc2626", 0.05), p: 2, borderRadius: 2, mb: 3 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#dc2626", mb: 1 }}>
                What MUST NOT be tailored:
              </Typography>
              <Typography variant="body2">
                The 7 principles are mandatory. All must be applied for a project to be considered PRINCE2 compliant.
              </Typography>
            </Box>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              What CAN be tailored:
            </Typography>
            <Grid container spacing={2}>
              {[
                { area: "Themes", example: "Simplify risk management for low-risk projects" },
                { area: "Processes", example: "Combine stages for small projects" },
                { area: "Roles", example: "Combine Executive and Senior User roles" },
                { area: "Management Products", example: "Merge documents, simplify formats" },
                { area: "Terminology", example: "Use organization's preferred terms" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.area}>
                  <Box sx={{ p: 2, bgcolor: alpha(ACCENT_COLOR, 0.05), borderRadius: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                      {item.area}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.example}
                    </Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* PRINCE2 Agile */}
          <Paper id="prince2-agile" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <CompareArrowsIcon sx={{ color: "#0891b2" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                PRINCE2 Agile
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              PRINCE2 Agile combines the governance and control of PRINCE2 with the flexibility and responsiveness
              of agile methods like Scrum, Kanban, and Lean Startup.
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Box sx={{ bgcolor: alpha("#0891b2", 0.05), p: 2, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2 }}>
                    Key Concepts
                  </Typography>
                  <List dense>
                    {[
                      "Fix time and cost, flex scope",
                      "Use sprints within PRINCE2 stages",
                      "Servant leadership for Scrum Masters",
                      "Incorporate user stories and backlogs",
                      "Iterative delivery within governance framework",
                    ].map((item, i) => (
                      <ListItem key={i}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: "#0891b2" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Box sx={{ bgcolor: alpha("#0891b2", 0.05), p: 2, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2 }}>
                    Agilometer
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    PRINCE2 Agile introduces the "Agilometer" to assess how agile a project can be based on:
                  </Typography>
                  <List dense>
                    {["Flexibility on requirements", "Speed of communication", "Ease of collaboration", "Ability to release frequently", "Level of stakeholder involvement"].map((item, i) => (
                      <ListItem key={i} sx={{ py: 0 }}>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              </Grid>
            </Grid>
          </Paper>

          {/* Career Paths & Salary Guide */}
          <Paper
            id="career-paths"
            elevation={0}
            sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#22c55e", 0.3)}`, bgcolor: alpha("#22c55e", 0.02) }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <SchoolIcon sx={{ color: "#22c55e" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                💼 Career Paths & Salary Guide
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              PRINCE2 certification opens doors across industries. Here are typical UK/US salary ranges (2024):
            </Typography>
            <TableContainer sx={{ mb: 3 }}>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#22c55e", 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Role</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>UK Salary Range</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>US Salary Range</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Typical Cert Level</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { role: "Junior Project Coordinator", uk: "£25-35K", us: "$45-55K", cert: "Foundation" },
                    { role: "Project Administrator", uk: "£30-40K", us: "$50-65K", cert: "Foundation" },
                    { role: "Assistant Project Manager", uk: "£35-50K", us: "$60-80K", cert: "Foundation/Practitioner" },
                    { role: "Project Manager", uk: "£45-70K", us: "$75-110K", cert: "Practitioner" },
                    { role: "Senior Project Manager", uk: "£60-90K", us: "$95-140K", cert: "Practitioner + experience" },
                    { role: "Programme Manager", uk: "£75-120K", us: "$120-180K", cert: "Practitioner + MSP" },
                    { role: "PMO Manager", uk: "£55-85K", us: "$90-130K", cert: "Practitioner" },
                    { role: "Head of Projects", uk: "£90-150K", us: "$150-220K", cert: "Multiple certifications" },
                  ].map((row) => (
                    <TableRow key={row.role}>
                      <TableCell sx={{ fontWeight: 500 }}>{row.role}</TableCell>
                      <TableCell>{row.uk}</TableCell>
                      <TableCell>{row.us}</TableCell>
                      <TableCell><Chip label={row.cert} size="small" sx={{ fontSize: "0.7rem" }} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              Career Progression Timeline:
            </Typography>
            <Grid container spacing={1}>
              {[
                { stage: "1", years: "0-2 years", role: "Project Coordinator/Administrator", focus: "Learn processes, assist PM, PRINCE2 Foundation", color: "#3b82f6" },
                { stage: "2", years: "2-4 years", role: "Assistant/Junior Project Manager", focus: "Run small projects, get Practitioner certified", color: "#8b5cf6" },
                { stage: "3", years: "4-7 years", role: "Project Manager", focus: "Lead medium projects, build stakeholder skills", color: ACCENT_COLOR },
                { stage: "4", years: "7-10 years", role: "Senior PM / Programme Manager", focus: "Complex portfolios, mentor others, MSP/MoP", color: "#f59e0b" },
                { stage: "5", years: "10+ years", role: "PMO Director / Head of Projects", focus: "Strategic leadership, organizational PM maturity", color: "#22c55e" },
              ].map((item) => (
                <Grid item xs={12} key={item.stage}>
                  <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2, p: 1.5, bgcolor: alpha(item.color, 0.05), borderRadius: 1 }}>
                    <Box sx={{ width: 32, height: 32, borderRadius: "50%", bgcolor: item.color, color: "white", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, flexShrink: 0 }}>
                      {item.stage}
                    </Box>
                    <Box sx={{ flex: 1 }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.role}</Typography>
                        <Chip label={item.years} size="small" sx={{ fontSize: "0.7rem", bgcolor: alpha(item.color, 0.2) }} />
                      </Box>
                      <Typography variant="body2" color="text.secondary">{item.focus}</Typography>
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
            <Box sx={{ mt: 3, p: 2, bgcolor: alpha("#22c55e", 0.1), borderRadius: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                🔍 Job Titles to Search For:
              </Typography>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                {["PRINCE2 Project Manager", "IT Project Manager", "Programme Manager", "PMO Analyst", "Delivery Manager", "Project Lead", "Change Manager", "Implementation Manager"].map((title) => (
                  <Chip key={title} label={title} size="small" variant="outlined" />
                ))}
              </Box>
            </Box>
          </Paper>

          {/* Certifications */}
          <Paper id="certifications" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <WorkspacePremiumIcon sx={{ color: "#f59e0b" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                PRINCE2 Certifications
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              PRINCE2 offers a certification path that validates your knowledge and ability to apply the methodology.
              Certifications are administered by AXELOS through accredited training organizations.
            </Typography>
            <Grid container spacing={2}>
              {[
                {
                  level: "PRINCE2 Foundation",
                  description: "Understand PRINCE2 principles, themes, and processes. Can work as an informed member of a project team.",
                  prereq: "None",
                  exam: "60 questions, 55% to pass",
                  color: "#22c55e",
                },
                {
                  level: "PRINCE2 Practitioner",
                  description: "Apply PRINCE2 in real projects. Can tailor the method and manage projects using PRINCE2.",
                  prereq: "Foundation or equivalent",
                  exam: "68 questions, 60% to pass",
                  color: "#3b82f6",
                },
                {
                  level: "PRINCE2 Agile Foundation",
                  description: "Understand how to combine PRINCE2 with agile concepts and techniques.",
                  prereq: "None",
                  exam: "50 questions, 55% to pass",
                  color: "#0891b2",
                },
                {
                  level: "PRINCE2 Agile Practitioner",
                  description: "Apply PRINCE2 Agile in projects. Blend governance with agile delivery.",
                  prereq: "Foundation in PRINCE2 or PRINCE2 Agile",
                  exam: "50 questions, 60% to pass",
                  color: "#8b5cf6",
                },
              ].map((cert) => (
                <Grid item xs={12} sm={6} key={cert.level}>
                  <Card sx={{ height: "100%", borderTop: `4px solid ${cert.color}` }}>
                    <CardContent>
                      <Typography variant="h6" sx={{ fontWeight: 700, color: cert.color, mb: 1 }}>
                        {cert.level}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                        {cert.description}
                      </Typography>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                        <Typography variant="caption" color="text.secondary">
                          <strong>Prerequisite:</strong> {cert.prereq}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          <strong>Exam:</strong> {cert.exam}
                        </Typography>
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Exam Tips Section */}
          <Paper
            id="exam-tips"
            elevation={0}
            sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha("#f59e0b", 0.3)}`, bgcolor: alpha("#f59e0b", 0.02) }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <SchoolIcon sx={{ color: "#f59e0b" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                📝 Exam Preparation Tips
              </Typography>
            </Box>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Box sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05), borderRadius: 2, height: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
                    Foundation Exam Format
                  </Typography>
                  <List dense>
                    {[
                      "60 multiple-choice questions",
                      "60 minutes (1 hour)",
                      "55% pass mark (33/60 correct)",
                      "Closed book - no manual allowed",
                      "Cost: ~£300-400 / $350-450",
                      "Online proctored or test center",
                    ].map((item, i) => (
                      <ListItem key={i} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 24 }}>
                          <ArrowRightIcon sx={{ color: "#f59e0b" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Box sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.05), borderRadius: 2, height: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
                    Practitioner Exam Format
                  </Typography>
                  <List dense>
                    {[
                      "68 questions (objective testing)",
                      "150 minutes (2.5 hours)",
                      "60% pass mark (38/68 correct)",
                      "Open book - official manual allowed",
                      "Cost: ~£400-500 / $450-550",
                      "Scenario-based questions",
                    ].map((item, i) => (
                      <ListItem key={i} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 24 }}>
                          <ArrowRightIcon sx={{ color: "#8b5cf6" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              </Grid>
            </Grid>
            <Box sx={{ mt: 3, p: 2, bgcolor: alpha(ACCENT_COLOR, 0.05), borderRadius: 2 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2 }}>
                Foundation Exam Topic Weightings:
              </Typography>
              <Grid container spacing={1}>
                {[
                  { topic: "Principles", weight: "12%", questions: "~7 questions" },
                  { topic: "Themes", weight: "35%", questions: "~21 questions" },
                  { topic: "Processes", weight: "35%", questions: "~21 questions" },
                  { topic: "Roles", weight: "12%", questions: "~7 questions" },
                  { topic: "Management Products", weight: "6%", questions: "~4 questions" },
                ].map((item) => (
                  <Grid item xs={6} md={2.4} key={item.topic}>
                    <Box sx={{ textAlign: "center", p: 1.5, bgcolor: "background.paper", borderRadius: 1 }}>
                      <Typography variant="h6" sx={{ fontWeight: 700, color: ACCENT_COLOR }}>{item.weight}</Typography>
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>{item.topic}</Typography>
                      <Typography variant="caption" color="text.secondary">{item.questions}</Typography>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Box>
            <Grid container spacing={2} sx={{ mt: 2 }}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                  <CheckCircleIcon sx={{ color: "#22c55e", fontSize: 20 }} />
                  Study These Well:
                </Typography>
                <List dense>
                  {[
                    "7 Principles - know ALL by heart",
                    "7 Themes - what each addresses",
                    "7 Processes - who does what",
                    "Management by Exception concept",
                    "Roles: Executive vs PM responsibilities",
                    "Tolerance dimensions (Time, Cost, Quality, Scope, Benefits, Risk)",
                  ].map((tip, i) => (
                    <ListItem key={i} sx={{ py: 0.5 }}>
                      <ListItemText primary={tip} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                  <WarningIcon sx={{ color: "#dc2626", fontSize: 20 }} />
                  Common Exam Traps:
                </Typography>
                <List dense>
                  {[
                    "Confusing Executive with Sponsor (PRINCE2 uses Executive)",
                    "Mixing up themes with processes",
                    "Forgetting who APPROVES vs who CREATES products",
                    "Stage vs Project level tolerances",
                    "Checkpoint Report (TM→PM) vs Highlight Report (PM→Board)",
                    "Thinking principles can be tailored (they can't!)",
                  ].map((trap, i) => (
                    <ListItem key={i} sx={{ py: 0.5 }}>
                      <ListItemText primary={trap} primaryTypographyProps={{ variant: "body2" }} />
                    </ListItem>
                  ))}
                </List>
              </Grid>
            </Grid>
            <Box sx={{ mt: 3, p: 2, bgcolor: alpha("#22c55e", 0.1), borderRadius: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
                📚 Recommended Study Resources:
              </Typography>
              <Grid container spacing={1}>
                {[
                  { resource: "Official AXELOS Manual", type: "Essential" },
                  { resource: "PRINCE2 Foundation Training Course", type: "Recommended" },
                  { resource: "Practice Exam Simulators", type: "Highly Recommended" },
                  { resource: "PRINCE2 Wiki & Glossary", type: "Quick Reference" },
                ].map((item) => (
                  <Grid item xs={12} sm={6} md={3} key={item.resource}>
                    <Box sx={{ p: 1, bgcolor: "background.paper", borderRadius: 1, textAlign: "center" }}>
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>{item.resource}</Typography>
                      <Chip label={item.type} size="small" sx={{ mt: 0.5, fontSize: "0.65rem" }} />
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Box>
          </Paper>

          {/* Quiz Section */}
          <Box id="quiz">
            <QuizSection
              questions={quizQuestions}
              accentColor={ACCENT_COLOR}
              title="PRINCE2 Knowledge Check"
              description="Test your understanding of PRINCE2 with these questions covering fundamentals, themes, processes, roles, and management products."
            />
          </Box>

          <Divider sx={{ my: 4 }} />

          <Box sx={{ display: "flex", justifyContent: "center" }}>
            <Button
              variant="contained"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate("/learn")}
              sx={{ bgcolor: ACCENT_COLOR, "&:hover": { bgcolor: "#6d28d9" }, px: 4, py: 1.5, fontWeight: 700 }}
            >
              Back to Learning Hub
            </Button>
          </Box>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
