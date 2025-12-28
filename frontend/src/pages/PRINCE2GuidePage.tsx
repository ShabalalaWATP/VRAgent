import { useState, useEffect } from "react";
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
  { id: "roles", label: "Roles & Responsibilities" },
  { id: "management-products", label: "Management Products" },
  { id: "tailoring", label: "Tailoring PRINCE2" },
  { id: "prince2-agile", label: "PRINCE2 Agile" },
  { id: "certifications", label: "Certifications" },
  { id: "quiz", label: "Knowledge Check" },
];

export default function PRINCE2GuidePage() {
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

          {/* Quiz Section */}
          <Box id="quiz">
            <QuizSection
              questions={quizQuestions}
              accentColor={ACCENT_COLOR}
              title="PRINCE2 Knowledge Check"
              description="Test your understanding of PRINCE2 with these questions covering fundamentals, themes, processes, roles, and management products."
            />
          </Box>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
