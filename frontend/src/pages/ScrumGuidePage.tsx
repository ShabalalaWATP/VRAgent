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
import LoopIcon from "@mui/icons-material/Loop";
import GroupsIcon from "@mui/icons-material/Groups";
import PersonIcon from "@mui/icons-material/Person";
import AssignmentIcon from "@mui/icons-material/Assignment";
import EventIcon from "@mui/icons-material/Event";
import InventoryIcon from "@mui/icons-material/Inventory";
import VerifiedIcon from "@mui/icons-material/Verified";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import WarningIcon from "@mui/icons-material/Warning";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";

const ACCENT_COLOR = "#0891b2"; // Cyan for Scrum

// ========== QUIZ BANK (75 questions, 5 topics) ==========
const quizQuestions: QuizQuestion[] = [
  // Topic 1: Scrum Fundamentals (15 questions)
  {
    id: 1,
    topic: "Scrum Fundamentals",
    question: "What is the foundation of Scrum based on?",
    options: ["Predictive planning", "Empiricism", "Waterfall methodology", "Fixed scope delivery"],
    correctAnswer: 1,
    explanation: "Scrum is founded on empiricism, which asserts that knowledge comes from experience and making decisions based on what is observed."
  },
  {
    id: 2,
    topic: "Scrum Fundamentals",
    question: "What are the three pillars of empiricism in Scrum?",
    options: ["Plan, Execute, Review", "Transparency, Inspection, Adaptation", "Define, Build, Test", "Vision, Strategy, Execution"],
    correctAnswer: 1,
    explanation: "The three pillars of empiricism are Transparency (visibility), Inspection (timely checks), and Adaptation (adjusting based on findings)."
  },
  {
    id: 3,
    topic: "Scrum Fundamentals",
    question: "How many Scrum Values are there?",
    options: ["3", "4", "5", "7"],
    correctAnswer: 2,
    explanation: "There are five Scrum Values: Commitment, Focus, Openness, Respect, and Courage."
  },
  {
    id: 4,
    topic: "Scrum Fundamentals",
    question: "What is the maximum recommended size of a Scrum Team?",
    options: ["5 people", "7 people", "10 people", "15 people"],
    correctAnswer: 2,
    explanation: "The Scrum Guide recommends Scrum Teams be 10 or fewer people. Smaller teams communicate better and are more productive."
  },
  {
    id: 5,
    topic: "Scrum Fundamentals",
    question: "What is a Sprint in Scrum?",
    options: ["A planning meeting", "A fixed-length iteration", "A review session", "A retrospective"],
    correctAnswer: 1,
    explanation: "A Sprint is a fixed-length iteration (typically 1-4 weeks) during which a potentially releasable Increment is created."
  },
  {
    id: 6,
    topic: "Scrum Fundamentals",
    question: "Which Scrum Value is about team members trusting each other?",
    options: ["Commitment", "Focus", "Openness", "Respect"],
    correctAnswer: 3,
    explanation: "Respect is about Scrum Team members respecting each other as capable, independent people and being respected as such by others."
  },
  {
    id: 7,
    topic: "Scrum Fundamentals",
    question: "What does 'Transparency' mean in Scrum?",
    options: ["Sharing all code publicly", "Making the work visible to those performing and receiving it", "Publishing all meeting notes", "Open-source development"],
    correctAnswer: 1,
    explanation: "Transparency means the emergent process and work must be visible to those performing the work as well as those receiving the work."
  },
  {
    id: 8,
    topic: "Scrum Fundamentals",
    question: "What happens when Inspection reveals problems?",
    options: ["The Sprint is cancelled", "Adaptation must occur", "A new team is formed", "The project is paused"],
    correctAnswer: 1,
    explanation: "When Inspection reveals problems or undesirable variances, the process or materials being processed must be adjusted (Adaptation)."
  },
  {
    id: 9,
    topic: "Scrum Fundamentals",
    question: "What is the primary purpose of Scrum?",
    options: ["To deliver software faster", "To generate value through adaptive solutions for complex problems", "To reduce project costs", "To eliminate documentation"],
    correctAnswer: 1,
    explanation: "Scrum's purpose is to generate value through adaptive solutions for complex problems, not just speed or cost reduction."
  },
  {
    id: 10,
    topic: "Scrum Fundamentals",
    question: "Which Scrum Value is demonstrated when the team admits when something is harder than expected?",
    options: ["Commitment", "Focus", "Openness", "Courage"],
    correctAnswer: 2,
    explanation: "Openness is demonstrated when the Scrum Team and stakeholders are open about the work and challenges."
  },
  {
    id: 11,
    topic: "Scrum Fundamentals",
    question: "What is empirical process control?",
    options: ["Controlling through detailed upfront planning", "Controlling through observation and adjustment", "Controlling through management hierarchy", "Controlling through automation"],
    correctAnswer: 1,
    explanation: "Empirical process control relies on observation and experimentation rather than detailed upfront planning."
  },
  {
    id: 12,
    topic: "Scrum Fundamentals",
    question: "Which Scrum Value supports focusing on Sprint work and team goals?",
    options: ["Commitment", "Focus", "Openness", "Respect"],
    correctAnswer: 1,
    explanation: "Focus means the primary focus is on the work of the Sprint to make the best possible progress toward team goals."
  },
  {
    id: 13,
    topic: "Scrum Fundamentals",
    question: "What is lean thinking's contribution to Scrum?",
    options: ["Adding more documentation", "Reducing waste and focusing on essentials", "Increasing team size", "Extending Sprint length"],
    correctAnswer: 1,
    explanation: "Lean thinking reduces waste and focuses on the essentials, which Scrum incorporates alongside empiricism."
  },
  {
    id: 14,
    topic: "Scrum Fundamentals",
    question: "Which Scrum Value requires doing the right thing even when it's difficult?",
    options: ["Commitment", "Focus", "Openness", "Courage"],
    correctAnswer: 3,
    explanation: "Courage means Scrum Team members have the courage to do the right thing and work on tough problems."
  },
  {
    id: 15,
    topic: "Scrum Fundamentals",
    question: "What is the relationship between the three pillars of Scrum?",
    options: ["They are independent", "They are sequential", "They reinforce each other", "They are optional"],
    correctAnswer: 2,
    explanation: "The three pillars of Transparency, Inspection, and Adaptation reinforce each other and support empirical process control."
  },

  // Topic 2: Scrum Roles (15 questions)
  {
    id: 16,
    topic: "Scrum Roles",
    question: "How many accountabilities exist in a Scrum Team?",
    options: ["2", "3", "4", "5"],
    correctAnswer: 1,
    explanation: "There are three accountabilities in a Scrum Team: Product Owner, Scrum Master, and Developers."
  },
  {
    id: 17,
    topic: "Scrum Roles",
    question: "Who is accountable for maximizing the value of the product?",
    options: ["Scrum Master", "Developers", "Product Owner", "Stakeholders"],
    correctAnswer: 2,
    explanation: "The Product Owner is accountable for maximizing the value of the product resulting from the work of the Scrum Team."
  },
  {
    id: 18,
    topic: "Scrum Roles",
    question: "Who is accountable for the Scrum Team's effectiveness?",
    options: ["Product Owner", "Developers", "Scrum Master", "Project Manager"],
    correctAnswer: 2,
    explanation: "The Scrum Master is accountable for the Scrum Team's effectiveness and helps the team improve its practices."
  },
  {
    id: 19,
    topic: "Scrum Roles",
    question: "Who creates the Sprint Backlog?",
    options: ["Product Owner", "Scrum Master", "Developers", "Stakeholders"],
    correctAnswer: 2,
    explanation: "The Developers create the Sprint Backlog, which is their plan for achieving the Sprint Goal."
  },
  {
    id: 20,
    topic: "Scrum Roles",
    question: "Can the Product Owner delegate ordering of the Product Backlog?",
    options: ["No, never", "Yes, but they remain accountable", "Yes, to the Scrum Master only", "Yes, to Developers only"],
    correctAnswer: 1,
    explanation: "The Product Owner may delegate the work of ordering the Product Backlog to others, but they remain accountable."
  },
  {
    id: 21,
    topic: "Scrum Roles",
    question: "What is the Scrum Master's role regarding impediments?",
    options: ["Ignore them", "Assign them to Developers", "Help remove them", "Report them to management"],
    correctAnswer: 2,
    explanation: "The Scrum Master helps remove impediments to the Scrum Team's progress."
  },
  {
    id: 22,
    topic: "Scrum Roles",
    question: "Who is responsible for managing the Product Backlog?",
    options: ["Scrum Master", "Developers", "Product Owner", "The entire Scrum Team"],
    correctAnswer: 2,
    explanation: "The Product Owner is responsible for Product Backlog management, including developing and communicating the Product Goal."
  },
  {
    id: 23,
    topic: "Scrum Roles",
    question: "Are Developers specialists or cross-functional?",
    options: ["Always specialists", "Always generalists", "Cross-functional as a team", "It doesn't matter"],
    correctAnswer: 2,
    explanation: "Developers are cross-functional as a team, meaning collectively they have all skills needed to create an Increment each Sprint."
  },
  {
    id: 24,
    topic: "Scrum Roles",
    question: "Who adapts the Sprint Backlog during the Sprint?",
    options: ["Product Owner", "Scrum Master", "Developers", "Stakeholders"],
    correctAnswer: 2,
    explanation: "The Developers adapt the Sprint Backlog throughout the Sprint as they learn more about the work."
  },
  {
    id: 25,
    topic: "Scrum Roles",
    question: "What is the Scrum Master's relationship to the organization?",
    options: ["Reports to management", "Serves the organization", "Independent contractor", "External consultant"],
    correctAnswer: 1,
    explanation: "The Scrum Master serves the organization by helping people understand Scrum and leading adoption efforts."
  },
  {
    id: 26,
    topic: "Scrum Roles",
    question: "Who decides how to accomplish work during the Sprint?",
    options: ["Product Owner", "Scrum Master", "Developers", "Management"],
    correctAnswer: 2,
    explanation: "The Developers decide how to accomplish the work, they are self-managing in this regard."
  },
  {
    id: 27,
    topic: "Scrum Roles",
    question: "Can there be sub-teams within Developers?",
    options: ["Yes, with different titles", "No sub-teams or hierarchies exist", "Yes, with Scrum Master approval", "Only for large projects"],
    correctAnswer: 1,
    explanation: "Within a Scrum Team, there are no sub-teams or hierarchies. Developers are accountable as a whole."
  },
  {
    id: 28,
    topic: "Scrum Roles",
    question: "What does the Scrum Master coach the team on?",
    options: ["Technical skills only", "Self-management and cross-functionality", "Product requirements", "Time management"],
    correctAnswer: 1,
    explanation: "The Scrum Master coaches the team on self-management and cross-functionality."
  },
  {
    id: 29,
    topic: "Scrum Roles",
    question: "Who ensures that stakeholders understand the Product Backlog?",
    options: ["Scrum Master", "Developers", "Product Owner", "Project Manager"],
    correctAnswer: 2,
    explanation: "The Product Owner ensures the Product Backlog is transparent, visible, and understood by stakeholders."
  },
  {
    id: 30,
    topic: "Scrum Roles",
    question: "Is the Product Owner a committee or one person?",
    options: ["Always a committee", "One person who may represent a committee", "Either works", "Depends on project size"],
    correctAnswer: 1,
    explanation: "The Product Owner is one person, not a committee. They may represent the needs of many stakeholders."
  },

  // Topic 3: Scrum Events (15 questions)
  {
    id: 31,
    topic: "Scrum Events",
    question: "How many formal events does Scrum have?",
    options: ["3", "4", "5", "6"],
    correctAnswer: 2,
    explanation: "Scrum has five events: The Sprint (container), Sprint Planning, Daily Scrum, Sprint Review, and Sprint Retrospective."
  },
  {
    id: 32,
    topic: "Scrum Events",
    question: "What is the maximum length of a Sprint?",
    options: ["2 weeks", "3 weeks", "4 weeks / 1 month", "6 weeks"],
    correctAnswer: 2,
    explanation: "Sprints are fixed length events of one month or less to create consistency."
  },
  {
    id: 33,
    topic: "Scrum Events",
    question: "What is the time-box for Sprint Planning for a one-month Sprint?",
    options: ["2 hours", "4 hours", "8 hours", "No limit"],
    correctAnswer: 2,
    explanation: "Sprint Planning is time-boxed to a maximum of 8 hours for a one-month Sprint. Shorter Sprints have shorter planning."
  },
  {
    id: 34,
    topic: "Scrum Events",
    question: "What is the time-box for the Daily Scrum?",
    options: ["15 minutes", "30 minutes", "45 minutes", "1 hour"],
    correctAnswer: 0,
    explanation: "The Daily Scrum is a 15-minute time-boxed event for the Developers."
  },
  {
    id: 35,
    topic: "Scrum Events",
    question: "What is the purpose of the Sprint Review?",
    options: ["To criticize team performance", "To inspect the Increment and adapt the Product Backlog", "To assign blame for issues", "To plan the next Sprint"],
    correctAnswer: 1,
    explanation: "The purpose of the Sprint Review is to inspect the outcome of the Sprint and determine future adaptations."
  },
  {
    id: 36,
    topic: "Scrum Events",
    question: "What is discussed in the Sprint Retrospective?",
    options: ["Product features only", "Ways to increase quality and effectiveness", "Only technical issues", "Stakeholder requirements"],
    correctAnswer: 1,
    explanation: "The Sprint Retrospective focuses on how the Sprint went regarding individuals, interactions, processes, tools, and Definition of Done."
  },
  {
    id: 37,
    topic: "Scrum Events",
    question: "Can a Sprint be cancelled?",
    options: ["Never", "Only by the Scrum Master", "Only by the Product Owner", "By any team member"],
    correctAnswer: 2,
    explanation: "Only the Product Owner has the authority to cancel a Sprint."
  },
  {
    id: 38,
    topic: "Scrum Events",
    question: "What happens if work turns out to be different than expected during a Sprint?",
    options: ["The Sprint is cancelled", "Developers negotiate scope with the Product Owner", "The Sprint is extended", "Work is deferred to next Sprint"],
    correctAnswer: 1,
    explanation: "If work turns out to be different, Developers negotiate the scope of the Sprint Backlog with the Product Owner."
  },
  {
    id: 39,
    topic: "Scrum Events",
    question: "Who must attend the Daily Scrum?",
    options: ["The entire Scrum Team", "Only Developers", "Developers and Scrum Master", "Product Owner and Developers"],
    correctAnswer: 1,
    explanation: "The Daily Scrum is for Developers. If the Product Owner or Scrum Master are actively working on items, they participate as Developers."
  },
  {
    id: 40,
    topic: "Scrum Events",
    question: "What is the time-box for Sprint Retrospective for a one-month Sprint?",
    options: ["1 hour", "2 hours", "3 hours", "4 hours"],
    correctAnswer: 2,
    explanation: "The Sprint Retrospective is time-boxed to a maximum of 3 hours for a one-month Sprint."
  },
  {
    id: 41,
    topic: "Scrum Events",
    question: "What is the time-box for Sprint Review for a one-month Sprint?",
    options: ["2 hours", "4 hours", "6 hours", "8 hours"],
    correctAnswer: 1,
    explanation: "The Sprint Review is time-boxed to a maximum of 4 hours for a one-month Sprint."
  },
  {
    id: 42,
    topic: "Scrum Events",
    question: "What three topics are addressed in Sprint Planning?",
    options: ["Budget, Timeline, Resources", "Why, What, How", "Who, When, Where", "Risk, Quality, Scope"],
    correctAnswer: 1,
    explanation: "Sprint Planning addresses Why (Sprint Goal), What (Product Backlog items), and How (plan for delivering)."
  },
  {
    id: 43,
    topic: "Scrum Events",
    question: "When does the Sprint Retrospective occur?",
    options: ["Before Sprint Planning", "After the Daily Scrum", "After the Sprint Review", "At the middle of the Sprint"],
    correctAnswer: 2,
    explanation: "The Sprint Retrospective concludes the Sprint, occurring after the Sprint Review."
  },
  {
    id: 44,
    topic: "Scrum Events",
    question: "What is a key outcome of the Sprint Retrospective?",
    options: ["Updated Product Backlog", "Performance reviews", "Identified improvements for next Sprint", "Stakeholder feedback"],
    correctAnswer: 2,
    explanation: "The Scrum Team identifies the most helpful changes to improve effectiveness, addressing them as soon as possible."
  },
  {
    id: 45,
    topic: "Scrum Events",
    question: "Can the Sprint Review be considered a 'gate' or 'release approval'?",
    options: ["Yes, that's its purpose", "No, it's a working session to elicit feedback", "Only for external stakeholders", "Depends on the organization"],
    correctAnswer: 1,
    explanation: "The Sprint Review is a working session, not a gate. Stakeholders collaborate with the team to determine what could be done next."
  },

  // Topic 4: Scrum Artifacts (15 questions)
  {
    id: 46,
    topic: "Scrum Artifacts",
    question: "How many artifacts does Scrum define?",
    options: ["2", "3", "4", "5"],
    correctAnswer: 1,
    explanation: "Scrum defines three artifacts: Product Backlog, Sprint Backlog, and Increment."
  },
  {
    id: 47,
    topic: "Scrum Artifacts",
    question: "What is the commitment for the Product Backlog?",
    options: ["Sprint Goal", "Definition of Done", "Product Goal", "Release Plan"],
    correctAnswer: 2,
    explanation: "The Product Goal is the commitment for the Product Backlog, describing a future state of the product."
  },
  {
    id: 48,
    topic: "Scrum Artifacts",
    question: "What is the commitment for the Sprint Backlog?",
    options: ["Product Goal", "Sprint Goal", "Definition of Done", "Velocity"],
    correctAnswer: 1,
    explanation: "The Sprint Goal is the commitment for the Sprint Backlog, providing the single objective for the Sprint."
  },
  {
    id: 49,
    topic: "Scrum Artifacts",
    question: "What is the commitment for the Increment?",
    options: ["Sprint Goal", "Product Goal", "Definition of Done", "Acceptance Criteria"],
    correctAnswer: 2,
    explanation: "The Definition of Done is the commitment for the Increment, describing the quality measures required."
  },
  {
    id: 50,
    topic: "Scrum Artifacts",
    question: "What is the Product Backlog?",
    options: ["A fixed requirements document", "An emergent, ordered list of what is needed", "A project plan", "A test plan"],
    correctAnswer: 1,
    explanation: "The Product Backlog is an emergent, ordered list of what is needed to improve the product."
  },
  {
    id: 51,
    topic: "Scrum Artifacts",
    question: "What does the Sprint Backlog contain?",
    options: ["Only Product Backlog Items", "Sprint Goal, selected PBIs, and plan for delivering", "Bug reports only", "Test cases only"],
    correctAnswer: 1,
    explanation: "The Sprint Backlog contains the Sprint Goal, selected Product Backlog items, and the plan for delivering the Increment."
  },
  {
    id: 52,
    topic: "Scrum Artifacts",
    question: "When is an Increment created?",
    options: ["At the end of the Sprint only", "Whenever a PBI meets the Definition of Done", "During Sprint Review", "After stakeholder approval"],
    correctAnswer: 1,
    explanation: "An Increment is created whenever a Product Backlog item meets the Definition of Done, potentially multiple times per Sprint."
  },
  {
    id: 53,
    topic: "Scrum Artifacts",
    question: "Who owns the Product Backlog?",
    options: ["Developers", "Scrum Master", "Product Owner", "Stakeholders"],
    correctAnswer: 2,
    explanation: "The Product Owner is accountable for the Product Backlog, including its content, ordering, and availability."
  },
  {
    id: 54,
    topic: "Scrum Artifacts",
    question: "Is the Product Backlog ever complete?",
    options: ["Yes, before the project starts", "No, it evolves as long as the product exists", "Yes, at the end of each Sprint", "Depends on project type"],
    correctAnswer: 1,
    explanation: "The Product Backlog is never complete. It evolves as the product and its environment evolve."
  },
  {
    id: 55,
    topic: "Scrum Artifacts",
    question: "What makes an Increment usable?",
    options: ["Stakeholder approval", "Meeting the Definition of Done", "Product Owner sign-off", "Passing all tests"],
    correctAnswer: 1,
    explanation: "An Increment must meet the Definition of Done to be considered usable. If it doesn't, it cannot be released."
  },
  {
    id: 56,
    topic: "Scrum Artifacts",
    question: "Can multiple Increments be created within a Sprint?",
    options: ["No, only one per Sprint", "Yes, multiple Increments can be created", "Only with Scrum Master approval", "Only in short Sprints"],
    correctAnswer: 1,
    explanation: "Multiple Increments can be created within a Sprint. The sum of Increments is presented at the Sprint Review."
  },
  {
    id: 57,
    topic: "Scrum Artifacts",
    question: "What is Product Backlog refinement?",
    options: ["A formal Scrum event", "Breaking down and defining Product Backlog items", "Sprint planning activity", "Retrospective outcome"],
    correctAnswer: 1,
    explanation: "Product Backlog refinement is the act of breaking down and defining PBIs. It's an ongoing activity, not a formal event."
  },
  {
    id: 58,
    topic: "Scrum Artifacts",
    question: "Who creates the Definition of Done?",
    options: ["Product Owner alone", "Scrum Master alone", "The Scrum Team", "Organizational standards override"],
    correctAnswer: 2,
    explanation: "If not an organizational standard, the Scrum Team must create a Definition of Done appropriate for the product."
  },
  {
    id: 59,
    topic: "Scrum Artifacts",
    question: "What happens to work that doesn't meet Definition of Done?",
    options: ["It's released anyway", "It returns to the Product Backlog", "It's discarded", "It's auto-completed"],
    correctAnswer: 1,
    explanation: "If a PBI does not meet the Definition of Done, it cannot be released or presented. It returns to the Product Backlog."
  },
  {
    id: 60,
    topic: "Scrum Artifacts",
    question: "How should Product Backlog items be ordered?",
    options: ["Alphabetically", "By value, risk, dependencies, and other factors", "By creation date", "Randomly"],
    correctAnswer: 1,
    explanation: "PBIs are ordered based on value, risk, dependencies, and other factors the Product Owner considers important."
  },

  // Topic 5: Advanced Scrum & Anti-Patterns (15 questions)
  {
    id: 61,
    topic: "Advanced Scrum",
    question: "What is 'Scrum of Scrums'?",
    options: ["A certification level", "A scaling technique for multiple Scrum Teams", "A type of retrospective", "A sprint planning format"],
    correctAnswer: 1,
    explanation: "Scrum of Scrums is a scaling technique where representatives from multiple Scrum Teams meet to coordinate work."
  },
  {
    id: 62,
    topic: "Advanced Scrum",
    question: "What is a common anti-pattern in Daily Scrums?",
    options: ["Standing up", "Status reporting to Scrum Master", "Time-boxing to 15 minutes", "Meeting at the same time"],
    correctAnswer: 1,
    explanation: "A common anti-pattern is Developers reporting status to the Scrum Master instead of collaborating with each other."
  },
  {
    id: 63,
    topic: "Advanced Scrum",
    question: "What is technical debt?",
    options: ["Money owed to vendors", "Accumulated shortcuts in code quality", "Sprint velocity", "Budget overrun"],
    correctAnswer: 1,
    explanation: "Technical debt refers to accumulated shortcuts and compromises in code quality that create future work."
  },
  {
    id: 64,
    topic: "Advanced Scrum",
    question: "What is a 'Zombie Scrum' team?",
    options: ["A team working night shifts", "A team going through motions without delivering value", "A team with many sick days", "A very fast team"],
    correctAnswer: 1,
    explanation: "Zombie Scrum refers to teams that go through Scrum motions mechanically without delivering real value or improvement."
  },
  {
    id: 65,
    topic: "Advanced Scrum",
    question: "What is velocity in Scrum?",
    options: ["How fast code is written", "Amount of work completed per Sprint", "Number of bugs fixed", "Team's mood score"],
    correctAnswer: 1,
    explanation: "Velocity measures the amount of work (often story points) a team completes in a Sprint, used for forecasting."
  },
  {
    id: 66,
    topic: "Advanced Scrum",
    question: "What is 'Sprint Stuffing'?",
    options: ["Adding buffer time", "Adding too much work to a Sprint", "Celebrating Sprint success", "Early Sprint completion"],
    correctAnswer: 1,
    explanation: "Sprint Stuffing is an anti-pattern where too much work is added to a Sprint, leading to incomplete items."
  },
  {
    id: 67,
    topic: "Advanced Scrum",
    question: "What is a 'hardening Sprint'?",
    options: ["A recommended Scrum practice", "An anti-pattern for fixing quality issues", "A Sprint focused on infrastructure", "A Sprint for new team members"],
    correctAnswer: 1,
    explanation: "Hardening Sprints are an anti-pattern where separate Sprints are dedicated to fixing quality issues, indicating DoD problems."
  },
  {
    id: 68,
    topic: "Advanced Scrum",
    question: "What does 'INVEST' stand for in user stories?",
    options: ["Internal Value Estimation", "Independent, Negotiable, Valuable, Estimable, Small, Testable", "Investment Strategy", "Iterative Value Testing"],
    correctAnswer: 1,
    explanation: "INVEST criteria: Independent, Negotiable, Valuable, Estimable, Small, Testable - qualities of good user stories."
  },
  {
    id: 69,
    topic: "Advanced Scrum",
    question: "What is the 'Definition of Ready'?",
    options: ["Part of the Scrum Guide", "Team agreement on when items are ready for Sprint", "Same as Definition of Done", "A certification requirement"],
    correctAnswer: 1,
    explanation: "Definition of Ready is a team agreement (not in Scrum Guide) about criteria for items to enter a Sprint."
  },
  {
    id: 70,
    topic: "Advanced Scrum",
    question: "What is 'Mini-Waterfall' in Scrum context?",
    options: ["A valid Scrum practice", "An anti-pattern with sequential phases in Sprint", "A small project approach", "A Sprint planning technique"],
    correctAnswer: 1,
    explanation: "Mini-Waterfall is an anti-pattern where Sprints contain sequential phases (design, code, test) instead of cross-functional work."
  },
  {
    id: 71,
    topic: "Advanced Scrum",
    question: "What is Nexus in the context of Scrum?",
    options: ["A project management tool", "A scaling framework for 3-9 Scrum Teams", "A certification level", "A type of retrospective"],
    correctAnswer: 1,
    explanation: "Nexus is a scaling framework from Scrum.org for coordinating 3-9 Scrum Teams working on a single product."
  },
  {
    id: 72,
    topic: "Advanced Scrum",
    question: "What is 'Sprint Zero'?",
    options: ["A standard Scrum practice", "An anti-pattern for setup work before 'real' Sprints", "The first Sprint ever", "A planning Sprint"],
    correctAnswer: 1,
    explanation: "Sprint Zero is often an anti-pattern where teams do 'setup' work without delivering value, delaying real Sprints."
  },
  {
    id: 73,
    topic: "Advanced Scrum",
    question: "What is the purpose of burndown charts?",
    options: ["To track developer hours", "To visualize remaining work in Sprint or Release", "To measure team happiness", "To report to stakeholders only"],
    correctAnswer: 1,
    explanation: "Burndown charts visualize remaining work over time, helping teams track progress toward Sprint or Release goals."
  },
  {
    id: 74,
    topic: "Advanced Scrum",
    question: "What is 'Scrum But'?",
    options: ["A valid Scrum variation", "Claiming to do Scrum but omitting key elements", "A retrospective format", "An estimation technique"],
    correctAnswer: 1,
    explanation: "'Scrum But' refers to claiming to do Scrum but making exceptions that undermine its effectiveness."
  },
  {
    id: 75,
    topic: "Advanced Scrum",
    question: "What should happen if the Sprint Goal becomes obsolete?",
    options: ["Continue the Sprint anyway", "The Product Owner may cancel the Sprint", "The Scrum Master decides", "Wait until Sprint Review"],
    correctAnswer: 1,
    explanation: "If the Sprint Goal becomes obsolete, the Product Owner has the authority to cancel the Sprint."
  },
];

// ========== SIDEBAR SECTIONS ==========
const sections = [
  { id: "introduction", label: "Introduction" },
  { id: "learning-objectives", label: "Learning Objectives" },
  { id: "scrum-theory", label: "Scrum Theory" },
  { id: "scrum-values", label: "Scrum Values" },
  { id: "scrum-team", label: "The Scrum Team" },
  { id: "product-owner", label: "Product Owner" },
  { id: "scrum-master", label: "Scrum Master" },
  { id: "developers", label: "Developers" },
  { id: "scrum-events", label: "Scrum Events" },
  { id: "scrum-flow", label: "Scrum Flow" },
  { id: "sprint", label: "The Sprint" },
  { id: "sprint-planning", label: "Sprint Planning" },
  { id: "daily-scrum", label: "Daily Scrum" },
  { id: "sprint-review", label: "Sprint Review" },
  { id: "sprint-retrospective", label: "Sprint Retrospective" },
  { id: "scrum-artifacts", label: "Scrum Artifacts" },
  { id: "product-backlog", label: "Product Backlog" },
  { id: "sprint-backlog", label: "Sprint Backlog" },
  { id: "increment", label: "Increment" },
  { id: "definition-of-done", label: "Definition of Done" },
  { id: "scaling-scrum", label: "Scaling Scrum" },
  { id: "anti-patterns", label: "Anti-Patterns" },
  { id: "quiz", label: "Knowledge Check" },
];

export default function ScrumGuidePage() {
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

  const pageContext = `The Scrum Guide - Comprehensive guide to the Scrum framework covering theory, values, roles (Product Owner, Scrum Master, Developers), events (Sprint, Sprint Planning, Daily Scrum, Sprint Review, Sprint Retrospective), artifacts (Product Backlog, Sprint Backlog, Increment), Definition of Done, scaling techniques, and common anti-patterns.`;

  return (
    <LearnPageLayout pageTitle="The Scrum Guide" pageContext={pageContext}>
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
              background: `linear-gradient(135deg, ${alpha(ACCENT_COLOR, 0.1)} 0%, ${alpha("#06b6d4", 0.05)} 100%)`,
              border: `1px solid ${alpha(ACCENT_COLOR, 0.2)}`,
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: ACCENT_COLOR, width: 64, height: 64 }}>
                <LoopIcon sx={{ fontSize: 36 }} />
              </Avatar>
              <Box>
                <Typography variant="h3" sx={{ fontWeight: 800 }}>
                  The Scrum Guide
                </Typography>
                <Typography variant="h6" color="text.secondary">
                  The Definitive Guide to Scrum: The Rules of the Game
                </Typography>
              </Box>
            </Box>
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              Scrum is a lightweight framework that helps people, teams, and organizations generate value through
              adaptive solutions for complex problems. This guide covers everything from the theory and values that
              underpin Scrum to the roles, events, and artifacts that make it work.
            </Typography>
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              <strong>Why Scrum Exists:</strong> Traditional project management often assumes you can predict everything
              upfront—requirements, timelines, and solutions. But in complex work like software development, this rarely
              holds true. Scrum embraces uncertainty by delivering work in small increments, gathering feedback frequently,
              and adapting based on what you learn. Instead of a massive plan that becomes outdated, you have a living
              process that evolves with your understanding.
            </Typography>
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              <strong>Who Uses Scrum:</strong> While Scrum originated in software development, it's now used across
              industries—from marketing teams planning campaigns to HR departments improving hiring processes. Any work
              that benefits from iterative delivery and continuous improvement can leverage Scrum's principles.
            </Typography>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
              {["Framework", "Agile", "Empiricism", "Iterative", "Incremental"].map((tag) => (
                <Chip
                  key={tag}
                  label={tag}
                  size="small"
                  sx={{ bgcolor: alpha(ACCENT_COLOR, 0.1), color: ACCENT_COLOR, fontWeight: 500 }}
                />
              ))}
            </Box>
          </Paper>

          {/* Learning Objectives */}
          <Paper
            id="learning-objectives"
            elevation={0}
            sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <MenuBookIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Learning Objectives
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              By the end of this guide, you should be able to explain the foundations of Scrum, run the key events,
              and apply the artifacts and commitments to real work.
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Card sx={{ height: "100%", bgcolor: alpha(ACCENT_COLOR, 0.04) }}>
                  <CardContent>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
                      You will be able to:
                    </Typography>
                    <List dense>
                      {[
                        "Explain empiricism and the five Scrum Values",
                        "Describe the accountabilities and how they collaborate",
                        "Facilitate Sprint Planning, Daily Scrum, Review, and Retrospective",
                        "Use Scrum artifacts with their commitments",
                        "Spot common anti-patterns and correct them",
                      ].map((item, i) => (
                        <ListItem key={i}>
                          <ListItemIcon sx={{ minWidth: 28 }}>
                            <CheckCircleIcon sx={{ fontSize: 16, color: ACCENT_COLOR }} />
                          </ListItemIcon>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={6}>
                <Card sx={{ height: "100%", bgcolor: alpha("#22c55e", 0.05) }}>
                  <CardContent>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
                      Scrum is a good fit when:
                    </Typography>
                    <List dense>
                      {[
                        "Work is complex and benefits from frequent feedback",
                        "Teams can deliver usable increments each Sprint",
                        "Stakeholders are available to collaborate",
                        "Scope and solution are expected to evolve",
                      ].map((item, i) => (
                        <ListItem key={i}>
                          <ListItemIcon sx={{ minWidth: 28 }}>
                            <CheckCircleIcon sx={{ fontSize: 16, color: "#22c55e" }} />
                          </ListItemIcon>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
            <Box sx={{ mt: 2, bgcolor: alpha("#f59e0b", 0.08), p: 2, borderRadius: 2 }}>
              <Typography variant="body2">
                <strong>Heads-up:</strong> If work is highly predictable, fully defined up front, or teams cannot
                collaborate cross-functionally, Scrum may add overhead without improving outcomes.
              </Typography>
            </Box>
          </Paper>

          {/* Scrum Theory Section */}
          <Paper id="scrum-theory" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <TipsAndUpdatesIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Scrum Theory
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Scrum is founded on <strong>empiricism</strong> and <strong>lean thinking</strong>. Empiricism asserts
              that knowledge comes from experience and making decisions based on what is observed. Lean thinking
              reduces waste and focuses on the essentials.
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Scrum employs an iterative, incremental approach to optimize predictability and control risk. It engages
              groups of people who collectively have all the skills needed to do the work.
            </Typography>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide: Understanding Empiricism
              </Typography>
              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                <strong>What does "empiricism" really mean?</strong> Think of it like a scientist running experiments.
                Instead of assuming you know the answer, you try something, observe the results, and adjust. In Scrum:
              </Typography>
              <Typography variant="body2" component="div" sx={{ pl: 2, mb: 2 }}>
                • <strong>Week 1:</strong> You think users want Feature X based on initial research<br/>
                • <strong>Week 2:</strong> You build a small version and show it to real users<br/>
                • <strong>Week 3:</strong> Users say "This is great, but we actually need Feature Y more"<br/>
                • <strong>Week 4:</strong> You pivot to Feature Y instead of wasting months on X
              </Typography>
              <Typography variant="body2" sx={{ fontStyle: "italic", color: "text.secondary" }}>
                This is empiricism in action—learning from real experience rather than assumptions.
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                Beginner's Guide: Understanding Lean Thinking
              </Typography>
              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                <strong>What is "waste" in software development?</strong> Lean thinking comes from manufacturing (Toyota),
                but applies perfectly to knowledge work. Common wastes in software include:
              </Typography>
              <Typography variant="body2" component="div" sx={{ pl: 2, mb: 2 }}>
                • <strong>Overproduction:</strong> Building features nobody uses<br/>
                • <strong>Waiting:</strong> Developers waiting for decisions, approvals, or other teams<br/>
                • <strong>Handoffs:</strong> Work passing through 5 people when 2 would do<br/>
                • <strong>Defects:</strong> Bugs that could have been prevented with better practices<br/>
                • <strong>Over-processing:</strong> Excessive documentation nobody reads
              </Typography>
              <Typography variant="body2" sx={{ fontStyle: "italic", color: "text.secondary" }}>
                Scrum reduces waste by focusing on valuable work, keeping teams small, and delivering frequently.
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              The Three Pillars of Empiricism
            </Typography>
            <Grid container spacing={2}>
              {[
                {
                  title: "Transparency",
                  description: "The emergent process and work must be visible to those performing and receiving the work. Important decisions are based on the perceived state of its three formal artifacts.",
                  icon: "🔍",
                },
                {
                  title: "Inspection",
                  description: "The Scrum artifacts and progress toward agreed goals must be inspected frequently to detect potentially undesirable variances or problems. Inspection is enabled by the five Scrum events.",
                  icon: "🔬",
                },
                {
                  title: "Adaptation",
                  description: "If any aspects of a process deviate outside acceptable limits or the product is unacceptable, the process or materials must be adjusted as soon as possible to minimize further deviation.",
                  icon: "🔄",
                },
              ].map((pillar) => (
                <Grid item xs={12} md={4} key={pillar.title}>
                  <Card sx={{ height: "100%", bgcolor: alpha(ACCENT_COLOR, 0.03), border: `1px solid ${alpha(ACCENT_COLOR, 0.1)}` }}>
                    <CardContent>
                      <Typography variant="h2" sx={{ mb: 1 }}>{pillar.icon}</Typography>
                      <Typography variant="h6" sx={{ fontWeight: 600, mb: 1, color: ACCENT_COLOR }}>
                        {pillar.title}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {pillar.description}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Scrum Values Section */}
          <Paper id="scrum-values" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <EmojiEventsIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Scrum Values
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Successful use of Scrum depends on people becoming more proficient in living five values. These values
              give direction to the Scrum Team with regard to their work, actions, and behavior. Without these values,
              Scrum becomes just a set of meetings and artifacts—it loses its soul.
            </Typography>

            <Box sx={{ bgcolor: alpha(ACCENT_COLOR, 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha(ACCENT_COLOR, 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: ACCENT_COLOR }}>
                Why Values Matter: A Real-World Example
              </Typography>
              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                Imagine a team that does all the Scrum ceremonies but lacks these values. During Daily Scrum, developers
                hide that they're stuck because they fear looking incompetent (<em>no Openness</em>). The Product Owner
                commits to deadlines without consulting the team (<em>no Respect</em>). Developers take on work they know
                they can't finish to avoid conflict (<em>no Courage</em>). The result? A team going through the motions
                while trust erodes and delivery suffers.
              </Typography>
              <Typography variant="body2" sx={{ fontStyle: "italic", color: "text.secondary" }}>
                Now imagine the opposite: A team where it's safe to say "I'm stuck," where the PO trusts developers'
                estimates, and where anyone can challenge a bad idea. That's Scrum working as intended.
              </Typography>
            </Box>

            <Grid container spacing={2}>
              {[
                {
                  value: "Commitment",
                  description: "The Scrum Team commits to achieving its goals and supporting each other. This doesn't mean committing to fixed scope—it means committing to doing your best work and supporting teammates.",
                  example: "When a teammate is struggling, you offer to pair program or take on some of their tasks.",
                  color: "#dc2626",
                },
                {
                  value: "Focus",
                  description: "Primary focus is on the work of the Sprint to make the best possible progress toward goals. This means saying 'no' to distractions and context-switching.",
                  example: "When stakeholders ask for urgent additions mid-Sprint, the team explains the current Sprint Goal and negotiates properly.",
                  color: "#f59e0b",
                },
                {
                  value: "Openness",
                  description: "The Scrum Team and stakeholders are open about the work and challenges. Bad news early is better than bad news late.",
                  example: "A developer says 'I underestimated this task, I need help' on day 2, not day 10.",
                  color: "#22c55e",
                },
                {
                  value: "Respect",
                  description: "Scrum Team members respect each other as capable, independent people. Micromanagement and blame have no place here.",
                  example: "The team trusts developers to figure out HOW to build something; the PO focuses on WHAT and WHY.",
                  color: "#3b82f6",
                },
                {
                  value: "Courage",
                  description: "Members have courage to do the right thing and work on tough problems, even when it's uncomfortable.",
                  example: "A junior developer speaks up when they notice a security flaw in a senior's code.",
                  color: "#8b5cf6",
                },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.value}>
                  <Card sx={{ height: "100%", borderTop: `4px solid ${item.color}` }}>
                    <CardContent>
                      <Typography variant="h6" sx={{ fontWeight: 700, color: item.color, mb: 1 }}>
                        {item.value}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                        {item.description}
                      </Typography>
                      <Box sx={{ bgcolor: alpha(item.color, 0.08), p: 1.5, borderRadius: 1 }}>
                        <Typography variant="caption" sx={{ fontWeight: 600 }}>Example: </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {item.example}
                        </Typography>
                      </Box>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, mt: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#f59e0b" }}>
                How to Build These Values in Your Team
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
                • <strong>Model the behavior:</strong> Leaders and Scrum Masters should demonstrate these values first<br/>
                • <strong>Celebrate examples:</strong> When someone shows courage or openness, acknowledge it publicly<br/>
                • <strong>Make it safe to fail:</strong> Create an environment where mistakes are learning opportunities<br/>
                • <strong>Address violations:</strong> When values are broken, discuss it in retrospectives without blame<br/>
                • <strong>Hire for values:</strong> Technical skills can be taught; values alignment is harder to change
              </Typography>
            </Box>
          </Paper>

          {/* Scrum Team Section */}
          <Paper id="scrum-team" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <GroupsIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                The Scrum Team
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The fundamental unit of Scrum is a small team of people, a Scrum Team. The Scrum Team consists of one
              Scrum Master, one Product Owner, and Developers. Within a Scrum Team, there are no sub-teams or
              hierarchies.
            </Typography>
            <Box sx={{ bgcolor: alpha(ACCENT_COLOR, 0.05), p: 3, borderRadius: 2, mb: 3 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2 }}>
                Key Characteristics:
              </Typography>
              <List dense>
                {[
                  "Cross-functional: Members have all skills necessary to create value each Sprint",
                  "Self-managing: Internally decide who does what, when, and how",
                  "Small enough to remain nimble (typically 10 or fewer people)",
                  "Large enough to complete significant work within a Sprint",
                  "Accountable for all product-related activities",
                ].map((item, i) => (
                  <ListItem key={i}>
                    <ListItemIcon sx={{ minWidth: 32 }}>
                      <CheckCircleIcon sx={{ fontSize: 18, color: ACCENT_COLOR }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Box>
          </Paper>

          {/* Product Owner Section */}
          <Paper id="product-owner" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <PersonIcon sx={{ color: "#dc2626" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Product Owner
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Product Owner is accountable for maximizing the value of the product resulting from the work of the
              Scrum Team. The Product Owner is one person, not a committee. This single point of accountability is crucial—when
              everyone is responsible for product decisions, no one is.
            </Typography>

            <Box sx={{ bgcolor: alpha("#dc2626", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#dc2626" }}>
                A Day in the Life of a Product Owner
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>8:30 AM - Check metrics and feedback:</strong> Review analytics dashboards, customer support tickets,
                and user feedback from overnight. Note any urgent issues that might affect backlog priorities.<br/><br/>

                <strong>9:00 AM - Stakeholder call:</strong> Meet with sales team who reports customers are asking for a
                specific integration. Document requirements and explain current roadmap priorities.<br/><br/>

                <strong>10:00 AM - Daily Scrum (observe):</strong> Listen to understand progress and blockers. Don't direct
                the conversation—that's the developers' time. Note any questions about requirements to address afterward.<br/><br/>

                <strong>10:30 AM - Clarify requirements:</strong> A developer has questions about a user story. Walk through
                the acceptance criteria together, maybe sketch a quick wireframe.<br/><br/>

                <strong>11:00 AM - Backlog refinement prep:</strong> Review upcoming items, write acceptance criteria for
                new stories, gather data to help with estimation discussions.<br/><br/>

                <strong>1:00 PM - Customer interview:</strong> Talk to an actual user about their workflow. Discover they
                use the product differently than expected—this might change priorities.<br/><br/>

                <strong>2:30 PM - Backlog refinement session:</strong> Work with developers to break down large items,
                clarify requirements, and discuss technical considerations that might affect value.<br/><br/>

                <strong>4:00 PM - Update roadmap:</strong> Based on today's learnings, adjust the Product Backlog order.
                Communicate changes to stakeholders who need to know.
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              Core Accountabilities:
            </Typography>
            <List>
              {[
                "Developing and explicitly communicating the Product Goal",
                "Creating and clearly communicating Product Backlog items",
                "Ordering Product Backlog items to best achieve goals",
                "Ensuring that the Product Backlog is transparent, visible, and understood",
              ].map((item, i) => (
                <ListItem key={i}>
                  <ListItemIcon sx={{ minWidth: 32 }}>
                    <ArrowRightIcon sx={{ color: "#dc2626" }} />
                  </ListItemIcon>
                  <ListItemText primary={item} />
                </ListItem>
              ))}
            </List>

            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, mt: 3 }}>
              Common Mistakes New Product Owners Make:
            </Typography>
            <Grid container spacing={2}>
              {[
                { mistake: "Acting as a proxy", fix: "Have authority to make decisions, don't just relay messages from stakeholders" },
                { mistake: "Writing technical solutions", fix: "Describe WHAT users need, let developers determine HOW" },
                { mistake: "Ignoring the team's input", fix: "Developers often know what's technically valuable—listen to them" },
                { mistake: "Changing priorities constantly", fix: "Protect Sprint scope; save changes for Sprint Planning" },
              ].map((item, i) => (
                <Grid item xs={12} sm={6} key={i}>
                  <Box sx={{ bgcolor: alpha("#dc2626", 0.04), p: 2, borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ color: "#dc2626", fontWeight: 600 }}>
                      {item.mistake}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.fix}
                    </Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>

            <Box sx={{ bgcolor: alpha("#dc2626", 0.05), p: 2, borderRadius: 2, mt: 3 }}>
              <Typography variant="body2">
                <strong>Important:</strong> For Product Owners to succeed, the entire organization must respect their
                decisions. These decisions are visible in the Product Backlog content and ordering. If a VP can override
                the PO at will, the PO role becomes meaningless.
              </Typography>
            </Box>
          </Paper>

          {/* Scrum Master Section */}
          <Paper id="scrum-master" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <PersonIcon sx={{ color: "#22c55e" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Scrum Master
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Scrum Master is accountable for establishing Scrum as defined in the Scrum Guide. They help everyone
              understand Scrum theory and practice, both within the Scrum Team and the organization. The Scrum Master
              is a <strong>servant-leader</strong>—they lead by serving others, not by commanding.
            </Typography>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Understanding the Scrum Master Role: What It Is and Isn't
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "#22c55e", mb: 1 }}>
                    The Scrum Master IS:
                  </Typography>
                  <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
                    • A coach who helps the team improve<br/>
                    • A facilitator who makes events effective<br/>
                    • A shield who protects the team from distractions<br/>
                    • An impediment remover who clears blockers<br/>
                    • A change agent who helps the org adopt Scrum
                  </Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "#dc2626", mb: 1 }}>
                    The Scrum Master is NOT:
                  </Typography>
                  <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
                    • A project manager who assigns work<br/>
                    • A boss who approves time off<br/>
                    • A secretary who takes notes<br/>
                    • A status reporter to management<br/>
                    • A police officer enforcing "Scrum rules"
                  </Typography>
                </Grid>
              </Grid>
            </Box>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                A Day in the Life of a Scrum Master
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>8:30 AM - Prepare for Daily Scrum:</strong> Review the Sprint board. Are there any items stuck?
                Any patterns emerging? Think about coaching questions rather than solutions.<br/><br/>

                <strong>9:00 AM - Facilitate Daily Scrum:</strong> Ensure the 15-minute timebox is respected. If
                discussions go long, suggest "let's take that offline." Don't solve problems—help the team solve them.<br/><br/>

                <strong>9:30 AM - Follow up on impediments:</strong> A developer mentioned waiting on IT for server access.
                Call IT, escalate if needed, remove the blocker so developers can focus on development.<br/><br/>

                <strong>10:30 AM - Coach a team member:</strong> A developer is frustrated about unclear requirements.
                Instead of fixing it, coach them on how to communicate with the Product Owner effectively.<br/><br/>

                <strong>11:30 AM - Meet with other Scrum Masters:</strong> Share challenges and solutions. Learn that
                another team solved a similar problem—bring that knowledge back to your team.<br/><br/>

                <strong>1:00 PM - Stakeholder management:</strong> A manager wants "just a quick status update meeting."
                Explain that Sprint Review serves this purpose and invite them to attend.<br/><br/>

                <strong>2:00 PM - Prepare for Retrospective:</strong> The team has been struggling with code reviews.
                Design a focused retrospective activity to surface root causes.<br/><br/>

                <strong>3:30 PM - Observe and coach:</strong> Notice two developers avoiding collaboration. Have a
                private conversation to understand if there's a conflict that needs addressing.
              </Typography>
            </Box>

            <Grid container spacing={3}>
              <Grid item xs={12} md={4}>
                <Card sx={{ height: "100%", bgcolor: alpha("#22c55e", 0.05) }}>
                  <CardContent>
                    <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#22c55e", mb: 1 }}>
                      Serves the Scrum Team
                    </Typography>
                    <List dense>
                      {[
                        "Coaching on self-management and cross-functionality",
                        "Helping focus on creating high-value Increments",
                        "Removing impediments to progress",
                        "Ensuring all events are positive, productive, and timeboxed",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0 }}>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={4}>
                <Card sx={{ height: "100%", bgcolor: alpha("#22c55e", 0.05) }}>
                  <CardContent>
                    <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#22c55e", mb: 1 }}>
                      Serves the Product Owner
                    </Typography>
                    <List dense>
                      {[
                        "Helping find techniques for effective Product Goal definition",
                        "Helping establish empirical product planning",
                        "Facilitating stakeholder collaboration as needed",
                        "Helping ensure the Product Backlog is well-understood",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0 }}>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </CardContent>
                </Card>
              </Grid>
              <Grid item xs={12} md={4}>
                <Card sx={{ height: "100%", bgcolor: alpha("#22c55e", 0.05) }}>
                  <CardContent>
                    <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#22c55e", mb: 1 }}>
                      Serves the Organization
                    </Typography>
                    <List dense>
                      {[
                        "Leading, training, and coaching Scrum adoption",
                        "Planning and advising Scrum implementations",
                        "Helping employees understand empirical approach",
                        "Removing barriers between stakeholders and teams",
                      ].map((item, i) => (
                        <ListItem key={i} sx={{ py: 0 }}>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, mt: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#f59e0b" }}>
                Facilitation Tips for New Scrum Masters
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
                • <strong>Ask, don't tell:</strong> "What do you think we should do?" is more powerful than giving answers<br/>
                • <strong>Use silence:</strong> After asking a question, wait. Uncomfortable silence often leads to breakthroughs<br/>
                • <strong>Timebox ruthlessly:</strong> Respect people's time—end meetings on time, every time<br/>
                • <strong>Make it safe:</strong> No question is stupid, no concern is too small to raise<br/>
                • <strong>Follow up:</strong> When you commit to removing an impediment, do it—credibility is earned through action
              </Typography>
            </Box>
          </Paper>

          {/* Developers Section */}
          <Paper id="developers" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <GroupsIcon sx={{ color: "#3b82f6" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Developers
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Developers are the people in the Scrum Team that are committed to creating any aspect of a usable
              Increment each Sprint. The specific skills needed by Developers are often broad and vary with the domain
              of work.
            </Typography>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              Developers are always accountable for:
            </Typography>
            <List>
              {[
                "Creating a plan for the Sprint, the Sprint Backlog",
                "Instilling quality by adhering to a Definition of Done",
                "Adapting their plan each day toward the Sprint Goal",
                "Holding each other accountable as professionals",
              ].map((item, i) => (
                <ListItem key={i}>
                  <ListItemIcon sx={{ minWidth: 32 }}>
                    <CheckCircleIcon sx={{ fontSize: 18, color: "#3b82f6" }} />
                  </ListItemIcon>
                  <ListItemText primary={item} />
                </ListItem>
              ))}
            </List>
          </Paper>

          {/* Scrum Events Overview */}
          <Paper id="scrum-events" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <EventIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Scrum Events
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Sprint is a container for all other events. Each event in Scrum is a formal opportunity to inspect
              and adapt Scrum artifacts. These events are designed to enable transparency and minimize the need for
              undefined meetings.
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha(ACCENT_COLOR, 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Event</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Time-box (1-month Sprint)</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { event: "Sprint", timebox: "1 month or less", purpose: "Container for all events, create Increment" },
                    { event: "Sprint Planning", timebox: "8 hours max", purpose: "Define Sprint Goal, select items, plan work" },
                    { event: "Daily Scrum", timebox: "15 minutes", purpose: "Inspect progress, adapt Sprint Backlog" },
                    { event: "Sprint Review", timebox: "4 hours max", purpose: "Inspect Increment, adapt Product Backlog" },
                    { event: "Sprint Retrospective", timebox: "3 hours max", purpose: "Improve team effectiveness" },
                  ].map((row) => (
                    <TableRow key={row.event}>
                      <TableCell sx={{ fontWeight: 600 }}>{row.event}</TableCell>
                      <TableCell>{row.timebox}</TableCell>
                      <TableCell>{row.purpose}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          {/* Scrum Flow */}
          <Paper id="scrum-flow" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <LoopIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Scrum Flow
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Scrum works as a repeating cycle. Each Sprint creates an Increment, which fuels feedback, adapts the
              Product Backlog, and sets up the next Sprint.
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, alignItems: "center", mb: 3 }}>
              {[
                { label: "Product Goal + Backlog", color: "#0891b2" },
                { label: "Sprint Planning", color: "#8b5cf6" },
                { label: "Build + Daily Scrum", color: "#22c55e" },
                { label: "Sprint Review", color: "#3b82f6" },
                { label: "Retrospective", color: "#f59e0b" },
                { label: "Next Sprint", color: "#0891b2" },
              ].map((step, idx, arr) => (
                <Box key={step.label} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Chip
                    label={step.label}
                    size="small"
                    sx={{ bgcolor: alpha(step.color, 0.15), color: step.color, fontWeight: 600 }}
                  />
                  {idx < arr.length - 1 && <ArrowRightIcon sx={{ color: "text.disabled", fontSize: 18 }} />}
                </Box>
              ))}
            </Box>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Box sx={{ bgcolor: alpha(ACCENT_COLOR, 0.05), p: 2, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                    Typical Inputs
                  </Typography>
                  <List dense>
                    {[
                      "Clear Product Goal and ordered Product Backlog",
                      "Known team capacity and constraints",
                      "Definition of Done agreed by the team",
                    ].map((item, i) => (
                      <ListItem key={i}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: ACCENT_COLOR }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Box sx={{ bgcolor: alpha("#22c55e", 0.05), p: 2, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                    Typical Outputs
                  </Typography>
                  <List dense>
                    {[
                      "Sprint Goal and Sprint Backlog",
                      "A usable Increment that meets the Definition of Done",
                      "Updated Product Backlog based on feedback",
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
            </Grid>
          </Paper>

          {/* The Sprint */}
          <Paper id="sprint" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <LoopIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                The Sprint
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Sprints are the heartbeat of Scrum, where ideas are turned into value. They are fixed length events of
              one month or less to create consistency. A new Sprint starts immediately after the conclusion of the
              previous Sprint.
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Box sx={{ bgcolor: alpha(ACCENT_COLOR, 0.05), p: 2, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                    During the Sprint:
                  </Typography>
                  <List dense>
                    {[
                      "No changes that endanger the Sprint Goal",
                      "Quality does not decrease",
                      "Product Backlog is refined as needed",
                      "Scope may be clarified with Product Owner",
                    ].map((item, i) => (
                      <ListItem key={i}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: ACCENT_COLOR }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Box sx={{ bgcolor: alpha("#dc2626", 0.05), p: 2, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                    Sprint Cancellation:
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    Only the Product Owner can cancel a Sprint if the Sprint Goal becomes obsolete.
                  </Typography>
                  <Typography variant="body2">
                    This might occur if the company changes direction or market conditions change. Cancellation
                    consumes resources as the team regroups for Sprint Planning.
                  </Typography>
                </Box>
              </Grid>
            </Grid>
          </Paper>

          {/* Sprint Planning */}
          <Paper id="sprint-planning" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <AssignmentIcon sx={{ color: "#8b5cf6" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Sprint Planning
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Sprint Planning initiates the Sprint by laying out the work to be performed. The entire Scrum Team
              collaborates on this plan. Time-boxed to 8 hours for a one-month Sprint, shorter for shorter Sprints
              (typically 2 hours for a 2-week Sprint).
            </Typography>

            <Box sx={{ bgcolor: alpha("#8b5cf6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#8b5cf6" }}>
                Step-by-Step Sprint Planning Guide for Beginners
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Before the Meeting (Preparation):</strong><br/>
                • PO has refined top backlog items with acceptance criteria<br/>
                • Team knows their capacity (vacations, holidays, other commitments)<br/>
                • Previous Sprint velocity is available as a reference<br/><br/>

                <strong>Step 1: Set the Stage (5-10 min)</strong><br/>
                • Review the Product Goal and how this Sprint contributes to it<br/>
                • Discuss any constraints (team capacity, dependencies, deadlines)<br/><br/>

                <strong>Step 2: Craft the Sprint Goal (15-30 min)</strong><br/>
                • PO proposes what value we want to deliver this Sprint<br/>
                • Team discusses and refines until everyone commits to the goal<br/>
                • Write it down clearly—this guides all decisions during the Sprint<br/><br/>

                <strong>Step 3: Select Product Backlog Items (30-60 min)</strong><br/>
                • Starting from the top, developers pull items they believe they can complete<br/>
                • Discuss each item: Is it clear? Does it support the Sprint Goal?<br/>
                • Stop when the team feels they have enough work (use velocity as guide)<br/><br/>

                <strong>Step 4: Plan the Work (30-60 min)</strong><br/>
                • Break selected items into tasks (ideally ≤1 day each)<br/>
                • Identify dependencies and risks<br/>
                • Developers self-organize: who will work on what first?<br/><br/>

                <strong>Step 5: Confirm Commitment (5 min)</strong><br/>
                • Review Sprint Goal one more time<br/>
                • Does everyone believe we can achieve this? If not, adjust scope<br/>
                • Sprint officially begins!
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              The Three Topics Addressed:
            </Typography>
            <Accordion defaultExpanded sx={{ mb: 1 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontWeight: 600 }}>Topic 1: Why is this Sprint valuable?</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" sx={{ mb: 2 }}>
                  The Product Owner proposes how the product could increase value. The whole Scrum Team collaborates
                  to define a <strong>Sprint Goal</strong> that communicates why the Sprint is valuable to stakeholders.
                </Typography>
                <Box sx={{ bgcolor: alpha("#8b5cf6", 0.05), p: 2, borderRadius: 1 }}>
                  <Typography variant="caption" sx={{ fontWeight: 600 }}>Example Sprint Goals:</Typography>
                  <Typography variant="caption" component="div" sx={{ mt: 1 }}>
                    • "Users can complete checkout without creating an account"<br/>
                    • "Admin dashboard shows real-time sales metrics"<br/>
                    • "Mobile app loads 50% faster on slow connections"
                  </Typography>
                </Box>
              </AccordionDetails>
            </Accordion>
            <Accordion sx={{ mb: 1 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontWeight: 600 }}>Topic 2: What can be Done this Sprint?</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" sx={{ mb: 2 }}>
                  Developers select Product Backlog items to include in the current Sprint. The Scrum Team may refine
                  items during this process. <strong>Selecting how much can be completed is solely up to the Developers</strong>—the
                  PO cannot force more work onto the team.
                </Typography>
                <Box sx={{ bgcolor: alpha("#f59e0b", 0.05), p: 2, borderRadius: 1 }}>
                  <Typography variant="caption" sx={{ fontWeight: 600 }}>Pro Tip:</Typography>
                  <Typography variant="caption" component="div" sx={{ mt: 1 }}>
                    New teams often overcommit. Start conservative and increase over time. It's better to finish
                    early and pull more work than to carry incomplete items into the next Sprint.
                  </Typography>
                </Box>
              </AccordionDetails>
            </Accordion>
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontWeight: 600 }}>Topic 3: How will the chosen work get done?</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" sx={{ mb: 2 }}>
                  Developers plan the work necessary to create an Increment that meets the Definition of Done.
                  This is often done by decomposing PBIs into smaller work items of one day or less.
                </Typography>
                <Box sx={{ bgcolor: alpha("#22c55e", 0.05), p: 2, borderRadius: 1 }}>
                  <Typography variant="caption" sx={{ fontWeight: 600 }}>Task Breakdown Example:</Typography>
                  <Typography variant="caption" component="div" sx={{ mt: 1 }}>
                    User Story: "As a user, I can reset my password via email"<br/>
                    Tasks: Design email template (2h) → Build reset endpoint (4h) → Create reset page UI (3h) →
                    Write tests (2h) → Security review (1h) → Update documentation (1h)
                  </Typography>
                </Box>
              </AccordionDetails>
            </Accordion>

            <Box sx={{ bgcolor: alpha("#dc2626", 0.08), p: 3, borderRadius: 2, mt: 3, border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#dc2626" }}>
                Common Sprint Planning Mistakes to Avoid
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
                • <strong>No Sprint Goal:</strong> Just picking random items from the backlog without a unifying purpose<br/>
                • <strong>PO not available:</strong> Developers can't get questions answered, leading to assumptions<br/>
                • <strong>Skipping task breakdown:</strong> "We'll figure it out" leads to hidden complexity<br/>
                • <strong>Overcommitting:</strong> Saying yes to pressure instead of being realistic<br/>
                • <strong>Not considering capacity:</strong> Forgetting about vacations, meetings, and other commitments
              </Typography>
            </Box>
          </Paper>

          {/* Daily Scrum */}
          <Paper id="daily-scrum" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <EventIcon sx={{ color: "#f59e0b" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Daily Scrum
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Daily Scrum is a 15-minute event for Developers to inspect progress toward the Sprint Goal and
              adapt the Sprint Backlog as necessary. It is held at the same time and place every working day. Despite
              its brevity, this is often where teams win or lose—it's the daily heartbeat that keeps everyone aligned.
            </Typography>

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#f59e0b" }}>
                How to Run an Effective Daily Scrum (Beginner's Guide)
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>The Traditional Three Questions (Optional but Common):</strong><br/>
                Many teams use these as a starting point, though the Scrum Guide no longer prescribes them:<br/>
                1. What did I do yesterday that helped the team meet the Sprint Goal?<br/>
                2. What will I do today to help the team meet the Sprint Goal?<br/>
                3. Do I see any impediments that prevent me or the team from meeting the Sprint Goal?<br/><br/>

                <strong>Alternative Formats Teams Use:</strong><br/>
                • <strong>Walk the Board:</strong> Go through each in-progress item on the Sprint board from right to left<br/>
                • <strong>Focus on Flow:</strong> "What's blocked? What's about to be finished? What should we start?"<br/>
                • <strong>Round Robin:</strong> Each person gives a quick update in turn<br/>
                • <strong>Parking Lot:</strong> Note topics for after the standup on a visible list<br/><br/>

                <strong>The Key Mindset Shift:</strong><br/>
                Daily Scrum is NOT a status report to the Scrum Master or PO. It's developers talking TO EACH OTHER
                about how to coordinate their work. The Scrum Master facilitates but doesn't run it like a meeting.
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                What a Good Daily Scrum Sounds Like
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9, fontStyle: "italic" }}>
                <strong>Developer 1:</strong> "I finished the API endpoint for user profiles. Today I'm picking up the
                frontend integration. Sarah, I'll need your CSS component around 2pm—will that work?"<br/><br/>

                <strong>Developer 2 (Sarah):</strong> "Yes, I'll have it ready by noon. I'm a bit stuck on the responsive
                layout though—could use another pair of eyes."<br/><br/>

                <strong>Developer 3:</strong> "I can help with that right after this. I'm finishing up tests for the
                checkout flow. Actually, I noticed the Sprint Goal is at risk if we don't resolve that payment gateway
                issue today. Can we sync with the PO after this?"<br/><br/>

                <strong>Developer 1:</strong> "Good catch. Let's all stay for 5 minutes after to figure that out."
              </Typography>
              <Typography variant="caption" sx={{ display: "block", mt: 2, color: "text.secondary" }}>
                Notice: No one asked "what did you do yesterday?" They're coordinating today's work and solving problems together.
              </Typography>
            </Box>

            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Box sx={{ bgcolor: alpha("#22c55e", 0.05), p: 2, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#22c55e", mb: 1 }}>
                    Signs of a Healthy Daily Scrum
                  </Typography>
                  <List dense>
                    {[
                      "Developers talk to each other, not the Scrum Master",
                      "Focus is on Sprint Goal progress, not individual tasks",
                      "Problems surface quickly and get addressed",
                      "People offer to help each other spontaneously",
                      "It ends on time (or early!)",
                      "Energy is positive—people want to be there",
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
                <Box sx={{ bgcolor: alpha("#dc2626", 0.05), p: 2, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#dc2626", mb: 1 }}>
                    Warning Signs (Anti-Patterns)
                  </Typography>
                  <List dense>
                    {[
                      "Everyone reports to the Scrum Master like a boss",
                      "Detailed problem-solving during the standup",
                      "Consistently going over 15 minutes",
                      "People showing up late or not at all",
                      "Updates that don't relate to Sprint Goal",
                      "No one asks questions or offers help",
                    ].map((item, i) => (
                      <ListItem key={i}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <WarningIcon sx={{ fontSize: 16, color: "#dc2626" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              </Grid>
            </Grid>

            <Box sx={{ bgcolor: alpha(ACCENT_COLOR, 0.08), p: 3, borderRadius: 2, mt: 3, border: `1px solid ${alpha(ACCENT_COLOR, 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: ACCENT_COLOR }}>
                Pro Tips for Remote/Distributed Teams
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
                • <strong>Camera on:</strong> Helps build connection and keeps people engaged<br/>
                • <strong>Async option:</strong> Some teams post updates in Slack/Teams before a shorter live sync<br/>
                • <strong>Time zones:</strong> Rotate the meeting time so the same people aren't always inconvenienced<br/>
                • <strong>Virtual board:</strong> Share screen with the Sprint board during the standup<br/>
                • <strong>Keep it human:</strong> A quick "how is everyone?" before diving in builds team cohesion
              </Typography>
            </Box>
          </Paper>

          {/* Sprint Review */}
          <Paper id="sprint-review" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <EventIcon sx={{ color: "#3b82f6" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Sprint Review
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Sprint Review is to inspect the outcome of the Sprint and determine future adaptations. The Scrum
              Team presents results to key stakeholders and progress toward the Product Goal is discussed. This is where
              the empirical loop closes—real feedback from real stakeholders shapes what comes next.
            </Typography>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                How to Run a Great Sprint Review (Step-by-Step)
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Before the Review:</strong><br/>
                • Invite key stakeholders (customers, users, sponsors, other teams)<br/>
                • Prepare a working demo environment—avoid "it works on my machine"<br/>
                • Review what was Done vs. what was planned<br/><br/>

                <strong>During the Review (Sample Agenda for 2-week Sprint):</strong><br/>
                <strong>1. Welcome & Context (5 min):</strong> PO recaps the Sprint Goal and what we set out to achieve<br/>
                <strong>2. Demo the Increment (30-40 min):</strong> Developers show WORKING software—not slides, not mockups<br/>
                <strong>3. Discussion & Feedback (20-30 min):</strong> Stakeholders ask questions, provide feedback, share concerns<br/>
                <strong>4. Market/Business Update (10 min):</strong> PO shares any changes in market conditions or priorities<br/>
                <strong>5. Backlog Collaboration (10-15 min):</strong> Discuss what should come next based on what we learned<br/><br/>

                <strong>The Crucial Mindset:</strong><br/>
                Sprint Review is a CONVERSATION, not a presentation. Stakeholders should talk more than the team.
                If you're just showing slides and asking "any questions?" you're doing it wrong.
              </Typography>
            </Box>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Box sx={{ bgcolor: alpha("#22c55e", 0.05), p: 2, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#22c55e", mb: 1 }}>
                    What Makes Reviews Effective
                  </Typography>
                  <List dense>
                    {[
                      "Show working software, not presentations",
                      "Invite real users when possible",
                      "Actively solicit critical feedback",
                      "Adjust backlog based on what you learn",
                      "Keep it collaborative and interactive",
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
                <Box sx={{ bgcolor: alpha("#dc2626", 0.05), p: 2, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#dc2626", mb: 1 }}>
                    Common Review Anti-Patterns
                  </Typography>
                  <List dense>
                    {[
                      "PowerPoint presentations instead of demos",
                      "Only developers attend (no stakeholders)",
                      "No time for questions or feedback",
                      "Treating it as a gate/approval meeting",
                      "Demoing incomplete or broken features",
                    ].map((item, i) => (
                      <ListItem key={i}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <WarningIcon sx={{ fontSize: 16, color: "#dc2626" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              </Grid>
            </Grid>

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 2, borderRadius: 2 }}>
              <Typography variant="body2">
                <strong>Pro Tip:</strong> The best Sprint Reviews feel like a product discovery session. Stakeholders
                leave saying "I didn't know we could do that!" or "What if we tried this instead?" That's the feedback
                loop working as intended.
              </Typography>
            </Box>
          </Paper>

          {/* Sprint Retrospective */}
          <Paper id="sprint-retrospective" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <EventIcon sx={{ color: "#8b5cf6" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Sprint Retrospective
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Sprint Retrospective concludes the Sprint. It is an opportunity for the Scrum Team to inspect itself
              and create a plan for improvements to be enacted during the next Sprint. This is arguably the most important
              Scrum event—it's where teams get better, Sprint over Sprint.
            </Typography>

            <Box sx={{ bgcolor: alpha("#8b5cf6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#8b5cf6" }}>
                Retrospective Formats for Every Situation
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>1. Start, Stop, Continue (Classic - Good for Beginners)</strong><br/>
                • What should we START doing?<br/>
                • What should we STOP doing?<br/>
                • What should we CONTINUE doing?<br/><br/>

                <strong>2. Mad, Sad, Glad (Emotion-Focused)</strong><br/>
                • What made you MAD this Sprint?<br/>
                • What made you SAD?<br/>
                • What made you GLAD?<br/><br/>

                <strong>3. 4Ls (Comprehensive)</strong><br/>
                • What did we LOVE?<br/>
                • What did we LEARN?<br/>
                • What did we LACK?<br/>
                • What did we LONG for?<br/><br/>

                <strong>4. Sailboat (Visual Metaphor)</strong><br/>
                • Wind (what's pushing us forward)<br/>
                • Anchors (what's holding us back)<br/>
                • Rocks (risks ahead)<br/>
                • Island (our goal/destination)
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Sample Retrospective Agenda (90 minutes for 2-week Sprint)
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>1. Set the Stage (5 min):</strong> Check-in activity. "In one word, how do you feel about this Sprint?"<br/><br/>

                <strong>2. Gather Data (20 min):</strong> Collect observations using your chosen format (sticky notes, digital board)<br/><br/>

                <strong>3. Generate Insights (25 min):</strong> Group similar items, discuss patterns, identify root causes<br/><br/>

                <strong>4. Decide What to Do (20 min):</strong> Vote on top items, create specific action items with owners<br/><br/>

                <strong>5. Close the Retro (10 min):</strong> Summarize actions, appreciate team members, check out<br/><br/>

                <strong>Buffer (10 min):</strong> Always build in buffer—good discussions shouldn't be cut short
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              Focus Areas to Inspect:
            </Typography>
            <Grid container spacing={2}>
              {[
                { area: "Individuals", icon: "👤", description: "How did team members interact and collaborate? Any skills gaps?" },
                { area: "Interactions", icon: "🤝", description: "How effective was communication? Were there conflicts?" },
                { area: "Processes", icon: "⚙️", description: "What processes worked? What caused friction or delays?" },
                { area: "Tools", icon: "🔧", description: "Are tools enabling or hindering? Any tooling improvements needed?" },
                { area: "Definition of Done", icon: "✅", description: "Is our DoD appropriate? Should we strengthen it?" },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.area}>
                  <Card sx={{ height: "100%", textAlign: "center", p: 2 }}>
                    <Typography variant="h3">{item.icon}</Typography>
                    <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                      {item.area}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.description}
                    </Typography>
                  </Card>
                </Grid>
              ))}
            </Grid>

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, mt: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#f59e0b" }}>
                Making Retros Actually Lead to Change
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
                The #1 reason retrospectives fail: <strong>no follow-through</strong>. Here's how to fix that:<br/><br/>
                • <strong>Limit action items:</strong> Pick 1-2 improvements max—trying to fix everything fixes nothing<br/>
                • <strong>Make them SMART:</strong> Specific, Measurable, Achievable, Relevant, Time-bound<br/>
                • <strong>Assign owners:</strong> "The team will do X" means no one will do X<br/>
                • <strong>Add to Sprint Backlog:</strong> Important improvements deserve Sprint capacity<br/>
                • <strong>Review last Sprint's actions:</strong> Start each retro by checking if previous actions happened<br/>
                • <strong>Track improvement over time:</strong> Are we actually getting better? Measure it
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#dc2626", 0.08), p: 3, borderRadius: 2, mt: 3, border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#dc2626" }}>
                When Retros Go Wrong: Common Anti-Patterns
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
                • <strong>"Same retro every time":</strong> Vary your format—repetition breeds disengagement<br/>
                • <strong>"Nothing ever changes":</strong> If actions aren't happening, make fewer and track harder<br/>
                • <strong>"People don't speak up":</strong> Use anonymous input gathering, create psychological safety<br/>
                • <strong>"Blame game":</strong> Focus on processes and systems, not individuals<br/>
                • <strong>"Management attends":</strong> Unless they're part of the Scrum Team, they shouldn't be there<br/>
                • <strong>"We skip it when busy":</strong> That's exactly when you need it most
              </Typography>
            </Box>
          </Paper>

          {/* Scrum Artifacts Overview */}
          <Paper id="scrum-artifacts" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <InventoryIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Scrum Artifacts
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Scrum's artifacts represent work or value. They maximize transparency of key information so everyone
              has the same understanding. Each artifact contains a commitment to provide focus and measure progress.
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha(ACCENT_COLOR, 0.1) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Artifact</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Commitment</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Owner</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {[
                    { artifact: "Product Backlog", commitment: "Product Goal", owner: "Product Owner" },
                    { artifact: "Sprint Backlog", commitment: "Sprint Goal", owner: "Developers" },
                    { artifact: "Increment", commitment: "Definition of Done", owner: "Scrum Team" },
                  ].map((row) => (
                    <TableRow key={row.artifact}>
                      <TableCell sx={{ fontWeight: 600 }}>{row.artifact}</TableCell>
                      <TableCell>{row.commitment}</TableCell>
                      <TableCell>{row.owner}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          {/* Product Backlog */}
          <Paper id="product-backlog" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <AssignmentIcon sx={{ color: "#dc2626" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Product Backlog
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Product Backlog is an emergent, ordered list of what is needed to improve the product. It is the
              single source of work undertaken by the Scrum Team.
            </Typography>
            <Box sx={{ bgcolor: alpha("#dc2626", 0.05), p: 3, borderRadius: 2, mb: 3 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2 }}>
                Product Goal (Commitment)
              </Typography>
              <Typography variant="body2">
                The Product Goal describes a future state of the product and serves as a target for the Scrum Team.
                The Product Goal is in the Product Backlog. The rest of the Product Backlog emerges to define "what"
                will fulfill the Product Goal.
              </Typography>
            </Box>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              Characteristics:
            </Typography>
            <List>
              {[
                "Never complete - evolves with the product and environment",
                "Product Backlog items (PBIs) are ordered by the Product Owner",
                "Higher-ordered items are more refined and detailed",
                "PBIs ready for selection are refined to be done in one Sprint",
                "Refinement is an ongoing activity to add detail and estimates",
              ].map((item, i) => (
                <ListItem key={i}>
                  <ListItemIcon sx={{ minWidth: 32 }}>
                    <CheckCircleIcon sx={{ fontSize: 18, color: "#dc2626" }} />
                  </ListItemIcon>
                  <ListItemText primary={item} />
                </ListItem>
              ))}
            </List>
          </Paper>

          {/* Sprint Backlog */}
          <Paper id="sprint-backlog" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <AssignmentIcon sx={{ color: "#f59e0b" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Sprint Backlog
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Sprint Backlog is composed of the Sprint Goal (why), the set of Product Backlog items selected for
              the Sprint (what), and an actionable plan for delivering the Increment (how).
            </Typography>
            <Box sx={{ bgcolor: alpha("#f59e0b", 0.05), p: 3, borderRadius: 2, mb: 3 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2 }}>
                Sprint Goal (Commitment)
              </Typography>
              <Typography variant="body2">
                The Sprint Goal is the single objective for the Sprint. It provides flexibility in terms of the exact
                work needed to achieve it. The Sprint Goal creates coherence and focus, encouraging the Scrum Team
                to work together rather than on separate initiatives.
              </Typography>
            </Box>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              Key Points:
            </Typography>
            <List>
              {[
                "Created by and for the Developers",
                "A real-time picture of work in the Sprint",
                "Updated throughout the Sprint as more is learned",
                "Should have enough detail for inspection in Daily Scrum",
              ].map((item, i) => (
                <ListItem key={i}>
                  <ListItemIcon sx={{ minWidth: 32 }}>
                    <ArrowRightIcon sx={{ color: "#f59e0b" }} />
                  </ListItemIcon>
                  <ListItemText primary={item} />
                </ListItem>
              ))}
            </List>
          </Paper>

          {/* Increment */}
          <Paper id="increment" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <VerifiedIcon sx={{ color: "#22c55e" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Increment
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              An Increment is a concrete stepping stone toward the Product Goal. Each Increment is additive to all
              prior Increments and thoroughly verified, ensuring all Increments work together.
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Box sx={{ bgcolor: alpha("#22c55e", 0.05), p: 2, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                    Increment Requirements
                  </Typography>
                  <List dense>
                    {[
                      "Must meet the Definition of Done",
                      "Must be usable (potentially releasable)",
                      "Multiple Increments may be created per Sprint",
                      "The sum of Increments is presented at Sprint Review",
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
                <Box sx={{ bgcolor: alpha("#3b82f6", 0.05), p: 2, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                    Value Delivery
                  </Typography>
                  <Typography variant="body2">
                    An Increment may be delivered to stakeholders prior to the end of the Sprint. The Sprint Review
                    should never be considered a gate to releasing value. Work cannot be part of an Increment unless
                    it meets the Definition of Done.
                  </Typography>
                </Box>
              </Grid>
            </Grid>
          </Paper>

          {/* Definition of Done */}
          <Paper id="definition-of-done" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <VerifiedIcon sx={{ color: "#8b5cf6" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Definition of Done
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Definition of Done is a formal description of the state of the Increment when it meets the quality
              measures required for the product. When a Product Backlog item meets the Definition of Done, an
              Increment is born.
            </Typography>
            <Box sx={{ bgcolor: "#1a1a2e", p: 3, borderRadius: 2, mb: 3, fontFamily: "monospace" }}>
              <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 2 }}>
                Example Definition of Done:
              </Typography>
              <Typography variant="body2" component="pre" sx={{ color: "#e0e0e0", fontSize: "0.85rem" }}>
{`- Code reviewed by at least one other developer
- All unit tests passing (>80% coverage)
- Integration tests passing
- No critical or high severity bugs
- Documentation updated
- Performance benchmarks met
- Security scan completed
- Deployed to staging environment
- Acceptance criteria verified
- Product Owner demo completed`}
              </Typography>
            </Box>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              Key Points:
            </Typography>
            <List>
              {[
                "Creates transparency by providing shared understanding",
                "If organizational standard exists, all teams must follow it as minimum",
                "If not an organizational standard, Scrum Team must create one",
                "Developers must conform to the Definition of Done",
                "Definition of Done should be strengthened over time",
              ].map((item, i) => (
                <ListItem key={i}>
                  <ListItemIcon sx={{ minWidth: 32 }}>
                    <CheckCircleIcon sx={{ fontSize: 18, color: "#8b5cf6" }} />
                  </ListItemIcon>
                  <ListItemText primary={item} />
                </ListItem>
              ))}
            </List>
          </Paper>

          {/* Scaling Scrum */}
          <Paper id="scaling-scrum" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <AccountTreeIcon sx={{ color: ACCENT_COLOR }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Scaling Scrum
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              When multiple Scrum Teams work on the same product, they need coordination mechanisms. Several
              frameworks extend Scrum for enterprise scale while preserving its core principles.
            </Typography>
            <Grid container spacing={2}>
              {[
                {
                  name: "Nexus",
                  description: "From Scrum.org. Coordinates 3-9 Scrum Teams on a single product with a Nexus Integration Team.",
                  color: "#0891b2",
                },
                {
                  name: "LeSS",
                  description: "Large-Scale Scrum. Minimalist scaling with one Product Owner, one Product Backlog for multiple teams.",
                  color: "#dc2626",
                },
                {
                  name: "SAFe",
                  description: "Scaled Agile Framework. Comprehensive enterprise framework with Agile Release Trains (ARTs).",
                  color: "#22c55e",
                },
                {
                  name: "Scrum@Scale",
                  description: "From Scrum Inc. Modular approach using Scrum of Scrums and Executive Action Teams.",
                  color: "#8b5cf6",
                },
              ].map((framework) => (
                <Grid item xs={12} sm={6} key={framework.name}>
                  <Card sx={{ height: "100%", borderLeft: `4px solid ${framework.color}` }}>
                    <CardContent>
                      <Typography variant="h6" sx={{ fontWeight: 700, color: framework.color }}>
                        {framework.name}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {framework.description}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              ))}
            </Grid>
            <Box sx={{ bgcolor: alpha(ACCENT_COLOR, 0.05), p: 2, borderRadius: 2, mt: 3 }}>
              <Typography variant="body2">
                <strong>Note:</strong> The Scrum Guide itself doesn't prescribe scaling. These frameworks are
                complementary approaches built on Scrum's foundation.
              </Typography>
            </Box>
          </Paper>

          {/* Anti-Patterns */}
          <Paper id="anti-patterns" elevation={0} sx={{ p: 4, mb: 4, borderRadius: 3, border: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 3 }}>
              <WarningIcon sx={{ color: "#dc2626" }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }}>
                Common Anti-Patterns
              </Typography>
            </Box>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Anti-patterns are common practices that undermine Scrum's effectiveness. Recognizing them helps teams
              stay true to empirical process control and continuous improvement.
            </Typography>
            <Grid container spacing={2}>
              {[
                {
                  pattern: "Zombie Scrum",
                  description: "Going through Scrum motions without delivering real value or stakeholder engagement.",
                  fix: "Focus on outcomes, involve stakeholders, measure value delivery",
                },
                {
                  pattern: "Sprint Stuffing",
                  description: "Overcommitting to too much work, resulting in incomplete items.",
                  fix: "Use velocity data, leave buffer, say no to scope creep",
                },
                {
                  pattern: "Scrum But",
                  description: "'We do Scrum, but...' - making exceptions that undermine the framework.",
                  fix: "Commit fully to Scrum, address underlying issues properly",
                },
                {
                  pattern: "Mini-Waterfall",
                  description: "Sequential phases (design, code, test) within a Sprint.",
                  fix: "Cross-functional work, integrate continuously, slice vertically",
                },
                {
                  pattern: "Sprint Zero",
                  description: "Dedicated 'setup' Sprint without delivering value.",
                  fix: "Deliver value from Sprint 1, do setup incrementally",
                },
                {
                  pattern: "Hardening Sprints",
                  description: "Separate Sprints to fix quality issues before release.",
                  fix: "Strengthen Definition of Done, build quality in every Sprint",
                },
              ].map((item) => (
                <Grid item xs={12} md={6} key={item.pattern}>
                  <Card sx={{ height: "100%", bgcolor: alpha("#dc2626", 0.03) }}>
                    <CardContent>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#dc2626", mb: 1 }}>
                        {item.pattern}
                      </Typography>
                      <Typography variant="body2" sx={{ mb: 1 }}>
                        {item.description}
                      </Typography>
                      <Typography variant="body2" sx={{ color: "#22c55e" }}>
                        <strong>Fix:</strong> {item.fix}
                      </Typography>
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
              title="Scrum Knowledge Check"
              description="Test your understanding of the Scrum framework with these questions covering theory, roles, events, artifacts, and advanced topics."
            />
          </Box>

          <Divider sx={{ my: 4 }} />

          <Box sx={{ display: "flex", justifyContent: "center" }}>
            <Button
              variant="contained"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate("/learn")}
              sx={{ bgcolor: ACCENT_COLOR, "&:hover": { bgcolor: "#0e7490" }, px: 4, py: 1.5, fontWeight: 700 }}
            >
              Back to Learning Hub
            </Button>
          </Box>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
