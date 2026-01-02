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
  { id: "scrum-theory", label: "Scrum Theory" },
  { id: "scrum-values", label: "Scrum Values" },
  { id: "scrum-team", label: "The Scrum Team" },
  { id: "product-owner", label: "Product Owner" },
  { id: "scrum-master", label: "Scrum Master" },
  { id: "developers", label: "Developers" },
  { id: "scrum-events", label: "Scrum Events" },
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
              give direction to the Scrum Team with regard to their work, actions, and behavior.
            </Typography>
            <Grid container spacing={2}>
              {[
                {
                  value: "Commitment",
                  description: "The Scrum Team commits to achieving its goals and supporting each other.",
                  color: "#dc2626",
                },
                {
                  value: "Focus",
                  description: "Primary focus is on the work of the Sprint to make the best possible progress toward goals.",
                  color: "#f59e0b",
                },
                {
                  value: "Openness",
                  description: "The Scrum Team and stakeholders are open about the work and challenges.",
                  color: "#22c55e",
                },
                {
                  value: "Respect",
                  description: "Scrum Team members respect each other as capable, independent people.",
                  color: "#3b82f6",
                },
                {
                  value: "Courage",
                  description: "Members have courage to do the right thing and work on tough problems.",
                  color: "#8b5cf6",
                },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.value}>
                  <Card sx={{ height: "100%", borderTop: `4px solid ${item.color}` }}>
                    <CardContent>
                      <Typography variant="h6" sx={{ fontWeight: 700, color: item.color, mb: 1 }}>
                        {item.value}
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
              Scrum Team. The Product Owner is one person, not a committee.
            </Typography>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              Accountabilities:
            </Typography>
            <List>
              {[
                "Developing and explicitly communicating the Product Goal",
                "Creating and clearly communicating Product Backlog items",
                "Ordering Product Backlog items",
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
            <Box sx={{ bgcolor: alpha("#dc2626", 0.05), p: 2, borderRadius: 2, mt: 2 }}>
              <Typography variant="body2">
                <strong>Important:</strong> For Product Owners to succeed, the entire organization must respect their
                decisions. These decisions are visible in the Product Backlog content and ordering.
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
              understand Scrum theory and practice, both within the Scrum Team and the organization.
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={4}>
                <Card sx={{ height: "100%", bgcolor: alpha("#22c55e", 0.05) }}>
                  <CardContent>
                    <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#22c55e", mb: 1 }}>
                      Serves the Team
                    </Typography>
                    <List dense>
                      {[
                        "Coaching on self-management",
                        "Helping focus on high-value Increments",
                        "Removing impediments",
                        "Ensuring effective events",
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
                        "Finding techniques for Product Goal",
                        "Helping understand Product Backlog",
                        "Facilitating stakeholder collaboration",
                        "Establishing empirical planning",
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
                        "Leading Scrum adoption",
                        "Planning implementations",
                        "Removing barriers",
                        "Helping understand empiricism",
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
              collaborates on this plan. Time-boxed to 8 hours for a one-month Sprint, shorter for shorter Sprints.
            </Typography>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              Three Topics Addressed:
            </Typography>
            <Accordion defaultExpanded sx={{ mb: 1 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontWeight: 600 }}>Topic 1: Why is this Sprint valuable?</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2">
                  The Product Owner proposes how the product could increase value. The whole Scrum Team collaborates
                  to define a <strong>Sprint Goal</strong> that communicates why the Sprint is valuable to
                  stakeholders.
                </Typography>
              </AccordionDetails>
            </Accordion>
            <Accordion sx={{ mb: 1 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontWeight: 600 }}>Topic 2: What can be Done this Sprint?</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2">
                  Developers select Product Backlog items to include in the current Sprint. The Scrum Team may refine
                  items during this process. Selecting how much can be completed is solely up to the Developers.
                </Typography>
              </AccordionDetails>
            </Accordion>
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontWeight: 600 }}>Topic 3: How will the chosen work get done?</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2">
                  Developers plan the work necessary to create an Increment that meets the Definition of Done.
                  This is often done by decomposing PBIs into smaller work items of one day or less.
                </Typography>
              </AccordionDetails>
            </Accordion>
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
              adapt the Sprint Backlog as necessary. It is held at the same time and place every working day.
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Box sx={{ bgcolor: alpha("#22c55e", 0.05), p: 2, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#22c55e", mb: 1 }}>
                    Best Practices
                  </Typography>
                  <List dense>
                    {[
                      "Focus on progress toward Sprint Goal",
                      "Developers choose structure/techniques",
                      "Create focus and improve self-management",
                      "Identify impediments quickly",
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
                <Box sx={{ bgcolor: alpha("#dc2626", 0.05), p: 2, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, color: "#dc2626", mb: 1 }}>
                    Anti-Patterns to Avoid
                  </Typography>
                  <List dense>
                    {[
                      "Status reporting to Scrum Master",
                      "Detailed problem-solving discussions",
                      "Going over 15 minutes",
                      "Missing the Daily Scrum",
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
              Team presents results to key stakeholders and progress toward the Product Goal is discussed.
            </Typography>
            <Box sx={{ bgcolor: alpha("#3b82f6", 0.05), p: 3, borderRadius: 2, mb: 3 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2 }}>
                Key Points:
              </Typography>
              <List dense>
                {[
                  "Time-boxed to 4 hours for a one-month Sprint",
                  "Attendees collaborate on what to do next",
                  "Product Backlog may be adjusted based on feedback",
                  "This is a working session, not a presentation",
                  "Not a gate or release approval meeting",
                ].map((item, i) => (
                  <ListItem key={i}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <ArrowRightIcon sx={{ color: "#3b82f6" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
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
              and create a plan for improvements to be enacted during the next Sprint.
            </Typography>
            <Typography variant="h6" sx={{ fontWeight: 600, mb: 2 }}>
              Focus Areas:
            </Typography>
            <Grid container spacing={2}>
              {[
                { area: "Individuals", icon: "👤", description: "How did team members interact and collaborate?" },
                { area: "Interactions", icon: "🤝", description: "How effective was communication?" },
                { area: "Processes", icon: "⚙️", description: "What processes worked well or need improvement?" },
                { area: "Tools", icon: "🔧", description: "Are the tools enabling or hindering the team?" },
                { area: "Definition of Done", icon: "✅", description: "Is the DoD appropriate for the product?" },
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
            <Box sx={{ bgcolor: alpha("#8b5cf6", 0.05), p: 2, borderRadius: 2, mt: 3 }}>
              <Typography variant="body2">
                <strong>Output:</strong> The team identifies the most impactful improvements to address as soon as
                possible. The most important may even be added to the Sprint Backlog for the next Sprint.
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
