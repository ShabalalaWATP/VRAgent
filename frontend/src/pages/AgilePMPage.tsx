import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Typography,
  Paper,
  Chip,
  Button,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Alert,
  AlertTitle,
  Radio,
  RadioGroup,
  FormControlLabel,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  alpha,
  useTheme,
  Fab,
  Drawer,
  IconButton,
  Tooltip,
  useMediaQuery,
  LinearProgress,
  Avatar,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import SpeedIcon from "@mui/icons-material/Speed";
import GroupsIcon from "@mui/icons-material/Groups";
import LoopIcon from "@mui/icons-material/Loop";
import AssignmentIcon from "@mui/icons-material/Assignment";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import TimelineIcon from "@mui/icons-material/Timeline";
import EventRepeatIcon from "@mui/icons-material/EventRepeat";
import PeopleIcon from "@mui/icons-material/People";
import ViewKanbanIcon from "@mui/icons-material/ViewKanban";
import DashboardIcon from "@mui/icons-material/Dashboard";
import FlagIcon from "@mui/icons-material/Flag";
import CancelIcon from "@mui/icons-material/Cancel";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import BuildIcon from "@mui/icons-material/Build";
import BarChartIcon from "@mui/icons-material/BarChart";
import MeetingRoomIcon from "@mui/icons-material/MeetingRoom";
import AutorenewIcon from "@mui/icons-material/Autorenew";
import { Link, useNavigate } from "react-router-dom";

interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  topic: string;
}

const questionBank: QuizQuestion[] = [
  // Topic 1: Agile Fundamentals (1-15)
  { id: 1, question: "What is the primary focus of Agile methodology?", options: ["Extensive documentation", "Following a strict plan", "Delivering value through iterative development", "Minimizing team communication"], correctAnswer: 2, explanation: "Agile prioritizes delivering working software and value to customers through iterative, incremental development.", topic: "Fundamentals" },
  { id: 2, question: "Which is NOT one of the four values in the Agile Manifesto?", options: ["Individuals and interactions over processes and tools", "Working software over comprehensive documentation", "Detailed contracts over customer collaboration", "Responding to change over following a plan"], correctAnswer: 2, explanation: "The Agile Manifesto values customer collaboration over contract negotiation, not detailed contracts.", topic: "Fundamentals" },
  { id: 3, question: "What does 'iterative development' mean in Agile?", options: ["Developing everything at once", "Repeating the same work", "Building in small cycles with continuous improvement", "Writing code without testing"], correctAnswer: 2, explanation: "Iterative development means building software in small cycles, each producing a potentially shippable increment.", topic: "Fundamentals" },
  { id: 4, question: "What is an 'increment' in Agile?", options: ["A bug fix", "The sum of all completed backlog items that add value", "A meeting type", "A type of documentation"], correctAnswer: 1, explanation: "An increment is the sum of all Product Backlog items completed during a Sprint plus all previous increments.", topic: "Fundamentals" },
  { id: 5, question: "Which Agile principle emphasizes sustainable development?", options: ["Move fast and break things", "Work overtime to meet deadlines", "Maintain a constant pace indefinitely", "Finish everything in the first sprint"], correctAnswer: 2, explanation: "Agile promotes sustainable development where teams can maintain a constant pace indefinitely.", topic: "Fundamentals" },
  { id: 6, question: "What is 'empirical process control' in Agile?", options: ["Following a predetermined plan exactly", "Making decisions based on observation and experimentation", "Controlling team members strictly", "Using only proven technologies"], correctAnswer: 1, explanation: "Empirical process control means making decisions based on what is observed and experienced, not predictions.", topic: "Fundamentals" },
  { id: 7, question: "What are the three pillars of empiricism?", options: ["Plan, Do, Check", "Transparency, Inspection, Adaptation", "Speed, Quality, Cost", "Design, Build, Test"], correctAnswer: 1, explanation: "The three pillars of empiricism are Transparency (visibility), Inspection (checking progress), and Adaptation (adjusting).", topic: "Fundamentals" },
  { id: 8, question: "What does 'self-organizing team' mean?", options: ["Team with no manager", "Team decides how to accomplish work", "Team that works alone", "Team without deadlines"], correctAnswer: 1, explanation: "Self-organizing teams choose how best to accomplish their work rather than being directed by others.", topic: "Fundamentals" },
  { id: 9, question: "What is 'timeboxing' in Agile?", options: ["Working within fixed time periods", "Extending deadlines as needed", "Working overtime", "Ignoring time constraints"], correctAnswer: 0, explanation: "Timeboxing means allocating a fixed time period to an activity, after which it ends regardless of completion.", topic: "Fundamentals" },
  { id: 10, question: "Which statement best describes Agile's approach to change?", options: ["Change should be avoided", "Change is welcome, even late in development", "Change requires formal approval process", "Change is only allowed in the first sprint"], correctAnswer: 1, explanation: "Agile welcomes changing requirements, even late in development, to provide competitive advantage.", topic: "Fundamentals" },
  { id: 11, question: "What is 'incremental delivery'?", options: ["Delivering everything at the end", "Delivering small pieces of value regularly", "Delivering only documentation", "Delivering without testing"], correctAnswer: 1, explanation: "Incremental delivery means releasing small, usable portions of the product regularly.", topic: "Fundamentals" },
  { id: 12, question: "What is the main benefit of face-to-face communication in Agile?", options: ["Reduces email usage", "Most efficient and effective method of conveying information", "Eliminates need for documentation", "Faster than typing"], correctAnswer: 1, explanation: "The Agile Manifesto states face-to-face conversation is the most efficient way to convey information.", topic: "Fundamentals" },
  { id: 13, question: "What does 'working software' mean as a measure of progress?", options: ["Software without bugs", "Functional software that delivers value", "Software with complete documentation", "Software ready for production"], correctAnswer: 1, explanation: "Working software is the primary measure of progress - functional code that provides value to users.", topic: "Fundamentals" },
  { id: 14, question: "What is 'technical excellence' in Agile?", options: ["Using the latest technologies", "Continuous attention to good design and quality", "Having expert developers only", "Writing complex code"], correctAnswer: 1, explanation: "Technical excellence means continuous attention to good design, clean code, and technical quality.", topic: "Fundamentals" },
  { id: 15, question: "What is 'simplicity' in Agile context?", options: ["Writing less code", "Maximizing work not done", "Avoiding complex features", "Using simple tools only"], correctAnswer: 1, explanation: "Simplicity is the art of maximizing the amount of work not done - focusing only on what's needed.", topic: "Fundamentals" },
  // Topic 2: Scrum Framework (16-35)
  { id: 16, question: "What are the three Scrum roles?", options: ["Manager, Developer, Tester", "Product Owner, Scrum Master, Development Team", "Architect, Developer, QA", "CEO, Manager, Employee"], correctAnswer: 1, explanation: "Scrum has three roles: Product Owner (what to build), Scrum Master (how to work), Development Team (builders).", topic: "Scrum" },
  { id: 17, question: "What is the Product Owner's primary responsibility?", options: ["Writing code", "Managing the team", "Maximizing the value of the product", "Removing impediments"], correctAnswer: 2, explanation: "The Product Owner is responsible for maximizing the value of the product and managing the Product Backlog.", topic: "Scrum" },
  { id: 18, question: "What is the Scrum Master's primary responsibility?", options: ["Assigning tasks to developers", "Ensuring Scrum is understood and enacted", "Approving the product", "Writing user stories"], correctAnswer: 1, explanation: "The Scrum Master ensures Scrum is understood and enacted, serving the team and organization.", topic: "Scrum" },
  { id: 19, question: "What is a Sprint in Scrum?", options: ["A meeting type", "A time-boxed iteration of one month or less", "A type of user story", "A deployment process"], correctAnswer: 1, explanation: "A Sprint is a time-boxed iteration of one month or less during which a Done increment is created.", topic: "Scrum" },
  { id: 20, question: "What happens during Sprint Planning?", options: ["Team reviews completed work", "Team plans what to build and how", "Stakeholders demo the product", "Team reflects on the sprint"], correctAnswer: 1, explanation: "Sprint Planning defines what can be delivered in the Sprint and how the work will be achieved.", topic: "Scrum" },
  { id: 21, question: "What is the Daily Scrum?", options: ["15-minute daily meeting for the Development Team", "Daily report to management", "Code review meeting", "Planning session"], correctAnswer: 0, explanation: "The Daily Scrum is a 15-minute time-boxed event for the Development Team to synchronize and plan.", topic: "Scrum" },
  { id: 22, question: "What are the three questions traditionally asked in Daily Scrum?", options: ["What did you do? What will you do? Any problems?", "What did you do yesterday? What will you do today? Any impediments?", "Are you on track? Need help? Any risks?", "Hours worked? Tasks completed? Blockers?"], correctAnswer: 1, explanation: "Traditional Daily Scrum: What did I do yesterday? What will I do today? Are there any impediments?", topic: "Scrum" },
  { id: 23, question: "What is the Sprint Review?", options: ["Team performance review", "Inspect the increment and adapt the backlog", "Code review session", "Management approval meeting"], correctAnswer: 1, explanation: "Sprint Review is held to inspect the increment and adapt the Product Backlog if needed.", topic: "Scrum" },
  { id: 24, question: "What is the Sprint Retrospective?", options: ["Review of code quality", "Team inspects itself and creates improvement plan", "Customer feedback session", "Sprint planning for next sprint"], correctAnswer: 1, explanation: "The Sprint Retrospective is for the team to inspect itself and create a plan for improvements.", topic: "Scrum" },
  { id: 25, question: "What is the Product Backlog?", options: ["List of bugs", "Ordered list of everything needed in the product", "Sprint tasks list", "Documentation requirements"], correctAnswer: 1, explanation: "The Product Backlog is an ordered list of everything that is known to be needed in the product.", topic: "Scrum" },
  { id: 26, question: "What is the Sprint Backlog?", options: ["All product requirements", "Sprint Goal plus selected items and plan", "List of impediments", "Team availability"], correctAnswer: 1, explanation: "The Sprint Backlog is the Sprint Goal, selected Product Backlog items, and plan for delivering them.", topic: "Scrum" },
  { id: 27, question: "What is the Definition of Done?", options: ["When product is shipped", "Shared understanding of when work is complete", "Manager's approval", "All tests passing"], correctAnswer: 1, explanation: "Definition of Done is a shared understanding of what it means for work to be complete.", topic: "Scrum" },
  { id: 28, question: "Who can cancel a Sprint?", options: ["Scrum Master", "Development Team", "Product Owner only", "Anyone on the team"], correctAnswer: 2, explanation: "Only the Product Owner has the authority to cancel a Sprint.", topic: "Scrum" },
  { id: 29, question: "What is Sprint Goal?", options: ["Number of story points to complete", "Objective that provides guidance on why increment is valuable", "Team velocity target", "Deadline for the sprint"], correctAnswer: 1, explanation: "The Sprint Goal is an objective that provides guidance on why the team is building the increment.", topic: "Scrum" },
  { id: 30, question: "What is backlog refinement?", options: ["Removing items from backlog", "Adding detail, estimates, and order to backlog items", "Sprint planning", "Retrospective action"], correctAnswer: 1, explanation: "Backlog refinement is adding detail, estimates, and order to Product Backlog items.", topic: "Scrum" },
  { id: 31, question: "What is the recommended size of a Scrum Development Team?", options: ["1-3 people", "3-9 people", "10-15 people", "No limit"], correctAnswer: 1, explanation: "Optimal Development Team size is 3-9 people - small enough to be nimble, large enough to complete work.", topic: "Scrum" },
  { id: 32, question: "How long is the Daily Scrum?", options: ["30 minutes", "1 hour", "15 minutes", "As long as needed"], correctAnswer: 2, explanation: "The Daily Scrum is time-boxed to 15 minutes.", topic: "Scrum" },
  { id: 33, question: "What is velocity in Scrum?", options: ["Speed of typing", "Amount of work completed per Sprint", "Number of meetings", "Lines of code written"], correctAnswer: 1, explanation: "Velocity is the amount of work (often in story points) a team completes in a Sprint.", topic: "Scrum" },
  { id: 34, question: "What is a Scrum of Scrums?", options: ["Multiple sprints", "Scaling technique for multiple teams", "Extra daily standup", "Sprint review with stakeholders"], correctAnswer: 1, explanation: "Scrum of Scrums is a scaling technique where representatives from multiple Scrum teams synchronize.", topic: "Scrum" },
  { id: 35, question: "What should happen if Sprint work cannot be completed?", options: ["Extend the Sprint", "Remove items from Sprint scope", "Add more team members", "Cancel the Sprint"], correctAnswer: 1, explanation: "If work can't be completed, scope is negotiated between PO and Dev Team - Sprint duration is never extended.", topic: "Scrum" },
  // Topic 3: Kanban (36-50)
  { id: 36, question: "What is the core principle of Kanban?", options: ["Fixed iterations", "Visualize workflow and limit WIP", "Daily standups", "Sprint planning"], correctAnswer: 1, explanation: "Kanban's core principles are visualizing workflow and limiting Work in Progress (WIP).", topic: "Kanban" },
  { id: 37, question: "What does WIP stand for in Kanban?", options: ["Work in Production", "Work in Progress", "Weekly Implementation Plan", "Work Item Priority"], correctAnswer: 1, explanation: "WIP stands for Work in Progress - the amount of work currently being worked on.", topic: "Kanban" },
  { id: 38, question: "Why limit WIP in Kanban?", options: ["To reduce team size", "To improve flow and reduce cycle time", "To have more meetings", "To create more documentation"], correctAnswer: 1, explanation: "Limiting WIP improves flow, reduces cycle time, and helps identify bottlenecks.", topic: "Kanban" },
  { id: 39, question: "What is a Kanban board?", options: ["A planning document", "Visual representation of workflow with columns", "A meeting agenda", "A type of chart"], correctAnswer: 1, explanation: "A Kanban board visually represents workflow stages as columns with work items as cards.", topic: "Kanban" },
  { id: 40, question: "What is 'cycle time' in Kanban?", options: ["Sprint duration", "Time from work started to completed", "Time between releases", "Meeting duration"], correctAnswer: 1, explanation: "Cycle time is the time from when work begins on an item to when it's completed.", topic: "Kanban" },
  { id: 41, question: "What is 'lead time' in Kanban?", options: ["Time for a meeting", "Time from request to delivery", "Time for planning", "Time for testing only"], correctAnswer: 1, explanation: "Lead time is the total time from when a request is made to when it's delivered.", topic: "Kanban" },
  { id: 42, question: "What is a 'swimlane' in Kanban?", options: ["A type of meeting", "Horizontal row to categorize work items", "A priority level", "A column type"], correctAnswer: 1, explanation: "Swimlanes are horizontal rows on a Kanban board used to categorize different types of work.", topic: "Kanban" },
  { id: 43, question: "What does 'pull system' mean in Kanban?", options: ["Push work to team members", "Work is pulled when capacity exists", "Pull requests for code", "Management assigns work"], correctAnswer: 1, explanation: "A pull system means new work is only pulled into the system when there's capacity to handle it.", topic: "Kanban" },
  { id: 44, question: "What is the purpose of WIP limits?", options: ["Reduce team size", "Create bottleneck visibility and improve flow", "Limit working hours", "Reduce meetings"], correctAnswer: 1, explanation: "WIP limits expose bottlenecks, improve flow, and prevent overloading the team.", topic: "Kanban" },
  { id: 45, question: "How does Kanban handle priorities?", options: ["Everything equal priority", "Items at top of column are typically higher priority", "No prioritization allowed", "Only Product Owner decides"], correctAnswer: 1, explanation: "In Kanban, items at the top of each column typically have higher priority.", topic: "Kanban" },
  { id: 46, question: "What is a 'blocked' item in Kanban?", options: ["Deleted item", "Work that cannot progress due to impediment", "Completed item", "Low priority item"], correctAnswer: 1, explanation: "A blocked item is work that cannot progress due to some impediment or dependency.", topic: "Kanban" },
  { id: 47, question: "What is 'cumulative flow diagram'?", options: ["Organization chart", "Chart showing work items in each state over time", "Burndown chart", "Velocity chart"], correctAnswer: 1, explanation: "A Cumulative Flow Diagram shows the quantity of work items in each state over time.", topic: "Kanban" },
  { id: 48, question: "Does Kanban have fixed iterations?", options: ["Yes, always 2 weeks", "Yes, always 1 month", "No, it's continuous flow", "Yes, always 1 week"], correctAnswer: 2, explanation: "Kanban uses continuous flow rather than fixed iterations or sprints.", topic: "Kanban" },
  { id: 49, question: "What is 'service level expectation' in Kanban?", options: ["Customer service hours", "Expected time to complete work items of a class", "Meeting schedule", "Team availability"], correctAnswer: 1, explanation: "Service Level Expectation (SLE) is the expected time to complete work items of a particular class.", topic: "Kanban" },
  { id: 50, question: "What is the key difference between Scrum and Kanban?", options: ["Scrum has roles, Kanban doesn't require them", "Scrum uses timeboxes, Kanban uses continuous flow", "Both A and B", "They are the same"], correctAnswer: 2, explanation: "Key differences: Scrum has defined roles and timeboxed sprints; Kanban uses continuous flow without required roles.", topic: "Kanban" },
  // Topic 4: User Stories & Estimation (51-65)
  { id: 51, question: "What is a user story?", options: ["Technical specification", "Short description of a feature from user perspective", "Bug report", "Test case"], correctAnswer: 1, explanation: "A user story is a short, simple description of a feature told from the user's perspective.", topic: "Stories & Estimation" },
  { id: 52, question: "What is the typical user story format?", options: ["Title and description", "As a [user], I want [goal], so that [benefit]", "Given-When-Then", "Requirement ID and text"], correctAnswer: 1, explanation: "The typical format: 'As a [type of user], I want [goal], so that [benefit].'", topic: "Stories & Estimation" },
  { id: 53, question: "What does INVEST stand for in user stories?", options: ["Investment criteria", "Independent, Negotiable, Valuable, Estimable, Small, Testable", "Story sizing method", "Planning technique"], correctAnswer: 1, explanation: "INVEST: Independent, Negotiable, Valuable, Estimable, Small, Testable - criteria for good user stories.", topic: "Stories & Estimation" },
  { id: 54, question: "What are acceptance criteria?", options: ["Management approval", "Conditions that must be met for story to be accepted", "Test coverage percentage", "Code review checklist"], correctAnswer: 1, explanation: "Acceptance criteria define the conditions that must be satisfied for the story to be considered done.", topic: "Stories & Estimation" },
  { id: 55, question: "What are story points?", options: ["Actual hours of work", "Relative measure of effort, complexity, and uncertainty", "Lines of code", "Number of tasks"], correctAnswer: 1, explanation: "Story points are a relative measure of effort, complexity, and uncertainty for completing a user story.", topic: "Stories & Estimation" },
  { id: 56, question: "What is Planning Poker?", options: ["Card game for fun", "Consensus-based estimation technique", "Project planning tool", "Resource allocation method"], correctAnswer: 1, explanation: "Planning Poker is a consensus-based estimation technique where team members use cards to estimate.", topic: "Stories & Estimation" },
  { id: 57, question: "What is the Fibonacci sequence used for in Agile?", options: ["Sorting backlog", "Story point values (1,2,3,5,8,13...)", "Sprint numbering", "Team sizing"], correctAnswer: 1, explanation: "Fibonacci numbers (1,2,3,5,8,13...) are commonly used for story point values to reflect uncertainty in estimates.", topic: "Stories & Estimation" },
  { id: 58, question: "What is an Epic in Agile?", options: ["Completed feature", "Large user story that needs to be broken down", "Sprint goal", "Release milestone"], correctAnswer: 1, explanation: "An Epic is a large user story that is too big to complete in one sprint and needs to be broken into smaller stories.", topic: "Stories & Estimation" },
  { id: 59, question: "What is a Theme in Agile?", options: ["Visual design element", "Collection of related user stories or epics", "Sprint name", "Team motto"], correctAnswer: 1, explanation: "A Theme is a collection of related user stories or epics that share a common goal or topic.", topic: "Stories & Estimation" },
  { id: 60, question: "What is 'spike' in Agile?", options: ["Urgent bug", "Time-boxed research or investigation task", "Sprint cancellation", "Priority increase"], correctAnswer: 1, explanation: "A spike is a time-boxed task for research, investigation, or prototyping to reduce uncertainty.", topic: "Stories & Estimation" },
  { id: 61, question: "What is relative estimation?", options: ["Comparing stories to each other rather than absolute time", "Estimating in hours", "Estimating by manager", "Random estimation"], correctAnswer: 0, explanation: "Relative estimation compares stories to each other (e.g., 'this is twice as complex as that') rather than absolute time.", topic: "Stories & Estimation" },
  { id: 62, question: "What is T-shirt sizing in estimation?", options: ["Ordering team t-shirts", "Using XS, S, M, L, XL for rough estimates", "Sizing user interface", "Team capacity planning"], correctAnswer: 1, explanation: "T-shirt sizing uses XS, S, M, L, XL for quick, rough relative estimates before detailed planning.", topic: "Stories & Estimation" },
  { id: 63, question: "What is 'Definition of Ready'?", options: ["Story is deployed", "Story has enough detail to start work", "Sprint is complete", "Team is available"], correctAnswer: 1, explanation: "Definition of Ready defines criteria a story must meet before it can be brought into a Sprint.", topic: "Stories & Estimation" },
  { id: 64, question: "What is story splitting?", options: ["Deleting stories", "Breaking large stories into smaller, deliverable pieces", "Assigning to multiple people", "Prioritizing stories"], correctAnswer: 1, explanation: "Story splitting breaks large stories into smaller pieces that can be completed in a single sprint.", topic: "Stories & Estimation" },
  { id: 65, question: "What is 'vertical slicing'?", options: ["Splitting by technical layer", "Splitting to deliver end-to-end functionality", "Dividing team vertically", "Sorting backlog"], correctAnswer: 1, explanation: "Vertical slicing means splitting stories to deliver thin slices of end-to-end functionality.", topic: "Stories & Estimation" },
  // Topic 5: Agile Practices & Tools (66-75)
  { id: 66, question: "What is a burndown chart?", options: ["Chart showing completed features", "Chart showing remaining work over time", "Financial chart", "Team capacity chart"], correctAnswer: 1, explanation: "A burndown chart shows the amount of work remaining over time during a sprint or release.", topic: "Practices & Tools" },
  { id: 67, question: "What is a burnup chart?", options: ["Chart showing work completed over time", "Chart of team energy", "Chart of bugs found", "Chart of meetings held"], correctAnswer: 0, explanation: "A burnup chart shows cumulative work completed over time, often with a scope line.", topic: "Practices & Tools" },
  { id: 68, question: "What is pair programming?", options: ["Two teams working together", "Two developers working together on same code", "Duplicate code writing", "Code review process"], correctAnswer: 1, explanation: "Pair programming is two developers working together at one workstation, one typing and one reviewing.", topic: "Practices & Tools" },
  { id: 69, question: "What is Test-Driven Development (TDD)?", options: ["Testing after development", "Writing tests before code", "Only unit testing", "Manual testing first"], correctAnswer: 1, explanation: "TDD means writing failing tests first, then writing code to pass them, then refactoring.", topic: "Practices & Tools" },
  { id: 70, question: "What is Continuous Integration (CI)?", options: ["Frequent team meetings", "Frequently merging code changes with automated testing", "Continuous planning", "Integration testing only"], correctAnswer: 1, explanation: "CI is frequently merging code changes into a shared repository with automated builds and tests.", topic: "Practices & Tools" },
  { id: 71, question: "What is Continuous Delivery (CD)?", options: ["Delivering documents continuously", "Ability to release to production at any time", "Daily deployments required", "Continuous documentation"], correctAnswer: 1, explanation: "Continuous Delivery means code is always in a deployable state and can be released at any time.", topic: "Practices & Tools" },
  { id: 72, question: "What is a 'information radiator'?", options: ["Computer monitor", "Highly visible display of project information", "Email newsletter", "Project report"], correctAnswer: 1, explanation: "An information radiator is a highly visible physical display of key project information for the team and stakeholders.", topic: "Practices & Tools" },
  { id: 73, question: "What is 'mobbing' or 'mob programming'?", options: ["Angry development", "Whole team working on same thing at same time", "Code review meeting", "Sprint planning"], correctAnswer: 1, explanation: "Mob programming is the whole team working on the same thing, at the same time, at the same computer.", topic: "Practices & Tools" },
  { id: 74, question: "What is a 'walking skeleton'?", options: ["Halloween decoration", "Minimal end-to-end implementation proving architecture", "Documentation outline", "Team structure diagram"], correctAnswer: 1, explanation: "A walking skeleton is a minimal end-to-end implementation that proves the architecture works.", topic: "Practices & Tools" },
  { id: 75, question: "What is 'technical debt'?", options: ["Money owed for software", "Implied cost of future rework from quick solutions", "Debt to technical team", "Software license costs"], correctAnswer: 1, explanation: "Technical debt is the implied cost of additional rework caused by choosing quick solutions instead of better approaches.", topic: "Practices & Tools" },
];

const QuizSection: React.FC = () => {
  const [quizState, setQuizState] = useState<"start" | "active" | "results">("start");
  const [questions, setQuestions] = useState<QuizQuestion[]>([]);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<{ [key: number]: number }>({});
  const [showExplanation, setShowExplanation] = useState(false);
  const [score, setScore] = useState(0);

  const QUESTIONS_PER_QUIZ = 10;
  const accent = "#6366f1";
  const accentDark = "#4f46e5";
  const success = "#22c55e";
  const error = "#ef4444";

  const startQuiz = () => {
    const shuffled = [...questionBank].sort(() => Math.random() - 0.5);
    setQuestions(shuffled.slice(0, QUESTIONS_PER_QUIZ));
    setCurrentQuestionIndex(0);
    setSelectedAnswers({});
    setShowExplanation(false);
    setScore(0);
    setQuizState("active");
  };

  const handleAnswerSelect = (answerIndex: number) => {
    if (showExplanation) return;
    setSelectedAnswers(prev => ({
      ...prev,
      [currentQuestionIndex]: answerIndex,
    }));
  };

  const handleSubmitAnswer = () => {
    if (selectedAnswers[currentQuestionIndex] === undefined) return;
    setShowExplanation(true);
    if (selectedAnswers[currentQuestionIndex] === questions[currentQuestionIndex].correctAnswer) {
      setScore(prev => prev + 1);
    }
  };

  const handleNextQuestion = () => {
    if (currentQuestionIndex < questions.length - 1) {
      setCurrentQuestionIndex(prev => prev + 1);
      setShowExplanation(false);
    } else {
      setQuizState("results");
    }
  };

  const currentQuestion = questions[currentQuestionIndex];
  const selectedAnswer = selectedAnswers[currentQuestionIndex];
  const isCorrect = selectedAnswer === currentQuestion?.correctAnswer;

  if (quizState === "start") {
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <QuizIcon sx={{ fontSize: 64, color: accent, mb: 2 }} />
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
          Agile Project Management Quiz
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 520, mx: "auto" }}>
          Test your understanding with {QUESTIONS_PER_QUIZ} randomly selected questions from a 75-question bank. Topics include Agile fundamentals, Scrum, Kanban, user stories, estimation, and Agile practices.
        </Typography>
        <Button
          variant="contained"
          size="large"
          onClick={startQuiz}
          sx={{
            bgcolor: accent,
            "&:hover": { bgcolor: accentDark },
            px: 4,
            py: 1.5,
            fontWeight: 700,
          }}
        >
          Start Quiz ({QUESTIONS_PER_QUIZ} Questions)
        </Button>
      </Box>
    );
  }

  if (quizState === "results") {
    const percentage = Math.round((score / QUESTIONS_PER_QUIZ) * 100);
    const isPassing = percentage >= 70;
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <EmojiEventsIcon sx={{ fontSize: 80, color: isPassing ? success : accent, mb: 2 }} />
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          Quiz Complete
        </Typography>
        <Typography variant="h5" sx={{ fontWeight: 700, color: isPassing ? success : accent, mb: 2 }}>
          {score} / {QUESTIONS_PER_QUIZ} ({percentage}%)
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 420, mx: "auto" }}>
          {isPassing
            ? "Excellent! You have a solid understanding of Agile project management."
            : "Keep learning. Review the sections above and try again."}
        </Typography>
        <Button
          variant="contained"
          size="large"
          onClick={startQuiz}
          startIcon={<RefreshIcon />}
          sx={{
            bgcolor: accent,
            "&:hover": { bgcolor: accentDark },
            px: 4,
            py: 1.5,
            fontWeight: 700,
          }}
        >
          Try Again
        </Button>
      </Box>
    );
  }

  if (!currentQuestion) return null;

  return (
    <Box sx={{ py: 2 }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
          <Chip
            label={`Question ${currentQuestionIndex + 1}/${QUESTIONS_PER_QUIZ}`}
            size="small"
            sx={{ bgcolor: alpha(accent, 0.15), color: accent, fontWeight: 700 }}
          />
          <Chip label={currentQuestion.topic} size="small" variant="outlined" />
        </Box>
        <Chip
          label={`Score: ${score}/${currentQuestionIndex + (showExplanation ? 1 : 0)}`}
          size="small"
          sx={{ bgcolor: alpha(success, 0.15), color: success, fontWeight: 600 }}
        />
      </Box>

      <Box sx={{ mb: 3, bgcolor: alpha(accent, 0.1), borderRadius: 1, height: 8 }}>
        <Box
          sx={{
            width: `${((currentQuestionIndex + (showExplanation ? 1 : 0)) / QUESTIONS_PER_QUIZ) * 100}%`,
            bgcolor: accent,
            borderRadius: 1,
            height: "100%",
            transition: "width 0.3s ease",
          }}
        />
      </Box>

      <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
        {currentQuestion.question}
      </Typography>

      <RadioGroup value={selectedAnswer ?? ""} onChange={(e) => handleAnswerSelect(parseInt(e.target.value, 10))}>
        {currentQuestion.options.map((option, idx) => (
          <Paper
            key={option}
            sx={{
              p: 2,
              mb: 1.5,
              borderRadius: 2,
              cursor: showExplanation ? "default" : "pointer",
              border: `2px solid ${
                showExplanation
                  ? idx === currentQuestion.correctAnswer
                    ? success
                    : idx === selectedAnswer
                    ? error
                    : "transparent"
                  : selectedAnswer === idx
                  ? accent
                  : "transparent"
              }`,
              bgcolor: showExplanation
                ? idx === currentQuestion.correctAnswer
                  ? alpha(success, 0.1)
                  : idx === selectedAnswer
                  ? alpha(error, 0.1)
                  : "transparent"
                : selectedAnswer === idx
                ? alpha(accent, 0.1)
                : "transparent",
              transition: "all 0.2s ease",
              "&:hover": {
                bgcolor: showExplanation ? undefined : alpha(accent, 0.05),
              },
            }}
            onClick={() => handleAnswerSelect(idx)}
          >
            <FormControlLabel
              value={idx}
              control={<Radio sx={{ color: accent, "&.Mui-checked": { color: accent } }} />}
              label={option}
              sx={{ m: 0, width: "100%" }}
              disabled={showExplanation}
            />
          </Paper>
        ))}
      </RadioGroup>

      {!showExplanation ? (
        <Button
          variant="contained"
          fullWidth
          onClick={handleSubmitAnswer}
          disabled={selectedAnswer === undefined}
          sx={{
            mt: 2,
            bgcolor: accent,
            "&:hover": { bgcolor: accentDark },
            "&:disabled": { bgcolor: alpha(accent, 0.3) },
            py: 1.5,
            fontWeight: 700,
          }}
        >
          Submit Answer
        </Button>
      ) : (
        <Box sx={{ mt: 3 }}>
          <Alert severity={isCorrect ? "success" : "error"} sx={{ mb: 2, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>
              {isCorrect ? "Correct" : "Incorrect"}
            </AlertTitle>
            {currentQuestion.explanation}
          </Alert>
          <Button
            variant="contained"
            fullWidth
            onClick={handleNextQuestion}
            sx={{
              bgcolor: accent,
              "&:hover": { bgcolor: accentDark },
              py: 1.5,
              fontWeight: 700,
            }}
          >
            {currentQuestionIndex < questions.length - 1 ? "Next Question" : "See Results"}
          </Button>
        </Box>
      )}
    </Box>
  );
};

export default function AgilePMPage() {
  const navigate = useNavigate();
  const theme = useTheme();

  const pageContext = `Agile Project Management learning page. Covers Agile fundamentals, Agile Manifesto values and principles, Scrum framework (roles, events, artifacts), Kanban methodology, user stories, estimation techniques, velocity, burndown charts, and Agile best practices. Includes a randomized 75-question quiz.`;

  const quickStats = [
    { label: "Modules", value: "15", color: "#6366f1" },
    { label: "Frameworks", value: "3", color: "#22c55e" },
    { label: "Quiz Questions", value: "75", color: "#f59e0b" },
    { label: "Difficulty", value: "Beginner", color: "#ec4899" },
  ];

  const agileValues = [
    { left: "Individuals and interactions", right: "Processes and tools", emphasis: "left" },
    { left: "Working software", right: "Comprehensive documentation", emphasis: "left" },
    { left: "Customer collaboration", right: "Contract negotiation", emphasis: "left" },
    { left: "Responding to change", right: "Following a plan", emphasis: "left" },
  ];

  const agilePrinciples = [
    "Highest priority is customer satisfaction through early and continuous delivery",
    "Welcome changing requirements, even late in development",
    "Deliver working software frequently (weeks rather than months)",
    "Business people and developers must work together daily",
    "Build projects around motivated individuals, give them support and trust",
    "Face-to-face conversation is the most efficient communication method",
    "Working software is the primary measure of progress",
    "Sustainable development - maintain a constant pace indefinitely",
    "Continuous attention to technical excellence and good design",
    "Simplicity - the art of maximizing work not done",
    "Best architectures emerge from self-organizing teams",
    "Regular reflection and adjustment on how to become more effective",
  ];

  const scrumRoles = [
    { role: "Product Owner", responsibilities: ["Manages Product Backlog", "Defines priorities", "Represents stakeholders", "Maximizes product value"], color: "#6366f1" },
    { role: "Scrum Master", responsibilities: ["Facilitates Scrum events", "Removes impediments", "Coaches the team", "Protects the team"], color: "#22c55e" },
    { role: "Development Team", responsibilities: ["Self-organizing", "Cross-functional", "Delivers increments", "Estimates work"], color: "#f59e0b" },
  ];

  const scrumEvents = [
    { event: "Sprint", duration: "1-4 weeks", purpose: "Time-box to create Done increment" },
    { event: "Sprint Planning", duration: "8 hours max (for 1-month Sprint)", purpose: "Define Sprint Goal and Sprint Backlog" },
    { event: "Daily Scrum", duration: "15 minutes", purpose: "Inspect progress, plan next 24 hours" },
    { event: "Sprint Review", duration: "4 hours max", purpose: "Inspect increment, adapt backlog" },
    { event: "Sprint Retrospective", duration: "3 hours max", purpose: "Inspect process, create improvement plan" },
  ];

  const scrumArtifacts = [
    { artifact: "Product Backlog", description: "Ordered list of everything needed in the product", owner: "Product Owner" },
    { artifact: "Sprint Backlog", description: "Sprint Goal + selected items + delivery plan", owner: "Development Team" },
    { artifact: "Increment", description: "Sum of completed items meeting Definition of Done", owner: "Development Team" },
  ];

  const kanbanPrinciples = [
    { principle: "Visualize Workflow", description: "Make work visible using boards and cards" },
    { principle: "Limit WIP", description: "Set limits on work in progress to improve flow" },
    { principle: "Manage Flow", description: "Monitor and optimize how work moves through the system" },
    { principle: "Make Policies Explicit", description: "Clearly define rules for how work is handled" },
    { principle: "Implement Feedback Loops", description: "Regular cadences for inspection and adaptation" },
    { principle: "Improve Collaboratively", description: "Use models and experiments to evolve" },
  ];

  const estimationTechniques = [
    { technique: "Planning Poker", description: "Team consensus using cards with Fibonacci values", when: "Sprint Planning, Refinement" },
    { technique: "T-Shirt Sizing", description: "Quick relative sizing using XS, S, M, L, XL", when: "Early estimation, roadmapping" },
    { technique: "Affinity Estimation", description: "Grouping similar items without discussion", when: "Large backlog estimation" },
    { technique: "Dot Voting", description: "Team votes with dots to indicate relative size", when: "Prioritization, quick estimates" },
  ];

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const moduleNavItems = [
    { id: "introduction", label: "Introduction", icon: "📚" },
    { id: "agile-manifesto", label: "Agile Manifesto", icon: "📜" },
    { id: "agile-principles", label: "12 Principles", icon: "✨" },
    { id: "scrum-overview", label: "Scrum Overview", icon: "🔄" },
    { id: "scrum-roles", label: "Scrum Roles", icon: "👥" },
    { id: "scrum-events", label: "Scrum Events", icon: "📅" },
    { id: "scrum-artifacts", label: "Scrum Artifacts", icon: "📋" },
    { id: "kanban", label: "Kanban", icon: "📊" },
    { id: "user-stories", label: "User Stories", icon: "📝" },
    { id: "estimation", label: "Estimation", icon: "🎯" },
    { id: "metrics", label: "Metrics & Charts", icon: "📈" },
    { id: "practices", label: "Agile Practices", icon: "⚡" },
    { id: "scaling", label: "Scaling Agile", icon: "🚀" },
    { id: "anti-patterns", label: "Anti-Patterns", icon: "⚠️" },
    { id: "quiz-section", label: "Quiz", icon: "❓" },
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
    handleScroll();
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const scrollToTop = () => window.scrollTo({ top: 0, behavior: "smooth" });

  const currentIndex = moduleNavItems.findIndex(item => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / moduleNavItems.length) * 100 : 0;

  const accent = "#6366f1";
  const accentDark = "#4f46e5";

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
        "&::-webkit-scrollbar": { width: 6 },
        "&::-webkit-scrollbar-thumb": { bgcolor: alpha(accent, 0.3), borderRadius: 3 },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: accent, display: "flex", alignItems: "center", gap: 1 }}>
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">Progress</Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>{Math.round(progressPercent)}%</Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha(accent, 0.1),
              "& .MuiLinearProgress-bar": { bgcolor: accent, borderRadius: 3 },
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
                bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                "&:hover": { bgcolor: alpha(accent, 0.08) },
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

  return (
    <LearnPageLayout pageTitle="Agile Project Management" pageContext={pageContext}>
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
            "&:hover": { bgcolor: accentDark },
            boxShadow: `0 4px 20px ${alpha(accent, 0.4)}`,
            display: { xs: "flex", lg: "none" },
          }}
        >
          <ListAltIcon />
        </Fab>
      </Tooltip>

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

      <Drawer
        anchor="right"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        PaperProps={{
          sx: { width: isMobile ? "85%" : 320, bgcolor: theme.palette.background.paper, backgroundImage: "none" },
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
          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">Progress</Typography>
              <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>{Math.round(progressPercent)}%</Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{
                height: 6,
                borderRadius: 3,
                bgcolor: alpha(accent, 0.1),
                "& .MuiLinearProgress-bar": { bgcolor: accent, borderRadius: 3 },
              }}
            />
          </Box>
          <List dense sx={{ mx: -1 }}>
            {moduleNavItems.map((item) => (
              <ListItem
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                sx={{
                  borderRadius: 2,
                  mb: 0.5,
                  cursor: "pointer",
                  bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                  borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                  "&:hover": { bgcolor: alpha(accent, 0.1) },
                  transition: "all 0.2s ease",
                }}
              >
                <ListItemIcon sx={{ minWidth: 32, fontSize: "1.1rem" }}>{item.icon}</ListItemIcon>
                <ListItemText
                  primary={
                    <Typography
                      variant="body2"
                      sx={{
                        fontWeight: activeSection === item.id ? 700 : 500,
                        color: activeSection === item.id ? accent : "text.primary",
                      }}
                    >
                      {item.label}
                    </Typography>
                  }
                />
                {activeSection === item.id && (
                  <Chip label="Current" size="small" sx={{ height: 20, fontSize: "0.65rem", bgcolor: alpha(accent, 0.2), color: accent }} />
                )}
              </ListItem>
            ))}
          </List>
          <Divider sx={{ my: 2 }} />
          <Box sx={{ display: "flex", gap: 1 }}>
            <Button size="small" variant="outlined" onClick={scrollToTop} startIcon={<KeyboardArrowUpIcon />} sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}>
              Top
            </Button>
            <Button size="small" variant="outlined" onClick={() => scrollToSection("quiz-section")} startIcon={<QuizIcon />} sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}>
              Quiz
            </Button>
          </Box>
        </Box>
      </Drawer>

      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, sm: 3 }, py: 4 }}>
        {sidebarNav}

        <Box sx={{ flex: 1, minWidth: 0 }}>
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
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              background: `linear-gradient(135deg, ${alpha("#6366f1", 0.15)} 0%, ${alpha("#8b5cf6", 0.12)} 50%, ${alpha("#a855f7", 0.1)} 100%)`,
              border: `1px solid ${alpha("#6366f1", 0.2)}`,
              position: "relative",
              overflow: "hidden",
            }}
          >
            <Box sx={{ position: "absolute", top: -60, right: -40, width: 220, height: 220, borderRadius: "50%", background: `radial-gradient(circle, ${alpha("#6366f1", 0.15)} 0%, transparent 70%)` }} />
            <Box sx={{ position: "absolute", bottom: -40, left: "30%", width: 180, height: 180, borderRadius: "50%", background: `radial-gradient(circle, ${alpha("#8b5cf6", 0.15)} 0%, transparent 70%)` }} />

            <Box sx={{ position: "relative", zIndex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
                <Box
                  sx={{
                    width: 80,
                    height: 80,
                    borderRadius: 3,
                    background: "linear-gradient(135deg, #6366f1, #a855f7)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    boxShadow: `0 8px 32px ${alpha("#6366f1", 0.35)}`,
                  }}
                >
                  <SpeedIcon sx={{ fontSize: 44, color: "white" }} />
                </Box>
                <Box>
                  <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                    Agile Project Management
                  </Typography>
                  <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                    Deliver value through iterative, collaborative development
                  </Typography>
                </Box>
              </Box>

              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                <Chip label="Agile" sx={{ bgcolor: alpha("#6366f1", 0.15), color: "#6366f1", fontWeight: 600 }} />
                <Chip label="Scrum" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
                <Chip label="Kanban" sx={{ bgcolor: alpha("#f59e0b", 0.15), color: "#f59e0b", fontWeight: 600 }} />
                <Chip label="User Stories" sx={{ bgcolor: alpha("#ec4899", 0.15), color: "#ec4899", fontWeight: 600 }} />
                <Chip label="Sprint Planning" sx={{ bgcolor: alpha("#0ea5e9", 0.15), color: "#0ea5e9", fontWeight: 600 }} />
              </Box>

              <Grid container spacing={2}>
                {quickStats.map((stat) => (
                  <Grid item xs={6} sm={3} key={stat.label}>
                    <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, bgcolor: alpha(stat.color, 0.1), border: `1px solid ${alpha(stat.color, 0.2)}` }}>
                      <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>{stat.value}</Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>{stat.label}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Box>
          </Paper>

          {/* Introduction */}
          <Paper id="introduction" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Avatar sx={{ bgcolor: alpha(accent, 0.15), color: accent }}><SpeedIcon /></Avatar>
              What is Agile?
            </Typography>
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              <strong>Agile</strong> is a mindset and set of values for software development that emphasizes iterative delivery, collaboration, and adaptability. Unlike traditional "waterfall" approaches that try to plan everything upfront, Agile embraces change and focuses on delivering working software in small increments.
            </Typography>
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              The Agile approach emerged from the frustration with heavyweight, documentation-driven processes that often delivered software that didn't meet user needs. In 2001, seventeen software developers met in Utah and created the <strong>Agile Manifesto</strong>, which defined the core values and principles that guide Agile practices today.
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Agile is not a specific methodology but an umbrella term covering various frameworks like <strong>Scrum</strong>, <strong>Kanban</strong>, <strong>XP (Extreme Programming)</strong>, and others. What they share is a commitment to iterative development, customer collaboration, and continuous improvement.
            </Typography>
            <Alert severity="info" sx={{ borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Key Insight</AlertTitle>
              Agile is a mindset, not just a process. The goal is not to follow rituals but to deliver value to customers faster and respond to change effectively.
            </Alert>
          </Paper>

          {/* Agile Manifesto */}
          <Paper id="agile-manifesto" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <AssignmentIcon sx={{ color: accent }} />
              The Agile Manifesto
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Agile Manifesto defines four core values. While there is value in the items on the right, Agile values the items on the left more.
            </Typography>
            <Grid container spacing={2}>
              {agileValues.map((value, idx) => (
                <Grid item xs={12} key={idx}>
                  <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accent, 0.03) }}>
                    <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 2, flexWrap: "wrap" }}>
                      <Typography variant="h6" sx={{ fontWeight: 700, color: accent }}>{value.left}</Typography>
                      <Typography variant="body2" color="text.secondary">over</Typography>
                      <Typography variant="h6" sx={{ fontWeight: 500, color: "text.secondary" }}>{value.right}</Typography>
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* 12 Principles */}
          <Paper id="agile-principles" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <TipsAndUpdatesIcon sx={{ color: accent }} />
              The 12 Agile Principles
            </Typography>
            <Grid container spacing={2}>
              {agilePrinciples.map((principle, idx) => (
                <Grid item xs={12} md={6} key={idx}>
                  <Paper sx={{ p: 2, borderRadius: 2, height: "100%", bgcolor: alpha(accent, 0.03) }}>
                    <Box sx={{ display: "flex", gap: 2, alignItems: "flex-start" }}>
                      <Avatar sx={{ width: 28, height: 28, bgcolor: accent, fontSize: 14, fontWeight: 700 }}>{idx + 1}</Avatar>
                      <Typography variant="body2">{principle}</Typography>
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Scrum Overview */}
          <Paper id="scrum-overview" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <LoopIcon sx={{ color: accent }} />
              Scrum Overview
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              <strong>Scrum</strong> is the most popular Agile framework. It's a lightweight process framework for developing complex products. Scrum uses fixed-length iterations called <strong>Sprints</strong> (typically 2-4 weeks) to deliver potentially shippable increments.
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#6366f1", 0.08) }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#6366f1" }}>3 Roles</Typography>
                  <List dense>
                    {["Product Owner", "Scrum Master", "Development Team"].map((role) => (
                      <ListItem key={role} sx={{ px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ color: "#6366f1", fontSize: 20 }} /></ListItemIcon>
                        <ListItemText primary={role} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#22c55e", 0.08) }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>5 Events</Typography>
                  <List dense>
                    {["Sprint", "Sprint Planning", "Daily Scrum", "Sprint Review", "Sprint Retrospective"].map((event) => (
                      <ListItem key={event} sx={{ px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ color: "#22c55e", fontSize: 20 }} /></ListItemIcon>
                        <ListItemText primary={event} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#f59e0b", 0.08) }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>3 Artifacts</Typography>
                  <List dense>
                    {["Product Backlog", "Sprint Backlog", "Increment"].map((artifact) => (
                      <ListItem key={artifact} sx={{ px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ color: "#f59e0b", fontSize: 20 }} /></ListItemIcon>
                        <ListItemText primary={artifact} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            </Grid>
          </Paper>

          {/* Scrum Roles */}
          <Paper id="scrum-roles" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <GroupsIcon sx={{ color: accent }} />
              Scrum Roles
            </Typography>
            <Grid container spacing={3}>
              {scrumRoles.map((role) => (
                <Grid item xs={12} md={4} key={role.role}>
                  <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha(role.color, 0.08), border: `1px solid ${alpha(role.color, 0.2)}` }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                      <Avatar sx={{ bgcolor: role.color }}><PeopleIcon /></Avatar>
                      <Typography variant="h6" sx={{ fontWeight: 700 }}>{role.role}</Typography>
                    </Box>
                    <List dense>
                      {role.responsibilities.map((resp) => (
                        <ListItem key={resp} sx={{ px: 0 }}>
                          <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ color: role.color, fontSize: 20 }} /></ListItemIcon>
                          <ListItemText primary={resp} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Scrum Events */}
          <Paper id="scrum-events" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <EventRepeatIcon sx={{ color: accent }} />
              Scrum Events
            </Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
              <Table>
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha(accent, 0.08) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Event</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Duration</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {scrumEvents.map((event) => (
                    <TableRow key={event.event}>
                      <TableCell sx={{ fontWeight: 600 }}>{event.event}</TableCell>
                      <TableCell>{event.duration}</TableCell>
                      <TableCell>{event.purpose}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          {/* Scrum Artifacts */}
          <Paper id="scrum-artifacts" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <AccountTreeIcon sx={{ color: accent }} />
              Scrum Artifacts
            </Typography>
            <Grid container spacing={2}>
              {scrumArtifacts.map((artifact) => (
                <Grid item xs={12} md={4} key={artifact.artifact}>
                  <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: accent }}>{artifact.artifact}</Typography>
                    <Typography variant="body2" sx={{ mb: 1 }}>{artifact.description}</Typography>
                    <Chip label={`Owner: ${artifact.owner}`} size="small" variant="outlined" />
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Kanban */}
          <Paper id="kanban" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <ViewKanbanIcon sx={{ color: accent }} />
              Kanban
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              <strong>Kanban</strong> is a visual workflow management method. Unlike Scrum, Kanban doesn't use fixed iterations - work flows continuously through the system. The key focus is on visualizing work and limiting work-in-progress to improve flow and identify bottlenecks.
            </Typography>
            <Grid container spacing={2}>
              {kanbanPrinciples.map((item) => (
                <Grid item xs={12} md={6} key={item.principle}>
                  <Paper sx={{ p: 2.5, borderRadius: 2, height: "100%", bgcolor: alpha(accent, 0.05) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: accent, mb: 0.5 }}>{item.principle}</Typography>
                    <Typography variant="body2" color="text.secondary">{item.description}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* User Stories */}
          <Paper id="user-stories" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <FlagIcon sx={{ color: accent }} />
              User Stories
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              User stories are short, simple descriptions of a feature told from the perspective of the user. They follow a specific format and help teams focus on delivering user value.
            </Typography>
            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// User Story Format</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>As a</span> [type of user],{"\n"}
                <span style={{ color: "#ff79c6" }}>I want</span> [some goal or action],{"\n"}
                <span style={{ color: "#ff79c6" }}>So that</span> [some benefit or reason].{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Example</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>As a</span> <span style={{ color: "#f1fa8c" }}>registered user</span>,{"\n"}
                <span style={{ color: "#ff79c6" }}>I want</span> <span style={{ color: "#f1fa8c" }}>to reset my password via email</span>,{"\n"}
                <span style={{ color: "#ff79c6" }}>So that</span> <span style={{ color: "#f1fa8c" }}>I can regain access if I forget it</span>.
              </Typography>
            </Paper>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>INVEST Criteria</Typography>
            <Grid container spacing={2}>
              {[
                { letter: "I", word: "Independent", desc: "Can be developed in any order" },
                { letter: "N", word: "Negotiable", desc: "Details can be discussed" },
                { letter: "V", word: "Valuable", desc: "Delivers user value" },
                { letter: "E", word: "Estimable", desc: "Can be sized" },
                { letter: "S", word: "Small", desc: "Fits in one sprint" },
                { letter: "T", word: "Testable", desc: "Has clear acceptance criteria" },
              ].map((item) => (
                <Grid item xs={6} md={4} key={item.letter}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                      <Avatar sx={{ bgcolor: accent, width: 32, height: 32, fontSize: 16 }}>{item.letter}</Avatar>
                      <Box>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.word}</Typography>
                        <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                      </Box>
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Estimation */}
          <Paper id="estimation" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <BarChartIcon sx={{ color: accent }} />
              Estimation Techniques
            </Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
              <Table>
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha(accent, 0.08) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Technique</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>When to Use</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {estimationTechniques.map((tech) => (
                    <TableRow key={tech.technique}>
                      <TableCell sx={{ fontWeight: 600 }}>{tech.technique}</TableCell>
                      <TableCell>{tech.description}</TableCell>
                      <TableCell>{tech.when}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>

          {/* Metrics & Charts */}
          <Paper id="metrics" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <TrendingUpIcon sx={{ color: accent }} />
              Metrics & Charts
            </Typography>
            <Grid container spacing={3}>
              {[
                { name: "Velocity", desc: "Amount of work completed per sprint, used for planning" },
                { name: "Burndown Chart", desc: "Shows remaining work over time in a sprint" },
                { name: "Burnup Chart", desc: "Shows completed work and scope over time" },
                { name: "Cumulative Flow Diagram", desc: "Shows work items in each state over time (Kanban)" },
                { name: "Cycle Time", desc: "Time from work started to completed" },
                { name: "Lead Time", desc: "Time from request to delivery" },
              ].map((metric) => (
                <Grid item xs={12} md={6} key={metric.name}>
                  <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: accent }}>{metric.name}</Typography>
                    <Typography variant="body2" color="text.secondary">{metric.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Agile Practices */}
          <Paper id="practices" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <BuildIcon sx={{ color: accent }} />
              Agile Practices
            </Typography>
            <Grid container spacing={2}>
              {[
                "Continuous Integration / Continuous Delivery",
                "Test-Driven Development (TDD)",
                "Pair Programming / Mob Programming",
                "Code Reviews and Pull Requests",
                "Refactoring and Technical Debt Management",
                "Definition of Done and Definition of Ready",
                "Information Radiators (visible boards)",
                "Walking Skeletons and Spikes",
              ].map((practice) => (
                <Grid item xs={12} md={6} key={practice}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05) }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <CheckCircleIcon sx={{ color: "#22c55e" }} />
                      <Typography variant="body2" sx={{ fontWeight: 500 }}>{practice}</Typography>
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Scaling Agile */}
          <Paper id="scaling" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <RocketLaunchIcon sx={{ color: accent }} />
              Scaling Agile
            </Typography>
            <Typography variant="body1" sx={{ mb: 3 }}>
              When organizations grow, they often need frameworks to scale Agile across multiple teams.
            </Typography>
            <Grid container spacing={2}>
              {[
                { name: "SAFe", full: "Scaled Agile Framework", desc: "Comprehensive framework for large enterprises" },
                { name: "LeSS", full: "Large-Scale Scrum", desc: "Minimal framework extending Scrum to multiple teams" },
                { name: "Nexus", full: "Scrum.org's scaling framework", desc: "Extension of Scrum for 3-9 teams" },
                { name: "Scrum of Scrums", full: "Coordination meeting", desc: "Representatives from each team synchronize" },
              ].map((fw) => (
                <Grid item xs={12} md={6} key={fw.name}>
                  <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: accent }}>{fw.name}</Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>{fw.full}</Typography>
                    <Typography variant="body2" sx={{ mt: 0.5 }}>{fw.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Anti-Patterns */}
          <Paper id="anti-patterns" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <CancelIcon sx={{ color: "#ef4444" }} />
              Common Anti-Patterns
            </Typography>
            <Grid container spacing={2}>
              {[
                "Treating Daily Scrum as a status report to managers",
                "Extending sprints to finish incomplete work",
                "Product Owner writing detailed specifications",
                "Scrum Master assigning tasks to developers",
                "Skipping retrospectives when under pressure",
                "Not having a clear Definition of Done",
                "Ignoring technical debt indefinitely",
                "Cherry-picking practices without embracing the mindset",
              ].map((pattern) => (
                <Grid item xs={12} md={6} key={pattern}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ef4444", 0.05) }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <CancelIcon sx={{ color: "#ef4444" }} />
                      <Typography variant="body2" sx={{ fontWeight: 500 }}>{pattern}</Typography>
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Quiz Section */}
          <Paper id="quiz-section" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <QuizIcon sx={{ color: accent }} />
              Knowledge Check
            </Typography>
            <QuizSection />
          </Paper>

          <Divider sx={{ my: 4 }} />

          <Box sx={{ display: "flex", justifyContent: "center" }}>
            <Button
              variant="contained"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate("/learn")}
              sx={{ bgcolor: accent, "&:hover": { bgcolor: accentDark }, px: 4, py: 1.5, fontWeight: 700 }}
            >
              Back to Learning Hub
            </Button>
          </Box>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
