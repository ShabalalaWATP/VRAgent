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

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide: Why Agile Exists
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>The Problem with Traditional Development:</strong><br/>
                Imagine you're building a house. You hire an architect who spends 6 months creating detailed blueprints.
                Then construction takes 12 months. Finally, you move in and realize: "I wanted the kitchen on the other side!"
                But it's too late—the house is built.<br/><br/>

                <strong>This happened constantly in software:</strong><br/>
                • 18-month projects delivered software nobody wanted anymore<br/>
                • Requirements gathered in month 1 were obsolete by month 12<br/>
                • Customers saw nothing until the very end—too late to change course<br/>
                • Teams delivered what was specified, not what was actually needed<br/><br/>

                <strong>Agile's Solution:</strong><br/>
                Instead of building the whole house, build one room at a time. After each room, check with the
                homeowner: "Is this what you wanted? What should we adjust?" This way, even if requirements change,
                you've only invested in one room, not the whole house.
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                Waterfall vs. Agile: A Side-by-Side Comparison
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Box sx={{ bgcolor: alpha("#dc2626", 0.08), p: 2, borderRadius: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "#dc2626", mb: 1 }}>
                      Traditional Waterfall
                    </Typography>
                    <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
                      • Plan everything upfront (months)<br/>
                      • Build everything at once<br/>
                      • Test at the end<br/>
                      • Deliver once, at the end<br/>
                      • Change is expensive and discouraged<br/>
                      • Customer sees product only at delivery
                    </Typography>
                  </Box>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 2, borderRadius: 2 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "#22c55e", mb: 1 }}>
                      Agile Approach
                    </Typography>
                    <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
                      • Plan just enough for the next iteration<br/>
                      • Build in small increments<br/>
                      • Test continuously<br/>
                      • Deliver frequently (every 1-4 weeks)<br/>
                      • Change is welcomed and expected<br/>
                      • Customer sees working software regularly
                    </Typography>
                  </Box>
                </Grid>
              </Grid>
            </Box>

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#f59e0b" }}>
                When Agile Works Best (And When It Doesn't)
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>Agile Excels When:</Typography>
                  <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
                    • Requirements are uncertain or evolving<br/>
                    • Fast feedback is valuable<br/>
                    • Innovation and experimentation matter<br/>
                    • Customer collaboration is possible<br/>
                    • Teams need autonomy to solve problems
                  </Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>Consider Alternatives When:</Typography>
                  <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
                    • Requirements are truly fixed and well-understood<br/>
                    • Regulatory compliance requires upfront documentation<br/>
                    • Customer can't or won't participate regularly<br/>
                    • The project is very short (&lt; 1 month)<br/>
                    • Physical manufacturing with high change costs
                  </Typography>
                </Grid>
              </Grid>
            </Box>

            <Alert severity="info" sx={{ borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Key Insight</AlertTitle>
              Agile is a mindset, not just a process. The goal is not to follow rituals but to deliver value to customers faster and respond to change effectively. If you're doing Scrum ceremonies but not delivering working software every Sprint, you're missing the point.
            </Alert>
          </Paper>

          {/* Agile Manifesto */}
          <Paper id="agile-manifesto" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <AssignmentIcon sx={{ color: accent }} />
              The Agile Manifesto
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Agile Manifesto defines four core values. <strong>Important:</strong> This isn't saying the items on the right
              are bad—they have value. But when forced to choose, Agile prioritizes the items on the left.
            </Typography>
            <Grid container spacing={2} sx={{ mb: 4 }}>
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

            <Box sx={{ bgcolor: alpha(accent, 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha(accent, 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: accent }}>
                Understanding Each Value (With Real Examples)
              </Typography>

              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, mt: 2 }}>
                1. Individuals and Interactions over Processes and Tools
              </Typography>
              <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8 }}>
                <strong>What it means:</strong> A great team with mediocre tools will outperform a mediocre team with
                great tools. Focus on hiring well, communicating openly, and building trust.<br/>
                <strong>Example:</strong> Instead of mandating that all communication go through Jira tickets, allow
                developers to walk over and have a 5-minute conversation when needed. The ticket can be updated afterward.
              </Typography>

              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
                2. Working Software over Comprehensive Documentation
              </Typography>
              <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8 }}>
                <strong>What it means:</strong> Documentation is valuable, but running code that users can actually use
                is more valuable. Write enough documentation to be useful, not more.<br/>
                <strong>Example:</strong> Instead of spending 3 weeks writing a 100-page specification, spend 2 weeks
                building a working prototype. Show it to users and let their feedback guide the detailed requirements.
              </Typography>

              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
                3. Customer Collaboration over Contract Negotiation
              </Typography>
              <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8 }}>
                <strong>What it means:</strong> Treat customers as partners in building the product, not adversaries
                bound by contract terms. Success is measured by customer outcomes, not contract compliance.<br/>
                <strong>Example:</strong> When a customer says "this feature isn't quite what we needed," respond with
                "let's figure out what you actually need" rather than "but that's what the contract specified."
              </Typography>

              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
                4. Responding to Change over Following a Plan
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
                <strong>What it means:</strong> Plans are useful starting points, but the world changes. The ability
                to adapt is more valuable than rigid adherence to an outdated plan.<br/>
                <strong>Example:</strong> Mid-project, a competitor launches a similar feature. Instead of ignoring
                this and following the original plan, the team pivots to differentiate—delivering more value.
              </Typography>
            </Box>

            <Alert severity="warning" sx={{ borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Common Misunderstanding</AlertTitle>
              "Agile means no documentation" is FALSE. The manifesto says working software is <em>more valuable</em>,
              not that documentation has <em>no value</em>. Write documentation that helps—just don't write it for its
              own sake or because "that's the process."
            </Alert>
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
              <strong>Kanban</strong> is a visual workflow management method. Unlike Scrum, Kanban doesn't use fixed iterations—work
              flows continuously through the system. The key focus is on visualizing work and limiting work-in-progress to improve
              flow and identify bottlenecks.
            </Typography>

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#f59e0b" }}>
                Beginner's Guide: Understanding the Kanban Board
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Imagine a Whiteboard with Columns:</strong><br/>
                A typical Kanban board has columns representing workflow stages. Cards (sticky notes or digital) represent
                work items that move from left to right as work progresses.<br/><br/>

                <strong>Simple Example Board:</strong><br/>
                | <strong>To Do</strong> | <strong>In Progress</strong> | <strong>Review</strong> | <strong>Done</strong> |<br/>
                | Task A | Task C | Task E | Task F |<br/>
                | Task B | Task D | | Task G |<br/><br/>

                <strong>How It Works:</strong><br/>
                1. New work enters the "To Do" column<br/>
                2. When someone starts work, they pull a card to "In Progress"<br/>
                3. When coding is complete, it moves to "Review"<br/>
                4. After review/testing, it moves to "Done"<br/>
                5. Each column has a <strong>WIP limit</strong>—max cards allowed at once
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#dc2626", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#dc2626" }}>
                Why WIP Limits Matter (The Highway Analogy)
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                Think of a highway. When there are few cars, traffic flows smoothly at 70 mph. Add more cars and
                everyone slows to 50 mph. Add even more and you get a traffic jam—nobody moves.<br/><br/>

                <strong>The same happens with work:</strong><br/>
                • <strong>Too much WIP:</strong> Context-switching kills productivity. Starting 10 tasks means finishing none.<br/>
                • <strong>Optimal WIP:</strong> Starting fewer tasks means finishing them faster. "Stop starting, start finishing."<br/>
                • <strong>Example:</strong> If your "In Progress" WIP limit is 3, nobody can start a 4th task until one finishes.
                This forces the team to collaborate to finish work rather than starting new work.<br/><br/>

                <strong>Little's Law:</strong> Lead Time = WIP / Throughput<br/>
                Translation: The more work in progress, the longer everything takes to complete.
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>The Six Kanban Practices</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {kanbanPrinciples.map((item) => (
                <Grid item xs={12} md={6} key={item.principle}>
                  <Paper sx={{ p: 2.5, borderRadius: 2, height: "100%", bgcolor: alpha(accent, 0.05) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: accent, mb: 0.5 }}>{item.principle}</Typography>
                    <Typography variant="body2" color="text.secondary">{item.description}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                Scrum vs. Kanban: When to Use Each
              </Typography>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>Choose Scrum When:</Typography>
                  <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
                    • Teams are new to Agile (more structure helps)<br/>
                    • Work is project-based with clear goals<br/>
                    • You need predictable delivery cadence<br/>
                    • Stakeholders want regular demos
                  </Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>Choose Kanban When:</Typography>
                  <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
                    • Work is interrupt-driven (support, ops)<br/>
                    • Priorities change frequently<br/>
                    • You want to improve existing process gradually<br/>
                    • Fixed iterations feel too rigid
                  </Typography>
                </Grid>
              </Grid>
            </Box>
          </Paper>

          {/* User Stories */}
          <Paper id="user-stories" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <FlagIcon sx={{ color: accent }} />
              User Stories
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              User stories are short, simple descriptions of a feature told from the perspective of the user. They follow
              a specific format and help teams focus on delivering user value rather than technical specifications.
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

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Writing Great User Stories: A Beginner's Guide
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Why the Format Matters:</strong><br/>
                The "As a... I want... So that..." format forces you to think about:<br/>
                • <strong>WHO</strong> benefits from this feature (the persona)<br/>
                • <strong>WHAT</strong> they want to do (the functionality)<br/>
                • <strong>WHY</strong> they want it (the value/benefit)<br/><br/>

                <strong>Good vs. Bad User Stories:</strong><br/><br/>

                <strong style={{ color: "#dc2626" }}>Bad:</strong> "Implement login functionality"<br/>
                <em>Problem: No user, no benefit, sounds like a task</em><br/><br/>

                <strong style={{ color: "#22c55e" }}>Good:</strong> "As a returning customer, I want to log in with my email
                and password so that I can access my order history and saved preferences."<br/>
                <em>Clear user, clear action, clear benefit</em><br/><br/>

                <strong style={{ color: "#dc2626" }}>Bad:</strong> "Build admin dashboard"<br/>
                <em>Problem: Too vague, no specific value</em><br/><br/>

                <strong style={{ color: "#22c55e" }}>Good:</strong> "As a store manager, I want to see today's sales summary
                on my dashboard so that I can quickly assess daily performance without running reports."
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                Acceptance Criteria: How You Know When It's Done
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                Every user story needs <strong>acceptance criteria</strong>—specific conditions that must be met for the
                story to be considered complete.<br/><br/>

                <strong>Example User Story:</strong><br/>
                "As a customer, I want to filter products by price range so that I can find items within my budget."<br/><br/>

                <strong>Acceptance Criteria:</strong><br/>
                • User can set minimum and maximum price values<br/>
                • Filter updates product list immediately (no page reload)<br/>
                • Product count shows number of matching items<br/>
                • "Clear filters" button resets to show all products<br/>
                • Filter persists when navigating back to the product page<br/>
                • Works on mobile devices (responsive design)<br/><br/>

                <strong>Why this matters:</strong> Without acceptance criteria, "done" is subjective. With them,
                everyone agrees on what complete looks like.
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>INVEST Criteria for Good User Stories</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { letter: "I", word: "Independent", desc: "Can be developed in any order, not dependent on other stories" },
                { letter: "N", word: "Negotiable", desc: "Details can be discussed and refined with the team" },
                { letter: "V", word: "Valuable", desc: "Delivers clear value to users or business" },
                { letter: "E", word: "Estimable", desc: "Team can estimate the effort required" },
                { letter: "S", word: "Small", desc: "Can be completed in one sprint (ideally a few days)" },
                { letter: "T", word: "Testable", desc: "Has clear acceptance criteria that can be verified" },
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

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#f59e0b" }}>
                Story Hierarchy: Epics, Stories, and Tasks
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Epic:</strong> A large body of work that takes multiple sprints. Too big to estimate accurately.<br/>
                <em>Example: "User Account Management"</em><br/><br/>

                <strong>User Story:</strong> A single piece of functionality that delivers value. Fits in one sprint.<br/>
                <em>Example: "As a user, I want to update my email address..."</em><br/><br/>

                <strong>Task:</strong> Technical work needed to complete a story. Assigned to individuals.<br/>
                <em>Example: "Add email validation", "Update database schema", "Write unit tests"</em><br/><br/>

                <strong>The Flow:</strong> Epics are broken into Stories during backlog refinement.
                Stories are broken into Tasks during Sprint Planning.
              </Typography>
            </Box>
          </Paper>

          {/* Estimation */}
          <Paper id="estimation" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <BarChartIcon sx={{ color: accent }} />
              Estimation Techniques
            </Typography>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide: Why We Use Story Points (Not Hours)
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>The Problem with Hours:</strong><br/>
                If you ask "how many hours will this take?", different developers give wildly different answers.
                A senior might say "4 hours" while a junior says "16 hours." Who's right? Both are—for themselves.<br/><br/>

                <strong>Story Points Solve This:</strong><br/>
                Story points measure <strong>relative complexity</strong>, not absolute time. Instead of asking "how long?",
                we ask "how hard is this compared to other things we've done?"<br/><br/>

                <strong>Example:</strong><br/>
                • "Add a new button" = 1 point (simple, we've done this many times)<br/>
                • "Integrate payment gateway" = 8 points (complex, unfamiliar, risk involved)<br/>
                • The payment task is "8 times more complex" than the button—regardless of who does it<br/><br/>

                <strong>How Teams Learn Their Velocity:</strong><br/>
                After a few sprints, you'll know "we complete about 30 story points per sprint." Now you can plan:
                "We have 30 points of capacity, let's not commit to 50 points of work."
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                How to Run Planning Poker (Step-by-Step)
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Setup:</strong> Each person gets cards with Fibonacci numbers: 1, 2, 3, 5, 8, 13, 21<br/><br/>

                <strong>Step 1:</strong> Product Owner reads the user story and answers questions about it<br/>
                <strong>Step 2:</strong> Each person privately selects a card representing their estimate<br/>
                <strong>Step 3:</strong> Everyone reveals their cards simultaneously<br/>
                <strong>Step 4:</strong> If estimates differ significantly (e.g., 3 and 13), discuss:<br/>
                &nbsp;&nbsp;• "Why did you say 13?" → "There's a database migration nobody mentioned"<br/>
                &nbsp;&nbsp;• "Why did you say 3?" → "We can reuse the existing component"<br/>
                <strong>Step 5:</strong> Re-vote after discussion. Repeat until consensus.<br/>
                <strong>Step 6:</strong> Record the agreed estimate and move to the next story<br/><br/>

                <strong>Why it works:</strong> Simultaneous reveal prevents anchoring bias (people don't just agree
                with the first number said). Discussion surfaces hidden knowledge.
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Estimation Techniques Comparison</Typography>
            <TableContainer component={Paper} sx={{ borderRadius: 2, mb: 3 }}>
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

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#f59e0b" }}>
                The Fibonacci Scale: Why Those Weird Numbers?
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                The Fibonacci sequence (1, 2, 3, 5, 8, 13, 21...) has gaps that grow larger as numbers increase.
                This reflects reality:<br/><br/>

                • <strong>Small stories are easier to estimate:</strong> You can distinguish 2 from 3 fairly accurately<br/>
                • <strong>Large stories are harder:</strong> Can you really tell the difference between a "15" and a "17"? No.<br/>
                • <strong>The gaps signal uncertainty:</strong> If something is bigger than an 8, it's either a 13 or needs
                to be broken down further<br/><br/>

                <strong>Rule of thumb:</strong> If a story is larger than 13 points, break it into smaller stories before
                committing to it in a sprint.
              </Typography>
            </Box>
          </Paper>

          {/* Metrics & Charts */}
          <Paper id="metrics" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <TrendingUpIcon sx={{ color: accent }} />
              Metrics & Charts
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Agile teams use metrics not to measure individual performance, but to understand team health, predict future
              capacity, and identify areas for improvement. The key is using metrics to ask questions, not to assign blame.
            </Typography>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide: Understanding Velocity
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>What is Velocity?</strong><br/>
                Velocity is the average number of story points your team completes per sprint. It's your team's "speed"
                for planning purposes.<br/><br/>

                <strong>Example:</strong><br/>
                • Sprint 1: Team completed 24 story points<br/>
                • Sprint 2: Team completed 28 story points<br/>
                • Sprint 3: Team completed 26 story points<br/>
                • <strong>Average velocity: 26 points</strong><br/><br/>

                <strong>How to Use Velocity:</strong><br/>
                For your next sprint planning: "We have 26 points of capacity. Let's select roughly 26 points of work
                from the backlog." Don't overcommit just because one sprint went well—use the average.<br/><br/>

                <strong>Common Mistakes:</strong><br/>
                • <strong>Comparing team velocities:</strong> "Team A does 40 points, Team B only does 25!"—This is meaningless.
                Story points are relative within a team, not across teams.<br/>
                • <strong>Velocity as a target:</strong> "You need to increase velocity by 20%!"—This leads to point inflation, not more work.
                • <strong>Ignoring context:</strong> Velocity will drop during holidays, onboarding, or technical debt sprints—that's normal.
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                How to Read a Burndown Chart
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                A burndown chart shows remaining work over time. The ideal line goes from top-left to bottom-right.<br/><br/>

                <strong>Anatomy of a Burndown Chart:</strong><br/>
                • <strong>Y-axis:</strong> Remaining work (story points or tasks)<br/>
                • <strong>X-axis:</strong> Time (days of the sprint)<br/>
                • <strong>Ideal line:</strong> Straight diagonal showing perfect progress<br/>
                • <strong>Actual line:</strong> Zigzag showing real progress<br/><br/>

                <strong>Reading the Patterns:</strong><br/>
                • <strong>Line above ideal:</strong> Behind schedule—team may not finish all committed work<br/>
                • <strong>Line below ideal:</strong> Ahead of schedule—team might pull in more work<br/>
                • <strong>Flat line:</strong> No progress—something's blocking the team<br/>
                • <strong>Line goes UP:</strong> Scope was added mid-sprint (usually a problem!)<br/><br/>

                <strong>Example Sprint Burndown:</strong><br/>
                Day 1: 30 points remaining (started with 30)<br/>
                Day 3: 24 points remaining (6 points done, on track)<br/>
                Day 5: 22 points remaining (slightly behind)<br/>
                Day 7: 12 points remaining (big push, catching up)<br/>
                Day 10: 2 points remaining (almost done!)<br/>
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#f59e0b" }}>
                Burnup Charts: The Better Alternative?
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                Burnup charts show work completed over time, with a line showing total scope. They reveal scope changes
                that burndowns hide.<br/><br/>

                <strong>Why Burnups Can Be Better:</strong><br/>
                • <strong>Burndown problem:</strong> If scope increases and team works harder, the burndown looks flat—hiding both facts.<br/>
                • <strong>Burnup solution:</strong> Two lines—one for completed work (going up), one for total scope (also tracked).
                You can see when scope grew AND when the team made progress.<br/><br/>

                <strong>Reading a Burnup:</strong><br/>
                • <strong>Work line approaching scope line:</strong> On track to finish<br/>
                • <strong>Scope line keeps rising:</strong> Scope creep! New work being added faster than completed<br/>
                • <strong>Gap between lines:</strong> The remaining work to be done
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#8b5cf6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#8b5cf6" }}>
                Cumulative Flow Diagrams (CFD) for Kanban
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                A CFD shows how many work items are in each state over time. It's the primary chart for Kanban teams.<br/><br/>

                <strong>How to Read a CFD:</strong><br/>
                • <strong>Bands represent states:</strong> To Do (bottom), In Progress (middle), Done (top)<br/>
                • <strong>Band width = WIP:</strong> A wide "In Progress" band means lots of work in progress<br/>
                • <strong>Vertical distance = cycle time:</strong> Measure vertically from when work enters "In Progress"
                to when it reaches "Done"<br/>
                • <strong>Horizontal distance = lead time:</strong> Measure horizontally from entry to completion<br/><br/>

                <strong>Warning Signs:</strong><br/>
                • <strong>Widening bands:</strong> Work piling up in a state—bottleneck<br/>
                • <strong>Parallel lines:</strong> Healthy flow, stable system<br/>
                • <strong>"Staircase" pattern:</strong> Batch releases instead of continuous flow
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Key Metrics Summary</Typography>
            <Grid container spacing={3} sx={{ mb: 3 }}>
              {[
                { name: "Velocity", desc: "Story points completed per sprint. Use for capacity planning, not performance measurement.", color: "#22c55e" },
                { name: "Burndown Chart", desc: "Remaining work over time in a sprint. Shows if team is on track to meet sprint goal.", color: "#3b82f6" },
                { name: "Burnup Chart", desc: "Completed work and scope over time. Better than burndown for tracking scope changes.", color: "#f59e0b" },
                { name: "Cumulative Flow Diagram", desc: "Work items in each state over time. Primary chart for Kanban teams.", color: "#8b5cf6" },
                { name: "Cycle Time", desc: "Time from work started to completed. Lower is better—indicates faster delivery.", color: "#ec4899" },
                { name: "Lead Time", desc: "Time from request to delivery. What customers experience end-to-end.", color: "#06b6d4" },
              ].map((metric) => (
                <Grid item xs={12} md={6} key={metric.name}>
                  <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha(metric.color, 0.08), border: `1px solid ${alpha(metric.color, 0.2)}` }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: metric.color }}>{metric.name}</Typography>
                    <Typography variant="body2" color="text.secondary">{metric.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Alert severity="warning" sx={{ borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Metrics Anti-Pattern Warning</AlertTitle>
              Never use metrics to compare individuals or punish teams. "Developer X completed fewer points" creates
              gaming behavior where people inflate estimates or avoid hard problems. Metrics are for team improvement,
              not surveillance.
            </Alert>
          </Paper>

          {/* Agile Practices */}
          <Paper id="practices" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <BuildIcon sx={{ color: accent }} />
              Agile Practices
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Agile is supported by engineering practices that enable teams to deliver quality software frequently.
              These practices aren't optional extras—they're what make sustainable Agile delivery possible.
            </Typography>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Continuous Integration / Continuous Delivery (CI/CD)
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Continuous Integration (CI):</strong><br/>
                Developers merge code changes into a shared repository multiple times a day. Each merge triggers
                automated builds and tests. This catches integration problems early, when they're small and easy to fix.<br/><br/>

                <strong>Continuous Delivery (CD):</strong><br/>
                Code is always in a deployable state. After passing automated tests, code could be released to production
                at any moment with the push of a button. Some teams practice "Continuous Deployment"—automatically
                releasing every change that passes tests.<br/><br/>

                <strong>Why This Matters for Agile:</strong><br/>
                • <strong>Without CI/CD:</strong> "Integration hell" at the end of each sprint. Merging weeks of work causes conflicts and bugs.<br/>
                • <strong>With CI/CD:</strong> Small, frequent integrations. If something breaks, you know exactly which small change caused it.<br/><br/>

                <strong>Beginner Tip:</strong> Start with basic CI—run automated tests on every push. Add more automation
                gradually: code linting, security scans, automated deployments to staging environments.
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                Test-Driven Development (TDD)
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>The TDD Cycle (Red-Green-Refactor):</strong><br/>
                1. <strong>Red:</strong> Write a failing test for the behavior you want<br/>
                2. <strong>Green:</strong> Write the minimum code to make the test pass<br/>
                3. <strong>Refactor:</strong> Clean up the code while keeping tests green<br/>
                4. Repeat<br/><br/>

                <strong>Example:</strong><br/>
                Want to build a function that calculates discounts?<br/>
                • First write a test: <code>expect(calculateDiscount(100, 0.1)).toBe(90)</code><br/>
                • Test fails (red)—the function doesn't exist yet<br/>
                • Write simple code to make it pass (green)<br/>
                • Clean up, add more test cases, repeat<br/><br/>

                <strong>Why TDD Works:</strong><br/>
                • Tests written after code often test what code does, not what it should do<br/>
                • Writing tests first forces you to think about design before coding<br/>
                • You build a safety net of tests that enables fearless refactoring
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#f59e0b" }}>
                Pair Programming & Mob Programming
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Pair Programming:</strong><br/>
                Two developers work together at one computer. One "drives" (types), one "navigates" (thinks ahead, spots
                errors, suggests improvements). Roles switch frequently.<br/><br/>

                <strong>Mob Programming:</strong><br/>
                The whole team works on the same thing, at the same time, on the same computer. One person types while
                others guide. Sounds inefficient? Teams report fewer bugs, faster knowledge sharing, and better designs.<br/><br/>

                <strong>Common Objections (and Responses):</strong><br/>
                • <strong>"Half the output!"</strong> → Studies show pairs produce fewer bugs, so total cost is often lower<br/>
                • <strong>"Introverts hate it!"</strong> → Many introverts prefer pairing to meetings. It's focused collaboration.<br/>
                • <strong>"Slows seniors down!"</strong> → Seniors share knowledge; juniors ramp up faster. Investment pays off.<br/><br/>

                <strong>How to Start:</strong><br/>
                Don't mandate 100% pairing. Start with complex features, bug investigations, or onboarding new team members.
                Let pairs form naturally for hard problems.
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#8b5cf6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#8b5cf6" }}>
                Technical Debt Management
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>What is Technical Debt?</strong><br/>
                Quick solutions that save time now but require more work later. Like financial debt, it accumulates
                interest—the longer you wait, the harder it is to fix.<br/><br/>

                <strong>Types of Technical Debt:</strong><br/>
                • <strong>Deliberate:</strong> "We know this is hacky but we need to ship. We'll fix it next sprint."<br/>
                • <strong>Accidental:</strong> "We didn't know a better way when we wrote this."<br/>
                • <strong>Bit rot:</strong> Code that was fine but became debt as requirements evolved<br/><br/>

                <strong>Managing Technical Debt:</strong><br/>
                1. <strong>Make it visible:</strong> Track debt items in the backlog, not in developers' heads<br/>
                2. <strong>Allocate capacity:</strong> Reserve 10-20% of each sprint for debt paydown<br/>
                3. <strong>Pay as you go:</strong> When touching code, leave it better than you found it<br/>
                4. <strong>Prioritize by pain:</strong> Fix debt that slows the team daily, not theoretical concerns<br/><br/>

                <strong>Warning Signs of Too Much Debt:</strong><br/>
                • Simple changes take days instead of hours<br/>
                • Fear of touching certain parts of the codebase<br/>
                • New developers take months to become productive
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#ec4899", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#ec4899", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#ec4899" }}>
                Definition of Done (DoD) & Definition of Ready (DoR)
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Definition of Done:</strong><br/>
                A checklist of criteria that must be met before work is considered complete. Prevents "90% done" stories
                from lingering sprint after sprint.<br/><br/>

                <strong>Example DoD:</strong><br/>
                • Code is written and code-reviewed<br/>
                • Unit tests written and passing<br/>
                • Integration tests passing<br/>
                • Documentation updated<br/>
                • Deployed to staging environment<br/>
                • Product Owner has accepted the work<br/><br/>

                <strong>Definition of Ready:</strong><br/>
                Criteria a story must meet before it can be pulled into a sprint. Prevents poorly defined work from
                causing confusion mid-sprint.<br/><br/>

                <strong>Example DoR:</strong><br/>
                • User story follows standard format<br/>
                • Acceptance criteria are clear and testable<br/>
                • Dependencies identified<br/>
                • Story is sized (estimated)<br/>
                • UI mockups available (if applicable)
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Quick Reference: Engineering Practices</Typography>
            <Grid container spacing={2}>
              {[
                { practice: "Continuous Integration", desc: "Merge code frequently, run automated tests on every commit" },
                { practice: "Continuous Delivery", desc: "Keep code deployable at all times, automate release process" },
                { practice: "Test-Driven Development", desc: "Write tests first, then code to pass them" },
                { practice: "Pair Programming", desc: "Two developers, one computer, real-time collaboration" },
                { practice: "Code Reviews", desc: "Peer review all code changes before merging" },
                { practice: "Refactoring", desc: "Continuously improve code structure without changing behavior" },
                { practice: "Information Radiators", desc: "Visible boards showing team status and progress" },
                { practice: "Walking Skeletons", desc: "Minimal end-to-end implementation proving architecture works" },
              ].map((item) => (
                <Grid item xs={12} md={6} key={item.practice}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05) }}>
                    <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2 }}>
                      <CheckCircleIcon sx={{ color: "#22c55e", mt: 0.3 }} />
                      <Box>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.practice}</Typography>
                        <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                      </Box>
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
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Agile started with small, co-located teams. But what happens when you have 50 developers? 200? Large organizations
              need frameworks to coordinate multiple Agile teams while preserving the benefits of agility.
            </Typography>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide: The Scaling Challenge
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Why Scaling Is Hard:</strong><br/>
                A single Scrum team of 7 people works great. But what happens with 70 people building one product?<br/><br/>

                <strong>Common Problems at Scale:</strong><br/>
                • <strong>Dependencies:</strong> Team A can't finish their story until Team B completes theirs<br/>
                • <strong>Integration:</strong> 10 teams each building features—how do you merge them into one product?<br/>
                • <strong>Alignment:</strong> How do you ensure all teams are pulling in the same direction?<br/>
                • <strong>Communication:</strong> In a 7-person team, there are 21 communication paths. In 70 people? 2,415!<br/><br/>

                <strong>The Key Insight:</strong><br/>
                Scaling isn't about doing Agile at a bigger scale. It's about creating structures that allow multiple
                small teams to work together while staying agile. The goal is "scaling down" the problem into manageable
                pieces, not "scaling up" the bureaucracy.
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                Scrum of Scrums: The Simplest Scaling Approach
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>How It Works:</strong><br/>
                Representatives from each Scrum team meet regularly (daily or several times per week) to synchronize
                across teams. It's like a Daily Scrum, but for the whole program.<br/><br/>

                <strong>The Format:</strong><br/>
                Each representative answers:<br/>
                1. What did my team do since the last meeting that affects other teams?<br/>
                2. What will my team do that might affect other teams?<br/>
                3. What impediments does my team face that involve other teams?<br/><br/>

                <strong>When to Use:</strong><br/>
                • 2-5 teams working on related products<br/>
                • Teams have occasional dependencies<br/>
                • You want minimal process overhead<br/><br/>

                <strong>Limitations:</strong><br/>
                Becomes unwieldy with more than 5-7 teams. Representatives become bottlenecks. Consider more
                structured frameworks at that point.
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Scaling Frameworks Comparison</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                {
                  name: "SAFe",
                  full: "Scaled Agile Framework",
                  desc: "Most comprehensive and prescriptive. Defines roles, events, and artifacts at team, program, and portfolio levels. Good for large enterprises needing structure.",
                  pros: "Comprehensive, well-documented, training available",
                  cons: "Heavy, can feel bureaucratic, expensive to implement",
                  teams: "50-500+ people",
                  color: "#6366f1"
                },
                {
                  name: "LeSS",
                  full: "Large-Scale Scrum",
                  desc: "Minimalist approach—extend Scrum rules to multiple teams with minimal additions. One Product Backlog, one Product Owner, multiple teams.",
                  pros: "Simple, true to Scrum, low overhead",
                  cons: "Requires strong Scrum foundation, limited guidance",
                  teams: "2-8 teams",
                  color: "#22c55e"
                },
                {
                  name: "Nexus",
                  full: "Scrum.org's Scaling Framework",
                  desc: "Created by Scrum.org. Adds a Nexus Integration Team to coordinate multiple Scrum teams. Focus on integration and dependencies.",
                  pros: "Official Scrum extension, clear integration focus",
                  cons: "Less guidance for portfolio level",
                  teams: "3-9 teams",
                  color: "#f59e0b"
                },
                {
                  name: "Spotify Model",
                  full: "Squads, Tribes, Chapters, Guilds",
                  desc: "Not a framework but an organizational structure. Autonomous squads grouped into tribes. Chapters for functional expertise, guilds for cross-cutting interests.",
                  pros: "Flexible, emphasizes autonomy and culture",
                  cons: "Hard to copy—it emerged from Spotify's culture",
                  teams: "Varies",
                  color: "#ec4899"
                },
              ].map((fw) => (
                <Grid item xs={12} md={6} key={fw.name}>
                  <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(fw.color, 0.05), border: `1px solid ${alpha(fw.color, 0.2)}`, height: "100%" }}>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: fw.color, mb: 0.5 }}>{fw.name}</Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>{fw.full}</Typography>
                    <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>{fw.desc}</Typography>
                    <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                      <Typography variant="caption"><strong>Best for:</strong> {fw.teams}</Typography>
                      <Typography variant="caption" sx={{ color: "#22c55e" }}><strong>Pros:</strong> {fw.pros}</Typography>
                      <Typography variant="caption" sx={{ color: "#ef4444" }}><strong>Cons:</strong> {fw.cons}</Typography>
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Box sx={{ bgcolor: alpha("#f59e0b", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#f59e0b" }}>
                How to Choose a Scaling Framework
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Start With These Questions:</strong><br/>
                1. <strong>How mature is your Agile practice?</strong> If teams aren't doing Scrum well yet, scaling will magnify problems.<br/>
                2. <strong>How many teams?</strong> 3 teams? Start with Scrum of Scrums. 30 teams? Consider SAFe or LeSS Huge.<br/>
                3. <strong>How coupled are the teams?</strong> Independent products need less coordination than one integrated system.<br/>
                4. <strong>What's your culture?</strong> Command-and-control cultures may need SAFe's structure. Autonomous cultures may prefer LeSS.<br/><br/>

                <strong>Common Mistakes:</strong><br/>
                • <strong>Adopting the Spotify Model because Spotify is cool:</strong> Their model emerged from their culture. You can't copy-paste it.<br/>
                • <strong>Choosing SAFe because it's comprehensive:</strong> More process isn't always better. Start simple.<br/>
                • <strong>Scaling before you need to:</strong> If 2 teams can be truly independent, don't force coordination on them.
              </Typography>
            </Box>

            <Alert severity="info" sx={{ borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>Before You Scale</AlertTitle>
              Make sure individual teams are doing Agile well before scaling. Scaling broken processes just creates bigger
              broken processes. Get one team working well, then expand. As the saying goes: "If you can't feed a team with
              two pizzas, it's too large."
            </Alert>
          </Paper>

          {/* Anti-Patterns */}
          <Paper id="anti-patterns" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <CancelIcon sx={{ color: "#ef4444" }} />
              Common Anti-Patterns
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Anti-patterns are common mistakes that look like good practices but actually undermine Agile values. Learning
              to recognize them helps teams avoid common traps and stay truly agile instead of "Agile in name only."
            </Typography>

            <Box sx={{ bgcolor: alpha("#ef4444", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#ef4444" }}>
                "Scrumbut" and "Dark Scrum"
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Scrumbut:</strong><br/>
                "We use Scrum, but..." followed by dropping essential elements. Examples:<br/>
                • "We do Scrum, but we don't have a Product Owner—the manager decides priorities"<br/>
                • "We do Scrum, but sprints are 6 weeks because 2 weeks is too short"<br/>
                • "We do Scrum, but we skip retrospectives—no time"<br/><br/>

                <strong>Dark Scrum:</strong><br/>
                Using Scrum terminology while practicing command-and-control management:<br/>
                • Managers attend Daily Scrum and use it to check up on people<br/>
                • Velocity is used as a performance metric to pressure teams<br/>
                • "Self-organization" means "figure it out yourselves with no support"<br/>
                • Sprints become mini-waterfalls with deadlines to meet<br/><br/>

                <strong>The Core Problem:</strong><br/>
                Adopting Scrum's practices without its values creates a worse situation than no Agile at all. Teams get
                the overhead of ceremonies without the benefits of agility.
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Anti-Patterns Explained</Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                {
                  pattern: "Daily Scrum as Status Report",
                  symptom: "Team members report to a manager instead of coordinating with each other",
                  fix: "Managers should not attend. Focus on team coordination, not individual accountability.",
                  color: "#ef4444"
                },
                {
                  pattern: "Sprint Extension",
                  symptom: "Sprints regularly run over to 'finish everything'",
                  fix: "Sprints are fixed timeboxes. Incomplete work returns to the backlog. Adjust capacity, not time.",
                  color: "#f59e0b"
                },
                {
                  pattern: "Absent Product Owner",
                  symptom: "PO is too busy to attend planning, refinement, or answer questions",
                  fix: "PO must be available. If they can't, they need a proxy with decision authority.",
                  color: "#ef4444"
                },
                {
                  pattern: "Scrum Master as Task Assigner",
                  symptom: "SM tells developers what to work on instead of team self-organizing",
                  fix: "SM facilitates, doesn't direct. Team members pull work based on priorities and skills.",
                  color: "#f59e0b"
                },
                {
                  pattern: "Skipping Retrospectives",
                  symptom: "'We're too busy to improve' or retros become complaint sessions",
                  fix: "Retros are mandatory. If they're not useful, fix the retro format—don't skip them.",
                  color: "#ef4444"
                },
                {
                  pattern: "No Definition of Done",
                  symptom: "'Done' means different things to different people; stories reopen",
                  fix: "Create and enforce a team DoD. Stories that don't meet DoD aren't done.",
                  color: "#f59e0b"
                },
                {
                  pattern: "Technical Debt Denial",
                  symptom: "'We don't have time for cleanup' sprint after sprint",
                  fix: "Allocate capacity for debt. Track debt items visibly. Pay as you go.",
                  color: "#ef4444"
                },
                {
                  pattern: "Fake Self-Organization",
                  symptom: "'Team decides' but manager overrules decisions or punishes 'wrong' choices",
                  fix: "True self-organization requires psychological safety and real authority over how work is done.",
                  color: "#f59e0b"
                },
              ].map((item) => (
                <Grid item xs={12} key={item.pattern}>
                  <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha(item.color, 0.05), border: `1px solid ${alpha(item.color, 0.15)}` }}>
                    <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2 }}>
                      <CancelIcon sx={{ color: item.color, mt: 0.3 }} />
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color }}>{item.pattern}</Typography>
                        <Typography variant="body2" sx={{ mb: 1 }}><strong>Symptom:</strong> {item.symptom}</Typography>
                        <Typography variant="body2" sx={{ color: "#22c55e" }}><strong>Fix:</strong> {item.fix}</Typography>
                      </Box>
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Box sx={{ bgcolor: alpha("#3b82f6", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#3b82f6" }}>
                "Cargo Cult Agile"
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>What It Is:</strong><br/>
                Copying Agile practices superficially without understanding why they work. Named after Pacific Island
                cargo cults that built fake runways hoping planes would bring goods.<br/><br/>

                <strong>Examples:</strong><br/>
                • Standing during Daily Scrum (copying the "standup" practice) but meetings still last 45 minutes<br/>
                • Using story points but converting them to hours for management<br/>
                • Having a Kanban board but never updating it or using WIP limits<br/>
                • Renaming "Project Manager" to "Scrum Master" with no change in behavior<br/><br/>

                <strong>The Problem:</strong><br/>
                The rituals are visible; the values aren't. Teams adopt what they can see (standups, boards, sprints)
                but miss what makes them work (collaboration, feedback loops, continuous improvement).<br/><br/>

                <strong>The Solution:</strong><br/>
                Start with "why." Don't just do standups—understand they're for team coordination. Don't just have
                sprints—understand they create feedback loops. Then adapt practices to serve those purposes.
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Signs You're Actually Doing Agile Well
              </Typography>
              <Typography variant="body2" component="div" sx={{ lineHeight: 1.9 }}>
                <strong>Healthy Signs:</strong><br/>
                • Working software ships every sprint (or more frequently)<br/>
                • Customers give feedback regularly and it influences priorities<br/>
                • Team members feel safe raising problems and experiments<br/>
                • Retrospective actions actually get implemented<br/>
                • People ask "what's the value?" not just "what's the deadline?"<br/>
                • Technical quality stays high (tests, clean code, etc.)<br/>
                • Stakeholders trust the team's estimates and commitments<br/>
                • Change is welcomed, not feared<br/><br/>

                <strong>The Ultimate Test:</strong><br/>
                If your practices aren't helping you deliver value faster, respond to change better, and keep teams
                sustainable—something's wrong. Agile isn't about following rules; it's about getting results.
              </Typography>
            </Box>
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
