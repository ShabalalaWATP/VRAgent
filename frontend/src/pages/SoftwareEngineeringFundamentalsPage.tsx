import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import {
  Box,
  Container,
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
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import SchoolIcon from "@mui/icons-material/School";
import BuildIcon from "@mui/icons-material/Build";
import CodeIcon from "@mui/icons-material/Code";
import TerminalIcon from "@mui/icons-material/Terminal";
import GitHubIcon from "@mui/icons-material/GitHub";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import LanguageIcon from "@mui/icons-material/Language";
import PhoneIphoneIcon from "@mui/icons-material/PhoneIphone";
import AndroidIcon from "@mui/icons-material/Android";
import CloudIcon from "@mui/icons-material/Cloud";
import SecurityIcon from "@mui/icons-material/Security";
import StorageIcon from "@mui/icons-material/Storage";
import BugReportIcon from "@mui/icons-material/BugReport";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import WarningIcon from "@mui/icons-material/Warning";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import { useNavigate } from "react-router-dom";

interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  topic: string;
}

const questionBank: QuizQuestion[] = [
  // Topic 1: Core Concepts (1-13)
  { id: 1, question: "What is software engineering?", options: ["Only writing code", "Applying engineering principles to build and maintain software", "Hardware repair", "Graphic design"], correctAnswer: 1, explanation: "Software engineering is the disciplined application of engineering principles to design, build, test, deploy, and maintain software systems.", topic: "Core Concepts" },
  { id: 2, question: "Which SDLC stage defines what the software should do?", options: ["Implementation", "Testing", "Requirements and analysis", "Deployment"], correctAnswer: 2, explanation: "Requirements and analysis capture what the system must do and the constraints it must meet.", topic: "Core Concepts" },
  { id: 3, question: "What is a requirement in software projects?", options: ["A coding style rule", "A documented need or constraint from stakeholders", "A database table", "A test result"], correctAnswer: 1, explanation: "Requirements describe stakeholder needs, constraints, and expected behavior for the system.", topic: "Core Concepts" },
  { id: 4, question: "Which is a non-functional requirement?", options: ["Allow users to reset passwords", "System should load a page in under 2 seconds", "Send email notifications", "Support file uploads"], correctAnswer: 1, explanation: "Non-functional requirements describe quality attributes like performance, reliability, and usability.", topic: "Core Concepts" },
  { id: 5, question: "Which phase often consumes the most long-term effort?", options: ["Planning", "Implementation", "Maintenance", "Unit testing"], correctAnswer: 2, explanation: "Maintenance typically dominates the total cost over a product's lifetime due to fixes, updates, and evolving needs.", topic: "Core Concepts" },
  { id: 6, question: "What is a bug in software?", options: ["A required feature", "A defect or error that causes incorrect behavior", "A version label", "A deployment environment"], correctAnswer: 1, explanation: "A bug is a defect that causes software to behave differently than intended.", topic: "Core Concepts" },
  { id: 7, question: "What does technical debt describe?", options: ["A billing issue", "The cost of quick solutions that need refactoring later", "A licensing fee", "An operating system update"], correctAnswer: 1, explanation: "Technical debt is the future cost of taking shortcuts now instead of implementing a better solution.", topic: "Core Concepts" },
  { id: 8, question: "What does semantic versioning use to signal changes?", options: ["Date and time", "Major.Minor.Patch", "Random numbers", "Build size"], correctAnswer: 1, explanation: "Semantic versioning uses Major.Minor.Patch to communicate breaking changes, new features, and fixes.", topic: "Core Concepts" },
  { id: 9, question: "What is scope creep?", options: ["Adding features beyond the original plan without control", "A code formatting tool", "A type of database index", "A release strategy"], correctAnswer: 0, explanation: "Scope creep is uncontrolled expansion of project requirements after planning.", topic: "Core Concepts" },
  { id: 10, question: "What is an algorithm?", options: ["A data storage format", "A step-by-step procedure to solve a problem", "A UI component", "A file type"], correctAnswer: 1, explanation: "Algorithms describe the sequence of steps used to solve a problem or compute a result.", topic: "Core Concepts" },
  { id: 11, question: "What is a data structure?", options: ["A design mockup", "A way to organize and store data for efficient access", "A network protocol", "A build script"], correctAnswer: 1, explanation: "Data structures organize data so it can be accessed and modified efficiently.", topic: "Core Concepts" },
  { id: 12, question: "What does modularity help with?", options: ["Larger files", "Breaking a system into smaller, reusable parts", "Fewer tests", "Hard-coding values"], correctAnswer: 1, explanation: "Modularity reduces complexity by organizing code into reusable, well-defined components.", topic: "Core Concepts" },
  { id: 13, question: "What is abstraction in software?", options: ["Hiding details while exposing essential behavior", "Writing low-level code only", "Copying code between files", "Avoiding documentation"], correctAnswer: 0, explanation: "Abstraction hides internal complexity and exposes a simpler interface to users.", topic: "Core Concepts" },
  // Topic 2: Tools and IDEs (14-25)
  { id: 14, question: "What does IDE stand for?", options: ["Integrated Development Environment", "Internal Debug Engine", "Internet Development Editor", "Interactive Design Extension"], correctAnswer: 0, explanation: "An IDE combines a code editor, debugger, build tools, and other features in one place.", topic: "Tools and IDEs" },
  { id: 15, question: "Which is commonly considered a lightweight editor rather than a full IDE?", options: ["Visual Studio", "VS Code", "IntelliJ IDEA Ultimate", "Android Studio"], correctAnswer: 1, explanation: "VS Code is primarily a code editor that becomes IDE-like through extensions.", topic: "Tools and IDEs" },
  { id: 16, question: "Which IDE is commonly used for .NET development?", options: ["Eclipse", "Visual Studio", "PyCharm", "Xcode"], correctAnswer: 1, explanation: "Visual Studio is the primary IDE for .NET and C# development.", topic: "Tools and IDEs" },
  { id: 17, question: "Which IDE is popular for Java development?", options: ["IntelliJ IDEA", "Notepad", "Paint", "Wireshark"], correctAnswer: 0, explanation: "IntelliJ IDEA is a popular Java IDE known for strong refactoring and tooling.", topic: "Tools and IDEs" },
  { id: 18, question: "What is a linter used for?", options: ["Running servers", "Checking code for style and potential errors", "Compressing images", "Monitoring memory"], correctAnswer: 1, explanation: "Linters analyze code for errors, style problems, and potential issues.", topic: "Tools and IDEs" },
  { id: 19, question: "What is the purpose of a code formatter?", options: ["To change program logic", "To enforce consistent code style", "To encrypt code", "To build binaries"], correctAnswer: 1, explanation: "Formatters apply consistent styling rules without changing behavior.", topic: "Tools and IDEs" },
  { id: 20, question: "What does a debugger help you do?", options: ["Create UI designs", "Step through code and inspect state", "Deploy to production", "Generate documentation"], correctAnswer: 1, explanation: "Debuggers let you step through code, set breakpoints, and inspect variables.", topic: "Tools and IDEs" },
  { id: 21, question: "Which tool category compiles or packages code?", options: ["Build tools", "Issue trackers", "Chat clients", "Image editors"], correctAnswer: 0, explanation: "Build tools automate compilation, bundling, and packaging tasks.", topic: "Tools and IDEs" },
  { id: 22, question: "What does a package manager do?", options: ["Design UI screens", "Manage project dependencies", "Run penetration tests", "Create virtual machines"], correctAnswer: 1, explanation: "Package managers install, update, and resolve third-party dependencies.", topic: "Tools and IDEs" },
  { id: 23, question: "What is a terminal or shell primarily used for?", options: ["Photo editing", "Running commands and scripts", "Animating videos", "Designing logos"], correctAnswer: 1, explanation: "Terminals let you run commands, scripts, and developer tools quickly.", topic: "Tools and IDEs" },
  { id: 24, question: "What does a compiler do?", options: ["Executes code line by line", "Translates code into machine-readable output", "Stores files in the cloud", "Manages network traffic"], correctAnswer: 1, explanation: "Compilers translate source code into machine code or intermediate output.", topic: "Tools and IDEs" },
  { id: 25, question: "What does an interpreter do?", options: ["Translates code into machine code ahead of time", "Executes code directly at runtime", "Only checks syntax", "Creates UI mockups"], correctAnswer: 1, explanation: "Interpreters execute code at runtime without a separate compile step.", topic: "Tools and IDEs" },
  // Topic 3: Version Control and Collaboration (26-37)
  { id: 26, question: "What is version control?", options: ["A file compression method", "A system to track and manage code changes", "A hardware device", "A database query language"], correctAnswer: 1, explanation: "Version control tracks changes, history, and collaboration across files.", topic: "Version Control" },
  { id: 27, question: "Which Git command records a snapshot of changes?", options: ["git push", "git commit", "git clone", "git fetch"], correctAnswer: 1, explanation: "git commit records a snapshot of staged changes in local history.", topic: "Version Control" },
  { id: 28, question: "What is a branch in Git?", options: ["A type of server", "A parallel line of development", "A password file", "A compiled binary"], correctAnswer: 1, explanation: "Branches allow parallel work without affecting the main line until merged.", topic: "Version Control" },
  { id: 29, question: "What does merging do?", options: ["Deletes history", "Combines changes from different branches", "Creates a new repository", "Compresses files"], correctAnswer: 1, explanation: "Merging integrates changes from one branch into another.", topic: "Version Control" },
  { id: 30, question: "What is a pull request?", options: ["A local backup", "A proposal to merge changes with review", "A database query", "A license file"], correctAnswer: 1, explanation: "Pull requests allow review and discussion before merging changes.", topic: "Version Control" },
  { id: 31, question: "What is the difference between Git and GitHub?", options: ["They are the same tool", "Git is a VCS, GitHub is a hosting platform", "GitHub replaces Git", "Git is a GUI only"], correctAnswer: 1, explanation: "Git is the version control system, GitHub hosts repositories and collaboration features.", topic: "Version Control" },
  { id: 32, question: "What is a remote repository?", options: ["A local folder", "A repository stored on a server", "A backup zip file", "A build artifact"], correctAnswer: 1, explanation: "Remotes are repositories hosted elsewhere, such as GitHub or GitLab.", topic: "Version Control" },
  { id: 33, question: "What is a merge conflict?", options: ["A security alert", "Overlapping changes Git cannot auto-merge", "A successful deployment", "A test pass"], correctAnswer: 1, explanation: "Conflicts happen when changes overlap and require manual resolution.", topic: "Version Control" },
  { id: 34, question: "Why use a .gitignore file?", options: ["To encrypt files", "To exclude files from version control", "To rename branches", "To compile code"], correctAnswer: 1, explanation: ".gitignore prevents committing generated or sensitive files.", topic: "Version Control" },
  { id: 35, question: "What does git clone do?", options: ["Delete a branch", "Copy a repository to your machine", "Upload changes", "Create a tag"], correctAnswer: 1, explanation: "git clone makes a local copy of a remote repository.", topic: "Version Control" },
  { id: 36, question: "What is a fork on GitHub?", options: ["A merge tool", "A personal copy of someone else's repository", "A build artifact", "A programming language"], correctAnswer: 1, explanation: "Forks allow you to copy and modify a repository under your account.", topic: "Version Control" },
  { id: 37, question: "What is a Git tag commonly used for?", options: ["Tracking releases", "Running tests", "Editing README files", "Creating branches"], correctAnswer: 0, explanation: "Tags label specific commits, often used for releases.", topic: "Version Control" },
  // Topic 4: Development Workflow (38-50)
  { id: 38, question: "What is a local development environment?", options: ["A production server", "Your machine configured to build and run the project", "A public web server", "A database backup"], correctAnswer: 1, explanation: "Local environments include tools, dependencies, and settings to run the app locally.", topic: "Workflow" },
  { id: 39, question: "What is a dependency?", options: ["A code comment", "An external library or package the project needs", "A compiler error", "A UI component"], correctAnswer: 1, explanation: "Dependencies are external libraries or packages that your project relies on.", topic: "Workflow" },
  { id: 40, question: "What is a build artifact?", options: ["A source code file", "Compiled or packaged output from a build", "A pull request", "A configuration file"], correctAnswer: 1, explanation: "Build artifacts are outputs like binaries, bundles, or packages produced by a build.", topic: "Workflow" },
  { id: 41, question: "What is a unit test?", options: ["A test of the entire system", "A test for a small piece of code in isolation", "A test of network latency", "A manual test"], correctAnswer: 1, explanation: "Unit tests verify small units like functions or classes in isolation.", topic: "Workflow" },
  { id: 42, question: "What is an integration test?", options: ["A test of one function", "A test of multiple components working together", "A UI screenshot", "A static analysis report"], correctAnswer: 1, explanation: "Integration tests validate that components interact correctly.", topic: "Workflow" },
  { id: 43, question: "What does CI stand for?", options: ["Code Inspection", "Continuous Integration", "Cloud Integration", "Central Interface"], correctAnswer: 1, explanation: "Continuous Integration automatically builds and tests changes on every update.", topic: "Workflow" },
  { id: 44, question: "What does CD often refer to in DevOps?", options: ["Code Delivery", "Continuous Deployment or Continuous Delivery", "Compact Disk", "Client Database"], correctAnswer: 1, explanation: "CD automates the release pipeline for deploying software.", topic: "Workflow" },
  { id: 45, question: "What is code review?", options: ["Running the app", "Reviewing changes for quality and correctness", "Generating documentation", "Publishing packages"], correctAnswer: 1, explanation: "Code reviews catch bugs, improve quality, and spread knowledge.", topic: "Workflow" },
  { id: 46, question: "Why use an issue tracker?", options: ["To store compiled binaries", "To track tasks, bugs, and features", "To host images", "To replace Git"], correctAnswer: 1, explanation: "Issue trackers organize work items and their status.", topic: "Workflow" },
  { id: 47, question: "What is logging used for?", options: ["Styling code", "Capturing runtime information for debugging and monitoring", "Compiling code", "Generating UI layouts"], correctAnswer: 1, explanation: "Logs help diagnose issues and monitor system behavior.", topic: "Workflow" },
  { id: 48, question: "What is a staging environment?", options: ["A production environment", "A pre-production environment for final testing", "A personal laptop", "A backup server only"], correctAnswer: 1, explanation: "Staging mimics production to validate releases before going live.", topic: "Workflow" },
  { id: 49, question: "What is a rollback?", options: ["Adding features", "Reverting to a previous working version", "Creating a branch", "Changing UI theme"], correctAnswer: 1, explanation: "Rollback restores a prior stable version after a bad release.", topic: "Workflow" },
  { id: 50, question: "What is a backlog?", options: ["A list of planned work items", "A database cache", "A server log", "A dependency list"], correctAnswer: 0, explanation: "A backlog is a prioritized list of tasks, features, and fixes.", topic: "Workflow" },
  // Topic 5: Areas and Roles (51-63)
  { id: 51, question: "Frontend development primarily focuses on:", options: ["Server hardware", "User interface and client-side behavior", "Database replication", "Operating system kernels"], correctAnswer: 1, explanation: "Frontend work builds the UI and client-side logic users interact with.", topic: "Areas and Roles" },
  { id: 52, question: "Backend development primarily focuses on:", options: ["UI design", "Server-side logic, APIs, and databases", "Graphic assets", "Device drivers"], correctAnswer: 1, explanation: "Backend work handles data, business logic, and server infrastructure.", topic: "Areas and Roles" },
  { id: 53, question: "A full-stack developer typically works on:", options: ["Only databases", "Both frontend and backend systems", "Only UI graphics", "Only network hardware"], correctAnswer: 1, explanation: "Full-stack developers work across the client and server side of applications.", topic: "Areas and Roles" },
  { id: 54, question: "Mobile development targets:", options: ["Desktop-only apps", "Smartphones and tablets", "Routers", "Printers"], correctAnswer: 1, explanation: "Mobile development focuses on iOS and Android apps.", topic: "Areas and Roles" },
  { id: 55, question: "Embedded software is commonly used in:", options: ["Web browsers", "Microcontrollers and IoT devices", "Cloud storage services", "Word processors"], correctAnswer: 1, explanation: "Embedded systems run on constrained hardware like microcontrollers.", topic: "Areas and Roles" },
  { id: 56, question: "Data engineering focuses on:", options: ["Game graphics", "Building data pipelines and storage systems", "Logo design", "Audio processing only"], correctAnswer: 1, explanation: "Data engineers build pipelines to collect, transform, and store data.", topic: "Areas and Roles" },
  { id: 57, question: "DevOps emphasizes:", options: ["Only writing tests", "Automation of delivery and infrastructure", "Only UI design", "Only database modeling"], correctAnswer: 1, explanation: "DevOps integrates development and operations to speed up and stabilize delivery.", topic: "Areas and Roles" },
  { id: 58, question: "QA engineers are primarily responsible for:", options: ["Marketing", "Testing and quality assurance", "Managing payroll", "Hardware repairs"], correctAnswer: 1, explanation: "QA focuses on verifying behavior and preventing defects.", topic: "Areas and Roles" },
  { id: 59, question: "Security engineering aims to:", options: ["Increase app size", "Protect systems against vulnerabilities and threats", "Remove testing", "Skip code reviews"], correctAnswer: 1, explanation: "Security engineering reduces risk and defends systems and data.", topic: "Areas and Roles" },
  { id: 60, question: "Game development often involves:", options: ["Real-time rendering and physics", "Only database tuning", "Only text processing", "Only spreadsheet logic"], correctAnswer: 0, explanation: "Game development includes real-time graphics, physics, and input handling.", topic: "Areas and Roles" },
  { id: 61, question: "Site Reliability Engineering (SRE) focuses on:", options: ["Pure UI design", "System reliability, uptime, and automation", "Logo creation", "Manual testing only"], correctAnswer: 1, explanation: "SRE applies engineering to operations to improve reliability.", topic: "Areas and Roles" },
  { id: 62, question: "Cloud engineering commonly includes:", options: ["Maintaining on-premise printers", "Designing cloud infrastructure and services", "Desktop wallpaper design", "Firmware flashing only"], correctAnswer: 1, explanation: "Cloud engineering builds and manages infrastructure on cloud platforms.", topic: "Areas and Roles" },
  { id: 63, question: "AI/ML engineering often involves:", options: ["Training models and deploying them", "Only writing HTML", "Network cabling", "Printing documents"], correctAnswer: 0, explanation: "AI/ML engineers build and deploy models, plus supporting data pipelines.", topic: "Areas and Roles" },
  // Topic 6: Architecture Basics (64-75)
  { id: 64, question: "What is an API?", options: ["A data backup", "A defined way for software components to communicate", "A server rack", "A log file"], correctAnswer: 1, explanation: "APIs define how software components interact and exchange data.", topic: "Architecture Basics" },
  { id: 65, question: "What does client-server architecture describe?", options: ["A single program only", "Clients request services from a server", "Multiple databases in one file", "A hardware wiring diagram"], correctAnswer: 1, explanation: "In client-server models, clients request data or services from servers.", topic: "Architecture Basics" },
  { id: 66, question: "What is a database used for?", options: ["Rendering UI", "Storing and querying structured data", "Testing network latency", "Compiling code"], correctAnswer: 1, explanation: "Databases manage structured data with efficient querying and storage.", topic: "Architecture Basics" },
  { id: 67, question: "Which statement best describes SQL vs NoSQL?", options: ["SQL is for images only", "SQL uses structured schemas, NoSQL is more flexible", "NoSQL cannot scale", "SQL databases never use tables"], correctAnswer: 1, explanation: "SQL databases use schemas and tables, while NoSQL stores data more flexibly.", topic: "Architecture Basics" },
  { id: 68, question: "What is a monolith?", options: ["Many independent services", "A single deployable application", "A network cable", "A mobile device"], correctAnswer: 1, explanation: "Monolithic applications package all features into a single deployment unit.", topic: "Architecture Basics" },
  { id: 69, question: "What are microservices?", options: ["A single large server", "Small services that communicate over a network", "A file format", "A testing technique"], correctAnswer: 1, explanation: "Microservices split an application into smaller services with clear boundaries.", topic: "Architecture Basics" },
  { id: 70, question: "What does REST commonly use for communication?", options: ["Bluetooth", "HTTP methods and resource URLs", "Email", "SSH only"], correctAnswer: 1, explanation: "REST APIs typically use HTTP methods like GET and POST over URLs.", topic: "Architecture Basics" },
  { id: 71, question: "What is the difference between authentication and authorization?", options: ["They are identical", "Authentication verifies identity, authorization defines permissions", "Authorization is about passwords only", "Authentication is only for databases"], correctAnswer: 1, explanation: "Authentication proves who you are; authorization determines what you can do.", topic: "Architecture Basics" },
  { id: 72, question: "What is caching?", options: ["Deleting data", "Storing data temporarily for faster access", "Encrypting files", "Formatting code"], correctAnswer: 1, explanation: "Caching stores frequently accessed data to reduce latency.", topic: "Architecture Basics" },
  { id: 73, question: "What is load balancing?", options: ["Storing backups", "Distributing traffic across multiple servers", "Running unit tests", "Compiling code faster"], correctAnswer: 1, explanation: "Load balancers spread traffic to improve reliability and performance.", topic: "Architecture Basics" },
  { id: 74, question: "What is scalability?", options: ["Changing fonts", "Ability to handle growth in users or load", "Logging in", "Copying files"], correctAnswer: 1, explanation: "Scalability is the ability to handle increased demand by adding resources.", topic: "Architecture Basics" },
  { id: 75, question: "What is latency?", options: ["The number of servers", "Delay before data is transferred", "Database schema", "Source code style"], correctAnswer: 1, explanation: "Latency measures the time delay between request and response.", topic: "Architecture Basics" },
];

const QuizSection: React.FC = () => {
  const [quizState, setQuizState] = useState<"start" | "active" | "results">("start");
  const [questions, setQuestions] = useState<QuizQuestion[]>([]);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<{ [key: number]: number }>({});
  const [showExplanation, setShowExplanation] = useState(false);
  const [score, setScore] = useState(0);

  const QUESTIONS_PER_QUIZ = 10;
  const accent = "#f97316";
  const accentDark = "#ea580c";
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
          Software Engineering Fundamentals Quiz
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 520, mx: "auto" }}>
          Test your understanding with {QUESTIONS_PER_QUIZ} randomly selected questions from a 75-question bank. Topics include core concepts, tools, Git, workflows, specializations, and architecture basics.
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
            ? "Great work. You have a strong grasp of the fundamentals."
            : "Keep going. Review the sections above and try again."}
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

export default function SoftwareEngineeringFundamentalsPage() {
  const navigate = useNavigate();
  const theme = useTheme();

  const pageContext = `Software Engineering Fundamentals learning page. Covers core software engineering concepts, tools and IDEs (VS Code, Visual Studio, IntelliJ, Xcode), Git and GitHub workflows, SDLC and methodologies, clean code principles, testing and quality, debugging, delivery and operations basics, security and performance fundamentals, and common software engineering specializations including web, mobile, backend, cloud, DevOps, data, and security. Includes a randomized 75-question quiz to reinforce learning.`;

  const quickStats = [
    { label: "Modules", value: "18", color: "#f97316" },
    { label: "Tools", value: "20+", color: "#3b82f6" },
    { label: "Quiz Questions", value: "75", color: "#22c55e" },
    { label: "Difficulty", value: "Beginner", color: "#8b5cf6" },
  ];

  const learningPlan = [
    {
      title: "Phase 1: Foundations",
      items: [
        "Understand what software engineering is and how it differs from just coding.",
        "Learn problem solving with algorithms and data structures.",
        "Get comfortable with requirements, design, and testing concepts.",
      ],
    },
    {
      title: "Phase 2: Tooling",
      items: [
        "Pick an editor or IDE (VS Code, Visual Studio, IntelliJ).",
        "Learn the terminal basics and your platform package manager.",
        "Set up debugging, linting, and formatting for clean code.",
      ],
    },
    {
      title: "Phase 3: Version Control",
      items: [
        "Master Git basics: commit, branch, merge, and resolve conflicts.",
        "Use GitHub for pull requests, reviews, and collaboration.",
        "Adopt clean commit messages and a branching strategy.",
      ],
    },
    {
      title: "Phase 4: Build and Test",
      items: [
        "Understand build tools and dependency management.",
        "Write unit and integration tests for reliability.",
        "Learn CI basics to automate builds and tests.",
      ],
    },
    {
      title: "Phase 5: Specialize",
      items: [
        "Explore web, mobile, backend, cloud, data, or security roles.",
        "Build small projects and iterate based on feedback.",
        "Keep learning and stay current with tools and best practices.",
      ],
    },
    {
      title: "Phase 6: Quality and Operations",
      items: [
        "Improve reliability with testing, monitoring, and incident response.",
        "Treat security and privacy as core requirements, not add-ons.",
        "Refine processes with retrospectives and technical debt paydown.",
      ],
    },
  ];

  const toolingRows = [
    { category: "Editors and IDEs", examples: "VS Code, Visual Studio, IntelliJ IDEA, PyCharm, Eclipse, Xcode, Android Studio, Vim, Neovim", purpose: "Write, refactor, debug, and run code efficiently." },
    { category: "Version control", examples: "Git, GitHub, GitLab, Bitbucket", purpose: "Track changes and collaborate with teams." },
    { category: "Build and package", examples: "npm, pnpm, yarn, Maven, Gradle, MSBuild, Make, CMake", purpose: "Compile, bundle, and manage dependencies." },
    { category: "Testing and QA", examples: "Jest, PyTest, JUnit, NUnit, Cypress, Playwright", purpose: "Automate tests to prevent regressions." },
    { category: "Debugging and profiling", examples: "VS Code Debugger, Visual Studio Debugger, Chrome DevTools", purpose: "Inspect runtime state and performance." },
    { category: "Containers and environments", examples: "Docker, Compose, VM tools", purpose: "Reproduce consistent development environments." },
  ];

  const specializations = [
    {
      title: "Frontend Web",
      description: "Build user interfaces, accessibility, and client-side performance.",
      icon: <LanguageIcon sx={{ fontSize: 36 }} />,
      color: "#3b82f6",
    },
    {
      title: "Backend and APIs",
      description: "Design server logic, databases, and API contracts.",
      icon: <AccountTreeIcon sx={{ fontSize: 36 }} />,
      color: "#10b981",
    },
    {
      title: "Mobile",
      description: "Create native or cross-platform apps for iOS and Android.",
      icon: <PhoneIphoneIcon sx={{ fontSize: 36 }} />,
      color: "#f97316",
    },
    {
      title: "Android",
      description: "Focus on the Android ecosystem, Kotlin, and app tooling.",
      icon: <AndroidIcon sx={{ fontSize: 36 }} />,
      color: "#22c55e",
    },
    {
      title: "Cloud and DevOps",
      description: "Deploy, scale, and automate infrastructure and pipelines.",
      icon: <CloudIcon sx={{ fontSize: 36 }} />,
      color: "#0ea5e9",
    },
    {
      title: "Security Engineering",
      description: "Build secure systems, reduce risk, and prevent attacks.",
      icon: <SecurityIcon sx={{ fontSize: 36 }} />,
      color: "#ef4444",
    },
    {
      title: "Data and ML",
      description: "Design data pipelines and deploy machine learning models.",
      icon: <StorageIcon sx={{ fontSize: 36 }} />,
      color: "#8b5cf6",
    },
    {
      title: "QA and Testing",
      description: "Build test strategies, automation, and quality processes.",
      icon: <BugReportIcon sx={{ fontSize: 36 }} />,
      color: "#f59e0b",
    },
  ];

  const qualityAttributes = [
    { name: "Reliability", description: "Works consistently and recovers from failures.", color: "#22c55e" },
    { name: "Maintainability", description: "Easy to change, refactor, and extend.", color: "#3b82f6" },
    { name: "Security", description: "Protects data and reduces attack surface.", color: "#ef4444" },
    { name: "Performance", description: "Fast response times and efficient resource use.", color: "#f97316" },
    { name: "Scalability", description: "Handles growth in users and data.", color: "#8b5cf6" },
    { name: "Usability", description: "Clear, accessible, and easy to learn.", color: "#0ea5e9" },
  ];

  const ideGuideRows = [
    { tool: "VS Code", bestFor: "General purpose, web, scripting", notes: "Lightweight with extensions and great community support." },
    { tool: "Visual Studio", bestFor: ".NET, Windows desktop, enterprise apps", notes: "Powerful debugger and integrated tooling." },
    { tool: "IntelliJ IDEA / PyCharm", bestFor: "Java/Kotlin or Python development", notes: "Deep refactoring and strong code intelligence." },
    { tool: "Xcode", bestFor: "iOS and macOS apps", notes: "Required for Apple platform builds and signing." },
    { tool: "Android Studio", bestFor: "Android apps", notes: "Android SDK, emulator, and profiling tools." },
    { tool: "Vim / Neovim", bestFor: "Terminal-centric workflows", notes: "Fast once mastered, highly customizable." },
  ];

  const codePrinciples = [
    { title: "DRY", description: "Do not repeat yourself. Extract common logic." },
    { title: "KISS", description: "Keep it simple. Prefer clear over clever." },
    { title: "YAGNI", description: "Do not build features before they are needed." },
    { title: "SOLID", description: "Design classes with clear responsibilities." },
    { title: "Separation of Concerns", description: "Split UI, logic, and data responsibilities." },
    { title: "Readability First", description: "Code is read more than it is written." },
  ];

  const environmentChecklist = [
    "Keep configuration in environment variables or config files.",
    "Never commit secrets or API keys to Git.",
    "Align local, staging, and production settings.",
    "Use sample data or seed scripts for local setup.",
    "Document setup steps in a README.",
  ];

  const debuggingChecklist = [
    "Reproduce the issue reliably and note steps.",
    "Check logs and error messages for the first clue.",
    "Isolate the change with a binary search or git bisect.",
    "Use a debugger to inspect state at runtime.",
    "Add a test to prevent the bug from returning.",
  ];

  const securityBasics = [
    "Validate inputs and handle errors safely.",
    "Use least privilege for access and credentials.",
    "Keep dependencies updated and review advisories.",
    "Hash and salt passwords, never store plain text.",
    "Log security events without leaking sensitive data.",
  ];

  const performanceBasics = [
    "Measure before optimizing to avoid guesswork.",
    "Cache expensive work and reduce repeated calls.",
    "Avoid N+1 queries with batching or joins.",
    "Paginate large lists and stream big responses.",
    "Load test to understand capacity and bottlenecks.",
  ];

  const branchingStrategies = [
    { name: "Trunk-based", description: "Short-lived branches and fast merges to main." },
    { name: "GitHub flow", description: "Branch per feature, merge via pull request." },
    { name: "Git flow", description: "Separate develop and release branches for complex releases." },
  ];

  // ============ BEGINNER-FOCUSED CONTENT ============

  // What is code? - Explained simply
  const whatIsCodeExplanations = [
    {
      concept: "Code is Instructions",
      analogy: "Like a recipe for a chef",
      explanation: "Just like a recipe tells a chef what ingredients to use and steps to follow, code tells a computer exactly what to do, step by step. The computer follows your instructions precisely.",
    },
    {
      concept: "Programming Languages",
      analogy: "Like different human languages",
      explanation: "Just as humans speak English, Spanish, or Japanese, computers can understand different programming languages like Python, JavaScript, or Java. Each has its own vocabulary and grammar rules.",
    },
    {
      concept: "Variables Store Data",
      analogy: "Like labeled boxes",
      explanation: "Imagine labeled boxes where you store things. A variable called 'userName' might store 'Alice'. You can look inside the box, change what's in it, or use it in calculations.",
    },
    {
      concept: "Functions Do Tasks",
      analogy: "Like a microwave's buttons",
      explanation: "When you press 'Popcorn' on a microwave, it runs a preset sequence. Functions work the same way - you give them a name, define what they do, and call them whenever needed.",
    },
    {
      concept: "Loops Repeat Actions",
      analogy: "Like an alarm that repeats",
      explanation: "An alarm rings every day at 7am until you turn it off. Loops let code repeat actions - like 'send a reminder to each user in this list' or 'keep asking for password until correct'.",
    },
    {
      concept: "Conditionals Make Decisions",
      analogy: "Like a traffic light",
      explanation: "A traffic light checks conditions: if cars are waiting AND the timer expired, turn green. Code uses 'if' statements the same way: if user is logged in, show dashboard; otherwise, show login page.",
    },
  ];

  // How programs actually run
  const howProgramsRun = [
    {
      step: "1. You Write Code",
      description: "You type instructions in a text file using a programming language. This is called 'source code' - it's human-readable.",
      icon: "📝",
    },
    {
      step: "2. Code Gets Translated",
      description: "Computers only understand 1s and 0s. A compiler or interpreter translates your code into machine language the computer understands.",
      icon: "🔄",
    },
    {
      step: "3. Program Loads into Memory",
      description: "When you run the program, it's loaded into RAM (your computer's short-term memory) so the CPU can access it quickly.",
      icon: "💾",
    },
    {
      step: "4. CPU Executes Instructions",
      description: "The CPU (computer's brain) reads your instructions one by one and performs them - calculations, displaying text, saving files, etc.",
      icon: "🧠",
    },
    {
      step: "5. Program Interacts with World",
      description: "Your program might read keyboard input, display graphics, save to disk, or send data over the internet. These are 'inputs' and 'outputs'.",
      icon: "🌐",
    },
    {
      step: "6. Program Ends or Keeps Running",
      description: "Some programs finish and exit (like a calculator). Others keep running until stopped (like a web server waiting for requests 24/7).",
      icon: "🏁",
    },
  ];

  // Your first program - step by step
  const firstProgramSteps = [
    {
      step: "Install a Code Editor",
      details: "Download VS Code (free) from code.visualstudio.com. It's beginner-friendly and works on Windows, Mac, and Linux.",
      tip: "VS Code will be your workspace for writing, editing, and running code.",
    },
    {
      step: "Choose a First Language",
      details: "Python is recommended for beginners - it reads almost like English and forgives many mistakes. JavaScript is great if you want to build websites.",
      tip: "Don't worry about picking the 'wrong' language. Skills transfer between languages.",
    },
    {
      step: "Install the Language",
      details: "For Python: download from python.org. For JavaScript: it comes built into your browser, or install Node.js for running outside browsers.",
      tip: "Follow the official installation guide for your operating system.",
    },
    {
      step: "Write Hello World",
      details: "Create a new file (hello.py for Python or hello.js for JavaScript). Type: print('Hello, World!') for Python or console.log('Hello, World!'); for JavaScript.",
      tip: "This is tradition! Almost every programmer's first program prints 'Hello, World!'",
    },
    {
      step: "Run Your Program",
      details: "In VS Code, open the terminal (View > Terminal) and type 'python hello.py' or 'node hello.js'. You should see 'Hello, World!' printed.",
      tip: "If you see an error, read it carefully - errors tell you what went wrong and where.",
    },
    {
      step: "Experiment and Break Things",
      details: "Change the message, add more print statements, try removing a quote mark to see what error you get. Breaking code and fixing it is how you learn.",
      tip: "You cannot break your computer with code mistakes. The worst case is an error message!",
    },
  ];

  // Common beginner mistakes
  const beginnerMistakes = [
    {
      mistake: "Trying to learn everything at once",
      why: "There are hundreds of languages, frameworks, and tools. It's overwhelming.",
      solution: "Pick ONE language and stick with it for at least 3 months. Learn the basics deeply before exploring more.",
      severity: "high",
    },
    {
      mistake: "Only watching tutorials, never coding",
      why: "Watching feels productive but you don't build muscle memory or problem-solving skills.",
      solution: "For every hour of tutorial, spend two hours coding on your own. Build small projects, don't just follow along.",
      severity: "high",
    },
    {
      mistake: "Copying code without understanding",
      why: "You might get something working but won't know how to fix it or modify it.",
      solution: "Type code yourself (don't copy-paste). After each line, explain to yourself what it does. If you can't, look it up.",
      severity: "high",
    },
    {
      mistake: "Giving up when stuck",
      why: "Being stuck is frustrating, but it's where the real learning happens.",
      solution: "Take a break, ask for help, use Google, read documentation. Every developer gets stuck - the skill is learning to get unstuck.",
      severity: "medium",
    },
    {
      mistake: "Not using version control (Git)",
      why: "Without Git, one mistake can destroy hours of work. You can't track changes or collaborate.",
      solution: "Learn basic Git commands in your first month: init, add, commit, push, pull. Use GitHub to backup your code.",
      severity: "medium",
    },
    {
      mistake: "Skipping fundamentals for frameworks",
      why: "Jumping to React or Django without knowing JavaScript or Python basics leads to confusion.",
      solution: "Learn core language features first: variables, functions, loops, arrays, objects. Then add frameworks.",
      severity: "medium",
    },
    {
      mistake: "Comparing yourself to experienced developers",
      why: "Seeing polished code from 10-year veterans is discouraging when you're just starting.",
      solution: "Everyone was a beginner once. Compare yourself to yourself a month ago, not to experts.",
      severity: "low",
    },
    {
      mistake: "Not reading error messages",
      why: "Errors seem scary but they're actually helpful - they tell you exactly what went wrong.",
      solution: "Read the entire error message. Look for the file name, line number, and error type. Google the exact error text.",
      severity: "medium",
    },
  ];

  // Programming language comparison for beginners
  const languageComparison = [
    {
      language: "Python",
      difficulty: "Easy",
      bestFor: "Beginners, data science, automation, AI/ML",
      pros: ["Reads like English", "Huge community", "Versatile"],
      cons: ["Slower than compiled languages", "Not great for mobile apps"],
      firstProject: "A calculator, to-do list app, or web scraper",
    },
    {
      language: "JavaScript",
      difficulty: "Easy-Medium",
      bestFor: "Websites, web apps, full-stack development",
      pros: ["Runs in browsers", "Huge job market", "Can build anything web"],
      cons: ["Quirky behaviors", "Too many frameworks to choose from"],
      firstProject: "Interactive website, browser game, or Chrome extension",
    },
    {
      language: "Java",
      difficulty: "Medium",
      bestFor: "Enterprise apps, Android apps, large systems",
      pros: ["Strongly typed catches errors", "Huge enterprise use", "Platform independent"],
      cons: ["Verbose syntax", "Slower to write"],
      firstProject: "Android app, simple game, or command-line tool",
    },
    {
      language: "C#",
      difficulty: "Medium",
      bestFor: "Windows apps, games (Unity), enterprise",
      pros: ["Great tooling (Visual Studio)", "Strong typing", "Unity game engine"],
      cons: ["Historically Windows-focused", "Learning curve for OOP"],
      firstProject: "Unity game, Windows app, or ASP.NET website",
    },
    {
      language: "Go",
      difficulty: "Medium",
      bestFor: "Backend services, DevOps tools, cloud",
      pros: ["Simple syntax", "Fast execution", "Great for servers"],
      cons: ["Smaller ecosystem", "Less flexible"],
      firstProject: "CLI tool, REST API, or file processor",
    },
    {
      language: "Rust",
      difficulty: "Hard",
      bestFor: "Systems programming, performance-critical apps",
      pros: ["Memory safe", "Very fast", "Modern features"],
      cons: ["Steep learning curve", "Longer compile times"],
      firstProject: "Command-line tool or small game (after basics)",
    },
  ];

  // Real-world analogies for concepts
  const realWorldAnalogies = [
    {
      concept: "API (Application Programming Interface)",
      analogy: "A restaurant menu",
      explanation: "A menu tells you what dishes are available and how to order them, but hides the kitchen complexity. An API tells other programs what services are available and how to request them, hiding the internal code.",
    },
    {
      concept: "Database",
      analogy: "A giant filing cabinet",
      explanation: "A filing cabinet organizes documents in folders so you can find them quickly. A database organizes data in tables so programs can store, find, and update information efficiently.",
    },
    {
      concept: "Server",
      analogy: "A waiter in a restaurant",
      explanation: "A waiter takes your order (request), goes to the kitchen (processes it), and brings back your food (response). A server receives requests from users, processes them, and sends back data.",
    },
    {
      concept: "Frontend vs Backend",
      analogy: "A store's showroom vs warehouse",
      explanation: "The showroom (frontend) is what customers see - displays, layout, design. The warehouse (backend) is hidden but essential - inventory, processing, logistics. Both must work together.",
    },
    {
      concept: "Bug",
      analogy: "A typo in a recipe",
      explanation: "If a recipe says 'add 1 cup of salt' instead of '1 teaspoon', the dish is ruined. A bug is a mistake in code that causes wrong behavior. Finding and fixing bugs is called 'debugging'.",
    },
    {
      concept: "Debugging",
      analogy: "Detective work",
      explanation: "Like a detective gathering clues to solve a mystery, debugging involves following evidence (error messages, logs, behavior) to find where and why your code is misbehaving.",
    },
    {
      concept: "Git Repository",
      analogy: "A Google Doc with version history",
      explanation: "Google Docs saves every version so you can see changes and restore old versions. Git does this for code - tracking every change, who made it, when, and why.",
    },
    {
      concept: "Deployment",
      analogy: "Opening night for a play",
      explanation: "After rehearsals (development and testing), the play goes live for audiences (deployment). If something goes wrong, you might need to cancel the show (rollback) and fix it.",
    },
  ];

  // Glossary for beginners
  const beginnerGlossary = [
    { term: "Algorithm", definition: "A step-by-step procedure to solve a problem, like a recipe for code." },
    { term: "Array", definition: "A list that holds multiple items, like a shopping list with numbered items." },
    { term: "Boolean", definition: "A value that is either true or false, like a yes/no answer." },
    { term: "Bug", definition: "An error or flaw in code that causes unexpected behavior." },
    { term: "Class", definition: "A blueprint for creating objects with specific properties and behaviors." },
    { term: "Compile", definition: "Convert human-readable code into machine code the computer can run." },
    { term: "Console", definition: "A text-based interface for running commands and seeing program output." },
    { term: "Debug", definition: "Find and fix errors in your code." },
    { term: "Deploy", definition: "Make your application available for users, typically on a server." },
    { term: "Framework", definition: "Pre-built code structure that helps you build applications faster." },
    { term: "Function", definition: "A reusable block of code that performs a specific task." },
    { term: "IDE", definition: "Integrated Development Environment - software for writing and running code." },
    { term: "Library", definition: "Pre-written code you can use in your projects to avoid reinventing the wheel." },
    { term: "Loop", definition: "Code that repeats a block of instructions multiple times." },
    { term: "Object", definition: "A collection of related data and functions bundled together." },
    { term: "Parameter", definition: "A value you pass into a function so it knows what to work with." },
    { term: "Repository (Repo)", definition: "A storage location for code, typically managed by Git." },
    { term: "Runtime", definition: "When the program is actually running, as opposed to when you're writing it." },
    { term: "Syntax", definition: "The grammar rules of a programming language - how code must be written." },
    { term: "Variable", definition: "A named container that stores a value you can use and change." },
  ];

  // FAQ for beginners
  const beginnerFAQ = [
    {
      question: "Do I need to be good at math to code?",
      answer: "Not really! Most programming uses basic math (add, subtract, multiply, compare). Advanced math is only needed for specific fields like game physics, machine learning, or cryptography. Logic and problem-solving matter more than calculus.",
    },
    {
      question: "How long does it take to learn to code?",
      answer: "You can write simple programs in a few weeks. Basic competency takes 3-6 months of regular practice. Getting job-ready typically takes 6-12 months of focused learning and building projects. Mastery is a lifelong journey.",
    },
    {
      question: "Should I learn multiple languages at once?",
      answer: "No! Start with one language and stick with it for at least 3-6 months. Once you know one language well, picking up others becomes much easier because concepts transfer.",
    },
    {
      question: "Do I need a computer science degree?",
      answer: "No. Many successful developers are self-taught or bootcamp graduates. What matters is: can you build things that work? A portfolio of projects often matters more than credentials.",
    },
    {
      question: "Is it too late to start coding?",
      answer: "Absolutely not. People successfully switch careers to software development in their 30s, 40s, and beyond. Your life experience can actually be an advantage - you understand real problems.",
    },
    {
      question: "What computer do I need?",
      answer: "Almost any computer from the last 5-10 years works for learning. You don't need a gaming PC or expensive Mac. Even a $300 laptop can run VS Code and learn most languages.",
    },
    {
      question: "How do I stay motivated when it's hard?",
      answer: "Build projects you care about. Join a community (Discord, Reddit, local meetups). Celebrate small wins. Remember that confusion means you're learning. Take breaks when frustrated.",
    },
    {
      question: "What if I feel like an imposter?",
      answer: "Imposter syndrome is extremely common, even among senior developers. Remember: everyone Googles things, everyone forgets syntax, everyone was a beginner once. Focus on learning, not on feeling like you 'should' know things.",
    },
  ];

  // Practical exercises for beginners
  const practicalExercises = [
    {
      name: "Hello World Variations",
      difficulty: "Beginner",
      description: "Modify Hello World to greet the user by name, print multiple lines, or use different colors.",
      skills: ["Print statements", "Variables", "String concatenation"],
      time: "15 minutes",
    },
    {
      name: "Simple Calculator",
      difficulty: "Beginner",
      description: "Build a calculator that takes two numbers and performs add, subtract, multiply, divide.",
      skills: ["User input", "Variables", "Arithmetic", "Conditionals"],
      time: "30 minutes",
    },
    {
      name: "Number Guessing Game",
      difficulty: "Beginner",
      description: "Computer picks a random number 1-100. User guesses until correct, getting 'higher' or 'lower' hints.",
      skills: ["Loops", "Conditionals", "Random numbers", "User input"],
      time: "45 minutes",
    },
    {
      name: "To-Do List (Command Line)",
      difficulty: "Beginner-Intermediate",
      description: "Create a to-do app where users can add tasks, mark complete, and list all tasks.",
      skills: ["Arrays/Lists", "Functions", "Loops", "File I/O (optional)"],
      time: "1-2 hours",
    },
    {
      name: "Rock Paper Scissors",
      difficulty: "Beginner",
      description: "Play rock-paper-scissors against the computer. Track wins, losses, and ties.",
      skills: ["Conditionals", "Random choice", "Loops", "Score tracking"],
      time: "45 minutes",
    },
    {
      name: "Temperature Converter",
      difficulty: "Beginner",
      description: "Convert between Celsius, Fahrenheit, and Kelvin. Let user choose direction.",
      skills: ["Functions", "Math operations", "User input", "Conditionals"],
      time: "30 minutes",
    },
    {
      name: "Word Counter",
      difficulty: "Beginner",
      description: "Count words, characters, and sentences in a text input. Show statistics.",
      skills: ["String manipulation", "Loops", "Counting", "Functions"],
      time: "30 minutes",
    },
    {
      name: "Simple Quiz App",
      difficulty: "Beginner-Intermediate",
      description: "Multiple-choice quiz with questions stored in arrays. Track score and show results.",
      skills: ["Arrays of objects", "Loops", "Conditionals", "Score calculation"],
      time: "1-2 hours",
    },
  ];

  // Daily coding habits
  const dailyCodingHabits = [
    { habit: "Code for at least 30 minutes", why: "Consistency beats intensity. Daily practice builds lasting skills and habits." },
    { habit: "Read one error message completely", why: "Errors are teachers. Understanding them makes you a better debugger." },
    { habit: "Look up one new concept", why: "Small daily learning compounds into deep knowledge over time." },
    { habit: "Comment your code", why: "Explaining code helps you understand it and helps future-you remember." },
    { habit: "Review code you wrote yesterday", why: "Fresh eyes catch mistakes and reveal ways to improve." },
    { habit: "Ask one question (even to Google)", why: "Asking questions is a skill. Practice getting unstuck independently." },
  ];

  // Motivation quotes
  const motivationForBeginners = [
    { quote: "Every expert was once a beginner.", author: "Helen Hayes" },
    { quote: "The only way to learn a new programming language is by writing programs in it.", author: "Dennis Ritchie" },
    { quote: "First, solve the problem. Then, write the code.", author: "John Johnson" },
    { quote: "Code is like humor. When you have to explain it, it's bad.", author: "Cory House" },
    { quote: "The best error message is the one that never shows up.", author: "Thomas Fuchs" },
  ];

  const projectStructure = [
    { path: "src/", purpose: "Application code and main entry points." },
    { path: "tests/", purpose: "Unit, integration, and end-to-end tests." },
    { path: "docs/", purpose: "Project documentation and guides." },
    { path: "configs/", purpose: "Environment-specific settings and tooling config." },
    { path: "scripts/", purpose: "Automation scripts for setup and maintenance." },
  ];

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  // Module navigation items
  const moduleNavItems = [
    { id: "introduction", label: "Introduction", icon: "📖" },
    { id: "new-to-coding", label: "New to Coding?", icon: "🌟" },
    { id: "what-is-code", label: "What is Code?", icon: "💡" },
    { id: "how-programs-run", label: "How Programs Run", icon: "⚙️" },
    { id: "first-program", label: "Your First Program", icon: "🚀" },
    { id: "language-guide", label: "Language Guide", icon: "🗺️" },
    { id: "beginner-mistakes", label: "Common Mistakes", icon: "⚠️" },
    { id: "real-world-analogies", label: "Real-World Analogies", icon: "🔗" },
    { id: "practice-exercises", label: "Practice Exercises", icon: "💪" },
    { id: "beginner-faq", label: "Beginner FAQ", icon: "❓" },
    { id: "glossary", label: "Glossary", icon: "📚" },
    { id: "engineering-mindset", label: "Engineering Mindset", icon: "🧠" },
    { id: "learning-plan", label: "Learning Plan", icon: "📋" },
    { id: "tooling-ides", label: "Tooling & IDEs", icon: "🔧" },
    { id: "git-github", label: "Git & GitHub", icon: "🐙" },
    { id: "workflow", label: "Dev Workflow", icon: "⚡" },
    { id: "project-structure", label: "Project Structure", icon: "📁" },
    { id: "clean-code", label: "Clean Code", icon: "✨" },
    { id: "debugging", label: "Debugging", icon: "🐛" },
    { id: "sdlc", label: "SDLC", icon: "🔄" },
    { id: "methodologies", label: "Methodologies", icon: "📊" },
    { id: "testing-quality", label: "Testing & Quality", icon: "✅" },
    { id: "security-reliability", label: "Security & Reliability", icon: "🔒" },
    { id: "delivery-ops", label: "Delivery & Ops", icon: "🚀" },
    { id: "performance", label: "Performance", icon: "⚡" },
    { id: "team-practices", label: "Team Practices", icon: "👥" },
    { id: "specializations", label: "Specializations", icon: "🎯" },
    { id: "starter-checklist", label: "Starter Checklist", icon: "📝" },
    { id: "quiz-section", label: "Quiz", icon: "❓" },
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
        border: `1px solid ${alpha("#f97316", 0.15)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        display: { xs: "none", lg: "block" },
        "&::-webkit-scrollbar": {
          width: 6,
        },
        "&::-webkit-scrollbar-thumb": {
          bgcolor: alpha("#f97316", 0.3),
          borderRadius: 3,
        },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f97316", display: "flex", alignItems: "center", gap: 1 }}>
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">Progress</Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: "#f97316" }}>{Math.round(progressPercent)}%</Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha("#f97316", 0.1),
              "& .MuiLinearProgress-bar": {
                bgcolor: "#f97316",
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
                bgcolor: activeSection === item.id ? alpha("#f97316", 0.15) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid #f97316` : "3px solid transparent",
                "&:hover": {
                  bgcolor: alpha("#f97316", 0.08),
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
                      color: activeSection === item.id ? "#f97316" : "text.secondary",
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
    <LearnPageLayout pageTitle="Software Engineering Fundamentals" pageContext={pageContext}>
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
            bgcolor: "#f97316",
            "&:hover": { bgcolor: "#ea580c" },
            boxShadow: `0 4px 20px ${alpha("#f97316", 0.4)}`,
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
            bgcolor: alpha("#f97316", 0.15),
            color: "#f97316",
            "&:hover": { bgcolor: alpha("#f97316", 0.25) },
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
              <ListAltIcon sx={{ color: "#f97316" }} />
              Course Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} size="small">
              <CloseIcon />
            </IconButton>
          </Box>
          
          <Divider sx={{ mb: 2 }} />

          {/* Progress indicator */}
          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha("#f97316", 0.05) }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">Progress</Typography>
              <Typography variant="caption" sx={{ fontWeight: 600, color: "#f97316" }}>{Math.round(progressPercent)}%</Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{
                height: 6,
                borderRadius: 3,
                bgcolor: alpha("#f97316", 0.1),
                "& .MuiLinearProgress-bar": {
                  bgcolor: "#f97316",
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
                  bgcolor: activeSection === item.id ? alpha("#f97316", 0.15) : "transparent",
                  borderLeft: activeSection === item.id ? `3px solid #f97316` : "3px solid transparent",
                  "&:hover": {
                    bgcolor: alpha("#f97316", 0.1),
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
                        color: activeSection === item.id ? "#f97316" : "text.primary",
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
                      bgcolor: alpha("#f97316", 0.2),
                      color: "#f97316",
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
              sx={{ flex: 1, borderColor: alpha("#f97316", 0.3), color: "#f97316" }}
            >
              Top
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => scrollToSection("quiz-section")}
              startIcon={<QuizIcon />}
              sx={{ flex: 1, borderColor: alpha("#f97316", 0.3), color: "#f97316" }}
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
        <Chip
          icon={<ArrowBackIcon />}
          label="Back to Learning Hub"
          onClick={() => navigate("/learn")}
          sx={{ mb: 3, fontWeight: 600, cursor: "pointer" }}
          clickable
        />

        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#f97316", 0.15)} 0%, ${alpha("#ea580c", 0.12)} 50%, ${alpha("#dc2626", 0.1)} 100%)`,
            border: `1px solid ${alpha("#f97316", 0.2)}`,
            position: "relative",
            overflow: "hidden",
          }}
        >
          <Box
            sx={{
              position: "absolute",
              top: -60,
              right: -40,
              width: 220,
              height: 220,
              borderRadius: "50%",
              background: `radial-gradient(circle, ${alpha("#f97316", 0.15)} 0%, transparent 70%)`,
            }}
          />
          <Box
            sx={{
              position: "absolute",
              bottom: -40,
              left: "30%",
              width: 180,
              height: 180,
              borderRadius: "50%",
              background: `radial-gradient(circle, ${alpha("#ea580c", 0.15)} 0%, transparent 70%)`,
            }}
          />

          <Box sx={{ position: "relative", zIndex: 1 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
              <Box
                sx={{
                  width: 80,
                  height: 80,
                  borderRadius: 3,
                  background: "linear-gradient(135deg, #f97316, #dc2626)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  boxShadow: `0 8px 32px ${alpha("#f97316", 0.35)}`,
                }}
              >
                <SchoolIcon sx={{ fontSize: 44, color: "white" }} />
              </Box>
              <Box>
                <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                  Software Engineering Fundamentals
                </Typography>
                <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                  Tools, workflows, and core concepts for beginners
                </Typography>
              </Box>
            </Box>

            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
              <Chip label="Beginner" color="warning" />
              <Chip label="Tools" sx={{ bgcolor: alpha("#3b82f6", 0.15), color: "#3b82f6", fontWeight: 600 }} />
              <Chip label="Git and GitHub" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
              <Chip label="Workflows" sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }} />
              <Chip label="Software Engineering" sx={{ bgcolor: alpha("#f97316", 0.15), color: "#f97316", fontWeight: 600 }} />
            </Box>

            <Grid container spacing={2}>
              {quickStats.map((stat) => (
                <Grid item xs={6} sm={3} key={stat.label}>
                  <Paper
                    sx={{
                      p: 2,
                      textAlign: "center",
                      borderRadius: 2,
                      bgcolor: alpha(stat.color, 0.1),
                      border: `1px solid ${alpha(stat.color, 0.2)}`,
                    }}
                  >
                    <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>
                      {stat.value}
                    </Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
                      {stat.label}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Box>
        </Paper>

        <Paper
          id="introduction"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                background: "linear-gradient(135deg, #f97316, #ea580c)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <SchoolIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            Software Engineering Explained
          </Typography>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.7 }}>
            Software engineering is the practice of building reliable software by applying engineering principles.
            It is not just about writing code, it is about turning a problem into a well designed system that can
            be built, tested, shipped, and maintained over time. You start by understanding the problem and writing
            clear requirements, then design the system, implement it with clean code, verify it with tests, deploy it,
            and keep it healthy with monitoring and maintenance.
          </Typography>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.7 }}>
            Beginners often focus on syntax and forget the bigger picture. Good software engineers balance tradeoffs:
            speed vs quality, features vs simplicity, and performance vs cost. Tools like VS Code and Visual Studio help
            you write and debug code, while Git and GitHub help teams collaborate safely. Understanding the process gives
            you structure so you can ship software that others can trust and build on.
          </Typography>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.7 }}>
            The field is broad. Web developers build user interfaces and APIs, mobile developers target iOS and Android,
            backend engineers design data systems, and DevOps engineers automate delivery. This page gives you a complete
            foundation: core concepts, essential tools, Git workflows, and a roadmap to choose a specialization.
          </Typography>
        </Paper>

        {/* ============ BEGINNER SECTIONS ============ */}

        {/* New to Coding? Start Here */}
        <Paper
          id="new-to-coding"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#22c55e", 0.15)} 0%, ${alpha("#10b981", 0.1)} 100%)`,
            border: `2px solid ${alpha("#22c55e", 0.3)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2, color: "#22c55e" }}>
            <Box sx={{ fontSize: 40 }}>🌟</Box>
            New to Coding? Start Here!
          </Typography>
          <Typography variant="h6" sx={{ mb: 3, lineHeight: 1.7 }}>
            Welcome! If you've never written a line of code before, you're in the right place. This section will take you from zero to writing your first program.
          </Typography>
          <Grid container spacing={2}>
            {[
              { label: "No prior experience needed", icon: "✅" },
              { label: "Learn at your own pace", icon: "⏰" },
              { label: "Hands-on exercises included", icon: "💪" },
              { label: "Common questions answered", icon: "❓" },
            ].map((item) => (
              <Grid item xs={6} sm={3} key={item.label}>
                <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, bgcolor: alpha("#22c55e", 0.1) }}>
                  <Typography variant="h5" sx={{ mb: 1 }}>{item.icon}</Typography>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>{item.label}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
          <Alert severity="success" sx={{ mt: 3 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>You Can Do This!</AlertTitle>
            Millions of people have learned to code with no prior experience. The key is consistency, curiosity, and not being afraid to make mistakes. Every error is a learning opportunity.
          </Alert>
        </Paper>

        {/* What is Code? */}
        <Paper id="what-is-code" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ fontSize: 32 }}>💡</Box>
            What is Code? (Explained Simply)
          </Typography>
          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.7 }}>
            Code is just instructions written in a language computers can understand. Think of it like writing a very precise recipe - the computer follows your instructions exactly, step by step.
          </Typography>
          <Grid container spacing={3}>
            {whatIsCodeExplanations.map((item, i) => (
              <Grid item xs={12} md={6} key={i}>
                <Paper
                  sx={{
                    p: 3,
                    height: "100%",
                    borderRadius: 3,
                    bgcolor: alpha("#f97316", 0.05),
                    border: `1px solid ${alpha("#f97316", 0.2)}`,
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                    <Chip label={item.analogy} size="small" sx={{ bgcolor: alpha("#f97316", 0.15), color: "#f97316", fontWeight: 600 }} />
                  </Box>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>{item.concept}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>
                    {item.explanation}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* How Programs Run */}
        <Paper id="how-programs-run" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ fontSize: 32 }}>⚙️</Box>
            How Programs Actually Run
          </Typography>
          <Typography variant="body1" sx={{ mb: 3 }}>
            Ever wondered what happens when you run a program? Here's the journey from your code to results on screen:
          </Typography>
          <Grid container spacing={2}>
            {howProgramsRun.map((item, i) => (
              <Grid item xs={12} sm={6} md={4} key={i}>
                <Paper
                  sx={{
                    p: 3,
                    height: "100%",
                    borderRadius: 3,
                    bgcolor: alpha("#3b82f6", 0.05),
                    border: `1px solid ${alpha("#3b82f6", 0.15)}`,
                    textAlign: "center",
                  }}
                >
                  <Typography variant="h3" sx={{ mb: 2 }}>{item.icon}</Typography>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>{item.step}</Typography>
                  <Typography variant="body2" color="text.secondary">{item.description}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Your First Program */}
        <Paper id="first-program" sx={{ p: 4, mb: 5, borderRadius: 4, bgcolor: alpha("#8b5cf6", 0.03) }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ fontSize: 32 }}>🚀</Box>
            Your First Program: Step by Step
          </Typography>
          <Typography variant="body1" sx={{ mb: 3 }}>
            Ready to write your first program? Follow these steps and you'll have code running in about 15 minutes.
          </Typography>
          {firstProgramSteps.map((item, i) => (
            <Paper key={i} sx={{ p: 3, mb: 2, borderRadius: 2, border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
              <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2 }}>
                <Box
                  sx={{
                    width: 40,
                    height: 40,
                    borderRadius: "50%",
                    bgcolor: "#8b5cf6",
                    color: "#fff",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontWeight: 700,
                    flexShrink: 0,
                  }}
                >
                  {i + 1}
                </Box>
                <Box sx={{ flex: 1 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>{item.step}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>{item.details}</Typography>
                  <Chip
                    icon={<TipsAndUpdatesIcon sx={{ fontSize: 16 }} />}
                    label={item.tip}
                    size="small"
                    sx={{ bgcolor: alpha("#22c55e", 0.1), color: "#22c55e" }}
                  />
                </Box>
              </Box>
            </Paper>
          ))}
          <Paper sx={{ p: 3, mt: 3, borderRadius: 2, bgcolor: alpha("#22c55e", 0.1), border: `1px solid ${alpha("#22c55e", 0.3)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
              <CodeIcon /> Example: Hello World in Python
            </Typography>
            <Box
              sx={{
                p: 2,
                bgcolor: "#1e1e1e",
                borderRadius: 2,
                fontFamily: "monospace",
                color: "#d4d4d4",
                fontSize: "0.9rem",
              }}
            >
              <Box component="span" sx={{ color: "#c586c0" }}>print</Box>
              <Box component="span" sx={{ color: "#d4d4d4" }}>(</Box>
              <Box component="span" sx={{ color: "#ce9178" }}>'Hello, World!'</Box>
              <Box component="span" sx={{ color: "#d4d4d4" }}>)</Box>
            </Box>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
              That's it! One line of code. When you run this, you'll see "Hello, World!" printed on your screen. Congratulations - you're officially a programmer!
            </Typography>
          </Paper>
        </Paper>

        {/* Language Comparison Guide */}
        <Paper id="language-guide" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ fontSize: 32 }}>🗺️</Box>
            Which Programming Language Should I Learn?
          </Typography>
          <Typography variant="body1" sx={{ mb: 3 }}>
            There's no single "best" language. Pick one based on what you want to build. Here's an honest comparison:
          </Typography>
          <Grid container spacing={3}>
            {languageComparison.map((lang) => (
              <Grid item xs={12} md={6} key={lang.language}>
                <Paper
                  sx={{
                    p: 3,
                    height: "100%",
                    borderRadius: 3,
                    border: `1px solid ${alpha(
                      lang.difficulty === "Easy" ? "#22c55e" : lang.difficulty === "Hard" ? "#ef4444" : "#f59e0b",
                      0.3
                    )}`,
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                    <Typography variant="h6" sx={{ fontWeight: 700 }}>{lang.language}</Typography>
                    <Chip
                      label={lang.difficulty}
                      size="small"
                      sx={{
                        bgcolor: alpha(
                          lang.difficulty === "Easy" ? "#22c55e" : lang.difficulty === "Hard" ? "#ef4444" : "#f59e0b",
                          0.15
                        ),
                        color: lang.difficulty === "Easy" ? "#22c55e" : lang.difficulty === "Hard" ? "#ef4444" : "#f59e0b",
                        fontWeight: 600,
                      }}
                    />
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    <strong>Best for:</strong> {lang.bestFor}
                  </Typography>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="caption" sx={{ fontWeight: 600, color: "#22c55e" }}>Pros:</Typography>
                    <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", mt: 0.5 }}>
                      {lang.pros.map((pro) => (
                        <Chip key={pro} label={pro} size="small" sx={{ bgcolor: alpha("#22c55e", 0.1), fontSize: "0.7rem" }} />
                      ))}
                    </Box>
                  </Box>
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="caption" sx={{ fontWeight: 600, color: "#ef4444" }}>Cons:</Typography>
                    <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", mt: 0.5 }}>
                      {lang.cons.map((con) => (
                        <Chip key={con} label={con} size="small" sx={{ bgcolor: alpha("#ef4444", 0.1), fontSize: "0.7rem" }} />
                      ))}
                    </Box>
                  </Box>
                  <Typography variant="caption" color="text.secondary">
                    <strong>First project idea:</strong> {lang.firstProject}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
          <Alert severity="info" sx={{ mt: 3 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Recommendation for Absolute Beginners</AlertTitle>
            Start with <strong>Python</strong> if you want to learn programming concepts with the simplest syntax. Start with <strong>JavaScript</strong> if you're excited about building websites. Either choice is great!
          </Alert>
        </Paper>

        {/* Common Beginner Mistakes */}
        <Paper id="beginner-mistakes" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2, color: "#ef4444" }}>
            <WarningIcon sx={{ color: "#ef4444", fontSize: 32 }} />
            Common Beginner Mistakes (and How to Avoid Them)
          </Typography>
          <Typography variant="body1" sx={{ mb: 3 }}>
            Learn from others' mistakes so you don't have to make them yourself. These are the most common traps new programmers fall into:
          </Typography>
          <Grid container spacing={2}>
            {beginnerMistakes.map((item, i) => (
              <Grid item xs={12} md={6} key={i}>
                <Paper
                  sx={{
                    p: 3,
                    height: "100%",
                    borderRadius: 2,
                    borderLeft: `4px solid ${
                      item.severity === "high" ? "#ef4444" : item.severity === "medium" ? "#f59e0b" : "#3b82f6"
                    }`,
                    bgcolor: alpha(
                      item.severity === "high" ? "#ef4444" : item.severity === "medium" ? "#f59e0b" : "#3b82f6",
                      0.03
                    ),
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <WarningIcon
                      sx={{
                        color: item.severity === "high" ? "#ef4444" : item.severity === "medium" ? "#f59e0b" : "#3b82f6",
                        fontSize: 20,
                      }}
                    />
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{item.mistake}</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
                    <strong>Why it happens:</strong> {item.why}
                  </Typography>
                  <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                    <CheckCircleIcon sx={{ color: "#22c55e", fontSize: 18, mt: 0.3 }} />
                    <Typography variant="body2"><strong>Solution:</strong> {item.solution}</Typography>
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Real-World Analogies */}
        <Paper id="real-world-analogies" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ fontSize: 32 }}>🔗</Box>
            Real-World Analogies for Programming Concepts
          </Typography>
          <Typography variant="body1" sx={{ mb: 3 }}>
            Programming concepts make more sense when connected to everyday things you already understand:
          </Typography>
          <Grid container spacing={3}>
            {realWorldAnalogies.map((item, i) => (
              <Grid item xs={12} md={6} key={i}>
                <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03) }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                    <Typography variant="h6" sx={{ fontWeight: 700 }}>{item.concept}</Typography>
                  </Box>
                  <Chip
                    label={`"Like ${item.analogy}"`}
                    size="small"
                    sx={{ mb: 2, bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }}
                  />
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>
                    {item.explanation}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Practice Exercises */}
        <Paper id="practice-exercises" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ fontSize: 32 }}>💪</Box>
            Practice Exercises for Beginners
          </Typography>
          <Typography variant="body1" sx={{ mb: 3 }}>
            Learning by doing is the fastest way to improve. Try these exercises in order of difficulty:
          </Typography>
          <Grid container spacing={2}>
            {practicalExercises.map((ex, i) => (
              <Grid item xs={12} sm={6} md={4} key={i}>
                <Paper
                  sx={{
                    p: 2.5,
                    height: "100%",
                    borderRadius: 2,
                    border: `1px solid ${alpha("#f97316", 0.2)}`,
                    "&:hover": { borderColor: "#f97316", boxShadow: `0 4px 20px ${alpha("#f97316", 0.15)}` },
                    transition: "all 0.2s ease",
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{ex.name}</Typography>
                    <Chip
                      label={ex.difficulty}
                      size="small"
                      sx={{
                        bgcolor: alpha(ex.difficulty === "Beginner" ? "#22c55e" : "#f59e0b", 0.15),
                        color: ex.difficulty === "Beginner" ? "#22c55e" : "#f59e0b",
                        fontSize: "0.65rem",
                      }}
                    />
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    {ex.description}
                  </Typography>
                  <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", mb: 1.5 }}>
                    {ex.skills.map((skill) => (
                      <Chip key={skill} label={skill} size="small" sx={{ fontSize: "0.65rem", height: 22 }} />
                    ))}
                  </Box>
                  <Typography variant="caption" color="text.secondary">
                    Estimated time: {ex.time}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
          <Paper sx={{ p: 3, mt: 3, borderRadius: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Daily Coding Habits for Success</Typography>
            <Grid container spacing={2}>
              {dailyCodingHabits.map((item, i) => (
                <Grid item xs={12} sm={6} key={i}>
                  <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                    <CheckCircleIcon sx={{ color: "#10b981", fontSize: 18, mt: 0.3 }} />
                    <Box>
                      <Typography variant="body2" sx={{ fontWeight: 600 }}>{item.habit}</Typography>
                      <Typography variant="caption" color="text.secondary">{item.why}</Typography>
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>
        </Paper>

        {/* Beginner FAQ */}
        <Paper id="beginner-faq" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ fontSize: 32 }}>❓</Box>
            Frequently Asked Questions (Beginner Edition)
          </Typography>
          {beginnerFAQ.map((item, i) => (
            <Accordion key={i} defaultExpanded={i === 0}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontWeight: 700 }}>{item.question}</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" sx={{ lineHeight: 1.7 }}>{item.answer}</Typography>
              </AccordionDetails>
            </Accordion>
          ))}
        </Paper>

        {/* Glossary */}
        <Paper id="glossary" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box sx={{ fontSize: 32 }}>📚</Box>
            Beginner's Glossary
          </Typography>
          <Typography variant="body1" sx={{ mb: 3 }}>
            Don't know what a term means? Here's a quick reference for the most common programming vocabulary:
          </Typography>
          <Grid container spacing={1}>
            {beginnerGlossary.map((item, i) => (
              <Grid item xs={12} sm={6} md={4} key={i}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.03), height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 0.5 }}>
                    {item.term}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {item.definition}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* Motivational Quote */}
        <Paper
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#f97316", 0.1)} 0%, ${alpha("#8b5cf6", 0.1)} 100%)`,
            textAlign: "center",
          }}
        >
          <Typography variant="h4" sx={{ fontStyle: "italic", mb: 2 }}>
            "{motivationForBeginners[0].quote}"
          </Typography>
          <Typography variant="body1" color="text.secondary">
            — {motivationForBeginners[0].author}
          </Typography>
        </Paper>

        {/* ============ END BEGINNER SECTIONS ============ */}

        <Paper id="engineering-mindset" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <TipsAndUpdatesIcon sx={{ color: "#f97316" }} />
            Engineering Mindset and Quality Attributes
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            Great engineers think in tradeoffs. Every design decision impacts speed, cost, quality, and risk. The goal
            is not perfection, it is balancing the right attributes for your users and constraints.
          </Typography>
          <Grid container spacing={2}>
            {qualityAttributes.map((attribute) => (
              <Grid item xs={12} sm={6} md={4} key={attribute.name}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha(attribute.color, 0.08), border: `1px solid ${alpha(attribute.color, 0.2)}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: attribute.color, mb: 0.5 }}>
                    {attribute.name}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {attribute.description}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
          <Divider sx={{ my: 3 }} />
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                Branching Strategies
              </Typography>
              <List dense>
                {branchingStrategies.map((strategy) => (
                  <ListItem key={strategy.name} sx={{ px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ color: "#f97316", fontSize: 20 }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={strategy.name}
                      secondary={strategy.description}
                    />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                Commit and Review Hygiene
              </Typography>
              <List dense>
                {[
                  "Write clear commit messages that explain why a change exists.",
                  "Keep commits small and focused to simplify review.",
                  "Describe the impact and testing in pull requests.",
                  "Use code review comments as learning opportunities.",
                ].map((item) => (
                  <ListItem key={item} sx={{ px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CodeIcon sx={{ color: "#f97316", fontSize: 20 }} />
                    </ListItemIcon>
                    <ListItemText primary={item} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>
        </Paper>

        <Paper id="learning-plan" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <TipsAndUpdatesIcon sx={{ color: "#f97316" }} />
            Comprehensive Learning Plan
          </Typography>
          <Grid container spacing={3}>
            {learningPlan.map((phase) => (
              <Grid item xs={12} md={6} key={phase.title}>
                <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha("#f97316", 0.05) }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
                    {phase.title}
                  </Typography>
                  <List dense>
                    {phase.items.map((item) => (
                      <ListItem key={item} sx={{ px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 32 }}>
                          <CheckCircleIcon sx={{ color: "#f97316" }} />
                        </ListItemIcon>
                        <ListItemText primary={item} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        <Paper id="tooling-ides" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <BuildIcon sx={{ color: "#f97316" }} />
            Tooling and IDEs
          </Typography>
          <Typography variant="body1" sx={{ mb: 3 }}>
            Your tools shape your workflow. Most beginners start with VS Code because it is lightweight and flexible,
            while Visual Studio, IntelliJ IDEA, and Xcode provide powerful IDE features out of the box. The goal is not
            to memorize every tool but to understand what each category does and when to use it.
          </Typography>
          <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Category</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Examples</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {toolingRows.map((row) => (
                  <TableRow key={row.category}>
                    <TableCell sx={{ fontWeight: 600 }}>{row.category}</TableCell>
                    <TableCell>{row.examples}</TableCell>
                    <TableCell>{row.purpose}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
          <Typography variant="h6" sx={{ fontWeight: 700, mt: 3, mb: 2 }}>
            IDE Selection Guide
          </Typography>
          <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Tool</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Best For</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Notes</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {ideGuideRows.map((row) => (
                  <TableRow key={row.tool}>
                    <TableCell sx={{ fontWeight: 600 }}>{row.tool}</TableCell>
                    <TableCell>{row.bestFor}</TableCell>
                    <TableCell>{row.notes}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
          <Alert severity="info" sx={{ mt: 3 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Beginner Tip</AlertTitle>
            Pick one editor or IDE and learn it well before switching. Productivity comes from mastery, not from having
            every tool installed.
          </Alert>
        </Paper>

        <Paper id="git-github" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <GitHubIcon sx={{ color: "#f97316" }} />
            Git and GitHub Fundamentals
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <List>
                <ListItem>
                  <ListItemIcon>
                    <CodeIcon sx={{ color: "#f97316" }} />
                  </ListItemIcon>
                  <ListItemText
                    primary="Git tracks your history"
                    secondary="Commit small, clear changes so you can understand and undo them later."
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <AccountTreeIcon sx={{ color: "#f97316" }} />
                  </ListItemIcon>
                  <ListItemText
                    primary="Branches let you work safely"
                    secondary="Create a new branch for each feature or fix to avoid breaking main."
                  />
                </ListItem>
                <ListItem>
                  <ListItemIcon>
                    <BuildIcon sx={{ color: "#f97316" }} />
                  </ListItemIcon>
                  <ListItemText
                    primary="Pull requests enable review"
                    secondary="Ask teammates to review changes before merging into the main branch."
                  />
                </ListItem>
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 3, bgcolor: alpha("#f97316", 0.05) }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                  Typical Git Workflow
                </Typography>
                <List dense>
                  {[
                    "Clone the repository to your machine.",
                    "Create a branch for your work.",
                    "Commit changes with clear messages.",
                    "Push the branch to GitHub.",
                    "Open a pull request and request review.",
                    "Merge after checks pass.",
                  ].map((step) => (
                    <ListItem key={step} sx={{ px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}>
                        <CheckCircleIcon sx={{ color: "#f97316", fontSize: 20 }} />
                      </ListItemIcon>
                      <ListItemText primary={step} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>
        </Paper>

        <Paper id="workflow" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <TerminalIcon sx={{ color: "#f97316" }} />
            Development Workflow Essentials
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={7}>
              <Typography variant="body1" sx={{ mb: 2 }}>
                A consistent workflow makes you faster and reduces mistakes. Most teams follow a loop: plan work,
                implement changes locally, test, review, and deploy. Build habits that keep your projects healthy.
              </Typography>
              <List>
                {[
                  "Set up a clean local environment with dependencies and configuration.",
                  "Run the app locally and learn how to debug errors.",
                  "Write tests for key logic and run them before committing.",
                  "Use code review to catch issues early.",
                  "Automate checks with continuous integration.",
                ].map((item) => (
                  <ListItem key={item} sx={{ px: 0 }}>
                    <ListItemIcon>
                      <CheckCircleIcon sx={{ color: "#f97316" }} />
                    </ListItemIcon>
                    <ListItemText primary={item} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={5}>
              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography sx={{ fontWeight: 700 }}>Common Workflow Terms</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense>
                    {[
                      "CI: automatic builds and tests for each change.",
                      "CD: automated delivery or deployment to environments.",
                      "Staging: pre-production environment for validation.",
                      "Rollback: revert to the last known good release.",
                    ].map((item) => (
                      <ListItem key={item} sx={{ px: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CodeIcon sx={{ color: "#f97316", fontSize: 20 }} />
                        </ListItemIcon>
                        <ListItemText primary={item} />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>
            </Grid>
          </Grid>
        </Paper>

        <Paper id="project-structure" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <BuildIcon sx={{ color: "#f97316" }} />
            Project Structure and Environments
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                Common Project Layout
              </Typography>
              <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ fontWeight: 700 }}>Path</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {projectStructure.map((row) => (
                      <TableRow key={row.path}>
                        <TableCell sx={{ fontWeight: 600 }}>{row.path}</TableCell>
                        <TableCell>{row.purpose}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                Environment Checklist
              </Typography>
              <List dense>
                {environmentChecklist.map((item) => (
                  <ListItem key={item} sx={{ px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckCircleIcon sx={{ color: "#f97316", fontSize: 20 }} />
                    </ListItemIcon>
                    <ListItemText primary={item} />
                  </ListItem>
                ))}
              </List>
              <Alert severity="info" sx={{ mt: 2 }}>
                <AlertTitle sx={{ fontWeight: 700 }}>Tip</AlertTitle>
                Keep production settings separate and review them before each release.
              </Alert>
            </Grid>
          </Grid>
        </Paper>

        <Paper id="clean-code" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <CodeIcon sx={{ color: "#f97316" }} />
            Clean Code and Design Principles
          </Typography>
          <Grid container spacing={2}>
            {codePrinciples.map((principle) => (
              <Grid item xs={12} md={6} key={principle.title}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha("#f97316", 0.05) }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5 }}>
                    {principle.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {principle.description}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        <Paper id="debugging" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <BugReportIcon sx={{ color: "#f97316" }} />
            Debugging Playbook
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            Debugging is a skill. The goal is not to guess, it is to reduce uncertainty step by step.
          </Typography>
          <List>
            {debuggingChecklist.map((item) => (
              <ListItem key={item} sx={{ px: 0 }}>
                <ListItemIcon>
                  <CheckCircleIcon sx={{ color: "#f97316" }} />
                </ListItemIcon>
                <ListItemText primary={item} />
              </ListItem>
            ))}
          </List>
        </Paper>

        <Paper id="sdlc" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <BuildIcon sx={{ color: "#f97316" }} />
            Software Development Lifecycle (SDLC)
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            The SDLC is the structured path from idea to reliable software. It reduces chaos by defining stages and
            expectations, so teams can move fast without breaking quality.
          </Typography>
          <Grid container spacing={2}>
            {[
              { title: "Requirements", desc: "Clarify user needs, goals, and constraints." },
              { title: "Design", desc: "Plan architecture, data flow, and interfaces." },
              { title: "Implementation", desc: "Build features incrementally and review code." },
              { title: "Testing", desc: "Verify correctness, performance, and security." },
              { title: "Deployment", desc: "Release safely with automation and rollouts." },
              { title: "Maintenance", desc: "Monitor, fix, and evolve the system over time." },
            ].map((step) => (
              <Grid item xs={12} md={6} key={step.title}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha("#f97316", 0.05) }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5 }}>
                    {step.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {step.desc}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        <Paper id="methodologies" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <TipsAndUpdatesIcon sx={{ color: "#f97316" }} />
            Common Methodologies
          </Typography>
          {[
            {
              title: "Waterfall",
              summary: "Sequential phases with strong upfront planning.",
              detail: "Works best for stable requirements and regulated environments where changes are rare.",
            },
            {
              title: "Agile and Scrum",
              summary: "Iterative delivery in short sprints with regular feedback.",
              detail: "Teams deliver small increments, review frequently, and adapt based on real user input.",
            },
            {
              title: "Kanban",
              summary: "Flow-based work with visible boards and WIP limits.",
              detail: "Improves throughput by limiting work in progress and revealing bottlenecks.",
            },
          ].map((method) => (
            <Accordion key={method.title} defaultExpanded={method.title === "Agile and Scrum"}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontWeight: 700 }}>{method.title}</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" sx={{ mb: 1, color: "text.secondary" }}>
                  {method.summary}
                </Typography>
                <Typography variant="body2">{method.detail}</Typography>
              </AccordionDetails>
            </Accordion>
          ))}
        </Paper>

        <Paper id="testing-quality" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <BugReportIcon sx={{ color: "#f97316" }} />
            Testing and Quality Essentials
          </Typography>
          <List>
            {[
              "Use the test pyramid: many unit tests, fewer integration tests, and fewer end-to-end tests.",
              "Define acceptance criteria before coding to guide verification.",
              "Automate regression tests to prevent repeat bugs.",
              "Combine code review with automated checks for stronger quality.",
            ].map((item) => (
              <ListItem key={item} sx={{ px: 0 }}>
                <ListItemIcon>
                  <CheckCircleIcon sx={{ color: "#f97316" }} />
                </ListItemIcon>
                <ListItemText primary={item} />
              </ListItem>
            ))}
          </List>
          <Alert severity="info" sx={{ mt: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Quality Signal</AlertTitle>
            Automated tests reduce risk, but human review still catches edge cases and design issues.
          </Alert>
        </Paper>

        <Paper id="security-reliability" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <SecurityIcon sx={{ color: "#f97316" }} />
            Security and Reliability Basics
          </Typography>
          <List>
            {securityBasics.map((item) => (
              <ListItem key={item} sx={{ px: 0 }}>
                <ListItemIcon>
                  <CheckCircleIcon sx={{ color: "#f97316" }} />
                </ListItemIcon>
                <ListItemText primary={item} />
              </ListItem>
            ))}
          </List>
        </Paper>

        <Paper id="delivery-ops" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <TerminalIcon sx={{ color: "#f97316" }} />
            Delivery and Operations Basics
          </Typography>
          <Grid container spacing={2}>
            {[
              "Automate builds and tests with continuous integration.",
              "Use rollout strategies like blue-green or canary releases.",
              "Monitor latency, error rate, and throughput after launch.",
              "Have rollback and incident response plans ready.",
            ].map((item) => (
              <Grid item xs={12} md={6} key={item}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f97316", 0.05) }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                    <CheckCircleIcon sx={{ color: "#f97316" }} />
                    <Typography variant="body2" sx={{ fontWeight: 600 }}>
                      {item}
                    </Typography>
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        <Paper id="performance" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <StorageIcon sx={{ color: "#f97316" }} />
            Performance and Scalability Basics
          </Typography>
          <List>
            {performanceBasics.map((item) => (
              <ListItem key={item} sx={{ px: 0 }}>
                <ListItemIcon>
                  <CheckCircleIcon sx={{ color: "#f97316" }} />
                </ListItemIcon>
                <ListItemText primary={item} />
              </ListItem>
            ))}
          </List>
        </Paper>

        <Paper id="team-practices" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <BuildIcon sx={{ color: "#f97316" }} />
            Team Practices That Scale
          </Typography>
          <List>
            {[
              "Run code reviews to share context and catch defects early.",
              "Hold short daily standups to surface blockers.",
              "Use retrospectives to improve how the team works.",
              "Keep documentation updated for onboarding and support.",
            ].map((item) => (
              <ListItem key={item} sx={{ px: 0 }}>
                <ListItemIcon>
                  <CheckCircleIcon sx={{ color: "#f97316" }} />
                </ListItemIcon>
                <ListItemText primary={item} />
              </ListItem>
            ))}
          </List>
        </Paper>

        <Paper id="specializations" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <CodeIcon sx={{ color: "#f97316" }} />
            Areas of Software Engineering
          </Typography>
          <Grid container spacing={3}>
            {specializations.map((spec) => (
              <Grid item xs={12} sm={6} lg={3} key={spec.title}>
                <Paper
                  sx={{
                    p: 3,
                    borderRadius: 3,
                    textAlign: "center",
                    border: `1px solid ${alpha(spec.color, 0.3)}`,
                    bgcolor: alpha(spec.color, 0.08),
                  }}
                >
                  <Box sx={{ display: "flex", justifyContent: "center", mb: 2, color: spec.color }}>
                    {spec.icon}
                  </Box>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
                    {spec.title}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {spec.description}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        <Paper id="starter-checklist" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <BuildIcon sx={{ color: "#f97316" }} />
            Starter Project Checklist
          </Typography>
          <Grid container spacing={2}>
            {[
              "Define a small problem and write simple requirements.",
              "Create a Git repository and a README.",
              "Build a minimal version that works end to end.",
              "Add tests for core logic.",
              "Document how to run the project locally.",
              "Deploy or share a demo link when possible.",
            ].map((item) => (
              <Grid item xs={12} md={6} key={item}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f97316", 0.05) }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                    <CheckCircleIcon sx={{ color: "#f97316" }} />
                    <Typography variant="body1" sx={{ fontWeight: 500 }}>
                      {item}
                    </Typography>
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>

        <Paper id="quiz-section" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <QuizIcon sx={{ color: "#f97316" }} />
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
            sx={{
              bgcolor: "#f97316",
              "&:hover": { bgcolor: "#ea580c" },
              px: 4,
              py: 1.5,
              fontWeight: 700,
            }}
          >
            Back to Learning Hub
          </Button>
        </Box>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
