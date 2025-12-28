import React, { useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box,
  Typography,
  Paper,
  Grid,
  Chip,
  Avatar,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  alpha,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import CodeIcon from "@mui/icons-material/Code";
import MemoryIcon from "@mui/icons-material/Memory";
import StorageIcon from "@mui/icons-material/Storage";
import BuildIcon from "@mui/icons-material/Build";
import SpeedIcon from "@mui/icons-material/Speed";
import SecurityIcon from "@mui/icons-material/Security";
import DeveloperBoardIcon from "@mui/icons-material/DeveloperBoard";
import TerminalIcon from "@mui/icons-material/Terminal";
import BugReportIcon from "@mui/icons-material/BugReport";
import SchoolIcon from "@mui/icons-material/School";
import HistoryIcon from "@mui/icons-material/History";
import ExtensionIcon from "@mui/icons-material/Extension";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import LayersIcon from "@mui/icons-material/Layers";
import ViewModuleIcon from "@mui/icons-material/ViewModule";
import AutoFixHighIcon from "@mui/icons-material/AutoFixHigh";
import HttpIcon from "@mui/icons-material/Http";
import CloudIcon from "@mui/icons-material/Cloud";
import SyncIcon from "@mui/icons-material/Sync";
import DataObjectIcon from "@mui/icons-material/DataObject";
import LockIcon from "@mui/icons-material/Lock";
import SwapHorizIcon from "@mui/icons-material/SwapHoriz";
import CategoryIcon from "@mui/icons-material/Category";
import TimelineIcon from "@mui/icons-material/Timeline";
import WarningIcon from "@mui/icons-material/Warning";
import ClassIcon from "@mui/icons-material/Class";
import IntegrationInstructionsIcon from "@mui/icons-material/IntegrationInstructions";
import DevicesIcon from "@mui/icons-material/Devices";
import StreamIcon from "@mui/icons-material/Stream";
import FolderIcon from "@mui/icons-material/Folder";
import HubIcon from "@mui/icons-material/Hub";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import Button from "@mui/material/Button";
import RadioGroup from "@mui/material/RadioGroup";
import FormControlLabel from "@mui/material/FormControlLabel";
import Radio from "@mui/material/Radio";
import LinearProgress from "@mui/material/LinearProgress";
import LearnPageLayout from "../components/LearnPageLayout";

const accentColor = "#E76F00"; // Java's official orange color
const accentColorDark = "#5382A1"; // Java's blue accent

// Module navigation items for sidebar
const moduleNavItems = [
  { id: "introduction", label: "Introduction", icon: <SchoolIcon /> },
  { id: "history", label: "History & Evolution", icon: <HistoryIcon /> },
  { id: "setup", label: "Environment Setup", icon: <BuildIcon /> },
  { id: "basics", label: "Java Basics & Syntax", icon: <CodeIcon /> },
  { id: "variables", label: "Variables & Data Types", icon: <DataObjectIcon /> },
  { id: "operators", label: "Operators & Expressions", icon: <SwapHorizIcon /> },
  { id: "control-flow", label: "Control Flow", icon: <AccountTreeIcon /> },
  { id: "arrays", label: "Arrays & Strings", icon: <StorageIcon /> },
  { id: "oop-basics", label: "OOP Fundamentals", icon: <ClassIcon /> },
  { id: "inheritance", label: "Inheritance & Polymorphism", icon: <LayersIcon /> },
  { id: "interfaces", label: "Interfaces & Abstract Classes", icon: <ExtensionIcon /> },
  { id: "exceptions", label: "Exception Handling", icon: <BugReportIcon /> },
  { id: "collections", label: "Collections Framework", icon: <CategoryIcon /> },
  { id: "generics", label: "Generics", icon: <AutoFixHighIcon /> },
  { id: "io", label: "I/O & File Handling", icon: <FolderIcon /> },
  { id: "multithreading", label: "Multithreading", icon: <SyncIcon /> },
  { id: "lambdas", label: "Lambdas & Streams", icon: <StreamIcon /> },
  { id: "jdbc", label: "JDBC & Databases", icon: <StorageIcon /> },
  { id: "networking", label: "Networking", icon: <HubIcon /> },
  { id: "frameworks", label: "Frameworks & Ecosystem", icon: <IntegrationInstructionsIcon /> },
  { id: "advanced", label: "Advanced Topics", icon: <DeveloperBoardIcon /> },
  { id: "quiz", label: "Knowledge Quiz", icon: <QuizIcon /> },
];

// Quick stats for hero section
const quickStats = [
  { label: "Created", value: "1995", color: "#E76F00" },
  { label: "Creator", value: "Sun/Oracle", color: "#5382A1" },
  { label: "Paradigm", value: "OOP", color: "#4A90D9" },
  { label: "Latest Ver", value: "21 LTS", color: "#48BB78" },
];

// Placeholder component for sections to be expanded
interface TopicPlaceholderProps {
  id: string;
  title: string;
  icon: React.ReactNode;
  color: string;
  description: string;
}

function TopicPlaceholder({ id, title, icon, color, description }: TopicPlaceholderProps) {
  return (
    <Paper
      id={id}
      sx={{
        p: 4,
        mb: 4,
        borderRadius: 4,
        border: `2px dashed ${alpha(color, 0.4)}`,
        bgcolor: alpha(color, 0.03),
        position: "relative",
        overflow: "hidden",
      }}
    >
      <Chip
        label="Coming Soon"
        size="small"
        sx={{
          position: "absolute",
          top: 16,
          right: 16,
          bgcolor: alpha(color, 0.15),
          color: color,
          fontWeight: 700,
        }}
      />
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
        <Avatar sx={{ bgcolor: alpha(color, 0.15), color: color, width: 48, height: 48 }}>
          {icon}
        </Avatar>
        <Typography variant="h5" sx={{ fontWeight: 800 }}>
          {title}
        </Typography>
      </Box>
      <Typography variant="body1" color="text.secondary" sx={{ lineHeight: 1.8 }}>
        {description}
      </Typography>
    </Paper>
  );
}

// Question bank for Java quiz (75 questions)
interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  topic: string;
}

const javaQuestionBank: QuizQuestion[] = [
  // History & Evolution (Questions 1-10)
  { id: 1, question: "In what year was Java first released?", options: ["1991", "1995", "1998", "2000"], correctAnswer: 1, topic: "History" },
  { id: 2, question: "What was the original name of the Java programming language?", options: ["Coffee", "Oak", "Mocha", "Duke"], correctAnswer: 1, topic: "History" },
  { id: 3, question: "Who is credited as the primary creator of Java?", options: ["Linus Torvalds", "Dennis Ritchie", "James Gosling", "Bjarne Stroustrup"], correctAnswer: 2, topic: "History" },
  { id: 4, question: "Which company originally developed Java?", options: ["Microsoft", "IBM", "Sun Microsystems", "Apple"], correctAnswer: 2, topic: "History" },
  { id: 5, question: "Which company acquired Sun Microsystems and now owns Java?", options: ["Google", "Oracle", "Amazon", "Microsoft"], correctAnswer: 1, topic: "History" },
  { id: 6, question: "What is the mascot of Java called?", options: ["Java Bean", "Duke", "Coffee Cup", "Java Joe"], correctAnswer: 1, topic: "History" },
  { id: 7, question: "Java's motto 'Write Once, Run Anywhere' refers to:", options: ["Code reusability", "Platform independence", "Fast compilation", "Easy debugging"], correctAnswer: 1, topic: "History" },
  { id: 8, question: "Which Java version introduced lambda expressions?", options: ["Java 5", "Java 7", "Java 8", "Java 11"], correctAnswer: 2, topic: "History" },
  { id: 9, question: "What does LTS stand for in Java versioning?", options: ["Long-Term Support", "Latest Technical Standard", "Lightweight Testing System", "Legacy Type System"], correctAnswer: 0, topic: "History" },
  { id: 10, question: "The Java Community Process (JCP) is responsible for:", options: ["Selling Java licenses", "Developing Java specifications", "Providing customer support", "Training developers"], correctAnswer: 1, topic: "History" },
  
  // Environment Setup (Questions 11-20)
  { id: 11, question: "What does JDK stand for?", options: ["Java Developer Kit", "Java Development Kit", "Java Desktop Kit", "Java Deployment Kit"], correctAnswer: 1, topic: "Setup" },
  { id: 12, question: "What does JRE stand for?", options: ["Java Runtime Environment", "Java Runtime Execution", "Java Rapid Editor", "Java Resource Engine"], correctAnswer: 0, topic: "Setup" },
  { id: 13, question: "What does JVM stand for?", options: ["Java Virtual Machine", "Java Variable Manager", "Java Version Manager", "Java Visual Mode"], correctAnswer: 0, topic: "Setup" },
  { id: 14, question: "Which of the following is NOT an IDE for Java development?", options: ["IntelliJ IDEA", "Eclipse", "Visual Studio Code", "Photoshop"], correctAnswer: 3, topic: "Setup" },
  { id: 15, question: "The 'javac' command is used to:", options: ["Run Java programs", "Compile Java source code", "Debug Java code", "Package JAR files"], correctAnswer: 1, topic: "Setup" },
  { id: 16, question: "Which environment variable must be set to run Java from command line?", options: ["JAVA_DIR", "JAVA_PATH", "PATH (including JDK bin)", "CLASSPATH only"], correctAnswer: 2, topic: "Setup" },
  { id: 17, question: "What file extension do compiled Java files have?", options: [".java", ".class", ".jar", ".jvm"], correctAnswer: 1, topic: "Setup" },
  { id: 18, question: "Which build tool uses pom.xml for configuration?", options: ["Gradle", "Ant", "Maven", "Make"], correctAnswer: 2, topic: "Setup" },
  { id: 19, question: "Which build tool uses build.gradle for configuration?", options: ["Maven", "Gradle", "Ant", "CMake"], correctAnswer: 1, topic: "Setup" },
  { id: 20, question: "A JAR file is:", options: ["A Java compiler", "A Java Archive", "A Java Runtime", "A Java Debugger"], correctAnswer: 1, topic: "Setup" },
  
  // Java Basics & Syntax (Questions 21-30)
  { id: 21, question: "Every Java application must have:", options: ["A GUI", "A database connection", "A main() method", "Multiple classes"], correctAnswer: 2, topic: "Basics" },
  { id: 22, question: "Which is the correct signature of the main method?", options: ["public void main(String args)", "public static void main(String[] args)", "static public main(String args[])", "void main()"], correctAnswer: 1, topic: "Basics" },
  { id: 23, question: "Java source files must have the extension:", options: [".class", ".java", ".jav", ".txt"], correctAnswer: 1, topic: "Basics" },
  { id: 24, question: "Single-line comments in Java start with:", options: ["/*", "//", "#", "<!--"], correctAnswer: 1, topic: "Basics" },
  { id: 25, question: "Multi-line comments in Java are enclosed in:", options: ["// and //", "/* and */", "# and #", "<!-- and -->"], correctAnswer: 1, topic: "Basics" },
  { id: 26, question: "Which statement is used to print output to the console?", options: ["print()", "console.log()", "System.out.println()", "echo()"], correctAnswer: 2, topic: "Basics" },
  { id: 27, question: "Package declarations must be:", options: ["Inside the class", "After import statements", "The first statement in a file", "Optional and can be anywhere"], correctAnswer: 2, topic: "Basics" },
  { id: 28, question: "Which naming convention is used for Java classes?", options: ["snake_case", "camelCase", "PascalCase", "kebab-case"], correctAnswer: 2, topic: "Basics" },
  { id: 29, question: "Which naming convention is used for Java methods and variables?", options: ["snake_case", "camelCase", "PascalCase", "UPPER_CASE"], correctAnswer: 1, topic: "Basics" },
  { id: 30, question: "Constants in Java are typically written in:", options: ["camelCase", "PascalCase", "SCREAMING_SNAKE_CASE", "lowercase"], correctAnswer: 2, topic: "Basics" },
  
  // Variables & Data Types (Questions 31-45)
  { id: 31, question: "How many primitive data types does Java have?", options: ["6", "7", "8", "10"], correctAnswer: 2, topic: "Variables" },
  { id: 32, question: "Which primitive type is used for whole numbers?", options: ["float", "double", "int", "char"], correctAnswer: 2, topic: "Variables" },
  { id: 33, question: "Which primitive type uses 64 bits?", options: ["int", "float", "long", "short"], correctAnswer: 2, topic: "Variables" },
  { id: 34, question: "The default value of a boolean in Java is:", options: ["true", "false", "0", "null"], correctAnswer: 1, topic: "Variables" },
  { id: 35, question: "Which data type would you use for a single character?", options: ["String", "char", "Character", "byte"], correctAnswer: 1, topic: "Variables" },
  { id: 36, question: "What is the range of a byte in Java?", options: ["-128 to 127", "0 to 255", "-256 to 255", "-127 to 128"], correctAnswer: 0, topic: "Variables" },
  { id: 37, question: "Which is NOT a primitive data type in Java?", options: ["int", "boolean", "String", "char"], correctAnswer: 2, topic: "Variables" },
  { id: 38, question: "To declare a constant in Java, you use:", options: ["const", "final", "static", "constant"], correctAnswer: 1, topic: "Variables" },
  { id: 39, question: "The wrapper class for int is:", options: ["Int", "Integer", "IntWrapper", "Number"], correctAnswer: 1, topic: "Variables" },
  { id: 40, question: "Automatic conversion from primitive to wrapper is called:", options: ["Unboxing", "Autoboxing", "Casting", "Wrapping"], correctAnswer: 1, topic: "Variables" },
  { id: 41, question: "Which statement correctly declares a double?", options: ["double x = 3.14f;", "double x = 3.14;", "Double x = 3.14d;", "All of the above"], correctAnswer: 1, topic: "Variables" },
  { id: 42, question: "Local variables in Java are stored in:", options: ["Heap", "Stack", "Method Area", "Register"], correctAnswer: 1, topic: "Variables" },
  { id: 43, question: "What happens when you assign a larger type to a smaller type?", options: ["Automatic conversion", "Compilation error without explicit cast", "Runtime error", "Data corruption"], correctAnswer: 1, topic: "Variables" },
  { id: 44, question: "String in Java is:", options: ["A primitive type", "An immutable object", "A mutable object", "A character array"], correctAnswer: 1, topic: "Variables" },
  { id: 45, question: "Which method converts a String to an int?", options: ["String.toInt()", "Integer.parseInt()", "Int.parse()", "Convert.toInt()"], correctAnswer: 1, topic: "Variables" },
  
  // Operators & Expressions (Questions 46-55)
  { id: 46, question: "Which operator is used for integer division in Java?", options: ["/", "//", "%", "div"], correctAnswer: 0, topic: "Operators" },
  { id: 47, question: "What is the result of 10 % 3?", options: ["3", "3.33", "1", "0"], correctAnswer: 2, topic: "Operators" },
  { id: 48, question: "The ++ operator is called:", options: ["Addition operator", "Increment operator", "Plus operator", "Double plus"], correctAnswer: 1, topic: "Operators" },
  { id: 49, question: "What does the && operator represent?", options: ["Bitwise AND", "Logical AND", "Assignment", "Comparison"], correctAnswer: 1, topic: "Operators" },
  { id: 50, question: "What does the || operator represent?", options: ["Bitwise OR", "Logical OR", "Concatenation", "Division"], correctAnswer: 1, topic: "Operators" },
  { id: 51, question: "The ternary operator has the syntax:", options: ["if ? then : else", "condition ? true : false", "a ?? b : c", "test -> result"], correctAnswer: 1, topic: "Operators" },
  { id: 52, question: "Which operator checks equality of objects' references?", options: ["==", ".equals()", "===", "compare()"], correctAnswer: 0, topic: "Operators" },
  { id: 53, question: "What does != mean in Java?", options: ["Assignment", "Not equal to", "Negation", "Null check"], correctAnswer: 1, topic: "Operators" },
  { id: 54, question: "The compound assignment operator += is equivalent to:", options: ["a = + a", "a = a + value", "a ++ value", "add(a, value)"], correctAnswer: 1, topic: "Operators" },
  { id: 55, question: "Which has higher precedence: * or +?", options: ["+ has higher", "* has higher", "They are equal", "Depends on context"], correctAnswer: 1, topic: "Operators" },
  
  // Control Flow (Questions 56-65)
  { id: 56, question: "Which keyword is used to exit a loop prematurely?", options: ["exit", "break", "stop", "return"], correctAnswer: 1, topic: "Control Flow" },
  { id: 57, question: "Which keyword skips the current iteration and continues with the next?", options: ["skip", "next", "continue", "pass"], correctAnswer: 2, topic: "Control Flow" },
  { id: 58, question: "A do-while loop executes at least:", options: ["Zero times", "One time", "Twice", "It depends"], correctAnswer: 1, topic: "Control Flow" },
  { id: 59, question: "The enhanced for loop (for-each) was introduced in:", options: ["Java 1.4", "Java 5", "Java 7", "Java 8"], correctAnswer: 1, topic: "Control Flow" },
  { id: 60, question: "In a switch statement, what happens if break is omitted?", options: ["Compilation error", "Fall-through to next case", "Loop continues", "Return to start"], correctAnswer: 1, topic: "Control Flow" },
  { id: 61, question: "Switch expressions (returning values) were added in:", options: ["Java 8", "Java 11", "Java 14", "Java 17"], correctAnswer: 2, topic: "Control Flow" },
  { id: 62, question: "Which of these is a valid infinite loop?", options: ["for(;;)", "while(1)", "do while", "loop()"], correctAnswer: 0, topic: "Control Flow" },
  { id: 63, question: "The default case in a switch is:", options: ["Required", "Optional", "Must be first", "Must be last"], correctAnswer: 1, topic: "Control Flow" },
  { id: 64, question: "Which cannot be used in a switch statement (before Java 7)?", options: ["int", "char", "String", "enum"], correctAnswer: 2, topic: "Control Flow" },
  { id: 65, question: "A labeled break is used to:", options: ["Name a loop", "Exit nested loops", "Create a goto statement", "Debug code"], correctAnswer: 1, topic: "Control Flow" },
  
  // Arrays & Strings (Questions 66-75)
  { id: 66, question: "Array indices in Java start at:", options: ["0", "1", "-1", "Depends on declaration"], correctAnswer: 0, topic: "Arrays" },
  { id: 67, question: "To get the length of an array, you use:", options: ["array.length()", "array.size()", "array.length", "len(array)"], correctAnswer: 2, topic: "Arrays" },
  { id: 68, question: "Which creates a 2D array with 3 rows and 4 columns?", options: ["int[][] arr = new int[4][3];", "int[][] arr = new int[3][4];", "int[3][4] arr = new int;", "int arr[3,4];"], correctAnswer: 1, topic: "Arrays" },
  { id: 69, question: "The Arrays.sort() method sorts:", options: ["In descending order", "In ascending order", "Randomly", "By length"], correctAnswer: 1, topic: "Arrays" },
  { id: 70, question: "Strings in Java are:", options: ["Mutable", "Immutable", "Primitive", "Variable length primitives"], correctAnswer: 1, topic: "Strings" },
  { id: 71, question: "To compare String contents, you should use:", options: ["==", ".equals()", ">", ".compare()"], correctAnswer: 1, topic: "Strings" },
  { id: 72, question: "Which class is used for mutable strings in single-threaded code?", options: ["String", "StringBuffer", "StringBuilder", "MutableString"], correctAnswer: 2, topic: "Strings" },
  { id: 73, question: "The String pool is located in:", options: ["Stack memory", "Heap memory", "Method area", "Register"], correctAnswer: 1, topic: "Strings" },
  { id: 74, question: "Which method splits a String into an array?", options: [".divide()", ".split()", ".toArray()", ".separate()"], correctAnswer: 1, topic: "Strings" },
  { id: 75, question: "Text blocks (multi-line strings) were added in:", options: ["Java 8", "Java 11", "Java 15", "Java 17"], correctAnswer: 2, topic: "Strings" },
];

// Shuffle array using Fisher-Yates algorithm
function shuffleArray<T>(array: T[]): T[] {
  const shuffled = [...array];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

// Quiz Component
function JavaQuiz() {
  const [quizStarted, setQuizStarted] = useState(false);
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [selectedAnswer, setSelectedAnswer] = useState<number | null>(null);
  const [answers, setAnswers] = useState<(number | null)[]>([]);
  const [showResults, setShowResults] = useState(false);
  const [quizQuestions, setQuizQuestions] = useState<QuizQuestion[]>([]);

  const startQuiz = () => {
    const selected = shuffleArray(javaQuestionBank).slice(0, 10);
    setQuizQuestions(selected);
    setQuizStarted(true);
    setCurrentQuestion(0);
    setSelectedAnswer(null);
    setAnswers([]);
    setShowResults(false);
  };

  const handleAnswerSelect = (answerIndex: number) => {
    setSelectedAnswer(answerIndex);
  };

  const handleNext = () => {
    const newAnswers = [...answers];
    newAnswers[currentQuestion] = selectedAnswer;
    setAnswers(newAnswers);

    if (currentQuestion < 9) {
      setCurrentQuestion(currentQuestion + 1);
      setSelectedAnswer(answers[currentQuestion + 1] ?? null);
    } else {
      setShowResults(true);
    }
  };

  const handlePrevious = () => {
    if (currentQuestion > 0) {
      const newAnswers = [...answers];
      newAnswers[currentQuestion] = selectedAnswer;
      setAnswers(newAnswers);
      setCurrentQuestion(currentQuestion - 1);
      setSelectedAnswer(answers[currentQuestion - 1] ?? null);
    }
  };

  const calculateScore = () => {
    let score = 0;
    answers.forEach((answer, index) => {
      if (answer === quizQuestions[index]?.correctAnswer) {
        score++;
      }
    });
    return score;
  };

  const getScoreMessage = (score: number) => {
    if (score === 10) return { text: "Perfect! You're a Java Master! 🏆", color: "#48BB78" };
    if (score >= 8) return { text: "Excellent! You have a strong understanding of Java! 🌟", color: "#68D391" };
    if (score >= 6) return { text: "Good job! Keep practicing to improve! 👍", color: "#ECC94B" };
    if (score >= 4) return { text: "Not bad! Review the topics you missed. 📚", color: "#ED8936" };
    return { text: "Keep studying! Review the material and try again. 💪", color: "#FC8181" };
  };

  if (!quizStarted) {
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <EmojiEventsIcon sx={{ fontSize: 64, color: "#667EEA", mb: 2 }} />
        <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
          Ready to Test Your Knowledge?
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          10 random questions • Multiple choice • Instant results
        </Typography>
        <Button
          variant="contained"
          size="large"
          onClick={startQuiz}
          startIcon={<QuizIcon />}
          sx={{
            bgcolor: "#667EEA",
            "&:hover": { bgcolor: "#5A67D8" },
            px: 4,
            py: 1.5,
            borderRadius: 2,
            fontWeight: 700,
          }}
        >
          Start Quiz
        </Button>
      </Box>
    );
  }

  if (showResults) {
    const score = calculateScore();
    const scoreInfo = getScoreMessage(score);
    
    return (
      <Box>
        <Box sx={{ textAlign: "center", py: 3 }}>
          <Typography variant="h3" sx={{ fontWeight: 800, color: scoreInfo.color, mb: 1 }}>
            {score} / 10
          </Typography>
          <Typography variant="h6" sx={{ color: scoreInfo.color, mb: 3 }}>
            {scoreInfo.text}
          </Typography>
          <LinearProgress
            variant="determinate"
            value={score * 10}
            sx={{
              height: 12,
              borderRadius: 6,
              mb: 4,
              bgcolor: alpha(scoreInfo.color, 0.2),
              "& .MuiLinearProgress-bar": { bgcolor: scoreInfo.color, borderRadius: 6 },
            }}
          />
        </Box>

        <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
          Review Your Answers:
        </Typography>

        <Box sx={{ display: "flex", flexDirection: "column", gap: 2, mb: 4 }}>
          {quizQuestions.map((q, index) => {
            const isCorrect = answers[index] === q.correctAnswer;
            return (
              <Paper
                key={q.id}
                sx={{
                  p: 2,
                  borderRadius: 2,
                  border: `1px solid ${isCorrect ? "#48BB78" : "#FC8181"}`,
                  bgcolor: alpha(isCorrect ? "#48BB78" : "#FC8181", 0.05),
                }}
              >
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                  <Chip
                    label={isCorrect ? "✓" : "✗"}
                    size="small"
                    sx={{
                      bgcolor: isCorrect ? "#48BB78" : "#FC8181",
                      color: "white",
                      fontWeight: 700,
                      minWidth: 28,
                    }}
                  />
                  <Box sx={{ flex: 1 }}>
                    <Typography variant="body2" sx={{ fontWeight: 600, mb: 1 }}>
                      {index + 1}. {q.question}
                    </Typography>
                    <Typography variant="caption" sx={{ color: isCorrect ? "#48BB78" : "#FC8181" }}>
                      {isCorrect ? "Correct!" : `Your answer: ${q.options[answers[index] ?? 0]} | Correct: ${q.options[q.correctAnswer]}`}
                    </Typography>
                  </Box>
                  <Chip label={q.topic} size="small" variant="outlined" sx={{ fontSize: "0.7rem" }} />
                </Box>
              </Paper>
            );
          })}
        </Box>

        <Box sx={{ display: "flex", justifyContent: "center", gap: 2 }}>
          <Button
            variant="contained"
            onClick={startQuiz}
            startIcon={<RefreshIcon />}
            sx={{
              bgcolor: "#667EEA",
              "&:hover": { bgcolor: "#5A67D8" },
              px: 4,
              borderRadius: 2,
              fontWeight: 700,
            }}
          >
            Try Again
          </Button>
        </Box>
      </Box>
    );
  }

  const question = quizQuestions[currentQuestion];
  const progress = ((currentQuestion + 1) / 10) * 100;

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
        <Typography variant="body2" color="text.secondary">
          Question {currentQuestion + 1} of 10
        </Typography>
        <Chip label={question.topic} size="small" sx={{ bgcolor: alpha("#667EEA", 0.1), color: "#667EEA" }} />
      </Box>
      
      <LinearProgress
        variant="determinate"
        value={progress}
        sx={{
          height: 8,
          borderRadius: 4,
          mb: 3,
          bgcolor: alpha("#667EEA", 0.1),
          "& .MuiLinearProgress-bar": { bgcolor: "#667EEA", borderRadius: 4 },
        }}
      />

      <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
        {question.question}
      </Typography>

      <RadioGroup value={selectedAnswer} onChange={(e) => handleAnswerSelect(Number(e.target.value))}>
        {question.options.map((option, index) => (
          <Paper
            key={index}
            sx={{
              mb: 1.5,
              p: 0.5,
              borderRadius: 2,
              border: `2px solid ${selectedAnswer === index ? "#667EEA" : "transparent"}`,
              bgcolor: selectedAnswer === index ? alpha("#667EEA", 0.05) : "background.paper",
              cursor: "pointer",
              transition: "all 0.2s",
              "&:hover": {
                borderColor: alpha("#667EEA", 0.5),
                bgcolor: alpha("#667EEA", 0.03),
              },
            }}
            onClick={() => handleAnswerSelect(index)}
          >
            <FormControlLabel
              value={index}
              control={<Radio sx={{ color: "#667EEA", "&.Mui-checked": { color: "#667EEA" } }} />}
              label={option}
              sx={{ m: 0, width: "100%", py: 1, px: 1 }}
            />
          </Paper>
        ))}
      </RadioGroup>

      <Box sx={{ display: "flex", justifyContent: "space-between", mt: 4 }}>
        <Button
          variant="outlined"
          onClick={handlePrevious}
          disabled={currentQuestion === 0}
          sx={{ borderColor: "#667EEA", color: "#667EEA", "&:hover": { borderColor: "#5A67D8" } }}
        >
          Previous
        </Button>
        <Button
          variant="contained"
          onClick={handleNext}
          disabled={selectedAnswer === null}
          sx={{
            bgcolor: "#667EEA",
            "&:hover": { bgcolor: "#5A67D8" },
            "&.Mui-disabled": { bgcolor: alpha("#667EEA", 0.3) },
          }}
        >
          {currentQuestion === 9 ? "Finish Quiz" : "Next"}
        </Button>
      </Box>
    </Box>
  );
}

export default function JavaProgrammingPage() {
  const navigate = useNavigate();

  return (
    <LearnPageLayout pageTitle="Java Programming" pageContext="Comprehensive Java programming course covering object-oriented programming, enterprise development, and modern Java features.">
      <Box sx={{ display: "flex", gap: 4 }}>
        {/* Sidebar Navigation */}
        <Paper
          sx={{
            width: 280,
            flexShrink: 0,
            p: 2,
            borderRadius: 3,
            position: "sticky",
            top: 24,
            maxHeight: "calc(100vh - 48px)",
            overflow: "auto",
            display: { xs: "none", md: "block" },
          }}
        >
          <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2, color: "text.secondary", px: 1 }}>
            MODULES
          </Typography>
          <List dense disablePadding>
            {moduleNavItems.map((item) => (
              <ListItem
                key={item.id}
                component="a"
                href={`#${item.id}`}
                sx={{
                  borderRadius: 2,
                  mb: 0.5,
                  color: "text.primary",
                  textDecoration: "none",
                  "&:hover": {
                    bgcolor: alpha(accentColor, 0.1),
                  },
                }}
              >
                <ListItemIcon sx={{ minWidth: 36, color: accentColor }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={item.label}
                  primaryTypographyProps={{ fontSize: 13, fontWeight: 500 }}
                />
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* Main Content */}
        <Box sx={{ flex: 1, minWidth: 0 }}>
          {/* Back to Learning Hub */}
          <Chip
            icon={<ArrowBackIcon />}
            label="Back to Learning Hub"
            onClick={() => navigate("/learn")}
            sx={{
              mb: 3,
              fontWeight: 600,
              cursor: "pointer",
              "&:hover": { bgcolor: alpha(accentColor, 0.1) },
            }}
            clickable
          />

          {/* Hero Section */}
          <Paper
            id="introduction"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              background: `linear-gradient(135deg, ${alpha(accentColor, 0.1)} 0%, ${alpha(accentColorDark, 0.1)} 100%)`,
              border: `1px solid ${alpha(accentColor, 0.2)}`,
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar
                sx={{
                  width: 64,
                  height: 64,
                  bgcolor: accentColor,
                  fontSize: 28,
                  fontWeight: 800,
                }}
              >
                ☕
              </Avatar>
              <Box>
                <Typography variant="h4" sx={{ fontWeight: 900 }}>
                  Java Programming
                </Typography>
                <Typography variant="body1" color="text.secondary">
                  Write Once, Run Anywhere — The Enterprise Standard
                </Typography>
              </Box>
            </Box>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {quickStats.map((stat) => (
                <Grid item xs={6} sm={3} key={stat.label}>
                  <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2 }}>
                    <Typography variant="h6" sx={{ fontWeight: 800, color: stat.color }}>
                      {stat.value}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {stat.label}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              {["Object-Oriented", "Platform Independent", "Enterprise", "Android", "Spring Boot", "Microservices", "Strong Typing", "JVM"].map((tag) => (
                <Chip
                  key={tag}
                  label={tag}
                  size="small"
                  sx={{ bgcolor: alpha(accentColor, 0.15), fontWeight: 600 }}
                />
              ))}
            </Box>
          </Paper>

          {/* Main Introduction Content */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              What is Java?
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Java is one of the most influential and widely-used programming languages in the history of 
              computing. Created by James Gosling and his team at Sun Microsystems in 1995, Java was designed 
              with a revolutionary philosophy: <strong>"Write Once, Run Anywhere" (WORA)</strong>. This means 
              that Java code, once compiled, can run on any platform that has a Java Virtual Machine (JVM), 
              regardless of the underlying hardware or operating system. This platform independence, combined 
              with Java's robust object-oriented design, made it an instant success and cemented its place as 
              a cornerstone of modern software development.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              At its core, Java is a <strong>statically-typed, class-based, object-oriented programming language</strong>. 
              Every piece of code in Java exists within a class, and nearly everything is an object (except for 
              primitive types like int, boolean, and char). This strict adherence to object-oriented principles 
              encourages well-organized, modular, and maintainable code. Java's syntax was intentionally designed 
              to be familiar to C and C++ programmers, making it easier to learn for those with prior programming 
              experience, while removing many of the dangerous features (like pointers and manual memory management) 
              that made C/C++ programs prone to bugs and security vulnerabilities.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              One of Java's most important features is its <strong>automatic memory management through garbage 
              collection</strong>. Unlike C or C++, where programmers must manually allocate and free memory, 
              Java's garbage collector automatically reclaims memory that is no longer in use. This eliminates 
              entire classes of bugs like memory leaks and dangling pointers, making Java programs more reliable 
              and easier to write. The JVM monitors memory usage and periodically runs the garbage collector to 
              clean up unused objects, allowing developers to focus on business logic rather than memory management.
            </Typography>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Why Learn Java in 2024?
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Despite being nearly 30 years old, Java remains one of the most popular and in-demand programming 
              languages in the world. According to various industry surveys, Java consistently ranks in the top 3 
              programming languages alongside Python and JavaScript. There are several compelling reasons why Java 
              continues to thrive and why learning it is a wise investment in your programming career:
            </Typography>

            <Grid container spacing={3} sx={{ mb: 4 }}>
              {[
                {
                  title: "Enterprise Dominance",
                  description: "Java powers the backend systems of most Fortune 500 companies. Banks, insurance companies, healthcare organizations, and government agencies rely heavily on Java for their mission-critical applications. If you want to work in enterprise software development, Java knowledge is often a prerequisite.",
                  icon: <SecurityIcon />,
                },
                {
                  title: "Android Development",
                  description: "Java was the primary language for Android app development for over a decade and still maintains significant usage. While Kotlin has become the preferred language, understanding Java is essential because millions of existing Android apps are written in Java, and Kotlin runs on the JVM and interoperates with Java seamlessly.",
                  icon: <DevicesIcon />,
                },
                {
                  title: "Massive Ecosystem",
                  description: "Java has one of the largest and most mature ecosystems in software development. From build tools (Maven, Gradle) to testing frameworks (JUnit, TestNG) to application frameworks (Spring, Jakarta EE), the Java ecosystem provides battle-tested solutions for virtually every programming challenge.",
                  icon: <IntegrationInstructionsIcon />,
                },
                {
                  title: "Job Market",
                  description: "Java developers are consistently among the most sought-after professionals in the tech industry. The language's prevalence in enterprise environments, combined with its use in emerging fields like cloud computing and microservices, ensures a steady demand for Java skills.",
                  icon: <CloudIcon />,
                },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.title}>
                  <Paper sx={{ p: 3, height: "100%", borderRadius: 3, bgcolor: alpha(accentColor, 0.03) }}>
                    <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, mb: 2 }}>
                      {item.icon}
                    </Avatar>
                    <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
                      {item.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>
                      {item.description}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              How Java Works: The JVM Architecture
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Understanding how Java programs execute is crucial to becoming a proficient Java developer. Unlike 
              languages like C or C++ that compile directly to machine code, Java uses a two-step compilation 
              process that enables its platform independence. When you write Java code (stored in .java files), 
              the Java compiler (javac) compiles it into an intermediate format called <strong>bytecode</strong>, 
              which is stored in .class files. This bytecode is not specific to any particular hardware platform.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              The magic happens when you run a Java program. The <strong>Java Virtual Machine (JVM)</strong> reads 
              the bytecode and interprets or compiles it to native machine code at runtime. This is where the 
              "Write Once, Run Anywhere" promise is fulfilled—as long as a device has a JVM installed, it can run 
              any Java bytecode, regardless of where it was originally compiled. The JVM acts as an abstraction 
              layer between your Java code and the underlying operating system and hardware.
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// The Java compilation and execution process:</span>{"\n"}
                {"\n"}
                <span style={{ color: "#50fa7b" }}>HelloWorld.java</span>  <span style={{ color: "#6272a4" }}>// Your source code</span>{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#8be9fd" }}>javac</span> HelloWorld.java  <span style={{ color: "#6272a4" }}>// Compile to bytecode</span>{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#50fa7b" }}>HelloWorld.class</span>  <span style={{ color: "#6272a4" }}>// Platform-independent bytecode</span>{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#8be9fd" }}>java</span> HelloWorld  <span style={{ color: "#6272a4" }}>// JVM executes the bytecode</span>{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#f1fa8c" }}>Hello, World!</span>  <span style={{ color: "#6272a4" }}>// Output</span>
              </Typography>
            </Paper>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Modern JVMs include sophisticated optimization techniques, most notably the <strong>Just-In-Time 
              (JIT) compiler</strong>. The JIT compiler analyzes bytecode as it runs and compiles frequently 
              executed code paths ("hot spots") into optimized native machine code. This means that while Java 
              programs may start slightly slower than natively compiled programs, they can achieve comparable 
              (and sometimes even better) performance for long-running applications. This is why Java excels in 
              server-side applications that run continuously—the JVM has time to optimize the code to peak performance.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              The JVM also provides critical runtime services beyond just executing code. It manages memory through 
              the heap and stack, runs the garbage collector, handles exceptions, provides security through the 
              Security Manager, and offers profiling and debugging capabilities. The JVM is essentially a complete 
              runtime environment that abstracts away the complexities of the underlying system.
            </Typography>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Core Principles of Java
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Java was designed around several fundamental principles that have guided its evolution over the years. 
              Understanding these principles helps you write better Java code and appreciate why certain language 
              features exist:
            </Typography>

            <List sx={{ mb: 3 }}>
              {[
                {
                  title: "Object-Oriented Programming (OOP)",
                  desc: "Everything in Java is modeled as objects that combine data (fields) and behavior (methods). The four pillars of OOP—Encapsulation, Inheritance, Polymorphism, and Abstraction—are fundamental to Java programming. Classes serve as blueprints for objects, and well-designed class hierarchies promote code reuse and maintainability.",
                },
                {
                  title: "Strong Static Typing",
                  desc: "Every variable in Java has a declared type that is checked at compile time. This catches many errors before your program even runs, making Java programs more reliable. While this requires more upfront code (type declarations), it provides better tooling support, clearer documentation, and fewer runtime surprises.",
                },
                {
                  title: "Platform Independence",
                  desc: "Java bytecode runs on any platform with a JVM. This has made Java the language of choice for distributed systems, web services, and enterprise applications where software must run across diverse environments. You write code once and deploy it everywhere.",
                },
                {
                  title: "Security",
                  desc: "Java was designed with security in mind from the beginning. The JVM provides a sandboxed execution environment, the class loader verifies bytecode before execution, and the Security Manager can restrict what code can do. This makes Java well-suited for networked applications and environments where code from untrusted sources might run.",
                },
                {
                  title: "Robustness",
                  desc: "Java eliminates many sources of programming errors. There's no pointer arithmetic, memory is managed automatically, array bounds are checked, and exceptions must be handled. These safety features, while sometimes feeling restrictive, result in more stable and maintainable applications.",
                },
                {
                  title: "Multithreading Built-In",
                  desc: "Java has had first-class support for concurrent programming since version 1.0. The language includes synchronized methods and blocks, the Thread class, and a rich concurrency API. This has been crucial for server applications that must handle many simultaneous connections.",
                },
              ].map((item, index) => (
                <ListItem key={index} sx={{ display: "block", px: 0, py: 1 }}>
                  <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2 }}>
                    <CheckCircleIcon sx={{ color: accentColor, mt: 0.5 }} />
                    <Box>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                        {item.title}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>
                        {item.desc}
                      </Typography>
                    </Box>
                  </Box>
                </ListItem>
              ))}
            </List>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Java Editions and Their Uses
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Java comes in several editions, each tailored for different types of development. Understanding 
              these editions helps you choose the right tools for your projects:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 4 }}>
              {[
                {
                  edition: "Java SE (Standard Edition)",
                  description: "The core Java platform containing the fundamental libraries and APIs. This is what you'll learn first—it includes everything needed for desktop applications, command-line tools, and serves as the foundation for all other editions.",
                  color: "#E76F00",
                },
                {
                  edition: "Java EE / Jakarta EE (Enterprise Edition)",
                  description: "Built on top of Java SE, this edition adds APIs for building large-scale, distributed, multi-tiered enterprise applications. Includes specifications for web services, transactions, persistence (JPA), messaging (JMS), and more.",
                  color: "#5382A1",
                },
                {
                  edition: "Java ME (Micro Edition)",
                  description: "A subset of Java SE designed for resource-constrained devices like embedded systems, IoT devices, and mobile phones. While less relevant today due to Android, it's still used in certain embedded applications.",
                  color: "#48BB78",
                },
              ].map((item) => (
                <Grid item xs={12} key={item.edition}>
                  <Paper sx={{ p: 3, borderRadius: 2, borderLeft: `4px solid ${item.color}`, bgcolor: alpha(item.color, 0.03) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color, mb: 1 }}>
                      {item.edition}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>
                      {item.description}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Modern Java: A Language That Keeps Evolving
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              One of the most exciting aspects of Java today is its rapid pace of evolution. Since 2017, Java has 
              adopted a six-month release cycle, delivering new features and improvements twice a year. Long-Term 
              Support (LTS) versions are released every two years (Java 11, 17, 21) for organizations that prefer 
              stability. This new release cadence has transformed Java from a language often criticized for being 
              slow to change into one that actively incorporates modern programming concepts.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Recent Java versions have introduced features that make the language more expressive and concise:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { feature: "var keyword", version: "Java 10", desc: "Local variable type inference" },
                { feature: "Records", version: "Java 16", desc: "Concise data-carrying classes" },
                { feature: "Sealed Classes", version: "Java 17", desc: "Restricted class hierarchies" },
                { feature: "Pattern Matching", version: "Java 17+", desc: "Enhanced instanceof and switch" },
                { feature: "Virtual Threads", version: "Java 21", desc: "Lightweight concurrency" },
                { feature: "Text Blocks", version: "Java 15", desc: "Multi-line string literals" },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.feature}>
                  <Paper sx={{ p: 2, borderRadius: 2, height: "100%", bgcolor: alpha(accentColor, 0.03) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: accentColor }}>
                      {item.feature}
                    </Typography>
                    <Chip label={item.version} size="small" sx={{ my: 0.5, fontSize: 10, height: 20 }} />
                    <Typography variant="caption" display="block" color="text.secondary">
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              These modern features, combined with powerful frameworks like <strong>Spring Boot</strong> for 
              microservices, <strong>Quarkus</strong> for cloud-native applications, and <strong>Jakarta EE</strong> 
              for enterprise systems, make Java more relevant than ever. The language has successfully adapted to 
              new paradigms like functional programming (with lambdas and streams), reactive programming (with 
              Project Reactor and RxJava), and cloud-native development (with GraalVM native compilation).
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColor, 0.08), border: `1px solid ${alpha(accentColor, 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                💡 Getting Started Tip
              </Typography>
              <Typography variant="body2" color="text.secondary">
                As a beginner, start with <strong>Java 21 LTS</strong> (or the latest LTS version). It includes all 
                modern features while providing long-term support. Use an IDE like <strong>IntelliJ IDEA</strong> 
                (Community Edition is free) or <strong>VS Code</strong> with the Java Extension Pack. These tools 
                will significantly accelerate your learning with features like code completion, error highlighting, 
                and debugging support.
              </Typography>
            </Paper>
          </Paper>

          {/* Your First Java Program */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Your First Java Program
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Let's look at the classic "Hello, World!" program in Java. This simple example illustrates several 
              fundamental concepts that every Java program shares:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// HelloWorld.java - Every Java file contains a class</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>public class</span> <span style={{ color: "#8be9fd" }}>HelloWorld</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// The main method - entry point of the program</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public static void</span> <span style={{ color: "#50fa7b" }}>main</span>(<span style={{ color: "#8be9fd" }}>String</span>[] args) {"{"}{"\n"}
                {"        "}<span style={{ color: "#6272a4" }}>// Print to the console</span>{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>System</span>.out.println(<span style={{ color: "#f1fa8c" }}>"Hello, World!"</span>);{"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Let's break down every part of this program:
            </Typography>

            <List>
              {[
                { code: "public class HelloWorld", desc: "Declares a public class named HelloWorld. In Java, the filename must match the class name (HelloWorld.java). The 'public' keyword means this class is accessible from anywhere." },
                { code: "public static void main(String[] args)", desc: "The main method is the entry point where the JVM starts executing your program. 'public' makes it accessible, 'static' means it belongs to the class (not instances), 'void' means it returns nothing, and 'String[] args' accepts command-line arguments." },
                { code: "System.out.println(...)", desc: "System is a built-in class, 'out' is a static PrintStream object, and 'println' is a method that prints text followed by a newline. This is Java's standard way to output to the console." },
              ].map((item, index) => (
                <ListItem key={index} sx={{ display: "block", px: 0, py: 1.5 }}>
                  <Typography variant="subtitle2" sx={{ fontFamily: "monospace", color: accentColor, mb: 0.5 }}>
                    {item.code}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>
                    {item.desc}
                  </Typography>
                </ListItem>
              ))}
            </List>
          </Paper>

          {/* History & Evolution Section */}
          <Paper id="history" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#E76F00", 0.15), color: "#E76F00", width: 48, height: 48 }}>
                <HistoryIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                History & Evolution
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              The story of Java begins in 1991 at Sun Microsystems, where a small team of engineers known as the 
              <strong> "Green Team"</strong> embarked on a project to create a programming language for the next 
              generation of smart consumer devices. Led by <strong>James Gosling</strong>, along with Mike Sheridan 
              and Patrick Naughton, the team originally developed a language called <strong>"Oak"</strong> (named 
              after an oak tree outside Gosling's office). The goal was to create a platform-independent language 
              that could run on various consumer electronics like set-top boxes and handheld devices.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              When the consumer electronics market didn't materialize as expected, Sun Microsystems pivoted the 
              technology toward the emerging World Wide Web. In 1995, the language was renamed <strong>"Java"</strong> 
              (reportedly inspired by Java coffee) and was publicly released with the slogan "Write Once, Run 
              Anywhere." The timing was perfect—the web was exploding in popularity, and Java's ability to run 
              interactive "applets" in web browsers captured the imagination of developers worldwide.
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { year: "1991", event: "Green Team project begins", desc: "James Gosling starts development of Oak language at Sun Microsystems" },
                { year: "1995", event: "Java 1.0 Released", desc: "Java publicly launched with HotJava browser demonstrating applets" },
                { year: "1998", event: "Java 2 (J2SE 1.2)", desc: "Major update introducing Swing, Collections framework, and JIT compiler" },
                { year: "2004", event: "Java 5 (Tiger)", desc: "Generics, annotations, enums, autoboxing, and enhanced for loop added" },
                { year: "2006", event: "Java Goes Open Source", desc: "Sun releases Java under GPL, creating the OpenJDK project" },
                { year: "2010", event: "Oracle Acquires Sun", desc: "Oracle Corporation purchases Sun Microsystems for $7.4 billion" },
                { year: "2014", event: "Java 8 Released", desc: "Lambdas, Stream API, and Optional class revolutionize Java development" },
                { year: "2017", event: "Six-Month Release Cycle", desc: "Java adopts rapid release schedule with LTS versions every 2-3 years" },
                { year: "2021", event: "Java 17 LTS", desc: "Sealed classes, pattern matching, and enhanced switch expressions" },
                { year: "2023", event: "Java 21 LTS", desc: "Virtual threads, record patterns, and string templates introduced" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.year}>
                  <Paper sx={{ p: 2, height: "100%", borderRadius: 2, borderLeft: `4px solid ${accentColor}`, bgcolor: alpha(accentColor, 0.03) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 800, color: accentColor }}>
                      {item.year} — {item.event}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              A pivotal moment came in <strong>2006</strong> when Sun Microsystems made Java open source under the 
              GNU General Public License (GPL), creating the <strong>OpenJDK</strong> project. This decision ensured 
              Java's long-term viability and community-driven development. When <strong>Oracle acquired Sun in 2010</strong>, 
              there were initial concerns about Java's future, but Oracle has continued to invest heavily in the 
              language, maintaining a rigorous release schedule and contributing significant resources to the OpenJDK.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              The adoption of the <strong>six-month release cycle in 2017</strong> was transformational. Previously, 
              major Java versions were released every 2-3 years, which made the language feel slow to evolve. Now, 
              developers get new features twice a year, with <strong>Long-Term Support (LTS) versions</strong> every 
              two years (Java 11, 17, 21) for enterprises requiring stability. This cadence has reinvigorated Java, 
              allowing it to rapidly adopt modern language features while maintaining its legendary backward compatibility.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColorDark, 0.08), border: `1px solid ${alpha(accentColorDark, 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                🏛️ Java's Influence
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Java has profoundly influenced programming language design. Its virtual machine concept inspired 
                the .NET CLR, its syntax influenced C#, and its garbage collection approach became standard in 
                modern languages. The JVM itself became a platform hosting other languages like Kotlin, Scala, 
                Groovy, and Clojure, creating a rich polyglot ecosystem.
              </Typography>
            </Paper>
          </Paper>

          {/* Environment Setup Section */}
          <Paper id="setup" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#5382A1", 0.15), color: "#5382A1", width: 48, height: 48 }}>
                <BuildIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Environment Setup
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Before writing your first Java program, you need to set up your development environment. This involves 
              installing the <strong>Java Development Kit (JDK)</strong>, configuring environment variables, and 
              choosing an <strong>Integrated Development Environment (IDE)</strong>. Let's walk through each step.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColorDark }}>
              Understanding JDK, JRE, and JVM
            </Typography>

            <Grid container spacing={2} sx={{ mb: 4 }}>
              {[
                {
                  name: "JVM (Java Virtual Machine)",
                  desc: "The runtime engine that executes Java bytecode. It's platform-specific—different JVMs exist for Windows, macOS, Linux, etc. The JVM handles memory management, garbage collection, and provides the runtime environment for Java applications.",
                  color: "#E76F00",
                },
                {
                  name: "JRE (Java Runtime Environment)",
                  desc: "Contains the JVM plus the core Java class libraries needed to run Java applications. End users who only need to run Java programs (not develop them) install the JRE. It includes everything needed for execution but not compilation.",
                  color: "#5382A1",
                },
                {
                  name: "JDK (Java Development Kit)",
                  desc: "The complete development toolkit. It includes the JRE plus development tools like the compiler (javac), debugger (jdb), archiver (jar), documentation generator (javadoc), and other utilities. Developers must install the JDK.",
                  color: "#48BB78",
                },
              ].map((item) => (
                <Grid item xs={12} key={item.name}>
                  <Paper sx={{ p: 3, borderRadius: 2, borderLeft: `4px solid ${item.color}`, bgcolor: alpha(item.color, 0.03) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color, mb: 1 }}>
                      {item.name}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColorDark }}>
              Installing the JDK
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              You have several options for obtaining a JDK. The most common distributions are:
            </Typography>

            <List sx={{ mb: 3 }}>
              {[
                { name: "Oracle JDK", desc: "Oracle's official distribution. Free for development, requires a commercial license for production use in some cases." },
                { name: "OpenJDK", desc: "The open-source reference implementation. Fully free and available from adoptium.net (Eclipse Temurin), Amazon Corretto, or Azul Zulu." },
                { name: "Eclipse Temurin", desc: "Recommended for beginners. Community-supported, production-ready builds from the Adoptium project." },
              ].map((item, index) => (
                <ListItem key={index} sx={{ display: "block", px: 0, py: 1 }}>
                  <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2 }}>
                    <CheckCircleIcon sx={{ color: accentColor, mt: 0.5 }} />
                    <Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                        {item.name}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        {item.desc}
                      </Typography>
                    </Box>
                  </Box>
                </ListItem>
              ))}
            </List>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="caption" sx={{ color: "#6272a4", display: "block", mb: 1 }}>
                # Verify Java installation from command line:
              </Typography>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#8be9fd" }}>java</span> --version{"\n"}
                <span style={{ color: "#6272a4" }}># openjdk 21.0.1 2023-10-17</span>{"\n"}
                <span style={{ color: "#6272a4" }}># OpenJDK Runtime Environment Temurin-21.0.1+12 (build 21.0.1+12)</span>{"\n\n"}
                <span style={{ color: "#8be9fd" }}>javac</span> --version{"\n"}
                <span style={{ color: "#6272a4" }}># javac 21.0.1</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColorDark }}>
              Setting Environment Variables
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              After installing the JDK, you typically need to set two environment variables:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="caption" sx={{ color: "#6272a4", display: "block", mb: 1 }}>
                # Windows (PowerShell - set permanently via System Properties):
              </Typography>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>$env:</span><span style={{ color: "#50fa7b" }}>JAVA_HOME</span> = <span style={{ color: "#f1fa8c" }}>"C:\Program Files\Java\jdk-21"</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$env:</span><span style={{ color: "#50fa7b" }}>PATH</span> += <span style={{ color: "#f1fa8c" }}>";$env:JAVA_HOME\bin"</span>
              </Typography>
              <Typography variant="caption" sx={{ color: "#6272a4", display: "block", mt: 2, mb: 1 }}>
                # macOS/Linux (add to ~/.bashrc, ~/.zshrc, or ~/.bash_profile):
              </Typography>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>export</span> <span style={{ color: "#50fa7b" }}>JAVA_HOME</span>=<span style={{ color: "#f1fa8c" }}>"/usr/lib/jvm/java-21-openjdk"</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>export</span> <span style={{ color: "#50fa7b" }}>PATH</span>=<span style={{ color: "#f1fa8c" }}>"$JAVA_HOME/bin:$PATH"</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColorDark }}>
              Choosing an IDE
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                {
                  ide: "IntelliJ IDEA",
                  desc: "The most popular Java IDE. Community Edition is free and excellent for learning. Ultimate Edition adds enterprise features. Outstanding code completion, refactoring, and debugging.",
                  rec: "Highly Recommended",
                  color: "#E76F00",
                },
                {
                  ide: "Visual Studio Code",
                  desc: "Lightweight editor with Java Extension Pack. Great for beginners who want a simpler interface. Free, fast, and highly customizable with thousands of extensions.",
                  rec: "Good for Beginners",
                  color: "#5382A1",
                },
                {
                  ide: "Eclipse",
                  desc: "Veteran open-source IDE. Still widely used in enterprise environments. Free with extensive plugin ecosystem. Some find it less intuitive than IntelliJ.",
                  rec: "Enterprise Standard",
                  color: "#48BB78",
                },
              ].map((item) => (
                <Grid item xs={12} md={4} key={item.ide}>
                  <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha(item.color, 0.3)}`, bgcolor: alpha(item.color, 0.03) }}>
                    <Chip label={item.rec} size="small" sx={{ mb: 1, bgcolor: alpha(item.color, 0.15), color: item.color, fontWeight: 700 }} />
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
                      {item.ide}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColorDark }}>
              Build Tools (Optional for Beginners)
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              As your projects grow, you'll use build tools to manage dependencies, compile code, run tests, and 
              package applications. The two dominant Java build tools are:
            </Typography>

            <Grid container spacing={2}>
              {[
                { name: "Maven", desc: "Convention over configuration. Uses XML for project configuration (pom.xml). Extensive plugin ecosystem. The older, more established choice." },
                { name: "Gradle", desc: "Uses Groovy or Kotlin DSL for configuration. More flexible and often faster than Maven. Increasingly popular, especially for Android and Spring Boot projects." },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.name}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(accentColor, 0.03) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: accentColor, mb: 0.5 }}>
                      {item.name}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Java Basics & Syntax Section */}
          <Paper id="basics" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#48BB78", 0.15), color: "#48BB78", width: 48, height: 48 }}>
                <CodeIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Java Basics & Syntax
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Java has a clean, readable syntax that was influenced by C and C++ but removes many of their 
              complexities. Understanding Java's basic syntax and structure is essential before diving into 
              more advanced topics.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Structure of a Java Program
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Every Java program follows a consistent structure. Code is organized into <strong>packages</strong>, 
              which contain <strong>classes</strong>. Here's the anatomy of a typical Java file:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// 1. Package declaration (optional, but recommended)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>package</span> com.example.myapp;{"\n\n"}
                <span style={{ color: "#6272a4" }}>// 2. Import statements (bring in other classes)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>import</span> java.util.Scanner;{"\n"}
                <span style={{ color: "#ff79c6" }}>import</span> java.util.ArrayList;{"\n\n"}
                <span style={{ color: "#6272a4" }}>// 3. Class declaration (filename must match class name)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>public class</span> <span style={{ color: "#8be9fd" }}>MyFirstProgram</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// 4. Fields (instance/class variables)</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>private</span> <span style={{ color: "#8be9fd" }}>String</span> name;{"\n\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// 5. Constructor</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#50fa7b" }}>MyFirstProgram</span>(<span style={{ color: "#8be9fd" }}>String</span> name) {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>this</span>.name = name;{"\n"}
                {"    "}{"}"}{"\n\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// 6. Methods</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public void</span> <span style={{ color: "#50fa7b" }}>greet</span>() {"{"}{"\n"}
                {"        "}System.out.println(<span style={{ color: "#f1fa8c" }}>"Hello, "</span> + name);{"\n"}
                {"    "}{"}"}{"\n\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// 7. Main method (program entry point)</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public static void</span> <span style={{ color: "#50fa7b" }}>main</span>(<span style={{ color: "#8be9fd" }}>String</span>[] args) {"{"}{"\n"}
                {"        "}MyFirstProgram program = <span style={{ color: "#ff79c6" }}>new</span> MyFirstProgram(<span style={{ color: "#f1fa8c" }}>"World"</span>);{"\n"}
                {"        "}program.greet();{"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Packages and Imports
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Packages are Java's way of organizing classes into namespaces, preventing naming conflicts and 
              providing access control. Package names follow the reverse domain convention:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Package structure mirrors directory structure:</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// src/com/example/app/User.java</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>package</span> com.example.app;{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Import a single class</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>import</span> java.util.ArrayList;{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Import all classes from a package (avoid in production)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>import</span> java.util.*;{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Static import - import static members directly</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>import static</span> java.lang.Math.PI;{"\n"}
                <span style={{ color: "#ff79c6" }}>import static</span> java.lang.Math.sqrt;
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Comments
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Java supports three types of comments for documenting your code:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Single-line comment - for brief explanations</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>/*</span>{"\n"}
                <span style={{ color: "#6272a4" }}> * Multi-line comment</span>{"\n"}
                <span style={{ color: "#6272a4" }}> * Spans multiple lines</span>{"\n"}
                <span style={{ color: "#6272a4" }}> * Useful for longer explanations</span>{"\n"}
                <span style={{ color: "#6272a4" }}> */</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>/**</span>{"\n"}
                <span style={{ color: "#6272a4" }}> * Javadoc comment - generates API documentation</span>{"\n"}
                <span style={{ color: "#6272a4" }}> * @param name The user's name</span>{"\n"}
                <span style={{ color: "#6272a4" }}> * @return A greeting message</span>{"\n"}
                <span style={{ color: "#6272a4" }}> * @throws IllegalArgumentException if name is null</span>{"\n"}
                <span style={{ color: "#6272a4" }}> */</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#8be9fd" }}>String</span> <span style={{ color: "#50fa7b" }}>createGreeting</span>(<span style={{ color: "#8be9fd" }}>String</span> name) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#f1fa8c" }}>"Hello, "</span> + name;{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Naming Conventions
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Java has well-established naming conventions that all developers follow:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { type: "Classes & Interfaces", convention: "PascalCase", example: "UserAccount, HttpServlet, Serializable" },
                { type: "Methods & Variables", convention: "camelCase", example: "getUserName(), firstName, isActive" },
                { type: "Constants", convention: "UPPER_SNAKE_CASE", example: "MAX_VALUE, DEFAULT_TIMEOUT, PI" },
                { type: "Packages", convention: "lowercase", example: "com.example.myapp, java.util" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.type}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#48BB78", 0.05) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#48BB78" }}>
                      {item.type}
                    </Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", color: "text.secondary" }}>
                      {item.convention}: {item.example}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Basic Input and Output
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>import</span> java.util.Scanner;{"\n\n"}
                <span style={{ color: "#ff79c6" }}>public class</span> <span style={{ color: "#8be9fd" }}>InputExample</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public static void</span> <span style={{ color: "#50fa7b" }}>main</span>(<span style={{ color: "#8be9fd" }}>String</span>[] args) {"{"}{"\n"}
                {"        "}<span style={{ color: "#6272a4" }}>// Output - print to console</span>{"\n"}
                {"        "}System.out.println(<span style={{ color: "#f1fa8c" }}>"What's your name?"</span>); <span style={{ color: "#6272a4" }}>// with newline</span>{"\n"}
                {"        "}System.out.print(<span style={{ color: "#f1fa8c" }}>"Enter: "</span>);                <span style={{ color: "#6272a4" }}>// no newline</span>{"\n\n"}
                {"        "}<span style={{ color: "#6272a4" }}>// Input - read from console</span>{"\n"}
                {"        "}Scanner scanner = <span style={{ color: "#ff79c6" }}>new</span> Scanner(System.in);{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>String</span> name = scanner.nextLine();  <span style={{ color: "#6272a4" }}>// read line</span>{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>int</span> age = scanner.nextInt();       <span style={{ color: "#6272a4" }}>// read integer</span>{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>double</span> score = scanner.nextDouble(); <span style={{ color: "#6272a4" }}>// read double</span>{"\n\n"}
                {"        "}<span style={{ color: "#6272a4" }}>// Formatted output</span>{"\n"}
                {"        "}System.out.printf(<span style={{ color: "#f1fa8c" }}>"Hello %s, you are %d years old%n"</span>, name, age);{"\n\n"}
                {"        "}scanner.close(); <span style={{ color: "#6272a4" }}>// Always close resources</span>{"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#48BB78", 0.08), border: `1px solid ${alpha("#48BB78", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                ⚠️ Common Beginner Mistakes
              </Typography>
              <Typography variant="body2" color="text.secondary" component="div">
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  <li>Forgetting semicolons at the end of statements</li>
                  <li>Mismatched braces {"{ }"} — use IDE auto-formatting</li>
                  <li>Case sensitivity: <code>String</code> ≠ <code>string</code></li>
                  <li>File name must match the public class name exactly</li>
                  <li>Missing the <code>main</code> method when trying to run a program</li>
                </ul>
              </Typography>
            </Paper>
          </Paper>

          {/* Variables & Data Types Section */}
          <Paper id="variables" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#667EEA", 0.15), color: "#667EEA", width: 48, height: 48 }}>
                <DataObjectIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Variables & Data Types
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Java is a <strong>statically-typed language</strong>, meaning every variable must have a declared 
              type that is known at compile time. This catches many errors early but requires you to think about 
              types as you write code. Java has two categories of types: <strong>primitive types</strong> (which 
              store values directly) and <strong>reference types</strong> (which store memory addresses pointing 
              to objects).
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Primitive Data Types
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Java has 8 primitive types that represent simple values. They're stored directly on the stack 
              and are very efficient:
            </Typography>

            <Grid container spacing={1} sx={{ mb: 3 }}>
              {[
                { type: "byte", size: "1 byte", range: "-128 to 127", example: "byte age = 25;" },
                { type: "short", size: "2 bytes", range: "-32,768 to 32,767", example: "short year = 2024;" },
                { type: "int", size: "4 bytes", range: "~±2.1 billion", example: "int count = 1_000_000;" },
                { type: "long", size: "8 bytes", range: "~±9.2 quintillion", example: "long population = 8_000_000_000L;" },
                { type: "float", size: "4 bytes", range: "~±3.4 × 10³⁸", example: "float pi = 3.14f;" },
                { type: "double", size: "8 bytes", range: "~±1.8 × 10³⁰⁸", example: "double e = 2.718281828;" },
                { type: "char", size: "2 bytes", range: "Unicode characters", example: "char grade = 'A';" },
                { type: "boolean", size: "1 bit*", range: "true or false", example: "boolean active = true;" },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={3} key={item.type}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, height: "100%", bgcolor: alpha("#667EEA", 0.03), border: `1px solid ${alpha("#667EEA", 0.1)}` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 800, color: "#667EEA", fontFamily: "monospace" }}>
                      {item.type}
                    </Typography>
                    <Typography variant="caption" sx={{ display: "block", color: "text.secondary" }}>
                      {item.size} | {item.range}
                    </Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", fontSize: 10, color: "#48BB78" }}>
                      {item.example}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Variable Declaration and Initialization
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Declaration - tells compiler the variable exists</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> count;{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Initialization - assigns a value</span>{"\n"}
                count = <span style={{ color: "#bd93f9" }}>10</span>;{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Declaration + Initialization (most common)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> score = <span style={{ color: "#bd93f9" }}>100</span>;{"\n"}
                <span style={{ color: "#8be9fd" }}>double</span> price = <span style={{ color: "#bd93f9" }}>19.99</span>;{"\n"}
                <span style={{ color: "#8be9fd" }}>char</span> initial = <span style={{ color: "#f1fa8c" }}>'J'</span>;{"\n"}
                <span style={{ color: "#8be9fd" }}>boolean</span> isReady = <span style={{ color: "#ff79c6" }}>true</span>;{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Multiple declarations of same type</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> x = <span style={{ color: "#bd93f9" }}>1</span>, y = <span style={{ color: "#bd93f9" }}>2</span>, z = <span style={{ color: "#bd93f9" }}>3</span>;{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Constants (cannot be changed)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>final</span> <span style={{ color: "#8be9fd" }}>double</span> PI = <span style={{ color: "#bd93f9" }}>3.14159265359</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>final</span> <span style={{ color: "#8be9fd" }}>int</span> MAX_USERS = <span style={{ color: "#bd93f9" }}>1000</span>;{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Type inference with var (Java 10+)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> message = <span style={{ color: "#f1fa8c" }}>"Hello"</span>;      <span style={{ color: "#6272a4" }}>// infers String</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> items = <span style={{ color: "#bd93f9" }}>42</span>;             <span style={{ color: "#6272a4" }}>// infers int</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> total = <span style={{ color: "#bd93f9" }}>99.95</span>;          <span style={{ color: "#6272a4" }}>// infers double</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Type Casting
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Sometimes you need to convert between types. Java supports two types of casting:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// WIDENING (Implicit) - automatic, safe, no data loss</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// byte → short → int → long → float → double</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> myInt = <span style={{ color: "#bd93f9" }}>100</span>;{"\n"}
                <span style={{ color: "#8be9fd" }}>long</span> myLong = myInt;       <span style={{ color: "#6272a4" }}>// Automatic: int to long</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>double</span> myDouble = myLong;  <span style={{ color: "#6272a4" }}>// Automatic: long to double</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// NARROWING (Explicit) - manual, may lose data!</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>double</span> pi = <span style={{ color: "#bd93f9" }}>3.14159</span>;{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> approxPi = (<span style={{ color: "#8be9fd" }}>int</span>) pi;  <span style={{ color: "#6272a4" }}>// Result: 3 (decimal lost!)</span>{"\n\n"}
                <span style={{ color: "#8be9fd" }}>long</span> bigNumber = <span style={{ color: "#bd93f9" }}>1_000_000_000_000L</span>;{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> overflow = (<span style={{ color: "#8be9fd" }}>int</span>) bigNumber;  <span style={{ color: "#6272a4" }}>// Data loss! Result: -727379968</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Reference Types and Wrapper Classes
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Reference types store addresses pointing to objects in memory. Java provides <strong>wrapper 
              classes</strong> for each primitive, allowing them to be used as objects:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Wrapper classes for primitives</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>Integer</span> count = <span style={{ color: "#bd93f9" }}>42</span>;        <span style={{ color: "#6272a4" }}>// int → Integer</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>Double</span> price = <span style={{ color: "#bd93f9" }}>19.99</span>;      <span style={{ color: "#6272a4" }}>// double → Double</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>Boolean</span> active = <span style={{ color: "#ff79c6" }}>true</span>;    <span style={{ color: "#6272a4" }}>// boolean → Boolean</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>Character</span> grade = <span style={{ color: "#f1fa8c" }}>'A'</span>;   <span style={{ color: "#6272a4" }}>// char → Character</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Autoboxing - automatic primitive to wrapper</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>Integer</span> boxed = <span style={{ color: "#bd93f9" }}>100</span>;  <span style={{ color: "#6272a4" }}>// int automatically becomes Integer</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Unboxing - automatic wrapper to primitive</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> unboxed = boxed;   <span style={{ color: "#6272a4" }}>// Integer automatically becomes int</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Useful wrapper class methods</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> parsed = Integer.parseInt(<span style={{ color: "#f1fa8c" }}>"123"</span>);     <span style={{ color: "#6272a4" }}>// String to int</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> str = Integer.toString(<span style={{ color: "#bd93f9" }}>456</span>);      <span style={{ color: "#6272a4" }}>// int to String</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> max = Integer.MAX_VALUE;                <span style={{ color: "#6272a4" }}>// 2147483647</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              String Basics
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Strings are reference types, not primitives, but they're used so often that Java provides special 
              support for them. Strings are <strong>immutable</strong>—once created, they cannot be changed:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Creating Strings</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> s1 = <span style={{ color: "#f1fa8c" }}>"Hello"</span>;                  <span style={{ color: "#6272a4" }}>// String literal (preferred)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> s2 = <span style={{ color: "#ff79c6" }}>new</span> String(<span style={{ color: "#f1fa8c" }}>"Hello"</span>);      <span style={{ color: "#6272a4" }}>// Using constructor</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// String concatenation</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> full = <span style={{ color: "#f1fa8c" }}>"Hello"</span> + <span style={{ color: "#f1fa8c" }}>" "</span> + <span style={{ color: "#f1fa8c" }}>"World"</span>;  <span style={{ color: "#6272a4" }}>// "Hello World"</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Common String methods</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> text = <span style={{ color: "#f1fa8c" }}>"  Java Programming  "</span>;{"\n"}
                text.length();          <span style={{ color: "#6272a4" }}>// 20</span>{"\n"}
                text.trim();            <span style={{ color: "#6272a4" }}>// "Java Programming"</span>{"\n"}
                text.toLowerCase();     <span style={{ color: "#6272a4" }}>// "  java programming  "</span>{"\n"}
                text.toUpperCase();     <span style={{ color: "#6272a4" }}>// "  JAVA PROGRAMMING  "</span>{"\n"}
                text.charAt(<span style={{ color: "#bd93f9" }}>2</span>);         <span style={{ color: "#6272a4" }}>// 'J'</span>{"\n"}
                text.contains(<span style={{ color: "#f1fa8c" }}>"Java"</span>);  <span style={{ color: "#6272a4" }}>// true</span>{"\n"}
                text.startsWith(<span style={{ color: "#f1fa8c" }}>"  J"</span>); <span style={{ color: "#6272a4" }}>// true</span>{"\n"}
                text.substring(<span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>6</span>);    <span style={{ color: "#6272a4" }}>// "Java"</span>{"\n"}
                text.replace(<span style={{ color: "#f1fa8c" }}>"Java"</span>, <span style={{ color: "#f1fa8c" }}>"Kotlin"</span>);  <span style={{ color: "#6272a4" }}>// "  Kotlin Programming  "</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// String comparison - ALWAYS use .equals() for content!</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> a = <span style={{ color: "#f1fa8c" }}>"hello"</span>;{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> b = <span style={{ color: "#f1fa8c" }}>"hello"</span>;{"\n"}
                a == b;          <span style={{ color: "#6272a4" }}>// May be true (String pool), but unreliable!</span>{"\n"}
                a.equals(b);     <span style={{ color: "#6272a4" }}>// true - correct way to compare content</span>{"\n"}
                a.equalsIgnoreCase(<span style={{ color: "#f1fa8c" }}>"HELLO"</span>);  <span style={{ color: "#6272a4" }}>// true</span>
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#667EEA", 0.08), border: `1px solid ${alpha("#667EEA", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                💡 Key Takeaways
              </Typography>
              <Typography variant="body2" color="text.secondary" component="div">
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  <li>Use <code>int</code> for whole numbers, <code>double</code> for decimals in most cases</li>
                  <li>Add <code>L</code> suffix for long literals, <code>f</code> for float literals</li>
                  <li>Use <code>final</code> for constants that shouldn't change</li>
                  <li>Always use <code>.equals()</code> to compare String content, not <code>==</code></li>
                  <li>Prefer wrapper classes when you need nullability or generics</li>
                </ul>
              </Typography>
            </Paper>
          </Paper>

          {/* Operators & Expressions Section */}
          <Paper id="operators" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#ED8936", 0.15), color: "#ED8936", width: 48, height: 48 }}>
                <SwapHorizIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Operators & Expressions
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Operators are special symbols that perform operations on variables and values. Java provides a rich 
              set of operators that allow you to perform arithmetic, comparisons, logical operations, and more. 
              Understanding operators is fundamental to writing expressions—combinations of variables, operators, 
              and method calls that evaluate to a single value.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Arithmetic Operators
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              These operators perform mathematical calculations:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#8be9fd" }}>int</span> a = <span style={{ color: "#bd93f9" }}>10</span>, b = <span style={{ color: "#bd93f9" }}>3</span>;{"\n\n"}
                a + b    <span style={{ color: "#6272a4" }}>// Addition:       13</span>{"\n"}
                a - b    <span style={{ color: "#6272a4" }}>// Subtraction:    7</span>{"\n"}
                a * b    <span style={{ color: "#6272a4" }}>// Multiplication: 30</span>{"\n"}
                a / b    <span style={{ color: "#6272a4" }}>// Division:       3 (integer division!)</span>{"\n"}
                a % b    <span style={{ color: "#6272a4" }}>// Modulus:        1 (remainder)</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Integer division truncates - use double for decimals</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>double</span> result = (<span style={{ color: "#8be9fd" }}>double</span>) a / b;  <span style={{ color: "#6272a4" }}>// 3.333...</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Increment and Decrement</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> x = <span style={{ color: "#bd93f9" }}>5</span>;{"\n"}
                x++      <span style={{ color: "#6272a4" }}>// Post-increment: returns 5, then x becomes 6</span>{"\n"}
                ++x      <span style={{ color: "#6272a4" }}>// Pre-increment:  x becomes 7, returns 7</span>{"\n"}
                x--      <span style={{ color: "#6272a4" }}>// Post-decrement: returns 7, then x becomes 6</span>{"\n"}
                --x      <span style={{ color: "#6272a4" }}>// Pre-decrement:  x becomes 5, returns 5</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Assignment Operators
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#8be9fd" }}>int</span> x = <span style={{ color: "#bd93f9" }}>10</span>;   <span style={{ color: "#6272a4" }}>// Simple assignment</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Compound assignment operators (shorthand)</span>{"\n"}
                x += <span style={{ color: "#bd93f9" }}>5</span>;    <span style={{ color: "#6272a4" }}>// x = x + 5  → 15</span>{"\n"}
                x -= <span style={{ color: "#bd93f9" }}>3</span>;    <span style={{ color: "#6272a4" }}>// x = x - 3  → 12</span>{"\n"}
                x *= <span style={{ color: "#bd93f9" }}>2</span>;    <span style={{ color: "#6272a4" }}>// x = x * 2  → 24</span>{"\n"}
                x /= <span style={{ color: "#bd93f9" }}>4</span>;    <span style={{ color: "#6272a4" }}>// x = x / 4  → 6</span>{"\n"}
                x %= <span style={{ color: "#bd93f9" }}>4</span>;    <span style={{ color: "#6272a4" }}>// x = x % 4  → 2</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Also works with bitwise operators</span>{"\n"}
                x &= <span style={{ color: "#bd93f9" }}>1</span>;    <span style={{ color: "#6272a4" }}>// x = x & 1</span>{"\n"}
                x |= <span style={{ color: "#bd93f9" }}>4</span>;    <span style={{ color: "#6272a4" }}>// x = x | 4</span>{"\n"}
                x ^= <span style={{ color: "#bd93f9" }}>2</span>;    <span style={{ color: "#6272a4" }}>// x = x ^ 2</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Comparison (Relational) Operators
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              These operators compare two values and return a boolean result:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#8be9fd" }}>int</span> a = <span style={{ color: "#bd93f9" }}>5</span>, b = <span style={{ color: "#bd93f9" }}>10</span>;{"\n\n"}
                a == b   <span style={{ color: "#6272a4" }}>// Equal to:                false</span>{"\n"}
                a != b   <span style={{ color: "#6272a4" }}>// Not equal to:            true</span>{"\n"}
                a {">"} b    <span style={{ color: "#6272a4" }}>// Greater than:            false</span>{"\n"}
                a {"<"} b    <span style={{ color: "#6272a4" }}>// Less than:               true</span>{"\n"}
                a {">"}= b   <span style={{ color: "#6272a4" }}>// Greater than or equal:   false</span>{"\n"}
                a {"<"}= b   <span style={{ color: "#6272a4" }}>// Less than or equal:      true</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// ⚠️ For objects, == compares REFERENCES, not content!</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> s1 = <span style={{ color: "#ff79c6" }}>new</span> String(<span style={{ color: "#f1fa8c" }}>"hello"</span>);{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> s2 = <span style={{ color: "#ff79c6" }}>new</span> String(<span style={{ color: "#f1fa8c" }}>"hello"</span>);{"\n"}
                s1 == s2        <span style={{ color: "#6272a4" }}>// false (different objects!)</span>{"\n"}
                s1.equals(s2)   <span style={{ color: "#6272a4" }}>// true  (same content)</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Logical Operators
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Logical operators work with boolean values and are essential for building complex conditions:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#8be9fd" }}>boolean</span> x = <span style={{ color: "#ff79c6" }}>true</span>, y = <span style={{ color: "#ff79c6" }}>false</span>;{"\n\n"}
                x && y   <span style={{ color: "#6272a4" }}>// Logical AND:  false (both must be true)</span>{"\n"}
                x || y   <span style={{ color: "#6272a4" }}>// Logical OR:   true  (at least one true)</span>{"\n"}
                !x       <span style={{ color: "#6272a4" }}>// Logical NOT:  false (inverts value)</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Short-circuit evaluation (very important!)</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// && stops if first operand is false</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// || stops if first operand is true</span>{"\n\n"}
                <span style={{ color: "#8be9fd" }}>String</span> name = <span style={{ color: "#ff79c6" }}>null</span>;{"\n"}
                <span style={{ color: "#6272a4" }}>// Safe null check using short-circuit</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> (name != <span style={{ color: "#ff79c6" }}>null</span> && name.length() {">"} <span style={{ color: "#bd93f9" }}>0</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// name.length() only called if name isn't null</span>{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Bitwise Operators
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Bitwise operators manipulate individual bits. They're used in low-level programming, encryption, 
              and optimization:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#8be9fd" }}>int</span> a = <span style={{ color: "#bd93f9" }}>5</span>;   <span style={{ color: "#6272a4" }}>// binary: 0101</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> b = <span style={{ color: "#bd93f9" }}>3</span>;   <span style={{ color: "#6272a4" }}>// binary: 0011</span>{"\n\n"}
                a & b    <span style={{ color: "#6272a4" }}>// AND:  1 (0001) - both bits must be 1</span>{"\n"}
                a | b    <span style={{ color: "#6272a4" }}>// OR:   7 (0111) - either bit is 1</span>{"\n"}
                a ^ b    <span style={{ color: "#6272a4" }}>// XOR:  6 (0110) - bits are different</span>{"\n"}
                ~a       <span style={{ color: "#6272a4" }}>// NOT: -6 (inverts all bits)</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Shift operators</span>{"\n"}
                a {"<<"} <span style={{ color: "#bd93f9" }}>1</span>   <span style={{ color: "#6272a4" }}>// Left shift:  10 (1010) - multiply by 2</span>{"\n"}
                a {">>"} <span style={{ color: "#bd93f9" }}>1</span>   <span style={{ color: "#6272a4" }}>// Right shift:  2 (0010) - divide by 2</span>{"\n"}
                a {">>>"} <span style={{ color: "#bd93f9" }}>1</span>  <span style={{ color: "#6272a4" }}>// Unsigned right shift (fills with 0s)</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Ternary Operator
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              The ternary operator <code>?:</code> is a concise way to write simple if-else expressions:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Syntax: condition ? valueIfTrue : valueIfFalse</span>{"\n\n"}
                <span style={{ color: "#8be9fd" }}>int</span> age = <span style={{ color: "#bd93f9" }}>20</span>;{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> status = age {">"}= <span style={{ color: "#bd93f9" }}>18</span> ? <span style={{ color: "#f1fa8c" }}>"adult"</span> : <span style={{ color: "#f1fa8c" }}>"minor"</span>;{"\n"}
                <span style={{ color: "#6272a4" }}>// status = "adult"</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Can be nested (but avoid for readability)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> score = <span style={{ color: "#bd93f9" }}>85</span>;{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> grade = score {">"}= <span style={{ color: "#bd93f9" }}>90</span> ? <span style={{ color: "#f1fa8c" }}>"A"</span> :{"\n"}
                {"               "}score {">"}= <span style={{ color: "#bd93f9" }}>80</span> ? <span style={{ color: "#f1fa8c" }}>"B"</span> :{"\n"}
                {"               "}score {">"}= <span style={{ color: "#bd93f9" }}>70</span> ? <span style={{ color: "#f1fa8c" }}>"C"</span> : <span style={{ color: "#f1fa8c" }}>"F"</span>;{"\n"}
                <span style={{ color: "#6272a4" }}>// grade = "B"</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Operator Precedence
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              When multiple operators appear in an expression, precedence determines the order of evaluation. 
              Higher precedence operators are evaluated first:
            </Typography>

            <Grid container spacing={1} sx={{ mb: 3 }}>
              {[
                { level: "1 (highest)", ops: "() [] .", desc: "Parentheses, array access, member access" },
                { level: "2", ops: "++ -- ! ~", desc: "Unary operators" },
                { level: "3", ops: "* / %", desc: "Multiplication, division, modulus" },
                { level: "4", ops: "+ -", desc: "Addition, subtraction" },
                { level: "5", ops: "<< >> >>>", desc: "Shift operators" },
                { level: "6", ops: "< <= > >= instanceof", desc: "Relational" },
                { level: "7", ops: "== !=", desc: "Equality" },
                { level: "8-10", ops: "& ^ |", desc: "Bitwise AND, XOR, OR" },
                { level: "11-12", ops: "&& ||", desc: "Logical AND, OR" },
                { level: "13", ops: "?:", desc: "Ternary" },
                { level: "14 (lowest)", ops: "= += -= etc.", desc: "Assignment" },
              ].map((item, idx) => (
                <Grid item xs={12} sm={6} md={4} key={idx}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, height: "100%", bgcolor: alpha("#ED8936", 0.03) }}>
                    <Typography variant="caption" sx={{ fontWeight: 700, color: "#ED8936" }}>
                      {item.level}
                    </Typography>
                    <Typography variant="body2" sx={{ fontFamily: "monospace", fontWeight: 600 }}>
                      {item.ops}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#ED8936", 0.08), border: `1px solid ${alpha("#ED8936", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                💡 Best Practice: Use Parentheses for Clarity
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Even when you know the precedence rules, use parentheses to make your intent clear. 
                <code style={{ marginLeft: 8 }}>a + b * c</code> is correct, but{" "}
                <code>a + (b * c)</code> is more readable. Future you (and your teammates) will thank you!
              </Typography>
            </Paper>
          </Paper>

          {/* Control Flow Section */}
          <Paper id="control-flow" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#38B2AC", 0.15), color: "#38B2AC", width: 48, height: 48 }}>
                <AccountTreeIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Control Flow
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Control flow statements determine the order in which code is executed. Java provides several 
              constructs for making decisions (if-else, switch) and repeating code (loops). Mastering these 
              is essential for writing programs that can respond to different conditions and process data.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              If-Else Statements
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              The if-else statement executes different code blocks based on a boolean condition:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#8be9fd" }}>int</span> score = <span style={{ color: "#bd93f9" }}>85</span>;{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Simple if</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> (score {">"}= <span style={{ color: "#bd93f9" }}>60</span>) {"{"}{"\n"}
                {"    "}System.out.println(<span style={{ color: "#f1fa8c" }}>"Passed!"</span>);{"\n"}
                {"}"}{"\n\n"}
                <span style={{ color: "#6272a4" }}>// If-else</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> (score {">"}= <span style={{ color: "#bd93f9" }}>60</span>) {"{"}{"\n"}
                {"    "}System.out.println(<span style={{ color: "#f1fa8c" }}>"Passed!"</span>);{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>else</span> {"{"}{"\n"}
                {"    "}System.out.println(<span style={{ color: "#f1fa8c" }}>"Failed."</span>);{"\n"}
                {"}"}{"\n\n"}
                <span style={{ color: "#6272a4" }}>// If-else-if ladder</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> (score {">"}= <span style={{ color: "#bd93f9" }}>90</span>) {"{"}{"\n"}
                {"    "}System.out.println(<span style={{ color: "#f1fa8c" }}>"A - Excellent!"</span>);{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>else if</span> (score {">"}= <span style={{ color: "#bd93f9" }}>80</span>) {"{"}{"\n"}
                {"    "}System.out.println(<span style={{ color: "#f1fa8c" }}>"B - Good job!"</span>);{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>else if</span> (score {">"}= <span style={{ color: "#bd93f9" }}>70</span>) {"{"}{"\n"}
                {"    "}System.out.println(<span style={{ color: "#f1fa8c" }}>"C - Satisfactory"</span>);{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>else</span> {"{"}{"\n"}
                {"    "}System.out.println(<span style={{ color: "#f1fa8c" }}>"Need improvement"</span>);{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              Switch Statement & Expressions
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Switch is cleaner than long if-else chains when comparing a variable against multiple values. 
              Modern Java (12+) introduces switch expressions with arrow syntax:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Traditional switch statement</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> day = <span style={{ color: "#f1fa8c" }}>"Monday"</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>switch</span> (day) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> <span style={{ color: "#f1fa8c" }}>"Monday"</span>:{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> <span style={{ color: "#f1fa8c" }}>"Tuesday"</span>:{"\n"}
                {"        "}System.out.println(<span style={{ color: "#f1fa8c" }}>"Start of week"</span>);{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>break</span>;  <span style={{ color: "#6272a4" }}>// Don't forget break!</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> <span style={{ color: "#f1fa8c" }}>"Friday"</span>:{"\n"}
                {"        "}System.out.println(<span style={{ color: "#f1fa8c" }}>"TGIF!"</span>);{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>break</span>;{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>default</span>:{"\n"}
                {"        "}System.out.println(<span style={{ color: "#f1fa8c" }}>"Regular day"</span>);{"\n"}
                {"}"}{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Modern switch expression (Java 14+) - cleaner!</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> dayType = <span style={{ color: "#ff79c6" }}>switch</span> (day) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> <span style={{ color: "#f1fa8c" }}>"Saturday"</span>, <span style={{ color: "#f1fa8c" }}>"Sunday"</span> -{">"} <span style={{ color: "#f1fa8c" }}>"Weekend"</span>;{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> <span style={{ color: "#f1fa8c" }}>"Monday"</span> -{">"} <span style={{ color: "#f1fa8c" }}>"Start of week"</span>;{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> <span style={{ color: "#f1fa8c" }}>"Friday"</span> -{">"} <span style={{ color: "#f1fa8c" }}>"Almost weekend!"</span>;{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>default</span> -{">"} <span style={{ color: "#f1fa8c" }}>"Midweek"</span>;{"\n"}
                {"}"};{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Switch with yield (for complex logic)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> numDays = <span style={{ color: "#ff79c6" }}>switch</span> (month) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> <span style={{ color: "#f1fa8c" }}>"February"</span> -{">"} {"{"}{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>boolean</span> isLeap = year % <span style={{ color: "#bd93f9" }}>4</span> == <span style={{ color: "#bd93f9" }}>0</span>;{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>yield</span> isLeap ? <span style={{ color: "#bd93f9" }}>29</span> : <span style={{ color: "#bd93f9" }}>28</span>;{"\n"}
                {"    "}{"}"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> <span style={{ color: "#f1fa8c" }}>"April"</span>, <span style={{ color: "#f1fa8c" }}>"June"</span>, <span style={{ color: "#f1fa8c" }}>"September"</span>, <span style={{ color: "#f1fa8c" }}>"November"</span> -{">"} <span style={{ color: "#bd93f9" }}>30</span>;{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>default</span> -{">"} <span style={{ color: "#bd93f9" }}>31</span>;{"\n"}
                {"}"};
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              Loops
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Loops execute a block of code repeatedly. Java provides several loop constructs for different use cases:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// FOR loop - when you know how many iterations</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> (<span style={{ color: "#8be9fd" }}>int</span> i = <span style={{ color: "#bd93f9" }}>0</span>; i {"<"} <span style={{ color: "#bd93f9" }}>5</span>; i++) {"{"}{"\n"}
                {"    "}System.out.println(<span style={{ color: "#f1fa8c" }}>"Iteration: "</span> + i);{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#6272a4" }}>// Output: 0, 1, 2, 3, 4</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// FOR-EACH (enhanced for) - for collections/arrays</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span>[] fruits = {"{"}<span style={{ color: "#f1fa8c" }}>"Apple"</span>, <span style={{ color: "#f1fa8c" }}>"Banana"</span>, <span style={{ color: "#f1fa8c" }}>"Cherry"</span>{"}"};{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> (<span style={{ color: "#8be9fd" }}>String</span> fruit : fruits) {"{"}{"\n"}
                {"    "}System.out.println(fruit);{"\n"}
                {"}"}{"\n\n"}
                <span style={{ color: "#6272a4" }}>// WHILE loop - condition checked before each iteration</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> count = <span style={{ color: "#bd93f9" }}>0</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>while</span> (count {"<"} <span style={{ color: "#bd93f9" }}>3</span>) {"{"}{"\n"}
                {"    "}System.out.println(<span style={{ color: "#f1fa8c" }}>"Count: "</span> + count);{"\n"}
                {"    "}count++;{"\n"}
                {"}"}{"\n\n"}
                <span style={{ color: "#6272a4" }}>// DO-WHILE loop - executes at least once</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> x = <span style={{ color: "#bd93f9" }}>0</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>do</span> {"{"}{"\n"}
                {"    "}System.out.println(<span style={{ color: "#f1fa8c" }}>"x = "</span> + x);{"\n"}
                {"    "}x++;{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>while</span> (x {"<"} <span style={{ color: "#bd93f9" }}>3</span>);
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              Break and Continue
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// BREAK - exit the loop entirely</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> (<span style={{ color: "#8be9fd" }}>int</span> i = <span style={{ color: "#bd93f9" }}>0</span>; i {"<"} <span style={{ color: "#bd93f9" }}>10</span>; i++) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>if</span> (i == <span style={{ color: "#bd93f9" }}>5</span>) {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>break</span>;  <span style={{ color: "#6272a4" }}>// Exit loop when i reaches 5</span>{"\n"}
                {"    "}{"}"}{"\n"}
                {"    "}System.out.println(i);{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#6272a4" }}>// Output: 0, 1, 2, 3, 4</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// CONTINUE - skip current iteration, continue loop</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> (<span style={{ color: "#8be9fd" }}>int</span> i = <span style={{ color: "#bd93f9" }}>0</span>; i {"<"} <span style={{ color: "#bd93f9" }}>5</span>; i++) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>if</span> (i == <span style={{ color: "#bd93f9" }}>2</span>) {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>continue</span>;  <span style={{ color: "#6272a4" }}>// Skip when i is 2</span>{"\n"}
                {"    "}{"}"}{"\n"}
                {"    "}System.out.println(i);{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#6272a4" }}>// Output: 0, 1, 3, 4</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Labeled break/continue for nested loops</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>outer</span>: <span style={{ color: "#ff79c6" }}>for</span> (<span style={{ color: "#8be9fd" }}>int</span> i = <span style={{ color: "#bd93f9" }}>0</span>; i {"<"} <span style={{ color: "#bd93f9" }}>3</span>; i++) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>for</span> (<span style={{ color: "#8be9fd" }}>int</span> j = <span style={{ color: "#bd93f9" }}>0</span>; j {"<"} <span style={{ color: "#bd93f9" }}>3</span>; j++) {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>if</span> (i == <span style={{ color: "#bd93f9" }}>1</span> && j == <span style={{ color: "#bd93f9" }}>1</span>) {"{"}{"\n"}
                {"            "}<span style={{ color: "#ff79c6" }}>break</span> <span style={{ color: "#50fa7b" }}>outer</span>;  <span style={{ color: "#6272a4" }}>// Break out of BOTH loops</span>{"\n"}
                {"        "}{"}"}{"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Grid container spacing={2}>
              {[
                { loop: "for", use: "Known number of iterations, counter-based" },
                { loop: "for-each", use: "Iterating over arrays/collections" },
                { loop: "while", use: "Unknown iterations, condition first" },
                { loop: "do-while", use: "Execute at least once, condition after" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.loop}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#38B2AC", 0.05) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#38B2AC", fontFamily: "monospace" }}>
                      {item.loop}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {item.use}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Arrays & Strings Section */}
          <Paper id="arrays" sx={{ p: 4, borderRadius: 3, background: `linear-gradient(135deg, ${alpha("#9F7AEA", 0.10)} 0%, ${alpha("#9F7AEA", 0.02)} 100%)`, border: `1px solid ${alpha("#9F7AEA", 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", mb: 3 }}>
              <StorageIcon sx={{ fontSize: 32, color: "#9F7AEA", mr: 2 }} />
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#9F7AEA" }}>
                Arrays & Strings
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Arrays and Strings are fundamental data structures in Java. <strong>Arrays</strong> store fixed-size collections of elements
              of the same type, while <strong>Strings</strong> represent sequences of characters with special immutability properties.
              Understanding both is essential for effective Java programming.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9F7AEA" }}>
              Declaring and Initializing Arrays
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Arrays in Java are objects that store multiple values of the same type. Once created, their size is fixed
              and cannot be changed. Array indices start at 0.
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Declaration syntaxes</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span>[] numbers;        <span style={{ color: "#6272a4" }}>// Preferred style</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> scores[];         <span style={{ color: "#6272a4" }}>// C-style (valid but less common)</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Creating arrays</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span>[] ages = <span style={{ color: "#ff79c6" }}>new</span> <span style={{ color: "#8be9fd" }}>int</span>[<span style={{ color: "#bd93f9" }}>5</span>];           <span style={{ color: "#6272a4" }}>// Array of 5 integers (default: 0)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span>[] names = <span style={{ color: "#ff79c6" }}>new</span> <span style={{ color: "#8be9fd" }}>String</span>[<span style={{ color: "#bd93f9" }}>3</span>]; <span style={{ color: "#6272a4" }}>// Array of 3 Strings (default: null)</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Array literal initialization</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span>[] primes = {"{"}<span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>5</span>, <span style={{ color: "#bd93f9" }}>7</span>, <span style={{ color: "#bd93f9" }}>11</span>{"}"};{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span>[] fruits = {"{"}<span style={{ color: "#f1fa8c" }}>"Apple"</span>, <span style={{ color: "#f1fa8c" }}>"Banana"</span>, <span style={{ color: "#f1fa8c" }}>"Cherry"</span>{"}"};{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Accessing and modifying elements</span>{"\n"}
                System.out.println(primes[<span style={{ color: "#bd93f9" }}>0</span>]);   <span style={{ color: "#6272a4" }}>// Output: 2 (first element)</span>{"\n"}
                System.out.println(primes[<span style={{ color: "#bd93f9" }}>4</span>]);   <span style={{ color: "#6272a4" }}>// Output: 11 (last element)</span>{"\n"}
                primes[<span style={{ color: "#bd93f9" }}>0</span>] = <span style={{ color: "#bd93f9" }}>13</span>;                  <span style={{ color: "#6272a4" }}>// Modify first element</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Array length property</span>{"\n"}
                System.out.println(primes.<span style={{ color: "#50fa7b" }}>length</span>); <span style={{ color: "#6272a4" }}>// Output: 5 (NOT a method!)</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9F7AEA" }}>
              Multi-Dimensional Arrays
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// 2D Array (matrix)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span>[][] matrix = <span style={{ color: "#ff79c6" }}>new</span> <span style={{ color: "#8be9fd" }}>int</span>[<span style={{ color: "#bd93f9" }}>3</span>][<span style={{ color: "#bd93f9" }}>4</span>];  <span style={{ color: "#6272a4" }}>// 3 rows, 4 columns</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// 2D array literal</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span>[][] grid = {"{"}{"\n"}
                {"    "}{"{"}<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>{"}"},     <span style={{ color: "#6272a4" }}>// Row 0</span>{"\n"}
                {"    "}{"{"}<span style={{ color: "#bd93f9" }}>4</span>, <span style={{ color: "#bd93f9" }}>5</span>, <span style={{ color: "#bd93f9" }}>6</span>{"}"},     <span style={{ color: "#6272a4" }}>// Row 1</span>{"\n"}
                {"    "}{"{"}<span style={{ color: "#bd93f9" }}>7</span>, <span style={{ color: "#bd93f9" }}>8</span>, <span style={{ color: "#bd93f9" }}>9</span>{"}"}      <span style={{ color: "#6272a4" }}>// Row 2</span>{"\n"}
                {"}"};{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Accessing elements</span>{"\n"}
                System.out.println(grid[<span style={{ color: "#bd93f9" }}>1</span>][<span style={{ color: "#bd93f9" }}>2</span>]);  <span style={{ color: "#6272a4" }}>// Output: 6 (row 1, column 2)</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Iterating through 2D array</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> (<span style={{ color: "#8be9fd" }}>int</span> i = <span style={{ color: "#bd93f9" }}>0</span>; i {"<"} grid.<span style={{ color: "#50fa7b" }}>length</span>; i++) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>for</span> (<span style={{ color: "#8be9fd" }}>int</span> j = <span style={{ color: "#bd93f9" }}>0</span>; j {"<"} grid[i].<span style={{ color: "#50fa7b" }}>length</span>; j++) {"{"}{"\n"}
                {"        "}System.out.print(grid[i][j] + <span style={{ color: "#f1fa8c" }}>" "</span>);{"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Jagged arrays (rows of different lengths)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span>[][] jagged = <span style={{ color: "#ff79c6" }}>new</span> <span style={{ color: "#8be9fd" }}>int</span>[<span style={{ color: "#bd93f9" }}>3</span>][];{"\n"}
                jagged[<span style={{ color: "#bd93f9" }}>0</span>] = <span style={{ color: "#ff79c6" }}>new</span> <span style={{ color: "#8be9fd" }}>int</span>[]{"{"}<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>{"}"};       <span style={{ color: "#6272a4" }}>// 2 elements</span>{"\n"}
                jagged[<span style={{ color: "#bd93f9" }}>1</span>] = <span style={{ color: "#ff79c6" }}>new</span> <span style={{ color: "#8be9fd" }}>int</span>[]{"{"}<span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>4</span>, <span style={{ color: "#bd93f9" }}>5</span>{"}"};    <span style={{ color: "#6272a4" }}>// 3 elements</span>{"\n"}
                jagged[<span style={{ color: "#bd93f9" }}>2</span>] = <span style={{ color: "#ff79c6" }}>new</span> <span style={{ color: "#8be9fd" }}>int</span>[]{"{"}<span style={{ color: "#bd93f9" }}>6</span>{"}"};          <span style={{ color: "#6272a4" }}>// 1 element</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9F7AEA" }}>
              Arrays Utility Class
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              The <code>java.util.Arrays</code> class provides many useful methods for working with arrays:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>import</span> java.util.Arrays;{"\n\n"}
                <span style={{ color: "#8be9fd" }}>int</span>[] nums = {"{"}<span style={{ color: "#bd93f9" }}>5</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>8</span>, <span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>9</span>{"}"};{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Sort array (in-place)</span>{"\n"}
                Arrays.<span style={{ color: "#50fa7b" }}>sort</span>(nums);  <span style={{ color: "#6272a4" }}>// nums is now {"{"}1, 2, 5, 8, 9{"}"}</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Binary search (array must be sorted!)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> index = Arrays.<span style={{ color: "#50fa7b" }}>binarySearch</span>(nums, <span style={{ color: "#bd93f9" }}>5</span>); <span style={{ color: "#6272a4" }}>// Returns 2</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Convert to String for printing</span>{"\n"}
                System.out.println(Arrays.<span style={{ color: "#50fa7b" }}>toString</span>(nums));{"\n"}
                <span style={{ color: "#6272a4" }}>// Output: [1, 2, 5, 8, 9]</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Fill array with value</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span>[] zeros = <span style={{ color: "#ff79c6" }}>new</span> <span style={{ color: "#8be9fd" }}>int</span>[<span style={{ color: "#bd93f9" }}>5</span>];{"\n"}
                Arrays.<span style={{ color: "#50fa7b" }}>fill</span>(zeros, <span style={{ color: "#bd93f9" }}>42</span>);  <span style={{ color: "#6272a4" }}>// All elements are now 42</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Copy array</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span>[] copy = Arrays.<span style={{ color: "#50fa7b" }}>copyOf</span>(nums, nums.<span style={{ color: "#50fa7b" }}>length</span>);{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span>[] partial = Arrays.<span style={{ color: "#50fa7b" }}>copyOfRange</span>(nums, <span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>4</span>); <span style={{ color: "#6272a4" }}>// Elements 1-3</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Compare arrays</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>boolean</span> equal = Arrays.<span style={{ color: "#50fa7b" }}>equals</span>(nums, copy); <span style={{ color: "#6272a4" }}>// true</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// For 2D arrays, use deepToString and deepEquals</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span>[][] matrix = {"{"}{"{"}<span style={{ color: "#bd93f9" }}>1</span>,<span style={{ color: "#bd93f9" }}>2</span>{"}"}, {"{"}<span style={{ color: "#bd93f9" }}>3</span>,<span style={{ color: "#bd93f9" }}>4</span>{"}"}{"}"};{"\n"}
                System.out.println(Arrays.<span style={{ color: "#50fa7b" }}>deepToString</span>(matrix));{"\n"}
                <span style={{ color: "#6272a4" }}>// Output: [[1, 2], [3, 4]]</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9F7AEA" }}>
              String Basics & Immutability
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Strings in Java are <strong>immutable</strong>—once created, they cannot be changed. Any operation that appears to 
              modify a String actually creates a new String object. Java maintains a <strong>String pool</strong> for efficiency.
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// String creation</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> s1 = <span style={{ color: "#f1fa8c" }}>"Hello"</span>;         <span style={{ color: "#6272a4" }}>// String literal (stored in pool)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> s2 = <span style={{ color: "#f1fa8c" }}>"Hello"</span>;         <span style={{ color: "#6272a4" }}>// Same object as s1 (from pool)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> s3 = <span style={{ color: "#ff79c6" }}>new</span> String(<span style={{ color: "#f1fa8c" }}>"Hello"</span>); <span style={{ color: "#6272a4" }}>// New object (not from pool)</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// String pool behavior</span>{"\n"}
                System.out.println(s1 == s2);     <span style={{ color: "#6272a4" }}>// true (same reference)</span>{"\n"}
                System.out.println(s1 == s3);     <span style={{ color: "#6272a4" }}>// false (different objects)</span>{"\n"}
                System.out.println(s1.<span style={{ color: "#50fa7b" }}>equals</span>(s3)); <span style={{ color: "#6272a4" }}>// true (same content)</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Always use .equals() for String comparison!</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Immutability demonstration</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> original = <span style={{ color: "#f1fa8c" }}>"Java"</span>;{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> modified = original.<span style={{ color: "#50fa7b" }}>concat</span>(<span style={{ color: "#f1fa8c" }}>" Programming"</span>);{"\n"}
                System.out.println(original);  <span style={{ color: "#6272a4" }}>// Still "Java"</span>{"\n"}
                System.out.println(modified);  <span style={{ color: "#6272a4" }}>// "Java Programming" (new String)</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9F7AEA" }}>
              Common String Methods
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#8be9fd" }}>String</span> text = <span style={{ color: "#f1fa8c" }}>"  Hello, Java World!  "</span>;{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Length and character access</span>{"\n"}
                text.<span style={{ color: "#50fa7b" }}>length</span>();           <span style={{ color: "#6272a4" }}>// 23</span>{"\n"}
                text.<span style={{ color: "#50fa7b" }}>charAt</span>(<span style={{ color: "#bd93f9" }}>8</span>);          <span style={{ color: "#6272a4" }}>// 'J' (0-indexed)</span>{"\n"}
                text.<span style={{ color: "#50fa7b" }}>isEmpty</span>();          <span style={{ color: "#6272a4" }}>// false</span>{"\n"}
                text.<span style={{ color: "#50fa7b" }}>isBlank</span>();          <span style={{ color: "#6272a4" }}>// false (Java 11+)</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Case conversion</span>{"\n"}
                text.<span style={{ color: "#50fa7b" }}>toUpperCase</span>();      <span style={{ color: "#6272a4" }}>// "  HELLO, JAVA WORLD!  "</span>{"\n"}
                text.<span style={{ color: "#50fa7b" }}>toLowerCase</span>();      <span style={{ color: "#6272a4" }}>// "  hello, java world!  "</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Trimming whitespace</span>{"\n"}
                text.<span style={{ color: "#50fa7b" }}>trim</span>();             <span style={{ color: "#6272a4" }}>// "Hello, Java World!"</span>{"\n"}
                text.<span style={{ color: "#50fa7b" }}>strip</span>();            <span style={{ color: "#6272a4" }}>// Same, but handles Unicode (Java 11+)</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Searching</span>{"\n"}
                text.<span style={{ color: "#50fa7b" }}>indexOf</span>(<span style={{ color: "#f1fa8c" }}>"Java"</span>);     <span style={{ color: "#6272a4" }}>// 9 (first occurrence)</span>{"\n"}
                text.<span style={{ color: "#50fa7b" }}>lastIndexOf</span>(<span style={{ color: "#f1fa8c" }}>"o"</span>);   <span style={{ color: "#6272a4" }}>// 17 (last occurrence)</span>{"\n"}
                text.<span style={{ color: "#50fa7b" }}>contains</span>(<span style={{ color: "#f1fa8c" }}>"World"</span>);   <span style={{ color: "#6272a4" }}>// true</span>{"\n"}
                text.<span style={{ color: "#50fa7b" }}>startsWith</span>(<span style={{ color: "#f1fa8c" }}>"  H"</span>);  <span style={{ color: "#6272a4" }}>// true</span>{"\n"}
                text.<span style={{ color: "#50fa7b" }}>endsWith</span>(<span style={{ color: "#f1fa8c" }}>"!  "</span>);    <span style={{ color: "#6272a4" }}>// true</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Extracting substrings</span>{"\n"}
                text.<span style={{ color: "#50fa7b" }}>substring</span>(<span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>7</span>);     <span style={{ color: "#6272a4" }}>// "Hello" (start inclusive, end exclusive)</span>{"\n"}
                text.<span style={{ color: "#50fa7b" }}>substring</span>(<span style={{ color: "#bd93f9" }}>9</span>);        <span style={{ color: "#6272a4" }}>// "Java World!  " (from index to end)</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Replacing</span>{"\n"}
                text.<span style={{ color: "#50fa7b" }}>replace</span>(<span style={{ color: "#f1fa8c" }}>'o'</span>, <span style={{ color: "#f1fa8c" }}>'0'</span>);      <span style={{ color: "#6272a4" }}>// "  Hell0, Java W0rld!  "</span>{"\n"}
                text.<span style={{ color: "#50fa7b" }}>replace</span>(<span style={{ color: "#f1fa8c" }}>"Java"</span>, <span style={{ color: "#f1fa8c" }}>"Python"</span>); <span style={{ color: "#6272a4" }}>// "  Hello, Python World!  "</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Splitting</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> csv = <span style={{ color: "#f1fa8c" }}>"apple,banana,cherry"</span>;{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span>[] parts = csv.<span style={{ color: "#50fa7b" }}>split</span>(<span style={{ color: "#f1fa8c" }}>","</span>); <span style={{ color: "#6272a4" }}>// ["apple", "banana", "cherry"]</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Joining (Java 8+)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> joined = String.<span style={{ color: "#50fa7b" }}>join</span>(<span style={{ color: "#f1fa8c" }}>" - "</span>, parts);{"\n"}
                <span style={{ color: "#6272a4" }}>// "apple - banana - cherry"</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9F7AEA" }}>
              StringBuilder & StringBuffer
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              When you need to modify strings frequently, use <code>StringBuilder</code> (not thread-safe, faster) or 
              <code>StringBuffer</code> (thread-safe, slower). These are mutable and avoid creating many String objects.
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// StringBuilder - preferred for single-threaded code</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>StringBuilder</span> sb = <span style={{ color: "#ff79c6" }}>new</span> StringBuilder();{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Append various types</span>{"\n"}
                sb.<span style={{ color: "#50fa7b" }}>append</span>(<span style={{ color: "#f1fa8c" }}>"Hello"</span>);{"\n"}
                sb.<span style={{ color: "#50fa7b" }}>append</span>(<span style={{ color: "#f1fa8c" }}>" "</span>);{"\n"}
                sb.<span style={{ color: "#50fa7b" }}>append</span>(<span style={{ color: "#f1fa8c" }}>"World"</span>);{"\n"}
                sb.<span style={{ color: "#50fa7b" }}>append</span>(<span style={{ color: "#bd93f9" }}>2024</span>);{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Method chaining</span>{"\n"}
                sb.<span style={{ color: "#50fa7b" }}>append</span>(<span style={{ color: "#f1fa8c" }}>"!"</span>).<span style={{ color: "#50fa7b" }}>append</span>(<span style={{ color: "#f1fa8c" }}>" Java"</span>).<span style={{ color: "#50fa7b" }}>append</span>(<span style={{ color: "#f1fa8c" }}>" Rocks"</span>);{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Insert at position</span>{"\n"}
                sb.<span style={{ color: "#50fa7b" }}>insert</span>(<span style={{ color: "#bd93f9" }}>5</span>, <span style={{ color: "#f1fa8c" }}>" Dear"</span>);{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Delete characters</span>{"\n"}
                sb.<span style={{ color: "#50fa7b" }}>delete</span>(<span style={{ color: "#bd93f9" }}>0</span>, <span style={{ color: "#bd93f9" }}>5</span>);     <span style={{ color: "#6272a4" }}>// Remove first 5 chars</span>{"\n"}
                sb.<span style={{ color: "#50fa7b" }}>deleteCharAt</span>(<span style={{ color: "#bd93f9" }}>0</span>); <span style={{ color: "#6272a4" }}>// Remove char at index 0</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Reverse</span>{"\n"}
                sb.<span style={{ color: "#50fa7b" }}>reverse</span>();{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Convert to String</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> result = sb.<span style={{ color: "#50fa7b" }}>toString</span>();{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Performance comparison</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// BAD - creates many String objects:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> s = <span style={{ color: "#f1fa8c" }}>""</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> (<span style={{ color: "#8be9fd" }}>int</span> i = <span style={{ color: "#bd93f9" }}>0</span>; i {"<"} <span style={{ color: "#bd93f9" }}>1000</span>; i++) {"{"}{"\n"}
                {"    "}s += i;  <span style={{ color: "#6272a4" }}>// Creates new String each iteration!</span>{"\n"}
                {"}"}{"\n\n"}
                <span style={{ color: "#6272a4" }}>// GOOD - efficient:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>StringBuilder</span> builder = <span style={{ color: "#ff79c6" }}>new</span> StringBuilder();{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> (<span style={{ color: "#8be9fd" }}>int</span> i = <span style={{ color: "#bd93f9" }}>0</span>; i {"<"} <span style={{ color: "#bd93f9" }}>1000</span>; i++) {"{"}{"\n"}
                {"    "}builder.<span style={{ color: "#50fa7b" }}>append</span>(i);{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9F7AEA" }}>
              String Formatting
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#8be9fd" }}>String</span> name = <span style={{ color: "#f1fa8c" }}>"Alice"</span>;{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> age = <span style={{ color: "#bd93f9" }}>30</span>;{"\n"}
                <span style={{ color: "#8be9fd" }}>double</span> salary = <span style={{ color: "#bd93f9" }}>75000.5</span>;{"\n\n"}
                <span style={{ color: "#6272a4" }}>// String.format() - printf-style formatting</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> info = String.<span style={{ color: "#50fa7b" }}>format</span>(<span style={{ color: "#f1fa8c" }}>"%s is %d years old"</span>, name, age);{"\n"}
                <span style={{ color: "#6272a4" }}>// "Alice is 30 years old"</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Common format specifiers</span>{"\n"}
                String.<span style={{ color: "#50fa7b" }}>format</span>(<span style={{ color: "#f1fa8c" }}>"String: %s"</span>, name);        <span style={{ color: "#6272a4" }}>// %s - String</span>{"\n"}
                String.<span style={{ color: "#50fa7b" }}>format</span>(<span style={{ color: "#f1fa8c" }}>"Integer: %d"</span>, age);       <span style={{ color: "#6272a4" }}>// %d - decimal integer</span>{"\n"}
                String.<span style={{ color: "#50fa7b" }}>format</span>(<span style={{ color: "#f1fa8c" }}>"Float: %.2f"</span>, salary);   <span style={{ color: "#6272a4" }}>// %.2f - 2 decimal places</span>{"\n"}
                String.<span style={{ color: "#50fa7b" }}>format</span>(<span style={{ color: "#f1fa8c" }}>"Hex: %x"</span>, <span style={{ color: "#bd93f9" }}>255</span>);          <span style={{ color: "#6272a4" }}>// %x - hexadecimal → "ff"</span>{"\n"}
                String.<span style={{ color: "#50fa7b" }}>format</span>(<span style={{ color: "#f1fa8c" }}>"Padded: %10s"</span>, name);    <span style={{ color: "#6272a4" }}>// Right-pad to 10 chars</span>{"\n"}
                String.<span style={{ color: "#50fa7b" }}>format</span>(<span style={{ color: "#f1fa8c" }}>"Left: %-10s"</span>, name);     <span style={{ color: "#6272a4" }}>// Left-pad to 10 chars</span>{"\n"}
                String.<span style={{ color: "#50fa7b" }}>format</span>(<span style={{ color: "#f1fa8c" }}>"Zero: %05d"</span>, <span style={{ color: "#bd93f9" }}>42</span>);       <span style={{ color: "#6272a4" }}>// Zero-pad → "00042"</span>{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Text blocks (Java 15+) - multiline strings</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> json = <span style={{ color: "#f1fa8c" }}>"""</span>{"\n"}
                {"    "}{"{"}{"\n"}
                {"        "}"name": "Alice",{"\n"}
                {"        "}"age": 30{"\n"}
                {"    "}{"}"}{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>"""</span>;{"\n\n"}
                <span style={{ color: "#6272a4" }}>// Formatted text blocks (Java 15+)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>String</span> formatted = <span style={{ color: "#f1fa8c" }}>"""</span>{"\n"}
                {"    "}Name: %s{"\n"}
                {"    "}Age: %d{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>"""</span>.<span style={{ color: "#50fa7b" }}>formatted</span>(name, age);
              </Typography>
            </Paper>

            <Grid container spacing={2}>
              {[
                { method: "length()", desc: "Number of characters in String" },
                { method: "charAt(i)", desc: "Character at index i" },
                { method: "equals()", desc: "Compare content (not ==)" },
                { method: "substring()", desc: "Extract portion of String" },
                { method: "split()", desc: "Divide into array by delimiter" },
                { method: "trim()/strip()", desc: "Remove leading/trailing spaces" },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.method}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#9F7AEA", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#9F7AEA", fontFamily: "monospace" }}>
                      {item.method}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* OOP Fundamentals Placeholder */}
          <TopicPlaceholder
            id="oop-basics"
            title="OOP Fundamentals"
            icon={<ClassIcon />}
            color="#E53E3E"
            description="Understand object-oriented programming: classes as blueprints, objects as instances, fields (instance variables), methods, constructors (default, parameterized, overloading), the 'this' keyword, access modifiers (public, private, protected, default), encapsulation with getters/setters, static members vs. instance members, and the object lifecycle."
          />

          {/* Inheritance & Polymorphism Placeholder */}
          <TopicPlaceholder
            id="inheritance"
            title="Inheritance & Polymorphism"
            icon={<LayersIcon />}
            color="#DD6B20"
            description="Build class hierarchies: extending classes with 'extends', the Object class (root of all classes), method overriding and @Override annotation, super keyword for parent access, constructor chaining, polymorphism (compile-time vs. runtime), method overloading, type casting with instanceof, and the final keyword to prevent inheritance."
          />

          {/* Interfaces & Abstract Classes Placeholder */}
          <TopicPlaceholder
            id="interfaces"
            title="Interfaces & Abstract Classes"
            icon={<ExtensionIcon />}
            color="#319795"
            description="Design with abstraction: abstract classes and abstract methods, interfaces and multiple inheritance, default and static interface methods (Java 8+), private interface methods (Java 9+), functional interfaces and @FunctionalInterface, marker interfaces, sealed interfaces (Java 17+), when to use abstract classes vs. interfaces, and common design patterns."
          />

          {/* Exception Handling Placeholder */}
          <TopicPlaceholder
            id="exceptions"
            title="Exception Handling"
            icon={<BugReportIcon />}
            color="#E53E3E"
            description="Handle errors gracefully: the exception hierarchy (Throwable, Exception, Error), checked vs. unchecked exceptions, try-catch-finally blocks, try-with-resources for automatic cleanup, throwing exceptions with 'throw', declaring exceptions with 'throws', creating custom exceptions, exception chaining, best practices for exception handling."
          />

          {/* Collections Framework Placeholder */}
          <TopicPlaceholder
            id="collections"
            title="Collections Framework"
            icon={<CategoryIcon />}
            color="#805AD5"
            description="Master data structures: Collection interface hierarchy, List implementations (ArrayList, LinkedList), Set implementations (HashSet, TreeSet, LinkedHashSet), Map implementations (HashMap, TreeMap, LinkedHashMap), Queue and Deque, iterating with Iterator and for-each, Comparable vs. Comparator, Collections utility class, and choosing the right collection."
          />

          {/* Generics Placeholder */}
          <TopicPlaceholder
            id="generics"
            title="Generics"
            icon={<AutoFixHighIcon />}
            color="#D69E2E"
            description="Write type-safe reusable code: generic classes and methods, type parameters and naming conventions, bounded type parameters (extends, super), wildcards (?, extends, super), type erasure and its implications, generic inheritance, restrictions on generics, and practical patterns for using generics effectively."
          />

          {/* I/O & File Handling Placeholder */}
          <TopicPlaceholder
            id="io"
            title="I/O & File Handling"
            icon={<FolderIcon />}
            color="#3182CE"
            description="Work with files and streams: byte streams vs. character streams, FileInputStream/FileOutputStream, FileReader/FileWriter, BufferedReader/BufferedWriter, the java.nio.file package (Files, Paths), reading and writing text files, working with binary data, serialization and deserialization, Properties files, and file system operations."
          />

          {/* Multithreading Placeholder */}
          <TopicPlaceholder
            id="multithreading"
            title="Multithreading"
            icon={<SyncIcon />}
            color="#2B6CB0"
            description="Write concurrent programs: creating threads (Thread class vs. Runnable), thread lifecycle and states, synchronization and locks, the synchronized keyword, volatile variables, wait/notify/notifyAll, thread pools with ExecutorService, Callable and Future, concurrent collections, atomic variables, deadlock prevention, and modern concurrency with virtual threads."
          />

          {/* Lambdas & Streams Placeholder */}
          <TopicPlaceholder
            id="lambdas"
            title="Lambdas & Streams"
            icon={<StreamIcon />}
            color="#00B5D8"
            description="Embrace functional programming: lambda expression syntax, functional interfaces (Predicate, Function, Consumer, Supplier), method references, the Stream API, intermediate operations (filter, map, flatMap, sorted), terminal operations (collect, reduce, forEach), parallel streams, Optional class for null safety, and practical functional patterns."
          />

          {/* JDBC & Databases Placeholder */}
          <TopicPlaceholder
            id="jdbc"
            title="JDBC & Databases"
            icon={<StorageIcon />}
            color="#68D391"
            description="Connect to databases: JDBC architecture and drivers, establishing connections, executing queries with Statement and PreparedStatement, processing ResultSets, transactions and commit/rollback, connection pooling basics, batch processing, stored procedures, handling SQL exceptions, and introduction to JPA/Hibernate for ORM."
          />

          {/* Networking Placeholder */}
          <TopicPlaceholder
            id="networking"
            title="Networking"
            icon={<HubIcon />}
            color="#FC8181"
            description="Build networked applications: TCP/IP fundamentals, Socket and ServerSocket classes, URL and HttpURLConnection, the modern HttpClient (Java 11+), building client-server applications, handling multiple clients, UDP with DatagramSocket, working with JSON (Jackson, Gson), REST API consumption, and WebSocket basics."
          />

          {/* Frameworks & Ecosystem Placeholder */}
          <TopicPlaceholder
            id="frameworks"
            title="Frameworks & Ecosystem"
            icon={<IntegrationInstructionsIcon />}
            color="#B794F4"
            description="Explore the Java ecosystem: Spring Framework and Spring Boot for enterprise applications, dependency injection and IoC, Spring MVC for web applications, Spring Data for persistence, testing with JUnit 5 and Mockito, build automation with Maven and Gradle, logging with SLF4J and Logback, and an overview of microservices architecture."
          />

          {/* Advanced Topics Placeholder */}
          <TopicPlaceholder
            id="advanced"
            title="Advanced Topics"
            icon={<DeveloperBoardIcon />}
            color="#718096"
            description="Master advanced concepts: reflection and annotations, class loading and the classpath, JVM internals and garbage collection tuning, native compilation with GraalVM, modules (Java 9+), design patterns in Java, performance optimization, security best practices, debugging and profiling tools, and preparing for Java certifications."
          />

          {/* Knowledge Quiz Section */}
          <Paper id="quiz" sx={{ p: 4, borderRadius: 3, background: `linear-gradient(135deg, ${alpha("#667EEA", 0.10)} 0%, ${alpha("#764BA2", 0.05)} 100%)`, border: `1px solid ${alpha("#667EEA", 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", mb: 3 }}>
              <QuizIcon sx={{ fontSize: 32, color: "#667EEA", mr: 2 }} />
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#667EEA" }}>
                Java Knowledge Quiz
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Test your understanding of Java concepts with this interactive quiz. Each attempt randomly selects
              <strong> 10 questions</strong> from a bank of <strong>75 questions</strong> covering all topics.
              See how well you've mastered the fundamentals!
            </Typography>

            <JavaQuiz />
          </Paper>

          {/* Continue Your Journey */}
          <Paper sx={{ p: 4, borderRadius: 4, border: `1px solid ${alpha(accentColor, 0.2)}` }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 2 }}>
              Continue Your Journey
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              After mastering Java, explore related topics to expand your expertise:
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              {[
                { label: "Kotlin Programming", path: "/learn/kotlin-programming" },
                { label: "Spring Boot", path: "/learn/spring-boot" },
                { label: "Python Programming", path: "/learn/python-programming" },
                { label: "SQL Databases", path: "/learn/sql-databases" },
                { label: "Computer Networking", path: "/learn/networking" },
                { label: "Data Structures", path: "/learn/data-structures" },
                { label: "Design Patterns", path: "/learn/design-patterns" },
                { label: "Cloud Computing", path: "/learn/cloud-computing" },
              ].map((item) => (
                <Chip
                  key={item.label}
                  label={item.label}
                  onClick={() => navigate(item.path)}
                  sx={{
                    cursor: "pointer",
                    fontWeight: 600,
                    "&:hover": { bgcolor: alpha(accentColor, 0.15) },
                  }}
                  clickable
                />
              ))}
            </Box>
          </Paper>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
