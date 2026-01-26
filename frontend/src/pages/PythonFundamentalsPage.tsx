import React, { useState, useEffect } from "react";
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
  Alert,
  AlertTitle,
  Radio,
  RadioGroup,
  FormControlLabel,
  Divider,
  alpha,
  useTheme,
  Fab,
  Drawer,
  IconButton,
  Tooltip,
  useMediaQuery,
  LinearProgress,
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
import CodeIcon from "@mui/icons-material/Code";
import SchoolIcon from "@mui/icons-material/School";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import TerminalIcon from "@mui/icons-material/Terminal";
import StorageIcon from "@mui/icons-material/Storage";
import BuildIcon from "@mui/icons-material/Build";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import DataObjectIcon from "@mui/icons-material/DataObject";
import LoopIcon from "@mui/icons-material/Loop";
import FunctionsIcon from "@mui/icons-material/Functions";
import FolderIcon from "@mui/icons-material/Folder";
import BugReportIcon from "@mui/icons-material/BugReport";
import ExtensionIcon from "@mui/icons-material/Extension";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import CategoryIcon from "@mui/icons-material/Category";
import SecurityIcon from "@mui/icons-material/Security";
import SpeedIcon from "@mui/icons-material/Speed";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import WarningIcon from "@mui/icons-material/Warning";
import InfoIcon from "@mui/icons-material/Info";
import NavigateNextIcon from "@mui/icons-material/NavigateNext";
import TimerIcon from "@mui/icons-material/Timer";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import ListAltIcon from "@mui/icons-material/ListAlt";
import { Link, useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";

// ==================== QUIZ SECTION ====================
interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  topic: string;
}

// Full 75-question bank covering Python fundamentals
const questionBank: QuizQuestion[] = [
  // ==================== Topic 1: Getting Started (Questions 1-15) ====================
  { id: 1, question: "What is Python?", options: ["A database", "A high-level programming language", "An operating system", "A web browser"], correctAnswer: 1, explanation: "Python is a high-level programming language designed for readability and productivity.", topic: "Getting Started" },
  { id: 2, question: "How are code blocks defined in Python?", options: ["Curly braces {}", "Parentheses ()", "Indentation and colons", "Semicolons ;"], correctAnswer: 2, explanation: "Python uses indentation and a trailing colon to define code blocks such as functions and loops.", topic: "Getting Started" },
  { id: 3, question: "Which function prints text to the screen?", options: ["echo()", "display()", "print()", "write()"], correctAnswer: 2, explanation: "print() sends output to the console or terminal.", topic: "Getting Started" },
  { id: 4, question: "How do you write a single-line comment in Python?", options: ["// comment", "# comment", "/* comment */", "<!-- comment -->"], correctAnswer: 1, explanation: "Python uses the # symbol for single-line comments.", topic: "Getting Started" },
  { id: 5, question: "How does Python typically execute code?", options: ["It compiles to machine code first", "It is interpreted by the Python runtime", "It runs only inside a browser", "It is executed by the database"], correctAnswer: 1, explanation: "Python code is executed by the Python interpreter at runtime.", topic: "Getting Started" },
  { id: 6, question: "Which command runs a Python script named app.py?", options: ["run app.py", "python app.py", "start app.py", "execute app.py"], correctAnswer: 1, explanation: "python app.py runs the script using the interpreter on your PATH.", topic: "Getting Started" },
  { id: 7, question: "What does REPL stand for?", options: ["Read Execute Print List", "Run Evaluate Print Loop", "Read Evaluate Print Loop", "Read Edit Print Loop"], correctAnswer: 2, explanation: "REPL stands for Read Evaluate Print Loop, an interactive Python prompt.", topic: "Getting Started" },
  { id: 8, question: "Which keyword loads a module?", options: ["include", "use", "import", "load"], correctAnswer: 2, explanation: "import brings a module into your program.", topic: "Getting Started" },
  { id: 9, question: "Are variable names case-sensitive in Python?", options: ["Yes", "No", "Only in functions", "Only in classes"], correctAnswer: 0, explanation: "name and Name refer to different variables in Python.", topic: "Getting Started" },
  { id: 10, question: "What is the common naming style for variables in Python?", options: ["camelCase", "snake_case", "PascalCase", "kebab-case"], correctAnswer: 1, explanation: "Python style guides recommend snake_case for variables and functions.", topic: "Getting Started" },
  { id: 11, question: "What is PEP 8?", options: ["A Python package", "A style guide for Python code", "A debugging tool", "A testing framework"], correctAnswer: 1, explanation: "PEP 8 describes recommended formatting and style rules for Python code.", topic: "Getting Started" },
  { id: 12, question: "What does the value None represent?", options: ["Zero", "An empty string", "No value or missing value", "False"], correctAnswer: 2, explanation: "None is a special value that represents the absence of a value.", topic: "Getting Started" },
  { id: 13, question: "Which statement does nothing but keeps code syntactically valid?", options: ["stop", "skip", "pass", "empty"], correctAnswer: 2, explanation: "pass is a placeholder statement that does nothing.", topic: "Getting Started" },
  { id: 14, question: "What is pip used for?", options: ["Running Python files", "Managing Python packages", "Formatting code", "Debugging scripts"], correctAnswer: 1, explanation: "pip is the package installer for Python.", topic: "Getting Started" },
  { id: 15, question: "Why use a virtual environment?", options: ["To speed up Python execution", "To isolate project dependencies", "To hide source code", "To run code in the browser"], correctAnswer: 1, explanation: "Virtual environments keep project dependencies separate from system Python packages.", topic: "Getting Started" },

  // ==================== Topic 2: Data Types and Expressions (Questions 16-30) ====================
  { id: 16, question: "Which type represents whole numbers?", options: ["float", "int", "str", "bool"], correctAnswer: 1, explanation: "int is used for whole numbers like 1, 42, or -7.", topic: "Data Types" },
  { id: 17, question: "Which type represents decimal numbers?", options: ["float", "int", "str", "list"], correctAnswer: 0, explanation: "float stores numbers with decimal points like 3.14.", topic: "Data Types" },
  { id: 18, question: "Which type represents text?", options: ["str", "int", "bool", "set"], correctAnswer: 0, explanation: "str is the string type used for text.", topic: "Data Types" },
  { id: 19, question: "Which value is a boolean?", options: ["0", "\"True\"", "True", "1.0"], correctAnswer: 2, explanation: "True and False are the two boolean values in Python.", topic: "Data Types" },
  { id: 20, question: "What is the main difference between a list and a tuple?", options: ["Lists are immutable, tuples are mutable", "Lists are mutable, tuples are immutable", "Lists are only for numbers", "Tuples cannot be indexed"], correctAnswer: 1, explanation: "Lists can be changed after creation, while tuples are immutable.", topic: "Data Types" },
  { id: 21, question: "Which data type stores key-value pairs?", options: ["list", "tuple", "dict", "set"], correctAnswer: 2, explanation: "A dictionary (dict) maps keys to values.", topic: "Data Types" },
  { id: 22, question: "Which data type stores unique, unordered values?", options: ["list", "tuple", "dict", "set"], correctAnswer: 3, explanation: "A set stores unique elements without a guaranteed order.", topic: "Data Types" },
  { id: 23, question: "Which function returns the type of a value?", options: ["type()", "kind()", "what()", "dtype()"], correctAnswer: 0, explanation: "type(value) tells you the type of a variable or literal.", topic: "Data Types" },
  { id: 24, question: "What does int(\"5\") return?", options: ["The string \"5\"", "The number 5", "An error", "None"], correctAnswer: 1, explanation: "int(\"5\") converts the string to the integer 5.", topic: "Data Types" },
  { id: 25, question: "What does the // operator do?", options: ["Regular division", "Floor division", "Modulo", "Exponentiation"], correctAnswer: 1, explanation: "Floor division returns the quotient without the fractional part.", topic: "Data Types" },
  { id: 26, question: "What does the % operator do?", options: ["Exponentiation", "Modulo (remainder)", "String join", "Floor division"], correctAnswer: 1, explanation: "% returns the remainder from division.", topic: "Data Types" },
  { id: 27, question: "What does the ** operator do?", options: ["Multiply", "Exponentiation", "Bitwise XOR", "String repeat"], correctAnswer: 1, explanation: "** raises a number to a power, like 2 ** 3 = 8.", topic: "Data Types" },
  { id: 28, question: "Which operator checks equality?", options: ["=", "==", "!=", ":="], correctAnswer: 1, explanation: "== compares values, while = assigns a value.", topic: "Data Types" },
  { id: 29, question: "Which value is considered falsy?", options: ["\"hello\"", "1", "[]", "True"], correctAnswer: 2, explanation: "Empty lists, empty strings, 0, and None are falsy.", topic: "Data Types" },
  { id: 30, question: "What does len([1, 2, 3]) return?", options: ["0", "2", "3", "4"], correctAnswer: 2, explanation: "len returns the number of elements in a sequence.", topic: "Data Types" },
  // ==================== Topic 3: Control Flow and Iteration (Questions 31-45) ====================
  { id: 31, question: "Which keyword begins a conditional block?", options: ["if", "for", "def", "class"], correctAnswer: 0, explanation: "if starts a conditional branch.", topic: "Control Flow" },
  { id: 32, question: "What does elif mean?", options: ["End if", "Else if", "Else for", "Error if"], correctAnswer: 1, explanation: "elif is used for additional conditions after an if statement.", topic: "Control Flow" },
  { id: 33, question: "How do you start a loop that runs 5 times?", options: ["for i in range(5):", "for i in 5:", "loop 5 times:", "range(5):"], correctAnswer: 0, explanation: "range(5) produces 0 through 4, which is five iterations.", topic: "Control Flow" },
  { id: 34, question: "What does range(3) produce?", options: ["1, 2, 3", "0, 1, 2", "0, 1, 2, 3", "1, 2"], correctAnswer: 1, explanation: "range(3) yields 0, 1, 2.", topic: "Control Flow" },
  { id: 35, question: "Which loop repeats while a condition is true?", options: ["for", "while", "if", "repeat"], correctAnswer: 1, explanation: "while loops keep running as long as the condition stays true.", topic: "Control Flow" },
  { id: 36, question: "What does break do in a loop?", options: ["Skips to the next iteration", "Stops the loop completely", "Restarts the loop", "Pauses the loop"], correctAnswer: 1, explanation: "break exits the loop immediately.", topic: "Control Flow" },
  { id: 37, question: "What does continue do in a loop?", options: ["Exits the loop", "Skips to the next iteration", "Stops the program", "Pauses the loop"], correctAnswer: 1, explanation: "continue skips the rest of the current loop body.", topic: "Control Flow" },
  { id: 38, question: "Which operator checks membership?", options: ["in", "is", "has", "contains"], correctAnswer: 0, explanation: "Use in to check if an item is inside a list, string, or other container.", topic: "Control Flow" },
  { id: 39, question: "Which expression is true?", options: ["True and False", "True or False", "False and False", "not True"], correctAnswer: 1, explanation: "True or False evaluates to True.", topic: "Control Flow" },
  { id: 40, question: "What does 0 < x < 10 check?", options: ["x equals 0 or 10", "x is between 0 and 10", "x is greater than 10", "x is not equal to 10"], correctAnswer: 1, explanation: "Python supports chained comparisons for ranges.", topic: "Control Flow" },
  { id: 41, question: "Which is a list comprehension?", options: ["[x for x in range(5)]", "list(range(5))", "for x in range(5):", "{x: x for x in range(5)}"], correctAnswer: 0, explanation: "List comprehensions build lists in a compact expression.", topic: "Control Flow" },
  { id: 42, question: "What does enumerate do?", options: ["Sorts a list", "Returns index-value pairs", "Removes duplicates", "Counts characters"], correctAnswer: 1, explanation: "enumerate adds an index to each item in an iterable.", topic: "Control Flow" },
  { id: 43, question: "When does a loop else block run?", options: ["Always", "Only if the loop finishes without break", "Only if break is used", "Only in while loops"], correctAnswer: 1, explanation: "The else block runs when the loop completes normally.", topic: "Control Flow" },
  { id: 44, question: "What type does input() return?", options: ["int", "float", "str", "bool"], correctAnswer: 2, explanation: "input() always returns a string, even if you type numbers.", topic: "Control Flow" },
  { id: 45, question: "How do you convert input to an integer?", options: ["int(input())", "input(int)", "integer(input())", "input().int()"], correctAnswer: 0, explanation: "Use int(...) to convert a string to an integer if it is valid.", topic: "Control Flow" },

  // ==================== Topic 4: Functions and Modules (Questions 46-60) ====================
  { id: 46, question: "Which keyword defines a function?", options: ["func", "def", "lambda", "function"], correctAnswer: 1, explanation: "def starts a function definition in Python.", topic: "Functions and Modules" },
  { id: 47, question: "What does a return statement do?", options: ["Prints a value", "Ends the function and sends back a value", "Restarts the function", "Skips one line"], correctAnswer: 1, explanation: "return exits the function and provides a result to the caller.", topic: "Functions and Modules" },
  { id: 48, question: "What is a default parameter?", options: ["A parameter with a starting value", "A parameter that is required", "A parameter that is always a string", "A parameter inside a loop"], correctAnswer: 0, explanation: "Default parameters provide a value if the caller does not pass one.", topic: "Functions and Modules" },
  { id: 49, question: "What does *args allow?", options: ["A list of named arguments", "Multiple positional arguments", "Only keyword arguments", "Optional imports"], correctAnswer: 1, explanation: "*args collects extra positional arguments into a tuple.", topic: "Functions and Modules" },
  { id: 50, question: "What does **kwargs allow?", options: ["Multiple keyword arguments", "Only positional arguments", "No arguments", "Arguments without names"], correctAnswer: 0, explanation: "**kwargs collects extra keyword arguments into a dictionary.", topic: "Functions and Modules" },
  { id: 51, question: "What is a local variable?", options: ["A variable defined inside a function", "A variable in a different file", "A variable in the OS", "A variable in the global scope"], correctAnswer: 0, explanation: "Local variables exist only within the function where they are defined.", topic: "Functions and Modules" },
  { id: 52, question: "What is a docstring?", options: ["A comment after code", "A string that documents a function or module", "A special file extension", "A type of error"], correctAnswer: 1, explanation: "Docstrings are placed right after a function or class definition to describe it.", topic: "Functions and Modules" },
  { id: 53, question: "Which statement imports a single function named sqrt from math?", options: ["import math.sqrt", "from math import sqrt", "import sqrt from math", "use math.sqrt"], correctAnswer: 1, explanation: "from math import sqrt imports the specific name.", topic: "Functions and Modules" },
  { id: 54, question: "Why use if __name__ == \"__main__\":?", options: ["To install packages", "To run code only when the file is executed directly", "To define a class", "To import modules"], correctAnswer: 1, explanation: "That block runs only when the file is the main program, not when imported.", topic: "Functions and Modules" },
  { id: 55, question: "What does pip install do?", options: ["Runs a Python script", "Installs a package", "Formats code", "Uninstalls Python"], correctAnswer: 1, explanation: "pip install downloads and installs packages from PyPI or other indexes.", topic: "Functions and Modules" },
  { id: 56, question: "What is a requirements.txt file used for?", options: ["Storing source code", "Listing dependencies", "Holding environment variables", "Running tests"], correctAnswer: 1, explanation: "requirements.txt lists packages so others can install the same dependencies.", topic: "Functions and Modules" },
  { id: 57, question: "Which built-in function shows help for an object?", options: ["help()", "info()", "docs()", "manual()"], correctAnswer: 0, explanation: "help() opens the built-in documentation for modules, functions, or classes.", topic: "Functions and Modules" },
  { id: 58, question: "What is a module?", options: ["A Python file with code", "A database table", "A compiled binary", "A virtual environment"], correctAnswer: 0, explanation: "A module is a Python file that can be imported and reused.", topic: "Functions and Modules" },
  { id: 59, question: "What is a package?", options: ["A single function", "A directory of modules", "A compiled executable", "A data type"], correctAnswer: 1, explanation: "A package is a directory that groups multiple modules together.", topic: "Functions and Modules" },
  { id: 60, question: "Which module helps generate random numbers?", options: ["random", "math", "string", "time"], correctAnswer: 0, explanation: "The random module provides functions like randint and choice.", topic: "Functions and Modules" },
  // ==================== Topic 5: Collections, Files, and OOP (Questions 61-75) ====================
  { id: 61, question: "Which list method adds an item to the end?", options: ["add()", "append()", "insert()", "extend()"], correctAnswer: 1, explanation: "append() adds a single item to the end of a list.", topic: "Collections and Files" },
  { id: 62, question: "What does numbers[1:3] return?", options: ["Items at index 1 and 2", "Items at index 1 and 3", "Items from start to 3", "Only item at index 3"], correctAnswer: 0, explanation: "Slicing is end-exclusive, so it returns index 1 and 2.", topic: "Collections and Files" },
  { id: 63, question: "Why choose a tuple over a list?", options: ["Tuples are faster to create and immutable", "Tuples store only strings", "Tuples cannot be indexed", "Tuples are always sorted"], correctAnswer: 0, explanation: "Tuples are immutable and can be safer for fixed data.", topic: "Collections and Files" },
  { id: 64, question: "What happens if you access a missing key in a dict?", options: ["Returns None", "Returns 0", "Raises a KeyError", "Creates the key"], correctAnswer: 2, explanation: "Accessing a missing key with dict[key] raises KeyError.", topic: "Collections and Files" },
  { id: 65, question: "Which method safely gets a value from a dict?", options: ["fetch()", "get()", "read()", "find()"], correctAnswer: 1, explanation: "dict.get(key, default) returns a default if the key is missing.", topic: "Collections and Files" },
  { id: 66, question: "Which operation removes duplicates from a list?", options: ["list()", "set()", "tuple()", "dict()"], correctAnswer: 1, explanation: "Converting to a set removes duplicates because sets store unique items.", topic: "Collections and Files" },
  { id: 67, question: "What does text[:4] return?", options: ["The last 4 characters", "The first 4 characters", "All characters except 4", "Only the 4th character"], correctAnswer: 1, explanation: "Slicing with [:4] returns the first 4 characters.", topic: "Collections and Files" },
  { id: 68, question: "Which syntax builds a formatted string?", options: ["\"Hello\" + name", "f\"Hello {name}\"", "format(name)", "print(name)"], correctAnswer: 1, explanation: "f-strings are the most common modern way to format text.", topic: "Collections and Files" },
  { id: 69, question: "Which mode opens a file for reading?", options: ["\"r\"", "\"w\"", "\"a\"", "\"x\""], correctAnswer: 0, explanation: "\"r\" opens a file for reading.", topic: "Collections and Files" },
  { id: 70, question: "Why use with open(...) as f:", options: ["It makes the file faster", "It automatically closes the file", "It only works for images", "It prevents reading"], correctAnswer: 1, explanation: "The with statement ensures the file closes, even if errors occur.", topic: "Collections and Files" },
  { id: 71, question: "What does f.read() return?", options: ["A list of lines", "A single string with the full file contents", "A dictionary", "Only the first line"], correctAnswer: 1, explanation: "read() returns the entire file contents as one string.", topic: "Collections and Files" },
  { id: 72, question: "Which block is used for error handling?", options: ["if/else", "try/except", "for/while", "with/as"], correctAnswer: 1, explanation: "try/except handles exceptions and keeps programs from crashing.", topic: "Collections and Files" },
  { id: 73, question: "How do you define a class in Python?", options: ["class MyClass:", "def MyClass:", "object MyClass:", "new MyClass()"], correctAnswer: 0, explanation: "Classes are defined with the class keyword.", topic: "Collections and Files" },
  { id: 74, question: "What does self represent in a class method?", options: ["The class itself", "The current instance", "A global variable", "The parent class"], correctAnswer: 1, explanation: "self refers to the instance that calls the method.", topic: "Collections and Files" },
  { id: 75, question: "How do you call a method on an object?", options: ["object->method()", "object.method()", "method(object)", "call object.method"], correctAnswer: 1, explanation: "Use dot notation to call methods on objects.", topic: "Collections and Files" },
];

const CodeBlock: React.FC<{ code: string; title?: string }> = ({ code, title }) => (
  <Paper
    sx={{
      p: 2.5,
      borderRadius: 2,
      bgcolor: "#1e1e1e",
      border: `1px solid ${alpha("#3776ab", 0.3)}`,
      position: "relative",
      overflow: "hidden",
    }}
  >
    {title && (
      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1.5, color: "#f59e0b", letterSpacing: 0.5 }}>
        {title}
      </Typography>
    )}
    <Box
      component="pre"
      sx={{
        m: 0,
        fontFamily: "'Fira Code', Consolas, Monaco, 'Courier New', monospace",
        fontSize: "0.875rem",
        lineHeight: 1.7,
        whiteSpace: "pre-wrap",
        color: "#d4d4d4",
        "& .keyword": { color: "#569cd6" },
        "& .string": { color: "#ce9178" },
        "& .comment": { color: "#6a9955" },
        "& .function": { color: "#dcdcaa" },
        "& .number": { color: "#b5cea8" },
      }}
    >
      {code}
    </Box>
  </Paper>
);

// Difficulty badge component
const DifficultyBadge: React.FC<{ level: "beginner" | "intermediate" | "advanced" }> = ({ level }) => {
  const colors = {
    beginner: { bg: "#22c55e", text: "Beginner" },
    intermediate: { bg: "#f59e0b", text: "Intermediate" },
    advanced: { bg: "#ef4444", text: "Advanced" },
  };
  return (
    <Chip
      label={colors[level].text}
      size="small"
      sx={{
        bgcolor: alpha(colors[level].bg, 0.15),
        color: colors[level].bg,
        fontWeight: 700,
        fontSize: "0.7rem",
      }}
    />
  );
};

// Pro tip component
const ProTip: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <Paper
    sx={{
      p: 2,
      borderRadius: 2,
      bgcolor: alpha("#8b5cf6", 0.08),
      border: `1px solid ${alpha("#8b5cf6", 0.3)}`,
      display: "flex",
      gap: 1.5,
      alignItems: "flex-start",
    }}
  >
    <LightbulbIcon sx={{ color: "#8b5cf6", fontSize: 20, mt: 0.2 }} />
    <Typography variant="body2" sx={{ color: "text.primary" }}>
      {children}
    </Typography>
  </Paper>
);

// Warning box component
const WarningBox: React.FC<{ title?: string; children: React.ReactNode }> = ({ title, children }) => (
  <Paper
    sx={{
      p: 2,
      borderRadius: 2,
      bgcolor: alpha("#f59e0b", 0.08),
      border: `1px solid ${alpha("#f59e0b", 0.3)}`,
    }}
  >
    <Box sx={{ display: "flex", gap: 1.5, alignItems: "flex-start" }}>
      <WarningIcon sx={{ color: "#f59e0b", fontSize: 20, mt: 0.2 }} />
      <Box>
        {title && (
          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 0.5 }}>
            {title}
          </Typography>
        )}
        <Typography variant="body2">{children}</Typography>
      </Box>
    </Box>
  </Paper>
);

const QuizSection: React.FC = () => {
  const [quizState, setQuizState] = useState<"start" | "active" | "results">("start");
  const [questions, setQuestions] = useState<QuizQuestion[]>([]);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<{ [key: number]: number }>({});
  const [showExplanation, setShowExplanation] = useState(false);
  const [score, setScore] = useState(0);

  const QUESTIONS_PER_QUIZ = 10;

  const startQuiz = () => {
    const shuffled = [...questionBank].sort(() => Math.random() - 0.5);
    const selected = shuffled.slice(0, QUESTIONS_PER_QUIZ);
    setQuestions(selected);
    setCurrentQuestionIndex(0);
    setSelectedAnswers({});
    setShowExplanation(false);
    setScore(0);
    setQuizState("active");
  };

  const handleAnswerSelect = (answerIndex: number) => {
    if (showExplanation) return;
    setSelectedAnswers((prev) => ({
      ...prev,
      [currentQuestionIndex]: answerIndex,
    }));
  };

  const handleSubmitAnswer = () => {
    if (selectedAnswers[currentQuestionIndex] === undefined) return;
    setShowExplanation(true);
    if (selectedAnswers[currentQuestionIndex] === questions[currentQuestionIndex].correctAnswer) {
      setScore((prev) => prev + 1);
    }
  };

  const handleNextQuestion = () => {
    if (currentQuestionIndex < questions.length - 1) {
      setCurrentQuestionIndex((prev) => prev + 1);
      setShowExplanation(false);
    } else {
      setQuizState("results");
    }
  };

  const currentQuestion = questions[currentQuestionIndex];

  if (quizState === "start") {
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <QuizIcon sx={{ fontSize: 64, color: "#3776ab", mb: 2 }} />
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
          Python Fundamentals Quiz
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 520, mx: "auto" }}>
          Test your knowledge with {QUESTIONS_PER_QUIZ} random questions from a 75-question bank. Topics cover setup,
          data types, control flow, functions, modules, collections, file handling, and basic OOP.
        </Typography>
        <Button
          variant="contained"
          size="large"
          onClick={startQuiz}
          sx={{
            bgcolor: "#3776ab",
            "&:hover": { bgcolor: "#2f5f88" },
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
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <EmojiEventsIcon sx={{ fontSize: 64, color: percentage >= 70 ? "#22c55e" : "#f59e0b", mb: 2 }} />
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 2 }}>
          Quiz Complete!
        </Typography>
        <Typography variant="h5" sx={{ mb: 1 }}>
          Score: {score}/{QUESTIONS_PER_QUIZ} ({percentage}%)
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          {percentage >= 90 ? "Excellent! You're a Python expert!" :
           percentage >= 70 ? "Great job! You have solid Python knowledge." :
           percentage >= 50 ? "Good effort! Review the topics and try again." :
           "Keep learning! Review the fundamentals and try again."}
        </Typography>
        <Button
          variant="contained"
          startIcon={<RefreshIcon />}
          onClick={startQuiz}
          sx={{
            bgcolor: "#3776ab",
            "&:hover": { bgcolor: "#2f5f88" },
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

  const selectedAnswer = selectedAnswers[currentQuestionIndex];
  const isCorrect = selectedAnswer === currentQuestion.correctAnswer;

  // Active quiz state
  return (
    <Box>
      {/* Progress */}
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Chip label={`Question ${currentQuestionIndex + 1} of ${QUESTIONS_PER_QUIZ}`} sx={{ fontWeight: 600 }} />
        <Chip label={currentQuestion.topic} variant="outlined" sx={{ fontWeight: 600 }} />
      </Box>

      {/* Question */}
      <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
        {currentQuestion.question}
      </Typography>

      {/* Options */}
      <RadioGroup value={selectedAnswer ?? ""} onChange={(e) => handleAnswerSelect(Number(e.target.value))}>
        {currentQuestion.options.map((option, index) => (
          <FormControlLabel
            key={index}
            value={index}
            control={<Radio />}
            label={option}
            disabled={showExplanation}
            sx={{
              mb: 1,
              p: 1.5,
              borderRadius: 2,
              border: `1px solid ${alpha("#3776ab", 0.2)}`,
              bgcolor: showExplanation
                ? index === currentQuestion.correctAnswer
                  ? alpha("#22c55e", 0.1)
                  : index === selectedAnswer
                  ? alpha("#ef4444", 0.1)
                  : "transparent"
                : "transparent",
              "&:hover": { bgcolor: showExplanation ? undefined : alpha("#3776ab", 0.05) },
            }}
          />
        ))}
      </RadioGroup>

      {/* Explanation */}
      {showExplanation && (
        <Alert severity={isCorrect ? "success" : "error"} sx={{ mt: 2, mb: 2 }}>
          <AlertTitle>{isCorrect ? "Correct!" : "Incorrect"}</AlertTitle>
          {currentQuestion.explanation}
        </Alert>
      )}

      {/* Actions */}
      <Box sx={{ display: "flex", gap: 2, mt: 3 }}>
        {!showExplanation ? (
          <Button
            variant="contained"
            onClick={handleSubmitAnswer}
            disabled={selectedAnswer === undefined}
            sx={{ bgcolor: "#3776ab", "&:hover": { bgcolor: "#2f5f88" } }}
          >
            Submit Answer
          </Button>
        ) : (
          <Button
            variant="contained"
            onClick={handleNextQuestion}
            sx={{ bgcolor: "#3776ab", "&:hover": { bgcolor: "#2f5f88" } }}
          >
            {currentQuestionIndex < QUESTIONS_PER_QUIZ - 1 ? "Next Question" : "See Results"}
          </Button>
        )}
      </Box>
    </Box>
  );
};

// ==================== MAIN PAGE COMPONENT ====================
export default function PythonFundamentalsPage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");

  const pageContext = `Python Fundamentals learning page - comprehensive guide covering Python setup, syntax, data types, operators, control flow, functions, modules, collections, file I/O, error handling, OOP, and best practices. Includes 75-question quiz bank and practical projects. Part of the Software Engineering section.`;

  // Module navigation items
  const moduleNavItems = [
    { id: "introduction", label: "Introduction", icon: "📖" },
    { id: "beginner-basics", label: "Beginner Kickstart", icon: "🧭" },
    { id: "module-1", label: "1. Getting Started", icon: "🚀" },
    { id: "module-2", label: "2. Python Syntax", icon: "📝" },
    { id: "module-3", label: "3. Variables & Types", icon: "📦" },
    { id: "module-4", label: "4. Operators", icon: "➕" },
    { id: "module-5", label: "5. Strings Deep Dive", icon: "📜" },
    { id: "module-6", label: "6. Control Flow", icon: "🔀" },
    { id: "module-7", label: "7. Loops", icon: "🔄" },
    { id: "module-8", label: "8. Lists & Tuples", icon: "📋" },
    { id: "module-9", label: "9. Dicts & Sets", icon: "🗂️" },
    { id: "module-10", label: "10. Functions", icon: "⚡" },
    { id: "module-11", label: "11. File Handling", icon: "📁" },
    { id: "module-12", label: "12. Error Handling", icon: "🛡️" },
    { id: "module-13", label: "13. Classes & OOP", icon: "🏗️" },
    { id: "module-14", label: "14. Modules & Packages", icon: "📚" },
    { id: "libraries", label: "Libraries & Ecosystem", icon: "🧰" },
    { id: "module-15", label: "15. Advanced Topics", icon: "✨" },
    { id: "quiz-section", label: "Knowledge Quiz", icon: "❓" },
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
    handleScroll();
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const quickStats = [
    { label: "Modules", value: "15", color: "#3776ab" },
    { label: "Code Examples", value: "50+", color: "#22c55e" },
    { label: "Quiz Questions", value: "75", color: "#f59e0b" },
    { label: "Projects", value: "10+", color: "#8b5cf6" },
  ];

  const environmentChecklist = [
    "Install Python 3 from python.org or your OS package manager.",
    "Verify with python --version and pip --version.",
    "Create a virtual environment per project to isolate packages.",
    "Pick an editor (VS Code, PyCharm, or a simple IDE).",
    "Add a requirements.txt file for dependencies.",
  ];

  const firstSteps = [
    "Start in the REPL to test small ideas quickly.",
    "Write small scripts and run them from the terminal.",
    "Use print() to confirm variable values as you learn.",
    "Read error messages from top to bottom and fix one issue at a time.",
  ];

  const dataTypes = [
    { name: "int", description: "Whole numbers used for counts, indexes, and IDs.", example: "age = 21" },
    { name: "float", description: "Decimal numbers used for measurements and averages.", example: "price = 19.99" },
    { name: "str", description: "Text values for names, labels, and messages.", example: "name = \"Ada\"" },
    { name: "bool", description: "True/False values for conditions and flags.", example: "is_active = True" },
    { name: "list", description: "Ordered, mutable collections of items.", example: "tags = [\"python\", \"dev\"]" },
    { name: "dict", description: "Key-value mappings for structured data.", example: "user = {\"id\": 7, \"name\": \"Sam\"}" },
  ];

  const controlFlowTips = [
    "Use if/elif/else to make decisions based on conditions.",
    "Use for loops to iterate over sequences like lists or strings.",
    "Use while loops when you do not know the number of iterations.",
    "Use break to stop a loop early and continue to skip one iteration.",
    "Use range() to generate numeric sequences for loops.",
  ];

  const functionTips = [
    "Functions group reusable logic under a clear name.",
    "Parameters are inputs; return values are outputs.",
    "Defaults reduce repetitive arguments for common cases.",
    "Docstrings describe what the function does and how to use it.",
  ];

  const collectionTips = [
    "Lists preserve order and can be changed after creation.",
    "Tuples are fixed, which makes them safe for constants.",
    "Dictionaries map keys to values for fast lookups.",
    "Sets store unique items and remove duplicates quickly.",
  ];

  const fileTips = [
    "Use with open(...) as f to ensure files close correctly.",
    "Read small files with read() and large files line by line.",
    "Write with \"w\" to overwrite or \"a\" to append.",
    "Store file paths in variables and keep them readable.",
  ];

  const oopTips = [
    "Classes group data and behavior together.",
    "self refers to the current object instance.",
    "__init__ sets up initial state when creating an object.",
    "Methods are functions that live inside a class.",
  ];

  const beginnerProjects = [
    "Build a CLI to-do list that saves tasks to a file.",
    "Write a log parser that counts errors and warnings.",
    "Create a password strength checker with clear rules.",
    "Automate file cleanup with filters and a report summary.",
    "Make a simple quiz app that loads questions from JSON.",
  ];

  // Navigation drawer content
  const drawerContent = (
    <Box sx={{ width: 280, p: 2 }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
        <Typography variant="h6" sx={{ fontWeight: 700, color: "#3776ab" }}>
          📘 Modules
        </Typography>
        <IconButton onClick={() => setNavDrawerOpen(false)} size="small">
          <CloseIcon />
        </IconButton>
      </Box>
      <Divider sx={{ mb: 2 }} />
      <List dense>
        {moduleNavItems.map((item) => (
          <ListItem
            key={item.id}
            onClick={() => scrollToSection(item.id)}
            sx={{
              borderRadius: 2,
              mb: 0.5,
              cursor: "pointer",
              bgcolor: activeSection === item.id ? alpha("#3776ab", 0.15) : "transparent",
              "&:hover": { bgcolor: alpha("#3776ab", 0.1) },
              transition: "all 0.2s",
            }}
          >
            <ListItemIcon sx={{ minWidth: 36, fontSize: "1.1rem" }}>{item.icon}</ListItemIcon>
            <ListItemText
              primary={item.label}
              primaryTypographyProps={{
                fontSize: "0.875rem",
                fontWeight: activeSection === item.id ? 700 : 500,
                color: activeSection === item.id ? "#3776ab" : "text.primary",
              }}
            />
          </ListItem>
        ))}
      </List>
    </Box>
  );

  // Compact sidebar navigation for desktop
  const sidebarNav = (
    <Box
      sx={{
        position: "sticky",
        top: 80,
        maxHeight: "calc(100vh - 100px)",
        overflowY: "auto",
        pr: 1,
        "&::-webkit-scrollbar": { width: 4 },
        "&::-webkit-scrollbar-thumb": { bgcolor: alpha("#3776ab", 0.3), borderRadius: 2 },
      }}
    >
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
        <MenuBookIcon sx={{ color: "#3776ab", fontSize: 20 }} />
        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3776ab" }}>
          Modules
        </Typography>
      </Box>
      <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
        {moduleNavItems.map((item, index) => {
          const isActive = activeSection === item.id;
          const progress = moduleNavItems.findIndex(m => m.id === activeSection);
          const isCompleted = index < progress;
          
          return (
            <Box
              key={item.id}
              onClick={() => scrollToSection(item.id)}
              sx={{
                display: "flex",
                alignItems: "center",
                gap: 1,
                py: 0.75,
                px: 1.5,
                borderRadius: 1.5,
                cursor: "pointer",
                bgcolor: isActive ? alpha("#3776ab", 0.15) : "transparent",
                borderLeft: isActive ? `3px solid #3776ab` : "3px solid transparent",
                "&:hover": { bgcolor: alpha("#3776ab", 0.08) },
                transition: "all 0.15s ease",
              }}
            >
              <Typography sx={{ fontSize: "0.9rem", opacity: isCompleted ? 0.6 : 1 }}>
                {item.icon}
              </Typography>
              <Typography
                sx={{
                  fontSize: "0.75rem",
                  fontWeight: isActive ? 700 : 500,
                  color: isActive ? "#3776ab" : isCompleted ? "text.secondary" : "text.primary",
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}
              >
                {item.label}
              </Typography>
            </Box>
          );
        })}
      </Box>
      
      {/* Progress indicator */}
      <Box sx={{ mt: 3, pt: 2, borderTop: `1px solid ${alpha("#3776ab", 0.1)}` }}>
        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
          Progress
        </Typography>
        <LinearProgress
          variant="determinate"
          value={((moduleNavItems.findIndex(m => m.id === activeSection) + 1) / moduleNavItems.length) * 100}
          sx={{
            height: 6,
            borderRadius: 3,
            bgcolor: alpha("#3776ab", 0.1),
            "& .MuiLinearProgress-bar": { bgcolor: "#3776ab", borderRadius: 3 },
          }}
        />
        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5, textAlign: "center" }}>
          {moduleNavItems.findIndex(m => m.id === activeSection) + 1} / {moduleNavItems.length}
        </Typography>
      </Box>
    </Box>
  );

  return (
    <LearnPageLayout pageTitle="Python Fundamentals" pageContext={pageContext}>
      {/* Mobile Navigation Drawer */}
      <Drawer
        anchor="left"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        sx={{ 
          "& .MuiDrawer-paper": { bgcolor: theme.palette.background.default },
          display: { xs: "block", lg: "none" }
        }}
      >
        {drawerContent}
      </Drawer>

      {/* Floating Navigation Button - Mobile Only */}
      <Tooltip title="Module Navigation" placement="left">
        <Fab
          color="primary"
          onClick={() => setNavDrawerOpen(true)}
          sx={{
            position: "fixed",
            bottom: isMobile ? 80 : 32,
            right: 32,
            bgcolor: "#3776ab",
            "&:hover": { bgcolor: "#2f5f88" },
            zIndex: 1000,
            display: { xs: "flex", lg: "none" },
          }}
        >
          <ListAltIcon />
        </Fab>
      </Tooltip>

      {/* Main Layout with Sidebar */}
      <Box sx={{ display: "flex", gap: 4, maxWidth: 1400, mx: "auto", px: { xs: 2, md: 3 }, py: 4 }}>
        {/* Desktop Sidebar */}
        <Box
          sx={{
            display: { xs: "none", lg: "block" },
            width: 220,
            flexShrink: 0,
          }}
        >
          {sidebarNav}
        </Box>

        {/* Main Content */}
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

        {/* ==================== HERO SECTION ==================== */}
        <Paper
          id="introduction"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#3776ab", 0.18)} 0%, ${alpha("#2563eb", 0.12)} 50%, ${alpha("#f59e0b", 0.12)} 100%)`,
            border: `1px solid ${alpha("#3776ab", 0.2)}`,
            position: "relative",
            overflow: "hidden",
          }}
        >
          <Box
            sx={{
              position: "absolute",
              top: -50,
              right: -40,
              width: 220,
              height: 220,
              borderRadius: "50%",
              background: `radial-gradient(circle, ${alpha("#3776ab", 0.15)} 0%, transparent 70%)`,
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
              background: `radial-gradient(circle, ${alpha("#f59e0b", 0.15)} 0%, transparent 70%)`,
            }}
          />

          <Box sx={{ position: "relative", zIndex: 1 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
              <Box
                sx={{
                  width: 80,
                  height: 80,
                  borderRadius: 3,
                  background: "linear-gradient(135deg, #3776ab, #f59e0b)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  boxShadow: `0 8px 32px ${alpha("#3776ab", 0.3)}`,
                }}
              >
                <CodeIcon sx={{ fontSize: 44, color: "white" }} />
              </Box>
              <Box>
                <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                  Python Fundamentals
                </Typography>
                <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                  Beginner-friendly guide to writing real Python programs
                </Typography>
              </Box>
            </Box>

            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
              <Chip label="Beginner" color="warning" />
              <Chip label="Syntax" sx={{ bgcolor: alpha("#3776ab", 0.15), color: "#3776ab", fontWeight: 600 }} />
              <Chip label="Automation" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
              <Chip label="Software Engineering" sx={{ bgcolor: alpha("#f59e0b", 0.15), color: "#f59e0b", fontWeight: 600 }} />
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

        {/* ==================== WHY PYTHON SECTION ==================== */}
        <Paper
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 2, display: "flex", alignItems: "center", gap: 2 }}>
            <SchoolIcon sx={{ color: "#3776ab" }} />
            Why Learn Python?
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={8}>
              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                Python is a high-level language that focuses on clarity. You read it almost like plain English, which makes
                it ideal for people learning to program for the first time. Instead of worrying about complex syntax, you
                can focus on the problem you want to solve.
              </Typography>
              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                Python is widely used across many domains: <strong>web development</strong> (Django, Flask, FastAPI), 
                <strong> data science</strong> (pandas, NumPy, scikit-learn), <strong>automation</strong> (scripting, DevOps), 
                <strong> cybersecurity</strong> (penetration testing, malware analysis), and <strong>AI/ML</strong> (TensorFlow, PyTorch).
              </Typography>
              <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
                This comprehensive guide takes you from zero to confident Python programmer with 15 modules covering 
                everything from installation to object-oriented programming.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2.5, borderRadius: 3, bgcolor: alpha("#3776ab", 0.08), border: `1px solid ${alpha("#3776ab", 0.2)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#3776ab" }}>
                  Python Use Cases
                </Typography>
                {["Web Development", "Data Science & Analytics", "Automation & Scripting", "Cybersecurity Tools", "Machine Learning / AI", "Game Development", "Desktop Applications"].map((item) => (
                  <Box key={item} sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <CheckCircleIcon sx={{ color: "#22c55e", fontSize: 18 }} />
                    <Typography variant="body2">{item}</Typography>
                  </Box>
                ))}
              </Paper>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== BEGINNER KICKSTART ==================== */}
        <Paper
          id="beginner-basics"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.7),
            border: `1px solid ${alpha("#3776ab", 0.12)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2, flexWrap: "wrap" }}>
            <PlayArrowIcon sx={{ color: "#3776ab" }} />
            <Typography variant="h5" sx={{ fontWeight: 800 }}>
              Beginner Kickstart: Run Your First Python Code
            </Typography>
            <DifficultyBadge level="beginner" />
          </Box>
          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            If you are brand new to coding, focus on two things first: being able to run Python reliably, and building
            a habit of making tiny changes and seeing the result. That feedback loop is how you learn fastest.
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3776ab" }}>
                Setup checklist (do this once)
              </Typography>
              <List dense>
                {environmentChecklist.map((item, idx) => (
                  <ListItem key={idx} sx={{ px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}>
                      <CheckCircleIcon sx={{ color: "#22c55e", fontSize: 18 }} />
                    </ListItemIcon>
                    <ListItemText primary={item} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3776ab" }}>
                First steps that work every time
              </Typography>
              <List dense>
                {firstSteps.map((item, idx) => (
                  <ListItem key={idx} sx={{ px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}>
                      <CheckCircleIcon sx={{ color: "#3776ab", fontSize: 18 }} />
                    </ListItemIcon>
                    <ListItemText primary={item} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>

          <Box sx={{ mt: 3 }}>
            <CodeBlock
              title="Your First Script (save as hello.py)"
              code={`name = input("What is your name? ")
print(f"Hello, {name}! You just ran Python.")`}
            />
          </Box>

          <Box sx={{ mt: 2 }}>
            <ProTip>
              The REPL (type <code>python</code>) is great for quick experiments. Scripts (files ending in .py) are for
              repeatable work you can run again.
            </ProTip>
          </Box>
          <Box sx={{ mt: 2 }}>
            <WarningBox title="Common beginner pitfall">
              Python uses indentation to group code. If a block looks indented, it must be indented consistently
              (4 spaces is the norm).
            </WarningBox>
          </Box>
        </Paper>

        {/* ==================== MODULE 1: GETTING STARTED ==================== */}
        <Paper id="module-1" sx={{ p: 4, mb: 5, borderRadius: 4, border: `1px solid ${alpha("#3776ab", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
              <RocketLaunchIcon sx={{ color: "#3776ab" }} />
              Module 1: Getting Started with Python
            </Typography>
            <DifficultyBadge level="beginner" />
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Before writing any code, you need to set up your Python environment. This module covers installing Python, 
            understanding the interpreter, and configuring your development tools.
          </Typography>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            Python is released frequently, so it is worth choosing a recent stable 3.x version and being consistent. On
            Windows, the <code>py</code> launcher helps you target a specific version (for example <code>py -3.12</code>),
            while macOS and Linux typically use <code>python3</code>. Knowing which interpreter your terminal is running
            avoids confusing errors when packages appear to be "missing" or when your code uses syntax not supported by
            an older install.
          </Typography>
          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Think of Python as two parts: the interpreter and the standard library. The interpreter runs your code, and
            the standard library provides batteries like <code>json</code>, <code>pathlib</code>, and <code>datetime</code>.
            Keeping versions aligned per project with virtual environments prevents dependency conflicts and makes your
            projects reproducible for teammates and future you.
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3776ab" }}>
                Installation Steps
              </Typography>
              <List dense>
                {[
                  "Download Python 3.x from python.org (choose latest stable version)",
                  "Run installer - check 'Add Python to PATH' on Windows",
                  "Verify installation: python --version or python3 --version",
                  "Verify pip: pip --version or pip3 --version",
                  "Install VS Code or PyCharm as your editor",
                ].map((item, idx) => (
                  <ListItem key={idx} sx={{ px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 36 }}>
                      <Chip label={idx + 1} size="small" sx={{ width: 24, height: 24, bgcolor: "#3776ab", color: "white", fontWeight: 700 }} />
                    </ListItemIcon>
                    <ListItemText primary={item} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Verify Your Installation"
                code={`# Check Python version
python --version
# Output: Python 3.12.0

# Check pip version
pip --version
# Output: pip 23.3.1

# Start the Python REPL
python
>>> print("Hello, Python!")
Hello, Python!
>>> exit()`}
              />
            </Grid>
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3776ab" }}>
            Understanding the Python Interpreter
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            Python is an <strong>interpreted language</strong>, meaning code is executed line by line by the Python 
            interpreter rather than being compiled into machine code first. This enables:
          </Typography>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            Under the hood, Python compiles your source into bytecode and runs it on a virtual machine. You do not need
            to manage that process, but understanding it helps explain why startup time exists, why some libraries use
            C extensions for speed, and why caching is beneficial in long-running programs.
          </Typography>
              <List dense>
                {[
                  "Interactive development with the REPL (Read-Eval-Print Loop)",
                  "Quick prototyping and testing",
                  "Easy debugging with immediate feedback",
                  "Cross-platform compatibility (same code runs on Windows, Mac, Linux)",
                ].map((item, idx) => (
                  <ListItem key={idx} sx={{ px: 0 }}>
                    <ListItemIcon><CheckCircleIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
                    <ListItemText primary={item} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="REPL Quick Start"
                code={`# The REPL is great for quick experiments
>>> 2 + 2
4
>>> name = "Python"
>>> f"Learning {name} is fun!"
'Learning Python is fun!'
>>> type(42)
<class 'int'>
>>> help(print)  # Get help on any function`}
              />
            </Grid>
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3776ab" }}>
            Virtual Environments
          </Typography>
          <Alert severity="info" sx={{ mb: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Why Virtual Environments?</AlertTitle>
            Virtual environments isolate project dependencies so different projects can use different package versions without conflicts.
          </Alert>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Windows"
                code={`# Create virtual environment
python -m venv .venv

# Activate it
.venv\\Scripts\\activate

# You'll see (.venv) in your prompt
(.venv) C:\\project>

# Deactivate when done
deactivate`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="macOS / Linux"
                code={`# Create virtual environment
python3 -m venv .venv

# Activate it
source .venv/bin/activate

# You'll see (.venv) in your prompt
(.venv) ~/project$

# Deactivate when done
deactivate`}
              />
            </Grid>
          </Grid>

          <Box sx={{ mt: 3 }}>
            <ProTip>
              Always create a virtual environment for each project. Add <code>.venv/</code> to your <code>.gitignore</code> file 
              and use <code>pip freeze &gt; requirements.txt</code> to save your dependencies.
            </ProTip>
          </Box>
        </Paper>

        {/* ==================== MODULE 2: PYTHON SYNTAX ==================== */}
        <Paper id="module-2" sx={{ p: 4, mb: 5, borderRadius: 4, border: `1px solid ${alpha("#3776ab", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
              <CodeIcon sx={{ color: "#3776ab" }} />
              Module 2: Python Syntax Basics
            </Typography>
            <DifficultyBadge level="beginner" />
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Python's syntax is designed to be clean and readable. Unlike many languages that use braces, Python uses 
            <strong> indentation</strong> to define code blocks. This enforces readable code by design.
          </Typography>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            Indentation is not just style in Python, it is part of the grammar. That means whitespace conveys structure
            the same way braces do in other languages. A single extra space can change program meaning, so editors that
            show indentation guides and automatically format files are very helpful.
          </Typography>
          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Python also favors explicit, readable constructs over clever shortcuts. You will see that mindset again and
            again in core features like list comprehensions, readable boolean operators, and the standard library naming
            conventions. Following PEP 8 formatting rules makes your code easier to scan and easier to share.
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3776ab" }}>
                Your First Python Script
              </Typography>
              <CodeBlock
                title="hello.py"
                code={`# This is a comment - Python ignores these
# Comments explain your code to humans

# Print text to the console
print("Hello, World!")

# Variables store values
name = "Python Developer"
print(f"Welcome, {name}!")

# Python is dynamically typed
age = 25           # This is an integer
price = 19.99      # This is a float
is_active = True   # This is a boolean`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3776ab" }}>
                Running Your Script
              </Typography>
              <CodeBlock
                title="Terminal"
                code={`# Save as hello.py, then run:
python hello.py

# Output:
Hello, World!
Welcome, Python Developer!`}
              />
              <Box sx={{ mt: 2 }}>
                <WarningBox title="Common Mistake">
                  Make sure you're in the correct directory before running your script. Use <code>cd path/to/folder</code> to navigate.
                </WarningBox>
              </Box>
            </Grid>
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3776ab" }}>
            Indentation Rules
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                Python uses indentation (whitespace) to define code blocks. This is mandatory, not optional:
              </Typography>
              <List dense>
                {[
                  "Use 4 spaces per indentation level (PEP 8 standard)",
                  "Never mix tabs and spaces",
                  "Code at the same indentation level belongs together",
                  "Colons (:) indicate the start of an indented block",
                ].map((item, idx) => (
                  <ListItem key={idx} sx={{ px: 0 }}>
                    <ListItemIcon><CheckCircleIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
                    <ListItemText primary={item} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Indentation Example"
                code={`# Correct indentation
if True:
    print("This is indented")
    print("Same block")
print("Back to base level")

# Function with indented body
def greet(name):
    message = f"Hello, {name}!"
    return message

# Nested indentation
for i in range(3):
    if i > 0:
        print(f"Number: {i}")`}
              />
            </Grid>
          </Grid>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3776ab" }}>
            Comments and Documentation
          </Typography>
          <CodeBlock
            title="Comments in Python"
            code={`# Single-line comment - starts with #

# Multi-line comments use multiple # symbols
# Line 1 of comment
# Line 2 of comment

"""
Docstrings (triple quotes) document functions/classes.
They can span multiple lines and are accessible via help().
"""

def calculate_area(length, width):
    """
    Calculate the area of a rectangle.
    
    Args:
        length: The length of the rectangle
        width: The width of the rectangle
    
    Returns:
        The area as a float
    """
    return length * width

# Inline comments (use sparingly)
x = 10  # This is an inline comment`}
          />

          <Box sx={{ mt: 3 }}>
            <ProTip>
              Use docstrings to document functions, classes, and modules. You can view them with <code>help(function_name)</code> 
              or <code>function_name.__doc__</code>.
            </ProTip>
          </Box>
        </Paper>

        {/* ==================== MODULE 3: VARIABLES & DATA TYPES ==================== */}
        <Paper id="module-3" sx={{ p: 4, mb: 5, borderRadius: 4, border: `1px solid ${alpha("#3776ab", 0.15)}` }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
              <DataObjectIcon sx={{ color: "#3776ab" }} />
              Module 3: Variables & Data Types
            </Typography>
            <DifficultyBadge level="beginner" />
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Variables are containers for storing data values. Python is <strong>dynamically typed</strong>, meaning 
            you don't need to declare the type—Python figures it out automatically.
          </Typography>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            Dynamic typing does not mean types are ignored. Every value in Python has a type at runtime, and variables
            simply reference those values. That makes reassignment easy, but it also means you should be clear about the
            shape of your data through naming, docstrings, and (optionally) type hints.
          </Typography>
          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            It also helps to understand mutability early. Lists and dictionaries can be modified in place, while strings
            and tuples cannot. This influences performance and bugs, especially when the same object is referenced from
            multiple places. Learning when Python copies a value versus when it shares a reference will save time later.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3776ab" }}>
            Variable Naming Rules
          </Typography>
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>✓ Valid Names</Typography>
                <CodeBlock code={`name = "Alice"
user_name = "Bob"
userName2 = "Charlie"
_private = "hidden"
MAX_SIZE = 100  # Convention for constants`} />
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ef4444", 0.08), border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>✗ Invalid Names</Typography>
                <CodeBlock code={`2fast = "error"     # Can't start with number
my-name = "error"   # No hyphens allowed
my name = "error"   # No spaces allowed
class = "error"     # Reserved keyword
for = "error"       # Reserved keyword`} />
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3776ab" }}>
            Core Data Types
          </Typography>
          <TableContainer component={Paper} sx={{ mb: 3, borderRadius: 2 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#3776ab", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Check Type</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {[
                  { type: "int", desc: "Whole numbers (no decimals)", example: "42, -7, 0", check: "type(42) → <class 'int'>" },
                  { type: "float", desc: "Decimal numbers", example: "3.14, -0.5, 2.0", check: "type(3.14) → <class 'float'>" },
                  { type: "str", desc: "Text/string values", example: '"hello", \'world\'', check: 'type("hi") → <class \'str\'>' },
                  { type: "bool", desc: "True or False values", example: "True, False", check: "type(True) → <class 'bool'>" },
                  { type: "None", desc: "Represents 'no value'", example: "None", check: "type(None) → <class 'NoneType'>" },
                  { type: "list", desc: "Ordered, mutable collection", example: "[1, 2, 3]", check: "type([]) → <class 'list'>" },
                  { type: "tuple", desc: "Ordered, immutable collection", example: "(1, 2, 3)", check: "type(()) → <class 'tuple'>" },
                  { type: "dict", desc: "Key-value pairs", example: '{"a": 1}', check: "type({}) → <class 'dict'>" },
                  { type: "set", desc: "Unordered, unique values", example: "{1, 2, 3}", check: "type(set()) → <class 'set'>" },
                ].map((row) => (
                  <TableRow key={row.type}>
                    <TableCell sx={{ fontFamily: "monospace", fontWeight: 600, color: "#3776ab" }}>{row.type}</TableCell>
                    <TableCell>{row.desc}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{row.example}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>{row.check}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Working with Numbers"
                code={`# Integers
age = 25
count = -10
hex_num = 0xFF      # 255 in hexadecimal
binary = 0b1010     # 10 in binary

# Floats
price = 19.99
scientific = 1.5e-4  # 0.00015
infinity = float('inf')

# Type conversion
int_from_float = int(3.7)    # 3 (truncates)
float_from_int = float(42)   # 42.0
int_from_str = int("123")    # 123`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Working with Strings"
                code={`# String creation
single = 'Hello'
double = "World"
multi = """This spans
multiple lines"""

# String concatenation
full = single + " " + double  # "Hello World"

# f-strings (formatted strings) - Python 3.6+
name = "Alice"
age = 30
intro = f"I'm {name}, {age} years old"

# String methods
text = "  Hello World  "
text.strip()      # "Hello World"
text.lower()      # "  hello world  "
text.upper()      # "  HELLO WORLD  "
text.replace("World", "Python")`}
              />
            </Grid>
          </Grid>

          <Box sx={{ mt: 3 }}>
            <ProTip>
              Use <code>type(variable)</code> to check a variable's type, and <code>isinstance(variable, type)</code> to verify 
              if a variable is of a specific type: <code>isinstance(42, int)</code> returns <code>True</code>.
            </ProTip>
          </Box>
        </Paper>

        {/* ==================== MODULE 4: OPERATORS ==================== */}
        <Paper id="module-4" sx={{ p: 4, mb: 5, borderRadius: 4, border: '1px solid', borderColor: 'divider' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
              <BuildIcon sx={{ color: "#3776ab", fontSize: 32 }} />
              Module 4: Operators
            </Typography>
            <DifficultyBadge level="beginner" />
          </Box>
          
          <Typography variant="body1" sx={{ mb: 3, fontSize: '1.1rem', lineHeight: 1.8 }}>
            Operators are special symbols that perform operations on values. Python supports arithmetic, comparison, 
            logical, assignment, and more. Understanding operators is essential for writing expressions and making decisions.
          </Typography>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            Operator behavior is predictable but has a few important nuances. Division with <code>/</code> always
            produces a float, while <code>//</code> floors to an integer. Comparisons can be chained
            (<code>1 &lt; x &lt; 10</code>), and logical operators return one of the operands, not just True or False.
          </Typography>
          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            Later you will also see bitwise operators, identity checks with <code>is</code>, and membership tests with
            <code>in</code>. These are powerful tools for working with flags, caching, and container types, so it is worth
            building an intuition for them early.
          </Typography>

          {/* Arithmetic Operators */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Arithmetic Operators
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            Used for mathematical calculations. Python follows standard math precedence (PEMDAS).
          </Typography>
          
          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha('#3776ab', 0.03) }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha('#3776ab', 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Operator</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Name</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Result</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {[
                  { op: '+', name: 'Addition', example: '10 + 3', result: '13' },
                  { op: '-', name: 'Subtraction', example: '10 - 3', result: '7' },
                  { op: '*', name: 'Multiplication', example: '10 * 3', result: '30' },
                  { op: '/', name: 'Division', example: '10 / 3', result: '3.333...' },
                  { op: '//', name: 'Floor Division', example: '10 // 3', result: '3' },
                  { op: '%', name: 'Modulus (Remainder)', example: '10 % 3', result: '1' },
                  { op: '**', name: 'Exponentiation', example: '2 ** 4', result: '16' },
                ].map((row) => (
                  <TableRow key={row.op}>
                    <TableCell sx={{ fontFamily: 'Fira Code, monospace', fontWeight: 600 }}>{row.op}</TableCell>
                    <TableCell>{row.name}</TableCell>
                    <TableCell sx={{ fontFamily: 'Fira Code, monospace' }}>{row.example}</TableCell>
                    <TableCell sx={{ fontFamily: 'Fira Code, monospace', color: '#2e7d32' }}>{row.result}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Arithmetic in Action"
                code={`# Basic math
total = 100 + 50          # 150
difference = 100 - 30     # 70
product = 7 * 8           # 56
quotient = 15 / 4         # 3.75

# Floor division vs regular division
print(17 / 5)   # 3.4 (float result)
print(17 // 5)  # 3   (integer, rounded down)

# Modulus - great for checking even/odd
number = 42
is_even = number % 2 == 0  # True

# Exponentiation
square = 5 ** 2     # 25
cube = 3 ** 3       # 27
sqrt = 16 ** 0.5    # 4.0`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Operator Precedence"
                code={`# Python follows PEMDAS
# Parentheses → Exponents → Mult/Div → Add/Sub

result = 2 + 3 * 4        # 14 (not 20!)
result = (2 + 3) * 4      # 20

# Mix of operators
value = 10 + 5 * 2 ** 2   # 10 + 5 * 4 = 30
value = (10 + 5) * 2 ** 2 # 15 * 4 = 60

# Use parentheses for clarity!
price = 100
tax_rate = 0.08
discount = 10
final = (price - discount) * (1 + tax_rate)  # 97.2

# Negative exponents
small = 10 ** -2  # 0.01`}
              />
            </Grid>
          </Grid>

          {/* Comparison Operators */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Comparison Operators
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            Compare two values and return a boolean (<code>True</code> or <code>False</code>). Essential for conditionals and loops.
          </Typography>

          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha('#3776ab', 0.03) }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha('#3776ab', 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Operator</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Meaning</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Result</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {[
                  { op: '==', name: 'Equal to', example: '5 == 5', result: 'True' },
                  { op: '!=', name: 'Not equal to', example: '5 != 3', result: 'True' },
                  { op: '<', name: 'Less than', example: '3 < 5', result: 'True' },
                  { op: '>', name: 'Greater than', example: '5 > 3', result: 'True' },
                  { op: '<=', name: 'Less than or equal', example: '5 <= 5', result: 'True' },
                  { op: '>=', name: 'Greater than or equal', example: '5 >= 3', result: 'True' },
                ].map((row) => (
                  <TableRow key={row.op}>
                    <TableCell sx={{ fontFamily: 'Fira Code, monospace', fontWeight: 600 }}>{row.op}</TableCell>
                    <TableCell>{row.name}</TableCell>
                    <TableCell sx={{ fontFamily: 'Fira Code, monospace' }}>{row.example}</TableCell>
                    <TableCell sx={{ fontFamily: 'Fira Code, monospace', color: row.result === 'True' ? '#2e7d32' : '#c62828' }}>{row.result}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Comparison Examples"
                code={`age = 25
is_adult = age >= 18        # True
is_senior = age >= 65       # False
is_teen = 13 <= age <= 19   # False (chaining!)

# String comparison (alphabetical)
"apple" < "banana"   # True
"Apple" < "apple"    # True (uppercase < lowercase)

# Comparing different types
5 == 5.0    # True (int vs float)
"5" == 5    # False (string vs int)

# None comparison
value = None
is_none = value is None     # True (use 'is' for None)
is_not_none = value is not None  # False`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <WarningBox>
                <strong>Common Mistake:</strong> Using <code>=</code> instead of <code>==</code>. 
                Single <code>=</code> is assignment, double <code>==</code> is comparison.
                <br /><br />
                <code>if x = 5:</code> → SyntaxError! ❌<br />
                <code>if x == 5:</code> → Correct! ✓
              </WarningBox>
            </Grid>
          </Grid>

          {/* Logical Operators */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Logical Operators
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            Combine multiple conditions. Python uses words (<code>and</code>, <code>or</code>, <code>not</code>) instead of symbols.
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Logical Operator Basics"
                code={`# and - both conditions must be True
age = 25
has_license = True
can_drive = age >= 16 and has_license  # True

# or - at least one condition must be True  
is_weekend = False
is_holiday = True
day_off = is_weekend or is_holiday  # True

# not - inverts the boolean
is_raining = False
go_outside = not is_raining  # True

# Combining operators
x = 15
in_range = x >= 10 and x <= 20  # True
out_of_range = not in_range     # False`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Short-Circuit Evaluation"
                code={`# Python stops evaluating as soon as result is known

# 'and' stops at first False
def check():
    print("Checked!")
    return True

False and check()  # check() never runs!
True and check()   # "Checked!" - runs

# 'or' stops at first True
True or check()    # check() never runs!
False or check()   # "Checked!" - runs

# Practical use: safe attribute access
user = None
# This won't crash:
is_admin = user is not None and user.is_admin

# Default values with 'or'
name = "" or "Anonymous"  # "Anonymous"`}
              />
            </Grid>
          </Grid>

          {/* Assignment Operators */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Assignment Operators
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            Shorthand for performing an operation and assigning the result back to a variable.
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <TableContainer component={Paper} sx={{ bgcolor: alpha('#3776ab', 0.03) }}>
                <Table size="small">
                  <TableHead>
                    <TableRow sx={{ bgcolor: alpha('#3776ab', 0.1) }}>
                      <TableCell sx={{ fontWeight: 700 }}>Operator</TableCell>
                      <TableCell sx={{ fontWeight: 700 }}>Equivalent</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {[
                      { op: 'x += 5', equiv: 'x = x + 5' },
                      { op: 'x -= 5', equiv: 'x = x - 5' },
                      { op: 'x *= 5', equiv: 'x = x * 5' },
                      { op: 'x /= 5', equiv: 'x = x / 5' },
                      { op: 'x //= 5', equiv: 'x = x // 5' },
                      { op: 'x %= 5', equiv: 'x = x % 5' },
                      { op: 'x **= 5', equiv: 'x = x ** 5' },
                    ].map((row) => (
                      <TableRow key={row.op}>
                        <TableCell sx={{ fontFamily: 'Fira Code, monospace' }}>{row.op}</TableCell>
                        <TableCell sx={{ fontFamily: 'Fira Code, monospace' }}>{row.equiv}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Assignment Operators in Use"
                code={`score = 100

score += 10   # score is now 110
score -= 20   # score is now 90
score *= 2    # score is now 180
score //= 3   # score is now 60

# String concatenation
message = "Hello"
message += " World"  # "Hello World"

# List extension
items = [1, 2]
items += [3, 4]  # [1, 2, 3, 4]`}
              />
            </Grid>
          </Grid>

          {/* Membership & Identity Operators */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Membership & Identity Operators
          </Typography>
          
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Membership: in / not in"
                code={`# Check if item exists in a sequence
fruits = ["apple", "banana", "cherry"]

"apple" in fruits      # True
"grape" in fruits      # False
"grape" not in fruits  # True

# Works with strings too
text = "Hello World"
"World" in text   # True
"world" in text   # False (case-sensitive)

# And dictionaries (checks keys)
user = {"name": "Alice", "age": 30}
"name" in user    # True
"Alice" in user   # False (it's a value, not key)`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Identity: is / is not"
                code={`# Check if two variables point to the SAME object
a = [1, 2, 3]
b = [1, 2, 3]
c = a

a == b  # True (same content)
a is b  # False (different objects)
a is c  # True (same object!)

# Always use 'is' for None comparison
value = None
value is None      # True ✓
value == None      # Works, but not Pythonic

# Singleton comparisons
x = True
x is True   # True (booleans are singletons)

# Small integers are cached
a = 5
b = 5
a is b  # True (Python caches -5 to 256)`}
              />
            </Grid>
          </Grid>

          <Box sx={{ mt: 3 }}>
            <ProTip>
              Use <code>in</code> to check membership - it's more readable than loops!
              Instead of writing a loop to find an item, just write <code>if item in collection</code>.
            </ProTip>
          </Box>
        </Paper>

        {/* ==================== MODULE 5: STRINGS DEEP DIVE ==================== */}
        <Paper id="module-5" sx={{ p: 4, mb: 5, borderRadius: 4, border: '1px solid', borderColor: 'divider' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
              <DataObjectIcon sx={{ color: "#3776ab", fontSize: 32 }} />
              Module 5: Strings Deep Dive
            </Typography>
            <DifficultyBadge level="beginner" />
          </Box>
          
          <Typography variant="body1" sx={{ mb: 3, fontSize: '1.1rem', lineHeight: 1.8 }}>
            Strings are one of Python's most used data types. This module covers string creation, indexing, slicing, 
            methods, and formatting - essential skills for any Python programmer.
          </Typography>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            Strings are sequences of Unicode characters and are immutable. That means you can index and slice them like
            lists, but any "change" creates a new string. This design is safe and efficient for many workloads, but it
            also means you should build strings with <code>"".join(...)</code> when you are combining many pieces.
          </Typography>
          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            It is also important to distinguish between text (<code>str</code>) and raw bytes (<code>bytes</code>).
            Files, network traffic, and encryption libraries often require bytes, so learning how to encode and decode
            text will help you avoid bugs like mojibake or unexpected exceptions when handling non-ASCII data.
          </Typography>

          {/* String Creation */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Creating Strings
          </Typography>
          
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="String Basics"
                code={`# Single or double quotes - both work!
single = 'Hello World'
double = "Hello World"

# Triple quotes for multi-line
poem = """Roses are red,
Violets are blue,
Python is awesome,
And so are you!"""

# Triple quotes preserve formatting
sql = '''
SELECT *
FROM users
WHERE active = true
'''

# Empty string
empty = ""
also_empty = str()`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Escape Characters"
                code={`# Special characters with backslash
newline = "Line 1\\nLine 2"
tab = "Col1\\tCol2"
quote = "She said \\"Hello!\\""
backslash = "C:\\\\Users\\\\Name"

# Common escape sequences:
# \\n  - Newline
# \\t  - Tab
# \\\\ - Backslash
# \\"  - Double quote
# \\'  - Single quote

# Raw strings - ignore escapes
path = r"C:\\Users\\Name"  # No double backslash needed
regex = r"\\d+\\.\\d+"      # Useful for regex patterns`}
              />
            </Grid>
          </Grid>

          {/* String Indexing & Slicing */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Indexing & Slicing
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            Access individual characters or substrings. Python uses zero-based indexing.
          </Typography>

          <Box sx={{ mb: 3, p: 2, bgcolor: alpha('#3776ab', 0.05), borderRadius: 2, fontFamily: 'Fira Code, monospace' }}>
            <Typography variant="body2" sx={{ mb: 1, fontWeight: 600 }}>String: "PYTHON"</Typography>
            <Box sx={{ display: 'flex', gap: 0 }}>
              {['P', 'Y', 'T', 'H', 'O', 'N'].map((char, i) => (
                <Box key={i} sx={{ textAlign: 'center', minWidth: 50 }}>
                  <Box sx={{ p: 1, border: '1px solid', borderColor: '#3776ab', bgcolor: 'white' }}>{char}</Box>
                  <Typography variant="caption" sx={{ display: 'block', color: '#2e7d32' }}>+{i}</Typography>
                  <Typography variant="caption" sx={{ display: 'block', color: '#c62828' }}>{i - 6}</Typography>
                </Box>
              ))}
            </Box>
            <Typography variant="caption" sx={{ mt: 1, display: 'block' }}>
              Green = positive index, Red = negative index
            </Typography>
          </Box>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Indexing"
                code={`text = "PYTHON"

# Positive indexing (from start)
text[0]    # 'P' (first character)
text[1]    # 'Y'
text[5]    # 'N' (last character)

# Negative indexing (from end)
text[-1]   # 'N' (last character)
text[-2]   # 'O'
text[-6]   # 'P' (first character)

# Index out of range
text[10]   # IndexError!
text[-10]  # IndexError!

# Strings are immutable
text[0] = 'J'  # TypeError! Can't modify`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Slicing [start:stop:step]"
                code={`text = "PYTHON"

# Basic slicing [start:stop]
text[0:3]    # 'PYT' (indices 0, 1, 2)
text[2:5]    # 'THO'
text[:3]     # 'PYT' (from beginning)
text[3:]     # 'HON' (to end)
text[:]      # 'PYTHON' (copy)

# With step [start:stop:step]
text[::2]    # 'PTO' (every 2nd char)
text[1::2]   # 'YHN' (start at 1, every 2nd)
text[::-1]   # 'NOHTYP' (reverse!)

# Negative indices in slices
text[-3:]    # 'HON' (last 3)
text[:-3]    # 'PYT' (all but last 3)
text[-4:-1]  # 'THO'`}
              />
            </Grid>
          </Grid>

          {/* String Methods */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Essential String Methods
          </Typography>
          
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Case & Whitespace Methods"
                code={`text = "  Hello World  "

# Case methods
text.lower()       # "  hello world  "
text.upper()       # "  HELLO WORLD  "
text.title()       # "  Hello World  "
text.capitalize()  # "  hello world  "
text.swapcase()    # "  hELLO wORLD  "

# Whitespace methods
text.strip()       # "Hello World"
text.lstrip()      # "Hello World  "
text.rstrip()      # "  Hello World"

# Remove specific characters
"###hello###".strip("#")  # "hello"

# Check methods (return bool)
"hello".islower()     # True
"HELLO".isupper()     # True
"Hello".istitle()     # True
"12345".isdigit()     # True
"hello".isalpha()     # True
"hello123".isalnum()  # True`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Search & Replace Methods"
                code={`text = "Hello World, Hello Python"

# Find methods
text.find("Hello")      # 0 (first occurrence)
text.find("Hello", 5)   # 13 (start search at index 5)
text.find("Java")       # -1 (not found)
text.rfind("Hello")     # 13 (last occurrence)

# Index (like find, but raises error if not found)
text.index("World")     # 6
text.index("Java")      # ValueError!

# Count occurrences
text.count("Hello")     # 2
text.count("o")         # 3

# Replace
text.replace("Hello", "Hi")      # "Hi World, Hi Python"
text.replace("Hello", "Hi", 1)   # "Hi World, Hello Python"

# Check start/end
text.startswith("Hello")  # True
text.endswith("Python")   # True`}
              />
            </Grid>
          </Grid>

          <Grid container spacing={3} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Split & Join"
                code={`# Split string into list
text = "apple,banana,cherry"
fruits = text.split(",")  # ['apple', 'banana', 'cherry']

# Split on whitespace (default)
"Hello World Python".split()  # ['Hello', 'World', 'Python']

# Split with max splits
"a-b-c-d".split("-", 2)  # ['a', 'b', 'c-d']

# Split lines
multiline = "Line1\\nLine2\\nLine3"
multiline.splitlines()  # ['Line1', 'Line2', 'Line3']

# Join list into string
fruits = ['apple', 'banana', 'cherry']
",".join(fruits)     # "apple,banana,cherry"
" - ".join(fruits)   # "apple - banana - cherry"
"".join(fruits)      # "applebananacherry"`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Padding & Alignment"
                code={`# Center, left, right align
"hello".center(11)      # "   hello   "
"hello".ljust(10)       # "hello     "
"hello".rjust(10)       # "     hello"

# With custom fill character
"42".center(10, "-")    # "----42----"
"42".zfill(5)           # "00042"

# Practical example: table formatting
items = [("Apple", 1.50), ("Banana", 0.75), ("Cherry", 2.00)]
for name, price in items:
    print(f"{name.ljust(10)} \${price:.2f}")
# Output:
# Apple      $1.50
# Banana     $0.75
# Cherry     $2.00`}
              />
            </Grid>
          </Grid>

          {/* String Formatting */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            String Formatting
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            Three ways to format strings: f-strings (recommended), .format(), and % formatting (legacy).
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="F-Strings (Python 3.6+) - Recommended!"
                code={`name = "Alice"
age = 30
price = 19.99

# Basic interpolation
f"Hello, {name}!"           # "Hello, Alice!"
f"{name} is {age} years old"  # "Alice is 30 years old"

# Expressions inside braces
f"Next year: {age + 1}"     # "Next year: 31"
f"Name length: {len(name)}"  # "Name length: 5"

# Number formatting
f"Price: \${price:.2f}"       # "Price: $19.99"
f"Percent: {0.756:.1%}"      # "Percent: 75.6%"
f"Binary: {42:b}"            # "Binary: 101010"
f"Hex: {255:x}"              # "Hex: ff"

# Padding
f"{42:05d}"                  # "00042"
f"{'hi':>10}"                # "        hi"
f"{'hi':<10}"                # "hi        "
f"{'hi':^10}"                # "    hi    "`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Other Formatting Methods"
                code={`# .format() method
"Hello, {}!".format("World")     # "Hello, World!"
"Hello, {0}! Bye, {0}!".format("Alice")  # Reuse
"{name} is {age}".format(name="Bob", age=25)

# % formatting (legacy - avoid in new code)
"Hello, %s!" % "World"           # "Hello, World!"
"Value: %d" % 42                 # "Value: 42"
"Price: %.2f" % 19.99            # "Price: 19.99"

# F-string debugging (Python 3.8+)
x = 10
y = 20
f"{x=}, {y=}"        # "x=10, y=20"
f"{x + y = }"        # "x + y = 30"

# Multi-line f-strings
message = (
    f"Name: {name}\\n"
    f"Age: {age}\\n"
    f"Status: Active"
)`}
              />
            </Grid>
          </Grid>

          <Box sx={{ mt: 3 }}>
            <ProTip>
              Always use f-strings for new code - they're faster, more readable, and more powerful than older methods.
              The <code>=</code> specifier in Python 3.8+ is great for debugging: <code>f"&#123;variable=&#125;"</code> prints both name and value!
            </ProTip>
          </Box>
        </Paper>

        {/* ==================== MODULE 6: CONTROL FLOW ==================== */}
        <Paper id="module-6" sx={{ p: 4, mb: 5, borderRadius: 4, border: '1px solid', borderColor: 'divider' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
              <AccountTreeIcon sx={{ color: "#3776ab", fontSize: 32 }} />
              Module 6: Control Flow
            </Typography>
            <DifficultyBadge level="beginner" />
          </Box>
          
          <Typography variant="body1" sx={{ mb: 3, fontSize: '1.1rem', lineHeight: 1.8 }}>
            Control flow determines the order in which code executes. With conditionals, you can make decisions; 
            with the match statement, you can elegantly handle multiple cases. This is where your programs start to think!
          </Typography>

          {/* If/Elif/Else */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            If, Elif, Else Statements
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            The fundamental decision-making structure in Python. Indent consistently (4 spaces recommended).
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Basic Conditionals"
                code={`age = 18

# Simple if
if age >= 18:
    print("You are an adult")

# If-else
if age >= 18:
    print("Adult")
else:
    print("Minor")

# If-elif-else chain
if age < 13:
    category = "Child"
elif age < 20:
    category = "Teenager"
elif age < 65:
    category = "Adult"
else:
    category = "Senior"

print(f"Category: {category}")`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Nested Conditionals"
                code={`is_member = True
purchase_amount = 150

# Nested if statements
if is_member:
    if purchase_amount >= 100:
        discount = 0.20  # 20% for members with $100+
    else:
        discount = 0.10  # 10% for members
else:
    if purchase_amount >= 100:
        discount = 0.05  # 5% for non-members with $100+
    else:
        discount = 0     # No discount

# Flatten with 'and' - often cleaner
if is_member and purchase_amount >= 100:
    discount = 0.20
elif is_member:
    discount = 0.10
elif purchase_amount >= 100:
    discount = 0.05
else:
    discount = 0`}
              />
            </Grid>
          </Grid>

          {/* Truthiness */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Truthiness and Falsy Values
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            Python evaluates non-boolean values in conditionals. Understanding "truthy" and "falsy" is key!
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha('#c62828', 0.05), borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: '#c62828', mb: 1 }}>
                  Falsy Values (evaluate to False)
                </Typography>
                <Box sx={{ fontFamily: 'Fira Code, monospace', fontSize: '0.9rem' }}>
                  <Box>• <code>False</code> - Boolean false</Box>
                  <Box>• <code>None</code> - Null value</Box>
                  <Box>• <code>0</code> - Zero (int)</Box>
                  <Box>• <code>0.0</code> - Zero (float)</Box>
                  <Box>• <code>""</code> - Empty string</Box>
                  <Box>• <code>[]</code> - Empty list</Box>
                  <Box>• <code>{}</code> - Empty dict</Box>
                  <Box>• <code>()</code> - Empty tuple</Box>
                  <Box>• <code>set()</code> - Empty set</Box>
                </Box>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha('#2e7d32', 0.05), borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: '#2e7d32', mb: 1 }}>
                  Truthy Values (evaluate to True)
                </Typography>
                <Box sx={{ fontFamily: 'Fira Code, monospace', fontSize: '0.9rem' }}>
                  <Box>• <code>True</code> - Boolean true</Box>
                  <Box>• Non-zero numbers (<code>1</code>, <code>-5</code>, <code>3.14</code>)</Box>
                  <Box>• Non-empty strings (<code>"hello"</code>, <code>" "</code>)</Box>
                  <Box>• Non-empty collections (<code>[1, 2]</code>, <code>{`{"a": 1}`}</code>)</Box>
                  <Box>• Most objects</Box>
                </Box>
              </Paper>
            </Grid>
          </Grid>

          <Grid container spacing={3} sx={{ mt: 1 }}>
            <Grid item xs={12}>
              <CodeBlock
                title="Truthiness in Practice"
                code={`# Pythonic way to check for empty
items = []
if items:              # Falsy - empty list
    print("Has items")
else:
    print("Empty!")    # This prints

# Pythonic way to check for value
name = ""
if name:               # Falsy - empty string
    print(f"Hello, {name}")
else:
    print("No name provided")  # This prints

# Common pattern: default values
user_input = ""
name = user_input or "Anonymous"  # "Anonymous"

data = None
result = data or []  # [] (use empty list as default)

# Check for None specifically (not just falsy)
value = 0
if value is not None:   # True! 0 is not None
    print("Value exists")  # This prints`}
              />
            </Grid>
          </Grid>

          {/* Ternary Operator */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Conditional Expressions (Ternary Operator)
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            One-line if-else for simple conditions. Use sparingly - readability matters!
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Ternary Syntax"
                code={`# Syntax: value_if_true if condition else value_if_false

age = 20
status = "adult" if age >= 18 else "minor"

# Equivalent to:
if age >= 18:
    status = "adult"
else:
    status = "minor"

# Practical examples
score = 85
grade = "Pass" if score >= 60 else "Fail"

x = 10
abs_x = x if x >= 0 else -x

items = ["apple"]
message = f"{len(items)} item" if len(items) == 1 else f"{len(items)} items"`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Nested Ternary (Use Sparingly!)"
                code={`# Chained ternary - can get hard to read!
score = 85
grade = (
    "A" if score >= 90 else
    "B" if score >= 80 else
    "C" if score >= 70 else
    "D" if score >= 60 else
    "F"
)

# Often clearer as regular if-elif
if score >= 90:
    grade = "A"
elif score >= 80:
    grade = "B"
# ... etc

# Good use: simple toggle
is_active = True
status = "ON" if is_active else "OFF"

# In f-strings
count = 5
print(f"Found {count} {'item' if count == 1 else 'items'}")`}
              />
            </Grid>
          </Grid>

          <WarningBox>
            <strong>Readability Warning:</strong> Don't nest ternary operators more than once.
            If the logic is complex, use a regular if-elif-else block. Your future self will thank you!
          </WarningBox>

          {/* Match Statement */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Match Statement (Python 3.10+)
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            Structural pattern matching - Python's powerful switch-case equivalent with pattern matching superpowers.
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Basic Match Statement"
                code={`# Simple value matching
def get_day_type(day):
    match day:
        case "Saturday" | "Sunday":
            return "Weekend"
        case "Monday":
            return "Start of week"
        case "Friday":
            return "TGIF!"
        case _:  # Default case (wildcard)
            return "Weekday"

print(get_day_type("Saturday"))  # "Weekend"
print(get_day_type("Tuesday"))   # "Weekday"

# Matching with guards (conditions)
def categorize_number(n):
    match n:
        case 0:
            return "Zero"
        case n if n > 0:
            return "Positive"
        case _:
            return "Negative"`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Pattern Matching with Structures"
                code={`# Matching sequences
def analyze_point(point):
    match point:
        case (0, 0):
            return "Origin"
        case (x, 0):
            return f"On X-axis at {x}"
        case (0, y):
            return f"On Y-axis at {y}"
        case (x, y):
            return f"Point at ({x}, {y})"

print(analyze_point((3, 0)))  # "On X-axis at 3"

# Matching dictionaries
def handle_response(response):
    match response:
        case {"status": 200, "data": data}:
            return f"Success: {data}"
        case {"status": 404}:
            return "Not found"
        case {"status": status}:
            return f"Error: {status}"
        case _:
            return "Unknown response"`}
              />
            </Grid>
          </Grid>

          <Grid container spacing={3} sx={{ mt: 1 }}>
            <Grid item xs={12}>
              <CodeBlock
                title="Advanced Pattern Matching"
                code={`# Matching with type checking
def process(value):
    match value:
        case str() as s:
            return f"String: {s.upper()}"
        case int() | float() as n:
            return f"Number: {n * 2}"
        case list() as lst if len(lst) > 0:
            return f"Non-empty list with {len(lst)} items"
        case []:
            return "Empty list"
        case _:
            return "Unknown type"

# Matching class instances
class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

def describe_point(p):
    match p:
        case Point(x=0, y=0):
            return "At origin"
        case Point(x=x, y=y) if x == y:
            return f"On diagonal at {x}"
        case Point(x=x, y=y):
            return f"Point({x}, {y})"`}
              />
            </Grid>
          </Grid>

          <Box sx={{ mt: 3 }}>
            <ProTip>
              The match statement is much more powerful than traditional switch-case. Use it for:
              parsing commands, handling API responses, processing data structures, and replacing complex if-elif chains.
              The underscore <code>_</code> is the wildcard pattern that matches anything.
            </ProTip>
          </Box>

          {/* Best Practices */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Control Flow Best Practices
          </Typography>
          
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Accordion sx={{ bgcolor: alpha('#3776ab', 0.03) }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight={600}>✓ Do: Early Returns</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    title="Reduce nesting with early returns"
                    code={`# Instead of deeply nested:
def process(data):
    if data:
        if data.is_valid:
            if data.value > 0:
                return data.value * 2
    return None

# Use early returns:
def process(data):
    if not data:
        return None
    if not data.is_valid:
        return None
    if data.value <= 0:
        return None
    return data.value * 2`}
                  />
                </AccordionDetails>
              </Accordion>
            </Grid>
            <Grid item xs={12} md={6}>
              <Accordion sx={{ bgcolor: alpha('#3776ab', 0.03) }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight={600}>✓ Do: Use Dictionary Dispatch</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CodeBlock
                    title="Replace long if-elif chains"
                    code={`# Instead of:
def get_handler(action):
    if action == "create":
        return create_item
    elif action == "update":
        return update_item
    elif action == "delete":
        return delete_item
    
# Use a dictionary:
handlers = {
    "create": create_item,
    "update": update_item,
    "delete": delete_item,
}
handler = handlers.get(action, default_handler)`}
                  />
                </AccordionDetails>
              </Accordion>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== MODULE 7: LOOPS ==================== */}
        <Paper id="module-7" sx={{ p: 4, mb: 5, borderRadius: 4, border: '1px solid', borderColor: 'divider' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
              <LoopIcon sx={{ color: "#3776ab", fontSize: 32 }} />
              Module 7: Loops
            </Typography>
            <DifficultyBadge level="beginner" />
          </Box>
          
          <Typography variant="body1" sx={{ mb: 3, fontSize: '1.1rem', lineHeight: 1.8 }}>
            Loops let you repeat code. Python has two main loop types: <code>for</code> loops iterate over sequences,
            while <code>while</code> loops continue until a condition becomes false. Master both to write efficient code.
          </Typography>

          {/* For Loops */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            For Loops
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            The <code>for</code> loop iterates over any iterable (lists, strings, ranges, etc.). Python's for loop is more like "for each" in other languages.
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Basic For Loop"
                code={`# Loop over a list
fruits = ["apple", "banana", "cherry"]
for fruit in fruits:
    print(fruit)
# apple
# banana
# cherry

# Loop over a string
for char in "Python":
    print(char)
# P, y, t, h, o, n

# Loop over a range
for i in range(5):
    print(i)
# 0, 1, 2, 3, 4

# Range with start, stop, step
for i in range(2, 10, 2):
    print(i)
# 2, 4, 6, 8`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="enumerate() and zip()"
                code={`# Get index AND value with enumerate
fruits = ["apple", "banana", "cherry"]
for index, fruit in enumerate(fruits):
    print(f"{index}: {fruit}")
# 0: apple
# 1: banana
# 2: cherry

# Start enumerate at different number
for i, fruit in enumerate(fruits, start=1):
    print(f"{i}. {fruit}")

# zip() - iterate over multiple sequences
names = ["Alice", "Bob", "Charlie"]
scores = [95, 87, 92]
for name, score in zip(names, scores):
    print(f"{name}: {score}")
# Alice: 95
# Bob: 87
# Charlie: 92`}
              />
            </Grid>
          </Grid>

          {/* While Loops */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            While Loops
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            The <code>while</code> loop continues as long as a condition is true. Be careful to avoid infinite loops!
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Basic While Loop"
                code={`# Count down
count = 5
while count > 0:
    print(count)
    count -= 1
print("Blastoff!")
# 5, 4, 3, 2, 1, Blastoff!

# Input validation loop
while True:
    user_input = input("Enter a number: ")
    if user_input.isdigit():
        number = int(user_input)
        break
    print("Invalid! Try again.")

# Process until condition
items = [1, 2, 3, 4, 5]
while items:  # While list is not empty
    item = items.pop()
    print(f"Processing {item}")`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <WarningBox>
                <strong>Infinite Loop Warning!</strong> Always ensure your while loop has a way to exit.
                <br /><br />
                <code>while True:</code> without a <code>break</code> will run forever!
                <br /><br />
                Common causes:
                <ul style={{ margin: '8px 0', paddingLeft: '20px' }}>
                  <li>Forgetting to update the loop variable</li>
                  <li>Condition that never becomes False</li>
                  <li>Off-by-one errors in counters</li>
                </ul>
              </WarningBox>
            </Grid>
          </Grid>

          {/* Loop Control */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Loop Control: break, continue, else
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <CodeBlock
                title="break - Exit Loop"
                code={`# Stop when found
numbers = [1, 2, 3, 4, 5, 6]
for num in numbers:
    if num == 4:
        print("Found 4!")
        break
    print(num)
# 1, 2, 3, Found 4!

# Search and exit
for item in items:
    if is_target(item):
        result = item
        break`}
              />
            </Grid>
            <Grid item xs={12} md={4}>
              <CodeBlock
                title="continue - Skip Iteration"
                code={`# Skip even numbers
for i in range(10):
    if i % 2 == 0:
        continue
    print(i)
# 1, 3, 5, 7, 9

# Skip invalid items
for item in items:
    if not item.is_valid:
        continue
    process(item)`}
              />
            </Grid>
            <Grid item xs={12} md={4}>
              <CodeBlock
                title="else - No Break Occurred"
                code={`# else runs if loop completes
# without hitting break
for n in range(2, 10):
    for x in range(2, n):
        if n % x == 0:
            break
    else:
        # No break = prime
        print(f"{n} is prime")

# Search with else
for item in items:
    if item == target:
        print("Found!")
        break
else:
    print("Not found")`}
              />
            </Grid>
          </Grid>

          {/* List Comprehensions */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            List Comprehensions
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            A concise way to create lists from loops. More Pythonic and often faster than regular loops.
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Basic Comprehensions"
                code={`# Traditional loop
squares = []
for x in range(10):
    squares.append(x ** 2)

# List comprehension - same result!
squares = [x ** 2 for x in range(10)]
# [0, 1, 4, 9, 16, 25, 36, 49, 64, 81]

# With condition (filter)
evens = [x for x in range(20) if x % 2 == 0]
# [0, 2, 4, 6, 8, 10, 12, 14, 16, 18]

# Transform and filter
words = ["hello", "WORLD", "Python"]
lower_long = [w.lower() for w in words if len(w) > 4]
# ["hello", "world", "python"]`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Advanced Comprehensions"
                code={`# Nested loops in comprehension
matrix = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]
flat = [num for row in matrix for num in row]
# [1, 2, 3, 4, 5, 6, 7, 8, 9]

# Dictionary comprehension
names = ["alice", "bob"]
name_lengths = {name: len(name) for name in names}
# {"alice": 5, "bob": 3}

# Set comprehension
nums = [1, 2, 2, 3, 3, 3]
unique_squares = {x ** 2 for x in nums}
# {1, 4, 9}

# Generator expression (memory efficient)
sum_of_squares = sum(x ** 2 for x in range(1000000))
# Doesn't create list in memory!`}
              />
            </Grid>
          </Grid>

          <Box sx={{ mt: 3 }}>
            <ProTip>
              Use list comprehensions for simple transformations, but stick with regular loops for complex logic.
              If a comprehension gets hard to read, break it into a regular loop. Readability counts!
            </ProTip>
          </Box>
        </Paper>

        {/* ==================== MODULE 8: LISTS & TUPLES ==================== */}
        <Paper id="module-8" sx={{ p: 4, mb: 5, borderRadius: 4, border: '1px solid', borderColor: 'divider' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
              <StorageIcon sx={{ color: "#3776ab", fontSize: 32 }} />
              Module 8: Lists & Tuples
            </Typography>
            <DifficultyBadge level="beginner" />
          </Box>
          
          <Typography variant="body1" sx={{ mb: 3, fontSize: '1.1rem', lineHeight: 1.8 }}>
            Lists and tuples are ordered sequences. Lists are mutable (changeable), tuples are immutable (fixed).
            Choose lists when you need to modify data, tuples when data should stay constant.
          </Typography>

          {/* Lists */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Lists - Mutable Sequences
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Creating & Accessing Lists"
                code={`# Create lists
empty = []
numbers = [1, 2, 3, 4, 5]
mixed = [1, "hello", 3.14, True]
nested = [[1, 2], [3, 4], [5, 6]]

# Access by index
numbers[0]    # 1 (first)
numbers[-1]   # 5 (last)
numbers[1:3]  # [2, 3] (slice)

# Nested access
nested[0][1]  # 2

# Check membership
3 in numbers  # True
10 in numbers # False

# List length
len(numbers)  # 5`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Modifying Lists"
                code={`nums = [1, 2, 3]

# Change element
nums[0] = 10       # [10, 2, 3]

# Add elements
nums.append(4)     # [10, 2, 3, 4]
nums.insert(1, 15) # [10, 15, 2, 3, 4]
nums.extend([5, 6])# [10, 15, 2, 3, 4, 5, 6]

# Remove elements
nums.pop()         # Returns 6, list is now shorter
nums.pop(0)        # Returns 10, removes first
nums.remove(15)    # Removes first occurrence of 15

# Clear all
nums.clear()       # []

# Delete by index/slice
del nums[0]        # Delete first element
del nums[1:3]      # Delete slice`}
              />
            </Grid>
          </Grid>

          <Grid container spacing={3} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="List Methods"
                code={`numbers = [3, 1, 4, 1, 5, 9, 2, 6]

# Sorting
numbers.sort()              # In-place: [1, 1, 2, 3, 4, 5, 6, 9]
numbers.sort(reverse=True)  # Descending

# sorted() returns new list (doesn't modify original)
original = [3, 1, 2]
new_sorted = sorted(original)  # [1, 2, 3]

# Reverse
numbers.reverse()  # In-place reversal

# Count & Index
numbers.count(1)   # How many 1s?
numbers.index(5)   # Index of first 5

# Copy (shallow)
copy1 = numbers.copy()
copy2 = numbers[:]
copy3 = list(numbers)`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="List Operations"
                code={`# Concatenation
[1, 2] + [3, 4]  # [1, 2, 3, 4]

# Repetition
[0] * 5  # [0, 0, 0, 0, 0]

# Unpacking
first, *rest = [1, 2, 3, 4]
# first = 1, rest = [2, 3, 4]

a, b, *_ = [1, 2, 3, 4, 5]
# a = 1, b = 2, _ = [3, 4, 5]

# Min, Max, Sum
numbers = [5, 2, 8, 1, 9]
min(numbers)  # 1
max(numbers)  # 9
sum(numbers)  # 25

# Convert to list
list("hello")       # ['h', 'e', 'l', 'l', 'o']
list(range(5))      # [0, 1, 2, 3, 4]
list({1, 2, 3})     # [1, 2, 3] (from set)`}
              />
            </Grid>
          </Grid>

          {/* Tuples */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Tuples - Immutable Sequences
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Creating & Using Tuples"
                code={`# Create tuples
empty = ()
single = (1,)        # Note the comma!
point = (3, 4)
rgb = (255, 128, 0)
mixed = (1, "hello", 3.14)

# Access (same as lists)
point[0]    # 3
point[-1]   # 4
rgb[0:2]    # (255, 128)

# Tuples are IMMUTABLE
point[0] = 5  # TypeError!

# But can contain mutable objects
data = ([1, 2], [3, 4])
data[0].append(3)  # OK! List inside is mutable
# data is now ([1, 2, 3], [3, 4])`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Tuple Unpacking"
                code={`# Basic unpacking
point = (3, 4)
x, y = point  # x = 3, y = 4

# Swap variables (Pythonic!)
a, b = 1, 2
a, b = b, a  # Now a = 2, b = 1

# Return multiple values from function
def get_stats(numbers):
    return min(numbers), max(numbers), sum(numbers)

low, high, total = get_stats([1, 2, 3, 4, 5])

# Unpacking in loops
points = [(1, 2), (3, 4), (5, 6)]
for x, y in points:
    print(f"x={x}, y={y}")

# Named tuples for clarity
from collections import namedtuple
Point = namedtuple('Point', ['x', 'y'])
p = Point(3, 4)
print(p.x, p.y)  # 3 4`}
              />
            </Grid>
          </Grid>

          {/* When to Use Which */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Lists vs Tuples: When to Use Which?
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha('#2e7d32', 0.05), borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: '#2e7d32', mb: 1 }}>
                  Use Lists When:
                </Typography>
                <Box sx={{ fontSize: '0.9rem' }}>
                  <Box>• Data will change (add, remove, modify)</Box>
                  <Box>• Homogeneous data (all same type)</Box>
                  <Box>• Order matters and may change</Box>
                  <Box>• Building up data dynamically</Box>
                  <Box>• Need list methods (sort, append, etc.)</Box>
                </Box>
                <Box sx={{ mt: 1, fontFamily: 'Fira Code, monospace', fontSize: '0.85rem' }}>
                  <code>users = ["Alice", "Bob", "Charlie"]</code>
                </Box>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, bgcolor: alpha('#1565c0', 0.05), borderRadius: 2 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: '#1565c0', mb: 1 }}>
                  Use Tuples When:
                </Typography>
                <Box sx={{ fontSize: '0.9rem' }}>
                  <Box>• Data should not change (immutable)</Box>
                  <Box>• Heterogeneous data (different types)</Box>
                  <Box>• Fixed structure (coordinates, RGB)</Box>
                  <Box>• Dictionary keys (lists can't be keys!)</Box>
                  <Box>• Returning multiple values from functions</Box>
                </Box>
                <Box sx={{ mt: 1, fontFamily: 'Fira Code, monospace', fontSize: '0.85rem' }}>
                  <code>point = (x, y, z)</code>
                </Box>
              </Paper>
            </Grid>
          </Grid>

          <Box sx={{ mt: 3 }}>
            <ProTip>
              Tuples are slightly faster and use less memory than lists. For data that won't change,
              prefer tuples. They also signal intent: "this data is fixed."
            </ProTip>
          </Box>
        </Paper>

        {/* ==================== MODULE 9: DICTIONARIES & SETS ==================== */}
        <Paper id="module-9" sx={{ p: 4, mb: 5, borderRadius: 4, border: '1px solid', borderColor: 'divider' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
              <DataObjectIcon sx={{ color: "#3776ab", fontSize: 32 }} />
              Module 9: Dictionaries & Sets
            </Typography>
            <DifficultyBadge level="beginner" />
          </Box>
          
          <Typography variant="body1" sx={{ mb: 3, fontSize: '1.1rem', lineHeight: 1.8 }}>
            Dictionaries store key-value pairs for fast lookups. Sets store unique values and support mathematical set operations.
            Both are essential for efficient data handling.
          </Typography>

          {/* Dictionaries */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Dictionaries - Key-Value Storage
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Creating & Accessing Dictionaries"
                code={`# Create dictionaries
empty = {}
user = {"name": "Alice", "age": 30, "active": True}
using_dict = dict(name="Bob", age=25)

# Access values
user["name"]       # "Alice"
user.get("name")   # "Alice"
user.get("email")  # None (no error!)
user.get("email", "N/A")  # "N/A" (default)

# Check key exists
"name" in user     # True
"email" in user    # False

# Get all keys, values, items
user.keys()        # dict_keys(['name', 'age', 'active'])
user.values()      # dict_values(['Alice', 30, True])
user.items()       # dict_items([('name', 'Alice'), ...])`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Modifying Dictionaries"
                code={`user = {"name": "Alice", "age": 30}

# Add or update
user["email"] = "alice@email.com"  # Add new
user["age"] = 31                   # Update existing

# Update multiple at once
user.update({"city": "NYC", "age": 32})

# Remove
del user["age"]              # Delete key
email = user.pop("email")    # Remove & return
user.popitem()               # Remove last inserted

# setdefault - get or set if missing
user.setdefault("role", "user")  # Returns "user", adds if missing

# Clear all
user.clear()

# Copy
copy = user.copy()  # Shallow copy`}
              />
            </Grid>
          </Grid>

          <Grid container spacing={3} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Iterating Over Dictionaries"
                code={`user = {"name": "Alice", "age": 30, "city": "NYC"}

# Iterate over keys (default)
for key in user:
    print(key)

# Iterate over values
for value in user.values():
    print(value)

# Iterate over both (most common)
for key, value in user.items():
    print(f"{key}: {value}")

# Dictionary comprehension
squares = {x: x**2 for x in range(6)}
# {0: 0, 1: 1, 2: 4, 3: 9, 4: 16, 5: 25}

# Filter with comprehension
adults = {name: age for name, age in people.items() if age >= 18}`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Nested Dictionaries"
                code={`# Complex data structures
users = {
    "alice": {
        "email": "alice@email.com",
        "age": 30,
        "roles": ["admin", "editor"]
    },
    "bob": {
        "email": "bob@email.com",
        "age": 25,
        "roles": ["viewer"]
    }
}

# Access nested data
users["alice"]["email"]        # "alice@email.com"
users["alice"]["roles"][0]     # "admin"

# Safe nested access
users.get("charlie", {}).get("email", "N/A")

# Modify nested
users["alice"]["age"] = 31
users["bob"]["roles"].append("editor")`}
              />
            </Grid>
          </Grid>

          {/* Sets */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Sets - Unique Collections
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Creating & Using Sets"
                code={`# Create sets
empty = set()  # NOT {} - that's an empty dict!
numbers = {1, 2, 3, 4, 5}
from_list = set([1, 2, 2, 3, 3, 3])  # {1, 2, 3}

# Sets have NO duplicates
letters = set("hello")  # {'h', 'e', 'l', 'o'}

# Add and remove
numbers.add(6)         # Add single element
numbers.update([7, 8]) # Add multiple
numbers.remove(1)      # Remove (error if missing)
numbers.discard(100)   # Remove (no error if missing)
numbers.pop()          # Remove arbitrary element

# Membership testing (very fast!)
5 in numbers  # True - O(1) lookup!
10 in numbers # False`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Set Operations"
                code={`a = {1, 2, 3, 4}
b = {3, 4, 5, 6}

# Union (all elements from both)
a | b           # {1, 2, 3, 4, 5, 6}
a.union(b)      # Same

# Intersection (common elements)
a & b           # {3, 4}
a.intersection(b)

# Difference (in a but not in b)
a - b           # {1, 2}
a.difference(b)

# Symmetric difference (in a or b, not both)
a ^ b           # {1, 2, 5, 6}
a.symmetric_difference(b)

# Subset and superset
{1, 2} <= {1, 2, 3}  # True (subset)
{1, 2, 3} >= {1, 2}  # True (superset)`}
              />
            </Grid>
          </Grid>

          {/* Practical Uses */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Practical Use Cases
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Remove Duplicates"
                code={`# Quick way to remove duplicates
numbers = [1, 2, 2, 3, 3, 3, 4]
unique = list(set(numbers))  # [1, 2, 3, 4]

# Preserve order (Python 3.7+)
unique_ordered = list(dict.fromkeys(numbers))

# Find unique words in text
text = "the cat and the dog and the bird"
unique_words = set(text.split())
# {'the', 'cat', 'and', 'dog', 'bird'}`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Fast Lookups & Comparisons"
                code={`# Fast membership testing
valid_users = {"alice", "bob", "charlie"}
if username in valid_users:  # O(1) vs O(n) for lists
    grant_access()

# Find common elements
list1 = [1, 2, 3, 4, 5]
list2 = [4, 5, 6, 7, 8]
common = set(list1) & set(list2)  # {4, 5}

# Find differences
only_in_list1 = set(list1) - set(list2)  # {1, 2, 3}

# Count unique items
def count_unique(items):
    return len(set(items))`}
              />
            </Grid>
          </Grid>

          <Box sx={{ mt: 3 }}>
            <ProTip>
              Use sets for membership testing - <code>item in my_set</code> is O(1) constant time,
              while <code>item in my_list</code> is O(n) linear time. For large collections, this makes a huge difference!
            </ProTip>
          </Box>
        </Paper>

        {/* ==================== MODULE 10: FUNCTIONS ==================== */}
        <Paper id="module-10" sx={{ p: 4, mb: 5, borderRadius: 4, border: '1px solid', borderColor: 'divider' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
              <FunctionsIcon sx={{ color: "#3776ab", fontSize: 32 }} />
              Module 10: Functions
            </Typography>
            <DifficultyBadge level="intermediate" />
          </Box>
          
          <Typography variant="body1" sx={{ mb: 3, fontSize: '1.1rem', lineHeight: 1.8 }}>
            Functions are reusable blocks of code that perform specific tasks. They help organize code, reduce repetition,
            and make programs easier to understand and maintain. Master functions to write cleaner, more professional Python.
          </Typography>

          {/* Defining Functions */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Defining Functions
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Basic Function Syntax"
                code={`# Define a function with 'def'
def greet():
    print("Hello, World!")

# Call the function
greet()  # Output: Hello, World!

# Function with parameters
def greet_person(name):
    print(f"Hello, {name}!")

greet_person("Alice")  # Hello, Alice!

# Function with return value
def add(a, b):
    return a + b

result = add(3, 5)  # result = 8

# Multiple return values (returns tuple)
def get_name_and_age():
    return "Alice", 30

name, age = get_name_and_age()`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Docstrings & Type Hints"
                code={`def calculate_area(length: float, width: float) -> float:
    """
    Calculate the area of a rectangle.
    
    Args:
        length: The length of the rectangle.
        width: The width of the rectangle.
    
    Returns:
        The area as a float.
    
    Example:
        >>> calculate_area(5, 3)
        15.0
    """
    return length * width

# Access docstring
print(calculate_area.__doc__)

# Type hints don't enforce types, but help with:
# - Documentation
# - IDE autocompletion
# - Static type checkers (mypy)`}
              />
            </Grid>
          </Grid>

          {/* Parameters and Arguments */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Parameters and Arguments
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Default & Keyword Arguments"
                code={`# Default parameter values
def greet(name, greeting="Hello"):
    return f"{greeting}, {name}!"

greet("Alice")              # "Hello, Alice!"
greet("Alice", "Hi")        # "Hi, Alice!"

# Keyword arguments (named)
def create_user(name, age, city="Unknown"):
    return {"name": name, "age": age, "city": city}

# Positional
create_user("Alice", 30, "NYC")

# Keyword (order doesn't matter)
create_user(age=30, name="Alice", city="NYC")

# Mixed (positional first, then keyword)
create_user("Alice", city="NYC", age=30)`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="*args and **kwargs"
                code={`# *args - variable positional arguments (tuple)
def sum_all(*numbers):
    return sum(numbers)

sum_all(1, 2, 3)        # 6
sum_all(1, 2, 3, 4, 5)  # 15

# **kwargs - variable keyword arguments (dict)
def print_info(**kwargs):
    for key, value in kwargs.items():
        print(f"{key}: {value}")

print_info(name="Alice", age=30, city="NYC")

# Combining all parameter types
def func(pos1, pos2, *args, kw1="default", **kwargs):
    print(f"pos1={pos1}, pos2={pos2}")
    print(f"args={args}")
    print(f"kw1={kw1}")
    print(f"kwargs={kwargs}")

func(1, 2, 3, 4, kw1="custom", extra="value")`}
              />
            </Grid>
          </Grid>

          <WarningBox>
            <strong>Mutable Default Arguments Trap!</strong> Never use mutable objects (lists, dicts) as default values.
            <br /><br />
            <code>def add_item(item, items=[]):</code> ← Bug! The list is shared across calls!
            <br /><br />
            <code>def add_item(item, items=None):</code>
            <br />
            <code>&nbsp;&nbsp;&nbsp;&nbsp;items = items or []</code> ← Correct!
          </WarningBox>

          {/* Lambda Functions */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Lambda Functions
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            Anonymous, single-expression functions. Great for short operations, especially with map(), filter(), sorted().
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Lambda Basics"
                code={`# Syntax: lambda arguments: expression

# Regular function
def square(x):
    return x ** 2

# Equivalent lambda
square = lambda x: x ** 2

# Multiple arguments
add = lambda a, b: a + b
add(3, 5)  # 8

# Conditional expression
is_even = lambda x: "Even" if x % 2 == 0 else "Odd"
is_even(4)  # "Even"

# No arguments
get_pi = lambda: 3.14159`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Lambda with Built-in Functions"
                code={`# Sort by custom key
users = [{"name": "Alice", "age": 30},
         {"name": "Bob", "age": 25}]
sorted_users = sorted(users, key=lambda u: u["age"])

# Filter items
numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
evens = list(filter(lambda x: x % 2 == 0, numbers))
# [2, 4, 6, 8, 10]

# Transform items
squares = list(map(lambda x: x ** 2, numbers))
# [1, 4, 9, 16, 25, 36, 49, 64, 81, 100]

# Sort strings by length
words = ["python", "is", "awesome"]
sorted(words, key=lambda w: len(w))
# ["is", "python", "awesome"]`}
              />
            </Grid>
          </Grid>

          {/* Scope and Closures */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Scope and Closures
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Variable Scope (LEGB Rule)"
                code={`# L - Local: Inside current function
# E - Enclosing: Inside enclosing functions
# G - Global: Module level
# B - Built-in: Python built-ins

x = "global"  # Global scope

def outer():
    x = "enclosing"  # Enclosing scope
    
    def inner():
        x = "local"  # Local scope
        print(x)     # "local"
    
    inner()
    print(x)  # "enclosing"

outer()
print(x)  # "global"

# Modify global variable
count = 0
def increment():
    global count
    count += 1`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Closures"
                code={`# A closure "remembers" variables from enclosing scope

def make_multiplier(n):
    def multiplier(x):
        return x * n  # 'n' is remembered!
    return multiplier

double = make_multiplier(2)
triple = make_multiplier(3)

double(5)  # 10
triple(5)  # 15

# Practical: counter factory
def make_counter():
    count = 0
    def counter():
        nonlocal count  # Modify enclosing variable
        count += 1
        return count
    return counter

counter1 = make_counter()
counter1()  # 1
counter1()  # 2
counter1()  # 3`}
              />
            </Grid>
          </Grid>

          {/* Decorators */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Decorators
          </Typography>
          <Typography variant="body1" sx={{ mb: 2 }}>
            Functions that modify other functions. They wrap a function to extend its behavior without changing its code.
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Basic Decorator"
                code={`# Decorator function
def log_call(func):
    def wrapper(*args, **kwargs):
        print(f"Calling {func.__name__}")
        result = func(*args, **kwargs)
        print(f"Finished {func.__name__}")
        return result
    return wrapper

# Apply decorator with @
@log_call
def say_hello(name):
    print(f"Hello, {name}!")

say_hello("Alice")
# Output:
# Calling say_hello
# Hello, Alice!
# Finished say_hello`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Practical Decorators"
                code={`import time
from functools import wraps

# Timer decorator
def timer(func):
    @wraps(func)  # Preserves function metadata
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        print(f"{func.__name__} took {end - start:.4f}s")
        return result
    return wrapper

@timer
def slow_function():
    time.sleep(1)
    return "Done"

# Decorator with arguments
def repeat(times):
    def decorator(func):
        def wrapper(*args, **kwargs):
            for _ in range(times):
                result = func(*args, **kwargs)
            return result
        return wrapper
    return decorator

@repeat(3)
def say_hi():
    print("Hi!")`}
              />
            </Grid>
          </Grid>

          <Box sx={{ mt: 3 }}>
            <ProTip>
              Always use <code>@functools.wraps(func)</code> in your decorators to preserve the original function's
              name, docstring, and other metadata. This helps with debugging and introspection.
            </ProTip>
          </Box>
        </Paper>

        {/* ==================== MODULE 11: FILE HANDLING ==================== */}
        <Paper id="module-11" sx={{ p: 4, mb: 5, borderRadius: 4, border: '1px solid', borderColor: 'divider' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
              <FolderIcon sx={{ color: "#3776ab", fontSize: 32 }} />
              Module 11: File Handling
            </Typography>
            <DifficultyBadge level="intermediate" />
          </Box>
          
          <Typography variant="body1" sx={{ mb: 3, fontSize: '1.1rem', lineHeight: 1.8 }}>
            File handling allows your programs to persist data, read configurations, process logs, and interact with the file system.
            Python makes file operations simple with context managers that handle cleanup automatically.
          </Typography>

          {/* Reading Files */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Reading Files
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Basic File Reading"
                code={`# Always use 'with' - it auto-closes the file!
with open("data.txt", "r") as file:
    content = file.read()  # Read entire file
    print(content)

# Read line by line (memory efficient)
with open("data.txt", "r") as file:
    for line in file:
        print(line.strip())  # Remove newline

# Read all lines into list
with open("data.txt", "r") as file:
    lines = file.readlines()
    # ['Line 1\\n', 'Line 2\\n', 'Line 3\\n']

# Read single line
with open("data.txt", "r") as file:
    first_line = file.readline()
    second_line = file.readline()`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="File Modes & Encoding"
                code={`# Common file modes:
# 'r'  - Read (default)
# 'w'  - Write (overwrites!)
# 'a'  - Append
# 'x'  - Exclusive create (fails if exists)
# 'b'  - Binary mode
# '+'  - Read and write

# Text mode (default)
with open("file.txt", "r") as f:
    text = f.read()

# Binary mode (images, PDFs, etc.)
with open("image.png", "rb") as f:
    data = f.read()

# Specify encoding (important for non-ASCII!)
with open("data.txt", "r", encoding="utf-8") as f:
    content = f.read()

# Read with different encodings
with open("legacy.txt", "r", encoding="latin-1") as f:
    content = f.read()`}
              />
            </Grid>
          </Grid>

          {/* Writing Files */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Writing Files
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Basic File Writing"
                code={`# Write (overwrites existing content!)
with open("output.txt", "w") as file:
    file.write("Hello, World!\\n")
    file.write("Second line\\n")

# Append (adds to end)
with open("log.txt", "a") as file:
    file.write("New log entry\\n")

# Write multiple lines
lines = ["Line 1", "Line 2", "Line 3"]
with open("output.txt", "w") as file:
    file.writelines(line + "\\n" for line in lines)

# Write with print()
with open("output.txt", "w") as file:
    print("Hello!", file=file)
    print("World!", file=file)`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Read and Write Operations"
                code={`# Read and write (r+)
with open("data.txt", "r+") as file:
    content = file.read()
    file.write("\\nAppended text")

# File position
with open("data.txt", "r") as file:
    file.read(5)      # Read 5 characters
    pos = file.tell() # Get current position: 5
    file.seek(0)      # Go back to start
    file.read()       # Read from beginning

# Truncate file
with open("data.txt", "r+") as file:
    file.truncate(100)  # Keep first 100 bytes

# Safe write with temp file
import tempfile
import shutil

with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
    tmp.write("Safe content")
    shutil.move(tmp.name, "final.txt")`}
              />
            </Grid>
          </Grid>

          {/* Working with Paths */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Working with Paths (pathlib)
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="pathlib Basics"
                code={`from pathlib import Path

# Create path objects
path = Path("folder/file.txt")
home = Path.home()  # User's home directory
cwd = Path.cwd()    # Current working directory

# Path components
path = Path("/home/user/docs/file.txt")
path.name       # "file.txt"
path.stem       # "file"
path.suffix     # ".txt"
path.parent     # Path("/home/user/docs")
path.parts      # ('/', 'home', 'user', 'docs', 'file.txt')

# Build paths (works on any OS!)
path = Path("folder") / "subfolder" / "file.txt"

# Check path properties
path.exists()      # Does it exist?
path.is_file()     # Is it a file?
path.is_dir()      # Is it a directory?`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Directory Operations"
                code={`from pathlib import Path

# Create directories
Path("new_folder").mkdir(exist_ok=True)
Path("a/b/c").mkdir(parents=True, exist_ok=True)

# List directory contents
for item in Path(".").iterdir():
    print(item)

# Find files with glob
for py_file in Path(".").glob("*.py"):
    print(py_file)

# Recursive glob
for py_file in Path(".").rglob("*.py"):
    print(py_file)  # All .py files in subdirs too

# Read/write with pathlib
path = Path("data.txt")
content = path.read_text(encoding="utf-8")
path.write_text("New content", encoding="utf-8")

# Binary operations
data = path.read_bytes()
path.write_bytes(b"Binary data")`}
              />
            </Grid>
          </Grid>

          {/* CSV and JSON */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Working with CSV and JSON
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="CSV Files"
                code={`import csv

# Read CSV
with open("data.csv", "r") as file:
    reader = csv.reader(file)
    for row in reader:
        print(row)  # ['col1', 'col2', 'col3']

# Read CSV as dictionaries
with open("data.csv", "r") as file:
    reader = csv.DictReader(file)
    for row in reader:
        print(row["name"], row["age"])

# Write CSV
with open("output.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Name", "Age", "City"])
    writer.writerow(["Alice", 30, "NYC"])

# Write from dictionaries
with open("output.csv", "w", newline="") as file:
    fieldnames = ["name", "age"]
    writer = csv.DictWriter(file, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerow({"name": "Alice", "age": 30})`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="JSON Files"
                code={`import json

# Read JSON
with open("data.json", "r") as file:
    data = json.load(file)

# Write JSON
data = {"name": "Alice", "age": 30, "scores": [95, 87, 92]}
with open("output.json", "w") as file:
    json.dump(data, file, indent=2)

# JSON string conversion
json_string = json.dumps(data)  # Dict to string
data = json.loads(json_string)  # String to dict

# Handle special types
from datetime import datetime

def json_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type not serializable")

data = {"timestamp": datetime.now()}
json.dumps(data, default=json_serializer)`}
              />
            </Grid>
          </Grid>

          <Box sx={{ mt: 3 }}>
            <ProTip>
              Always use the <code>with</code> statement for file operations. It ensures files are properly closed
              even if an exception occurs. This prevents resource leaks and data corruption.
            </ProTip>
          </Box>
        </Paper>

        {/* ==================== MODULE 12: ERROR HANDLING ==================== */}
        <Paper id="module-12" sx={{ p: 4, mb: 5, borderRadius: 4, border: '1px solid', borderColor: 'divider' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
              <BugReportIcon sx={{ color: "#3776ab", fontSize: 32 }} />
              Module 12: Error Handling
            </Typography>
            <DifficultyBadge level="intermediate" />
          </Box>
          
          <Typography variant="body1" sx={{ mb: 3, fontSize: '1.1rem', lineHeight: 1.8 }}>
            Errors happen - files don't exist, networks fail, users input garbage. Error handling lets your program
            respond gracefully instead of crashing. Learn to catch, handle, and raise exceptions like a pro.
          </Typography>

          {/* Try/Except */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Try/Except Basics
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Basic Exception Handling"
                code={`# Without handling - program crashes!
# result = 10 / 0  # ZeroDivisionError

# With handling
try:
    result = 10 / 0
except ZeroDivisionError:
    print("Cannot divide by zero!")
    result = 0

# Catch multiple exception types
try:
    value = int(input("Enter a number: "))
    result = 100 / value
except ValueError:
    print("That's not a valid number!")
except ZeroDivisionError:
    print("Cannot divide by zero!")

# Catch multiple in one line
try:
    risky_operation()
except (ValueError, TypeError, KeyError):
    print("Something went wrong")`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Exception Details"
                code={`# Access exception information
try:
    result = 10 / 0
except ZeroDivisionError as e:
    print(f"Error: {e}")
    print(f"Type: {type(e).__name__}")

# Catch ALL exceptions (use sparingly!)
try:
    risky_operation()
except Exception as e:
    print(f"Unexpected error: {e}")

# BaseException catches even system exits
try:
    risky_operation()
except BaseException as e:  # Includes KeyboardInterrupt
    print("Something happened")

# Re-raise after logging
try:
    process_data()
except Exception as e:
    log_error(e)
    raise  # Re-raise same exception`}
              />
            </Grid>
          </Grid>

          {/* Try/Except/Else/Finally */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Complete Try Statement
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="try/except/else/finally"
                code={`try:
    file = open("data.txt", "r")
    content = file.read()
except FileNotFoundError:
    print("File not found!")
    content = ""
else:
    # Runs ONLY if no exception occurred
    print("File read successfully!")
    process_content(content)
finally:
    # ALWAYS runs (cleanup code)
    print("Cleanup complete")
    if 'file' in locals() and not file.closed:
        file.close()

# Practical pattern
def get_data():
    try:
        response = fetch_from_api()
    except ConnectionError:
        return get_cached_data()
    else:
        cache_response(response)
        return response`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Context Managers vs Try/Finally"
                code={`# Manual cleanup with try/finally
file = None
try:
    file = open("data.txt", "r")
    content = file.read()
finally:
    if file:
        file.close()

# Much cleaner with context manager!
with open("data.txt", "r") as file:
    content = file.read()
# File automatically closed

# Multiple context managers
with open("input.txt") as infile, \\
     open("output.txt", "w") as outfile:
    content = infile.read()
    outfile.write(content.upper())

# Custom context manager
from contextlib import contextmanager

@contextmanager
def timer():
    start = time.time()
    yield
    print(f"Elapsed: {time.time() - start:.2f}s")`}
              />
            </Grid>
          </Grid>

          {/* Common Exceptions */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Common Exception Types
          </Typography>

          <TableContainer component={Paper} sx={{ mb: 3, bgcolor: alpha('#3776ab', 0.03) }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha('#3776ab', 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Exception</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>When It Occurs</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {[
                  { ex: 'ValueError', when: 'Wrong value type', example: "int('abc')" },
                  { ex: 'TypeError', when: 'Wrong type for operation', example: "'2' + 2" },
                  { ex: 'KeyError', when: 'Dict key not found', example: "d['missing']" },
                  { ex: 'IndexError', when: 'List index out of range', example: "[1,2][5]" },
                  { ex: 'AttributeError', when: 'Attribute not found', example: "'str'.foo" },
                  { ex: 'FileNotFoundError', when: 'File doesn\'t exist', example: "open('x.txt')" },
                  { ex: 'ZeroDivisionError', when: 'Division by zero', example: "10 / 0" },
                  { ex: 'ImportError', when: 'Import fails', example: "import fake" },
                ].map((row) => (
                  <TableRow key={row.ex}>
                    <TableCell sx={{ fontFamily: 'Fira Code, monospace', fontWeight: 600, color: '#c62828' }}>{row.ex}</TableCell>
                    <TableCell>{row.when}</TableCell>
                    <TableCell sx={{ fontFamily: 'Fira Code, monospace', fontSize: '0.85rem' }}>{row.example}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          {/* Raising Exceptions */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Raising Exceptions
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Raise Built-in Exceptions"
                code={`# Raise an exception
def divide(a, b):
    if b == 0:
        raise ValueError("Cannot divide by zero")
    return a / b

# Raise with context
def get_user(user_id):
    user = database.find(user_id)
    if user is None:
        raise KeyError(f"User {user_id} not found")
    return user

# Assert for debugging (disabled with -O flag)
def process_age(age):
    assert age >= 0, "Age cannot be negative"
    assert age < 150, "Age seems unrealistic"
    return age

# Assertions are for bugs, not user input!`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Custom Exceptions"
                code={`# Define custom exceptions
class ValidationError(Exception):
    """Raised when validation fails."""
    pass

class InsufficientFundsError(Exception):
    def __init__(self, balance, amount):
        self.balance = balance
        self.amount = amount
        super().__init__(
            f"Cannot withdraw {amount}, "
            f"only {balance} available"
        )

# Use custom exceptions
def withdraw(account, amount):
    if amount > account.balance:
        raise InsufficientFundsError(
            account.balance, amount
        )
    account.balance -= amount

# Catch custom exceptions
try:
    withdraw(account, 1000)
except InsufficientFundsError as e:
    print(f"Error: {e}")
    print(f"Tried: {e.amount}, Have: {e.balance}")`}
              />
            </Grid>
          </Grid>

          {/* Exception Chaining */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Exception Chaining & Best Practices
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Exception Chaining"
                code={`# Chain exceptions to preserve context
try:
    config = load_config()
except FileNotFoundError as e:
    raise ConfigError("Failed to load config") from e

# The traceback shows both exceptions:
# FileNotFoundError: [Errno 2] No such file
# The above exception was the direct cause of:
# ConfigError: Failed to load config

# Suppress original exception
try:
    process()
except SomeError:
    raise DifferentError() from None

# Access the chain
try:
    operation()
except SomeError as e:
    print(e.__cause__)    # Explicit cause (from)
    print(e.__context__)  # Implicit cause`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <Accordion sx={{ bgcolor: alpha('#3776ab', 0.03) }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography fontWeight={600}>✓ Exception Handling Best Practices</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Box sx={{ fontSize: '0.9rem' }}>
                    <Box sx={{ mb: 1 }}>• <strong>Be specific</strong> - Catch specific exceptions, not bare <code>except:</code></Box>
                    <Box sx={{ mb: 1 }}>• <strong>Don't silence</strong> - Avoid empty except blocks</Box>
                    <Box sx={{ mb: 1 }}>• <strong>Log it</strong> - Always log unexpected exceptions</Box>
                    <Box sx={{ mb: 1 }}>• <strong>Clean up</strong> - Use <code>finally</code> or context managers</Box>
                    <Box sx={{ mb: 1 }}>• <strong>Fail fast</strong> - Validate input early</Box>
                    <Box sx={{ mb: 1 }}>• <strong>EAFP</strong> - "Easier to Ask Forgiveness than Permission"</Box>
                    <Box sx={{ mb: 1 }}>• <strong>Custom types</strong> - Create domain-specific exceptions</Box>
                    <Box>• <strong>Chain</strong> - Preserve context with <code>from</code></Box>
                  </Box>
                </AccordionDetails>
              </Accordion>
              <Box sx={{ mt: 2 }}>
                <ProTip>
                  Python philosophy: EAFP (try/except) is preferred over LBYL (if checks).
                  Instead of <code>if key in dict:</code> then access, just access and catch <code>KeyError</code>.
                </ProTip>
              </Box>
            </Grid>
          </Grid>
        </Paper>

        {/* ==================== MODULE 13: CLASSES & OOP ==================== */}
        <Paper id="module-13" sx={{ p: 4, mb: 5, borderRadius: 4, border: '1px solid', borderColor: 'divider' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
              <CategoryIcon sx={{ color: "#3776ab", fontSize: 32 }} />
              Module 13: Classes & Object-Oriented Programming
            </Typography>
            <DifficultyBadge level="intermediate" />
          </Box>
          
          <Typography variant="body1" sx={{ mb: 3, fontSize: '1.1rem', lineHeight: 1.8 }}>
            Object-Oriented Programming (OOP) is a paradigm that organizes code around objects - bundles of data and behavior.
            Classes are blueprints for creating objects. Master OOP to write scalable, maintainable, and reusable code.
          </Typography>

          {/* Class Basics */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Class Basics
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Defining Classes"
                code={`# Define a class
class Dog:
    # Class attribute (shared by all instances)
    species = "Canis familiaris"
    
    # Constructor (initializer)
    def __init__(self, name, age):
        # Instance attributes (unique to each instance)
        self.name = name
        self.age = age
    
    # Instance method
    def bark(self):
        return f"{self.name} says woof!"
    
    # String representation
    def __str__(self):
        return f"{self.name}, {self.age} years old"
    
    def __repr__(self):
        return f"Dog('{self.name}', {self.age})"

# Create instances (objects)
buddy = Dog("Buddy", 3)
max = Dog("Max", 5)

print(buddy.name)      # "Buddy"
print(buddy.bark())    # "Buddy says woof!"
print(Dog.species)     # "Canis familiaris"`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Instance vs Class Attributes"
                code={`class Counter:
    # Class attribute
    total_count = 0
    
    def __init__(self):
        # Instance attribute
        self.count = 0
        Counter.total_count += 1
    
    def increment(self):
        self.count += 1
    
    @classmethod
    def get_total(cls):
        return cls.total_count
    
    @staticmethod
    def description():
        return "A simple counter class"

c1 = Counter()
c2 = Counter()
c1.increment()
c1.increment()
c2.increment()

print(c1.count)           # 2 (instance)
print(c2.count)           # 1 (instance)
print(Counter.total_count) # 2 (class)
print(Counter.get_total()) # 2
print(Counter.description()) # Static method`}
              />
            </Grid>
          </Grid>

          {/* Special Methods */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Special (Dunder) Methods
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Common Dunder Methods"
                code={`class Vector:
    def __init__(self, x, y):
        self.x = x
        self.y = y
    
    # String representations
    def __str__(self):
        return f"Vector({self.x}, {self.y})"
    
    def __repr__(self):
        return f"Vector({self.x!r}, {self.y!r})"
    
    # Arithmetic operators
    def __add__(self, other):
        return Vector(self.x + other.x, self.y + other.y)
    
    def __sub__(self, other):
        return Vector(self.x - other.x, self.y - other.y)
    
    def __mul__(self, scalar):
        return Vector(self.x * scalar, self.y * scalar)
    
    # Comparison
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y
    
    # Length
    def __len__(self):
        return int((self.x**2 + self.y**2)**0.5)

v1 = Vector(2, 3)
v2 = Vector(1, 1)
print(v1 + v2)   # Vector(3, 4)
print(v1 * 3)    # Vector(6, 9)`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Container & Context Dunders"
                code={`class DataStore:
    def __init__(self, data):
        self._data = list(data)
    
    # Container protocol
    def __len__(self):
        return len(self._data)
    
    def __getitem__(self, index):
        return self._data[index]
    
    def __setitem__(self, index, value):
        self._data[index] = value
    
    def __contains__(self, item):
        return item in self._data
    
    def __iter__(self):
        return iter(self._data)

store = DataStore([1, 2, 3, 4, 5])
print(len(store))    # 5
print(store[0])      # 1
print(3 in store)    # True
for item in store:
    print(item)

# Context manager protocol
class FileHandler:
    def __init__(self, filename):
        self.filename = filename
    
    def __enter__(self):
        self.file = open(self.filename)
        return self.file
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.file.close()
        return False  # Don't suppress exceptions`}
              />
            </Grid>
          </Grid>

          {/* Inheritance */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Inheritance
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Basic Inheritance"
                code={`# Base class (parent)
class Animal:
    def __init__(self, name):
        self.name = name
    
    def speak(self):
        raise NotImplementedError("Subclass must implement")
    
    def describe(self):
        return f"I am {self.name}"

# Derived class (child)
class Dog(Animal):
    def __init__(self, name, breed):
        super().__init__(name)  # Call parent constructor
        self.breed = breed
    
    def speak(self):  # Override parent method
        return "Woof!"
    
    def fetch(self):  # New method
        return f"{self.name} fetches the ball"

class Cat(Animal):
    def speak(self):
        return "Meow!"

dog = Dog("Buddy", "Labrador")
cat = Cat("Whiskers")

print(dog.describe())  # "I am Buddy" (inherited)
print(dog.speak())     # "Woof!" (overridden)
print(dog.fetch())     # New method
print(isinstance(dog, Animal))  # True`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Multiple Inheritance & MRO"
                code={`class A:
    def method(self):
        return "A"

class B(A):
    def method(self):
        return "B"

class C(A):
    def method(self):
        return "C"

class D(B, C):  # Multiple inheritance
    pass

d = D()
print(d.method())  # "B" (first parent)

# Method Resolution Order (MRO)
print(D.__mro__)
# (<class 'D'>, <class 'B'>, <class 'C'>, 
#  <class 'A'>, <class 'object'>)

# Using super() with MRO
class E(B, C):
    def method(self):
        return f"E -> {super().method()}"

e = E()
print(e.method())  # "E -> B"

# Mixins - reusable functionality
class JSONMixin:
    def to_json(self):
        import json
        return json.dumps(self.__dict__)

class Person(JSONMixin):
    def __init__(self, name):
        self.name = name

p = Person("Alice")
print(p.to_json())  # {"name": "Alice"}`}
              />
            </Grid>
          </Grid>

          {/* Properties and Encapsulation */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Properties & Encapsulation
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Properties (Getters/Setters)"
                code={`class Temperature:
    def __init__(self, celsius=0):
        self._celsius = celsius  # "Private" by convention
    
    @property
    def celsius(self):
        """Get temperature in Celsius."""
        return self._celsius
    
    @celsius.setter
    def celsius(self, value):
        if value < -273.15:
            raise ValueError("Below absolute zero!")
        self._celsius = value
    
    @property
    def fahrenheit(self):
        """Get temperature in Fahrenheit."""
        return self._celsius * 9/5 + 32
    
    @fahrenheit.setter
    def fahrenheit(self, value):
        self.celsius = (value - 32) * 5/9

temp = Temperature(25)
print(temp.celsius)     # 25
print(temp.fahrenheit)  # 77.0

temp.fahrenheit = 100
print(temp.celsius)     # 37.78...

# temp.celsius = -300  # Raises ValueError`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Data Classes (Python 3.7+)"
                code={`from dataclasses import dataclass, field
from typing import List

@dataclass
class Person:
    name: str
    age: int
    email: str = ""  # Default value

# Auto-generates __init__, __repr__, __eq__
alice = Person("Alice", 30, "alice@email.com")
bob = Person("Bob", 25)

print(alice)  # Person(name='Alice', age=30, ...)
print(alice == Person("Alice", 30, "alice@email.com"))  # True

# Advanced features
@dataclass(frozen=True)  # Immutable
class Point:
    x: float
    y: float

@dataclass
class Team:
    name: str
    members: List[str] = field(default_factory=list)
    _id: int = field(default=0, repr=False)
    
    def __post_init__(self):
        # Called after __init__
        self._id = hash(self.name)

team = Team("Avengers", ["Thor", "Hulk"])
print(team)  # Team(name='Avengers', members=[...])`}
              />
            </Grid>
          </Grid>

          <Box sx={{ mt: 3 }}>
            <ProTip>
              Use <code>@dataclass</code> for simple data containers - it saves tons of boilerplate!
              For more control, use regular classes with <code>@property</code> decorators for computed attributes.
            </ProTip>
          </Box>
        </Paper>

        {/* ==================== MODULE 14: MODULES & PACKAGES ==================== */}
        <Paper id="module-14" sx={{ p: 4, mb: 5, borderRadius: 4, border: '1px solid', borderColor: 'divider' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
              <ExtensionIcon sx={{ color: "#3776ab", fontSize: 32 }} />
              Module 14: Modules & Packages
            </Typography>
            <DifficultyBadge level="intermediate" />
          </Box>
          
          <Typography variant="body1" sx={{ mb: 3, fontSize: '1.1rem', lineHeight: 1.8 }}>
            Modules and packages help organize code into reusable components. A module is a single Python file,
            while a package is a directory of modules. Learn to structure projects professionally and leverage Python's rich ecosystem.
          </Typography>

          {/* Creating Modules */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Creating & Using Modules
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Creating a Module (math_utils.py)"
                code={`# math_utils.py
"""Math utility functions."""

PI = 3.14159
E = 2.71828

def add(a, b):
    """Add two numbers."""
    return a + b

def multiply(a, b):
    """Multiply two numbers."""
    return a * b

def factorial(n):
    """Calculate factorial recursively."""
    if n <= 1:
        return 1
    return n * factorial(n - 1)

class Calculator:
    """Simple calculator class."""
    def __init__(self):
        self.history = []
    
    def calculate(self, a, op, b):
        result = eval(f"{a} {op} {b}")
        self.history.append(result)
        return result

# Code that runs only when executed directly
if __name__ == "__main__":
    print("Testing math_utils...")
    print(add(2, 3))  # 5`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Importing Modules"
                code={`# Import entire module
import math_utils
print(math_utils.add(2, 3))
print(math_utils.PI)

# Import with alias
import math_utils as mu
print(mu.multiply(4, 5))

# Import specific items
from math_utils import add, PI
print(add(10, 20))
print(PI)

# Import with alias
from math_utils import Calculator as Calc
calc = Calc()

# Import all (avoid - pollutes namespace!)
from math_utils import *

# Import from standard library
import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict, Counter

# Import from package
from urllib.parse import urlparse
from pathlib import Path`}
              />
            </Grid>
          </Grid>

          {/* Creating Packages */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Creating Packages
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Package Structure"
                code={`# Package directory structure:
mypackage/
├── __init__.py      # Makes it a package
├── module1.py
├── module2.py
└── subpackage/
    ├── __init__.py
    └── module3.py

# __init__.py controls what's exported
# mypackage/__init__.py
"""My awesome package."""

__version__ = "1.0.0"
__all__ = ["module1", "func1", "Class1"]

from .module1 import func1, Class1
from .module2 import func2

# Now users can do:
# from mypackage import func1, Class1

# Or access subpackages:
# from mypackage.subpackage import module3`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Relative vs Absolute Imports"
                code={`# Inside mypackage/module2.py

# Absolute imports (recommended)
from mypackage.module1 import func1
from mypackage.subpackage.module3 import helper

# Relative imports (within same package)
from . import module1           # Same directory
from .module1 import func1      # Specific item
from .. import other_package    # Parent directory
from ..sibling import utils     # Sibling package

# Example package structure:
project/
├── main.py
└── myapp/
    ├── __init__.py
    ├── core/
    │   ├── __init__.py
    │   └── database.py
    ├── utils/
    │   ├── __init__.py
    │   └── helpers.py
    └── api/
        ├── __init__.py
        └── routes.py

# In routes.py:
from ..core.database import connect
from ..utils.helpers import format_response`}
              />
            </Grid>
          </Grid>

          {/* Python Path and Virtual Environments */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Python Path & Virtual Environments
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Understanding Python Path"
                code={`import sys

# Where Python looks for modules
for path in sys.path:
    print(path)
# 1. Current directory
# 2. PYTHONPATH environment variable
# 3. Standard library
# 4. site-packages (installed packages)

# Add to path at runtime
sys.path.append('/path/to/my/modules')

# Check where a module is loaded from
import os
print(os.__file__)  # /usr/lib/python3.x/os.py

# Inspect a module
import math
print(dir(math))  # List all attributes
help(math.sqrt)   # Get documentation

# Reload a module (for development)
import importlib
import mymodule
importlib.reload(mymodule)`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Virtual Environments"
                code={`# Create virtual environment
# $ python -m venv myenv

# Activate (Windows)
# $ myenv\\Scripts\\activate

# Activate (macOS/Linux)
# $ source myenv/bin/activate

# Install packages
# (myenv) $ pip install requests flask

# Save dependencies
# (myenv) $ pip freeze > requirements.txt

# requirements.txt content:
# requests==2.28.0
# flask==2.2.0

# Install from requirements
# $ pip install -r requirements.txt

# Deactivate
# (myenv) $ deactivate

# Modern alternative: Poetry
# $ poetry init
# $ poetry add requests
# $ poetry install

# Or: pipenv
# $ pipenv install requests
# $ pipenv shell`}
              />
            </Grid>
          </Grid>

          {/* Standard Library Highlights */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Standard Library Highlights
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Essential Standard Modules"
                code={`# Collections - specialized containers
from collections import Counter, defaultdict, deque

counter = Counter(['a', 'b', 'a', 'c', 'a'])
print(counter.most_common(2))  # [('a', 3), ('b', 1)]

dd = defaultdict(list)
dd['key'].append(1)  # No KeyError!

queue = deque([1, 2, 3])
queue.appendleft(0)  # Efficient left append

# itertools - iteration tools
from itertools import chain, cycle, combinations

# Chain iterables
list(chain([1, 2], [3, 4]))  # [1, 2, 3, 4]

# All combinations
list(combinations('ABC', 2))
# [('A','B'), ('A','C'), ('B','C')]

# functools - higher-order functions
from functools import lru_cache, partial

@lru_cache(maxsize=128)
def fibonacci(n):
    if n < 2: return n
    return fibonacci(n-1) + fibonacci(n-2)

add_ten = partial(add, 10)
add_ten(5)  # 15`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="More Useful Modules"
                code={`# datetime - date and time
from datetime import datetime, timedelta

now = datetime.now()
yesterday = now - timedelta(days=1)
formatted = now.strftime("%Y-%m-%d %H:%M")

# re - regular expressions
import re
pattern = r'\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b'
emails = re.findall(pattern, text)

# random - randomness
import random
random.choice([1, 2, 3])
random.shuffle(mylist)
random.randint(1, 100)

# logging - proper logging
import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.info("Application started")
logger.error("Something went wrong")

# argparse - CLI arguments
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("--name", required=True)
args = parser.parse_args()
print(args.name)`}
              />
            </Grid>
          </Grid>

          <Box sx={{ mt: 3 }}>
            <ProTip>
              Always use virtual environments for your projects! They isolate dependencies and prevent
              version conflicts. Tools like <code>poetry</code> or <code>pipenv</code> make management even easier.
            </ProTip>
          </Box>
        </Paper>

        {/* ==================== LIBRARIES & ECOSYSTEM ==================== */}
        <Paper id="libraries" sx={{ p: 4, mb: 5, borderRadius: 4, border: "1px solid", borderColor: "divider" }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
              <ExtensionIcon sx={{ color: "#3776ab", fontSize: 32 }} />
              Libraries & Ecosystem
            </Typography>
            <DifficultyBadge level="beginner" />
          </Box>

          <Typography variant="body1" sx={{ mb: 3, fontSize: "1.1rem", lineHeight: 1.8 }}>
            A library is reusable code that solves a specific problem so you do not have to build everything from
            scratch. Python ships with a <strong>standard library</strong> (built-in), and you can add
            <strong> third-party libraries</strong> from PyPI using <code>pip</code>.
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3776ab" }}>
                Standard library essentials
              </Typography>
              <List dense>
                {[
                  "pathlib: cross-platform file paths",
                  "json: read/write JSON data",
                  "datetime: dates and times",
                  "random: generate random numbers",
                  "csv: work with CSV files",
                  "math/statistics: math helpers and stats",
                ].map((item, idx) => (
                  <ListItem key={idx} sx={{ px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}>
                      <CheckCircleIcon sx={{ color: "#22c55e", fontSize: 18 }} />
                    </ListItemIcon>
                    <ListItemText primary={item} />
                  </ListItem>
                ))}
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3776ab" }}>
                Popular third-party libraries
              </Typography>
              <List dense>
                {[
                  "requests: make HTTP requests",
                  "numpy/pandas: data and analysis",
                  "matplotlib: charts and plots",
                  "flask/fastapi/django: web apps and APIs",
                  "pytest: testing your code",
                  "beautifulsoup4: parse HTML",
                ].map((item, idx) => (
                  <ListItem key={idx} sx={{ px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}>
                      <CheckCircleIcon sx={{ color: "#3776ab", fontSize: 18 }} />
                    </ListItemIcon>
                    <ListItemText primary={item} />
                  </ListItem>
                ))}
              </List>
            </Grid>
          </Grid>

          <Box sx={{ mt: 3 }}>
            <CodeBlock
              title="Install and use a library"
              code={`# Install a third-party library
python -m pip install requests

# Use it in your code
import requests
response = requests.get("https://api.github.com")
print(response.status_code)`}
            />
          </Box>

          <Box sx={{ mt: 2 }}>
            <ProTip>
              Keep a <code>requirements.txt</code> (or <code>pyproject.toml</code>) so others can install the same
              libraries. This makes your projects repeatable.
            </ProTip>
          </Box>
        </Paper>

        {/* ==================== MODULE 15: ADVANCED TOPICS ==================== */}
        <Paper id="module-15" sx={{ p: 4, mb: 5, borderRadius: 4, border: '1px solid', borderColor: 'divider' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
              <RocketLaunchIcon sx={{ color: "#3776ab", fontSize: 32 }} />
              Module 15: Advanced Topics
            </Typography>
            <DifficultyBadge level="advanced" />
          </Box>
          
          <Typography variant="body1" sx={{ mb: 3, fontSize: '1.1rem', lineHeight: 1.8 }}>
            Take your Python skills to the next level with advanced concepts. Generators for memory efficiency,
            async programming for concurrency, metaclasses for framework building, and type hints for robust code.
          </Typography>

          {/* Generators */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Generators & Iterators
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Generator Functions"
                code={`# Generator function (uses yield)
def count_up_to(n):
    i = 1
    while i <= n:
        yield i  # Pauses here, returns value
        i += 1

# Use the generator
for num in count_up_to(5):
    print(num)  # 1, 2, 3, 4, 5

# Generator creates values on-demand (lazy)
gen = count_up_to(1000000)
print(next(gen))  # 1
print(next(gen))  # 2
# Memory: only one value at a time!

# Read huge files line by line
def read_large_file(path):
    with open(path) as f:
        for line in f:
            yield line.strip()

# Process without loading entire file
for line in read_large_file("huge.log"):
    if "ERROR" in line:
        print(line)`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Generator Expressions & Tools"
                code={`# Generator expression (like list comp, but lazy)
squares = (x**2 for x in range(1000000))
# No memory allocated yet!

print(next(squares))  # 0
print(next(squares))  # 1

# Sum without creating list
total = sum(x**2 for x in range(1000000))

# Chain generators (pipelines)
def numbers():
    for i in range(10):
        yield i

def doubled(nums):
    for n in nums:
        yield n * 2

def filtered(nums):
    for n in nums:
        if n > 5:
            yield n

# Pipeline: numbers -> double -> filter
pipeline = filtered(doubled(numbers()))
print(list(pipeline))  # [6, 8, 10, 12, 14, 16, 18]

# yield from (delegate to sub-generator)
def flatten(nested):
    for item in nested:
        if isinstance(item, list):
            yield from flatten(item)
        else:
            yield item

list(flatten([1, [2, 3, [4, 5]], 6]))
# [1, 2, 3, 4, 5, 6]`}
              />
            </Grid>
          </Grid>

          {/* Async Programming */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Async/Await (Concurrency)
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Async Basics"
                code={`import asyncio

# Define async function (coroutine)
async def fetch_data(url):
    print(f"Fetching {url}...")
    await asyncio.sleep(1)  # Simulate network delay
    return f"Data from {url}"

# Run single coroutine
async def main():
    result = await fetch_data("https://api.example.com")
    print(result)

asyncio.run(main())

# Run multiple coroutines concurrently
async def main():
    # These run concurrently, not sequentially!
    results = await asyncio.gather(
        fetch_data("https://api1.com"),
        fetch_data("https://api2.com"),
        fetch_data("https://api3.com"),
    )
    print(results)  # All three results

# Takes ~1 second total, not 3!
asyncio.run(main())`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Practical Async Patterns"
                code={`import asyncio
import aiohttp  # pip install aiohttp

async def fetch_url(session, url):
    async with session.get(url) as response:
        return await response.text()

async def fetch_all(urls):
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_url(session, url) for url in urls]
        return await asyncio.gather(*tasks)

# Async context managers
class AsyncDatabase:
    async def __aenter__(self):
        await self.connect()
        return self
    
    async def __aexit__(self, *args):
        await self.disconnect()

async def main():
    async with AsyncDatabase() as db:
        await db.query("SELECT * FROM users")

# Async iterators
async def async_range(n):
    for i in range(n):
        await asyncio.sleep(0.1)
        yield i

async def main():
    async for num in async_range(5):
        print(num)`}
              />
            </Grid>
          </Grid>

          <WarningBox>
            <strong>Async vs Threading:</strong> Use <code>async/await</code> for I/O-bound tasks (network, disk).
            Use <code>threading</code> or <code>multiprocessing</code> for CPU-bound tasks. Async is cooperative
            (one thread), while threading is preemptive (multiple threads).
          </WarningBox>

          {/* Type Hints */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Type Hints & Static Typing
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Type Annotations"
                code={`from typing import List, Dict, Optional, Union, Tuple

# Basic type hints
def greet(name: str) -> str:
    return f"Hello, {name}!"

# Container types
def process_items(items: List[int]) -> Dict[str, int]:
    return {"sum": sum(items), "count": len(items)}

# Optional (can be None)
def find_user(user_id: int) -> Optional[str]:
    if user_id == 1:
        return "Alice"
    return None

# Union (multiple types)
def double(x: Union[int, float]) -> Union[int, float]:
    return x * 2

# Tuple with specific types
def get_point() -> Tuple[int, int]:
    return (10, 20)

# Type aliases
UserId = int
UserDict = Dict[str, Union[str, int]]

def get_user(id: UserId) -> UserDict:
    return {"name": "Alice", "age": 30}`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Advanced Type Hints"
                code={`from typing import (Callable, TypeVar, Generic,
                    Protocol, Literal)

# Callable types
def apply(func: Callable[[int, int], int], a: int, b: int) -> int:
    return func(a, b)

# TypeVar for generics
T = TypeVar('T')

def first(items: List[T]) -> T:
    return items[0]

# Generic classes
class Stack(Generic[T]):
    def __init__(self) -> None:
        self._items: List[T] = []
    
    def push(self, item: T) -> None:
        self._items.append(item)
    
    def pop(self) -> T:
        return self._items.pop()

stack: Stack[int] = Stack()
stack.push(1)

# Protocol (structural typing)
class Drawable(Protocol):
    def draw(self) -> None: ...

# Literal (specific values)
Mode = Literal["r", "w", "a"]

def open_file(path: str, mode: Mode) -> None:
    pass

# Run type checker: mypy script.py`}
              />
            </Grid>
          </Grid>

          {/* Metaclasses */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Metaclasses & Descriptors
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Metaclasses"
                code={`# Classes are instances of metaclasses
# type is the default metaclass

# Create class dynamically with type
MyClass = type('MyClass', (object,), {'x': 1})

# Custom metaclass
class SingletonMeta(type):
    _instances = {}
    
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]

class Database(metaclass=SingletonMeta):
    def __init__(self):
        print("Creating database connection")

# Only one instance ever created
db1 = Database()  # Creates
db2 = Database()  # Returns same instance
print(db1 is db2)  # True

# Registry metaclass
class PluginMeta(type):
    plugins = {}
    
    def __new__(mcs, name, bases, namespace):
        cls = super().__new__(mcs, name, bases, namespace)
        if name != 'Plugin':
            mcs.plugins[name] = cls
        return cls`}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <CodeBlock
                title="Descriptors"
                code={`# Descriptors control attribute access

class Validator:
    def __init__(self, min_value, max_value):
        self.min = min_value
        self.max = max_value
    
    def __set_name__(self, owner, name):
        self.name = name
    
    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        return obj.__dict__.get(self.name)
    
    def __set__(self, obj, value):
        if not self.min <= value <= self.max:
            raise ValueError(
                f"{self.name} must be between "
                f"{self.min} and {self.max}"
            )
        obj.__dict__[self.name] = value

class Person:
    age = Validator(0, 150)
    height = Validator(0, 300)
    
    def __init__(self, age, height):
        self.age = age
        self.height = height

p = Person(25, 180)
p.age = 200  # Raises ValueError!`}
              />
            </Grid>
          </Grid>

          {/* Testing */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 4, color: '#3776ab' }}>
            Testing Best Practices
          </Typography>

          <Grid container spacing={3}>
            <Grid item xs={12}>
              <CodeBlock
                title="pytest Testing"
                code={`# test_math_utils.py
import pytest
from math_utils import add, divide, Calculator

# Simple test function
def test_add():
    assert add(2, 3) == 5
    assert add(-1, 1) == 0

# Test exceptions
def test_divide_by_zero():
    with pytest.raises(ZeroDivisionError):
        divide(10, 0)

# Parametrized tests
@pytest.mark.parametrize("a,b,expected", [
    (2, 3, 5),
    (-1, 1, 0),
    (0, 0, 0),
])
def test_add_parametrized(a, b, expected):
    assert add(a, b) == expected

# Fixtures for setup/teardown
@pytest.fixture
def calculator():
    calc = Calculator()
    yield calc
    calc.cleanup()  # Teardown

def test_calculator_add(calculator):
    assert calculator.add(2, 3) == 5

# Mock external dependencies
from unittest.mock import patch, MagicMock

def test_api_call():
    with patch('mymodule.requests.get') as mock_get:
        mock_get.return_value.json.return_value = {"data": "test"}
        result = fetch_data()
        assert result == {"data": "test"}

# Run: pytest test_math_utils.py -v`}
              />
            </Grid>
          </Grid>

          <Box sx={{ mt: 3 }}>
            <Accordion sx={{ bgcolor: alpha('#3776ab', 0.03) }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography fontWeight={600}>🎯 Python Mastery Roadmap</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ p: 2, bgcolor: alpha('#4caf50', 0.1), borderRadius: 2 }}>
                      <Typography fontWeight={700} color="#2e7d32" gutterBottom>Beginner</Typography>
                      <Box component="ul" sx={{ pl: 2, m: 0 }}>
                        <li>Variables & Data Types</li>
                        <li>Control Flow (if/for/while)</li>
                        <li>Functions</li>
                        <li>Lists, Dicts, Sets</li>
                        <li>File I/O</li>
                        <li>Error Handling</li>
                      </Box>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ p: 2, bgcolor: alpha('#ff9800', 0.1), borderRadius: 2 }}>
                      <Typography fontWeight={700} color="#e65100" gutterBottom>Intermediate</Typography>
                      <Box component="ul" sx={{ pl: 2, m: 0 }}>
                        <li>OOP & Classes</li>
                        <li>Modules & Packages</li>
                        <li>Decorators</li>
                        <li>Context Managers</li>
                        <li>Regular Expressions</li>
                        <li>Unit Testing</li>
                      </Box>
                    </Box>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Box sx={{ p: 2, bgcolor: alpha('#f44336', 0.1), borderRadius: 2 }}>
                      <Typography fontWeight={700} color="#c62828" gutterBottom>Advanced</Typography>
                      <Box component="ul" sx={{ pl: 2, m: 0 }}>
                        <li>Generators & Iterators</li>
                        <li>Async/Await</li>
                        <li>Type Hints</li>
                        <li>Metaclasses</li>
                        <li>Descriptors</li>
                        <li>C Extensions</li>
                      </Box>
                    </Box>
                  </Grid>
                </Grid>
              </AccordionDetails>
            </Accordion>
          </Box>

          <Box sx={{ mt: 3 }}>
            <ProTip>
              You don't need to master everything at once! Focus on writing clean, readable code first.
              Advanced features like metaclasses are rarely needed - learn them when you encounter a real use case.
            </ProTip>
          </Box>
        </Paper>

        {/* ==================== QUIZ SECTION ==================== */}
        <Paper id="quiz-section" sx={{ p: 4, mb: 5, borderRadius: 4 }}>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <QuizIcon sx={{ color: "#3776ab" }} />
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
              bgcolor: "#3776ab",
              "&:hover": { bgcolor: "#2f5f88" },
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
