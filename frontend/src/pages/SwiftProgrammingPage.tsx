import React, { useState, useMemo } from "react";
import { Link, useNavigate } from "react-router-dom";
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
  Radio,
  RadioGroup,
  FormControlLabel,
  FormControl,
  Button,
  LinearProgress,
} from "@mui/material";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import CodeIcon from "@mui/icons-material/Code";
import StorageIcon from "@mui/icons-material/Storage";
import BuildIcon from "@mui/icons-material/Build";
import SecurityIcon from "@mui/icons-material/Security";
import DeveloperBoardIcon from "@mui/icons-material/DeveloperBoard";
import BugReportIcon from "@mui/icons-material/BugReport";
import SchoolIcon from "@mui/icons-material/School";
import HistoryIcon from "@mui/icons-material/History";
import ExtensionIcon from "@mui/icons-material/Extension";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import LayersIcon from "@mui/icons-material/Layers";
import ViewModuleIcon from "@mui/icons-material/ViewModule";
import AutoFixHighIcon from "@mui/icons-material/AutoFixHigh";
import SyncIcon from "@mui/icons-material/Sync";
import DataObjectIcon from "@mui/icons-material/DataObject";
import SwapHorizIcon from "@mui/icons-material/SwapHoriz";
import CategoryIcon from "@mui/icons-material/Category";
import ClassIcon from "@mui/icons-material/Class";
import IntegrationInstructionsIcon from "@mui/icons-material/IntegrationInstructions";
import AppleIcon from "@mui/icons-material/Apple";
import PhoneIphoneIcon from "@mui/icons-material/PhoneIphone";
import SpeedIcon from "@mui/icons-material/Speed";
import DesktopMacIcon from "@mui/icons-material/DesktopMac";
import WatchIcon from "@mui/icons-material/Watch";
import LearnPageLayout from "../components/LearnPageLayout";

const accentColor = "#F05138"; // Swift's official orange
const accentColorDark = "#FF6D3A"; // Swift's lighter orange

// Quiz Question Bank - 75 questions covering Swift topics
interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
}

const swiftQuestionBank: QuizQuestion[] = [
  // Swift Basics (1-15)
  { id: 1, question: "What keyword declares a constant in Swift?", options: ["var", "let", "const", "final"], correctAnswer: 1, explanation: "In Swift, 'let' declares a constant (immutable value), while 'var' declares a variable (mutable value)." },
  { id: 2, question: "What year was Swift introduced by Apple?", options: ["2012", "2013", "2014", "2015"], correctAnswer: 2, explanation: "Swift was announced at Apple's WWDC on June 2, 2014." },
  { id: 3, question: "Which symbol is used for string interpolation in Swift?", options: ["${}", "#{}", "\\()", "%s"], correctAnswer: 2, explanation: "Swift uses \\(expression) for string interpolation, e.g., \"Hello, \\(name)!\"" },
  { id: 4, question: "What is the default integer type in Swift?", options: ["Int32", "Int64", "Int", "Integer"], correctAnswer: 2, explanation: "Int is the default integer type in Swift and is platform-native (64-bit on modern platforms)." },
  { id: 5, question: "How do you create a multi-line string in Swift?", options: ["Using \\n", "Using triple double quotes \"\"\"", "Using backticks", "Using single quotes"], correctAnswer: 1, explanation: "Multi-line strings in Swift are created with triple double quotes (\"\"\"...\"\"\")" },
  { id: 6, question: "What memory management system does Swift use?", options: ["Garbage Collection", "Manual Memory Management", "Automatic Reference Counting (ARC)", "Stack-only allocation"], correctAnswer: 2, explanation: "Swift uses Automatic Reference Counting (ARC) to manage memory automatically at compile time." },
  { id: 7, question: "Which framework is Swift's declarative UI toolkit?", options: ["UIKit", "AppKit", "SwiftUI", "Cocoa"], correctAnswer: 2, explanation: "SwiftUI is Swift's declarative UI framework, introduced in 2019, for building UIs across all Apple platforms." },
  { id: 8, question: "What does the 'typealias' keyword do?", options: ["Creates a new type", "Creates an alias for an existing type", "Defines a protocol", "Declares a generic"], correctAnswer: 1, explanation: "typealias creates an alternative name for an existing type, making code more readable." },
  { id: 9, question: "Which compiler backend does Swift use?", options: ["GCC", "LLVM", "JVM", "CLR"], correctAnswer: 1, explanation: "Swift uses LLVM as its compiler backend, which produces highly optimized native code." },
  { id: 10, question: "What is the file extension for Swift source files?", options: [".sw", ".swt", ".swift", ".sf"], correctAnswer: 2, explanation: "Swift source files use the .swift file extension." },
  { id: 11, question: "How do you write a single-line comment in Swift?", options: ["# comment", "// comment", "/* comment */", "-- comment"], correctAnswer: 1, explanation: "Single-line comments in Swift use //, same as C-family languages." },
  { id: 12, question: "What is the Boolean type called in Swift?", options: ["boolean", "Boolean", "Bool", "bool"], correctAnswer: 2, explanation: "The Boolean type in Swift is 'Bool' with values 'true' and 'false'." },
  { id: 13, question: "Which operator checks for equality in Swift?", options: ["=", "==", "===", "eq"], correctAnswer: 1, explanation: "The == operator checks for value equality in Swift." },
  { id: 14, question: "What does ABI stability mean for Swift?", options: ["Apps can be smaller", "Binary interface is locked", "Runtime can be shared", "All of the above"], correctAnswer: 3, explanation: "ABI stability means the binary interface is locked, allowing apps to be smaller and share the Swift runtime in the OS." },
  { id: 15, question: "Who created Swift?", options: ["Bjarne Stroustrup", "Chris Lattner", "James Gosling", "Guido van Rossum"], correctAnswer: 1, explanation: "Chris Lattner began developing Swift at Apple in 2010. He's also the creator of LLVM." },

  // Optionals (16-30)
  { id: 16, question: "What symbol makes a type optional in Swift?", options: ["!", "*", "?", "&"], correctAnswer: 2, explanation: "Adding ? after a type makes it optional, e.g., String? can hold a String or nil." },
  { id: 17, question: "What is the nil coalescing operator?", options: ["?:", "??", "?.", "||"], correctAnswer: 1, explanation: "The ?? operator provides a default value when an optional is nil: optionalValue ?? defaultValue" },
  { id: 18, question: "What does 'if let' do?", options: ["Creates a constant", "Unwraps an optional safely", "Forces unwrapping", "Creates a variable"], correctAnswer: 1, explanation: "'if let' safely unwraps an optional, binding the value to a constant if not nil." },
  { id: 19, question: "What does the '!' operator do with optionals?", options: ["Checks for nil", "Force unwraps the optional", "Makes a type optional", "Negates the value"], correctAnswer: 1, explanation: "The ! force unwraps an optional, causing a crash if the value is nil." },
  { id: 20, question: "What is 'guard let' used for?", options: ["Loop control", "Early exit if nil", "Error handling", "Type casting"], correctAnswer: 1, explanation: "'guard let' unwraps an optional and requires an early exit (return, break, etc.) if nil." },
  { id: 21, question: "What is optional chaining?", options: ["Linking multiple optionals", "Safe property/method access on optionals", "Converting types", "Creating optional arrays"], correctAnswer: 1, explanation: "Optional chaining (?.) allows safe access to properties/methods on optionals, returning nil if any part is nil." },
  { id: 22, question: "What does 'String?' mean?", options: ["Required String", "String reference", "Optional String (can be nil)", "String array"], correctAnswer: 2, explanation: "String? is an optional String that can hold either a String value or nil." },
  { id: 23, question: "How do you safely unwrap multiple optionals at once?", options: ["Multiple if statements", "Comma-separated if let", "Using && operator", "Using switch"], correctAnswer: 1, explanation: "You can unwrap multiple optionals with comma-separated bindings: if let a = optA, let b = optB { }" },
  { id: 24, question: "What are implicitly unwrapped optionals?", options: ["Regular optionals", "Optionals that auto-unwrap when accessed", "Non-optional values", "Forced optionals"], correctAnswer: 1, explanation: "Implicitly unwrapped optionals (String!) automatically unwrap when accessed but can still be nil." },
  { id: 25, question: "What happens if you force unwrap a nil optional?", options: ["Returns nil", "Returns empty value", "Runtime crash", "Compilation error"], correctAnswer: 2, explanation: "Force unwrapping a nil optional causes a fatal runtime error (crash)." },
  { id: 26, question: "What protocol do optionals conform to for comparison?", options: ["Comparable", "Equatable", "Hashable", "Both Equatable and Hashable"], correctAnswer: 3, explanation: "Optionals conform to both Equatable and Hashable when their wrapped type does." },
  { id: 27, question: "How do you use 'try?' with a throwing function?", options: ["It throws the error", "It returns an optional result", "It crashes on error", "It requires catch"], correctAnswer: 1, explanation: "'try?' converts the result to an optional, returning nil if an error is thrown." },
  { id: 28, question: "What is the map() method on optionals?", options: ["Iterates over optional", "Transforms value if present, otherwise nil", "Converts to array", "Forces unwrap"], correctAnswer: 1, explanation: "Optional's map() transforms the wrapped value if present, returning nil otherwise." },
  { id: 29, question: "What does flatMap do on optionals?", options: ["Flattens nested optionals", "Creates arrays", "Converts to string", "Unwraps forcefully"], correctAnswer: 0, explanation: "flatMap on optionals transforms and flattens nested optionals (Optional<Optional<T>> to Optional<T>)." },
  { id: 30, question: "When should you use implicitly unwrapped optionals?", options: ["Always", "When value is set after init but before use", "Never", "For all properties"], correctAnswer: 1, explanation: "Use implicitly unwrapped optionals when a value is guaranteed after initialization but before first use." },

  // Functions & Closures (31-45)
  { id: 31, question: "What keyword declares a function in Swift?", options: ["function", "def", "func", "fn"], correctAnswer: 2, explanation: "Functions in Swift are declared using the 'func' keyword." },
  { id: 32, question: "How do you specify a return type in Swift functions?", options: ["function(): Type", "func name() -> Type", "func name(): Type", "Type func name()"], correctAnswer: 1, explanation: "Return types are specified with an arrow: func name() -> ReturnType" },
  { id: 33, question: "What is an argument label in Swift?", options: ["Parameter type", "External name for parameter", "Return type", "Function name"], correctAnswer: 1, explanation: "Argument labels are external names used when calling the function, separate from parameter names." },
  { id: 34, question: "How do you omit an argument label?", options: ["Using 'none'", "Using '_'", "Using 'skip'", "Using empty string"], correctAnswer: 1, explanation: "Use underscore _ before the parameter name to omit the argument label: func greet(_ name: String)" },
  { id: 35, question: "What is a trailing closure?", options: ["A closure that comes last", "Closure written after function parentheses", "A closure that returns", "An async closure"], correctAnswer: 1, explanation: "When a closure is the last argument, it can be written outside the parentheses as a trailing closure." },
  { id: 36, question: "What does @escaping mean for closures?", options: ["Closure runs immediately", "Closure can outlive function call", "Closure is optional", "Closure is async"], correctAnswer: 1, explanation: "@escaping indicates the closure may be stored and called after the function returns." },
  { id: 37, question: "What is the shorthand syntax for closure parameters?", options: ["$0, $1, $2...", "#0, #1, #2...", "@0, @1, @2...", "arg0, arg1..."], correctAnswer: 0, explanation: "Swift provides shorthand argument names: $0 for first argument, $1 for second, etc." },
  { id: 38, question: "What is a higher-order function?", options: ["A main function", "A function that takes/returns functions", "A recursive function", "A class method"], correctAnswer: 1, explanation: "Higher-order functions take functions as parameters or return functions (e.g., map, filter, reduce)." },
  { id: 39, question: "What does 'inout' do for parameters?", options: ["Makes parameter optional", "Allows modification of original value", "Makes parameter constant", "Creates a copy"], correctAnswer: 1, explanation: "'inout' allows a function to modify the original value passed to it." },
  { id: 40, question: "How do you mark a parameter as variadic?", options: ["...", "[]", "*", "...args"], correctAnswer: 0, explanation: "Variadic parameters use ... after the type: func sum(_ numbers: Int...)" },
  { id: 41, question: "What is a closure in Swift?", options: ["A class type", "A self-contained block of functionality", "A protocol", "A property wrapper"], correctAnswer: 1, explanation: "Closures are self-contained blocks of functionality that can be passed around and used in code." },
  { id: 42, question: "What does 'autoclosure' do?", options: ["Auto-runs closure", "Wraps expression in closure automatically", "Makes closure optional", "Optimizes closure"], correctAnswer: 1, explanation: "@autoclosure automatically wraps an expression in a closure, useful for lazy evaluation." },
  { id: 43, question: "How do you define a function type?", options: ["Function<Args, Return>", "(Args) -> Return", "func(Args): Return", "[Args] => Return"], correctAnswer: 1, explanation: "Function types are written as (ParameterTypes) -> ReturnType, e.g., (Int, Int) -> Int" },
  { id: 44, question: "What is closure capturing?", options: ["Taking a screenshot", "Storing references to values from surrounding context", "Copying closure", "Converting closure"], correctAnswer: 1, explanation: "Closures capture and store references to variables and constants from their surrounding context." },
  { id: 45, question: "What does [weak self] do in a closure?", options: ["Makes self strong", "Captures self weakly to avoid retain cycles", "Removes self", "Makes closure weak"], correctAnswer: 1, explanation: "[weak self] creates a weak reference to self, preventing retain cycles in closures." },

  // Collections (46-55)
  { id: 46, question: "How do you create an empty array of Integers?", options: ["var arr = Int[]", "var arr: [Int] = []", "var arr = new Array<Int>", "var arr = Array{}"], correctAnswer: 1, explanation: "Empty arrays are created with: var arr: [Int] = [] or [Int]()" },
  { id: 47, question: "What method adds an element to the end of an array?", options: ["add()", "push()", "append()", "insert()"], correctAnswer: 2, explanation: "The append() method adds an element to the end of an array." },
  { id: 48, question: "How do you create a dictionary in Swift?", options: ["Dict<K, V>", "[Key: Value]", "Dictionary{}", "Map<K, V>"], correctAnswer: 1, explanation: "Dictionaries use square brackets with key-value types: [String: Int] or [Key: Value]" },
  { id: 49, question: "What does the filter() method return?", options: ["A boolean", "A new array with matching elements", "The first match", "Count of matches"], correctAnswer: 1, explanation: "filter() returns a new array containing only elements that satisfy the given predicate." },
  { id: 50, question: "How do you get the number of elements in an array?", options: [".length", ".size", ".count", ".length()"], correctAnswer: 2, explanation: "The count property returns the number of elements in a collection." },
  { id: 51, question: "What is a Set in Swift?", options: ["Ordered collection", "Unordered collection of unique values", "Key-value pairs", "Linked list"], correctAnswer: 1, explanation: "Set is an unordered collection of unique values of the same type." },
  { id: 52, question: "What does map() do on a collection?", options: ["Finds elements", "Transforms each element", "Filters elements", "Sorts elements"], correctAnswer: 1, explanation: "map() transforms each element using a closure and returns a new array of transformed values." },
  { id: 53, question: "What does reduce() do?", options: ["Removes elements", "Combines elements into a single value", "Sorts elements", "Filters elements"], correctAnswer: 1, explanation: "reduce() combines all elements into a single value using a combining closure." },
  { id: 54, question: "How do you iterate over dictionary key-value pairs?", options: ["for item in dict", "for (key, value) in dict", "for key: value in dict", "dict.forEach"], correctAnswer: 1, explanation: "Use tuple decomposition: for (key, value) in dictionary { }" },
  { id: 55, question: "What does compactMap() do?", options: ["Compresses array", "Transforms and removes nil values", "Sorts compactly", "Merges arrays"], correctAnswer: 1, explanation: "compactMap() transforms elements and automatically filters out nil results." },

  // Structs, Classes & Enums (56-65)
  { id: 56, question: "What type are structs in Swift?", options: ["Reference types", "Value types", "Pointer types", "Abstract types"], correctAnswer: 1, explanation: "Structs are value types - they are copied when assigned or passed to functions." },
  { id: 57, question: "What type are classes in Swift?", options: ["Value types", "Reference types", "Primitive types", "Static types"], correctAnswer: 1, explanation: "Classes are reference types - multiple variables can reference the same instance." },
  { id: 58, question: "What keyword creates an enumeration?", options: ["enumeration", "enumerate", "enum", "Enum"], correctAnswer: 2, explanation: "Enumerations are declared with the 'enum' keyword." },
  { id: 59, question: "What are associated values in enums?", options: ["Raw values", "Values attached to enum cases", "Default values", "Computed values"], correctAnswer: 1, explanation: "Associated values let enum cases store additional data of varying types." },
  { id: 60, question: "What is a computed property?", options: ["Stored property", "Property calculated each time accessed", "Static property", "Lazy property"], correctAnswer: 1, explanation: "Computed properties calculate a value each time they're accessed using a getter." },
  { id: 61, question: "What does 'mutating' keyword do in structs?", options: ["Makes struct immutable", "Allows method to modify properties", "Creates a new instance", "Makes property optional"], correctAnswer: 1, explanation: "mutating allows a method to modify the struct's properties (since structs are value types)." },
  { id: 62, question: "What is a property observer?", options: ["Debugger tool", "Code that runs when property changes", "Property type", "Property modifier"], correctAnswer: 1, explanation: "Property observers (willSet/didSet) run code before/after a property's value changes." },
  { id: 63, question: "How do you create a class initializer?", options: ["constructor()", "init()", "new()", "create()"], correctAnswer: 1, explanation: "Initializers in Swift use the 'init' keyword: init() { }" },
  { id: 64, question: "What is inheritance in Swift?", options: ["Struct feature", "Class acquiring properties/methods of another class", "Protocol conformance", "Extension"], correctAnswer: 1, explanation: "Inheritance allows a class to inherit properties, methods, and other characteristics from another class." },
  { id: 65, question: "Can structs inherit from other structs?", options: ["Yes", "No", "Only with protocols", "Only with extensions"], correctAnswer: 1, explanation: "Structs cannot inherit from other structs. Only classes support inheritance." },

  // Protocols & Error Handling (66-75)
  { id: 66, question: "What keyword declares a protocol?", options: ["interface", "protocol", "trait", "abstract"], correctAnswer: 1, explanation: "Protocols are declared with the 'protocol' keyword in Swift." },
  { id: 67, question: "What is protocol conformance?", options: ["Creating a protocol", "Type implementing protocol requirements", "Extending a protocol", "Protocol inheritance"], correctAnswer: 1, explanation: "Protocol conformance means a type implements all requirements defined by a protocol." },
  { id: 68, question: "How do you throw an error in Swift?", options: ["raise error", "throw error", "error()", "raise(error)"], correctAnswer: 1, explanation: "Use the 'throw' keyword to throw an error: throw MyError.someError" },
  { id: 69, question: "What keyword marks a function that can throw?", options: ["throwing", "throws", "throwable", "error"], correctAnswer: 1, explanation: "Add 'throws' after parameters: func doSomething() throws -> String" },
  { id: 70, question: "How do you handle thrown errors?", options: ["try-catch", "do-catch", "try-except", "handle-error"], correctAnswer: 1, explanation: "Swift uses do-catch blocks to handle errors from throwing functions." },
  { id: 71, question: "What is the Codable protocol used for?", options: ["Code generation", "Encoding/decoding to JSON, etc.", "Comparing values", "Hashing"], correctAnswer: 1, explanation: "Codable (Encodable & Decodable) enables easy encoding/decoding to formats like JSON." },
  { id: 72, question: "What does the Equatable protocol enable?", options: ["Encoding", "Equality comparison with ==", "Sorting", "Hashing"], correctAnswer: 1, explanation: "Equatable enables equality comparison using the == operator." },
  { id: 73, question: "What is a protocol extension?", options: ["New protocol", "Adding default implementations to protocols", "Removing requirements", "Protocol inheritance"], correctAnswer: 1, explanation: "Protocol extensions provide default implementations for protocol methods." },
  { id: 74, question: "What does 'try!' do?", options: ["Always succeeds", "Force tries and crashes on error", "Returns optional", "Ignores errors"], correctAnswer: 1, explanation: "'try!' asserts that no error will occur - crashes if an error is thrown." },
  { id: 75, question: "What is the Result type used for?", options: ["Only for HTTP requests", "Representing success or failure", "Async operations only", "Database results"], correctAnswer: 1, explanation: "Result<Success, Failure> encapsulates either a success value or an error." },
];

// Shuffle function for randomizing questions
function shuffleArray<T>(array: T[]): T[] {
  const shuffled = [...array];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

// Quiz Component
function SwiftQuiz() {
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<{ [key: number]: number }>({});
  const [showResults, setShowResults] = useState(false);
  const [quizKey, setQuizKey] = useState(0);

  // Randomly select 10 questions from the bank
  const quizQuestions = useMemo(() => {
    return shuffleArray(swiftQuestionBank).slice(0, 10);
  }, [quizKey]);

  const handleAnswerSelect = (questionIndex: number, answerIndex: number) => {
    setSelectedAnswers({ ...selectedAnswers, [questionIndex]: answerIndex });
  };

  const handleNext = () => {
    if (currentQuestion < quizQuestions.length - 1) {
      setCurrentQuestion(currentQuestion + 1);
    }
  };

  const handlePrevious = () => {
    if (currentQuestion > 0) {
      setCurrentQuestion(currentQuestion - 1);
    }
  };

  const handleSubmit = () => {
    setShowResults(true);
  };

  const handleRetry = () => {
    setCurrentQuestion(0);
    setSelectedAnswers({});
    setShowResults(false);
    setQuizKey((prev) => prev + 1);
  };

  const calculateScore = () => {
    let correct = 0;
    quizQuestions.forEach((q, index) => {
      if (selectedAnswers[index] === q.correctAnswer) {
        correct++;
      }
    });
    return correct;
  };

  const score = calculateScore();
  const percentage = (score / quizQuestions.length) * 100;

  if (showResults) {
    return (
      <Paper sx={{ p: 4, borderRadius: 4 }}>
        <Box sx={{ textAlign: "center", mb: 4 }}>
          <Avatar sx={{ width: 80, height: 80, bgcolor: percentage >= 70 ? "#48BB78" : "#F56565", mx: "auto", mb: 2 }}>
            <EmojiEventsIcon sx={{ fontSize: 40 }} />
          </Avatar>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            {percentage >= 70 ? "Excellent!" : percentage >= 50 ? "Good Effort!" : "Keep Learning!"}
          </Typography>
          <Typography variant="h5" sx={{ color: percentage >= 70 ? "#48BB78" : "#F56565", fontWeight: 700 }}>
            {score} / {quizQuestions.length} ({percentage}%)
          </Typography>
        </Box>

        <LinearProgress
          variant="determinate"
          value={percentage}
          sx={{
            height: 12,
            borderRadius: 6,
            mb: 4,
            bgcolor: alpha(accentColor, 0.1),
            "& .MuiLinearProgress-bar": {
              bgcolor: percentage >= 70 ? "#48BB78" : percentage >= 50 ? "#ECC94B" : "#F56565",
              borderRadius: 6,
            },
          }}
        />

        <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
          Review Your Answers
        </Typography>

        {quizQuestions.map((q, index) => {
          const isCorrect = selectedAnswers[index] === q.correctAnswer;
          return (
            <Paper
              key={q.id}
              sx={{
                p: 3,
                mb: 2,
                borderRadius: 2,
                border: `2px solid ${isCorrect ? "#48BB78" : "#F56565"}`,
                bgcolor: alpha(isCorrect ? "#48BB78" : "#F56565", 0.05),
              }}
            >
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
                {index + 1}. {q.question}
              </Typography>
              <Typography variant="body2" sx={{ mb: 1 }}>
                Your answer: <strong>{q.options[selectedAnswers[index]] || "Not answered"}</strong>
              </Typography>
              {!isCorrect && (
                <Typography variant="body2" sx={{ color: "#48BB78", mb: 1 }}>
                  Correct answer: <strong>{q.options[q.correctAnswer]}</strong>
                </Typography>
              )}
              <Typography variant="body2" color="text.secondary" sx={{ fontStyle: "italic" }}>
                {q.explanation}
              </Typography>
            </Paper>
          );
        })}

        <Box sx={{ textAlign: "center", mt: 4 }}>
          <Button
            variant="contained"
            startIcon={<RefreshIcon />}
            onClick={handleRetry}
            sx={{
              bgcolor: accentColor,
              px: 4,
              py: 1.5,
              fontWeight: 700,
              "&:hover": { bgcolor: accentColorDark },
            }}
          >
            Try Another Quiz
          </Button>
        </Box>
      </Paper>
    );
  }

  const currentQ = quizQuestions[currentQuestion];
  const progress = ((currentQuestion + 1) / quizQuestions.length) * 100;

  return (
    <Paper sx={{ p: 4, borderRadius: 4 }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Typography variant="subtitle2" color="text.secondary">
          Question {currentQuestion + 1} of {quizQuestions.length}
        </Typography>
        <Chip label={`${Math.round(progress)}% Complete`} size="small" sx={{ bgcolor: alpha(accentColor, 0.15) }} />
      </Box>

      <LinearProgress
        variant="determinate"
        value={progress}
        sx={{
          height: 8,
          borderRadius: 4,
          mb: 4,
          bgcolor: alpha(accentColor, 0.1),
          "& .MuiLinearProgress-bar": { bgcolor: accentColor, borderRadius: 4 },
        }}
      />

      <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
        {currentQ.question}
      </Typography>

      <FormControl component="fieldset" sx={{ width: "100%", mb: 4 }}>
        <RadioGroup
          value={selectedAnswers[currentQuestion] ?? ""}
          onChange={(e) => handleAnswerSelect(currentQuestion, parseInt(e.target.value))}
        >
          {currentQ.options.map((option, index) => (
            <Paper
              key={index}
              sx={{
                mb: 1.5,
                p: 2,
                borderRadius: 2,
                border: `2px solid ${selectedAnswers[currentQuestion] === index ? accentColor : "transparent"}`,
                bgcolor: selectedAnswers[currentQuestion] === index ? alpha(accentColor, 0.08) : alpha("#000", 0.02),
                cursor: "pointer",
                transition: "all 0.2s",
                "&:hover": { bgcolor: alpha(accentColor, 0.05), borderColor: alpha(accentColor, 0.3) },
              }}
              onClick={() => handleAnswerSelect(currentQuestion, index)}
            >
              <FormControlLabel
                value={index}
                control={<Radio sx={{ color: accentColor, "&.Mui-checked": { color: accentColor } }} />}
                label={option}
                sx={{ m: 0, width: "100%" }}
              />
            </Paper>
          ))}
        </RadioGroup>
      </FormControl>

      <Box sx={{ display: "flex", justifyContent: "space-between" }}>
        <Button variant="outlined" onClick={handlePrevious} disabled={currentQuestion === 0} sx={{ borderColor: accentColor, color: accentColor }}>
          Previous
        </Button>
        {currentQuestion === quizQuestions.length - 1 ? (
          <Button
            variant="contained"
            onClick={handleSubmit}
            disabled={Object.keys(selectedAnswers).length < quizQuestions.length}
            sx={{ bgcolor: accentColor, "&:hover": { bgcolor: accentColorDark } }}
          >
            Submit Quiz
          </Button>
        ) : (
          <Button variant="contained" onClick={handleNext} sx={{ bgcolor: accentColor, "&:hover": { bgcolor: accentColorDark } }}>
            Next
          </Button>
        )}
      </Box>
    </Paper>
  );
}

// Module navigation items for sidebar
const moduleNavItems = [
  { id: "introduction", label: "Introduction", icon: <SchoolIcon /> },
  { id: "history", label: "History & Evolution", icon: <HistoryIcon /> },
  { id: "setup", label: "Environment Setup", icon: <BuildIcon /> },
  { id: "basics", label: "Swift Basics & Syntax", icon: <CodeIcon /> },
  { id: "variables", label: "Variables & Constants", icon: <DataObjectIcon /> },
  { id: "operators", label: "Operators & Expressions", icon: <SwapHorizIcon /> },
  { id: "control-flow", label: "Control Flow", icon: <AccountTreeIcon /> },
  { id: "functions", label: "Functions & Closures", icon: <ExtensionIcon /> },
  { id: "optionals", label: "Optionals", icon: <SecurityIcon /> },
  { id: "collections", label: "Collections", icon: <StorageIcon /> },
  { id: "structs", label: "Structs & Classes", icon: <ClassIcon /> },
  { id: "enums", label: "Enumerations", icon: <ViewModuleIcon /> },
  { id: "protocols", label: "Protocols", icon: <LayersIcon /> },
  { id: "error-handling", label: "Error Handling", icon: <BugReportIcon /> },
  { id: "generics", label: "Generics", icon: <AutoFixHighIcon /> },
  { id: "concurrency", label: "Concurrency", icon: <SyncIcon /> },
  { id: "swiftui", label: "SwiftUI", icon: <PhoneIphoneIcon /> },
  { id: "advanced", label: "Advanced Topics", icon: <DeveloperBoardIcon /> },
  { id: "quiz", label: "Knowledge Quiz", icon: <QuizIcon /> },
];

// Quick stats for hero section
const quickStats = [
  { label: "Created", value: "2014", color: "#F05138" },
  { label: "Creator", value: "Apple", color: "#555555" },
  { label: "Paradigm", value: "Multi", color: "#4A90D9" },
  { label: "Latest Ver", value: "5.10", color: "#48BB78" },
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

export default function SwiftProgrammingPage() {
  const navigate = useNavigate();

  return (
    <LearnPageLayout pageTitle="Swift Programming" pageContext="Comprehensive Swift programming course covering iOS/macOS development, SwiftUI, optionals, protocols, and modern Swift concurrency.">
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
                {/* Swift bird icon approximation */}
                <span role="img" aria-label="swift">🐦</span>
              </Avatar>
              <Box>
                <Typography variant="h4" sx={{ fontWeight: 900 }}>
                  Swift Programming
                </Typography>
                <Typography variant="body1" color="text.secondary">
                  Safe, Fast, Expressive — The Language of Apple Platforms
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
              {["iOS", "macOS", "SwiftUI", "Type Safe", "Optionals", "Protocols", "Concurrency", "Open Source"].map((tag) => (
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
              What is Swift?
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Swift is a powerful, intuitive programming language developed by <strong>Apple</strong> for
              building applications across all Apple platforms—iOS, macOS, watchOS, tvOS, and visionOS.
              Unveiled at WWDC 2014 and open-sourced in 2015, Swift was designed as a modern replacement
              for Objective-C, Apple's previous primary language. Swift combines the performance of compiled
              languages like C and C++ with the expressiveness and safety features of modern languages like
              Python and Ruby, creating a language that is both powerful for experts and accessible to beginners.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Swift's design philosophy centers on <strong>safety, speed, and expressiveness</strong>. The
              language eliminates entire categories of bugs through features like optionals (which prevent
              null pointer exceptions), strong typing with type inference, automatic memory management (ARC),
              and bounds checking for arrays. Yet despite this safety focus, Swift compiles to highly optimized
              native code that often outperforms Objective-C. The syntax is clean and modern, with features
              like trailing closures, type inference, and powerful pattern matching that make code readable
              and concise.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              With the introduction of <strong>SwiftUI</strong> in 2019, Swift became even more powerful
              for UI development. SwiftUI provides a declarative syntax for building user interfaces that
              automatically updates when data changes. Combined with Swift's modern concurrency system
              (async/await and actors, introduced in Swift 5.5), Swift is now a complete platform for
              building sophisticated, responsive applications. Whether you're building an iPhone app, a
              Mac application, a server-side service with Vapor, or even systems software, Swift has
              you covered.
            </Typography>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Why Learn Swift in 2024?
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              If you want to develop apps for any Apple platform, Swift is essential. It's not just the
              recommended language—it's the future of Apple development. New frameworks and APIs are
              Swift-first, and SwiftUI is exclusively available in Swift. Beyond Apple platforms, Swift
              is growing in server-side development and even embedded systems. Here's why Swift is worth
              your time:
            </Typography>

            <Grid container spacing={3} sx={{ mb: 4 }}>
              {[
                {
                  title: "Apple Ecosystem",
                  description: "Swift is the key to the entire Apple ecosystem. Build apps for 2 billion active Apple devices—iPhone, iPad, Mac, Apple Watch, Apple TV, and Vision Pro. The App Store remains one of the most lucrative markets for developers.",
                  icon: <AppleIcon />,
                },
                {
                  title: "SwiftUI Revolution",
                  description: "SwiftUI has transformed Apple development. Write once, run everywhere on Apple platforms with native performance. Live previews, declarative syntax, and automatic accessibility make building beautiful UIs faster than ever.",
                  icon: <PhoneIphoneIcon />,
                },
                {
                  title: "Safety & Performance",
                  description: "Swift's optionals eliminate null pointer crashes. Strong typing catches bugs at compile time. Yet Swift matches or exceeds C++ in benchmarks. You get safety without sacrificing speed—no other language offers this combination.",
                  icon: <SpeedIcon />,
                },
                {
                  title: "Modern Concurrency",
                  description: "Swift 5.5+ introduced async/await, actors, and structured concurrency. Write asynchronous code that's easy to read and reason about. Data races are caught at compile time with actors. Modern concurrency made simple.",
                  icon: <SyncIcon />,
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
              How Swift Works: Compilation and Runtime
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Swift is a compiled language that uses LLVM (Low Level Virtual Machine) as its compiler
              backend. When you build a Swift application, the Swift compiler (swiftc) transforms your
              source code into highly optimized machine code specific to the target platform. This means
              Swift apps run directly on the hardware without an interpreter or virtual machine, providing
              excellent performance.
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// The Swift compilation process:</span>{"\n"}
                {"\n"}
                <span style={{ color: "#50fa7b" }}>main.swift</span>  <span style={{ color: "#6272a4" }}>// Your Swift source code</span>{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#8be9fd" }}>Swift Frontend</span>  <span style={{ color: "#6272a4" }}>// Parsing, type checking, AST</span>{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#ff79c6" }}>SIL (Swift IL)</span>  <span style={{ color: "#6272a4" }}>// Swift Intermediate Language</span>{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#8be9fd" }}>SIL Optimizer</span>  <span style={{ color: "#6272a4" }}>// Swift-specific optimizations</span>{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#50fa7b" }}>LLVM IR</span>  <span style={{ color: "#6272a4" }}>// LLVM Intermediate Representation</span>{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#8be9fd" }}>LLVM Backend</span>  <span style={{ color: "#6272a4" }}>// Platform-specific codegen</span>{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#f1fa8c" }}>Native Binary</span>  <span style={{ color: "#6272a4" }}>// ARM64 for iOS, x86_64/ARM64 for Mac</span>
              </Typography>
            </Paper>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Swift uses <strong>Automatic Reference Counting (ARC)</strong> for memory management. Unlike
              garbage collection, ARC tracks object references at compile time and inserts memory management
              code automatically. Objects are deallocated immediately when no references remain, providing
              deterministic memory management without the pauses associated with garbage collectors. You
              occasionally need to understand strong, weak, and unowned references to break reference cycles,
              but day-to-day memory management is automatic.
            </Typography>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Core Principles of Swift
            </Typography>

            <List sx={{ mb: 3 }}>
              {[
                {
                  title: "Type Safety",
                  desc: "Swift is a strongly-typed language that catches type errors at compile time. Every variable has a specific type, and the compiler ensures you use it correctly. Type inference reduces verbosity while maintaining safety—you get the benefits of static typing with less boilerplate.",
                },
                {
                  title: "Optionals",
                  desc: "Swift's optionals elegantly solve the billion-dollar mistake of null references. A variable that can be nil must be explicitly typed as optional (String?). The compiler forces you to handle the nil case, eliminating null pointer crashes at runtime.",
                },
                {
                  title: "Value Types",
                  desc: "Swift prefers value types (structs, enums) over reference types (classes). Structs are copied when assigned, eliminating shared mutable state bugs. Collections, strings, and most standard library types are structs. This makes Swift code easier to reason about.",
                },
                {
                  title: "Protocol-Oriented Programming",
                  desc: "Swift embraces protocols (interfaces) with extensions. Define behavior in protocols, provide default implementations via extensions, and compose functionality. This 'protocol-oriented programming' paradigm is more flexible than traditional class inheritance.",
                },
                {
                  title: "Modern Concurrency",
                  desc: "Swift's concurrency model with async/await and actors makes asynchronous code look synchronous. Actors protect mutable state from data races. Structured concurrency with task groups ensures proper cleanup. Concurrent code has never been this safe and readable.",
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

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColor, 0.08), border: `1px solid ${alpha(accentColor, 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                Getting Started Tip
              </Typography>
              <Typography variant="body2" color="text.secondary">
                You'll need a <strong>Mac</strong> to develop for Apple platforms. Download <strong>Xcode</strong>
                from the Mac App Store—it's free and includes Swift, SDKs, simulators, and everything you need.
                For learning Swift syntax, use <strong>Swift Playgrounds</strong> (available on Mac and iPad) for
                an interactive experience, or create a Playground in Xcode. Apple's official <strong>"The Swift
                Programming Language"</strong> book (free at swift.org) is the definitive reference.
              </Typography>
            </Paper>
          </Paper>

          {/* Your First Swift Program */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Your First Swift Program
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Swift makes it easy to get started. Here's "Hello, World!" in Swift—no class or boilerplate
              required:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// hello.swift - That's it!</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Hello, World!"</span>)
              </Typography>
            </Paper>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              One line. No main function needed for simple programs. Let's see a slightly more complete
              example showing Swift's key features:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// A more complete example</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>import</span> Foundation{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Constants (let) and variables (var)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> language = <span style={{ color: "#f1fa8c" }}>"Swift"</span>      <span style={{ color: "#6272a4" }}>// Type inferred as String</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> version: <span style={{ color: "#8be9fd" }}>Double</span> = <span style={{ color: "#bd93f9" }}>5.10</span>  <span style={{ color: "#6272a4" }}>// Explicit type</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// String interpolation</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Hello, </span>\(<span style={{ color: "#ff79c6" }}>language</span>) \(<span style={{ color: "#ff79c6" }}>version</span>)<span style={{ color: "#f1fa8c" }}>!"</span>){"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Function declaration</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>greet</span>(name: <span style={{ color: "#8be9fd" }}>String</span>) -{">"} <span style={{ color: "#8be9fd" }}>String</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#f1fa8c" }}>"Welcome, </span>\(<span style={{ color: "#ff79c6" }}>name</span>)<span style={{ color: "#f1fa8c" }}>!"</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Optional - can be nil</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> nickname: <span style={{ color: "#8be9fd" }}>String</span>? = <span style={{ color: "#ff79c6" }}>nil</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(nickname ?? <span style={{ color: "#f1fa8c" }}>"Anonymous"</span>)  <span style={{ color: "#6272a4" }}>// Nil coalescing</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Call the function</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> message = <span style={{ color: "#50fa7b" }}>greet</span>(name: <span style={{ color: "#f1fa8c" }}>"Developer"</span>){"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(message)
              </Typography>
            </Paper>

            <List>
              {[
                { code: "let / var", desc: "let declares a constant (immutable). var declares a variable (mutable). Swift encourages using let whenever possible for safer, more predictable code." },
                { code: "print(\"...\")", desc: "The print() function outputs to the console. No import needed for basic functionality—it's part of the Swift standard library." },
                { code: '"Hello, \\(variable)"', desc: "String interpolation uses \\(expression) syntax. You can embed any expression inside the parentheses. Much cleaner than concatenation." },
                { code: "func name(param: Type) -> ReturnType", desc: "Functions declare parameters as name: Type. The return type follows -> (arrow). Omit -> for Void functions." },
                { code: "String?", desc: "The ? makes a type optional—it can hold either a String or nil. This is Swift's solution to null pointer exceptions." },
                { code: "??", desc: "The nil coalescing operator provides a default value when an optional is nil. In 'a ?? b', if a is nil, the result is b." },
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
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <HistoryIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                History & Evolution
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Swift's origins trace back to 2010 when <strong>Chris Lattner</strong>, creator of the LLVM
              compiler infrastructure, began working on a new programming language at Apple. Lattner aimed
              to create a language that would be approachable for newcomers yet powerful enough for systems
              programming—combining the best of Objective-C, Rust, Haskell, Ruby, and Python into something
              uniquely suited for Apple's platforms.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Swift was announced at Apple's Worldwide Developers Conference (<strong>WWDC</strong>) on
              June 2, 2014, surprising the developer community. Apple had kept the project secret for
              four years. The announcement came with a 500+ page book, "The Swift Programming Language,"
              making it one of the most comprehensive language introductions ever. Just over a year later,
              at WWDC 2015, Apple open-sourced Swift along with its compiler, standard library, and core
              libraries, making it available for Linux and inviting community contributions.
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { year: "2010", event: "Development Begins", desc: "Chris Lattner starts Swift development at Apple" },
                { year: "2014", event: "WWDC Announcement", desc: "Swift 1.0 unveiled, 'The Swift Programming Language' published" },
                { year: "2015", event: "Open Source", desc: "Swift 2.0 released, open-sourced on swift.org, Linux support added" },
                { year: "2016", event: "Swift 3.0", desc: "Major API redesign, Swift Package Manager, naming guidelines" },
                { year: "2017", event: "Swift 4.0", desc: "Codable for JSON, String as Collection, ABI stability progress" },
                { year: "2019", event: "Swift 5.0 & SwiftUI", desc: "ABI stability achieved! SwiftUI declarative UI framework introduced" },
                { year: "2021", event: "Swift 5.5", desc: "async/await, actors, structured concurrency revolutionize async code" },
                { year: "2023", event: "Swift 5.9", desc: "Swift macros, parameter packs, value and type parameter packs" },
                { year: "2024", event: "Swift 6.0 Preview", desc: "Complete data-race safety by default, embedded Swift" },
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
              A major milestone came with <strong>Swift 5.0 in 2019</strong>, which achieved <strong>ABI
              stability</strong>. This meant Swift's binary interface was locked, and the Swift runtime could
              be included in operating systems rather than bundled with each app. Apps became smaller, and
              Swift became a true system programming language. The same WWDC introduced <strong>SwiftUI</strong>,
              Apple's declarative UI framework that would transform how developers build interfaces.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              <strong>Swift 5.5 (2021)</strong> brought another revolutionary change: modern concurrency with
              async/await and actors. These features, inspired by academic research and practical experience
              with other languages, made asynchronous programming in Swift dramatically simpler and safer.
              The upcoming <strong>Swift 6</strong> will enable complete data-race safety by default, making
              Swift one of the safest languages for concurrent programming.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColorDark, 0.08), border: `1px solid ${alpha(accentColorDark, 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                Swift's Growing Ecosystem
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Swift has expanded far beyond Apple platforms. <strong>Vapor</strong> and <strong>Hummingbird</strong>
                enable server-side Swift. <strong>Swift on Windows</strong> is officially supported. The Swift
                Server Work Group develops cross-platform libraries. There's even work on <strong>Embedded Swift</strong>
                for microcontrollers. The language that started for iOS apps is becoming a general-purpose systems
                programming language.
              </Typography>
            </Paper>
          </Paper>

          {/* Environment Setup Section */}
          <Paper id="setup" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColorDark, 0.15), color: accentColorDark, width: 48, height: 48 }}>
                <BuildIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Environment Setup
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              To develop for Apple platforms, you need a Mac and Xcode. For Swift experimentation,
              Swift Playgrounds provides an interactive environment. Let's walk through the setup options.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColorDark }}>
              Xcode (Primary Development Environment)
            </Typography>

            <Grid container spacing={2} sx={{ mb: 4 }}>
              {[
                {
                  name: "Xcode",
                  desc: "Apple's official IDE. Download free from the Mac App Store. Includes Swift compiler, iOS/macOS SDKs, Interface Builder, simulators for all Apple devices, debugging tools, and everything for App Store submission.",
                  color: "#147EFB",
                },
                {
                  name: "Swift Playgrounds",
                  desc: "Interactive learning environment available on Mac and iPad. Perfect for learning Swift, experimenting with code, and prototyping. Supports Swift Package dependencies and can even export to Xcode projects.",
                  color: "#F05138",
                },
                {
                  name: "VS Code + Swift Extension",
                  desc: "For server-side Swift or editing on non-Mac platforms. The official Swift extension provides syntax highlighting, code completion, and debugging. Requires Swift toolchain installed separately.",
                  color: "#007ACC",
                },
              ].map((item) => (
                <Grid item xs={12} md={4} key={item.name}>
                  <Paper sx={{ p: 3, height: "100%", borderRadius: 3, border: `1px solid ${alpha(item.color, 0.3)}`, bgcolor: alpha(item.color, 0.03) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>
                      {item.name}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColorDark }}>
              Command Line Swift
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}># After installing Xcode, verify Swift:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>swift</span> --version{"\n"}
                <span style={{ color: "#6272a4" }}># Apple Swift version 5.10 (...)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Run Swift REPL (Read-Eval-Print Loop):</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>swift</span>{"\n"}
                <span style={{ color: "#6272a4" }}>{">"} print("Hello from REPL!")</span>{"\n"}
                <span style={{ color: "#6272a4" }}>{">"} let x = 42</span>{"\n"}
                <span style={{ color: "#6272a4" }}>{">"} :quit</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Compile and run a Swift file:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>swift</span> hello.swift{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Or compile to executable:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>swiftc</span> hello.swift -o hello{"\n"}
                ./hello
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColorDark }}>
              Swift Package Manager
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}># Create a new package:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>mkdir</span> MyProject && <span style={{ color: "#8be9fd" }}>cd</span> MyProject{"\n"}
                <span style={{ color: "#8be9fd" }}>swift</span> package init --type executable{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Build the project:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>swift</span> build{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Run the project:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>swift</span> run{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Run tests:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>swift</span> test
              </Typography>
            </Paper>
          </Paper>

          {/* Swift Basics & Syntax Section */}
          <Paper id="basics" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#48BB78", 0.15), color: "#48BB78", width: 48, height: 48 }}>
                <CodeIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Swift Basics & Syntax
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Swift has a clean, expressive syntax that feels modern and readable. If you're coming
              from C-family languages, much will feel familiar, but Swift has its own idioms and
              conventions that make code more concise and safe.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Constants and Variables
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Constants - cannot be changed after assignment</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> maximumAttempts = <span style={{ color: "#bd93f9" }}>3</span>       <span style={{ color: "#6272a4" }}>// Type inferred as Int</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> pi: <span style={{ color: "#8be9fd" }}>Double</span> = <span style={{ color: "#bd93f9" }}>3.14159</span>    <span style={{ color: "#6272a4" }}>// Explicit type annotation</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// maximumAttempts = 5            // Error! Cannot assign to 'let'</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Variables - can be modified</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> currentAttempt = <span style={{ color: "#bd93f9" }}>0</span>{"\n"}
                currentAttempt += <span style={{ color: "#bd93f9" }}>1</span>              <span style={{ color: "#6272a4" }}>// OK</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Multiple declarations</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> x = <span style={{ color: "#bd93f9" }}>0</span>, y = <span style={{ color: "#bd93f9" }}>0</span>, z = <span style={{ color: "#bd93f9" }}>0</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> a = <span style={{ color: "#bd93f9" }}>1</span>, b = <span style={{ color: "#bd93f9" }}>2</span>, c = <span style={{ color: "#bd93f9" }}>3</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Basic Types
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Integers</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> int8: <span style={{ color: "#8be9fd" }}>Int8</span> = <span style={{ color: "#bd93f9" }}>127</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> int: <span style={{ color: "#8be9fd" }}>Int</span> = <span style={{ color: "#bd93f9" }}>42</span>              <span style={{ color: "#6272a4" }}>// Platform-native (usually 64-bit)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> unsigned: <span style={{ color: "#8be9fd" }}>UInt</span> = <span style={{ color: "#bd93f9" }}>100</span>       <span style={{ color: "#6272a4" }}>// Unsigned integer</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> million = <span style={{ color: "#bd93f9" }}>1_000_000</span>          <span style={{ color: "#6272a4" }}>// Underscores for readability</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Floating-point</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> float: <span style={{ color: "#8be9fd" }}>Float</span> = <span style={{ color: "#bd93f9" }}>3.14</span>        <span style={{ color: "#6272a4" }}>// 32-bit</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> double = <span style={{ color: "#bd93f9" }}>3.14159</span>            <span style={{ color: "#6272a4" }}>// Default is Double (64-bit)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Boolean</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> isSwift = <span style={{ color: "#ff79c6" }}>true</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> isObjC = <span style={{ color: "#ff79c6" }}>false</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// String and Character</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> greeting = <span style={{ color: "#f1fa8c" }}>"Hello"</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> letter: <span style={{ color: "#8be9fd" }}>Character</span> = <span style={{ color: "#f1fa8c" }}>"S"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Multi-line strings</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> multiline = <span style={{ color: "#f1fa8c" }}>"""</span>{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>This is a</span>{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>multi-line</span>{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>string.</span>{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>"""</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              String Interpolation
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>let</span> name = <span style={{ color: "#f1fa8c" }}>"Swift"</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> version = <span style={{ color: "#bd93f9" }}>5.10</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Interpolate variables with \()</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Learning </span>\(<span style={{ color: "#ff79c6" }}>name</span>) \(<span style={{ color: "#ff79c6" }}>version</span>)<span style={{ color: "#f1fa8c" }}>"</span>){"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Expressions work too</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"2 + 2 = </span>\(<span style={{ color: "#bd93f9" }}>2</span> + <span style={{ color: "#bd93f9" }}>2</span>)<span style={{ color: "#f1fa8c" }}>"</span>){"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Name has </span>\(<span style={{ color: "#ff79c6" }}>name</span>.count)<span style={{ color: "#f1fa8c" }}> characters"</span>)
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Comments
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Single-line comment</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>/*</span>{"\n"}
                <span style={{ color: "#6272a4" }}> * Multi-line comment</span>{"\n"}
                <span style={{ color: "#6272a4" }}> * Can span multiple lines</span>{"\n"}
                <span style={{ color: "#6272a4" }}> */</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>/// Documentation comment (DocC)</span>{"\n"}
                <span style={{ color: "#6272a4" }}>/// - Parameter name: The person's name</span>{"\n"}
                <span style={{ color: "#6272a4" }}>/// - Returns: A personalized greeting</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>greet</span>(name: <span style={{ color: "#8be9fd" }}>String</span>) -{">"} <span style={{ color: "#8be9fd" }}>String</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#f1fa8c" }}>"Hello, </span>\(<span style={{ color: "#ff79c6" }}>name</span>)<span style={{ color: "#f1fa8c" }}>!"</span>{"\n"}
                {"}"}
              </Typography>
            </Paper>
          </Paper>

          {/* Variables & Constants Section */}
          <Paper id="variables" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#667EEA", 0.15), color: "#667EEA", width: 48, height: 48 }}>
                <DataObjectIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Variables & Constants
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Swift strongly encourages the use of constants (<code>let</code>) over variables (<code>var</code>).
              Using <code>let</code> whenever possible makes your code safer and clearer about intent. The
              compiler can also optimize constant values better.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Type Inference
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Swift infers types from initial values</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> message = <span style={{ color: "#f1fa8c" }}>"Hello"</span>      <span style={{ color: "#6272a4" }}>// Inferred as String</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> count = <span style={{ color: "#bd93f9" }}>42</span>             <span style={{ color: "#6272a4" }}>// Inferred as Int</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> price = <span style={{ color: "#bd93f9" }}>19.99</span>          <span style={{ color: "#6272a4" }}>// Inferred as Double</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> isValid = <span style={{ color: "#ff79c6" }}>true</span>         <span style={{ color: "#6272a4" }}>// Inferred as Bool</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Explicit type annotation when needed</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> explicitDouble: <span style={{ color: "#8be9fd" }}>Double</span> = <span style={{ color: "#bd93f9" }}>42</span>  <span style={{ color: "#6272a4" }}>// 42.0, not Int</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> explicitFloat: <span style={{ color: "#8be9fd" }}>Float</span> = <span style={{ color: "#bd93f9" }}>3.14</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Declare first, assign later</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> laterAssigned: <span style={{ color: "#8be9fd" }}>String</span>      <span style={{ color: "#6272a4" }}>// Must specify type</span>{"\n"}
                laterAssigned = <span style={{ color: "#f1fa8c" }}>"Value"</span>           <span style={{ color: "#6272a4" }}>// Assign before use</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Type Conversion
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Swift requires explicit conversion - no implicit coercion</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> integer = <span style={{ color: "#bd93f9" }}>42</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> decimal = <span style={{ color: "#bd93f9" }}>3.14</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// let sum = integer + decimal     // Error! Different types</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> sum = <span style={{ color: "#8be9fd" }}>Double</span>(integer) + decimal  <span style={{ color: "#6272a4" }}>// OK: 45.14</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> truncated = integer + <span style={{ color: "#8be9fd" }}>Int</span>(decimal)  <span style={{ color: "#6272a4" }}>// OK: 45 (truncates)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// String conversion</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> numString = <span style={{ color: "#8be9fd" }}>String</span>(integer)  <span style={{ color: "#6272a4" }}>// "42"</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> parsed = <span style={{ color: "#8be9fd" }}>Int</span>(<span style={{ color: "#f1fa8c" }}>"123"</span>)        <span style={{ color: "#6272a4" }}>// Optional Int? (might fail)</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Type Aliases
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Create meaningful names for existing types</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>typealias</span> <span style={{ color: "#8be9fd" }}>AudioSample</span> = <span style={{ color: "#8be9fd" }}>UInt16</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>typealias</span> <span style={{ color: "#8be9fd" }}>Distance</span> = <span style={{ color: "#8be9fd" }}>Double</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>typealias</span> <span style={{ color: "#8be9fd" }}>Completion</span> = (<span style={{ color: "#8be9fd" }}>Bool</span>) -{">"} <span style={{ color: "#8be9fd" }}>Void</span>{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> sample: <span style={{ color: "#8be9fd" }}>AudioSample</span> = <span style={{ color: "#bd93f9" }}>44100</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> marathon: <span style={{ color: "#8be9fd" }}>Distance</span> = <span style={{ color: "#bd93f9" }}>42.195</span>
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
              Swift's control flow is familiar but with enhancements. Conditions don't need parentheses
              (but braces are always required). The switch statement is powerful with pattern matching
              and doesn't fall through by default.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              If-Else
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>let</span> score = <span style={{ color: "#bd93f9" }}>85</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Parentheses optional, braces required</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> score {">"}= <span style={{ color: "#bd93f9" }}>90</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"A"</span>){"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>else if</span> score {">"}= <span style={{ color: "#bd93f9" }}>80</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"B"</span>){"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>else</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"C or below"</span>){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Ternary operator</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> status = score {">"}= <span style={{ color: "#bd93f9" }}>60</span> ? <span style={{ color: "#f1fa8c" }}>"Pass"</span> : <span style={{ color: "#f1fa8c" }}>"Fail"</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              Switch with Pattern Matching
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>let</span> grade = <span style={{ color: "#f1fa8c" }}>"A"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// No fallthrough, no break needed</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>switch</span> grade {"{"}{"\n"}
                <span style={{ color: "#ff79c6" }}>case</span> <span style={{ color: "#f1fa8c" }}>"A"</span>:{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Excellent!"</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>case</span> <span style={{ color: "#f1fa8c" }}>"B"</span>, <span style={{ color: "#f1fa8c" }}>"C"</span>:        <span style={{ color: "#6272a4" }}>// Multiple values</span>{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Good"</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>default</span>:{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Keep trying"</span>){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Range matching</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> score = <span style={{ color: "#bd93f9" }}>85</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>switch</span> score {"{"}{"\n"}
                <span style={{ color: "#ff79c6" }}>case</span> <span style={{ color: "#bd93f9" }}>90</span>...<span style={{ color: "#bd93f9" }}>100</span>:        <span style={{ color: "#6272a4" }}>// Closed range</span>{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"A"</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>case</span> <span style={{ color: "#bd93f9" }}>80</span>..{"<"}<span style={{ color: "#bd93f9" }}>90</span>:         <span style={{ color: "#6272a4" }}>// Half-open range</span>{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"B"</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>case</span> <span style={{ color: "#ff79c6" }}>let</span> x <span style={{ color: "#ff79c6" }}>where</span> x {">"} <span style={{ color: "#bd93f9" }}>0</span>:  <span style={{ color: "#6272a4" }}>// Value binding + where clause</span>{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Positive: </span>\(<span style={{ color: "#ff79c6" }}>x</span>)<span style={{ color: "#f1fa8c" }}>"</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>default</span>:{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Other"</span>){"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              Loops
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// For-in loop with ranges</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> i <span style={{ color: "#ff79c6" }}>in</span> <span style={{ color: "#bd93f9" }}>1</span>...<span style={{ color: "#bd93f9" }}>5</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(i)  <span style={{ color: "#6272a4" }}>// 1, 2, 3, 4, 5</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> i <span style={{ color: "#ff79c6" }}>in</span> <span style={{ color: "#bd93f9" }}>1</span>..{"<"}<span style={{ color: "#bd93f9" }}>5</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(i)  <span style={{ color: "#6272a4" }}>// 1, 2, 3, 4 (excludes 5)</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Iterating collections</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> names = [<span style={{ color: "#f1fa8c" }}>"Anna"</span>, <span style={{ color: "#f1fa8c" }}>"Brian"</span>, <span style={{ color: "#f1fa8c" }}>"Claire"</span>]{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> name <span style={{ color: "#ff79c6" }}>in</span> names {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(name){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// With enumerated (index + value)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> (index, name) <span style={{ color: "#ff79c6" }}>in</span> names.<span style={{ color: "#50fa7b" }}>enumerated</span>() {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"</span>\(<span style={{ color: "#ff79c6" }}>index</span>)<span style={{ color: "#f1fa8c" }}>: </span>\(<span style={{ color: "#ff79c6" }}>name</span>)<span style={{ color: "#f1fa8c" }}>"</span>){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// While loop</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> count = <span style={{ color: "#bd93f9" }}>3</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>while</span> count {">"} <span style={{ color: "#bd93f9" }}>0</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(count){"\n"}
                {"    "}count -= <span style={{ color: "#bd93f9" }}>1</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Repeat-while (do-while equivalent)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>repeat</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(count){"\n"}
                {"    "}count += <span style={{ color: "#bd93f9" }}>1</span>{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>while</span> count {"<"} <span style={{ color: "#bd93f9" }}>3</span>
              </Typography>
            </Paper>
          </Paper>

          {/* Operators & Expressions Section */}
          <Paper id="operators" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#E53E3E", 0.15), color: "#E53E3E", width: 48, height: 48 }}>
                <SwapHorizIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Operators & Expressions
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide to Operators
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
                <strong>Operators</strong> are special symbols that perform operations on values. Think of them as verbs in a sentence—they describe what action to take. Swift has familiar operators like + and -, but also powerful unique ones like <code>??</code> (nil coalescing) and <code>...</code> (ranges) that make code more expressive and safe.
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#E53E3E" }}>
              Arithmetic Operators
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>let</span> a = <span style={{ color: "#bd93f9" }}>10</span>, b = <span style={{ color: "#bd93f9" }}>3</span>{"\n"}
                {"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(a + b)  <span style={{ color: "#6272a4" }}>// 13 - Addition</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(a - b)  <span style={{ color: "#6272a4" }}>// 7  - Subtraction</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(a * b)  <span style={{ color: "#6272a4" }}>// 30 - Multiplication</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(a / b)  <span style={{ color: "#6272a4" }}>// 3  - Division (integer)</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(a % b)  <span style={{ color: "#6272a4" }}>// 1  - Remainder (modulo)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Swift prevents overflow by default (crashes if overflow)</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// Use overflow operators for wrapping behavior:</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> max = <span style={{ color: "#8be9fd" }}>UInt8</span>.max  <span style={{ color: "#6272a4" }}>// 255</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// let overflow = max + 1  // Crash! Overflow</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> wrapped = max &amp;+ <span style={{ color: "#bd93f9" }}>1</span>  <span style={{ color: "#6272a4" }}>// 0 (wraps around)</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#E53E3E" }}>
              Comparison & Logical Operators
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Comparison operators return Bool</span>{"\n"}
                <span style={{ color: "#bd93f9" }}>5</span> == <span style={{ color: "#bd93f9" }}>5</span>   <span style={{ color: "#6272a4" }}>// true  - Equal</span>{"\n"}
                <span style={{ color: "#bd93f9" }}>5</span> != <span style={{ color: "#bd93f9" }}>3</span>   <span style={{ color: "#6272a4" }}>// true  - Not equal</span>{"\n"}
                <span style={{ color: "#bd93f9" }}>5</span> {">"} <span style={{ color: "#bd93f9" }}>3</span>    <span style={{ color: "#6272a4" }}>// true  - Greater than</span>{"\n"}
                <span style={{ color: "#bd93f9" }}>5</span> {"<"} <span style={{ color: "#bd93f9" }}>3</span>    <span style={{ color: "#6272a4" }}>// false - Less than</span>{"\n"}
                <span style={{ color: "#bd93f9" }}>5</span> {">"}= <span style={{ color: "#bd93f9" }}>5</span>   <span style={{ color: "#6272a4" }}>// true  - Greater or equal</span>{"\n"}
                <span style={{ color: "#bd93f9" }}>5</span> {"<"}= <span style={{ color: "#bd93f9" }}>5</span>   <span style={{ color: "#6272a4" }}>// true  - Less or equal</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Logical operators (combine Bools)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> hasKey = <span style={{ color: "#ff79c6" }}>true</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> doorOpen = <span style={{ color: "#ff79c6" }}>false</span>{"\n"}
                {"\n"}
                !hasKey              <span style={{ color: "#6272a4" }}>// false - NOT (negation)</span>{"\n"}
                hasKey && doorOpen   <span style={{ color: "#6272a4" }}>// false - AND (both must be true)</span>{"\n"}
                hasKey || doorOpen   <span style={{ color: "#6272a4" }}>// true  - OR (at least one true)</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#E53E3E" }}>
              Range Operators (Swift's Special Power)
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Closed range: includes both endpoints</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> i <span style={{ color: "#ff79c6" }}>in</span> <span style={{ color: "#bd93f9" }}>1</span>...<span style={{ color: "#bd93f9" }}>5</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(i)  <span style={{ color: "#6272a4" }}>// 1, 2, 3, 4, 5</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Half-open range: excludes upper bound (great for arrays)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> names = [<span style={{ color: "#f1fa8c" }}>"A"</span>, <span style={{ color: "#f1fa8c" }}>"B"</span>, <span style={{ color: "#f1fa8c" }}>"C"</span>]{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> i <span style={{ color: "#ff79c6" }}>in</span> <span style={{ color: "#bd93f9" }}>0</span>..{"<"}names.count {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(names[i])  <span style={{ color: "#6272a4" }}>// A, B, C (no out of bounds!)</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// One-sided ranges</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> items = [<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>4</span>, <span style={{ color: "#bd93f9" }}>5</span>]{"\n"}
                items[<span style={{ color: "#bd93f9" }}>2</span>...]    <span style={{ color: "#6272a4" }}>// [3, 4, 5] - from index 2 to end</span>{"\n"}
                items[..{"<"}<span style={{ color: "#bd93f9" }}>3</span>]    <span style={{ color: "#6272a4" }}>// [1, 2, 3] - from start to index 2</span>{"\n"}
                items[...<span style={{ color: "#bd93f9" }}>2</span>]    <span style={{ color: "#6272a4" }}>// [1, 2, 3] - from start through index 2</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#E53E3E" }}>
              Nil Coalescing & Optional Chaining
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Nil coalescing (??) provides default for nil</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> username: <span style={{ color: "#8be9fd" }}>String</span>? = <span style={{ color: "#ff79c6" }}>nil</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> displayName = username ?? <span style={{ color: "#f1fa8c" }}>"Anonymous"</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(displayName)  <span style={{ color: "#6272a4" }}>// "Anonymous"</span>{"\n"}
                {"\n"}
                username = <span style={{ color: "#f1fa8c" }}>"Alice"</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> name = username ?? <span style={{ color: "#f1fa8c" }}>"Anonymous"</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(name)  <span style={{ color: "#6272a4" }}>// "Alice"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Optional chaining (?.) safely accesses properties/methods</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>Person</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> address: <span style={{ color: "#8be9fd" }}>Address</span>?{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>Address</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> city: <span style={{ color: "#8be9fd" }}>String</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> person: <span style={{ color: "#8be9fd" }}>Person</span>? = Person(address: <span style={{ color: "#ff79c6" }}>nil</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> city = person?.address?.city  <span style={{ color: "#6272a4" }}>// nil (safely, no crash)</span>
              </Typography>
            </Paper>
          </Paper>

          {/* Functions & Closures Section */}
          <Paper id="functions" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#9F7AEA", 0.15), color: "#9F7AEA", width: 48, height: 48 }}>
                <ExtensionIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Functions & Closures
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
                <strong>Functions</strong> are reusable blocks of code that perform a specific task. Think of them like recipes—you define the steps once, then use the recipe whenever you need it. <strong>Closures</strong> are like anonymous functions you can pass around—similar to JavaScript's arrow functions. They're essential for Swift's functional programming features.
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9F7AEA" }}>
              Function Basics
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Basic function with parameters and return type</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>greet</span>(person: <span style={{ color: "#8be9fd" }}>String</span>) -{">"} <span style={{ color: "#8be9fd" }}>String</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#f1fa8c" }}>"Hello, </span>\(<span style={{ color: "#ff79c6" }}>person</span>)<span style={{ color: "#f1fa8c" }}>!"</span>{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#50fa7b" }}>greet</span>(person: <span style={{ color: "#f1fa8c" }}>"Alice"</span>))  <span style={{ color: "#6272a4" }}>// "Hello, Alice!"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Function with no parameters, no return value</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>sayHello</span>() {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Hello!"</span>){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Multiple return values with tuples</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>minMax</span>(array: [<span style={{ color: "#8be9fd" }}>Int</span>]) -{">"} (min: <span style={{ color: "#8be9fd" }}>Int</span>, max: <span style={{ color: "#8be9fd" }}>Int</span>)? {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>guard</span> !array.isEmpty <span style={{ color: "#ff79c6" }}>else</span> {"{"} <span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#ff79c6" }}>nil</span> {"}"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> (array.min()!, array.max()!){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>if let</span> result = <span style={{ color: "#50fa7b" }}>minMax</span>(array: [<span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>4</span>, <span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>5</span>]) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Min: </span>\(<span style={{ color: "#ff79c6" }}>result.min</span>)<span style={{ color: "#f1fa8c" }}>, Max: </span>\(<span style={{ color: "#ff79c6" }}>result.max</span>)<span style={{ color: "#f1fa8c" }}>"</span>)  <span style={{ color: "#6272a4" }}>// Min: 1, Max: 5</span>{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9F7AEA" }}>
              Argument Labels & Parameter Names
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Argument label (external) vs parameter name (internal)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>greet</span>(person name: <span style={{ color: "#8be9fd" }}>String</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Hello, </span>\(<span style={{ color: "#ff79c6" }}>name</span>)<span style={{ color: "#f1fa8c" }}>!"</span>)  <span style={{ color: "#6272a4" }}>// Use 'name' inside</span>{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#50fa7b" }}>greet</span>(person: <span style={{ color: "#f1fa8c" }}>"Bob"</span>)  <span style={{ color: "#6272a4" }}>// Use 'person' when calling</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Omit argument label with underscore</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>double</span>(_ number: <span style={{ color: "#8be9fd" }}>Int</span>) -{">"} <span style={{ color: "#8be9fd" }}>Int</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> number * <span style={{ color: "#bd93f9" }}>2</span>{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#50fa7b" }}>double</span>(<span style={{ color: "#bd93f9" }}>5</span>))  <span style={{ color: "#6272a4" }}>// 10 - cleaner call site</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Default parameter values</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>greet</span>(name: <span style={{ color: "#8be9fd" }}>String</span>, greeting: <span style={{ color: "#8be9fd" }}>String</span> = <span style={{ color: "#f1fa8c" }}>"Hello"</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"\(greeting), \(name)!"</span>){"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#50fa7b" }}>greet</span>(name: <span style={{ color: "#f1fa8c" }}>"Alice"</span>)                <span style={{ color: "#6272a4" }}>// "Hello, Alice!"</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>greet</span>(name: <span style={{ color: "#f1fa8c" }}>"Alice"</span>, greeting: <span style={{ color: "#f1fa8c" }}>"Hi"</span>)  <span style={{ color: "#6272a4" }}>// "Hi, Alice!"</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9F7AEA" }}>
              Closures (Anonymous Functions)
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Full closure syntax</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> addClosure = {"{"} (a: <span style={{ color: "#8be9fd" }}>Int</span>, b: <span style={{ color: "#8be9fd" }}>Int</span>) -{">"} <span style={{ color: "#8be9fd" }}>Int</span> <span style={{ color: "#ff79c6" }}>in</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> a + b{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(addClosure(<span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>4</span>))  <span style={{ color: "#6272a4" }}>// 7</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Shortened versions (type inference)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> numbers = [<span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>4</span>, <span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>5</span>]{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Full form</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> sorted1 = numbers.<span style={{ color: "#50fa7b" }}>sorted</span>(by: {"{"} (a: <span style={{ color: "#8be9fd" }}>Int</span>, b: <span style={{ color: "#8be9fd" }}>Int</span>) -{">"} <span style={{ color: "#8be9fd" }}>Bool</span> <span style={{ color: "#ff79c6" }}>in</span> a {"<"} b {"}"}){"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Inferred types</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> sorted2 = numbers.<span style={{ color: "#50fa7b" }}>sorted</span>(by: {"{"} a, b <span style={{ color: "#ff79c6" }}>in</span> a {"<"} b {"}"}){"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Shorthand argument names ($0, $1, ...)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> sorted3 = numbers.<span style={{ color: "#50fa7b" }}>sorted</span>(by: {"{"} $0 {"<"} $1 {"}"}){"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Operator as closure</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> sorted4 = numbers.<span style={{ color: "#50fa7b" }}>sorted</span>(by: {"<"}){"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Trailing closure syntax (closure is last argument)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> sorted5 = numbers.<span style={{ color: "#50fa7b" }}>sorted</span> {"{"} $0 {"<"} $1 {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9F7AEA" }}>
              Higher-Order Functions
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>let</span> numbers = [<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>4</span>, <span style={{ color: "#bd93f9" }}>5</span>]{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// map: transform each element</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> doubled = numbers.<span style={{ color: "#50fa7b" }}>map</span> {"{"} $0 * <span style={{ color: "#bd93f9" }}>2</span> {"}"}  <span style={{ color: "#6272a4" }}>// [2, 4, 6, 8, 10]</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// filter: keep elements matching condition</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> evens = numbers.<span style={{ color: "#50fa7b" }}>filter</span> {"{"} $0 % <span style={{ color: "#bd93f9" }}>2</span> == <span style={{ color: "#bd93f9" }}>0</span> {"}"}  <span style={{ color: "#6272a4" }}>// [2, 4]</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// reduce: combine into single value</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> sum = numbers.<span style={{ color: "#50fa7b" }}>reduce</span>(<span style={{ color: "#bd93f9" }}>0</span>) {"{"} $0 + $1 {"}"}  <span style={{ color: "#6272a4" }}>// 15</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> sum2 = numbers.<span style={{ color: "#50fa7b" }}>reduce</span>(<span style={{ color: "#bd93f9" }}>0</span>, +)           <span style={{ color: "#6272a4" }}>// 15 (same)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Chaining</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> result = numbers{"\n"}
                {"    "}.<span style={{ color: "#50fa7b" }}>filter</span> {"{"} $0 % <span style={{ color: "#bd93f9" }}>2</span> == <span style={{ color: "#bd93f9" }}>0</span> {"}"}  <span style={{ color: "#6272a4" }}>// [2, 4]</span>{"\n"}
                {"    "}.<span style={{ color: "#50fa7b" }}>map</span> {"{"} $0 * <span style={{ color: "#bd93f9" }}>10</span> {"}"}         <span style={{ color: "#6272a4" }}>// [20, 40]</span>{"\n"}
                {"    "}.<span style={{ color: "#50fa7b" }}>reduce</span>(<span style={{ color: "#bd93f9" }}>0</span>, +)            <span style={{ color: "#6272a4" }}>// 60</span>
              </Typography>
            </Paper>
          </Paper>

          {/* Optionals Deep Dive Section */}
          <Paper id="optionals" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#ED8936", 0.15), color: "#ED8936", width: 48, height: 48 }}>
                <SecurityIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Optionals Deep Dive
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                The Billion-Dollar Mistake—Solved!
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
                Tony Hoare, inventor of null references, called them his "billion-dollar mistake" because they've caused countless crashes and bugs. Swift's <strong>optionals</strong> solve this elegantly: a value is either <em>present</em> or <em>absent (nil)</em>, and the type system forces you to handle both cases. This single feature eliminates an entire category of runtime crashes.
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              What Are Optionals?
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// An optional can hold a value OR nil</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> name: <span style={{ color: "#8be9fd" }}>String</span>? = <span style={{ color: "#f1fa8c" }}>"Alice"</span>   <span style={{ color: "#6272a4" }}>// Has a value</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> age: <span style={{ color: "#8be9fd" }}>Int</span>? = <span style={{ color: "#ff79c6" }}>nil</span>             <span style={{ color: "#6272a4" }}>// No value</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Think of optional as a box that might be empty:</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// String?  =  Box that contains String | empty box (nil)</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// String   =  Always contains a String (never empty)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// You can't use an optional directly as its wrapped type</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// let greeting = "Hello, " + name   // Error!</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// You must "unwrap" it first to access the value inside</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Safe Unwrapping: if let & guard let
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>var</span> username: <span style={{ color: "#8be9fd" }}>String</span>? = <span style={{ color: "#f1fa8c" }}>"Alice"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// if let: unwrap and use in scope</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>if let</span> name = username {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// 'name' is String (not String?) - guaranteed not nil here</span>{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Hello, </span>\(<span style={{ color: "#ff79c6" }}>name</span>)<span style={{ color: "#f1fa8c" }}>!"</span>){"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>else</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"No username"</span>){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Swift 5.7+: shorthand when variable name matches</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>if let</span> username {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Hello, </span>\(<span style={{ color: "#ff79c6" }}>username</span>)<span style={{ color: "#f1fa8c" }}>!"</span>)  <span style={{ color: "#6272a4" }}>// username is unwrapped</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// guard let: unwrap with early exit (great for functions)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>greetUser</span>(_ username: <span style={{ color: "#8be9fd" }}>String</span>?) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>guard let</span> name = username <span style={{ color: "#ff79c6" }}>else</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"No name provided"</span>){"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span>  <span style={{ color: "#6272a4" }}>// Must exit scope</span>{"\n"}
                {"    }"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// 'name' is available for rest of function</span>{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Hello, </span>\(<span style={{ color: "#ff79c6" }}>name</span>)<span style={{ color: "#f1fa8c" }}>!"</span>){"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Nil Coalescing & Force Unwrapping
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>var</span> optionalName: <span style={{ color: "#8be9fd" }}>String</span>? = <span style={{ color: "#ff79c6" }}>nil</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Nil coalescing: provide default if nil</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> displayName = optionalName ?? <span style={{ color: "#f1fa8c" }}>"Guest"</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(displayName)  <span style={{ color: "#6272a4" }}>// "Guest"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Force unwrapping with ! (DANGER: crashes if nil!)</span>{"\n"}
                optionalName = <span style={{ color: "#f1fa8c" }}>"Alice"</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> forced = optionalName!  <span style={{ color: "#6272a4" }}>// "Alice" - but risky!</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// optionalName = nil</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// let crash = optionalName!  // Fatal error: nil!</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Only force unwrap when you're 100% certain it's not nil</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// Prefer if let, guard let, or ?? instead</span>
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#f44336", 0.1), border: `1px solid ${alpha("#f44336", 0.3)}`, mb: 3 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f44336", mb: 1 }}>
                Warning: Force Unwrapping
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
                Using <code>!</code> to force unwrap is dangerous! If the value is nil, your app crashes. Use it only when you're absolutely certain the value exists (like immediately after assignment). Prefer <code>if let</code>, <code>guard let</code>, or <code>??</code> for safe handling.
              </Typography>
            </Paper>
          </Paper>

          {/* Collections Section */}
          <Paper id="collections" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#4299E1", 0.15), color: "#4299E1", width: 48, height: 48 }}>
                <StorageIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Collections
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
                Swift has three primary collection types: <strong>Array</strong> (ordered list), <strong>Set</strong> (unordered unique values), and <strong>Dictionary</strong> (key-value pairs). All are generic, type-safe, and come with powerful functional methods like <code>map</code>, <code>filter</code>, and <code>reduce</code>.
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4299E1" }}>
              Arrays
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Creating arrays</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> numbers: [<span style={{ color: "#8be9fd" }}>Int</span>] = [<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>]   <span style={{ color: "#6272a4" }}>// Explicit type</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> names = [<span style={{ color: "#f1fa8c" }}>"Alice"</span>, <span style={{ color: "#f1fa8c" }}>"Bob"</span>]        <span style={{ color: "#6272a4" }}>// Inferred [String]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> empty: [<span style={{ color: "#8be9fd" }}>String</span>] = []                <span style={{ color: "#6272a4" }}>// Empty array</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> zeros = <span style={{ color: "#8be9fd" }}>Array</span>(repeating: <span style={{ color: "#bd93f9" }}>0</span>, count: <span style={{ color: "#bd93f9" }}>5</span>)  <span style={{ color: "#6272a4" }}>// [0,0,0,0,0]</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Accessing & modifying</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(numbers[<span style={{ color: "#bd93f9" }}>0</span>])         <span style={{ color: "#6272a4" }}>// 1 (first element)</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(numbers.first)       <span style={{ color: "#6272a4" }}>// Optional(1) - safe</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(numbers.count)       <span style={{ color: "#6272a4" }}>// 3</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(numbers.isEmpty)     <span style={{ color: "#6272a4" }}>// false</span>{"\n"}
                {"\n"}
                numbers.<span style={{ color: "#50fa7b" }}>append</span>(<span style={{ color: "#bd93f9" }}>4</span>)           <span style={{ color: "#6272a4" }}>// [1, 2, 3, 4]</span>{"\n"}
                numbers += [<span style={{ color: "#bd93f9" }}>5</span>, <span style={{ color: "#bd93f9" }}>6</span>]           <span style={{ color: "#6272a4" }}>// [1, 2, 3, 4, 5, 6]</span>{"\n"}
                numbers.<span style={{ color: "#50fa7b" }}>insert</span>(<span style={{ color: "#bd93f9" }}>0</span>, at: <span style={{ color: "#bd93f9" }}>0</span>)    <span style={{ color: "#6272a4" }}>// [0, 1, 2, 3, 4, 5, 6]</span>{"\n"}
                numbers.<span style={{ color: "#50fa7b" }}>remove</span>(at: <span style={{ color: "#bd93f9" }}>0</span>)        <span style={{ color: "#6272a4" }}>// [1, 2, 3, 4, 5, 6]</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Slicing with ranges</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> slice = numbers[<span style={{ color: "#bd93f9" }}>1</span>...<span style={{ color: "#bd93f9" }}>3</span>]  <span style={{ color: "#6272a4" }}>// [2, 3, 4]</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4299E1" }}>
              Dictionaries
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Key-value pairs</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> scores: [<span style={{ color: "#8be9fd" }}>String</span>: <span style={{ color: "#8be9fd" }}>Int</span>] = [<span style={{ color: "#f1fa8c" }}>"Alice"</span>: <span style={{ color: "#bd93f9" }}>95</span>, <span style={{ color: "#f1fa8c" }}>"Bob"</span>: <span style={{ color: "#bd93f9" }}>87</span>]{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Access returns optional (key might not exist)</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(scores[<span style={{ color: "#f1fa8c" }}>"Alice"</span>])        <span style={{ color: "#6272a4" }}>// Optional(95)</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(scores[<span style={{ color: "#f1fa8c" }}>"Unknown"</span>])      <span style={{ color: "#6272a4" }}>// nil</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(scores[<span style={{ color: "#f1fa8c" }}>"Unknown"</span>, default: <span style={{ color: "#bd93f9" }}>0</span>])  <span style={{ color: "#6272a4" }}>// 0</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Adding/updating</span>{"\n"}
                scores[<span style={{ color: "#f1fa8c" }}>"Charlie"</span>] = <span style={{ color: "#bd93f9" }}>92</span>       <span style={{ color: "#6272a4" }}>// Add new</span>{"\n"}
                scores[<span style={{ color: "#f1fa8c" }}>"Alice"</span>] = <span style={{ color: "#bd93f9" }}>98</span>         <span style={{ color: "#6272a4" }}>// Update existing</span>{"\n"}
                scores[<span style={{ color: "#f1fa8c" }}>"Bob"</span>] = <span style={{ color: "#ff79c6" }}>nil</span>           <span style={{ color: "#6272a4" }}>// Remove Bob</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Iterating</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> (name, score) <span style={{ color: "#ff79c6" }}>in</span> scores {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"\(name): \(score)"</span>){"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> name <span style={{ color: "#ff79c6" }}>in</span> scores.keys {"{"} <span style={{ color: "#50fa7b" }}>print</span>(name) {"}"}{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> score <span style={{ color: "#ff79c6" }}>in</span> scores.values {"{"} <span style={{ color: "#50fa7b" }}>print</span>(score) {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4299E1" }}>
              Sets
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Unordered collection of unique values</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> fruits: <span style={{ color: "#8be9fd" }}>Set</span>{"<"}<span style={{ color: "#8be9fd" }}>String</span>{">"} = [<span style={{ color: "#f1fa8c" }}>"Apple"</span>, <span style={{ color: "#f1fa8c" }}>"Banana"</span>]{"\n"}
                fruits.<span style={{ color: "#50fa7b" }}>insert</span>(<span style={{ color: "#f1fa8c" }}>"Orange"</span>){"\n"}
                fruits.<span style={{ color: "#50fa7b" }}>insert</span>(<span style={{ color: "#f1fa8c" }}>"Apple"</span>)   <span style={{ color: "#6272a4" }}>// Ignored - already exists</span>{"\n"}
                {"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(fruits.<span style={{ color: "#50fa7b" }}>contains</span>(<span style={{ color: "#f1fa8c" }}>"Apple"</span>))  <span style={{ color: "#6272a4" }}>// true - O(1) lookup!</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Set operations</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> a: <span style={{ color: "#8be9fd" }}>Set</span> = [<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>]{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> b: <span style={{ color: "#8be9fd" }}>Set</span> = [<span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>4</span>]{"\n"}
                {"\n"}
                a.<span style={{ color: "#50fa7b" }}>union</span>(b)          <span style={{ color: "#6272a4" }}>// {1, 2, 3, 4}</span>{"\n"}
                a.<span style={{ color: "#50fa7b" }}>intersection</span>(b)   <span style={{ color: "#6272a4" }}>// {2, 3}</span>{"\n"}
                a.<span style={{ color: "#50fa7b" }}>subtracting</span>(b)    <span style={{ color: "#6272a4" }}>// {1}</span>{"\n"}
                a.<span style={{ color: "#50fa7b" }}>symmetricDifference</span>(b)  <span style={{ color: "#6272a4" }}>// {1, 4}</span>
              </Typography>
            </Paper>
          </Paper>

          {/* Structs & Classes Section */}
          <Paper id="structs" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#38A169", 0.15), color: "#38A169", width: 48, height: 48 }}>
                <ClassIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Structs & Classes
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Value Types vs Reference Types
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
                <strong>Structs</strong> are <em>value types</em>—when you assign or pass them, Swift makes a copy. Think of passing a photo (copy—original unchanged). <strong>Classes</strong> are <em>reference types</em>—variables share the same instance. Think of sharing a Google Doc link (everyone sees changes). Swift strongly prefers structs for most cases because they're safer and easier to reason about.
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38A169" }}>
              Structs (Value Types)
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>Point</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> x: <span style={{ color: "#8be9fd" }}>Double</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> y: <span style={{ color: "#8be9fd" }}>Double</span>{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Computed property</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> magnitude: <span style={{ color: "#8be9fd" }}>Double</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> (x*x + y*y).<span style={{ color: "#50fa7b" }}>squareRoot</span>(){"\n"}
                {"    }"}{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Method that modifies struct must be 'mutating'</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>mutating func</span> <span style={{ color: "#50fa7b" }}>moveBy</span>(dx: <span style={{ color: "#8be9fd" }}>Double</span>, dy: <span style={{ color: "#8be9fd" }}>Double</span>) {"{"}{"\n"}
                {"        "}x += dx{"\n"}
                {"        "}y += dy{"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Automatic memberwise initializer</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> point = <span style={{ color: "#8be9fd" }}>Point</span>(x: <span style={{ color: "#bd93f9" }}>3</span>, y: <span style={{ color: "#bd93f9" }}>4</span>){"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(point.magnitude)  <span style={{ color: "#6272a4" }}>// 5.0</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Value semantics - copying</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> copy = point{"\n"}
                copy.x = <span style={{ color: "#bd93f9" }}>100</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(point.x)  <span style={{ color: "#6272a4" }}>// 3 - original unchanged!</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38A169" }}>
              Classes (Reference Types)
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Person</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> name: <span style={{ color: "#8be9fd" }}>String</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> age: <span style={{ color: "#8be9fd" }}>Int</span>{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Classes need explicit initializers</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>init</span>(name: <span style={{ color: "#8be9fd" }}>String</span>, age: <span style={{ color: "#8be9fd" }}>Int</span>) {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>self</span>.name = name{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>self</span>.age = age{"\n"}
                {"    }"}{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// deinit called when instance is deallocated</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>deinit</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"\(name) is being deallocated"</span>){"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> alice = <span style={{ color: "#8be9fd" }}>Person</span>(name: <span style={{ color: "#f1fa8c" }}>"Alice"</span>, age: <span style={{ color: "#bd93f9" }}>30</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> reference = alice  <span style={{ color: "#6272a4" }}>// Same instance, not a copy!</span>{"\n"}
                reference.age = <span style={{ color: "#bd93f9" }}>31</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(alice.age)  <span style={{ color: "#6272a4" }}>// 31 - both point to same object!</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Identity comparison</span>{"\n"}
                alice === reference  <span style={{ color: "#6272a4" }}>// true - same instance</span>
              </Typography>
            </Paper>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#38A169", 0.08), height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#38A169", mb: 1 }}>
                    When to Use Structs (Default Choice)
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>
                    • Most data types (coordinates, colors, dates)<br/>
                    • When you want independent copies<br/>
                    • Value doesn't need identity<br/>
                    • Thread-safe by default
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#E53E3E", 0.08), height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#E53E3E", mb: 1 }}>
                    When to Use Classes
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>
                    • Need inheritance (subclassing)<br/>
                    • Need identity (=== comparison)<br/>
                    • Interop with Objective-C<br/>
                    • Shared mutable state (carefully!)
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
          </Paper>

          {/* Enumerations Section */}
          <Paper id="enums" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#805AD5", 0.15), color: "#805AD5", width: 48, height: 48 }}>
                <ViewModuleIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Enumerations
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
                <strong>Enums</strong> define a type with a fixed set of possible values. Think of a traffic light: it can only be red, yellow, or green—nothing else. Swift's enums are extremely powerful: they can have <em>associated values</em> (data attached to each case) and <em>raw values</em>. They're perfect for modeling states and making invalid states impossible.
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#805AD5" }}>
              Basic Enums & Raw Values
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Simple enum</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>enum</span> <span style={{ color: "#8be9fd" }}>Direction</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> north, south, east, west{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> heading = <span style={{ color: "#8be9fd" }}>Direction</span>.north{"\n"}
                heading = .south  <span style={{ color: "#6272a4" }}>// Type inferred, shorthand</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Raw values (integers, strings, etc.)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>enum</span> <span style={{ color: "#8be9fd" }}>StatusCode</span>: <span style={{ color: "#8be9fd" }}>Int</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> ok = <span style={{ color: "#bd93f9" }}>200</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> notFound = <span style={{ color: "#bd93f9" }}>404</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> serverError = <span style={{ color: "#bd93f9" }}>500</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> status = <span style={{ color: "#8be9fd" }}>StatusCode</span>.notFound{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(status.rawValue)  <span style={{ color: "#6272a4" }}>// 404</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Create from raw value (returns optional)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>if let</span> code = <span style={{ color: "#8be9fd" }}>StatusCode</span>(rawValue: <span style={{ color: "#bd93f9" }}>200</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Got code: </span>\(<span style={{ color: "#ff79c6" }}>code</span>)<span style={{ color: "#f1fa8c" }}>"</span>)  <span style={{ color: "#6272a4" }}>// Got code: ok</span>{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#805AD5" }}>
              Associated Values (Powerful!)
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Cases can carry different data</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>enum</span> <span style={{ color: "#8be9fd" }}>APIResult</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> success(data: <span style={{ color: "#8be9fd" }}>Data</span>, statusCode: <span style={{ color: "#8be9fd" }}>Int</span>){"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> failure(error: <span style={{ color: "#8be9fd" }}>Error</span>){"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> loading{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> result = <span style={{ color: "#8be9fd" }}>APIResult</span>.success(data: someData, statusCode: <span style={{ color: "#bd93f9" }}>200</span>){"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Pattern matching with switch</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>switch</span> result {"{"}{"\n"}
                <span style={{ color: "#ff79c6" }}>case</span> .success(<span style={{ color: "#ff79c6" }}>let</span> data, <span style={{ color: "#ff79c6" }}>let</span> code):{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Success! Code: </span>\(<span style={{ color: "#ff79c6" }}>code</span>)<span style={{ color: "#f1fa8c" }}>, bytes: </span>\(<span style={{ color: "#ff79c6" }}>data</span>.count)<span style={{ color: "#f1fa8c" }}>"</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>case</span> .failure(<span style={{ color: "#ff79c6" }}>let</span> error):{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Error: </span>\(<span style={{ color: "#ff79c6" }}>error</span>)<span style={{ color: "#f1fa8c" }}>"</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>case</span> .loading:{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Loading..."</span>){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Extract with if case</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>if case</span> .success(<span style={{ color: "#ff79c6" }}>let</span> data, _) = result {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Got </span>\(<span style={{ color: "#ff79c6" }}>data</span>.count)<span style={{ color: "#f1fa8c" }}> bytes"</span>){"\n"}
                {"}"}
              </Typography>
            </Paper>
          </Paper>

          {/* Protocols Section */}
          <Paper id="protocols" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#DD6B20", 0.15), color: "#DD6B20", width: 48, height: 48 }}>
                <LayersIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Protocols
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
                <strong>Protocols</strong> define a blueprint of methods, properties, and requirements. They're like a contract: any type that "conforms" to the protocol promises to implement those requirements. Think of it like a job description—it says what capabilities are needed, not how to do them. This enables <em>protocol-oriented programming</em>, Swift's preferred paradigm over class inheritance.
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#DD6B20" }}>
              Defining & Conforming to Protocols
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Define a protocol</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>protocol</span> <span style={{ color: "#8be9fd" }}>Describable</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> description: <span style={{ color: "#8be9fd" }}>String</span> {"{"} <span style={{ color: "#ff79c6" }}>get</span> {"}"}  <span style={{ color: "#6272a4" }}>// Require a readable property</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>describe</span>() -{">"} <span style={{ color: "#8be9fd" }}>String</span>    <span style={{ color: "#6272a4" }}>// Require a method</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Struct conforms to protocol</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>Person</span>: <span style={{ color: "#8be9fd" }}>Describable</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> name: <span style={{ color: "#8be9fd" }}>String</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> age: <span style={{ color: "#8be9fd" }}>Int</span>{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> description: <span style={{ color: "#8be9fd" }}>String</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#f1fa8c" }}>"\(name), \(age) years old"</span>{"\n"}
                {"    }"}{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>describe</span>() -{">"} <span style={{ color: "#8be9fd" }}>String</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#f1fa8c" }}>"Person: </span>\(<span style={{ color: "#ff79c6" }}>description</span>)<span style={{ color: "#f1fa8c" }}>"</span>{"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Use protocol as type</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>printInfo</span>(_ item: <span style={{ color: "#8be9fd" }}>Describable</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(item.<span style={{ color: "#50fa7b" }}>describe</span>()){"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#DD6B20" }}>
              Common Swift Protocols
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Equatable: enables == comparison</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>Point</span>: <span style={{ color: "#8be9fd" }}>Equatable</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> x: <span style={{ color: "#8be9fd" }}>Int</span>, y: <span style={{ color: "#8be9fd" }}>Int</span>  <span style={{ color: "#6272a4" }}>// Auto-synthesized!</span>{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#8be9fd" }}>Point</span>(x: <span style={{ color: "#bd93f9" }}>1</span>, y: <span style={{ color: "#bd93f9" }}>2</span>) == <span style={{ color: "#8be9fd" }}>Point</span>(x: <span style={{ color: "#bd93f9" }}>1</span>, y: <span style={{ color: "#bd93f9" }}>2</span>)  <span style={{ color: "#6272a4" }}>// true</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Hashable: can be used in Sets/Dictionary keys</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>User</span>: <span style={{ color: "#8be9fd" }}>Hashable</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> id: <span style={{ color: "#8be9fd" }}>Int</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> name: <span style={{ color: "#8be9fd" }}>String</span>{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> users: <span style={{ color: "#8be9fd" }}>Set</span>{"<"}<span style={{ color: "#8be9fd" }}>User</span>{">"} = []  <span style={{ color: "#6272a4" }}>// Works!</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Codable: JSON encoding/decoding</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>APIResponse</span>: <span style={{ color: "#8be9fd" }}>Codable</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> id: <span style={{ color: "#8be9fd" }}>Int</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> message: <span style={{ color: "#8be9fd" }}>String</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> json = <span style={{ color: "#f1fa8c" }}>#"{"{"}"id": 1, "message": "Hello"{"}"}"#</span>.data(using: .utf8)!{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> response = <span style={{ color: "#ff79c6" }}>try</span> <span style={{ color: "#8be9fd" }}>JSONDecoder</span>().<span style={{ color: "#50fa7b" }}>decode</span>(<span style={{ color: "#8be9fd" }}>APIResponse</span>.<span style={{ color: "#ff79c6" }}>self</span>, from: json)
              </Typography>
            </Paper>
          </Paper>

          {/* Error Handling Section */}
          <Paper id="error-handling" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#E53E3E", 0.15), color: "#E53E3E", width: 48, height: 48 }}>
                <BugReportIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Error Handling
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
                Swift's error handling uses <code>throw</code>, <code>try</code>, and <code>catch</code>—similar to other languages but with explicit marking. Functions that can fail are marked with <code>throws</code>, and callers must acknowledge this with <code>try</code>. This eliminates "hidden" failures—every error path is visible in the code.
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#E53E3E" }}>
              Defining & Throwing Errors
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Define errors as enum conforming to Error</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>enum</span> <span style={{ color: "#8be9fd" }}>ValidationError</span>: <span style={{ color: "#8be9fd" }}>Error</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> tooShort(minimum: <span style={{ color: "#8be9fd" }}>Int</span>){"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> tooLong(maximum: <span style={{ color: "#8be9fd" }}>Int</span>){"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> invalidCharacters{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Function that throws must be marked 'throws'</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>validate</span>(password: <span style={{ color: "#8be9fd" }}>String</span>) <span style={{ color: "#ff79c6" }}>throws</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>if</span> password.count {"<"} <span style={{ color: "#bd93f9" }}>8</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>throw</span> <span style={{ color: "#8be9fd" }}>ValidationError</span>.tooShort(minimum: <span style={{ color: "#bd93f9" }}>8</span>){"\n"}
                {"    }"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>if</span> password.count {">"} <span style={{ color: "#bd93f9" }}>100</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>throw</span> <span style={{ color: "#8be9fd" }}>ValidationError</span>.tooLong(maximum: <span style={{ color: "#bd93f9" }}>100</span>){"\n"}
                {"    }"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Password valid!"</span>){"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#E53E3E" }}>
              Handling Errors: do-catch
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Must use 'try' when calling throwing function</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>do</span> {"{"}{"\n"}
                {"    "}<span style="{{ color: "#ff79c6" }}>try</span> <span style={{ color: "#50fa7b" }}>validate</span>(password: <span style={{ color: "#f1fa8c" }}>"abc"</span>){"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Success!"</span>){"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>catch</span> <span style={{ color: "#8be9fd" }}>ValidationError</span>.tooShort(<span style={{ color: "#ff79c6" }}>let</span> min) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Password too short. Need </span>\(<span style={{ color: "#ff79c6" }}>min</span>)<span style={{ color: "#f1fa8c" }}>+ chars"</span>){"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>catch</span> <span style={{ color: "#8be9fd" }}>ValidationError</span>.tooLong {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Password too long"</span>){"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>catch</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Unexpected error: </span>\(<span style={{ color: "#ff79c6" }}>error</span>)<span style={{ color: "#f1fa8c" }}>"</span>)  <span style={{ color: "#6272a4" }}>// 'error' is implicit</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// try?: returns optional (nil on error)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> result = <span style={{ color: "#ff79c6" }}>try</span>? <span style={{ color: "#50fa7b" }}>validate</span>(password: <span style={{ color: "#f1fa8c" }}>"abc"</span>)  <span style={{ color: "#6272a4" }}>// nil</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// try!: force (crashes on error - use carefully!)</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// try! validate(password: "abc")  // Crash!</span>
              </Typography>
            </Paper>
          </Paper>

          {/* Generics Section */}
          <Paper id="generics" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#667EEA", 0.15), color: "#667EEA", width: 48, height: 48 }}>
                <AutoFixHighIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Generics
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
                <strong>Generics</strong> let you write flexible, reusable code that works with any type. Instead of writing separate functions for Int, String, Double, etc., you write one generic function. Think of it like a cookie cutter—same shape, works with any dough. Swift's Array, Dictionary, and Optional are all generic types!
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Generic Functions
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Without generics: need separate functions</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>swapInts</span>(_ a: <span style={{ color: "#ff79c6" }}>inout</span> <span style={{ color: "#8be9fd" }}>Int</span>, _ b: <span style={{ color: "#ff79c6" }}>inout</span> <span style={{ color: "#8be9fd" }}>Int</span>) {"{"} ... {"}"}{"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>swapStrings</span>(_ a: <span style={{ color: "#ff79c6" }}>inout</span> <span style={{ color: "#8be9fd" }}>String</span>, _ b: <span style={{ color: "#ff79c6" }}>inout</span> <span style={{ color: "#8be9fd" }}>String</span>) {"{"} ... {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// With generics: one function works for ANY type</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>swapValues</span>{"<"}<span style={{ color: "#8be9fd" }}>T</span>{">"}(_ a: <span style={{ color: "#ff79c6" }}>inout</span> <span style={{ color: "#8be9fd" }}>T</span>, _ b: <span style={{ color: "#ff79c6" }}>inout</span> <span style={{ color: "#8be9fd" }}>T</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> temp = a{"\n"}
                {"    "}a = b{"\n"}
                {"    "}b = temp{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> x = <span style={{ color: "#bd93f9" }}>5</span>, y = <span style={{ color: "#bd93f9" }}>10</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>swapValues</span>(&amp;x, &amp;y)  <span style={{ color: "#6272a4" }}>// T inferred as Int</span>{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> a = <span style={{ color: "#f1fa8c" }}>"hello"</span>, b = <span style={{ color: "#f1fa8c" }}>"world"</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>swapValues</span>(&amp;a, &amp;b)  <span style={{ color: "#6272a4" }}>// T inferred as String</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Type Constraints
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Constraining T to types that conform to Equatable</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>findIndex</span>{"<"}<span style={{ color: "#8be9fd" }}>T</span>: <span style={{ color: "#8be9fd" }}>Equatable</span>{">"}(of value: <span style={{ color: "#8be9fd" }}>T</span>, in array: [<span style={{ color: "#8be9fd" }}>T</span>]) -{">"} <span style={{ color: "#8be9fd" }}>Int</span>? {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>for</span> (index, item) <span style={{ color: "#ff79c6" }}>in</span> array.<span style={{ color: "#50fa7b" }}>enumerated</span>() {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>if</span> item == value {"{"}{"\n"}
                {"            "}<span style={{ color: "#ff79c6" }}>return</span> index{"\n"}
                {"        }"}{"\n"}
                {"    }"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#ff79c6" }}>nil</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> index = <span style={{ color: "#50fa7b" }}>findIndex</span>(of: <span style={{ color: "#bd93f9" }}>3</span>, in: [<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>4</span>])  <span style={{ color: "#6272a4" }}>// Optional(2)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// where clause for complex constraints</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>allEqual</span>{"<"}<span style={{ color: "#8be9fd" }}>T</span>{">"}(_ items: [<span style={{ color: "#8be9fd" }}>T</span>]) -{">"} <span style={{ color: "#8be9fd" }}>Bool</span> <span style={{ color: "#ff79c6" }}>where</span> <span style={{ color: "#8be9fd" }}>T</span>: <span style={{ color: "#8be9fd" }}>Equatable</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>guard let</span> first = items.first <span style={{ color: "#ff79c6" }}>else</span> {"{"} <span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#ff79c6" }}>true</span> {"}"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> items.<span style={{ color: "#50fa7b" }}>allSatisfy</span> {"{"} $0 == first {"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Generic Types
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Generic struct - Stack that works with any type</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>Stack</span>{"<"}<span style={{ color: "#8be9fd" }}>Element</span>{">"} {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>private var</span> items: [<span style={{ color: "#8be9fd" }}>Element</span>] = []{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>mutating func</span> <span style={{ color: "#50fa7b" }}>push</span>(_ item: <span style={{ color: "#8be9fd" }}>Element</span>) {"{"}{"\n"}
                {"        "}items.<span style={{ color: "#50fa7b" }}>append</span>(item){"\n"}
                {"    }"}{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>mutating func</span> <span style={{ color: "#50fa7b" }}>pop</span>() -{">"} <span style={{ color: "#8be9fd" }}>Element</span>? {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> items.<span style={{ color: "#50fa7b" }}>popLast</span>(){"\n"}
                {"    }"}{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> isEmpty: <span style={{ color: "#8be9fd" }}>Bool</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> items.isEmpty{"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> intStack = <span style={{ color: "#8be9fd" }}>Stack</span>{"<"}<span style={{ color: "#8be9fd" }}>Int</span>{">"}(){"\n"}
                intStack.<span style={{ color: "#50fa7b" }}>push</span>(<span style={{ color: "#bd93f9" }}>1</span>){"\n"}
                intStack.<span style={{ color: "#50fa7b" }}>push</span>(<span style={{ color: "#bd93f9" }}>2</span>){"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(intStack.<span style={{ color: "#50fa7b" }}>pop</span>())  <span style={{ color: "#6272a4" }}>// Optional(2)</span>
              </Typography>
            </Paper>
          </Paper>

          {/* Concurrency Section */}
          <Paper id="concurrency" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#319795", 0.15), color: "#319795", width: 48, height: 48 }}>
                <SyncIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Concurrency (async/await)
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
                Swift's modern concurrency (introduced in Swift 5.5) makes async code readable and safe. <strong>async</strong> marks functions that can pause, <strong>await</strong> suspends until a result is ready, and <strong>actors</strong> protect mutable state from data races. No more callback pyramids!
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#319795" }}>
              async/await Basics
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Async function - can pause without blocking</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>fetchUser</span>(id: <span style={{ color: "#8be9fd" }}>Int</span>) <span style={{ color: "#ff79c6" }}>async throws</span> -{">"} <span style={{ color: "#8be9fd" }}>User</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> url = URL(string: <span style={{ color: "#f1fa8c" }}>"https://api.example.com/users/</span>\(<span style={{ color: "#ff79c6" }}>id</span>)<span style={{ color: "#f1fa8c" }}>"</span>)!{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> (data, _) = <span style={{ color: "#ff79c6" }}>try await</span> <span style={{ color: "#8be9fd" }}>URLSession</span>.shared.<span style={{ color: "#50fa7b" }}>data</span>(from: url){"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return try</span> <span style={{ color: "#8be9fd" }}>JSONDecoder</span>().<span style={{ color: "#50fa7b" }}>decode</span>(<span style={{ color: "#8be9fd" }}>User</span>.<span style={{ color: "#ff79c6" }}>self</span>, from: data){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Calling async function</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>loadUserData</span>() <span style={{ color: "#ff79c6" }}>async</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>do</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>let</span> user = <span style={{ color: "#ff79c6" }}>try await</span> <span style={{ color: "#50fa7b" }}>fetchUser</span>(id: <span style={{ color: "#bd93f9" }}>123</span>){"\n"}
                {"        "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Loaded: </span>\(<span style={{ color: "#ff79c6" }}>user</span>.name)<span style={{ color: "#f1fa8c" }}>"</span>){"\n"}
                {"    }"} <span style={{ color: "#ff79c6" }}>catch</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Error: </span>\(<span style={{ color: "#ff79c6" }}>error</span>)<span style={{ color: "#f1fa8c" }}>"</span>){"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Create a task to call async code from sync context</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>Task</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>await</span> <span style={{ color: "#50fa7b" }}>loadUserData</span>(){"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#319795" }}>
              Parallel Execution
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Sequential: one after another</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> user1 = <span style={{ color: "#ff79c6" }}>try await</span> <span style={{ color: "#50fa7b" }}>fetchUser</span>(id: <span style={{ color: "#bd93f9" }}>1</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> user2 = <span style={{ color: "#ff79c6" }}>try await</span> <span style={{ color: "#50fa7b" }}>fetchUser</span>(id: <span style={{ color: "#bd93f9" }}>2</span>)  <span style={{ color: "#6272a4" }}>// Waits for user1 first</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Parallel: run concurrently with async let</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>async let</span> u1 = <span style={{ color: "#50fa7b" }}>fetchUser</span>(id: <span style={{ color: "#bd93f9" }}>1</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>async let</span> u2 = <span style={{ color: "#50fa7b" }}>fetchUser</span>(id: <span style={{ color: "#bd93f9" }}>2</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> users = <span style={{ color: "#ff79c6" }}>try await</span> [u1, u2]  <span style={{ color: "#6272a4" }}>// Both run in parallel!</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// TaskGroup for dynamic number of tasks</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> userIDs = [<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>4</span>, <span style={{ color: "#bd93f9" }}>5</span>]{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> allUsers = <span style={{ color: "#ff79c6" }}>try await</span> <span style={{ color: "#50fa7b" }}>withThrowingTaskGroup</span>(of: <span style={{ color: "#8be9fd" }}>User</span>.<span style={{ color: "#ff79c6" }}>self</span>) {"{"} group <span style={{ color: "#ff79c6" }}>in</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>for</span> id <span style={{ color: "#ff79c6" }}>in</span> userIDs {"{"}{"\n"}
                {"        "}group.<span style={{ color: "#50fa7b" }}>addTask</span> {"{"} <span style={{ color: "#ff79c6" }}>try await</span> <span style={{ color: "#50fa7b" }}>fetchUser</span>(id: id) {"}"}{"\n"}
                {"    }"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return try await</span> group.<span style={{ color: "#50fa7b" }}>reduce</span>(into: []) {"{"} $0.<span style={{ color: "#50fa7b" }}>append</span>($1) {"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#319795" }}>
              Actors (Thread-Safe State)
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Actor protects mutable state from data races</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>actor</span> <span style={{ color: "#8be9fd" }}>BankAccount</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>private var</span> balance: <span style={{ color: "#8be9fd" }}>Double</span>{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>init</span>(initialBalance: <span style={{ color: "#8be9fd" }}>Double</span>) {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>self</span>.balance = initialBalance{"\n"}
                {"    }"}{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>deposit</span>(_ amount: <span style={{ color: "#8be9fd" }}>Double</span>) {"{"}{"\n"}
                {"        "}balance += amount{"\n"}
                {"    }"}{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>getBalance</span>() -{">"} <span style={{ color: "#8be9fd" }}>Double</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> balance{"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> account = <span style={{ color: "#8be9fd" }}>BankAccount</span>(initialBalance: <span style={{ color: "#bd93f9" }}>1000</span>){"\n"}
                <span style={{ color: "#6272a4" }}>// Must await when accessing actor from outside</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>await</span> account.<span style={{ color: "#50fa7b" }}>deposit</span>(<span style={{ color: "#bd93f9" }}>500</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> balance = <span style={{ color: "#ff79c6" }}>await</span> account.<span style={{ color: "#50fa7b" }}>getBalance</span>()
              </Typography>
            </Paper>
          </Paper>

          {/* SwiftUI Section */}
          <Paper id="swiftui" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <PhoneIphoneIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                SwiftUI
              </Typography>
            </Box>

            <Box sx={{ bgcolor: alpha("#22c55e", 0.08), p: 3, borderRadius: 2, mb: 3, border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="h6" sx={{ fontWeight: 600, mb: 2, color: "#22c55e" }}>
                Beginner's Guide
              </Typography>
              <Typography variant="body2" sx={{ lineHeight: 1.9 }}>
                <strong>SwiftUI</strong> is Apple's declarative UI framework. Instead of imperatively telling the UI what to do step-by-step, you <em>declare</em> what the UI should look like based on state. When state changes, SwiftUI automatically updates the UI. It's like magic—and it works across all Apple platforms!
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Basic SwiftUI View
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>import</span> SwiftUI{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>ContentView</span>: <span style={{ color: "#8be9fd" }}>View</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> body: <span style={{ color: "#ff79c6" }}>some</span> <span style={{ color: "#8be9fd" }}>View</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>VStack</span>(spacing: <span style={{ color: "#bd93f9" }}>20</span>) {"{"}{"\n"}
                {"            "}<span style={{ color: "#8be9fd" }}>Text</span>(<span style={{ color: "#f1fa8c" }}>"Hello, SwiftUI!"</span>){"\n"}
                {"                "}.<span style={{ color: "#50fa7b" }}>font</span>(.largeTitle){"\n"}
                {"                "}.<span style={{ color: "#50fa7b" }}>foregroundColor</span>(.blue){"\n"}
                {"            "}{"\n"}
                {"            "}<span style={{ color: "#8be9fd" }}>Image</span>(systemName: <span style={{ color: "#f1fa8c" }}>"swift"</span>){"\n"}
                {"                "}.<span style={{ color: "#50fa7b" }}>font</span>(.system(size: <span style={{ color: "#bd93f9" }}>80</span>)){"\n"}
                {"                "}.<span style={{ color: "#50fa7b" }}>foregroundColor</span>(.orange){"\n"}
                {"            "}{"\n"}
                {"            "}<span style={{ color: "#8be9fd" }}>Button</span>(<span style={{ color: "#f1fa8c" }}>"Tap Me"</span>) {"{"}{"\n"}
                {"                "}<span style={{ color: "#50fa7b" }}>print</span>(<span style={{ color: "#f1fa8c" }}>"Button tapped!"</span>){"\n"}
                {"            }"}{"\n"}
                {"            "}.<span style={{ color: "#50fa7b" }}>buttonStyle</span>(.borderedProminent){"\n"}
                {"        }"}{"\n"}
                {"        "}.<span style={{ color: "#50fa7b" }}>padding</span>(){"\n"}
                {"    }"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              State Management
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>CounterView</span>: <span style={{ color: "#8be9fd" }}>View</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// @State: view-local mutable state</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>@State private var</span> count = <span style={{ color: "#bd93f9" }}>0</span>{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> body: <span style={{ color: "#ff79c6" }}>some</span> <span style={{ color: "#8be9fd" }}>View</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>VStack</span> {"{"}{"\n"}
                {"            "}<span style={{ color: "#8be9fd" }}>Text</span>(<span style={{ color: "#f1fa8c" }}>"Count: </span>\(<span style={{ color: "#ff79c6" }}>count</span>)<span style={{ color: "#f1fa8c" }}>"</span>){"\n"}
                {"                "}.<span style={{ color: "#50fa7b" }}>font</span>(.largeTitle){"\n"}
                {"            "}{"\n"}
                {"            "}<span style={{ color: "#8be9fd" }}>HStack</span> {"{"}{"\n"}
                {"                "}<span style={{ color: "#8be9fd" }}>Button</span>(<span style={{ color: "#f1fa8c" }}>"−"</span>) {"{"} count -= <span style={{ color: "#bd93f9" }}>1</span> {"}"}{"\n"}
                {"                "}<span style={{ color: "#8be9fd" }}>Button</span>(<span style={{ color: "#f1fa8c" }}>"+"</span>) {"{"} count += <span style={{ color: "#bd93f9" }}>1</span> {"}"}{"\n"}
                {"            }"}{"\n"}
                {"            "}.<span style={{ color: "#50fa7b" }}>buttonStyle</span>(.bordered){"\n"}
                {"        }"}{"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Other property wrappers:</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// @Binding: pass state to child views</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// @ObservedObject: observe external reference type</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// @EnvironmentObject: shared app-wide state</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// @StateObject: view-owned reference type</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Lists and Navigation
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>Item</span>: <span style={{ color: "#8be9fd" }}>Identifiable</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> id = UUID(){"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> name: <span style={{ color: "#8be9fd" }}>String</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>ItemListView</span>: <span style={{ color: "#8be9fd" }}>View</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> items = [<span style={{ color: "#8be9fd" }}>Item</span>(name: <span style={{ color: "#f1fa8c" }}>"Apple"</span>), <span style={{ color: "#8be9fd" }}>Item</span>(name: <span style={{ color: "#f1fa8c" }}>"Banana"</span>)]{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> body: <span style={{ color: "#ff79c6" }}>some</span> <span style={{ color: "#8be9fd" }}>View</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>NavigationStack</span> {"{"}{"\n"}
                {"            "}<span style={{ color: "#8be9fd" }}>List</span>(items) {"{"} item <span style={{ color: "#ff79c6" }}>in</span>{"\n"}
                {"                "}<span style={{ color: "#8be9fd" }}>NavigationLink</span>(item.name) {"{"}{"\n"}
                {"                    "}<span style={{ color: "#8be9fd" }}>Text</span>(<span style={{ color: "#f1fa8c" }}>"Detail for </span>\(<span style={{ color: "#ff79c6" }}>item</span>.name)<span style={{ color: "#f1fa8c" }}>"</span>){"\n"}
                {"                }"}{"\n"}
                {"            }"}{"\n"}
                {"            "}.<span style={{ color: "#50fa7b" }}>navigationTitle</span>(<span style={{ color: "#f1fa8c" }}>"Fruits"</span>){"\n"}
                {"        }"}{"\n"}
                {"    }"}{"\n"}
                {"}"}
              </Typography>
            </Paper>
          </Paper>

          {/* Advanced Topics Section */}
          <Paper id="advanced" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#6B46C1", 0.15), color: "#6B46C1", width: 48, height: 48 }}>
                <DeveloperBoardIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Advanced Topics
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#6B46C1" }}>
              Memory Management (ARC)
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Strong reference (default) - keeps object alive</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Person</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> name: <span style={{ color: "#8be9fd" }}>String</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> apartment: <span style={{ color: "#8be9fd" }}>Apartment</span>?  <span style={{ color: "#6272a4" }}>// Strong reference</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>init</span>(name: <span style={{ color: "#8be9fd" }}>String</span>) {"{"} <span style={{ color: "#ff79c6" }}>self</span>.name = name {"}"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Apartment</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> number: <span style={{ color: "#8be9fd" }}>Int</span>{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// weak reference - doesn't keep Person alive</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>weak var</span> tenant: <span style={{ color: "#8be9fd" }}>Person</span>?  <span style={{ color: "#6272a4" }}>// Must be optional</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>init</span>(number: <span style={{ color: "#8be9fd" }}>Int</span>) {"{"} <span style={{ color: "#ff79c6" }}>self</span>.number = number {"}"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// In closures, capture self weakly to avoid retain cycles</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>ViewController</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>loadData</span>() {"{"}{"\n"}
                {"        "}<span style={{ color: "#50fa7b" }}>fetchData</span> {"{"} [<span style={{ color: "#ff79c6" }}>weak self</span>] data <span style={{ color: "#ff79c6" }}>in</span>{"\n"}
                {"            "}<span style={{ color: "#ff79c6" }}>guard let self</span> <span style={{ color: "#ff79c6" }}>else</span> {"{"} <span style={{ color: "#ff79c6" }}>return</span> {"}"}{"\n"}
                {"            "}<span style={{ color: "#ff79c6" }}>self</span>.<span style={{ color: "#50fa7b" }}>updateUI</span>(with: data){"\n"}
                {"        }"}{"\n"}
                {"    }"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#6B46C1" }}>
              Property Wrappers
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Custom property wrapper</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>@propertyWrapper</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>Clamped</span>{"<"}<span style={{ color: "#8be9fd" }}>Value</span>: <span style={{ color: "#8be9fd" }}>Comparable</span>{">"} {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> value: <span style={{ color: "#8be9fd" }}>Value</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> range: <span style={{ color: "#8be9fd" }}>ClosedRange</span>{"<"}<span style={{ color: "#8be9fd" }}>Value</span>{">"}{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> wrappedValue: <span style={{ color: "#8be9fd" }}>Value</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>get</span> {"{"} value {"}"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>set</span> {"{"} value = <span style={{ color: "#50fa7b" }}>min</span>(<span style={{ color: "#50fa7b" }}>max</span>(newValue, range.lowerBound), range.upperBound) {"}"}{"\n"}
                {"    }"}{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>init</span>(wrappedValue: <span style={{ color: "#8be9fd" }}>Value</span>, _ range: <span style={{ color: "#8be9fd" }}>ClosedRange</span>{"<"}<span style={{ color: "#8be9fd" }}>Value</span>{">"}) {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>self</span>.range = range{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>self</span>.value = <span style={{ color: "#50fa7b" }}>min</span>(<span style={{ color: "#50fa7b" }}>max</span>(wrappedValue, range.lowerBound), range.upperBound){"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>Player</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>@Clamped</span>(<span style={{ color: "#bd93f9" }}>0</span>...<span style={{ color: "#bd93f9" }}>100</span>) <span style={{ color: "#ff79c6" }}>var</span> health: <span style={{ color: "#8be9fd" }}>Int</span> = <span style={{ color: "#bd93f9" }}>100</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> player = <span style={{ color: "#8be9fd" }}>Player</span>(){"\n"}
                player.health = <span style={{ color: "#bd93f9" }}>150</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(player.health)  <span style={{ color: "#6272a4" }}>// 100 (clamped!)</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#6B46C1" }}>
              Result Builders (DSL)
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Result builders power SwiftUI's declarative syntax</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// This is how VStack {"{"} Text() Text() {"}"} works!</span>{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>@resultBuilder</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>StringBuilder</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>static func</span> <span style={{ color: "#50fa7b" }}>buildBlock</span>(_ parts: <span style={{ color: "#8be9fd" }}>String</span>...) -{">"} <span style={{ color: "#8be9fd" }}>String</span> {"{"}{"\n"}
                {"        "}parts.<span style={{ color: "#50fa7b" }}>joined</span>(separator: <span style={{ color: "#f1fa8c" }}>" "</span>){"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>func</span> <span style={{ color: "#50fa7b" }}>makeSentence</span>(<span style={{ color: "#ff79c6" }}>@StringBuilder</span> _ content: () -{">"} <span style={{ color: "#8be9fd" }}>String</span>) -{">"} <span style={{ color: "#8be9fd" }}>String</span> {"{"}{"\n"}
                {"    "}content(){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> sentence = <span style={{ color: "#50fa7b" }}>makeSentence</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>"Hello"</span>{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>"Swift"</span>{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>"World"</span>{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#50fa7b" }}>print</span>(sentence)  <span style={{ color: "#6272a4" }}>// "Hello Swift World"</span>
              </Typography>
            </Paper>
          </Paper>

          {/* Quiz Section */}
          <Paper id="quiz" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <QuizIcon />
              </Avatar>
              <Box>
                <Typography variant="h5" sx={{ fontWeight: 800 }}>
                  Swift Knowledge Quiz
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Test your understanding with 10 randomly selected questions from our 75-question bank
                </Typography>
              </Box>
            </Box>
            <SwiftQuiz />
          </Paper>

          {/* Bottom Navigation */}
          <Box sx={{ mt: 4, textAlign: "center" }}>
            <Button
              variant="outlined"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate("/learn")}
              sx={{ borderColor: "#8b5cf6", color: "#8b5cf6" }}
            >
              Back to Learning Hub
            </Button>
          </Box>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
