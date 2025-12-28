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

          {/* Remaining sections as placeholders */}
          <TopicPlaceholder
            id="operators"
            title="Operators & Expressions"
            icon={<SwapHorizIcon />}
            color={accentColor}
            description="Arithmetic, comparison, logical, range operators (..., ..<), nil coalescing (??), optional chaining (?.), and custom operator overloading."
          />

          <TopicPlaceholder
            id="functions"
            title="Functions & Closures"
            icon={<ExtensionIcon />}
            color={accentColor}
            description="Function syntax, argument labels, default values, variadic parameters, inout parameters, closures (trailing syntax, capturing values), and higher-order functions."
          />

          <TopicPlaceholder
            id="optionals"
            title="Optionals"
            icon={<SecurityIcon />}
            color={accentColor}
            description="Deep dive into optionals: optional binding (if let, guard let), optional chaining, nil coalescing, force unwrapping, implicitly unwrapped optionals, and best practices."
          />

          <TopicPlaceholder
            id="collections"
            title="Collections"
            icon={<StorageIcon />}
            color={accentColor}
            description="Arrays, Sets, Dictionaries, collection operations (map, filter, reduce, compactMap, flatMap), subscripts, and iterating collections."
          />

          <TopicPlaceholder
            id="structs"
            title="Structs & Classes"
            icon={<ClassIcon />}
            color={accentColor}
            description="Value types vs reference types, properties (stored, computed, lazy, observers), methods, initializers, deinit, inheritance, and when to use struct vs class."
          />

          <TopicPlaceholder
            id="enums"
            title="Enumerations"
            icon={<ViewModuleIcon />}
            color={accentColor}
            description="Enum basics, raw values, associated values, recursive enums, pattern matching with enums, and using enums to model state."
          />

          <TopicPlaceholder
            id="protocols"
            title="Protocols"
            icon={<LayersIcon />}
            color={accentColor}
            description="Protocol declaration, protocol conformance, protocol extensions with default implementations, protocol-oriented programming, and common protocols (Equatable, Hashable, Codable)."
          />

          <TopicPlaceholder
            id="error-handling"
            title="Error Handling"
            icon={<BugReportIcon />}
            color={accentColor}
            description="Throwing functions, do-catch, try/try?/try!, error propagation, defining custom errors, and Result type."
          />

          <TopicPlaceholder
            id="generics"
            title="Generics"
            icon={<AutoFixHighIcon />}
            color={accentColor}
            description="Generic functions, generic types, type constraints, associated types, where clauses, and building reusable, type-safe code."
          />

          <TopicPlaceholder
            id="concurrency"
            title="Concurrency"
            icon={<SyncIcon />}
            color={accentColor}
            description="async/await, Task, TaskGroup, actors for data isolation, MainActor, Sendable protocol, structured concurrency, and migrating from GCD/completion handlers."
          />

          <TopicPlaceholder
            id="swiftui"
            title="SwiftUI"
            icon={<PhoneIphoneIcon />}
            color={accentColor}
            description="Declarative UI with SwiftUI: Views, @State, @Binding, @ObservedObject, @EnvironmentObject, navigation, animations, and building multi-platform apps."
          />

          <TopicPlaceholder
            id="advanced"
            title="Advanced Topics"
            icon={<DeveloperBoardIcon />}
            color={accentColor}
            description="Memory management (ARC, strong/weak/unowned), opaque types (some), property wrappers, result builders, macros (Swift 5.9+), and interoperability with Objective-C."
          />

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
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
