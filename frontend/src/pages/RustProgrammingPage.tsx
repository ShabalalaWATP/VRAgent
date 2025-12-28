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
  Button,
  Radio,
  RadioGroup,
  FormControlLabel,
  FormControl,
  LinearProgress,
} from "@mui/material";
import QuizIcon from "@mui/icons-material/Quiz";
import RestartAltIcon from "@mui/icons-material/RestartAlt";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
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
import LearnPageLayout from "../components/LearnPageLayout";

const accentColor = "#DEA584"; // Rust's official orange/copper color
const accentColorDark = "#B7410E"; // Rust darker shade

// Module navigation items for sidebar
const moduleNavItems = [
  { id: "introduction", label: "Introduction", icon: <SchoolIcon /> },
  { id: "history", label: "History & Philosophy", icon: <HistoryIcon /> },
  { id: "setup", label: "Environment Setup", icon: <BuildIcon /> },
  { id: "basics", label: "Rust Basics & Syntax", icon: <CodeIcon /> },
  { id: "ownership", label: "Ownership & Borrowing", icon: <LockIcon /> },
  { id: "types", label: "Types & Data Structures", icon: <DataObjectIcon /> },
  { id: "structs-enums", label: "Structs & Enums", icon: <CategoryIcon /> },
  { id: "pattern-matching", label: "Pattern Matching", icon: <SwapHorizIcon /> },
  { id: "error-handling", label: "Error Handling", icon: <BugReportIcon /> },
  { id: "traits", label: "Traits & Generics", icon: <ExtensionIcon /> },
  { id: "lifetimes", label: "Lifetimes", icon: <TimelineIcon /> },
  { id: "modules", label: "Modules & Crates", icon: <ViewModuleIcon /> },
  { id: "testing", label: "Testing", icon: <SpeedIcon /> },
  { id: "concurrency", label: "Concurrency", icon: <SyncIcon /> },
  { id: "unsafe", label: "Unsafe Rust", icon: <WarningIcon /> },
  { id: "web", label: "Web Development", icon: <HttpIcon /> },
  { id: "cli", label: "CLI Applications", icon: <TerminalIcon /> },
  { id: "advanced", label: "Advanced Topics", icon: <DeveloperBoardIcon /> },
  { id: "quiz", label: "Knowledge Quiz", icon: <QuizIcon /> },
];

// Quick stats for hero section
const quickStats = [
  { label: "Created", value: "2010", color: "#DEA584" },
  { label: "Creator", value: "Mozilla", color: "#E66000" },
  { label: "Paradigm", value: "Systems", color: "#4A90D9" },
  { label: "Latest Ver", value: "1.75+", color: "#48BB78" },
];

// Quiz question bank (75 questions)
interface QuizQuestion {
  question: string;
  options: string[];
  correct: number;
  explanation: string;
}

const questionBank: QuizQuestion[] = [
  // Basics & Syntax (1-15)
  { question: "What keyword is used to declare an immutable variable in Rust?", options: ["var", "let", "const", "mut"], correct: 1, explanation: "'let' declares variables. By default, they are immutable unless 'mut' is added." },
  { question: "How do you make a variable mutable in Rust?", options: ["mutable x", "var x", "let mut x", "let x = mutable"], correct: 2, explanation: "Use 'let mut x' to declare a mutable variable." },
  { question: "What is the Rust compiler called?", options: ["gcc", "rustc", "cargo", "llvm"], correct: 1, explanation: "rustc is the Rust compiler, though most developers use cargo which calls rustc internally." },
  { question: "What file extension do Rust source files use?", options: [".rust", ".rs", ".rt", ".r"], correct: 1, explanation: "Rust source files use the .rs extension." },
  { question: "How do you print 'Hello' to the console?", options: ["print('Hello')", "console.log('Hello')", "println!(\"Hello\")", "echo 'Hello'"], correct: 2, explanation: "println! is a macro (note the !) that prints to stdout with a newline." },
  { question: "What does the '!' after println indicate?", options: ["It's a function", "It's a macro", "It's a method", "It's deprecated"], correct: 1, explanation: "The ! indicates a macro invocation, not a regular function call." },
  { question: "Which type is a 32-bit signed integer?", options: ["int", "i32", "int32", "s32"], correct: 1, explanation: "i32 is a 32-bit signed integer. Rust uses explicit bit sizes: i8, i16, i32, i64, i128." },
  { question: "What is the default integer type in Rust?", options: ["i64", "int", "i32", "isize"], correct: 2, explanation: "If you don't specify, integer literals default to i32." },
  { question: "How do you create a constant in Rust?", options: ["const X = 5", "let const X = 5", "const X: i32 = 5", "constant X = 5"], correct: 2, explanation: "Constants require type annotation: const X: i32 = 5;" },
  { question: "What is the boolean type in Rust?", options: ["boolean", "Boolean", "bool", "bit"], correct: 2, explanation: "Rust uses 'bool' for boolean values (true/false)." },
  { question: "How do you write an infinite loop?", options: ["while(true) {}", "for(;;) {}", "loop {}", "infinite {}"], correct: 2, explanation: "Rust has a dedicated 'loop' keyword for infinite loops." },
  { question: "What keyword exits a loop early?", options: ["exit", "stop", "break", "return"], correct: 2, explanation: "'break' exits a loop. You can also use 'break value' to return a value from a loop." },
  { question: "What is the range syntax for 1 to 5 (inclusive)?", options: ["1..5", "1...5", "1..=5", "[1,5]"], correct: 2, explanation: "1..=5 is inclusive (1,2,3,4,5). 1..5 is exclusive (1,2,3,4)." },
  { question: "How do you write a function that returns i32?", options: ["fn foo() -> i32", "fn foo(): i32", "fn foo() returns i32", "function foo() -> i32"], correct: 0, explanation: "fn name() -> ReturnType is the syntax. Use -> for return types." },
  { question: "What happens if you don't use a semicolon on the last expression?", options: ["Syntax error", "It's returned", "It's ignored", "Compiler warning"], correct: 1, explanation: "The last expression without a semicolon becomes the return value." },
  
  // Ownership & Borrowing (16-30)
  { question: "What is Rust's primary memory management strategy?", options: ["Garbage collection", "Manual malloc/free", "Ownership system", "Reference counting"], correct: 2, explanation: "Rust uses an ownership system checked at compile time, with no runtime GC." },
  { question: "How many owners can a value have at once?", options: ["Unlimited", "Two", "One", "Zero"], correct: 2, explanation: "Each value has exactly one owner. When the owner goes out of scope, the value is dropped." },
  { question: "What happens when you assign a String to another variable?", options: ["Copy", "Move", "Clone", "Reference"], correct: 1, explanation: "String is moved (not copied). The original variable becomes invalid." },
  { question: "Which types implement Copy trait automatically?", options: ["String, Vec", "i32, bool, f64", "All types", "No types"], correct: 1, explanation: "Simple scalar types like integers, bools, floats, and char implement Copy." },
  { question: "What symbol creates an immutable reference?", options: ["*", "&", "@", "#"], correct: 1, explanation: "&x creates an immutable reference (borrow) to x." },
  { question: "What is &mut used for?", options: ["Immutable reference", "Mutable reference", "Pointer dereference", "Type annotation"], correct: 1, explanation: "&mut creates a mutable reference, allowing modification of the borrowed value." },
  { question: "How many mutable references can exist at once?", options: ["Unlimited", "Two", "One", "Zero"], correct: 2, explanation: "Only ONE mutable reference can exist at a time (prevents data races)." },
  { question: "Can you have mutable and immutable references simultaneously?", options: ["Yes", "No", "Only in unsafe", "Only with Arc"], correct: 1, explanation: "No! You can have multiple &T OR one &mut T, but not both." },
  { question: "What is a 'dangling reference'?", options: ["A circular reference", "A reference to freed memory", "A null pointer", "An unused reference"], correct: 1, explanation: "A dangling reference points to memory that has been freed. Rust prevents these at compile time." },
  { question: "What does 'borrowing' mean in Rust?", options: ["Copying data", "Taking ownership", "Creating a reference", "Allocating memory"], correct: 2, explanation: "Borrowing means creating a reference to data without taking ownership." },
  { question: "When is a value 'dropped' in Rust?", options: ["When manually freed", "When reference count hits 0", "When owner goes out of scope", "Never automatically"], correct: 2, explanation: "Values are dropped when their owner goes out of scope (RAII pattern)." },
  { question: "What is a 'slice' in Rust?", options: ["A copy of part of a collection", "A reference to a contiguous sequence", "A new vector", "A string type"], correct: 1, explanation: "A slice is a reference to a contiguous sequence of elements, like &[i32] or &str." },
  { question: "What type is a string literal like \"hello\"?", options: ["String", "str", "&str", "&String"], correct: 2, explanation: "String literals are &str (string slices), stored in the binary." },
  { question: "How do you get a &str from a String?", options: ["s.to_str()", "&s or s.as_str()", "s.slice()", "str(s)"], correct: 1, explanation: "Use &s (deref coercion) or s.as_str() to get a &str from String." },
  { question: "What does .clone() do?", options: ["Creates a reference", "Moves the value", "Creates a deep copy", "Nothing"], correct: 2, explanation: ".clone() creates a deep copy of the data. Use sparingly as it can be expensive." },
  
  // Types & Data Structures (31-40)
  { question: "How do you create a vector?", options: ["Vector::new()", "vec![]", "new Vec()", "[]"], correct: 1, explanation: "Use vec![] macro or Vec::new() to create vectors." },
  { question: "What is the type of vec![1, 2, 3]?", options: ["[i32]", "Vec<i32>", "Array<i32>", "List<i32>"], correct: 1, explanation: "Vectors are Vec<T>. vec![1,2,3] creates a Vec<i32>." },
  { question: "How do you access element at index 2 safely?", options: ["v[2]", "v.get(2)", "v.at(2)", "v->2"], correct: 1, explanation: "v.get(2) returns Option<&T>, while v[2] panics if out of bounds." },
  { question: "What is a tuple in Rust?", options: ["A resizable array", "A fixed-size collection of different types", "A key-value store", "A linked list"], correct: 1, explanation: "Tuples group different types: (i32, f64, bool). Fixed size, known at compile time." },
  { question: "How do you access the second element of a tuple?", options: ["t[1]", "t.1", "t.get(1)", "t->1"], correct: 1, explanation: "Use dot notation: t.0, t.1, t.2, etc." },
  { question: "What is the 'unit type' in Rust?", options: ["null", "void", "()", "None"], correct: 2, explanation: "() is the unit type, similar to void. Functions that don't return anything return ()." },
  { question: "How do you create a HashMap?", options: ["HashMap::new()", "map!{}", "new HashMap()", "{}"], correct: 0, explanation: "Use HashMap::new() or collect() from an iterator. Need 'use std::collections::HashMap'." },
  { question: "What does Option<T> represent?", options: ["An error type", "A nullable value", "A result type", "A reference"], correct: 1, explanation: "Option<T> is Some(value) or None, used for values that might be absent." },
  { question: "What are the variants of Result<T, E>?", options: ["Some/None", "Ok/Err", "True/False", "Success/Failure"], correct: 1, explanation: "Result<T, E> has Ok(T) for success and Err(E) for errors." },
  { question: "What is the 'turbofish' syntax?", options: ["::<>", "->", "=>", "<>"], correct: 0, explanation: "Turbofish ::<Type> specifies generic types: \"5\".parse::<i32>()" },
  
  // Structs & Enums (41-48)
  { question: "How do you define a struct?", options: ["class Foo {}", "struct Foo {}", "type Foo = {}", "object Foo {}"], correct: 1, explanation: "Use 'struct Name { field: Type }' to define structs." },
  { question: "What is a 'tuple struct'?", options: ["A struct inside a tuple", "A struct with named fields", "A struct with unnamed fields", "A generic struct"], correct: 2, explanation: "Tuple structs have fields without names: struct Color(u8, u8, u8);" },
  { question: "Where do you implement methods for a struct?", options: ["Inside the struct", "In an impl block", "In a class block", "In a module"], correct: 1, explanation: "Use 'impl StructName { fn method(&self) {...} }' to add methods." },
  { question: "What does &self mean in a method?", options: ["Takes ownership", "Immutable borrow of instance", "Mutable borrow", "Static method"], correct: 1, explanation: "&self is shorthand for self: &Self, an immutable reference to the instance." },
  { question: "How do you define an enum with data?", options: ["enum { A(i32) }", "enum E { A(i32) }", "enum E = A(i32)", "enum { A: i32 }"], correct: 1, explanation: "Enum variants can hold data: enum E { A(i32), B(String), C { x: i32 } }" },
  { question: "What is Option<T> defined as?", options: ["struct Option { some: T, none: bool }", "enum Option<T> { Some(T), None }", "type Option<T> = T | null", "trait Option<T>"], correct: 1, explanation: "Option is an enum: enum Option<T> { Some(T), None }" },
  { question: "How do you create an instance with struct update syntax?", options: ["Foo { x: 1, ...other }", "Foo { x: 1, ..other }", "Foo { x: 1 }.extend(other)", "Foo::from(other, x: 1)"], correct: 1, explanation: "Use ..other to copy remaining fields: Foo { x: 1, ..other }" },
  { question: "What does #[derive(Debug)] do?", options: ["Enables debugging", "Auto-implements Debug trait", "Adds breakpoints", "Logs to console"], correct: 1, explanation: "#[derive(Debug)] auto-generates Debug trait, enabling {:?} formatting." },
  
  // Pattern Matching & Error Handling (49-56)
  { question: "What keyword is used for pattern matching?", options: ["switch", "case", "match", "when"], correct: 2, explanation: "'match' is Rust's powerful pattern matching expression." },
  { question: "Must match expressions be exhaustive?", options: ["No", "Yes", "Only for enums", "Only with _"], correct: 1, explanation: "Yes! match must cover all possible values. Use _ as a catch-all." },
  { question: "What does 'if let' do?", options: ["Conditional variable", "Match single pattern", "Loop construct", "Error handling"], correct: 1, explanation: "'if let' matches a single pattern, useful when you only care about one case." },
  { question: "What does the ? operator do?", options: ["Null coalescing", "Propagates errors", "Optional chaining", "Pattern matching"], correct: 1, explanation: "? propagates errors: returns early with Err if Result is Err, otherwise unwraps Ok." },
  { question: "What does .unwrap() do on Option?", options: ["Returns None", "Panics if None, returns value if Some", "Returns default", "Creates clone"], correct: 1, explanation: ".unwrap() returns the value or panics if None/Err. Use carefully!" },
  { question: "What is a safer alternative to unwrap()?", options: [".get()", ".unwrap_or(default)", ".take()", ".extract()"], correct: 1, explanation: ".unwrap_or(default) returns the value or a default, never panics." },
  { question: "How do you cause a panic intentionally?", options: ["throw", "raise", "panic!()", "abort()"], correct: 2, explanation: "panic!(\"message\") immediately crashes the program (or unwinds the stack)." },
  { question: "What does @ do in patterns?", options: ["At operator", "Binds value while matching", "Reference operator", "Dereference"], correct: 1, explanation: "@ binds a value while matching: Some(x @ 1..=5) captures x if 1-5." },
  
  // Traits & Generics (57-64)
  { question: "What is a trait in Rust?", options: ["A class", "Shared behavior definition", "A macro", "A module"], correct: 1, explanation: "Traits define shared behavior, similar to interfaces in other languages." },
  { question: "How do you implement a trait for a type?", options: ["type: Trait", "impl Trait for Type {}", "Type implements Trait", "extend Type with Trait"], correct: 1, explanation: "Use 'impl TraitName for TypeName { methods... }'" },
  { question: "What does <T: Clone> mean?", options: ["T is Clone type", "T must implement Clone", "T is cloned", "T is generic Clone"], correct: 1, explanation: "This is a trait bound: T must implement the Clone trait." },
  { question: "What is 'impl Trait' syntax used for?", options: ["Trait implementation", "Return type abstraction", "Generic bounds", "All of the above"], correct: 3, explanation: "'impl Trait' is used in function parameters and return types to abstract concrete types." },
  { question: "What does 'dyn Trait' indicate?", options: ["Dynamic typing", "Trait object (dynamic dispatch)", "Derived trait", "Default trait"], correct: 1, explanation: "'dyn Trait' creates a trait object using dynamic dispatch via vtable." },
  { question: "What is monomorphization?", options: ["Runtime polymorphism", "Compile-time generic specialization", "Type erasure", "Memory optimization"], correct: 1, explanation: "Compiler generates specialized code for each concrete type used with generics." },
  { question: "Which trait enables == comparison?", options: ["Eq", "PartialEq", "Compare", "Equal"], correct: 1, explanation: "PartialEq enables == and !=. Eq extends it for total equality (reflexive)." },
  { question: "What does the From trait do?", options: ["Formats output", "Converts from another type", "Iterates", "Compares"], correct: 1, explanation: "From<T> enables conversion: let s: String = String::from(\"hello\");" },
  
  // Lifetimes & Memory (65-70)
  { question: "What does a lifetime parameter like 'a represent?", options: ["A type parameter", "How long a reference is valid", "A variable name", "An error type"], correct: 1, explanation: "Lifetimes describe how long references are valid, preventing dangling references." },
  { question: "What is the 'static lifetime?", options: ["Static variable lifetime", "Entire program duration", "Function scope", "Module scope"], correct: 1, explanation: "'static means the reference is valid for the entire program (e.g., string literals)." },
  { question: "What is lifetime elision?", options: ["Removing lifetimes", "Compiler inferring lifetimes", "Lifetime errors", "Short lifetimes"], correct: 1, explanation: "Elision rules let the compiler infer lifetimes in common patterns, reducing annotation." },
  { question: "What does Box<T> do?", options: ["Creates a copy", "Heap allocates with ownership", "Creates a reference", "Wraps in Option"], correct: 1, explanation: "Box<T> allocates T on the heap with single ownership. Useful for recursive types." },
  { question: "What is Rc<T> used for?", options: ["Thread-safe sharing", "Single-threaded reference counting", "Raw pointers", "Runtime checks"], correct: 1, explanation: "Rc<T> enables multiple owners via reference counting (single-threaded only)." },
  { question: "What is Arc<T>?", options: ["Array container", "Atomic reference counting", "Async runtime", "Archive type"], correct: 1, explanation: "Arc<T> is Atomic Rc - thread-safe reference counting for shared ownership." },
  
  // Concurrency & Advanced (71-75)
  { question: "What trait must types implement to be sent between threads?", options: ["Sync", "Send", "Transfer", "Thread"], correct: 1, explanation: "Send indicates a type can be transferred to another thread." },
  { question: "What does Mutex<T> provide?", options: ["Read-only access", "Mutual exclusion for safe mutation", "Message passing", "Async execution"], correct: 1, explanation: "Mutex provides interior mutability with locking for thread-safe mutation." },
  { question: "What does async/await enable?", options: ["Multi-threading", "Asynchronous programming", "Garbage collection", "Dynamic typing"], correct: 1, explanation: "async/await enables writing asynchronous code that looks synchronous." },
  { question: "What is 'unsafe' used for in Rust?", options: ["Marking bugs", "Bypassing some compiler checks", "Error handling", "Testing"], correct: 1, explanation: "unsafe blocks allow operations the compiler can't verify as safe (raw pointers, FFI, etc.)." },
  { question: "What is a procedural macro?", options: ["A function-like macro", "Code that generates code at compile time", "A debugging tool", "A type alias"], correct: 1, explanation: "Procedural macros are Rust code that manipulates syntax trees at compile time." },
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

// Quiz Component
function QuizComponent() {
  const [quizStarted, setQuizStarted] = useState(false);
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [selectedAnswer, setSelectedAnswer] = useState<number | null>(null);
  const [showResult, setShowResult] = useState(false);
  const [score, setScore] = useState(0);
  const [answers, setAnswers] = useState<(number | null)[]>([]);
  const [quizComplete, setQuizComplete] = useState(false);

  // Randomly select 10 questions from the bank
  const quizQuestions = useMemo(() => {
    const shuffled = [...questionBank].sort(() => Math.random() - 0.5);
    return shuffled.slice(0, 10);
  }, [quizStarted]);

  const handleStartQuiz = () => {
    setQuizStarted(true);
    setCurrentQuestion(0);
    setSelectedAnswer(null);
    setShowResult(false);
    setScore(0);
    setAnswers([]);
    setQuizComplete(false);
  };

  const handleAnswerSelect = (index: number) => {
    if (!showResult) {
      setSelectedAnswer(index);
    }
  };

  const handleSubmitAnswer = () => {
    if (selectedAnswer === null) return;
    
    setShowResult(true);
    const newAnswers = [...answers, selectedAnswer];
    setAnswers(newAnswers);
    
    if (selectedAnswer === quizQuestions[currentQuestion].correct) {
      setScore(score + 1);
    }
  };

  const handleNextQuestion = () => {
    if (currentQuestion < 9) {
      setCurrentQuestion(currentQuestion + 1);
      setSelectedAnswer(null);
      setShowResult(false);
    } else {
      setQuizComplete(true);
    }
  };

  const getScoreColor = () => {
    const percentage = (score / 10) * 100;
    if (percentage >= 80) return "#48BB78";
    if (percentage >= 60) return "#ECC94B";
    return "#FC8181";
  };

  const getScoreMessage = () => {
    const percentage = (score / 10) * 100;
    if (percentage === 100) return "🎉 Perfect Score! You're a Rust master!";
    if (percentage >= 80) return "🌟 Excellent! You know Rust well!";
    if (percentage >= 60) return "👍 Good job! Keep practicing!";
    if (percentage >= 40) return "📚 Not bad, but review the material!";
    return "💪 Keep studying! Rust takes time to master.";
  };

  if (!quizStarted) {
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <EmojiEventsIcon sx={{ fontSize: 64, color: accentColor, mb: 2 }} />
        <Typography variant="h6" sx={{ mb: 2, fontWeight: 700 }}>
          Ready to Test Your Rust Knowledge?
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          10 questions randomly selected from a bank of 75 covering all topics.
          <br />
          No time limit — take your time and learn!
        </Typography>
        <Button
          variant="contained"
          size="large"
          onClick={handleStartQuiz}
          startIcon={<QuizIcon />}
          sx={{
            bgcolor: accentColor,
            "&:hover": { bgcolor: accentColorDark },
            px: 4,
            py: 1.5,
            fontWeight: 700,
            borderRadius: 2,
          }}
        >
          Start Quiz
        </Button>
      </Box>
    );
  }

  if (quizComplete) {
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <Box
          sx={{
            width: 120,
            height: 120,
            borderRadius: "50%",
            bgcolor: alpha(getScoreColor(), 0.15),
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            mx: "auto",
            mb: 3,
          }}
        >
          <Typography variant="h3" sx={{ fontWeight: 800, color: getScoreColor() }}>
            {score}/10
          </Typography>
        </Box>
        <Typography variant="h6" sx={{ mb: 1, fontWeight: 700 }}>
          {getScoreMessage()}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          You got {score} out of 10 questions correct ({(score / 10) * 100}%)
        </Typography>

        <Divider sx={{ my: 3 }} />

        <Typography variant="subtitle2" sx={{ mb: 2, fontWeight: 700, textAlign: "left" }}>
          Review Your Answers:
        </Typography>
        <Box sx={{ textAlign: "left", mb: 3 }}>
          {quizQuestions.map((q, idx) => (
            <Paper
              key={idx}
              sx={{
                p: 2,
                mb: 2,
                borderRadius: 2,
                bgcolor: answers[idx] === q.correct ? alpha("#48BB78", 0.1) : alpha("#FC8181", 0.1),
                borderLeft: `4px solid ${answers[idx] === q.correct ? "#48BB78" : "#FC8181"}`,
              }}
            >
              <Typography variant="body2" sx={{ fontWeight: 600, mb: 1 }}>
                {idx + 1}. {q.question}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Your answer: <strong>{q.options[answers[idx] ?? 0]}</strong>
                {answers[idx] !== q.correct && (
                  <> · Correct: <strong style={{ color: "#48BB78" }}>{q.options[q.correct]}</strong></>
                )}
              </Typography>
              <Typography variant="caption" sx={{ display: "block", mt: 0.5, fontStyle: "italic" }}>
                {q.explanation}
              </Typography>
            </Paper>
          ))}
        </Box>

        <Button
          variant="contained"
          onClick={handleStartQuiz}
          startIcon={<RestartAltIcon />}
          sx={{
            bgcolor: accentColor,
            "&:hover": { bgcolor: accentColorDark },
            px: 4,
            fontWeight: 700,
            borderRadius: 2,
          }}
        >
          Try Again (New Questions)
        </Button>
      </Box>
    );
  }

  const currentQ = quizQuestions[currentQuestion];

  return (
    <Box>
      {/* Progress */}
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1 }}>
          <Typography variant="body2" color="text.secondary">
            Question {currentQuestion + 1} of 10
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Score: {score}/{currentQuestion + (showResult ? 1 : 0)}
          </Typography>
        </Box>
        <LinearProgress
          variant="determinate"
          value={(currentQuestion + (showResult ? 1 : 0)) * 10}
          sx={{
            height: 8,
            borderRadius: 4,
            bgcolor: alpha(accentColor, 0.1),
            "& .MuiLinearProgress-bar": {
              bgcolor: accentColor,
              borderRadius: 4,
            },
          }}
        />
      </Box>

      {/* Question */}
      <Typography variant="h6" sx={{ mb: 3, fontWeight: 700 }}>
        {currentQ.question}
      </Typography>

      {/* Options */}
      <FormControl component="fieldset" sx={{ width: "100%", mb: 3 }}>
        <RadioGroup value={selectedAnswer} onChange={(e) => handleAnswerSelect(parseInt(e.target.value))}>
          {currentQ.options.map((option, idx) => {
            let bgcolor = "transparent";
            let borderColor = alpha(accentColor, 0.2);

            if (showResult) {
              if (idx === currentQ.correct) {
                bgcolor = alpha("#48BB78", 0.15);
                borderColor = "#48BB78";
              } else if (idx === selectedAnswer && idx !== currentQ.correct) {
                bgcolor = alpha("#FC8181", 0.15);
                borderColor = "#FC8181";
              }
            } else if (idx === selectedAnswer) {
              bgcolor = alpha(accentColor, 0.1);
              borderColor = accentColor;
            }

            return (
              <Paper
                key={idx}
                sx={{
                  mb: 1.5,
                  p: 0.5,
                  borderRadius: 2,
                  bgcolor,
                  border: `2px solid ${borderColor}`,
                  cursor: showResult ? "default" : "pointer",
                  transition: "all 0.2s",
                  "&:hover": !showResult ? { bgcolor: alpha(accentColor, 0.05) } : {},
                }}
                onClick={() => handleAnswerSelect(idx)}
              >
                <FormControlLabel
                  value={idx}
                  control={<Radio disabled={showResult} sx={{ color: accentColor, "&.Mui-checked": { color: accentColor } }} />}
                  label={option}
                  sx={{ width: "100%", m: 0, py: 0.5, px: 1 }}
                />
              </Paper>
            );
          })}
        </RadioGroup>
      </FormControl>

      {/* Explanation */}
      {showResult && (
        <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: alpha("#4299E1", 0.1), border: `1px solid ${alpha("#4299E1", 0.3)}` }}>
          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#4299E1", mb: 0.5 }}>
            💡 Explanation
          </Typography>
          <Typography variant="body2">
            {currentQ.explanation}
          </Typography>
        </Paper>
      )}

      {/* Actions */}
      <Box sx={{ display: "flex", gap: 2, justifyContent: "flex-end" }}>
        {!showResult ? (
          <Button
            variant="contained"
            onClick={handleSubmitAnswer}
            disabled={selectedAnswer === null}
            sx={{
              bgcolor: accentColor,
              "&:hover": { bgcolor: accentColorDark },
              "&:disabled": { bgcolor: alpha(accentColor, 0.3) },
              fontWeight: 700,
              borderRadius: 2,
            }}
          >
            Submit Answer
          </Button>
        ) : (
          <Button
            variant="contained"
            onClick={handleNextQuestion}
            sx={{
              bgcolor: accentColor,
              "&:hover": { bgcolor: accentColorDark },
              fontWeight: 700,
              borderRadius: 2,
            }}
          >
            {currentQuestion < 9 ? "Next Question" : "See Results"}
          </Button>
        )}
      </Box>
    </Box>
  );
}

export default function RustProgrammingPage() {
  const navigate = useNavigate();

  return (
    <LearnPageLayout pageTitle="Rust Programming" pageContext="Comprehensive Rust programming course covering ownership, borrowing, memory safety, concurrency, and systems programming.">
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
                    color: accentColor,
                  },
                }}
              >
                <ListItemIcon sx={{ minWidth: 36, color: "inherit" }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={item.label}
                  primaryTypographyProps={{ fontSize: 14, fontWeight: 500 }}
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
              "&:hover": { bgcolor: alpha(accentColor, 0.15) },
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
              background: `linear-gradient(135deg, ${alpha(accentColor, 0.15)} 0%, ${alpha(accentColorDark, 0.1)} 100%)`,
              border: `1px solid ${alpha(accentColor, 0.2)}`,
              position: "relative",
              overflow: "hidden",
            }}
          >
            {/* Ferris the Crab decoration */}
            <Box
              sx={{
                position: "absolute",
                top: -30,
                right: -30,
                width: 200,
                height: 200,
                borderRadius: "50%",
                background: `radial-gradient(circle, ${alpha(accentColor, 0.2)} 0%, transparent 70%)`,
              }}
            />

            <Box sx={{ position: "relative", zIndex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
                <Avatar
                  sx={{
                    width: 64,
                    height: 64,
                    bgcolor: alpha(accentColor, 0.2),
                    color: accentColor,
                    fontSize: 32,
                    fontWeight: 800,
                  }}
                >
                  🦀
                </Avatar>
                <Box>
                  <Typography variant="h3" sx={{ fontWeight: 900, color: "text.primary" }}>
                    Rust Programming
                  </Typography>
                  <Typography variant="h6" sx={{ color: "text.secondary", fontWeight: 500 }}>
                    Memory safety without garbage collection
                  </Typography>
                </Box>
              </Box>

              {/* Quick Stats */}
              <Grid container spacing={2} sx={{ mb: 3 }}>
                {quickStats.map((stat) => (
                  <Grid item xs={6} sm={3} key={stat.label}>
                    <Paper
                      sx={{
                        p: 2,
                        textAlign: "center",
                        bgcolor: alpha(stat.color, 0.1),
                        border: `1px solid ${alpha(stat.color, 0.2)}`,
                      }}
                    >
                      <Typography variant="h5" sx={{ fontWeight: 800, color: stat.color }}>
                        {stat.value}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {stat.label}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>

              {/* Key Features */}
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                {[
                  "Zero-Cost Abstractions",
                  "Memory Safety",
                  "No Garbage Collector",
                  "Fearless Concurrency",
                  "Pattern Matching",
                  "Type Inference",
                  "WASM Support",
                  "Cross-Platform",
                ].map((feature) => (
                  <Chip
                    key={feature}
                    label={feature}
                    size="small"
                    sx={{
                      bgcolor: alpha(accentColor, 0.1),
                      color: accentColor,
                      fontWeight: 600,
                    }}
                  />
                ))}
              </Box>
            </Box>
          </Paper>

          {/* What is Rust Section */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              What is Rust?
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Rust is a modern systems programming language that achieves something many thought impossible: 
              <strong> memory safety without garbage collection</strong>. While languages like C and C++ give 
              programmers direct control over memory but are prone to bugs like buffer overflows, use-after-free, 
              and data races, and languages like Java and Go use garbage collectors that add runtime overhead, 
              Rust takes a revolutionary approach. It uses a sophisticated <strong>ownership system</strong> with 
              rules that are checked at compile time, ensuring memory safety with zero runtime cost.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Imagine you're writing a program that processes financial transactions at a bank. A single memory 
              bug could lead to security vulnerabilities, corrupted data, or system crashes. In C/C++, such bugs 
              might only appear in production after months of operation. In Rust, the compiler catches these 
              errors <strong>before your code ever runs</strong>. This isn't just type checking—it's a 
              fundamental analysis of how your data flows through the program, ensuring that memory is never 
              accessed after being freed, that data races are impossible, and that null pointers cannot occur.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Rust's mascot is <strong>Ferris</strong>, an adorable crab (🦀). The name "Rust" comes from the 
              rust fungus, which is surprisingly robust and persistent—qualities the language embodies. Rust has 
              consistently been voted the <strong>"most loved programming language"</strong> in Stack Overflow's 
              Developer Survey for multiple years running, thanks to its unique combination of safety, speed, 
              and modern tooling.
            </Typography>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Why Learn Rust?
            </Typography>

            <Grid container spacing={3}>
              {[
                {
                  title: "Memory Safety Without Garbage Collection",
                  description:
                    "Rust's ownership system guarantees memory safety at compile time, eliminating entire classes of bugs like null pointer dereferences, buffer overflows, and use-after-free errors—all without the performance overhead of a garbage collector.",
                  icon: <SecurityIcon />,
                },
                {
                  title: "Blazing Fast Performance",
                  description:
                    "Rust compiles to native machine code and provides performance comparable to C and C++. Its zero-cost abstractions mean you don't pay for features you don't use, and the abstractions you do use cost nothing at runtime.",
                  icon: <SpeedIcon />,
                },
                {
                  title: "Fearless Concurrency",
                  description:
                    "The same ownership rules that ensure memory safety also prevent data races. Rust lets you write concurrent code confidently—if it compiles, it won't have data races. This is revolutionary for systems programming.",
                  icon: <SyncIcon />,
                },
                {
                  title: "Modern Developer Experience",
                  description:
                    "Cargo (Rust's build tool and package manager) is exceptional. The compiler provides incredibly helpful error messages. The ecosystem is growing rapidly with crates.io hosting over 130,000 packages.",
                  icon: <BuildIcon />,
                },
                {
                  title: "Growing Industry Adoption",
                  description:
                    "Major companies like Microsoft, Google, Amazon, Meta, Cloudflare, Discord, and Dropbox use Rust in production. The Linux kernel now accepts Rust code. It's becoming essential for systems programming.",
                  icon: <CloudIcon />,
                },
                {
                  title: "WebAssembly First-Class Support",
                  description:
                    "Rust is one of the best languages for WebAssembly (WASM). You can write high-performance code that runs in browsers at near-native speed, enabling applications previously impossible on the web.",
                  icon: <HttpIcon />,
                },
              ].map((item) => (
                <Grid item xs={12} md={6} key={item.title}>
                  <Paper
                    sx={{
                      p: 3,
                      height: "100%",
                      borderRadius: 3,
                      border: `1px solid ${alpha(accentColor, 0.1)}`,
                      "&:hover": {
                        borderColor: alpha(accentColor, 0.3),
                        bgcolor: alpha(accentColor, 0.02),
                      },
                      transition: "all 0.2s",
                    }}
                  >
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                      <Avatar sx={{ bgcolor: alpha(accentColor, 0.1), color: accentColor }}>
                        {item.icon}
                      </Avatar>
                      <Typography variant="h6" sx={{ fontWeight: 700 }}>
                        {item.title}
                      </Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>
                      {item.description}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Understanding Ownership: Rust's Revolutionary Feature
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Before diving into Rust syntax, it's crucial to understand the concept that makes Rust unique: 
              <strong> ownership</strong>. This is the feature that allows Rust to guarantee memory safety 
              without a garbage collector, and understanding it is the key to becoming proficient in Rust.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              In most programming languages, you can copy a variable freely. In Python or JavaScript, if you 
              write <code>b = a</code>, both <code>a</code> and <code>b</code> point to the same data, and a 
              garbage collector eventually cleans up the memory when nothing references it anymore. In C, you 
              might manually allocate memory, and if you forget to free it or free it twice, you have a bug.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Rust takes a different approach with <strong>three simple rules</strong>:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                {
                  rule: "1. Each value has an owner",
                  explanation:
                    "Every piece of data in Rust has exactly one variable that 'owns' it. The owner is responsible for the data's lifecycle.",
                },
                {
                  rule: "2. There can only be one owner at a time",
                  explanation:
                    "When you assign a value to another variable, ownership is transferred (moved). The original variable can no longer be used.",
                },
                {
                  rule: "3. When the owner goes out of scope, the value is dropped",
                  explanation:
                    "Rust automatically deallocates memory when the owning variable goes out of scope. No garbage collector needed!",
                },
              ].map((item, idx) => (
                <Grid item xs={12} key={idx}>
                  <Paper
                    sx={{
                      p: 3,
                      borderRadius: 2,
                      bgcolor: alpha(accentColor, 0.05),
                      borderLeft: `4px solid ${accentColor}`,
                    }}
                  >
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, color: accentColor }}>
                      {item.rule}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.explanation}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              But what if you want to use data without taking ownership? That's where <strong>borrowing</strong> 
              comes in. You can create references to data that let you access it without owning it. Rust has two 
              types of references: <strong>immutable references</strong> (<code>&amp;T</code>) that let you read 
              data, and <strong>mutable references</strong> (<code>&amp;mut T</code>) that let you modify it. 
              The key rule: you can have either <em>many immutable references</em> or <em>one mutable reference</em>, 
              but never both at the same time. This prevents data races at compile time!
            </Typography>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Rust vs Other Languages
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColor, 0.03), mb: 3 }}>
              <Grid container spacing={2}>
                <Grid item xs={12} md={4}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
                    Rust vs C/C++
                  </Typography>
                  <List dense>
                    {[
                      "Memory safety guaranteed at compile time",
                      "No null pointers (uses Option<T>)",
                      "No data races possible",
                      "Modern package manager (Cargo)",
                      "Similar performance characteristics",
                      "Steeper learning curve initially",
                    ].map((item, idx) => (
                      <ListItem key={idx} sx={{ px: 0, py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: accentColor }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
                    Rust vs Go
                  </Typography>
                  <List dense>
                    {[
                      "No garbage collector overhead",
                      "More powerful type system",
                      "Better for CPU-intensive tasks",
                      "Generics from the start",
                      "More complex concurrency model",
                      "Go compiles faster, simpler syntax",
                    ].map((item, idx) => (
                      <ListItem key={idx} sx={{ px: 0, py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: accentColor }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
                <Grid item xs={12} md={4}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
                    Rust vs Python/JavaScript
                  </Typography>
                  <List dense>
                    {[
                      "10-100x faster execution",
                      "Compiled, not interpreted",
                      "Strong static typing",
                      "Predictable performance",
                      "No runtime exceptions",
                      "Steeper learning curve",
                    ].map((item, idx) => (
                      <ListItem key={idx} sx={{ px: 0, py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <CheckCircleIcon sx={{ fontSize: 16, color: accentColor }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
              </Grid>
            </Paper>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Who Uses Rust?
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Rust has been adopted by major technology companies and projects for critical infrastructure:
            </Typography>

            <Grid container spacing={2}>
              {[
                { name: "Microsoft", usage: "Windows kernel components, Azure services, VS Code components" },
                { name: "Google", usage: "Android (Bluetooth, kernel), Chrome, Fuchsia OS" },
                { name: "Amazon", usage: "Firecracker (Lambda/Fargate), Bottlerocket OS, S3" },
                { name: "Meta", usage: "Source control (Mononoke), Libra/Diem blockchain" },
                { name: "Discord", usage: "Read States service, game SDK (switched from Go)" },
                { name: "Cloudflare", usage: "HTTP proxy, firewall rules engine, Pingora" },
                { name: "Dropbox", usage: "File sync engine (nucleus), compression" },
                { name: "Mozilla", usage: "Firefox (Stylo, WebRender), Servo browser engine" },
                { name: "Linux Kernel", usage: "Second language for kernel development (Rust for Linux)" },
                { name: "1Password", usage: "Core cryptographic operations and backend" },
              ].map((company) => (
                <Grid item xs={12} sm={6} md={4} key={company.name}>
                  <Paper sx={{ p: 2, borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: accentColor }}>
                      {company.name}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {company.usage}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              What Will You Learn?
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              This comprehensive guide will take you from Rust beginner to proficient systems programmer:
            </Typography>

            <Grid container spacing={1}>
              {[
                "Rust syntax and basic programming concepts",
                "The ownership system, borrowing, and references",
                "Structs, enums, and pattern matching",
                "Error handling with Result and Option",
                "Traits and generics for polymorphism",
                "Lifetimes and their annotations",
                "Modules, crates, and the Cargo ecosystem",
                "Testing and documentation",
                "Concurrent programming with threads and async",
                "Unsafe Rust and FFI",
                "Building web services and CLI applications",
                "Best practices for production Rust code",
              ].map((item, idx) => (
                <Grid item xs={12} sm={6} key={idx}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, py: 1 }}>
                    <CheckCircleIcon sx={{ color: accentColor, fontSize: 20 }} />
                    <Typography variant="body2">{item}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>

            <Paper
              sx={{
                p: 3,
                mt: 4,
                borderRadius: 3,
                bgcolor: alpha(accentColor, 0.08),
                border: `1px solid ${alpha(accentColor, 0.2)}`,
              }}
            >
              <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2 }}>
                <Avatar sx={{ bgcolor: accentColor, width: 40, height: 40 }}>🦀</Avatar>
                <Box>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5 }}>
                    A Note About Learning Rust
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>
                    Rust has a reputation for being difficult to learn, and there's truth to it—the compiler 
                    is strict and will reject code that other languages would accept. But this is a feature, 
                    not a bug! The "fight with the borrow checker" that beginners experience is actually the 
                    compiler teaching you to think about memory and data flow correctly. Once concepts click, 
                    you'll find Rust incredibly productive, and the confidence that compiling code works 
                    correctly is unmatched. Embrace the learning curve—it's worth it! 🦀
                  </Typography>
                </Box>
              </Box>
            </Paper>
          </Paper>

          {/* History & Philosophy Section */}
          <Paper id="history" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#B7410E", 0.15), color: "#B7410E", width: 48, height: 48 }}>
                <HistoryIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                History & Philosophy
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Rust began in <strong>2006</strong> as a personal project by <strong>Graydon Hoare</strong>, a Mozilla 
              employee who was frustrated with the state of systems programming. The project's name comes from rust 
              fungi—organisms known for being incredibly robust and persistent, qualities Hoare wanted in the language. 
              Mozilla officially sponsored the project in 2009, seeing potential for a language that could help build 
              a safer, faster web browser engine.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              The language was initially designed to solve a fundamental problem: <strong>memory safety and concurrency 
              bugs account for approximately 70% of all security vulnerabilities</strong> in systems software, according 
              to studies by Microsoft, Google, and others. These bugs—buffer overflows, use-after-free, data races—have 
              plagued software development for decades. Traditional solutions involved either accepting the risk (C/C++) 
              or accepting performance overhead (garbage-collected languages). Rust charted a third path.
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { year: "2006", event: "Graydon Hoare starts Rust as a personal project" },
                { year: "2009", event: "Mozilla officially sponsors Rust development" },
                { year: "2010", event: "First public announcement at Mozilla Summit" },
                { year: "2012", event: "First numbered pre-alpha release (0.1)" },
                { year: "2013", event: "Servo browser engine development begins in Rust" },
                { year: "2015", event: "Rust 1.0 released with stability guarantee" },
                { year: "2018", event: "Rust 2018 edition with NLL and async groundwork" },
                { year: "2021", event: "Rust Foundation formed; Linux kernel accepts Rust" },
                { year: "2024", event: "Rust in Windows kernel; widespread adoption" },
              ].map((item, idx) => (
                <Grid item xs={12} sm={6} md={4} key={idx}>
                  <Paper
                    sx={{
                      p: 2,
                      borderRadius: 2,
                      bgcolor: alpha("#B7410E", 0.05),
                      borderLeft: `3px solid #B7410E`,
                    }}
                  >
                    <Typography variant="subtitle2" sx={{ fontWeight: 800, color: "#B7410E" }}>
                      {item.year}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.event}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#B7410E" }}>
              Design Philosophy: Zero-Cost Abstractions
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Rust's core philosophy can be summarized as: <strong>"What you don't use, you don't pay for. And what you 
              do use, you couldn't hand-code any better."</strong> This principle, borrowed from C++ but more strictly 
              enforced, means that high-level abstractions compile down to code that's as efficient as if you'd written 
              low-level C. Iterators, pattern matching, Option types—all compile away to optimal machine code.
            </Typography>

            <Grid container spacing={2}>
              {[
                {
                  principle: "Safety Without Garbage Collection",
                  description: "The ownership system ensures memory safety at compile time, eliminating runtime overhead while preventing bugs.",
                },
                {
                  principle: "Fearless Concurrency",
                  description: "The type system prevents data races. If code compiles, concurrent access is safe.",
                },
                {
                  principle: "Ergonomic Developer Experience",
                  description: "Despite being a systems language, Rust has modern tooling: Cargo, rustfmt, clippy, rust-analyzer.",
                },
                {
                  principle: "Gradual Learning Curve",
                  description: "You can start simple and learn advanced features as needed. The compiler guides you.",
                },
              ].map((item, idx) => (
                <Grid item xs={12} sm={6} key={idx}>
                  <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#B7410E", 0.03) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                      {item.principle}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.description}
                    </Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Environment Setup Section */}
          <Paper id="setup" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#4A90D9", 0.15), color: "#4A90D9", width: 48, height: 48 }}>
                <BuildIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Environment Setup
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Setting up Rust is remarkably easy thanks to <strong>rustup</strong>, the official Rust toolchain 
              installer and version manager. Unlike many languages where you download an installer, rustup manages 
              your entire Rust installation, making it easy to switch between versions and keep everything updated.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4A90D9" }}>
              Installing Rust with rustup
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#7ec8e3", mb: 1 }}>
                # On Linux/macOS (run in terminal):
              </Typography>
              <Typography variant="body2" sx={{ color: "#f8f8f2", mb: 2 }}>
                curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
              </Typography>
              <Typography variant="body2" sx={{ color: "#7ec8e3", mb: 1 }}>
                # On Windows, download and run rustup-init.exe from:
              </Typography>
              <Typography variant="body2" sx={{ color: "#f8f8f2", mb: 2 }}>
                https://rustup.rs
              </Typography>
              <Typography variant="body2" sx={{ color: "#7ec8e3", mb: 1 }}>
                # Verify installation:
              </Typography>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                rustc --version{"\n"}cargo --version
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4A90D9" }}>
              Toolchain Channels
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                {
                  channel: "stable",
                  description: "Production-ready releases every 6 weeks. Use this for real projects.",
                  command: "rustup default stable",
                },
                {
                  channel: "beta",
                  description: "Next release candidate. Test upcoming features before they're stable.",
                  command: "rustup default beta",
                },
                {
                  channel: "nightly",
                  description: "Bleeding-edge features. Required for some experimental features.",
                  command: "rustup default nightly",
                },
              ].map((item) => (
                <Grid item xs={12} md={4} key={item.channel}>
                  <Paper sx={{ p: 2, borderRadius: 2, height: "100%", bgcolor: alpha("#4A90D9", 0.05) }}>
                    <Chip
                      label={item.channel}
                      size="small"
                      sx={{ mb: 1, fontWeight: 700, bgcolor: alpha("#4A90D9", 0.15), color: "#4A90D9" }}
                    />
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      {item.description}
                    </Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#4A90D9" }}>
                      {item.command}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4A90D9" }}>
              Essential Cargo Commands
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              <strong>Cargo</strong> is Rust's build system and package manager. It handles compiling, dependency 
              management, testing, documentation, and more. Here are the commands you'll use daily:
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#7ec8e3", mb: 1 }}>
                # Create a new project
              </Typography>
              <Typography variant="body2" sx={{ color: "#f8f8f2", mb: 2 }}>
                cargo new my_project      # Creates binary project{"\n"}cargo new my_lib --lib   # Creates library project
              </Typography>
              <Typography variant="body2" sx={{ color: "#7ec8e3", mb: 1 }}>
                # Build and run
              </Typography>
              <Typography variant="body2" sx={{ color: "#f8f8f2", mb: 2 }}>
                cargo build              # Compile (debug mode){"\n"}cargo build --release    # Compile (optimized){"\n"}cargo run                # Build and execute
              </Typography>
              <Typography variant="body2" sx={{ color: "#7ec8e3", mb: 1 }}>
                # Quality checks
              </Typography>
              <Typography variant="body2" sx={{ color: "#f8f8f2", mb: 2 }}>
                cargo check              # Fast compile check{"\n"}cargo test               # Run tests{"\n"}cargo clippy             # Linting{"\n"}cargo fmt                # Format code
              </Typography>
              <Typography variant="body2" sx={{ color: "#7ec8e3", mb: 1 }}>
                # Documentation
              </Typography>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                cargo doc --open         # Generate and view docs
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4A90D9" }}>
              IDE Setup: VS Code with rust-analyzer
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              For the best Rust development experience, use VS Code with the <strong>rust-analyzer</strong> extension:
            </Typography>

            <List dense>
              {[
                "Install VS Code and the 'rust-analyzer' extension from the marketplace",
                "Features: intelligent code completion, inline type hints, go-to-definition",
                "Real-time error checking as you type (no need to compile)",
                "Automatic imports, code actions, and refactoring support",
                "Integrated debugging with CodeLLDB extension",
              ].map((item, idx) => (
                <ListItem key={idx} sx={{ py: 0.5 }}>
                  <ListItemIcon sx={{ minWidth: 28 }}>
                    <CheckCircleIcon sx={{ fontSize: 18, color: "#4A90D9" }} />
                  </ListItemIcon>
                  <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                </ListItem>
              ))}
            </List>
          </Paper>

          {/* Rust Basics & Syntax Section */}
          <Paper id="basics" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <CodeIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Rust Basics & Syntax
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Rust's syntax will feel familiar if you know C, C++, or JavaScript, but with important differences 
              that support its safety guarantees. Let's explore the fundamentals.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Variables and Mutability
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Variables in Rust are <strong>immutable by default</strong>. This is a deliberate design choice that 
              encourages safer code. To make a variable mutable, you must explicitly use the <code>mut</code> keyword:
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>main</span>() {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> x = <span style={{ color: "#bd93f9" }}>5</span>;           <span style={{ color: "#6272a4" }}>// Immutable</span>{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// x = 6;           // ERROR: cannot assign twice</span>{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let mut</span> y = <span style={{ color: "#bd93f9" }}>10</span>;       <span style={{ color: "#6272a4" }}>// Mutable</span>{"\n"}
                {"    "}y = <span style={{ color: "#bd93f9" }}>20</span>;             <span style={{ color: "#6272a4" }}>// OK!</span>{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Shadowing: create new variable with same name</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> x = x + <span style={{ color: "#bd93f9" }}>1</span>;       <span style={{ color: "#6272a4" }}>// OK! This creates a NEW x</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> x = <span style={{ color: "#f1fa8c" }}>"now a string"</span>; <span style={{ color: "#6272a4" }}>// Can even change type</span>{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Basic Data Types
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                {
                  category: "Integers",
                  types: "i8, i16, i32, i64, i128, isize (signed)\nu8, u16, u32, u64, u128, usize (unsigned)",
                  example: "let age: u8 = 25;",
                },
                {
                  category: "Floats",
                  types: "f32 (single precision)\nf64 (double precision, default)",
                  example: "let pi: f64 = 3.14159;",
                },
                {
                  category: "Boolean",
                  types: "bool (true or false)",
                  example: "let is_active: bool = true;",
                },
                {
                  category: "Character",
                  types: "char (4-byte Unicode scalar)",
                  example: "let emoji: char = '🦀';",
                },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.category}>
                  <Paper sx={{ p: 2, borderRadius: 2, height: "100%", bgcolor: alpha(accentColor, 0.03) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: accentColor }}>
                      {item.category}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: "pre-line", mb: 1 }}>
                      {item.types}
                    </Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", color: accentColor }}>
                      {item.example}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Strings: String vs &str
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Rust has two main string types. Understanding the difference is crucial:
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// &str: String slice - immutable, borrowed, often a literal</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> greeting: &<span style={{ color: "#8be9fd" }}>str</span> = <span style={{ color: "#f1fa8c" }}>"Hello"</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// String: Owned, heap-allocated, growable</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let mut</span> name = <span style={{ color: "#8be9fd" }}>String</span>::from(<span style={{ color: "#f1fa8c" }}>"Ferris"</span>);{"\n"}
                name.push_str(<span style={{ color: "#f1fa8c" }}>" the Crab"</span>);  <span style={{ color: "#6272a4" }}>// Can grow!</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Convert between them</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> s: <span style={{ color: "#8be9fd" }}>String</span> = greeting.to_string();  <span style={{ color: "#6272a4" }}>// &str → String</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> r: &<span style={{ color: "#8be9fd" }}>str</span> = &name;                  <span style={{ color: "#6272a4" }}>// String → &str</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Control Flow
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// if is an expression (returns a value!)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> status = <span style={{ color: "#ff79c6" }}>if</span> age {">"}= <span style={{ color: "#bd93f9" }}>18</span> {"{"} <span style={{ color: "#f1fa8c" }}>"adult"</span> {"}"} <span style={{ color: "#ff79c6" }}>else</span> {"{"} <span style={{ color: "#f1fa8c" }}>"minor"</span> {"}"};{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// loop: infinite loop (break to exit)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> result = <span style={{ color: "#ff79c6" }}>loop</span> {"{"}{"\n"}
                {"    "}counter += <span style={{ color: "#bd93f9" }}>1</span>;{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>if</span> counter == <span style={{ color: "#bd93f9" }}>10</span> {"{"} <span style={{ color: "#ff79c6" }}>break</span> counter * <span style={{ color: "#bd93f9" }}>2</span>; {"}"}{"\n"}
                {"}"};{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// while loop</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>while</span> count {"<"} <span style={{ color: "#bd93f9" }}>5</span> {"{"}{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"count: {"{"}{"}"}"</span>, count);{"\n"}
                {"    "}count += <span style={{ color: "#bd93f9" }}>1</span>;{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// for loop (most common)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> i <span style={{ color: "#ff79c6" }}>in</span> <span style={{ color: "#bd93f9" }}>0</span>..<span style={{ color: "#bd93f9" }}>5</span> {"{"}{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"index: {"{"}{"}"}"</span>, i);{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> item <span style={{ color: "#ff79c6" }}>in</span> vec.iter() {"{"}{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"item: {"{"}{"}"}"</span>, item);{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Functions
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Function with parameters and return type</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>add</span>(a: <span style={{ color: "#8be9fd" }}>i32</span>, b: <span style={{ color: "#8be9fd" }}>i32</span>) -{">"} <span style={{ color: "#8be9fd" }}>i32</span> {"{"}{"\n"}
                {"    "}a + b  <span style={{ color: "#6272a4" }}>// No semicolon = return value (expression)</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Alternative with explicit return</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>multiply</span>(a: <span style={{ color: "#8be9fd" }}>i32</span>, b: <span style={{ color: "#8be9fd" }}>i32</span>) -{">"} <span style={{ color: "#8be9fd" }}>i32</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> a * b;  <span style={{ color: "#6272a4" }}>// With semicolon, explicit return</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Function with no return (returns unit type ())</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>greet</span>(name: &<span style={{ color: "#8be9fd" }}>str</span>) {"{"}{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"Hello, {"{"}{"}"}"</span>, name);{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColor, 0.08), border: `1px solid ${alpha(accentColor, 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                💡 Key Rust Syntax Insight
              </Typography>
              <Typography variant="body2" color="text.secondary">
                In Rust, almost everything is an <strong>expression</strong> that returns a value. If you omit the 
                semicolon at the end of a line, it becomes the return value. Adding a semicolon turns it into a 
                <strong> statement</strong> that returns the unit type <code>()</code>. This is why function bodies 
                often end without a semicolon—the last expression is implicitly returned.
              </Typography>
            </Paper>
          </Paper>

          {/* Ownership & Borrowing Section */}
          <Paper id="ownership" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#E53E3E", 0.15), color: "#E53E3E", width: 48, height: 48 }}>
                <LockIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Ownership & Borrowing
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Ownership is Rust's most distinctive feature. It enables memory safety without garbage collection. 
              This section dives deep into the rules and shows how borrowing lets you use data without taking ownership.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#E53E3E" }}>
              The Move Semantics
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              When you assign a heap-allocated value to another variable, <strong>ownership moves</strong>. The 
              original variable is no longer valid:
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>let</span> s1 = <span style={{ color: "#8be9fd" }}>String</span>::from(<span style={{ color: "#f1fa8c" }}>"hello"</span>);{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> s2 = s1;  <span style={{ color: "#6272a4" }}>// Ownership MOVES to s2</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// println!("{"{"}{"}"}", s1);  // ERROR! s1 is no longer valid</span>{"\n"}
                println!(<span style={{ color: "#f1fa8c" }}>"{"{}"}{"}"}"</span>, s2);  <span style={{ color: "#6272a4" }}>// OK! s2 owns the data</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Stack-only types (Copy trait) are copied, not moved</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> x = <span style={{ color: "#bd93f9" }}>5</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> y = x;  <span style={{ color: "#6272a4" }}>// x is COPIED (integers implement Copy)</span>{"\n"}
                println!(<span style={{ color: "#f1fa8c" }}>"x={"{"}{"}"}, y={"{}"}{"}"}"</span>, x, y);  <span style={{ color: "#6272a4" }}>// Both valid!</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#E53E3E" }}>
              Borrowing with References
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              What if you want to use data without taking ownership? Use <strong>references</strong> to borrow it:
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>calculate_length</span>(s: &<span style={{ color: "#8be9fd" }}>String</span>) -{">"} <span style={{ color: "#8be9fd" }}>usize</span> {"{"}{"\n"}
                {"    "}s.len()  <span style={{ color: "#6272a4" }}>// We can read s, but don't own it</span>{"\n"}
                {"}"}  <span style={{ color: "#6272a4" }}>// s goes out of scope, but since it doesn't own</span>{"\n"}
                {"   "}<span style={{ color: "#6272a4" }}>// the String, nothing is dropped</span>{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>main</span>() {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> s1 = <span style={{ color: "#8be9fd" }}>String</span>::from(<span style={{ color: "#f1fa8c" }}>"hello"</span>);{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> len = calculate_length(&s1);  <span style={{ color: "#6272a4" }}>// Pass a reference</span>{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"Length of '{"{}"}' is {"{}"}{"}"}"</span>, s1, len);  <span style={{ color: "#6272a4" }}>// s1 still valid!</span>{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#E53E3E" }}>
              Mutable References
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Immutable references (<code>&T</code>) let you read data. Mutable references (<code>&mut T</code>) 
              let you modify it. But there's a critical rule:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#E53E3E", 0.08), borderLeft: `4px solid #E53E3E` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, color: "#E53E3E" }}>
                The Borrowing Rules
              </Typography>
              <Typography variant="body2" color="text.secondary">
                At any given time, you can have <strong>either</strong>:
                <br />• One mutable reference (<code>&mut T</code>), OR
                <br />• Any number of immutable references (<code>&T</code>)
                <br /><br />
                <strong>Never both at the same time!</strong> This prevents data races at compile time.
              </Typography>
            </Paper>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>main</span>() {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let mut</span> s = <span style={{ color: "#8be9fd" }}>String</span>::from(<span style={{ color: "#f1fa8c" }}>"hello"</span>);{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Mutable borrow - can modify</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> r1 = &<span style={{ color: "#ff79c6" }}>mut</span> s;{"\n"}
                {"    "}r1.push_str(<span style={{ color: "#f1fa8c" }}>" world"</span>);{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"{"{}"}{"}"}"</span>, r1);{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// After r1 is done being used, we can borrow again</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> r2 = &s;  <span style={{ color: "#6272a4" }}>// Immutable borrow OK now</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> r3 = &s;  <span style={{ color: "#6272a4" }}>// Multiple immutable borrows OK</span>{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"r2={"{"}{"}"}, r3={"{}"}{"}"}"</span>, r2, r3);{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#E53E3E" }}>
              Slices: Borrowing Part of a Collection
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              <strong>Slices</strong> let you reference a contiguous sequence within a collection without taking ownership:
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>let</span> s = <span style={{ color: "#8be9fd" }}>String</span>::from(<span style={{ color: "#f1fa8c" }}>"hello world"</span>);{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> hello = &s[<span style={{ color: "#bd93f9" }}>0</span>..<span style={{ color: "#bd93f9" }}>5</span>];    <span style={{ color: "#6272a4" }}>// "hello"</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> world = &s[<span style={{ color: "#bd93f9" }}>6</span>..<span style={{ color: "#bd93f9" }}>11</span>];   <span style={{ color: "#6272a4" }}>// "world"</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> full = &s[..];        <span style={{ color: "#6272a4" }}>// Entire string</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Array slices work the same way</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> arr = [<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>4</span>, <span style={{ color: "#bd93f9" }}>5</span>];{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> slice = &arr[<span style={{ color: "#bd93f9" }}>1</span>..<span style={{ color: "#bd93f9" }}>4</span>];  <span style={{ color: "#6272a4" }}>// [2, 3, 4]</span>
              </Typography>
            </Paper>

            <Grid container spacing={2}>
              {[
                {
                  title: "Ownership Prevents",
                  items: ["Double-free bugs", "Use-after-free", "Dangling pointers", "Memory leaks (mostly)"],
                  color: "#E53E3E",
                },
                {
                  title: "Borrowing Prevents",
                  items: ["Data races", "Iterator invalidation", "Aliased mutation", "Concurrent modification"],
                  color: "#48BB78",
                },
              ].map((box) => (
                <Grid item xs={12} sm={6} key={box.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(box.color, 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: box.color }}>
                      {box.title}
                    </Typography>
                    <List dense disablePadding>
                      {box.items.map((item, idx) => (
                        <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <CheckCircleIcon sx={{ fontSize: 14, color: box.color }} />
                          </ListItemIcon>
                          <ListItemText primary={item} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Types & Data Structures Section */}
          <Paper id="types" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#9F7AEA", 0.15), color: "#9F7AEA", width: 48, height: 48 }}>
                <DataObjectIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Types & Data Structures
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Rust has a rich type system with both primitive compound types and powerful collection types from the 
              standard library. Understanding these is essential for effective Rust programming.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9F7AEA" }}>
              Tuples
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Tuples group multiple values of different types into one compound type. They have a fixed length 
              and their types are known at compile time:
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Create a tuple</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> person: (<span style={{ color: "#8be9fd" }}>&str</span>, <span style={{ color: "#8be9fd" }}>i32</span>, <span style={{ color: "#8be9fd" }}>bool</span>) = (<span style={{ color: "#f1fa8c" }}>"Alice"</span>, <span style={{ color: "#bd93f9" }}>30</span>, <span style={{ color: "#bd93f9" }}>true</span>);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Access by index</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> name = person.<span style={{ color: "#bd93f9" }}>0</span>;    <span style={{ color: "#6272a4" }}>// "Alice"</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> age = person.<span style={{ color: "#bd93f9" }}>1</span>;     <span style={{ color: "#6272a4" }}>// 30</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Destructuring</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> (name, age, active) = person;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Unit type () - empty tuple, represents "no value"</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>do_nothing</span>() -{">"} () {"{"} () {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9F7AEA" }}>
              Arrays
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Arrays have a fixed length known at compile time. All elements must be the same type. 
              Arrays are stack-allocated and useful when you know the exact size:
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Fixed-size array</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> numbers: [<span style={{ color: "#8be9fd" }}>i32</span>; <span style={{ color: "#bd93f9" }}>5</span>] = [<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>4</span>, <span style={{ color: "#bd93f9" }}>5</span>];{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Initialize with same value</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> zeros = [<span style={{ color: "#bd93f9" }}>0</span>; <span style={{ color: "#bd93f9" }}>10</span>];  <span style={{ color: "#6272a4" }}>// [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Access elements (bounds-checked at runtime!)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> first = numbers[<span style={{ color: "#bd93f9" }}>0</span>];{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> len = numbers.len();  <span style={{ color: "#6272a4" }}>// 5</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9F7AEA" }}>
              Vectors (Vec&lt;T&gt;)
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Vectors are heap-allocated, growable arrays. They're the go-to choice when you need a 
              dynamically-sized list:
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Create vectors</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let mut</span> vec1: <span style={{ color: "#8be9fd" }}>Vec</span>{"<"}<span style={{ color: "#8be9fd" }}>i32</span>{">"} = <span style={{ color: "#8be9fd" }}>Vec</span>::new();{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> vec2 = <span style={{ color: "#50fa7b" }}>vec!</span>[<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>];  <span style={{ color: "#6272a4" }}>// Macro shorthand</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Add elements</span>{"\n"}
                vec1.push(<span style={{ color: "#bd93f9" }}>10</span>);{"\n"}
                vec1.push(<span style={{ color: "#bd93f9" }}>20</span>);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Access (two ways)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> third = &vec2[<span style={{ color: "#bd93f9" }}>2</span>];       <span style={{ color: "#6272a4" }}>// Panics if out of bounds</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> third = vec2.get(<span style={{ color: "#bd93f9" }}>2</span>);    <span style={{ color: "#6272a4" }}>// Returns Option&lt;T&gt;</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Iterate</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> item <span style={{ color: "#ff79c6" }}>in</span> &vec2 {"{"}{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"{"{}"}{"}"}"</span>, item);{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9F7AEA" }}>
              HashMap&lt;K, V&gt;
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Hash maps store key-value pairs with O(1) average lookup time:
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>use</span> std::collections::<span style={{ color: "#8be9fd" }}>HashMap</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>let mut</span> scores = <span style={{ color: "#8be9fd" }}>HashMap</span>::new();{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Insert</span>{"\n"}
                scores.insert(<span style={{ color: "#f1fa8c" }}>"Blue"</span>, <span style={{ color: "#bd93f9" }}>10</span>);{"\n"}
                scores.insert(<span style={{ color: "#f1fa8c" }}>"Red"</span>, <span style={{ color: "#bd93f9" }}>50</span>);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Access (returns Option)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> blue_score = scores.get(<span style={{ color: "#f1fa8c" }}>"Blue"</span>);  <span style={{ color: "#6272a4" }}>// Some(&10)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Insert only if key doesn't exist</span>{"\n"}
                scores.entry(<span style={{ color: "#f1fa8c" }}>"Yellow"</span>).or_insert(<span style={{ color: "#bd93f9" }}>25</span>);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Iterate</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> (key, value) <span style={{ color: "#ff79c6" }}>in</span> &scores {"{"}{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"{"{}"}:{"{"}{"}"}"</span>, key, value);{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9F7AEA" }}>
              Type Aliases & The Turbofish
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Type alias for complex types</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>type</span> <span style={{ color: "#8be9fd" }}>Kilometers</span> = <span style={{ color: "#8be9fd" }}>i32</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>type</span> <span style={{ color: "#8be9fd" }}>Result</span>{"<"}<span style={{ color: "#8be9fd" }}>T</span>{">"} = std::result::<span style={{ color: "#8be9fd" }}>Result</span>{"<"}<span style={{ color: "#8be9fd" }}>T</span>, <span style={{ color: "#8be9fd" }}>MyError</span>{">"};{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Turbofish ::{"{"}T{"}"} - explicit type annotation</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> parsed = <span style={{ color: "#f1fa8c" }}>"42"</span>.parse::{"<"}<span style={{ color: "#8be9fd" }}>i32</span>{">"};{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> vec = <span style={{ color: "#8be9fd" }}>Vec</span>::{"<"}<span style={{ color: "#8be9fd" }}>i32</span>{">"}.new();{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// The never type ! (functions that never return)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>loop_forever</span>() -{">"} ! {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>loop</span> {"{"} {"}"}  <span style={{ color: "#6272a4" }}>// Never returns</span>{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Grid container spacing={2}>
              {[
                { type: "Vec<T>", use: "Dynamic lists", when: "Unknown size, frequent additions" },
                { type: "HashMap<K, V>", use: "Key-value storage", when: "Fast lookups by key" },
                { type: "HashSet<T>", use: "Unique values", when: "No duplicates, membership testing" },
                { type: "VecDeque<T>", use: "Double-ended queue", when: "Efficient push/pop both ends" },
                { type: "BinaryHeap<T>", use: "Priority queue", when: "Always access largest element" },
                { type: "BTreeMap<K, V>", use: "Sorted map", when: "Need sorted key iteration" },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.type}>
                  <Paper sx={{ p: 2, borderRadius: 2, height: "100%", bgcolor: alpha("#9F7AEA", 0.03) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#9F7AEA", fontFamily: "monospace" }}>
                      {item.type}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      <strong>{item.use}</strong>
                      <br />
                      {item.when}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Structs & Enums Section */}
          <Paper id="structs-enums" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#38B2AC", 0.15), color: "#38B2AC", width: 48, height: 48 }}>
                <CategoryIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Structs & Enums
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Structs and enums are Rust's primary tools for creating custom types. Together with impl blocks, 
              they enable object-oriented-style programming with Rust's unique ownership model.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              Defining Structs
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Regular struct with named fields</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>User</span> {"{"}{"\n"}
                {"    "}username: <span style={{ color: "#8be9fd" }}>String</span>,{"\n"}
                {"    "}email: <span style={{ color: "#8be9fd" }}>String</span>,{"\n"}
                {"    "}active: <span style={{ color: "#8be9fd" }}>bool</span>,{"\n"}
                {"    "}sign_in_count: <span style={{ color: "#8be9fd" }}>u64</span>,{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Create an instance</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> user1 = <span style={{ color: "#8be9fd" }}>User</span> {"{"}{"\n"}
                {"    "}email: <span style={{ color: "#8be9fd" }}>String</span>::from(<span style={{ color: "#f1fa8c" }}>"user@example.com"</span>),{"\n"}
                {"    "}username: <span style={{ color: "#8be9fd" }}>String</span>::from(<span style={{ color: "#f1fa8c" }}>"ferris"</span>),{"\n"}
                {"    "}active: <span style={{ color: "#bd93f9" }}>true</span>,{"\n"}
                {"    "}sign_in_count: <span style={{ color: "#bd93f9" }}>1</span>,{"\n"}
                {"}"};{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Tuple struct (named tuple)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>Point</span>(<span style={{ color: "#8be9fd" }}>i32</span>, <span style={{ color: "#8be9fd" }}>i32</span>, <span style={{ color: "#8be9fd" }}>i32</span>);{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> origin = <span style={{ color: "#8be9fd" }}>Point</span>(<span style={{ color: "#bd93f9" }}>0</span>, <span style={{ color: "#bd93f9" }}>0</span>, <span style={{ color: "#bd93f9" }}>0</span>);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Unit struct (no fields)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>AlwaysEqual</span>;
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              Methods with impl Blocks
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>Rectangle</span> {"{"}{"\n"}
                {"    "}width: <span style={{ color: "#8be9fd" }}>u32</span>,{"\n"}
                {"    "}height: <span style={{ color: "#8be9fd" }}>u32</span>,{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>impl</span> <span style={{ color: "#8be9fd" }}>Rectangle</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Method: takes &self as first parameter</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>area</span>(&<span style={{ color: "#ff79c6" }}>self</span>) -{">"} <span style={{ color: "#8be9fd" }}>u32</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>self</span>.width * <span style={{ color: "#ff79c6" }}>self</span>.height{"\n"}
                {"    "}{"}"}{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Method that modifies self</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>scale</span>(&<span style={{ color: "#ff79c6" }}>mut self</span>, factor: <span style={{ color: "#8be9fd" }}>u32</span>) {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>self</span>.width *= factor;{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>self</span>.height *= factor;{"\n"}
                {"    "}{"}"}{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Associated function (no self) - often constructors</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>square</span>(size: <span style={{ color: "#8be9fd" }}>u32</span>) -{">"} <span style={{ color: "#8be9fd" }}>Rectangle</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>Rectangle</span> {"{"} width: size, height: size {"}"}{"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> rect = <span style={{ color: "#8be9fd" }}>Rectangle</span>::square(<span style={{ color: "#bd93f9" }}>10</span>);  <span style={{ color: "#6272a4" }}>// Associated fn call</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> area = rect.area();           <span style={{ color: "#6272a4" }}>// Method call</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              Enums: Algebraic Data Types
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Rust enums are incredibly powerful—each variant can hold different types and amounts of data:
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Simple enum</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>enum</span> <span style={{ color: "#8be9fd" }}>Direction</span> {"{"}{"\n"}
                {"    "}North,{"\n"}
                {"    "}South,{"\n"}
                {"    "}East,{"\n"}
                {"    "}West,{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Enum with data in variants</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>enum</span> <span style={{ color: "#8be9fd" }}>Message</span> {"{"}{"\n"}
                {"    "}Quit,                          <span style={{ color: "#6272a4" }}>// No data</span>{"\n"}
                {"    "}Move {"{"} x: <span style={{ color: "#8be9fd" }}>i32</span>, y: <span style={{ color: "#8be9fd" }}>i32</span> {"}"},     <span style={{ color: "#6272a4" }}>// Named fields</span>{"\n"}
                {"    "}Write(<span style={{ color: "#8be9fd" }}>String</span>),                 <span style={{ color: "#6272a4" }}>// Single value</span>{"\n"}
                {"    "}ChangeColor(<span style={{ color: "#8be9fd" }}>i32</span>, <span style={{ color: "#8be9fd" }}>i32</span>, <span style={{ color: "#8be9fd" }}>i32</span>),    <span style={{ color: "#6272a4" }}>// Tuple</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> msg = <span style={{ color: "#8be9fd" }}>Message</span>::Write(<span style={{ color: "#8be9fd" }}>String</span>::from(<span style={{ color: "#f1fa8c" }}>"hello"</span>));
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              Option&lt;T&gt; and Result&lt;T, E&gt;
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Rust has no null! Instead, it uses <code>Option&lt;T&gt;</code> for values that might be absent 
              and <code>Result&lt;T, E&gt;</code> for operations that might fail:
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Option: Some(T) or None</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>enum</span> <span style={{ color: "#8be9fd" }}>Option</span>{"<"}<span style={{ color: "#8be9fd" }}>T</span>{">"} {"{"}{"\n"}
                {"    "}Some(<span style={{ color: "#8be9fd" }}>T</span>),{"\n"}
                {"    "}None,{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> some_number: <span style={{ color: "#8be9fd" }}>Option</span>{"<"}<span style={{ color: "#8be9fd" }}>i32</span>{">"} = <span style={{ color: "#8be9fd" }}>Some</span>(<span style={{ color: "#bd93f9" }}>5</span>);{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> no_number: <span style={{ color: "#8be9fd" }}>Option</span>{"<"}<span style={{ color: "#8be9fd" }}>i32</span>{">"} = <span style={{ color: "#8be9fd" }}>None</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Result: Ok(T) or Err(E)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>enum</span> <span style={{ color: "#8be9fd" }}>Result</span>{"<"}<span style={{ color: "#8be9fd" }}>T</span>, <span style={{ color: "#8be9fd" }}>E</span>{">"} {"{"}{"\n"}
                {"    "}Ok(<span style={{ color: "#8be9fd" }}>T</span>),{"\n"}
                {"    "}Err(<span style={{ color: "#8be9fd" }}>E</span>),{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>divide</span>(a: <span style={{ color: "#8be9fd" }}>f64</span>, b: <span style={{ color: "#8be9fd" }}>f64</span>) -{">"} <span style={{ color: "#8be9fd" }}>Result</span>{"<"}<span style={{ color: "#8be9fd" }}>f64</span>, <span style={{ color: "#8be9fd" }}>String</span>{">"} {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>if</span> b == <span style={{ color: "#bd93f9" }}>0.0</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>Err</span>(<span style={{ color: "#8be9fd" }}>String</span>::from(<span style={{ color: "#f1fa8c" }}>"Division by zero"</span>)){"\n"}
                {"    "}{"}"} <span style={{ color: "#ff79c6" }}>else</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>Ok</span>(a / b){"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#38B2AC", 0.08), border: `1px solid ${alpha("#38B2AC", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                💡 Why No Null?
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Tony Hoare (inventor of null) called it his "billion-dollar mistake." Null references cause countless 
                bugs because the compiler can't track whether a value might be null. With Option&lt;T&gt;, the type 
                system <strong>forces</strong> you to handle the None case—you literally cannot access the value 
                without considering that it might not exist.
              </Typography>
            </Paper>
          </Paper>

          {/* Pattern Matching Section */}
          <Paper id="pattern-matching" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#ED8936", 0.15), color: "#ED8936", width: 48, height: 48 }}>
                <SwapHorizIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Pattern Matching
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Pattern matching is one of Rust's most powerful features. The <code>match</code> expression lets 
              you compare a value against patterns and execute code based on which pattern matches. Unlike 
              switch statements in other languages, Rust's match is <strong>exhaustive</strong>—you must 
              handle every possible case.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              The match Expression
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>enum</span> <span style={{ color: "#8be9fd" }}>Coin</span> {"{"}{"\n"}
                {"    "}Penny, Nickel, Dime, Quarter,{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>value_in_cents</span>(coin: <span style={{ color: "#8be9fd" }}>Coin</span>) -{">"} <span style={{ color: "#8be9fd" }}>u8</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>match</span> coin {"{"}{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>Coin</span>::Penny ={">"} <span style={{ color: "#bd93f9" }}>1</span>,{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>Coin</span>::Nickel ={">"} <span style={{ color: "#bd93f9" }}>5</span>,{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>Coin</span>::Dime ={">"} <span style={{ color: "#bd93f9" }}>10</span>,{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>Coin</span>::Quarter ={">"} <span style={{ color: "#bd93f9" }}>25</span>,{"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// match is an expression - returns a value!</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> cents = value_in_cents(<span style={{ color: "#8be9fd" }}>Coin</span>::Dime);  <span style={{ color: "#6272a4" }}>// 10</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Matching with Bindings
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Extract values from enum variants</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>process_message</span>(msg: <span style={{ color: "#8be9fd" }}>Message</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>match</span> msg {"{"}{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>Message</span>::Quit ={">"} println!(<span style={{ color: "#f1fa8c" }}>"Quitting"</span>),{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>Message</span>::Move {"{"} x, y {"}"} ={">"} {"{"}{"\n"}
                {"            "}println!(<span style={{ color: "#f1fa8c" }}>"Move to ({"{"}{"}"}, {"{}"}{"}"}"</span>, x, y);{"\n"}
                {"        "}{"}"}{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>Message</span>::Write(text) ={">"} println!(<span style={{ color: "#f1fa8c" }}>"Message: {"{}"}{"}"}"</span>, text),{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>Message</span>::ChangeColor(r, g, b) ={">"} {"{"}{"\n"}
                {"            "}println!(<span style={{ color: "#f1fa8c" }}>"Color: rgb({"{"}{"}"},{"{"}{"}"},{"{"}{"}"}"</span>, r, g, b);{"\n"}
                {"        "}{"}"}{"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Matching Option</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>plus_one</span>(x: <span style={{ color: "#8be9fd" }}>Option</span>{"<"}<span style={{ color: "#8be9fd" }}>i32</span>{">"}) -{">"} <span style={{ color: "#8be9fd" }}>Option</span>{"<"}<span style={{ color: "#8be9fd" }}>i32</span>{">"} {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>match</span> x {"{"}{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>None</span> ={">"} <span style={{ color: "#8be9fd" }}>None</span>,{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>Some</span>(i) ={">"} <span style={{ color: "#8be9fd" }}>Some</span>(i + <span style={{ color: "#bd93f9" }}>1</span>),{"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Pattern Syntax
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { pattern: "_", description: "Wildcard - matches anything, ignores the value" },
                { pattern: "x @ pattern", description: "Bind matched value to variable x" },
                { pattern: "1 | 2 | 3", description: "Match any of these values (OR)" },
                { pattern: "1..=5", description: "Inclusive range (1 through 5)" },
                { pattern: "(x, y, _)", description: "Destructure tuple, ignore third" },
                { pattern: "Point { x, y: 0 }", description: "Match struct with specific field value" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.pattern}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ED8936", 0.03) }}>
                    <Typography variant="subtitle2" sx={{ fontFamily: "monospace", color: "#ED8936" }}>
                      {item.pattern}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.description}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Match Guards and if let
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Match guard: additional condition after pattern</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> num = <span style={{ color: "#8be9fd" }}>Some</span>(<span style={{ color: "#bd93f9" }}>4</span>);{"\n"}
                <span style={{ color: "#ff79c6" }}>match</span> num {"{"}{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>Some</span>(x) <span style={{ color: "#ff79c6" }}>if</span> x {"<"} <span style={{ color: "#bd93f9" }}>5</span> ={">"} println!(<span style={{ color: "#f1fa8c" }}>"less than 5: {"{}"}{"}"}"</span>, x),{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>Some</span>(x) ={">"} println!(<span style={{ color: "#f1fa8c" }}>"{"{}"}{"}"}"</span>, x),{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>None</span> ={">"} (),{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// if let: concise match for single pattern</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>if let</span> <span style={{ color: "#8be9fd" }}>Some</span>(value) = some_option {"{"}{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"Got: {"{}"}{"}"}"</span>, value);{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// while let: loop while pattern matches</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let mut</span> stack = <span style={{ color: "#50fa7b" }}>vec!</span>[<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>];{"\n"}
                <span style={{ color: "#ff79c6" }}>while let</span> <span style={{ color: "#8be9fd" }}>Some</span>(top) = stack.pop() {"{"}{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"{"{}"}{"}"}"</span>, top);{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#ED8936", 0.08), border: `1px solid ${alpha("#ED8936", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                💡 Exhaustive Matching
              </Typography>
              <Typography variant="body2" color="text.secondary">
                The Rust compiler ensures every match is <strong>exhaustive</strong>—you must handle all possible 
                cases. If you add a new variant to an enum, every match statement using it will fail to compile 
                until updated. This prevents bugs where you forget to handle a case!
              </Typography>
            </Paper>
          </Paper>

          {/* Error Handling Section */}
          <Paper id="error-handling" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#F56565", 0.15), color: "#F56565", width: 48, height: 48 }}>
                <BugReportIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Error Handling
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Rust has no exceptions. Instead, it distinguishes between <strong>recoverable errors</strong> 
              (using <code>Result&lt;T, E&gt;</code>) and <strong>unrecoverable errors</strong> (using 
              <code>panic!</code>). This makes error handling explicit and forces you to consider failure cases.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#F56565" }}>
              Unrecoverable Errors: panic!
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Use <code>panic!</code> when something has gone terribly wrong and recovery isn't possible:
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Explicit panic</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>panic!</span>(<span style={{ color: "#f1fa8c" }}>"Something went terribly wrong!"</span>);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Implicit panic (out of bounds)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> v = <span style={{ color: "#50fa7b" }}>vec!</span>[<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>];{"\n"}
                v[<span style={{ color: "#bd93f9" }}>99</span>];  <span style={{ color: "#6272a4" }}>// Panics!</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Get backtrace: RUST_BACKTRACE=1 cargo run</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#F56565" }}>
              Recoverable Errors: Result&lt;T, E&gt;
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>use</span> std::fs::<span style={{ color: "#8be9fd" }}>File</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>use</span> std::io::<span style={{ color: "#8be9fd" }}>ErrorKind</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> file_result = <span style={{ color: "#8be9fd" }}>File</span>::open(<span style={{ color: "#f1fa8c" }}>"hello.txt"</span>);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Handle with match</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> file = <span style={{ color: "#ff79c6" }}>match</span> file_result {"{"}{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>Ok</span>(f) ={">"} f,{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>Err</span>(error) ={">"} <span style={{ color: "#ff79c6" }}>match</span> error.kind() {"{"}{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>ErrorKind</span>::NotFound ={">"} {"{"}{"\n"}
                {"            "}<span style={{ color: "#6272a4" }}>// Create file if it doesn't exist</span>{"\n"}
                {"            "}<span style={{ color: "#8be9fd" }}>File</span>::create(<span style={{ color: "#f1fa8c" }}>"hello.txt"</span>).unwrap(){"\n"}
                {"        "}{"}"}{"\n"}
                {"        "}other ={">"} <span style={{ color: "#50fa7b" }}>panic!</span>(<span style={{ color: "#f1fa8c" }}>"Problem: {"{"}:?{"}"}"</span>, other),{"\n"}
                {"    "}{"}"}{"\n"}
                {"}"};
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#F56565" }}>
              Shortcuts: unwrap, expect, and ?
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// unwrap: panic on Err, return value on Ok</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> file = <span style={{ color: "#8be9fd" }}>File</span>::open(<span style={{ color: "#f1fa8c" }}>"hello.txt"</span>).unwrap();{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// expect: like unwrap but with custom panic message</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> file = <span style={{ color: "#8be9fd" }}>File</span>::open(<span style={{ color: "#f1fa8c" }}>"hello.txt"</span>){"\n"}
                {"    "}.expect(<span style={{ color: "#f1fa8c" }}>"Failed to open hello.txt"</span>);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// ? operator: propagate error to calling function</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>read_username</span>() -{">"} <span style={{ color: "#8be9fd" }}>Result</span>{"<"}<span style={{ color: "#8be9fd" }}>String</span>, io::<span style={{ color: "#8be9fd" }}>Error</span>{">"} {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let mut</span> file = <span style={{ color: "#8be9fd" }}>File</span>::open(<span style={{ color: "#f1fa8c" }}>"username.txt"</span>)?;  <span style={{ color: "#6272a4" }}>// Returns Err if fails</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let mut</span> s = <span style={{ color: "#8be9fd" }}>String</span>::new();{"\n"}
                {"    "}file.read_to_string(&<span style={{ color: "#ff79c6" }}>mut</span> s)?;  <span style={{ color: "#6272a4" }}>// Returns Err if fails</span>{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>Ok</span>(s){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// ? also works with Option (returns None on None)</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#F56565" }}>
              Custom Error Types
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Define custom error enum</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>#[derive(Debug)]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>enum</span> <span style={{ color: "#8be9fd" }}>AppError</span> {"{"}{"\n"}
                {"    "}IoError(std::io::<span style={{ color: "#8be9fd" }}>Error</span>),{"\n"}
                {"    "}ParseError(<span style={{ color: "#8be9fd" }}>String</span>),{"\n"}
                {"    "}NotFound,{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Implement From for automatic conversion with ?</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>impl</span> <span style={{ color: "#8be9fd" }}>From</span>{"<"}std::io::<span style={{ color: "#8be9fd" }}>Error</span>{">"} <span style={{ color: "#ff79c6" }}>for</span> <span style={{ color: "#8be9fd" }}>AppError</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>from</span>(err: std::io::<span style={{ color: "#8be9fd" }}>Error</span>) -{">"} <span style={{ color: "#8be9fd" }}>AppError</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>AppError</span>::IoError(err){"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Grid container spacing={2}>
              {[
                {
                  crate: "thiserror",
                  description: "Derive macro for custom error types. Great for libraries.",
                  usage: "#[derive(Error)]",
                },
                {
                  crate: "anyhow",
                  description: "Easy error handling for applications. Wraps any error type.",
                  usage: "anyhow::Result<T>",
                },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.crate}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#F56565", 0.05) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#F56565" }}>
                      {item.crate}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      {item.description}
                    </Typography>
                    <Chip label={item.usage} size="small" sx={{ fontFamily: "monospace", fontSize: 11 }} />
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, mt: 3, borderRadius: 2, bgcolor: alpha("#F56565", 0.08), border: `1px solid ${alpha("#F56565", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                💡 When to panic! vs Result
              </Typography>
              <Typography variant="body2" color="text.secondary">
                <strong>Use panic!</strong> when: the error represents a bug in your code (not external input), 
                you're writing examples or tests, or continuing is impossible.
                <br /><br />
                <strong>Use Result</strong> when: failure is expected (file not found, network error), the caller 
                can meaningfully handle the error, or you're writing a library.
              </Typography>
            </Paper>
          </Paper>

          {/* Traits & Generics Section */}
          <Paper id="traits" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#667EEA", 0.15), color: "#667EEA", width: 48, height: 48 }}>
                <ExtensionIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Traits & Generics
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Traits define shared behavior across types—similar to interfaces in other languages but more 
              powerful. Combined with generics, they enable writing flexible, reusable code without sacrificing 
              performance (thanks to monomorphization).
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Defining and Implementing Traits
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Define a trait</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>trait</span> <span style={{ color: "#8be9fd" }}>Summary</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>summarize</span>(&<span style={{ color: "#ff79c6" }}>self</span>) -{">"} <span style={{ color: "#8be9fd" }}>String</span>;{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Default implementation</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>summarize_author</span>(&<span style={{ color: "#ff79c6" }}>self</span>) -{">"} <span style={{ color: "#8be9fd" }}>String</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>String</span>::from(<span style={{ color: "#f1fa8c" }}>"(Unknown author)"</span>){"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>Article</span> {"{"}{"\n"}
                {"    "}headline: <span style={{ color: "#8be9fd" }}>String</span>,{"\n"}
                {"    "}author: <span style={{ color: "#8be9fd" }}>String</span>,{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Implement trait for a type</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>impl</span> <span style={{ color: "#8be9fd" }}>Summary</span> <span style={{ color: "#ff79c6" }}>for</span> <span style={{ color: "#8be9fd" }}>Article</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>summarize</span>(&<span style={{ color: "#ff79c6" }}>self</span>) -{">"} <span style={{ color: "#8be9fd" }}>String</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#50fa7b" }}>format!</span>(<span style={{ color: "#f1fa8c" }}>"{"{}"} by {"{}"}{"}"}"</span>, <span style={{ color: "#ff79c6" }}>self</span>.headline, <span style={{ color: "#ff79c6" }}>self</span>.author){"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Generic Types
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Generic function</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>largest</span>{"<"}<span style={{ color: "#8be9fd" }}>T</span>: <span style={{ color: "#8be9fd" }}>PartialOrd</span>{">"} (list: &[<span style={{ color: "#8be9fd" }}>T</span>]) -{">"} &<span style={{ color: "#8be9fd" }}>T</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let mut</span> largest = &list[<span style={{ color: "#bd93f9" }}>0</span>];{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>for</span> item <span style={{ color: "#ff79c6" }}>in</span> list {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>if</span> item {">"} largest {"{"} largest = item; {"}"}{"\n"}
                {"    "}{"}"}{"\n"}
                {"    "}largest{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Generic struct</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>Point</span>{"<"}<span style={{ color: "#8be9fd" }}>T</span>{">"} {"{"}{"\n"}
                {"    "}x: <span style={{ color: "#8be9fd" }}>T</span>,{"\n"}
                {"    "}y: <span style={{ color: "#8be9fd" }}>T</span>,{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Multiple generic types</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>Pair</span>{"<"}<span style={{ color: "#8be9fd" }}>T</span>, <span style={{ color: "#8be9fd" }}>U</span>{">"} {"{"}{"\n"}
                {"    "}first: <span style={{ color: "#8be9fd" }}>T</span>,{"\n"}
                {"    "}second: <span style={{ color: "#8be9fd" }}>U</span>,{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Trait Bounds
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Trait bound syntax</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>notify</span>{"<"}<span style={{ color: "#8be9fd" }}>T</span>: <span style={{ color: "#8be9fd" }}>Summary</span>{">"} (item: &<span style={{ color: "#8be9fd" }}>T</span>) {"{"}{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"Breaking: {"{"}{"}"}"</span>, item.summarize());{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// impl Trait syntax (shorthand)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>notify</span>(item: &<span style={{ color: "#ff79c6" }}>impl</span> <span style={{ color: "#8be9fd" }}>Summary</span>) {"{"}{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"Breaking: {"{"}{"}"}"</span>, item.summarize());{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Multiple trait bounds</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>process</span>{"<"}<span style={{ color: "#8be9fd" }}>T</span>: <span style={{ color: "#8be9fd" }}>Summary</span> + <span style={{ color: "#8be9fd" }}>Clone</span>{">"} (item: <span style={{ color: "#8be9fd" }}>T</span>) {"{"} ... {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// where clause for complex bounds</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>complex</span>{"<"}<span style={{ color: "#8be9fd" }}>T</span>, <span style={{ color: "#8be9fd" }}>U</span>{">"}(t: &<span style={{ color: "#8be9fd" }}>T</span>, u: &<span style={{ color: "#8be9fd" }}>U</span>) -{">"} <span style={{ color: "#8be9fd" }}>i32</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>where</span>{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>T</span>: <span style={{ color: "#8be9fd" }}>Display</span> + <span style={{ color: "#8be9fd" }}>Clone</span>,{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>U</span>: <span style={{ color: "#8be9fd" }}>Clone</span> + <span style={{ color: "#8be9fd" }}>Debug</span>,{"\n"}
                {"{"} ... {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Common Standard Library Traits
            </Typography>

            <Grid container spacing={2}>
              {[
                { trait: "Debug", description: "Format for debugging ({:?})", derive: true },
                { trait: "Clone", description: "Explicit deep copy with .clone()", derive: true },
                { trait: "Copy", description: "Implicit bitwise copy (stack only)", derive: true },
                { trait: "Default", description: "Create default values", derive: true },
                { trait: "PartialEq / Eq", description: "Equality comparison (==)", derive: true },
                { trait: "PartialOrd / Ord", description: "Ordering comparison (<, >)", derive: true },
                { trait: "From / Into", description: "Type conversions", derive: false },
                { trait: "Display", description: "User-facing formatting ({})", derive: false },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={3} key={item.trait}>
                  <Paper sx={{ p: 2, borderRadius: 2, height: "100%", bgcolor: alpha("#667EEA", 0.03) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#667EEA", fontFamily: "monospace" }}>
                      {item.trait}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ fontSize: 12 }}>
                      {item.description}
                    </Typography>
                    {item.derive && (
                      <Chip label="derivable" size="small" sx={{ mt: 1, fontSize: 10, height: 20 }} />
                    )}
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, mt: 3, borderRadius: 2, bgcolor: alpha("#667EEA", 0.08), border: `1px solid ${alpha("#667EEA", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                💡 Static vs Dynamic Dispatch
              </Typography>
              <Typography variant="body2" color="text.secondary">
                <strong>Generics</strong> use static dispatch (monomorphization)—the compiler generates specialized 
                code for each type, resulting in zero runtime cost but larger binaries.
                <br /><br />
                <strong>Trait objects</strong> (<code>dyn Trait</code>) use dynamic dispatch via vtables—smaller 
                binaries but slight runtime overhead. Use <code>Box{"<"}dyn Trait{">"}</code> when you need 
                heterogeneous collections or don't know the concrete type at compile time.
              </Typography>
            </Paper>
          </Paper>

          {/* Lifetimes Section */}
          <Paper id="lifetimes" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#FC8181", 0.15), color: "#FC8181", width: 48, height: 48 }}>
                <TimelineIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Lifetimes
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Lifetimes are Rust's way of ensuring that references are always valid. Every reference has a 
              lifetime—the scope for which that reference is valid. Most of the time, lifetimes are inferred, 
              but sometimes you need to annotate them explicitly.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#FC8181" }}>
              The Problem Lifetimes Solve
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// This won't compile - dangling reference!</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>dangle</span>() -{">"} &<span style={{ color: "#8be9fd" }}>String</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> s = <span style={{ color: "#8be9fd" }}>String</span>::from(<span style={{ color: "#f1fa8c" }}>"hello"</span>);{"\n"}
                {"    "}&s  <span style={{ color: "#6272a4" }}>// ERROR: s is dropped here, reference invalid!</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Which string does the return reference come from?</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>longest</span>(x: &<span style={{ color: "#8be9fd" }}>str</span>, y: &<span style={{ color: "#8be9fd" }}>str</span>) -{">"} &<span style={{ color: "#8be9fd" }}>str</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>if</span> x.len() {">"} y.len() {"{"} x {"}"} <span style={{ color: "#ff79c6" }}>else</span> {"{"} y {"}"}{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#6272a4" }}>// ERROR: compiler can't determine lifetime of return value</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#FC8181" }}>
              Lifetime Annotation Syntax
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// 'a is a lifetime parameter (like a generic type)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>longest</span>{"<"}<span style={{ color: "#ffb86c" }}>'a</span>{">"}(x: &<span style={{ color: "#ffb86c" }}>'a</span> <span style={{ color: "#8be9fd" }}>str</span>, y: &<span style={{ color: "#ffb86c" }}>'a</span> <span style={{ color: "#8be9fd" }}>str</span>) -{">"} &<span style={{ color: "#ffb86c" }}>'a</span> <span style={{ color: "#8be9fd" }}>str</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>if</span> x.len() {">"} y.len() {"{"} x {"}"} <span style={{ color: "#ff79c6" }}>else</span> {"{"} y {"}"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// This tells the compiler: the returned reference</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// lives as long as the SHORTER of x and y's lifetimes</span>{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>main</span>() {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> s1 = <span style={{ color: "#8be9fd" }}>String</span>::from(<span style={{ color: "#f1fa8c" }}>"long string"</span>);{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> result;{"\n"}
                {"    "}{"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>let</span> s2 = <span style={{ color: "#8be9fd" }}>String</span>::from(<span style={{ color: "#f1fa8c" }}>"short"</span>);{"\n"}
                {"        "}result = longest(&s1, &s2);{"\n"}
                {"        "}println!(<span style={{ color: "#f1fa8c" }}>"Longest: {"{"}{"}"}"</span>, result);  <span style={{ color: "#6272a4" }}>// OK here</span>{"\n"}
                {"    "}{"}"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// println!("{"{}"}", result); // ERROR: s2 dropped!</span>{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#FC8181" }}>
              Lifetimes in Structs
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Struct holding a reference needs lifetime annotation</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>ImportantExcerpt</span>{"<"}<span style={{ color: "#ffb86c" }}>'a</span>{">"} {"{"}{"\n"}
                {"    "}part: &<span style={{ color: "#ffb86c" }}>'a</span> <span style={{ color: "#8be9fd" }}>str</span>,{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>impl</span>{"<"}<span style={{ color: "#ffb86c" }}>'a</span>{">"} <span style={{ color: "#8be9fd" }}>ImportantExcerpt</span>{"<"}<span style={{ color: "#ffb86c" }}>'a</span>{">"} {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>level</span>(&<span style={{ color: "#ff79c6" }}>self</span>) -{">"} <span style={{ color: "#8be9fd" }}>i32</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#bd93f9" }}>3</span>{"\n"}
                {"    "}{"}"}{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Return type uses struct's lifetime</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>announce</span>(&<span style={{ color: "#ff79c6" }}>self</span>, announcement: &<span style={{ color: "#8be9fd" }}>str</span>) -{">"} &<span style={{ color: "#ffb86c" }}>'a</span> <span style={{ color: "#8be9fd" }}>str</span> {"{"}{"\n"}
                {"        "}println!(<span style={{ color: "#f1fa8c" }}>"Attention: {"{"}{"}"}"</span>, announcement);{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>self</span>.part{"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#FC8181" }}>
              Lifetime Elision Rules
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              The compiler applies these rules to infer lifetimes automatically. If all rules apply, you don't 
              need explicit annotations:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { rule: "Rule 1", description: "Each reference parameter gets its own lifetime parameter" },
                { rule: "Rule 2", description: "If exactly one input lifetime, it's assigned to all output lifetimes" },
                { rule: "Rule 3", description: "If &self or &mut self, self's lifetime is assigned to outputs" },
              ].map((item) => (
                <Grid item xs={12} key={item.rule}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#FC8181", 0.05), borderLeft: `3px solid #FC8181` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#FC8181" }}>
                      {item.rule}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.description}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Static lifetime: lives for entire program duration</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> s: &<span style={{ color: "#ffb86c" }}>'static</span> <span style={{ color: "#8be9fd" }}>str</span> = <span style={{ color: "#f1fa8c" }}>"I live forever!"</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// String literals are always 'static</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// Be careful with 'static in function signatures</span>
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#FC8181", 0.08), border: `1px solid ${alpha("#FC8181", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                💡 Thinking About Lifetimes
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Lifetimes don't change how long data lives—they describe relationships between reference lifetimes 
                so the compiler can verify safety. Think: "This reference is valid for at least as long as that 
                reference." Most code doesn't need explicit lifetimes thanks to elision rules.
              </Typography>
            </Paper>
          </Paper>

          {/* Modules & Crates Section */}
          <Paper id="modules" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#4FD1C5", 0.15), color: "#4FD1C5", width: 48, height: 48 }}>
                <ViewModuleIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Modules & Crates
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Rust's module system helps you organize code into logical units, control visibility, and manage 
              dependencies. Understanding crates, modules, and paths is essential for building larger projects.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4FD1C5" }}>
              Crates: Binary vs Library
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} sm={6}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#4FD1C5", 0.05), height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#4FD1C5" }}>
                    Binary Crate
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    Compiles to an executable. Entry point is <code>main.rs</code> with a <code>fn main()</code>.
                  </Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace" }}>
                    cargo new my_app
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#4FD1C5", 0.05), height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#4FD1C5" }}>
                    Library Crate
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    Compiles to code meant to be used by other crates. Entry point is <code>lib.rs</code>.
                  </Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace" }}>
                    cargo new my_lib --lib
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4FD1C5" }}>
              Defining Modules
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// In lib.rs or main.rs</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>mod</span> front_of_house {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>pub mod</span> hosting {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>pub fn</span> <span style={{ color: "#50fa7b" }}>add_to_waitlist</span>() {"{"}{"}"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>seat_at_table</span>() {"{"}{"}"}  <span style={{ color: "#6272a4" }}>// Private!</span>{"\n"}
                {"    "}{"}"}{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>mod</span> serving {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>take_order</span>() {"{"}{"}"}  <span style={{ color: "#6272a4" }}>// Private module, private fn</span>{"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Using paths to reference items</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>pub fn</span> <span style={{ color: "#50fa7b" }}>eat_at_restaurant</span>() {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Absolute path (from crate root)</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>crate</span>::front_of_house::hosting::add_to_waitlist();{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Relative path</span>{"\n"}
                {"    "}front_of_house::hosting::add_to_waitlist();{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4FD1C5" }}>
              The use Keyword
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Bring items into scope</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>use</span> <span style={{ color: "#ff79c6" }}>crate</span>::front_of_house::hosting;{"\n"}
                hosting::add_to_waitlist();{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Alias with 'as'</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>use</span> std::io::<span style={{ color: "#8be9fd" }}>Result</span> <span style={{ color: "#ff79c6" }}>as</span> <span style={{ color: "#8be9fd" }}>IoResult</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Re-export with 'pub use'</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>pub use</span> <span style={{ color: "#ff79c6" }}>crate</span>::front_of_house::hosting;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Nested paths</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>use</span> std::{"{"}<span style={{ color: "#8be9fd" }}>io</span>, <span style={{ color: "#8be9fd" }}>fs</span>{"}"};{"\n"}
                <span style={{ color: "#ff79c6" }}>use</span> std::io::{"{"}self, <span style={{ color: "#8be9fd" }}>Write</span>{"}"};{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Glob operator (use sparingly)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>use</span> std::collections::*;
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4FD1C5" }}>
              Modules in Separate Files
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Project structure:</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// src/</span>{"\n"}
                <span style={{ color: "#6272a4" }}>//   lib.rs</span>{"\n"}
                <span style={{ color: "#6272a4" }}>//   front_of_house.rs      (or front_of_house/mod.rs)</span>{"\n"}
                <span style={{ color: "#6272a4" }}>//   front_of_house/</span>{"\n"}
                <span style={{ color: "#6272a4" }}>//     hosting.rs</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// In lib.rs:</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>mod</span> front_of_house;  <span style={{ color: "#6272a4" }}>// Loads from front_of_house.rs</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// In front_of_house.rs:</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>pub mod</span> hosting;  <span style={{ color: "#6272a4" }}>// Loads from front_of_house/hosting.rs</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4FD1C5" }}>
              Cargo.toml and Dependencies
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}># Cargo.toml</span>{"\n"}
                [package]{"\n"}
                name = <span style={{ color: "#f1fa8c" }}>"my_project"</span>{"\n"}
                version = <span style={{ color: "#f1fa8c" }}>"0.1.0"</span>{"\n"}
                edition = <span style={{ color: "#f1fa8c" }}>"2021"</span>{"\n"}
                {"\n"}
                [dependencies]{"\n"}
                serde = {"{"} version = <span style={{ color: "#f1fa8c" }}>"1.0"</span>, features = [<span style={{ color: "#f1fa8c" }}>"derive"</span>] {"}"}{"\n"}
                tokio = {"{"} version = <span style={{ color: "#f1fa8c" }}>"1"</span>, features = [<span style={{ color: "#f1fa8c" }}>"full"</span>] {"}"}{"\n"}
                rand = <span style={{ color: "#f1fa8c" }}>"0.8"</span>{"\n"}
                {"\n"}
                [dev-dependencies]{"\n"}
                criterion = <span style={{ color: "#f1fa8c" }}>"0.5"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Then: cargo build</span>
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#4FD1C5", 0.08), border: `1px solid ${alpha("#4FD1C5", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                💡 crates.io
              </Typography>
              <Typography variant="body2" color="text.secondary">
                <strong>crates.io</strong> is Rust's official package registry with 130,000+ crates. Use 
                <code> cargo search {"<"}query{">"}</code> to find packages, or browse at crates.io. 
                <code> cargo add {"<"}crate{">"}</code> adds dependencies to your Cargo.toml automatically.
              </Typography>
            </Paper>
          </Paper>

          {/* Testing Section */}
          <Paper id="testing" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#48BB78", 0.15), color: "#48BB78", width: 48, height: 48 }}>
                <SpeedIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Testing
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Rust has first-class support for testing built into the language and Cargo. Write unit tests 
              alongside your code, integration tests in a separate directory, and even test code examples in 
              documentation.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Writing Unit Tests
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>pub fn</span> <span style={{ color: "#50fa7b" }}>add</span>(a: <span style={{ color: "#8be9fd" }}>i32</span>, b: <span style={{ color: "#8be9fd" }}>i32</span>) -{">"} <span style={{ color: "#8be9fd" }}>i32</span> {"{"}{"\n"}
                {"    "}a + b{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Test module - only compiled when testing</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>#[cfg(test)]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>mod</span> tests {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>use super</span>::*;  <span style={{ color: "#6272a4" }}>// Import from parent module</span>{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>#[test]</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>test_add</span>() {"{"}{"\n"}
                {"        "}<span style={{ color: "#50fa7b" }}>assert_eq!</span>(add(<span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>2</span>), <span style={{ color: "#bd93f9" }}>4</span>);{"\n"}
                {"    "}{"}"}{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>#[test]</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>test_add_negative</span>() {"{"}{"\n"}
                {"        "}<span style={{ color: "#50fa7b" }}>assert_eq!</span>(add(-<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>1</span>), <span style={{ color: "#bd93f9" }}>0</span>);{"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Assertion Macros
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { macro: "assert!(expr)", description: "Panics if expression is false" },
                { macro: "assert_eq!(a, b)", description: "Panics if a != b, shows both values" },
                { macro: "assert_ne!(a, b)", description: "Panics if a == b" },
                { macro: 'assert!(expr, "msg")', description: "Custom failure message" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.macro}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#48BB78", 0.03) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#48BB78", fontFamily: "monospace" }}>
                      {item.macro}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.description}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Testing for Panics and Results
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Test that code panics</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>#[test]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>#[should_panic]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>test_divide_by_zero</span>() {"{"}{"\n"}
                {"    "}divide(<span style={{ color: "#bd93f9" }}>10</span>, <span style={{ color: "#bd93f9" }}>0</span>);  <span style={{ color: "#6272a4" }}>// Should panic</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Expected panic message</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>#[test]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>#[should_panic(expected = "division by zero")]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>test_specific_panic</span>() {"{"}{"\n"}
                {"    "}divide(<span style={{ color: "#bd93f9" }}>10</span>, <span style={{ color: "#bd93f9" }}>0</span>);{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Testing Result returns</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>#[test]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>test_result</span>() -{">"} <span style={{ color: "#8be9fd" }}>Result</span>{"<"}(), <span style={{ color: "#8be9fd" }}>String</span>{">"} {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>if</span> <span style={{ color: "#bd93f9" }}>2</span> + <span style={{ color: "#bd93f9" }}>2</span> == <span style={{ color: "#bd93f9" }}>4</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>Ok</span>(()){"\n"}
                {"    "}{"}"} <span style={{ color: "#ff79c6" }}>else</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>Err</span>(<span style={{ color: "#8be9fd" }}>String</span>::from(<span style={{ color: "#f1fa8c" }}>"math is broken"</span>)){"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Integration Tests
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// tests/integration_test.rs (in tests/ directory)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>use</span> my_crate;  <span style={{ color: "#6272a4" }}>// Import your library crate</span>{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>#[test]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>test_public_api</span>() {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Only public API is accessible</span>{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>assert_eq!</span>(my_crate::add(<span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>2</span>), <span style={{ color: "#bd93f9" }}>4</span>);{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Running Tests
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}># Run all tests</span>{"\n"}
                cargo test{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Run tests matching a name</span>{"\n"}
                cargo test test_add{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Run ignored tests</span>{"\n"}
                cargo test -- --ignored{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Show println! output</span>{"\n"}
                cargo test -- --nocapture{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Run tests in single thread</span>{"\n"}
                cargo test -- --test-threads=1
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#48BB78", 0.08), border: `1px solid ${alpha("#48BB78", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                💡 Documentation Tests
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Code blocks in documentation comments (///) are automatically run as tests! This ensures your 
                examples stay correct. Use <code>cargo test --doc</code> to run doc tests specifically. Add 
                <code> # </code> prefix to hide setup lines from docs while still running them.
              </Typography>
            </Paper>
          </Paper>

          {/* Concurrency Section */}
          <Paper id="concurrency" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#4299E1", 0.15), color: "#4299E1", width: 48, height: 48 }}>
                <SyncIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Concurrency
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Rust's ownership system enables "fearless concurrency"—the compiler prevents data races at compile 
              time. Whether using threads, channels, or async/await, Rust guarantees memory safety without a 
              garbage collector.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4299E1" }}>
              Creating Threads
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>use</span> std::thread;{"\n"}
                <span style={{ color: "#ff79c6" }}>use</span> std::time::<span style={{ color: "#8be9fd" }}>Duration</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>main</span>() {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Spawn a new thread</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> handle = thread::spawn(|| {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>for</span> i <span style={{ color: "#ff79c6" }}>in</span> <span style={{ color: "#bd93f9" }}>1</span>..=<span style={{ color: "#bd93f9" }}>5</span> {"{"}{"\n"}
                {"            "}println!(<span style={{ color: "#f1fa8c" }}>"Thread: {"{"}{"}"}"</span>, i);{"\n"}
                {"            "}thread::sleep(<span style={{ color: "#8be9fd" }}>Duration</span>::from_millis(<span style={{ color: "#bd93f9" }}>100</span>));{"\n"}
                {"        "}{"}"}{"\n"}
                {"    "}{"}"});{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Wait for thread to finish</span>{"\n"}
                {"    "}handle.join().unwrap();{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Move data into thread with 'move' closure</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> data = <span style={{ color: "#50fa7b" }}>vec!</span>[<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>];{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> handle = thread::spawn(<span style={{ color: "#ff79c6" }}>move</span> || {"{"}{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"Data: {"{"}:?{"}"}"</span>, data);  <span style={{ color: "#6272a4" }}>// data moved here</span>{"\n"}
                {"}"});
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4299E1" }}>
              Shared State with Arc and Mutex
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>use</span> std::sync::{"{"}Arc, Mutex{"}"};{"\n"}
                <span style={{ color: "#ff79c6" }}>use</span> std::thread;{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>main</span>() {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Arc = Atomic Reference Counting (thread-safe Rc)</span>{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Mutex = Mutual exclusion lock</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> counter = <span style={{ color: "#8be9fd" }}>Arc</span>::new(<span style={{ color: "#8be9fd" }}>Mutex</span>::new(<span style={{ color: "#bd93f9" }}>0</span>));{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let mut</span> handles = <span style={{ color: "#50fa7b" }}>vec!</span>[];{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>for</span> _ <span style={{ color: "#ff79c6" }}>in</span> <span style={{ color: "#bd93f9" }}>0</span>..<span style={{ color: "#bd93f9" }}>10</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>let</span> counter = <span style={{ color: "#8be9fd" }}>Arc</span>::clone(&counter);{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>let</span> handle = thread::spawn(<span style={{ color: "#ff79c6" }}>move</span> || {"{"}{"\n"}
                {"            "}<span style={{ color: "#ff79c6" }}>let mut</span> num = counter.lock().unwrap();{"\n"}
                {"            "}*num += <span style={{ color: "#bd93f9" }}>1</span>;{"\n"}
                {"        "}{"}"});{"\n"}
                {"        "}handles.push(handle);{"\n"}
                {"    "}{"}"}{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>for</span> handle <span style={{ color: "#ff79c6" }}>in</span> handles {"{"}{"\n"}
                {"        "}handle.join().unwrap();{"\n"}
                {"    "}{"}"}{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"Result: {"{"}{"}"}"</span>, *counter.lock().unwrap());  <span style={{ color: "#6272a4" }}>// 10</span>{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4299E1" }}>
              Message Passing with Channels
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>use</span> std::sync::mpsc;  <span style={{ color: "#6272a4" }}>// multi-producer, single-consumer</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>use</span> std::thread;{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>main</span>() {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> (tx, rx) = mpsc::channel();{"\n"}
                {"    "}{"\n"}
                {"    "}thread::spawn(<span style={{ color: "#ff79c6" }}>move</span> || {"{"}{"\n"}
                {"        "}tx.send(<span style={{ color: "#f1fa8c" }}>"Hello from thread!"</span>).unwrap();{"\n"}
                {"    "}{"}"});{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// recv() blocks until message received</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> msg = rx.recv().unwrap();{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"Got: {"{"}{"}"}"</span>, msg);{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Multiple producers: clone tx</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> tx2 = tx.clone();
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4299E1" }}>
              Async/Await (with Tokio)
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Cargo.toml: tokio = {"{"} version = "1", features = ["full"] {"}"}</span>{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>use</span> tokio::time::{"{"}sleep, <span style={{ color: "#8be9fd" }}>Duration</span>{"}"};{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>#[tokio::main]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>async fn</span> <span style={{ color: "#50fa7b" }}>main</span>() {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Spawn async tasks</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> task1 = tokio::spawn(<span style={{ color: "#ff79c6" }}>async</span> {"{"}{"\n"}
                {"        "}sleep(<span style={{ color: "#8be9fd" }}>Duration</span>::from_millis(<span style={{ color: "#bd93f9" }}>100</span>)).<span style={{ color: "#ff79c6" }}>await</span>;{"\n"}
                {"        "}<span style={{ color: "#f1fa8c" }}>"Task 1 done"</span>{"\n"}
                {"    "}{"}"});{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> task2 = tokio::spawn(fetch_data());{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Wait for both</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> (r1, r2) = tokio::join!(task1, task2);{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>async fn</span> <span style={{ color: "#50fa7b" }}>fetch_data</span>() -{">"} <span style={{ color: "#8be9fd" }}>String</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// .await suspends until ready, doesn't block thread</span>{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>String</span>::from(<span style={{ color: "#f1fa8c" }}>"data"</span>){"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Grid container spacing={2}>
              {[
                { trait: "Send", description: "Type can be transferred to another thread" },
                { trait: "Sync", description: "Type can be shared between threads via references" },
                { trait: "RwLock", description: "Multiple readers OR single writer lock" },
                { trait: "Atomic*", description: "Lock-free atomic operations (AtomicBool, AtomicUsize, etc.)" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.trait}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#4299E1", 0.03) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#4299E1", fontFamily: "monospace" }}>
                      {item.trait}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.description}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, mt: 3, borderRadius: 2, bgcolor: alpha("#4299E1", 0.08), border: `1px solid ${alpha("#4299E1", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                💡 Threads vs Async
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Use <strong>threads</strong> for CPU-bound work (parallel computation). Use <strong>async/await</strong> 
                for I/O-bound work (network requests, file I/O)—async tasks are lightweight and can have thousands 
                running concurrently on a single thread.
              </Typography>
            </Paper>
          </Paper>

          {/* Unsafe Rust Section */}
          <Paper id="unsafe" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#ECC94B", 0.15), color: "#ECC94B", width: 48, height: 48 }}>
                <WarningIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Unsafe Rust
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Unsafe Rust lets you bypass some of the compiler's safety checks for low-level operations. It's an 
              escape hatch, not a license to write unsafe code carelessly. Most Rust code should be safe; use 
              unsafe only when necessary and wrap it in safe abstractions.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ECC94B" }}>
              What Unsafe Allows
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { power: "Dereference raw pointers", desc: "*const T and *mut T without automatic safety checks" },
                { power: "Call unsafe functions", desc: "Functions marked unsafe or FFI functions" },
                { power: "Access mutable statics", desc: "static mut variables (inherently unsafe)" },
                { power: "Implement unsafe traits", desc: "Traits like Send and Sync when you guarantee safety" },
                { power: "Access union fields", desc: "Reading union fields requires manual type safety" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.power}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ECC94B", 0.05), borderLeft: `3px solid #ECC94B` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ECC94B" }}>
                      {item.power}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ECC94B" }}>
              Raw Pointers
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>let mut</span> num = <span style={{ color: "#bd93f9" }}>5</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Creating raw pointers is safe</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> r1 = &num <span style={{ color: "#ff79c6" }}>as</span> *<span style={{ color: "#ff79c6" }}>const</span> <span style={{ color: "#8be9fd" }}>i32</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> r2 = &<span style={{ color: "#ff79c6" }}>mut</span> num <span style={{ color: "#ff79c6" }}>as</span> *<span style={{ color: "#ff79c6" }}>mut</span> <span style={{ color: "#8be9fd" }}>i32</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Dereferencing requires unsafe</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>unsafe</span> {"{"}{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"r1: {"{"}{"}"}"</span>, *r1);{"\n"}
                {"    "}*r2 = <span style={{ color: "#bd93f9" }}>10</span>;{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Raw pointers can be null or dangling!</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// They don't implement automatic cleanup</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ECC94B" }}>
              Unsafe Functions
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Declaring an unsafe function</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>unsafe fn</span> <span style={{ color: "#50fa7b" }}>dangerous</span>() {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Can do unsafe things without unsafe block</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Must call in unsafe block</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>unsafe</span> {"{"}{"\n"}
                {"    "}dangerous();{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Safe abstraction over unsafe code</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>split_at_mut</span>(slice: &<span style={{ color: "#ff79c6" }}>mut</span> [<span style={{ color: "#8be9fd" }}>i32</span>], mid: <span style={{ color: "#8be9fd" }}>usize</span>) -{">"} (&<span style={{ color: "#ff79c6" }}>mut</span> [<span style={{ color: "#8be9fd" }}>i32</span>], &<span style={{ color: "#ff79c6" }}>mut</span> [<span style={{ color: "#8be9fd" }}>i32</span>]) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> len = slice.len();{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> ptr = slice.as_mut_ptr();{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>assert!</span>(mid {"<"}= len);{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>unsafe</span> {"{"}{"\n"}
                {"        "}(std::slice::from_raw_parts_mut(ptr, mid),{"\n"}
                {"         "}std::slice::from_raw_parts_mut(ptr.add(mid), len - mid)){"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ECC94B" }}>
              FFI (Foreign Function Interface)
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Calling C functions from Rust</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>extern</span> <span style={{ color: "#f1fa8c" }}>"C"</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>abs</span>(input: <span style={{ color: "#8be9fd" }}>i32</span>) -{">"} <span style={{ color: "#8be9fd" }}>i32</span>;{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>strlen</span>(s: *<span style={{ color: "#ff79c6" }}>const</span> <span style={{ color: "#8be9fd" }}>i8</span>) -{">"} <span style={{ color: "#8be9fd" }}>usize</span>;{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>main</span>() {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>unsafe</span> {"{"}{"\n"}
                {"        "}println!(<span style={{ color: "#f1fa8c" }}>"abs(-5) = {"{"}{"}"}"</span>, abs(-<span style={{ color: "#bd93f9" }}>5</span>));{"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Exposing Rust to C</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>#[no_mangle]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>pub extern</span> <span style={{ color: "#f1fa8c" }}>"C"</span> <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>call_from_c</span>() {"{"}{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"Called from C!"</span>);{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#ECC94B", 0.08), border: `1px solid ${alpha("#ECC94B", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                ⚠️ Unsafe Best Practices
              </Typography>
              <Typography variant="body2" color="text.secondary">
                <strong>Minimize unsafe:</strong> Keep unsafe blocks as small as possible.
                <br /><strong>Document invariants:</strong> Explain why the unsafe code is actually safe.
                <br /><strong>Wrap in safe APIs:</strong> Encapsulate unsafe code behind safe abstractions.
                <br /><strong>Test thoroughly:</strong> Use tools like Miri and ASAN to catch undefined behavior.
              </Typography>
            </Paper>
          </Paper>

          {/* Web Development Section */}
          <Paper id="web" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#0BC5EA", 0.15), color: "#0BC5EA", width: 48, height: 48 }}>
                <HttpIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Web Development
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Rust excels at building fast, reliable web services. Its async ecosystem, strong typing, and 
              memory safety make it ideal for backend APIs, microservices, and even frontend via WebAssembly.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0BC5EA" }}>
              Popular Web Frameworks
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "Axum", desc: "Modern, ergonomic framework built on Tokio/Tower. Great DX.", stars: "⭐ Rising" },
                { name: "Actix-web", desc: "Extremely fast, battle-tested, feature-rich.", stars: "⭐ Popular" },
                { name: "Rocket", desc: "Developer-friendly with type-safe routing. Uses macros.", stars: "⭐ Ergonomic" },
                { name: "Warp", desc: "Composable filter-based framework. Lightweight.", stars: "⭐ Minimal" },
              ].map((fw) => (
                <Grid item xs={12} sm={6} key={fw.name}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#0BC5EA", 0.03) }}>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#0BC5EA" }}>
                        {fw.name}
                      </Typography>
                      <Chip label={fw.stars} size="small" sx={{ fontSize: 10, height: 20 }} />
                    </Box>
                    <Typography variant="body2" color="text.secondary">
                      {fw.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0BC5EA" }}>
              REST API with Axum
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Cargo.toml: axum = "0.7", tokio = {"{"} version = "1", features = ["full"] {"}"}</span>{"\n"}
                <span style={{ color: "#6272a4" }}>//             serde = {"{"} version = "1", features = ["derive"] {"}"}</span>{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>use</span> axum::{"{"}routing::{"{"}get, post{"}"}, <span style={{ color: "#8be9fd" }}>Router</span>, <span style={{ color: "#8be9fd" }}>Json</span>{"}"};{"\n"}
                <span style={{ color: "#ff79c6" }}>use</span> serde::{"{"}Deserialize, Serialize{"}"};{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>#[derive(Serialize)]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>User</span> {"{"} id: <span style={{ color: "#8be9fd" }}>u64</span>, name: <span style={{ color: "#8be9fd" }}>String</span> {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>#[derive(Deserialize)]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>CreateUser</span> {"{"} name: <span style={{ color: "#8be9fd" }}>String</span> {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>#[tokio::main]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>async fn</span> <span style={{ color: "#50fa7b" }}>main</span>() {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> app = <span style={{ color: "#8be9fd" }}>Router</span>::new(){"\n"}
                {"        "}.route(<span style={{ color: "#f1fa8c" }}>"/"</span>, get(|| <span style={{ color: "#ff79c6" }}>async</span> {"{"} <span style={{ color: "#f1fa8c" }}>"Hello, World!"</span> {"}"}))){"\n"}
                {"        "}.route(<span style={{ color: "#f1fa8c" }}>"/users"</span>, get(list_users)){"\n"}
                {"        "}.route(<span style={{ color: "#f1fa8c" }}>"/users"</span>, post(create_user));{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> listener = tokio::net::<span style={{ color: "#8be9fd" }}>TcpListener</span>::bind(<span style={{ color: "#f1fa8c" }}>"0.0.0.0:3000"</span>).<span style={{ color: "#ff79c6" }}>await</span>.unwrap();{"\n"}
                {"    "}axum::serve(listener, app).<span style={{ color: "#ff79c6" }}>await</span>.unwrap();{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>async fn</span> <span style={{ color: "#50fa7b" }}>list_users</span>() -{">"} <span style={{ color: "#8be9fd" }}>Json</span>{"<"}<span style={{ color: "#8be9fd" }}>Vec</span>{"<"}<span style={{ color: "#8be9fd" }}>User</span>{">>"} {"{"}{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>Json</span>(<span style={{ color: "#50fa7b" }}>vec!</span>[<span style={{ color: "#8be9fd" }}>User</span> {"{"} id: <span style={{ color: "#bd93f9" }}>1</span>, name: <span style={{ color: "#f1fa8c" }}>"Alice"</span>.into() {"}"}]){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>async fn</span> <span style={{ color: "#50fa7b" }}>create_user</span>(<span style={{ color: "#8be9fd" }}>Json</span>(payload): <span style={{ color: "#8be9fd" }}>Json</span>{"<"}<span style={{ color: "#8be9fd" }}>CreateUser</span>{">"}) -{">"} <span style={{ color: "#8be9fd" }}>Json</span>{"<"}<span style={{ color: "#8be9fd" }}>User</span>{">"} {"{"}{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>Json</span>(<span style={{ color: "#8be9fd" }}>User</span> {"{"} id: <span style={{ color: "#bd93f9" }}>2</span>, name: payload.name {"}"}){"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#0BC5EA" }}>
              Database Access (SQLx)
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// sqlx = {"{"} version = "0.7", features = ["runtime-tokio", "postgres"] {"}"}</span>{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>use</span> sqlx::postgres::<span style={{ color: "#8be9fd" }}>PgPoolOptions</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>#[derive(sqlx::FromRow)]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>User</span> {"{"} id: <span style={{ color: "#8be9fd" }}>i32</span>, name: <span style={{ color: "#8be9fd" }}>String</span> {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>async fn</span> <span style={{ color: "#50fa7b" }}>get_users</span>() -{">"} <span style={{ color: "#8be9fd" }}>Result</span>{"<"}<span style={{ color: "#8be9fd" }}>Vec</span>{"<"}<span style={{ color: "#8be9fd" }}>User</span>{">"}, sqlx::<span style={{ color: "#8be9fd" }}>Error</span>{">"} {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> pool = <span style={{ color: "#8be9fd" }}>PgPoolOptions</span>::new(){"\n"}
                {"        "}.connect(<span style={{ color: "#f1fa8c" }}>"postgres://user:pass@localhost/db"</span>).<span style={{ color: "#ff79c6" }}>await</span>?;{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Compile-time checked SQL!</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> users = sqlx::query_as!(User, <span style={{ color: "#f1fa8c" }}>"SELECT id, name FROM users"</span>){"\n"}
                {"        "}.fetch_all(&pool).<span style={{ color: "#ff79c6" }}>await</span>?;{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>Ok</span>(users){"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#0BC5EA", 0.08), border: `1px solid ${alpha("#0BC5EA", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                💡 WebAssembly (WASM)
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Compile Rust to WebAssembly with <code>wasm-pack</code> for near-native performance in browsers. 
                Use <strong>Yew</strong> or <strong>Leptos</strong> for full-stack Rust web apps with reactive UIs. 
                Great for computationally intensive web apps like games, image processing, or crypto.
              </Typography>
            </Paper>
          </Paper>

          {/* CLI Applications Section */}
          <Paper id="cli" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#718096", 0.15), color: "#718096", width: 48, height: 48 }}>
                <TerminalIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                CLI Applications
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Rust is excellent for building command-line tools: fast startup, single-binary distribution, 
              cross-platform compilation, and great libraries for argument parsing, terminal UIs, and more.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#718096" }}>
              Argument Parsing with Clap
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Cargo.toml: clap = {"{"} version = "4", features = ["derive"] {"}"}</span>{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>use</span> clap::<span style={{ color: "#8be9fd" }}>Parser</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>#[derive(Parser)]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>#[command(name = "myapp")]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>#[command(about = "A fantastic CLI tool")]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>struct</span> <span style={{ color: "#8be9fd" }}>Args</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>/// Input file to process</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>#[arg(short, long)]</span>{"\n"}
                {"    "}input: <span style={{ color: "#8be9fd" }}>String</span>,{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>/// Output directory</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>#[arg(short, long, default_value = ".")]</span>{"\n"}
                {"    "}output: <span style={{ color: "#8be9fd" }}>String</span>,{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>/// Verbose mode</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>#[arg(short, long)]</span>{"\n"}
                {"    "}verbose: <span style={{ color: "#8be9fd" }}>bool</span>,{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>main</span>() {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>let</span> args = <span style={{ color: "#8be9fd" }}>Args</span>::parse();{"\n"}
                {"    "}println!(<span style={{ color: "#f1fa8c" }}>"Processing: {"{"}{"}"}"</span>, args.input);{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Usage: myapp -i file.txt -o /out -v</span>{"\n"}
                <span style={{ color: "#6272a4" }}>//        myapp --help</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#718096" }}>
              Progress Bars with Indicatif
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>use</span> indicatif::{"{"}ProgressBar, ProgressStyle{"}"};{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> pb = <span style={{ color: "#8be9fd" }}>ProgressBar</span>::new(<span style={{ color: "#bd93f9" }}>100</span>);{"\n"}
                pb.set_style(<span style={{ color: "#8be9fd" }}>ProgressStyle</span>::default_bar(){"\n"}
                {"    "}.template(<span style={{ color: "#f1fa8c" }}>"[{"{"}bar:40{"}"}] {"{"}pos{"}"}/{"{"}len{"}"} {"{"}msg{"}"}"</span>)?{"\n"}
                {"    "}.progress_chars(<span style={{ color: "#f1fa8c" }}>"##-"</span>));{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> i <span style={{ color: "#ff79c6" }}>in</span> <span style={{ color: "#bd93f9" }}>0</span>..<span style={{ color: "#bd93f9" }}>100</span> {"{"}{"\n"}
                {"    "}pb.inc(<span style={{ color: "#bd93f9" }}>1</span>);{"\n"}
                {"    "}pb.set_message(<span style={{ color: "#50fa7b" }}>format!</span>(<span style={{ color: "#f1fa8c" }}>"Processing item {"{"}{"}"}"</span>, i));{"\n"}
                {"    "}std::thread::sleep(std::time::Duration::from_millis(<span style={{ color: "#bd93f9" }}>50</span>));{"\n"}
                {"}"}{"\n"}
                pb.finish_with_message(<span style={{ color: "#f1fa8c" }}>"Done!"</span>);
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#718096" }}>
              Essential CLI Crates
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "clap", desc: "Argument parser with derive macros" },
                { name: "indicatif", desc: "Progress bars and spinners" },
                { name: "dialoguer", desc: "Interactive prompts and menus" },
                { name: "colored", desc: "Colored terminal output" },
                { name: "anyhow", desc: "Easy error handling" },
                { name: "dirs", desc: "Platform-specific directories" },
              ].map((crate_info) => (
                <Grid item xs={6} sm={4} key={crate_info.name}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#718096", 0.03), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#718096", fontFamily: "monospace" }}>
                      {crate_info.name}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {crate_info.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}># Cross-compile for different platforms</span>{"\n"}
                rustup target add x86_64-unknown-linux-musl{"\n"}
                cargo build --release --target x86_64-unknown-linux-musl{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Common targets:</span>{"\n"}
                <span style={{ color: "#6272a4" }}># x86_64-pc-windows-msvc      (Windows)</span>{"\n"}
                <span style={{ color: "#6272a4" }}># x86_64-apple-darwin         (macOS Intel)</span>{"\n"}
                <span style={{ color: "#6272a4" }}># aarch64-apple-darwin        (macOS ARM)</span>{"\n"}
                <span style={{ color: "#6272a4" }}># x86_64-unknown-linux-gnu    (Linux)</span>{"\n"}
                <span style={{ color: "#6272a4" }}># x86_64-unknown-linux-musl   (Linux static)</span>
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#718096", 0.08), border: `1px solid ${alpha("#718096", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                💡 Popular Rust CLI Tools
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Many beloved CLI tools are built with Rust: <strong>ripgrep</strong> (fast grep), <strong>fd</strong> (fast find), 
                <strong> bat</strong> (better cat), <strong>exa/eza</strong> (better ls), <strong>delta</strong> (git diff viewer), 
                <strong> starship</strong> (shell prompt), <strong>zoxide</strong> (smart cd). Install them with <code>cargo install</code>!
              </Typography>
            </Paper>
          </Paper>

          {/* Advanced Topics Section */}
          <Paper id="advanced" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#805AD5", 0.15), color: "#805AD5", width: 48, height: 48 }}>
                <DeveloperBoardIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Advanced Topics
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              These advanced features give you fine-grained control over memory, enable powerful abstractions, 
              and unlock metaprogramming capabilities. Master these to write truly idiomatic Rust.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#805AD5" }}>
              Smart Pointers
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "Box<T>", desc: "Heap allocation with single ownership. Enables recursive types.", example: "Box::new(5)" },
                { name: "Rc<T>", desc: "Reference counting (single-threaded). Multiple owners.", example: "Rc::clone(&rc)" },
                { name: "Arc<T>", desc: "Atomic Rc for thread-safe sharing.", example: "Arc::clone(&arc)" },
                { name: "RefCell<T>", desc: "Interior mutability with runtime borrow checking.", example: "cell.borrow_mut()" },
                { name: "Mutex<T>", desc: "Thread-safe interior mutability with locking.", example: "mutex.lock()" },
                { name: "RwLock<T>", desc: "Multiple readers OR single writer lock.", example: "rw.read()" },
              ].map((ptr) => (
                <Grid item xs={12} sm={6} md={4} key={ptr.name}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#805AD5", 0.03), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#805AD5", fontFamily: "monospace" }}>
                      {ptr.name}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ fontSize: 12, mb: 1 }}>
                      {ptr.desc}
                    </Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#50fa7b" }}>
                      {ptr.example}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#805AD5" }}>
              Closures
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Closure syntax</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> add = |a, b| a + b;{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> add_typed = |a: <span style={{ color: "#8be9fd" }}>i32</span>, b: <span style={{ color: "#8be9fd" }}>i32</span>| -{">"} <span style={{ color: "#8be9fd" }}>i32</span> {"{"} a + b {"}"};{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Closures capture environment</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> x = <span style={{ color: "#bd93f9" }}>10</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> add_x = |n| n + x;  <span style={{ color: "#6272a4" }}>// Captures x by reference</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// move keyword takes ownership</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> s = <span style={{ color: "#8be9fd" }}>String</span>::from(<span style={{ color: "#f1fa8c" }}>"hello"</span>);{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> consume = <span style={{ color: "#ff79c6" }}>move</span> || println!(<span style={{ color: "#f1fa8c" }}>"{"{}"}"</span>, s);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Fn traits: Fn, FnMut, FnOnce</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fn</span> <span style={{ color: "#50fa7b" }}>apply</span>{"<"}<span style={{ color: "#8be9fd" }}>F</span>: <span style={{ color: "#8be9fd" }}>Fn</span>(<span style={{ color: "#8be9fd" }}>i32</span>) -{">"} <span style={{ color: "#8be9fd" }}>i32</span>{">"}(f: <span style={{ color: "#8be9fd" }}>F</span>, x: <span style={{ color: "#8be9fd" }}>i32</span>) -{">"} <span style={{ color: "#8be9fd" }}>i32</span> {"{"}{"\n"}
                {"    "}f(x){"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#805AD5" }}>
              Iterators
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>let</span> v = <span style={{ color: "#50fa7b" }}>vec!</span>[<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>4</span>, <span style={{ color: "#bd93f9" }}>5</span>];{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Iterator adaptors (lazy!)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>let</span> result: <span style={{ color: "#8be9fd" }}>Vec</span>{"<"}<span style={{ color: "#8be9fd" }}>i32</span>{">"} = v.iter(){"\n"}
                {"    "}.map(|x| x * <span style={{ color: "#bd93f9" }}>2</span>)           <span style={{ color: "#6272a4" }}>// [2, 4, 6, 8, 10]</span>{"\n"}
                {"    "}.filter(|x| *x {">"} <span style={{ color: "#bd93f9" }}>5</span>)     <span style={{ color: "#6272a4" }}>// [6, 8, 10]</span>{"\n"}
                {"    "}.take(<span style={{ color: "#bd93f9" }}>2</span>)                <span style={{ color: "#6272a4" }}>// [6, 8]</span>{"\n"}
                {"    "}.collect();           <span style={{ color: "#6272a4" }}>// Consume iterator</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Useful methods</span>{"\n"}
                v.iter().sum::{"<"}<span style={{ color: "#8be9fd" }}>i32</span>{">"}()         <span style={{ color: "#6272a4" }}>// 15</span>{"\n"}
                v.iter().any(|x| *x {">"} <span style={{ color: "#bd93f9" }}>3</span>)   <span style={{ color: "#6272a4" }}>// true</span>{"\n"}
                v.iter().find(|x| **x == <span style={{ color: "#bd93f9" }}>3</span>) <span style={{ color: "#6272a4" }}>// Some(&3)</span>{"\n"}
                v.iter().enumerate()         <span style={{ color: "#6272a4" }}>// [(0,&1), (1,&2), ...]</span>{"\n"}
                v.iter().zip(other.iter())   <span style={{ color: "#6272a4" }}>// Pair up elements</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#805AD5" }}>
              Declarative Macros
            </Typography>

            <Paper sx={{ p: 2, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Define a macro with macro_rules!</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>macro_rules!</span> say_hello {"{"}{"\n"}
                {"    "}() ={">"}  {"{"}{"\n"}
                {"        "}println!(<span style={{ color: "#f1fa8c" }}>"Hello!"</span>);{"\n"}
                {"    "}{"}"}; {"\n"}
                {"    "}($name:expr) ={">"}  {"{"}{"\n"}
                {"        "}println!(<span style={{ color: "#f1fa8c" }}>"Hello, {"{"}{"}"}"</span>, $name);{"\n"}
                {"    "}{"}"};{"\n"}
                {"}"}{"\n"}
                {"\n"}
                say_hello!();              <span style={{ color: "#6272a4" }}>// Hello!</span>{"\n"}
                say_hello!(<span style={{ color: "#f1fa8c" }}>"Rust"</span>);        <span style={{ color: "#6272a4" }}>// Hello, Rust</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// vec! is a macro! Here's how it might work:</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>macro_rules!</span> my_vec {"{"}{"\n"}
                {"    "}( $( $x:expr ),* ) ={">"}  {"{"}{"\n"}
                {"        "}{"{"}{"\n"}
                {"            "}<span style={{ color: "#ff79c6" }}>let mut</span> temp = <span style={{ color: "#8be9fd" }}>Vec</span>::new();{"\n"}
                {"            "}$( temp.push($x); )*{"\n"}
                {"            "}temp{"\n"}
                {"        "}{"}"}{"\n"}
                {"    "}{"}"};{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Grid container spacing={2}>
              {[
                { topic: "Const Generics", desc: "Generic over constant values: [T; N]" },
                { topic: "GATs", desc: "Generic Associated Types for advanced patterns" },
                { topic: "Procedural Macros", desc: "#[derive], attribute, and function-like macros" },
                { topic: "no_std", desc: "Embedded development without standard library" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.topic}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#805AD5", 0.05), borderLeft: `3px solid #805AD5` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#805AD5" }}>
                      {item.topic}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, mt: 3, borderRadius: 2, bgcolor: alpha("#805AD5", 0.08), border: `1px solid ${alpha("#805AD5", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                💡 Performance Tips
              </Typography>
              <Typography variant="body2" color="text.secondary">
                <strong>Release builds:</strong> <code>cargo build --release</code> enables optimizations (huge difference!).
                <br /><strong>Avoid allocations:</strong> Reuse buffers, use iterators, prefer &str over String when possible.
                <br /><strong>Profile first:</strong> Use <code>cargo flamegraph</code> or <code>perf</code> before optimizing.
                <br /><strong>Consider SIMD:</strong> Crates like <code>packed_simd</code> for data parallelism.
              </Typography>
            </Paper>
          </Paper>

          {/* Quiz Section */}
          <Paper id="quiz" sx={{ p: 4, mb: 4, borderRadius: 4, border: `2px solid ${alpha(accentColor, 0.3)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <QuizIcon />
              </Avatar>
              <Box>
                <Typography variant="h5" sx={{ fontWeight: 800 }}>
                  Knowledge Quiz
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Test your understanding with 10 random questions from a bank of 75
                </Typography>
              </Box>
            </Box>

            <QuizComponent />
          </Paper>

          {/* Continue Your Journey */}
          <Paper sx={{ p: 4, borderRadius: 4, border: `1px solid ${alpha(accentColor, 0.2)}` }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 2 }}>
              Continue Your Journey
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              After mastering Rust, explore related topics to expand your expertise:
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              {[
                { label: "C Programming", path: "/learn/c-programming" },
                { label: "C++ Programming", path: "/learn/cpp-programming" },
                { label: "Go Programming", path: "/learn/go-programming" },
                { label: "Systems Programming", path: "/learn/systems-administration" },
                { label: "WebAssembly", path: "/learn/webassembly" },
                { label: "Linux Fundamentals", path: "/learn/linux-fundamentals" },
                { label: "Computer Networking", path: "/learn/networking" },
                { label: "Reverse Engineering", path: "/learn/intro-to-re" },
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
