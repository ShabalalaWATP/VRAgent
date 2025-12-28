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
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import CodeIcon from "@mui/icons-material/Code";
import StorageIcon from "@mui/icons-material/Storage";
import BuildIcon from "@mui/icons-material/Build";
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
import CloudIcon from "@mui/icons-material/Cloud";
import SyncIcon from "@mui/icons-material/Sync";
import DataObjectIcon from "@mui/icons-material/DataObject";
import SwapHorizIcon from "@mui/icons-material/SwapHoriz";
import CategoryIcon from "@mui/icons-material/Category";
import ClassIcon from "@mui/icons-material/Class";
import IntegrationInstructionsIcon from "@mui/icons-material/IntegrationInstructions";
import MemoryIcon from "@mui/icons-material/Memory";
import WebIcon from "@mui/icons-material/Web";
import SportsEsportsIcon from "@mui/icons-material/SportsEsports";
import DesktopWindowsIcon from "@mui/icons-material/DesktopWindows";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutline";
import CancelOutlinedIcon from "@mui/icons-material/CancelOutlined";
import LearnPageLayout from "../components/LearnPageLayout";

const accentColor = "#512BD4"; // .NET purple
const accentColorDark = "#68217A"; // Visual Studio purple

// Module navigation items for sidebar
const moduleNavItems = [
  { id: "introduction", label: "Introduction", icon: <SchoolIcon /> },
  { id: "history", label: "History & Evolution", icon: <HistoryIcon /> },
  { id: "setup", label: "Environment Setup", icon: <BuildIcon /> },
  { id: "basics", label: "C# Basics & Syntax", icon: <CodeIcon /> },
  { id: "variables", label: "Variables & Data Types", icon: <DataObjectIcon /> },
  { id: "operators", label: "Operators & Expressions", icon: <SwapHorizIcon /> },
  { id: "control-flow", label: "Control Flow", icon: <AccountTreeIcon /> },
  { id: "arrays", label: "Arrays & Collections", icon: <StorageIcon /> },
  { id: "methods", label: "Methods", icon: <ExtensionIcon /> },
  { id: "oop", label: "OOP Fundamentals", icon: <ClassIcon /> },
  { id: "inheritance", label: "Inheritance & Polymorphism", icon: <LayersIcon /> },
  { id: "interfaces", label: "Interfaces & Abstracts", icon: <ViewModuleIcon /> },
  { id: "exceptions", label: "Exception Handling", icon: <BugReportIcon /> },
  { id: "generics", label: "Generics", icon: <AutoFixHighIcon /> },
  { id: "linq", label: "LINQ", icon: <CategoryIcon /> },
  { id: "async", label: "Async/Await", icon: <SyncIcon /> },
  { id: "dotnet", label: ".NET Ecosystem", icon: <IntegrationInstructionsIcon /> },
  { id: "advanced", label: "Advanced Topics", icon: <DeveloperBoardIcon /> },
  { id: "quiz", label: "Knowledge Quiz", icon: <QuizIcon /> },
];

// Quick stats for hero section
const quickStats = [
  { label: "Created", value: "2000", color: "#512BD4" },
  { label: "Creator", value: "Microsoft", color: "#68217A" },
  { label: "Paradigm", value: "OOP", color: "#4A90D9" },
  { label: "Latest Ver", value: "12.0", color: "#48BB78" },
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

// Quiz interfaces
interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
}

// 75-question bank for C#
const csharpQuestionBank: QuizQuestion[] = [
  // C# Basics (1-15)
  { id: 1, question: "Who created C# and when?", options: ["Sun Microsystems, 1995", "Microsoft/Anders Hejlsberg, 2000", "Apple, 2014", "Google, 2009"], correctAnswer: 1, explanation: "C# was created by Anders Hejlsberg at Microsoft and released in 2000 as part of the .NET initiative." },
  { id: 2, question: "What does the 'using' directive do?", options: ["Creates a new object", "Imports a namespace", "Defines a variable", "Declares a method"], correctAnswer: 1, explanation: "The 'using' directive imports namespaces so you can use types without fully qualifying them. Example: using System;" },
  { id: 3, question: "Which keyword is used to define a class?", options: ["struct", "type", "class", "define"], correctAnswer: 2, explanation: "The 'class' keyword defines a reference type. Classes support inheritance, unlike structs which are value types." },
  { id: 4, question: "What is the entry point of a C# application?", options: ["Start()", "Main()", "Run()", "Init()"], correctAnswer: 1, explanation: "Main() is the entry point. In C# 9+, top-level statements can be used, but internally they compile to a Main method." },
  { id: 5, question: "How do you declare a constant in C#?", options: ["final int x = 5;", "const int x = 5;", "constant int x = 5;", "static int x = 5;"], correctAnswer: 1, explanation: "const declares compile-time constants. readonly is for runtime constants that can be set in constructor." },
  { id: 6, question: "What is the difference between 'var' and explicit typing?", options: ["var is untyped", "var is implicitly typed at compile time", "var is dynamic", "No difference"], correctAnswer: 1, explanation: "var allows implicit typing where the compiler infers the type. It's still strongly typed at compile time." },
  { id: 7, question: "Which statement correctly prints to the console?", options: ["print('Hello');", "Console.WriteLine('Hello');", "System.out.println('Hello');", "echo 'Hello';"], correctAnswer: 1, explanation: "Console.WriteLine() writes to standard output with a newline. Console.Write() doesn't add a newline." },
  { id: 8, question: "What is the default access modifier for class members?", options: ["public", "private", "protected", "internal"], correctAnswer: 1, explanation: "Class members default to private. Classes themselves default to internal within an assembly." },
  { id: 9, question: "How do you create a single-line comment?", options: ["# comment", "// comment", "/* comment */", "-- comment"], correctAnswer: 1, explanation: "// creates single-line comments. /* */ is for multi-line. /// is for XML documentation comments." },
  { id: 10, question: "What is string interpolation syntax?", options: ["'Hello {name}'", "\"Hello \" + name", "$\"Hello {name}\"", "f\"Hello {name}\""], correctAnswer: 2, explanation: "String interpolation uses $ prefix: $\"Hello {name}\". It's cleaner than concatenation and was added in C# 6." },
  { id: 11, question: "What does 'namespace' do?", options: ["Creates a class", "Organizes code into logical groups", "Imports libraries", "Defines scope"], correctAnswer: 1, explanation: "Namespaces organize code and prevent naming conflicts. They provide a hierarchical system for types." },
  { id: 12, question: "What is the null-conditional operator?", options: ["??", "?.", "?:", "!."], correctAnswer: 1, explanation: "?. safely accesses members of potentially null objects. obj?.Property returns null if obj is null instead of throwing." },
  { id: 13, question: "How do you declare a nullable value type?", options: ["int null x;", "int? x;", "nullable int x;", "int x = null;"], correctAnswer: 1, explanation: "int? (Nullable<int>) allows value types to be null. Essential for database columns that can be NULL." },
  { id: 14, question: "What is the null-coalescing operator?", options: ["?.", "??", "?:", "||"], correctAnswer: 1, explanation: "?? returns left operand if not null, otherwise right operand. Example: string name = input ?? \"default\";" },
  { id: 15, question: "What does 'nameof' return?", options: ["Type of variable", "Name of variable as string", "Value of variable", "Hash code"], correctAnswer: 1, explanation: "nameof() returns the name of a variable, type, or member as a string. Useful for avoiding magic strings in error messages." },
  
  // OOP Concepts (16-30)
  { id: 16, question: "What is encapsulation?", options: ["Code reuse", "Hiding internal details behind public interface", "Multiple inheritance", "Method overloading"], correctAnswer: 1, explanation: "Encapsulation bundles data and methods, hiding implementation details. Achieved through access modifiers and properties." },
  { id: 17, question: "How do you define a property with automatic backing field?", options: ["public int Age;", "public int Age { get; set; }", "property int Age;", "int Age => value;"], correctAnswer: 1, explanation: "Auto-implemented properties generate a hidden backing field. { get; set; } is the syntax for read-write properties." },
  { id: 18, question: "What keyword prevents a class from being inherited?", options: ["static", "sealed", "final", "private"], correctAnswer: 1, explanation: "sealed prevents inheritance. A sealed class cannot be used as a base class. Methods can also be sealed." },
  { id: 19, question: "What is polymorphism?", options: ["Single inheritance", "Same interface, different implementations", "Multiple classes", "Static typing"], correctAnswer: 1, explanation: "Polymorphism allows objects of different types to be treated uniformly. Achieved through inheritance and interfaces." },
  { id: 20, question: "What does 'virtual' keyword do?", options: ["Makes method abstract", "Allows method to be overridden", "Makes method static", "Prevents overriding"], correctAnswer: 1, explanation: "virtual allows a method to be overridden in derived classes using the override keyword." },
  { id: 21, question: "What is the difference between 'override' and 'new'?", options: ["No difference", "override replaces, new hides", "new replaces, override hides", "Both replace"], correctAnswer: 1, explanation: "override provides polymorphic behavior (runtime binding). new hides the base method (compile-time binding)." },
  { id: 22, question: "What is an abstract class?", options: ["A class with no methods", "A class that cannot be instantiated directly", "A static class", "A sealed class"], correctAnswer: 1, explanation: "Abstract classes cannot be instantiated and may contain abstract members that derived classes must implement." },
  { id: 23, question: "What can an interface contain in modern C#?", options: ["Only method signatures", "Method signatures and default implementations", "Only properties", "Only events"], correctAnswer: 1, explanation: "Since C# 8, interfaces can have default implementations. They can contain methods, properties, events, and indexers." },
  { id: 24, question: "What is the 'base' keyword used for?", options: ["Creating base class", "Accessing base class members", "Defining inheritance", "Creating objects"], correctAnswer: 1, explanation: "base accesses members of the base class, commonly used to call base constructor or overridden methods." },
  { id: 25, question: "Can a class implement multiple interfaces?", options: ["No", "Yes", "Only two", "Only with abstract class"], correctAnswer: 1, explanation: "C# supports implementing multiple interfaces but only single class inheritance. This enables multiple type contracts." },
  { id: 26, question: "What is a constructor?", options: ["A destructor", "A method called when object is created", "A static method", "A property"], correctAnswer: 1, explanation: "Constructors initialize objects. They have the same name as the class and no return type." },
  { id: 27, question: "What is a static class?", options: ["A class that can't have methods", "A class that cannot be instantiated, only static members", "A sealed class", "An abstract class"], correctAnswer: 1, explanation: "Static classes cannot be instantiated and can only contain static members. Useful for utility classes." },
  { id: 28, question: "What does 'this' refer to?", options: ["The class type", "The current instance", "The base class", "The static context"], correctAnswer: 1, explanation: "this refers to the current instance of the class. Used to disambiguate or pass the instance to other methods." },
  { id: 29, question: "What is object initializer syntax?", options: ["new Object().Init()", "new Object { Prop = value }", "Object.Create()", "init Object()"], correctAnswer: 1, explanation: "Object initializers allow setting properties at creation: new Person { Name = \"John\", Age = 30 };" },
  { id: 30, question: "What is a partial class?", options: ["Incomplete class", "Class split across multiple files", "Abstract class", "Nested class"], correctAnswer: 1, explanation: "Partial classes allow splitting a class definition across multiple files. Useful for generated code scenarios." },
  
  // Collections & Generics (31-45)
  { id: 31, question: "What is the difference between Array and List<T>?", options: ["No difference", "Array is fixed size, List is dynamic", "List is fixed size, Array is dynamic", "Array is generic"], correctAnswer: 1, explanation: "Arrays have fixed size. List<T> can grow dynamically and provides more methods like Add, Remove, etc." },
  { id: 32, question: "How do you declare a generic class?", options: ["class MyClass<>", "class MyClass<T>", "generic class MyClass", "class<T> MyClass"], correctAnswer: 1, explanation: "Generic classes use angle brackets: class MyClass<T>. T is a type parameter replaced with actual type at usage." },
  { id: 33, question: "What is the purpose of generic constraints?", options: ["Limit memory usage", "Restrict type parameters", "Improve performance", "Enable reflection"], correctAnswer: 1, explanation: "Constraints like 'where T : class' restrict what types can be used. Enables using specific members of constrained types." },
  { id: 34, question: "What does Dictionary<TKey, TValue> store?", options: ["Single values", "Key-value pairs", "Only strings", "Ordered list"], correctAnswer: 1, explanation: "Dictionary stores key-value pairs with O(1) lookup by key. Keys must be unique and implement GetHashCode." },
  { id: 35, question: "What is IEnumerable<T>?", options: ["A class", "An interface for iteration", "A collection type", "A generic constraint"], correctAnswer: 1, explanation: "IEnumerable<T> is the base interface for collections that can be iterated with foreach. Enables LINQ operations." },
  { id: 36, question: "What is the yield keyword used for?", options: ["Stopping execution", "Creating iterators", "Exception handling", "Thread synchronization"], correctAnswer: 1, explanation: "yield return creates iterator methods that return IEnumerable. Enables lazy evaluation of sequences." },
  { id: 37, question: "What collection ensures unique elements?", options: ["List<T>", "HashSet<T>", "Queue<T>", "Stack<T>"], correctAnswer: 1, explanation: "HashSet<T> stores unique elements with O(1) add/remove/contains. Useful for membership testing." },
  { id: 38, question: "What is Queue<T> behavior?", options: ["LIFO", "FIFO", "Random access", "Sorted order"], correctAnswer: 1, explanation: "Queue is First-In-First-Out (FIFO). Enqueue adds to end, Dequeue removes from front." },
  { id: 39, question: "What is Stack<T> behavior?", options: ["FIFO", "LIFO", "Random access", "Sorted order"], correctAnswer: 1, explanation: "Stack is Last-In-First-Out (LIFO). Push adds to top, Pop removes from top." },
  { id: 40, question: "What does covariance (out) enable?", options: ["Input only", "Output only, enables derived-to-base assignment", "Both input and output", "Nothing"], correctAnswer: 1, explanation: "out makes generic type covariant. IEnumerable<Dog> can be assigned to IEnumerable<Animal>." },
  { id: 41, question: "What does contravariance (in) enable?", options: ["Output only", "Input only, enables base-to-derived assignment", "Both input and output", "Nothing"], correctAnswer: 1, explanation: "in makes generic type contravariant. Action<Animal> can be assigned to Action<Dog>." },
  { id: 42, question: "How do you initialize a List with values?", options: ["new List<int>().Add(1,2,3)", "new List<int> { 1, 2, 3 }", "List<int>(1,2,3)", "[1, 2, 3]"], correctAnswer: 1, explanation: "Collection initializer syntax allows inline initialization. C# 12 adds collection expressions: [1, 2, 3]." },
  { id: 43, question: "What is Span<T>?", options: ["A collection type", "A memory-safe view over contiguous memory", "A string type", "A thread-safe list"], correctAnswer: 1, explanation: "Span<T> provides a type-safe, memory-safe view over arrays or memory without allocations. Great for performance." },
  { id: 44, question: "What is the default value for reference types?", options: ["0", "Empty", "null", "undefined"], correctAnswer: 2, explanation: "Reference types default to null. Value types default to their zero-equivalent (0 for int, false for bool, etc.)." },
  { id: 45, question: "What is a tuple in C#?", options: ["An array", "A lightweight data structure for multiple values", "A dictionary", "A list"], correctAnswer: 1, explanation: "Tuples group multiple values: (int, string) or (int Age, string Name). Useful for returning multiple values." },
  
  // LINQ & Lambda (46-55)
  { id: 46, question: "What does LINQ stand for?", options: ["Linked Query", "Language Integrated Query", "List Query", "Lambda Query"], correctAnswer: 1, explanation: "LINQ (Language Integrated Query) provides query capabilities directly in C# syntax for various data sources." },
  { id: 47, question: "What is a lambda expression?", options: ["A named method", "An anonymous function using =>", "A LINQ query", "A delegate type"], correctAnswer: 1, explanation: "Lambdas are anonymous functions: x => x * 2 or (x, y) => x + y. Used extensively with LINQ and delegates." },
  { id: 48, question: "What does Where() do in LINQ?", options: ["Sorts data", "Filters data based on condition", "Groups data", "Joins data"], correctAnswer: 1, explanation: "Where filters elements matching a predicate. Example: list.Where(x => x > 5) returns items greater than 5." },
  { id: 49, question: "What does Select() do in LINQ?", options: ["Filters data", "Projects/transforms each element", "Orders data", "Groups data"], correctAnswer: 1, explanation: "Select transforms each element. Example: list.Select(x => x * 2) doubles each value. Like map in other languages." },
  { id: 50, question: "What is deferred execution in LINQ?", options: ["Query runs immediately", "Query runs when results are enumerated", "Query never runs", "Query runs in background"], correctAnswer: 1, explanation: "Most LINQ operations are deferred - they don't execute until you iterate (foreach) or call ToList/ToArray." },
  { id: 51, question: "Which method forces immediate execution?", options: ["Where()", "Select()", "ToList()", "OrderBy()"], correctAnswer: 2, explanation: "ToList(), ToArray(), Count(), First() force immediate execution. Where/Select/OrderBy are deferred." },
  { id: 52, question: "What does GroupBy() return?", options: ["Single group", "IGrouping<TKey, TElement> sequence", "Dictionary", "Sorted list"], correctAnswer: 1, explanation: "GroupBy returns IEnumerable<IGrouping<TKey, TElement>>. Each group has a Key and contains matching elements." },
  { id: 53, question: "What is the difference between First() and FirstOrDefault()?", options: ["No difference", "First throws if empty, FirstOrDefault returns default", "FirstOrDefault throws if empty", "First is faster"], correctAnswer: 1, explanation: "First throws InvalidOperationException if sequence is empty. FirstOrDefault returns default(T) instead." },
  { id: 54, question: "What does Any() check?", options: ["If all match", "If any element matches condition", "Count of matches", "First match"], correctAnswer: 1, explanation: "Any() returns true if any element matches the predicate (or if sequence is non-empty with no predicate)." },
  { id: 55, question: "What is method chaining in LINQ?", options: ["Calling methods sequentially on results", "Using multiple classes", "Parallel execution", "Error handling"], correctAnswer: 0, explanation: "Method chaining calls multiple LINQ methods in sequence: list.Where(x => x > 0).Select(x => x * 2).ToList();" },
  
  // Async/Await (56-65)
  { id: 56, question: "What does 'async' keyword do?", options: ["Makes method run in parallel", "Enables await keyword in method", "Makes method faster", "Creates a thread"], correctAnswer: 1, explanation: "async modifier enables using await in the method. It doesn't automatically make code run asynchronously." },
  { id: 57, question: "What does 'await' do?", options: ["Blocks the thread", "Asynchronously waits for task completion", "Creates a new thread", "Cancels operation"], correctAnswer: 1, explanation: "await suspends method execution until Task completes, releasing the thread for other work. Non-blocking." },
  { id: 58, question: "What should an async method return?", options: ["void only", "Task or Task<T> (or void for events)", "int", "Any type"], correctAnswer: 1, explanation: "Async methods return Task, Task<T>, or void (only for event handlers). ValueTask for performance-critical scenarios." },
  { id: 59, question: "Why avoid async void?", options: ["It's slower", "Exceptions can't be caught properly", "It doesn't work", "It's deprecated"], correctAnswer: 1, explanation: "async void exceptions crash the process. Use async Task so callers can await and catch exceptions." },
  { id: 60, question: "What is Task.WhenAll used for?", options: ["Running tasks sequentially", "Awaiting multiple tasks concurrently", "Cancelling tasks", "Creating tasks"], correctAnswer: 1, explanation: "Task.WhenAll runs multiple tasks concurrently and completes when all finish. More efficient than sequential awaits." },
  { id: 61, question: "What is CancellationToken?", options: ["Error type", "Mechanism to cancel async operations", "Thread type", "Task type"], correctAnswer: 1, explanation: "CancellationToken enables cooperative cancellation of async operations. Check IsCancellationRequested or ThrowIfCancellationRequested." },
  { id: 62, question: "What does ConfigureAwait(false) do?", options: ["Disables await", "Doesn't capture synchronization context", "Makes await faster", "Cancels operation"], correctAnswer: 1, explanation: "ConfigureAwait(false) avoids capturing sync context, useful in library code to prevent deadlocks and improve performance." },
  { id: 63, question: "What is a deadlock in async code?", options: ["Slow execution", "Two operations waiting for each other forever", "Memory leak", "Exception"], correctAnswer: 1, explanation: "Deadlock occurs when blocking on async code (like .Result) while sync context is needed. Use await instead." },
  { id: 64, question: "What is Task.Run used for?", options: ["Creating async method", "Running code on thread pool", "Waiting for task", "Cancelling task"], correctAnswer: 1, explanation: "Task.Run queues work to run on the thread pool. Useful for CPU-bound work in UI applications." },
  { id: 65, question: "What is the difference between Task and ValueTask?", options: ["No difference", "ValueTask avoids allocation for sync completion", "Task is faster", "ValueTask is obsolete"], correctAnswer: 1, explanation: "ValueTask can avoid heap allocation when operation completes synchronously. Use for hot paths, Task for general use." },
  
  // Modern C# & Advanced (66-75)
  { id: 66, question: "What is a record in C#?", options: ["A database row", "Reference type with value equality", "A struct", "A tuple"], correctAnswer: 1, explanation: "Records provide value-based equality, immutability by default, and concise syntax for data classes. record struct is value type." },
  { id: 67, question: "What is pattern matching?", options: ["Regex", "Testing values against patterns in conditions", "String matching", "Type inference"], correctAnswer: 1, explanation: "Pattern matching tests expressions against patterns: is, switch expressions, property patterns, etc." },
  { id: 68, question: "What are init-only properties?", options: ["Read-only properties", "Properties settable only during initialization", "Private properties", "Static properties"], correctAnswer: 1, explanation: "init accessor allows setting property during object initialization only. Enables immutable objects with cleaner syntax." },
  { id: 69, question: "What is a global using?", options: ["Using in global namespace", "Using statement applied to entire project", "Public using", "Static using"], correctAnswer: 1, explanation: "global using (C# 10) makes a using directive apply to all files in the project. Reduces repetitive imports." },
  { id: 70, question: "What are file-scoped namespaces?", options: ["Namespaces for files only", "namespace X; syntax without braces", "Private namespaces", "Partial namespaces"], correctAnswer: 1, explanation: "File-scoped namespace (namespace X;) applies to entire file without braces, reducing indentation." },
  { id: 71, question: "What is a required member in C# 11?", options: ["Optional member", "Member that must be set during initialization", "Static member", "Abstract member"], correctAnswer: 1, explanation: "required modifier ensures a property must be set in object initializer or constructor, enabling non-nullable guarantees." },
  { id: 72, question: "What is a primary constructor?", options: ["Default constructor", "Constructor parameters declared with class", "Static constructor", "Private constructor"], correctAnswer: 1, explanation: "Primary constructors (C# 12) declare parameters directly on class/struct: class Person(string Name). Captured in scope." },
  { id: 73, question: "What are collection expressions?", options: ["LINQ queries", "[1, 2, 3] syntax for creating collections", "Array initializers only", "List comprehensions"], correctAnswer: 1, explanation: "Collection expressions (C# 12) use [1, 2, 3] syntax for any collection type. Includes spread operator (..)." },
  { id: 74, question: "What is Source Generator?", options: ["Random number generator", "Compile-time code generation", "Data generator", "Test generator"], correctAnswer: 1, explanation: "Source Generators create code at compile time, enabling metaprogramming without runtime reflection overhead." },
  { id: 75, question: "What is the ! (null-forgiving) operator?", options: ["Negation", "Tells compiler expression is not null", "Throws if null", "Converts to non-null"], correctAnswer: 1, explanation: "The ! operator suppresses nullable warnings when you know something isn't null but compiler can't prove it." },
];

// Fisher-Yates shuffle algorithm
function shuffleArray<T>(array: T[]): T[] {
  const newArray = [...array];
  for (let i = newArray.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [newArray[i], newArray[j]] = [newArray[j], newArray[i]];
  }
  return newArray;
}

// Quiz Component
function CSharpQuiz() {
  const [quizStarted, setQuizStarted] = useState(false);
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<number[]>([]);
  const [showResults, setShowResults] = useState(false);
  const [quizQuestions, setQuizQuestions] = useState<QuizQuestion[]>([]);

  const startQuiz = () => {
    const shuffled = shuffleArray(csharpQuestionBank);
    setQuizQuestions(shuffled.slice(0, 10));
    setCurrentQuestion(0);
    setSelectedAnswers([]);
    setShowResults(false);
    setQuizStarted(true);
  };

  const handleAnswerSelect = (answerIndex: number) => {
    const newAnswers = [...selectedAnswers];
    newAnswers[currentQuestion] = answerIndex;
    setSelectedAnswers(newAnswers);
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

  const score = useMemo(() => {
    if (!showResults || quizQuestions.length === 0) return 0;
    return quizQuestions.reduce((acc, q, idx) => {
      return acc + (selectedAnswers[idx] === q.correctAnswer ? 1 : 0);
    }, 0);
  }, [showResults, quizQuestions, selectedAnswers]);

  const getScoreColor = (s: number) => {
    if (s >= 8) return "#10b981";
    if (s >= 6) return "#f59e0b";
    return "#ef4444";
  };

  const getScoreMessage = (s: number) => {
    if (s === 10) return "Perfect! You're a C# Master! 🏆";
    if (s >= 8) return "Excellent! You know C# very well! 🌟";
    if (s >= 6) return "Good job! Keep learning! 📚";
    if (s >= 4) return "Not bad, room for improvement! 💪";
    return "Keep studying! C# has a lot to offer! 💜";
  };

  if (!quizStarted) {
    return (
      <Paper
        id="quiz"
        sx={{
          p: 4,
          mb: 4,
          borderRadius: 4,
          background: `linear-gradient(135deg, ${alpha(accentColor, 0.1)} 0%, ${alpha(accentColorDark, 0.1)} 100%)`,
          border: `1px solid ${alpha(accentColor, 0.2)}`,
          textAlign: "center",
        }}
      >
        <Avatar sx={{ bgcolor: accentColor, width: 64, height: 64, mx: "auto", mb: 2 }}>
          <QuizIcon sx={{ fontSize: 32 }} />
        </Avatar>
        <Typography variant="h5" sx={{ fontWeight: 800, mb: 2 }}>
          C# Knowledge Quiz
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 500, mx: "auto" }}>
          Test your C# knowledge with 10 randomly selected questions from our 75-question bank covering 
          OOP, LINQ, async/await, generics, and modern C# features!
        </Typography>
        <Button
          variant="contained"
          size="large"
          onClick={startQuiz}
          startIcon={<QuizIcon />}
          sx={{
            bgcolor: accentColor,
            "&:hover": { bgcolor: accentColorDark },
            px: 4,
            py: 1.5,
            fontWeight: 700,
          }}
        >
          Start Quiz
        </Button>
      </Paper>
    );
  }

  if (showResults) {
    return (
      <Paper id="quiz" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha(accentColor, 0.2)}` }}>
        <Box sx={{ textAlign: "center", mb: 4 }}>
          <Avatar sx={{ bgcolor: getScoreColor(score), width: 80, height: 80, mx: "auto", mb: 2 }}>
            <EmojiEventsIcon sx={{ fontSize: 40 }} />
          </Avatar>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            {score} / 10
          </Typography>
          <Typography variant="h6" sx={{ color: getScoreColor(score), fontWeight: 600, mb: 2 }}>
            {getScoreMessage(score)}
          </Typography>
          <LinearProgress
            variant="determinate"
            value={score * 10}
            sx={{
              height: 10,
              borderRadius: 5,
              maxWidth: 300,
              mx: "auto",
              mb: 3,
              bgcolor: alpha(getScoreColor(score), 0.2),
              "& .MuiLinearProgress-bar": { bgcolor: getScoreColor(score) },
            }}
          />
        </Box>

        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
          Review Your Answers:
        </Typography>

        {quizQuestions.map((q, idx) => {
          const isCorrect = selectedAnswers[idx] === q.correctAnswer;
          return (
            <Paper
              key={q.id}
              sx={{
                p: 2,
                mb: 2,
                borderRadius: 2,
                border: `1px solid ${isCorrect ? "#10b981" : "#ef4444"}`,
                bgcolor: alpha(isCorrect ? "#10b981" : "#ef4444", 0.05),
              }}
            >
              <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1, mb: 1 }}>
                {isCorrect ? (
                  <CheckCircleOutlineIcon sx={{ color: "#10b981", mt: 0.5 }} />
                ) : (
                  <CancelOutlinedIcon sx={{ color: "#ef4444", mt: 0.5 }} />
                )}
                <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                  {idx + 1}. {q.question}
                </Typography>
              </Box>
              {!isCorrect && (
                <Typography variant="body2" sx={{ ml: 4, color: "#ef4444" }}>
                  Your answer: {q.options[selectedAnswers[idx]] || "Not answered"}
                </Typography>
              )}
              <Typography variant="body2" sx={{ ml: 4, color: "#10b981", fontWeight: 500 }}>
                Correct: {q.options[q.correctAnswer]}
              </Typography>
              <Typography variant="caption" sx={{ ml: 4, display: "block", mt: 1, color: "text.secondary" }}>
                {q.explanation}
              </Typography>
            </Paper>
          );
        })}

        <Box sx={{ display: "flex", justifyContent: "center", gap: 2, mt: 3 }}>
          <Button
            variant="contained"
            startIcon={<RefreshIcon />}
            onClick={startQuiz}
            sx={{ bgcolor: accentColor, "&:hover": { bgcolor: accentColorDark } }}
          >
            Try Again
          </Button>
          <Button
            variant="outlined"
            onClick={() => setQuizStarted(false)}
            sx={{ borderColor: accentColor, color: accentColor }}
          >
            Back to Start
          </Button>
        </Box>
      </Paper>
    );
  }

  const question = quizQuestions[currentQuestion];

  return (
    <Paper id="quiz" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha(accentColor, 0.2)}` }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Typography variant="h6" sx={{ fontWeight: 700 }}>
          C# Quiz
        </Typography>
        <Chip
          label={`Question ${currentQuestion + 1} of ${quizQuestions.length}`}
          sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, fontWeight: 600 }}
        />
      </Box>

      <LinearProgress
        variant="determinate"
        value={((currentQuestion + 1) / quizQuestions.length) * 100}
        sx={{
          height: 8,
          borderRadius: 4,
          mb: 3,
          bgcolor: alpha(accentColor, 0.1),
          "& .MuiLinearProgress-bar": { bgcolor: accentColor },
        }}
      />

      <Typography variant="h6" sx={{ fontWeight: 600, mb: 3 }}>
        {question.question}
      </Typography>

      <FormControl component="fieldset" sx={{ width: "100%", mb: 3 }}>
        <RadioGroup
          value={selectedAnswers[currentQuestion] ?? -1}
          onChange={(e) => handleAnswerSelect(Number(e.target.value))}
        >
          {question.options.map((option, idx) => (
            <Paper
              key={idx}
              sx={{
                mb: 1,
                borderRadius: 2,
                border: `1px solid ${
                  selectedAnswers[currentQuestion] === idx ? accentColor : alpha(accentColor, 0.2)
                }`,
                bgcolor: selectedAnswers[currentQuestion] === idx ? alpha(accentColor, 0.08) : "transparent",
                transition: "all 0.2s",
                "&:hover": { bgcolor: alpha(accentColor, 0.05) },
              }}
            >
              <FormControlLabel
                value={idx}
                control={<Radio sx={{ color: accentColor, "&.Mui-checked": { color: accentColor } }} />}
                label={option}
                sx={{ m: 0, p: 1.5, width: "100%" }}
              />
            </Paper>
          ))}
        </RadioGroup>
      </FormControl>

      <Box sx={{ display: "flex", justifyContent: "space-between" }}>
        <Button onClick={handlePrevious} disabled={currentQuestion === 0} sx={{ color: accentColor }}>
          Previous
        </Button>
        {currentQuestion === quizQuestions.length - 1 ? (
          <Button
            variant="contained"
            onClick={handleSubmit}
            disabled={selectedAnswers.length !== quizQuestions.length || selectedAnswers.includes(undefined as any)}
            sx={{ bgcolor: accentColor, "&:hover": { bgcolor: accentColorDark } }}
          >
            Submit Quiz
          </Button>
        ) : (
          <Button
            variant="contained"
            onClick={handleNext}
            sx={{ bgcolor: accentColor, "&:hover": { bgcolor: accentColorDark } }}
          >
            Next
          </Button>
        )}
      </Box>
    </Paper>
  );
}

export default function CSharpProgrammingPage() {
  const navigate = useNavigate();

  return (
    <LearnPageLayout pageTitle="C# Programming" pageContext="Comprehensive C# programming course covering object-oriented programming, .NET development, game development with Unity, and enterprise applications.">
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
                  fontSize: 24,
                  fontWeight: 800,
                }}
              >
                C#
              </Avatar>
              <Box>
                <Typography variant="h4" sx={{ fontWeight: 900 }}>
                  C# Programming
                </Typography>
                <Typography variant="body1" color="text.secondary">
                  The Modern, Versatile Language for Microsoft & Beyond
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
              {["Object-Oriented", ".NET", "Unity", "ASP.NET", "Cross-Platform", "LINQ", "Azure", "Enterprise"].map((tag) => (
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
              What is C#?
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              C# (pronounced "C-sharp") is a modern, object-oriented programming language developed by
              Microsoft as part of its .NET initiative. Designed by <strong>Anders Hejlsberg</strong>
              (who also created Turbo Pascal and contributed to TypeScript), C# was first released in 2000
              with the goal of combining the computing power of C++ with the simplicity of Visual Basic.
              Today, C# has evolved into one of the most versatile and powerful programming languages,
              used for everything from Windows desktop applications to mobile apps, web services, cloud
              computing, and game development with Unity.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              C# is a <strong>statically-typed, strongly-typed language</strong> that runs on the
              <strong> Common Language Runtime (CLR)</strong>, the execution engine of the .NET platform.
              The CLR provides crucial services like garbage collection, type safety, exception handling,
              and security. When you compile C# code, it's transformed into an intermediate language (IL)
              that runs on the CLR, similar to how Java compiles to bytecode for the JVM. This architecture
              enables C# applications to be cross-platform—running on Windows, macOS, and Linux through
              .NET Core/.NET 5+ and Mono.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              What sets C# apart is its continuous evolution while maintaining backward compatibility.
              Modern C# (versions 9-12) includes features like <strong>records</strong> for immutable data,
              <strong> pattern matching</strong> for elegant conditionals, <strong>nullable reference types</strong>
              for null safety, <strong>async/await</strong> for asynchronous programming, and
              <strong> LINQ</strong> for powerful data querying. These features make C# exceptionally productive
              for building robust, maintainable applications while staying current with programming paradigm trends.
            </Typography>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Why Learn C# in 2024?
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              C# offers an exceptional combination of power, elegance, and versatility. Whether you want
              to build enterprise applications, create video games, develop cloud services, or craft
              cross-platform mobile apps, C# provides the tools and ecosystem to succeed. Here's why
              learning C# is an excellent investment:
            </Typography>

            <Grid container spacing={3} sx={{ mb: 4 }}>
              {[
                {
                  title: "Unity Game Development",
                  description: "Unity, the world's most popular game engine, uses C# as its primary scripting language. Over 50% of all games are made with Unity, including hits on mobile, PC, consoles, and VR. Learning C# opens the door to a thriving game development career.",
                  icon: <SportsEsportsIcon />,
                },
                {
                  title: "Enterprise & Cloud",
                  description: "C# and .NET dominate enterprise software development, especially in industries like finance, healthcare, and government. Azure, Microsoft's cloud platform, provides first-class support for C# applications with seamless integration and powerful services.",
                  icon: <CloudIcon />,
                },
                {
                  title: "Cross-Platform Development",
                  description: ".NET MAUI (Multi-platform App UI) enables building native mobile and desktop apps for iOS, Android, macOS, and Windows from a single C# codebase. Blazor lets you build interactive web UIs using C# instead of JavaScript.",
                  icon: <DesktopWindowsIcon />,
                },
                {
                  title: "Modern Language Features",
                  description: "C# continuously evolves with features that boost productivity: records, pattern matching, nullable reference types, top-level statements, global usings, and more. It's a language that respects developers' time while providing powerful capabilities.",
                  icon: <AutoFixHighIcon />,
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
              How C# Works: The .NET Runtime
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Understanding the .NET execution model helps you write better C# code. When you compile a C#
              program, the compiler (Roslyn) transforms your source code into <strong>Intermediate Language
              (IL)</strong>, also known as MSIL or CIL. This IL code is stored in assemblies (.dll or .exe files).
              When you run the application, the <strong>Common Language Runtime (CLR)</strong> loads these
              assemblies and uses a <strong>Just-In-Time (JIT) compiler</strong> to convert IL to native
              machine code optimized for the current platform.
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// The C# compilation and execution process:</span>{"\n"}
                {"\n"}
                <span style={{ color: "#50fa7b" }}>Program.cs</span>  <span style={{ color: "#6272a4" }}>// Your C# source code</span>{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#8be9fd" }}>dotnet build</span>  <span style={{ color: "#6272a4" }}>// Roslyn compiler</span>{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#50fa7b" }}>Program.dll</span>  <span style={{ color: "#6272a4" }}>// IL code in assembly</span>{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#8be9fd" }}>dotnet run</span>  <span style={{ color: "#6272a4" }}>// CLR loads assembly</span>{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#ff79c6" }}>JIT Compiler</span>  <span style={{ color: "#6272a4" }}>// Converts IL to native code</span>{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#f1fa8c" }}>Execution</span>  <span style={{ color: "#6272a4" }}>// Native machine code runs</span>
              </Typography>
            </Paper>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              The CLR provides essential services that make C# development productive and safe. The
              <strong> garbage collector (GC)</strong> automatically manages memory, freeing developers from
              manual memory allocation. <strong>Type safety</strong> prevents many common bugs at compile time.
              The <strong>exception handling</strong> system provides structured error management. The
              <strong> security model</strong> helps prevent malicious code execution. All these features work
              together to let you focus on solving problems rather than managing low-level details.
            </Typography>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Core Principles of C#
            </Typography>

            <List sx={{ mb: 3 }}>
              {[
                {
                  title: "Type Safety",
                  desc: "C# enforces type safety at compile time, catching type-related errors before your code runs. Every variable has a declared type, and the compiler ensures you only perform operations valid for that type. This catches bugs early and improves code reliability.",
                },
                {
                  title: "Object-Oriented Design",
                  desc: "Everything in C# revolves around classes and objects. The language fully supports encapsulation (access modifiers), inheritance (single class inheritance, multiple interface implementation), and polymorphism (virtual methods, interfaces). This enables clean, modular, and reusable code.",
                },
                {
                  title: "Memory Management",
                  desc: "C# uses automatic garbage collection, eliminating manual memory management. You create objects with 'new', and the GC reclaims memory when objects are no longer referenced. For deterministic cleanup of resources (files, connections), C# provides the 'using' statement and IDisposable pattern.",
                },
                {
                  title: "Modern Language Features",
                  desc: "C# continuously adopts modern programming concepts: lambda expressions and LINQ for functional programming, async/await for non-blocking I/O, pattern matching for concise conditionals, and nullable reference types for null safety. The language evolves without breaking existing code.",
                },
                {
                  title: "Unified Type System",
                  desc: "In C#, everything derives from System.Object. Even primitive types like int and bool are objects (value types box to objects when needed). This unified type system enables powerful features like generics, reflection, and consistent APIs across all types.",
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
                Begin with the latest <strong>.NET 8 SDK</strong> and <strong>Visual Studio 2022 Community Edition</strong>
                (free) or <strong>VS Code</strong> with the C# Dev Kit extension. For game development, download
                <strong> Unity Hub</strong> and create a new project—Unity handles .NET integration automatically.
                The <code>dotnet</code> CLI is your friend for creating projects, building, and running from the terminal.
              </Typography>
            </Paper>
          </Paper>

          {/* Your First C# Program */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Your First C# Program
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Let's look at "Hello, World!" in C#. Modern C# (10+) supports top-level statements,
              making simple programs incredibly concise:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Modern C# 10+ (top-level statements)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>Console</span>.<span style={{ color: "#50fa7b" }}>WriteLine</span>(<span style={{ color: "#f1fa8c" }}>"Hello, World!"</span>);
              </Typography>
            </Paper>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              That's it! One line. But let's also see the traditional structure that's still used for
              larger applications:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Traditional C# structure</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>using</span> System;{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>namespace</span> <span style={{ color: "#8be9fd" }}>MyFirstApp</span>{"\n"}
                {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Program</span>{"\n"}
                {"    "}{"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>static void</span> <span style={{ color: "#50fa7b" }}>Main</span>(<span style={{ color: "#8be9fd" }}>string</span>[] args){"\n"}
                {"        "}{"{"}{"\n"}
                {"            "}<span style={{ color: "#6272a4" }}>// Entry point of the application</span>{"\n"}
                {"            "}<span style={{ color: "#8be9fd" }}>Console</span>.<span style={{ color: "#50fa7b" }}>WriteLine</span>(<span style={{ color: "#f1fa8c" }}>"Hello, World!"</span>);{"\n"}
                {"            "}{"\n"}
                {"            "}<span style={{ color: "#8be9fd" }}>string</span> name = <span style={{ color: "#f1fa8c" }}>"Developer"</span>;{"\n"}
                {"            "}<span style={{ color: "#8be9fd" }}>Console</span>.<span style={{ color: "#50fa7b" }}>WriteLine</span>(<span style={{ color: "#f1fa8c" }}>$"Welcome, </span>{"{"}name{"}"}<span style={{ color: "#f1fa8c" }}>!"</span>);{"\n"}
                {"        "}{"}"}{"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <List>
              {[
                { code: "using System;", desc: "Imports the System namespace, providing access to fundamental classes like Console. Similar to import in Java or Python." },
                { code: "namespace MyFirstApp", desc: "Namespaces organize code and prevent naming conflicts. They're similar to packages in Java or modules in other languages." },
                { code: "class Program", desc: "Classes are the fundamental building blocks in C#. All code must be inside a class (except with top-level statements in C# 9+)." },
                { code: "static void Main(string[] args)", desc: "The Main method is the entry point. 'static' means it belongs to the class, not instances. 'void' means no return value. 'args' receives command-line arguments." },
                { code: 'Console.WriteLine("...")', desc: "Console is a static class for console I/O. WriteLine outputs text followed by a newline. Write() outputs without a newline." },
                { code: '$"Welcome, {name}!"', desc: "String interpolation (C# 6+). The $ prefix allows embedding expressions in strings using {}. Much cleaner than concatenation." },
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
              C# was born from Microsoft's need for a modern programming language for its .NET platform.
              In the late 1990s, Microsoft was embroiled in a legal battle with Sun Microsystems over its
              implementation of Java. Rather than continue the dispute, Microsoft decided to create their
              own language. <strong>Anders Hejlsberg</strong>, recruited from Borland where he had created
              Turbo Pascal and Delphi, led the design of what would become C#.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              The name "C#" reflects the language's heritage and ambitions. The '#' (sharp) symbol in music
              indicates a note raised by a semitone—suggesting C# is an improvement over C++. Additionally,
              the '#' can be seen as four '+' signs arranged in a 2x2 grid, playfully suggesting "C++++".
              Originally codenamed "Cool" (C-like Object Oriented Language), the language was announced as
              C# in July 2000 and released with .NET Framework 1.0 in January 2002.
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { year: "2000", event: "C# 1.0 Announced", desc: "Anders Hejlsberg unveils C# at the Professional Developers Conference" },
                { year: "2002", event: "C# 1.0 Released", desc: ".NET Framework 1.0 ships with C# 1.0 and Visual Studio .NET" },
                { year: "2005", event: "C# 2.0", desc: "Generics, nullable types, anonymous methods, iterators added" },
                { year: "2007", event: "C# 3.0", desc: "LINQ, lambda expressions, extension methods, anonymous types—a revolutionary release" },
                { year: "2010", event: "C# 4.0", desc: "Dynamic typing, named arguments, optional parameters, covariance" },
                { year: "2012", event: "C# 5.0", desc: "async/await revolutionizes asynchronous programming" },
                { year: "2015", event: "C# 6.0", desc: "String interpolation, null-conditional operators, expression-bodied members" },
                { year: "2016", event: ".NET Core 1.0", desc: "Cross-platform, open-source .NET runtime released" },
                { year: "2020", event: "C# 9.0 & .NET 5", desc: "Records, top-level statements, unified .NET platform" },
                { year: "2023", event: "C# 12 & .NET 8", desc: "Primary constructors, collection expressions, inline arrays" },
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
              A pivotal moment came in <strong>2014</strong> when Microsoft announced that .NET would become
              open source and cross-platform. This led to .NET Core in 2016 and eventually the unified
              .NET 5 in 2020. For the first time, C# developers could build and run applications on Linux
              and macOS, not just Windows. This transformation, combined with the acquisition of Xamarin
              (enabling mobile development) and investments in VS Code, opened C# to a much broader audience.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColorDark, 0.08), border: `1px solid ${alpha(accentColorDark, 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                C#'s Influence
              </Typography>
              <Typography variant="body2" color="text.secondary">
                C# has influenced many languages. TypeScript was also designed by Anders Hejlsberg and shares
                C#'s philosophy. Swift borrowed features like optional chaining and pattern matching. Kotlin's
                null safety approach mirrors C#'s. The async/await pattern pioneered in C# has been adopted by
                JavaScript, Python, Rust, and many others. C# continues to be a language that other languages
                look to for innovation.
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
              Setting up a C# development environment is straightforward thanks to the comprehensive
              tooling Microsoft provides. You'll need the .NET SDK and an IDE or code editor.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColorDark }}>
              Installing the .NET SDK
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="caption" sx={{ color: "#6272a4", display: "block", mb: 1 }}>
                # Download from https://dotnet.microsoft.com/download or use package managers:
              </Typography>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}># Windows (winget):</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>winget</span> install Microsoft.DotNet.SDK.8{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># macOS (Homebrew):</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>brew</span> install dotnet-sdk{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Ubuntu/Debian:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>sudo</span> apt install dotnet-sdk-8.0{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Verify installation:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>dotnet</span> --version{"\n"}
                <span style={{ color: "#6272a4" }}># 8.0.xxx</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColorDark }}>
              Creating Your First Project
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}># Create a new console application:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>dotnet</span> new console -n MyFirstApp{"\n"}
                <span style={{ color: "#8be9fd" }}>cd</span> MyFirstApp{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Run the application:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>dotnet</span> run{"\n"}
                <span style={{ color: "#6272a4" }}># Hello, World!</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Build the application:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>dotnet</span> build{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Publish for deployment:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>dotnet</span> publish -c Release
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColorDark }}>
              Recommended IDEs and Editors
            </Typography>

            <Grid container spacing={2}>
              {[
                { ide: "Visual Studio 2022", desc: "Microsoft's flagship IDE. Community Edition is free and fully-featured. Best debugging, IntelliSense, and integrated tools. Windows and macOS.", rec: "Best for Windows", color: "#68217A" },
                { ide: "VS Code + C# Dev Kit", desc: "Lightweight, cross-platform, free. The C# Dev Kit extension provides full language support, debugging, and project management. Great for all platforms.", rec: "Best for Cross-Platform", color: "#007ACC" },
                { ide: "JetBrains Rider", desc: "Cross-platform .NET IDE from JetBrains. Excellent code analysis, refactoring, and performance. Paid but offers student/OSS licenses.", rec: "Premium Choice", color: "#FF318C" },
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
          </Paper>

          {/* C# Basics & Syntax Section */}
          <Paper id="basics" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#48BB78", 0.15), color: "#48BB78", width: 48, height: 48 }}>
                <CodeIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                C# Basics & Syntax
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              C# has a clean, readable syntax derived from C and C++, but with improvements that make
              it safer and more expressive. If you know Java, JavaScript, or C++, you'll find C# syntax
              familiar yet refined.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Program Structure
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// 1. Using directives (imports)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>using</span> System;{"\n"}
                <span style={{ color: "#ff79c6" }}>using</span> System.Collections.Generic;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// 2. Namespace declaration</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>namespace</span> <span style={{ color: "#8be9fd" }}>MyApplication</span>{"\n"}
                {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// 3. Class declaration</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public class</span> <span style={{ color: "#8be9fd" }}>Program</span>{"\n"}
                {"    "}{"{"}{"\n"}
                {"        "}<span style={{ color: "#6272a4" }}>// 4. Fields (class-level variables)</span>{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>private</span> <span style={{ color: "#8be9fd" }}>string</span> _name;{"\n"}
                {"\n"}
                {"        "}<span style={{ color: "#6272a4" }}>// 5. Properties</span>{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#8be9fd" }}>string</span> Name {"{"} <span style={{ color: "#ff79c6" }}>get</span>; <span style={{ color: "#ff79c6" }}>set</span>; {"}"}{"\n"}
                {"\n"}
                {"        "}<span style={{ color: "#6272a4" }}>// 6. Constructor</span>{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#50fa7b" }}>Program</span>(<span style={{ color: "#8be9fd" }}>string</span> name){"\n"}
                {"        "}{"{"}{"\n"}
                {"            "}Name = name;{"\n"}
                {"        "}{"}"}{"\n"}
                {"\n"}
                {"        "}<span style={{ color: "#6272a4" }}>// 7. Methods</span>{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>public void</span> <span style={{ color: "#50fa7b" }}>Greet</span>(){"\n"}
                {"        "}{"{"}{"\n"}
                {"            "}Console.WriteLine(<span style={{ color: "#f1fa8c" }}>$"Hello, </span>{"{"}<span style={{ color: "#ff79c6" }}>Name</span>{"}"}<span style={{ color: "#f1fa8c" }}>!"</span>);{"\n"}
                {"        "}{"}"}{"\n"}
                {"\n"}
                {"        "}<span style={{ color: "#6272a4" }}>// 8. Entry point</span>{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>public static void</span> <span style={{ color: "#50fa7b" }}>Main</span>(<span style={{ color: "#8be9fd" }}>string</span>[] args){"\n"}
                {"        "}{"{"}{"\n"}
                {"            "}<span style={{ color: "#ff79c6" }}>var</span> program = <span style={{ color: "#ff79c6" }}>new</span> Program(<span style={{ color: "#f1fa8c" }}>"World"</span>);{"\n"}
                {"            "}program.Greet();{"\n"}
                {"        "}{"}"}{"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}
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
                <span style={{ color: "#6272a4" }}> * Can span several lines</span>{"\n"}
                <span style={{ color: "#6272a4" }}> */</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>/// &lt;summary&gt;</span>{"\n"}
                <span style={{ color: "#6272a4" }}>/// XML documentation comment</span>{"\n"}
                <span style={{ color: "#6272a4" }}>/// Used for generating API documentation</span>{"\n"}
                <span style={{ color: "#6272a4" }}>/// &lt;/summary&gt;</span>{"\n"}
                <span style={{ color: "#6272a4" }}>/// &lt;param name="name"&gt;The person's name&lt;/param&gt;</span>{"\n"}
                <span style={{ color: "#6272a4" }}>/// &lt;returns&gt;A greeting message&lt;/returns&gt;</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#8be9fd" }}>string</span> <span style={{ color: "#50fa7b" }}>CreateGreeting</span>(<span style={{ color: "#8be9fd" }}>string</span> name) ={">"} <span style={{ color: "#f1fa8c" }}>$"Hello, </span>{"{"}name{"}"}<span style={{ color: "#f1fa8c" }}>!"</span>;
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Naming Conventions
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { type: "Classes, Structs, Enums", convention: "PascalCase", example: "UserAccount, OrderStatus" },
                { type: "Methods, Properties", convention: "PascalCase", example: "GetUserName(), FirstName" },
                { type: "Local Variables, Parameters", convention: "camelCase", example: "userName, orderTotal" },
                { type: "Private Fields", convention: "_camelCase", example: "_connectionString, _logger" },
                { type: "Constants", convention: "PascalCase", example: "MaxRetryCount, DefaultTimeout" },
                { type: "Interfaces", convention: "IPascalCase", example: "IDisposable, IEnumerable" },
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
              C# is a strongly-typed language where every variable must have a declared type. The type
              system includes value types (stored on the stack) and reference types (stored on the heap
              with a stack reference). Understanding this distinction is crucial for writing efficient code.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Value Types
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Integral types</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>byte</span> b = <span style={{ color: "#bd93f9" }}>255</span>;           <span style={{ color: "#6272a4" }}>// 0 to 255</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>short</span> s = <span style={{ color: "#bd93f9" }}>-32768</span>;       <span style={{ color: "#6272a4" }}>// -32,768 to 32,767</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> i = <span style={{ color: "#bd93f9" }}>2147483647</span>;    <span style={{ color: "#6272a4" }}>// ~±2.1 billion (most common)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>long</span> l = <span style={{ color: "#bd93f9" }}>9223372036854775807L</span>;  <span style={{ color: "#6272a4" }}>// ~±9.2 quintillion</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Floating-point types</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>float</span> f = <span style={{ color: "#bd93f9" }}>3.14f</span>;        <span style={{ color: "#6272a4" }}>// 7 digits precision</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>double</span> d = <span style={{ color: "#bd93f9" }}>3.14159265359</span>; <span style={{ color: "#6272a4" }}>// 15-17 digits (default for decimals)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>decimal</span> m = <span style={{ color: "#bd93f9" }}>19.99m</span>;      <span style={{ color: "#6272a4" }}>// 28-29 digits (for financial)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Other value types</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>bool</span> isActive = <span style={{ color: "#ff79c6" }}>true</span>;    <span style={{ color: "#6272a4" }}>// true or false</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>char</span> letter = <span style={{ color: "#f1fa8c" }}>'A'</span>;       <span style={{ color: "#6272a4" }}>// Single Unicode character</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Structs (custom value types)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>DateTime</span> now = <span style={{ color: "#8be9fd" }}>DateTime</span>.Now;{"\n"}
                <span style={{ color: "#8be9fd" }}>TimeSpan</span> duration = <span style={{ color: "#8be9fd" }}>TimeSpan</span>.FromHours(<span style={{ color: "#bd93f9" }}>2</span>);
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Reference Types
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// String (immutable reference type)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>string</span> name = <span style={{ color: "#f1fa8c" }}>"Hello"</span>;{"\n"}
                <span style={{ color: "#8be9fd" }}>string</span> interpolated = <span style={{ color: "#f1fa8c" }}>$"Value: </span>{"{"}<span style={{ color: "#ff79c6" }}>i</span>{"}"}<span style={{ color: "#f1fa8c" }}>"</span>;{"\n"}
                <span style={{ color: "#8be9fd" }}>string</span> verbatim = <span style={{ color: "#f1fa8c" }}>@"C:\Users\File.txt"</span>;  <span style={{ color: "#6272a4" }}>// No escape needed</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>string</span> raw = <span style={{ color: "#f1fa8c" }}>"""</span>{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>Multi-line</span>{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>raw string literal</span>{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>"""</span>;  <span style={{ color: "#6272a4" }}>// C# 11+</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Arrays</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span>[] numbers = {"{"} <span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>4</span>, <span style={{ color: "#bd93f9" }}>5</span> {"}"};{"\n"}
                <span style={{ color: "#8be9fd" }}>string</span>[] names = <span style={{ color: "#ff79c6" }}>new</span> <span style={{ color: "#8be9fd" }}>string</span>[<span style={{ color: "#bd93f9" }}>3</span>];{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Objects</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>object</span> obj = <span style={{ color: "#f1fa8c" }}>"anything"</span>;   <span style={{ color: "#6272a4" }}>// Base type of all types</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>dynamic</span> dyn = <span style={{ color: "#f1fa8c" }}>"resolved at runtime"</span>;
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Type Inference and Nullability
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Type inference with var</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> count = <span style={{ color: "#bd93f9" }}>42</span>;          <span style={{ color: "#6272a4" }}>// Inferred as int</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> price = <span style={{ color: "#bd93f9" }}>19.99</span>;        <span style={{ color: "#6272a4" }}>// Inferred as double</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> names = <span style={{ color: "#ff79c6" }}>new</span> List{"<"}<span style={{ color: "#8be9fd" }}>string</span>{">"}();  <span style={{ color: "#6272a4" }}>// Inferred as List{"<"}string{">"}</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Nullable value types</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span>? maybeNumber = <span style={{ color: "#ff79c6" }}>null</span>;{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> result = maybeNumber ?? <span style={{ color: "#bd93f9" }}>0</span>;  <span style={{ color: "#6272a4" }}>// Null coalescing</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Nullable reference types (C# 8+)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>string</span>? maybeString = <span style={{ color: "#ff79c6" }}>null</span>;  <span style={{ color: "#6272a4" }}>// Explicitly nullable</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>string</span> definitelyString = <span style={{ color: "#f1fa8c" }}>"text"</span>;  <span style={{ color: "#6272a4" }}>// Non-null by default</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Null-conditional and null-coalescing</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span>? length = maybeString?.Length;  <span style={{ color: "#6272a4" }}>// null if maybeString is null</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>string</span> name = maybeString ?? <span style={{ color: "#f1fa8c" }}>"default"</span>;  <span style={{ color: "#6272a4" }}>// "default" if null</span>{"\n"}
                maybeString ??= <span style={{ color: "#f1fa8c" }}>"assigned if null"</span>;  <span style={{ color: "#6272a4" }}>// Null-coalescing assignment</span>
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
              C# provides a comprehensive set of operators. Most are familiar from other C-style languages,
              but C# adds several modern operators for null handling and pattern matching.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Arithmetic & Assignment
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#8be9fd" }}>int</span> a = <span style={{ color: "#bd93f9" }}>10</span>, b = <span style={{ color: "#bd93f9" }}>3</span>;{"\n"}
                {"\n"}
                a + b    <span style={{ color: "#6272a4" }}>// Addition: 13</span>{"\n"}
                a - b    <span style={{ color: "#6272a4" }}>// Subtraction: 7</span>{"\n"}
                a * b    <span style={{ color: "#6272a4" }}>// Multiplication: 30</span>{"\n"}
                a / b    <span style={{ color: "#6272a4" }}>// Integer division: 3</span>{"\n"}
                a % b    <span style={{ color: "#6272a4" }}>// Modulus: 1</span>{"\n"}
                {"\n"}
                a++      <span style={{ color: "#6272a4" }}>// Post-increment</span>{"\n"}
                ++a      <span style={{ color: "#6272a4" }}>// Pre-increment</span>{"\n"}
                a += <span style={{ color: "#bd93f9" }}>5</span>   <span style={{ color: "#6272a4" }}>// Compound assignment: a = a + 5</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Comparison & Logical
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                a == b   <span style={{ color: "#6272a4" }}>// Equality</span>{"\n"}
                a != b   <span style={{ color: "#6272a4" }}>// Inequality</span>{"\n"}
                a {">"} b    <span style={{ color: "#6272a4" }}>// Greater than</span>{"\n"}
                a {"<"} b    <span style={{ color: "#6272a4" }}>// Less than</span>{"\n"}
                a {">"}= b   <span style={{ color: "#6272a4" }}>// Greater or equal</span>{"\n"}
                a {"<"}= b   <span style={{ color: "#6272a4" }}>// Less or equal</span>{"\n"}
                {"\n"}
                x && y   <span style={{ color: "#6272a4" }}>// Logical AND (short-circuit)</span>{"\n"}
                x || y   <span style={{ color: "#6272a4" }}>// Logical OR (short-circuit)</span>{"\n"}
                !x       <span style={{ color: "#6272a4" }}>// Logical NOT</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Null & Conditional Operators
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Null-conditional (?.) - returns null if left is null</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>string</span>? name = person?.Name;{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span>? length = items?.Length;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Null-coalescing (??) - returns right if left is null</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>string</span> result = name ?? <span style={{ color: "#f1fa8c" }}>"Anonymous"</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Null-coalescing assignment (??=)</span>{"\n"}
                name ??= <span style={{ color: "#f1fa8c" }}>"Default"</span>;  <span style={{ color: "#6272a4" }}>// Assigns only if null</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Null-forgiving (!) - tells compiler it's not null</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>string</span> definite = maybeNull!;  <span style={{ color: "#6272a4" }}>// Trust me, it's not null</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Ternary conditional</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>string</span> status = age {">"}= <span style={{ color: "#bd93f9" }}>18</span> ? <span style={{ color: "#f1fa8c" }}>"Adult"</span> : <span style={{ color: "#f1fa8c" }}>"Minor"</span>;
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
              C# control flow statements are similar to other C-style languages, but modern C# adds
              powerful pattern matching capabilities that make conditional logic more expressive.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              If-Else & Switch
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// If-else</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> (score {">"}= <span style={{ color: "#bd93f9" }}>90</span>){"\n"}
                {"    "}grade = <span style={{ color: "#f1fa8c" }}>"A"</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>else if</span> (score {">"}= <span style={{ color: "#bd93f9" }}>80</span>){"\n"}
                {"    "}grade = <span style={{ color: "#f1fa8c" }}>"B"</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>else</span>{"\n"}
                {"    "}grade = <span style={{ color: "#f1fa8c" }}>"C"</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Switch expression (C# 8+) - recommended!</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>string</span> grade = score <span style={{ color: "#ff79c6" }}>switch</span>{"\n"}
                {"{"}{"\n"}
                {"    "}{">"}= <span style={{ color: "#bd93f9" }}>90</span> ={">"} <span style={{ color: "#f1fa8c" }}>"A"</span>,{"\n"}
                {"    "}{">"}= <span style={{ color: "#bd93f9" }}>80</span> ={">"} <span style={{ color: "#f1fa8c" }}>"B"</span>,{"\n"}
                {"    "}{">"}= <span style={{ color: "#bd93f9" }}>70</span> ={">"} <span style={{ color: "#f1fa8c" }}>"C"</span>,{"\n"}
                {"    "}_ ={">"} <span style={{ color: "#f1fa8c" }}>"F"</span>  <span style={{ color: "#6272a4" }}>// Default case</span>{"\n"}
                {"}"};{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Pattern matching in switch</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>string</span> message = obj <span style={{ color: "#ff79c6" }}>switch</span>{"\n"}
                {"{"}{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>string</span> s ={">"} <span style={{ color: "#f1fa8c" }}>$"String: </span>{"{"}s{"}"}<span style={{ color: "#f1fa8c" }}>"</span>,{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>int</span> n <span style={{ color: "#ff79c6" }}>when</span> n {">"} <span style={{ color: "#bd93f9" }}>0</span> ={">"} <span style={{ color: "#f1fa8c" }}>$"Positive: </span>{"{"}n{"}"}<span style={{ color: "#f1fa8c" }}>"</span>,{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>int</span> n ={">"} <span style={{ color: "#f1fa8c" }}>$"Non-positive: </span>{"{"}n{"}"}<span style={{ color: "#f1fa8c" }}>"</span>,{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>null</span> ={">"} <span style={{ color: "#f1fa8c" }}>"null"</span>,{"\n"}
                {"    "}_ ={">"} <span style={{ color: "#f1fa8c" }}>"Unknown"</span>{"\n"}
                {"}"};
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              Loops
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// For loop</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> (<span style={{ color: "#8be9fd" }}>int</span> i = <span style={{ color: "#bd93f9" }}>0</span>; i {"<"} <span style={{ color: "#bd93f9" }}>5</span>; i++){"\n"}
                {"    "}Console.WriteLine(i);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Foreach (most common for collections)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>foreach</span> (<span style={{ color: "#ff79c6" }}>var</span> item <span style={{ color: "#ff79c6" }}>in</span> items){"\n"}
                {"    "}Console.WriteLine(item);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// While loop</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>while</span> (condition){"\n"}
                {"    "}DoSomething();{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Do-while loop</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>do</span>{"\n"}
                {"{"}{"\n"}
                {"    "}DoSomething();{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>while</span> (condition);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Loop control</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>break</span>;     <span style={{ color: "#6272a4" }}>// Exit loop entirely</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>continue</span>;  <span style={{ color: "#6272a4" }}>// Skip to next iteration</span>
              </Typography>
            </Paper>
          </Paper>

          {/* Arrays & Collections Section */}
          <Paper id="arrays" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <StorageIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Arrays & Collections
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              C# provides a rich collection of data structures from simple arrays to powerful generic collections.
              Understanding when to use each collection type is crucial for writing efficient code.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Arrays
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Array declaration and initialization</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span>[] numbers = <span style={{ color: "#ff79c6" }}>new</span> <span style={{ color: "#8be9fd" }}>int</span>[<span style={{ color: "#bd93f9" }}>5</span>];{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span>[] primes = {"{"} <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>5</span>, <span style={{ color: "#bd93f9" }}>7</span>, <span style={{ color: "#bd93f9" }}>11</span> {"}"};{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span>[] zeros = <span style={{ color: "#ff79c6" }}>new</span> <span style={{ color: "#8be9fd" }}>int</span>[] {"{"} <span style={{ color: "#bd93f9" }}>0</span>, <span style={{ color: "#bd93f9" }}>0</span>, <span style={{ color: "#bd93f9" }}>0</span> {"}"};{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Accessing elements</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> first = primes[<span style={{ color: "#bd93f9" }}>0</span>];    <span style={{ color: "#6272a4" }}>// 2</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> last = primes[^<span style={{ color: "#bd93f9" }}>1</span>];   <span style={{ color: "#6272a4" }}>// 11 (index from end)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Slicing (C# 8+)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span>[] slice = primes[<span style={{ color: "#bd93f9" }}>1</span>..<span style={{ color: "#bd93f9" }}>4</span>];  <span style={{ color: "#6272a4" }}>// [3, 5, 7]</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Generic Collections
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// List&lt;T&gt; - Dynamic array</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>List</span>{"<"}<span style={{ color: "#8be9fd" }}>string</span>{">"} names = <span style={{ color: "#ff79c6" }}>new</span>() {"{"} <span style={{ color: "#f1fa8c" }}>"Alice"</span>, <span style={{ color: "#f1fa8c" }}>"Bob"</span> {"}"};{"\n"}
                names.Add(<span style={{ color: "#f1fa8c" }}>"Charlie"</span>);{"\n"}
                names.RemoveAt(<span style={{ color: "#bd93f9" }}>0</span>);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Dictionary&lt;TKey, TValue&gt;</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>var</span> ages = <span style={{ color: "#ff79c6" }}>new</span> <span style={{ color: "#8be9fd" }}>Dictionary</span>{"<"}<span style={{ color: "#8be9fd" }}>string</span>, <span style={{ color: "#8be9fd" }}>int</span>{">"} {"{"}{"\n"}
                {"    "}[<span style={{ color: "#f1fa8c" }}>"Alice"</span>] = <span style={{ color: "#bd93f9" }}>30</span>,{"\n"}
                {"    "}[<span style={{ color: "#f1fa8c" }}>"Bob"</span>] = <span style={{ color: "#bd93f9" }}>25</span>{"\n"}
                {"}"};{"\n"}
                ages.TryGetValue(<span style={{ color: "#f1fa8c" }}>"Alice"</span>, <span style={{ color: "#ff79c6" }}>out</span> <span style={{ color: "#8be9fd" }}>int</span> age);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// HashSet&lt;T&gt; - Unique items</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>var</span> uniqueIds = <span style={{ color: "#ff79c6" }}>new</span> <span style={{ color: "#8be9fd" }}>HashSet</span>{"<"}<span style={{ color: "#8be9fd" }}>int</span>{">"} {"{"} <span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span> {"}"};{"\n"}
                uniqueIds.Add(<span style={{ color: "#bd93f9" }}>2</span>);  <span style={{ color: "#6272a4" }}>// Ignored, already exists</span>
              </Typography>
            </Paper>
          </Paper>

          {/* Methods Section */}
          <Paper id="methods" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <ExtensionIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Methods
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Methods in C# are highly flexible with features like parameter modifiers (ref, out, in),
              optional parameters, expression-bodied members, and extension methods.
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Basic method</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#8be9fd" }}>int</span> Add(<span style={{ color: "#8be9fd" }}>int</span> a, <span style={{ color: "#8be9fd" }}>int</span> b) ={">"} a + b;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Parameter modifiers</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>void</span> Swap(<span style={{ color: "#ff79c6" }}>ref</span> <span style={{ color: "#8be9fd" }}>int</span> a, <span style={{ color: "#ff79c6" }}>ref</span> <span style={{ color: "#8be9fd" }}>int</span> b) {"{"} (a, b) = (b, a); {"}"}{"\n"}
                <span style={{ color: "#ff79c6" }}>bool</span> TryParse(<span style={{ color: "#8be9fd" }}>string</span> s, <span style={{ color: "#ff79c6" }}>out</span> <span style={{ color: "#8be9fd" }}>int</span> result) {"{"} ... {"}"}{"\n"}
                <span style={{ color: "#ff79c6" }}>void</span> Display(<span style={{ color: "#ff79c6" }}>in</span> <span style={{ color: "#8be9fd" }}>LargeStruct</span> data) {"{"} ... {"}"}  <span style={{ color: "#6272a4" }}>// Read-only ref</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Optional and params</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>void</span> Log(<span style={{ color: "#8be9fd" }}>string</span> msg, <span style={{ color: "#8be9fd" }}>int</span> level = <span style={{ color: "#bd93f9" }}>0</span>) {"{"} ... {"}"}{"\n"}
                <span style={{ color: "#8be9fd" }}>int</span> Sum(<span style={{ color: "#ff79c6" }}>params</span> <span style={{ color: "#8be9fd" }}>int</span>[] numbers) ={">"} numbers.Sum();{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Extension method</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>public static</span> <span style={{ color: "#8be9fd" }}>bool</span> IsNullOrEmpty(<span style={{ color: "#ff79c6" }}>this</span> <span style={{ color: "#8be9fd" }}>string</span>? s) ={">"}{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>string</span>.IsNullOrEmpty(s);
              </Typography>
            </Paper>
          </Paper>

          {/* OOP Fundamentals Section */}
          <Paper id="oop" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <ClassIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                OOP Fundamentals
              </Typography>
            </Box>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>public class</span> <span style={{ color: "#8be9fd" }}>Person</span>{"\n"}
                {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Properties (preferred over public fields)</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#8be9fd" }}>string</span> Name {"{"} <span style={{ color: "#ff79c6" }}>get</span>; <span style={{ color: "#ff79c6" }}>set</span>; {"}"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#8be9fd" }}>int</span> Age {"{"} <span style={{ color: "#ff79c6" }}>get</span>; <span style={{ color: "#ff79c6" }}>private set</span>; {"}"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#8be9fd" }}>string</span> Email {"{"} <span style={{ color: "#ff79c6" }}>get</span>; <span style={{ color: "#ff79c6" }}>init</span>; {"}"}  <span style={{ color: "#6272a4" }}>// Init-only (C# 9+)</span>{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Constructor</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public</span> Person(<span style={{ color: "#8be9fd" }}>string</span> name, <span style={{ color: "#8be9fd" }}>int</span> age){"\n"}
                {"    "}{"{"}{"\n"}
                {"        "}Name = name;{"\n"}
                {"        "}Age = age;{"\n"}
                {"    }"}{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Primary constructor (C# 12+)</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Primary constructor syntax</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>public class</span> <span style={{ color: "#8be9fd" }}>Point</span>(<span style={{ color: "#8be9fd" }}>int</span> X, <span style={{ color: "#8be9fd" }}>int</span> Y);
              </Typography>
            </Paper>
          </Paper>

          {/* Inheritance & Polymorphism Section */}
          <Paper id="inheritance" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <LayersIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Inheritance & Polymorphism
              </Typography>
            </Box>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>public class</span> <span style={{ color: "#8be9fd" }}>Animal</span>{"\n"}
                {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public virtual void</span> Speak() ={">"} Console.WriteLine(<span style={{ color: "#f1fa8c" }}>"..."</span>);{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>public class</span> <span style={{ color: "#8be9fd" }}>Dog</span> : <span style={{ color: "#8be9fd" }}>Animal</span>{"\n"}
                {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public override void</span> Speak() ={">"} Console.WriteLine(<span style={{ color: "#f1fa8c" }}>"Woof!"</span>);{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>public sealed class</span> <span style={{ color: "#8be9fd" }}>Bulldog</span> : <span style={{ color: "#8be9fd" }}>Dog</span>  <span style={{ color: "#6272a4" }}>// Cannot be inherited</span>{"\n"}
                {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public new void</span> Speak() ={">"} Console.WriteLine(<span style={{ color: "#f1fa8c" }}>"Gruff!"</span>);  <span style={{ color: "#6272a4" }}>// Hides, doesn't override</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Polymorphism in action</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>Animal</span> animal = <span style={{ color: "#ff79c6" }}>new</span> Dog();{"\n"}
                animal.Speak();  <span style={{ color: "#6272a4" }}>// "Woof!" - runtime polymorphism</span>
              </Typography>
            </Paper>
          </Paper>

          {/* Interfaces & Abstract Classes Section */}
          <Paper id="interfaces" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <ViewModuleIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Interfaces & Abstract Classes
              </Typography>
            </Box>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Interface</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>public interface</span> <span style={{ color: "#8be9fd" }}>IRepository</span>{"<"}<span style={{ color: "#8be9fd" }}>T</span>{">"}{"\n"}
                {"{"}{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>T</span>? GetById(<span style={{ color: "#8be9fd" }}>int</span> id);{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>void</span> Add(<span style={{ color: "#8be9fd" }}>T</span> entity);{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Default implementation (C# 8+)</span>{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>void</span> Log(<span style={{ color: "#8be9fd" }}>string</span> msg) ={">"} Console.WriteLine(msg);{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Abstract class</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>public abstract class</span> <span style={{ color: "#8be9fd" }}>Shape</span>{"\n"}
                {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public abstract</span> <span style={{ color: "#8be9fd" }}>double</span> Area {"{"} <span style={{ color: "#ff79c6" }}>get</span>; {"}"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public virtual void</span> Draw() ={">"} Console.WriteLine(<span style={{ color: "#f1fa8c" }}>"Drawing shape"</span>);{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>public class</span> <span style={{ color: "#8be9fd" }}>Circle</span>(<span style={{ color: "#8be9fd" }}>double</span> Radius) : <span style={{ color: "#8be9fd" }}>Shape</span>{"\n"}
                {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public override</span> <span style={{ color: "#8be9fd" }}>double</span> Area ={">"} Math.PI * Radius * Radius;{"\n"}
                {"}"}
              </Typography>
            </Paper>
          </Paper>

          {/* Exception Handling Section */}
          <Paper id="exceptions" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <BugReportIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Exception Handling
              </Typography>
            </Box>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>try</span>{"\n"}
                {"{"}{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>int</span> result = Divide(a, b);{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#ff79c6" }}>catch</span> (<span style={{ color: "#8be9fd" }}>DivideByZeroException</span> ex){"\n"}
                {"{"}{"\n"}
                {"    "}Console.WriteLine($<span style={{ color: "#f1fa8c" }}>"Cannot divide: {"{"}ex.Message{"}"}"</span>);{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#ff79c6" }}>catch</span> (<span style={{ color: "#8be9fd" }}>Exception</span> ex) <span style={{ color: "#ff79c6" }}>when</span> (ex.Message.Contains(<span style={{ color: "#f1fa8c" }}>"overflow"</span>))  <span style={{ color: "#6272a4" }}>// Exception filter</span>{"\n"}
                {"{"}{"\n"}
                {"    "}Console.WriteLine(<span style={{ color: "#f1fa8c" }}>"Overflow detected"</span>);{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#ff79c6" }}>finally</span>{"\n"}
                {"{"}{"\n"}
                {"    "}Console.WriteLine(<span style={{ color: "#f1fa8c" }}>"Cleanup"</span>);{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Throwing exceptions</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>throw new</span> ArgumentNullException(<span style={{ color: "#ff79c6" }}>nameof</span>(param));{"\n"}
                <span style={{ color: "#ff79c6" }}>throw new</span> InvalidOperationException(<span style={{ color: "#f1fa8c" }}>"Cannot do that"</span>);
              </Typography>
            </Paper>
          </Paper>

          {/* Generics Section */}
          <Paper id="generics" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <AutoFixHighIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Generics
              </Typography>
            </Box>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Generic class</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>public class</span> <span style={{ color: "#8be9fd" }}>Repository</span>{"<"}<span style={{ color: "#8be9fd" }}>T</span>{">"} <span style={{ color: "#ff79c6" }}>where</span> <span style={{ color: "#8be9fd" }}>T</span> : <span style={{ color: "#ff79c6" }}>class</span>, <span style={{ color: "#ff79c6" }}>new</span>(){"\n"}
                {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>private</span> <span style={{ color: "#8be9fd" }}>List</span>{"<"}<span style={{ color: "#8be9fd" }}>T</span>{">"} _items = <span style={{ color: "#ff79c6" }}>new</span>();{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public void</span> Add(<span style={{ color: "#8be9fd" }}>T</span> item) ={">"} _items.Add(item);{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#8be9fd" }}>T</span> Create() ={">"} <span style={{ color: "#ff79c6" }}>new</span> <span style={{ color: "#8be9fd" }}>T</span>();{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Generic method</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#8be9fd" }}>T</span> Max{"<"}<span style={{ color: "#8be9fd" }}>T</span>{">"}(<span style={{ color: "#8be9fd" }}>T</span> a, <span style={{ color: "#8be9fd" }}>T</span> b) <span style={{ color: "#ff79c6" }}>where</span> <span style={{ color: "#8be9fd" }}>T</span> : <span style={{ color: "#8be9fd" }}>IComparable</span>{"<"}<span style={{ color: "#8be9fd" }}>T</span>{">"}{"\n"}
                {"    "}={">"} a.CompareTo(b) {">"} <span style={{ color: "#bd93f9" }}>0</span> ? a : b;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Common constraints</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// where T : class      - reference type</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// where T : struct     - value type</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// where T : new()      - has parameterless constructor</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// where T : BaseClass  - inherits from BaseClass</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// where T : IInterface - implements interface</span>
              </Typography>
            </Paper>
          </Paper>

          {/* LINQ Section */}
          <Paper id="linq" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <CategoryIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                LINQ
              </Typography>
            </Box>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#8be9fd" }}>var</span> numbers = <span style={{ color: "#ff79c6" }}>new</span>[] {"{"} <span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>4</span>, <span style={{ color: "#bd93f9" }}>5</span>, <span style={{ color: "#bd93f9" }}>6</span>, <span style={{ color: "#bd93f9" }}>7</span>, <span style={{ color: "#bd93f9" }}>8</span>, <span style={{ color: "#bd93f9" }}>9</span>, <span style={{ color: "#bd93f9" }}>10</span> {"}"};{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Method syntax (more common)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>var</span> evens = numbers{"\n"}
                {"    "}.Where(n ={">"} n % <span style={{ color: "#bd93f9" }}>2</span> == <span style={{ color: "#bd93f9" }}>0</span>){"\n"}
                {"    "}.Select(n ={">"} n * n){"\n"}
                {"    "}.OrderByDescending(n ={">"} n){"\n"}
                {"    "}.ToList();  <span style={{ color: "#6272a4" }}>// [100, 64, 36, 16, 4]</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Query syntax</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>var</span> query = <span style={{ color: "#ff79c6" }}>from</span> n <span style={{ color: "#ff79c6" }}>in</span> numbers{"\n"}
                {"            "}<span style={{ color: "#ff79c6" }}>where</span> n % <span style={{ color: "#bd93f9" }}>2</span> == <span style={{ color: "#bd93f9" }}>0</span>{"\n"}
                {"            "}<span style={{ color: "#ff79c6" }}>orderby</span> n <span style={{ color: "#ff79c6" }}>descending</span>{"\n"}
                {"            "}<span style={{ color: "#ff79c6" }}>select</span> n * n;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Common LINQ methods</span>{"\n"}
                numbers.First();           <span style={{ color: "#6272a4" }}>// 1</span>{"\n"}
                numbers.Last();            <span style={{ color: "#6272a4" }}>// 10</span>{"\n"}
                numbers.Any(n ={">"} n {">"} <span style={{ color: "#bd93f9" }}>5</span>);   <span style={{ color: "#6272a4" }}>// true</span>{"\n"}
                numbers.All(n ={">"} n {">"} <span style={{ color: "#bd93f9" }}>0</span>);   <span style={{ color: "#6272a4" }}>// true</span>{"\n"}
                numbers.Sum();             <span style={{ color: "#6272a4" }}>// 55</span>{"\n"}
                numbers.Average();         <span style={{ color: "#6272a4" }}>// 5.5</span>
              </Typography>
            </Paper>
          </Paper>

          {/* Async/Await Section */}
          <Paper id="async" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <SyncIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Async/Await
              </Typography>
            </Box>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Async method</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>public async</span> <span style={{ color: "#8be9fd" }}>Task</span>{"<"}<span style={{ color: "#8be9fd" }}>string</span>{">"} FetchDataAsync(<span style={{ color: "#8be9fd" }}>string</span> url){"\n"}
                {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>using</span> <span style={{ color: "#8be9fd" }}>var</span> client = <span style={{ color: "#ff79c6" }}>new</span> HttpClient();{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>string</span> result = <span style={{ color: "#ff79c6" }}>await</span> client.GetStringAsync(url);{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> result;{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// With cancellation token</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>public async</span> <span style={{ color: "#8be9fd" }}>Task</span> ProcessAsync(<span style={{ color: "#8be9fd" }}>CancellationToken</span> ct = <span style={{ color: "#ff79c6" }}>default</span>){"\n"}
                {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>await</span> Task.Delay(<span style={{ color: "#bd93f9" }}>1000</span>, ct);{"\n"}
                {"    "}ct.ThrowIfCancellationRequested();{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Parallel async</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>var</span> tasks = urls.Select(url ={">"} FetchDataAsync(url));{"\n"}
                <span style={{ color: "#8be9fd" }}>string</span>[] results = <span style={{ color: "#ff79c6" }}>await</span> Task.WhenAll(tasks);
              </Typography>
            </Paper>
          </Paper>

          {/* .NET Ecosystem Section */}
          <Paper id="dotnet" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <IntegrationInstructionsIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                .NET Ecosystem
              </Typography>
            </Box>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "ASP.NET Core", desc: "Modern web framework for building APIs and web apps. Minimal APIs, MVC, Razor Pages.", color: "#512BD4" },
                { name: "Entity Framework Core", desc: "ORM for database access. Code-first migrations, LINQ queries, multiple providers.", color: "#68217A" },
                { name: "Blazor", desc: "Build interactive web UIs with C# instead of JavaScript. WebAssembly or Server-side.", color: "#512BD4" },
                { name: ".NET MAUI", desc: "Cross-platform native apps for iOS, Android, macOS, Windows from single codebase.", color: "#512BD4" },
              ].map((fw) => (
                <Grid item xs={12} sm={6} key={fw.name}>
                  <Paper sx={{ p: 2, height: "100%", borderRadius: 2, border: `1px solid ${alpha(fw.color, 0.3)}` }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5 }}>{fw.name}</Typography>
                    <Typography variant="body2" color="text.secondary">{fw.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Advanced Topics Section */}
          <Paper id="advanced" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <DeveloperBoardIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Advanced Topics
              </Typography>
            </Box>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Records (C# 9+)
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Immutable reference type with value equality</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>public record</span> <span style={{ color: "#8be9fd" }}>Person</span>(<span style={{ color: "#8be9fd" }}>string</span> Name, <span style={{ color: "#8be9fd" }}>int</span> Age);{"\n"}
                {"\n"}
                <span style={{ color: "#8be9fd" }}>var</span> p1 = <span style={{ color: "#ff79c6" }}>new</span> Person(<span style={{ color: "#f1fa8c" }}>"Alice"</span>, <span style={{ color: "#bd93f9" }}>30</span>);{"\n"}
                <span style={{ color: "#8be9fd" }}>var</span> p2 = p1 <span style={{ color: "#ff79c6" }}>with</span> {"{"} Age = <span style={{ color: "#bd93f9" }}>31</span> {"}"};  <span style={{ color: "#6272a4" }}>// Non-destructive mutation</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>var</span> p3 = <span style={{ color: "#ff79c6" }}>new</span> Person(<span style={{ color: "#f1fa8c" }}>"Alice"</span>, <span style={{ color: "#bd93f9" }}>30</span>);{"\n"}
                Console.WriteLine(p1 == p3);  <span style={{ color: "#6272a4" }}>// true (value equality)</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Pattern Matching
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#8be9fd" }}>string</span> GetDescription(<span style={{ color: "#8be9fd" }}>object</span> obj) ={">"} obj <span style={{ color: "#ff79c6" }}>switch</span>{"\n"}
                {"{"}{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>int</span> n <span style={{ color: "#ff79c6" }}>when</span> n {"<"} <span style={{ color: "#bd93f9" }}>0</span> ={">"} <span style={{ color: "#f1fa8c" }}>"Negative"</span>,{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>int</span> n ={">"} $<span style={{ color: "#f1fa8c" }}>"Number: {"{"}n{"}"}"</span>,{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>string</span> s ={">"} $<span style={{ color: "#f1fa8c" }}>"String: {"{"}s{"}"}"</span>,{"\n"}
                {"    "}{"{"} Length: {">"} <span style={{ color: "#bd93f9" }}>5</span> {"}"} ={">"} <span style={{ color: "#f1fa8c" }}>"Long collection"</span>,{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>null</span> ={">"} <span style={{ color: "#f1fa8c" }}>"Null"</span>,{"\n"}
                {"    "}_ ={">"} <span style={{ color: "#f1fa8c" }}>"Unknown"</span>{"\n"}
                {"}"};
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColor, 0.08), border: `1px solid ${alpha(accentColor, 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                More Modern C# Features
              </Typography>
              <Typography variant="body2" color="text.secondary" component="div">
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  <li><strong>Nullable Reference Types:</strong> <code>string?</code> for explicit nullability</li>
                  <li><strong>Span{"<T>"}:</strong> Memory-efficient slicing without allocations</li>
                  <li><strong>Source Generators:</strong> Compile-time code generation</li>
                  <li><strong>File-scoped Namespaces:</strong> Reduce indentation with <code>namespace X;</code></li>
                </ul>
              </Typography>
            </Paper>
          </Paper>

          {/* C# Quiz Section */}
          <CSharpQuiz />
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
