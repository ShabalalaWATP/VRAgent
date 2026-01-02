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
import HubIcon from "@mui/icons-material/Hub";
import QuizIcon from "@mui/icons-material/Quiz";
import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutline";
import CancelOutlinedIcon from "@mui/icons-material/CancelOutlined";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import LearnPageLayout from "../components/LearnPageLayout";

const accentColor = "#00ADD8"; // Go's official cyan color
const accentColorDark = "#007d9c";

// Module navigation items for sidebar
const moduleNavItems = [
  { id: "introduction", label: "Introduction", icon: <SchoolIcon /> },
  { id: "history", label: "History & Philosophy", icon: <HistoryIcon /> },
  { id: "setup", label: "Environment Setup", icon: <BuildIcon /> },
  { id: "basics", label: "Go Basics & Syntax", icon: <CodeIcon /> },
  { id: "types", label: "Types & Data Structures", icon: <DataObjectIcon /> },
  { id: "functions", label: "Functions & Methods", icon: <AccountTreeIcon /> },
  { id: "interfaces", label: "Interfaces & Composition", icon: <ExtensionIcon /> },
  { id: "concurrency", label: "Concurrency & Goroutines", icon: <SyncIcon /> },
  { id: "channels", label: "Channels & Communication", icon: <HubIcon /> },
  { id: "error-handling", label: "Error Handling", icon: <BugReportIcon /> },
  { id: "packages", label: "Packages & Modules", icon: <ViewModuleIcon /> },
  { id: "testing", label: "Testing & Benchmarking", icon: <SpeedIcon /> },
  { id: "web", label: "Web Development", icon: <HttpIcon /> },
  { id: "cli", label: "CLI Applications", icon: <TerminalIcon /> },
  { id: "cloud", label: "Cloud & Microservices", icon: <CloudIcon /> },
  { id: "advanced", label: "Advanced Topics", icon: <DeveloperBoardIcon /> },
  { id: "quiz", label: "Knowledge Quiz", icon: <QuizIcon /> },
];

// Quick stats for hero section
const quickStats = [
  { label: "Created", value: "2009", color: "#00ADD8" },
  { label: "Creator", value: "Google", color: "#4285F4" },
  { label: "Paradigm", value: "Concurrent", color: "#34A853" },
  { label: "Latest Ver", value: "Go 1.22", color: "#FBBC05" },
];

// Quiz question bank - 75 questions covering all Go topics
interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correct: number;
  explanation: string;
  topic: string;
}

const questionBank: QuizQuestion[] = [
  // History & Philosophy (5 questions)
  { id: 1, question: "In what year was Go first publicly released?", options: ["2007", "2009", "2011", "2012"], correct: 1, explanation: "Go was announced publicly in November 2009, though development started in 2007 at Google.", topic: "History" },
  { id: 2, question: "Who are the original creators of Go?", options: ["Guido van Rossum and James Gosling", "Robert Griesemer, Rob Pike, and Ken Thompson", "Dennis Ritchie and Brian Kernighan", "Bjarne Stroustrup and Linus Torvalds"], correct: 1, explanation: "Go was created by Robert Griesemer, Rob Pike, and Ken Thompson at Google.", topic: "History" },
  { id: 3, question: "What is Go's mascot called?", options: ["Gofer", "Gopher", "Gopherus", "GoGo"], correct: 1, explanation: "The Go mascot is called the Gopher, designed by Renée French.", topic: "History" },
  { id: 4, question: "Which company originally developed Go?", options: ["Microsoft", "Apple", "Google", "Facebook"], correct: 2, explanation: "Go was developed at Google to address issues with large-scale software development.", topic: "History" },
  { id: 5, question: "What was a primary motivation for creating Go?", options: ["To replace JavaScript", "To compete with Java mobile apps", "To address slow compilation and complexity in large codebases", "To create a language for embedded systems"], correct: 2, explanation: "Go was created to address slow compilation times and complexity issues Google faced with large C++ codebases.", topic: "History" },

  // Environment & Setup (5 questions)
  { id: 6, question: "What command initializes a new Go module?", options: ["go new module", "go mod init", "go create mod", "go init module"], correct: 1, explanation: "The 'go mod init <module-name>' command creates a new go.mod file and initializes a module.", topic: "Setup" },
  { id: 7, question: "What file tracks Go module dependencies and their checksums?", options: ["go.lock", "go.sum", "go.deps", "package.json"], correct: 1, explanation: "go.sum contains the expected cryptographic checksums of the content of specific module versions.", topic: "Setup" },
  { id: 8, question: "Which command downloads and installs dependencies?", options: ["go get", "go install deps", "go download", "go fetch"], correct: 0, explanation: "'go get' downloads and installs packages and their dependencies.", topic: "Setup" },
  { id: 9, question: "What does 'go mod tidy' do?", options: ["Formats go.mod file", "Adds missing and removes unused dependencies", "Cleans the build cache", "Updates all dependencies to latest"], correct: 1, explanation: "'go mod tidy' adds missing dependencies and removes unused ones from go.mod and go.sum.", topic: "Setup" },
  { id: 10, question: "What environment variable sets the Go workspace directory?", options: ["GOROOT", "GOPATH", "GOHOME", "GOWORK"], correct: 1, explanation: "GOPATH sets the location of the Go workspace (less important with modules, but still used for some purposes).", topic: "Setup" },

  // Basics & Syntax (10 questions)
  { id: 11, question: "How do you declare a variable with type inference in Go?", options: ["var x = 10", "x := 10", "let x = 10", "Both A and B"], correct: 3, explanation: "Both 'var x = 10' and 'x := 10' declare variables with type inference. := is the short declaration operator.", topic: "Basics" },
  { id: 12, question: "What is the zero value for a string in Go?", options: ["null", "nil", "\"\" (empty string)", "undefined"], correct: 2, explanation: "The zero value for strings in Go is an empty string \"\". Go doesn't have null for value types.", topic: "Basics" },
  { id: 13, question: "Which keyword is used to create a constant in Go?", options: ["const", "final", "static", "immutable"], correct: 0, explanation: "The 'const' keyword is used to declare constants in Go.", topic: "Basics" },
  { id: 14, question: "What does the 'defer' keyword do?", options: ["Delays execution until the surrounding function returns", "Creates a goroutine", "Handles errors", "Skips the current iteration"], correct: 0, explanation: "defer schedules a function call to be run after the function containing it returns.", topic: "Basics" },
  { id: 15, question: "How do you write an infinite loop in Go?", options: ["while(true) {}", "for {}", "loop {}", "forever {}"], correct: 1, explanation: "In Go, 'for {}' creates an infinite loop. Go only has the 'for' keyword for all loops.", topic: "Basics" },
  { id: 16, question: "What is the correct syntax for a switch statement without an expression?", options: ["switch { case x > 0: }", "switch true { case x > 0: }", "select { case x > 0: }", "match { case x > 0: }"], correct: 0, explanation: "A switch without an expression is equivalent to 'switch true' and allows for cleaner if-else chains.", topic: "Basics" },
  { id: 17, question: "What happens when you use ':=' with an already declared variable?", options: ["It reassigns the value", "Compilation error unless at least one variable is new", "Runtime error", "It shadows the variable"], correct: 1, explanation: "Short declaration ':=' requires at least one new variable on the left side, otherwise it's a compile error.", topic: "Basics" },
  { id: 18, question: "How do you get the address of a variable in Go?", options: ["address(x)", "*x", "&x", "ref(x)"], correct: 2, explanation: "The & operator returns the memory address of a variable, creating a pointer.", topic: "Basics" },
  { id: 19, question: "What is the purpose of the blank identifier '_'?", options: ["To create a null pointer", "To discard a value", "To declare an unused variable", "To import a package for side effects only"], correct: 1, explanation: "The blank identifier _ is used to discard values, such as unused return values.", topic: "Basics" },
  { id: 20, question: "Which statement about Go's semicolons is correct?", options: ["They are required at end of every statement", "They are automatically inserted by the lexer", "They are never used", "They are optional like JavaScript"], correct: 1, explanation: "Go's lexer automatically inserts semicolons, so they're rarely written explicitly.", topic: "Basics" },

  // Types & Data Structures (10 questions)
  { id: 21, question: "What is the difference between an array and a slice in Go?", options: ["Arrays are dynamic, slices are fixed", "Arrays are fixed size, slices are dynamic", "They are the same", "Slices can't be nil"], correct: 1, explanation: "Arrays have fixed size defined at compile time, while slices are dynamic views into arrays.", topic: "Types" },
  { id: 22, question: "How do you create an empty slice with a capacity of 10?", options: ["make([]int, 10)", "make([]int, 0, 10)", "new([]int, 10)", "[]int{cap: 10}"], correct: 1, explanation: "make([]int, 0, 10) creates a slice with length 0 and capacity 10.", topic: "Types" },
  { id: 23, question: "What does the 'append' function return?", options: ["Nothing (modifies in place)", "A new slice", "An error", "The number of elements added"], correct: 1, explanation: "append returns a new slice because the underlying array might be reallocated if capacity is exceeded.", topic: "Types" },
  { id: 24, question: "How do you check if a key exists in a map?", options: ["map.contains(key)", "map.has(key)", "value, ok := map[key]", "exists(map, key)"], correct: 2, explanation: "The comma-ok idiom 'value, ok := map[key]' returns a boolean indicating if the key exists.", topic: "Types" },
  { id: 25, question: "What is the zero value for a map in Go?", options: ["An empty map {}", "nil", "undefined", "map[]"], correct: 1, explanation: "The zero value for a map is nil. You must use make() to create a usable map.", topic: "Types" },
  { id: 26, question: "How do you define a struct with an embedded type?", options: ["type A struct { B B }", "type A struct { B }", "type A extends B {}", "type A struct { embed B }"], correct: 1, explanation: "Embedding is done by including just the type name without a field name: 'type A struct { B }'.", topic: "Types" },
  { id: 27, question: "What is the result of len() on a nil slice?", options: ["Panic", "0", "-1", "Compilation error"], correct: 1, explanation: "len() on a nil slice returns 0. Nil slices have zero length and zero capacity.", topic: "Types" },
  { id: 28, question: "Which type is NOT a reference type in Go?", options: ["slice", "map", "array", "channel"], correct: 2, explanation: "Arrays are value types in Go. Slices, maps, and channels are reference types.", topic: "Types" },
  { id: 29, question: "How do you delete a key from a map?", options: ["map.remove(key)", "delete(map, key)", "map[key] = nil", "map.delete(key)"], correct: 1, explanation: "The built-in delete() function removes a key-value pair from a map.", topic: "Types" },
  { id: 30, question: "What happens when you access a non-existent key in a map?", options: ["Panic", "Returns nil", "Returns the zero value of the value type", "Compilation error"], correct: 2, explanation: "Accessing a non-existent key returns the zero value of the value type (0 for int, \"\" for string, etc.).", topic: "Types" },

  // Functions & Methods (8 questions)
  { id: 31, question: "Can Go functions return multiple values?", options: ["No", "Yes, but only two", "Yes, any number", "Only with special syntax"], correct: 2, explanation: "Go functions can return any number of values, commonly used for returning a result and an error.", topic: "Functions" },
  { id: 32, question: "What is a variadic function?", options: ["A function with optional parameters", "A function that accepts a variable number of arguments", "A function that returns multiple values", "A generic function"], correct: 1, explanation: "Variadic functions accept a variable number of arguments using ... syntax, like fmt.Printf.", topic: "Functions" },
  { id: 33, question: "How do you define a method with a pointer receiver?", options: ["func *T.Method()", "func (t *T) Method()", "func T*.Method()", "func Method(*T)"], correct: 1, explanation: "Methods with pointer receivers use syntax: func (t *T) Method() where t is the receiver.", topic: "Functions" },
  { id: 34, question: "When should you use a pointer receiver over a value receiver?", options: ["When the method needs to modify the receiver", "When the struct is large", "For consistency if other methods use pointers", "All of the above"], correct: 3, explanation: "Use pointer receivers to modify the receiver, avoid copying large structs, and for consistency.", topic: "Functions" },
  { id: 35, question: "What is a closure in Go?", options: ["A function that closes resources", "A function that captures variables from its surrounding scope", "A function with no parameters", "A method on a struct"], correct: 1, explanation: "A closure is a function that references variables from outside its body, capturing them.", topic: "Functions" },
  { id: 36, question: "What are named return values used for?", options: ["Documentation and naked returns", "Better performance", "Type safety", "Error handling"], correct: 0, explanation: "Named return values document what's returned and enable 'naked returns' (return without arguments).", topic: "Functions" },
  { id: 37, question: "How do you pass a slice to a variadic function?", options: ["fn(slice)", "fn(slice...)", "fn(*slice)", "fn(&slice)"], correct: 1, explanation: "Use the ... operator to expand a slice when passing to a variadic function: fn(slice...).", topic: "Functions" },
  { id: 38, question: "Can methods be defined on built-in types like int?", options: ["Yes, directly", "No, but you can define a new type based on int", "Yes, with special syntax", "No, never"], correct: 1, explanation: "You can't add methods to types from other packages, but you can create a new type: 'type MyInt int'.", topic: "Functions" },

  // Interfaces (7 questions)
  { id: 39, question: "How does a type implement an interface in Go?", options: ["Using 'implements' keyword", "By implementing all interface methods (implicit)", "By extending the interface", "By registering with the interface"], correct: 1, explanation: "Go interfaces are satisfied implicitly - any type with matching methods implements the interface.", topic: "Interfaces" },
  { id: 40, question: "What is the empty interface 'interface{}' used for?", options: ["To define no methods", "To accept any type", "Both A and B", "To create abstract classes"], correct: 2, explanation: "interface{} has no methods, so all types satisfy it, allowing it to accept any value.", topic: "Interfaces" },
  { id: 41, question: "What is a type assertion?", options: ["Checking if a type implements an interface", "Extracting the concrete type from an interface value", "Casting between types", "Declaring a type alias"], correct: 1, explanation: "Type assertion extracts the concrete type from an interface: value := i.(ConcreteType).", topic: "Interfaces" },
  { id: 42, question: "What happens if a type assertion fails without the comma-ok form?", options: ["Returns nil", "Returns zero value", "Panics", "Compilation error"], correct: 2, explanation: "A failed type assertion without comma-ok (i.(T)) causes a panic at runtime.", topic: "Interfaces" },
  { id: 43, question: "What is 'any' in Go 1.18+?", options: ["A generic type parameter", "An alias for interface{}", "A new keyword for generics", "A constraint type"], correct: 1, explanation: "'any' is a predeclared identifier that is an alias for interface{}, added in Go 1.18.", topic: "Interfaces" },
  { id: 44, question: "Which is the idiomatic way to check if a type satisfies an interface?", options: ["var _ Interface = (*Type)(nil)", "implements(Type, Interface)", "Type.Satisfies(Interface)", "interface.Check(Type)"], correct: 0, explanation: "The compile-time check 'var _ Interface = (*Type)(nil)' verifies Type implements Interface.", topic: "Interfaces" },
  { id: 45, question: "What is interface composition?", options: ["Embedding interfaces within interfaces", "Implementing multiple interfaces", "Creating interface hierarchies", "All of the above"], correct: 0, explanation: "Interface composition embeds interfaces within other interfaces to combine their method sets.", topic: "Interfaces" },

  // Concurrency & Goroutines (10 questions)
  { id: 46, question: "How do you start a goroutine?", options: ["goroutine fn()", "go fn()", "async fn()", "spawn fn()"], correct: 1, explanation: "The 'go' keyword before a function call starts it as a goroutine.", topic: "Concurrency" },
  { id: 47, question: "What is the approximate initial stack size of a goroutine?", options: ["1KB", "2KB", "1MB", "8KB"], correct: 1, explanation: "Goroutines start with a small stack of about 2KB, which can grow as needed.", topic: "Concurrency" },
  { id: 48, question: "What does sync.WaitGroup do?", options: ["Synchronizes access to shared memory", "Waits for a collection of goroutines to finish", "Creates a group of goroutines", "Limits concurrent goroutines"], correct: 1, explanation: "WaitGroup waits for a collection of goroutines to finish using Add, Done, and Wait methods.", topic: "Concurrency" },
  { id: 49, question: "What is a data race?", options: ["When two goroutines access shared data without synchronization", "When a goroutine runs too fast", "When the scheduler is unfair", "When channels block"], correct: 0, explanation: "A data race occurs when two goroutines access the same memory location concurrently with at least one write.", topic: "Concurrency" },
  { id: 50, question: "How do you detect data races in Go?", options: ["go test -check", "go run -race", "go build -detect", "go vet -race"], correct: 1, explanation: "The -race flag enables the race detector: go run -race, go test -race, go build -race.", topic: "Concurrency" },
  { id: 51, question: "What is the difference between sync.Mutex and sync.RWMutex?", options: ["Mutex is faster", "RWMutex allows multiple readers", "Mutex allows multiple writers", "There is no difference"], correct: 1, explanation: "RWMutex allows multiple concurrent readers OR one writer, better for read-heavy workloads.", topic: "Concurrency" },
  { id: 52, question: "What does sync.Once do?", options: ["Runs a function once per goroutine", "Ensures a function runs exactly once across all goroutines", "Creates a single goroutine", "Synchronizes once per second"], correct: 1, explanation: "sync.Once ensures a function is executed exactly once, useful for initialization.", topic: "Concurrency" },
  { id: 53, question: "Which package provides atomic operations?", options: ["sync", "sync/atomic", "runtime", "concurrent"], correct: 1, explanation: "The sync/atomic package provides low-level atomic operations for integers and pointers.", topic: "Concurrency" },
  { id: 54, question: "What is the Go concurrency philosophy?", options: ["Share memory by communicating", "Don't communicate by sharing memory; share memory by communicating", "Use locks everywhere", "Avoid concurrency"], correct: 1, explanation: "Go promotes 'Don't communicate by sharing memory; share memory by communicating' via channels.", topic: "Concurrency" },
  { id: 55, question: "What happens if you don't wait for goroutines before main exits?", options: ["They continue running", "They are killed", "The program hangs", "Runtime error"], correct: 1, explanation: "When main returns, the program exits and all goroutines are terminated immediately.", topic: "Concurrency" },

  // Channels (8 questions)
  { id: 56, question: "What is the difference between buffered and unbuffered channels?", options: ["Buffered channels are faster", "Unbuffered channels block until both sender and receiver are ready", "Buffered channels can't be closed", "There is no difference"], correct: 1, explanation: "Unbuffered channels synchronize sender and receiver; buffered channels only block when full/empty.", topic: "Channels" },
  { id: 57, question: "How do you create a buffered channel with capacity 5?", options: ["make(chan int, 5)", "chan int[5]", "new(chan int, 5)", "buffer(chan int, 5)"], correct: 0, explanation: "make(chan int, 5) creates a buffered channel of integers with capacity 5.", topic: "Channels" },
  { id: 58, question: "What does the 'select' statement do?", options: ["Selects a type from interface", "Waits on multiple channel operations", "Selects a goroutine to run", "Filters channel values"], correct: 1, explanation: "select waits on multiple channel operations and executes the first one that's ready.", topic: "Channels" },
  { id: 59, question: "What happens when you receive from a closed channel?", options: ["Panic", "Block forever", "Returns zero value immediately", "Compilation error"], correct: 2, explanation: "Receiving from a closed channel returns the zero value immediately. Use comma-ok to detect closure.", topic: "Channels" },
  { id: 60, question: "Who should close a channel?", options: ["The receiver", "The sender", "Either party", "The runtime automatically"], correct: 1, explanation: "Only the sender should close a channel. Sending to a closed channel causes a panic.", topic: "Channels" },
  { id: 61, question: "What is a send-only channel type?", options: ["chan<- int", "<-chan int", "chan int ->", "send chan int"], correct: 0, explanation: "chan<- int is a send-only channel. <-chan int is receive-only. Used for function signatures.", topic: "Channels" },
  { id: 62, question: "What is the fan-out pattern?", options: ["Multiple channels to one goroutine", "One channel to multiple goroutines", "Closing all channels at once", "Broadcasting to all channels"], correct: 1, explanation: "Fan-out distributes work from one channel to multiple goroutines for parallel processing.", topic: "Channels" },
  { id: 63, question: "How do you implement a timeout with channels?", options: ["Using time.Sleep", "Using select with time.After", "Using context.Timeout", "Both B and C"], correct: 3, explanation: "Timeouts can be implemented with select + time.After or using context.WithTimeout.", topic: "Channels" },

  // Error Handling (5 questions)
  { id: 64, question: "What is the idiomatic way to handle errors in Go?", options: ["try-catch blocks", "if err != nil { return err }", "Error callbacks", "Global error handler"], correct: 1, explanation: "Go uses explicit error checking: 'if err != nil' is the standard pattern.", topic: "Errors" },
  { id: 65, question: "What does fmt.Errorf with %w do?", options: ["Wraps an error preserving the chain", "Writes error to stderr", "Creates a warning", "Formats error as string only"], correct: 0, explanation: "fmt.Errorf with %w wraps an error, allowing errors.Is and errors.As to unwrap it.", topic: "Errors" },
  { id: 66, question: "What is errors.Is used for?", options: ["Creating new errors", "Checking if an error matches a target in the chain", "Converting errors to strings", "Ignoring errors"], correct: 1, explanation: "errors.Is checks if any error in the chain matches a specific error value.", topic: "Errors" },
  { id: 67, question: "When should you use panic?", options: ["For all errors", "For programmer errors and unrecoverable situations", "For user input validation", "Never"], correct: 1, explanation: "panic is for truly exceptional cases like programmer errors, not normal error conditions.", topic: "Errors" },
  { id: 68, question: "How do you recover from a panic?", options: ["try-catch", "Using recover() in a deferred function", "Using handle()", "Panics cannot be recovered"], correct: 1, explanation: "recover() only works inside a deferred function and returns the panic value.", topic: "Errors" },

  // Testing (5 questions)
  { id: 69, question: "What must test function names start with?", options: ["test_", "Test", "_test", "Any name"], correct: 1, explanation: "Test functions must start with 'Test' followed by an uppercase letter: func TestXxx(t *testing.T).", topic: "Testing" },
  { id: 70, question: "What is a table-driven test?", options: ["Tests using a database", "Tests defined in a struct slice with multiple cases", "Tests that create tables", "Tests for HTML tables"], correct: 1, explanation: "Table-driven tests use a slice of test cases (structs) to test multiple inputs/outputs cleanly.", topic: "Testing" },
  { id: 71, question: "How do you run benchmarks in Go?", options: ["go benchmark", "go test -bench=.", "go run -bench", "go perf"], correct: 1, explanation: "go test -bench=. runs all benchmarks. Benchmark functions start with Benchmark.", topic: "Testing" },
  { id: 72, question: "What does t.Helper() do?", options: ["Creates a helper function", "Marks a function as a test helper for better error reporting", "Helps with test setup", "Runs tests in parallel"], correct: 1, explanation: "t.Helper() marks a function as a helper so errors report the caller's line number.", topic: "Testing" },
  { id: 73, question: "What is fuzzing in Go?", options: ["Making code unclear", "Automated testing with random inputs", "Testing with fuzzy logic", "Load testing"], correct: 1, explanation: "Fuzzing generates random inputs to find edge cases and bugs. Added in Go 1.18.", topic: "Testing" },

  // Packages & Modules (4 questions)
  { id: 74, question: "What makes an identifier exported (public) in Go?", options: ["Using 'public' keyword", "Starting with uppercase letter", "Using 'export' keyword", "Placing in a public package"], correct: 1, explanation: "Identifiers starting with uppercase are exported; lowercase are unexported (package-private).", topic: "Packages" },
  { id: 75, question: "What is special about the 'internal' directory?", options: ["It contains configuration", "Code can only be imported by parent package tree", "It's for internal testing", "It's hidden from git"], correct: 1, explanation: "Go enforces that code in internal/ can only be imported by code in the parent directory tree.", topic: "Packages" },
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

export default function GoProgrammingPage() {
  const navigate = useNavigate();

  // Quiz state
  const [quizStarted, setQuizStarted] = useState(false);
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [selectedAnswer, setSelectedAnswer] = useState<number | null>(null);
  const [showResult, setShowResult] = useState(false);
  const [score, setScore] = useState(0);
  const [quizComplete, setQuizComplete] = useState(false);
  const [answeredQuestions, setAnsweredQuestions] = useState<{ questionId: number; correct: boolean; selected: number }[]>([]);

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
    setQuizComplete(false);
    setAnsweredQuestions([]);
  };

  const handleAnswerSelect = (index: number) => {
    if (!showResult) {
      setSelectedAnswer(index);
    }
  };

  const handleSubmitAnswer = () => {
    if (selectedAnswer === null) return;
    
    const isCorrect = selectedAnswer === quizQuestions[currentQuestion].correct;
    if (isCorrect) setScore((prev) => prev + 1);
    
    setAnsweredQuestions((prev) => [
      ...prev,
      { questionId: quizQuestions[currentQuestion].id, correct: isCorrect, selected: selectedAnswer },
    ]);
    setShowResult(true);
  };

  const handleNextQuestion = () => {
    if (currentQuestion < quizQuestions.length - 1) {
      setCurrentQuestion((prev) => prev + 1);
      setSelectedAnswer(null);
      setShowResult(false);
    } else {
      setQuizComplete(true);
    }
  };

  const handleRestartQuiz = () => {
    setQuizStarted(false);
    setTimeout(() => handleStartQuiz(), 100);
  };

  return (
    <LearnPageLayout pageTitle="Go Programming" pageContext="Comprehensive Go programming course covering concurrency, interfaces, web development, and cloud-native applications.">
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
              background: `linear-gradient(135deg, ${alpha(accentColor, 0.15)} 0%, ${alpha(accentColorDark, 0.1)} 100%)`,
              border: `1px solid ${alpha(accentColor, 0.2)}`,
              position: "relative",
              overflow: "hidden",
            }}
          >
            {/* Decorative Gopher silhouette */}
            <Box
              sx={{
                position: "absolute",
                top: -20,
                right: -20,
                width: 200,
                height: 200,
                borderRadius: "50%",
                bgcolor: alpha(accentColor, 0.1),
                display: { xs: "none", md: "block" },
              }}
            />
            <Box
              sx={{
                position: "absolute",
                bottom: -30,
                right: 80,
                width: 120,
                height: 120,
                borderRadius: "50%",
                bgcolor: alpha(accentColor, 0.08),
                display: { xs: "none", md: "block" },
              }}
            />

            <Box sx={{ position: "relative", zIndex: 1 }}>
              <Chip
                label="Programming Languages"
                size="small"
                sx={{ mb: 2, bgcolor: alpha(accentColor, 0.15), color: accentColor, fontWeight: 700 }}
              />
              <Typography variant="h3" sx={{ fontWeight: 900, mb: 2 }}>
                Go Programming
              </Typography>
              <Typography variant="h6" color="text.secondary" sx={{ mb: 3, maxWidth: 700, lineHeight: 1.7 }}>
                Master the language that powers the cloud. Go (Golang) combines the simplicity of Python 
                with the performance of C, featuring built-in concurrency and a robust standard library.
              </Typography>

              {/* Quick Stats */}
              <Grid container spacing={2}>
                {quickStats.map((stat) => (
                  <Grid item xs={6} sm={3} key={stat.label}>
                    <Paper
                      sx={{
                        p: 2,
                        textAlign: "center",
                        borderRadius: 2,
                        bgcolor: "background.paper",
                        border: `1px solid ${alpha(stat.color, 0.3)}`,
                      }}
                    >
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
            </Box>
          </Paper>

          {/* What is Go? Section */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3 }}>
              What is Go?
            </Typography>
            
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              <strong>Go</strong>, also known as <strong>Golang</strong>, is an open-source programming language 
              developed at Google by Robert Griesemer, Rob Pike, and Ken Thompson. First announced in 2009 and 
              reaching version 1.0 in 2012, Go was designed to address the challenges of developing software at 
              scale—combining the ease of programming of a dynamic language with the efficiency and safety of a 
              statically typed, compiled language.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Go was born out of frustration with the complexity of C++ and Java in large-scale software development. 
              The creators wanted a language that would compile quickly, run efficiently, and be easy to write and 
              maintain. The result is a language with a remarkably simple specification—just 50 keywords—yet powerful 
              enough to build everything from command-line tools to distributed systems powering the world's largest 
              infrastructure.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Core Design Principles
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              {[
                {
                  title: "Simplicity",
                  desc: "Go deliberately omits features like inheritance, generics (until 1.18), and exceptions. This constraint leads to clearer, more maintainable code. There's usually one obvious way to do things.",
                  icon: <CodeIcon />,
                },
                {
                  title: "Concurrency",
                  desc: "Goroutines and channels are first-class citizens, making concurrent programming intuitive. Launch thousands of goroutines with minimal overhead—a goroutine costs only ~2KB of stack space.",
                  icon: <SyncIcon />,
                },
                {
                  title: "Fast Compilation",
                  desc: "Go compiles directly to machine code with dependency analysis that enables lightning-fast builds. A large project that takes minutes in C++ compiles in seconds in Go.",
                  icon: <SpeedIcon />,
                },
                {
                  title: "Static Typing",
                  desc: "Strong static typing catches errors at compile time, with type inference reducing verbosity. The compiler is strict but fair—no undefined behavior, no surprises at runtime.",
                  icon: <SecurityIcon />,
                },
              ].map((principle) => (
                <Grid item xs={12} sm={6} key={principle.title}>
                  <Paper sx={{ p: 3, borderRadius: 2, height: "100%", bgcolor: alpha(accentColor, 0.03) }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1.5 }}>
                      <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 36, height: 36 }}>
                        {principle.icon}
                      </Avatar>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                        {principle.title}
                      </Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>
                      {principle.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Why Learn Go?
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Go has become the de facto language for cloud infrastructure and DevOps tooling. Docker, Kubernetes, 
              Terraform, Prometheus, Grafana, Vault, Consul, etcd, and countless other critical infrastructure 
              tools are written in Go. Learning Go opens doors to contributing to and building upon this ecosystem.
            </Typography>

            <List>
              {[
                { primary: "Cloud-Native Development", secondary: "Go is the language of cloud infrastructure—Kubernetes, Docker, and most CNCF projects are written in Go." },
                { primary: "Excellent Performance", secondary: "Compiled to native machine code with garbage collection that's optimized for low latency. Typical services handle millions of requests with minimal memory." },
                { primary: "Simple Deployment", secondary: "Go compiles to a single static binary with no external dependencies. Deploy by copying one file—no runtime, no VM, no package managers." },
                { primary: "Built-in Tooling", secondary: "go fmt enforces consistent style, go test provides testing, go mod handles dependencies, go vet catches bugs, and gopls powers IDE support." },
                { primary: "Growing Job Market", secondary: "High demand in cloud, DevOps, backend services, and cybersecurity. Go developers command competitive salaries across the industry." },
                { primary: "Security Applications", secondary: "Many security tools are written in Go: nuclei, subfinder, httpx, naabu, and more. Go's static compilation makes distribution trivial." },
              ].map((item) => (
                <ListItem key={item.primary} sx={{ py: 1 }}>
                  <ListItemIcon>
                    <CheckCircleIcon sx={{ color: "#22c55e" }} />
                  </ListItemIcon>
                  <ListItemText
                    primary={item.primary}
                    secondary={item.secondary}
                    primaryTypographyProps={{ fontWeight: 600 }}
                    secondaryTypographyProps={{ sx: { lineHeight: 1.6 } }}
                  />
                </ListItem>
              ))}
            </List>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Go vs Other Languages
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Hello World in Different Languages

// Go - Simple, explicit, fast compilation
package main

import "fmt"

func main() {
    fmt.Println("Hello, World!")
}

// Python - Dynamic typing, slower execution
print("Hello, World!")

// Rust - Memory safety guarantees, complex ownership
fn main() {
    println!("Hello, World!");
}

// Java - Verbose, requires JVM
public class HelloWorld {
    public static void main(String[] args) {
        System.out.println("Hello, World!");
    }
}`}
              </Typography>
            </Paper>

            <Grid container spacing={2}>
              {[
                { vs: "Go vs Python", diff: "Go is 10-40x faster, statically typed, and compiles to native binaries. Python has broader libraries and is better for scripting/ML." },
                { vs: "Go vs Rust", diff: "Go has simpler syntax, faster compilation, and GC. Rust offers memory safety guarantees and is better for systems programming without GC." },
                { vs: "Go vs Java", diff: "Go compiles to native code (no JVM), has simpler syntax, faster startup. Java has a mature ecosystem and stronger enterprise adoption." },
                { vs: "Go vs Node.js", diff: "Go has better performance and concurrency. Node.js has a larger package ecosystem and is often preferred for web frontends." },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.vs}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(accentColor, 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: accentColor, mb: 0.5 }}>
                      {item.vs}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.diff}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Who Uses Go?
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Go powers critical infrastructure at some of the world's largest companies. Its adoption continues 
              to grow as organizations seek to build reliable, scalable systems with smaller teams.
            </Typography>

            <Grid container spacing={1} sx={{ mb: 3 }}>
              {[
                { company: "Google", use: "YouTube, dl.google.com, Kubernetes" },
                { company: "Docker", use: "The entire Docker platform" },
                { company: "Uber", use: "High-throughput services handling millions of trips" },
                { company: "Twitch", use: "Real-time chat and video delivery" },
                { company: "Dropbox", use: "Performance-critical backend services" },
                { company: "Cloudflare", use: "Edge services and security products" },
                { company: "Netflix", use: "Data processing and orchestration" },
                { company: "SoundCloud", use: "Build and deployment infrastructure" },
              ].map((item) => (
                <Grid item xs={6} sm={3} key={item.company}>
                  <Paper sx={{ p: 1.5, textAlign: "center", borderRadius: 2, height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.company}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.use}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColor, 0.1), border: `1px solid ${alpha(accentColor, 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <TerminalIcon sx={{ color: accentColor }} />
                Your First Go Program
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Here's a simple Go program that demonstrates the language's clarity. Notice how everything 
                is explicit—no hidden magic, no implicit behavior.
              </Typography>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e" }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`package main  // Every Go file belongs to a package

import (
    "fmt"    // Standard library for formatted I/O
    "time"   // Standard library for time operations
)

func main() {
    // Variables with type inference
    name := "Gopher"
    year := time.Now().Year()
    
    // Formatted output
    fmt.Printf("Hello, %s! Welcome to Go in %d.\\n", name, year)
    
    // Simple loop
    for i := 1; i <= 3; i++ {
        fmt.Printf("Go is fun! (iteration %d)\\n", i)
    }
}

// Output:
// Hello, Gopher! Welcome to Go in 2024.
// Go is fun! (iteration 1)
// Go is fun! (iteration 2)
// Go is fun! (iteration 3)`}
                </Typography>
              </Paper>
            </Paper>
          </Paper>

          {/* History & Philosophy Section */}
          <Paper id="history" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#4285F4", 0.15), color: "#4285F4", width: 48, height: 48 }}>
                <HistoryIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                History & Philosophy
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Go's story begins in late 2007 at Google, born from frustration with the complexity of existing languages. 
              Robert Griesemer, Rob Pike, and Ken Thompson—three legendary computer scientists—started sketching ideas 
              while waiting for a large C++ project to compile. That long compilation time symbolized everything they 
              wanted to fix: slow builds, complex dependencies, and code that was hard to maintain at scale.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4285F4" }}>
              The Creators
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              {[
                {
                  name: "Ken Thompson",
                  role: "Co-creator of Unix, B language, Plan 9, UTF-8",
                  contribution: "Brought decades of systems programming experience. Co-designed Unix and created the B language (predecessor to C). His focus on simplicity and orthogonal design deeply influenced Go.",
                },
                {
                  name: "Rob Pike",
                  role: "Co-creator of UTF-8, Plan 9, Limbo, Newsqueak",
                  contribution: "Expert in concurrent programming languages. His work on Newsqueak and Limbo directly inspired Go's goroutines and channels. Advocates for simplicity in language design.",
                },
                {
                  name: "Robert Griesemer",
                  role: "V8 JavaScript engine, Java HotSpot VM",
                  contribution: "Brought compiler and runtime expertise from Google's V8 and Sun's Java VM. Focused on Go's type system, garbage collector, and making the compiler fast.",
                },
              ].map((creator) => (
                <Grid item xs={12} md={4} key={creator.name}>
                  <Paper sx={{ p: 3, borderRadius: 2, height: "100%", bgcolor: alpha("#4285F4", 0.03) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#4285F4" }}>
                      {creator.name}
                    </Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                      {creator.role}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>
                      {creator.contribution}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4285F4" }}>
              Timeline
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { year: "2007", event: "Initial design discussions begin at Google" },
                { year: "2008", event: "Ian Lance Taylor and Russ Cox join the team" },
                { year: "2009", event: "Go announced publicly as open source (November 10)" },
                { year: "2012", event: "Go 1.0 released with compatibility promise" },
                { year: "2015", event: "Go 1.5: Compiler rewritten in Go (self-hosting)" },
                { year: "2018", event: "Go 1.11: Modules introduced for dependency management" },
                { year: "2022", event: "Go 1.18: Generics finally added after years of design" },
                { year: "2024", event: "Go 1.22: Enhanced routing, loop improvements" },
              ].map((item) => (
                <Grid item xs={6} sm={3} key={item.year}>
                  <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, height: "100%" }}>
                    <Typography variant="h6" sx={{ fontWeight: 800, color: "#4285F4" }}>{item.year}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.event}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4285F4" }}>
              Design Philosophy
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Go's philosophy can be summarized as <strong>"less is exponentially more."</strong> The language 
              deliberately omits features that other languages consider essential—no inheritance, no method 
              overloading, no generics (until 2022), no exceptions. This isn't oversight; it's intentional design. 
              Every feature has costs: learning, implementation, interaction with other features, and maintenance.
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { principle: "Simplicity", desc: "One obvious way to do things. If a feature can be removed without losing expressive power, it should be." },
                { principle: "Readability", desc: "Code is read far more than it's written. Go prioritizes clarity over cleverness." },
                { principle: "Orthogonality", desc: "Features should be independent and composable, not overlapping or redundant." },
                { principle: "Safety", desc: "Memory safety through garbage collection. Type safety through static typing. No undefined behavior." },
                { principle: "Practicality", desc: "Go is designed for real-world software engineering at Google scale, not academic elegance." },
                { principle: "Fast Feedback", desc: "Compilation should be nearly instant. The edit-compile-run cycle should feel like an interpreted language." },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.principle}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#4285F4", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#4285F4", mb: 0.5 }}>
                      {item.principle}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#4285F4", 0.1), border: `1px solid ${alpha("#4285F4", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <HistoryIcon sx={{ color: "#4285F4" }} />
                The Gopher Mascot
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Go's mascot, the Gopher, was designed by Renée French (who also created the Plan 9 bunny). 
                The friendly, approachable design reflects Go's philosophy of being welcoming to newcomers 
                while being powerful enough for experts. The Gopher has become one of the most recognizable 
                mascots in programming, appearing at conferences, on stickers, and in countless memes.
              </Typography>
            </Paper>
          </Paper>

          {/* Environment Setup Section */}
          <Paper id="setup" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#34A853", 0.15), color: "#34A853", width: 48, height: 48 }}>
                <BuildIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Environment Setup
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Setting up Go is remarkably simple compared to other languages. There's no virtual machine to 
              configure, no complex build system to install, and no package manager chaos. Go's toolchain 
              is self-contained and consistent across all platforms.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#34A853" }}>
              Installation
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              {[
                {
                  os: "Windows",
                  steps: [
                    "Download the MSI installer from go.dev/dl",
                    "Run the installer (default: C:\\Go)",
                    "The installer adds Go to PATH automatically",
                    "Open a new terminal and verify with: go version",
                  ],
                },
                {
                  os: "macOS",
                  steps: [
                    "Using Homebrew: brew install go",
                    "Or download the .pkg from go.dev/dl",
                    "The package installs to /usr/local/go",
                    "Verify with: go version",
                  ],
                },
                {
                  os: "Linux",
                  steps: [
                    "Download the tarball from go.dev/dl",
                    "Extract: sudo tar -C /usr/local -xzf go*.tar.gz",
                    "Add to PATH in ~/.bashrc or ~/.zshrc",
                    "export PATH=$PATH:/usr/local/go/bin",
                  ],
                },
              ].map((platform) => (
                <Grid item xs={12} md={4} key={platform.os}>
                  <Paper sx={{ p: 3, borderRadius: 2, height: "100%", bgcolor: alpha("#34A853", 0.03) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#34A853", mb: 2 }}>
                      {platform.os}
                    </Typography>
                    <List dense disablePadding>
                      {platform.steps.map((step, idx) => (
                        <ListItem key={idx} sx={{ py: 0.5, px: 0 }}>
                          <ListItemIcon sx={{ minWidth: 28 }}>
                            <CheckCircleIcon sx={{ fontSize: 16, color: "#34A853" }} />
                          </ListItemIcon>
                          <ListItemText
                            primary={step}
                            primaryTypographyProps={{ fontSize: 13 }}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#34A853" }}>
              Go Workspace & Modules
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Modern Go uses <strong>modules</strong> for dependency management. The old GOPATH approach is 
              deprecated. A module is defined by a <code>go.mod</code> file in your project root.
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`# Create a new project directory
mkdir myproject && cd myproject

# Initialize a new module (use your GitHub path or any unique name)
go mod init github.com/username/myproject

# This creates go.mod:
module github.com/username/myproject

go 1.22

# When you import external packages, Go automatically:
# 1. Downloads them to ~/go/pkg/mod (module cache)
# 2. Adds them to go.mod (require section)
# 3. Creates go.sum (cryptographic checksums)

# Example: adding a dependency
go get github.com/gin-gonic/gin

# Tidy up unused dependencies
go mod tidy`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#34A853" }}>
              Project Structure
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`myproject/
├── go.mod              # Module definition
├── go.sum              # Dependency checksums
├── main.go             # Entry point (package main)
├── cmd/                # Command-line applications
│   └── server/
│       └── main.go     # go run ./cmd/server
├── internal/           # Private packages (can't be imported externally)
│   ├── auth/
│   │   └── auth.go
│   └── database/
│       └── db.go
├── pkg/                # Public packages (can be imported by others)
│   └── api/
│       └── handler.go
├── config/             # Configuration files
├── scripts/            # Build/deployment scripts
└── Makefile            # Common tasks

# Common commands:
go build              # Build current package
go run main.go        # Compile and run
go run .              # Run package in current directory
go test ./...         # Run all tests
go fmt ./...          # Format all code
go vet ./...          # Static analysis`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#34A853" }}>
              IDE Setup: VS Code
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              VS Code with the official Go extension provides an excellent development experience with 
              IntelliSense, debugging, testing, and more.
            </Typography>

            <List>
              {[
                { step: "Install VS Code", desc: "Download from code.visualstudio.com" },
                { step: "Install Go Extension", desc: "Search for 'Go' by Go Team at Google in Extensions (Ctrl+Shift+X)" },
                { step: "Install Go Tools", desc: "Press Ctrl+Shift+P → 'Go: Install/Update Tools' → Select all → OK" },
                { step: "Configure Settings", desc: "The extension auto-detects your Go installation. Optionally configure formatting, linting." },
              ].map((item) => (
                <ListItem key={item.step} sx={{ py: 1 }}>
                  <ListItemIcon>
                    <CheckCircleIcon sx={{ color: "#34A853" }} />
                  </ListItemIcon>
                  <ListItemText
                    primary={item.step}
                    secondary={item.desc}
                    primaryTypographyProps={{ fontWeight: 600 }}
                  />
                </ListItem>
              ))}
            </List>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#34A853" }}>
              Essential Go Commands
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`# Building and running
go build                    # Build package, output binary
go build -o myapp           # Specify output name
go run main.go              # Compile and run (no binary saved)
go install                  # Build and install to $GOPATH/bin

# Module management
go mod init <module-path>   # Initialize new module
go mod tidy                 # Add missing, remove unused deps
go mod download             # Download dependencies to cache
go mod vendor               # Copy deps to ./vendor folder
go get package@version      # Add/update dependency

# Testing and quality
go test                     # Run tests in current package
go test ./...               # Run all tests recursively
go test -v                  # Verbose output
go test -cover              # Show coverage percentage
go test -race               # Detect race conditions
go fmt ./...                # Format code (gofmt)
go vet ./...                # Static analysis for bugs
go doc fmt.Println          # View documentation

# Cross-compilation (build for other platforms!)
GOOS=linux GOARCH=amd64 go build    # Linux binary
GOOS=windows GOARCH=amd64 go build  # Windows binary
GOOS=darwin GOARCH=arm64 go build   # macOS ARM binary`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#34A853", 0.1), border: `1px solid ${alpha("#34A853", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <BuildIcon sx={{ color: "#34A853" }} />
                Verify Your Installation
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Create a simple "Hello, World!" program to verify everything is working:
              </Typography>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e" }}>
                <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`# Create project
mkdir hello && cd hello
go mod init hello

# Create main.go with this content:
# package main
# import "fmt"
# func main() { fmt.Println("Hello, Gopher!") }

# Run it
go run .
# Output: Hello, Gopher!`}
                </Typography>
              </Paper>
            </Paper>
          </Paper>

          {/* Go Basics & Syntax Section */}
          <Paper id="basics" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <CodeIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Go Basics & Syntax
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Go's syntax is intentionally minimalist. Coming from C, Java, or JavaScript, you'll find it 
              familiar yet refreshingly clean. There are no semicolons (the compiler inserts them), no 
              parentheses around conditions, and formatting is enforced by <code>go fmt</code>.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Variable Declarations
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`package main

import "fmt"

func main() {
    // Method 1: var with explicit type
    var name string = "Gopher"
    var age int = 10
    
    // Method 2: var with type inference
    var language = "Go"  // inferred as string
    var year = 2009      // inferred as int
    
    // Method 3: Short declaration (most common, inside functions only)
    city := "Mountain View"   // := declares AND assigns
    population := 82376
    
    // Multiple declarations
    var x, y, z int = 1, 2, 3
    a, b, c := "one", 2, true
    
    // Block declaration
    var (
        firstName = "Rob"
        lastName  = "Pike"
        active    = true
    )
    
    // Constants (compile-time values)
    const Pi = 3.14159
    const (
        StatusOK    = 200
        StatusError = 500
    )
    
    // iota: auto-incrementing constant generator
    const (
        Sunday = iota  // 0
        Monday         // 1
        Tuesday        // 2
        Wednesday      // 3
    )
    
    // Zero values: Go initializes uninitialized variables
    var i int      // 0
    var f float64  // 0.0
    var s string   // "" (empty string)
    var b bool     // false
    var p *int     // nil (null pointer)
    
    fmt.Println(name, age, city)
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Basic Types
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { category: "Integers", types: "int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, uintptr" },
                { category: "Floats", types: "float32, float64 (no plain 'float')" },
                { category: "Complex", types: "complex64, complex128" },
                { category: "Boolean", types: "bool (true/false, no truthy values)" },
                { category: "String", types: "string (immutable UTF-8 bytes)" },
                { category: "Byte/Rune", types: "byte (alias for uint8), rune (alias for int32, Unicode)" },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.category}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(accentColor, 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: accentColor, mb: 0.5 }}>
                      {item.category}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ fontFamily: "monospace", fontSize: 12 }}>
                      {item.types}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Control Flow
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// IF statements (no parentheses required!)
if x > 10 {
    fmt.Println("big")
} else if x > 5 {
    fmt.Println("medium")
} else {
    fmt.Println("small")
}

// If with initialization statement (scope limited to if block)
if err := doSomething(); err != nil {
    fmt.Println("error:", err)
}

// FOR is the only loop (no while, no do-while)
for i := 0; i < 10; i++ {
    fmt.Println(i)
}

// For as "while"
count := 0
for count < 10 {
    count++
}

// Infinite loop
for {
    // break to exit
    break
}

// Range over collections
nums := []int{1, 2, 3}
for index, value := range nums {
    fmt.Println(index, value)
}

// Ignore index with _
for _, value := range nums {
    fmt.Println(value)
}

// Range over string (yields runes, not bytes)
for i, r := range "Go语言" {
    fmt.Printf("%d: %c\\n", i, r)
}

// SWITCH (no fall-through by default, no break needed)
switch day := "Monday"; day {
case "Monday":
    fmt.Println("Start of week")
case "Friday":
    fmt.Println("TGIF!")
case "Saturday", "Sunday":
    fmt.Println("Weekend!")
default:
    fmt.Println("Midweek")
}

// Switch without expression (cleaner than if-else chains)
score := 85
switch {
case score >= 90:
    fmt.Println("A")
case score >= 80:
    fmt.Println("B")
case score >= 70:
    fmt.Println("C")
default:
    fmt.Println("F")
}

// Type switch (for interface{} values)
var val interface{} = "hello"
switch v := val.(type) {
case int:
    fmt.Println("int:", v)
case string:
    fmt.Println("string:", v)
default:
    fmt.Println("unknown type")
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Defer, Panic, and Recover
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// DEFER: Schedule function to run when surrounding function returns
// Common for cleanup: closing files, releasing locks, etc.

func readFile(filename string) {
    file, err := os.Open(filename)
    if err != nil {
        return
    }
    defer file.Close()  // Will run when readFile returns
    
    // ... read file ...
    // file.Close() is guaranteed to be called
}

// Multiple defers execute in LIFO order (stack)
func demo() {
    defer fmt.Println("first")
    defer fmt.Println("second")
    defer fmt.Println("third")
}
// Output: third, second, first

// Defer with cleanup pattern
func processWithLock(mu *sync.Mutex) {
    mu.Lock()
    defer mu.Unlock()
    // ... critical section ...
}

// PANIC: Crash the program (like throw in other languages)
// Use sparingly - only for unrecoverable errors
func mustParse(s string) int {
    n, err := strconv.Atoi(s)
    if err != nil {
        panic("invalid number: " + s)
    }
    return n
}

// RECOVER: Catch panics (like catch in other languages)
// Must be called inside a deferred function
func safeCall() {
    defer func() {
        if r := recover(); r != nil {
            fmt.Println("Recovered from:", r)
        }
    }()
    
    panic("something went wrong")
    // Code after panic doesn't execute
}
// safeCall() prints "Recovered from: something went wrong"
// and continues normally`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Pointers
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Pointers hold memory addresses
// Unlike C, Go has no pointer arithmetic (safer)

func main() {
    x := 42
    p := &x      // p is a pointer to x (type: *int)
    
    fmt.Println(*p)  // 42 (dereference: get value at address)
    
    *p = 100     // Modify value through pointer
    fmt.Println(x)   // 100 (x changed!)
    
    // Why use pointers?
    // 1. Modify variables in functions
    // 2. Avoid copying large structs
    // 3. Share data between goroutines
}

// Passing by value (copy)
func double(x int) {
    x = x * 2  // Only modifies local copy
}

// Passing by pointer (reference)
func doublePtr(x *int) {
    *x = *x * 2  // Modifies original
}

func main() {
    n := 5
    double(n)
    fmt.Println(n)  // Still 5
    
    doublePtr(&n)
    fmt.Println(n)  // Now 10
}

// new() allocates zeroed memory and returns pointer
p := new(int)    // *int pointing to 0
*p = 42

// Go automatically handles pointer vs value
type Person struct { Name string }
p := &Person{Name: "Alice"}
fmt.Println(p.Name)   // Go auto-dereferences: (*p).Name`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColor, 0.1), border: `1px solid ${alpha(accentColor, 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CodeIcon sx={{ color: accentColor }} />
                Key Syntax Differences from Other Languages
              </Typography>
              <Grid container spacing={2} sx={{ mt: 1 }}>
                {[
                  { from: "No semicolons", desc: "Compiler inserts them automatically" },
                  { from: "No parentheses in if/for", desc: "if x > 0 { } not if (x > 0) { }" },
                  { from: "Type after name", desc: "var x int not int x" },
                  { from: "No ternary operator", desc: "No x ? a : b - use if/else" },
                  { from: "No implicit conversions", desc: "Must explicitly convert types" },
                  { from: "Unused = error", desc: "Unused variables/imports are compile errors" },
                ].map((item) => (
                  <Grid item xs={12} sm={6} key={item.from}>
                    <Typography variant="body2">
                      <strong>{item.from}:</strong> {item.desc}
                    </Typography>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Paper>

          {/* Types & Data Structures Section */}
          <Paper id="types" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#EA4335", 0.15), color: "#EA4335", width: 48, height: 48 }}>
                <DataObjectIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Types & Data Structures
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Go has a rich type system with composite types that let you build complex data structures. 
              Understanding the difference between arrays (fixed-size, value type), slices (dynamic, 
              reference-like), and maps (hash tables) is essential for effective Go programming.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#EA4335" }}>
              Arrays
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Arrays in Go are <strong>fixed-size</strong> and <strong>value types</strong>. When you assign 
              an array to another variable or pass it to a function, the entire array is copied. Arrays are 
              rarely used directly—slices are preferred.
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Array declaration (size is part of the type!)
var arr [5]int                    // [0, 0, 0, 0, 0]
arr2 := [3]string{"a", "b", "c"}  // Literal
arr3 := [...]int{1, 2, 3, 4}      // Size inferred: [4]int

// Accessing elements
fmt.Println(arr2[0])  // "a"
arr2[1] = "B"

// Length
fmt.Println(len(arr))  // 5

// Arrays are VALUE TYPES (copying!)
a := [3]int{1, 2, 3}
b := a        // b is a COPY of a
b[0] = 999
fmt.Println(a[0])  // Still 1 (a unchanged)

// [3]int and [4]int are DIFFERENT types
// var x [3]int = [4]int{1,2,3,4}  // Compile error!

// Multi-dimensional arrays
matrix := [2][3]int{
    {1, 2, 3},
    {4, 5, 6},
}
fmt.Println(matrix[1][2])  // 6`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#EA4335" }}>
              Slices
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Slices are the workhorse of Go collections. They're <strong>dynamic</strong>, 
              <strong>flexible</strong>, and <strong>reference an underlying array</strong>. Most Go code 
              uses slices, not arrays.
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Slice declaration (no size = slice, not array)
var s []int                  // nil slice (length 0, capacity 0)
s2 := []int{1, 2, 3}         // Literal
s3 := make([]int, 5)         // Length 5, capacity 5, all zeros
s4 := make([]int, 3, 10)     // Length 3, capacity 10

// Slices have length and capacity
fmt.Println(len(s2), cap(s2))  // 3, 3

// Slicing (creates view into same underlying array)
arr := [5]int{1, 2, 3, 4, 5}
slice := arr[1:4]   // [2, 3, 4] (indices 1, 2, 3)
slice2 := arr[:3]   // [1, 2, 3] (from start)
slice3 := arr[2:]   // [3, 4, 5] (to end)
slice4 := arr[:]    // [1, 2, 3, 4, 5] (entire array)

// IMPORTANT: Slices share underlying data!
slice[0] = 999
fmt.Println(arr[1])  // 999 (arr changed too!)

// Append (may reallocate if capacity exceeded)
s := []int{1, 2, 3}
s = append(s, 4)           // [1, 2, 3, 4]
s = append(s, 5, 6, 7)     // [1, 2, 3, 4, 5, 6, 7]
s = append(s, []int{8,9}...)  // Append another slice

// Copy (creates independent copy)
src := []int{1, 2, 3}
dst := make([]int, len(src))
copy(dst, src)
dst[0] = 999
fmt.Println(src[0])  // Still 1 (independent)

// Nil vs empty slice
var nilSlice []int          // nil, len=0, cap=0
emptySlice := []int{}       // Not nil, len=0, cap=0
emptySlice2 := make([]int, 0)  // Not nil, len=0, cap=0

// Both work the same in most cases
if nilSlice == nil { }  // true
if len(nilSlice) == 0 { }  // true (safe to check len on nil)

// Removing elements (no built-in delete)
s := []int{1, 2, 3, 4, 5}
i := 2  // Remove index 2
s = append(s[:i], s[i+1:]...)  // [1, 2, 4, 5]`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#EA4335" }}>
              Maps
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Maps are Go's hash tables—unordered key-value pairs with O(1) average lookup time.
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Map declaration
var m map[string]int         // nil map (can read, can't write!)
m2 := make(map[string]int)   // Empty map (can read and write)
m3 := map[string]int{        // Literal
    "alice": 30,
    "bob":   25,
}

// IMPORTANT: nil map panics on write
// var m map[string]int
// m["key"] = 1  // PANIC!

// Setting and getting values
m2["charlie"] = 35
age := m2["charlie"]  // 35

// Check if key exists (comma-ok idiom)
val, ok := m2["david"]
if ok {
    fmt.Println("Found:", val)
} else {
    fmt.Println("Not found")
}

// Short form for existence check
if age, ok := m3["alice"]; ok {
    fmt.Println("Alice is", age)
}

// Delete a key
delete(m3, "bob")

// Length
fmt.Println(len(m3))  // Number of key-value pairs

// Iterating (order is randomized!)
for key, value := range m3 {
    fmt.Printf("%s: %d\\n", key, value)
}

// Maps are reference types
original := map[string]int{"a": 1}
copy := original
copy["a"] = 999
fmt.Println(original["a"])  // 999 (both point to same map)

// Map with struct values
type Person struct {
    Name string
    Age  int
}
people := map[string]Person{
    "emp1": {Name: "Alice", Age: 30},
    "emp2": {Name: "Bob", Age: 25},
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#EA4335" }}>
              Structs
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Structs are Go's way to define custom types with named fields. They're similar to classes 
              in other languages but without inheritance (Go uses composition instead).
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Struct definition
type Person struct {
    Name    string
    Age     int
    Email   string
    Active  bool
}

// Creating struct instances
p1 := Person{Name: "Alice", Age: 30, Email: "alice@example.com"}
p2 := Person{"Bob", 25, "bob@example.com", true}  // Positional (fragile)
p3 := Person{}  // Zero values: "", 0, "", false

// Accessing fields
fmt.Println(p1.Name)
p1.Age = 31

// Pointers to structs
p := &Person{Name: "Charlie", Age: 35}
fmt.Println(p.Name)    // Go auto-dereferences (no ->)
fmt.Println((*p).Name) // Explicit dereference (same result)

// Anonymous structs (useful for one-off data)
point := struct {
    X, Y int
}{10, 20}

// Struct embedding (composition, not inheritance)
type Address struct {
    Street  string
    City    string
    Country string
}

type Employee struct {
    Person    // Embedded - fields promoted
    Address   // Embedded
    EmployeeID string
    Salary     float64
}

emp := Employee{
    Person:     Person{Name: "David", Age: 40},
    Address:    Address{City: "NYC"},
    EmployeeID: "E123",
    Salary:     75000,
}

// Promoted fields accessed directly
fmt.Println(emp.Name)    // From Person
fmt.Println(emp.City)    // From Address
fmt.Println(emp.Person)  // Access embedded struct

// Struct tags (metadata for JSON, DB, validation)
type User struct {
    ID        int    \`json:"id" db:"user_id"\`
    Username  string \`json:"username" validate:"required"\`
    Password  string \`json:"-"\`  // Omit from JSON
    CreatedAt time.Time \`json:"created_at,omitempty"\`
}

// Comparing structs
a := Person{Name: "Alice", Age: 30}
b := Person{Name: "Alice", Age: 30}
fmt.Println(a == b)  // true (all fields equal)

// Structs with slices/maps can't use ==
type Data struct {
    Values []int
}
// d1 == d2  // Compile error!`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#EA4335" }}>
              Type Definitions & Aliases
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Type definition (creates NEW type)
type Celsius float64
type Fahrenheit float64

func (c Celsius) ToFahrenheit() Fahrenheit {
    return Fahrenheit(c*9/5 + 32)
}

var temp Celsius = 100
// var f Fahrenheit = temp  // Error! Different types
var f Fahrenheit = temp.ToFahrenheit()  // OK

// Type alias (same type, just different name)
type MyInt = int  // MyInt and int are identical

var x int = 5
var y MyInt = x  // OK, same type

// Common use: byte and rune are aliases
// type byte = uint8
// type rune = int32

// Custom types for clarity and methods
type UserID string
type OrderID string

func GetUser(id UserID) { }
func GetOrder(id OrderID) { }

// Can't accidentally mix them up:
// GetUser(OrderID("123"))  // Compile error!`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#EA4335", 0.1), border: `1px solid ${alpha("#EA4335", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <StorageIcon sx={{ color: "#EA4335" }} />
                Value Types vs Reference Types
              </Typography>
              <Grid container spacing={2} sx={{ mt: 1 }}>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Value Types (Copied)</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Basic types (int, float, bool, string), arrays, structs. Assigning creates a copy.
                  </Typography>
                </Grid>
                <Grid item xs={12} sm={6}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Reference Types (Shared)</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Slices, maps, channels, functions, pointers. Assigning shares the underlying data.
                  </Typography>
                </Grid>
              </Grid>
            </Paper>
          </Paper>

          {/* Functions & Methods Section */}
          <Paper id="functions" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#FBBC05", 0.15), color: "#FBBC05", width: 48, height: 48 }}>
                <AccountTreeIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Functions & Methods
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Functions are the building blocks of Go programs. Go supports multiple return values, named 
              returns, variadic functions, closures, and first-class functions. Methods are functions 
              attached to types, enabling object-oriented patterns without inheritance.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#FBBC05" }}>
              Function Basics
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Basic function definition
func greet(name string) string {
    return "Hello, " + name
}

// Multiple parameters of same type
func add(a, b int) int {
    return a + b
}

// Multiple return values (idiomatic Go!)
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("division by zero")
    }
    return a / b, nil
}

// Calling with multiple returns
result, err := divide(10, 2)
if err != nil {
    log.Fatal(err)
}
fmt.Println(result)  // 5

// Named return values (use sparingly, for documentation)
func rectangle(width, height float64) (area, perimeter float64) {
    area = width * height
    perimeter = 2 * (width + height)
    return  // "naked return" - returns named values
}

// Variadic functions (variable number of arguments)
func sum(nums ...int) int {
    total := 0
    for _, n := range nums {
        total += n
    }
    return total
}

sum(1, 2, 3)           // 6
sum(1, 2, 3, 4, 5)     // 15

// Passing slice to variadic function
numbers := []int{1, 2, 3, 4}
sum(numbers...)        // 10 (spread operator)

// Blank identifier to ignore returns
_, err := divide(10, 0)  // Ignore result, keep error`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#FBBC05" }}>
              First-Class Functions & Closures
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Functions are first-class citizens
// They can be assigned to variables, passed as arguments, returned

// Function as variable
var operation func(int, int) int
operation = add
fmt.Println(operation(2, 3))  // 5

// Function type definition
type MathFunc func(int, int) int

func apply(fn MathFunc, a, b int) int {
    return fn(a, b)
}

multiply := func(a, b int) int { return a * b }
fmt.Println(apply(multiply, 4, 5))  // 20

// Anonymous functions (lambdas)
result := func(x int) int {
    return x * x
}(5)  // Immediately invoked: 25

// Closures - functions that capture variables from outer scope
func counter() func() int {
    count := 0
    return func() int {
        count++  // Captures 'count' from outer function
        return count
    }
}

c := counter()
fmt.Println(c())  // 1
fmt.Println(c())  // 2
fmt.Println(c())  // 3

c2 := counter()   // New counter, separate state
fmt.Println(c2()) // 1

// Closure gotcha in loops
funcs := make([]func(), 3)
for i := 0; i < 3; i++ {
    i := i  // Create new variable for each iteration!
    funcs[i] = func() { fmt.Println(i) }
}
// Without 'i := i', all would print 3

// Higher-order functions
func filter(nums []int, predicate func(int) bool) []int {
    result := []int{}
    for _, n := range nums {
        if predicate(n) {
            result = append(result, n)
        }
    }
    return result
}

evens := filter([]int{1,2,3,4,5,6}, func(n int) bool {
    return n%2 == 0
})
// evens = [2, 4, 6]`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#FBBC05" }}>
              Methods
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Methods are functions with a <strong>receiver</strong> argument. They let you attach behavior 
              to types. The receiver can be a value or a pointer, which affects whether the method can 
              modify the receiver.
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`type Rectangle struct {
    Width, Height float64
}

// Value receiver - gets a COPY of the struct
// Cannot modify the original
func (r Rectangle) Area() float64 {
    return r.Width * r.Height
}

// Pointer receiver - gets pointer to original
// CAN modify the original
func (r *Rectangle) Scale(factor float64) {
    r.Width *= factor   // Modifies original!
    r.Height *= factor
}

func main() {
    rect := Rectangle{Width: 10, Height: 5}
    
    fmt.Println(rect.Area())  // 50
    
    rect.Scale(2)              // Modifies rect
    fmt.Println(rect.Width)    // 20
    
    // Go auto-converts between value and pointer
    // These are equivalent:
    (&rect).Scale(2)  // Explicit pointer
    rect.Scale(2)     // Go converts automatically
}

// When to use pointer receivers:
// 1. When the method needs to modify the receiver
// 2. When the struct is large (avoid copying)
// 3. For consistency (if any method uses pointer, all should)

// Methods on any type (not just structs)
type MyInt int

func (m MyInt) Double() MyInt {
    return m * 2
}

func (m *MyInt) Increment() {
    *m++
}

n := MyInt(5)
fmt.Println(n.Double())  // 10
n.Increment()
fmt.Println(n)           // 6

// Methods cannot be defined on types from other packages
// type MyString string  // OK - new type
// func (s string) Upper() string { }  // ERROR - can't add to string`}
              </Typography>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "Value Receiver (r Rect)", desc: "Gets a copy. Safe, cannot modify. Use for small, immutable types." },
                { title: "Pointer Receiver (r *Rect)", desc: "Gets pointer. Can modify. Use for mutations, large structs, consistency." },
                { title: "Auto-conversion", desc: "Go auto-converts value↔pointer when calling methods. Convenience feature." },
                { title: "Nil Receivers", desc: "Pointer receivers can be nil! Methods must handle this case gracefully." },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#FBBC05", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#FBBC05", mb: 0.5 }}>
                      {item.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Interfaces & Composition Section */}
          <Paper id="interfaces" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#9C27B0", 0.15), color: "#9C27B0", width: 48, height: 48 }}>
                <ExtensionIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Interfaces & Composition
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Interfaces are Go's primary abstraction mechanism. Unlike Java or C#, Go interfaces are 
              <strong> implicitly satisfied</strong>—a type implements an interface simply by having the 
              required methods. No "implements" keyword needed. This enables powerful decoupling and testing.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9C27B0" }}>
              Interface Basics
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Interface definition
type Speaker interface {
    Speak() string
}

// Any type with Speak() method implements Speaker
// No explicit declaration needed!

type Dog struct {
    Name string
}

func (d Dog) Speak() string {
    return d.Name + " says woof!"
}

type Cat struct {
    Name string
}

func (c Cat) Speak() string {
    return c.Name + " says meow!"
}

// Both Dog and Cat implement Speaker
func announce(s Speaker) {
    fmt.Println(s.Speak())
}

func main() {
    dog := Dog{Name: "Rex"}
    cat := Cat{Name: "Whiskers"}
    
    announce(dog)  // Rex says woof!
    announce(cat)  // Whiskers says meow!
    
    // Slice of interface type
    animals := []Speaker{dog, cat}
    for _, a := range animals {
        fmt.Println(a.Speak())
    }
}

// Interface with multiple methods
type ReadWriter interface {
    Read(p []byte) (n int, err error)
    Write(p []byte) (n int, err error)
}

// A type must implement ALL methods to satisfy interface`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9C27B0" }}>
              Empty Interface & Type Assertions
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Empty interface - satisfied by ANY type
// interface{} or 'any' (Go 1.18+)

func printAnything(v interface{}) {
    fmt.Println(v)
}

// Same as:
func printAnything2(v any) {
    fmt.Println(v)
}

printAnything(42)
printAnything("hello")
printAnything([]int{1, 2, 3})

// Type assertion - extract concrete type from interface
var val interface{} = "hello"

// Basic assertion (panics if wrong type)
s := val.(string)
fmt.Println(s)  // "hello"

// Safe assertion with comma-ok idiom
s, ok := val.(string)
if ok {
    fmt.Println("It's a string:", s)
}

n, ok := val.(int)
if !ok {
    fmt.Println("Not an int")  // This prints
}

// Type switch - check multiple types
func describe(v interface{}) {
    switch val := v.(type) {
    case int:
        fmt.Printf("Integer: %d\\n", val)
    case string:
        fmt.Printf("String: %s\\n", val)
    case bool:
        fmt.Printf("Boolean: %t\\n", val)
    case []int:
        fmt.Printf("Int slice with %d elements\\n", len(val))
    default:
        fmt.Printf("Unknown type: %T\\n", val)
    }
}

describe(42)        // Integer: 42
describe("hello")   // String: hello
describe(true)      // Boolean: true`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9C27B0" }}>
              Interface Composition & Common Interfaces
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Interface embedding (composition)
type Reader interface {
    Read(p []byte) (n int, err error)
}

type Writer interface {
    Write(p []byte) (n int, err error)
}

// Composed interface
type ReadWriter interface {
    Reader  // Embeds Reader
    Writer  // Embeds Writer
}

// Equivalent to:
type ReadWriter2 interface {
    Read(p []byte) (n int, err error)
    Write(p []byte) (n int, err error)
}

// Common standard library interfaces:

// fmt.Stringer - custom string representation
type Stringer interface {
    String() string
}

type Person struct {
    Name string
    Age  int
}

func (p Person) String() string {
    return fmt.Sprintf("%s (%d years)", p.Name, p.Age)
}

fmt.Println(Person{"Alice", 30})  // Alice (30 years)

// error interface - the foundation of error handling
type error interface {
    Error() string
}

// io.Reader and io.Writer - the foundation of I/O
// Used by files, network connections, buffers, etc.

// sort.Interface - for custom sorting
type Interface interface {
    Len() int
    Less(i, j int) bool
    Swap(i, j int)
}

// json.Marshaler/Unmarshaler - custom JSON encoding
type Marshaler interface {
    MarshalJSON() ([]byte, error)
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9C27B0" }}>
              Composition Over Inheritance
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Go has NO inheritance - use composition instead

// Embedding for code reuse
type Engine struct {
    Horsepower int
}

func (e Engine) Start() string {
    return "Engine started"
}

func (e Engine) Stop() string {
    return "Engine stopped"
}

type Car struct {
    Engine  // Embedded - Car "has an" Engine
    Model   string
    Year    int
}

func main() {
    car := Car{
        Engine: Engine{Horsepower: 200},
        Model:  "Tesla",
        Year:   2024,
    }
    
    // Promoted methods - called directly on Car
    fmt.Println(car.Start())      // Engine started
    fmt.Println(car.Horsepower)   // 200
    
    // Or explicitly
    fmt.Println(car.Engine.Start())
}

// Override promoted method
func (c Car) Start() string {
    return fmt.Sprintf("%s %d starting: %s", 
        c.Model, c.Year, c.Engine.Start())
}

// Embedding interfaces
type Logger interface {
    Log(msg string)
}

type Service struct {
    Logger  // Embed interface - must be set before use!
    Name    string
}

func (s *Service) DoWork() {
    s.Log("Starting work...")  // Calls embedded Logger
    // ... work ...
    s.Log("Work complete")
}

// Dependency injection via interface
type ConsoleLogger struct{}
func (c ConsoleLogger) Log(msg string) { fmt.Println(msg) }

service := &Service{
    Logger: ConsoleLogger{},
    Name:   "MyService",
}
service.DoWork()`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#9C27B0", 0.1), border: `1px solid ${alpha("#9C27B0", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <ExtensionIcon sx={{ color: "#9C27B0" }} />
                Interface Best Practices
              </Typography>
              <Grid container spacing={2} sx={{ mt: 1 }}>
                {[
                  { tip: "Accept interfaces, return structs", desc: "Functions should accept interface types for flexibility but return concrete types." },
                  { tip: "Keep interfaces small", desc: "Prefer many small interfaces over few large ones. io.Reader has just one method." },
                  { tip: "Define interfaces where used", desc: "Define interfaces in the consuming package, not the implementing package." },
                  { tip: "Don't export for testing only", desc: "If you only need an interface for mocking, define it in the test file." },
                ].map((item) => (
                  <Grid item xs={12} sm={6} key={item.tip}>
                    <Typography variant="body2">
                      <strong>{item.tip}:</strong> {item.desc}
                    </Typography>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Paper>

          {/* Concurrency & Goroutines Section */}
          <Paper id="concurrency" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#00BCD4", 0.15), color: "#00BCD4", width: 48, height: 48 }}>
                <SyncIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Concurrency & Goroutines
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Concurrency is Go's superpower. <strong>Goroutines</strong> are lightweight threads managed by 
              the Go runtime, costing only ~2KB of stack space. You can launch thousands or even millions of 
              goroutines on a single machine. Combined with channels, they enable elegant concurrent programs.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00BCD4" }}>
              Goroutines
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Launch a goroutine with 'go' keyword
func sayHello(name string) {
    fmt.Println("Hello,", name)
}

func main() {
    go sayHello("Alice")  // Runs concurrently
    go sayHello("Bob")    // Runs concurrently
    
    // Main goroutine continues immediately
    fmt.Println("Main function")
    
    // Problem: main exits before goroutines finish!
    time.Sleep(100 * time.Millisecond)  // Bad! Don't use in production
}

// Anonymous goroutine
go func() {
    fmt.Println("Anonymous goroutine")
}()

// Goroutine with parameters
for i := 0; i < 5; i++ {
    go func(n int) {
        fmt.Println("Goroutine", n)
    }(i)  // Pass i as argument - important!
}

// Without passing i, all goroutines might print "5"
// because they capture the loop variable by reference

// Goroutine overhead comparison:
// OS Thread: ~1MB stack, expensive context switch
// Goroutine: ~2KB stack, cheap Go scheduler switch
// Can run 100,000+ goroutines easily`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00BCD4" }}>
              WaitGroup - Synchronization
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`import "sync"

func main() {
    var wg sync.WaitGroup
    
    for i := 1; i <= 5; i++ {
        wg.Add(1)  // Increment counter before goroutine
        
        go func(n int) {
            defer wg.Done()  // Decrement when done
            
            fmt.Printf("Worker %d starting\\n", n)
            time.Sleep(time.Second)
            fmt.Printf("Worker %d done\\n", n)
        }(i)
    }
    
    wg.Wait()  // Block until counter reaches 0
    fmt.Println("All workers completed")
}

// Common pattern: worker pool
func worker(id int, jobs <-chan int, results chan<- int, wg *sync.WaitGroup) {
    defer wg.Done()
    for job := range jobs {
        fmt.Printf("Worker %d processing job %d\\n", id, job)
        results <- job * 2
    }
}

func main() {
    jobs := make(chan int, 100)
    results := make(chan int, 100)
    var wg sync.WaitGroup
    
    // Start 3 workers
    for w := 1; w <= 3; w++ {
        wg.Add(1)
        go worker(w, jobs, results, &wg)
    }
    
    // Send 5 jobs
    for j := 1; j <= 5; j++ {
        jobs <- j
    }
    close(jobs)
    
    wg.Wait()
    close(results)
    
    for r := range results {
        fmt.Println("Result:", r)
    }
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00BCD4" }}>
              Mutex - Mutual Exclusion
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`import "sync"

// Race condition example (BAD!)
var counter int

func incrementBad() {
    for i := 0; i < 1000; i++ {
        counter++  // NOT atomic! Race condition!
    }
}

// Fixed with Mutex
type SafeCounter struct {
    mu    sync.Mutex
    value int
}

func (c *SafeCounter) Increment() {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.value++
}

func (c *SafeCounter) Value() int {
    c.mu.Lock()
    defer c.mu.Unlock()
    return c.value
}

// RWMutex - multiple readers, single writer
type Cache struct {
    mu   sync.RWMutex
    data map[string]string
}

func (c *Cache) Get(key string) (string, bool) {
    c.mu.RLock()         // Read lock - multiple readers OK
    defer c.mu.RUnlock()
    val, ok := c.data[key]
    return val, ok
}

func (c *Cache) Set(key, value string) {
    c.mu.Lock()          // Write lock - exclusive
    defer c.mu.Unlock()
    c.data[key] = value
}

// Atomic operations (for simple cases)
import "sync/atomic"

var atomicCounter int64

func incrementAtomic() {
    atomic.AddInt64(&atomicCounter, 1)
}

func getAtomic() int64 {
    return atomic.LoadInt64(&atomicCounter)
}

// sync.Once - run exactly once
var once sync.Once
var instance *Database

func GetDatabase() *Database {
    once.Do(func() {
        instance = &Database{}
        instance.Connect()
    })
    return instance
}`}
              </Typography>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "Goroutines", desc: "Lightweight threads. Use 'go' keyword. ~2KB stack. Launch thousands." },
                { title: "sync.WaitGroup", desc: "Wait for goroutines to complete. Add before, Done after, Wait at end." },
                { title: "sync.Mutex", desc: "Mutual exclusion. Lock/Unlock for critical sections. Use defer Unlock." },
                { title: "sync.RWMutex", desc: "Read-Write mutex. Multiple readers OR one writer. Better for read-heavy." },
                { title: "sync/atomic", desc: "Atomic operations. AddInt64, LoadInt64. For simple counters/flags." },
                { title: "Race Detector", desc: "go run -race / go test -race. Finds data races at runtime." },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#00BCD4", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#00BCD4", mb: 0.5 }}>
                      {item.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Channels & Communication Section */}
          <Paper id="channels" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#FF5722", 0.15), color: "#FF5722", width: 48, height: 48 }}>
                <HubIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Channels & Communication
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Channels are Go's primary mechanism for communication between goroutines. They embody the 
              philosophy: <strong>"Don't communicate by sharing memory; share memory by communicating."</strong> 
              Channels are typed, thread-safe, and can be buffered or unbuffered.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#FF5722" }}>
              Channel Basics
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Create channels
ch := make(chan int)        // Unbuffered channel
ch2 := make(chan string, 5) // Buffered channel (capacity 5)

// Send and receive
ch <- 42       // Send value to channel
value := <-ch  // Receive value from channel

// Unbuffered channels BLOCK:
// - Send blocks until someone receives
// - Receive blocks until someone sends
// This provides synchronization!

func main() {
    ch := make(chan string)
    
    go func() {
        ch <- "Hello from goroutine!"  // Blocks until received
    }()
    
    msg := <-ch  // Blocks until sent
    fmt.Println(msg)
}

// Buffered channels only block when full/empty
ch := make(chan int, 3)
ch <- 1  // Doesn't block (buffer not full)
ch <- 2  // Doesn't block
ch <- 3  // Doesn't block
ch <- 4  // BLOCKS - buffer full!

// Channel direction (for function signatures)
func sendOnly(ch chan<- int) {
    ch <- 42
    // <-ch  // Compile error - can't receive
}

func receiveOnly(ch <-chan int) {
    val := <-ch
    // ch <- 1  // Compile error - can't send
}

// Closing channels
ch := make(chan int)
close(ch)

// Receiving from closed channel:
val, ok := <-ch
if !ok {
    fmt.Println("Channel closed")
}

// Range over channel (until closed)
for val := range ch {
    fmt.Println(val)
}
// Loop exits when channel is closed`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#FF5722" }}>
              Select Statement
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Select waits on multiple channel operations
// Like switch, but for channels

func main() {
    ch1 := make(chan string)
    ch2 := make(chan string)
    
    go func() {
        time.Sleep(100 * time.Millisecond)
        ch1 <- "from ch1"
    }()
    
    go func() {
        time.Sleep(200 * time.Millisecond)
        ch2 <- "from ch2"
    }()
    
    // Wait for first message
    select {
    case msg1 := <-ch1:
        fmt.Println(msg1)
    case msg2 := <-ch2:
        fmt.Println(msg2)
    }
}

// Timeout pattern
select {
case result := <-ch:
    fmt.Println("Got result:", result)
case <-time.After(1 * time.Second):
    fmt.Println("Timeout!")
}

// Non-blocking operations with default
select {
case msg := <-ch:
    fmt.Println("Received:", msg)
default:
    fmt.Println("No message available")
}

// Ticker for periodic operations
ticker := time.NewTicker(500 * time.Millisecond)
done := make(chan bool)

go func() {
    for {
        select {
        case <-done:
            return
        case t := <-ticker.C:
            fmt.Println("Tick at", t)
        }
    }
}()

time.Sleep(2 * time.Second)
ticker.Stop()
done <- true`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#FF5722" }}>
              Common Channel Patterns
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Pattern 1: Generator
func generateNumbers(max int) <-chan int {
    ch := make(chan int)
    go func() {
        for i := 1; i <= max; i++ {
            ch <- i
        }
        close(ch)
    }()
    return ch
}

for n := range generateNumbers(5) {
    fmt.Println(n)
}

// Pattern 2: Fan-out (distribute work)
func fanOut(input <-chan int, workers int) []<-chan int {
    outputs := make([]<-chan int, workers)
    for i := 0; i < workers; i++ {
        outputs[i] = worker(input)
    }
    return outputs
}

// Pattern 3: Fan-in (merge channels)
func fanIn(channels ...<-chan int) <-chan int {
    var wg sync.WaitGroup
    merged := make(chan int)
    
    output := func(ch <-chan int) {
        defer wg.Done()
        for val := range ch {
            merged <- val
        }
    }
    
    wg.Add(len(channels))
    for _, ch := range channels {
        go output(ch)
    }
    
    go func() {
        wg.Wait()
        close(merged)
    }()
    
    return merged
}

// Pattern 4: Pipeline
func square(in <-chan int) <-chan int {
    out := make(chan int)
    go func() {
        for n := range in {
            out <- n * n
        }
        close(out)
    }()
    return out
}

// Pipeline: generate -> square -> print
for n := range square(generateNumbers(5)) {
    fmt.Println(n)  // 1, 4, 9, 16, 25
}

// Pattern 5: Context for cancellation
func doWork(ctx context.Context) error {
    for {
        select {
        case <-ctx.Done():
            return ctx.Err()  // Cancelled or deadline exceeded
        default:
            // Do work...
        }
    }
}

ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
go doWork(ctx)`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#FF5722", 0.1), border: `1px solid ${alpha("#FF5722", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <HubIcon sx={{ color: "#FF5722" }} />
                Channel Guidelines
              </Typography>
              <Grid container spacing={2} sx={{ mt: 1 }}>
                {[
                  { tip: "Close only from sender", desc: "Only the sender should close a channel. Closing twice panics!" },
                  { tip: "Nil channels block forever", desc: "Receiving from or sending to a nil channel blocks forever. Useful in select." },
                  { tip: "Use context for cancellation", desc: "context.Context is the standard way to propagate cancellation signals." },
                  { tip: "Buffer size matters", desc: "Unbuffered = synchronization. Buffered = async up to capacity. Choose wisely." },
                ].map((item) => (
                  <Grid item xs={12} sm={6} key={item.tip}>
                    <Typography variant="body2">
                      <strong>{item.tip}:</strong> {item.desc}
                    </Typography>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Paper>

          {/* Error Handling Section */}
          <Paper id="error-handling" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#F44336", 0.15), color: "#F44336", width: 48, height: 48 }}>
                <BugReportIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Error Handling
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Go takes a radically different approach to error handling compared to exceptions in other languages. 
              Errors are <strong>values</strong> that are explicitly returned and checked. This makes error handling 
              visible, forces developers to consider failure modes, and keeps control flow predictable.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#F44336" }}>
              The error Interface
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// The error interface is simple
type error interface {
    Error() string
}

// Functions return errors as the last return value
func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, errors.New("division by zero")
    }
    return a / b, nil
}

// Always check errors!
result, err := divide(10, 0)
if err != nil {
    log.Fatal(err)  // Handle the error
}
fmt.Println(result)

// The infamous Go pattern
file, err := os.Open("file.txt")
if err != nil {
    return err  // Propagate error up
}
defer file.Close()

// Creating errors
import "errors"

err := errors.New("something went wrong")

// Formatted errors with context
import "fmt"

err := fmt.Errorf("failed to process user %d: %s", userID, reason)

// Sentinel errors - predefined error values
var ErrNotFound = errors.New("not found")
var ErrPermissionDenied = errors.New("permission denied")

func findUser(id int) (*User, error) {
    if id < 0 {
        return nil, ErrNotFound
    }
    // ...
}

// Check for sentinel errors
if err == ErrNotFound {
    // Handle not found case
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#F44336" }}>
              Error Wrapping (Go 1.13+)
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Wrap errors to add context while preserving the original
func processFile(path string) error {
    file, err := os.Open(path)
    if err != nil {
        // %w wraps the error - preserves error chain
        return fmt.Errorf("processFile %s: %w", path, err)
    }
    defer file.Close()
    
    data, err := io.ReadAll(file)
    if err != nil {
        return fmt.Errorf("reading file: %w", err)
    }
    // ...
    return nil
}

// errors.Is - check if error chain contains a specific error
if errors.Is(err, os.ErrNotExist) {
    fmt.Println("File does not exist")
}

// Works through wrapped errors
err := processFile("missing.txt")
if errors.Is(err, os.ErrNotExist) {
    // Still matches even though error was wrapped!
}

// errors.As - extract specific error type from chain
var pathErr *os.PathError
if errors.As(err, &pathErr) {
    fmt.Println("Failed path:", pathErr.Path)
    fmt.Println("Operation:", pathErr.Op)
}

// Custom error types
type ValidationError struct {
    Field   string
    Message string
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("validation failed on %s: %s", e.Field, e.Message)
}

func validate(user User) error {
    if user.Email == "" {
        return &ValidationError{Field: "email", Message: "required"}
    }
    return nil
}

// Check for custom error type
var valErr *ValidationError
if errors.As(err, &valErr) {
    fmt.Printf("Field %s: %s\\n", valErr.Field, valErr.Message)
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#F44336" }}>
              Panic & Recover
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// panic - for truly exceptional situations
// Unwinds the stack, runs deferred functions, then crashes

func mustOpen(path string) *os.File {
    f, err := os.Open(path)
    if err != nil {
        panic(err)  // Program can't continue without this file
    }
    return f
}

// Common panic situations:
// - nil pointer dereference
// - out of bounds array access
// - closing a closed channel
// - type assertion failure

// recover - catch panics (use sparingly!)
// Only works inside deferred functions

func safeOperation() (err error) {
    defer func() {
        if r := recover(); r != nil {
            err = fmt.Errorf("panic recovered: %v", r)
        }
    }()
    
    // Code that might panic
    riskyOperation()
    return nil
}

// HTTP server example - recover middleware
func recoveryMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if err := recover(); err != nil {
                log.Printf("panic: %v\\n%s", err, debug.Stack())
                http.Error(w, "Internal Server Error", 500)
            }
        }()
        next.ServeHTTP(w, r)
    })
}

// When to use panic:
// ✓ Programmer errors (impossible states, violated invariants)
// ✓ Initialization failures (config, required resources)
// ✗ Expected errors (file not found, network timeout)
// ✗ User input validation`}
              </Typography>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "Always Check Errors", desc: "Never ignore errors with _. Handle or propagate them explicitly." },
                { title: "Add Context", desc: "Use fmt.Errorf with %w to wrap errors with additional context." },
                { title: "Use errors.Is/As", desc: "Check error chains properly instead of direct comparison." },
                { title: "Panic Sparingly", desc: "Reserve panic for truly unrecoverable situations. Prefer returning errors." },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#F44336", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#F44336", mb: 0.5 }}>
                      {item.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Packages & Modules Section */}
          <Paper id="packages" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#3F51B5", 0.15), color: "#3F51B5", width: 48, height: 48 }}>
                <ViewModuleIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Packages & Modules
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Go organizes code into <strong>packages</strong> for encapsulation and reuse. Since Go 1.11, 
              <strong> modules</strong> provide dependency management with versioning. Understanding packages 
              and modules is essential for building maintainable Go applications.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3F51B5" }}>
              Package Basics
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Every Go file starts with package declaration
package main  // Executable program

package user  // Library package

// Importing packages
import "fmt"
import "os"

// Grouped imports (preferred)
import (
    "fmt"
    "os"
    
    // Third-party packages
    "github.com/gin-gonic/gin"
)

// Import aliases
import (
    "fmt"
    
    // Alias to avoid name conflicts
    mylog "github.com/sirupsen/logrus"
    
    // Blank import - for side effects only (init functions)
    _ "github.com/lib/pq"
)

// Visibility rules - SIMPLE but important!
// Uppercase = Exported (public)
// Lowercase = unexported (private to package)

package user

type User struct {       // Exported - visible outside package
    ID   int             // Exported field
    Name string          // Exported field
    hash string          // unexported - only visible in 'user' package
}

func NewUser(name string) *User {   // Exported function
    return &User{Name: name, hash: generateHash()}
}

func generateHash() string {         // unexported function
    return "internal"
}

// Package documentation
// File: doc.go
/*
Package user provides types and functions for user management.

This package handles user creation, authentication, and profile management.
*/
package user`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3F51B5" }}>
              Go Modules
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`# Initialize a new module
$ go mod init github.com/username/myproject

# This creates go.mod:
module github.com/username/myproject

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/lib/pq v1.10.9
)

# go.sum contains cryptographic checksums of dependencies

# Common go mod commands
$ go mod tidy          # Add missing, remove unused deps
$ go mod download      # Download dependencies to cache
$ go mod verify        # Verify dependencies match checksums
$ go mod vendor        # Copy deps to vendor/ directory
$ go mod graph         # Print dependency graph
$ go mod why <pkg>     # Explain why package is needed

# Adding dependencies
$ go get github.com/gin-gonic/gin@v1.9.1  # Specific version
$ go get github.com/gin-gonic/gin@latest  # Latest version
$ go get -u ./...                          # Update all deps

# Version selection
github.com/pkg/errors v0.9.1    # Exact version
github.com/pkg/errors v0.9      # Latest v0.9.x
github.com/pkg/errors v0        # Latest v0.x.x

# Major version paths (v2+)
import "github.com/user/repo/v2"  # v2.x.x
import "github.com/user/repo/v3"  # v3.x.x

# Local development with replace
replace github.com/original/pkg => ../local/pkg
replace github.com/original/pkg => github.com/fork/pkg v1.0.0`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3F51B5" }}>
              Package Organization
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`# Recommended project structure
myproject/
├── go.mod
├── go.sum
├── main.go              # Entry point
├── cmd/                 # Additional executables
│   └── cli/
│       └── main.go
├── internal/            # Private packages (can't be imported externally!)
│   ├── config/
│   │   └── config.go
│   └── database/
│       └── db.go
├── pkg/                 # Public packages (can be imported)
│   └── api/
│       └── api.go
├── api/                 # API definitions, OpenAPI specs
├── web/                 # Web assets, templates
└── scripts/             # Build/deployment scripts

// internal/ is special - Go enforces visibility!
// Code in internal/ can only be imported by code in the same module
// Great for keeping implementation details private

// init() function - runs when package is imported
package database

var db *sql.DB

func init() {
    // Runs once when package is first imported
    // Use sparingly! Can make testing harder
    db = connectToDatabase()
}

// Multiple init() functions allowed, run in order
func init() {
    fmt.Println("First init")
}

func init() {
    fmt.Println("Second init")
}

// Blank imports run init() without using package
import _ "github.com/lib/pq"  // Registers postgres driver`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#3F51B5", 0.1), border: `1px solid ${alpha("#3F51B5", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <ViewModuleIcon sx={{ color: "#3F51B5" }} />
                Package Best Practices
              </Typography>
              <Grid container spacing={2} sx={{ mt: 1 }}>
                {[
                  { tip: "Name by functionality", desc: "Package names should describe what they do, not what they contain (user, not models)." },
                  { tip: "Avoid stutter", desc: "Don't repeat package name in identifiers. Use user.New(), not user.NewUser()." },
                  { tip: "Use internal/", desc: "Put implementation details in internal/ to prevent external imports." },
                  { tip: "Keep main small", desc: "main() should only wire dependencies and start the app. Logic goes in packages." },
                ].map((item) => (
                  <Grid item xs={12} sm={6} key={item.tip}>
                    <Typography variant="body2">
                      <strong>{item.tip}:</strong> {item.desc}
                    </Typography>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Paper>

          {/* Testing & Benchmarking Section */}
          <Paper id="testing" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#4CAF50", 0.15), color: "#4CAF50", width: 48, height: 48 }}>
                <SpeedIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Testing & Benchmarking
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Go has excellent built-in testing support with no external frameworks required. The testing 
              package provides unit tests, benchmarks, examples, and fuzzing. The go test command handles 
              test discovery, execution, and coverage analysis.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4CAF50" }}>
              Writing Tests
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// File: math.go
package math

func Add(a, b int) int {
    return a + b
}

func Divide(a, b int) (int, error) {
    if b == 0 {
        return 0, errors.New("division by zero")
    }
    return a / b, nil
}

// File: math_test.go (must end with _test.go)
package math

import "testing"

// Test function must start with Test and take *testing.T
func TestAdd(t *testing.T) {
    result := Add(2, 3)
    if result != 5 {
        t.Errorf("Add(2, 3) = %d; want 5", result)
    }
}

// Table-driven tests - THE Go way!
func TestAddTableDriven(t *testing.T) {
    tests := []struct {
        name     string
        a, b     int
        expected int
    }{
        {"positive numbers", 2, 3, 5},
        {"negative numbers", -2, -3, -5},
        {"zero", 0, 0, 0},
        {"mixed", -2, 3, 1},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := Add(tt.a, tt.b)
            if result != tt.expected {
                t.Errorf("Add(%d, %d) = %d; want %d", 
                    tt.a, tt.b, result, tt.expected)
            }
        })
    }
}

// Testing errors
func TestDivideByZero(t *testing.T) {
    _, err := Divide(10, 0)
    if err == nil {
        t.Error("expected error for division by zero")
    }
}

// Test helpers
func assertEqual(t *testing.T, got, want int) {
    t.Helper()  // Marks this as helper - errors show caller's line
    if got != want {
        t.Errorf("got %d; want %d", got, want)
    }
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4CAF50" }}>
              Running Tests & Coverage
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`# Run all tests in current package
$ go test

# Run all tests recursively
$ go test ./...

# Verbose output
$ go test -v

# Run specific test
$ go test -run TestAdd
$ go test -run "TestAdd.*"  # Regex pattern

# Run specific subtest
$ go test -run "TestAddTableDriven/positive"

# Test coverage
$ go test -cover
$ go test -coverprofile=coverage.out
$ go tool cover -html=coverage.out  # Visual report

# Race detector (finds data races)
$ go test -race

# Short mode (skip long tests)
$ go test -short

func TestLongOperation(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping long test in short mode")
    }
    // Long test...
}

# Parallel tests
func TestParallel(t *testing.T) {
    t.Parallel()  // Mark test as safe for parallel execution
    // ...
}

# Test timeout
$ go test -timeout 30s

# Test with build tags
// +build integration
func TestIntegration(t *testing.T) { }
$ go test -tags=integration`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#4CAF50" }}>
              Benchmarks & Examples
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Benchmarks - function starts with Benchmark
func BenchmarkAdd(b *testing.B) {
    // b.N is set by testing framework
    for i := 0; i < b.N; i++ {
        Add(2, 3)
    }
}

// Run benchmarks
$ go test -bench=.
$ go test -bench=BenchmarkAdd
$ go test -bench=. -benchmem  # Include memory stats

// Output:
// BenchmarkAdd-8    1000000000    0.290 ns/op    0 B/op    0 allocs/op

// Benchmark with setup
func BenchmarkComplexOperation(b *testing.B) {
    // Setup code (not measured)
    data := prepareTestData()
    
    b.ResetTimer()  // Reset timer after setup
    
    for i := 0; i < b.N; i++ {
        processData(data)
    }
}

// Sub-benchmarks
func BenchmarkProcess(b *testing.B) {
    sizes := []int{10, 100, 1000, 10000}
    for _, size := range sizes {
        b.Run(fmt.Sprintf("size-%d", size), func(b *testing.B) {
            data := make([]int, size)
            b.ResetTimer()
            for i := 0; i < b.N; i++ {
                process(data)
            }
        })
    }
}

// Example functions - shown in godoc, verified by go test
func ExampleAdd() {
    result := Add(2, 3)
    fmt.Println(result)
    // Output: 5
}

func ExampleDivide() {
    result, err := Divide(10, 2)
    if err != nil {
        fmt.Println("error:", err)
        return
    }
    fmt.Println(result)
    // Output: 5
}

// Fuzzing (Go 1.18+)
func FuzzReverse(f *testing.F) {
    // Seed corpus
    f.Add("hello")
    f.Add("world")
    
    f.Fuzz(func(t *testing.T, s string) {
        rev := Reverse(s)
        doubleRev := Reverse(rev)
        if s != doubleRev {
            t.Errorf("double reverse mismatch: %q", s)
        }
    })
}
$ go test -fuzz=FuzzReverse`}
              </Typography>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "Table-Driven Tests", desc: "Use struct slices for multiple test cases. Clear, maintainable, easy to add cases." },
                { title: "t.Helper()", desc: "Mark helper functions so errors report the caller's line number." },
                { title: "t.Parallel()", desc: "Enable parallel execution for independent tests. Speeds up test suite." },
                { title: "testdata/", desc: "Special directory for test fixtures. Ignored by go build, included by go test." },
                { title: "-race Flag", desc: "Detects data races at runtime. Use in CI/CD for concurrent code." },
                { title: "Fuzzing", desc: "Automated testing with random inputs. Great for finding edge cases." },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#4CAF50", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#4CAF50", mb: 0.5 }}>
                      {item.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Web Development Section */}
          <Paper id="web" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#2196F3", 0.15), color: "#2196F3", width: 48, height: 48 }}>
                <HttpIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Web Development
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Go excels at building web services. The standard library's net/http package is production-ready 
              and powers many high-traffic sites. Popular frameworks like Gin, Echo, and Chi add conveniences 
              while maintaining Go's performance. Let's build APIs and web applications.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#2196F3" }}>
              HTTP Basics with net/http
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`package main

import (
    "fmt"
    "log"
    "net/http"
)

// Handler function signature
func helloHandler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, %s!", r.URL.Path[1:])
}

// Handler using http.HandlerFunc type
var aboutHandler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/html")
    fmt.Fprint(w, "<h1>About Page</h1>")
}

func main() {
    // Register handlers
    http.HandleFunc("/hello/", helloHandler)
    http.HandleFunc("/about", aboutHandler)
    
    // Serve static files
    fs := http.FileServer(http.Dir("./static"))
    http.Handle("/static/", http.StripPrefix("/static/", fs))
    
    // Start server
    log.Println("Server starting on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

// Reading request data
func formHandler(w http.ResponseWriter, r *http.Request) {
    // Only allow POST
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    // Parse form data
    if err := r.ParseForm(); err != nil {
        http.Error(w, "Bad request", http.StatusBadRequest)
        return
    }
    
    name := r.FormValue("name")
    email := r.PostFormValue("email")  // POST only
    
    // Query parameters
    page := r.URL.Query().Get("page")
    
    // Headers
    userAgent := r.Header.Get("User-Agent")
    
    fmt.Fprintf(w, "Name: %s, Email: %s", name, email)
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#2196F3" }}>
              JSON APIs
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`import (
    "encoding/json"
    "net/http"
)

type User struct {
    ID        int    \`json:"id"\`
    Name      string \`json:"name"\`
    Email     string \`json:"email"\`
    Password  string \`json:"-"\`              // Omit from JSON
    CreatedAt string \`json:"created_at,omitempty"\`  // Omit if empty
}

// GET /users - Return JSON
func getUsersHandler(w http.ResponseWriter, r *http.Request) {
    users := []User{
        {ID: 1, Name: "Alice", Email: "alice@example.com"},
        {ID: 2, Name: "Bob", Email: "bob@example.com"},
    }
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(users)
}

// POST /users - Accept JSON
func createUserHandler(w http.ResponseWriter, r *http.Request) {
    var user User
    
    // Decode JSON body
    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }
    
    // Validate
    if user.Name == "" || user.Email == "" {
        http.Error(w, "Name and email required", http.StatusBadRequest)
        return
    }
    
    // Save user... (assign ID)
    user.ID = 123
    
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusCreated)
    json.NewEncoder(w).Encode(user)
}

// Custom JSON response helper
func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    json.NewEncoder(w).Encode(data)
}

type APIError struct {
    Error   string \`json:"error"\`
    Code    int    \`json:"code"\`
}

func jsonError(w http.ResponseWriter, message string, status int) {
    jsonResponse(w, status, APIError{Error: message, Code: status})
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#2196F3" }}>
              Middleware & Routing
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Middleware - wraps handlers to add functionality
type Middleware func(http.Handler) http.Handler

// Logging middleware
func loggingMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        log.Printf("Started %s %s", r.Method, r.URL.Path)
        
        next.ServeHTTP(w, r)
        
        log.Printf("Completed in %v", time.Since(start))
    })
}

// Auth middleware
func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := r.Header.Get("Authorization")
        if token == "" {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        // Validate token...
        next.ServeHTTP(w, r)
    })
}

// Chain middleware
func chain(h http.Handler, middlewares ...Middleware) http.Handler {
    for _, m := range middlewares {
        h = m(h)
    }
    return h
}

// Using http.ServeMux (Go 1.22+ has better routing)
mux := http.NewServeMux()
mux.HandleFunc("GET /users", getUsersHandler)
mux.HandleFunc("POST /users", createUserHandler)
mux.HandleFunc("GET /users/{id}", getUserByIDHandler)  // Go 1.22+

// Popular router: chi (lightweight, idiomatic)
import "github.com/go-chi/chi/v5"

r := chi.NewRouter()
r.Use(loggingMiddleware)

r.Route("/api", func(r chi.Router) {
    r.Use(authMiddleware)
    r.Get("/users", getUsersHandler)
    r.Post("/users", createUserHandler)
    r.Get("/users/{id}", getUserByIDHandler)
})

// Popular framework: Gin (fast, feature-rich)
import "github.com/gin-gonic/gin"

r := gin.Default()  // Includes logger & recovery middleware

r.GET("/users", func(c *gin.Context) {
    c.JSON(200, users)
})

r.POST("/users", func(c *gin.Context) {
    var user User
    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(400, gin.H{"error": err.Error()})
        return
    }
    c.JSON(201, user)
})`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#2196F3", 0.1), border: `1px solid ${alpha("#2196F3", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <HttpIcon sx={{ color: "#2196F3" }} />
                Web Development Tips
              </Typography>
              <Grid container spacing={2} sx={{ mt: 1 }}>
                {[
                  { tip: "Use http.Server", desc: "For production, configure timeouts: ReadTimeout, WriteTimeout, IdleTimeout." },
                  { tip: "Graceful shutdown", desc: "Use server.Shutdown(ctx) to finish active requests before stopping." },
                  { tip: "Context for cancellation", desc: "Use r.Context() to handle client disconnects and timeouts." },
                  { tip: "Validate input", desc: "Never trust user input. Validate and sanitize all data server-side." },
                ].map((item) => (
                  <Grid item xs={12} sm={6} key={item.tip}>
                    <Typography variant="body2">
                      <strong>{item.tip}:</strong> {item.desc}
                    </Typography>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Paper>

          {/* CLI Applications Section */}
          <Paper id="cli" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#607D8B", 0.15), color: "#607D8B", width: 48, height: 48 }}>
                <TerminalIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                CLI Applications
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Go is exceptional for building command-line tools. Single binary deployment, fast startup, 
              cross-compilation, and excellent standard library support make Go the go-to choice for CLI 
              applications. Tools like Docker, Kubernetes, Terraform, and Hugo are all written in Go.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#607D8B" }}>
              Flag Package Basics
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`package main

import (
    "flag"
    "fmt"
    "os"
)

func main() {
    // Define flags
    name := flag.String("name", "World", "Name to greet")
    count := flag.Int("count", 1, "Number of greetings")
    verbose := flag.Bool("verbose", false, "Enable verbose output")
    
    // Custom usage message
    flag.Usage = func() {
        fmt.Fprintf(os.Stderr, "Usage: %s [options]\\n\\nOptions:\\n", os.Args[0])
        flag.PrintDefaults()
    }
    
    // Parse command line
    flag.Parse()
    
    // Remaining args after flags
    args := flag.Args()
    
    if *verbose {
        fmt.Println("Verbose mode enabled")
    }
    
    for i := 0; i < *count; i++ {
        fmt.Printf("Hello, %s!\\n", *name)
    }
    
    if len(args) > 0 {
        fmt.Println("Extra arguments:", args)
    }
}

// Usage:
// $ ./greet -name=Alice -count=3
// Hello, Alice!
// Hello, Alice!
// Hello, Alice!

// $ ./greet -h
// Usage: ./greet [options]
// Options:
//   -count int
//         Number of greetings (default 1)
//   -name string
//         Name to greet (default "World")
//   -verbose
//         Enable verbose output`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#607D8B" }}>
              Building with Cobra
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Cobra - the most popular CLI framework
// Used by: kubectl, hugo, gh (GitHub CLI), docker

// $ go get github.com/spf13/cobra/cobra@latest

// Project structure:
// myapp/
// ├── cmd/
// │   ├── root.go
// │   ├── serve.go
// │   └── version.go
// └── main.go

// main.go
package main

import "myapp/cmd"

func main() {
    cmd.Execute()
}

// cmd/root.go
package cmd

import (
    "fmt"
    "os"
    
    "github.com/spf13/cobra"
)

var cfgFile string
var verbose bool

var rootCmd = &cobra.Command{
    Use:   "myapp",
    Short: "MyApp is a fantastic CLI tool",
    Long: \`MyApp is a CLI application that does amazing things.
Complete documentation is available at https://example.com\`,
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Println("Welcome to MyApp! Use --help for commands.")
    },
}

func Execute() {
    if err := rootCmd.Execute(); err != nil {
        os.Exit(1)
    }
}

func init() {
    // Global flags
    rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", 
        "config file (default is $HOME/.myapp.yaml)")
    rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, 
        "verbose output")
}

// cmd/serve.go - Subcommand
package cmd

import (
    "fmt"
    "github.com/spf13/cobra"
)

var port int

var serveCmd = &cobra.Command{
    Use:   "serve",
    Short: "Start the server",
    Long:  \`Start the HTTP server on the specified port.\`,
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Printf("Starting server on port %d...\\n", port)
    },
}

func init() {
    rootCmd.AddCommand(serveCmd)
    serveCmd.Flags().IntVarP(&port, "port", "p", 8080, "port to listen on")
}

// Usage:
// $ myapp serve -p 3000
// $ myapp serve --port=3000
// $ myapp --verbose serve`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#607D8B" }}>
              I/O, Signals & Cross-Compilation
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Standard I/O streams
import (
    "bufio"
    "fmt"
    "io"
    "os"
)

// Reading from stdin
func readInput() {
    reader := bufio.NewReader(os.Stdin)
    fmt.Print("Enter your name: ")
    name, _ := reader.ReadString('\\n')
    fmt.Printf("Hello, %s", name)
}

// Piping support
func processPipe() {
    // $ echo "hello" | myapp
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        line := scanner.Text()
        fmt.Println("Processed:", line)
    }
}

// Writing to stderr
fmt.Fprintln(os.Stderr, "Error: something went wrong")

// Exit codes
os.Exit(0)  // Success
os.Exit(1)  // General error
os.Exit(2)  // Misuse (bad args)

// Signal handling (graceful shutdown)
import (
    "os"
    "os/signal"
    "syscall"
)

func handleSignals() {
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
    
    go func() {
        sig := <-sigChan
        fmt.Printf("\\nReceived signal: %v\\n", sig)
        // Cleanup...
        os.Exit(0)
    }()
}

// Cross-compilation - build for any platform!
# Build for Linux from Windows/Mac
$ GOOS=linux GOARCH=amd64 go build -o myapp-linux

# Build for Windows from Linux/Mac
$ GOOS=windows GOARCH=amd64 go build -o myapp.exe

# Build for Mac from Linux/Windows
$ GOOS=darwin GOARCH=amd64 go build -o myapp-mac
$ GOOS=darwin GOARCH=arm64 go build -o myapp-mac-m1

# Common GOOS values: linux, windows, darwin, freebsd
# Common GOARCH values: amd64, arm64, 386, arm

# Reduce binary size
$ go build -ldflags="-s -w" -o myapp
# -s: strip symbol table
# -w: strip DWARF debug info`}
              </Typography>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "flag Package", desc: "Built-in argument parsing. Simple and sufficient for basic CLIs." },
                { title: "Cobra", desc: "Full-featured CLI framework. Subcommands, auto-completion, man pages." },
                { title: "Viper", desc: "Configuration library. Works with Cobra. Supports files, env, flags." },
                { title: "Single Binary", desc: "No dependencies to install. Just copy and run anywhere." },
                { title: "Cross-Compile", desc: "Build for any OS/arch from any platform. GOOS + GOARCH." },
                { title: "Fast Startup", desc: "Go binaries start instantly. Perfect for CLI tools." },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#607D8B", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#607D8B", mb: 0.5 }}>
                      {item.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Cloud & Microservices Section */}
          <Paper id="cloud" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#00897B", 0.15), color: "#00897B", width: 48, height: 48 }}>
                <CloudIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Cloud & Microservices
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Go dominates cloud infrastructure. Docker, Kubernetes, Prometheus, Terraform, and most CNCF 
              projects are written in Go. Its concurrency model, small binaries, and fast startup make it 
              perfect for containerized microservices.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00897B" }}>
              gRPC & Protocol Buffers
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Protocol Buffers - efficient binary serialization
// user.proto
syntax = "proto3";
package user;
option go_package = "./pb";

service UserService {
    rpc GetUser(GetUserRequest) returns (User);
    rpc ListUsers(ListUsersRequest) returns (stream User);
    rpc CreateUser(CreateUserRequest) returns (User);
}

message User {
    int64 id = 1;
    string name = 2;
    string email = 3;
    repeated string roles = 4;
}

message GetUserRequest {
    int64 id = 1;
}

// Generate Go code
$ protoc --go_out=. --go-grpc_out=. user.proto

// Server implementation
package main

import (
    "context"
    "net"
    "google.golang.org/grpc"
    pb "myapp/pb"
)

type server struct {
    pb.UnimplementedUserServiceServer
}

func (s *server) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.User, error) {
    return &pb.User{
        Id:    req.Id,
        Name:  "Alice",
        Email: "alice@example.com",
    }, nil
}

func main() {
    lis, _ := net.Listen("tcp", ":50051")
    s := grpc.NewServer()
    pb.RegisterUserServiceServer(s, &server{})
    s.Serve(lis)
}

// Client
conn, _ := grpc.Dial("localhost:50051", grpc.WithInsecure())
defer conn.Close()

client := pb.NewUserServiceClient(conn)
user, err := client.GetUser(context.Background(), &pb.GetUserRequest{Id: 1})`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00897B" }}>
              Docker & Health Checks
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`# Multi-stage Dockerfile for Go
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/server

# Minimal final image
FROM scratch
COPY --from=builder /app/server /server
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8080
ENTRYPOINT ["/server"]

# Result: ~10-20MB image vs 300MB+ with full Go image

// Health check endpoints
package main

import (
    "encoding/json"
    "net/http"
    "sync/atomic"
)

var healthy int32 = 1

// Liveness - is the process alive?
func livenessHandler(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("ok"))
}

// Readiness - is the service ready to accept traffic?
func readinessHandler(w http.ResponseWriter, r *http.Request) {
    if atomic.LoadInt32(&healthy) == 1 {
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(map[string]string{
            "status": "ready",
            "db": "connected",
        })
    } else {
        w.WriteHeader(http.StatusServiceUnavailable)
    }
}

// Register health endpoints
http.HandleFunc("/healthz", livenessHandler)   // Kubernetes liveness
http.HandleFunc("/readyz", readinessHandler)   // Kubernetes readiness

// Graceful shutdown
func gracefulShutdown(server *http.Server) {
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit
    
    log.Println("Shutting down server...")
    atomic.StoreInt32(&healthy, 0)  // Mark unhealthy
    
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    if err := server.Shutdown(ctx); err != nil {
        log.Fatal("Server forced to shutdown:", err)
    }
    log.Println("Server exited")
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00897B" }}>
              Configuration & Observability
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Environment-based configuration (12-factor app)
import "os"

type Config struct {
    Port        string
    DatabaseURL string
    LogLevel    string
}

func LoadConfig() *Config {
    return &Config{
        Port:        getEnv("PORT", "8080"),
        DatabaseURL: getEnv("DATABASE_URL", "postgres://localhost/myapp"),
        LogLevel:    getEnv("LOG_LEVEL", "info"),
    }
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

// Structured logging with slog (Go 1.21+)
import "log/slog"

logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
}))

logger.Info("request received",
    "method", r.Method,
    "path", r.URL.Path,
    "duration", time.Since(start),
)

// Output: {"time":"2024-01-15T10:30:00Z","level":"INFO","msg":"request received","method":"GET","path":"/users","duration":"1.234ms"}

// OpenTelemetry for distributed tracing
import (
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/trace"
)

tracer := otel.Tracer("my-service")

func handleRequest(ctx context.Context) {
    ctx, span := tracer.Start(ctx, "handleRequest")
    defer span.End()
    
    // Add attributes
    span.SetAttributes(
        attribute.String("user.id", userID),
        attribute.Int("items.count", len(items)),
    )
    
    // Nested span
    processItems(ctx, items)
}

// Prometheus metrics
import "github.com/prometheus/client_golang/prometheus"

var httpRequestsTotal = prometheus.NewCounterVec(
    prometheus.CounterOpts{
        Name: "http_requests_total",
        Help: "Total HTTP requests",
    },
    []string{"method", "path", "status"},
)

func init() {
    prometheus.MustRegister(httpRequestsTotal)
}

// In handler
httpRequestsTotal.WithLabelValues("GET", "/users", "200").Inc()`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#00897B", 0.1), border: `1px solid ${alpha("#00897B", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CloudIcon sx={{ color: "#00897B" }} />
                Cloud-Native Best Practices
              </Typography>
              <Grid container spacing={2} sx={{ mt: 1 }}>
                {[
                  { tip: "12-Factor App", desc: "Config from env vars. Stateless processes. Dev/prod parity. Logs to stdout." },
                  { tip: "Health endpoints", desc: "/healthz for liveness, /readyz for readiness. Kubernetes uses these." },
                  { tip: "Graceful shutdown", desc: "Handle SIGTERM, drain connections, finish in-flight requests." },
                  { tip: "Structured logging", desc: "JSON logs with context. Use slog or zerolog. Machine-parseable." },
                ].map((item) => (
                  <Grid item xs={12} sm={6} key={item.tip}>
                    <Typography variant="body2">
                      <strong>{item.tip}:</strong> {item.desc}
                    </Typography>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Paper>

          {/* Advanced Topics Section */}
          <Paper id="advanced" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#795548", 0.15), color: "#795548", width: 48, height: 48 }}>
                <DeveloperBoardIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Advanced Topics
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Go provides powerful advanced features for building high-performance systems. Generics enable 
              type-safe reusable code, reflection allows runtime introspection, and profiling tools help 
              optimize performance. Let's explore Go's advanced capabilities.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#795548" }}>
              Generics (Go 1.18+)
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Type parameters with constraints
func Min[T constraints.Ordered](a, b T) T {
    if a < b {
        return a
    }
    return b
}

result := Min(3, 5)       // int
result := Min(3.14, 2.71) // float64
result := Min("a", "b")   // string

// Generic slice functions
func Map[T, U any](slice []T, fn func(T) U) []U {
    result := make([]U, len(slice))
    for i, v := range slice {
        result[i] = fn(v)
    }
    return result
}

func Filter[T any](slice []T, predicate func(T) bool) []T {
    result := []T{}
    for _, v := range slice {
        if predicate(v) {
            result = append(result, v)
        }
    }
    return result
}

// Usage
numbers := []int{1, 2, 3, 4, 5}
doubled := Map(numbers, func(n int) int { return n * 2 })
evens := Filter(numbers, func(n int) bool { return n%2 == 0 })

// Generic data structures
type Stack[T any] struct {
    items []T
}

func (s *Stack[T]) Push(item T) {
    s.items = append(s.items, item)
}

func (s *Stack[T]) Pop() (T, bool) {
    if len(s.items) == 0 {
        var zero T
        return zero, false
    }
    item := s.items[len(s.items)-1]
    s.items = s.items[:len(s.items)-1]
    return item, true
}

// Type constraints
type Number interface {
    ~int | ~int64 | ~float64  // ~ includes underlying types
}

func Sum[T Number](nums []T) T {
    var total T
    for _, n := range nums {
        total += n
    }
    return total
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#795548" }}>
              Reflection
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`import "reflect"

// Inspect types at runtime
func inspect(v interface{}) {
    t := reflect.TypeOf(v)
    val := reflect.ValueOf(v)
    
    fmt.Printf("Type: %v\\n", t)
    fmt.Printf("Kind: %v\\n", t.Kind())
    fmt.Printf("Value: %v\\n", val)
}

type User struct {
    Name  string \`json:"name" validate:"required"\`
    Email string \`json:"email" validate:"email"\`
    Age   int    \`json:"age" validate:"min=0,max=150"\`
}

// Iterate struct fields
func printFields(v interface{}) {
    t := reflect.TypeOf(v)
    val := reflect.ValueOf(v)
    
    for i := 0; i < t.NumField(); i++ {
        field := t.Field(i)
        value := val.Field(i)
        
        fmt.Printf("Field: %s\\n", field.Name)
        fmt.Printf("  Type: %v\\n", field.Type)
        fmt.Printf("  Value: %v\\n", value)
        fmt.Printf("  JSON tag: %s\\n", field.Tag.Get("json"))
        fmt.Printf("  Validate: %s\\n", field.Tag.Get("validate"))
    }
}

// Modify values with reflection (must be pointer)
func setField(obj interface{}, name string, value interface{}) error {
    val := reflect.ValueOf(obj)
    if val.Kind() != reflect.Ptr {
        return errors.New("obj must be pointer")
    }
    
    field := val.Elem().FieldByName(name)
    if !field.IsValid() {
        return errors.New("field not found")
    }
    if !field.CanSet() {
        return errors.New("cannot set field")
    }
    
    field.Set(reflect.ValueOf(value))
    return nil
}

// Reflection is powerful but:
// - Slower than direct access
// - No compile-time type checking
// - Harder to read and debug
// Use sparingly! Generics often better choice.`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#795548" }}>
              Profiling & Performance
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 13, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// pprof - Go's built-in profiler
import (
    "net/http"
    _ "net/http/pprof"  // Registers /debug/pprof endpoints
)

func main() {
    // Add pprof endpoints to your server
    go func() {
        http.ListenAndServe("localhost:6060", nil)
    }()
    
    // Your main application...
}

// Access profiles:
// http://localhost:6060/debug/pprof/
// http://localhost:6060/debug/pprof/heap
// http://localhost:6060/debug/pprof/goroutine
// http://localhost:6060/debug/pprof/profile?seconds=30

// CLI profiling
$ go tool pprof http://localhost:6060/debug/pprof/heap
(pprof) top 10
(pprof) web          # Opens graph in browser
(pprof) list MyFunc  # Source annotated with profile data

// CPU profiling in code
import "runtime/pprof"

f, _ := os.Create("cpu.prof")
pprof.StartCPUProfile(f)
defer pprof.StopCPUProfile()
// Code to profile...

// Memory profiling
f, _ := os.Create("mem.prof")
runtime.GC()  // Get up-to-date statistics
pprof.WriteHeapProfile(f)

// Benchmark with profiling
$ go test -bench=. -cpuprofile=cpu.prof -memprofile=mem.prof
$ go tool pprof -http=:8080 cpu.prof

// Escape analysis - see what allocates on heap
$ go build -gcflags="-m" ./...

// Race detector
$ go run -race main.go
$ go test -race ./...

// Memory stats
var m runtime.MemStats
runtime.ReadMemStats(&m)
fmt.Printf("Alloc: %d MB\\n", m.Alloc/1024/1024)
fmt.Printf("TotalAlloc: %d MB\\n", m.TotalAlloc/1024/1024)
fmt.Printf("NumGC: %d\\n", m.NumGC)`}
              </Typography>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "Generics", desc: "Type parameters for reusable code. Constraints define allowed types. Go 1.18+." },
                { title: "Reflection", desc: "Runtime type inspection. Powerful but slow. Use for frameworks, not hot paths." },
                { title: "pprof", desc: "Built-in profiler. CPU, memory, goroutine, block profiles. Essential for optimization." },
                { title: "Race Detector", desc: "-race flag finds data races. Use in tests and development. Some overhead." },
                { title: "unsafe Package", desc: "Bypass type safety. For interop, performance hacks. Avoid in normal code." },
                { title: "cgo", desc: "Call C code from Go. Useful for legacy libs. Adds complexity, breaks cross-compile." },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#795548", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#795548", mb: 0.5 }}>
                      {item.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Quiz Section */}
          <Paper id="quiz" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <QuizIcon />
              </Avatar>
              <Box>
                <Typography variant="h5" sx={{ fontWeight: 800 }}>
                  Go Knowledge Quiz
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Test your understanding with 10 random questions from our bank of 75
                </Typography>
              </Box>
            </Box>

            {!quizStarted ? (
              // Quiz Start Screen
              <Box sx={{ textAlign: "center", py: 4 }}>
                <Box
                  sx={{
                    width: 120,
                    height: 120,
                    borderRadius: "50%",
                    bgcolor: alpha(accentColor, 0.1),
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    mx: "auto",
                    mb: 3,
                  }}
                >
                  <QuizIcon sx={{ fontSize: 60, color: accentColor }} />
                </Box>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
                  Ready to Test Your Go Knowledge?
                </Typography>
                <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 500, mx: "auto" }}>
                  This quiz covers all aspects of Go programming: syntax, types, functions, interfaces,
                  concurrency, channels, error handling, testing, and more. Each attempt randomly selects
                  10 questions from our bank of 75.
                </Typography>
                <Grid container spacing={2} sx={{ maxWidth: 400, mx: "auto", mb: 4 }}>
                  {[
                    { label: "Questions", value: "10" },
                    { label: "Question Bank", value: "75" },
                    { label: "Topics", value: "12+" },
                    { label: "Time Limit", value: "None" },
                  ].map((stat) => (
                    <Grid item xs={6} key={stat.label}>
                      <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(accentColor, 0.05) }}>
                        <Typography variant="h5" sx={{ fontWeight: 800, color: accentColor }}>
                          {stat.value}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {stat.label}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
                <Button
                  variant="contained"
                  size="large"
                  onClick={handleStartQuiz}
                  sx={{
                    bgcolor: accentColor,
                    px: 6,
                    py: 1.5,
                    fontWeight: 700,
                    "&:hover": { bgcolor: accentColorDark },
                  }}
                >
                  Start Quiz
                </Button>
              </Box>
            ) : quizComplete ? (
              // Quiz Complete Screen
              <Box sx={{ textAlign: "center", py: 4 }}>
                <Box
                  sx={{
                    width: 120,
                    height: 120,
                    borderRadius: "50%",
                    bgcolor: alpha(score >= 7 ? "#4CAF50" : score >= 5 ? "#FF9800" : "#F44336", 0.1),
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    mx: "auto",
                    mb: 3,
                  }}
                >
                  <EmojiEventsIcon
                    sx={{
                      fontSize: 60,
                      color: score >= 7 ? "#4CAF50" : score >= 5 ? "#FF9800" : "#F44336",
                    }}
                  />
                </Box>
                <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
                  {score >= 8 ? "Excellent!" : score >= 6 ? "Good Job!" : score >= 4 ? "Keep Learning!" : "Keep Practicing!"}
                </Typography>
                <Typography variant="h2" sx={{ fontWeight: 800, color: accentColor, mb: 1 }}>
                  {score}/10
                </Typography>
                <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>
                  {score >= 8
                    ? "You have a strong grasp of Go programming!"
                    : score >= 6
                    ? "Good understanding! Review the topics you missed."
                    : score >= 4
                    ? "You're getting there! Keep studying the fundamentals."
                    : "Don't give up! Review the sections above and try again."}
                </Typography>

                {/* Results Breakdown */}
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColor, 0.03), mb: 4, maxWidth: 600, mx: "auto" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>
                    Results Breakdown
                  </Typography>
                  <Grid container spacing={1}>
                    {answeredQuestions.map((q, idx) => {
                      const question = quizQuestions[idx];
                      return (
                        <Grid item xs={12} key={q.questionId}>
                          <Box
                            sx={{
                              display: "flex",
                              alignItems: "center",
                              gap: 1,
                              p: 1.5,
                              borderRadius: 1,
                              bgcolor: q.correct ? alpha("#4CAF50", 0.1) : alpha("#F44336", 0.1),
                            }}
                          >
                            {q.correct ? (
                              <CheckCircleOutlineIcon sx={{ color: "#4CAF50", fontSize: 20 }} />
                            ) : (
                              <CancelOutlinedIcon sx={{ color: "#F44336", fontSize: 20 }} />
                            )}
                            <Typography variant="body2" sx={{ flex: 1, textAlign: "left" }}>
                              <strong>Q{idx + 1}:</strong> {question.question.slice(0, 60)}...
                            </Typography>
                            <Chip label={question.topic} size="small" sx={{ fontSize: 11 }} />
                          </Box>
                        </Grid>
                      );
                    })}
                  </Grid>
                </Paper>

                <Box sx={{ display: "flex", gap: 2, justifyContent: "center" }}>
                  <Button
                    variant="contained"
                    startIcon={<RefreshIcon />}
                    onClick={handleRestartQuiz}
                    sx={{
                      bgcolor: accentColor,
                      fontWeight: 700,
                      "&:hover": { bgcolor: accentColorDark },
                    }}
                  >
                    Try Again
                  </Button>
                  <Button
                    variant="outlined"
                    onClick={() => {
                      setQuizStarted(false);
                      setQuizComplete(false);
                    }}
                    sx={{ fontWeight: 700, borderColor: accentColor, color: accentColor }}
                  >
                    Back to Start
                  </Button>
                </Box>
              </Box>
            ) : (
              // Quiz Questions
              <Box>
                {/* Progress */}
                <Box sx={{ mb: 3 }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1 }}>
                    <Typography variant="body2" color="text.secondary">
                      Question {currentQuestion + 1} of {quizQuestions.length}
                    </Typography>
                    <Chip
                      label={quizQuestions[currentQuestion].topic}
                      size="small"
                      sx={{ bgcolor: alpha(accentColor, 0.1), color: accentColor, fontWeight: 600 }}
                    />
                  </Box>
                  <LinearProgress
                    variant="determinate"
                    value={((currentQuestion + 1) / quizQuestions.length) * 100}
                    sx={{
                      height: 8,
                      borderRadius: 4,
                      bgcolor: alpha(accentColor, 0.1),
                      "& .MuiLinearProgress-bar": { bgcolor: accentColor, borderRadius: 4 },
                    }}
                  />
                </Box>

                {/* Question */}
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
                  {quizQuestions[currentQuestion].question}
                </Typography>

                {/* Options */}
                <FormControl component="fieldset" sx={{ width: "100%", mb: 3 }}>
                  <RadioGroup value={selectedAnswer} onChange={(e) => handleAnswerSelect(Number(e.target.value))}>
                    {quizQuestions[currentQuestion].options.map((option, idx) => {
                      const isCorrect = idx === quizQuestions[currentQuestion].correct;
                      const isSelected = selectedAnswer === idx;
                      let bgcolor = "transparent";
                      let borderColor = alpha(accentColor, 0.2);

                      if (showResult) {
                        if (isCorrect) {
                          bgcolor = alpha("#4CAF50", 0.1);
                          borderColor = "#4CAF50";
                        } else if (isSelected && !isCorrect) {
                          bgcolor = alpha("#F44336", 0.1);
                          borderColor = "#F44336";
                        }
                      } else if (isSelected) {
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
                            border: `2px solid ${borderColor}`,
                            bgcolor,
                            cursor: showResult ? "default" : "pointer",
                            transition: "all 0.2s",
                            "&:hover": {
                              bgcolor: showResult ? bgcolor : alpha(accentColor, 0.05),
                            },
                          }}
                          onClick={() => handleAnswerSelect(idx)}
                        >
                          <FormControlLabel
                            value={idx}
                            control={
                              <Radio
                                disabled={showResult}
                                sx={{
                                  color: accentColor,
                                  "&.Mui-checked": { color: accentColor },
                                }}
                              />
                            }
                            label={
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                <Typography>{option}</Typography>
                                {showResult && isCorrect && (
                                  <CheckCircleOutlineIcon sx={{ color: "#4CAF50", fontSize: 20 }} />
                                )}
                                {showResult && isSelected && !isCorrect && (
                                  <CancelOutlinedIcon sx={{ color: "#F44336", fontSize: 20 }} />
                                )}
                              </Box>
                            }
                            sx={{ width: "100%", m: 0, py: 1 }}
                          />
                        </Paper>
                      );
                    })}
                  </RadioGroup>
                </FormControl>

                {/* Explanation */}
                {showResult && (
                  <Paper
                    sx={{
                      p: 2,
                      borderRadius: 2,
                      bgcolor: alpha(accentColor, 0.05),
                      border: `1px solid ${alpha(accentColor, 0.2)}`,
                      mb: 3,
                    }}
                  >
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: accentColor, mb: 0.5 }}>
                      Explanation
                    </Typography>
                    <Typography variant="body2">{quizQuestions[currentQuestion].explanation}</Typography>
                  </Paper>
                )}

                {/* Actions */}
                <Box sx={{ display: "flex", gap: 2 }}>
                  {!showResult ? (
                    <Button
                      variant="contained"
                      fullWidth
                      disabled={selectedAnswer === null}
                      onClick={handleSubmitAnswer}
                      sx={{
                        bgcolor: accentColor,
                        fontWeight: 700,
                        py: 1.5,
                        "&:hover": { bgcolor: accentColorDark },
                        "&:disabled": { bgcolor: alpha(accentColor, 0.3) },
                      }}
                    >
                      Submit Answer
                    </Button>
                  ) : (
                    <Button
                      variant="contained"
                      fullWidth
                      onClick={handleNextQuestion}
                      sx={{
                        bgcolor: accentColor,
                        fontWeight: 700,
                        py: 1.5,
                        "&:hover": { bgcolor: accentColorDark },
                      }}
                    >
                      {currentQuestion < quizQuestions.length - 1 ? "Next Question" : "See Results"}
                    </Button>
                  )}
                </Box>

                {/* Score tracker */}
                <Box sx={{ display: "flex", justifyContent: "center", gap: 1, mt: 3 }}>
                  {Array.from({ length: 10 }).map((_, idx) => {
                    let color = alpha(accentColor, 0.2);
                    if (idx < answeredQuestions.length) {
                      color = answeredQuestions[idx].correct ? "#4CAF50" : "#F44336";
                    } else if (idx === currentQuestion) {
                      color = accentColor;
                    }
                    return (
                      <Box
                        key={idx}
                        sx={{
                          width: 12,
                          height: 12,
                          borderRadius: "50%",
                          bgcolor: color,
                          transition: "all 0.3s",
                        }}
                      />
                    );
                  })}
                </Box>
              </Box>
            )}
          </Paper>

          {/* Continue Your Journey */}
          <Paper sx={{ p: 4, borderRadius: 4, border: `1px solid ${alpha(accentColor, 0.2)}` }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 2 }}>
              Continue Your Journey
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              After mastering Go, explore related topics to expand your expertise:
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              {[
                { label: "Docker & Containers", path: "/learn/container-exploitation" },
                { label: "Cloud Computing", path: "/learn/cloud-computing" },
                { label: "Computer Networking", path: "/learn/networking" },
                { label: "Systems Administration", path: "/learn/systems-administration" },
                { label: "C Programming", path: "/learn/c-programming" },
                { label: "Python Fundamentals", path: "/learn/python-fundamentals" },
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
