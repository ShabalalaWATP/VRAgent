import React, { useState, useEffect } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
import QuizSection, { QuizQuestion } from "../components/QuizSection";
import { Link } from "react-router-dom";
import {
  Box,
  Container,
  Typography,
  Paper,
  Grid,
  Chip,
  alpha,
  useTheme,
  Divider,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Alert,
  AlertTitle,
  Button,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Drawer,
  Fab,
  IconButton,
  Tooltip,
  LinearProgress,
  useMediaQuery,
} from "@mui/material";
import InfoIcon from "@mui/icons-material/Info";
import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutline";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import PsychologyIcon from "@mui/icons-material/Psychology";
import BuildIcon from "@mui/icons-material/Build";
import ComputerIcon from "@mui/icons-material/Computer";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import SchoolIcon from "@mui/icons-material/School";
import DataArrayIcon from "@mui/icons-material/DataArray";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import SpeedIcon from "@mui/icons-material/Speed";
import MemoryIcon from "@mui/icons-material/Memory";
import CodeIcon from "@mui/icons-material/Code";
import StorageIcon from "@mui/icons-material/Storage";
import LayersIcon from "@mui/icons-material/Layers";
import CategoryIcon from "@mui/icons-material/Category";
import FunctionsIcon from "@mui/icons-material/Functions";
import TimelineIcon from "@mui/icons-material/Timeline";
import HubIcon from "@mui/icons-material/Hub";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import QuizIcon from "@mui/icons-material/Quiz";
import { useNavigate } from "react-router-dom";

// ========== DATA STRUCTURES ==========
const dataStructures = [
  { name: "Array", type: "Linear", description: "Fixed-size sequential collection of elements", access: "O(1)", search: "O(n)", insert: "O(n)", delete: "O(n)", useCase: "Fast access by index, cache-friendly" },
  { name: "Linked List", type: "Linear", description: "Nodes connected by pointers", access: "O(n)", search: "O(n)", insert: "O(1)", delete: "O(1)", useCase: "Frequent insertions/deletions" },
  { name: "Stack", type: "Linear", description: "LIFO (Last In, First Out)", access: "O(n)", search: "O(n)", insert: "O(1)", delete: "O(1)", useCase: "Undo operations, parsing, recursion" },
  { name: "Queue", type: "Linear", description: "FIFO (First In, First Out)", access: "O(n)", search: "O(n)", insert: "O(1)", delete: "O(1)", useCase: "Task scheduling, BFS" },
  { name: "Hash Table", type: "Non-Linear", description: "Key-value pairs with hash function", access: "O(1)*", search: "O(1)*", insert: "O(1)*", delete: "O(1)*", useCase: "Fast lookups, caching, indexing" },
  { name: "Binary Tree", type: "Non-Linear", description: "Hierarchical with max 2 children per node", access: "O(log n)*", search: "O(log n)*", insert: "O(log n)*", delete: "O(log n)*", useCase: "Hierarchical data, file systems" },
  { name: "Binary Search Tree", type: "Non-Linear", description: "Ordered binary tree", access: "O(log n)*", search: "O(log n)*", insert: "O(log n)*", delete: "O(log n)*", useCase: "Sorted data, range queries" },
  { name: "Heap", type: "Non-Linear", description: "Complete binary tree with heap property", access: "O(1)", search: "O(n)", insert: "O(log n)", delete: "O(log n)", useCase: "Priority queues, heap sort" },
  { name: "Graph", type: "Non-Linear", description: "Vertices connected by edges", access: "O(V+E)", search: "O(V+E)", insert: "O(1)", delete: "O(V+E)", useCase: "Networks, social graphs, maps" },
  { name: "Trie", type: "Non-Linear", description: "Tree for storing strings by prefix", access: "O(m)", search: "O(m)", insert: "O(m)", delete: "O(m)", useCase: "Autocomplete, spell check, IP routing" },
];

// ========== BIG O NOTATION ==========
const bigOComplexities = [
  { notation: "O(1)", name: "Constant", description: "Same time regardless of input size", example: "Array access, hash table lookup", color: "#22c55e" },
  { notation: "O(log n)", name: "Logarithmic", description: "Halves problem size each step", example: "Binary search, balanced BST operations", color: "#84cc16" },
  { notation: "O(n)", name: "Linear", description: "Time grows linearly with input", example: "Linear search, array traversal", color: "#eab308" },
  { notation: "O(n log n)", name: "Linearithmic", description: "Slightly worse than linear", example: "Merge sort, heap sort, quick sort (avg)", color: "#f97316" },
  { notation: "O(n²)", name: "Quadratic", description: "Nested iterations over data", example: "Bubble sort, insertion sort, nested loops", color: "#ef4444" },
  { notation: "O(n³)", name: "Cubic", description: "Triple nested iterations", example: "Matrix multiplication (naive), 3D DP", color: "#dc2626" },
  { notation: "O(2ⁿ)", name: "Exponential", description: "Doubles with each input increase", example: "Recursive Fibonacci, subset generation", color: "#b91c1c" },
  { notation: "O(n!)", name: "Factorial", description: "Grows extremely fast", example: "Permutations, traveling salesman (brute)", color: "#991b1b" },
];

// ========== SORTING ALGORITHMS ==========
const sortingAlgorithms = [
  { name: "Bubble Sort", best: "O(n)", average: "O(n²)", worst: "O(n²)", space: "O(1)", stable: "Yes", description: "Repeatedly swaps adjacent elements" },
  { name: "Selection Sort", best: "O(n²)", average: "O(n²)", worst: "O(n²)", space: "O(1)", stable: "No", description: "Finds minimum and places at start" },
  { name: "Insertion Sort", best: "O(n)", average: "O(n²)", worst: "O(n²)", space: "O(1)", stable: "Yes", description: "Builds sorted array one element at a time" },
  { name: "Merge Sort", best: "O(n log n)", average: "O(n log n)", worst: "O(n log n)", space: "O(n)", stable: "Yes", description: "Divide and conquer, merges sorted halves" },
  { name: "Quick Sort", best: "O(n log n)", average: "O(n log n)", worst: "O(n²)", space: "O(log n)", stable: "No", description: "Partition around pivot element" },
  { name: "Heap Sort", best: "O(n log n)", average: "O(n log n)", worst: "O(n log n)", space: "O(1)", stable: "No", description: "Uses heap data structure" },
  { name: "Counting Sort", best: "O(n+k)", average: "O(n+k)", worst: "O(n+k)", space: "O(k)", stable: "Yes", description: "Counts occurrences, good for small range" },
  { name: "Radix Sort", best: "O(nk)", average: "O(nk)", worst: "O(nk)", space: "O(n+k)", stable: "Yes", description: "Sorts by individual digits" },
];

// ========== SEARCHING ALGORITHMS ==========
const searchingAlgorithms = [
  { name: "Linear Search", timeComplexity: "O(n)", spaceComplexity: "O(1)", requirement: "None", description: "Check each element sequentially" },
  { name: "Binary Search", timeComplexity: "O(log n)", spaceComplexity: "O(1)", requirement: "Sorted array", description: "Divide search space in half each step" },
  { name: "Jump Search", timeComplexity: "O(√n)", spaceComplexity: "O(1)", requirement: "Sorted array", description: "Jump ahead by fixed steps, then linear" },
  { name: "Interpolation Search", timeComplexity: "O(log log n)*", spaceComplexity: "O(1)", requirement: "Sorted, uniform distribution", description: "Estimates position based on value" },
  { name: "Hash Table Lookup", timeComplexity: "O(1)*", spaceComplexity: "O(n)", requirement: "Hash table", description: "Direct access via hash function" },
  { name: "BFS (Graph)", timeComplexity: "O(V+E)", spaceComplexity: "O(V)", requirement: "Graph", description: "Level-by-level traversal using queue" },
  { name: "DFS (Graph)", timeComplexity: "O(V+E)", spaceComplexity: "O(V)", requirement: "Graph", description: "Explore as far as possible using stack" },
];

// ========== PROGRAMMING PARADIGMS ==========
const programmingParadigms = [
  { name: "Imperative", description: "Step-by-step instructions changing program state", languages: "C, Go, Assembly", keyFeatures: "Variables, loops, conditionals, sequential execution" },
  { name: "Object-Oriented (OOP)", description: "Organize code around objects with data and methods", languages: "Java, C++, Python, C#", keyFeatures: "Encapsulation, inheritance, polymorphism, abstraction" },
  { name: "Functional", description: "Pure functions, immutable data, no side effects", languages: "Haskell, Erlang, Clojure, F#", keyFeatures: "First-class functions, higher-order functions, recursion" },
  { name: "Declarative", description: "Describe what to do, not how to do it", languages: "SQL, HTML, Prolog", keyFeatures: "Focus on results, less control flow" },
  { name: "Procedural", description: "Sequence of procedures/routines", languages: "C, Pascal, BASIC", keyFeatures: "Functions, modularity, local variables" },
  { name: "Event-Driven", description: "Flow determined by events (clicks, messages)", languages: "JavaScript, C#", keyFeatures: "Event handlers, callbacks, listeners" },
];

// ========== OOP PRINCIPLES ==========
const oopPrinciples = [
  { principle: "Encapsulation", description: "Bundle data and methods, hide internal state", benefit: "Data protection, reduced complexity", example: "Private fields with public getters/setters" },
  { principle: "Abstraction", description: "Show only essential features, hide complexity", benefit: "Simpler interfaces, reduced coupling", example: "Abstract classes, interfaces" },
  { principle: "Inheritance", description: "Create new classes based on existing ones", benefit: "Code reuse, hierarchical classification", example: "class Dog extends Animal" },
  { principle: "Polymorphism", description: "Same interface, different implementations", benefit: "Flexibility, extensibility", example: "Method overriding, interfaces" },
];

// ========== SOLID PRINCIPLES ==========
const solidPrinciples = [
  { letter: "S", name: "Single Responsibility", description: "A class should have only one reason to change", example: "Separate User class from UserValidator" },
  { letter: "O", name: "Open/Closed", description: "Open for extension, closed for modification", example: "Use interfaces to add new features" },
  { letter: "L", name: "Liskov Substitution", description: "Subtypes must be substitutable for base types", example: "Square shouldn't extend Rectangle if it breaks behavior" },
  { letter: "I", name: "Interface Segregation", description: "Many specific interfaces over one general", example: "Split IPrinter into IPrint, IScan, IFax" },
  { letter: "D", name: "Dependency Inversion", description: "Depend on abstractions, not concretions", example: "Inject IDatabase instead of MySQLDatabase" },
];

// ========== MEMORY CONCEPTS ==========
const memoryConcepts = [
  { concept: "Stack", description: "LIFO memory for function calls and local variables", characteristics: "Fast, automatic allocation/deallocation, limited size", managed: "Compiler" },
  { concept: "Heap", description: "Dynamic memory allocation for objects", characteristics: "Flexible size, manual/GC managed, slower than stack", managed: "Programmer/GC" },
  { concept: "Garbage Collection", description: "Automatic memory management", characteristics: "Prevents memory leaks, adds overhead", managed: "Runtime" },
  { concept: "Pointers", description: "Variables storing memory addresses", characteristics: "Direct memory access, powerful but dangerous", managed: "Programmer" },
  { concept: "References", description: "Aliases to existing variables", characteristics: "Safer than pointers, cannot be null (usually)", managed: "Compiler" },
  { concept: "Memory Leak", description: "Memory allocated but never freed", characteristics: "Gradual memory exhaustion, performance degradation", managed: "Bug" },
];

// ========== NUMBER SYSTEMS ==========
const numberSystems = [
  { system: "Binary", base: 2, digits: "0, 1", prefix: "0b", example: "0b1010 = 10", useCase: "Computer hardware, bitwise operations" },
  { system: "Octal", base: 8, digits: "0-7", prefix: "0o", example: "0o12 = 10", useCase: "Unix file permissions" },
  { system: "Decimal", base: 10, digits: "0-9", prefix: "None", example: "10 = 10", useCase: "Human-readable numbers" },
  { system: "Hexadecimal", base: 16, digits: "0-9, A-F", prefix: "0x", example: "0xA = 10", useCase: "Memory addresses, colors, MAC addresses" },
];

// ========== OPERATING SYSTEM FUNDAMENTALS ==========
const osFundamentals = [
  { concept: "Process", description: "A running program with its own virtual address space", why: "Isolation and scheduling unit", example: "Browser tabs in separate processes" },
  { concept: "Thread", description: "Execution path inside a process that shares memory", why: "Concurrency and responsiveness", example: "UI thread with worker threads" },
  { concept: "Context Switch", description: "CPU saves/restores state between tasks", why: "Enables multitasking with overhead", example: "Switching from editor to compiler" },
  { concept: "Scheduling", description: "Decides which task runs next", why: "Balances throughput, latency, fairness", example: "Round-robin or priority scheduling" },
  { concept: "System Call", description: "Gateway from user space to kernel", why: "Access files, network, devices", example: "open(), read(), socket()" },
  { concept: "Virtual Memory", description: "Private address space per process", why: "Isolation, paging, memory overcommit", example: "Heap/stack separated per process" },
];

// ========== CONCURRENCY CONCEPTS ==========
const concurrencyConcepts = [
  { concept: "Race Condition", description: "Outcome depends on timing between threads", pitfall: "Corrupted state, heisenbugs", mitigation: "Locks or atomic operations" },
  { concept: "Deadlock", description: "Tasks wait forever on each other", pitfall: "System stalls", mitigation: "Lock ordering, timeouts" },
  { concept: "Mutex vs Semaphore", description: "Mutex is exclusive; semaphore counts permits", pitfall: "Over or under locking", mitigation: "Keep critical sections small" },
  { concept: "Thread Pool", description: "Reuse workers to run tasks", pitfall: "Queue growth, starvation", mitigation: "Backpressure, bounded queues" },
  { concept: "Async IO", description: "Non-blocking operations with callbacks/promises", pitfall: "Hidden concurrency bugs", mitigation: "Structured async/await" },
  { concept: "Parallelism", description: "Tasks run at the same time on multiple cores", pitfall: "Contention, false sharing", mitigation: "Batch work, reduce shared state" },
];

// ========== NETWORKING LAYERS ==========
const networkLayers = [
  { layer: "Application", purpose: "User-facing protocols", examples: "HTTP, DNS, SSH, SMTP", dataUnit: "Message" },
  { layer: "Transport", purpose: "End-to-end delivery and ports", examples: "TCP, UDP, QUIC", dataUnit: "Segment/Datagram" },
  { layer: "Internet", purpose: "Routing across networks", examples: "IP, ICMP", dataUnit: "Packet" },
  { layer: "Link", purpose: "Local network framing", examples: "Ethernet, Wi-Fi", dataUnit: "Frame" },
];

// ========== DATABASE BASICS ==========
const dataModels = [
  { model: "Relational", description: "Tables with rows and columns", strengths: "Strong consistency, joins, ACID", useCase: "Transactions, reporting" },
  { model: "Document", description: "JSON-like documents", strengths: "Flexible schema, nested data", useCase: "Content, user profiles" },
  { model: "Key-Value", description: "Simple key to value mapping", strengths: "Fast lookups, caching", useCase: "Sessions, feature flags" },
  { model: "Graph", description: "Nodes and edges", strengths: "Relationship queries, traversals", useCase: "Recommendations, fraud detection" },
];

const storageConcepts = [
  { concept: "Indexing", description: "Auxiliary structure to speed lookups", tradeoff: "Faster reads, slower writes", example: "B-tree on email column" },
  { concept: "Transactions (ACID)", description: "Atomicity, Consistency, Isolation, Durability", tradeoff: "Consistency vs throughput", example: "Bank transfers" },
  { concept: "Replication", description: "Copy data to multiple nodes", tradeoff: "Read scaling, failover complexity", example: "Primary/replica" },
  { concept: "Sharding", description: "Split data across partitions", tradeoff: "Scales writes, complex queries", example: "Shard by user_id" },
];

// ========== DESIGN PATTERNS ==========
const designPatterns = [
  { name: "Singleton", category: "Creational", description: "Ensure only one instance of a class exists", useCase: "Database connections, logging, configuration" },
  { name: "Factory", category: "Creational", description: "Create objects without specifying exact class", useCase: "Object creation based on conditions" },
  { name: "Builder", category: "Creational", description: "Construct complex objects step by step", useCase: "Building objects with many optional parameters" },
  { name: "Observer", category: "Behavioral", description: "Notify multiple objects of state changes", useCase: "Event systems, pub/sub, MVC" },
  { name: "Strategy", category: "Behavioral", description: "Define family of algorithms, make interchangeable", useCase: "Payment methods, sorting strategies" },
  { name: "Command", category: "Behavioral", description: "Encapsulate a request as an object", useCase: "Undo/redo, task queues, logging" },
  { name: "Decorator", category: "Structural", description: "Add behavior to objects dynamically", useCase: "Adding features without subclassing" },
  { name: "Adapter", category: "Structural", description: "Convert interface to another interface", useCase: "Legacy code integration, API wrappers" },
  { name: "Facade", category: "Structural", description: "Simplified interface to a complex subsystem", useCase: "Library wrappers, API simplification" },
];

// ========== RECURSION CONCEPTS ==========
const recursionConcepts = [
  { concept: "Base Case", description: "Condition that stops recursion", example: "if (n <= 1) return 1", importance: "Prevents infinite recursion" },
  { concept: "Recursive Case", description: "Function calls itself with modified input", example: "return n * factorial(n-1)", importance: "Breaks problem into smaller parts" },
  { concept: "Call Stack", description: "Stack of function calls waiting to complete", example: "Each recursive call adds a frame", importance: "Memory usage consideration" },
  { concept: "Stack Overflow", description: "When call stack exceeds memory limit", example: "Missing or incorrect base case", importance: "Common bug to avoid" },
  { concept: "Tail Recursion", description: "Recursive call is the last operation", example: "return factorial(n-1, acc*n)", importance: "Can be optimized by compilers" },
  { concept: "Memoization", description: "Cache results of expensive function calls", example: "Store fib(n) to avoid recalculation", importance: "Converts O(2^n) to O(n)" },
];

// ========== COMMON INTERVIEW CONCEPTS ==========
const interviewConcepts = [
  { topic: "Two Pointers", description: "Use two pointers to traverse data structure", useCase: "Finding pairs, reversing arrays, detecting cycles", complexity: "Often O(n)" },
  { topic: "Sliding Window", description: "Maintain a window of elements that slides through array", useCase: "Substring problems, max sum subarrays", complexity: "O(n)" },
  { topic: "Binary Search", description: "Divide search space in half each iteration", useCase: "Sorted array search, finding boundaries", complexity: "O(log n)" },
  { topic: "Depth-First Search", description: "Explore as deep as possible before backtracking", useCase: "Path finding, tree traversal, maze solving", complexity: "O(V+E)" },
  { topic: "Breadth-First Search", description: "Explore all neighbors before going deeper", useCase: "Shortest path, level-order traversal", complexity: "O(V+E)" },
  { topic: "Dynamic Programming", description: "Break problem into overlapping subproblems", useCase: "Optimization problems, counting paths", complexity: "Varies" },
  { topic: "Greedy Algorithms", description: "Make locally optimal choice at each step", useCase: "Scheduling, minimum spanning trees", complexity: "Often O(n log n)" },
  { topic: "Backtracking", description: "Try solutions and backtrack when invalid", useCase: "Permutations, sudoku, N-queens", complexity: "Often exponential" },
];

// ========== TREE TRAVERSALS ==========
const treeTraversals = [
  { name: "In-Order (LNR)", order: "Left → Node → Right", result: "Sorted order for BST", useCase: "Get sorted elements from BST", recursive: "inOrder(left); visit(node); inOrder(right)" },
  { name: "Pre-Order (NLR)", order: "Node → Left → Right", result: "Root first, then children", useCase: "Copy tree, serialize tree structure", recursive: "visit(node); preOrder(left); preOrder(right)" },
  { name: "Post-Order (LRN)", order: "Left → Right → Node", result: "Children first, then root", useCase: "Delete tree, evaluate expressions", recursive: "postOrder(left); postOrder(right); visit(node)" },
  { name: "Level-Order (BFS)", order: "Level by level, left to right", result: "Breadth-first traversal", useCase: "Find shortest path, serialize by level", recursive: "Use queue, not recursion" },
];

// ========== GRAPH REPRESENTATIONS ==========
const graphRepresentations = [
  { type: "Adjacency Matrix", space: "O(V²)", addEdge: "O(1)", removeEdge: "O(1)", checkEdge: "O(1)", pros: "Fast edge lookup, simple implementation", cons: "Wastes space for sparse graphs" },
  { type: "Adjacency List", space: "O(V+E)", addEdge: "O(1)", removeEdge: "O(E)", checkEdge: "O(V)", pros: "Space efficient for sparse graphs", cons: "Slower edge lookup" },
  { type: "Edge List", space: "O(E)", addEdge: "O(1)", removeEdge: "O(E)", checkEdge: "O(E)", pros: "Simple, good for edge-centric algorithms", cons: "Slow for most operations" },
];

// ========== BIT MANIPULATION ==========
const bitOperations = [
  { operation: "AND (&)", symbol: "&", description: "1 if both bits are 1", example: "5 & 3 = 1 (101 & 011 = 001)", useCase: "Check if bit is set, masking" },
  { operation: "OR (|)", symbol: "|", description: "1 if either bit is 1", example: "5 | 3 = 7 (101 | 011 = 111)", useCase: "Set a bit, combine flags" },
  { operation: "XOR (^)", symbol: "^", description: "1 if bits are different", example: "5 ^ 3 = 6 (101 ^ 011 = 110)", useCase: "Toggle bit, find unique element" },
  { operation: "NOT (~)", symbol: "~", description: "Flip all bits", example: "~5 = -6 (inverts all bits)", useCase: "Invert mask" },
  { operation: "Left Shift (<<)", symbol: "<<", description: "Shift bits left, fill with 0", example: "5 << 1 = 10 (101 → 1010)", useCase: "Multiply by 2^n" },
  { operation: "Right Shift (>>)", symbol: ">>", description: "Shift bits right", example: "5 >> 1 = 2 (101 → 10)", useCase: "Divide by 2^n" },
];

// ========== COMMON BIT TRICKS ==========
const bitTricks = [
  { trick: "Check if even", code: "(n & 1) == 0", explanation: "Last bit is 0 for even numbers" },
  { trick: "Check if power of 2", code: "n > 0 && (n & (n-1)) == 0", explanation: "Powers of 2 have exactly one bit set" },
  { trick: "Get i-th bit", code: "(n >> i) & 1", explanation: "Shift bit to position 0, then AND with 1" },
  { trick: "Set i-th bit", code: "n | (1 << i)", explanation: "OR with 1 shifted to position i" },
  { trick: "Clear i-th bit", code: "n & ~(1 << i)", explanation: "AND with inverted mask" },
  { trick: "Toggle i-th bit", code: "n ^ (1 << i)", explanation: "XOR with 1 shifted to position i" },
  { trick: "Count set bits", code: "while(n) { count++; n &= n-1; }", explanation: "Brian Kernighan's algorithm" },
  { trick: "Swap without temp", code: "a^=b; b^=a; a^=b;", explanation: "XOR swap trick" },
];

// ========== COMPLEXITY CLASSES ==========
const complexityClasses = [
  { class: "P", description: "Problems solvable in polynomial time", examples: "Sorting, searching, shortest path", decidable: "Yes" },
  { class: "NP", description: "Solutions verifiable in polynomial time", examples: "Sudoku, traveling salesman (verify)", decidable: "Yes" },
  { class: "NP-Complete", description: "Hardest problems in NP", examples: "SAT, Hamiltonian path, subset sum", decidable: "Yes" },
  { class: "NP-Hard", description: "At least as hard as NP-Complete", examples: "Halting problem, optimization versions", decidable: "Maybe" },
];

// ========== STRING ALGORITHMS ==========
const stringAlgorithms = [
  { name: "Naive Pattern Match", complexity: "O(n*m)", description: "Check every position for pattern match", useCase: "Simple, small inputs" },
  { name: "KMP Algorithm", complexity: "O(n+m)", description: "Use failure function to skip comparisons", useCase: "Text search, no preprocessing overhead" },
  { name: "Rabin-Karp", complexity: "O(n+m) avg", description: "Rolling hash for pattern matching", useCase: "Multiple pattern search, plagiarism detection" },
  { name: "Boyer-Moore", complexity: "O(n/m) best", description: "Skip sections using bad character rule", useCase: "Text editors, grep" },
  { name: "Z-Algorithm", complexity: "O(n+m)", description: "Z-array for pattern matching", useCase: "Pattern matching, string analysis" },
];

// ========== MACHINE CODE CONCEPTS ==========
const machineCodeConcepts = [
  { concept: "Opcode", description: "The operation code that tells the CPU what instruction to perform (e.g., ADD, MOV, JMP)", example: "0x89 = MOV (x86)" },
  { concept: "Operand", description: "The data or address that the instruction operates on", example: "MOV EAX, 5 — '5' is the operand" },
  { concept: "Instruction", description: "Complete machine code command: opcode + operands encoded as bytes", example: "B8 05 00 00 00 = MOV EAX, 5" },
  { concept: "Word Size", description: "The natural unit of data for a processor (32-bit = 4 bytes, 64-bit = 8 bytes)", example: "64-bit CPU handles 8 bytes at once" },
  { concept: "Endianness", description: "Byte order in memory — Little-endian (LE) stores LSB first, Big-endian (BE) stores MSB first", example: "0x12345678 → 78 56 34 12 (LE)" },
  { concept: "Instruction Pointer", description: "Register (EIP/RIP) that holds the address of the next instruction to execute", example: "RIP increments after each instruction" },
];

const cpuRegistersX86 = [
  { register: "EAX/RAX", purpose: "Accumulator", description: "Used for arithmetic operations and function return values", bits: "32/64" },
  { register: "EBX/RBX", purpose: "Base", description: "General-purpose, often used as a base pointer for memory access", bits: "32/64" },
  { register: "ECX/RCX", purpose: "Counter", description: "Used for loop counters and shift/rotate operations", bits: "32/64" },
  { register: "EDX/RDX", purpose: "Data", description: "Used for I/O operations and multiplication/division overflow", bits: "32/64" },
  { register: "ESI/RSI", purpose: "Source Index", description: "Source pointer for string operations", bits: "32/64" },
  { register: "EDI/RDI", purpose: "Destination Index", description: "Destination pointer for string operations", bits: "32/64" },
  { register: "ESP/RSP", purpose: "Stack Pointer", description: "Points to top of the stack — critical for function calls", bits: "32/64" },
  { register: "EBP/RBP", purpose: "Base Pointer", description: "Points to base of current stack frame", bits: "32/64" },
  { register: "EIP/RIP", purpose: "Instruction Pointer", description: "Address of next instruction to execute — controls program flow", bits: "32/64" },
  { register: "EFLAGS/RFLAGS", purpose: "Flags", description: "Status flags (Zero, Carry, Sign, Overflow) set by operations", bits: "32/64" },
];

const commonInstructions = [
  { instruction: "MOV", category: "Data Transfer", description: "Copy data from source to destination", example: "MOV EAX, 10 ; EAX = 10" },
  { instruction: "PUSH/POP", category: "Stack", description: "Push value onto stack / Pop value from stack", example: "PUSH EAX ; Save EAX to stack" },
  { instruction: "ADD/SUB", category: "Arithmetic", description: "Add or subtract values", example: "ADD EAX, EBX ; EAX = EAX + EBX" },
  { instruction: "MUL/DIV", category: "Arithmetic", description: "Multiply or divide (uses EAX implicitly)", example: "MUL EBX ; EDX:EAX = EAX * EBX" },
  { instruction: "AND/OR/XOR", category: "Logical", description: "Bitwise logical operations", example: "XOR EAX, EAX ; Clear EAX (set to 0)" },
  { instruction: "CMP", category: "Comparison", description: "Compare two values (sets flags, doesn't store result)", example: "CMP EAX, 5 ; Compare EAX with 5" },
  { instruction: "JMP", category: "Control Flow", description: "Unconditional jump to address", example: "JMP 0x401000 ; Jump to address" },
  { instruction: "JE/JNE/JG/JL", category: "Control Flow", description: "Conditional jumps based on flags", example: "JE label ; Jump if equal (ZF=1)" },
  { instruction: "CALL/RET", category: "Functions", description: "Call function / Return from function", example: "CALL printf ; Call printf function" },
  { instruction: "NOP", category: "Misc", description: "No operation — does nothing, often used for alignment or shellcode", example: "NOP ; 0x90 in x86" },
  { instruction: "LEA", category: "Address", description: "Load effective address — calculates address without dereferencing", example: "LEA EAX, [EBX+4] ; EAX = EBX+4" },
  { instruction: "INT", category: "Interrupts", description: "Software interrupt — triggers system calls or handlers", example: "INT 0x80 ; Linux syscall" },
];

const instructionCycle = [
  { phase: "1. Fetch", description: "CPU reads the instruction from memory at the address in the Instruction Pointer (IP/EIP/RIP)" },
  { phase: "2. Decode", description: "CPU decodes the opcode to determine what operation to perform and identifies operands" },
  { phase: "3. Execute", description: "CPU performs the operation (arithmetic, memory access, jump, etc.)" },
  { phase: "4. Write Back", description: "Results are written back to registers or memory" },
  { phase: "5. Update IP", description: "Instruction Pointer is updated to point to the next instruction (unless a jump occurred)" },
];

const memorySegments = [
  { segment: "Text/Code (.text)", description: "Contains executable machine code instructions. Usually read-only to prevent self-modifying code.", permissions: "R-X" },
  { segment: "Data (.data)", description: "Initialized global and static variables with predefined values.", permissions: "RW-" },
  { segment: "BSS (.bss)", description: "Uninitialized global and static variables — zeroed at program start.", permissions: "RW-" },
  { segment: "Heap", description: "Dynamically allocated memory (malloc, new). Grows toward higher addresses.", permissions: "RW-" },
  { segment: "Stack", description: "Function call frames, local variables, return addresses. Grows toward lower addresses.", permissions: "RW-" },
];

const ACCENT_COLOR = "#8b5cf6";
const QUIZ_QUESTION_COUNT = 10;

const selectRandomQuestions = (questions: QuizQuestion[], count: number) =>
  [...questions].sort(() => Math.random() - 0.5).slice(0, count);

const quizQuestions: QuizQuestion[] = [
  {
    id: 1,
    topic: "Data Structures",
    question: "What is the typical time complexity of array index access?",
    options: ["O(1)", "O(log n)", "O(n)", "O(n log n)"],
    correctAnswer: 0,
    explanation: "Arrays provide constant-time access by index.",
  },
  {
    id: 2,
    topic: "Data Structures",
    question: "What is the time complexity of inserting at the head of a linked list?",
    options: ["O(1)", "O(log n)", "O(n)", "O(n^2)"],
    correctAnswer: 0,
    explanation: "Inserting at the head updates a few pointers, so it is O(1).",
  },
  {
    id: 3,
    topic: "Data Structures",
    question: "A stack follows which access pattern?",
    options: ["LIFO", "FIFO", "Random access", "Priority-based"],
    correctAnswer: 0,
    explanation: "Stacks are Last In, First Out (LIFO).",
  },
  {
    id: 4,
    topic: "Data Structures",
    question: "A queue follows which access pattern?",
    options: ["FIFO", "LIFO", "Random access", "Priority-based"],
    correctAnswer: 0,
    explanation: "Queues are First In, First Out (FIFO).",
  },
  {
    id: 5,
    topic: "Data Structures",
    question: "Average-case lookup in a hash table is typically:",
    options: ["O(1)", "O(log n)", "O(n)", "O(n log n)"],
    correctAnswer: 0,
    explanation: "With a good hash function, lookup is O(1) on average.",
  },
  {
    id: 6,
    topic: "Data Structures",
    question: "How many children can a binary tree node have at most?",
    options: ["2", "3", "4", "Unlimited"],
    correctAnswer: 0,
    explanation: "Binary trees allow up to two children per node.",
  },
  {
    id: 7,
    topic: "Data Structures",
    question: "What property defines a Binary Search Tree (BST)?",
    options: ["Left < Node < Right", "All nodes equal", "Left > Node > Right", "Random order"],
    correctAnswer: 0,
    explanation: "BSTs keep smaller values on the left and larger values on the right.",
  },
  {
    id: 8,
    topic: "Data Structures",
    question: "In a max-heap, the root node contains:",
    options: ["The largest value", "The smallest value", "A random value", "The median value"],
    correctAnswer: 0,
    explanation: "Max-heaps keep the largest value at the root.",
  },
  {
    id: 9,
    topic: "Data Structures",
    question: "Which representation is typically best for sparse graphs?",
    options: ["Adjacency list", "Adjacency matrix", "Incidence matrix", "Edge list only"],
    correctAnswer: 0,
    explanation: "Adjacency lists are memory-efficient for sparse graphs.",
  },
  {
    id: 10,
    topic: "Data Structures",
    question: "Tries are commonly used for:",
    options: ["Prefix search/autocomplete", "Sorting arrays", "Matrix multiplication", "Scheduling"],
    correctAnswer: 0,
    explanation: "Tries efficiently support prefix lookups.",
  },
  {
    id: 11,
    topic: "Big O",
    question: "O(1) describes:",
    options: ["Constant time", "Linear time", "Quadratic time", "Logarithmic time"],
    correctAnswer: 0,
    explanation: "O(1) means runtime does not depend on input size.",
  },
  {
    id: 12,
    topic: "Big O",
    question: "Binary search runs in:",
    options: ["O(log n)", "O(n)", "O(n log n)", "O(1)"],
    correctAnswer: 0,
    explanation: "Binary search halves the search space each step.",
  },
  {
    id: 13,
    topic: "Big O",
    question: "Linear search runs in:",
    options: ["O(n)", "O(log n)", "O(1)", "O(n log n)"],
    correctAnswer: 0,
    explanation: "Linear search checks each element in the worst case.",
  },
  {
    id: 14,
    topic: "Big O",
    question: "Which is typical for merge sort?",
    options: ["O(n log n)", "O(n^2)", "O(log n)", "O(1)"],
    correctAnswer: 0,
    explanation: "Merge sort runs in O(n log n) for all cases.",
  },
  {
    id: 15,
    topic: "Big O",
    question: "Nested loops over n items are typically:",
    options: ["O(n^2)", "O(n)", "O(log n)", "O(1)"],
    correctAnswer: 0,
    explanation: "Two nested loops usually yield O(n^2).",
  },
  {
    id: 16,
    topic: "Big O",
    question: "Generating all subsets of a set of size n is:",
    options: ["O(2^n)", "O(n^2)", "O(n log n)", "O(log n)"],
    correctAnswer: 0,
    explanation: "There are 2^n possible subsets.",
  },
  {
    id: 17,
    topic: "Big O",
    question: "Generating all permutations of n items is:",
    options: ["O(n!)", "O(2^n)", "O(n log n)", "O(n)"],
    correctAnswer: 0,
    explanation: "There are n! permutations of n items.",
  },
  {
    id: 18,
    topic: "Big O",
    question: "Big-O notation ignores:",
    options: ["Constants and lower-order terms", "Input size", "All runtime", "Worst-case only"],
    correctAnswer: 0,
    explanation: "Big-O focuses on growth rate, ignoring constants.",
  },
  {
    id: 19,
    topic: "Big O",
    question: "Worst-case complexity describes:",
    options: ["The maximum time for any input of size n", "The average time", "The minimum time", "The median time"],
    correctAnswer: 0,
    explanation: "Worst-case gives an upper bound for runtime.",
  },
  {
    id: 20,
    topic: "Big O",
    question: "A space-time tradeoff means:",
    options: ["Using more memory to reduce time", "Always using less memory", "Always faster code", "Always fewer lines"],
    correctAnswer: 0,
    explanation: "Often you can speed up at the cost of extra memory.",
  },
  {
    id: 21,
    topic: "Sorting",
    question: "Worst-case time complexity of bubble sort is:",
    options: ["O(n^2)", "O(n log n)", "O(n)", "O(log n)"],
    correctAnswer: 0,
    explanation: "Bubble sort compares and swaps across the array, O(n^2).",
  },
  {
    id: 22,
    topic: "Sorting",
    question: "Is merge sort stable?",
    options: ["Yes", "No", "Only on small arrays", "Only on large arrays"],
    correctAnswer: 0,
    explanation: "Merge sort can preserve the order of equal elements.",
  },
  {
    id: 23,
    topic: "Sorting",
    question: "Average time complexity of quick sort is:",
    options: ["O(n log n)", "O(n^2)", "O(n)", "O(log n)"],
    correctAnswer: 0,
    explanation: "Quick sort averages O(n log n) with good pivots.",
  },
  {
    id: 24,
    topic: "Sorting",
    question: "Worst-case time complexity of quick sort is:",
    options: ["O(n^2)", "O(n log n)", "O(n)", "O(log n)"],
    correctAnswer: 0,
    explanation: "Bad pivot choices can degrade quick sort to O(n^2).",
  },
  {
    id: 25,
    topic: "Sorting",
    question: "Which sort is often best for nearly sorted data?",
    options: ["Insertion sort", "Heap sort", "Quick sort", "Selection sort"],
    correctAnswer: 0,
    explanation: "Insertion sort performs well on nearly sorted inputs.",
  },
  {
    id: 26,
    topic: "Sorting",
    question: "Counting sort is best when:",
    options: ["Keys are small integers", "Data is already sorted", "Data is huge and random", "Memory is extremely limited"],
    correctAnswer: 0,
    explanation: "Counting sort depends on a small key range.",
  },
  {
    id: 27,
    topic: "Sorting",
    question: "Heap sort is based on which data structure?",
    options: ["Heap", "Stack", "Queue", "Trie"],
    correctAnswer: 0,
    explanation: "Heap sort uses a binary heap.",
  },
  {
    id: 28,
    topic: "Sorting",
    question: "Selection sort is generally:",
    options: ["Not stable", "Always stable", "O(n log n)", "Faster than quick sort"],
    correctAnswer: 0,
    explanation: "Selection sort can change the order of equal elements.",
  },
  {
    id: 29,
    topic: "Sorting",
    question: "Radix sort processes data by:",
    options: ["Digits or positions", "Comparing pairs", "Swapping randomly", "Hashing"],
    correctAnswer: 0,
    explanation: "Radix sort groups values by digit/position.",
  },
  {
    id: 30,
    topic: "Sorting",
    question: "A stable sort guarantees:",
    options: ["Equal elements keep original order", "Always O(n log n)", "Always O(1) space", "Fewer comparisons"],
    correctAnswer: 0,
    explanation: "Stability preserves ordering of equal keys.",
  },
  {
    id: 31,
    topic: "Searching",
    question: "Binary search requires the data to be:",
    options: ["Sorted", "Random", "Hashed", "Encrypted"],
    correctAnswer: 0,
    explanation: "Binary search only works on sorted data.",
  },
  {
    id: 32,
    topic: "Searching",
    question: "Which data structure is used by BFS?",
    options: ["Queue", "Stack", "Heap", "Trie"],
    correctAnswer: 0,
    explanation: "BFS explores level by level using a queue.",
  },
  {
    id: 33,
    topic: "Searching",
    question: "Which data structure is used by DFS?",
    options: ["Stack (or recursion)", "Queue", "Heap", "Hash table"],
    correctAnswer: 0,
    explanation: "DFS uses a stack or recursion.",
  },
  {
    id: 34,
    topic: "Searching",
    question: "BFS finds the shortest path in:",
    options: ["Unweighted graphs", "Weighted graphs with negatives", "Trees only", "All graphs"],
    correctAnswer: 0,
    explanation: "BFS finds shortest paths in unweighted graphs.",
  },
  {
    id: 35,
    topic: "Searching",
    question: "Which algorithm finds shortest paths with non-negative weights?",
    options: ["Dijkstra's algorithm", "BFS", "DFS", "Bellman-Ford only"],
    correctAnswer: 0,
    explanation: "Dijkstra's works for non-negative edge weights.",
  },
  {
    id: 36,
    topic: "Searching",
    question: "BFS time complexity on a graph is:",
    options: ["O(V+E)", "O(V^2)", "O(E log V)", "O(log V)"],
    correctAnswer: 0,
    explanation: "BFS visits each vertex and edge once.",
  },
  {
    id: 37,
    topic: "Searching",
    question: "A hash collision happens when:",
    options: ["Two keys map to the same slot", "The table is empty", "Keys are sorted", "A lookup is O(1)"],
    correctAnswer: 0,
    explanation: "Different keys can hash to the same index.",
  },
  {
    id: 38,
    topic: "Searching",
    question: "Adjacency matrices are most efficient for:",
    options: ["Dense graphs", "Sparse graphs", "Trees only", "Unweighted graphs only"],
    correctAnswer: 0,
    explanation: "Matrices use O(V^2) space, best for dense graphs.",
  },
  {
    id: 39,
    topic: "Searching",
    question: "DAG stands for:",
    options: ["Directed Acyclic Graph", "Directed Array Graph", "Dynamic Adjacency Graph", "Data Access Graph"],
    correctAnswer: 0,
    explanation: "A DAG is a Directed Acyclic Graph.",
  },
  {
    id: 40,
    topic: "Searching",
    question: "Topological sort applies to:",
    options: ["DAGs", "Cyclic graphs", "All trees", "Hash tables"],
    correctAnswer: 0,
    explanation: "Topological ordering is defined for DAGs.",
  },
  {
    id: 41,
    topic: "Paradigms",
    question: "Imperative programming focuses on:",
    options: ["Changing program state with statements", "Pure functions only", "Declarative rules only", "Event streams only"],
    correctAnswer: 0,
    explanation: "Imperative code uses statements that update state.",
  },
  {
    id: 42,
    topic: "Paradigms",
    question: "Functional programming emphasizes:",
    options: ["Pure functions and immutability", "Shared mutable state", "Global variables", "Side effects"],
    correctAnswer: 0,
    explanation: "Functional programming prefers pure functions and immutable data.",
  },
  {
    id: 43,
    topic: "Paradigms",
    question: "Declarative programming focuses on:",
    options: ["What to do, not how", "Step-by-step execution", "Manual memory management", "Thread scheduling"],
    correctAnswer: 0,
    explanation: "Declarative code describes the desired result.",
  },
  {
    id: 44,
    topic: "OOP",
    question: "Encapsulation means:",
    options: ["Bundling data and methods, hiding internals", "Copying code", "Using global variables", "Only inheritance"],
    correctAnswer: 0,
    explanation: "Encapsulation hides internal state behind an interface.",
  },
  {
    id: 45,
    topic: "OOP",
    question: "Polymorphism allows:",
    options: ["One interface, multiple implementations", "Only one implementation", "No inheritance", "Only static methods"],
    correctAnswer: 0,
    explanation: "Polymorphism enables different behaviors behind a common interface.",
  },
  {
    id: 46,
    topic: "OOP",
    question: "Inheritance primarily provides:",
    options: ["Code reuse via parent classes", "Faster algorithms", "Stronger encryption", "Lower memory usage always"],
    correctAnswer: 0,
    explanation: "Inheritance reuses behavior from a base class.",
  },
  {
    id: 47,
    topic: "OOP",
    question: "Abstraction means:",
    options: ["Hiding complexity behind simpler interfaces", "Duplicating code", "Avoiding functions", "Using global state"],
    correctAnswer: 0,
    explanation: "Abstraction shows essentials and hides details.",
  },
  {
    id: 48,
    topic: "Paradigms",
    question: "Event-driven programming reacts to:",
    options: ["Events and callbacks", "Only loops", "Only recursion", "Only compile-time rules"],
    correctAnswer: 0,
    explanation: "Event-driven systems respond to events like clicks or messages.",
  },
  {
    id: 49,
    topic: "Design",
    question: "Composition over inheritance suggests:",
    options: ["Build behavior by combining objects", "Always use inheritance", "Avoid interfaces", "Use globals instead"],
    correctAnswer: 0,
    explanation: "Composition provides flexibility by assembling behaviors.",
  },
  {
    id: 50,
    topic: "Algorithms",
    question: "Recursion requires a:",
    options: ["Base case", "Global variable", "Shared pointer", "Mutex"],
    correctAnswer: 0,
    explanation: "A base case prevents infinite recursion.",
  },
  {
    id: 51,
    topic: "SOLID",
    question: "Single Responsibility Principle means:",
    options: ["One reason to change", "One class per file", "One method per class", "One variable per function"],
    correctAnswer: 0,
    explanation: "SRP: a class should have a single responsibility.",
  },
  {
    id: 52,
    topic: "SOLID",
    question: "Open/Closed Principle means:",
    options: ["Open for extension, closed for modification", "Closed source only", "Open classes only", "No inheritance"],
    correctAnswer: 0,
    explanation: "You should extend behavior without changing existing code.",
  },
  {
    id: 53,
    topic: "SOLID",
    question: "Liskov Substitution Principle means:",
    options: ["Subtypes must be substitutable for base types", "No inheritance allowed", "Only interfaces", "Only static methods"],
    correctAnswer: 0,
    explanation: "Derived classes should be usable anywhere their base class is expected.",
  },
  {
    id: 54,
    topic: "SOLID",
    question: "Interface Segregation Principle suggests:",
    options: ["Many small interfaces", "One huge interface", "No interfaces", "Only abstract classes"],
    correctAnswer: 0,
    explanation: "Clients should not depend on methods they do not use.",
  },
  {
    id: 55,
    topic: "SOLID",
    question: "Dependency Inversion Principle suggests:",
    options: ["Depend on abstractions, not concretions", "Depend on concrete classes", "Avoid interfaces", "Use globals"],
    correctAnswer: 0,
    explanation: "High-level modules should depend on abstractions.",
  },
  {
    id: 56,
    topic: "Design",
    question: "High cohesion means:",
    options: ["Related responsibilities grouped together", "Unrelated responsibilities mixed", "No responsibilities", "Only static data"],
    correctAnswer: 0,
    explanation: "High cohesion keeps related functionality together.",
  },
  {
    id: 57,
    topic: "Design",
    question: "Low coupling is desirable because it:",
    options: ["Reduces ripple effects of changes", "Increases dependencies", "Forces tight integration", "Slows development"],
    correctAnswer: 0,
    explanation: "Low coupling makes modules easier to change independently.",
  },
  {
    id: 58,
    topic: "Design",
    question: "DRY stands for:",
    options: ["Don't Repeat Yourself", "Do Repeat Yourself", "Dynamic Runtime Yield", "Data Run Yield"],
    correctAnswer: 0,
    explanation: "DRY encourages avoiding duplicated logic.",
  },
  {
    id: 59,
    topic: "Design",
    question: "YAGNI stands for:",
    options: ["You Aren't Gonna Need It", "You Always Get New Ideas", "Your API Grows Naturally", "Yield And Go Next Iteration"],
    correctAnswer: 0,
    explanation: "YAGNI encourages avoiding unnecessary features.",
  },
  {
    id: 60,
    topic: "Design",
    question: "KISS stands for:",
    options: ["Keep It Simple, Stupid", "Keep It Secure, Stable", "Kernel Is Super Simple", "Known Interface System Standard"],
    correctAnswer: 0,
    explanation: "KISS encourages simplicity in design.",
  },
  {
    id: 61,
    topic: "Algorithms",
    question: "Merge sort is an example of:",
    options: ["Divide and conquer", "Greedy", "Dynamic programming", "Backtracking"],
    correctAnswer: 0,
    explanation: "Merge sort splits and merges subproblems.",
  },
  {
    id: 62,
    topic: "Algorithms",
    question: "Dynamic programming is best for problems with:",
    options: ["Overlapping subproblems", "No subproblems", "Only randomness", "Only sorting"],
    correctAnswer: 0,
    explanation: "DP reuses results from overlapping subproblems.",
  },
  {
    id: 63,
    topic: "Algorithms",
    question: "A greedy algorithm chooses:",
    options: ["The locally optimal choice each step", "The worst choice each step", "Only random choices", "All choices at once"],
    correctAnswer: 0,
    explanation: "Greedy algorithms pick locally optimal options.",
  },
  {
    id: 64,
    topic: "Algorithms",
    question: "Memoization is:",
    options: ["Caching results of function calls", "Sorting data", "Encrypting data", "Removing recursion"],
    correctAnswer: 0,
    explanation: "Memoization stores results to avoid duplicate work.",
  },
  {
    id: 65,
    topic: "Algorithms",
    question: "Backtracking is commonly used for:",
    options: ["Constraint satisfaction problems", "Sorting arrays", "Hashing data", "Streaming video"],
    correctAnswer: 0,
    explanation: "Backtracking explores and undoes choices to satisfy constraints.",
  },
  {
    id: 66,
    topic: "Systems",
    question: "RAM is:",
    options: ["Volatile memory", "Non-volatile storage", "Permanent storage", "A CPU register"],
    correctAnswer: 0,
    explanation: "RAM loses its contents when power is removed.",
  },
  {
    id: 67,
    topic: "Systems",
    question: "CPU cache is typically:",
    options: ["Faster than RAM", "Slower than RAM", "On disk", "A replacement for SSD"],
    correctAnswer: 0,
    explanation: "Cache is small and very fast to reduce memory latency.",
  },
  {
    id: 68,
    topic: "Systems",
    question: "The call stack is used for:",
    options: ["Function call frames", "Long-term storage", "Network packets", "File permissions"],
    correctAnswer: 0,
    explanation: "The stack stores function call data and local variables.",
  },
  {
    id: 69,
    topic: "Systems",
    question: "The heap is used for:",
    options: ["Dynamic memory allocation", "CPU scheduling", "Instruction decoding", "Networking"],
    correctAnswer: 0,
    explanation: "The heap holds dynamically allocated memory.",
  },
  {
    id: 70,
    topic: "Systems",
    question: "CPU registers are:",
    options: ["Small, fast storage inside the CPU", "Large disk-based storage", "Network buffers", "Swap space"],
    correctAnswer: 0,
    explanation: "Registers are the fastest storage close to execution units.",
  },
  {
    id: 71,
    topic: "Systems",
    question: "A context switch is:",
    options: ["Switching CPU from one process/thread to another", "Allocating more RAM", "Compiling code", "Resolving DNS"],
    correctAnswer: 0,
    explanation: "Context switching swaps CPU execution between tasks.",
  },
  {
    id: 72,
    topic: "Systems",
    question: "Concurrency differs from parallelism because concurrency:",
    options: ["Manages multiple tasks at once, not necessarily simultaneously", "Always uses multiple CPUs", "Is always faster", "Requires GPU"],
    correctAnswer: 0,
    explanation: "Concurrency is about structuring tasks; parallelism is simultaneous execution.",
  },
  {
    id: 73,
    topic: "Systems",
    question: "Which is required for a deadlock?",
    options: ["Circular wait", "Stateless functions", "Immutable data", "Binary search"],
    correctAnswer: 0,
    explanation: "Deadlock requires circular wait among other conditions.",
  },
  {
    id: 74,
    topic: "Systems",
    question: "How many bits are in a byte?",
    options: ["8", "4", "16", "32"],
    correctAnswer: 0,
    explanation: "A byte contains 8 bits.",
  },
  {
    id: 75,
    topic: "Systems",
    question: "A compiler generally:",
    options: ["Translates source code to machine code before execution", "Runs code line by line without output", "Only checks syntax", "Only debugs programs"],
    correctAnswer: 0,
    explanation: "Compilers produce executable code ahead of time.",
  },
];

const ComputerScienceFundamentalsPage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const accent = "#8b5cf6";
  const [quizPool] = useState<QuizQuestion[]>(() =>
    selectRandomQuestions(quizQuestions, QUIZ_QUESTION_COUNT)
  );

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const sectionNavItems = [
    { id: "intro", label: "Introduction", icon: <InfoIcon /> },
    { id: "big-o", label: "Big O Notation", icon: <SpeedIcon /> },
    { id: "data-structures", label: "Data Structures", icon: <DataArrayIcon /> },
    { id: "sorting", label: "Sorting Algorithms", icon: <TimelineIcon /> },
    { id: "searching", label: "Searching Algorithms", icon: <AccountTreeIcon /> },
    { id: "paradigms", label: "Programming Paradigms", icon: <CodeIcon /> },
    { id: "oop", label: "OOP Principles", icon: <CategoryIcon /> },
    { id: "solid", label: "SOLID Principles", icon: <LayersIcon /> },
    { id: "patterns", label: "Design Patterns", icon: <BuildIcon /> },
    { id: "memory", label: "Memory Management", icon: <MemoryIcon /> },
    { id: "os", label: "Operating Systems", icon: <ComputerIcon /> },
    { id: "concurrency", label: "Concurrency", icon: <SpeedIcon /> },
    { id: "networking", label: "Networking", icon: <HubIcon /> },
    { id: "databases", label: "Databases", icon: <StorageIcon /> },
    { id: "machine-code", label: "Machine Code", icon: <MemoryIcon /> },
    { id: "recursion", label: "Recursion", icon: <FunctionsIcon /> },
    { id: "trees", label: "Trees & Traversal", icon: <AccountTreeIcon /> },
    { id: "graphs", label: "Graph Algorithms", icon: <HubIcon /> },
    { id: "bits", label: "Bit Operations", icon: <ComputerIcon /> },
    { id: "strings", label: "String Algorithms", icon: <StorageIcon /> },
    { id: "complexity", label: "P vs NP", icon: <PsychologyIcon /> },
    { id: "quiz", label: "Quiz", icon: <QuizIcon /> },
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
      const sections = sectionNavItems.map((item) => item.id);
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

  const currentIndex = sectionNavItems.findIndex((item) => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / sectionNavItems.length) * 100 : 0;

  const pageContext = `Computer Science Fundamentals learning page - Essential CS concepts for developers and security professionals. Covers data structures (arrays, linked lists, trees, graphs, hash tables), algorithms (sorting, searching, Big O notation), programming paradigms (OOP, functional, procedural), SOLID principles, design patterns, memory management, operating systems, concurrency, networking, databases, and number systems. Foundation knowledge for software development, coding interviews, and understanding system internals.`;

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
        "&::-webkit-scrollbar": {
          width: 6,
        },
        "&::-webkit-scrollbar-thumb": {
          bgcolor: alpha(accent, 0.3),
          borderRadius: 3,
        },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography
          variant="subtitle2"
          sx={{ fontWeight: 700, mb: 1, color: accent, display: "flex", alignItems: "center", gap: 1 }}
        >
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">
              Progress
            </Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>
              {Math.round(progressPercent)}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha(accent, 0.1),
              "& .MuiLinearProgress-bar": {
                bgcolor: accent,
                borderRadius: 3,
              },
            }}
          />
        </Box>
        <Divider sx={{ mb: 1 }} />
        <List dense sx={{ mx: -1 }}>
          {sectionNavItems.map((item) => (
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
                "&:hover": {
                  bgcolor: alpha(accent, 0.08),
                },
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
    <LearnPageLayout pageTitle="Computer Science Fundamentals" pageContext={pageContext}>
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
            bgcolor: accent,
            "&:hover": { bgcolor: "#7c3aed" },
            boxShadow: `0 4px 20px ${alpha(accent, 0.4)}`,
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
            bgcolor: alpha(accent, 0.15),
            color: accent,
            "&:hover": { bgcolor: alpha(accent, 0.25) },
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
              <ListAltIcon sx={{ color: accent }} />
              Course Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} size="small">
              <CloseIcon />
            </IconButton>
          </Box>

          <Divider sx={{ mb: 2 }} />

          {/* Progress indicator */}
          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha(accent, 0.05) }}>
            <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">
                Progress
              </Typography>
              <Typography variant="caption" sx={{ fontWeight: 600, color: accent }}>
                {Math.round(progressPercent)}%
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progressPercent}
              sx={{
                height: 6,
                borderRadius: 3,
                bgcolor: alpha(accent, 0.1),
                "& .MuiLinearProgress-bar": {
                  bgcolor: accent,
                  borderRadius: 3,
                },
              }}
            />
          </Box>

          {/* Navigation List */}
          <List dense sx={{ mx: -1 }}>
            {sectionNavItems.map((item) => (
              <ListItem
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                sx={{
                  borderRadius: 2,
                  mb: 0.5,
                  cursor: "pointer",
                  bgcolor: activeSection === item.id ? alpha(accent, 0.15) : "transparent",
                  borderLeft: activeSection === item.id ? `3px solid ${accent}` : "3px solid transparent",
                  "&:hover": {
                    bgcolor: alpha(accent, 0.1),
                  },
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
                  <Chip
                    label="Current"
                    size="small"
                    sx={{
                      height: 20,
                      fontSize: "0.65rem",
                      bgcolor: alpha(accent, 0.2),
                      color: accent,
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
              sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}
            >
              Top
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => scrollToSection("quiz")}
              startIcon={<QuizIcon />}
              sx={{ flex: 1, borderColor: alpha(accent, 0.3), color: accent }}
            >
              Quiz
            </Button>
          </Box>
        </Box>
      </Drawer>

      {/* Main Layout with Sidebar */}
      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, sm: 3 }, py: 4 }}>
        {sidebarNav}

        <Box sx={{ flex: 1, minWidth: 0 }}>
          {/* Back Button */}
          <Chip
            component={Link}
            to="/learn"
            icon={<ArrowBackIcon />}
            label="Back to Learning Hub"
            clickable
            variant="outlined"
            sx={{ borderRadius: 2, mb: 3 }}
          />

        {/* Hero Banner */}
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.15)} 0%, ${alpha("#6366f1", 0.1)} 100%)`,
            border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
            position: "relative",
            overflow: "hidden",
          }}
        >
          <Box
            sx={{
              position: "absolute",
              top: -50,
              right: -50,
              width: 200,
              height: 200,
              borderRadius: "50%",
              background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.1)}, transparent)`,
            }}
          />
          <Box sx={{ display: "flex", alignItems: "center", gap: 3, position: "relative" }}>
            <Box
              sx={{
                width: 80,
                height: 80,
                borderRadius: 3,
                background: `linear-gradient(135deg, #8b5cf6, #6366f1)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                boxShadow: `0 8px 32px ${alpha("#8b5cf6", 0.3)}`,
              }}
            >
              <SchoolIcon sx={{ fontSize: 45, color: "white" }} />
            </Box>
            <Box>
              <Chip label="IT Fundamentals" size="small" sx={{ mb: 1, fontWeight: 600, bgcolor: alpha("#8b5cf6", 0.1), color: "#8b5cf6" }} />
              <Typography variant="h3" sx={{ fontWeight: 800, mb: 1 }}>
                Computer Science Fundamentals
              </Typography>
              <Typography variant="h6" color="text.secondary" sx={{ maxWidth: 600 }}>
                Core concepts every developer and security professional should know
              </Typography>
            </Box>
          </Box>
        </Paper>

        {/* Quick Navigation */}
        <Paper
          sx={{
            p: 2,
            mb: 4,
            borderRadius: 3,
            position: { xs: "static", md: "sticky" },
            top: { md: 16, xs: "auto" },
            zIndex: 10,
            bgcolor: alpha(theme.palette.background.paper, 0.95),
            backdropFilter: "blur(8px)",
            border: `1px solid ${alpha(theme.palette.divider, 0.15)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mr: 1 }}>
              📍 Jump to:
            </Typography>
            {[
              { id: "intro", label: "Introduction" },
              { id: "big-o", label: "Big O" },
              { id: "data-structures", label: "Data Structures" },
              { id: "sorting", label: "Sorting" },
              { id: "searching", label: "Searching" },
              { id: "paradigms", label: "Paradigms" },
              { id: "oop", label: "OOP" },
              { id: "solid", label: "SOLID" },
              { id: "patterns", label: "Patterns" },
              { id: "memory", label: "Memory" },
              { id: "os", label: "Operating Systems" },
              { id: "concurrency", label: "Concurrency" },
              { id: "networking", label: "Networking" },
              { id: "databases", label: "Databases" },
              { id: "machine-code", label: "Machine Code" },
              { id: "recursion", label: "Recursion" },
              { id: "trees", label: "Trees" },
              { id: "graphs", label: "Graphs" },
              { id: "bits", label: "Bit Ops" },
              { id: "strings", label: "Strings" },
              { id: "complexity", label: "P vs NP" },
            ].map((section) => (
              <Chip
                key={section.id}
                label={section.label}
                component="a"
                href={`#${section.id}`}
                clickable
                size="small"
                sx={{
                  textDecoration: "none",
                  bgcolor: alpha("#8b5cf6", 0.08),
                  color: "#8b5cf6",
                  fontWeight: 600,
                  "&:hover": { bgcolor: alpha("#8b5cf6", 0.18) },
                }}
              />
            ))}
          </Box>
        </Paper>

        {/* Detailed Introduction - What is Computer Science? */}
        <Paper
          id="intro"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            scrollMarginTop: 80,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
            <InfoIcon sx={{ color: "#8b5cf6" }} />
            What is Computer Science?
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            <strong>Computer Science</strong> is the study of computers and computational systems. Unlike electrical engineering, 
            which focuses on hardware, computer science primarily deals with <em>software</em> — the programs and systems that 
            make computers useful. Think of it this way: if a computer is a car, computer science teaches you how to design 
            the engine's logic, plan the most efficient routes, and create the dashboard interface — not how to build the 
            physical parts.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            At its core, computer science is about <strong>problem-solving</strong>. You learn how to take a complex problem, 
            break it down into smaller pieces, and create step-by-step instructions (called <em>algorithms</em>) for a computer 
            to solve it. These solutions need to be <em>efficient</em> — using the least amount of time and memory possible — 
            which is why understanding concepts like Big O notation and data structures is so important.
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.1)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
              <LightbulbIcon sx={{ color: "#8b5cf6" }} />
              A Simple Analogy
            </Typography>
            <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
              Imagine you're organizing a library. <strong>Data structures</strong> are like the different ways you could organize 
              the books — alphabetically on shelves, in numbered boxes, or using a card catalog system. Each method has trade-offs: 
              alphabetical makes finding a specific book fast, but adding new books requires shifting everything. 
              <strong>Algorithms</strong> are the step-by-step processes you'd follow, like "to find a book, first check the catalog, 
              then go to row 3, shelf 2." Computer science teaches you which organizational method and process works best for 
              different situations.
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <PsychologyIcon sx={{ color: "#6366f1" }} />
            Key Areas of Computer Science
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, height: "100%", borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.2)}`, bgcolor: alpha("#22c55e", 0.03) }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>🧱 Data Structures</Typography>
                <Typography variant="body2" color="text.secondary">
                  Ways to organize and store data. Like choosing between a filing cabinet (organized but slow to add), 
                  a pile (fast to add but slow to find), or a phonebook (great for lookups). Each structure — arrays, 
                  linked lists, trees, hash tables — excels in different scenarios.
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, height: "100%", borderRadius: 2, border: `1px solid ${alpha("#0ea5e9", 0.2)}`, bgcolor: alpha("#0ea5e9", 0.03) }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#0ea5e9", mb: 1 }}>⚡ Algorithms</Typography>
                <Typography variant="body2" color="text.secondary">
                  Step-by-step procedures for solving problems. Like a recipe for cooking, an algorithm tells the computer 
                  exactly what to do. Sorting algorithms arrange data, searching algorithms find items, and graph algorithms 
                  navigate networks.
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, height: "100%", borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.2)}`, bgcolor: alpha("#f59e0b", 0.03) }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>🏗️ Software Design</Typography>
                <Typography variant="body2" color="text.secondary">
                  How to structure code so it's maintainable, reusable, and scalable. Object-Oriented Programming (OOP), 
                  SOLID principles, and Design Patterns are proven approaches developed over decades to write better software.
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, height: "100%", borderRadius: 2, border: `1px solid ${alpha("#ec4899", 0.2)}`, bgcolor: alpha("#ec4899", 0.03) }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ec4899", mb: 1 }}>🔧 Systems & Theory</Typography>
                <Typography variant="body2" color="text.secondary">
                  How computers actually work at a lower level — memory management, how CPUs execute instructions, 
                  number systems (binary, hexadecimal), and computational theory. This knowledge helps you write efficient 
                  code and debug tricky issues.
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <BuildIcon sx={{ color: "#ef4444" }} />
            Why It Matters for Security Professionals
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            For cybersecurity professionals, CS fundamentals aren't just academic — they're essential tools:
          </Typography>

          <List dense sx={{ mb: 3 }}>
            <ListItem>
              <ListItemIcon><CheckCircleOutlineIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
              <ListItemText 
                primary="Understanding vulnerabilities" 
                secondary="Buffer overflows, race conditions, and memory corruption all require understanding how data structures and memory work"
              />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleOutlineIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
              <ListItemText 
                primary="Reverse engineering malware" 
                secondary="Analyzing malicious code requires understanding algorithms, data structures, and how programs execute"
              />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleOutlineIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
              <ListItemText 
                primary="Building security tools" 
                secondary="Writing scanners, fuzzers, and analysis tools requires choosing the right data structures for performance"
              />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleOutlineIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
              <ListItemText 
                primary="Cryptography" 
                secondary="Understanding encryption algorithms, hash functions, and number theory is fundamental to security"
              />
            </ListItem>
          </List>

          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>💡 Learning Tip</AlertTitle>
            <Typography variant="body2">
              Don't try to memorize everything at once. Focus on understanding the <em>concepts</em> and <em>trade-offs</em>. 
              When you encounter a new data structure, ask: "When would I use this? What's it good at? What's it bad at?" 
              This approach builds intuition that helps you apply knowledge to real problems.
            </Typography>
          </Alert>

          <Divider sx={{ my: 4 }} />

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>📚 What You'll Learn on This Page</AlertTitle>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6} md={3}>
                <Typography variant="body2">• Big O Notation</Typography>
                <Typography variant="body2">• Data Structures</Typography>
                <Typography variant="body2">• Arrays & Linked Lists</Typography>
                <Typography variant="body2">• Trees & Graphs</Typography>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Typography variant="body2">• Sorting Algorithms</Typography>
                <Typography variant="body2">• Searching Algorithms</Typography>
                <Typography variant="body2">• Algorithm Complexity</Typography>
                <Typography variant="body2">• Space vs Time Trade-offs</Typography>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Typography variant="body2">• OOP Principles</Typography>
                <Typography variant="body2">• SOLID Principles</Typography>
                <Typography variant="body2">• Design Patterns</Typography>
                <Typography variant="body2">• Programming Paradigms</Typography>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Typography variant="body2">• Memory Management</Typography>
                <Typography variant="body2">• Stack vs Heap</Typography>
                <Typography variant="body2">• Number Systems</Typography>
                <Typography variant="body2">• Binary & Hexadecimal</Typography>
              </Grid>
            </Grid>
          </Alert>
        </Paper>

        {/* Big O Notation */}
        <Typography id="big-o" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          ⏱️ Big O Notation
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Understanding algorithm efficiency and time complexity
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <SpeedIcon sx={{ color: "#f59e0b" }} />
            What is Big O Notation?
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            <strong>Big O notation</strong> is a mathematical notation that describes the limiting behavior of a function when the argument 
            tends towards a particular value or infinity. In computer science, it's used to classify algorithms according to how their 
            run time or space requirements grow as the input size grows. When we say an algorithm is O(n), we mean its running time 
            grows linearly with the input size — double the input, double the time.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Big O describes the <strong>worst-case scenario</strong> and focuses on the dominant term (the part that grows fastest). 
            We drop constants and lower-order terms because they become irrelevant as n approaches infinity. For example, if an 
            algorithm takes 3n² + 5n + 100 steps, we say it's O(n²) because the n² term dominates as n gets large. Whether it's 
            3n² or 1000n², it's still O(n²) — the shape of the growth curve matters more than the exact coefficients.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Understanding Big O is crucial for writing efficient code. An O(n²) algorithm might work fine for 100 elements but become 
            unusable with 1,000,000 elements. Consider: O(n) with n=1,000,000 means ~1 million operations. O(n²) means ~1 trillion operations. 
            At 1 billion operations per second, that's the difference between 0.001 seconds and 16+ minutes.
          </Typography>

          <Alert severity="info" sx={{ borderRadius: 2, mb: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>💡 Practical Tip</AlertTitle>
            <Typography variant="body2">
              In interviews and real-world code reviews, you'll often be asked "What's the time complexity?" Being able to quickly 
              identify Big O shows you understand scalability. Always ask: "How does this behave with 10x or 100x more data?"
            </Typography>
          </Alert>

          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.1), border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Time Complexity</Typography>
                <Typography variant="body2" color="text.secondary">
                  How runtime grows with input size. Most commonly analyzed. Usually what people mean by "Big O."
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#0ea5e9", 0.1), border: `1px solid ${alpha("#0ea5e9", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#0ea5e9", mb: 1 }}>Space Complexity</Typography>
                <Typography variant="body2" color="text.secondary">
                  How memory usage grows with input size. Important for memory-constrained environments.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.1), border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>Amortized Analysis</Typography>
                <Typography variant="body2" color="text.secondary">
                  Average time per operation over a sequence. Used when occasional operations are expensive but rare.
                </Typography>
              </Box>
            </Grid>
          </Grid>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {bigOComplexities.map((complexity) => (
            <Grid item xs={12} sm={6} md={3} key={complexity.notation}>
              <Paper
                sx={{
                  p: 2,
                  borderRadius: 2,
                  border: `2px solid ${alpha(complexity.color, 0.3)}`,
                  bgcolor: alpha(complexity.color, 0.05),
                  height: "100%",
                }}
              >
                <Typography variant="h5" sx={{ fontFamily: "monospace", fontWeight: 800, color: complexity.color, mb: 0.5 }}>
                  {complexity.notation}
                </Typography>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>{complexity.name}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.8rem", mb: 1 }}>
                  {complexity.description}
                </Typography>
                <Typography variant="caption" sx={{ fontStyle: "italic" }}>
                  Ex: {complexity.example}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Data Structures */}
        <Typography id="data-structures" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          📊 Data Structures
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Fundamental ways to organize and store data
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <DataArrayIcon sx={{ color: "#8b5cf6" }} />
            Understanding Data Structures
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            A <strong>data structure</strong> is a particular way of organizing data in a computer so that it can be used efficiently. 
            Different data structures are suited for different kinds of applications, and some are highly specialized for specific tasks. 
            Choosing the right data structure can be the difference between an algorithm running in milliseconds versus hours.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Data structures can be broadly categorized into <strong>linear</strong> (elements arranged sequentially — arrays, linked lists, 
            stacks, queues) and <strong>non-linear</strong> (elements not in sequence — trees, graphs, hash tables). Linear structures are 
            simpler but may not be efficient for certain operations. Non-linear structures offer faster operations for specific use cases 
            but are more complex to implement and understand.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            The key trade-offs to consider when choosing a data structure are: <strong>Time complexity</strong> (how fast are operations?), 
            <strong>Space complexity</strong> (how much memory is used?), <strong>Ease of implementation</strong> (how complex is the code?), 
            and <strong>Cache performance</strong> (how well does it work with CPU caches?). For example, arrays have excellent cache locality 
            because elements are stored contiguously in memory, while linked lists have poor cache performance because nodes are scattered.
          </Typography>

          <Grid container spacing={2} sx={{ mb: 2 }}>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.1) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>🔢 Arrays</Typography>
                <Typography variant="body2" color="text.secondary">
                  Contiguous memory, O(1) access by index, but O(n) insertion/deletion in the middle. Best when you know the size upfront
                  and need fast random access. Most cache-friendly structure.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#0ea5e9", 0.1) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#0ea5e9", mb: 1 }}>🔗 Linked Lists</Typography>
                <Typography variant="body2" color="text.secondary">
                  Non-contiguous nodes with pointers, O(1) insertion/deletion (if you have the node), but O(n) access. Good for frequent 
                  insertions/deletions and unknown sizes.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.1) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>#️⃣ Hash Tables</Typography>
                <Typography variant="body2" color="text.secondary">
                  Key-value storage with O(1) average-case operations using hash functions. The workhorse of modern programming — 
                  dictionaries, sets, caches, and objects in many languages.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ec4899", 0.1) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ec4899", mb: 1 }}>🌳 Trees</Typography>
                <Typography variant="body2" color="text.secondary">
                  Hierarchical structure with parent-child relationships. Binary Search Trees give O(log n) operations when balanced. 
                  Used in filesystems, databases (B-trees), and parsing (ASTs).
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#6366f1", 0.1) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#6366f1", mb: 1 }}>📊 Graphs</Typography>
                <Typography variant="body2" color="text.secondary">
                  Nodes (vertices) connected by edges. Can be directed/undirected, weighted/unweighted. Model relationships, networks, 
                  dependencies — social networks, maps, the internet.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ef4444", 0.1) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>📚 Stacks & Queues</Typography>
                <Typography variant="body2" color="text.secondary">
                  Restricted access structures. Stacks: LIFO (Last In, First Out) — undo operations, function calls. 
                  Queues: FIFO (First In, First Out) — task scheduling, BFS.
                </Typography>
              </Box>
            </Grid>
          </Grid>

          <Alert severity="warning" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>⚠️ Common Interview Trap</AlertTitle>
            <Typography variant="body2">
              Hash tables have O(1) <em>average</em> case, but O(n) <em>worst</em> case (when all keys hash to the same bucket). 
              Always clarify whether you're discussing average or worst case. Similarly, BSTs are O(log n) only when <em>balanced</em> — 
              a degenerate tree becomes a linked list with O(n) operations.
            </Typography>
          </Alert>
        </Paper>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Structure</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Access</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Search</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Insert</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Delete</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Use Case</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {dataStructures.map((ds) => (
                <TableRow key={ds.name}>
                  <TableCell sx={{ fontWeight: 600 }}>{ds.name}</TableCell>
                  <TableCell>
                    <Chip label={ds.type} size="small" sx={{ fontSize: "0.7rem", height: 20 }} />
                  </TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#22c55e" }}>{ds.access}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#f59e0b" }}>{ds.search}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#0ea5e9" }}>{ds.insert}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#ef4444" }}>{ds.delete}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{ds.useCase}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Sorting Algorithms */}
        <Typography id="sorting" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🔄 Sorting Algorithms
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Methods for arranging data in a specific order
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TimelineIcon sx={{ color: "#22c55e" }} />
            Why Sorting Matters
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            <strong>Sorting</strong> is one of the most fundamental operations in computer science. A sorted dataset enables binary search 
            (O(log n) instead of O(n)), makes duplicates adjacent (easy to find), and is required by many algorithms. Databases sort 
            results, search engines rank pages, and operating systems prioritize processes — sorting is everywhere.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Sorting algorithms are classified by several characteristics: <strong>Time complexity</strong> (how fast?), 
            <strong>Space complexity</strong> (in-place vs. requiring extra memory), <strong>Stability</strong> (do equal elements 
            maintain their original order?), and <strong>Adaptivity</strong> (does it run faster on partially sorted data?). 
            No single algorithm is best for all situations — the choice depends on your data and constraints.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            The theoretical lower bound for comparison-based sorting is <strong>O(n log n)</strong> — you cannot do better by only 
            comparing elements. This is proven using decision tree analysis. However, non-comparison sorts like Radix Sort and 
            Counting Sort can achieve O(n) by exploiting properties of the data (e.g., bounded integer range).
          </Typography>

          <Grid container spacing={2}>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.1) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>🏆 Quick Sort (Most Popular)</Typography>
                <Typography variant="body2" color="text.secondary">
                  Average O(n log n), in-place, but unstable and O(n²) worst case. The go-to for general-purpose sorting. Most standard 
                  library sort functions use Quick Sort or a hybrid variant.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#0ea5e9", 0.1) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#0ea5e9", mb: 1 }}>📊 Merge Sort (Guaranteed O(n log n))</Typography>
                <Typography variant="body2" color="text.secondary">
                  Always O(n log n), stable, but requires O(n) extra space. Used when stability matters or when sorting linked lists 
                  (no random access penalty).
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.1) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>⚡ Tim Sort (Real-World Champion)</Typography>
                <Typography variant="body2" color="text.secondary">
                  Hybrid of Merge Sort and Insertion Sort. Exploits existing order in data. Used by Python's sorted(), Java's 
                  Arrays.sort() for objects, and Android.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={6}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ec4899", 0.1) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ec4899", mb: 1 }}>📝 Insertion Sort (Best for Small/Nearly Sorted)</Typography>
                <Typography variant="body2" color="text.secondary">
                  O(n) on nearly sorted data, O(n²) worst case. Simple, in-place, stable. Often used as the base case in hybrid sorts 
                  when subarrays are small.
                </Typography>
              </Box>
            </Grid>
          </Grid>

          <Alert severity="info" sx={{ mt: 3, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>💡 Interview Insight</AlertTitle>
            <Typography variant="body2">
              Be prepared to explain <em>why</em> you'd choose one sorting algorithm over another. "I'd use Merge Sort because stability 
              matters here" or "Quick Sort is fine since we don't need guaranteed O(n log n)" shows deeper understanding than just 
              reciting complexities.
            </Typography>
          </Alert>
        </Paper>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#22c55e", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Algorithm</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Best</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Average</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Worst</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Space</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Stable</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {sortingAlgorithms.map((algo) => (
                <TableRow key={algo.name}>
                  <TableCell sx={{ fontWeight: 600 }}>{algo.name}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#22c55e" }}>{algo.best}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#f59e0b" }}>{algo.average}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#ef4444" }}>{algo.worst}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>{algo.space}</TableCell>
                  <TableCell>
                    <Chip
                      label={algo.stable}
                      size="small"
                      sx={{
                        fontSize: "0.7rem",
                        height: 20,
                        bgcolor: algo.stable === "Yes" ? alpha("#22c55e", 0.1) : alpha("#ef4444", 0.1),
                        color: algo.stable === "Yes" ? "#22c55e" : "#ef4444",
                      }}
                    />
                  </TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{algo.description}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Searching Algorithms */}
        <Typography id="searching" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🔍 Searching Algorithms
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Methods for finding elements in data structures
        </Typography>

        <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#0ea5e9", 0.03), border: `1px solid ${alpha("#0ea5e9", 0.15)}` }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <AccountTreeIcon sx={{ color: "#0ea5e9" }} />
            The Art of Finding
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            <strong>Searching</strong> is the process of finding a specific item in a collection of items. The efficiency of searching 
            depends heavily on how the data is organized. Unorganized data requires examining every element (O(n)). Organized data 
            — sorted, indexed, or in a tree/hash structure — enables much faster searches.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            The most significant optimization is <strong>Binary Search</strong>, which halves the search space with each comparison. 
            Instead of checking 1 million elements one by one, binary search finds any element in at most 20 comparisons (log₂(1,000,000) ≈ 20). 
            However, binary search requires the data to be <em>sorted</em> — if you need to search frequently, the one-time cost of 
            sorting pays off quickly.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            For even faster searches, <strong>Hash Tables</strong> provide O(1) average-case lookup by computing where an element 
            <em>should</em> be stored, rather than searching for it. Hash tables power dictionaries, sets, caches, and database indexes. 
            However, they sacrifice ordering — if you need sorted data or range queries, use a tree-based structure instead.
          </Typography>

          <Grid container spacing={2}>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ef4444", 0.1) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>🐢 Linear Search O(n)</Typography>
                <Typography variant="body2" color="text.secondary">
                  Check every element. Simple but slow. Required for unsorted data. Only option when data structure doesn't support 
                  faster search.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.1) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>🚀 Binary Search O(log n)</Typography>
                <Typography variant="body2" color="text.secondary">
                  Divide and conquer on sorted data. Incredibly efficient — 1 billion elements searched in ~30 comparisons. Foundation 
                  of many algorithms.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.1) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>⚡ Hash Lookup O(1)</Typography>
                <Typography variant="body2" color="text.secondary">
                  Compute the location directly. Fastest possible average case. Powers dictionaries, sets, and most caching systems.
                </Typography>
              </Box>
            </Grid>
          </Grid>

          <Alert severity="warning" sx={{ mt: 3, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>⚠️ Binary Search Gotcha</AlertTitle>
            <Typography variant="body2">
              Binary search looks simple but is notoriously hard to implement correctly. Off-by-one errors are common. The "correct" 
              implementation eluded programmers for years — even Jon Bentley's original version had a bug. Use library implementations when possible!
            </Typography>
          </Alert>
        </Paper>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#0ea5e9", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Algorithm</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Time</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Space</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Requirement</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {searchingAlgorithms.map((algo) => (
                <TableRow key={algo.name}>
                  <TableCell sx={{ fontWeight: 600 }}>{algo.name}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#22c55e" }}>{algo.timeComplexity}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace" }}>{algo.spaceComplexity}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem" }}>{algo.requirement}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{algo.description}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Divider */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>PROGRAMMING CONCEPTS</Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* Programming Paradigms */}
        <Accordion id="paradigms" defaultExpanded sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" }, scrollMarginTop: 80 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#f59e0b", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <CategoryIcon sx={{ color: "#f59e0b" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b" }}>Programming Paradigms</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {programmingParadigms.map((paradigm) => (
                <Grid item xs={12} md={6} key={paradigm.name}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.15)}`, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 0.5 }}>{paradigm.name}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{paradigm.description}</Typography>
                    <Typography variant="caption" sx={{ display: "block", mb: 0.5 }}>
                      <strong>Languages:</strong> {paradigm.languages}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      <strong>Key Features:</strong> {paradigm.keyFeatures}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* OOP Principles */}
        <Accordion id="oop" sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" }, scrollMarginTop: 80 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#6366f1", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <AccountTreeIcon sx={{ color: "#6366f1" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#6366f1" }}>OOP Principles (4 Pillars)</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {oopPrinciples.map((principle) => (
                <Grid item xs={12} sm={6} key={principle.principle}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#6366f1", 0.15)}`, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#6366f1", mb: 0.5 }}>{principle.principle}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{principle.description}</Typography>
                    <Typography variant="caption" sx={{ display: "block", mb: 0.5 }}>
                      <strong>Benefit:</strong> {principle.benefit}
                    </Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: alpha("#6366f1", 0.05), px: 1, py: 0.5, borderRadius: 1 }}>
                      {principle.example}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* SOLID Principles */}
        <Accordion id="solid" sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" }, scrollMarginTop: 80 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#22c55e", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <LayersIcon sx={{ color: "#22c55e" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e" }}>SOLID Principles</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            {solidPrinciples.map((principle) => (
              <Paper key={principle.letter} sx={{ p: 2, mb: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1 }}>
                  <Chip label={principle.letter} sx={{ fontWeight: 800, bgcolor: "#22c55e", color: "white", fontSize: "1rem" }} />
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{principle.name}</Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{principle.description}</Typography>
                <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: alpha("#22c55e", 0.05), px: 1, py: 0.5, borderRadius: 1 }}>
                  Example: {principle.example}
                </Typography>
              </Paper>
            ))}
          </AccordionDetails>
        </Accordion>

        {/* Design Patterns */}
        <Accordion id="patterns" sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" }, scrollMarginTop: 80 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#ec4899", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <HubIcon sx={{ color: "#ec4899" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#ec4899" }}>Common Design Patterns</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {designPatterns.map((pattern) => (
                <Grid item xs={12} sm={6} md={4} key={pattern.name}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#ec4899", 0.15)}`, height: "100%" }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ec4899" }}>{pattern.name}</Typography>
                      <Chip label={pattern.category} size="small" sx={{ fontSize: "0.65rem", height: 18 }} />
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{pattern.description}</Typography>
                    <Typography variant="caption">
                      <strong>Use:</strong> {pattern.useCase}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* Memory Management */}
        <Accordion id="memory" sx={{ mb: 2, borderRadius: "12px !important", "&:before": { display: "none" }, scrollMarginTop: 80 }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#ef4444", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <MemoryIcon sx={{ color: "#ef4444" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444" }}>Memory Management</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {memoryConcepts.map((concept) => (
                <Grid item xs={12} sm={6} md={4} key={concept.concept}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#ef4444", 0.15)}`, height: "100%" }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 0.5 }}>{concept.concept}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{concept.description}</Typography>
                    <Typography variant="caption" sx={{ display: "block" }}>
                      <strong>Managed by:</strong> {concept.managed}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </AccordionDetails>
        </Accordion>

        {/* Number Systems */}
        <Accordion sx={{ mb: 5, borderRadius: "12px !important", "&:before": { display: "none" } }}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />} sx={{ background: alpha("#0ea5e9", 0.05) }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <FunctionsIcon sx={{ color: "#0ea5e9" }} />
              <Typography variant="h6" sx={{ fontWeight: 700, color: "#0ea5e9" }}>Number Systems</Typography>
            </Box>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#0ea5e9", 0.05) }}>
                    <TableCell sx={{ fontWeight: 700 }}>System</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Base</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Digits</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Prefix</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Use Case</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {numberSystems.map((sys) => (
                    <TableRow key={sys.system}>
                      <TableCell sx={{ fontWeight: 600 }}>{sys.system}</TableCell>
                      <TableCell>{sys.base}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace" }}>{sys.digits}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace", color: "#0ea5e9" }}>{sys.prefix}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace" }}>{sys.example}</TableCell>
                      <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{sys.useCase}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>

        {/* Operating Systems Essentials */}
        <Typography id="os" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🧭 Operating Systems Essentials
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          How the OS manages processes, memory, and hardware resources
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.12)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            The operating system is the traffic controller for your computer. It schedules work, isolates programs for safety,
            and provides system calls so applications can use files, networks, and devices. Knowing the OS model helps you
            reason about performance, permissions, and security boundaries.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {osFundamentals.map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.concept}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.2)}`, height: "100%", bgcolor: alpha("#3b82f6", 0.02) }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 0.5 }}>{item.concept}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.description}</Typography>
                <Typography variant="caption" sx={{ display: "block", mb: 0.5 }}>
                  <strong>Why it matters:</strong> {item.why}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  <strong>Example:</strong> {item.example}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Concurrency & Parallelism */}
        <Typography id="concurrency" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          ⚙️ Concurrency & Parallelism
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Structuring work so tasks can overlap, and using multiple cores safely
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.12)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            Concurrency is about <strong>structure</strong> (many tasks in progress), while parallelism is about
            <strong>execution</strong> (many tasks at the same time). Both introduce shared-state risks like race conditions
            and deadlocks, so careful synchronization and thoughtful architecture matter.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {concurrencyConcepts.map((item) => (
            <Grid item xs={12} sm={6} md={4} key={item.concept}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#f97316", 0.2)}`, height: "100%" }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 0.5 }}>{item.concept}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.description}</Typography>
                <Typography variant="caption" sx={{ display: "block", mb: 0.5 }}>
                  <strong>Pitfall:</strong> {item.pitfall}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  <strong>Mitigation:</strong> {item.mitigation}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Networking Fundamentals */}
        <Typography id="networking" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🌐 Networking Fundamentals
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          The layers and protocols that move data across the internet
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#14b8a6", 0.03), border: `1px solid ${alpha("#14b8a6", 0.12)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            Networking is layered so each level has a focused job: the link moves frames on a local network, the internet
            layer routes packets, transport handles ports and reliability, and the application layer defines the protocols
            you actually use. This separation makes systems interoperable and easier to debug.
          </Typography>
        </Paper>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#14b8a6", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Layer</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Examples</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Data Unit</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {networkLayers.map((layer) => (
                <TableRow key={layer.layer}>
                  <TableCell sx={{ fontWeight: 600 }}>{layer.layer}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem" }}>{layer.purpose}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{layer.examples}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#14b8a6" }}>{layer.dataUnit}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Databases & Storage */}
        <Typography id="databases" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🗃️ Databases & Storage
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Choosing the right data model and understanding storage trade-offs
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.12)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            Databases organize data for fast, reliable access. Different data models prioritize flexibility, relationships,
            or speed. Storage features like indexing, replication, and sharding make systems faster and more resilient, but
            they also introduce trade-offs you need to understand.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 4 }}>
          {dataModels.map((model) => (
            <Grid item xs={12} sm={6} md={3} key={model.model}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.2)}`, height: "100%" }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 0.5 }}>{model.model}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{model.description}</Typography>
                <Typography variant="caption" sx={{ display: "block", mb: 0.5 }}>
                  <strong>Strengths:</strong> {model.strengths}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  <strong>Best for:</strong> {model.useCase}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {storageConcepts.map((concept) => (
            <Grid item xs={12} sm={6} md={3} key={concept.concept}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.15)}`, height: "100%", bgcolor: alpha("#22c55e", 0.02) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#16a34a", mb: 0.5 }}>{concept.concept}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{concept.description}</Typography>
                <Typography variant="caption" sx={{ display: "block", mb: 0.5 }}>
                  <strong>Trade-off:</strong> {concept.tradeoff}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  <strong>Example:</strong> {concept.example}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ========== MACHINE CODE SECTION ========== */}
        <Box id="machine-code" sx={{ scrollMarginTop: 80 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1, mt: 5 }}>
            💻 Machine Code & Assembly Language
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Understanding how computers truly execute instructions at the lowest level
          </Typography>

          {/* Machine Code Introduction */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 3, bgcolor: alpha("#dc2626", 0.03), border: `1px solid ${alpha("#dc2626", 0.15)}` }}>
            <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
              <MemoryIcon sx={{ color: "#dc2626" }} />
              What is Machine Code?
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              <strong>Machine code</strong> is the lowest-level programming language — a sequence of binary digits (1s and 0s) 
              that the CPU can directly execute. When you write code in Python, JavaScript, C++, or any other language, it 
              eventually gets translated into machine code before the computer can actually run it. Every "high-level" 
              instruction you write becomes multiple machine code instructions that the processor reads and executes one at a time.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Machine code is <strong>processor-specific</strong>. An x86 processor (found in most desktops and laptops) uses 
              different machine code than an ARM processor (found in most smartphones and Apple Silicon Macs). This is why you 
              can't simply run a Windows program on an ARM-based device without emulation or recompilation — the machine 
              instructions are completely different.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              <strong>Assembly language</strong> is a human-readable representation of machine code. Instead of memorizing that 
              <code style={{ backgroundColor: alpha("#dc2626", 0.1), padding: "2px 6px", borderRadius: 4, fontFamily: "monospace" }}>
                B8 05 00 00 00
              </code> means "move the value 5 into the EAX register," we can write{" "}
              <code style={{ backgroundColor: alpha("#dc2626", 0.1), padding: "2px 6px", borderRadius: 4, fontFamily: "monospace" }}>
                MOV EAX, 5
              </code>. An <strong>assembler</strong> converts assembly language into machine code.
            </Typography>

            <Alert severity="info" sx={{ borderRadius: 2, mb: 3 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>🔑 Key Insight</AlertTitle>
              <Typography variant="body2">
                Understanding machine code is essential for security professionals. Reverse engineering malware, analyzing 
                exploits, understanding buffer overflows, and writing shellcode all require knowledge of how instructions 
                execute at this level. Even if you never write assembly, being able to <em>read</em> it is invaluable.
              </Typography>
            </Alert>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>
              The Compilation Journey
            </Typography>
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              Here's what happens when you write code:
            </Typography>
            <Box sx={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: 1, mb: 3 }}>
              <Chip label="Source Code" sx={{ bgcolor: alpha("#22c55e", 0.15), fontWeight: 600 }} />
              <Typography>→</Typography>
              <Chip label="Preprocessing" sx={{ bgcolor: alpha("#f59e0b", 0.15), fontWeight: 600 }} />
              <Typography>→</Typography>
              <Chip label="Compilation to Assembly" sx={{ bgcolor: alpha("#0ea5e9", 0.15), fontWeight: 600 }} />
              <Typography>→</Typography>
              <Chip label="Assembly to Object Code" sx={{ bgcolor: alpha("#8b5cf6", 0.15), fontWeight: 600 }} />
              <Typography>→</Typography>
              <Chip label="Linking" sx={{ bgcolor: alpha("#ec4899", 0.15), fontWeight: 600 }} />
              <Typography>→</Typography>
              <Chip label="Executable (Machine Code)" sx={{ bgcolor: alpha("#dc2626", 0.15), fontWeight: 700 }} />
            </Box>
          </Paper>

          {/* CPU Instruction Cycle */}
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#f59e0b", 0.03), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#f59e0b" }}>
              ⚙️ The CPU Instruction Cycle (Fetch-Decode-Execute)
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Every instruction the CPU executes follows a predictable cycle. Understanding this cycle helps you grasp how 
              programs actually run and why certain optimizations or attacks (like speculative execution vulnerabilities) work.
            </Typography>
            <Grid container spacing={2}>
              {instructionCycle.map((phase, index) => (
                <Grid item xs={12} key={phase.phase}>
                  <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2, p: 1.5, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.1)}` }}>
                    <Chip label={index + 1} size="small" sx={{ bgcolor: "#f59e0b", color: "white", fontWeight: 800, minWidth: 32 }} />
                    <Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>{phase.phase.split(". ")[1]}</Typography>
                      <Typography variant="body2" color="text.secondary">{phase.description}</Typography>
                    </Box>
                  </Box>
                </Grid>
              ))}
            </Grid>
            <Alert severity="warning" sx={{ mt: 2, borderRadius: 2 }}>
              <Typography variant="body2">
                Modern CPUs use <strong>pipelining</strong>, <strong>branch prediction</strong>, and <strong>out-of-order execution</strong> 
                to process multiple instructions simultaneously. This makes them much faster but also introduces security vulnerabilities 
                like Spectre and Meltdown.
              </Typography>
            </Alert>
          </Paper>

          {/* Machine Code Concepts */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            📖 Key Machine Code Concepts
          </Typography>
          <Grid container spacing={2} sx={{ mb: 4 }}>
            {machineCodeConcepts.map((concept) => (
              <Grid item xs={12} sm={6} md={4} key={concept.concept}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, border: `1px solid ${alpha("#dc2626", 0.15)}`, bgcolor: alpha("#dc2626", 0.02) }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#dc2626", mb: 0.5 }}>{concept.concept}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{concept.description}</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: alpha("#dc2626", 0.1), px: 1, py: 0.5, borderRadius: 1, display: "inline-block" }}>
                    {concept.example}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          {/* CPU Registers */}
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#8b5cf6" }}>
              🗄️ CPU Registers (x86/x64 Architecture)
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              <strong>Registers</strong> are tiny, ultra-fast storage locations inside the CPU. They hold data the processor is 
              actively working with. Accessing a register takes about 1 CPU cycle, while accessing RAM takes 100-300 cycles. 
              Understanding registers is crucial because exploits often manipulate them to control program execution.
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              In x86 architecture, registers have evolved from 16-bit (AX, BX) to 32-bit (EAX, EBX — the 'E' stands for 'Extended') 
              to 64-bit (RAX, RBX — 'R' for... well, just 64-bit). You can still access the smaller portions: AL (low 8 bits of AX), 
              AH (high 8 bits of AX), AX (low 16 bits of EAX), EAX (low 32 bits of RAX).
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha("#8b5cf6", 0.08) }}>
                    <TableCell sx={{ fontWeight: 700 }}>Register</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Purpose</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Size</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {cpuRegistersX86.map((reg) => (
                    <TableRow key={reg.register} sx={{ "&:hover": { bgcolor: alpha("#8b5cf6", 0.03) } }}>
                      <TableCell sx={{ fontFamily: "monospace", fontWeight: 700, color: "#8b5cf6" }}>{reg.register}</TableCell>
                      <TableCell sx={{ fontWeight: 600 }}>{reg.purpose}</TableCell>
                      <TableCell sx={{ fontSize: "0.85rem", color: "text.secondary" }}>{reg.description}</TableCell>
                      <TableCell sx={{ fontFamily: "monospace" }}>{reg.bits}-bit</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
            <Alert severity="error" sx={{ mt: 2, borderRadius: 2 }}>
              <AlertTitle sx={{ fontWeight: 700 }}>🔐 Security Note</AlertTitle>
              <Typography variant="body2">
                The <strong>EIP/RIP</strong> (Instruction Pointer) is the most targeted register in exploitation. If an attacker can 
                overwrite EIP (via buffer overflow, ROP chain, etc.), they can redirect program execution to their malicious code. 
                This is why understanding registers is essential for both offense and defense.
              </Typography>
            </Alert>
          </Paper>

          {/* Common Instructions */}
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            📋 Common x86 Assembly Instructions
          </Typography>
          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
            These are the most common instructions you'll encounter when reading disassembled code. They form the building 
            blocks of all programs. While there are hundreds of x86 instructions, knowing these ~15-20 will let you understand 
            most code you'll encounter.
          </Typography>
          <TableContainer component={Paper} sx={{ mb: 4, borderRadius: 3 }}>
            <Table size="small">
              <TableHead>
                <TableRow sx={{ bgcolor: alpha("#0ea5e9", 0.1) }}>
                  <TableCell sx={{ fontWeight: 700 }}>Instruction</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Category</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {commonInstructions.map((inst) => (
                  <TableRow key={inst.instruction} sx={{ "&:hover": { bgcolor: alpha("#0ea5e9", 0.03) } }}>
                    <TableCell sx={{ fontFamily: "monospace", fontWeight: 700, color: "#0ea5e9" }}>{inst.instruction}</TableCell>
                    <TableCell><Chip label={inst.category} size="small" sx={{ fontSize: "0.7rem", height: 20 }} /></TableCell>
                    <TableCell sx={{ fontSize: "0.85rem" }}>{inst.description}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem", color: "text.secondary" }}>{inst.example}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          {/* Memory Layout */}
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#22c55e" }}>
              🏗️ Program Memory Layout
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              When a program runs, the operating system loads it into memory following a specific layout. Understanding this 
              layout is crucial for exploit development, debugging, and reverse engineering. Each region has different purposes 
              and permissions.
            </Typography>
            <Grid container spacing={2}>
              {memorySegments.map((seg) => (
                <Grid item xs={12} sm={6} key={seg.segment}>
                  <Paper sx={{ p: 2, height: "100%", borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e" }}>{seg.segment}</Typography>
                      <Chip 
                        label={seg.permissions} 
                        size="small" 
                        sx={{ 
                          fontFamily: "monospace", 
                          fontSize: "0.7rem", 
                          height: 20,
                          bgcolor: seg.permissions.includes("X") ? alpha("#ef4444", 0.15) : alpha("#22c55e", 0.15),
                          color: seg.permissions.includes("X") ? "#ef4444" : "#22c55e"
                        }} 
                      />
                    </Box>
                    <Typography variant="body2" color="text.secondary">{seg.description}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
            <Box sx={{ mt: 3, p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px dashed ${alpha("#22c55e", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>📐 Memory Layout Visualization (High to Low Address)</Typography>
              <Typography variant="body2" sx={{ fontFamily: "monospace", whiteSpace: "pre-wrap", lineHeight: 2 }}>
{`┌─────────────────────────┐  High Address (e.g., 0xFFFFFFFF)
│      Kernel Space       │  ← Reserved for OS
├─────────────────────────┤
│         Stack           │  ← Grows DOWN ↓ (local vars, return addresses)
│           ↓             │
├ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
│                         │  ← Unused space
├ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
│           ↑             │
│          Heap           │  ← Grows UP ↑ (malloc, dynamic memory)
├─────────────────────────┤
│          BSS            │  ← Uninitialized global/static data
├─────────────────────────┤
│          Data           │  ← Initialized global/static data
├─────────────────────────┤
│     Text (Code)         │  ← Executable instructions
└─────────────────────────┘  Low Address (e.g., 0x00400000)`}
              </Typography>
            </Box>
          </Paper>

          {/* Practical Example */}
          <Paper sx={{ p: 3, mb: 4, borderRadius: 3, bgcolor: alpha("#ec4899", 0.03), border: `1px solid ${alpha("#ec4899", 0.15)}` }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1, color: "#ec4899" }}>
              🔬 Practical Example: C to Assembly
            </Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Let's see how a simple C function gets translated to assembly. Understanding this transformation helps you 
              read disassembled code and understand what compiled programs are actually doing.
            </Typography>
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#22c55e" }}>C Source Code</Typography>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4" }}>
                  <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{`int add_numbers(int a, int b) {
    int result;
    result = a + b;
    return result;
}`}</pre>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#0ea5e9" }}>x86 Assembly (Simplified)</Typography>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4" }}>
                  <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{`add_numbers:
    push ebp          ; Save old base pointer
    mov ebp, esp      ; Set up stack frame
    
    mov eax, [ebp+8]  ; Load 'a' into EAX
    add eax, [ebp+12] ; Add 'b' to EAX
    ; Result is now in EAX
    
    pop ebp           ; Restore base pointer
    ret               ; Return (EAX = result)`}</pre>
                </Paper>
              </Grid>
            </Grid>
            <Alert severity="info" sx={{ mt: 3, borderRadius: 2 }}>
              <Typography variant="body2">
                <strong>Key observation:</strong> The function's return value is stored in <code>EAX</code> by convention. 
                Parameters are accessed relative to <code>EBP</code> (base pointer). This is the <strong>calling convention</strong> 
                — the agreed-upon rules for how functions receive arguments and return values.
              </Typography>
            </Alert>
          </Paper>

          {/* Why This Matters */}
          <Alert severity="success" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>🎯 Why Machine Code Knowledge Matters</AlertTitle>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6} md={3}>
                <Typography variant="body2" sx={{ mb: 1 }}><strong>🔍 Reverse Engineering</strong></Typography>
                <Typography variant="caption" color="text.secondary">
                  Analyze malware, understand proprietary software, crack DRM (legally for security research)
                </Typography>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Typography variant="body2" sx={{ mb: 1 }}><strong>🐛 Exploit Development</strong></Typography>
                <Typography variant="caption" color="text.secondary">
                  Buffer overflows, ROP chains, shellcode writing all require assembly knowledge
                </Typography>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Typography variant="body2" sx={{ mb: 1 }}><strong>🛡️ Vulnerability Analysis</strong></Typography>
                <Typography variant="caption" color="text.secondary">
                  Understanding the root cause of CVEs often requires reading disassembly
                </Typography>
              </Grid>
              <Grid item xs={12} sm={6} md={3}>
                <Typography variant="body2" sx={{ mb: 1 }}><strong>⚡ Performance Optimization</strong></Typography>
                <Typography variant="caption" color="text.secondary">
                  See what the compiler generates, identify inefficiencies, write SIMD code
                </Typography>
              </Grid>
            </Grid>
          </Alert>
        </Box>

        {/* Divider - Advanced Topics */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 4, mt: 5 }}>
          <Divider sx={{ flex: 1 }} />
          <Typography variant="overline" color="text.secondary" sx={{ fontWeight: 700 }}>ADVANCED TOPICS</Typography>
          <Divider sx={{ flex: 1 }} />
        </Box>

        {/* Recursion Basics */}
        <Typography id="recursion" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🔄 Recursion Fundamentals
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Understanding how functions can call themselves to solve problems
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#a855f7", 0.03), border: `1px solid ${alpha("#a855f7", 0.1)}` }}>
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            <strong>Recursion</strong> is when a function calls itself to solve a problem by breaking it into smaller, 
            similar sub-problems. Think of it like Russian nesting dolls — each doll contains a smaller version of itself 
            until you reach the smallest one.
          </Typography>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            Every recursive function needs a <strong>base case</strong> (when to stop) and a <strong>recursive case</strong> 
            (how to break down the problem). Without a proper base case, you'll get infinite recursion and a stack overflow!
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {recursionConcepts.map((concept) => (
            <Grid item xs={12} sm={6} md={4} key={concept.concept}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#a855f7", 0.2)}`, height: "100%", bgcolor: alpha("#a855f7", 0.02) }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#a855f7", mb: 0.5 }}>{concept.concept}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{concept.description}</Typography>
                <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block", bgcolor: alpha("#a855f7", 0.08), px: 1, py: 0.5, borderRadius: 1, mb: 1 }}>
                  {concept.example}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  <strong>Why it matters:</strong> {concept.importance}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Interview Algorithm Patterns */}
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          🎯 Common Algorithm Patterns
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Essential problem-solving patterns used in technical interviews
        </Typography>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#f59e0b", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Pattern</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Use Cases</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Complexity</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {interviewConcepts.map((concept) => (
                <TableRow key={concept.topic}>
                  <TableCell sx={{ fontWeight: 600, color: "#f59e0b" }}>{concept.topic}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem" }}>{concept.description}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{concept.useCase}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#22c55e" }}>{concept.complexity}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Tree Traversals */}
        <Typography id="trees" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🌳 Tree Traversals
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Different ways to visit all nodes in a tree structure
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#10b981", 0.03), border: `1px solid ${alpha("#10b981", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            Tree traversal is the process of visiting each node in a tree exactly once. The order in which nodes are visited 
            depends on the traversal type. Understanding traversals is crucial for tasks like searching, serializing trees, 
            evaluating expressions, and many other operations. For a binary tree, the three main depth-first traversals differ 
            only in when you "visit" the current node relative to its children.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {treeTraversals.map((traversal) => (
            <Grid item xs={12} sm={6} key={traversal.name}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#10b981", 0.2)}`, height: "100%" }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 0.5 }}>{traversal.name}</Typography>
                <Typography variant="body2" sx={{ mb: 1, fontWeight: 600 }}>{traversal.order}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{traversal.result}</Typography>
                <Typography variant="caption" sx={{ display: "block", mb: 1 }}>
                  <strong>Use case:</strong> {traversal.useCase}
                </Typography>
                <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block", bgcolor: alpha("#10b981", 0.08), px: 1, py: 0.5, borderRadius: 1 }}>
                  {traversal.recursive}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Graph Representations */}
        <Typography id="graphs" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          📈 Graph Representations
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Different ways to store and represent graph data structures
        </Typography>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#6366f1", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Representation</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Space</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Add Edge</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Check Edge</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Pros</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Cons</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {graphRepresentations.map((rep) => (
                <TableRow key={rep.type}>
                  <TableCell sx={{ fontWeight: 600 }}>{rep.type}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#6366f1" }}>{rep.space}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#22c55e" }}>{rep.addEdge}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#f59e0b" }}>{rep.checkEdge}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{rep.pros}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "#ef4444" }}>{rep.cons}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Bit Manipulation */}
        <Typography id="bits" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🔢 Bit Manipulation
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Working directly with binary representations of numbers
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#14b8a6", 0.03), border: `1px solid ${alpha("#14b8a6", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            Bit manipulation involves directly working with individual bits of numbers. It's used for optimization, 
            cryptography, low-level programming, and solving specific algorithm problems efficiently. Understanding 
            these operations is essential for systems programming, embedded development, and many interview questions. 
            In security, bit manipulation is fundamental for understanding encryption, hashing, and binary protocols.
          </Typography>
        </Paper>

        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>Bitwise Operations</Typography>
        <TableContainer component={Paper} sx={{ mb: 4, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#14b8a6", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Operation</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Symbol</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Example</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Use Case</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {bitOperations.map((op) => (
                <TableRow key={op.operation}>
                  <TableCell sx={{ fontWeight: 600 }}>{op.operation}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "1.1rem", color: "#14b8a6" }}>{op.symbol}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem" }}>{op.description}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{op.example}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{op.useCase}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>Common Bit Tricks</Typography>
        <Grid container spacing={2} sx={{ mb: 5 }}>
          {bitTricks.map((trick) => (
            <Grid item xs={12} sm={6} md={4} key={trick.trick}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#14b8a6", 0.2)}`, height: "100%" }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#14b8a6", mb: 0.5 }}>{trick.trick}</Typography>
                <Typography variant="body2" sx={{ fontFamily: "monospace", bgcolor: alpha("#14b8a6", 0.08), px: 1, py: 0.5, borderRadius: 1, mb: 1, display: "inline-block" }}>
                  {trick.code}
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                  {trick.explanation}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* String Algorithms */}
        <Typography id="strings" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          📝 String Algorithms
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Algorithms for searching and manipulating text
        </Typography>

        <TableContainer component={Paper} sx={{ mb: 5, borderRadius: 3 }}>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ bgcolor: alpha("#ec4899", 0.1) }}>
                <TableCell sx={{ fontWeight: 700 }}>Algorithm</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Complexity</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Description</TableCell>
                <TableCell sx={{ fontWeight: 700 }}>Best For</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {stringAlgorithms.map((algo) => (
                <TableRow key={algo.name}>
                  <TableCell sx={{ fontWeight: 600 }}>{algo.name}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", color: "#22c55e" }}>{algo.complexity}</TableCell>
                  <TableCell sx={{ fontSize: "0.85rem" }}>{algo.description}</TableCell>
                  <TableCell sx={{ fontSize: "0.8rem", color: "text.secondary" }}>{algo.useCase}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        {/* Complexity Classes */}
        <Typography id="complexity" variant="h4" sx={{ fontWeight: 800, mb: 1, scrollMarginTop: 80 }}>
          🧮 Computational Complexity Classes
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Classifying problems by how hard they are to solve
        </Typography>

        <Paper sx={{ p: 3, mb: 3, borderRadius: 3, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.1)}` }}>
          <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
            Complexity theory classifies computational problems based on the resources required to solve them. 
            The famous <strong>P vs NP</strong> question asks whether every problem whose solution can be quickly 
            verified can also be quickly solved — one of the biggest unsolved problems in computer science. 
            Understanding these classes helps you recognize when a problem is fundamentally hard and when you 
            might need to use approximation algorithms or heuristics.
          </Typography>
        </Paper>

        <Grid container spacing={2} sx={{ mb: 5 }}>
          {complexityClasses.map((cls) => (
            <Grid item xs={12} sm={6} key={cls.class}>
              <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#8b5cf6", 0.2)}`, height: "100%" }}>
                <Chip label={cls.class} sx={{ fontWeight: 800, bgcolor: "#8b5cf6", color: "white", fontSize: "1rem", mb: 1 }} />
                <Typography variant="body2" sx={{ mb: 1, fontWeight: 600 }}>{cls.description}</Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.5 }}>
                  <strong>Examples:</strong> {cls.examples}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* Key Takeaways */}
        <Paper sx={{ p: 4, mb: 5, borderRadius: 3, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
            <TipsAndUpdatesIcon sx={{ color: "#22c55e" }} />
            Key Takeaways
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Know Your Trade-offs</Typography>
              <Typography variant="body2" color="text.secondary">
                There's rarely a "best" data structure or algorithm — only the best one for your specific situation. 
                Arrays are fast for access but slow for insertions. Hash tables are fast but use more memory. 
                Always consider time vs. space trade-offs.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Practice Pattern Recognition</Typography>
              <Typography variant="body2" color="text.secondary">
                Most coding problems fit common patterns (two pointers, sliding window, BFS/DFS). Learning to recognize 
                these patterns helps you quickly identify the right approach and avoid reinventing the wheel.
              </Typography>
            </Grid>
            <Grid item xs={12} md={4}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Understand, Don't Memorize</Typography>
              <Typography variant="body2" color="text.secondary">
                Focus on understanding <em>why</em> something works rather than memorizing implementations. 
                If you understand the underlying concepts, you can derive solutions even if you forget specifics.
              </Typography>
            </Grid>
          </Grid>
        </Paper>

        {/* Quiz Section */}
        <Box id="quiz" sx={{ mt: 5 }}>
          <QuizSection
            questions={quizPool}
            accentColor={ACCENT_COLOR}
            title="Computer Science Fundamentals Knowledge Check"
            description="Random 10-question quiz drawn from a 75-question bank each time the page loads."
            questionsPerQuiz={QUIZ_QUESTION_COUNT}
          />
        </Box>

        {/* Footer - Back to Learning Hub */}
        <Paper
          sx={{
            p: 4,
            borderRadius: 3,
            textAlign: "center",
            background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.05)}, ${alpha("#6366f1", 0.05)})`,
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          }}
        >
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
            🚧 More Content Coming Soon
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            This page will be expanded with interactive examples, code snippets, practice problems, and quizzes.
          </Typography>
          <Box sx={{ display: "flex", gap: 1, justifyContent: "center", flexWrap: "wrap", mb: 3 }}>
            <Chip label="Dynamic Programming Deep Dive" size="small" />
            <Chip label="Graph Algorithms (Dijkstra, A*)" size="small" />
            <Chip label="Advanced Data Structures" size="small" />
            <Chip label="System Design Patterns" size="small" />
            <Chip label="Interactive Quizzes" size="small" />
          </Box>
          <Divider sx={{ my: 3 }} />
          <Button
            variant="outlined"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{
              borderColor: "#8b5cf6",
              color: "#8b5cf6",
              fontWeight: 600,
              "&:hover": {
                borderColor: "#6366f1",
                bgcolor: alpha("#8b5cf6", 0.05),
              },
            }}
          >
            Return to Learning Hub
          </Button>
        </Paper>
        </Box>
      </Box>
    </LearnPageLayout>
  );
};

export default ComputerScienceFundamentalsPage;
