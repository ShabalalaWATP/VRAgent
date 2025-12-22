import React, { useState } from "react";
import LearnPageLayout from "../components/LearnPageLayout";
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

const ComputerScienceFundamentalsPage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();

  const pageContext = `Computer Science Fundamentals learning page - Essential CS concepts for developers and security professionals. Covers data structures (arrays, linked lists, trees, graphs, hash tables), algorithms (sorting, searching, Big O notation), programming paradigms (OOP, functional, procedural), SOLID principles, design patterns, memory management, and number systems. Foundation knowledge for software development, coding interviews, and understanding system internals.`;

  return (
    <LearnPageLayout pageTitle="Computer Science Fundamentals" pageContext={pageContext}>
      <Container maxWidth="lg" sx={{ py: 4 }}>
        {/* Back Button */}
        <Chip
          icon={<ArrowBackIcon />}
          label="Back to Learning Hub"
          onClick={() => navigate("/learn")}
          sx={{ mb: 3, fontWeight: 600, cursor: "pointer" }}
          clickable
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
      </Container>
    </LearnPageLayout>
  );
};

export default ComputerScienceFundamentalsPage;
