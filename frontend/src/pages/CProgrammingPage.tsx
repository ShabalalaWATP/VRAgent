import React, { useState, useEffect, useMemo } from "react";
import {
  Box,
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
  alpha,
  useTheme,
  Fab,
  Drawer,
  IconButton,
  Tooltip,
  useMediaQuery,
  LinearProgress,
  Avatar,
  Radio,
  RadioGroup,
  FormControlLabel,
  FormControl,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import CodeIcon from "@mui/icons-material/Code";
import SchoolIcon from "@mui/icons-material/School";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import TerminalIcon from "@mui/icons-material/Terminal";
import BuildIcon from "@mui/icons-material/Build";
import MemoryIcon from "@mui/icons-material/Memory";
import StorageIcon from "@mui/icons-material/Storage";
import SpeedIcon from "@mui/icons-material/Speed";
import BugReportIcon from "@mui/icons-material/BugReport";
import SecurityIcon from "@mui/icons-material/Security";
import DeveloperBoardIcon from "@mui/icons-material/DeveloperBoard";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import ListAltIcon from "@mui/icons-material/ListAlt";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutline";
import CancelOutlinedIcon from "@mui/icons-material/CancelOutlined";
import { Link, useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";

export default function CProgrammingPage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");

  const pageContext = `C Programming learning page - comprehensive guide covering C language fundamentals, memory management, pointers, data structures, system programming, and low-level development.`;

  const accentColor = "#5c6bc0"; // C blue/indigo
  const accentDark = "#3f51b5";

  const quickStats = [
    { label: "Modules", value: "15", color: "#5c6bc0" },
    { label: "Topics", value: "50+", color: "#26a69a" },
    { label: "Examples", value: "100+", color: "#22c55e" },
    { label: "Difficulty", value: "Intermediate", color: "#ff9800" },
  ];

  const moduleNavItems = [
    { id: "introduction", label: "Introduction", icon: "📖" },
    { id: "setup", label: "Environment Setup", icon: "🔧" },
    { id: "basics", label: "C Basics", icon: "🚀" },
    { id: "variables", label: "Variables & Types", icon: "📦" },
    { id: "operators", label: "Operators", icon: "➕" },
    { id: "control-flow", label: "Control Flow", icon: "🔀" },
    { id: "functions", label: "Functions", icon: "⚡" },
    { id: "arrays", label: "Arrays", icon: "📊" },
    { id: "pointers", label: "Pointers", icon: "🎯" },
    { id: "strings", label: "Strings", icon: "📝" },
    { id: "structs", label: "Structures & Unions", icon: "🏗️" },
    { id: "memory", label: "Memory Management", icon: "💾" },
    { id: "file-io", label: "File I/O", icon: "📁" },
    { id: "preprocessor", label: "Preprocessor", icon: "⚙️" },
    { id: "advanced", label: "Advanced Topics", icon: "🔬" },
    { id: "quiz", label: "Knowledge Quiz", icon: "📝" },
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
      const sections = moduleNavItems.map((item) => item.id);
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

  const currentIndex = moduleNavItems.findIndex((item) => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / moduleNavItems.length) * 100 : 0;

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
        border: `1px solid ${alpha(accentColor, 0.15)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        display: { xs: "none", lg: "block" },
        "&::-webkit-scrollbar": { width: 6 },
        "&::-webkit-scrollbar-thumb": { bgcolor: alpha(accentColor, 0.3), borderRadius: 3 },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: accentColor, display: "flex", alignItems: "center", gap: 1 }}>
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">Progress</Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: accentColor }}>{Math.round(progressPercent)}%</Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha(accentColor, 0.1),
              "& .MuiLinearProgress-bar": { bgcolor: accentColor, borderRadius: 3 },
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
                bgcolor: activeSection === item.id ? alpha(accentColor, 0.15) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid ${accentColor}` : "3px solid transparent",
                "&:hover": { bgcolor: alpha(accentColor, 0.08) },
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
                      color: activeSection === item.id ? accentColor : "text.secondary",
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

  const TopicPlaceholder: React.FC<{ id: string; title: string; icon: React.ReactNode; color: string; description: string }> = ({
    id,
    title,
    icon,
    color,
    description,
  }) => (
    <Paper id={id} sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha(color, 0.2)}` }}>
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
        <Box
          sx={{
            width: 48,
            height: 48,
            borderRadius: 2,
            bgcolor: alpha(color, 0.15),
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: color,
          }}
        >
          {icon}
        </Box>
        <Typography variant="h5" sx={{ fontWeight: 800 }}>
          {title}
        </Typography>
        <Chip label="Coming Soon" size="small" sx={{ bgcolor: alpha(color, 0.1), color: color, fontWeight: 600 }} />
      </Box>
      <Typography variant="body1" color="text.secondary">
        {description}
      </Typography>
    </Paper>
  );

  // Quiz interfaces and data
  interface QuizQuestion {
    id: number;
    question: string;
    options: string[];
    correctAnswer: number;
    explanation: string;
  }

  // 75-question bank for C Programming
  const cQuestionBank: QuizQuestion[] = [
    // C Basics (1-15)
    { id: 1, question: "Who developed the C programming language?", options: ["Bjarne Stroustrup", "Dennis Ritchie", "James Gosling", "Guido van Rossum"], correctAnswer: 1, explanation: "C was developed by Dennis Ritchie at Bell Labs in 1972. It was designed for writing operating systems, particularly UNIX." },
    { id: 2, question: "Which header file is required for printf() and scanf()?", options: ["<stdlib.h>", "<string.h>", "<stdio.h>", "<conio.h>"], correctAnswer: 2, explanation: "<stdio.h> (Standard Input Output) contains declarations for printf(), scanf(), and other I/O functions." },
    { id: 3, question: "What is the correct way to declare a main function in C?", options: ["void main()", "int main(void)", "main()", "All are valid"], correctAnswer: 1, explanation: "int main(void) is the standard-compliant way. main() should return an int to indicate success (0) or failure to the operating system." },
    { id: 4, question: "Which symbol ends most C statements?", options: [":", ".", ";", ","], correctAnswer: 2, explanation: "The semicolon (;) is the statement terminator in C. Every statement (except compound statements) must end with a semicolon." },
    { id: 5, question: "What does the '\\n' escape sequence represent?", options: ["Tab", "Newline", "Null character", "Backslash"], correctAnswer: 1, explanation: "\\n is the newline escape sequence that moves the cursor to the next line. Other common escapes include \\t (tab) and \\0 (null)." },
    { id: 6, question: "How do you write a single-line comment in C?", options: ["# comment", "// comment", "/* comment */", "-- comment"], correctAnswer: 1, explanation: "// starts a single-line comment (C99 onwards). /* */ is used for multi-line comments and was available in original C." },
    { id: 7, question: "Which keyword is used to define a constant in C?", options: ["constant", "final", "const", "define"], correctAnswer: 2, explanation: "The 'const' keyword makes a variable read-only. #define can also create constants but creates preprocessor macros instead." },
    { id: 8, question: "What is the size of 'int' on most 64-bit systems?", options: ["2 bytes", "4 bytes", "8 bytes", "Depends on compiler"], correctAnswer: 1, explanation: "On most modern systems, int is 4 bytes (32 bits). However, the C standard only guarantees minimum sizes, so it can vary." },
    { id: 9, question: "What does 'sizeof' return?", options: ["The value of a variable", "The size in bytes", "The memory address", "The data type"], correctAnswer: 1, explanation: "sizeof is an operator that returns the size of a type or variable in bytes. It's evaluated at compile time." },
    { id: 10, question: "Which format specifier is used for printing an integer?", options: ["%f", "%d", "%c", "%s"], correctAnswer: 1, explanation: "%d prints signed decimal integers. %i also works for integers. %u is for unsigned integers." },
    { id: 11, question: "What is the default value of an uninitialized local variable?", options: ["0", "NULL", "Garbage/undefined", "-1"], correctAnswer: 2, explanation: "Local variables in C are not automatically initialized. They contain garbage values (whatever was in that memory location)." },
    { id: 12, question: "Which operator is used for the modulus operation?", options: ["/", "%", "mod", "//"], correctAnswer: 1, explanation: "The % operator returns the remainder of integer division. For example, 10 % 3 equals 1." },
    { id: 13, question: "What does the 'return 0' statement indicate in main()?", options: ["Error occurred", "Program success", "Loop termination", "Nothing"], correctAnswer: 1, explanation: "return 0 in main() indicates successful program execution. Non-zero values typically indicate errors." },
    { id: 14, question: "What is the purpose of the 'void' keyword?", options: ["To declare empty variables", "To indicate no return value or parameters", "To create void pointers only", "To declare global variables"], correctAnswer: 1, explanation: "void indicates absence of type - used for functions returning nothing or taking no parameters, and for generic void pointers." },
    { id: 15, question: "Which is a valid variable name in C?", options: ["2variable", "my-var", "_myVar", "int"], correctAnswer: 2, explanation: "Variable names can contain letters, digits, and underscores, but cannot start with a digit or be a keyword." },
    
    // Data Types & Variables (16-25)
    { id: 16, question: "What is the range of 'char' in C?", options: ["-128 to 127 (signed)", "0 to 255 only", "0 to 127 only", "-256 to 255"], correctAnswer: 0, explanation: "A signed char ranges from -128 to 127 (8 bits). An unsigned char ranges from 0 to 255." },
    { id: 17, question: "Which data type is used for decimal numbers?", options: ["int", "char", "float or double", "long"], correctAnswer: 2, explanation: "float (32-bit) and double (64-bit) are floating-point types for decimal numbers. double is preferred for precision." },
    { id: 18, question: "What does 'unsigned' mean for a data type?", options: ["Cannot be negative", "Has no type", "Is very large", "Cannot be modified"], correctAnswer: 0, explanation: "unsigned means the variable can only hold non-negative values, effectively doubling the positive range." },
    { id: 19, question: "What is the format specifier for a float?", options: ["%d", "%f", "%lf", "%c"], correctAnswer: 1, explanation: "%f is used for float in printf(). For scanf(), %f is for float and %lf is for double." },
    { id: 20, question: "How do you declare a long integer?", options: ["big int x;", "long int x;", "integer long x;", "extended int x;"], correctAnswer: 1, explanation: "long int (or just 'long') declares a long integer. You can also use 'long long' for even larger integers." },
    { id: 21, question: "What is the difference between 'float' and 'double'?", options: ["No difference", "double has more precision", "float has more precision", "double is only for integers"], correctAnswer: 1, explanation: "double provides approximately 15-16 decimal digits of precision vs float's 6-7 digits. double uses 64 bits vs float's 32 bits." },
    { id: 22, question: "What does 'typedef' do?", options: ["Creates a new data type", "Creates an alias for existing type", "Defines a function", "Declares a variable"], correctAnswer: 1, explanation: "typedef creates an alias (alternative name) for an existing type. Example: typedef unsigned long ulong;" },
    { id: 23, question: "Which suffix denotes a long literal?", options: ["l or L", "g or G", "d or D", "n or N"], correctAnswer: 0, explanation: "L or l suffix makes an integer literal long. Example: 100L. Use LL for long long, F for float, U for unsigned." },
    { id: 24, question: "What is 'enum' used for?", options: ["Floating-point numbers", "Named integer constants", "String constants", "Array declaration"], correctAnswer: 1, explanation: "enum creates a set of named integer constants. Example: enum Color { RED, GREEN, BLUE }; where RED=0, GREEN=1, BLUE=2." },
    { id: 25, question: "What happens when you assign a float to an int?", options: ["Compilation error", "Runtime error", "Truncation occurs", "Rounding occurs"], correctAnswer: 2, explanation: "When assigning float to int, the decimal part is truncated (cut off), not rounded. 3.9 becomes 3." },
    
    // Operators (26-35)
    { id: 26, question: "What is the result of 5 / 2 in C (integer division)?", options: ["2.5", "2", "3", "2.0"], correctAnswer: 1, explanation: "Integer division truncates the result. 5/2 = 2 because both operands are integers." },
    { id: 27, question: "What does the '++' operator do?", options: ["Adds 2", "Increments by 1", "Doubles the value", "Squares the value"], correctAnswer: 1, explanation: "++ is the increment operator that adds 1 to the variable. x++ is post-increment, ++x is pre-increment." },
    { id: 28, question: "What is the difference between '==' and '='?", options: ["No difference", "'==' assigns, '=' compares", "'=' assigns, '==' compares", "They're both assignment"], correctAnswer: 2, explanation: "'=' is assignment operator, '==' is equality comparison. This is a common source of bugs when confused." },
    { id: 29, question: "What does '&&' represent?", options: ["Bitwise AND", "Logical AND", "Address operator", "Boolean value"], correctAnswer: 1, explanation: "'&&' is logical AND (short-circuit evaluation). '&' is bitwise AND. Logical operators work with boolean expressions." },
    { id: 30, question: "What is the result of !0 in C?", options: ["0", "1", "-1", "Error"], correctAnswer: 1, explanation: "! is the logical NOT operator. Since 0 is false in C, !0 is true, which equals 1." },
    { id: 31, question: "What does the '?:' operator do?", options: ["Division", "Conditional expression", "Pointer operation", "Type casting"], correctAnswer: 1, explanation: "The ternary operator ?: is a conditional: condition ? value_if_true : value_if_false" },
    { id: 32, question: "What is the result of 5 & 3 (bitwise AND)?", options: ["8", "2", "1", "15"], correctAnswer: 2, explanation: "5 = 101, 3 = 011 in binary. AND: 101 & 011 = 001 = 1. Only bits that are 1 in both remain 1." },
    { id: 33, question: "What does '<<' do?", options: ["Comparison", "Left bit shift", "Stream insertion", "Less than twice"], correctAnswer: 1, explanation: "<< shifts bits left. x << n multiplies x by 2^n. Example: 5 << 1 = 10 (shifts bits left by 1)." },
    { id: 34, question: "What is operator precedence?", options: ["Order of variable declaration", "Order operators are evaluated", "Operator overloading", "Type of operators"], correctAnswer: 1, explanation: "Precedence determines evaluation order. * and / have higher precedence than + and -. Use parentheses when unsure." },
    { id: 35, question: "What does the comma operator do?", options: ["Separates variables only", "Evaluates left to right, returns rightmost value", "Creates arrays", "Nothing"], correctAnswer: 1, explanation: "The comma operator evaluates expressions left to right and returns the rightmost value. Example: (a=1, b=2) returns 2." },
    
    // Pointers (36-50)
    { id: 36, question: "What is a pointer?", options: ["A variable storing a value", "A variable storing a memory address", "A constant", "A function"], correctAnswer: 1, explanation: "A pointer is a variable that stores the memory address of another variable. Declared with * symbol." },
    { id: 37, question: "How do you declare a pointer to an integer?", options: ["int ptr;", "int *ptr;", "pointer int ptr;", "int &ptr;"], correctAnswer: 1, explanation: "int *ptr; declares a pointer to an integer. The * indicates it's a pointer type." },
    { id: 38, question: "What does the '&' operator return?", options: ["Value of variable", "Address of variable", "Size of variable", "Type of variable"], correctAnswer: 1, explanation: "& is the address-of operator. &x returns the memory address where x is stored." },
    { id: 39, question: "What does the '*' operator do when used with a pointer?", options: ["Multiplies", "Dereferences (gets value at address)", "Gets address", "Creates pointer"], correctAnswer: 1, explanation: "When used with a pointer, * dereferences it - retrieves the value stored at the pointed address." },
    { id: 40, question: "What is NULL?", options: ["An error value", "A pointer that points to nothing", "Zero integer", "Empty string"], correctAnswer: 1, explanation: "NULL is a null pointer constant representing a pointer that doesn't point to any valid memory location." },
    { id: 41, question: "What is pointer arithmetic?", options: ["Math with addresses", "Pointer creation", "Memory allocation", "Type casting"], correctAnswer: 0, explanation: "Pointer arithmetic allows adding/subtracting integers to pointers. ptr+1 moves to the next element based on type size." },
    { id: 42, question: "What is a void pointer?", options: ["Invalid pointer", "Generic pointer to any type", "Null pointer", "Pointer to void function"], correctAnswer: 1, explanation: "void* is a generic pointer that can point to any data type. Must be cast before dereferencing." },
    { id: 43, question: "What is the relationship between arrays and pointers?", options: ["No relationship", "Array name is a pointer to first element", "Pointers are arrays", "Arrays can't use pointers"], correctAnswer: 1, explanation: "The array name acts as a pointer to the first element. arr is equivalent to &arr[0]." },
    { id: 44, question: "What is a dangling pointer?", options: ["Uninitialized pointer", "Pointer to freed/deallocated memory", "Null pointer", "Wild pointer"], correctAnswer: 1, explanation: "A dangling pointer points to memory that has been deallocated. Accessing it causes undefined behavior." },
    { id: 45, question: "What is a double pointer (pointer to pointer)?", options: ["A pointer with double precision", "A pointer storing address of another pointer", "Two pointers", "Invalid concept"], correctAnswer: 1, explanation: "int **pp; is a pointer to a pointer. Used for 2D arrays and when functions need to modify pointer values." },
    { id: 46, question: "How do you pass an array to a function?", options: ["By value only", "By passing pointer to first element", "Arrays can't be passed", "Using special syntax"], correctAnswer: 1, explanation: "Arrays decay to pointers when passed to functions. void func(int *arr) or void func(int arr[]) both work." },
    { id: 47, question: "What is a function pointer?", options: ["Pointer returned by function", "Pointer to a function's code", "Function that returns pointer", "Invalid concept"], correctAnswer: 1, explanation: "A function pointer stores the address of a function, allowing functions to be passed as arguments or stored in arrays." },
    { id: 48, question: "What does int (*p)[10] declare?", options: ["Array of 10 pointers", "Pointer to array of 10 ints", "Invalid declaration", "10 integer pointers"], correctAnswer: 1, explanation: "int (*p)[10] is a pointer to an array of 10 integers. Compare with int *p[10] which is an array of 10 pointers." },
    { id: 49, question: "What is the 'restrict' keyword?", options: ["Limits pointer access", "Promises no aliasing for optimization", "Makes pointer read-only", "Restricts memory allocation"], correctAnswer: 1, explanation: "restrict (C99) tells compiler this pointer is the only way to access that memory, enabling optimizations." },
    { id: 50, question: "What happens when you compare two pointers?", options: ["Compilation error", "Compares memory addresses", "Compares pointed values", "Runtime error"], correctAnswer: 1, explanation: "Pointer comparison compares the memory addresses. Comparing pointers to different arrays is undefined behavior." },
    
    // Memory Management (51-60)
    { id: 51, question: "What does malloc() do?", options: ["Frees memory", "Allocates memory on heap", "Allocates memory on stack", "Initializes memory to zero"], correctAnswer: 1, explanation: "malloc() allocates a block of memory on the heap and returns a pointer to it. Memory is uninitialized." },
    { id: 52, question: "What does free() do?", options: ["Deallocates heap memory", "Frees stack memory", "Deletes variables", "Frees all program memory"], correctAnswer: 0, explanation: "free() deallocates memory previously allocated with malloc/calloc/realloc. Using freed memory is undefined behavior." },
    { id: 53, question: "What is the difference between malloc() and calloc()?", options: ["No difference", "calloc initializes to zero", "malloc is faster", "calloc allocates on stack"], correctAnswer: 1, explanation: "calloc(n, size) allocates n*size bytes and initializes all to zero. malloc() leaves memory uninitialized." },
    { id: 54, question: "What does realloc() do?", options: ["Reallocates memory with new size", "Frees and reallocates", "Only increases size", "Creates new allocation"], correctAnswer: 0, explanation: "realloc() changes the size of previously allocated memory, potentially moving it to a new location." },
    { id: 55, question: "What is a memory leak?", options: ["Memory corruption", "Failure to free allocated memory", "Accessing freed memory", "Stack overflow"], correctAnswer: 1, explanation: "A memory leak occurs when allocated memory is no longer referenced but not freed, wasting resources." },
    { id: 56, question: "What is the stack vs heap?", options: ["Same thing", "Stack=automatic, Heap=dynamic allocation", "Heap=automatic, Stack=dynamic", "Stack is larger"], correctAnswer: 1, explanation: "Stack holds local variables (automatic), heap is for dynamic allocation (malloc). Stack is LIFO, faster but smaller." },
    { id: 57, question: "What causes a segmentation fault?", options: ["Syntax error", "Accessing invalid memory", "Division by zero", "Type mismatch"], correctAnswer: 1, explanation: "Segfault occurs when accessing memory the program doesn't have permission to access - null pointers, freed memory, etc." },
    { id: 58, question: "What is buffer overflow?", options: ["Too much printf output", "Writing beyond allocated memory", "Memory leak", "Stack underflow"], correctAnswer: 1, explanation: "Buffer overflow writes data beyond the allocated buffer bounds, potentially overwriting other data or return addresses." },
    { id: 59, question: "What header file contains malloc()?", options: ["<stdio.h>", "<string.h>", "<stdlib.h>", "<memory.h>"], correctAnswer: 2, explanation: "<stdlib.h> contains malloc(), free(), calloc(), realloc() and other general utility functions." },
    { id: 60, question: "Why should you check malloc's return value?", options: ["To get size", "To detect allocation failure (NULL)", "To initialize memory", "It's optional"], correctAnswer: 1, explanation: "malloc returns NULL if allocation fails (out of memory). Using NULL pointer causes crashes." },
    
    // Structures & Functions (61-70)
    { id: 61, question: "How do you define a structure?", options: ["class { }", "struct name { }", "structure name { }", "type name { }"], correctAnswer: 1, explanation: "struct keyword defines a structure: struct Point { int x; int y; }; Groups related variables together." },
    { id: 62, question: "How do you access a structure member?", options: ["structure->member", "structure.member", "structure[member]", "structure:member"], correctAnswer: 1, explanation: "Use dot notation: variable.member. Use arrow -> for pointer to structure: ptr->member (same as (*ptr).member)." },
    { id: 63, question: "What is a union in C?", options: ["Same as struct", "Members share same memory", "Collection of structs", "Type of array"], correctAnswer: 1, explanation: "A union's members share the same memory location. Only one member can hold a value at a time. Size equals largest member." },
    { id: 64, question: "What is 'pass by value' in C?", options: ["Passing pointer", "Passing copy of value", "Passing reference", "Passing array"], correctAnswer: 1, explanation: "C passes arguments by value - function receives a copy. To modify original, pass pointer to it." },
    { id: 65, question: "What is function prototype?", options: ["Function body", "Function declaration before use", "Function pointer", "Main function"], correctAnswer: 1, explanation: "A prototype declares a function's return type, name, and parameters before its actual definition. Enables forward references." },
    { id: 66, question: "What is recursion?", options: ["Loop type", "Function calling itself", "Goto statement", "Nested functions"], correctAnswer: 1, explanation: "Recursion is when a function calls itself. Requires a base case to prevent infinite recursion and stack overflow." },
    { id: 67, question: "What is 'static' for a local variable?", options: ["Makes it global", "Preserves value between calls", "Makes it constant", "Allocates on heap"], correctAnswer: 1, explanation: "static local variables retain their value between function calls. They're initialized only once." },
    { id: 68, question: "What is 'extern' used for?", options: ["External function", "Declaration of variable defined elsewhere", "External library", "Export variable"], correctAnswer: 1, explanation: "extern declares a variable that is defined in another file or later in the same file." },
    { id: 69, question: "What is the purpose of header files?", options: ["Store code", "Share declarations across files", "Compile faster", "Debug code"], correctAnswer: 1, explanation: "Header files (.h) contain declarations (prototypes, macros, types) shared across multiple source files." },
    { id: 70, question: "What does 'inline' suggest to compiler?", options: ["Ignore function", "Replace call with function body", "Make function static", "Optimize loops"], correctAnswer: 1, explanation: "inline suggests the compiler replace function calls with the function body to reduce call overhead. It's a hint, not a command." },
    
    // Advanced Topics (71-75)
    { id: 71, question: "What is the volatile keyword used for?", options: ["Fast variables", "Variables that may change unexpectedly", "Constant variables", "Global variables"], correctAnswer: 1, explanation: "volatile tells compiler the variable may change outside program control (hardware registers, signal handlers). Prevents optimization." },
    { id: 72, question: "What is bit-field in structures?", options: ["Array of bits", "Specifying exact bits for members", "Binary operations", "Bit masking"], correctAnswer: 1, explanation: "Bit-fields allow specifying exact number of bits for struct members: struct { unsigned flag : 1; }; Useful for hardware/protocols." },
    { id: 73, question: "What does #pragma once do?", options: ["Execute once", "Include guard for headers", "Define macro", "Optimize code"], correctAnswer: 1, explanation: "#pragma once is a non-standard but widely supported include guard that ensures a header is included only once." },
    { id: 74, question: "What is the purpose of assert()?", options: ["Error handling", "Debug-time condition checking", "Unit testing", "Memory check"], correctAnswer: 1, explanation: "assert() checks conditions during debugging. If false, it prints error and aborts. Disabled in release builds with NDEBUG." },
    { id: 75, question: "What is the difference between #include <> and #include \"\"?", options: ["No difference", "<> for system, \"\" for local headers", "\"\" for system, <> for local", "<> is deprecated"], correctAnswer: 1, explanation: "<file> searches system include paths first. \"file\" searches current directory first, then system paths." },
  ];

  // Fisher-Yates shuffle algorithm
  const shuffleArray = <T,>(array: T[]): T[] => {
    const newArray = [...array];
    for (let i = newArray.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [newArray[i], newArray[j]] = [newArray[j], newArray[i]];
    }
    return newArray;
  };

  // Quiz Component
  const CQuiz = () => {
    const [quizStarted, setQuizStarted] = useState(false);
    const [currentQuestion, setCurrentQuestion] = useState(0);
    const [selectedAnswers, setSelectedAnswers] = useState<number[]>([]);
    const [showResults, setShowResults] = useState(false);
    const [quizQuestions, setQuizQuestions] = useState<QuizQuestion[]>([]);

    const startQuiz = () => {
      const shuffled = shuffleArray(cQuestionBank);
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
      if (s === 10) return "Perfect! You're a C Master! 🏆";
      if (s >= 8) return "Excellent! You know C very well! 🌟";
      if (s >= 6) return "Good job! Keep practicing! 📚";
      if (s >= 4) return "Not bad, room for improvement! 💪";
      return "Keep studying! C takes time to master! 🔧";
    };

    if (!quizStarted) {
      return (
        <Paper
          id="quiz"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha(accentColor, 0.1)} 0%, ${alpha(accentDark, 0.1)} 100%)`,
            border: `1px solid ${alpha(accentColor, 0.2)}`,
            textAlign: "center",
          }}
        >
          <Avatar sx={{ bgcolor: accentColor, width: 64, height: 64, mx: "auto", mb: 2 }}>
            <QuizIcon sx={{ fontSize: 32 }} />
          </Avatar>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 2 }}>
            C Programming Knowledge Quiz
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 500, mx: "auto" }}>
            Test your C knowledge with 10 randomly selected questions from our 75-question bank covering 
            syntax, pointers, memory management, structures, and more!
          </Typography>
          <Button
            variant="contained"
            size="large"
            onClick={startQuiz}
            startIcon={<QuizIcon />}
            sx={{
              bgcolor: accentColor,
              "&:hover": { bgcolor: accentDark },
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
              sx={{ bgcolor: accentColor, "&:hover": { bgcolor: accentDark } }}
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
            C Programming Quiz
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
              sx={{ bgcolor: accentColor, "&:hover": { bgcolor: accentDark } }}
            >
              Submit Quiz
            </Button>
          ) : (
            <Button
              variant="contained"
              onClick={handleNext}
              sx={{ bgcolor: accentColor, "&:hover": { bgcolor: accentDark } }}
            >
              Next
            </Button>
          )}
        </Box>
      </Paper>
    );
  };

  return (
    <LearnPageLayout pageTitle="C Programming Fundamentals" pageContext={pageContext}>
      {/* Mobile FABs */}
      <Tooltip title="Navigate Sections" placement="left">
        <Fab
          color="primary"
          onClick={() => setNavDrawerOpen(true)}
          sx={{
            position: "fixed",
            bottom: 90,
            right: 24,
            zIndex: 1000,
            bgcolor: accentColor,
            color: "#fff",
            "&:hover": { bgcolor: accentDark },
            boxShadow: `0 4px 20px ${alpha(accentColor, 0.4)}`,
            display: { xs: "flex", lg: "none" },
          }}
        >
          <ListAltIcon />
        </Fab>
      </Tooltip>

      <Tooltip title="Scroll to Top" placement="left">
        <Fab
          size="small"
          onClick={scrollToTop}
          sx={{
            position: "fixed",
            bottom: 32,
            right: 28,
            zIndex: 1000,
            bgcolor: alpha(accentColor, 0.15),
            color: accentColor,
            "&:hover": { bgcolor: alpha(accentColor, 0.25) },
            display: { xs: "flex", lg: "none" },
          }}
        >
          <KeyboardArrowUpIcon />
        </Fab>
      </Tooltip>

      {/* Mobile Drawer */}
      <Drawer
        anchor="right"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        PaperProps={{ sx: { width: isMobile ? "85%" : 320, bgcolor: theme.palette.background.paper } }}
      >
        <Box sx={{ p: 2 }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700 }}>
              <ListAltIcon sx={{ color: accentColor, mr: 1, verticalAlign: "middle" }} />
              Navigation
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
                  bgcolor: activeSection === item.id ? alpha(accentColor, 0.15) : "transparent",
                  "&:hover": { bgcolor: alpha(accentColor, 0.1) },
                }}
              >
                <ListItemIcon sx={{ minWidth: 32 }}>{item.icon}</ListItemIcon>
                <ListItemText primary={item.label} />
              </ListItem>
            ))}
          </List>
        </Box>
      </Drawer>

      {/* Main Layout */}
      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, sm: 3 }, py: 4 }}>
        {sidebarNav}

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

          {/* Hero Section */}
          <Paper
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              background: `linear-gradient(135deg, ${alpha(accentColor, 0.15)} 0%, ${alpha("#1a237e", 0.1)} 100%)`,
              border: `1px solid ${alpha(accentColor, 0.2)}`,
              position: "relative",
              overflow: "hidden",
            }}
          >
            <Box sx={{ position: "relative", zIndex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
                <Box
                  sx={{
                    width: 80,
                    height: 80,
                    borderRadius: 3,
                    background: `linear-gradient(135deg, ${accentColor}, #1a237e)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    boxShadow: `0 8px 32px ${alpha(accentColor, 0.35)}`,
                  }}
                >
                  <Typography sx={{ fontSize: 32, fontWeight: 900, color: "#fff" }}>C</Typography>
                </Box>
                <Box>
                  <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                    C Programming
                  </Typography>
                  <Typography variant="h6" color="text.secondary">
                    Master the foundation of modern computing
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
                        borderRadius: 2,
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
                {["Low-Level Access", "Memory Control", "Pointers", "System Programming", "Embedded Systems", "Performance"].map((tag) => (
                  <Chip key={tag} label={tag} size="small" sx={{ bgcolor: alpha(accentColor, 0.15), fontWeight: 500 }} />
                ))}
              </Box>
            </Box>
          </Paper>

          {/* Introduction Section - Detailed Description */}
          <Paper id="introduction" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha(accentColor, 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2,
                  bgcolor: alpha(accentColor, 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: accentColor,
                }}
              >
                <SchoolIcon />
              </Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Introduction to C Programming
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              <strong>C</strong> is one of the most influential and foundational programming languages ever created. Developed in 1972 by 
              Dennis Ritchie at Bell Labs, C was designed to provide low-level access to memory while maintaining high-level language 
              constructs. This unique combination made it the language of choice for developing operating systems, with Unix being the 
              first major OS written almost entirely in C. Today, C remains the backbone of modern computing—from operating systems 
              like Linux, Windows, and macOS to embedded systems, database engines, and countless critical infrastructure components.
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Understanding C is essential for any serious programmer, especially those interested in <strong>systems programming</strong>, 
              <strong> cybersecurity</strong>, <strong>reverse engineering</strong>, or <strong>embedded development</strong>. C provides 
              direct access to memory through pointers, allows precise control over hardware resources, and produces highly efficient 
              compiled code. Many modern languages—including C++, Java, Python, and Rust—have been heavily influenced by C's syntax 
              and concepts. Learning C will deepen your understanding of how computers actually work at the hardware level, how memory 
              is organized, and how programs interact with the operating system.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Why Learn C Programming?
            </Typography>

            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2, mb: 2 }}>
                  <MemoryIcon sx={{ color: accentColor, mt: 0.5 }} />
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                      Direct Memory Access
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      C gives you direct control over memory allocation and manipulation through pointers. You decide exactly 
                      where and how data is stored, enabling optimization at the byte level. This is crucial for writing 
                      high-performance code and understanding memory vulnerabilities like buffer overflows.
                    </Typography>
                  </Box>
                </Box>
              </Grid>

              <Grid item xs={12} md={6}>
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2, mb: 2 }}>
                  <SpeedIcon sx={{ color: "#26a69a", mt: 0.5 }} />
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                      Unmatched Performance
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      C compiles directly to machine code with minimal runtime overhead. There's no garbage collector, 
                      no virtual machine, and no interpreter slowing things down. This makes C ideal for performance-critical 
                      applications like operating systems, game engines, and real-time systems.
                    </Typography>
                  </Box>
                </Box>
              </Grid>

              <Grid item xs={12} md={6}>
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2, mb: 2 }}>
                  <DeveloperBoardIcon sx={{ color: "#ff9800", mt: 0.5 }} />
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                      Systems & Embedded Programming
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      C is the dominant language for embedded systems, microcontrollers, and hardware interfaces. 
                      From Arduino to industrial PLCs, from car ECUs to medical devices, C's ability to interface 
                      directly with hardware makes it indispensable in the embedded world.
                    </Typography>
                  </Box>
                </Box>
              </Grid>

              <Grid item xs={12} md={6}>
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2, mb: 2 }}>
                  <SecurityIcon sx={{ color: "#ef5350", mt: 0.5 }} />
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                      Security & Reverse Engineering
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Understanding C is essential for security professionals. Most exploits target C programs, 
                      and understanding memory corruption, buffer overflows, and format string vulnerabilities 
                      requires deep knowledge of how C manages memory and data.
                    </Typography>
                  </Box>
                </Box>
              </Grid>
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              The History and Evolution of C
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              C evolved from an earlier language called <strong>B</strong>, which itself was derived from <strong>BCPL</strong> 
              (Basic Combined Programming Language). Dennis Ritchie developed C between 1969 and 1973 at Bell Labs as part of 
              the effort to create the Unix operating system. The language was designed to be portable, efficient, and capable 
              of expressing operations that previously required assembly language.
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              In 1978, Brian Kernighan and Dennis Ritchie published "The C Programming Language," commonly known as <strong>K&R C</strong>. 
              This book became the de facto standard for C programming and influenced countless programmers. The language was 
              later standardized by ANSI in 1989 (<strong>C89/ANSI C</strong>) and by ISO in 1990 (<strong>C90</strong>). 
              Subsequent standards include <strong>C99</strong> (1999), <strong>C11</strong> (2011), <strong>C17</strong> (2018), 
              and the latest <strong>C23</strong> (2024), each adding new features while maintaining backward compatibility.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColor, 0.05), border: `1px solid ${alpha(accentColor, 0.15)}`, mb: 3 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: accentColor }}>
                📚 C Standards Timeline
              </Typography>
              <Grid container spacing={2}>
                {[
                  { year: "1972", name: "Original C", desc: "Created by Dennis Ritchie at Bell Labs" },
                  { year: "1978", name: "K&R C", desc: "The C Programming Language book published" },
                  { year: "1989", name: "ANSI C (C89)", desc: "First official ANSI standard" },
                  { year: "1999", name: "C99", desc: "Inline functions, variable-length arrays, // comments" },
                  { year: "2011", name: "C11", desc: "Multi-threading support, anonymous structs" },
                  { year: "2018", name: "C17", desc: "Bug fixes and clarifications to C11" },
                  { year: "2024", name: "C23", desc: "Improved type inference, constexpr, attributes" },
                ].map((item) => (
                  <Grid item xs={12} sm={6} md={4} key={item.year}>
                    <Box sx={{ display: "flex", gap: 1 }}>
                      <Typography variant="body2" sx={{ fontWeight: 700, color: accentColor, minWidth: 45 }}>
                        {item.year}
                      </Typography>
                      <Box>
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>{item.name}</Typography>
                        <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                      </Box>
                    </Box>
                  </Grid>
                ))}
              </Grid>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Where C is Used Today
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Despite being over 50 years old, C remains one of the most widely used programming languages in the world. 
              Its influence is everywhere:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { title: "Operating Systems", desc: "Linux kernel, Windows kernel, macOS/iOS kernel (XNU), FreeBSD, and virtually all Unix variants", icon: <TerminalIcon /> },
                { title: "Databases", desc: "MySQL, PostgreSQL, SQLite, Redis, and most high-performance database engines", icon: <StorageIcon /> },
                { title: "Compilers & Interpreters", desc: "GCC, Clang, Python (CPython), Ruby (MRI), PHP, and many language runtimes", icon: <BuildIcon /> },
                { title: "Embedded Systems", desc: "Automotive ECUs, medical devices, IoT sensors, industrial controllers, aerospace systems", icon: <DeveloperBoardIcon /> },
                { title: "Network Infrastructure", desc: "Apache, Nginx, OpenSSL, curl, and most networking stacks and protocols", icon: <SecurityIcon /> },
                { title: "Game Engines", desc: "Portions of Unity, Unreal Engine, and many physics/graphics libraries", icon: <SpeedIcon /> },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(accentColor, 0.05), height: "100%" }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Box sx={{ color: accentColor }}>{item.icon}</Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              C for Security Professionals
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              For cybersecurity professionals, understanding C is not optional—it's essential. The vast majority of 
              security vulnerabilities occur in C and C++ code due to their manual memory management. Understanding 
              these concepts at a deep level is crucial for:
            </Typography>

            <List>
              {[
                { primary: "Exploit Development", secondary: "Buffer overflows, heap exploitation, format string attacks, and use-after-free vulnerabilities are all rooted in C's memory model" },
                { primary: "Reverse Engineering", secondary: "Decompiled code from IDA Pro, Ghidra, and Binary Ninja produces C-like pseudocode. Reading this requires C fluency" },
                { primary: "Malware Analysis", secondary: "Most malware is written in C/C++ for its low-level capabilities and small binary size" },
                { primary: "Vulnerability Research", secondary: "Finding and understanding CVEs in operating systems, browsers, and applications requires C knowledge" },
                { primary: "Tool Development", secondary: "Security tools like Nmap, Metasploit modules, and custom implants often require C for performance and stealth" },
              ].map((item, index) => (
                <ListItem key={index} sx={{ py: 0.5 }}>
                  <ListItemIcon>
                    <CheckCircleIcon sx={{ color: accentColor }} />
                  </ListItemIcon>
                  <ListItemText
                    primary={<Typography sx={{ fontWeight: 600 }}>{item.primary}</Typography>}
                    secondary={item.secondary}
                  />
                </ListItem>
              ))}
            </List>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              What You'll Learn in This Course
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              This comprehensive C programming course will take you from the basics of syntax and compilation through 
              advanced topics like dynamic memory management, file I/O, and system-level programming. You'll learn:
            </Typography>

            <Grid container spacing={2}>
              {[
                "Environment setup with GCC, Clang, and debugging tools",
                "Variables, data types, and type conversions",
                "Operators, expressions, and operator precedence",
                "Control flow: conditionals, loops, and branching",
                "Functions, parameters, return values, and recursion",
                "Arrays: declaration, initialization, and multidimensional arrays",
                "Pointers: memory addresses, dereferencing, and pointer arithmetic",
                "String handling with the C standard library",
                "Structures, unions, enumerations, and typedef",
                "Dynamic memory allocation: malloc, calloc, realloc, free",
                "File operations: opening, reading, writing, and seeking",
                "The preprocessor: macros, conditional compilation, and includes",
                "Advanced topics: bitwise operations, function pointers, and inline assembly",
              ].map((topic, index) => (
                <Grid item xs={12} sm={6} key={index}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <CheckCircleIcon sx={{ color: accentColor, fontSize: 18 }} />
                    <Typography variant="body2">{topic}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>

            <Paper 
              sx={{ 
                p: 3, 
                mt: 4, 
                borderRadius: 2, 
                bgcolor: alpha("#4caf50", 0.1), 
                border: `1px solid ${alpha("#4caf50", 0.3)}` 
              }}
            >
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon sx={{ color: "#4caf50" }} />
                Prerequisites
              </Typography>
              <Typography variant="body2" color="text.secondary">
                No prior C experience is required, but familiarity with basic programming concepts (variables, loops, 
                functions) in any language will be helpful. You should be comfortable using the command line for 
                compilation and basic file operations.
              </Typography>
            </Paper>
          </Paper>

          {/* Placeholder Sections */}
          <TopicPlaceholder
            id="setup"
            title="Environment Setup"
            icon={<BuildIcon />}
            color="#26a69a"
            description="Learn how to set up your C development environment with GCC/Clang compilers, Make build system, debuggers (GDB), and IDEs like VS Code, CLion, or Code::Blocks. We'll cover installation on Windows, macOS, and Linux."
          />

          <TopicPlaceholder
            id="basics"
            title="C Basics & Syntax"
            icon={<CodeIcon />}
            color={accentColor}
            description="Master the fundamental syntax of C: program structure, the main() function, statements and expressions, comments, compilation process, and your first Hello World program. Understand how C code becomes an executable."
          />

          <TopicPlaceholder
            id="variables"
            title="Variables & Data Types"
            icon={<StorageIcon />}
            color="#ff9800"
            description="Deep dive into C's type system: int, char, float, double, long, short, signed, unsigned. Learn about type sizes, type qualifiers (const, volatile), type conversions, and the sizeof operator."
          />

          <TopicPlaceholder
            id="operators"
            title="Operators & Expressions"
            icon={<TerminalIcon />}
            color="#e91e63"
            description="Explore arithmetic, relational, logical, bitwise, assignment, and ternary operators. Understand operator precedence and associativity, and learn how to write clear, efficient expressions."
          />

          <TopicPlaceholder
            id="control-flow"
            title="Control Flow"
            icon={<CodeIcon />}
            color="#9c27b0"
            description="Master decision-making with if-else, switch-case, and the ternary operator. Learn loops: for, while, do-while, and control statements like break, continue, and goto."
          />

          <TopicPlaceholder
            id="functions"
            title="Functions"
            icon={<BuildIcon />}
            color="#2196f3"
            description="Learn function declaration, definition, parameters, return values, and prototypes. Explore pass-by-value vs pass-by-reference, recursion, inline functions, and variadic functions."
          />

          <TopicPlaceholder
            id="arrays"
            title="Arrays"
            icon={<StorageIcon />}
            color="#00bcd4"
            description="Understand array declaration, initialization, and access. Learn about multidimensional arrays, array-pointer relationship, passing arrays to functions, and variable-length arrays (VLAs)."
          />

          <TopicPlaceholder
            id="pointers"
            title="Pointers"
            icon={<MemoryIcon />}
            color="#f44336"
            description="Master the most powerful feature of C: pointers. Learn memory addresses, dereferencing, pointer arithmetic, pointers to pointers, NULL pointers, and common pointer pitfalls."
          />

          <TopicPlaceholder
            id="strings"
            title="Strings"
            icon={<CodeIcon />}
            color="#8bc34a"
            description="Work with character arrays and string literals. Learn string manipulation functions: strlen, strcpy, strcat, strcmp, strchr, and safe alternatives. Understand null termination and buffer management."
          />

          <TopicPlaceholder
            id="structs"
            title="Structures & Unions"
            icon={<DeveloperBoardIcon />}
            color="#673ab7"
            description="Create custom data types with structures. Learn about unions, enumerations, typedef, nested structures, bit fields, and memory alignment. Understand how to design efficient data structures."
          />

          <TopicPlaceholder
            id="memory"
            title="Dynamic Memory Management"
            icon={<MemoryIcon />}
            color="#ff5722"
            description="Master malloc, calloc, realloc, and free. Learn about the heap vs stack, memory leaks, dangling pointers, double-free vulnerabilities, and best practices for memory safety."
          />

          <TopicPlaceholder
            id="file-io"
            title="File I/O"
            icon={<StorageIcon />}
            color="#607d8b"
            description="Learn file operations: fopen, fclose, fread, fwrite, fprintf, fscanf, fgets, fputs. Understand file modes, text vs binary files, file positioning with fseek/ftell, and error handling."
          />

          <TopicPlaceholder
            id="preprocessor"
            title="The C Preprocessor"
            icon={<BuildIcon />}
            color="#795548"
            description="Understand preprocessing directives: #include, #define, #ifdef, #ifndef, #pragma. Learn macro functions, conditional compilation, header guards, and include path management."
          />

          <TopicPlaceholder
            id="advanced"
            title="Advanced Topics"
            icon={<BugReportIcon />}
            color="#3f51b5"
            description="Explore advanced concepts: function pointers, void pointers, volatile keyword, inline assembly, memory-mapped I/O, signal handling, and interfacing with assembly language."
          />

          {/* C Quiz Section */}
          <CQuiz />

          {/* Next Steps */}
          <Paper sx={{ p: 4, borderRadius: 4, border: `1px solid ${alpha(accentColor, 0.2)}` }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 2 }}>
              Continue Your Journey
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              After mastering C fundamentals, explore related topics to expand your skills:
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              {[
                { label: "Assembly Language", path: "/learn/assembly" },
                { label: "Buffer Overflows", path: "/learn/buffer-overflow" },
                { label: "Heap Exploitation", path: "/learn/heap-exploitation" },
                { label: "Reverse Engineering", path: "/learn/intro-to-re" },
                { label: "Linux Internals", path: "/learn/linux-internals" },
                { label: "Windows Internals", path: "/learn/windows-internals" },
              ].map((item) => (
                <Chip
                  key={item.label}
                  label={item.label}
                  onClick={() => navigate(item.path)}
                  sx={{ cursor: "pointer", fontWeight: 600, "&:hover": { bgcolor: alpha(accentColor, 0.15) } }}
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
