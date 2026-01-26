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

          {/* Environment Setup Section */}
          <Paper id="setup" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#26a69a", 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2,
                  bgcolor: alpha("#26a69a", 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#26a69a",
                }}
              >
                <BuildIcon />
              </Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Environment Setup
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Before you can write and run C programs, you need to set up a proper development environment. Unlike interpreted 
              languages like Python or JavaScript, C is a <strong>compiled language</strong>—your source code must be translated 
              into machine code by a compiler before it can be executed. This section will guide you through setting up all the 
              tools you need for professional C development on any operating system.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3, color: "#26a69a" }}>
              The C Compilation Toolchain
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              When you're developing in C, you'll work with several interconnected tools that form your <strong>toolchain</strong>:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { title: "Compiler", desc: "Translates C source code (.c files) into object files (.o). Popular choices include GCC (GNU Compiler Collection), Clang/LLVM, and MSVC (Microsoft Visual C++).", icon: "🔨" },
                { title: "Assembler", desc: "Converts assembly language output from the compiler into machine code. Usually invoked automatically by the compiler.", icon: "⚙️" },
                { title: "Linker", desc: "Combines object files and libraries into a final executable. Resolves function references between different files and libraries.", icon: "🔗" },
                { title: "Debugger", desc: "Allows you to step through code, set breakpoints, and inspect variables. GDB is the standard on Linux/macOS, while LLDB is used with Clang.", icon: "🔍" },
                { title: "Build System", desc: "Automates the compilation process. Make is the traditional choice, while CMake is a modern cross-platform alternative.", icon: "📦" },
                { title: "Text Editor/IDE", desc: "Where you write your code. VS Code, CLion, Vim, and Emacs are popular choices with excellent C support.", icon: "📝" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#26a69a", 0.05), height: "100%" }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Typography sx={{ fontSize: 20 }}>{item.icon}</Typography>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#26a69a" }}>
              Installation by Operating System
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#2196f3", 0.05), border: `1px solid ${alpha("#2196f3", 0.2)}`, mb: 2 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                🐧 Linux (Ubuntu/Debian)
              </Typography>
              <Typography variant="body2" paragraph sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1 }}>
                {`# Install essential build tools
sudo apt update
sudo apt install build-essential gdb

# Verify installation
gcc --version
gdb --version

# Optional: Install Clang
sudo apt install clang lldb`}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                The <code>build-essential</code> meta-package installs GCC, G++, Make, and other essential development tools. 
                This is the quickest way to get a complete C/C++ development environment on Debian-based distributions.
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#f5f5f5", 0.5), border: `1px solid ${alpha("#666", 0.2)}`, mb: 2 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                🍎 macOS
              </Typography>
              <Typography variant="body2" paragraph sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1 }}>
                {`# Install Xcode Command Line Tools
xcode-select --install

# Verify installation (this installs Clang, not GCC)
clang --version
lldb --version

# Optional: Install GCC via Homebrew
brew install gcc gdb`}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                macOS uses Clang as its default compiler (aliased as <code>gcc</code>). The Xcode Command Line Tools provide 
                everything you need. Note that GDB requires code signing on macOS; LLDB is often easier to use.
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#00a4ef", 0.05), border: `1px solid ${alpha("#00a4ef", 0.2)}`, mb: 2 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                🪟 Windows
              </Typography>
              <Typography variant="body2" paragraph sx={{ lineHeight: 1.8 }}>
                Windows has several options for C development:
              </Typography>
              <List dense>
                <ListItem>
                  <ListItemText
                    primary={<Typography sx={{ fontWeight: 600 }}>MinGW-w64 (Recommended for beginners)</Typography>}
                    secondary="A native Windows port of GCC. Download from mingw-w64.org or use MSYS2 for easier package management."
                  />
                </ListItem>
                <ListItem>
                  <ListItemText
                    primary={<Typography sx={{ fontWeight: 600 }}>WSL (Windows Subsystem for Linux)</Typography>}
                    secondary="Run a full Linux environment inside Windows. Gives you access to all Linux tools including GCC and GDB."
                  />
                </ListItem>
                <ListItem>
                  <ListItemText
                    primary={<Typography sx={{ fontWeight: 600 }}>Visual Studio (MSVC)</Typography>}
                    secondary="Microsoft's full IDE with the MSVC compiler. Best integration with Windows but different from GCC in some ways."
                  />
                </ListItem>
              </List>
              <Typography variant="body2" sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1 }}>
                {`# Using MSYS2 (recommended for MinGW)
pacman -S mingw-w64-ucrt-x86_64-gcc
pacman -S mingw-w64-ucrt-x86_64-gdb

# Or using WSL
wsl --install
# Then follow Linux instructions inside WSL`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#26a69a" }}>
              Your First Compilation
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Let's verify your setup by compiling a simple program. Create a file called <code>hello.c</code>:
            </Typography>

            <Typography variant="body2" sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, mb: 2 }}>
              {`#include <stdio.h>

int main(void) {
    printf("Hello, World!\\n");
    return 0;
}`}
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Now compile and run it:
            </Typography>

            <Typography variant="body2" sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, mb: 2 }}>
              {`# Basic compilation
gcc hello.c -o hello

# Run the program
./hello          # Linux/macOS
hello.exe        # Windows

# Compilation with warnings and debugging info (recommended)
gcc -Wall -Wextra -g hello.c -o hello`}
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#26a69a", 0.08) }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Common GCC Flags</Typography>
                  <Typography variant="body2" component="div">
                    <code>-Wall</code>: Enable common warnings<br />
                    <code>-Wextra</code>: Enable extra warnings<br />
                    <code>-g</code>: Include debugging symbols<br />
                    <code>-O2</code>: Optimize for speed<br />
                    <code>-o name</code>: Name the output file<br />
                    <code>-c</code>: Compile only, don't link
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ff9800", 0.08) }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>The Compilation Process</Typography>
                  <Typography variant="body2" component="div">
                    1. <strong>Preprocessing</strong>: Process #include, #define<br />
                    2. <strong>Compilation</strong>: C → Assembly<br />
                    3. <strong>Assembly</strong>: Assembly → Object code<br />
                    4. <strong>Linking</strong>: Object files → Executable
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#26a69a" }}>
              IDE and Editor Setup
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              While you can write C code in any text editor, a good IDE or editor with proper configuration will dramatically 
              improve your productivity. Here are recommended setups:
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#26a69a", 0.2)}`, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>VS Code (Free)</Typography>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    Install the "C/C++" extension by Microsoft. Also install "Code Runner" for quick compilation. 
                    Configure tasks.json for custom build commands.
                  </Typography>
                  <Chip label="Best for beginners" size="small" sx={{ bgcolor: alpha("#4caf50", 0.15), color: "#4caf50" }} />
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#26a69a", 0.2)}`, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>CLion (Paid)</Typography>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    JetBrains IDE with excellent CMake integration, smart code completion, refactoring tools, and 
                    built-in debugging. Free for students.
                  </Typography>
                  <Chip label="Best for large projects" size="small" sx={{ bgcolor: alpha("#2196f3", 0.15), color: "#2196f3" }} />
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#26a69a", 0.2)}`, height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Vim/Neovim</Typography>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    Powerful terminal-based editors. Use with coc.nvim or clangd for code intelligence. Perfect for 
                    remote development and embedded work.
                  </Typography>
                  <Chip label="Best for power users" size="small" sx={{ bgcolor: alpha("#9c27b0", 0.15), color: "#9c27b0" }} />
                </Paper>
              </Grid>
            </Grid>

            <Paper sx={{ p: 3, mt: 3, borderRadius: 2, bgcolor: alpha("#4caf50", 0.1), border: `1px solid ${alpha("#4caf50", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon sx={{ color: "#4caf50" }} />
                Pro Tip: Always Enable Warnings!
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Always compile with <code>-Wall -Wextra</code> (GCC/Clang) or <code>/W4</code> (MSVC). Compiler warnings 
                catch many bugs before they become runtime errors. For even stricter checking, add <code>-Werror</code> to 
                treat warnings as errors. Many professional codebases require zero-warning builds.
              </Typography>
            </Paper>
          </Paper>

          {/* C Basics Section */}
          <Paper id="basics" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha(accentColor, 0.2)}` }}>
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
                <CodeIcon />
              </Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                C Basics & Syntax
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Understanding C's fundamental syntax and program structure is essential before diving into more complex topics. 
              C is a <strong>procedural programming language</strong>, which means programs are structured as sequences of 
              procedures (functions) that operate on data. Unlike object-oriented languages, C doesn't have classes or 
              inheritance—instead, it emphasizes simplicity, efficiency, and direct control over the machine.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3, color: accentColor }}>
              Anatomy of a C Program
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Every C program follows a consistent structure. Let's break down the components:
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`/* File: example.c
 * This is a multi-line comment explaining the program
 */

#include <stdio.h>    // Preprocessor directive: includes standard I/O library
#include <stdlib.h>   // Standard library functions (malloc, exit, etc.)

#define MAX_SIZE 100  // Preprocessor macro: constant definition

// Global variable (use sparingly!)
int globalCounter = 0;

// Function prototype (declaration)
void greetUser(const char *name);

// Main function: entry point of the program
int main(int argc, char *argv[]) {
    // Local variable declarations
    int number = 42;
    char message[] = "Hello";
    
    // Function call
    greetUser("Alice");
    
    // Print output
    printf("Number: %d\\n", number);
    
    return 0;  // Return success to operating system
}

// Function definition
void greetUser(const char *name) {
    printf("Welcome, %s!\\n", name);
}`}
              </Typography>
            </Paper>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { title: "Preprocessor Directives", desc: "Lines starting with # are processed before compilation. #include inserts header files, #define creates macros.", color: "#e91e63" },
                { title: "Comments", desc: "// for single-line (C99+), /* */ for multi-line. Comments are ignored by the compiler but essential for documentation.", color: "#9c27b0" },
                { title: "The main() Function", desc: "Every C program must have exactly one main() function. This is where execution begins. It returns an int: 0 for success.", color: "#2196f3" },
                { title: "Statements", desc: "Instructions that perform actions. Most statements end with a semicolon (;). Compound statements are enclosed in { }.", color: "#26a69a" },
                { title: "Functions", desc: "Reusable blocks of code that perform specific tasks. They have a return type, name, parameters, and body.", color: "#ff9800" },
                { title: "Variables", desc: "Named storage locations for data. Must be declared with a type before use. Scope determines where they're accessible.", color: "#f44336" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(item.color, 0.05), borderLeft: `4px solid ${item.color}`, height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5, color: item.color }}>{item.title}</Typography>
                    <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              The Compilation Process Explained
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              When you compile a C program, it goes through four distinct stages. Understanding this process helps you 
              debug compilation errors and understand how your code becomes an executable:
            </Typography>

            <Box sx={{ display: "flex", flexDirection: { xs: "column", md: "row" }, gap: 2, mb: 3, alignItems: "stretch" }}>
              {[
                { step: 1, title: "Preprocessing", desc: "The preprocessor handles all # directives. It expands macros, includes header files, and removes comments. Output: translated source code.", cmd: "gcc -E file.c -o file.i" },
                { step: 2, title: "Compilation", desc: "The compiler translates C code into assembly language for your target CPU. This is where syntax errors and type mismatches are caught.", cmd: "gcc -S file.c -o file.s" },
                { step: 3, title: "Assembly", desc: "The assembler converts assembly code into machine code (object file). Each .c file becomes a .o file containing binary instructions.", cmd: "gcc -c file.c -o file.o" },
                { step: 4, title: "Linking", desc: "The linker combines object files with libraries to create the final executable. Resolves function/variable references across files.", cmd: "gcc file.o -o program" },
              ].map((item) => (
                <Paper key={item.step} sx={{ flex: 1, p: 2, borderRadius: 2, bgcolor: alpha(accentColor, 0.05), textAlign: "center" }}>
                  <Avatar sx={{ bgcolor: accentColor, width: 36, height: 36, mx: "auto", mb: 1, fontSize: 16 }}>{item.step}</Avatar>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>{item.title}</Typography>
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>{item.desc}</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#4ec9b0", px: 1, py: 0.5, borderRadius: 1 }}>
                    {item.cmd}
                  </Typography>
                </Paper>
              ))}
            </Box>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Understanding Header Files
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Header files (<code>.h</code> files) contain declarations that can be shared across multiple source files. 
              They typically include:
            </Typography>

            <List>
              {[
                { primary: "Function prototypes", secondary: "Declarations that tell the compiler about a function's return type and parameters, without the actual implementation" },
                { primary: "Type definitions", secondary: "Custom types created with typedef, struct definitions, enum declarations, and unions" },
                { primary: "Macro definitions", secondary: "Constants and function-like macros defined with #define" },
                { primary: "External variable declarations", secondary: "Variables declared with extern that are defined in other files" },
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

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="caption" sx={{ color: "#6a9955", fontFamily: "monospace" }}>// myheader.h - Example header file</Typography>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`
#ifndef MYHEADER_H    // Include guard - prevents multiple inclusion
#define MYHEADER_H

#include <stddef.h>   // For size_t

// Macro constants
#define BUFFER_SIZE 1024
#define MAX(a, b) ((a) > (b) ? (a) : (b))

// Type definitions
typedef unsigned char byte;
typedef struct {
    int x;
    int y;
} Point;

// Function prototypes
int calculateSum(int *array, size_t length);
Point createPoint(int x, int y);
void printPoint(Point p);

// External variable declaration
extern int debugMode;

#endif // MYHEADER_H`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Standard C Libraries
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              C provides a standard library with essential functionality. Here are the most commonly used headers:
            </Typography>

            <Grid container spacing={2}>
              {[
                { header: "<stdio.h>", desc: "Standard I/O: printf, scanf, fopen, fclose, fread, fwrite", funcs: "printf, scanf, fgets, FILE" },
                { header: "<stdlib.h>", desc: "General utilities: memory allocation, conversions, random numbers", funcs: "malloc, free, atoi, exit" },
                { header: "<string.h>", desc: "String manipulation: copying, comparing, searching", funcs: "strlen, strcpy, strcmp, memcpy" },
                { header: "<math.h>", desc: "Mathematical functions (link with -lm)", funcs: "sqrt, pow, sin, cos, log" },
                { header: "<ctype.h>", desc: "Character classification and conversion", funcs: "isalpha, isdigit, toupper" },
                { header: "<stdint.h>", desc: "Fixed-width integer types (C99)", funcs: "int32_t, uint8_t, int64_t" },
                { header: "<stdbool.h>", desc: "Boolean type (C99)", funcs: "bool, true, false" },
                { header: "<assert.h>", desc: "Debugging assertions", funcs: "assert()" },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={3} key={item.header}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(accentColor, 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, fontFamily: "monospace", color: accentColor }}>{item.header}</Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.5 }}>{item.desc}</Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}>{item.funcs}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, mt: 3, borderRadius: 2, bgcolor: alpha("#ff9800", 0.1), border: `1px solid ${alpha("#ff9800", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                ⚠️ Common Beginner Mistakes
              </Typography>
              <List dense>
                <ListItem>
                  <ListItemText
                    primary="Forgetting semicolons at the end of statements"
                    secondary="C requires semicolons to terminate statements. The error message might point to the line after the actual problem."
                  />
                </ListItem>
                <ListItem>
                  <ListItemText
                    primary="Missing return statement in main()"
                    secondary="Always return 0 for success. While some compilers assume return 0, it's not guaranteed by older standards."
                  />
                </ListItem>
                <ListItem>
                  <ListItemText
                    primary="Using = instead of == in comparisons"
                    secondary="= is assignment, == is comparison. if (x = 5) assigns 5 to x, always evaluating to true!"
                  />
                </ListItem>
                <ListItem>
                  <ListItemText
                    primary="Forgetting to include required headers"
                    secondary="Each standard function requires its header. printf needs <stdio.h>, malloc needs <stdlib.h>."
                  />
                </ListItem>
              </List>
            </Paper>
          </Paper>

          {/* Variables & Data Types Section */}
          <Paper id="variables" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#ff9800", 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2,
                  bgcolor: alpha("#ff9800", 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#ff9800",
                }}
              >
                <StorageIcon />
              </Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Variables & Data Types
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              In C, every variable must have a specific <strong>data type</strong> that determines how much memory it occupies 
              and how its bits are interpreted. Unlike dynamically-typed languages, C is <strong>statically typed</strong>—the 
              compiler must know the type of every variable at compile time. This allows for efficient memory usage and fast 
              execution, but requires careful attention to type compatibility.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3, color: "#ff9800" }}>
              Primitive Data Types
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              C provides several fundamental data types. The exact size of each type depends on the platform and compiler, 
              but the C standard guarantees minimum sizes and relationships between types:
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ff9800", 0.05), mb: 3, overflowX: "auto" }}>
              <Typography variant="body2" component="div" sx={{ fontFamily: "monospace" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: "2px solid rgba(255, 152, 0, 0.3)" }}>
                      <th style={{ textAlign: "left", padding: "8px", fontWeight: 700 }}>Type</th>
                      <th style={{ textAlign: "center", padding: "8px", fontWeight: 700 }}>Size (typical)</th>
                      <th style={{ textAlign: "left", padding: "8px", fontWeight: 700 }}>Range (typical)</th>
                      <th style={{ textAlign: "left", padding: "8px", fontWeight: 700 }}>Use Case</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      { type: "char", size: "1 byte", range: "-128 to 127", use: "Single characters, small integers" },
                      { type: "unsigned char", size: "1 byte", range: "0 to 255", use: "Raw bytes, pixel values" },
                      { type: "short", size: "2 bytes", range: "-32,768 to 32,767", use: "Small integers, conserve memory" },
                      { type: "int", size: "4 bytes", range: "~±2 billion", use: "Default integer type" },
                      { type: "unsigned int", size: "4 bytes", range: "0 to ~4 billion", use: "Array indices, counts" },
                      { type: "long", size: "4-8 bytes", range: "At least ±2 billion", use: "Large integers (32/64-bit)" },
                      { type: "long long", size: "8 bytes", range: "~±9 quintillion", use: "Very large integers (C99)" },
                      { type: "float", size: "4 bytes", range: "~±3.4 × 10³⁸", use: "6-7 decimal digits precision" },
                      { type: "double", size: "8 bytes", range: "~±1.8 × 10³⁰⁸", use: "15-16 decimal digits precision" },
                    ].map((row, i) => (
                      <tr key={i} style={{ borderBottom: "1px solid rgba(255, 152, 0, 0.1)" }}>
                        <td style={{ padding: "6px 8px", color: "#ff9800", fontWeight: 600 }}>{row.type}</td>
                        <td style={{ padding: "6px 8px", textAlign: "center" }}>{row.size}</td>
                        <td style={{ padding: "6px 8px", fontSize: "0.85em" }}>{row.range}</td>
                        <td style={{ padding: "6px 8px", fontSize: "0.85em", color: "#888" }}>{row.use}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Typography>
            </Paper>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              <strong>Important:</strong> The sizes above are typical for 64-bit systems but not guaranteed by the C standard. 
              Use <code>sizeof(type)</code> to get the actual size on your system. For portable code requiring specific sizes, 
              use fixed-width types from <code>&lt;stdint.h&gt;</code>: <code>int8_t</code>, <code>int16_t</code>, <code>int32_t</code>, <code>int64_t</code>.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff9800" }}>
              Variable Declaration and Initialization
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Variables must be declared before use. A declaration specifies the variable's type and name. Initialization 
              assigns an initial value. In C89, declarations had to come before any statements in a block.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Declaration without initialization (contains garbage!)
int count;
double temperature;

// Declaration with initialization (recommended)
int score = 0;
float pi = 3.14159f;       // 'f' suffix for float literals
char grade = 'A';          // Single quotes for characters
double avogadro = 6.022e23; // Scientific notation

// Multiple declarations (same type)
int x = 1, y = 2, z = 3;

// Constants (cannot be modified after initialization)
const int MAX_PLAYERS = 100;
const double SPEED_OF_LIGHT = 299792458.0;

// Fixed-width types (C99, recommended for portability)
#include <stdint.h>
int32_t precise_int = 42;
uint8_t byte_value = 255;
int64_t large_number = 9223372036854775807LL;`}
              </Typography>
            </Paper>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#4caf50", 0.08), borderLeft: "4px solid #4caf50" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#4caf50", mb: 1 }}>✓ Good Practice</Typography>
                  <Typography variant="body2" component="div">
                    • Always initialize variables<br />
                    • Use meaningful names (camelCase or snake_case)<br />
                    • Declare close to first use (C99+)<br />
                    • Use const for values that shouldn't change<br />
                    • Use fixed-width types for binary protocols
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f44336", 0.08), borderLeft: "4px solid #f44336" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f44336", mb: 1 }}>✗ Avoid</Typography>
                  <Typography variant="body2" component="div">
                    • Uninitialized variables (undefined behavior)<br />
                    • Single-letter names (except loop counters)<br />
                    • Assuming int size (it varies!)<br />
                    • Shadowing variables in nested scopes<br />
                    • Global variables (hard to track)
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff9800" }}>
              Type Modifiers and Qualifiers
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              C provides modifiers to adjust the range or behavior of basic types:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { modifier: "signed / unsigned", desc: "signed (default for int) can be negative; unsigned uses all bits for positive range, doubling the maximum value", example: "unsigned int count = 0;" },
                { modifier: "short / long", desc: "Adjust the size of integers. long long (C99) guarantees at least 64 bits.", example: "long long bigNum = 1LL << 62;" },
                { modifier: "const", desc: "Makes a variable read-only. Attempting to modify causes a compile error.", example: "const double PI = 3.14159;" },
                { modifier: "volatile", desc: "Tells compiler the value may change externally (hardware registers, signal handlers). Prevents optimization.", example: "volatile int sensorValue;" },
                { modifier: "static", desc: "For local variables: retains value between function calls. For globals: limits visibility to current file.", example: "static int callCount = 0;" },
                { modifier: "extern", desc: "Declares a variable that's defined in another file. Used in headers.", example: "extern int globalSetting;" },
              ].map((item) => (
                <Grid item xs={12} md={6} key={item.modifier}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ff9800", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, fontFamily: "monospace", color: "#ff9800" }}>{item.modifier}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.desc}</Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#4ec9b0", p: 0.5, borderRadius: 1, display: "block" }}>
                      {item.example}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff9800" }}>
              Type Conversion (Casting)
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              C performs automatic type conversion (implicit casting) when mixing types in expressions, but you can also 
              force conversions explicitly. Understanding type conversion is crucial for avoiding subtle bugs:
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Implicit conversion (automatic)
int i = 10;
double d = i;          // int promoted to double: d = 10.0
int j = 3.7;           // double truncated to int: j = 3 (NOT rounded!)
char c = 1000;         // Overflow! 1000 doesn't fit in char

// Explicit conversion (casting)
int numerator = 5, denominator = 2;
double result = numerator / denominator;        // Wrong! Result is 2.0
double correct = (double)numerator / denominator; // Right! Result is 2.5

// Pointer casting (be careful!)
void *generic = malloc(100);
int *integers = (int *)generic;  // Cast void* to int*

// Integer promotion rules:
// char, short → int in expressions
// If operands differ, smaller type promoted to larger
// signed + unsigned → unsigned (can cause bugs!)`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#f44336", 0.1), border: `1px solid ${alpha("#f44336", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <BugReportIcon sx={{ color: "#f44336" }} />
                Common Type Conversion Bugs
              </Typography>
              <Typography variant="body2" component="div">
                <strong>Integer Division:</strong> <code>5/2</code> equals <code>2</code>, not <code>2.5</code>! Both operands are 
                integers, so integer division is performed. Cast one operand to double first.<br /><br />
                <strong>Signed/Unsigned Comparison:</strong> <code>-1 &gt; 0u</code> is <em>true</em>! When comparing signed and 
                unsigned, signed is converted to unsigned, and -1 becomes a large positive number.<br /><br />
                <strong>Truncation:</strong> Assigning double to int truncates—<code>3.99</code> becomes <code>3</code>. Use 
                <code>round()</code> from <code>&lt;math.h&gt;</code> if you need rounding.
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff9800" }}>
              The sizeof Operator
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              <code>sizeof</code> is a compile-time operator that returns the size of a type or variable in bytes. It's essential 
              for portable code and memory allocation:
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`#include <stdio.h>

int main(void) {
    // sizeof with types
    printf("char:   %zu bytes\\n", sizeof(char));      // Always 1
    printf("int:    %zu bytes\\n", sizeof(int));       // Usually 4
    printf("long:   %zu bytes\\n", sizeof(long));      // 4 or 8
    printf("double: %zu bytes\\n", sizeof(double));    // Usually 8
    printf("void*:  %zu bytes\\n", sizeof(void *));    // 4 (32-bit) or 8 (64-bit)

    // sizeof with variables
    int numbers[10];
    printf("Array size: %zu bytes\\n", sizeof(numbers));        // 40 bytes
    printf("Array elements: %zu\\n", sizeof(numbers) / sizeof(numbers[0])); // 10

    // sizeof for malloc (always use this pattern!)
    int *dynamic = malloc(100 * sizeof(*dynamic));  // Correct!
    int *wrong = malloc(100 * sizeof(int));         // Works, but less maintainable
    
    return 0;
}`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#4caf50", 0.1), border: `1px solid ${alpha("#4caf50", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon sx={{ color: "#4caf50" }} />
                Pro Tip: Portable malloc Pattern
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Always use <code>malloc(n * sizeof(*ptr))</code> instead of <code>malloc(n * sizeof(type))</code>. This way, 
                if you change the type of the pointer, the sizeof automatically adjusts. It's also more DRY (Don't Repeat Yourself).
              </Typography>
            </Paper>
          </Paper>

          {/* Operators Section */}
          <Paper id="operators" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#e91e63", 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2,
                  bgcolor: alpha("#e91e63", 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#e91e63",
                }}
              >
                <TerminalIcon />
              </Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Operators & Expressions
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Operators are symbols that tell the compiler to perform specific operations on operands. C has a rich set of 
              operators that allow you to perform arithmetic, comparisons, logical operations, bit manipulation, and more. 
              Understanding <strong>operator precedence</strong> (which operators execute first) and <strong>associativity</strong> 
              (left-to-right or right-to-left when operators have equal precedence) is crucial for writing correct expressions.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3, color: "#e91e63" }}>
              Arithmetic Operators
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              C provides standard arithmetic operators. Pay special attention to integer division, which truncates the result:
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`int a = 10, b = 3;

// Basic arithmetic
int sum = a + b;       // Addition: 13
int diff = a - b;      // Subtraction: 7
int prod = a * b;      // Multiplication: 30
int quot = a / b;      // Division: 3 (truncated! Not 3.33)
int rem = a % b;       // Modulus (remainder): 1

// Integer division gotcha
double result = 5 / 2;           // Result is 2.0, not 2.5!
double correct = 5.0 / 2;        // Result is 2.5
double also_correct = (double)5 / 2;  // Result is 2.5

// Modulus for negative numbers (implementation-defined before C99)
int neg_mod = -10 % 3;  // -1 in C99/C11 (sign of dividend)

// Unary operators
int pos = +5;          // Unary plus (rarely used)
int neg = -a;          // Unary minus: -10`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#e91e63" }}>
              Increment and Decrement Operators
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              The <code>++</code> and <code>--</code> operators add or subtract 1 from a variable. The prefix vs postfix 
              distinction is important when used in expressions:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#e91e63", 0.05) }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Prefix: ++x, --x</Typography>
                  <Typography variant="body2" paragraph>
                    Increment/decrement first, then use the value. The expression evaluates to the <em>new</em> value.
                  </Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1, borderRadius: 1 }}>
{`int x = 5;
int y = ++x;  // x is now 6, y is 6`}
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#e91e63", 0.05) }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Postfix: x++, x--</Typography>
                  <Typography variant="body2" paragraph>
                    Use the value first, then increment/decrement. The expression evaluates to the <em>original</em> value.
                  </Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1, borderRadius: 1 }}>
{`int x = 5;
int y = x++;  // y is 5, x is now 6`}
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ff9800", 0.1), border: `1px solid ${alpha("#ff9800", 0.3)}`, mb: 3 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ff9800", mb: 1 }}>⚠️ Warning: Undefined Behavior</Typography>
              <Typography variant="body2">
                Never modify a variable multiple times in the same expression: <code>x = x++ + ++x;</code> is <strong>undefined behavior</strong>. 
                The result varies between compilers. Similarly, <code>arr[i] = i++;</code> is undefined.
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#e91e63" }}>
              Relational and Logical Operators
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              These operators are used for comparisons and boolean logic. In C, any non-zero value is considered true, and zero is false:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#e91e63", 0.05) }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Relational (Comparison)</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                    {`== Equal to           (a == b)
!= Not equal to       (a != b)
<  Less than          (a < b)
>  Greater than       (a > b)
<= Less or equal      (a <= b)
>= Greater or equal   (a >= b)`}
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#e91e63", 0.05) }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>Logical</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                    {`&& Logical AND    (a && b)
|| Logical OR     (a || b)
!  Logical NOT    (!a)

Short-circuit evaluation:
(a && b) - b not evaluated if a is false
(a || b) - b not evaluated if a is true`}
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Short-circuit evaluation is useful and safe
if (ptr != NULL && ptr->value > 0) {
    // ptr->value only accessed if ptr is not NULL
}

// Common pattern: check array bounds first
if (index >= 0 && index < size && array[index] == target) {
    // Safe: bounds checked before access
}

// Be careful with = vs ==
int x = 5;
if (x = 0) {       // BUG! Assigns 0 to x, condition is always false
    printf("Never executed\\n");
}
if (x == 0) {      // CORRECT! Compares x with 0
    printf("x is zero\\n");
}

// Defensive style: constant on left (Yoda conditions)
if (0 == x) {      // If you accidentally write = instead of ==, compiler error!
    printf("x is zero\\n");
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#e91e63" }}>
              Bitwise Operators
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Bitwise operators work on the individual bits of integer values. They're essential for low-level programming, 
              flags, masks, and embedded systems:
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#e91e63", 0.05), mb: 3, overflowX: "auto" }}>
              <Typography variant="body2" component="div" sx={{ fontFamily: "monospace" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: "2px solid rgba(233, 30, 99, 0.3)" }}>
                      <th style={{ textAlign: "left", padding: "8px", fontWeight: 700 }}>Operator</th>
                      <th style={{ textAlign: "left", padding: "8px", fontWeight: 700 }}>Name</th>
                      <th style={{ textAlign: "left", padding: "8px", fontWeight: 700 }}>Example</th>
                      <th style={{ textAlign: "left", padding: "8px", fontWeight: 700 }}>Result</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      { op: "&", name: "Bitwise AND", example: "5 & 3 (0101 & 0011)", result: "1 (0001)" },
                      { op: "|", name: "Bitwise OR", example: "5 | 3 (0101 | 0011)", result: "7 (0111)" },
                      { op: "^", name: "Bitwise XOR", example: "5 ^ 3 (0101 ^ 0011)", result: "6 (0110)" },
                      { op: "~", name: "Bitwise NOT", example: "~5 (inverts all bits)", result: "-6 (signed)" },
                      { op: "<<", name: "Left shift", example: "5 << 2 (shift left 2)", result: "20 (×4)" },
                      { op: ">>", name: "Right shift", example: "20 >> 2 (shift right 2)", result: "5 (÷4)" },
                    ].map((row, i) => (
                      <tr key={i} style={{ borderBottom: "1px solid rgba(233, 30, 99, 0.1)" }}>
                        <td style={{ padding: "6px 8px", color: "#e91e63", fontWeight: 700 }}>{row.op}</td>
                        <td style={{ padding: "6px 8px" }}>{row.name}</td>
                        <td style={{ padding: "6px 8px", fontSize: "0.85em" }}>{row.example}</td>
                        <td style={{ padding: "6px 8px", fontSize: "0.85em" }}>{row.result}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="caption" sx={{ color: "#6a9955", fontFamily: "monospace" }}>// Common bitwise patterns</Typography>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`
#define FLAG_READ    (1 << 0)  // 0001 = 1
#define FLAG_WRITE   (1 << 1)  // 0010 = 2
#define FLAG_EXECUTE (1 << 2)  // 0100 = 4
#define FLAG_DELETE  (1 << 3)  // 1000 = 8

unsigned int permissions = 0;

// Set flags
permissions |= FLAG_READ;              // Turn on read
permissions |= FLAG_READ | FLAG_WRITE; // Turn on read and write

// Clear flags
permissions &= ~FLAG_WRITE;            // Turn off write

// Toggle flags
permissions ^= FLAG_EXECUTE;           // Flip execute

// Check flags
if (permissions & FLAG_READ) {
    printf("Read permission granted\\n");
}

// Bit manipulation tricks
int x = 42;
int isPowerOf2 = (x & (x - 1)) == 0 && x != 0;  // False for 42
int lowestBit = x & (-x);  // Extracts lowest set bit
int clearLowestBit = x & (x - 1);  // Clears lowest set bit`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#e91e63" }}>
              Assignment Operators
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              C provides compound assignment operators that combine an operation with assignment:
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`int x = 10;

x += 5;   // x = x + 5;   → x is 15
x -= 3;   // x = x - 3;   → x is 12
x *= 2;   // x = x * 2;   → x is 24
x /= 4;   // x = x / 4;   → x is 6
x %= 4;   // x = x % 4;   → x is 2

// Bitwise compound assignment
x &= 0xFF;   // x = x & 0xFF;
x |= 0x10;   // x = x | 0x10;
x ^= mask;   // x = x ^ mask;
x <<= 2;     // x = x << 2;
x >>= 1;     // x = x >> 1;

// Assignment is an expression that returns the assigned value
int a, b, c;
a = b = c = 0;  // Chain assignment (right-to-left)
// Equivalent to: c = 0; b = c; a = b;`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#e91e63" }}>
              The Ternary Operator
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              The conditional (ternary) operator <code>?:</code> is C's only operator that takes three operands. It's a 
              compact way to write simple if-else expressions:
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Syntax: condition ? value_if_true : value_if_false

int a = 10, b = 20;
int max = (a > b) ? a : b;  // max is 20

// Equivalent to:
int max2;
if (a > b) {
    max2 = a;
} else {
    max2 = b;
}

// Common use cases
printf("Result: %s\\n", success ? "pass" : "fail");

int abs_value = (x < 0) ? -x : x;

// Can be nested (but don't overdo it!)
const char *grade = (score >= 90) ? "A" :
                    (score >= 80) ? "B" :
                    (score >= 70) ? "C" :
                    (score >= 60) ? "D" : "F";`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#e91e63" }}>
              Operator Precedence
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Operators in C have different precedence levels. Higher precedence operators are evaluated first. When in doubt, 
              use parentheses to make your intent clear:
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#e91e63", 0.05), mb: 3, overflowX: "auto" }}>
              <Typography variant="caption" sx={{ fontWeight: 700, color: "#e91e63" }}>From highest to lowest precedence:</Typography>
              <Typography variant="body2" sx={{ fontFamily: "monospace", mt: 1 }}>
                {`1. () [] -> .              Postfix / member access
2. ! ~ ++ -- + - * & (type) sizeof   Unary / cast
3. * / %                    Multiplication, division, modulus
4. + -                      Addition, subtraction
5. << >>                    Bit shifts
6. < <= > >=                Relational
7. == !=                    Equality
8. &                        Bitwise AND
9. ^                        Bitwise XOR
10. |                       Bitwise OR
11. &&                      Logical AND
12. ||                      Logical OR
13. ?:                      Ternary conditional
14. = += -= *= /= etc.      Assignment
15. ,                       Comma`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#4caf50", 0.1), border: `1px solid ${alpha("#4caf50", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon sx={{ color: "#4caf50" }} />
                Best Practice: Use Parentheses
              </Typography>
              <Typography variant="body2">
                Don't rely on memorizing precedence rules. Use parentheses to make expressions clear and prevent bugs. 
                <code> a & b == c</code> is parsed as <code>a & (b == c)</code>, not <code>(a & b) == c</code>! This is a 
                common source of errors. Write <code>(a & b) == c</code> to be explicit.
              </Typography>
            </Paper>
          </Paper>

          {/* Control Flow Section */}
          <Paper id="control-flow" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#9c27b0", 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2,
                  bgcolor: alpha("#9c27b0", 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#9c27b0",
                }}
              >
                <CodeIcon />
              </Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Control Flow
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Control flow statements determine the order in which code executes. Without control flow, programs would run 
              linearly from top to bottom. C provides several constructs for <strong>decision making</strong> (if, switch) 
              and <strong>iteration</strong> (for, while, do-while), plus statements to alter flow within loops (break, continue).
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3, color: "#9c27b0" }}>
              Conditional Statements: if, else if, else
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              The <code>if</code> statement executes code conditionally. Remember that in C, any non-zero value is 
              considered true, and zero is false. There's no boolean type in C89 (use <code>&lt;stdbool.h&gt;</code> in C99+).
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Simple if statement
if (temperature > 100) {
    printf("Water is boiling!\\n");
}

// if-else
if (age >= 18) {
    printf("Adult\\n");
} else {
    printf("Minor\\n");
}

// if-else if-else chain
int score = 85;
if (score >= 90) {
    printf("Grade: A\\n");
} else if (score >= 80) {
    printf("Grade: B\\n");
} else if (score >= 70) {
    printf("Grade: C\\n");
} else if (score >= 60) {
    printf("Grade: D\\n");
} else {
    printf("Grade: F\\n");
}

// Nested if (be careful with readability)
if (x > 0) {
    if (y > 0) {
        printf("First quadrant\\n");
    } else {
        printf("Fourth quadrant\\n");
    }
}

// Single statement (braces optional but recommended)
if (condition)
    doSomething();  // Works but can lead to bugs
    doSomethingElse();  // NOT part of if! Always executes!

// Always use braces (best practice)
if (condition) {
    doSomething();
}`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f44336", 0.1), border: `1px solid ${alpha("#f44336", 0.3)}`, mb: 3 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f44336", mb: 1 }}>⚠️ The Dangling Else Problem</Typography>
              <Typography variant="body2">
                <code>if (a) if (b) s1; else s2;</code> — Does the else belong to the outer or inner if? It binds to the 
                nearest if, so the else goes with <code>if (b)</code>. Use braces to make intent clear!
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9c27b0" }}>
              Switch Statement
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              The <code>switch</code> statement is ideal for multiple equality comparisons against a single variable. 
              It's often more readable than long if-else chains and can be more efficient.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`int day = 3;

switch (day) {
    case 1:
        printf("Monday\\n");
        break;  // break exits the switch
    case 2:
        printf("Tuesday\\n");
        break;
    case 3:
        printf("Wednesday\\n");
        break;
    case 4:
    case 5:  // Fall-through: multiple cases, same action
        printf("Thursday or Friday\\n");
        break;
    case 6:
    case 7:
        printf("Weekend!\\n");
        break;
    default:  // Optional: handles all other values
        printf("Invalid day\\n");
        break;
}

// Switch works with integers and chars (not strings or floats!)
char grade = 'B';
switch (grade) {
    case 'A': printf("Excellent!\\n"); break;
    case 'B': printf("Good job!\\n"); break;
    case 'C': printf("Fair\\n"); break;
    default: printf("Keep trying\\n"); break;
}

// WARNING: forgetting break causes fall-through!
switch (x) {
    case 1:
        printf("One\\n");
        // No break! Execution continues to case 2!
    case 2:
        printf("Two\\n");  // This runs for x=1 too!
        break;
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9c27b0" }}>
              Loops: for, while, do-while
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Loops execute code repeatedly. Choose the right loop for your situation: <code>for</code> when you know 
              the iteration count, <code>while</code> when you check a condition before each iteration, and <code>do-while</code> 
              when you need to execute at least once.
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#9c27b0", 0.05), height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#9c27b0", mb: 1 }}>for loop</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1, borderRadius: 1, fontSize: "0.75rem" }}>
{`// Counter-based iteration
for (int i = 0; i < 10; i++) {
    printf("%d\\n", i);
}

// Syntax:
// for (init; condition; update)
// All parts are optional:
for (;;) { /* infinite */ }`}
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#9c27b0", 0.05), height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#9c27b0", mb: 1 }}>while loop</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1, borderRadius: 1, fontSize: "0.75rem" }}>
{`// Check condition first
int n = 5;
while (n > 0) {
    printf("%d\\n", n);
    n--;
}

// May execute zero times
while (condition) {
    // body
}`}
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#9c27b0", 0.05), height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#9c27b0", mb: 1 }}>do-while loop</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1, borderRadius: 1, fontSize: "0.75rem" }}>
{`// Execute at least once
int input;
do {
    printf("Enter > 0: ");
    scanf("%d", &input);
} while (input <= 0);

// Note semicolon after
// while condition!`}
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="caption" sx={{ color: "#6a9955", fontFamily: "monospace" }}>// Common loop patterns</Typography>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`
// Iterating over an array
int arr[] = {10, 20, 30, 40, 50};
int size = sizeof(arr) / sizeof(arr[0]);
for (int i = 0; i < size; i++) {
    printf("arr[%d] = %d\\n", i, arr[i]);
}

// Infinite loop (use break to exit)
while (1) {
    if (shouldExit) break;
    processData();
}

// Nested loops (matrix traversal)
for (int row = 0; row < ROWS; row++) {
    for (int col = 0; col < COLS; col++) {
        printf("%d ", matrix[row][col]);
    }
    printf("\\n");
}

// Reading until EOF
int c;
while ((c = getchar()) != EOF) {
    putchar(c);
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9c27b0" }}>
              Loop Control: break, continue, goto
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              These statements alter the normal flow of loops:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { keyword: "break", desc: "Exits the innermost loop or switch immediately. Execution continues after the loop.", example: "for(i=0;i<10;i++) { if(i==5) break; }" },
                { keyword: "continue", desc: "Skips the rest of the current iteration and jumps to the next iteration. For loops evaluate the update expression.", example: "for(i=0;i<10;i++) { if(i%2==0) continue; print(i); }" },
                { keyword: "goto", desc: "Jumps to a labeled statement. Generally avoided but useful for error handling with multiple cleanup steps.", example: "if(error) goto cleanup; ... cleanup: free(ptr);" },
              ].map((item) => (
                <Grid item xs={12} key={item.keyword}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#9c27b0", 0.05), borderLeft: `4px solid #9c27b0` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, fontFamily: "monospace", color: "#9c27b0" }}>{item.keyword}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.desc}</Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#4ec9b0", p: 0.5, borderRadius: 1, display: "inline-block" }}>
                      {item.example}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="caption" sx={{ color: "#6a9955", fontFamily: "monospace" }}>// Practical example: goto for cleanup</Typography>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`
int processFile(const char *filename) {
    FILE *fp = NULL;
    char *buffer = NULL;
    int result = -1;

    fp = fopen(filename, "r");
    if (fp == NULL) goto cleanup;

    buffer = malloc(BUFFER_SIZE);
    if (buffer == NULL) goto cleanup;

    // Process file...
    if (readError) goto cleanup;

    // Success
    result = 0;

cleanup:  // Single cleanup point
    free(buffer);    // free(NULL) is safe
    if (fp) fclose(fp);
    return result;
}`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#4caf50", 0.1), border: `1px solid ${alpha("#4caf50", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon sx={{ color: "#4caf50" }} />
                Best Practices for Control Flow
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Always use braces, even for single statements" secondary="Prevents bugs when adding code later" /></ListItem>
                <ListItem><ListItemText primary="Keep nesting shallow (≤3 levels)" secondary="Deep nesting is hard to read; extract to functions" /></ListItem>
                <ListItem><ListItemText primary="Return early from functions" secondary="Reduces nesting: if (error) return; instead of wrapping everything in else" /></ListItem>
                <ListItem><ListItemText primary="Use switch for multiple equality comparisons" secondary="More readable than long if-else chains" /></ListItem>
              </List>
            </Paper>
          </Paper>

          {/* Functions Section */}
          <Paper id="functions" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#2196f3", 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2,
                  bgcolor: alpha("#2196f3", 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#2196f3",
                }}
              >
                <BuildIcon />
              </Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Functions
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Functions are the building blocks of C programs. They encapsulate reusable code, making programs more modular, 
              readable, and maintainable. Every C program has at least one function: <code>main()</code>. Functions break 
              down complex problems into smaller, manageable pieces and allow code reuse without duplication.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3, color: "#2196f3" }}>
              Function Syntax and Structure
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Function declaration (prototype) - tells compiler about the function
return_type function_name(parameter_type parameter_name, ...);

// Function definition - implements the function
return_type function_name(parameter_type parameter_name, ...) {
    // function body
    return value;  // must match return_type (omit for void)
}

// Example: Function that calculates the square of a number
int square(int n);  // Declaration/prototype

int square(int n) {  // Definition
    return n * n;
}

// Example: Function with multiple parameters
double calculateBMI(double weightKg, double heightM) {
    if (heightM <= 0) {
        return -1.0;  // Error indicator
    }
    return weightKg / (heightM * heightM);
}

// Example: Function that returns nothing (void)
void printGreeting(const char *name) {
    printf("Hello, %s!\\n", name);
    // No return statement needed, or use: return;
}`}
              </Typography>
            </Paper>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { term: "Return Type", desc: "The data type of the value the function returns. Use void if it returns nothing." },
                { term: "Function Name", desc: "Identifier following C naming rules. Should describe what the function does." },
                { term: "Parameters", desc: "Variables that receive values when the function is called. Listed in parentheses." },
                { term: "Function Body", desc: "The code block enclosed in braces that executes when the function is called." },
                { term: "Return Statement", desc: "Exits the function and optionally returns a value to the caller." },
                { term: "Prototype", desc: "Declaration without body, usually in headers. Allows calling before definition." },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.term}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#2196f3", 0.05) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#2196f3" }}>{item.term}</Typography>
                    <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#2196f3" }}>
              Pass by Value vs Pass by Reference
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              C always passes arguments <strong>by value</strong>—functions receive copies of the arguments. To modify 
              the original variable, you must pass a <strong>pointer</strong> to it (simulating pass-by-reference).
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Pass by value - function gets a COPY
void tryToModify(int x) {
    x = 100;  // Only modifies the local copy
}

int main(void) {
    int num = 5;
    tryToModify(num);
    printf("%d\\n", num);  // Still prints 5!
    return 0;
}

// Pass by pointer - function can modify original
void actuallyModify(int *x) {
    *x = 100;  // Dereference to modify original
}

int main(void) {
    int num = 5;
    actuallyModify(&num);  // Pass address of num
    printf("%d\\n", num);    // Prints 100!
    return 0;
}

// Classic example: swap function
void swap(int *a, int *b) {
    int temp = *a;
    *a = *b;
    *b = temp;
}

int main(void) {
    int x = 10, y = 20;
    swap(&x, &y);  // x is now 20, y is now 10
    return 0;
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#2196f3" }}>
              Recursion
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              A <strong>recursive function</strong> calls itself. Every recursive function needs a <strong>base case</strong> 
              to stop the recursion, and a <strong>recursive case</strong> that moves toward the base case. Without a 
              proper base case, recursion leads to stack overflow.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Factorial using recursion
// n! = n × (n-1) × (n-2) × ... × 1
unsigned long long factorial(int n) {
    // Base case: 0! = 1, 1! = 1
    if (n <= 1) {
        return 1;
    }
    // Recursive case
    return n * factorial(n - 1);
}

// Fibonacci using recursion (inefficient but illustrative)
int fibonacci(int n) {
    if (n <= 0) return 0;
    if (n == 1) return 1;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

// Binary search using recursion
int binarySearch(int arr[], int left, int right, int target) {
    if (left > right) {
        return -1;  // Base case: not found
    }
    
    int mid = left + (right - left) / 2;  // Avoid overflow
    
    if (arr[mid] == target) {
        return mid;
    } else if (arr[mid] > target) {
        return binarySearch(arr, left, mid - 1, target);
    } else {
        return binarySearch(arr, mid + 1, right, target);
    }
}`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ff9800", 0.1), border: `1px solid ${alpha("#ff9800", 0.3)}`, mb: 3 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ff9800", mb: 1 }}>⚠️ Recursion vs Iteration</Typography>
              <Typography variant="body2">
                Recursion uses the call stack, which has limited size. Deep recursion causes stack overflow. 
                For performance-critical code, prefer iteration. Some compilers optimize "tail recursion" 
                (where the recursive call is the last operation), but C doesn't guarantee this.
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#2196f3" }}>
              Storage Classes and Scope
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Variables have <strong>scope</strong> (where they're visible) and <strong>lifetime</strong> (how long they exist). 
              Storage class specifiers control these properties:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { class: "auto", desc: "Default for local variables. Automatic storage duration—created when block is entered, destroyed when exited.", example: "auto int x; // same as: int x;" },
                { class: "static (local)", desc: "Retains value between function calls. Initialized only once. Lifetime extends to program end.", example: "static int count = 0; count++;" },
                { class: "static (global)", desc: "Limits visibility to the current file (internal linkage). Not accessible from other files.", example: "static int filePrivate = 0;" },
                { class: "extern", desc: "Declares a variable defined elsewhere. Used to share globals across files.", example: "extern int globalVar;" },
                { class: "register", desc: "Hint to store in CPU register for speed. Modern compilers usually ignore this.", example: "register int i; // hint only" },
              ].map((item) => (
                <Grid item xs={12} key={item.class}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#2196f3", 0.05), borderLeft: `4px solid #2196f3` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, fontFamily: "monospace", color: "#2196f3" }}>{item.class}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>{item.desc}</Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#4ec9b0", p: 0.5, borderRadius: 1, display: "inline-block" }}>
                      {item.example}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#2196f3" }}>
              Function Pointers
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Functions have addresses in memory, so you can create pointers to them. Function pointers enable callbacks, 
              dynamic dispatch, and implementing data structures like jump tables.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Declare a function pointer
// Syntax: return_type (*pointer_name)(parameter_types)
int (*operation)(int, int);

// Functions to point to
int add(int a, int b) { return a + b; }
int subtract(int a, int b) { return a - b; }
int multiply(int a, int b) { return a * b; }

int main(void) {
    // Assign function to pointer (two equivalent ways)
    operation = add;      // Function name decays to pointer
    operation = &add;     // Explicit address-of (same result)
    
    // Call through pointer (two equivalent ways)
    int result1 = operation(5, 3);     // 8
    int result2 = (*operation)(5, 3);  // 8 (explicit dereference)
    
    // Change which function the pointer points to
    operation = multiply;
    int result3 = operation(5, 3);     // 15
    
    return 0;
}

// Practical use: callback function
void processArray(int *arr, int size, int (*transform)(int)) {
    for (int i = 0; i < size; i++) {
        arr[i] = transform(arr[i]);
    }
}

int doubleValue(int x) { return x * 2; }
int squareValue(int x) { return x * x; }

// Usage:
processArray(numbers, 10, doubleValue);  // Double all elements
processArray(numbers, 10, squareValue);  // Square all elements`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#4caf50", 0.1), border: `1px solid ${alpha("#4caf50", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon sx={{ color: "#4caf50" }} />
                Function Design Best Practices
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Single Responsibility" secondary="Each function should do one thing well" /></ListItem>
                <ListItem><ListItemText primary="Keep functions short" secondary="If it doesn't fit on one screen, consider splitting it" /></ListItem>
                <ListItem><ListItemText primary="Use const for input parameters" secondary="const int *arr tells callers the array won't be modified" /></ListItem>
                <ListItem><ListItemText primary="Return error codes consistently" secondary="0 for success, negative for errors is a common convention" /></ListItem>
              </List>
            </Paper>
          </Paper>

          {/* Arrays Section */}
          <Paper id="arrays" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#00bcd4", 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2,
                  bgcolor: alpha("#00bcd4", 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#00bcd4",
                }}
              >
                <StorageIcon />
              </Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Arrays
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              An <strong>array</strong> is a collection of elements of the same type stored in contiguous memory locations. 
              Arrays provide efficient random access (O(1)) to elements using an index. Understanding arrays is fundamental 
              to C programming—they form the basis for strings, matrices, and many data structures.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3, color: "#00bcd4" }}>
              Declaring and Initializing Arrays
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Declaration: type name[size];
int numbers[5];        // Array of 5 integers (values undefined!)
double prices[100];    // Array of 100 doubles
char name[50];         // Array of 50 characters

// Initialization at declaration
int a[5] = {1, 2, 3, 4, 5};    // Fully initialized
int b[5] = {1, 2};             // Partially: {1, 2, 0, 0, 0}
int c[5] = {0};                // All zeros: {0, 0, 0, 0, 0}
int d[] = {1, 2, 3, 4, 5};     // Size inferred: 5 elements

// C99 designated initializers
int e[10] = {[0] = 1, [9] = 10};  // First and last, rest are 0
int f[5] = {[2] = 5, [4] = 9};    // {0, 0, 5, 0, 9}

// Character arrays (strings)
char str1[6] = {'H', 'e', 'l', 'l', 'o', '\\0'};
char str2[] = "Hello";  // Same as above, size is 6 (includes \\0)
char str3[50] = "Hi";   // "Hi\\0" with 47 more null bytes`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f44336", 0.1), border: `1px solid ${alpha("#f44336", 0.3)}`, mb: 3 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f44336", mb: 1 }}>⚠️ Critical: Uninitialized Arrays</Typography>
              <Typography variant="body2">
                Local arrays are <strong>not automatically initialized</strong> in C. They contain garbage values! 
                Always initialize arrays, especially when used with string functions or loops.
                <code> int arr[100] = {`{0}`};</code> is a quick way to zero-initialize.
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00bcd4" }}>
              Accessing Array Elements
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Array elements are accessed using an index (subscript). Index starts at 0, so valid indices for an array 
              of size N are 0 through N-1. <strong>C does not check array bounds</strong>—accessing outside the array 
              is undefined behavior and a major source of security vulnerabilities.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`int scores[5] = {90, 85, 78, 92, 88};

// Accessing elements (0-indexed)
int first = scores[0];   // 90
int third = scores[2];   // 78
int last = scores[4];    // 88

// Modifying elements
scores[1] = 95;          // Change second element

// Iterating through an array
int sum = 0;
for (int i = 0; i < 5; i++) {
    printf("scores[%d] = %d\\n", i, scores[i]);
    sum += scores[i];
}
double average = (double)sum / 5;

// DANGER: Out-of-bounds access (undefined behavior!)
// int oops = scores[5];    // BUG! Valid indices are 0-4
// scores[-1] = 100;        // BUG! No negative indices

// Getting array size (works for actual arrays, not pointers!)
int size = sizeof(scores) / sizeof(scores[0]);  // 5
printf("Array has %d elements\\n", size);`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00bcd4" }}>
              Arrays and Pointers
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              In most expressions, an array name "decays" to a pointer to its first element. This is why arrays are 
              passed to functions as pointers, and why pointer arithmetic works with arrays. However, arrays and 
              pointers are <em>not</em> identical—arrays have a fixed size known at compile time.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`int arr[5] = {10, 20, 30, 40, 50};
int *ptr = arr;  // Array decays to pointer (same as: &arr[0])

// Equivalent ways to access elements:
int val1 = arr[2];       // 30 (subscript)
int val2 = *(arr + 2);   // 30 (pointer arithmetic)
int val3 = ptr[2];       // 30 (pointer with subscript)
int val4 = *(ptr + 2);   // 30 (pointer arithmetic)

// Key difference: sizeof
printf("sizeof(arr) = %zu\\n", sizeof(arr));  // 20 (5 * 4 bytes)
printf("sizeof(ptr) = %zu\\n", sizeof(ptr));  // 8 (pointer size)

// arr is not modifiable
// arr = ptr;  // ERROR! Cannot assign to array
// arr++;      // ERROR! Cannot modify array

// ptr is modifiable
ptr++;         // OK, now points to arr[1]
ptr = arr + 3; // OK, now points to arr[3]`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00bcd4" }}>
              Multi-dimensional Arrays
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              C supports multi-dimensional arrays, most commonly 2D arrays for matrices and tables. In memory, 
              they're stored in <strong>row-major order</strong>—all elements of the first row, then the second, etc.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// 2D array declaration: type name[rows][cols]
int matrix[3][4];  // 3 rows, 4 columns (uninitialized!)

// 2D array initialization
int grid[3][4] = {
    {1, 2, 3, 4},     // Row 0
    {5, 6, 7, 8},     // Row 1
    {9, 10, 11, 12}   // Row 2
};

// Can omit first dimension
int table[][3] = {
    {1, 2, 3},
    {4, 5, 6}
};  // Compiler deduces 2 rows

// Accessing elements
int element = grid[1][2];  // Row 1, Column 2 → 7

// Nested loop iteration
for (int row = 0; row < 3; row++) {
    for (int col = 0; col < 4; col++) {
        printf("%3d ", grid[row][col]);
    }
    printf("\\n");
}

// Memory layout (row-major):
// grid[0][0], grid[0][1], grid[0][2], grid[0][3],
// grid[1][0], grid[1][1], grid[1][2], grid[1][3], ...

// Address calculation:
// &grid[r][c] == (int*)grid + r*4 + c  (4 = num columns)`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00bcd4" }}>
              Passing Arrays to Functions
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              When you pass an array to a function, it decays to a pointer. The function receives a pointer to the 
              first element, not a copy of the array. This means functions can modify the original array, and you 
              typically need to pass the size separately.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// These function signatures are ALL equivalent for 1D arrays:
void processArray(int arr[], int size);
void processArray(int *arr, int size);
void processArray(int arr[10], int size);  // 10 is ignored!

// Example implementation
void printArray(const int *arr, int size) {
    for (int i = 0; i < size; i++) {
        printf("%d ", arr[i]);
    }
    printf("\\n");
}

void doubleElements(int *arr, int size) {
    for (int i = 0; i < size; i++) {
        arr[i] *= 2;  // Modifies original array!
    }
}

// Calling
int nums[] = {1, 2, 3, 4, 5};
int n = sizeof(nums) / sizeof(nums[0]);
printArray(nums, n);
doubleElements(nums, n);

// For 2D arrays, must specify column count:
void printMatrix(int mat[][4], int rows) {
    for (int r = 0; r < rows; r++) {
        for (int c = 0; c < 4; c++) {
            printf("%d ", mat[r][c]);
        }
        printf("\\n");
    }
}

// Or use pointer to array:
void printMatrix2(int (*mat)[4], int rows);  // Same as above`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00bcd4" }}>
              Variable-Length Arrays (C99)
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              C99 introduced Variable-Length Arrays (VLAs) where the size can be determined at runtime. Note that VLAs 
              are allocated on the stack and made optional in C11, so use with caution.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// VLA - size determined at runtime (C99)
void processData(int n) {
    int values[n];  // VLA - n determined at runtime
    
    for (int i = 0; i < n; i++) {
        values[i] = i * i;
    }
    // values is deallocated when function returns
}

// VLA for 2D arrays
void create2DArray(int rows, int cols) {
    int matrix[rows][cols];  // Runtime-sized 2D array
    // ...
}

// VLA in function parameters (very useful!)
void processMatrix(int rows, int cols, int mat[rows][cols]) {
    for (int r = 0; r < rows; r++) {
        for (int c = 0; c < cols; c++) {
            printf("%d ", mat[r][c]);
        }
        printf("\\n");
    }
}`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ff9800", 0.1), border: `1px solid ${alpha("#ff9800", 0.3)}`, mb: 3 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ff9800", mb: 1 }}>⚠️ VLA Limitations</Typography>
              <Typography variant="body2">
                VLAs live on the stack with limited size (typically a few MB). Large VLAs can cause stack overflow. 
                For large or unknown-size arrays, prefer <code>malloc()</code>. VLAs are optional in C11 and not 
                supported in C++.
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#4caf50", 0.1), border: `1px solid ${alpha("#4caf50", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon sx={{ color: "#4caf50" }} />
                Array Best Practices
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Always bounds-check" secondary="Validate indices before accessing: if (i >= 0 && i < size)" /></ListItem>
                <ListItem><ListItemText primary="Pass size with array" secondary="Functions can't determine array size from a pointer" /></ListItem>
                <ListItem><ListItemText primary="Zero-initialize when needed" secondary="int arr[100] = {0}; prevents undefined values" /></ListItem>
                <ListItem><ListItemText primary="Use const for read-only access" secondary="void print(const int *arr, int n) prevents accidental modification" /></ListItem>
              </List>
            </Paper>
          </Paper>

          {/* Pointers Section */}
          <Paper id="pointers" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#f44336", 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2,
                  bgcolor: alpha("#f44336", 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#f44336",
                }}
              >
                <MemoryIcon />
              </Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Pointers
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Pointers are variables that store <strong>memory addresses</strong>. They are the most powerful and 
              distinctive feature of C, enabling direct memory manipulation, efficient data structure implementation, 
              and system-level programming. Pointers are also the source of many bugs and security vulnerabilities 
              when used incorrectly—mastering them is essential for C proficiency.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3, color: "#f44336" }}>
              What is a Pointer?
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              A pointer holds the memory address of another variable. Think of memory as a sequence of numbered 
              mailboxes—a pointer stores a mailbox number, not the contents inside.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Memory visualization:
// Address     |  Value    |  Variable
// 0x7ffc001   |  42       |  x
// 0x7ffc005   |  0x7ffc001|  ptr (stores address of x)

int x = 42;          // Regular variable holding value 42
int *ptr;            // Declare pointer to int (currently uninitialized!)
ptr = &x;            // Store address of x in ptr (&x = "address of x")

// Accessing values
printf("x = %d\\n", x);         // 42 (direct access)
printf("&x = %p\\n", &x);       // 0x7ffc001 (address of x)
printf("ptr = %p\\n", ptr);     // 0x7ffc001 (same address)
printf("*ptr = %d\\n", *ptr);   // 42 (dereference: value at address)

// Modifying through pointer
*ptr = 100;           // Changes x to 100!
printf("x = %d\\n", x); // 100`}
              </Typography>
            </Paper>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { op: "&", name: "Address-of", desc: "Gets the memory address of a variable", example: "int *p = &x; // p holds address of x" },
                { op: "*", name: "Declaration", desc: "Declares a pointer variable", example: "int *ptr; // ptr is a pointer to int" },
                { op: "*", name: "Dereference", desc: "Accesses value at the address", example: "int val = *ptr; // get value at ptr's address" },
              ].map((item, i) => (
                <Grid item xs={12} key={i}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f44336", 0.05), borderLeft: `4px solid #f44336` }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                      <Typography variant="h4" sx={{ fontFamily: "monospace", color: "#f44336", fontWeight: 700 }}>{item.op}</Typography>
                      <Box>
                        <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.name}</Typography>
                        <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                        <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#4ec9b0" }}>{item.example}</Typography>
                      </Box>
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              Pointer Types and Sizes
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              All pointers on a system have the same size (typically 8 bytes on 64-bit systems), but the type 
              matters for arithmetic and dereferencing. A <code>int*</code> knows it points to 4-byte integers; 
              a <code>char*</code> knows it points to 1-byte characters.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`int *ip;       // Pointer to int
char *cp;      // Pointer to char
double *dp;    // Pointer to double
void *vp;      // Void pointer (generic, can point to anything)

// All pointers are the same size on a given system
printf("sizeof(int*) = %zu\\n", sizeof(int*));     // 8 on 64-bit
printf("sizeof(char*) = %zu\\n", sizeof(char*));   // 8 on 64-bit
printf("sizeof(void*) = %zu\\n", sizeof(void*));   // 8 on 64-bit

// Type determines how dereferencing works
int num = 0x12345678;
int *pi = &num;
char *pc = (char*)&num;  // Cast to char pointer

printf("*pi = 0x%x\\n", *pi);   // 0x12345678 (whole int)
printf("*pc = 0x%x\\n", *pc);   // 0x78 (just first byte, little-endian)`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              Pointer Arithmetic
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Adding 1 to a pointer moves it to the <em>next element</em>, not the next byte. The compiler 
              automatically multiplies by the pointed-to type's size. This makes iterating through arrays natural.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`int arr[5] = {10, 20, 30, 40, 50};
int *p = arr;  // Points to arr[0]

// Pointer arithmetic
printf("*p     = %d\\n", *p);       // 10 (arr[0])
printf("*(p+1) = %d\\n", *(p+1));   // 20 (arr[1])
printf("*(p+2) = %d\\n", *(p+2));   // 30 (arr[2])

// Move the pointer
p++;           // Now points to arr[1]
printf("*p = %d\\n", *p);           // 20

p += 2;        // Now points to arr[3]
printf("*p = %d\\n", *p);           // 40

// Pointer subtraction gives element count, not byte count
int *start = arr;
int *end = arr + 4;
printf("end - start = %td\\n", end - start);  // 4 (elements)

// Array iteration with pointers
for (int *ptr = arr; ptr < arr + 5; ptr++) {
    printf("%d ", *ptr);
}
// Output: 10 20 30 40 50

// Equivalent to subscript notation
// arr[i] is exactly equivalent to *(arr + i)
// &arr[i] is exactly equivalent to (arr + i)`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              NULL Pointers and Safety
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              A <strong>NULL pointer</strong> points to nothing—it's a sentinel value indicating "no valid address." 
              Always initialize pointers and check for NULL before dereferencing. Dereferencing NULL causes 
              segmentation faults (crashes).
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`#include <stddef.h>  // For NULL (also in <stdlib.h>, <stdio.h>)

int *ptr = NULL;    // Initialize to NULL (good practice!)
// Equivalent: int *ptr = 0;

// Always check before dereferencing
if (ptr != NULL) {
    printf("Value: %d\\n", *ptr);  // Safe
} else {
    printf("Pointer is NULL\\n");
}

// Common pattern for functions that return pointers
char *result = findItem(key);
if (result == NULL) {
    printf("Item not found\\n");
    return -1;
}
printf("Found: %s\\n", result);

// After free, set to NULL to prevent use-after-free
free(buffer);
buffer = NULL;  // Now dereferencing will crash predictably

// Concise NULL check
if (ptr) {      // Same as: if (ptr != NULL)
    // ptr is valid
}

if (!ptr) {     // Same as: if (ptr == NULL)
    // ptr is NULL
}`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f44336", 0.1), border: `1px solid ${alpha("#f44336", 0.3)}`, mb: 3 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f44336", mb: 1 }}>🔴 Uninitialized Pointers = Danger</Typography>
              <Typography variant="body2">
                <code>int *p;</code> without initialization points to a <strong>random address</strong>. Dereferencing 
                it causes undefined behavior—possibly a crash, possibly corrupting memory silently. Always initialize: 
                <code>int *p = NULL;</code> or <code>int *p = &someVar;</code>
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              Pointers to Pointers
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              A pointer can point to another pointer. This is used for dynamic 2D arrays, modifying pointers 
              passed to functions, and implementing data structures like linked lists.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`int x = 100;
int *p = &x;      // p points to x
int **pp = &p;    // pp points to p (pointer to pointer)

printf("x = %d\\n", x);            // 100
printf("*p = %d\\n", *p);          // 100
printf("**pp = %d\\n", **pp);      // 100

// Modifying through pointer-to-pointer
**pp = 200;
printf("x = %d\\n", x);            // 200

// Use case: function that allocates memory
void allocateBuffer(int **buf, int size) {
    *buf = malloc(size * sizeof(int));  // Modify caller's pointer
}

int *buffer = NULL;
allocateBuffer(&buffer, 100);  // Pass address of pointer
// buffer now points to allocated memory
free(buffer);

// Use case: 2D array with pointer-to-pointer
int **matrix = malloc(rows * sizeof(int*));
for (int i = 0; i < rows; i++) {
    matrix[i] = malloc(cols * sizeof(int));
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              const Pointers
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              The <code>const</code> keyword with pointers can protect the pointed-to data, the pointer itself, or both. 
              Reading <code>const</code> declarations right-to-left helps understand what's constant.
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f44336", 0.05), mb: 3, overflowX: "auto" }}>
              <Typography variant="body2" component="div" sx={{ fontFamily: "monospace" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: "2px solid rgba(244, 67, 54, 0.3)" }}>
                      <th style={{ textAlign: "left", padding: "8px", fontWeight: 700 }}>Declaration</th>
                      <th style={{ textAlign: "left", padding: "8px", fontWeight: 700 }}>Can modify *p?</th>
                      <th style={{ textAlign: "left", padding: "8px", fontWeight: 700 }}>Can modify p?</th>
                      <th style={{ textAlign: "left", padding: "8px", fontWeight: 700 }}>Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      { decl: "int *p", modData: "Yes", modPtr: "Yes", desc: "Non-const pointer to non-const data" },
                      { decl: "const int *p", modData: "No", modPtr: "Yes", desc: "Pointer to const (read-only data)" },
                      { decl: "int * const p", modData: "Yes", modPtr: "No", desc: "Const pointer (fixed address)" },
                      { decl: "const int * const p", modData: "No", modPtr: "No", desc: "Both are const" },
                    ].map((row, i) => (
                      <tr key={i} style={{ borderBottom: "1px solid rgba(244, 67, 54, 0.1)" }}>
                        <td style={{ padding: "6px 8px", color: "#f44336", fontFamily: "monospace" }}>{row.decl}</td>
                        <td style={{ padding: "6px 8px" }}>{row.modData}</td>
                        <td style={{ padding: "6px 8px" }}>{row.modPtr}</td>
                        <td style={{ padding: "6px 8px", fontSize: "0.85em" }}>{row.desc}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#4caf50", 0.1), border: `1px solid ${alpha("#4caf50", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon sx={{ color: "#4caf50" }} />
                Pointer Safety Best Practices
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Always initialize pointers" secondary="Use NULL or a valid address; never use uninitialized pointers" /></ListItem>
                <ListItem><ListItemText primary="Check for NULL before dereferencing" secondary="if (ptr != NULL) { *ptr = value; }" /></ListItem>
                <ListItem><ListItemText primary="Set pointers to NULL after free" secondary="Prevents use-after-free bugs" /></ListItem>
                <ListItem><ListItemText primary="Use const for input parameters" secondary="void print(const char *str) documents read-only intent" /></ListItem>
              </List>
            </Paper>
          </Paper>

          {/* Strings Section */}
          <Paper id="strings" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#8bc34a", 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2,
                  bgcolor: alpha("#8bc34a", 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#8bc34a",
                }}
              >
                <CodeIcon />
              </Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Strings
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Unlike many languages, C has no built-in string type. Strings are simply <strong>null-terminated arrays 
              of characters</strong>. This design is efficient but places responsibility on the programmer to manage 
              memory and prevent buffer overflows—a major source of security vulnerabilities in C programs.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3, color: "#8bc34a" }}>
              String Basics
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// A string is a char array ending with '\\0' (null terminator)
char str1[] = "Hello";  // Compiler adds \\0 automatically
// Memory: ['H']['e']['l']['l']['o']['\\0'] → 6 bytes!

char str2[6] = {'H', 'e', 'l', 'l', 'o', '\\0'};  // Same as above

// Character array WITHOUT null terminator (NOT a string!)
char chars[5] = {'H', 'e', 'l', 'l', 'o'};  // No \\0, NOT a string!

// String literals are read-only (stored in read-only memory)
char *ptr = "Hello";   // Points to string literal
// ptr[0] = 'h';       // UNDEFINED BEHAVIOR! May crash

// Modifiable string
char buf[] = "Hello";  // Copies literal into local array
buf[0] = 'h';          // OK: modifies the copy

// Empty string vs NULL pointer
char empty[] = "";     // Valid string with just '\\0' (length 0)
char *null_ptr = NULL; // Not a string, just a null pointer`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f44336", 0.1), border: `1px solid ${alpha("#f44336", 0.3)}`, mb: 3 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f44336", mb: 1 }}>⚠️ Buffer Overflow Risk</Typography>
              <Typography variant="body2">
                String functions don't check bounds. Writing past the buffer corrupts adjacent memory, causing 
                crashes or security vulnerabilities. <code>strcpy(small, "very long string")</code> is a classic 
                buffer overflow. Use bounded functions like <code>strncpy</code> or <code>snprintf</code>.
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8bc34a" }}>
              Essential String Functions
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              The <code>&lt;string.h&gt;</code> header provides string manipulation functions. Always ensure 
              destination buffers are large enough!
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { fn: "strlen(s)", desc: "Returns length of s (not including null terminator)", ex: "strlen(\"Hello\") → 5" },
                { fn: "strcpy(dst, src)", desc: "Copies src to dst (including null). UNSAFE: no bounds check!", ex: "strcpy(buf, \"Hi\");" },
                { fn: "strncpy(dst, src, n)", desc: "Copies at most n chars. May not null-terminate!", ex: "strncpy(buf, s, sizeof(buf)-1);" },
                { fn: "strcat(dst, src)", desc: "Appends src to end of dst. UNSAFE: no bounds check!", ex: "strcat(greeting, name);" },
                { fn: "strncat(dst, src, n)", desc: "Appends at most n chars, always null-terminates", ex: "strncat(buf, s, remaining);" },
                { fn: "strcmp(s1, s2)", desc: "Compares strings. Returns 0 if equal, <0 if s1<s2, >0 if s1>s2", ex: "if (strcmp(a, b) == 0)" },
                { fn: "strncmp(s1, s2, n)", desc: "Compares first n characters", ex: "strncmp(s, \"GET\", 3)" },
                { fn: "strchr(s, c)", desc: "Finds first occurrence of c in s. Returns pointer or NULL", ex: "char *p = strchr(s, '@');" },
                { fn: "strrchr(s, c)", desc: "Finds last occurrence of c in s", ex: "char *ext = strrchr(file, '.');" },
                { fn: "strstr(haystack, needle)", desc: "Finds first occurrence of needle in haystack", ex: "if (strstr(s, \"error\"))" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.fn}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#8bc34a", 0.05) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, fontFamily: "monospace", color: "#8bc34a" }}>{item.fn}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.85rem" }}>{item.desc}</Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#4ec9b0", p: 0.5, borderRadius: 1, display: "inline-block", mt: 0.5 }}>
                      {item.ex}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8bc34a" }}>
              Safe String Handling
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Traditional functions like <code>strcpy</code> and <code>sprintf</code> are dangerous. Modern code 
              should use bounded alternatives:
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`#include <stdio.h>
#include <string.h>

char buffer[50];

// BAD: No bounds checking
strcpy(buffer, input);     // Buffer overflow if input > 49 chars!
sprintf(buffer, "%s", s);  // Same problem

// BETTER: Bounded versions
strncpy(buffer, input, sizeof(buffer) - 1);
buffer[sizeof(buffer) - 1] = '\\0';  // strncpy may not null-terminate!

// BEST: snprintf always null-terminates and returns needed size
int needed = snprintf(buffer, sizeof(buffer), "Hello, %s!", name);
if (needed >= sizeof(buffer)) {
    printf("Warning: string truncated\\n");
}

// Reading strings safely
char line[100];
// BAD: gets() - NEVER use, removed in C11
// gets(line);  // No length limit!

// GOOD: fgets() - specify buffer size
if (fgets(line, sizeof(line), stdin) != NULL) {
    // Remove trailing newline if present
    size_t len = strlen(line);
    if (len > 0 && line[len-1] == '\\n') {
        line[len-1] = '\\0';
    }
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8bc34a" }}>
              String Input and Output
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Output
char *name = "Alice";
printf("%s\\n", name);           // Print string
printf("%.5s\\n", "Hello World"); // Print first 5 chars: "Hello"
printf("%10s\\n", "Hi");          // Right-aligned in 10 chars: "        Hi"
printf("%-10s|\\n", "Hi");        // Left-aligned: "Hi        |"

// Character-by-character output
puts("Hello");     // Prints string + newline
fputs("Hi", stdout); // Prints without newline

// Input
char buffer[100];

// scanf with %s stops at whitespace, no bounds checking!
scanf("%s", buffer);              // DANGEROUS!
scanf("%99s", buffer);            // Better: limit input

// fgets is safer
fgets(buffer, sizeof(buffer), stdin);

// Reading a whole line including spaces
scanf("%99[^\\n]", buffer);        // Read until newline

// Parsing strings
int age;
char name[50];
sscanf("Alice 25", "%49s %d", name, &age);  // Parse from string`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8bc34a" }}>
              Common String Patterns
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Iterate through characters
const char *str = "Hello";
for (int i = 0; str[i] != '\\0'; i++) {
    printf("%c ", str[i]);
}
// Or with pointer
for (const char *p = str; *p; p++) {
    printf("%c ", *p);
}

// Reverse a string in place
void reverse(char *s) {
    int len = strlen(s);
    for (int i = 0; i < len / 2; i++) {
        char temp = s[i];
        s[i] = s[len - 1 - i];
        s[len - 1 - i] = temp;
    }
}

// Tokenizing
char text[] = "apple,banana,cherry";
char *token = strtok(text, ",");
while (token != NULL) {
    printf("%s\\n", token);
    token = strtok(NULL, ",");  // Continue tokenizing
}
// Note: strtok modifies the original string!

// Case conversion (from <ctype.h>)
#include <ctype.h>
char c = 'a';
char upper = toupper(c);  // 'A'
char lower = tolower('B'); // 'b'`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#4caf50", 0.1), border: `1px solid ${alpha("#4caf50", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon sx={{ color: "#4caf50" }} />
                String Safety Checklist
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Always allocate n+1 for strings of length n" secondary="Don't forget the null terminator!" /></ListItem>
                <ListItem><ListItemText primary="Use snprintf instead of sprintf" secondary="Prevents buffer overflow and tells you if truncated" /></ListItem>
                <ListItem><ListItemText primary="Never use gets()" secondary="Use fgets() instead; gets() was removed from C11" /></ListItem>
                <ListItem><ListItemText primary="Validate string pointers before use" secondary="Check for NULL: if (str != NULL && *str != '\\0')" /></ListItem>
              </List>
            </Paper>
          </Paper>

          {/* Structures & Unions Section */}
          <Paper id="structs" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#673ab7", 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2,
                  bgcolor: alpha("#673ab7", 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#673ab7",
                }}
              >
                <DeveloperBoardIcon />
              </Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Structures & Unions
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              <strong>Structures</strong> (structs) allow you to group related data of different types into a single 
              unit. They're the foundation for creating custom data types and are essential for organizing complex 
              data. <strong>Unions</strong> are similar but share memory between members—useful for type punning and 
              memory-efficient variant types.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3, color: "#673ab7" }}>
              Defining and Using Structures
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Define a structure
struct Point {
    int x;
    int y;
};

// Declare struct variables
struct Point p1;           // Uninitialized
struct Point p2 = {10, 20}; // Initialize x=10, y=20
struct Point p3 = {.y = 5, .x = 3};  // Designated initializers (C99)
struct Point p4 = {0};     // Zero-initialize all members

// Access members with dot operator
p1.x = 100;
p1.y = 200;
printf("Point: (%d, %d)\\n", p1.x, p1.y);

// More complex structure
struct Person {
    char name[50];
    int age;
    double height;
    struct Point location;  // Nested structure
};

struct Person alice = {
    .name = "Alice",
    .age = 30,
    .height = 1.65,
    .location = {100, 200}
};

printf("%s is at (%d, %d)\\n", alice.name, 
       alice.location.x, alice.location.y);`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#673ab7" }}>
              typedef for Cleaner Code
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              The <code>typedef</code> keyword creates an alias for a type, allowing you to use a shorter name 
              instead of <code>struct StructName</code> everywhere:
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Method 1: Separate typedef
struct point {
    int x, y;
};
typedef struct point Point;

// Method 2: Combined (most common)
typedef struct {
    int x, y;
} Point;

// Now you can use Point instead of struct point
Point p1 = {10, 20};
Point p2;
p2.x = 5;

// For self-referential structs (linked lists), need the tag:
typedef struct Node {
    int data;
    struct Node *next;  // Can't use 'Node' here yet
} Node;

Node *head = NULL;`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#673ab7" }}>
              Pointers to Structures
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Structures are often accessed through pointers, especially when passed to functions (to avoid copying) 
              or when dynamically allocated. Use the <code>-&gt;</code> operator to access members through a pointer.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`typedef struct {
    char name[50];
    int age;
} Person;

Person alice = {"Alice", 30};
Person *ptr = &alice;

// Two ways to access members through pointer:
printf("Age: %d\\n", (*ptr).age);  // Dereference, then dot
printf("Age: %d\\n", ptr->age);    // Arrow operator (preferred)

// Passing struct to function by pointer (efficient)
void birthday(Person *p) {
    p->age++;  // Modifies original
}

birthday(&alice);
printf("Alice is now %d\\n", alice.age);  // 31

// Dynamic allocation
Person *bob = malloc(sizeof(Person));
if (bob != NULL) {
    strcpy(bob->name, "Bob");
    bob->age = 25;
    // Use bob...
    free(bob);
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#673ab7" }}>
              Memory Layout and Padding
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Compilers align struct members for efficient CPU access, adding <strong>padding bytes</strong> between 
              members. The order of members affects struct size!
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Bad ordering (wastes space)
struct BadOrder {
    char a;     // 1 byte + 3 padding
    int b;      // 4 bytes
    char c;     // 1 byte + 3 padding
};  // Total: 12 bytes

// Good ordering (no wasted space)
struct GoodOrder {
    int b;      // 4 bytes
    char a;     // 1 byte
    char c;     // 1 byte + 2 padding
};  // Total: 8 bytes

printf("Bad: %zu, Good: %zu\\n", 
       sizeof(struct BadOrder),    // 12
       sizeof(struct GoodOrder));  // 8

// Get offset of a member
#include <stddef.h>
printf("Offset of 'b': %zu\\n", offsetof(struct GoodOrder, b));

// Packed structs (no padding, but slower access)
struct __attribute__((packed)) Packet {
    char type;
    int length;
    char data[10];
};  // Exactly 15 bytes, no padding`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#673ab7" }}>
              Unions
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              A <strong>union</strong> is like a struct, but all members share the same memory location. Only one 
              member can hold a value at a time. The union's size equals the largest member's size.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Union definition
union Data {
    int i;
    float f;
    char str[20];
};

union Data d;
printf("Size: %zu\\n", sizeof(d));  // 20 (size of largest member)

// Only one member is valid at a time
d.i = 42;
printf("d.i = %d\\n", d.i);  // 42

d.f = 3.14;
// d.i is now garbage! Only d.f is valid
printf("d.f = %f\\n", d.f);  // 3.14

// Common use: Type-punning (view one type as another)
union {
    float f;
    unsigned int bits;
} converter;

converter.f = 3.14f;
printf("Float bits: 0x%08X\\n", converter.bits);  // IEEE 754 representation

// Common use: Tagged union (variant type)
typedef struct {
    enum { INT, FLOAT, STRING } type;  // Tag
    union {
        int i;
        float f;
        char *s;
    } value;
} Variant;

Variant v;
v.type = INT;
v.value.i = 42;`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#673ab7" }}>
              Enumerations
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              <code>enum</code> creates named integer constants, making code more readable than magic numbers:
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Basic enum (values start at 0)
enum Color { RED, GREEN, BLUE };  // RED=0, GREEN=1, BLUE=2

enum Color c = GREEN;
if (c == GREEN) {
    printf("Color is green\\n");
}

// Explicit values
enum Status {
    OK = 0,
    ERROR = -1,
    PENDING = 100
};

// Flags (powers of 2 for bit operations)
enum Permissions {
    PERM_READ = 1,    // 0001
    PERM_WRITE = 2,   // 0010
    PERM_EXEC = 4,    // 0100
    PERM_DELETE = 8   // 1000
};

int perms = PERM_READ | PERM_WRITE;
if (perms & PERM_READ) {
    printf("Has read permission\\n");
}

// typedef with enum
typedef enum { FALSE, TRUE } bool;  // Pre-C99 boolean
bool done = FALSE;`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#4caf50", 0.1), border: `1px solid ${alpha("#4caf50", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon sx={{ color: "#4caf50" }} />
                Best Practices for Structures
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Order members by size (largest first)" secondary="Reduces padding and struct size" /></ListItem>
                <ListItem><ListItemText primary="Use typedef for cleaner code" secondary="typedef struct { ... } Name; avoids writing struct everywhere" /></ListItem>
                <ListItem><ListItemText primary="Pass large structs by pointer" secondary="Avoid expensive copying; use const if read-only" /></ListItem>
                <ListItem><ListItemText primary="Initialize all members" secondary="Use designated initializers: {.x=1, .y=2}" /></ListItem>
              </List>
            </Paper>
          </Paper>

          {/* Dynamic Memory Management Section */}
          <Paper id="memory" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#ff5722", 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2,
                  bgcolor: alpha("#ff5722", 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#ff5722",
                }}
              >
                <MemoryIcon />
              </Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Dynamic Memory Management
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Dynamic memory allocation allows programs to request memory at runtime from the <strong>heap</strong>. 
              Unlike stack-allocated variables (automatic storage), heap memory persists until explicitly freed. 
              This power comes with responsibility—improper memory management causes leaks, corruption, and 
              security vulnerabilities.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3, color: "#ff5722" }}>
              Stack vs Heap
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#ff5722", 0.05), height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ff5722", mb: 1 }}>Stack (Automatic)</Typography>
                  <List dense disablePadding>
                    <ListItem disableGutters><ListItemText primary="Function local variables" /></ListItem>
                    <ListItem disableGutters><ListItemText primary="Automatically allocated/freed" /></ListItem>
                    <ListItem disableGutters><ListItemText primary="Fixed size, limited (typically ~1MB)" /></ListItem>
                    <ListItem disableGutters><ListItemText primary="Very fast allocation" /></ListItem>
                    <ListItem disableGutters><ListItemText primary="LIFO (Last In First Out)" /></ListItem>
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#ff5722", 0.05), height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ff5722", mb: 1 }}>Heap (Dynamic)</Typography>
                  <List dense disablePadding>
                    <ListItem disableGutters><ListItemText primary="Explicitly managed with malloc/free" /></ListItem>
                    <ListItem disableGutters><ListItemText primary="Programmer controls lifetime" /></ListItem>
                    <ListItem disableGutters><ListItemText primary="Large size (limited by system RAM)" /></ListItem>
                    <ListItem disableGutters><ListItemText primary="Slower allocation" /></ListItem>
                    <ListItem disableGutters><ListItemText primary="Can be fragmented" /></ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff5722" }}>
              Allocation Functions
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`#include <stdlib.h>

// malloc: allocate uninitialized memory
void *malloc(size_t size);

int *p = malloc(sizeof(int));      // Single int
int *arr = malloc(10 * sizeof(int)); // Array of 10 ints

// ALWAYS check for allocation failure
if (arr == NULL) {
    perror("malloc failed");
    return -1;
}

// calloc: allocate and zero-initialize
void *calloc(size_t count, size_t size);

int *zeros = calloc(10, sizeof(int));  // 10 ints, all zero
// Equivalent to: malloc(10 * sizeof(int)) + memset to 0

// realloc: resize existing allocation
void *realloc(void *ptr, size_t new_size);

// Grow array from 10 to 20 elements
int *new_arr = realloc(arr, 20 * sizeof(int));
if (new_arr == NULL) {
    // arr is still valid! Don't lose it
    free(arr);
    return -1;
}
arr = new_arr;  // Safe to use larger array

// free: release memory
void free(void *ptr);

free(arr);
arr = NULL;  // Good practice: prevent use-after-free

// free(NULL) is safe and does nothing`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff5722" }}>
              Common Memory Bugs
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Memory bugs are among the most dangerous in C. They can cause crashes, data corruption, and 
              security vulnerabilities (buffer overflows, use-after-free exploits).
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { 
                  bug: "Memory Leak", 
                  desc: "Forgetting to free allocated memory. Memory fills up over time.",
                  code: "char *s = malloc(100);\nreturn; // Leak! s never freed"
                },
                { 
                  bug: "Use-After-Free", 
                  desc: "Accessing memory after free. May crash or return garbage/attacker data.",
                  code: "free(ptr);\nprintf(\"%d\", *ptr); // Undefined!"
                },
                { 
                  bug: "Double Free", 
                  desc: "Calling free twice on same pointer. Can corrupt heap metadata.",
                  code: "free(ptr);\nfree(ptr); // Crash or exploit"
                },
                { 
                  bug: "Dangling Pointer", 
                  desc: "Pointer to freed memory. Set to NULL after free to catch errors.",
                  code: "int *p = malloc(4);\nfree(p);\n*p = 5; // Dangling!"
                },
                { 
                  bug: "Buffer Overflow", 
                  desc: "Writing past allocated memory. Overwrites adjacent data.",
                  code: "char *s = malloc(5);\nstrcpy(s, \"Hello!\"); // Overflow!"
                },
                { 
                  bug: "Uninitialized Read", 
                  desc: "Reading malloc'd memory before writing. Contains garbage.",
                  code: "int *p = malloc(4);\nprintf(\"%d\", *p); // Garbage"
                },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.bug}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ff5722", 0.05), borderLeft: `4px solid #ff5722` }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ff5722" }}>{item.bug}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.85rem", mb: 1 }}>{item.desc}</Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#f44336", p: 1, borderRadius: 1, display: "block", whiteSpace: "pre-wrap" }}>
                      {item.code}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff5722" }}>
              Safe Memory Patterns
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Pattern 1: Always check malloc return value
int *data = malloc(n * sizeof(int));
if (data == NULL) {
    fprintf(stderr, "Out of memory\\n");
    exit(EXIT_FAILURE);
}

// Pattern 2: Set pointer to NULL after free
free(data);
data = NULL;

// Pattern 3: Safe realloc
int *new_data = realloc(data, new_size);
if (new_data == NULL) {
    // data is still valid, handle error
    free(data);
    return NULL;
}
data = new_data;

// Pattern 4: RAII-style cleanup with goto
int process_data(void) {
    int *buffer = NULL;
    FILE *fp = NULL;
    int result = -1;
    
    buffer = malloc(BUF_SIZE);
    if (!buffer) goto cleanup;
    
    fp = fopen("data.txt", "r");
    if (!fp) goto cleanup;
    
    // Process data...
    result = 0;
    
cleanup:
    free(buffer);  // free(NULL) is safe
    if (fp) fclose(fp);
    return result;
}

// Pattern 5: Wrapper function
void *safe_malloc(size_t size) {
    void *ptr = malloc(size);
    if (ptr == NULL && size > 0) {
        fprintf(stderr, "Fatal: out of memory\\n");
        abort();
    }
    return ptr;
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff5722" }}>
              Memory Debugging Tools
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Memory bugs are hard to find manually. Use tools to detect them:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { tool: "Valgrind (Linux)", desc: "Detects leaks, invalid reads/writes, uninitialized memory. Run: valgrind --leak-check=full ./program" },
                { tool: "AddressSanitizer", desc: "Compiler flag (-fsanitize=address) catches buffer overflows, use-after-free. Fast and precise." },
                { tool: "Dr. Memory (Windows)", desc: "Similar to Valgrind. Detects memory errors and leaks on Windows." },
                { tool: "Static Analyzers", desc: "Tools like clang-tidy, Coverity find bugs without running code." },
              ].map((t) => (
                <Grid item xs={12} sm={6} key={t.tool}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ff5722", 0.05) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{t.tool}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.85rem" }}>{t.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#4caf50", 0.1), border: `1px solid ${alpha("#4caf50", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon sx={{ color: "#4caf50" }} />
                Memory Management Golden Rules
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Every malloc needs a matching free" secondary="Track allocations carefully; use ownership patterns" /></ListItem>
                <ListItem><ListItemText primary="Always check allocation results" secondary="malloc returns NULL on failure" /></ListItem>
                <ListItem><ListItemText primary="Set pointers to NULL after free" secondary="Makes use-after-free bugs more obvious" /></ListItem>
                <ListItem><ListItemText primary="Use Valgrind/ASan during development" secondary="Catch memory bugs before production" /></ListItem>
              </List>
            </Paper>
          </Paper>

          {/* File I/O Section */}
          <Paper id="file-io" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#607d8b", 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2,
                  bgcolor: alpha("#607d8b", 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#607d8b",
                }}
              >
                <StorageIcon />
              </Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                File I/O
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              File I/O in C uses the <strong>FILE</strong> pointer abstraction from <code>&lt;stdio.h&gt;</code>. 
              The standard library provides functions for opening, reading, writing, and closing files in both 
              text and binary modes. Proper error handling and resource cleanup are essential for robust file operations.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3, color: "#607d8b" }}>
              Opening and Closing Files
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`#include <stdio.h>

// fopen: open a file
FILE *fp = fopen("data.txt", "r");  // Open for reading

// ALWAYS check if open succeeded
if (fp == NULL) {
    perror("Failed to open file");  // Prints system error
    return -1;
}

// File modes:
// "r"  - Read (file must exist)
// "w"  - Write (creates/truncates)
// "a"  - Append (creates if needed)
// "r+" - Read/write (must exist)
// "w+" - Read/write (creates/truncates)
// "a+" - Read/append
// Add "b" for binary: "rb", "wb", "ab"

// fclose: close the file (flushes buffers)
if (fclose(fp) != 0) {
    perror("Error closing file");
}
fp = NULL;  // Good practice

// Standard streams (already open)
// stdin  - Standard input (keyboard)
// stdout - Standard output (console)
// stderr - Standard error (console, unbuffered)`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#607d8b" }}>
              Text File Operations
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Character I/O
int c = fgetc(fp);       // Read one character (returns int for EOF)
fputc('A', fp);          // Write one character

// String I/O
char buffer[100];
fgets(buffer, sizeof(buffer), fp);  // Read line (safe, includes \\n)
fputs("Hello\\n", fp);               // Write string (no auto \\n)

// Formatted I/O (like printf/scanf)
fprintf(fp, "Name: %s, Age: %d\\n", name, age);
fscanf(fp, "%s %d", name, &age);

// Example: Read file line by line
FILE *fp = fopen("input.txt", "r");
if (fp) {
    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        printf("%s", line);  // fgets keeps the \\n
    }
    fclose(fp);
}

// Example: Write formatted data
FILE *out = fopen("output.txt", "w");
if (out) {
    for (int i = 0; i < 10; i++) {
        fprintf(out, "Line %d\\n", i);
    }
    fclose(out);
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#607d8b" }}>
              Binary File Operations
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Binary mode reads/writes raw bytes without text transformations. Use for structured data, 
              images, and any non-text files.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// fread/fwrite for binary data
size_t fread(void *ptr, size_t size, size_t count, FILE *fp);
size_t fwrite(const void *ptr, size_t size, size_t count, FILE *fp);

// Writing an array of structs
typedef struct { int id; char name[50]; } Record;
Record records[100];
// ... fill records ...

FILE *fp = fopen("data.bin", "wb");
if (fp) {
    size_t written = fwrite(records, sizeof(Record), 100, fp);
    printf("Wrote %zu records\\n", written);
    fclose(fp);
}

// Reading the array back
FILE *fp2 = fopen("data.bin", "rb");
if (fp2) {
    Record loaded[100];
    size_t read = fread(loaded, sizeof(Record), 100, fp2);
    printf("Read %zu records\\n", read);
    fclose(fp2);
}

// Reading individual bytes
unsigned char byte;
while (fread(&byte, 1, 1, fp) == 1) {
    printf("%02X ", byte);
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#607d8b" }}>
              File Positioning
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// ftell: get current position
long pos = ftell(fp);

// fseek: move to position
// SEEK_SET - from beginning
// SEEK_CUR - from current position  
// SEEK_END - from end
fseek(fp, 0, SEEK_SET);     // Go to beginning
fseek(fp, 100, SEEK_SET);   // Go to byte 100
fseek(fp, -10, SEEK_END);   // Go to 10 bytes before end
fseek(fp, 5, SEEK_CUR);     // Move forward 5 bytes

// rewind: go to beginning (clears error indicators)
rewind(fp);  // Same as fseek(fp, 0, SEEK_SET)

// Example: Get file size
fseek(fp, 0, SEEK_END);
long size = ftell(fp);
rewind(fp);
printf("File size: %ld bytes\\n", size);

// Example: Read specific record
int recordNum = 5;
fseek(fp, recordNum * sizeof(Record), SEEK_SET);
Record rec;
fread(&rec, sizeof(Record), 1, fp);`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#607d8b" }}>
              Error Handling
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Check for errors
if (ferror(fp)) {
    fprintf(stderr, "Error reading file\\n");
    clearerr(fp);  // Clear error indicator
}

// Check for end-of-file
if (feof(fp)) {
    printf("Reached end of file\\n");
}

// perror prints system error message
if (fp == NULL) {
    perror("fopen");  // Prints: "fopen: No such file or directory"
}

// errno contains error code
#include <errno.h>
if (fclose(fp) != 0) {
    printf("Error %d: %s\\n", errno, strerror(errno));
}

// Robust file reading pattern
FILE *fp = fopen(filename, "r");
if (!fp) {
    perror(filename);
    return -1;
}

char buffer[1024];
while (fgets(buffer, sizeof(buffer), fp)) {
    // Process line
}

if (ferror(fp)) {
    perror("Read error");
}

fclose(fp);`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#4caf50", 0.1), border: `1px solid ${alpha("#4caf50", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon sx={{ color: "#4caf50" }} />
                File I/O Best Practices
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Always check fopen return value" secondary="File may not exist or lack permissions" /></ListItem>
                <ListItem><ListItemText primary="Close files when done" secondary="Flushes buffers and releases resources" /></ListItem>
                <ListItem><ListItemText primary="Use binary mode for non-text data" secondary="Prevents newline translation issues" /></ListItem>
                <ListItem><ListItemText primary="Check fread/fwrite return values" secondary="Partial reads/writes are possible" /></ListItem>
              </List>
            </Paper>
          </Paper>

          {/* Preprocessor Section */}
          <Paper id="preprocessor" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#795548", 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2,
                  bgcolor: alpha("#795548", 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#795548",
                }}
              >
                <BuildIcon />
              </Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                The C Preprocessor
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              The <strong>preprocessor</strong> runs before the compiler, performing text transformations on your 
              source code. It handles file inclusion, macro expansion, and conditional compilation. Preprocessor 
              directives start with <code>#</code> and are not C statements (no semicolons).
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3, color: "#795548" }}>
              File Inclusion
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Include standard library headers
#include <stdio.h>    // Searches system directories first
#include <stdlib.h>
#include <string.h>

// Include your own headers
#include "myheader.h"  // Searches current directory first
#include "utils/helper.h"

// The preprocessor literally copies the header content here
// This is why headers need include guards to prevent double inclusion`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#795548" }}>
              Macros and #define
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Object-like macros (constants)
#define PI 3.14159
#define MAX_SIZE 100
#define VERSION "1.0.0"

double area = PI * r * r;  // PI replaced with 3.14159

// Function-like macros
#define SQUARE(x) ((x) * (x))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define PRINT_VAR(x) printf(#x " = %d\\n", x)

int result = SQUARE(5);  // Expands to: ((5) * (5))
int m = MAX(a, b);       // Expands to: ((a) > (b) ? (a) : (b))
PRINT_VAR(count);        // Expands to: printf("count" " = %d\\n", count)

// DANGER: Macros are text substitution!
#define BAD_SQUARE(x) x * x
int val = BAD_SQUARE(2 + 3);  // Becomes: 2 + 3 * 2 + 3 = 11, not 25!

// Always parenthesize macro arguments and the whole expression
#define GOOD_SQUARE(x) ((x) * (x))

// Undefine a macro
#undef PI

// Multi-line macros (use backslash)
#define SWAP(a, b) do { \\
    typeof(a) temp = a; \\
    a = b; \\
    b = temp; \\
} while(0)

// Token pasting (##)
#define MAKE_FUNC(name) void func_##name(void)
MAKE_FUNC(test);  // Creates: void func_test(void)

// Stringification (#)
#define STRINGIFY(x) #x
printf("%s\\n", STRINGIFY(hello));  // Prints: hello`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ff9800", 0.1), border: `1px solid ${alpha("#ff9800", 0.3)}`, mb: 3 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ff9800", mb: 1 }}>⚠️ Macro Pitfalls</Typography>
              <Typography variant="body2">
                Macros have no type checking and can cause subtle bugs. <code>MAX(i++, j)</code> may increment 
                <code>i</code> twice! For type-safe alternatives, use <code>inline</code> functions (C99+) 
                or <code>static inline</code> functions in headers.
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#795548" }}>
              Conditional Compilation
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Compile different code based on conditions—useful for platform-specific code, debugging, 
              and feature flags:
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// #ifdef / #ifndef - check if macro is defined
#define DEBUG

#ifdef DEBUG
    printf("Debug: x = %d\\n", x);
#endif

#ifndef RELEASE
    // Code for non-release builds
#endif

// #if / #elif / #else - evaluate expressions
#if VERSION >= 2
    // Code for version 2+
#elif VERSION == 1
    // Code for version 1
#else
    // Fallback code
#endif

// Check if macro is defined (alternative syntax)
#if defined(DEBUG) && defined(VERBOSE)
    // Both DEBUG and VERBOSE are defined
#endif

// Platform-specific code
#ifdef _WIN32
    #include <windows.h>
    #define CLEAR_SCREEN "cls"
#elif defined(__linux__)
    #include <unistd.h>
    #define CLEAR_SCREEN "clear"
#elif defined(__APPLE__)
    #include <unistd.h>
    #define CLEAR_SCREEN "clear"
#endif

// Compiler-specific code
#ifdef __GNUC__
    #define UNUSED __attribute__((unused))
#else
    #define UNUSED
#endif`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#795548" }}>
              Header Guards
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Header guards prevent multiple inclusion of the same header, which would cause redefinition errors:
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// myheader.h - Traditional include guards
#ifndef MYHEADER_H
#define MYHEADER_H

// Header content goes here
void my_function(void);
extern int global_var;

#endif // MYHEADER_H

// Alternative: #pragma once (non-standard but widely supported)
#pragma once

void my_function(void);
extern int global_var;`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#795548" }}>
              Predefined Macros
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#795548", 0.05), mb: 3, overflowX: "auto" }}>
              <Typography variant="body2" component="div" sx={{ fontFamily: "monospace" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: "2px solid rgba(121, 85, 72, 0.3)" }}>
                      <th style={{ textAlign: "left", padding: "8px", fontWeight: 700 }}>Macro</th>
                      <th style={{ textAlign: "left", padding: "8px", fontWeight: 700 }}>Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      { macro: "__FILE__", desc: "Current filename as a string" },
                      { macro: "__LINE__", desc: "Current line number as an integer" },
                      { macro: "__DATE__", desc: "Compilation date (\"Jan 25 2026\")" },
                      { macro: "__TIME__", desc: "Compilation time (\"14:30:00\")" },
                      { macro: "__func__", desc: "Current function name (C99)" },
                      { macro: "__STDC__", desc: "1 if compiler conforms to C standard" },
                      { macro: "__STDC_VERSION__", desc: "C standard version (199901L for C99, 201112L for C11)" },
                    ].map((row, i) => (
                      <tr key={i} style={{ borderBottom: "1px solid rgba(121, 85, 72, 0.1)" }}>
                        <td style={{ padding: "6px 8px", color: "#795548", fontWeight: 700 }}>{row.macro}</td>
                        <td style={{ padding: "6px 8px" }}>{row.desc}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="caption" sx={{ color: "#6a9955", fontFamily: "monospace" }}>// Common uses of predefined macros</Typography>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`
// Debug logging with file and line
#define LOG(msg) printf("[%s:%d] %s\\n", __FILE__, __LINE__, msg)

LOG("Starting process");  // [main.c:42] Starting process

// Assert macro
#define ASSERT(cond) do { \\
    if (!(cond)) { \\
        fprintf(stderr, "Assertion failed: %s\\n", #cond); \\
        fprintf(stderr, "  File: %s, Line: %d\\n", __FILE__, __LINE__); \\
        fprintf(stderr, "  Function: %s\\n", __func__); \\
        abort(); \\
    } \\
} while(0)

ASSERT(ptr != NULL);`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#4caf50", 0.1), border: `1px solid ${alpha("#4caf50", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon sx={{ color: "#4caf50" }} />
                Preprocessor Best Practices
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Use UPPER_CASE for macro names" secondary="Distinguishes macros from variables/functions" /></ListItem>
                <ListItem><ListItemText primary="Always use include guards" secondary="Prevents redefinition errors from multiple inclusion" /></ListItem>
                <ListItem><ListItemText primary="Parenthesize macro arguments" secondary="#define SQUARE(x) ((x) * (x)) not #define SQUARE(x) x * x" /></ListItem>
                <ListItem><ListItemText primary="Prefer inline functions over macros" secondary="Type-safe and debuggable" /></ListItem>
              </List>
            </Paper>
          </Paper>

          {/* Advanced Topics Section */}
          <Paper id="advanced" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#3f51b5", 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2,
                  bgcolor: alpha("#3f51b5", 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#3f51b5",
                }}
              >
                <BugReportIcon />
              </Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Advanced Topics
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              These advanced C concepts are essential for systems programming, embedded development, and understanding 
              how software interacts with hardware. They give you fine-grained control but require careful use to 
              avoid undefined behavior.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3, color: "#3f51b5" }}>
              Void Pointers
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              A <code>void*</code> is a generic pointer that can hold the address of any data type. It cannot be 
              dereferenced directly—you must cast it to a specific type first. Void pointers are used for generic 
              functions like <code>malloc</code>, <code>memcpy</code>, and callback mechanisms.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// void pointer basics
void *generic;
int x = 42;
double d = 3.14;

generic = &x;               // Can point to int
int *ip = (int*)generic;    // Cast back to use
printf("%d\\n", *ip);        // 42

generic = &d;               // Can point to double
double *dp = (double*)generic;
printf("%f\\n", *dp);        // 3.14

// Cannot dereference void* directly
// printf("%d\\n", *generic);  // ERROR!

// Generic function example (like qsort's compare)
int compare_ints(const void *a, const void *b) {
    int int_a = *(const int*)a;
    int int_b = *(const int*)b;
    return int_a - int_b;
}

// Using qsort with void pointers
int arr[] = {5, 2, 8, 1, 9};
qsort(arr, 5, sizeof(int), compare_ints);

// memcpy uses void* for any data type
void *memcpy(void *dest, const void *src, size_t n);
memcpy(dest_array, src_array, sizeof(src_array));`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3f51b5" }}>
              The volatile Keyword
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              <code>volatile</code> tells the compiler that a variable's value may change unexpectedly (by hardware, 
              another thread, or signal handler). The compiler won't optimize away reads or reorder operations on 
              volatile variables.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Memory-mapped I/O (hardware register)
volatile unsigned int *status_reg = (volatile unsigned int*)0x40000000;

// Wait for hardware ready bit (without volatile, compiler might optimize away)
while ((*status_reg & 0x01) == 0) {
    // Busy wait - compiler MUST re-read status_reg each iteration
}

// Signal handler flag
volatile sig_atomic_t got_signal = 0;

void signal_handler(int sig) {
    got_signal = 1;  // Set by signal handler
}

int main() {
    signal(SIGINT, signal_handler);
    
    while (!got_signal) {
        // Do work - volatile ensures got_signal is checked each iteration
    }
    printf("Signal received\\n");
    return 0;
}

// Note: volatile does NOT provide atomicity or thread safety!
// For multi-threading, use proper synchronization (mutex, atomic types)`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3f51b5" }}>
              Bit Fields
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Bit fields allow you to specify the exact number of bits for struct members, useful for memory-constrained 
              systems, hardware registers, and protocol parsing.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Bit field syntax
struct PackedFlags {
    unsigned int read : 1;     // 1 bit
    unsigned int write : 1;    // 1 bit
    unsigned int execute : 1;  // 1 bit
    unsigned int : 5;          // 5 bits padding (unnamed)
    unsigned int priority : 4; // 4 bits (0-15)
};

struct PackedFlags flags = {0};
flags.read = 1;
flags.write = 1;
flags.priority = 7;

printf("Size: %zu bytes\\n", sizeof(flags));  // Usually 4 bytes

// Real-world example: TCP header flags
struct TCPFlags {
    unsigned int fin : 1;
    unsigned int syn : 1;
    unsigned int rst : 1;
    unsigned int psh : 1;
    unsigned int ack : 1;
    unsigned int urg : 1;
};

// Warning: Bit field layout is implementation-defined
// Don't use for portable binary file formats`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3f51b5" }}>
              Inline Assembly
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              GCC and Clang support inline assembly for embedding assembly instructions directly in C code. This 
              is useful for accessing hardware features, atomic operations, and performance-critical sections.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Basic inline assembly (GCC/Clang x86-64)
int result;
int a = 10, b = 5;

// GCC extended asm syntax
asm volatile (
    "addl %1, %0"       // Assembly instruction
    : "=r" (result)     // Output operands
    : "r" (a), "0" (b)  // Input operands
    : "cc"              // Clobbered registers
);
printf("result = %d\\n", result);  // 15

// Read CPU timestamp counter
unsigned long long rdtsc(void) {
    unsigned int lo, hi;
    asm volatile (
        "rdtsc"
        : "=a" (lo), "=d" (hi)
    );
    return ((unsigned long long)hi << 32) | lo;
}

// Memory barrier
asm volatile ("mfence" ::: "memory");

// Breakpoint for debugging
asm volatile ("int $3");  // x86 breakpoint interrupt

// CPUID instruction
void cpuid(int code, int *a, int *b, int *c, int *d) {
    asm volatile (
        "cpuid"
        : "=a" (*a), "=b" (*b), "=c" (*c), "=d" (*d)
        : "a" (code)
    );
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3f51b5" }}>
              Signal Handling
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Signals are software interrupts that allow processes to handle asynchronous events like Ctrl+C, 
              segmentation faults, and timer expirations.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

volatile sig_atomic_t running = 1;

// Signal handler (must be async-signal-safe!)
void handle_sigint(int sig) {
    // Only set flags - don't call printf, malloc, etc.
    running = 0;
}

void handle_sigsegv(int sig) {
    fprintf(stderr, "Segmentation fault!\\n");
    exit(EXIT_FAILURE);
}

int main(void) {
    // Register signal handlers
    signal(SIGINT, handle_sigint);   // Ctrl+C
    signal(SIGSEGV, handle_sigsegv); // Segfault
    
    printf("Press Ctrl+C to stop...\\n");
    
    while (running) {
        // Main loop
        sleep(1);
        printf("Working...\\n");
    }
    
    printf("Gracefully shutting down\\n");
    return 0;
}

// Common signals:
// SIGINT  - Ctrl+C (interrupt)
// SIGTERM - Termination request
// SIGSEGV - Segmentation fault
// SIGFPE  - Floating-point exception
// SIGALRM - Alarm timer expired
// SIGCHLD - Child process state changed`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3f51b5" }}>
              Restrict Keyword (C99)
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              The <code>restrict</code> qualifier tells the compiler that a pointer is the only way to access the 
              memory it points to. This enables aggressive optimizations, especially in loops.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Without restrict, compiler assumes dst and src might overlap
void copy(int *dst, const int *src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        dst[i] = src[i];  // Must reload src[i] each iteration
    }
}

// With restrict, compiler knows they don't overlap
void fast_copy(int * restrict dst, const int * restrict src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        dst[i] = src[i];  // Can optimize more aggressively
    }
}

// Standard library uses restrict
void *memcpy(void * restrict dest, const void * restrict src, size_t n);
// vs memmove which handles overlapping:
void *memmove(void *dest, const void *src, size_t n);

// Warning: Using restrict incorrectly is undefined behavior!
// Only use when you KNOW pointers don't alias`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3f51b5" }}>
              Compound Literals (C99)
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Create unnamed arrays and structs inline
typedef struct { int x, y; } Point;

// Compound literal array
int sum = 0;
for (int *p = (int[]){1, 2, 3, 4, 5}; p < (int[]){1, 2, 3, 4, 5} + 5; p++) {
    sum += *p;
}

// Pass struct to function without declaring a variable
void draw_point(Point p);
draw_point((Point){10, 20});  // Compound literal struct

// Initialize pointer to struct
Point *origin = &(Point){0, 0};

// Useful for default arguments pattern
void config(int *options) {
    if (options == NULL) {
        options = (int[]){1, 0, 1, 0};  // Default
    }
}

// Array of structs
Point *points = (Point[]) {
    {0, 0}, {10, 10}, {20, 20}
};`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#4caf50", 0.1), border: `1px solid ${alpha("#4caf50", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon sx={{ color: "#4caf50" }} />
                Advanced C Resources
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="'The C Programming Language' by K&R" secondary="The definitive C book by the creators of C" /></ListItem>
                <ListItem><ListItemText primary="'Expert C Programming' by Peter van der Linden" secondary="Deep dive into C quirks and advanced topics" /></ListItem>
                <ListItem><ListItemText primary="'Modern C' by Jens Gustedt" secondary="Covers C11/C17 features and modern practices" /></ListItem>
                <ListItem><ListItemText primary="C Standard (ISO/IEC 9899)" secondary="The official specification for precise behavior" /></ListItem>
              </List>
            </Paper>
          </Paper>

          {/* C Quiz Section */}
          <CQuiz />

          {/* Debugging C Programs Section */}
          <Paper id="debugging" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#e91e63", 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2,
                  bgcolor: alpha("#e91e63", 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#e91e63",
                }}
              >
                <BugReportIcon />
              </Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Debugging C Programs
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Debugging is an essential skill for any C programmer. Unlike higher-level languages with built-in safety features, 
              C programs can fail in subtle ways—memory corruption, undefined behavior, and silent data corruption can make bugs 
              extremely difficult to track down. This section covers professional debugging techniques and tools that every 
              serious C developer should master.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3, color: "#e91e63" }}>
              GDB (GNU Debugger) Fundamentals
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              GDB is the standard debugger for C programs on Unix-like systems. It allows you to pause program execution, 
              inspect variables, step through code line by line, and examine the program's memory and call stack. Always 
              compile with <code>-g</code> flag to include debugging symbols.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="caption" sx={{ color: "#6a9955", fontFamily: "monospace" }}># Basic GDB Commands</Typography>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`
# Compile with debugging symbols
gcc -g -Wall program.c -o program

# Start GDB
gdb ./program
gdb --args ./program arg1 arg2    # With arguments

# Inside GDB:
(gdb) run                         # Start the program
(gdb) run arg1 arg2               # Start with arguments

# Breakpoints
(gdb) break main                  # Break at function start
(gdb) break file.c:42             # Break at specific line
(gdb) break function_name         # Break at function entry
(gdb) break *0x401234             # Break at address
(gdb) info breakpoints            # List all breakpoints
(gdb) delete 1                    # Delete breakpoint 1
(gdb) disable 2                   # Disable breakpoint 2
(gdb) condition 1 x > 10          # Conditional breakpoint

# Execution control
(gdb) next                        # Step over (next line)
(gdb) step                        # Step into function
(gdb) finish                      # Run until function returns
(gdb) continue                    # Continue to next breakpoint
(gdb) until 50                    # Run until line 50

# Examining data
(gdb) print variable              # Print variable value
(gdb) print *ptr                  # Dereference pointer
(gdb) print array[0]@10           # Print 10 elements
(gdb) print/x variable            # Print in hexadecimal
(gdb) print/t variable            # Print in binary
(gdb) print sizeof(int)           # Print expression result
(gdb) display variable            # Auto-print each step

# Memory examination
(gdb) x/10x 0x7fffffffe000        # Examine 10 hex words
(gdb) x/s string_ptr              # Examine as string
(gdb) x/20i function_name         # Examine 20 instructions
(gdb) x/4gx &variable             # 4 giant (64-bit) hex words

# Stack examination
(gdb) backtrace                   # Show call stack
(gdb) bt full                     # Backtrace with locals
(gdb) frame 2                     # Switch to frame 2
(gdb) info locals                 # Show local variables
(gdb) info args                   # Show function arguments

# Watchpoints (break when variable changes)
(gdb) watch variable              # Break when written
(gdb) rwatch variable             # Break when read
(gdb) awatch variable             # Break on read or write`}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#e91e63" }}>
              Debugging Memory Issues
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Memory-related bugs are the most common and dangerous issues in C programs. Tools like Valgrind, AddressSanitizer, 
              and MemorySanitizer can help identify memory errors that would be nearly impossible to find manually.
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#e91e63", 0.08), height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#e91e63" }}>Valgrind</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1, borderRadius: 1, mb: 1 }}>
{`# Basic memory check
valgrind ./program

# Detailed leak check
valgrind --leak-check=full ./program

# Track origins of uninit values
valgrind --track-origins=yes ./program

# Generate suppressions file
valgrind --gen-suppressions=all ./program`}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Valgrind runs your program in a virtual CPU and tracks all memory operations. Slower but very thorough.
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#e91e63", 0.08), height: "100%" }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#e91e63" }}>AddressSanitizer (ASan)</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1, borderRadius: 1, mb: 1 }}>
{`# Compile with ASan
gcc -fsanitize=address -g program.c -o program

# Run normally - ASan reports errors
./program

# Additional sanitizers
gcc -fsanitize=undefined   # UBSan
gcc -fsanitize=memory      # MSan (Clang)
gcc -fsanitize=thread      # TSan`}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Built into GCC/Clang. Faster than Valgrind with ~2x slowdown. Catches buffer overflows, use-after-free, etc.
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="caption" sx={{ color: "#6a9955", fontFamily: "monospace" }}>// Example: Finding memory bugs with ASan</Typography>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`
// buggy.c - This program has multiple memory bugs
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    // Bug 1: Heap buffer overflow
    char *buffer = malloc(10);
    strcpy(buffer, "Hello World!");  // Writes 13 bytes into 10-byte buffer!
    
    // Bug 2: Use after free
    free(buffer);
    printf("%s\\n", buffer);  // Accessing freed memory!
    
    // Bug 3: Memory leak
    char *leak = malloc(100);
    // Forgot to free(leak)!
    
    // Bug 4: Stack buffer overflow
    char stack_buf[8];
    strcpy(stack_buf, "This is way too long for the buffer");
    
    return 0;
}

// Compile and run with ASan:
// $ gcc -fsanitize=address -g buggy.c -o buggy
// $ ./buggy
// ASan will report detailed error with stack trace!`}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#e91e63" }}>
              Common Debugging Techniques
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { title: "Printf Debugging", desc: "Add strategic printf statements to trace execution flow and variable values. Simple but effective.", tip: "Use stderr: fprintf(stderr, \"Debug: x=%d\\n\", x);" },
                { title: "Binary Search", desc: "Comment out half the code to isolate which section contains the bug. Repeat until found.", tip: "git bisect automates this for version control" },
                { title: "Rubber Duck Debugging", desc: "Explain your code line-by-line to find logic errors. Often reveals assumptions you didn't realize.", tip: "Works surprisingly well for subtle bugs" },
                { title: "Core Dump Analysis", desc: "When a program crashes, examine the core dump with GDB to see the state at the moment of death.", tip: "ulimit -c unlimited to enable core dumps" },
                { title: "Static Analysis", desc: "Use tools like cppcheck, clang-tidy, and PVS-Studio to find bugs without running the code.", tip: "Integrates well with CI/CD pipelines" },
                { title: "Assertions", desc: "Use assert() to verify assumptions. Catches bugs close to their source.", tip: "NDEBUG disables them in release builds" },
              ].map((item) => (
                <Grid item xs={12} md={6} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#e91e63", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5, color: "#e91e63" }}>{item.title}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.desc}</Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#888" }}>{item.tip}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#e91e63" }}>
              Debugging Macros
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Useful debugging macros
#include <stdio.h>
#include <stdlib.h>

// Debug print with file and line
#ifdef DEBUG
    #define DBG(fmt, ...) fprintf(stderr, "[%s:%d] " fmt "\\n", \\
                          __FILE__, __LINE__, ##__VA_ARGS__)
#else
    #define DBG(fmt, ...) ((void)0)  // No-op in release
#endif

// Trace function entry/exit
#define TRACE_ENTER() DBG(">>> %s()", __func__)
#define TRACE_EXIT()  DBG("<<< %s()", __func__)

// Assert with message
#define ASSERT_MSG(cond, msg) do { \\
    if (!(cond)) { \\
        fprintf(stderr, "ASSERTION FAILED: %s\\n", msg); \\
        fprintf(stderr, "  Condition: %s\\n", #cond); \\
        fprintf(stderr, "  Location: %s:%d in %s()\\n", \\
                __FILE__, __LINE__, __func__); \\
        abort(); \\
    } \\
} while(0)

// Hexdump memory
void hexdump(const void *data, size_t size) {
    const unsigned char *p = data;
    for (size_t i = 0; i < size; i++) {
        if (i % 16 == 0) printf("%08zx: ", i);
        printf("%02x ", p[i]);
        if (i % 16 == 15 || i == size - 1) printf("\\n");
    }
}

// Usage example
int main(void) {
    TRACE_ENTER();
    
    int *ptr = malloc(sizeof(int));
    ASSERT_MSG(ptr != NULL, "Memory allocation failed");
    
    *ptr = 42;
    DBG("ptr=%p, *ptr=%d", (void*)ptr, *ptr);
    
    hexdump(ptr, sizeof(int));
    
    free(ptr);
    TRACE_EXIT();
    return 0;
}`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#4caf50", 0.1), border: `1px solid ${alpha("#4caf50", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon sx={{ color: "#4caf50" }} />
                Debugging Best Practices
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Always compile with -Wall -Wextra -Werror during development" secondary="Compiler warnings often reveal bugs before runtime" /></ListItem>
                <ListItem><ListItemText primary="Use version control (git) for debugging" secondary="git bisect can find exactly which commit introduced a bug" /></ListItem>
                <ListItem><ListItemText primary="Write unit tests for critical functions" secondary="Catches regressions and documents expected behavior" /></ListItem>
                <ListItem><ListItemText primary="Reproduce bugs with minimal test cases" secondary="Easier to debug and often reveals the cause" /></ListItem>
                <ListItem><ListItemText primary="Check return values of all functions" secondary="Many bugs come from ignoring error returns" /></ListItem>
              </List>
            </Paper>
          </Paper>

          {/* Common C Idioms Section */}
          <Paper id="idioms" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#00bcd4", 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2,
                  bgcolor: alpha("#00bcd4", 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#00bcd4",
                }}
              >
                <CodeIcon />
              </Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Common C Idioms & Patterns
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Experienced C programmers use certain patterns and idioms that are considered best practice. These idioms 
              represent decades of collective wisdom about writing safe, efficient, and maintainable C code. Learning 
              these patterns will make your code more professional and help you read others' code more easily.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3, color: "#00bcd4" }}>
              Resource Acquisition Patterns
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="caption" sx={{ color: "#6a9955", fontFamily: "monospace" }}>// Single exit point pattern for cleanup</Typography>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`
// PATTERN 1: Single exit point with goto cleanup
// Ensures all resources are freed on any error path
int process_file(const char *filename) {
    int result = -1;  // Assume failure
    FILE *fp = NULL;
    char *buffer = NULL;
    int *data = NULL;
    
    // Allocation phase
    fp = fopen(filename, "r");
    if (fp == NULL) {
        perror("fopen");
        goto cleanup;
    }
    
    buffer = malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        perror("malloc buffer");
        goto cleanup;
    }
    
    data = malloc(DATA_SIZE * sizeof(int));
    if (data == NULL) {
        perror("malloc data");
        goto cleanup;
    }
    
    // Processing phase
    // ... do work with fp, buffer, data ...
    
    result = 0;  // Success
    
cleanup:
    // Cleanup phase - order doesn't matter for independent resources
    free(data);      // free(NULL) is safe
    free(buffer);    // free(NULL) is safe
    if (fp) fclose(fp);
    
    return result;
}

// PATTERN 2: Init/destroy pair for structs
typedef struct {
    char *name;
    int *values;
    size_t count;
} MyObject;

int myobject_init(MyObject *obj, const char *name, size_t count) {
    obj->name = strdup(name);
    if (obj->name == NULL) return -1;
    
    obj->values = calloc(count, sizeof(int));
    if (obj->values == NULL) {
        free(obj->name);
        return -1;
    }
    
    obj->count = count;
    return 0;
}

void myobject_destroy(MyObject *obj) {
    if (obj == NULL) return;
    free(obj->name);
    free(obj->values);
    memset(obj, 0, sizeof(*obj));  // Defensive: zero out
}`}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00bcd4" }}>
              Defensive Programming Patterns
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// PATTERN: Defensive null checks and validation
void safe_function(const char *str, int *out_result) {
    // Check all pointer parameters
    if (str == NULL || out_result == NULL) {
        return;  // Or set an error code
    }
    
    // Validate string length before use
    size_t len = strlen(str);
    if (len > MAX_ALLOWED_LENGTH) {
        *out_result = -1;
        return;
    }
    
    // ... process safely ...
}

// PATTERN: Bounds-checked array access
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

int safe_array_get(int *arr, size_t arr_size, size_t index) {
    if (index >= arr_size) {
        return -1;  // Error value or handle appropriately
    }
    return arr[index];
}

// PATTERN: Strncpy with guaranteed null-termination
// Standard strncpy doesn't guarantee null-termination!
char *safe_strncpy(char *dest, const char *src, size_t size) {
    if (size > 0) {
        strncpy(dest, src, size - 1);
        dest[size - 1] = '\\0';  // Always null-terminate
    }
    return dest;
}

// PATTERN: Integer overflow checking
#include <limits.h>

int safe_add(int a, int b, int *result) {
    if ((b > 0 && a > INT_MAX - b) ||
        (b < 0 && a < INT_MIN - b)) {
        return -1;  // Overflow would occur
    }
    *result = a + b;
    return 0;
}

// PATTERN: Safe free macro
#define SAFE_FREE(ptr) do { free(ptr); (ptr) = NULL; } while(0)

// Usage:
int *data = malloc(100);
// ... use data ...
SAFE_FREE(data);  // Now data == NULL, safe to check`}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00bcd4" }}>
              Array and Loop Patterns
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// PATTERN: Array size macro (only for true arrays, not pointers!)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

int numbers[] = {1, 2, 3, 4, 5};
for (size_t i = 0; i < ARRAY_SIZE(numbers); i++) {
    printf("%d ", numbers[i]);
}

// PATTERN: Pointer iteration (more idiomatic for pointers)
int *arr = get_array(&size);
for (int *p = arr; p < arr + size; p++) {
    process(*p);
}

// PATTERN: String iteration
const char *str = "Hello";
for (const char *p = str; *p != '\\0'; p++) {
    process_char(*p);
}

// PATTERN: Linked list iteration
typedef struct Node {
    int value;
    struct Node *next;
} Node;

for (Node *curr = head; curr != NULL; curr = curr->next) {
    process(curr->value);
}

// PATTERN: Double pointer for list modification
void list_remove(Node **head, int value) {
    Node **curr = head;
    while (*curr != NULL) {
        if ((*curr)->value == value) {
            Node *temp = *curr;
            *curr = (*curr)->next;
            free(temp);
            return;
        }
        curr = &(*curr)->next;
    }
}

// PATTERN: Container_of macro (used in Linux kernel)
#define container_of(ptr, type, member) \\
    ((type *)((char *)(ptr) - offsetof(type, member)))`}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00bcd4" }}>
              Bit Manipulation Patterns
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// PATTERN: Bit flag operations
#define FLAG_READ    (1 << 0)  // 0x01
#define FLAG_WRITE   (1 << 1)  // 0x02
#define FLAG_EXECUTE (1 << 2)  // 0x04
#define FLAG_ALL     (FLAG_READ | FLAG_WRITE | FLAG_EXECUTE)

unsigned int permissions = 0;

// Set a flag
permissions |= FLAG_READ;

// Clear a flag
permissions &= ~FLAG_WRITE;

// Toggle a flag
permissions ^= FLAG_EXECUTE;

// Check if flag is set
if (permissions & FLAG_READ) {
    printf("Read permission granted\\n");
}

// Check if multiple flags are set
if ((permissions & (FLAG_READ | FLAG_WRITE)) == (FLAG_READ | FLAG_WRITE)) {
    printf("Both read and write set\\n");
}

// PATTERN: Extract bits
#define GET_BITS(value, start, count) \\
    (((value) >> (start)) & ((1 << (count)) - 1))

// Extract bits 4-7 (4 bits starting at position 4)
unsigned int nibble = GET_BITS(0xABCD, 4, 4);  // 0xC

// PATTERN: Power of 2 checks
#define IS_POWER_OF_2(x) ((x) != 0 && ((x) & ((x) - 1)) == 0)

// PATTERN: Round up to power of 2
unsigned int next_power_of_2(unsigned int v) {
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v++;
    return v;
}

// PATTERN: Swap without temp variable
#define SWAP(a, b) do { (a) ^= (b); (b) ^= (a); (a) ^= (b); } while(0)
// Note: Only works for integers, fails if a and b are same location`}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00bcd4" }}>
              Error Handling Patterns
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// PATTERN: Return error codes
typedef enum {
    SUCCESS = 0,
    ERR_NULL_POINTER = -1,
    ERR_OUT_OF_MEMORY = -2,
    ERR_INVALID_ARGUMENT = -3,
    ERR_FILE_NOT_FOUND = -4
} ErrorCode;

const char *error_to_string(ErrorCode err) {
    switch (err) {
        case SUCCESS: return "Success";
        case ERR_NULL_POINTER: return "Null pointer";
        case ERR_OUT_OF_MEMORY: return "Out of memory";
        case ERR_INVALID_ARGUMENT: return "Invalid argument";
        case ERR_FILE_NOT_FOUND: return "File not found";
        default: return "Unknown error";
    }
}

// PATTERN: Output parameter for result, return for status
ErrorCode divide(int a, int b, int *result) {
    if (result == NULL) return ERR_NULL_POINTER;
    if (b == 0) return ERR_INVALID_ARGUMENT;
    
    *result = a / b;
    return SUCCESS;
}

// PATTERN: Thread-local error storage (like errno)
#include <errno.h>

FILE *fp = fopen("nonexistent.txt", "r");
if (fp == NULL) {
    printf("Error: %s (errno=%d)\\n", strerror(errno), errno);
}

// PATTERN: Setjmp/longjmp for non-local jumps (poor man's exceptions)
#include <setjmp.h>
jmp_buf error_jump;

void risky_function(void) {
    if (error_condition) {
        longjmp(error_jump, 1);  // Jump back to setjmp
    }
}

int main(void) {
    if (setjmp(error_jump) != 0) {
        printf("Error occurred!\\n");
        return 1;
    }
    risky_function();  // May longjmp
    return 0;
}`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#4caf50", 0.1), border: `1px solid ${alpha("#4caf50", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon sx={{ color: "#4caf50" }} />
                Idiom Best Practices
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Use const liberally" secondary="Mark parameters and pointers as const when they shouldn't be modified" /></ListItem>
                <ListItem><ListItemText primary="Prefer static for file-local functions" secondary="Limits scope and enables better compiler optimization" /></ListItem>
                <ListItem><ListItemText primary="Use size_t for sizes, ptrdiff_t for pointer differences" secondary="These types are guaranteed to be the right size for the platform" /></ListItem>
                <ListItem><ListItemText primary="Initialize all variables at declaration" secondary="Prevents undefined behavior from uninitialized reads" /></ListItem>
              </List>
            </Paper>
          </Paper>

          {/* Security Vulnerabilities Section */}
          <Paper id="security" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#f44336", 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2,
                  bgcolor: alpha("#f44336", 0.15),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: "#f44336",
                }}
              >
                <SecurityIcon />
              </Box>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Security Vulnerabilities in C
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              C's power comes with significant security responsibilities. The language provides no runtime bounds checking, 
              no automatic memory management, and allows direct memory manipulation—all features that make it vulnerable 
              to exploitation when used carelessly. Understanding these vulnerabilities is crucial for both writing 
              secure code and for security professionals analyzing C programs.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#f44336", 0.08), border: `1px solid ${alpha("#f44336", 0.2)}`, mb: 3 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1, color: "#f44336" }}>
                ⚠️ Security Warning
              </Typography>
              <Typography variant="body2">
                The vulnerable code examples in this section are for educational purposes only. Understanding these 
                vulnerabilities helps you write secure code and recognize potential attack vectors. Never use vulnerable 
                patterns in production code.
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              Stack Buffer Overflow
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              A stack buffer overflow occurs when data is written beyond the bounds of a stack-allocated buffer. This 
              can overwrite adjacent stack variables, saved registers, and critically—the return address, allowing 
              an attacker to redirect program execution.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="caption" sx={{ color: "#f44336", fontFamily: "monospace" }}>// VULNERABLE CODE - DO NOT USE!</Typography>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`
#include <stdio.h>
#include <string.h>

// VULNERABLE: Classic stack buffer overflow
void vulnerable_function(char *input) {
    char buffer[64];      // 64 bytes allocated on stack
    strcpy(buffer, input); // No bounds check! Can overflow buffer
    printf("Received: %s\\n", buffer);
}

// What the stack looks like:
// +-------------------+ Higher addresses
// | Return Address    | <- Overwritten by attacker!
// +-------------------+
// | Saved EBP         | <- Can be overwritten
// +-------------------+
// | Local variables   |
// +-------------------+
// | buffer[63]        |
// |     ...           |
// | buffer[0]         | <- Start of buffer
// +-------------------+ Lower addresses

// SECURE VERSION
void secure_function(const char *input) {
    char buffer[64];
    
    // Option 1: Use strncpy with explicit null-termination
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';
    
    // Option 2: Use snprintf (safer, returns needed size)
    snprintf(buffer, sizeof(buffer), "%s", input);
    
    // Option 3: Check length first
    if (strlen(input) >= sizeof(buffer)) {
        fprintf(stderr, "Input too long!\\n");
        return;
    }
    strcpy(buffer, input);  // Now safe
    
    printf("Received: %s\\n", buffer);
}`}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              Heap Buffer Overflow
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Heap overflows occur in dynamically allocated memory. They can corrupt heap metadata, other heap objects, 
              and can be exploited to achieve arbitrary code execution through techniques like overwriting function pointers.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="caption" sx={{ color: "#f44336", fontFamily: "monospace" }}>// VULNERABLE: Heap overflow</Typography>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`
typedef struct {
    char name[32];
    int is_admin;  // 0 = normal user, 1 = admin
} User;

// VULNERABLE: Adjacent heap objects can be corrupted
User *create_user(const char *name) {
    User *u = malloc(sizeof(User));
    strcpy(u->name, name);  // Overflow can set is_admin!
    u->is_admin = 0;
    return u;
}

// Attack: create_user("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXXXX")
// The "XXXX" (0x58585858) overwrites is_admin!

// SECURE VERSION
User *secure_create_user(const char *name) {
    if (name == NULL) return NULL;
    
    User *u = malloc(sizeof(User));
    if (u == NULL) return NULL;
    
    // Initialize all fields to safe defaults FIRST
    memset(u, 0, sizeof(*u));
    
    // Safe copy with bounds check
    size_t len = strlen(name);
    if (len >= sizeof(u->name)) {
        len = sizeof(u->name) - 1;
    }
    memcpy(u->name, name, len);
    u->name[len] = '\\0';
    
    return u;
}`}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              Format String Vulnerabilities
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Format string vulnerabilities occur when user input is passed directly as a format string to printf-family 
              functions. Attackers can read stack memory, write to arbitrary addresses, and execute code.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="caption" sx={{ color: "#f44336", fontFamily: "monospace" }}>// VULNERABLE: Format string attack</Typography>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`
// VULNERABLE: User input as format string
void log_message(const char *user_input) {
    printf(user_input);  // NEVER DO THIS!
}

// What an attacker can do:
// 1. Read stack: "%x %x %x %x"  -> prints stack values
// 2. Read memory: "%s" with address on stack
// 3. Crash: "%n%n%n%n" writes to invalid addresses
// 4. Write memory: "%n" writes number of chars printed

// Attack example:
// Input: "%x.%x.%x.%x"
// Output: "deadbeef.41414141.7fff001b.400526"
// This leaks stack contents!

// SECURE VERSIONS
void secure_log_message(const char *user_input) {
    printf("%s", user_input);  // %s treats input as data
    // Or equivalently:
    fputs(user_input, stdout);
    // Or:
    puts(user_input);  // Adds newline
}

// Even format strings from files can be dangerous:
char fmt[100];
fgets(fmt, sizeof(fmt), config_file);
printf(fmt, value);  // Still vulnerable!
// Fix:
printf("%s", fmt);   // If you just want to print it
// Or validate fmt only contains expected specifiers`}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              Use-After-Free (UAF)
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Use-after-free occurs when memory is accessed after being freed. If the memory has been reallocated 
              for another purpose, this can lead to data corruption or code execution by manipulating heap objects.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="caption" sx={{ color: "#f44336", fontFamily: "monospace" }}>// VULNERABLE: Use-after-free</Typography>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`
typedef struct {
    void (*callback)(void);  // Function pointer
    char data[128];
} Object;

// VULNERABLE: Dangling pointer exploited
Object *global_obj = NULL;

void process(void) {
    global_obj = malloc(sizeof(Object));
    global_obj->callback = safe_function;
    
    // ... later, in error handling ...
    free(global_obj);  // Memory freed
    // BUG: global_obj still points to freed memory!
}

void trigger(void) {
    if (global_obj != NULL) {
        // Attacker allocates same memory, controls callback
        global_obj->callback();  // Calls attacker's code!
    }
}

// SECURE VERSION
void secure_process(void) {
    global_obj = malloc(sizeof(Object));
    if (global_obj == NULL) return;
    
    global_obj->callback = safe_function;
    
    // ... later, in error handling ...
    free(global_obj);
    global_obj = NULL;  // Clear the pointer!
}

// Using a macro for safety
#define SAFE_FREE(ptr) do { \\
    free(ptr); \\
    (ptr) = NULL; \\
} while(0)

SAFE_FREE(global_obj);`}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              Integer Overflow
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Integer overflows occur when arithmetic operations produce results outside the representable range. 
              In C, signed overflow is undefined behavior, while unsigned overflow wraps around. Both can lead 
              to security vulnerabilities when used for size calculations.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="caption" sx={{ color: "#f44336", fontFamily: "monospace" }}>// VULNERABLE: Integer overflow in allocation</Typography>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`
// VULNERABLE: Integer overflow leads to small allocation
void *copy_data(size_t count, size_t elem_size) {
    // If count * elem_size overflows, we allocate tiny buffer
    void *buf = malloc(count * elem_size);
    // Then copy huge amount of data into tiny buffer!
    return buf;
}

// Attack: copy_data(0x100000001, 16)
// On 32-bit: 0x100000001 * 16 = 16 (overflows!)
// malloc(16), then copy many bytes -> overflow

// SECURE VERSION
void *secure_copy_data(size_t count, size_t elem_size) {
    // Check for overflow before multiplication
    if (count > 0 && elem_size > SIZE_MAX / count) {
        return NULL;  // Would overflow
    }
    
    // Or use calloc which checks internally
    return calloc(count, elem_size);
}

// VULNERABLE: Signed integer used for length
void process_packet(int length) {
    if (length > MAX_LENGTH) {
        return;  // Reject too-large packets
    }
    
    char *buf = malloc(length);  // Negative length -> huge allocation?
    // Actually, negative int cast to size_t = huge number
    read(fd, buf, length);       // Wraps around!
}

// SECURE VERSION
void secure_process_packet(size_t length) {
    if (length == 0 || length > MAX_LENGTH) {
        return;
    }
    
    char *buf = malloc(length);
    if (buf == NULL) return;
    
    read(fd, buf, length);
}`}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              Other Common Vulnerabilities
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { title: "Null Pointer Dereference", desc: "Accessing memory through a NULL pointer. Can crash programs or be exploited if NULL is mapped.", fix: "Always check pointers before dereferencing" },
                { title: "Off-by-One Errors", desc: "Writing one byte past the buffer end, often from <= instead of < in loops.", fix: "Careful loop bounds; use < array_size, not <=" },
                { title: "Double Free", desc: "Freeing memory twice corrupts heap metadata, leading to exploitation.", fix: "Set pointers to NULL after freeing" },
                { title: "Uninitialized Memory", desc: "Reading uninitialized variables leaks stack/heap contents.", fix: "Always initialize variables; use memset for structs" },
                { title: "Race Conditions", desc: "Multiple threads accessing shared data without synchronization.", fix: "Use mutexes, atomic operations, or thread-safe designs" },
                { title: "Command Injection", desc: "User input in system() or popen() can execute arbitrary commands.", fix: "Avoid system(); use execve() with explicit arguments" },
              ].map((item) => (
                <Grid item xs={12} md={6} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f44336", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5, color: "#f44336" }}>{item.title}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.desc}</Typography>
                    <Typography variant="caption" sx={{ color: "#4caf50" }}>Fix: {item.fix}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              Compiler and Runtime Protections
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Modern systems employ multiple layers of defense. Understanding these helps you write exploit-resistant 
              code and appreciate why certain protections exist:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "Stack Canaries", desc: "Secret values placed before return addresses that are checked before returning. Detects stack buffer overflows.", cmd: "-fstack-protector-strong" },
                { name: "ASLR", desc: "Address Space Layout Randomization. Randomizes memory layout making exploitation harder.", cmd: "Enabled by OS" },
                { name: "DEP/NX", desc: "Data Execution Prevention. Marks data memory as non-executable, preventing shellcode execution.", cmd: "Enabled by default" },
                { name: "RELRO", desc: "Relocation Read-Only. Makes GOT and other sections read-only after startup.", cmd: "-Wl,-z,relro,-z,now" },
                { name: "PIE", desc: "Position Independent Executable. Enables full ASLR for the executable itself.", cmd: "-pie -fPIE" },
                { name: "FORTIFY_SOURCE", desc: "Adds bounds checking to common functions like memcpy, strcpy at compile time.", cmd: "-D_FORTIFY_SOURCE=2" },
              ].map((item) => (
                <Grid item xs={12} md={6} key={item.name}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#f44336", 0.2)}`, height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>{item.name}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1, fontSize: "0.85rem" }}>{item.desc}</Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#4ec9b0", px: 1, py: 0.5, borderRadius: 1 }}>
                      {item.cmd}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", mb: 3 }}>
              <Typography variant="caption" sx={{ color: "#6a9955", fontFamily: "monospace" }}># Compile with all security features enabled</Typography>
              <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`
# Maximum security compilation flags (GCC/Clang)
gcc -Wall -Wextra -Werror \\
    -fstack-protector-strong \\
    -D_FORTIFY_SOURCE=2 \\
    -pie -fPIE \\
    -Wl,-z,relro,-z,now \\
    -Wformat -Wformat-security \\
    program.c -o program

# Check binary security features:
checksec --file=program
# Or with pwntools:
pwn checksec program`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#4caf50", 0.1), border: `1px solid ${alpha("#4caf50", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CheckCircleIcon sx={{ color: "#4caf50" }} />
                Secure Coding Checklist
              </Typography>
              <List dense>
                <ListItem><ListItemText primary="Validate all input" secondary="Check bounds, types, and encoding of all external data" /></ListItem>
                <ListItem><ListItemText primary="Use safe string functions" secondary="snprintf over sprintf, strncpy with null termination, strlcpy if available" /></ListItem>
                <ListItem><ListItemText primary="Check all return values" secondary="malloc, fopen, and syscalls can fail; handle errors properly" /></ListItem>
                <ListItem><ListItemText primary="Avoid dangerous functions" secondary="gets(), sprintf(), strcpy() without bounds checking" /></ListItem>
                <ListItem><ListItemText primary="Initialize all variables" secondary="Uninitialized memory can leak sensitive data" /></ListItem>
                <ListItem><ListItemText primary="Clear sensitive data" secondary="Use memset_s or volatile function pointers to prevent optimization" /></ListItem>
                <ListItem><ListItemText primary="Compile with protections" secondary="Enable all compiler security features and warnings" /></ListItem>
                <ListItem><ListItemText primary="Use static analysis" secondary="Run cppcheck, clang-tidy, and sanitizers regularly" /></ListItem>
              </List>
            </Paper>
          </Paper>

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
