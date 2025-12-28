import React, { useState } from "react";
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
  Alert,
  AlertTitle,
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
import QuizIcon from "@mui/icons-material/Quiz";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import RefreshIcon from "@mui/icons-material/Refresh";
import LearnPageLayout from "../components/LearnPageLayout";

const accentColor = "#e91e63"; // Pink accent for C++
const accentColorDark = "#c2185b";

// Module navigation items for sidebar
const moduleNavItems = [
  { id: "introduction", label: "Introduction", icon: <SchoolIcon /> },
  { id: "history", label: "History & Evolution", icon: <HistoryIcon /> },
  { id: "setup", label: "Environment Setup", icon: <BuildIcon /> },
  { id: "basics", label: "C++ Basics & Syntax", icon: <CodeIcon /> },
  { id: "oop", label: "Object-Oriented Programming", icon: <AccountTreeIcon /> },
  { id: "classes", label: "Classes & Objects", icon: <ViewModuleIcon /> },
  { id: "inheritance", label: "Inheritance", icon: <LayersIcon /> },
  { id: "polymorphism", label: "Polymorphism", icon: <ExtensionIcon /> },
  { id: "templates", label: "Templates", icon: <AutoFixHighIcon /> },
  { id: "stl", label: "Standard Template Library", icon: <StorageIcon /> },
  { id: "memory", label: "Memory Management", icon: <MemoryIcon /> },
  { id: "smart-pointers", label: "Smart Pointers", icon: <SecurityIcon /> },
  { id: "exceptions", label: "Exception Handling", icon: <BugReportIcon /> },
  { id: "lambdas", label: "Lambda Expressions", icon: <CodeIcon /> },
  { id: "modern-cpp", label: "Modern C++ (11/14/17/20)", icon: <SpeedIcon /> },
  { id: "advanced", label: "Advanced Topics", icon: <TerminalIcon /> },
  { id: "quiz", label: "Test Your Knowledge", icon: <QuizIcon /> },
];

// Quick stats for hero section
const quickStats = [
  { label: "Created", value: "1979", color: "#f06292" },
  { label: "Creator", value: "Bjarne Stroustrup", color: "#ba68c8" },
  { label: "Paradigm", value: "Multi-Paradigm", color: "#4dd0e1" },
  { label: "Latest Std", value: "C++23", color: "#81c784" },
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

// ==================== QUIZ SECTION ====================
interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  topic: string;
}

// Full 75-question bank covering C++ topics
const questionBank: QuizQuestion[] = [
  // ==================== Topic 1: C++ Basics (Questions 1-15) ====================
  { id: 1, question: "What is the correct way to declare a constant in modern C++?", options: ["#define PI 3.14", "const double PI = 3.14;", "constexpr double PI = 3.14;", "Both B and C are correct"], correctAnswer: 3, explanation: "Both const and constexpr can declare constants. constexpr is preferred when the value can be computed at compile time, while const works for runtime constants too.", topic: "C++ Basics" },
  { id: 2, question: "What does 'auto' keyword do in C++11?", options: ["Declares automatic storage duration", "Enables automatic type deduction", "Creates an automatic pointer", "Defines an automated function"], correctAnswer: 1, explanation: "The 'auto' keyword in C++11 enables automatic type deduction, where the compiler determines the type based on the initializer expression.", topic: "C++ Basics" },
  { id: 3, question: "What is the difference between 'nullptr' and 'NULL'?", options: ["They are identical", "nullptr is type-safe and NULL is not", "NULL is faster", "nullptr only works with smart pointers"], correctAnswer: 1, explanation: "nullptr is a type-safe null pointer constant of type std::nullptr_t, while NULL is typically defined as 0 or (void*)0, which can cause ambiguity in function overloading.", topic: "C++ Basics" },
  { id: 4, question: "What is the output of: int x{3.14};", options: ["3", "3.14", "Compilation error (narrowing conversion)", "0"], correctAnswer: 2, explanation: "Uniform initialization with braces {} prevents narrowing conversions. Converting double 3.14 to int would lose data, so the compiler generates an error.", topic: "C++ Basics" },
  { id: 5, question: "What is a reference in C++?", options: ["A pointer that can be null", "An alias for another variable", "A copy of a variable", "A constant pointer"], correctAnswer: 1, explanation: "A reference is an alias for an existing variable. Once initialized, it cannot be changed to refer to another variable and cannot be null.", topic: "C++ Basics" },
  { id: 6, question: "What does 'using namespace std;' do?", options: ["Imports the std library", "Allows using std members without prefix", "Creates a new namespace", "Defines standard types"], correctAnswer: 1, explanation: "This directive allows you to use names from the std namespace without the 'std::' prefix. However, it's generally discouraged in headers due to potential name collisions.", topic: "C++ Basics" },
  { id: 7, question: "What is the scope resolution operator in C++?", options: [".", "->", "::", "::*"], correctAnswer: 2, explanation: "The double colon (::) is the scope resolution operator, used to access namespace members, class static members, and to define member functions outside the class.", topic: "C++ Basics" },
  { id: 8, question: "What is the difference between #include <header> and #include \"header\"?", options: ["No difference", "< > searches system paths first, \" \" searches local paths first", "\" \" is for C headers only", "< > is deprecated"], correctAnswer: 1, explanation: "Angle brackets search system include paths first, while quotes search the current directory and local paths first before system paths.", topic: "C++ Basics" },
  { id: 9, question: "What does 'const' after a member function declaration mean?", options: ["The function returns a const value", "The function cannot modify member variables", "The function takes const parameters", "The function is compile-time constant"], correctAnswer: 1, explanation: "A const member function promises not to modify any non-mutable member variables of the object. It can be called on const objects.", topic: "C++ Basics" },
  { id: 10, question: "What is a namespace used for?", options: ["Memory management", "Preventing name collisions", "Defining classes", "Error handling"], correctAnswer: 1, explanation: "Namespaces provide a way to group related code and prevent naming conflicts by creating separate scopes for identifiers.", topic: "C++ Basics" },
  { id: 11, question: "What is the correct syntax for a range-based for loop?", options: ["for (int i = 0; i < v.size(); i++)", "for (int x : v)", "for each (int x in v)", "foreach (x in v)"], correctAnswer: 1, explanation: "Range-based for loops use the syntax 'for (element : container)'. They work with any container that has begin() and end() methods.", topic: "C++ Basics" },
  { id: 12, question: "What does 'inline' keyword suggest to the compiler?", options: ["The function must be inlined", "The function should be considered for inlining", "The function runs faster", "The function is defined in a header"], correctAnswer: 1, explanation: "The 'inline' keyword is a hint to the compiler that a function is a good candidate for inlining. The compiler may ignore this hint based on optimization settings.", topic: "C++ Basics" },
  { id: 13, question: "What is the difference between 'struct' and 'class' in C++?", options: ["struct cannot have methods", "struct members are public by default, class members are private", "struct is for C compatibility only", "There is no difference"], correctAnswer: 1, explanation: "The only difference is default access: struct members are public by default, class members are private by default. Both can have methods, constructors, inheritance, etc.", topic: "C++ Basics" },
  { id: 14, question: "What does 'sizeof' operator return?", options: ["The number of elements", "The size in bytes", "The size in bits", "The memory address"], correctAnswer: 1, explanation: "sizeof returns the size of a type or object in bytes. It's evaluated at compile time for most cases.", topic: "C++ Basics" },
  { id: 15, question: "What is an lvalue in C++?", options: ["A literal value", "An expression that refers to a memory location", "A left-side only value", "A local value"], correctAnswer: 1, explanation: "An lvalue is an expression that refers to a memory location and can appear on the left side of an assignment. It has an identifiable address.", topic: "C++ Basics" },

  // ==================== Topic 2: Object-Oriented Programming (Questions 16-30) ====================
  { id: 16, question: "What is encapsulation?", options: ["Hiding implementation details and bundling data with methods", "Inheriting from multiple classes", "Creating objects from classes", "Using virtual functions"], correctAnswer: 0, explanation: "Encapsulation is bundling data (attributes) and methods (functions) that operate on the data into a single unit (class) while hiding internal implementation details.", topic: "OOP" },
  { id: 17, question: "What is the purpose of a constructor?", options: ["To destroy objects", "To initialize objects when created", "To copy objects", "To compare objects"], correctAnswer: 1, explanation: "A constructor is a special member function that is automatically called when an object is created. It initializes the object's data members.", topic: "OOP" },
  { id: 18, question: "When is a destructor called?", options: ["When object is created", "When object goes out of scope or is deleted", "When object is copied", "When object is assigned"], correctAnswer: 1, explanation: "A destructor is called automatically when an object goes out of scope (for stack objects) or when delete is called (for heap objects). It cleans up resources.", topic: "OOP" },
  { id: 19, question: "What is the 'this' pointer?", options: ["A pointer to the class definition", "A pointer to the current object instance", "A pointer to the parent class", "A null pointer"], correctAnswer: 1, explanation: "The 'this' pointer is an implicit pointer available in non-static member functions that points to the object for which the function was called.", topic: "OOP" },
  { id: 20, question: "What is inheritance?", options: ["Creating multiple objects", "A class deriving properties from another class", "Hiding data members", "Overloading operators"], correctAnswer: 1, explanation: "Inheritance allows a derived class to inherit attributes and methods from a base class, promoting code reuse and establishing an 'is-a' relationship.", topic: "OOP" },
  { id: 21, question: "What is polymorphism?", options: ["Having multiple constructors", "Objects of different types responding to the same interface differently", "Creating multiple classes", "Using multiple namespaces"], correctAnswer: 1, explanation: "Polymorphism allows objects of different types to be treated through a common interface, with each type providing its own implementation.", topic: "OOP" },
  { id: 22, question: "What does the 'virtual' keyword do?", options: ["Makes a function faster", "Enables runtime polymorphism via dynamic dispatch", "Makes a function inline", "Prevents function overriding"], correctAnswer: 1, explanation: "The virtual keyword enables dynamic dispatch - the correct function version is determined at runtime based on the actual object type, not the pointer/reference type.", topic: "OOP" },
  { id: 23, question: "What is a pure virtual function?", options: ["A function with no side effects", "A virtual function with no implementation (= 0)", "A very optimized function", "A private virtual function"], correctAnswer: 1, explanation: "A pure virtual function is declared with '= 0' and has no implementation in the base class. A class with at least one pure virtual function is abstract.", topic: "OOP" },
  { id: 24, question: "What is an abstract class?", options: ["A class with no data members", "A class with at least one pure virtual function", "A class that cannot be inherited", "A template class"], correctAnswer: 1, explanation: "An abstract class contains at least one pure virtual function. It cannot be instantiated directly - you must derive from it and implement all pure virtual functions.", topic: "OOP" },
  { id: 25, question: "What is the diamond problem in inheritance?", options: ["Memory leak in destructors", "Ambiguity when a class inherits from two classes with a common base", "Too many virtual functions", "Circular dependency"], correctAnswer: 1, explanation: "The diamond problem occurs in multiple inheritance when two parent classes share a common grandparent, causing ambiguity about which version of the grandparent's members to use.", topic: "OOP" },
  { id: 26, question: "How is the diamond problem solved in C++?", options: ["Using private inheritance", "Using virtual inheritance", "Using protected members", "It cannot be solved"], correctAnswer: 1, explanation: "Virtual inheritance ensures that only one copy of the common base class exists in the inheritance hierarchy, resolving ambiguity.", topic: "OOP" },
  { id: 27, question: "What is method overloading?", options: ["Redefining a base class method in derived class", "Multiple methods with the same name but different parameters", "Making methods virtual", "Hiding base class methods"], correctAnswer: 1, explanation: "Method overloading is defining multiple functions with the same name but different parameter lists (type, number, or order). The compiler selects the correct one at compile time.", topic: "OOP" },
  { id: 28, question: "What is method overriding?", options: ["Multiple methods with different parameters", "Derived class providing its own implementation of a base class virtual method", "Hiding base class methods", "Using the override keyword"], correctAnswer: 1, explanation: "Method overriding is when a derived class provides its own implementation of a virtual function defined in the base class, replacing the base class behavior.", topic: "OOP" },
  { id: 29, question: "What does the 'override' keyword do?", options: ["Forces a method to be virtual", "Ensures the method actually overrides a base class virtual method", "Makes the method faster", "Prevents further overriding"], correctAnswer: 1, explanation: "The 'override' keyword (C++11) tells the compiler to verify that the method actually overrides a base class virtual method. It catches errors if signatures don't match.", topic: "OOP" },
  { id: 30, question: "What does the 'final' keyword do?", options: ["Makes a variable constant", "Prevents a class from being inherited or a method from being overridden", "Finalizes memory allocation", "Ends the program"], correctAnswer: 1, explanation: "The 'final' keyword prevents a class from being inherited (class Foo final {}) or a virtual method from being overridden (void foo() final;).", topic: "OOP" },

  // ==================== Topic 3: Templates (Questions 31-45) ====================
  { id: 31, question: "What is a template in C++?", options: ["A pre-written code snippet", "A mechanism for generic programming", "A design pattern", "A type of class"], correctAnswer: 1, explanation: "Templates are C++'s mechanism for generic programming, allowing you to write code that works with any type. The compiler generates specialized versions as needed.", topic: "Templates" },
  { id: 32, question: "What is template instantiation?", options: ["Creating a template", "Compiler generating code for a specific type from a template", "Calling a template function", "Defining template parameters"], correctAnswer: 1, explanation: "Template instantiation is when the compiler generates actual code by substituting the template parameters with concrete types.", topic: "Templates" },
  { id: 33, question: "What is a non-type template parameter?", options: ["A template without parameters", "A template parameter that is a value, not a type", "A parameter that cannot vary", "An invalid template"], correctAnswer: 1, explanation: "Non-type template parameters are compile-time constant values like integers, pointers, or references, used to parameterize templates with values instead of types.", topic: "Templates" },
  { id: 34, question: "What is template specialization?", options: ["Making a template faster", "Providing a specific implementation for particular template arguments", "Using templates with special types", "Optimizing template code"], correctAnswer: 1, explanation: "Template specialization provides a custom implementation for specific template arguments, overriding the general template for those particular types.", topic: "Templates" },
  { id: 35, question: "What is partial template specialization?", options: ["Incomplete template definition", "Specializing a template for a subset of cases (e.g., all pointers)", "Half-implemented templates", "Template with some default arguments"], correctAnswer: 1, explanation: "Partial specialization allows specializing a template for a category of types (like all pointers T*) rather than a single specific type.", topic: "Templates" },
  { id: 36, question: "Why are templates defined in header files?", options: ["For faster compilation", "The compiler needs the full definition to instantiate templates", "Headers are faster to parse", "It's just a convention"], correctAnswer: 1, explanation: "Templates must be visible to the compiler at the point of instantiation because the compiler generates code for each type used. Separating declaration and definition causes linker errors.", topic: "Templates" },
  { id: 37, question: "What is SFINAE?", options: ["A C++ library", "Substitution Failure Is Not An Error - invalid substitutions are silently ignored", "A compiler optimization", "A type of template"], correctAnswer: 1, explanation: "SFINAE means that when substituting template parameters fails, the compiler doesn't generate an error but instead removes that overload from consideration.", topic: "Templates" },
  { id: 38, question: "What is a variadic template?", options: ["A template with variable types", "A template that accepts any number of arguments", "A template with default arguments", "An optimized template"], correctAnswer: 1, explanation: "Variadic templates (C++11) can accept any number of template arguments using parameter packs (typename... Args), enabling functions like std::make_tuple.", topic: "Templates" },
  { id: 39, question: "What does 'typename' keyword do in templates?", options: ["Declares a type alias", "Indicates that a dependent name is a type", "Creates a new type", "Both A and B are correct"], correctAnswer: 3, explanation: "typename is used both to declare template type parameters and to clarify that a dependent name inside a template refers to a type (not a value).", topic: "Templates" },
  { id: 40, question: "What is a concept in C++20?", options: ["A design idea", "A named set of requirements for template arguments", "A type of template", "A class interface"], correctAnswer: 1, explanation: "Concepts are named constraints that specify requirements for template arguments. They provide clearer error messages and make template requirements explicit and documentable.", topic: "Templates" },
  { id: 41, question: "What does 'requires' keyword do?", options: ["Requires a header file", "Specifies constraints on template parameters", "Requires a base class", "Requires initialization"], correctAnswer: 1, explanation: "The 'requires' keyword (C++20) specifies constraints on template parameters using concepts or ad-hoc requirements, enabling conditional compilation based on type properties.", topic: "Templates" },
  { id: 42, question: "What is std::enable_if used for?", options: ["Enabling compiler optimizations", "Conditionally enabling/disabling function overloads based on type traits", "Enabling exceptions", "Enabling debugging"], correctAnswer: 1, explanation: "std::enable_if is used with SFINAE to conditionally enable or disable function templates based on compile-time conditions, typically using type traits.", topic: "Templates" },
  { id: 43, question: "What is a type trait?", options: ["A template metaprogramming tool to query type properties at compile time", "A type inheritance feature", "A runtime type check", "A debugging feature"], correctAnswer: 0, explanation: "Type traits (in <type_traits>) provide compile-time type information like is_integral, is_pointer, etc., enabling conditional compilation based on type properties.", topic: "Templates" },
  { id: 44, question: "What is the difference between template<typename T> and template<class T>?", options: ["typename is for primitive types, class for objects", "They are identical in this context", "class allows inheritance", "typename is newer"], correctAnswer: 1, explanation: "In template parameter declarations, typename and class are interchangeable. The convention is to use typename for any type and class when T is expected to be a class type.", topic: "Templates" },
  { id: 45, question: "What is a fold expression in C++17?", options: ["A way to reduce template code size", "A syntax for applying an operator to all elements of a parameter pack", "A function folding optimization", "An error handling mechanism"], correctAnswer: 1, explanation: "Fold expressions provide a concise way to apply binary operators to all elements of a variadic parameter pack: (args + ...) sums all args.", topic: "Templates" },

  // ==================== Topic 4: STL & Containers (Questions 46-55) ====================
  { id: 46, question: "What is the STL?", options: ["Standard Type Library", "Standard Template Library - containers, algorithms, iterators", "System Template Library", "Simple Type Library"], correctAnswer: 1, explanation: "The Standard Template Library provides reusable generic components: containers (vector, map), algorithms (sort, find), and iterators connecting them.", topic: "STL" },
  { id: 47, question: "What is the time complexity of std::vector::push_back?", options: ["O(1) always", "O(n) always", "Amortized O(1)", "O(log n)"], correctAnswer: 2, explanation: "push_back is amortized O(1). Usually O(1), but occasionally O(n) when reallocation is needed. Over many operations, it averages to constant time.", topic: "STL" },
  { id: 48, question: "When should you use std::list over std::vector?", options: ["Always - list is more efficient", "When you need frequent insertions/deletions in the middle", "When you need random access", "When memory is limited"], correctAnswer: 1, explanation: "std::list (doubly-linked list) is preferred when you frequently insert/delete in the middle, as these operations are O(1) with an iterator. vector is better for most other cases.", topic: "STL" },
  { id: 49, question: "What is the difference between std::map and std::unordered_map?", options: ["map uses hash table, unordered_map uses tree", "map is ordered (tree-based), unordered_map uses hash table", "They are identical", "map is faster"], correctAnswer: 1, explanation: "std::map uses a red-black tree (O(log n) operations, sorted keys), while std::unordered_map uses a hash table (O(1) average operations, unsorted).", topic: "STL" },
  { id: 50, question: "What does std::vector::reserve() do?", options: ["Reserves memory without changing size", "Resizes the vector", "Reserves the vector for exclusive use", "Locks the vector"], correctAnswer: 0, explanation: "reserve() pre-allocates memory for at least the specified number of elements without changing the size. This prevents reallocations when you know the approximate final size.", topic: "STL" },
  { id: 51, question: "What is an iterator?", options: ["A loop counter", "An object that provides access to container elements in sequence", "A sorting algorithm", "A pointer wrapper"], correctAnswer: 1, explanation: "Iterators are objects that provide a common interface to access container elements sequentially. They abstract the container's internal structure.", topic: "STL" },
  { id: 52, question: "What does std::find return if element is not found?", options: ["nullptr", "An iterator to end()", "Throws an exception", "-1"], correctAnswer: 1, explanation: "std::find returns an iterator to end() if the element is not found. You should always compare the result with container.end() to check if the element was found.", topic: "STL" },
  { id: 53, question: "What is the erase-remove idiom?", options: ["A way to delete containers", "Combining std::remove with erase() to actually delete elements", "Removing iterators", "Erasing templates"], correctAnswer: 1, explanation: "std::remove doesn't actually remove elements - it moves unwanted elements to the end. You must call erase() on the returned iterator range to actually delete them.", topic: "STL" },
  { id: 54, question: "What does std::sort require from iterators?", options: ["Forward iterators", "Bidirectional iterators", "Random access iterators", "Any iterators"], correctAnswer: 2, explanation: "std::sort requires random access iterators because it needs to access elements at arbitrary positions efficiently. Use std::list::sort() for lists.", topic: "STL" },
  { id: 55, question: "What is std::set used for?", options: ["Setting values", "Storing unique sorted elements", "Creating subsets", "Mathematical set operations only"], correctAnswer: 1, explanation: "std::set is an associative container that stores unique elements in sorted order. Insertion, lookup, and deletion are O(log n).", topic: "STL" },

  // ==================== Topic 5: Memory Management (Questions 56-65) ====================
  { id: 56, question: "What is RAII?", options: ["Random Access In Iteration", "Resource Acquisition Is Initialization - tie resource lifetime to object lifetime", "Runtime Assertion In Implementation", "Reference And Iterator Interface"], correctAnswer: 1, explanation: "RAII means acquiring resources (memory, files, locks) in constructors and releasing them in destructors, ensuring automatic cleanup when objects go out of scope.", topic: "Memory" },
  { id: 57, question: "What is the difference between new and malloc?", options: ["No difference", "new calls constructor, malloc just allocates memory", "malloc is faster", "new is deprecated"], correctAnswer: 1, explanation: "new allocates memory AND calls the constructor. malloc only allocates raw memory. new also throws on failure (unless you use nothrow), malloc returns NULL.", topic: "Memory" },
  { id: 58, question: "What is a memory leak?", options: ["Memory being used too fast", "Allocated memory that is never freed", "Memory corruption", "Stack overflow"], correctAnswer: 1, explanation: "A memory leak occurs when dynamically allocated memory is never deallocated, causing the program to consume more and more memory over time.", topic: "Memory" },
  { id: 59, question: "What is a dangling pointer?", options: ["A pointer pointing to deallocated memory", "A null pointer", "An uninitialized pointer", "A smart pointer"], correctAnswer: 0, explanation: "A dangling pointer points to memory that has been freed/deallocated. Dereferencing it causes undefined behavior.", topic: "Memory" },
  { id: 60, question: "What is std::unique_ptr?", options: ["A pointer to unique elements", "A smart pointer with exclusive ownership - cannot be copied", "A unique memory address", "A special raw pointer"], correctAnswer: 1, explanation: "unique_ptr provides exclusive ownership semantics - only one unique_ptr can own a resource at a time. It cannot be copied, only moved.", topic: "Memory" },
  { id: 61, question: "What is std::shared_ptr?", options: ["A pointer shared between threads", "A smart pointer with shared ownership using reference counting", "A pointer to shared memory", "A weak pointer"], correctAnswer: 1, explanation: "shared_ptr uses reference counting to allow multiple pointers to share ownership of the same resource. The resource is freed when the last shared_ptr is destroyed.", topic: "Memory" },
  { id: 62, question: "What is std::weak_ptr used for?", options: ["Creating weak references that don't prevent deletion", "Weak memory allocation", "Slower but safer pointers", "Debugging memory leaks"], correctAnswer: 0, explanation: "weak_ptr observes a shared_ptr without affecting its reference count. It's used to break circular references and to check if the resource still exists before accessing it.", topic: "Memory" },
  { id: 63, question: "Why use std::make_unique instead of new with unique_ptr?", options: ["It's faster", "Exception safety and single allocation", "It's required", "Better error messages"], correctAnswer: 1, explanation: "make_unique provides exception safety (no leak if an exception occurs during construction) and is more concise. It's also single allocation for the pointer metadata.", topic: "Memory" },
  { id: 64, question: "What is the Rule of Zero?", options: ["Never use destructors", "If you don't manage resources, don't write special member functions", "Always use zero initialization", "Have zero memory leaks"], correctAnswer: 1, explanation: "The Rule of Zero states that if your class doesn't directly manage resources (uses RAII types like smart pointers), you shouldn't define destructor, copy/move constructors, or assignment operators.", topic: "Memory" },
  { id: 65, question: "What is the Rule of Five?", options: ["Always define five constructors", "If you define one special member, define all five (destructor, copy/move constructors, copy/move assignment)", "Five levels of access control", "Maximum five pointers per class"], correctAnswer: 1, explanation: "If you need a custom destructor, copy constructor, or copy assignment operator (for resource management), you likely need to define all five special member functions.", topic: "Memory" },

  // ==================== Topic 6: Modern C++ (Questions 66-75) ====================
  { id: 66, question: "What is move semantics?", options: ["Moving code to different files", "Transferring resources instead of copying them", "Moving objects in memory", "A new memory allocator"], correctAnswer: 1, explanation: "Move semantics (C++11) allows transferring ownership of resources from one object to another without copying, avoiding expensive deep copies for temporary objects.", topic: "Modern C++" },
  { id: 67, question: "What is an rvalue reference (&&)?", options: ["A reference that can be reassigned", "A reference to a temporary or movable object", "A double reference", "A constant reference"], correctAnswer: 1, explanation: "Rvalue references (T&&) bind to temporary objects and enable move semantics. They indicate that the referred-to object can be moved from.", topic: "Modern C++" },
  { id: 68, question: "What does std::move do?", options: ["Moves an object in memory", "Casts an lvalue to an rvalue reference, enabling move semantics", "Moves elements in a container", "Deletes an object"], correctAnswer: 1, explanation: "std::move is a cast that converts an lvalue to an rvalue reference, signaling that the object can be moved from. It doesn't actually move anything by itself.", topic: "Modern C++" },
  { id: 69, question: "What is perfect forwarding?", options: ["Forwarding emails perfectly", "Passing arguments with their original value category preserved", "A perfect hash function", "Forwarding to parent class"], correctAnswer: 1, explanation: "Perfect forwarding uses universal references (T&&) with std::forward to pass arguments exactly as received - preserving whether they were lvalues or rvalues.", topic: "Modern C++" },
  { id: 70, question: "What is a lambda expression?", options: ["A Greek programming language", "An anonymous inline function object", "A type of template", "A mathematical operator"], correctAnswer: 1, explanation: "Lambdas are anonymous functions defined inline: [captures](params) -> return_type { body }. They're useful for short callbacks and with STL algorithms.", topic: "Modern C++" },
  { id: 71, question: "What does [=] capture in a lambda?", options: ["Nothing", "All local variables by value", "All local variables by reference", "The this pointer"], correctAnswer: 1, explanation: "[=] captures all local variables used in the lambda by value (copy). [&] captures by reference, and [this] captures the this pointer.", topic: "Modern C++" },
  { id: 72, question: "What is std::optional used for?", options: ["Optional parameters only", "Representing a value that may or may not exist", "Optional compilation", "Optional inheritance"], correctAnswer: 1, explanation: "std::optional<T> (C++17) represents an optional value - it either contains a T or is empty. It's useful for functions that may not return a meaningful result.", topic: "Modern C++" },
  { id: 73, question: "What is std::variant?", options: ["A variable template", "A type-safe union that can hold one of several types", "A variant of std::vector", "A debugging type"], correctAnswer: 1, explanation: "std::variant<T1, T2, ...> (C++17) is a type-safe union that holds exactly one value of one of its alternative types at any time.", topic: "Modern C++" },
  { id: 74, question: "What are structured bindings in C++17?", options: ["A way to bind structs to memory", "Syntax for unpacking tuples/arrays/structs into named variables", "Binding structures together", "A memory binding technique"], correctAnswer: 1, explanation: "Structured bindings allow declaring multiple variables initialized from a tuple, pair, array, or struct: auto [x, y, z] = getTuple();", topic: "Modern C++" },
  { id: 75, question: "What is constexpr used for?", options: ["Constant expressions only", "Indicating that a function/variable can be evaluated at compile time", "Making code faster", "Defining constants"], correctAnswer: 1, explanation: "constexpr indicates that a variable or function can be evaluated at compile time. constexpr functions can also run at runtime if needed.", topic: "Modern C++" },
];

const QUESTIONS_PER_QUIZ = 10;

const QuizSection: React.FC = () => {
  const [quizState, setQuizState] = useState<'start' | 'active' | 'results'>('start');
  const [questions, setQuestions] = useState<QuizQuestion[]>([]);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<{ [key: number]: number }>({});
  const [showExplanation, setShowExplanation] = useState(false);
  const [score, setScore] = useState(0);

  const startQuiz = () => {
    const shuffled = [...questionBank].sort(() => Math.random() - 0.5);
    const selected = shuffled.slice(0, QUESTIONS_PER_QUIZ);
    setQuestions(selected);
    setCurrentQuestionIndex(0);
    setSelectedAnswers({});
    setShowExplanation(false);
    setScore(0);
    setQuizState('active');
  };

  const handleAnswerSelect = (answerIndex: number) => {
    if (showExplanation) return;
    setSelectedAnswers(prev => ({
      ...prev,
      [currentQuestionIndex]: answerIndex
    }));
  };

  const handleSubmitAnswer = () => {
    if (selectedAnswers[currentQuestionIndex] === undefined) return;
    setShowExplanation(true);
    if (selectedAnswers[currentQuestionIndex] === questions[currentQuestionIndex].correctAnswer) {
      setScore(prev => prev + 1);
    }
  };

  const handleNextQuestion = () => {
    if (currentQuestionIndex < questions.length - 1) {
      setCurrentQuestionIndex(prev => prev + 1);
      setShowExplanation(false);
    } else {
      setQuizState('results');
    }
  };

  const currentQuestion = questions[currentQuestionIndex];
  const selectedAnswer = selectedAnswers[currentQuestionIndex];
  const isCorrect = selectedAnswer === currentQuestion?.correctAnswer;

  if (quizState === 'start') {
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <QuizIcon sx={{ fontSize: 64, color: accentColor, mb: 2 }} />
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
          C++ Programming Quiz
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 500, mx: "auto" }}>
          Test your understanding of C++ concepts with {QUESTIONS_PER_QUIZ} randomly selected questions from our 75-question bank. Topics include Basics, OOP, Templates, STL, Memory Management, and Modern C++.
        </Typography>
        <Button
          variant="contained"
          size="large"
          onClick={startQuiz}
          sx={{
            bgcolor: accentColor,
            "&:hover": { bgcolor: accentColorDark },
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

  if (quizState === 'results') {
    const percentage = Math.round((score / QUESTIONS_PER_QUIZ) * 100);
    const isPassing = percentage >= 70;
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <EmojiEventsIcon sx={{ fontSize: 80, color: isPassing ? "#22c55e" : accentColor, mb: 2 }} />
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          Quiz Complete!
        </Typography>
        <Typography variant="h5" sx={{ fontWeight: 700, color: isPassing ? "#22c55e" : accentColor, mb: 2 }}>
          {score} / {QUESTIONS_PER_QUIZ} ({percentage}%)
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 400, mx: "auto" }}>
          {isPassing 
            ? "Great job! You have a solid understanding of C++ concepts." 
            : "Keep studying! Review the modules above and try again."}
        </Typography>
        <Button
          variant="contained"
          size="large"
          onClick={startQuiz}
          startIcon={<RefreshIcon />}
          sx={{
            bgcolor: accentColor,
            "&:hover": { bgcolor: accentColorDark },
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

  return (
    <Box sx={{ py: 2 }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
          <Chip 
            label={`Question ${currentQuestionIndex + 1}/${QUESTIONS_PER_QUIZ}`} 
            size="small" 
            sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, fontWeight: 700 }} 
          />
          <Chip label={currentQuestion.topic} size="small" variant="outlined" />
        </Box>
        <Chip 
          label={`Score: ${score}/${currentQuestionIndex + (showExplanation ? 1 : 0)}`} 
          size="small" 
          sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} 
        />
      </Box>

      <Box sx={{ mb: 3, bgcolor: alpha(accentColor, 0.1), borderRadius: 1, height: 8 }}>
        <Box 
          sx={{ 
            width: `${((currentQuestionIndex + (showExplanation ? 1 : 0)) / QUESTIONS_PER_QUIZ) * 100}%`, 
            bgcolor: accentColor, 
            borderRadius: 1, 
            height: "100%",
            transition: "width 0.3s ease"
          }} 
        />
      </Box>

      <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
        {currentQuestion.question}
      </Typography>

      <RadioGroup value={selectedAnswer ?? ""} onChange={(e) => handleAnswerSelect(parseInt(e.target.value))}>
        {currentQuestion.options.map((option, idx) => (
          <Paper
            key={idx}
            sx={{
              p: 2,
              mb: 1.5,
              borderRadius: 2,
              cursor: showExplanation ? "default" : "pointer",
              border: `2px solid ${
                showExplanation
                  ? idx === currentQuestion.correctAnswer
                    ? "#22c55e"
                    : idx === selectedAnswer
                    ? "#ef4444"
                    : "transparent"
                  : selectedAnswer === idx
                  ? accentColor
                  : "transparent"
              }`,
              bgcolor: showExplanation
                ? idx === currentQuestion.correctAnswer
                  ? alpha("#22c55e", 0.1)
                  : idx === selectedAnswer
                  ? alpha("#ef4444", 0.1)
                  : "transparent"
                : selectedAnswer === idx
                ? alpha(accentColor, 0.1)
                : "transparent",
              transition: "all 0.2s ease",
              "&:hover": {
                bgcolor: showExplanation ? undefined : alpha(accentColor, 0.05),
              },
            }}
            onClick={() => handleAnswerSelect(idx)}
          >
            <FormControlLabel
              value={idx}
              control={<Radio sx={{ color: accentColor, "&.Mui-checked": { color: accentColor } }} />}
              label={option}
              sx={{ m: 0, width: "100%" }}
              disabled={showExplanation}
            />
          </Paper>
        ))}
      </RadioGroup>

      {!showExplanation ? (
        <Button
          variant="contained"
          fullWidth
          onClick={handleSubmitAnswer}
          disabled={selectedAnswer === undefined}
          sx={{
            mt: 2,
            bgcolor: accentColor,
            "&:hover": { bgcolor: accentColorDark },
            "&:disabled": { bgcolor: alpha(accentColor, 0.3) },
            py: 1.5,
            fontWeight: 700,
          }}
        >
          Submit Answer
        </Button>
      ) : (
        <Box sx={{ mt: 3 }}>
          <Alert
            severity={isCorrect ? "success" : "error"}
            sx={{ mb: 2, borderRadius: 2 }}
          >
            <AlertTitle sx={{ fontWeight: 700 }}>
              {isCorrect ? "🎉 Correct!" : "❌ Incorrect"}
            </AlertTitle>
            {currentQuestion.explanation}
          </Alert>
          <Button
            variant="contained"
            fullWidth
            onClick={handleNextQuestion}
            sx={{
              bgcolor: accentColor,
              "&:hover": { bgcolor: accentColorDark },
              py: 1.5,
              fontWeight: 700,
            }}
          >
            {currentQuestionIndex < questions.length - 1 ? "Next Question" : "See Results"}
          </Button>
        </Box>
      )}
    </Box>
  );
};

export default function CppProgrammingPage() {
  const navigate = useNavigate();

  return (
    <LearnPageLayout pageTitle="C++ Programming" pageContext="Comprehensive C++ programming course covering OOP, templates, STL, memory management, and modern C++ features.">
      <Box sx={{ display: "flex", minHeight: "100vh", bgcolor: "background.default" }}>
        {/* Sidebar Navigation */}
        <Box
          sx={{
            width: 280,
            flexShrink: 0,
            borderRight: 1,
            borderColor: "divider",
            p: 2,
            position: "sticky",
            top: 0,
            height: "100vh",
            overflowY: "auto",
            display: { xs: "none", md: "block" },
          }}
        >
          <Typography variant="overline" sx={{ color: "text.secondary", fontWeight: 700, mb: 2, display: "block" }}>
            C++ Modules
          </Typography>
          <List dense>
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
                <ListItemIcon sx={{ minWidth: 36, color: accentColor }}>{item.icon}</ListItemIcon>
                <ListItemText primary={item.label} primaryTypographyProps={{ fontSize: 14 }} />
              </ListItem>
            ))}
          </List>
        </Box>

        {/* Main Content */}
        <Box sx={{ flex: 1, p: { xs: 2, md: 4 }, maxWidth: 1000, mx: "auto" }}>
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
              background: `linear-gradient(135deg, ${alpha(accentColor, 0.1)} 0%, ${alpha(accentColorDark, 0.05)} 100%)`,
              border: `1px solid ${alpha(accentColor, 0.2)}`,
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
              <Avatar
                sx={{
                  width: 80,
                  height: 80,
                  bgcolor: accentColor,
                  fontSize: 32,
                  fontWeight: 900,
                }}
              >
                C++
              </Avatar>
              <Box>
                <Typography variant="h3" sx={{ fontWeight: 900, mb: 0.5 }}>
                  C++ Programming
                </Typography>
                <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 500 }}>
                  Master the power of object-oriented and systems programming
                </Typography>
              </Box>
            </Box>

            {/* Quick Stats */}
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
                    <Typography variant="h6" sx={{ fontWeight: 800, color: stat.color }}>
                      {stat.value}
                    </Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
                      {stat.label}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Detailed Introduction Section */}
          <Paper id="history" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3 }}>
              Introduction to C++
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              C++ is one of the most powerful and versatile programming languages in existence. Created by{" "}
              <strong>Bjarne Stroustrup</strong> at Bell Labs in 1979 (originally named "C with Classes"), C++ 
              has evolved into a sophisticated multi-paradigm language that combines the low-level power of C 
              with high-level abstractions like object-oriented programming, generic programming, and functional 
              programming features.
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Unlike purely object-oriented languages, C++ gives programmers the freedom to choose their 
              programming paradigm based on the problem at hand. You can write procedural code like C, 
              design elegant object-oriented hierarchies, create generic algorithms with templates, or 
              use modern functional programming patterns—all within the same language.
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              C++ is known for its philosophy of <strong>"zero-cost abstractions"</strong>—the idea that 
              high-level features should not impose any runtime overhead beyond what a competent programmer 
              would write by hand. This makes C++ the language of choice for performance-critical applications 
              where every CPU cycle matters.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Why Learn C++?
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                {
                  title: "Unmatched Performance",
                  desc: "Direct hardware access, manual memory control, and zero-cost abstractions make C++ the fastest high-level language",
                  icon: <SpeedIcon />,
                },
                {
                  title: "Object-Oriented Design",
                  desc: "Classes, inheritance, polymorphism, and encapsulation enable building complex, maintainable software architectures",
                  icon: <AccountTreeIcon />,
                },
                {
                  title: "Generic Programming",
                  desc: "Templates enable writing type-safe, reusable code that works with any data type without runtime overhead",
                  icon: <AutoFixHighIcon />,
                },
                {
                  title: "Industry Standard",
                  desc: "Used in game development, finance, embedded systems, and anywhere performance and reliability are critical",
                  icon: <BuildIcon />,
                },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(accentColor, 0.05), height: "100%" }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Box sx={{ color: accentColor }}>{item.icon}</Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                        {item.title}
                      </Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary">
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              The Evolution of C++: A Historical Journey
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Understanding C++'s history helps explain why the language looks the way it does today. 
              Each major revision added features that addressed real-world programming challenges:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                {
                  year: "1979",
                  title: "C with Classes",
                  desc: "Bjarne Stroustrup begins work at Bell Labs, adding classes, derived classes, strong type checking, and inline functions to C",
                },
                {
                  year: "1983",
                  title: "C++ Named",
                  desc: "The language is renamed to C++ (the ++ being the increment operator). Virtual functions, function overloading, and references are added",
                },
                {
                  year: "1985",
                  title: "First Commercial Release",
                  desc: "Cfront 1.0 released. 'The C++ Programming Language' first edition published, becoming the definitive reference",
                },
                {
                  year: "1998",
                  title: "C++98 (ISO Standard)",
                  desc: "First ISO standardized version. Introduces STL, templates, exceptions, namespaces, and RTTI. The foundation of modern C++",
                },
                {
                  year: "2003",
                  title: "C++03",
                  desc: "Bug fix release addressing defects in C++98. No new features, but improved consistency and portability",
                },
                {
                  year: "2011",
                  title: "C++11 (Major Revolution)",
                  desc: "Massive update: auto, lambda expressions, move semantics, smart pointers, range-based for, nullptr, constexpr, threads, and much more",
                },
                {
                  year: "2014",
                  title: "C++14",
                  desc: "Refinements to C++11: generic lambdas, variable templates, relaxed constexpr, binary literals, digit separators",
                },
                {
                  year: "2017",
                  title: "C++17",
                  desc: "Structured bindings, if constexpr, std::optional, std::variant, std::string_view, parallel algorithms, filesystem library",
                },
                {
                  year: "2020",
                  title: "C++20 (Second Revolution)",
                  desc: "Concepts, ranges, coroutines, modules, three-way comparison (spaceship operator), calendar and timezone library",
                },
                {
                  year: "2023",
                  title: "C++23",
                  desc: "std::expected, deducing this, std::print, ranges improvements, multidimensional subscript operator, and more quality-of-life improvements",
                },
              ].map((item, index) => (
                <Grid item xs={12} sm={6} key={index}>
                  <Paper
                    sx={{
                      p: 2,
                      borderRadius: 2,
                      borderLeft: `4px solid ${accentColor}`,
                      bgcolor: alpha(accentColor, 0.02),
                    }}
                  >
                    <Chip
                      label={item.year}
                      size="small"
                      sx={{ bgcolor: accentColor, color: "white", fontWeight: 700, mb: 1 }}
                    />
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
                      {item.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Where C++ is Used Today
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              C++ powers some of the most demanding software systems in the world. Its combination of 
              performance, flexibility, and mature tooling makes it irreplaceable in many domains:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                {
                  title: "Game Development",
                  desc: "Unreal Engine, Unity (runtime), CryEngine, and most AAA game engines are built with C++. Game logic, physics, and rendering require C++ performance",
                  icon: <SpeedIcon />,
                },
                {
                  title: "Systems Software",
                  desc: "Operating systems (Windows, macOS components), compilers (GCC, Clang, MSVC), virtual machines (V8, JVM HotSpot), and databases",
                  icon: <TerminalIcon />,
                },
                {
                  title: "High-Frequency Trading",
                  desc: "Financial systems where microseconds matter. Trading platforms, risk engines, and market data systems rely on C++ for latency-critical paths",
                  icon: <SpeedIcon />,
                },
                {
                  title: "Embedded & IoT",
                  desc: "Automotive systems (AUTOSAR), medical devices, robotics (ROS), drones, and industrial automation where C provides power but C++ adds abstraction",
                  icon: <DeveloperBoardIcon />,
                },
                {
                  title: "Computer Graphics",
                  desc: "Graphics APIs (OpenGL, DirectX, Vulkan), 3D modeling software (Blender, Maya, 3ds Max), image processing, and CAD applications",
                  icon: <ViewModuleIcon />,
                },
                {
                  title: "Machine Learning",
                  desc: "TensorFlow, PyTorch, ONNX Runtime, and other ML frameworks are C++ under the hood. Inference engines and custom operators need C++ speed",
                  icon: <AutoFixHighIcon />,
                },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(accentColor, 0.05), height: "100%" }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Box sx={{ color: accentColor }}>{item.icon}</Box>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>
                        {item.title}
                      </Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary">
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              C++ for Security Professionals
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              For cybersecurity practitioners, C++ knowledge is invaluable. Many security-critical systems 
              and tools are built with C++, and understanding its intricacies is essential for:
            </Typography>

            <List>
              {[
                {
                  primary: "Exploit Development",
                  secondary:
                    "Use-after-free, type confusion, vtable hijacking, and template metaprogramming exploits require deep C++ understanding",
                },
                {
                  primary: "Malware Analysis",
                  secondary:
                    "Advanced malware often uses C++ for OOP obfuscation, exception-based control flow, and template-heavy code that complicates analysis",
                },
                {
                  primary: "Browser Security",
                  secondary:
                    "Chrome, Firefox, Edge, and Safari are C++ codebases. Browser exploitation requires understanding C++ object layouts and memory management",
                },
                {
                  primary: "Game Hacking & Anti-Cheat",
                  secondary:
                    "Game hacking, anti-cheat development, and game security research all require reverse engineering C++ binaries",
                },
                {
                  primary: "Security Tool Development",
                  secondary:
                    "Performance-critical security tools, fuzzing engines, static analyzers, and system utilities often need C++ for speed",
                },
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
              This comprehensive C++ course takes you from the basics through advanced topics. You'll gain 
              both theoretical understanding and practical skills:
            </Typography>

            <Grid container spacing={2}>
              {[
                "Development environment setup with g++, clang++, MSVC, and CMake",
                "C++ basics: namespaces, I/O streams, references, and modern syntax",
                "Object-oriented programming: classes, encapsulation, inheritance, polymorphism",
                "Constructors, destructors, and the rule of zero/three/five",
                "Operator overloading and friend functions",
                "Templates: function templates, class templates, and template specialization",
                "The Standard Template Library: containers, iterators, algorithms",
                "Memory management: RAII, smart pointers (unique_ptr, shared_ptr, weak_ptr)",
                "Move semantics and rvalue references",
                "Lambda expressions and functional programming",
                "Exception handling and error management strategies",
                "Modern C++ features: auto, constexpr, structured bindings, ranges",
                "Multithreading: std::thread, mutexes, condition variables, atomics",
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
                border: `1px solid ${alpha("#4caf50", 0.3)}`,
              }}
            >
              <Typography
                variant="subtitle1"
                sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}
              >
                <CheckCircleIcon sx={{ color: "#4caf50" }} />
                Prerequisites
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Basic understanding of C programming is recommended (variables, pointers, memory allocation), 
                though not strictly required. Familiarity with any programming language and basic computer 
                science concepts (data structures, algorithms) will help you progress faster.
              </Typography>
            </Paper>
          </Paper>

          {/* Environment Setup Section */}
          <Paper id="setup" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#26a69a", 0.15), color: "#26a69a", width: 48, height: 48 }}>
                <BuildIcon />
              </Avatar>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Environment Setup
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Before writing your first C++ program, you need to set up a proper development environment. 
              This includes choosing a compiler, configuring a build system, selecting an IDE or editor, 
              and understanding how C++ compilation works. A well-configured environment will make your 
              learning journey much smoother.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#26a69a" }}>
              Choosing a Compiler
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              C++ compilers translate your source code into executable machine code. The three major 
              compilers each have their strengths:
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                {
                  title: "GCC (g++)",
                  desc: "The GNU Compiler Collection. Excellent standards compliance, great error messages, available on Linux/macOS/Windows (via MinGW or WSL). Command: g++ -std=c++20 main.cpp -o main",
                  platform: "Linux, macOS, Windows",
                },
                {
                  title: "Clang (clang++)",
                  desc: "LLVM-based compiler known for exceptional error messages and fast compilation. Default on macOS, available everywhere. Command: clang++ -std=c++20 main.cpp -o main",
                  platform: "Linux, macOS, Windows",
                },
                {
                  title: "MSVC (cl.exe)",
                  desc: "Microsoft Visual C++ compiler. Best Windows integration, excellent debugger, required for some Windows-specific development. Comes with Visual Studio.",
                  platform: "Windows",
                },
              ].map((item) => (
                <Grid item xs={12} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#26a69a", 0.05) }}>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                      <Chip label={item.platform} size="small" sx={{ bgcolor: alpha("#26a69a", 0.15) }} />
                    </Box>
                    <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#26a69a" }}>
              Installation by Platform
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                {
                  title: "Windows",
                  steps: [
                    "Option 1: Install Visual Studio Community (includes MSVC, debugger, IDE)",
                    "Option 2: Install MSYS2/MinGW-w64 for GCC (pacman -S mingw-w64-x86_64-gcc)",
                    "Option 3: Use WSL2 with Ubuntu for a Linux environment",
                    "Add compiler to PATH environment variable",
                  ],
                },
                {
                  title: "macOS",
                  steps: [
                    "Install Xcode Command Line Tools: xcode-select --install",
                    "This provides Clang (aliased as g++ too)",
                    "Optional: Install Homebrew and run brew install gcc for actual GCC",
                    "Verify with: clang++ --version",
                  ],
                },
                {
                  title: "Linux (Ubuntu/Debian)",
                  steps: [
                    "sudo apt update && sudo apt install build-essential",
                    "This installs GCC, G++, and Make",
                    "For Clang: sudo apt install clang",
                    "For latest GCC: sudo apt install gcc-13 g++-13",
                  ],
                },
              ].map((item) => (
                <Grid item xs={12} md={4} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, height: "100%", bgcolor: alpha("#26a69a", 0.03) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, color: "#26a69a" }}>
                      {item.title}
                    </Typography>
                    <List dense>
                      {item.steps.map((step, idx) => (
                        <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                          <ListItemIcon sx={{ minWidth: 24 }}>
                            <CheckCircleIcon sx={{ fontSize: 16, color: "#26a69a" }} />
                          </ListItemIcon>
                          <ListItemText 
                            primary={step} 
                            primaryTypographyProps={{ variant: "body2" }} 
                          />
                        </ListItem>
                      ))}
                    </List>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#26a69a" }}>
              Recommended IDEs & Editors
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "Visual Studio Code", desc: "Free, lightweight, excellent C++ extension with IntelliSense, debugging, CMake integration", best: "Cross-platform, beginners" },
                { name: "CLion", desc: "JetBrains IDE with powerful refactoring, CMake-native, excellent code analysis", best: "Professional development" },
                { name: "Visual Studio", desc: "Full-featured Windows IDE, best MSVC integration, powerful debugger", best: "Windows development" },
                { name: "Qt Creator", desc: "Great for Qt development but works for any C++, good CMake support", best: "GUI applications" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.name}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#26a69a", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.name}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.desc}</Typography>
                    <Chip label={`Best for: ${item.best}`} size="small" sx={{ bgcolor: alpha("#26a69a", 0.15) }} />
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#26a69a" }}>
              Your First C++ Program
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Create a file called <code>hello.cpp</code> and compile it to verify your setup:
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// hello.cpp - Your first C++ program
#include <iostream>

int main() {
    std::cout << "Hello, C++!" << std::endl;
    return 0;
}`}
              </Typography>
            </Paper>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Compile and run with:
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0 }}>
{`# GCC/Clang
g++ -std=c++20 -Wall -Wextra hello.cpp -o hello
./hello

# MSVC (Developer Command Prompt)
cl /EHsc /std:c++20 hello.cpp
hello.exe`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#2196f3", 0.1), border: `1px solid ${alpha("#2196f3", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <BuildIcon sx={{ color: "#2196f3" }} />
                Compiler Flags to Know
              </Typography>
              <Typography variant="body2" color="text.secondary">
                <strong>-std=c++20</strong>: Use C++20 standard • <strong>-Wall -Wextra</strong>: Enable warnings • 
                <strong>-g</strong>: Include debug symbols • <strong>-O2</strong>: Optimize for speed • 
                <strong>-o name</strong>: Output filename • <strong>-fsanitize=address</strong>: Memory error detection
              </Typography>
            </Paper>
          </Paper>

          {/* C++ Basics & Syntax Section */}
          <Paper id="basics" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <CodeIcon />
              </Avatar>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                C++ Basics & Syntax
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              C++ builds upon C but introduces many new features that make code safer, more expressive, 
              and easier to maintain. Understanding these fundamentals is essential before diving into 
              object-oriented programming and advanced features.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Key Differences from C
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { feature: "I/O Streams", c: "printf/scanf", cpp: "std::cout/std::cin - Type-safe, extensible" },
                { feature: "Strings", c: "char arrays, strlen()", cpp: "std::string - Automatic memory management" },
                { feature: "Memory", c: "malloc/free", cpp: "new/delete, smart pointers (preferred)" },
                { feature: "Booleans", c: "_Bool or int", cpp: "bool (true/false) - Native type" },
                { feature: "References", c: "Pointers only", cpp: "References (&) - Safer aliasing" },
                { feature: "Namespaces", c: "None (prefix conventions)", cpp: "namespace - Avoid name collisions" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.feature}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(accentColor, 0.03) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: accentColor }}>{item.feature}</Typography>
                    <Typography variant="body2"><strong>C:</strong> {item.c}</Typography>
                    <Typography variant="body2"><strong>C++:</strong> {item.cpp}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Namespaces
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Namespaces prevent naming conflicts in large projects. The standard library lives in <code>std</code>:
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`#include <iostream>
#include <string>

// Explicit namespace qualification (recommended)
std::string name = "Alice";
std::cout << name << std::endl;

// Using declaration (import specific names)
using std::cout;
using std::endl;
cout << "Hello" << endl;

// Using directive (import everything - avoid in headers!)
using namespace std;
cout << "World" << endl;`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              References vs Pointers
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              References provide an alias to an existing variable. Unlike pointers, they cannot be null 
              and cannot be reseated to refer to a different object:
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`int x = 10;

// Reference - must be initialized, cannot be null
int& ref = x;      // ref is an alias for x
ref = 20;          // x is now 20

// Pointer - can be null, can be reassigned
int* ptr = &x;     // ptr holds address of x
*ptr = 30;         // x is now 30
ptr = nullptr;     // valid - ptr now points to nothing

// Function parameters
void byValue(int n) { n++; }           // Copy - original unchanged
void byPointer(int* p) { (*p)++; }     // Original modified
void byReference(int& r) { r++; }      // Original modified (cleaner)`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Auto Type Deduction
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              The <code>auto</code> keyword lets the compiler deduce the type from the initializer:
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`auto i = 42;              // int
auto d = 3.14;            // double
auto s = "hello";         // const char*
auto str = std::string("hello");  // std::string

// Very useful for complex types
std::vector<int> vec = {1, 2, 3};
auto it = vec.begin();    // std::vector<int>::iterator

// Range-based for loop (C++11)
for (auto& elem : vec) {
    elem *= 2;  // Modifies original
}

for (const auto& elem : vec) {
    std::cout << elem << " ";  // Read-only access
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Const Correctness
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Using <code>const</code> correctly prevents accidental modifications and enables compiler optimizations:
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`const int MAX = 100;           // Compile-time constant
constexpr int SIZE = 50;       // Guaranteed compile-time (C++11)

// Const with pointers (read right to left)
const int* p1;      // Pointer to const int (can't modify value)
int* const p2;      // Const pointer to int (can't change address)
const int* const p3; // Const pointer to const int

// Const references - common for function parameters
void print(const std::string& s) {
    // Can read s, but cannot modify it
    std::cout << s << std::endl;
}`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#ff9800", 0.1), border: `1px solid ${alpha("#ff9800", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CodeIcon sx={{ color: "#ff9800" }} />
                Best Practice
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Use <code>const</code> by default. Pass large objects by <code>const&</code> to avoid copies. 
                Use <code>auto</code> for complex types but be explicit when the type matters for readability.
                Prefer <code>std::string</code> over C-style strings and <code>std::vector</code> over raw arrays.
              </Typography>
            </Paper>
          </Paper>

          {/* Object-Oriented Programming Section */}
          <Paper id="oop" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#9c27b0", 0.15), color: "#9c27b0", width: 48, height: 48 }}>
                <AccountTreeIcon />
              </Avatar>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Object-Oriented Programming
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Object-Oriented Programming (OOP) is a paradigm that organizes code around objects—entities 
              that combine data (attributes) and behavior (methods). C++ supports OOP while also allowing 
              procedural and generic programming, giving you flexibility in how you structure your code.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9c27b0" }}>
              The Four Pillars of OOP
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                {
                  title: "Encapsulation",
                  icon: <SecurityIcon />,
                  desc: "Bundle data and methods that operate on that data within a single unit (class). Hide internal details and expose only what's necessary through public interfaces.",
                  example: "Private member variables with public getter/setter methods",
                },
                {
                  title: "Abstraction",
                  icon: <LayersIcon />,
                  desc: "Hide complex implementation details and show only essential features. Users interact with a simplified interface without needing to understand the underlying complexity.",
                  example: "A Database class that hides SQL queries behind simple save()/load() methods",
                },
                {
                  title: "Inheritance",
                  icon: <AccountTreeIcon />,
                  desc: "Create new classes based on existing ones, inheriting their properties and behaviors. Enables code reuse and establishes 'is-a' relationships.",
                  example: "class Dog : public Animal - Dog inherits from Animal",
                },
                {
                  title: "Polymorphism",
                  icon: <ExtensionIcon />,
                  desc: "Objects of different types can be treated through a common interface. The same method call can behave differently based on the actual object type.",
                  example: "animal->speak() calls Dog::speak() or Cat::speak() based on actual type",
                },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#9c27b0", 0.05), height: "100%" }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Box sx={{ color: "#9c27b0" }}>{item.icon}</Box>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.desc}</Typography>
                    <Chip label={item.example} size="small" sx={{ bgcolor: alpha("#9c27b0", 0.1), fontSize: 11 }} />
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9c27b0" }}>
              A Simple Class Example
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`class BankAccount {
private:
    std::string owner;    // Encapsulated data
    double balance;

public:
    // Constructor
    BankAccount(const std::string& name, double initial = 0.0)
        : owner(name), balance(initial) {}
    
    // Public interface (abstraction)
    void deposit(double amount) {
        if (amount > 0) balance += amount;
    }
    
    bool withdraw(double amount) {
        if (amount > 0 && amount <= balance) {
            balance -= amount;
            return true;
        }
        return false;
    }
    
    double getBalance() const { return balance; }
    const std::string& getOwner() const { return owner; }
};

// Usage
BankAccount account("Alice", 1000.0);
account.deposit(500);
account.withdraw(200);
std::cout << account.getBalance();  // 1300`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9c27b0" }}>
              Inheritance Example
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`class Animal {
protected:
    std::string name;
public:
    Animal(const std::string& n) : name(n) {}
    virtual void speak() const {
        std::cout << name << " makes a sound" << std::endl;
    }
    virtual ~Animal() = default;  // Virtual destructor!
};

class Dog : public Animal {
public:
    Dog(const std::string& n) : Animal(n) {}
    void speak() const override {  // Polymorphism
        std::cout << name << " barks: Woof!" << std::endl;
    }
};

class Cat : public Animal {
public:
    Cat(const std::string& n) : Animal(n) {}
    void speak() const override {
        std::cout << name << " meows: Meow!" << std::endl;
    }
};

// Polymorphism in action
std::vector<std::unique_ptr<Animal>> animals;
animals.push_back(std::make_unique<Dog>("Rex"));
animals.push_back(std::make_unique<Cat>("Whiskers"));

for (const auto& animal : animals) {
    animal->speak();  // Calls the correct speak() based on type
}
// Output: Rex barks: Woof!
//         Whiskers meows: Meow!`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9c27b0" }}>
              When to Use OOP
            </Typography>

            <Grid container spacing={2}>
              {[
                { good: true, text: "Modeling real-world entities with state and behavior" },
                { good: true, text: "Building extensible systems where new types can be added" },
                { good: true, text: "GUI frameworks, game entities, document objects" },
                { good: false, text: "Simple data transformations (use functions)" },
                { good: false, text: "Performance-critical inner loops (virtual calls have overhead)" },
                { good: false, text: "Stateless utilities (use namespaces with free functions)" },
              ].map((item, idx) => (
                <Grid item xs={12} sm={6} key={idx}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <CheckCircleIcon sx={{ color: item.good ? "#4caf50" : "#f44336", fontSize: 18 }} />
                    <Typography variant="body2">
                      <strong>{item.good ? "Good:" : "Avoid:"}</strong> {item.text}
                    </Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, mt: 3, borderRadius: 2, bgcolor: alpha("#9c27b0", 0.1), border: `1px solid ${alpha("#9c27b0", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <AccountTreeIcon sx={{ color: "#9c27b0" }} />
                Key Takeaway
              </Typography>
              <Typography variant="body2" color="text.secondary">
                OOP is a tool, not a religion. Modern C++ encourages a multi-paradigm approach: use classes 
                when you need to model entities with state, but don't force everything into a class hierarchy. 
                Free functions, templates, and value types are often cleaner solutions.
              </Typography>
            </Paper>
          </Paper>

          {/* Classes & Objects Section */}
          <Paper id="classes" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#2196f3", 0.15), color: "#2196f3", width: 48, height: 48 }}>
                <ViewModuleIcon />
              </Avatar>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Classes & Objects
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Classes are the building blocks of object-oriented C++. A class defines a blueprint for 
              creating objects, combining data (member variables) and behavior (member functions) into 
              a cohesive unit. Understanding classes deeply is essential for effective C++ programming.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#2196f3" }}>
              Class Definition & Access Specifiers
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`class Rectangle {
private:    // Only accessible within the class
    double width;
    double height;
    
protected:  // Accessible in derived classes too
    std::string label;
    
public:     // Accessible from anywhere
    // Constructor with initialization list (preferred!)
    Rectangle(double w, double h, const std::string& lbl = "")
        : width(w), height(h), label(lbl) {}
    
    // Member functions
    double area() const { return width * height; }
    double perimeter() const { return 2 * (width + height); }
    
    // Getters and setters
    double getWidth() const { return width; }
    void setWidth(double w) { if (w > 0) width = w; }
};

// Creating objects
Rectangle r1(10, 5);                    // Stack allocation
Rectangle r2(3, 4, "small");            // With label
Rectangle* r3 = new Rectangle(7, 2);   // Heap allocation
delete r3;                              // Don't forget!`}
              </Typography>
            </Paper>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { spec: "private", desc: "Default for class. Members only accessible inside the class itself.", use: "Data members, internal helpers" },
                { spec: "protected", desc: "Accessible in the class and its derived classes.", use: "Data needed by subclasses" },
                { spec: "public", desc: "Accessible from anywhere the object is visible.", use: "Public API, interface methods" },
              ].map((item) => (
                <Grid item xs={12} md={4} key={item.spec}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#2196f3", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#2196f3" }}>{item.spec}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.desc}</Typography>
                    <Chip label={`Use for: ${item.use}`} size="small" sx={{ bgcolor: alpha("#2196f3", 0.1) }} />
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#2196f3" }}>
              Constructors & Destructors
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`class Resource {
private:
    int* data;
    size_t size;
    
public:
    // Default constructor
    Resource() : data(nullptr), size(0) {}
    
    // Parameterized constructor
    Resource(size_t n) : data(new int[n]), size(n) {
        std::fill(data, data + n, 0);
    }
    
    // Copy constructor
    Resource(const Resource& other) : data(new int[other.size]), size(other.size) {
        std::copy(other.data, other.data + size, data);
    }
    
    // Move constructor (C++11)
    Resource(Resource&& other) noexcept 
        : data(other.data), size(other.size) {
        other.data = nullptr;
        other.size = 0;
    }
    
    // Destructor - called when object goes out of scope
    ~Resource() {
        delete[] data;  // Clean up!
    }
    
    // Copy assignment operator
    Resource& operator=(const Resource& other) {
        if (this != &other) {
            delete[] data;
            size = other.size;
            data = new int[size];
            std::copy(other.data, other.data + size, data);
        }
        return *this;
    }
    
    // Move assignment operator
    Resource& operator=(Resource&& other) noexcept {
        if (this != &other) {
            delete[] data;
            data = other.data;
            size = other.size;
            other.data = nullptr;
            other.size = 0;
        }
        return *this;
    }
};`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#2196f3" }}>
              The Rule of Zero/Three/Five
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { rule: "Rule of Zero", desc: "If your class doesn't manage resources directly, don't define any special members. Use RAII types like std::string, std::vector, std::unique_ptr." },
                { rule: "Rule of Three", desc: "If you define a destructor, copy constructor, or copy assignment, you probably need all three. (Pre-C++11)" },
                { rule: "Rule of Five", desc: "In C++11+, add move constructor and move assignment to the Rule of Three for efficiency." },
              ].map((item) => (
                <Grid item xs={12} key={item.rule}>
                  <Paper sx={{ p: 2, borderRadius: 2, borderLeft: `4px solid #2196f3`, bgcolor: alpha("#2196f3", 0.03) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.rule}</Typography>
                    <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#2196f3" }}>
              Static Members & The this Pointer
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`class Counter {
private:
    int value;
    static int totalCount;  // Shared by all instances
    
public:
    Counter(int v = 0) : value(v) { totalCount++; }
    ~Counter() { totalCount--; }
    
    // Static method - no 'this' pointer, can't access non-static members
    static int getTotalCount() { return totalCount; }
    
    // 'this' is a pointer to the current object
    Counter& increment() {
        this->value++;      // Explicit (optional)
        value++;            // Implicit
        return *this;       // Return reference to self (for chaining)
    }
    
    // Method chaining
    Counter& add(int n) { value += n; return *this; }
    Counter& multiply(int n) { value *= n; return *this; }
};

int Counter::totalCount = 0;  // Define static member outside class

// Usage
Counter c1, c2, c3;
std::cout << Counter::getTotalCount();  // 3

c1.add(5).multiply(2).increment();  // Chaining: value = (0+5)*2+1 = 11`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#2196f3", 0.1), border: `1px solid ${alpha("#2196f3", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <ViewModuleIcon sx={{ color: "#2196f3" }} />
                RAII: Resource Acquisition Is Initialization
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Acquire resources in the constructor, release them in the destructor. This ensures resources 
                are always cleaned up, even when exceptions occur. Modern C++ types like <code>std::vector</code>, 
                <code>std::string</code>, and smart pointers follow RAII, making manual memory management rarely needed.
              </Typography>
            </Paper>
          </Paper>

          {/* Inheritance Section */}
          <Paper id="inheritance" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#ff9800", 0.15), color: "#ff9800", width: 48, height: 48 }}>
                <LayersIcon />
              </Avatar>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Inheritance
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Inheritance allows you to create new classes based on existing ones, inheriting their 
              attributes and behaviors. This establishes an "is-a" relationship and enables code reuse. 
              However, modern C++ often favors composition over inheritance for flexibility.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff9800" }}>
              Basic Inheritance
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`class Shape {
protected:
    std::string color;
    
public:
    Shape(const std::string& c = "black") : color(c) {}
    virtual ~Shape() = default;  // Always virtual in base classes!
    
    virtual double area() const = 0;  // Pure virtual - makes Shape abstract
    virtual void draw() const {
        std::cout << "Drawing a " << color << " shape" << std::endl;
    }
    
    std::string getColor() const { return color; }
};

class Circle : public Shape {
private:
    double radius;
    
public:
    Circle(double r, const std::string& c = "black")
        : Shape(c), radius(r) {}  // Call base constructor
    
    double area() const override {  // 'override' catches errors
        return 3.14159 * radius * radius;
    }
    
    void draw() const override {
        std::cout << "Drawing a " << color << " circle with radius " 
                  << radius << std::endl;
    }
};

class Rectangle : public Shape {
private:
    double width, height;
    
public:
    Rectangle(double w, double h, const std::string& c = "black")
        : Shape(c), width(w), height(h) {}
    
    double area() const override {
        return width * height;
    }
};`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff9800" }}>
              Inheritance Access Specifiers
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { type: "public inheritance", syntax: "class D : public B", effect: "public→public, protected→protected. Most common - models 'is-a' relationship." },
                { type: "protected inheritance", syntax: "class D : protected B", effect: "public→protected, protected→protected. Rarely used - implementation inheritance." },
                { type: "private inheritance", syntax: "class D : private B", effect: "All→private. 'Implemented-in-terms-of' - prefer composition instead." },
              ].map((item) => (
                <Grid item xs={12} key={item.type}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ff9800", 0.05) }}>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ff9800" }}>{item.type}</Typography>
                      <Chip label={item.syntax} size="small" sx={{ fontFamily: "monospace", bgcolor: alpha("#ff9800", 0.15) }} />
                    </Box>
                    <Typography variant="body2" color="text.secondary">{item.effect}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff9800" }}>
              Constructor & Destructor Order
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`class Base {
public:
    Base() { std::cout << "Base constructor" << std::endl; }
    virtual ~Base() { std::cout << "Base destructor" << std::endl; }
};

class Derived : public Base {
public:
    Derived() { std::cout << "Derived constructor" << std::endl; }
    ~Derived() { std::cout << "Derived destructor" << std::endl; }
};

// Creating Derived object prints:
// Base constructor
// Derived constructor

// Destroying prints (reverse order):
// Derived destructor
// Base destructor

// WHY virtual destructor matters:
Base* ptr = new Derived();
delete ptr;  // Without virtual ~Base(): ONLY Base destructor called! (BAD)
             // With virtual ~Base(): Both destructors called correctly`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff9800" }}>
              The Diamond Problem & Virtual Inheritance
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`//        Animal
//        /    \\
//    Mammal  Bird
//        \\    /
//        Bat (can fly and is a mammal)

class Animal {
public:
    int age;
    virtual void eat() { std::cout << "Eating" << std::endl; }
};

// Without 'virtual': Bat has TWO copies of Animal!
class Mammal : virtual public Animal {
public:
    void nurse() { std::cout << "Nursing" << std::endl; }
};

class Bird : virtual public Animal {
public:
    void layEggs() { std::cout << "Laying eggs" << std::endl; }
};

class Bat : public Mammal, public Bird {
public:
    void fly() { std::cout << "Flying" << std::endl; }
    // With virtual inheritance: only ONE Animal subobject
    // age is unambiguous
};

Bat b;
b.age = 5;     // OK with virtual inheritance
b.eat();       // Unambiguous`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#ff9800", 0.1), border: `1px solid ${alpha("#ff9800", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <LayersIcon sx={{ color: "#ff9800" }} />
                Composition vs Inheritance
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Prefer composition ("has-a") over inheritance ("is-a") when possible. Inheritance creates 
                tight coupling and can lead to fragile base class problems. Use inheritance for true "is-a" 
                relationships and when you need polymorphism. Use composition for code reuse and flexibility.
              </Typography>
            </Paper>
          </Paper>

          {/* Polymorphism Section */}
          <Paper id="polymorphism" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#00bcd4", 0.15), color: "#00bcd4", width: 48, height: 48 }}>
                <ExtensionIcon />
              </Avatar>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Polymorphism
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Polymorphism ("many forms") allows objects of different types to be treated through a 
              common interface. C++ supports both compile-time (static) and runtime (dynamic) polymorphism, 
              each with different use cases and performance characteristics.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00bcd4" }}>
              Compile-Time Polymorphism
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Resolved at compile time with no runtime overhead. Includes function overloading and templates:
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Function Overloading - same name, different parameters
void print(int x) { std::cout << "Int: " << x << std::endl; }
void print(double x) { std::cout << "Double: " << x << std::endl; }
void print(const std::string& s) { std::cout << "String: " << s << std::endl; }

print(42);        // Calls print(int)
print(3.14);      // Calls print(double)
print("hello");   // Calls print(const std::string&)

// Templates - generic programming
template<typename T>
T maximum(T a, T b) {
    return (a > b) ? a : b;
}

int m1 = maximum(10, 20);           // T = int
double m2 = maximum(3.14, 2.72);    // T = double
std::string m3 = maximum(std::string("abc"), std::string("xyz"));

// Compiler generates specialized versions at compile time
// No virtual call overhead!`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00bcd4" }}>
              Runtime Polymorphism (Virtual Functions)
            </Typography>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Resolved at runtime using virtual function tables (vtables). Requires pointers or references:
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`class Weapon {
public:
    virtual ~Weapon() = default;
    virtual void attack() const = 0;      // Pure virtual
    virtual int getDamage() const = 0;
    virtual std::string getName() const { return "Unknown"; }  // Default impl
};

class Sword : public Weapon {
public:
    void attack() const override {
        std::cout << "Slash with sword!" << std::endl;
    }
    int getDamage() const override { return 25; }
    std::string getName() const override { return "Steel Sword"; }
};

class Bow : public Weapon {
public:
    void attack() const override {
        std::cout << "Fire arrow!" << std::endl;
    }
    int getDamage() const override { return 15; }
    std::string getName() const override { return "Longbow"; }
};

// Polymorphism in action
void useWeapon(const Weapon& w) {  // Works with ANY Weapon subclass
    std::cout << "Using " << w.getName() << std::endl;
    w.attack();
    std::cout << "Damage: " << w.getDamage() << std::endl;
}

Sword sword;
Bow bow;
useWeapon(sword);  // Uses Sword's implementations
useWeapon(bow);    // Uses Bow's implementations`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00bcd4" }}>
              How vtables Work
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { step: "1", title: "vtable Creation", desc: "Each class with virtual functions gets a vtable - an array of function pointers to its virtual methods." },
                { step: "2", title: "vptr Storage", desc: "Each object contains a hidden pointer (vptr) to its class's vtable. Added automatically by compiler." },
                { step: "3", title: "Dynamic Dispatch", desc: "Virtual call: object→vptr→vtable[index]→function. One indirection compared to direct call." },
                { step: "4", title: "Override Mechanism", desc: "Derived classes get their own vtable with pointers to their overridden functions." },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.step}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#00bcd4", 0.05), height: "100%" }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Avatar sx={{ width: 24, height: 24, bgcolor: "#00bcd4", fontSize: 12 }}>{item.step}</Avatar>
                      <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#00bcd4" }}>
              Abstract Classes & Interfaces
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Abstract class - has at least one pure virtual function
class Drawable {
public:
    virtual ~Drawable() = default;
    virtual void draw() const = 0;  // = 0 makes it pure virtual
    virtual void resize(double factor) = 0;
    
    // Can still have non-virtual methods
    void drawTwice() const { draw(); draw(); }
};

// Interface pattern - all pure virtual (like Java interface)
class ISerializable {
public:
    virtual ~ISerializable() = default;
    virtual std::string serialize() const = 0;
    virtual void deserialize(const std::string& data) = 0;
};

// A class can implement multiple interfaces
class GameEntity : public Drawable, public ISerializable {
public:
    void draw() const override { /* ... */ }
    void resize(double factor) override { /* ... */ }
    std::string serialize() const override { /* ... */ }
    void deserialize(const std::string& data) override { /* ... */ }
};

// Cannot instantiate abstract classes
// Drawable d;  // ERROR!
// But can have pointers/references to them
std::vector<std::unique_ptr<Drawable>> objects;`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#00bcd4", 0.1), border: `1px solid ${alpha("#00bcd4", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <ExtensionIcon sx={{ color: "#00bcd4" }} />
                Performance Considerations
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Virtual calls have overhead: vptr lookup + indirect call (can't be inlined). For 
                performance-critical code, consider: templates (compile-time polymorphism), final 
                keyword (devirtualization), or CRTP pattern. But don't optimize prematurely—virtual 
                calls are fast enough for most use cases.
              </Typography>
            </Paper>
          </Paper>

          {/* Templates Section */}
          <Paper id="templates" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#8bc34a", 0.15), color: "#8bc34a", width: 48, height: 48 }}>
                <AutoFixHighIcon />
              </Avatar>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Templates
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Templates are C++'s mechanism for generic programming, allowing you to write code that works 
              with any type. The compiler generates specialized versions at compile time, giving you 
              flexibility without runtime overhead. Templates are the foundation of the STL.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8bc34a" }}>
              Function Templates
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Basic function template
template<typename T>
T max(T a, T b) {
    return (a > b) ? a : b;
}

// Multiple template parameters
template<typename T, typename U>
auto add(T a, U b) -> decltype(a + b) {  // Trailing return type
    return a + b;
}

// C++14: simplified with auto return
template<typename T, typename U>
auto multiply(T a, U b) {
    return a * b;
}

// Usage - compiler deduces types
int m1 = max(10, 20);              // T = int
double m2 = max(3.14, 2.72);       // T = double
auto sum = add(5, 3.14);           // T=int, U=double, returns double

// Explicit template arguments
auto m3 = max<double>(10, 3.14);   // Force T = double`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8bc34a" }}>
              Class Templates
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Generic container class
template<typename T, size_t N>  // Type parameter + non-type parameter
class Array {
private:
    T data[N];
    
public:
    T& operator[](size_t index) { return data[index]; }
    const T& operator[](size_t index) const { return data[index]; }
    
    constexpr size_t size() const { return N; }
    
    T* begin() { return data; }
    T* end() { return data + N; }
};

// Usage
Array<int, 5> intArr;           // Array of 5 ints
Array<std::string, 3> strArr;   // Array of 3 strings

// Template with default parameters
template<typename T, typename Allocator = std::allocator<T>>
class Vector {
    // std::vector-like implementation
};

Vector<int> v1;                  // Uses default allocator
Vector<int, MyAllocator<int>> v2;  // Custom allocator`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8bc34a" }}>
              Template Specialization
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Primary template
template<typename T>
class TypeInfo {
public:
    static std::string name() { return "Unknown"; }
};

// Full specialization for int
template<>
class TypeInfo<int> {
public:
    static std::string name() { return "Integer"; }
};

// Full specialization for double
template<>
class TypeInfo<double> {
public:
    static std::string name() { return "Double"; }
};

// Partial specialization for pointers
template<typename T>
class TypeInfo<T*> {
public:
    static std::string name() { 
        return "Pointer to " + TypeInfo<T>::name(); 
    }
};

std::cout << TypeInfo<int>::name();     // "Integer"
std::cout << TypeInfo<float>::name();   // "Unknown"
std::cout << TypeInfo<int*>::name();    // "Pointer to Integer"`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8bc34a" }}>
              Variadic Templates (C++11)
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Variadic function template - accepts any number of arguments
template<typename... Args>
void print(Args... args) {
    // Fold expression (C++17) - expands to: (cout << arg1), (cout << arg2), ...
    ((std::cout << args << " "), ...);
    std::cout << std::endl;
}

print(1, 2.5, "hello", 'x');  // "1 2.5 hello x"

// Recursive approach (pre-C++17)
void printRecursive() {}  // Base case

template<typename T, typename... Rest>
void printRecursive(T first, Rest... rest) {
    std::cout << first << " ";
    printRecursive(rest...);  // Recursive call with remaining args
}

// Variadic class template
template<typename... Ts>
class Tuple;  // Like std::tuple

// sizeof... gets parameter pack size
template<typename... Args>
constexpr size_t countArgs() {
    return sizeof...(Args);
}

static_assert(countArgs<int, double, char>() == 3);`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8bc34a" }}>
              Concepts (C++20)
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`#include <concepts>

// Define a concept - requirements for a type
template<typename T>
concept Numeric = std::is_arithmetic_v<T>;

template<typename T>
concept Sortable = requires(T a, T b) {
    { a < b } -> std::convertible_to<bool>;
    { a == b } -> std::convertible_to<bool>;
};

// Use concept to constrain template
template<Numeric T>
T square(T x) {
    return x * x;
}

// Alternative syntax
template<typename T>
    requires Sortable<T>
void sort(std::vector<T>& v);

// Shortest syntax
void process(Numeric auto x) {
    std::cout << x * 2 << std::endl;
}

square(5);       // OK
square(3.14);    // OK
// square("hi"); // ERROR: std::string doesn't satisfy Numeric`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#8bc34a", 0.1), border: `1px solid ${alpha("#8bc34a", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <AutoFixHighIcon sx={{ color: "#8bc34a" }} />
                Template Best Practices
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Templates are defined in headers (not .cpp files) because the compiler needs to see the 
                full definition to instantiate them. Use concepts (C++20) for clear error messages. 
                Prefer <code>constexpr</code> functions over template metaprogramming when possible.
              </Typography>
            </Paper>
          </Paper>

          {/* STL Section */}
          <Paper id="stl" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#673ab7", 0.15), color: "#673ab7", width: 48, height: 48 }}>
                <StorageIcon />
              </Avatar>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Standard Template Library (STL)
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              The STL is a collection of template classes and functions that provide common data structures 
              and algorithms. It's built on three pillars: containers (store data), iterators (access data), 
              and algorithms (manipulate data). Mastering the STL dramatically improves productivity.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#673ab7" }}>
              Sequence Containers
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`#include <vector>
#include <deque>
#include <list>
#include <array>

// vector - dynamic array, contiguous memory
std::vector<int> v = {1, 2, 3, 4, 5};
v.push_back(6);              // Add to end - O(1) amortized
v[0] = 10;                   // Random access - O(1)
v.insert(v.begin() + 2, 99); // Insert in middle - O(n)

// deque - double-ended queue
std::deque<int> d = {1, 2, 3};
d.push_front(0);             // Add to front - O(1)
d.push_back(4);              // Add to end - O(1)

// list - doubly-linked list
std::list<int> lst = {1, 2, 3};
lst.push_front(0);           // O(1)
auto it = std::next(lst.begin(), 2);
lst.insert(it, 99);          // Insert anywhere - O(1) with iterator

// array - fixed-size, stack-allocated
std::array<int, 5> arr = {1, 2, 3, 4, 5};
arr[0] = 10;                 // No bounds checking
arr.at(10);                  // Throws std::out_of_range`}
              </Typography>
            </Paper>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "vector", when: "Default choice. Random access needed. Adding mostly at end.", perf: "O(1) access, O(1) push_back" },
                { name: "deque", when: "Need to add/remove at both ends frequently.", perf: "O(1) access, O(1) push front/back" },
                { name: "list", when: "Frequent insertions/deletions in middle. No random access needed.", perf: "O(1) insert/delete with iterator" },
                { name: "array", when: "Fixed size known at compile time. Stack allocation preferred.", perf: "O(1) access, no dynamic allocation" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.name}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#673ab7", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#673ab7" }}>{item.name}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.when}</Typography>
                    <Chip label={item.perf} size="small" sx={{ bgcolor: alpha("#673ab7", 0.1), fontFamily: "monospace", fontSize: 11 }} />
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#673ab7" }}>
              Associative Containers
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

// map - ordered key-value pairs (red-black tree)
std::map<std::string, int> ages;
ages["Alice"] = 30;
ages.insert({"Bob", 25});
if (ages.find("Alice") != ages.end()) {
    std::cout << ages["Alice"];  // 30
}

// set - ordered unique elements
std::set<int> s = {3, 1, 4, 1, 5};  // {1, 3, 4, 5} - sorted, no duplicates
s.insert(2);                        // {1, 2, 3, 4, 5}
s.count(3);                         // 1 (exists)

// unordered_map - hash table, faster average case
std::unordered_map<std::string, int> hash;
hash["key"] = 42;                   // O(1) average

// unordered_set - hash set
std::unordered_set<int> hs = {1, 2, 3};

// multimap/multiset allow duplicate keys
std::multimap<std::string, int> mm;
mm.insert({"key", 1});
mm.insert({"key", 2});  // Both stored!`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#673ab7" }}>
              Iterators
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`std::vector<int> v = {1, 2, 3, 4, 5};

// Iterator basics
std::vector<int>::iterator it = v.begin();
std::cout << *it;       // 1 - dereference
++it;                   // Move to next
std::cout << *it;       // 2

// Modern C++ - use auto
for (auto it = v.begin(); it != v.end(); ++it) {
    std::cout << *it << " ";
}

// Range-based for (even simpler)
for (int x : v) { std::cout << x << " "; }
for (int& x : v) { x *= 2; }  // Modify elements

// Reverse iterators
for (auto rit = v.rbegin(); rit != v.rend(); ++rit) {
    std::cout << *rit << " ";  // 5 4 3 2 1
}

// const iterators - can't modify elements
for (auto cit = v.cbegin(); cit != v.cend(); ++cit) {
    // *cit = 10;  // ERROR!
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#673ab7" }}>
              Algorithms
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`#include <algorithm>
#include <numeric>

std::vector<int> v = {5, 2, 8, 1, 9, 3};

// Sorting
std::sort(v.begin(), v.end());                    // Ascending
std::sort(v.begin(), v.end(), std::greater<>());  // Descending
std::sort(v.begin(), v.end(), [](int a, int b) { return a > b; });

// Searching
auto it = std::find(v.begin(), v.end(), 8);
if (it != v.end()) std::cout << "Found at index " << (it - v.begin());

bool exists = std::binary_search(v.begin(), v.end(), 5);  // Sorted only!

// Transformations
std::vector<int> doubled(v.size());
std::transform(v.begin(), v.end(), doubled.begin(), [](int x) { return x * 2; });

// Filtering with remove-erase idiom
v.erase(std::remove_if(v.begin(), v.end(), [](int x) { return x < 5; }), v.end());

// Accumulation
int sum = std::accumulate(v.begin(), v.end(), 0);
int product = std::accumulate(v.begin(), v.end(), 1, std::multiplies<>());

// Other useful algorithms
std::reverse(v.begin(), v.end());
std::fill(v.begin(), v.end(), 0);
int maxVal = *std::max_element(v.begin(), v.end());
bool allPositive = std::all_of(v.begin(), v.end(), [](int x) { return x > 0; });`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#673ab7", 0.1), border: `1px solid ${alpha("#673ab7", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <StorageIcon sx={{ color: "#673ab7" }} />
                STL Best Practices
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Use <code>vector</code> by default—it's cache-friendly and fastest for most use cases. 
                Use <code>unordered_map/set</code> for O(1) lookups when order doesn't matter. 
                Prefer algorithms over raw loops—they're optimized and express intent clearly. 
                Reserve capacity with <code>vector::reserve()</code> when size is known to avoid reallocations.
              </Typography>
            </Paper>
          </Paper>

          {/* Memory Management Section */}
          <Paper id="memory" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#f44336", 0.15), color: "#f44336", width: 48, height: 48 }}>
                <MemoryIcon />
              </Avatar>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Memory Management
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              C++ gives you direct control over memory allocation and deallocation. This power enables 
              high performance but also requires careful management to avoid leaks, corruption, and 
              undefined behavior. Understanding the memory model is essential for writing robust C++ code.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              Stack vs Heap
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { 
                  type: "Stack Memory", 
                  traits: ["Automatic allocation/deallocation", "Fast (just pointer adjustment)", "Limited size (~1-8MB)", "LIFO order", "Local variables, function params"],
                  color: "#4caf50"
                },
                { 
                  type: "Heap Memory", 
                  traits: ["Manual allocation (new/malloc)", "Slower (memory manager involved)", "Large (limited by system RAM)", "Any order allocation", "Dynamic data, objects with runtime size"],
                  color: "#f44336"
                },
              ].map((item) => (
                <Grid item xs={12} md={6} key={item.type}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(item.color, 0.05), border: `1px solid ${alpha(item.color, 0.2)}`, height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, mb: 1 }}>{item.type}</Typography>
                    {item.traits.map((trait, i) => (
                      <Typography key={i} variant="body2" color="text.secondary">• {trait}</Typography>
                    ))}
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`void memoryDemo() {
    // Stack allocation - automatic lifetime
    int x = 42;                    // On stack
    int arr[100];                  // Array on stack
    std::string s = "hello";       // std::string object on stack
                                   // (but its data buffer is on heap!)
    
    // Heap allocation - manual lifetime
    int* p = new int(42);          // Single int on heap
    int* arr2 = new int[100];      // Array on heap
    MyClass* obj = new MyClass();  // Object on heap
    
    // MUST delete to avoid memory leak!
    delete p;
    delete[] arr2;                 // Use delete[] for arrays!
    delete obj;
    
}  // Stack variables automatically destroyed here`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              Common Memory Errors
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// 1. MEMORY LEAK - forgetting to delete
void leak() {
    int* p = new int[1000];
    // No delete[] - memory lost forever!
}

// 2. DANGLING POINTER - using after delete
int* p = new int(42);
delete p;
*p = 10;  // UNDEFINED BEHAVIOR! p points to freed memory

// 3. DOUBLE FREE - deleting twice
int* p = new int(42);
delete p;
delete p;  // CRASH or corruption!

// 4. BUFFER OVERFLOW - writing past bounds
int* arr = new int[10];
arr[10] = 42;  // Out of bounds! (valid: 0-9)

// 5. USE AFTER FREE in containers
std::vector<int> v = {1, 2, 3};
int& ref = v[0];
v.push_back(4);  // May reallocate!
ref = 10;        // DANGER: ref may be dangling

// 6. MISMATCHED new/delete
int* arr = new int[10];
delete arr;      // WRONG! Use delete[]
int* single = new int(42);
delete[] single; // WRONG! Use delete`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              RAII: Resource Acquisition Is Initialization
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// RAII wrapper for file handles
class FileHandle {
private:
    FILE* fp;
    
public:
    FileHandle(const char* path, const char* mode) {
        fp = fopen(path, mode);
        if (!fp) throw std::runtime_error("Can't open file");
    }
    
    ~FileHandle() {
        if (fp) fclose(fp);  // Guaranteed cleanup!
    }
    
    // Prevent copying (Rule of Five)
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;
    
    // Allow moving
    FileHandle(FileHandle&& other) noexcept : fp(other.fp) {
        other.fp = nullptr;
    }
    
    FILE* get() { return fp; }
};

void processFile() {
    FileHandle file("data.txt", "r");
    // Use file.get()...
    
    if (someCondition) return;      // File closed!
    if (error) throw SomeError();   // File closed!
    
}  // File closed automatically!

// Standard RAII types: unique_ptr, shared_ptr, lock_guard, 
// fstream, vector, string - USE THEM!`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              Memory Debugging Tools
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { tool: "Valgrind", desc: "Linux memory debugger. Detects leaks, invalid access, uninitialized reads.", cmd: "valgrind --leak-check=full ./program" },
                { tool: "AddressSanitizer", desc: "Compiler instrumentation. Fast, catches buffer overflows, use-after-free.", cmd: "g++ -fsanitize=address -g program.cpp" },
                { tool: "Visual Studio", desc: "Windows debugging. Memory profiler, leak detection, heap analysis.", cmd: "Debug → Windows → Memory" },
                { tool: "Dr. Memory", desc: "Cross-platform. Similar to Valgrind but works on Windows too.", cmd: "drmemory -- ./program.exe" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.tool}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f44336", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f44336" }}>{item.tool}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.desc}</Typography>
                    <Chip label={item.cmd} size="small" sx={{ fontFamily: "monospace", fontSize: 10, bgcolor: alpha("#f44336", 0.1) }} />
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#f44336", 0.1), border: `1px solid ${alpha("#f44336", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <MemoryIcon sx={{ color: "#f44336" }} />
                Modern C++ Memory Guidelines
              </Typography>
              <Typography variant="body2" color="text.secondary">
                In modern C++, you rarely need raw <code>new/delete</code>. Use <code>std::vector</code> for 
                dynamic arrays, <code>std::unique_ptr</code> for exclusive ownership, <code>std::shared_ptr</code> for 
                shared ownership. Follow the Rule of Zero: if your class doesn't manage resources directly, 
                don't write any special member functions.
              </Typography>
            </Paper>
          </Paper>

          {/* Smart Pointers Section */}
          <Paper id="smart-pointers" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#ff5722", 0.15), color: "#ff5722", width: 48, height: 48 }}>
                <SecurityIcon />
              </Avatar>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Smart Pointers
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Smart pointers are RAII wrappers around raw pointers that automatically manage memory 
              lifetime. Introduced in C++11, they eliminate most memory leaks and dangling pointer bugs. 
              Modern C++ code should use smart pointers instead of raw <code>new/delete</code>.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff5722" }}>
              unique_ptr: Exclusive Ownership
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`#include <memory>

// Creating unique_ptr
std::unique_ptr<int> p1(new int(42));           // Direct (avoid)
std::unique_ptr<int> p2 = std::make_unique<int>(42);  // Preferred!

// unique_ptr cannot be copied (exclusive ownership)
// std::unique_ptr<int> p3 = p2;  // ERROR!

// But can be moved
std::unique_ptr<int> p3 = std::move(p2);  // p2 is now nullptr

// Accessing the value
std::cout << *p3 << std::endl;            // Dereference
std::cout << p3.get() << std::endl;       // Get raw pointer

// For arrays
std::unique_ptr<int[]> arr = std::make_unique<int[]>(10);
arr[0] = 42;

// Custom deleter
auto fileDeleter = [](FILE* f) { if (f) fclose(f); };
std::unique_ptr<FILE, decltype(fileDeleter)> file(
    fopen("data.txt", "r"), fileDeleter
);

// Releasing ownership
int* raw = p3.release();  // p3 is now nullptr, caller owns raw
delete raw;               // Must delete manually now!

// Reset to new value
p1.reset(new int(100));   // Deletes old, takes new
p1.reset();               // Deletes and sets to nullptr`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff5722" }}>
              shared_ptr: Shared Ownership
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Multiple owners - reference counted
std::shared_ptr<int> sp1 = std::make_shared<int>(42);
std::cout << sp1.use_count();  // 1

std::shared_ptr<int> sp2 = sp1;  // Copy OK!
std::cout << sp1.use_count();    // 2

{
    std::shared_ptr<int> sp3 = sp1;
    std::cout << sp1.use_count();  // 3
}  // sp3 destroyed, count = 2

sp2.reset();
std::cout << sp1.use_count();  // 1

// Object deleted when last shared_ptr dies

// make_shared is more efficient (single allocation)
auto sp = std::make_shared<MyClass>(arg1, arg2);

// Creating from unique_ptr (transfers ownership)
std::unique_ptr<int> up = std::make_unique<int>(100);
std::shared_ptr<int> sp4 = std::move(up);  // up is now nullptr

// Aliasing constructor - share ownership but point to different address
struct Node { int value; Node* next; };
auto node = std::make_shared<Node>();
std::shared_ptr<int> valuePtr(node, &node->value);  // Shares node's lifetime`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff5722" }}>
              weak_ptr: Breaking Cycles
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Problem: circular reference causes memory leak!
struct BadNode {
    std::shared_ptr<BadNode> next;  // Cycle = leak!
};

// Solution: use weak_ptr
struct GoodNode {
    std::shared_ptr<GoodNode> next;
    std::weak_ptr<GoodNode> prev;   // Doesn't increase ref count
};

// weak_ptr usage
std::shared_ptr<int> sp = std::make_shared<int>(42);
std::weak_ptr<int> wp = sp;  // Observe without owning

std::cout << wp.use_count();   // 1 (only sp owns it)
std::cout << wp.expired();     // false

// Must lock() to use - returns shared_ptr or nullptr
if (auto locked = wp.lock()) {
    std::cout << *locked;      // Safe access
} else {
    std::cout << "Object was deleted";
}

sp.reset();                    // Object deleted
std::cout << wp.expired();     // true
auto locked = wp.lock();       // Returns empty shared_ptr

// Common pattern: observer/cache
class Cache {
    std::unordered_map<int, std::weak_ptr<Resource>> cache;
public:
    std::shared_ptr<Resource> get(int id) {
        auto it = cache.find(id);
        if (it != cache.end()) {
            if (auto sp = it->second.lock()) {
                return sp;  // Still alive, reuse
            }
        }
        auto resource = std::make_shared<Resource>(id);
        cache[id] = resource;
        return resource;
    }
};`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff5722" }}>
              When to Use Each
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { ptr: "unique_ptr", when: "Default choice. Single owner. Function return values. Class members with clear ownership.", perf: "Zero overhead vs raw pointer" },
                { ptr: "shared_ptr", when: "Multiple owners needed. Shared caches. Observer patterns (with weak_ptr).", perf: "Ref counting overhead, control block allocation" },
                { ptr: "weak_ptr", when: "Breaking cycles. Caches. Observers that don't extend lifetime.", perf: "Must lock() to access" },
                { ptr: "Raw pointer", when: "Non-owning references. Optional parameters. Interfacing with C APIs.", perf: "Only when lifetime is guaranteed elsewhere" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.ptr}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ff5722", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ff5722" }}>{item.ptr}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.when}</Typography>
                    <Chip label={item.perf} size="small" sx={{ bgcolor: alpha("#ff5722", 0.1), fontSize: 11 }} />
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#ff5722", 0.1), border: `1px solid ${alpha("#ff5722", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <SecurityIcon sx={{ color: "#ff5722" }} />
                Smart Pointer Best Practices
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Always use <code>make_unique</code> and <code>make_shared</code> instead of <code>new</code>. 
                Pass smart pointers by reference when the function doesn't affect ownership. Pass by value 
                to transfer or share ownership. Never call <code>.get()</code> and store the result—the 
                smart pointer might die while you're using the raw pointer.
              </Typography>
            </Paper>
          </Paper>

          {/* Exception Handling Section */}
          <Paper id="exceptions" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#f44336", 0.15), color: "#f44336", width: 48, height: 48 }}>
                <BugReportIcon />
              </Avatar>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Exception Handling
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Exceptions provide a structured way to handle errors in C++. When an error occurs, you 
              throw an exception that propagates up the call stack until it's caught. Combined with RAII, 
              exceptions enable writing robust code that properly cleans up resources even when errors occur.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              Basic Exception Handling
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`#include <stdexcept>
#include <iostream>

double divide(double a, double b) {
    if (b == 0) {
        throw std::invalid_argument("Division by zero!");
    }
    return a / b;
}

int main() {
    try {
        double result = divide(10, 0);
        std::cout << "Result: " << result << std::endl;
    }
    catch (const std::invalid_argument& e) {
        std::cerr << "Invalid argument: " << e.what() << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Unknown exception!" << std::endl;
    }
    
    std::cout << "Program continues..." << std::endl;
    return 0;
}

// Re-throwing exceptions
try {
    riskyOperation();
}
catch (const std::exception& e) {
    logError(e);
    throw;  // Re-throw the same exception
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              Standard Exception Hierarchy
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`std::exception                 // Base class
├── std::logic_error           // Programmer errors (preventable)
│   ├── std::invalid_argument  // Bad function argument
│   ├── std::domain_error      // Math domain error
│   ├── std::length_error      // Size exceeds max
│   └── std::out_of_range      // Index out of bounds
│
├── std::runtime_error         // Errors detectable only at runtime
│   ├── std::range_error       // Result out of range
│   ├── std::overflow_error    // Arithmetic overflow
│   └── std::underflow_error   // Arithmetic underflow
│
└── std::bad_alloc             // new failed (out of memory)
    std::bad_cast              // dynamic_cast failed
    std::bad_typeid            // typeid on null pointer

// Usage examples
v.at(100);                     // throws std::out_of_range
new int[999999999999];         // throws std::bad_alloc
stoi("not a number");          // throws std::invalid_argument`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              Custom Exception Classes
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`class NetworkError : public std::runtime_error {
private:
    int errorCode;
    std::string host;
    
public:
    NetworkError(const std::string& msg, int code, const std::string& h)
        : std::runtime_error(msg), errorCode(code), host(h) {}
    
    int getErrorCode() const { return errorCode; }
    const std::string& getHost() const { return host; }
    
    // Override what() for custom message
    const char* what() const noexcept override {
        static std::string fullMsg;
        fullMsg = std::string(std::runtime_error::what()) + 
                  " [host=" + host + ", code=" + std::to_string(errorCode) + "]";
        return fullMsg.c_str();
    }
};

// Specific network errors
class ConnectionTimeout : public NetworkError {
public:
    ConnectionTimeout(const std::string& host, int timeout)
        : NetworkError("Connection timed out after " + std::to_string(timeout) + "ms",
                       ETIMEDOUT, host) {}
};

// Usage
try {
    connectTo("api.example.com");
}
catch (const ConnectionTimeout& e) {
    std::cerr << "Timeout connecting to " << e.getHost() << std::endl;
}
catch (const NetworkError& e) {
    std::cerr << "Network error: " << e.what() << std::endl;
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              noexcept Specifier
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// noexcept - promises function won't throw
void safeFunction() noexcept {
    // If this throws, std::terminate() is called!
}

// Conditional noexcept
template<typename T>
void process(T& obj) noexcept(noexcept(obj.doWork())) {
    obj.doWork();  // noexcept if T::doWork() is noexcept
}

// Move operations should be noexcept for performance
class Buffer {
    int* data;
    size_t size;
public:
    // noexcept move enables optimizations in STL containers
    Buffer(Buffer&& other) noexcept 
        : data(other.data), size(other.size) {
        other.data = nullptr;
        other.size = 0;
    }
    
    Buffer& operator=(Buffer&& other) noexcept {
        if (this != &other) {
            delete[] data;
            data = other.data;
            size = other.size;
            other.data = nullptr;
            other.size = 0;
        }
        return *this;
    }
};

// Check at compile time
static_assert(std::is_nothrow_move_constructible_v<Buffer>);

// Query noexcept
bool canThrow = noexcept(someFunction());  // false if it might throw`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f44336" }}>
              Exception Safety Guarantees
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { level: "No-throw", desc: "Operation will never throw. Required for destructors, move operations, swap.", example: "destructors, std::swap" },
                { level: "Strong", desc: "If exception thrown, state is unchanged (commit-or-rollback). Like a transaction.", example: "std::vector::push_back" },
                { level: "Basic", desc: "If exception thrown, no leaks and invariants preserved, but state may change.", example: "Most STL operations" },
                { level: "No guarantee", desc: "If exception thrown, anything can happen. Avoid writing such code!", example: "Legacy C code wrappers" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.level}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f44336", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f44336" }}>{item.level}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.desc}</Typography>
                    <Chip label={item.example} size="small" sx={{ bgcolor: alpha("#f44336", 0.1), fontSize: 11 }} />
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#f44336", 0.1), border: `1px solid ${alpha("#f44336", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <BugReportIcon sx={{ color: "#f44336" }} />
                Exception Best Practices
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Catch by const reference (<code>const std::exception&</code>) to avoid slicing. Use RAII so 
                resources are cleaned up during stack unwinding. Make destructors <code>noexcept</code> (they 
                are by default). Don't use exceptions for control flow—they're for exceptional situations. 
                Consider <code>std::optional</code> or error codes for expected failures.
              </Typography>
            </Paper>
          </Paper>

          {/* Lambda Expressions Section */}
          <Paper id="lambdas" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#9c27b0", 0.15), color: "#9c27b0", width: 48, height: 48 }}>
                <CodeIcon />
              </Avatar>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Lambda Expressions
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Lambdas are anonymous functions you can define inline. Introduced in C++11 and improved in 
              each subsequent standard, they're perfect for short callbacks, STL algorithm predicates, 
              and anywhere you need a quick function without the ceremony of a named function.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9c27b0" }}>
              Lambda Syntax
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Basic syntax: [captures](params) -> return_type { body }

// Simplest lambda
auto greet = []() { std::cout << "Hello!" << std::endl; };
greet();  // "Hello!"

// With parameters
auto add = [](int a, int b) { return a + b; };
std::cout << add(3, 4);  // 7

// Explicit return type (usually deduced)
auto divide = [](double a, double b) -> double {
    if (b == 0) return 0;
    return a / b;
};

// Immediately invoked lambda
int result = [](int x) { return x * x; }(5);  // 25

// Lambda as parameter
void forEach(const std::vector<int>& v, std::function<void(int)> fn) {
    for (int x : v) fn(x);
}
forEach({1, 2, 3}, [](int x) { std::cout << x << " "; });`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9c27b0" }}>
              Capture Clauses
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`int x = 10;
int y = 20;
std::string name = "Lambda";

// Capture by value (copy)
auto f1 = [x]() { return x * 2; };      // Only x
auto f2 = [=]() { return x + y; };      // All by value

// Capture by reference
auto f3 = [&x]() { x++; };              // Only x, can modify
auto f4 = [&]() { x++; y++; };          // All by reference

// Mixed captures
auto f5 = [=, &x]() { x = y; };         // y by value, x by reference
auto f6 = [&, x]() { return x + y; };   // x by value, y by reference

// Capture with initialization (C++14)
auto f7 = [z = x + y]() { return z; };  // z = 30
auto f8 = [ptr = std::make_unique<int>(42)]() { return *ptr; };

// Capture *this (C++17)
struct Counter {
    int value = 0;
    auto getIncrementer() {
        return [*this]() mutable { return ++value; };  // Copy of *this
    }
};

// mutable lambda - can modify captured-by-value variables
auto counter = [count = 0]() mutable { return ++count; };
std::cout << counter();  // 1
std::cout << counter();  // 2
std::cout << counter();  // 3`}
              </Typography>
            </Paper>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { capture: "[]", desc: "Capture nothing" },
                { capture: "[x]", desc: "Capture x by value" },
                { capture: "[&x]", desc: "Capture x by reference" },
                { capture: "[=]", desc: "Capture all used variables by value" },
                { capture: "[&]", desc: "Capture all used variables by reference" },
                { capture: "[=, &x]", desc: "All by value, except x by reference" },
                { capture: "[&, x]", desc: "All by reference, except x by value" },
                { capture: "[this]", desc: "Capture this pointer (access members)" },
              ].map((item) => (
                <Grid item xs={6} sm={3} key={item.capture}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha("#9c27b0", 0.05), height: "100%", textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#9c27b0", fontFamily: "monospace" }}>{item.capture}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9c27b0" }}>
              Generic Lambdas (C++14+)
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// C++14: auto parameters = generic lambda
auto print = [](auto x) { std::cout << x << std::endl; };
print(42);       // Works with int
print(3.14);     // Works with double
print("hello");  // Works with const char*

// Multiple auto parameters
auto add = [](auto a, auto b) { return a + b; };
std::cout << add(1, 2);        // 3 (int)
std::cout << add(1.5, 2.5);    // 4.0 (double)
std::cout << add(std::string("a"), std::string("b"));  // "ab"

// C++20: template lambdas with explicit type parameters
auto printVector = []<typename T>(const std::vector<T>& v) {
    for (const auto& item : v) {
        std::cout << item << " ";
    }
};

// C++20: constrained template lambda
auto numeric = []<typename T>(T a, T b) requires std::integral<T> {
    return a + b;
};

// Perfect forwarding in generic lambda (C++14)
auto wrapper = [](auto&& func, auto&&... args) {
    return std::forward<decltype(func)>(func)(
        std::forward<decltype(args)>(args)...
    );
};`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#9c27b0" }}>
              Lambdas with STL Algorithms
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`std::vector<int> nums = {5, 2, 8, 1, 9, 3, 7, 4, 6};

// Sorting with custom comparator
std::sort(nums.begin(), nums.end(), [](int a, int b) {
    return a > b;  // Descending order
});

// Finding with predicate
auto it = std::find_if(nums.begin(), nums.end(), [](int x) {
    return x > 5;  // First element > 5
});

// Counting matches
int count = std::count_if(nums.begin(), nums.end(), [](int x) {
    return x % 2 == 0;  // Count even numbers
});

// Transforming
std::vector<int> squared(nums.size());
std::transform(nums.begin(), nums.end(), squared.begin(), [](int x) {
    return x * x;
});

// Filtering (remove-erase idiom)
int threshold = 5;
nums.erase(
    std::remove_if(nums.begin(), nums.end(), [threshold](int x) {
        return x < threshold;  // Remove elements < threshold
    }),
    nums.end()
);

// For each with side effects
int sum = 0;
std::for_each(nums.begin(), nums.end(), [&sum](int x) {
    sum += x;
});`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#9c27b0", 0.1), border: `1px solid ${alpha("#9c27b0", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <CodeIcon sx={{ color: "#9c27b0" }} />
                Lambda Best Practices
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Keep lambdas short—if it's more than a few lines, consider a named function. Prefer capture 
                by reference for large objects, by value for small ones. Be careful with <code>[&]</code> if 
                the lambda outlives the scope (use <code>[=]</code> or explicit captures). Use 
                <code>std::function</code> when you need to store lambdas with the same signature.
              </Typography>
            </Paper>
          </Paper>

          {/* Modern C++ Features Section */}
          <Paper id="modern-cpp" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#3f51b5", 0.15), color: "#3f51b5", width: 48, height: 48 }}>
                <SpeedIcon />
              </Avatar>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Modern C++ Features (C++11/14/17/20/23)
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              Modern C++ (C++11 and beyond) revolutionized the language with features that make code 
              safer, more expressive, and often faster. These additions transformed C++ from a 
              "C with classes" reputation into a powerful modern language.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3f51b5" }}>
              C++11: The Revolution
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// auto - type deduction
auto x = 42;                              // int
auto pi = 3.14;                           // double
auto name = std::string("C++");           // std::string
auto it = myVector.begin();               // iterator type deduced

// Range-based for loops
std::vector<int> nums = {1, 2, 3, 4, 5};
for (int n : nums) { std::cout << n; }           // By value
for (int& n : nums) { n *= 2; }                  // By reference (modify)
for (const auto& n : nums) { std::cout << n; }  // Best for read-only

// nullptr - type-safe null pointer
int* p = nullptr;              // Not 0 or NULL
if (p == nullptr) { /* ... */ }

// Uniform initialization
int a{42};                     // Direct initialization
std::vector<int> v{1, 2, 3};   // Initializer list
MyClass obj{arg1, arg2};       // Works for any type

// enum class - scoped enumerations
enum class Color { Red, Green, Blue };
Color c = Color::Red;          // Must use scope
// int x = Color::Red;         // ERROR - no implicit conversion

// static_assert - compile-time assertions
static_assert(sizeof(int) == 4, "int must be 4 bytes");
static_assert(std::is_same_v<int, int32_t>);`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3f51b5" }}>
              Move Semantics & Rvalue References
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Lvalue vs Rvalue
int x = 10;        // x is lvalue (has address)
// 10 is rvalue (temporary, no address)

// Rvalue reference (&&)
void process(std::string&& s) {  // Takes ownership of temporary
    data = std::move(s);          // s is now empty
}

process(std::string("temp"));     // OK - temporary
std::string str = "hello";
// process(str);                  // ERROR - str is lvalue
process(std::move(str));          // OK - cast to rvalue, str now empty

// Move constructor & move assignment
class Buffer {
    int* data;
    size_t size;
public:
    // Move constructor - steal resources
    Buffer(Buffer&& other) noexcept 
        : data(other.data), size(other.size) {
        other.data = nullptr;
        other.size = 0;
    }
    
    // Move assignment
    Buffer& operator=(Buffer&& other) noexcept {
        if (this != &other) {
            delete[] data;
            data = other.data;
            size = other.size;
            other.data = nullptr;
            other.size = 0;
        }
        return *this;
    }
};

// std::move doesn't move - it casts to rvalue reference
std::vector<std::string> v1 = {"a", "b", "c"};
std::vector<std::string> v2 = std::move(v1);  // v1 is now empty`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3f51b5" }}>
              C++14/17 Features
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// C++14: Generic lambdas
auto add = [](auto a, auto b) { return a + b; };

// C++14: Return type deduction
auto factorial(int n) {  // Return type deduced as int
    return n <= 1 ? 1 : n * factorial(n - 1);
}

// C++14: Binary literals & digit separators
int binary = 0b1010'1010;      // 170
long big = 1'000'000'000;      // More readable

// C++17: Structured bindings
std::map<std::string, int> ages = {{"Alice", 30}, {"Bob", 25}};
for (const auto& [name, age] : ages) {
    std::cout << name << ": " << age << std::endl;
}

auto [x, y, z] = std::tuple{1, 2.0, "three"};

// C++17: if/switch with initializer
if (auto it = map.find(key); it != map.end()) {
    // use it
}

// C++17: std::optional - nullable value
std::optional<int> divide(int a, int b) {
    if (b == 0) return std::nullopt;
    return a / b;
}

auto result = divide(10, 2);
if (result) {
    std::cout << *result;  // 5
}

// C++17: std::variant - type-safe union
std::variant<int, double, std::string> v;
v = 42;
v = "hello";
std::cout << std::get<std::string>(v);  // "hello"

// C++17: if constexpr - compile-time conditional
template<typename T>
auto getValue(T t) {
    if constexpr (std::is_pointer_v<T>) {
        return *t;  // Dereference if pointer
    } else {
        return t;
    }
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3f51b5" }}>
              C++20: The Big Four
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { feature: "Concepts", desc: "Constrain templates with named requirements. Better error messages, clearer intent.", example: "template<std::integral T>" },
                { feature: "Ranges", desc: "Composable algorithms with lazy evaluation. Pipelines with | operator.", example: "nums | filter(even) | transform(square)" },
                { feature: "Coroutines", desc: "Suspend/resume functions. Enables async/await patterns, generators.", example: "co_await, co_yield, co_return" },
                { feature: "Modules", desc: "Replace headers with import/export. Faster compilation, better encapsulation.", example: "import std; export module MyLib;" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.feature}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#3f51b5", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3f51b5" }}>{item.feature}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.desc}</Typography>
                    <Chip label={item.example} size="small" sx={{ fontFamily: "monospace", fontSize: 10, bgcolor: alpha("#3f51b5", 0.1) }} />
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// C++20: Concepts
template<typename T>
concept Numeric = std::is_arithmetic_v<T>;

template<Numeric T>
T square(T x) { return x * x; }

// C++20: Ranges
#include <ranges>
std::vector<int> nums = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

auto result = nums 
    | std::views::filter([](int n) { return n % 2 == 0; })
    | std::views::transform([](int n) { return n * n; })
    | std::views::take(3);
// result: 4, 16, 36 (lazy evaluation)

// C++20: Three-way comparison (spaceship operator)
struct Point {
    int x, y;
    auto operator<=>(const Point&) const = default;  // All comparisons!
};
Point p1{1, 2}, p2{1, 3};
bool less = p1 < p2;      // Works!
bool equal = p1 == p2;    // Works!

// C++20: constexpr improvements
constexpr std::vector<int> getNumbers() {
    std::vector<int> v = {1, 2, 3};  // constexpr vector!
    v.push_back(4);
    return v;
}

// C++20: Designated initializers
struct Config {
    int width;
    int height;
    bool fullscreen;
};
Config cfg{.width = 1920, .height = 1080, .fullscreen = true};`}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#3f51b5", 0.1), border: `1px solid ${alpha("#3f51b5", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <SpeedIcon sx={{ color: "#3f51b5" }} />
                C++23 Highlights
              </Typography>
              <Typography variant="body2" color="text.secondary">
                C++23 brings <code>std::expected</code> (error handling without exceptions), <code>std::print</code> 
                (type-safe formatting), <code>std::mdspan</code> (multidimensional views), <code>if consteval</code>, 
                deducing <code>this</code>, and many range improvements. The language continues to evolve!
              </Typography>
            </Paper>
          </Paper>

          {/* Advanced Topics Section */}
          <Paper id="advanced" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#795548", 0.15), color: "#795548", width: 48, height: 48 }}>
                <TerminalIcon />
              </Avatar>
              <Typography variant="h4" sx={{ fontWeight: 800 }}>
                Advanced Topics
              </Typography>
            </Box>

            <Typography variant="body1" paragraph sx={{ lineHeight: 1.8 }}>
              These advanced C++ techniques are used in high-performance libraries, game engines, and 
              systems programming. Understanding them unlocks the full power of the language and helps 
              you read sophisticated C++ codebases.
            </Typography>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#795548" }}>
              Perfect Forwarding
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Problem: How to pass arguments exactly as received?
// - Lvalue should remain lvalue
// - Rvalue should remain rvalue

// Solution: Universal reference + std::forward
template<typename T>
void wrapper(T&& arg) {  // T&& is universal reference in template
    // std::forward preserves the value category
    actualFunction(std::forward<T>(arg));
}

// make_unique implementation uses perfect forwarding
template<typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args) {
    return std::unique_ptr<T>(
        new T(std::forward<Args>(args)...)
    );
}

// Reference collapsing rules:
// T& &   -> T&
// T& &&  -> T&
// T&& &  -> T&
// T&& && -> T&&

// When T = int&:  T&& becomes int& && -> int&
// When T = int:   T&& becomes int&&`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#795548" }}>
              Type Traits & SFINAE
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`#include <type_traits>

// Type traits - compile-time type queries
static_assert(std::is_integral_v<int>);           // true
static_assert(std::is_floating_point_v<double>);  // true
static_assert(std::is_pointer_v<int*>);           // true
static_assert(std::is_same_v<int, int32_t>);      // platform-dependent

// Type modifications
using T1 = std::remove_const_t<const int>;        // int
using T2 = std::add_pointer_t<int>;               // int*
using T3 = std::decay_t<const int&>;              // int

// SFINAE: Substitution Failure Is Not An Error
// Enable function only for integral types (pre-C++20)
template<typename T>
typename std::enable_if_t<std::is_integral_v<T>, T>
square(T x) {
    return x * x;
}

// C++17: constexpr if is cleaner
template<typename T>
auto process(T value) {
    if constexpr (std::is_pointer_v<T>) {
        return *value;
    } else if constexpr (std::is_integral_v<T>) {
        return value * 2;
    } else {
        return value;
    }
}

// C++20: Concepts replace SFINAE with clearer syntax
template<typename T>
    requires std::integral<T>
T square_modern(T x) {
    return x * x;
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#795548" }}>
              CRTP: Curiously Recurring Template Pattern
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// CRTP: Derived class passes itself as template argument to base
template<typename Derived>
class Counter {
    static int count;
public:
    Counter() { count++; }
    ~Counter() { count--; }
    static int getCount() { return count; }
};

template<typename Derived>
int Counter<Derived>::count = 0;

class Dog : public Counter<Dog> {};     // Dogs have their own counter
class Cat : public Counter<Cat> {};     // Cats have their own counter

Dog d1, d2, d3;
Cat c1, c2;
std::cout << Dog::getCount();  // 3
std::cout << Cat::getCount();  // 2

// Static polymorphism - no vtable overhead
template<typename Derived>
class Shape {
public:
    void draw() {
        static_cast<Derived*>(this)->drawImpl();  // Call derived implementation
    }
};

class Circle : public Shape<Circle> {
public:
    void drawImpl() { std::cout << "Circle" << std::endl; }
};

class Square : public Shape<Square> {
public:
    void drawImpl() { std::cout << "Square" << std::endl; }
};

// Use at compile time - no virtual call overhead
template<typename T>
void render(Shape<T>& shape) {
    shape.draw();  // Static dispatch, can be inlined
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#795548" }}>
              Compile-Time Computation
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// constexpr - evaluate at compile time if possible
constexpr int factorial(int n) {
    return n <= 1 ? 1 : n * factorial(n - 1);
}

constexpr int fact5 = factorial(5);  // Computed at compile time = 120

// C++17: constexpr if
template<int N>
constexpr int fib() {
    if constexpr (N <= 1) {
        return N;
    } else {
        return fib<N-1>() + fib<N-2>();
    }
}

// C++20: consteval - MUST be compile time
consteval int compiletime_only(int x) {
    return x * x;
}

constexpr int a = compiletime_only(5);  // OK
// int b = compiletime_only(runtime_value);  // ERROR!

// C++20: constinit - ensure static initialization at compile time
constinit int global = factorial(6);  // 720, guaranteed no dynamic init

// Compile-time string processing (C++20)
constexpr auto upper(std::string_view s) {
    std::string result;
    for (char c : s) {
        result += (c >= 'a' && c <= 'z') ? c - 32 : c;
    }
    return result;
}`}
              </Typography>
            </Paper>

            <Divider sx={{ my: 3 }} />

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#795548" }}>
              C Interoperability
            </Typography>

            <Paper sx={{ p: 2, borderRadius: 2, bgcolor: "#1e1e1e", mb: 2 }}>
              <Typography component="pre" sx={{ fontFamily: "monospace", fontSize: 14, color: "#d4d4d4", m: 0, overflow: "auto" }}>
{`// Calling C functions from C++
extern "C" {
    // These functions use C linkage (no name mangling)
    int c_function(int x);
    void process_data(void* data, size_t len);
}

// C header inclusion pattern
#ifdef __cplusplus
extern "C" {
#endif

int my_c_api(int x);  // Works in both C and C++

#ifdef __cplusplus
}
#endif

// Passing C++ objects to C
class MyClass {
public:
    int getValue() const;
};

// C-compatible wrapper
extern "C" {
    void* myclass_create() { return new MyClass(); }
    int myclass_getValue(void* obj) {
        return static_cast<MyClass*>(obj)->getValue();
    }
    void myclass_destroy(void* obj) {
        delete static_cast<MyClass*>(obj);
    }
}

// Using C libraries in C++
#include <cstring>   // C++ wrapper for string.h
#include <cstdlib>   // C++ wrapper for stdlib.h
#include <cstdio>    // C++ wrapper for stdio.h`}
              </Typography>
            </Paper>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { topic: "Custom Allocators", desc: "Control memory allocation strategy for containers. Pool allocators, arena allocators for performance." },
                { topic: "Expression Templates", desc: "Lazy evaluation of expressions. Used in Eigen, Blaze for matrix operations without temporaries." },
                { topic: "ABI Compatibility", desc: "Binary interface between libraries. Affects struct layout, vtable format, name mangling." },
                { topic: "Undefined Behavior", desc: "Code the compiler assumes never happens. Signed overflow, null deref, data races." },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.topic}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#795548", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#795548" }}>{item.topic}</Typography>
                    <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#795548", 0.1), border: `1px solid ${alpha("#795548", 0.3)}` }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                <TerminalIcon sx={{ color: "#795548" }} />
                Keep Learning
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Advanced C++ is a deep topic. Explore resources like "Effective Modern C++" by Scott Meyers, 
                "C++ Templates: The Complete Guide" by Vandevoorde/Josuttis/Gregor, and CppCon conference 
                talks. Practice by contributing to open-source C++ projects and reading library source code.
              </Typography>
            </Paper>
          </Paper>

          {/* Quiz Section */}
          <Paper id="quiz" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 1.5 }}>
              <QuizIcon sx={{ color: accentColor }} />
              Test Your Knowledge
            </Typography>
            <QuizSection />
          </Paper>

          {/* Continue Your Journey */}
          <Paper sx={{ p: 4, borderRadius: 4, border: `1px solid ${alpha(accentColor, 0.2)}` }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 2 }}>
              Continue Your Journey
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
              After mastering C++, explore related topics to expand your expertise:
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              {[
                { label: "C Programming", path: "/learn/c-programming" },
                { label: "Assembly Language", path: "/learn/assembly" },
                { label: "Reverse Engineering", path: "/learn/intro-to-re" },
                { label: "Buffer Overflows", path: "/learn/buffer-overflow" },
                { label: "Heap Exploitation", path: "/learn/heap-exploitation" },
                { label: "Windows Internals", path: "/learn/windows-internals" },
                { label: "Game Hacking", path: "/learn/game-hacking" },
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
