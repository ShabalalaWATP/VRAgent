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
import HttpIcon from "@mui/icons-material/Http";
import CloudIcon from "@mui/icons-material/Cloud";
import SyncIcon from "@mui/icons-material/Sync";
import DataObjectIcon from "@mui/icons-material/DataObject";
import LockIcon from "@mui/icons-material/Lock";
import SwapHorizIcon from "@mui/icons-material/SwapHoriz";
import CategoryIcon from "@mui/icons-material/Category";
import WarningIcon from "@mui/icons-material/Warning";
import ClassIcon from "@mui/icons-material/Class";
import IntegrationInstructionsIcon from "@mui/icons-material/IntegrationInstructions";
import FolderIcon from "@mui/icons-material/Folder";
import HubIcon from "@mui/icons-material/Hub";
import WebIcon from "@mui/icons-material/Web";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutline";
import CancelOutlinedIcon from "@mui/icons-material/CancelOutlined";
import LearnPageLayout from "../components/LearnPageLayout";

const accentColor = "#777BB4"; // PHP's official purple color
const accentColorDark = "#4F5B93"; // PHP's darker shade

// Module navigation items for sidebar
const moduleNavItems = [
  { id: "introduction", label: "Introduction", icon: <SchoolIcon /> },
  { id: "history", label: "History & Evolution", icon: <HistoryIcon /> },
  { id: "setup", label: "Environment Setup", icon: <BuildIcon /> },
  { id: "basics", label: "PHP Basics & Syntax", icon: <CodeIcon /> },
  { id: "variables", label: "Variables & Data Types", icon: <DataObjectIcon /> },
  { id: "operators", label: "Operators & Expressions", icon: <SwapHorizIcon /> },
  { id: "control-flow", label: "Control Flow", icon: <AccountTreeIcon /> },
  { id: "arrays", label: "Arrays & Strings", icon: <StorageIcon /> },
  { id: "functions", label: "Functions", icon: <ExtensionIcon /> },
  { id: "oop", label: "OOP in PHP", icon: <ClassIcon /> },
  { id: "inheritance", label: "Inheritance & Traits", icon: <LayersIcon /> },
  { id: "exceptions", label: "Exception Handling", icon: <BugReportIcon /> },
  { id: "forms", label: "Forms & Superglobals", icon: <WebIcon /> },
  { id: "database", label: "Database Access (PDO)", icon: <StorageIcon /> },
  { id: "security", label: "Security Best Practices", icon: <SecurityIcon /> },
  { id: "modern", label: "Modern PHP (8.x)", icon: <AutoFixHighIcon /> },
  { id: "frameworks", label: "Frameworks & Ecosystem", icon: <IntegrationInstructionsIcon /> },
  { id: "advanced", label: "Advanced Topics", icon: <DeveloperBoardIcon /> },
  { id: "quiz", label: "Knowledge Quiz", icon: <QuizIcon /> },
];

// Quick stats for hero section
const quickStats = [
  { label: "Created", value: "1995", color: "#777BB4" },
  { label: "Creator", value: "Rasmus Lerdorf", color: "#4F5B93" },
  { label: "Paradigm", value: "Multi", color: "#4A90D9" },
  { label: "Latest Ver", value: "8.3", color: "#48BB78" },
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

// 75-question bank for PHP
const phpQuestionBank: QuizQuestion[] = [
  // PHP Basics (1-15)
  { id: 1, question: "What does PHP originally stand for?", options: ["Personal Home Page", "PHP: Hypertext Preprocessor", "Private Host Protocol", "Public Hypertext Parser"], correctAnswer: 0, explanation: "PHP originally stood for 'Personal Home Page' when created by Rasmus Lerdorf in 1994. It was later renamed to the recursive acronym 'PHP: Hypertext Preprocessor'." },
  { id: 2, question: "Which symbol must precede all variable names in PHP?", options: ["@", "#", "$", "&"], correctAnswer: 2, explanation: "In PHP, all variable names must be prefixed with a dollar sign ($). For example: $name, $age, $total." },
  { id: 3, question: "What are the correct PHP opening and closing tags?", options: ["<php></php>", "<?php ?>", "<script php></script>", "{% %}"], correctAnswer: 1, explanation: "PHP code is enclosed within <?php ?> tags. The short echo tag <?= ?> can also be used for quick output." },
  { id: 4, question: "How do you output 'Hello World' in PHP?", options: ["print('Hello World');", "console.log('Hello World');", "System.out.println('Hello World');", "echo 'Hello World';"], correctAnswer: 3, explanation: "The echo statement is the most common way to output text in PHP. print() also works but echo is slightly faster and more commonly used." },
  { id: 5, question: "Which statement is used to end a PHP statement?", options: [":", ".", ";", ","], correctAnswer: 2, explanation: "Every PHP statement must end with a semicolon (;). This is mandatory unlike some other languages where it's optional." },
  { id: 6, question: "What is the correct way to create a single-line comment in PHP?", options: ["<!-- comment -->", "// comment", "** comment **", "/* comment */"], correctAnswer: 1, explanation: "Single-line comments in PHP use // (C++ style) or # (shell style). Multi-line comments use /* */." },
  { id: 7, question: "PHP is a _______ typed language.", options: ["Statically", "Strongly", "Dynamically", "Strictly"], correctAnswer: 2, explanation: "PHP is dynamically typed, meaning you don't need to declare variable types. The type is determined at runtime based on the value assigned." },
  { id: 8, question: "Which function is used to get the type of a variable?", options: ["type()", "gettype()", "typeof()", "vartype()"], correctAnswer: 1, explanation: "gettype() returns the type of a variable as a string. For type checking, is_string(), is_int(), is_array() etc. are also available." },
  { id: 9, question: "What is the difference between == and === in PHP?", options: ["No difference", "== compares values only, === compares values and types", "=== compares values only, == compares values and types", "== is for strings, === is for numbers"], correctAnswer: 1, explanation: "== performs loose comparison with type coercion, while === performs strict comparison checking both value AND type. Always prefer === to avoid unexpected type coercion bugs." },
  { id: 10, question: "How do you concatenate strings in PHP?", options: ["Using +", "Using .", "Using &", "Using concat()"], correctAnswer: 1, explanation: "The dot (.) operator is used for string concatenation in PHP. For example: $full = $first . ' ' . $last;" },
  { id: 11, question: "Which superglobal contains form data sent with POST method?", options: ["$_REQUEST", "$_FORM", "$_POST", "$_DATA"], correctAnswer: 2, explanation: "$_POST is a superglobal array containing data sent via HTTP POST method. $_GET contains URL parameters, and $_REQUEST contains both." },
  { id: 12, question: "What does the 'null coalescing' operator (??) do?", options: ["Checks if null then throws error", "Returns left operand if it exists and is not null, otherwise returns right", "Always returns null", "Converts value to null"], correctAnswer: 1, explanation: "The ?? operator returns the left operand if it exists and is not null, otherwise returns the right operand. Example: $name = $_GET['name'] ?? 'Guest';" },
  { id: 13, question: "Which PHP version introduced the JIT (Just-In-Time) compiler?", options: ["PHP 7.0", "PHP 7.4", "PHP 8.0", "PHP 8.1"], correctAnswer: 2, explanation: "PHP 8.0 introduced the JIT compiler which can provide performance improvements for CPU-intensive operations by compiling PHP code to machine code at runtime." },
  { id: 14, question: "What is the output of: echo 10 % 3;", options: ["3.33", "3", "1", "0"], correctAnswer: 2, explanation: "The % operator returns the remainder of division. 10 divided by 3 is 3 with a remainder of 1, so 10 % 3 = 1." },
  { id: 15, question: "How do you check if a variable is set and not null?", options: ["is_set()", "isset()", "is_null()", "exists()"], correctAnswer: 1, explanation: "isset() returns true if a variable is set and is not null. It's commonly used to check if array keys or form data exist before accessing them." },
  
  // Arrays & Strings (16-30)
  { id: 16, question: "What is the correct way to create an array in modern PHP?", options: ["array = (1, 2, 3)", "array(1, 2, 3) or [1, 2, 3]", "new Array(1, 2, 3)", "{1, 2, 3}"], correctAnswer: 1, explanation: "Both array(1, 2, 3) and [1, 2, 3] create arrays in PHP. The short syntax [] is preferred in modern PHP." },
  { id: 17, question: "How do you count the number of elements in an array?", options: ["length($arr)", "size($arr)", "count($arr)", "$arr.length"], correctAnswer: 2, explanation: "count() returns the number of elements in an array. sizeof() is an alias for count() but count() is more commonly used." },
  { id: 18, question: "Which function adds an element to the end of an array?", options: ["array_add()", "array_push()", "array_append()", "array_insert()"], correctAnswer: 1, explanation: "array_push() adds one or more elements to the end of an array. You can also use $arr[] = $value; as a shorthand for adding a single element." },
  { id: 19, question: "What does array_merge() do?", options: ["Sorts arrays", "Combines arrays into one", "Removes duplicates", "Finds common elements"], correctAnswer: 1, explanation: "array_merge() combines two or more arrays into a single array. For associative arrays, later values overwrite earlier ones for duplicate keys." },
  { id: 20, question: "How do you check if a value exists in an array?", options: ["array_exists()", "in_array()", "array_contains()", "has_value()"], correctAnswer: 1, explanation: "in_array() checks if a value exists in an array and returns true or false. For checking keys, use array_key_exists()." },
  { id: 21, question: "What is the output of: strlen('Hello');", options: ["4", "5", "6", "Error"], correctAnswer: 1, explanation: "strlen() returns the number of characters in a string. 'Hello' has 5 characters, so strlen('Hello') returns 5." },
  { id: 22, question: "Which function converts a string to lowercase?", options: ["lower()", "toLowerCase()", "strtolower()", "str_lower()"], correctAnswer: 2, explanation: "strtolower() converts all characters in a string to lowercase. strtoupper() does the opposite." },
  { id: 23, question: "How do you split a string into an array?", options: ["split()", "str_split() or explode()", "tokenize()", "divide()"], correctAnswer: 1, explanation: "explode() splits a string by a delimiter into an array. str_split() splits by character length. Example: explode(',', 'a,b,c') returns ['a', 'b', 'c']." },
  { id: 24, question: "What does trim() do?", options: ["Removes first character", "Removes last character", "Removes whitespace from beginning and end", "Removes all spaces"], correctAnswer: 2, explanation: "trim() removes whitespace (or specified characters) from the beginning and end of a string. ltrim() and rtrim() remove from left or right only." },
  { id: 25, question: "Which function finds the position of the first occurrence of a substring?", options: ["strfind()", "strpos()", "str_index()", "indexof()"], correctAnswer: 1, explanation: "strpos() returns the position of the first occurrence of a substring, or false if not found. Note: it returns 0 for position 0, so use === false for checking." },
  { id: 26, question: "What is the output of: implode('-', ['a', 'b', 'c']);", options: ["a-b-c", "abc", "[a-b-c]", "a,b,c"], correctAnswer: 0, explanation: "implode() joins array elements into a string using the specified separator. It's the opposite of explode()." },
  { id: 27, question: "Which function replaces all occurrences of a search string?", options: ["replace()", "str_replace()", "preg_replace()", "Both B and C"], correctAnswer: 3, explanation: "str_replace() does simple string replacement while preg_replace() uses regular expressions. Both can replace all occurrences." },
  { id: 28, question: "How do you get a portion of a string?", options: ["slice()", "substring()", "substr()", "extract()"], correctAnswer: 2, explanation: "substr() extracts a portion of a string. Example: substr('Hello', 0, 3) returns 'Hel'. Negative values count from the end." },
  { id: 29, question: "What does array_filter() return?", options: ["First matching element", "All elements that pass the callback test", "Count of matching elements", "Boolean"], correctAnswer: 1, explanation: "array_filter() filters elements using a callback function and returns an array containing only elements that pass the test (callback returns true)." },
  { id: 30, question: "Which function transforms each element of an array?", options: ["array_transform()", "array_map()", "array_foreach()", "array_apply()"], correctAnswer: 1, explanation: "array_map() applies a callback function to each element of an array and returns a new array with the transformed values." },
  
  // Functions (31-40)
  { id: 31, question: "What is the correct syntax for defining a function?", options: ["def functionName() {}", "function functionName() {}", "func functionName() {}", "fn functionName() {}"], correctAnswer: 1, explanation: "Functions in PHP are defined using the 'function' keyword followed by the function name and parentheses. fn is used for arrow functions." },
  { id: 32, question: "How do you specify a return type for a function in PHP 7+?", options: ["function foo() -> int", "function foo(): int", "function foo() returns int", "int function foo()"], correctAnswer: 1, explanation: "Return types are declared after the parameter list with a colon. Example: function add(int $a, int $b): int { return $a + $b; }" },
  { id: 33, question: "What is an anonymous function in PHP?", options: ["A function with no parameters", "A function with no return value", "A function with no name (closure)", "A private function"], correctAnswer: 2, explanation: "Anonymous functions (closures) are functions without names that can be assigned to variables and passed as arguments. Example: $fn = function($x) { return $x * 2; };" },
  { id: 34, question: "What keyword is used to capture variables from parent scope in a closure?", options: ["global", "use", "import", "capture"], correctAnswer: 1, explanation: "The 'use' keyword allows closures to capture variables from the parent scope. Example: $fn = function($x) use ($factor) { return $x * $factor; };" },
  { id: 35, question: "What is the syntax for an arrow function in PHP 7.4+?", options: ["() -> expression", "fn() => expression", "() => expression", "lambda() expression"], correctAnswer: 1, explanation: "Arrow functions use fn keyword: fn($x) => $x * 2. They automatically capture variables from parent scope and can only contain a single expression." },
  { id: 36, question: "How do you define a function that accepts any number of arguments?", options: ["function foo(array $args)", "function foo(...$args)", "function foo(* $args)", "function foo(params $args)"], correctAnswer: 1, explanation: "The splat operator (...) creates a variadic function that accepts any number of arguments as an array. Example: function sum(...$nums) { return array_sum($nums); }" },
  { id: 37, question: "What does a nullable type declaration look like?", options: ["function foo($x = null)", "function foo(?string $x)", "function foo(null|string $x)", "Both B and C"], correctAnswer: 3, explanation: "?string allows null or string. In PHP 8+, you can also use union types: string|null. Both syntaxes are valid for nullable parameters." },
  { id: 38, question: "What are named arguments in PHP 8?", options: ["Arguments with default values", "Arguments passed by name rather than position", "Arguments with type hints", "Required arguments"], correctAnswer: 1, explanation: "Named arguments allow passing parameters by name: foo(name: 'John', age: 25). This allows skipping optional parameters and improves readability." },
  { id: 39, question: "What is the purpose of declare(strict_types=1)?", options: ["Makes all variables constants", "Enables strict type checking for function arguments", "Requires all functions to have return types", "Disables type coercion in comparisons"], correctAnswer: 1, explanation: "declare(strict_types=1) at the top of a file enforces strict type checking. Type mismatches throw TypeError instead of being silently coerced." },
  { id: 40, question: "What does 'mixed' type mean in PHP 8?", options: ["Only numeric types", "Only scalar types", "Any type including null", "Mixed arrays only"], correctAnswer: 2, explanation: "The 'mixed' type in PHP 8 indicates the parameter or return value can be any type, including null. It's equivalent to no type declaration but explicit." },
  
  // OOP (41-55)
  { id: 41, question: "Which keyword is used to create a class in PHP?", options: ["object", "class", "type", "struct"], correctAnswer: 1, explanation: "Classes are defined using the 'class' keyword: class MyClass { }. PHP supports full object-oriented programming." },
  { id: 42, question: "How do you create an instance of a class?", options: ["MyClass()", "create MyClass()", "new MyClass()", "instance MyClass()"], correctAnswer: 2, explanation: "Objects are created using the 'new' keyword: $obj = new MyClass();. The constructor __construct() is called automatically." },
  { id: 43, question: "What is the constructor method called in PHP?", options: ["constructor()", "__construct()", "init()", "__init__()"], correctAnswer: 1, explanation: "__construct() is PHP's constructor method. It's called automatically when an object is created with 'new'." },
  { id: 44, question: "Which visibility modifier makes a property accessible only within the class?", options: ["public", "protected", "private", "internal"], correctAnswer: 2, explanation: "private makes members accessible only within the declaring class. protected allows access in child classes. public allows access from anywhere." },
  { id: 45, question: "How do you inherit from a parent class?", options: ["class Child implements Parent", "class Child : Parent", "class Child extends Parent", "class Child inherits Parent"], correctAnswer: 2, explanation: "The 'extends' keyword is used for inheritance: class Child extends Parent. PHP supports single inheritance only." },
  { id: 46, question: "What is the purpose of the 'static' keyword?", options: ["Makes variable constant", "Makes member belong to class rather than instances", "Makes method faster", "Makes property read-only"], correctAnswer: 1, explanation: "static members belong to the class itself, not instances. They're accessed with ClassName::$property or ClassName::method()." },
  { id: 47, question: "How do you reference the current object within a class?", options: ["this", "self", "$this", "$self"], correctAnswer: 2, explanation: "$this refers to the current object instance. self:: refers to the class itself (for static members). parent:: refers to the parent class." },
  { id: 48, question: "What is an interface in PHP?", options: ["A class with only private methods", "A contract that classes must implement", "A type of variable", "A built-in PHP class"], correctAnswer: 1, explanation: "Interfaces define a contract of methods that implementing classes must provide. Classes can implement multiple interfaces: class Foo implements Bar, Baz." },
  { id: 49, question: "What is a trait in PHP?", options: ["A type of interface", "A mechanism for code reuse in single inheritance", "A class modifier", "A type of variable"], correctAnswer: 1, explanation: "Traits allow horizontal code reuse. Multiple traits can be used in a class: use TraitA, TraitB;. They solve the single inheritance limitation." },
  { id: 50, question: "What is an abstract class?", options: ["A class that cannot have properties", "A class that cannot be instantiated directly", "A class with only static methods", "A class with no methods"], correctAnswer: 1, explanation: "Abstract classes cannot be instantiated directly and may contain abstract methods that child classes must implement." },
  { id: 51, question: "What is constructor property promotion in PHP 8?", options: ["Auto-generating getters/setters", "Declaring and assigning properties in constructor parameters", "Automatic type conversion", "Constructor overloading"], correctAnswer: 1, explanation: "PHP 8 allows declaring properties directly in constructor: public function __construct(public string $name). This reduces boilerplate code." },
  { id: 52, question: "What does the 'final' keyword do?", options: ["Makes variable constant", "Prevents class from being extended or method from being overridden", "Makes method abstract", "Requires method implementation"], correctAnswer: 1, explanation: "final on a class prevents inheritance. final on a method prevents overriding in child classes. It's used to lock down critical functionality." },
  { id: 53, question: "What is the readonly modifier in PHP 8.1?", options: ["Makes property constant after first assignment", "Makes property visible everywhere", "Makes property writable only once in constructor", "Both A and C"], correctAnswer: 3, explanation: "readonly properties can only be initialized once (typically in constructor) and cannot be modified afterwards. They must have a type declaration." },
  { id: 54, question: "How do you call a parent class method from a child class?", options: ["super.method()", "parent::method()", "base.method()", "this.parent.method()"], correctAnswer: 1, explanation: "parent::method() calls the parent class implementation. Commonly used in constructors: parent::__construct() or when extending method behavior." },
  { id: 55, question: "What are enums in PHP 8.1?", options: ["A type of array", "A type of constant", "A special class for defining a set of named values", "A type of trait"], correctAnswer: 2, explanation: "Enums define a type with a fixed set of possible values: enum Status { case Active; case Inactive; }. Backed enums can have string/int values." },
  
  // Database & PDO (56-65)
  { id: 56, question: "What does PDO stand for?", options: ["PHP Data Objects", "PHP Database Operations", "Personal Data Objects", "Portable Database Options"], correctAnswer: 0, explanation: "PDO (PHP Data Objects) is a database abstraction layer that provides a uniform interface for accessing different databases." },
  { id: 57, question: "Why should you use prepared statements?", options: ["They're faster", "They prevent SQL injection", "They use less memory", "They're required by PHP"], correctAnswer: 1, explanation: "Prepared statements separate SQL logic from data, preventing SQL injection attacks. The database treats parameters as data, not executable SQL." },
  { id: 58, question: "How do you execute a prepared statement with parameters?", options: ["$stmt->run($params)", "$stmt->execute($params)", "$stmt->query($params)", "$stmt->send($params)"], correctAnswer: 1, explanation: "execute() runs the prepared statement with the provided parameters: $stmt->execute(['value1', 'value2']) or $stmt->execute([':name' => 'John'])." },
  { id: 59, question: "Which method fetches all rows from a result set?", options: ["fetchAll()", "getAll()", "fetch(PDO::FETCH_ALL)", "rows()"], correctAnswer: 0, explanation: "fetchAll() returns all remaining rows as an array. fetch() returns one row at a time. Both accept fetch mode constants like PDO::FETCH_ASSOC." },
  { id: 60, question: "What does PDO::FETCH_ASSOC return?", options: ["Numeric array", "Associative array with column names as keys", "Object", "Both numeric and associative"], correctAnswer: 1, explanation: "FETCH_ASSOC returns an associative array keyed by column names. FETCH_NUM returns numeric keys. FETCH_BOTH returns both (default)." },
  { id: 61, question: "How do you get the ID of the last inserted row?", options: ["$pdo->lastId()", "$pdo->insertId()", "$pdo->lastInsertId()", "$stmt->lastId()"], correctAnswer: 2, explanation: "lastInsertId() returns the ID of the last inserted row for the connection. It should be called right after the INSERT statement." },
  { id: 62, question: "What is the purpose of beginTransaction()?", options: ["To start the database", "To begin a transaction that can be committed or rolled back", "To lock the database", "To start a query"], correctAnswer: 1, explanation: "beginTransaction() starts a transaction. Multiple operations can then be committed together with commit() or undone with rollBack()." },
  { id: 63, question: "Which placeholder syntax uses named parameters?", options: [":name", "?", "@name", "$name"], correctAnswer: 0, explanation: "Named placeholders use colon prefix: :name, :email. They're bound with associative arrays: [':name' => 'John']. ? uses positional binding." },
  { id: 64, question: "What happens if you call commit() without beginTransaction()?", options: ["Nothing", "Error is thrown", "Auto-commit is triggered", "Data is lost"], correctAnswer: 1, explanation: "Calling commit() without an active transaction typically throws an exception or returns false depending on error mode settings." },
  { id: 65, question: "What does PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION do?", options: ["Logs errors to file", "Throws exceptions on database errors", "Silently ignores errors", "Shows errors in browser"], correctAnswer: 1, explanation: "ERRMODE_EXCEPTION makes PDO throw PDOException on errors, allowing try-catch handling. This is the recommended error mode for development." },
  
  // Security & Modern PHP (66-75)
  { id: 66, question: "Which function should you use to hash passwords?", options: ["md5()", "sha1()", "password_hash()", "hash()"], correctAnswer: 2, explanation: "password_hash() is the recommended function for password hashing. It uses bcrypt by default and handles salting automatically. Never use md5() or sha1() for passwords." },
  { id: 67, question: "How do you verify a password against a hash?", options: ["$hash === password_hash($password)", "password_verify($password, $hash)", "hash_verify($password, $hash)", "compare_password($password, $hash)"], correctAnswer: 1, explanation: "password_verify() compares a plain password against a hash created by password_hash(). It handles the algorithm and salt automatically." },
  { id: 68, question: "What is XSS (Cross-Site Scripting)?", options: ["A PHP framework", "Injecting malicious scripts into web pages", "A type of SQL injection", "A PHP error type"], correctAnswer: 1, explanation: "XSS attacks inject malicious JavaScript into pages viewed by other users. Prevent it by escaping output with htmlspecialchars()." },
  { id: 69, question: "Which function prevents XSS when outputting user data?", options: ["strip_tags()", "htmlspecialchars()", "escape()", "sanitize()"], correctAnswer: 1, explanation: "htmlspecialchars() converts special characters to HTML entities, preventing script execution. Always use it when outputting user-supplied data." },
  { id: 70, question: "What is CSRF?", options: ["A PHP version", "Cross-Site Request Forgery", "A database type", "A PHP function"], correctAnswer: 1, explanation: "CSRF tricks users into performing unwanted actions on sites where they're authenticated. Prevent it with unique tokens in forms." },
  { id: 71, question: "What is the match expression in PHP 8?", options: ["A regex function", "An improved switch that returns values", "A string comparison", "A pattern matching function"], correctAnswer: 1, explanation: "match is like switch but returns a value, uses strict comparison, and doesn't fall through. Example: $result = match($x) { 1 => 'one', 2 => 'two' };" },
  { id: 72, question: "What is the nullsafe operator in PHP 8?", options: ["??", "?->", "?:", "?."], correctAnswer: 1, explanation: "The nullsafe operator ?-> short-circuits if null: $user?->address?->city returns null if any part is null, without throwing errors." },
  { id: 73, question: "What are attributes in PHP 8?", options: ["Variable properties", "Metadata annotations using #[...]", "Type declarations", "Access modifiers"], correctAnswer: 1, explanation: "Attributes like #[Route('/api')] add metadata to classes, methods, properties. They replace docblock annotations with native syntax." },
  { id: 74, question: "Which PHP 8.1 feature allows cooperative multitasking?", options: ["Threads", "Fibers", "Coroutines", "Async/Await"], correctAnswer: 1, explanation: "Fibers are lightweight, cooperative threads that allow pausing and resuming execution. They enable async programming patterns in PHP." },
  { id: 75, question: "What is Composer in PHP?", options: ["A code editor", "A dependency manager", "A web server", "A testing framework"], correctAnswer: 1, explanation: "Composer is PHP's dependency manager. It handles package installation, autoloading, and manages project dependencies via composer.json." },
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
function PHPQuiz() {
  const [quizStarted, setQuizStarted] = useState(false);
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<number[]>([]);
  const [showResults, setShowResults] = useState(false);
  const [quizQuestions, setQuizQuestions] = useState<QuizQuestion[]>([]);

  const startQuiz = () => {
    const shuffled = shuffleArray(phpQuestionBank);
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

  const getScoreColor = (score: number) => {
    if (score >= 8) return "#10b981";
    if (score >= 6) return "#f59e0b";
    return "#ef4444";
  };

  const getScoreMessage = (score: number) => {
    if (score === 10) return "Perfect! You're a PHP Master! 🏆";
    if (score >= 8) return "Excellent! You know PHP very well! 🌟";
    if (score >= 6) return "Good job! Keep learning! 📚";
    if (score >= 4) return "Not bad, but there's room to improve! 💪";
    return "Keep studying! PHP has a lot to offer! 🐘";
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
          PHP Knowledge Quiz
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 500, mx: "auto" }}>
          Test your PHP knowledge with 10 randomly selected questions from our 75-question bank covering 
          syntax, arrays, functions, OOP, databases, and security!
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
      <Paper
        id="quiz"
        sx={{
          p: 4,
          mb: 4,
          borderRadius: 4,
          border: `1px solid ${alpha(accentColor, 0.2)}`,
        }}
      >
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
    <Paper
      id="quiz"
      sx={{
        p: 4,
        mb: 4,
        borderRadius: 4,
        border: `1px solid ${alpha(accentColor, 0.2)}`,
      }}
    >
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Typography variant="h6" sx={{ fontWeight: 700 }}>
          PHP Quiz
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
                  selectedAnswers[currentQuestion] === idx
                    ? accentColor
                    : alpha(accentColor, 0.2)
                }`,
                bgcolor: selectedAnswers[currentQuestion] === idx
                  ? alpha(accentColor, 0.08)
                  : "transparent",
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
        <Button
          onClick={handlePrevious}
          disabled={currentQuestion === 0}
          sx={{ color: accentColor }}
        >
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

export default function PHPProgrammingPage() {
  const navigate = useNavigate();

  return (
    <LearnPageLayout pageTitle="PHP Programming" pageContext="Comprehensive PHP programming course covering web development, server-side scripting, database integration, and modern PHP features.">
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
                🐘
              </Avatar>
              <Box>
                <Typography variant="h4" sx={{ fontWeight: 900 }}>
                  PHP Programming
                </Typography>
                <Typography variant="body1" color="text.secondary">
                  The Language That Powers 78% of the Web
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
              {["Server-Side", "Web Development", "WordPress", "Laravel", "Symfony", "Database", "REST APIs", "CMS"].map((tag) => (
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
              What is PHP?
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              PHP (originally "Personal Home Page," now "PHP: Hypertext Preprocessor") is a widely-used,
              open-source, server-side scripting language designed specifically for web development. Created
              by <strong>Rasmus Lerdorf</strong> in 1995, PHP has evolved from a simple set of CGI binaries
              into one of the most powerful and versatile programming languages powering the modern web.
              Today, PHP runs on over <strong>78% of all websites</strong> with a known server-side programming
              language, including giants like Facebook (which created HHVM and Hack based on PHP), Wikipedia,
              WordPress, and countless other platforms.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              What makes PHP unique is its seamless integration with HTML. Unlike JavaScript which runs in
              the browser, PHP code is executed on the <strong>server</strong>, and the result is sent to the
              client as plain HTML. This server-side execution model means PHP can interact with databases,
              access file systems, manage sessions, send emails, and perform any server operation—all before
              the page reaches the user's browser. PHP code is embedded directly within HTML using special
              tags (<code>&lt;?php ... ?&gt;</code>), making it incredibly intuitive for web developers to
              mix presentation and logic.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              PHP is a <strong>dynamically-typed, interpreted language</strong> with a syntax inspired by C,
              Perl, and Java. It supports multiple programming paradigms including procedural, object-oriented,
              and functional programming. Modern PHP (versions 7.x and 8.x) has undergone a remarkable
              transformation, introducing features like type declarations, arrow functions, attributes, named
              arguments, union types, and the JIT (Just-In-Time) compiler—making it faster and more robust than
              ever before. The "PHP is dead" narrative couldn't be further from the truth; PHP continues to
              evolve rapidly with a vibrant community and ecosystem.
            </Typography>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Why Learn PHP in 2024?
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Despite the rise of JavaScript frameworks and other server-side languages, PHP remains an
              essential skill for web developers. Its dominance in the content management space (WordPress
              alone powers 43% of all websites), combined with powerful modern frameworks like Laravel and
              Symfony, ensures PHP's continued relevance. Here's why learning PHP is a smart investment:
            </Typography>

            <Grid container spacing={3} sx={{ mb: 4 }}>
              {[
                {
                  title: "WordPress & CMS Dominance",
                  description: "WordPress powers 43% of all websites globally. Learning PHP gives you the ability to customize themes, build plugins, and work with the largest CMS ecosystem. Drupal, Joomla, and Magento are also PHP-based, creating massive job opportunities.",
                  icon: <WebIcon />,
                },
                {
                  title: "Laravel Excellence",
                  description: "Laravel is consistently ranked as one of the most loved web frameworks. Its elegant syntax, powerful ORM (Eloquent), built-in authentication, queue management, and vast ecosystem make building modern web applications a joy. Laravel jobs are plentiful and well-paid.",
                  icon: <IntegrationInstructionsIcon />,
                },
                {
                  title: "Low Barrier to Entry",
                  description: "PHP is famously beginner-friendly. You can see results immediately—just save a .php file, refresh your browser, and see your changes. This instant feedback loop accelerates learning. Most shared hosting includes PHP support out of the box.",
                  icon: <SchoolIcon />,
                },
                {
                  title: "Mature & Stable Ecosystem",
                  description: "With 29+ years of development, PHP has solutions for virtually every web development challenge. Composer (package manager), PHPUnit (testing), Doctrine (ORM), and thousands of battle-tested libraries are at your disposal. The documentation is excellent.",
                  icon: <CategoryIcon />,
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
              How PHP Works: Server-Side Execution
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Understanding PHP's execution model is crucial to mastering the language. When a user requests
              a PHP page (e.g., <code>index.php</code>), the web server (Apache, Nginx, or others) recognizes
              the .php extension and passes the file to the PHP interpreter. The interpreter executes the PHP
              code, processing any logic, database queries, or file operations. The output—typically HTML—is
              then sent back to the web server, which delivers it to the user's browser. The user never sees
              the PHP code; they only receive the processed result.
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// The PHP request lifecycle:</span>{"\n"}
                {"\n"}
                <span style={{ color: "#50fa7b" }}>1. User Request</span> → Browser requests http://example.com/index.php{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#8be9fd" }}>2. Web Server</span> → Apache/Nginx receives request, recognizes .php{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#ff79c6" }}>3. PHP Interpreter</span> → Parses and executes PHP code{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#50fa7b" }}>4. Database/Files</span> → PHP queries MySQL, reads files, etc.{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#8be9fd" }}>5. HTML Output</span> → PHP generates HTML response{"\n"}
                {"        ↓"}{"\n"}
                <span style={{ color: "#f1fa8c" }}>6. Browser</span> → User sees rendered HTML page
              </Typography>
            </Paper>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              This server-side model has important implications. Since PHP runs on the server, it has access
              to server resources (databases, file systems, external APIs) that client-side JavaScript cannot
              directly access. It also means PHP code is never exposed to users—improving security for
              sensitive logic. However, every user interaction that requires PHP processing needs a round-trip
              to the server, which is why modern PHP applications often combine server-side PHP with
              client-side JavaScript for a responsive user experience.
            </Typography>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Core Features of PHP
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              PHP has evolved significantly since its early days. Modern PHP is a feature-rich language
              with capabilities that rival any contemporary programming language:
            </Typography>

            <List sx={{ mb: 3 }}>
              {[
                {
                  title: "Cross-Platform Compatibility",
                  desc: "PHP runs on virtually every operating system—Windows, macOS, Linux, and Unix variants. It works with all major web servers (Apache, Nginx, IIS, LiteSpeed) and supports numerous databases (MySQL, PostgreSQL, SQLite, MongoDB, Oracle). This universality makes PHP applications highly portable.",
                },
                {
                  title: "Database Integration",
                  desc: "PHP provides excellent database support through PDO (PHP Data Objects), a consistent interface for accessing databases. PDO supports prepared statements to prevent SQL injection, transactions for data integrity, and works with 12+ database drivers. The mysqli extension offers MySQL-specific optimizations.",
                },
                {
                  title: "Rich Standard Library",
                  desc: "PHP includes hundreds of built-in functions for string manipulation, array processing, file handling, date/time operations, mathematical calculations, encryption, and more. This extensive standard library means you can accomplish most tasks without external dependencies.",
                },
                {
                  title: "Session Management",
                  desc: "PHP has built-in session handling that makes managing user state across requests simple. Sessions can be stored in files, databases, or memory stores like Redis. Combined with cookies, PHP makes implementing authentication and user tracking straightforward.",
                },
                {
                  title: "Object-Oriented Programming",
                  desc: "Modern PHP is fully object-oriented with classes, interfaces, traits, abstract classes, namespaces, and autoloading. PHP 8 added constructor property promotion, match expressions, attributes, and union/intersection types, making OOP in PHP more powerful than ever.",
                },
                {
                  title: "Composer & Ecosystem",
                  desc: "Composer, PHP's dependency manager, revolutionized PHP development. With access to over 350,000 packages on Packagist, you can easily integrate authentication (Socialite), payment processing (Stripe SDK), email (PHPMailer), and countless other functionalities into your projects.",
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
                As a beginner, start with <strong>PHP 8.2 or 8.3</strong> to access all modern features. Use
                <strong> XAMPP</strong> (Windows/Mac) or <strong>MAMP</strong> (Mac) for a quick local development
                environment, or try <strong>Laravel Herd</strong> for an even simpler setup. For code editing,
                <strong> Visual Studio Code</strong> with the PHP Intelephense extension or <strong>PhpStorm</strong>
                (paid but excellent) will significantly accelerate your learning with intelligent code completion
                and error detection.
              </Typography>
            </Paper>
          </Paper>

          {/* Your First PHP Program */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Your First PHP Program
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Let's look at the classic "Hello, World!" program in PHP. This simple example demonstrates
              PHP's key concepts—embedding code in HTML and server-side execution:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>&lt;!-- hello.php - Save this file in your web server's document root --&gt;</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>&lt;!DOCTYPE html&gt;</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>&lt;html&gt;</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>&lt;head&gt;</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>&lt;title&gt;</span>My First PHP Page<span style={{ color: "#ff79c6" }}>&lt;/title&gt;</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>&lt;/head&gt;</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>&lt;body&gt;</span>{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>&lt;?php</span>{"\n"}
                {"        "}<span style={{ color: "#6272a4" }}>// This is a PHP comment</span>{"\n"}
                {"        "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"&lt;h1&gt;Hello, World!&lt;/h1&gt;"</span>;{"\n"}
                {"        "}{"\n"}
                {"        "}<span style={{ color: "#6272a4" }}>// Variables start with $</span>{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>$name</span> = <span style={{ color: "#f1fa8c" }}>"PHP Developer"</span>;{"\n"}
                {"        "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"&lt;p&gt;Welcome, $name!&lt;/p&gt;"</span>;{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>?&gt;</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>&lt;/body&gt;</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>&lt;/html&gt;</span>
              </Typography>
            </Paper>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Let's break down the key elements:
            </Typography>

            <List>
              {[
                { code: "<?php ... ?>", desc: "PHP opening and closing tags. All PHP code must be enclosed within these tags. You can also use the short echo tag <?= $var ?> for quick output. The closing tag is optional (and often omitted) in files containing only PHP." },
                { code: 'echo "text"', desc: "The echo statement outputs text to the browser. You can also use print, but echo is faster and more common. echo can output multiple values separated by commas." },
                { code: "$name", desc: "Variables in PHP always start with a dollar sign ($). PHP is loosely typed—you don't declare variable types. Variable names are case-sensitive ($name and $Name are different)." },
                { code: '"Welcome, $name!"', desc: "Double-quoted strings parse variables inside them (interpolation). Single-quoted strings treat everything literally. This is a key distinction in PHP." },
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
              PHP's story begins in 1994 when <strong>Rasmus Lerdorf</strong>, a Danish-Canadian programmer,
              created a set of Common Gateway Interface (CGI) binaries written in C. He used these tools to
              maintain his personal homepage and track visits to his online resume. He called this collection
              "Personal Home Page Tools," or PHP Tools. When he released the source code publicly in 1995,
              other developers began using and improving it, beginning PHP's journey as an open-source project.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              The language underwent a major transformation with <strong>PHP 3.0</strong> in 1998, rewritten
              from scratch by <strong>Zeev Suraski</strong> and <strong>Andi Gutmans</strong>. They renamed
              it to the recursive acronym "PHP: Hypertext Preprocessor" and introduced a more extensible
              architecture. This new foundation led to the creation of the <strong>Zend Engine</strong>,
              the heart of PHP that powers execution to this day. Zeev and Andi went on to found Zend
              Technologies, which has been instrumental in PHP's development.
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { year: "1994", event: "PHP Created", desc: "Rasmus Lerdorf creates CGI scripts for his personal homepage" },
                { year: "1995", event: "PHP/FI Released", desc: "Personal Home Page / Forms Interpreter released publicly" },
                { year: "1998", event: "PHP 3.0", desc: "Complete rewrite by Zeev Suraski and Andi Gutmans, renamed 'PHP: Hypertext Preprocessor'" },
                { year: "2000", event: "PHP 4.0", desc: "Zend Engine 1.0 introduced, significant performance improvements" },
                { year: "2004", event: "PHP 5.0", desc: "Zend Engine 2.0 with improved OOP support, PDO, and exceptions" },
                { year: "2015", event: "PHP 7.0", desc: "Massive performance boost (2x faster), scalar type hints, return types, null coalescing operator" },
                { year: "2020", event: "PHP 8.0", desc: "JIT compilation, union types, attributes, named arguments, match expression" },
                { year: "2022", event: "PHP 8.2", desc: "Readonly classes, disjunctive normal form types, deprecate dynamic properties" },
                { year: "2023", event: "PHP 8.3", desc: "Typed class constants, json_validate(), improved readonly properties" },
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
              The release of <strong>PHP 7.0 in 2015</strong> was a watershed moment. Thanks to the new Zend
              Engine 3.0 (sometimes called PHPNG), PHP 7 delivered up to <strong>2x performance improvements</strong>
              over PHP 5.6 while using less memory. This release also brought modern language features like
              scalar type declarations, return type declarations, the null coalescing operator (<code>??</code>),
              and the spaceship operator (<code>{"<=>"}</code>). PHP 7 silenced many critics and proved that
              PHP could be both fast and modern.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              <strong>PHP 8.0 in 2020</strong> continued this evolution with the introduction of the
              <strong> Just-In-Time (JIT) compiler</strong>, which can provide additional performance benefits
              for CPU-intensive operations. PHP 8 also brought long-awaited features like union types,
              attributes (annotations), named arguments, constructor property promotion, and the match
              expression. Each subsequent release (8.1, 8.2, 8.3) has added powerful features like enums,
              fibers (for async programming), readonly properties and classes, and improved type system
              capabilities.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColorDark, 0.08), border: `1px solid ${alpha(accentColorDark, 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                PHP's Lasting Impact
              </Typography>
              <Typography variant="body2" color="text.secondary">
                PHP democratized web development. Before PHP, building dynamic websites required complex CGI
                scripts or expensive proprietary solutions. PHP's simplicity and the LAMP stack (Linux, Apache,
                MySQL, PHP) made it possible for anyone to create interactive websites. WordPress, Wikipedia,
                Facebook, Slack, Mailchimp, Etsy, and countless other platforms were built with PHP. The
                language's influence on web development is immeasurable.
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
              Setting up a PHP development environment is straightforward. You'll need a web server with
              PHP installed, and optionally a database. The easiest approach for beginners is to use an
              all-in-one package that bundles everything together.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColorDark }}>
              All-in-One Development Stacks
            </Typography>

            <Grid container spacing={2} sx={{ mb: 4 }}>
              {[
                {
                  name: "XAMPP",
                  desc: "Cross-platform (Windows, macOS, Linux) package including Apache, MySQL, PHP, and Perl. Very beginner-friendly with a control panel to start/stop services. Most popular choice for learning.",
                  color: "#E76F00",
                },
                {
                  name: "MAMP",
                  desc: "Designed for macOS (also available for Windows). Includes Apache, Nginx, MySQL, and PHP. Clean interface and easy switching between PHP versions. Free version available.",
                  color: "#48BB78",
                },
                {
                  name: "Laravel Herd",
                  desc: "Modern, native PHP development environment for macOS and Windows. Blazing fast, includes PHP, MySQL, Redis, and more. Perfect for Laravel projects but works with any PHP.",
                  color: "#FF2D20",
                },
                {
                  name: "Docker",
                  desc: "Container-based approach giving you complete control. Use official PHP images and compose with MySQL, Redis, etc. Preferred for professional development and team consistency.",
                  color: "#2496ED",
                },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.name}>
                  <Paper sx={{ p: 3, borderRadius: 2, borderLeft: `4px solid ${item.color}`, bgcolor: alpha(item.color, 0.03) }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color, mb: 1 }}>
                      {item.name}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>
                      {item.desc}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColorDark }}>
              Installing PHP Standalone
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="caption" sx={{ color: "#6272a4", display: "block", mb: 1 }}>
                # macOS (using Homebrew):
              </Typography>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#8be9fd" }}>brew</span> install php{"\n"}
                <span style={{ color: "#8be9fd" }}>php</span> --version{"\n"}
                <span style={{ color: "#6272a4" }}># PHP 8.3.x (cli) (built: ...)</span>
              </Typography>
              <Typography variant="caption" sx={{ color: "#6272a4", display: "block", mt: 2, mb: 1 }}>
                # Ubuntu/Debian:
              </Typography>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#8be9fd" }}>sudo</span> apt update{"\n"}
                <span style={{ color: "#8be9fd" }}>sudo</span> apt install php php-mysql php-curl php-xml php-mbstring{"\n"}
                <span style={{ color: "#8be9fd" }}>php</span> --version
              </Typography>
              <Typography variant="caption" sx={{ color: "#6272a4", display: "block", mt: 2, mb: 1 }}>
                # Windows (using Chocolatey):
              </Typography>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#8be9fd" }}>choco</span> install php
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColorDark }}>
              PHP Built-in Development Server
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              PHP includes a built-in web server for development. It's perfect for learning and testing
              without needing Apache or Nginx:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}># Start the built-in server from your project directory:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>php</span> -S localhost:8000{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># With a specific document root:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>php</span> -S localhost:8000 -t public/{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Now visit http://localhost:8000 in your browser</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColorDark }}>
              Composer: PHP's Package Manager
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Composer is essential for modern PHP development. It manages dependencies and autoloading:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}># Install Composer (macOS/Linux):</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>curl</span> -sS https://getcomposer.org/installer | php{"\n"}
                <span style={{ color: "#8be9fd" }}>sudo</span> mv composer.phar /usr/local/bin/composer{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Verify installation:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>composer</span> --version{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Initialize a new project:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>composer</span> init{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Install a package:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>composer</span> require guzzlehttp/guzzle{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Install all dependencies from composer.json:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>composer</span> install
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColorDark }}>
              Recommended IDEs and Editors
            </Typography>

            <Grid container spacing={2}>
              {[
                { ide: "PhpStorm", desc: "JetBrains' professional PHP IDE. Best-in-class code intelligence, debugging, testing, database tools. Paid but worth it for serious development.", rec: "Professional Choice", color: "#9B5DE5" },
                { ide: "Visual Studio Code", desc: "Free, lightweight, highly extensible. With PHP Intelephense and PHP Debug extensions, it's a powerful PHP development environment.", rec: "Popular Free Option", color: "#007ACC" },
                { ide: "Sublime Text", desc: "Fast, elegant editor. With PHP packages from Package Control, it becomes a capable PHP editor. Great for quick edits.", rec: "Lightweight", color: "#FF9800" },
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

          {/* PHP Basics & Syntax Section */}
          <Paper id="basics" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#48BB78", 0.15), color: "#48BB78", width: 48, height: 48 }}>
                <CodeIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                PHP Basics & Syntax
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              PHP has a C-style syntax that is familiar to developers coming from C, Java, or JavaScript.
              However, it has unique characteristics that set it apart, particularly in how variables are
              declared and how the language interacts with HTML.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              PHP Tags
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Standard PHP tags (always use these)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>&lt;?php</span>{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"Hello, World!"</span>;{"\n"}
                <span style={{ color: "#8be9fd" }}>?&gt;</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Short echo tag (for quick output in templates)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>&lt;p&gt;</span>Welcome, <span style={{ color: "#8be9fd" }}>&lt;?=</span> <span style={{ color: "#ff79c6" }}>$username</span> <span style={{ color: "#8be9fd" }}>?&gt;</span><span style={{ color: "#ff79c6" }}>&lt;/p&gt;</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// In pure PHP files, omit the closing tag (best practice)</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>&lt;?php</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// All PHP code here...</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// No closing ?&gt; needed</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Comments
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Single-line comment (C++ style)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Single-line comment (shell style)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>/*</span>{"\n"}
                <span style={{ color: "#6272a4" }}> * Multi-line comment</span>{"\n"}
                <span style={{ color: "#6272a4" }}> * Spans multiple lines</span>{"\n"}
                <span style={{ color: "#6272a4" }}> */</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>/**</span>{"\n"}
                <span style={{ color: "#6272a4" }}> * PHPDoc comment - used for documentation</span>{"\n"}
                <span style={{ color: "#6272a4" }}> * @param string $name The user's name</span>{"\n"}
                <span style={{ color: "#6272a4" }}> * @return string A greeting message</span>{"\n"}
                <span style={{ color: "#6272a4" }}> */</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>function</span> <span style={{ color: "#50fa7b" }}>greet</span>(<span style={{ color: "#ff79c6" }}>string</span> <span style={{ color: "#ff79c6" }}>$name</span>): <span style={{ color: "#ff79c6" }}>string</span> {"{"}...{"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Statements and Semicolons
            </Typography>

            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
              Every PHP statement must end with a semicolon. This is mandatory (unlike JavaScript where
              it's sometimes optional):
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>$name</span> = <span style={{ color: "#f1fa8c" }}>"PHP"</span>;        <span style={{ color: "#6272a4" }}>// Correct</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"Hello"</span>;        <span style={{ color: "#6272a4" }}>// Correct</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$x</span> = <span style={{ color: "#bd93f9" }}>5</span>; <span style={{ color: "#ff79c6" }}>$y</span> = <span style={{ color: "#bd93f9" }}>10</span>;      <span style={{ color: "#6272a4" }}>// Multiple statements on one line (legal but discouraged)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Before the closing ?&gt; tag, the semicolon is optional:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>&lt;?php</span> <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"Hi"</span> <span style={{ color: "#8be9fd" }}>?&gt;</span>  <span style={{ color: "#6272a4" }}>// Works, but not recommended</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Case Sensitivity
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Variables ARE case-sensitive</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$name</span> = <span style={{ color: "#f1fa8c" }}>"John"</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>$Name</span> = <span style={{ color: "#f1fa8c" }}>"Jane"</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>$NAME</span> = <span style={{ color: "#f1fa8c" }}>"Bob"</span>;{"\n"}
                <span style={{ color: "#6272a4" }}>// These are THREE different variables!</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Functions, classes, and keywords are NOT case-sensitive</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>ECHO</span> <span style={{ color: "#f1fa8c" }}>"hello"</span>;     <span style={{ color: "#6272a4" }}>// Works (but use lowercase!)</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>Echo</span> <span style={{ color: "#f1fa8c" }}>"hello"</span>;     <span style={{ color: "#6272a4" }}>// Works</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"hello"</span>;     <span style={{ color: "#6272a4" }}>// Preferred style</span>
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#48BB78", 0.08), border: `1px solid ${alpha("#48BB78", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                Common Beginner Mistakes
              </Typography>
              <Typography variant="body2" color="text.secondary" component="div">
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  <li>Forgetting the <code>$</code> before variable names</li>
                  <li>Missing semicolons at the end of statements</li>
                  <li>Using <code>==</code> instead of <code>===</code> for comparisons (type coercion issues)</li>
                  <li>Mixing single and double quotes without understanding the difference</li>
                  <li>Not escaping user input (SQL injection, XSS vulnerabilities)</li>
                </ul>
              </Typography>
            </Paper>
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
              PHP is a <strong>dynamically-typed language</strong>, meaning you don't need to declare
              variable types explicitly (though PHP 7+ allows optional type declarations). Variables in
              PHP always start with a dollar sign (<code>$</code>), followed by the variable name. PHP
              supports several data types, each suited for different kinds of data.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Scalar Types
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// String - text enclosed in quotes</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$name</span> = <span style={{ color: "#f1fa8c" }}>"John Doe"</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>$greeting</span> = <span style={{ color: "#f1fa8c" }}>'Hello'</span>;          <span style={{ color: "#6272a4" }}>// Single quotes (literal)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$message</span> = <span style={{ color: "#f1fa8c" }}>"Hi, $name"</span>;       <span style={{ color: "#6272a4" }}>// Double quotes (interpolation) → "Hi, John Doe"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Integer - whole numbers</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$age</span> = <span style={{ color: "#bd93f9" }}>25</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>$negative</span> = <span style={{ color: "#bd93f9" }}>-100</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>$hex</span> = <span style={{ color: "#bd93f9" }}>0x1A</span>;              <span style={{ color: "#6272a4" }}>// Hexadecimal (26)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$octal</span> = <span style={{ color: "#bd93f9" }}>0755</span>;            <span style={{ color: "#6272a4" }}>// Octal (493)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$binary</span> = <span style={{ color: "#bd93f9" }}>0b1010</span>;          <span style={{ color: "#6272a4" }}>// Binary (10)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Float (double) - decimal numbers</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$price</span> = <span style={{ color: "#bd93f9" }}>19.99</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>$scientific</span> = <span style={{ color: "#bd93f9" }}>2.5e3</span>;       <span style={{ color: "#6272a4" }}>// 2500.0</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Boolean - true or false</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$isActive</span> = <span style={{ color: "#ff79c6" }}>true</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>$isDeleted</span> = <span style={{ color: "#ff79c6" }}>false</span>;
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Compound Types
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Array - ordered collection</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$colors</span> = [<span style={{ color: "#f1fa8c" }}>"red"</span>, <span style={{ color: "#f1fa8c" }}>"green"</span>, <span style={{ color: "#f1fa8c" }}>"blue"</span>];{"\n"}
                <span style={{ color: "#ff79c6" }}>$colors</span> = <span style={{ color: "#50fa7b" }}>array</span>(<span style={{ color: "#f1fa8c" }}>"red"</span>, <span style={{ color: "#f1fa8c" }}>"green"</span>, <span style={{ color: "#f1fa8c" }}>"blue"</span>);  <span style={{ color: "#6272a4" }}>// Older syntax</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Associative array (key-value pairs)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$user</span> = [{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>"name"</span> ={">"} <span style={{ color: "#f1fa8c" }}>"John"</span>,{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>"age"</span> ={">"} <span style={{ color: "#bd93f9" }}>25</span>,{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>"email"</span> ={">"} <span style={{ color: "#f1fa8c" }}>"john@example.com"</span>{"\n"}
                ];{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Object - instance of a class</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Person</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#ff79c6" }}>$name</span>;{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#ff79c6" }}>$person</span> = <span style={{ color: "#ff79c6" }}>new</span> Person();{"\n"}
                <span style={{ color: "#ff79c6" }}>$person</span>-{">"}name = <span style={{ color: "#f1fa8c" }}>"John"</span>;
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Special Types
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// NULL - represents no value</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$nothing</span> = <span style={{ color: "#ff79c6" }}>null</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>$name</span> = <span style={{ color: "#ff79c6" }}>null</span>;           <span style={{ color: "#6272a4" }}>// Explicitly set to null</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>unset</span>(<span style={{ color: "#ff79c6" }}>$name</span>);           <span style={{ color: "#6272a4" }}>// Destroys the variable</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Resource - holds reference to external resource</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$file</span> = <span style={{ color: "#50fa7b" }}>fopen</span>(<span style={{ color: "#f1fa8c" }}>"data.txt"</span>, <span style={{ color: "#f1fa8c" }}>"r"</span>);  <span style={{ color: "#6272a4" }}>// File handle</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$db</span> = <span style={{ color: "#50fa7b" }}>mysqli_connect</span>(...);     <span style={{ color: "#6272a4" }}>// Database connection</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Type Checking and Casting
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Check types</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>gettype</span>(<span style={{ color: "#ff79c6" }}>$var</span>);           <span style={{ color: "#6272a4" }}>// Returns type as string</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>is_string</span>(<span style={{ color: "#ff79c6" }}>$var</span>);         <span style={{ color: "#6272a4" }}>// true if string</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>is_int</span>(<span style={{ color: "#ff79c6" }}>$var</span>);            <span style={{ color: "#6272a4" }}>// true if integer</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>is_float</span>(<span style={{ color: "#ff79c6" }}>$var</span>);          <span style={{ color: "#6272a4" }}>// true if float</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>is_bool</span>(<span style={{ color: "#ff79c6" }}>$var</span>);           <span style={{ color: "#6272a4" }}>// true if boolean</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>is_array</span>(<span style={{ color: "#ff79c6" }}>$var</span>);          <span style={{ color: "#6272a4" }}>// true if array</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>is_null</span>(<span style={{ color: "#ff79c6" }}>$var</span>);           <span style={{ color: "#6272a4" }}>// true if null</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>isset</span>(<span style={{ color: "#ff79c6" }}>$var</span>);             <span style={{ color: "#6272a4" }}>// true if set and not null</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>empty</span>(<span style={{ color: "#ff79c6" }}>$var</span>);             <span style={{ color: "#6272a4" }}>// true if empty ("", 0, null, [], false)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Type casting</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$str</span> = <span style={{ color: "#f1fa8c" }}>"42"</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>$int</span> = (<span style={{ color: "#ff79c6" }}>int</span>) <span style={{ color: "#ff79c6" }}>$str</span>;       <span style={{ color: "#6272a4" }}>// 42</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$float</span> = (<span style={{ color: "#ff79c6" }}>float</span>) <span style={{ color: "#ff79c6" }}>$str</span>;   <span style={{ color: "#6272a4" }}>// 42.0</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$bool</span> = (<span style={{ color: "#ff79c6" }}>bool</span>) <span style={{ color: "#ff79c6" }}>$str</span>;     <span style={{ color: "#6272a4" }}>// true</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$arr</span> = (<span style={{ color: "#ff79c6" }}>array</span>) <span style={{ color: "#ff79c6" }}>$str</span>;    <span style={{ color: "#6272a4" }}>// ["42"]</span>
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#667EEA", 0.08), border: `1px solid ${alpha("#667EEA", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                PHP 8+ Type Declarations
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Modern PHP supports type declarations for function parameters and return types:
                <code style={{ marginLeft: 4 }}>function add(int $a, int $b): int</code>.
                PHP 8 introduced union types (<code>int|string</code>), mixed type, and intersection types.
                Use <code>declare(strict_types=1);</code> at the top of your file to enforce strict type checking.
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
              PHP provides a rich set of operators for performing operations on variables and values.
              Understanding these operators is essential for writing effective PHP code.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Arithmetic Operators
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>$a</span> = <span style={{ color: "#bd93f9" }}>10</span>; <span style={{ color: "#ff79c6" }}>$b</span> = <span style={{ color: "#bd93f9" }}>3</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>$a</span> + <span style={{ color: "#ff79c6" }}>$b</span>    <span style={{ color: "#6272a4" }}>// Addition: 13</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$a</span> - <span style={{ color: "#ff79c6" }}>$b</span>    <span style={{ color: "#6272a4" }}>// Subtraction: 7</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$a</span> * <span style={{ color: "#ff79c6" }}>$b</span>    <span style={{ color: "#6272a4" }}>// Multiplication: 30</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$a</span> / <span style={{ color: "#ff79c6" }}>$b</span>    <span style={{ color: "#6272a4" }}>// Division: 3.333... (always float if not even)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$a</span> % <span style={{ color: "#ff79c6" }}>$b</span>    <span style={{ color: "#6272a4" }}>// Modulus: 1</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$a</span> ** <span style={{ color: "#ff79c6" }}>$b</span>   <span style={{ color: "#6272a4" }}>// Exponentiation: 1000 (10^3)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Integer division (PHP 7+)</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>intdiv</span>(<span style={{ color: "#bd93f9" }}>10</span>, <span style={{ color: "#bd93f9" }}>3</span>)  <span style={{ color: "#6272a4" }}>// 3</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Comparison Operators
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Loose comparison (type coercion)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$a</span> == <span style={{ color: "#ff79c6" }}>$b</span>     <span style={{ color: "#6272a4" }}>// Equal (value only)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$a</span> != <span style={{ color: "#ff79c6" }}>$b</span>     <span style={{ color: "#6272a4" }}>// Not equal</span>{"\n"}
                <span style={{ color: "#f1fa8c" }}>"5"</span> == <span style={{ color: "#bd93f9" }}>5</span>      <span style={{ color: "#6272a4" }}>// true! (type coercion)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Strict comparison (recommended!)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$a</span> === <span style={{ color: "#ff79c6" }}>$b</span>    <span style={{ color: "#6272a4" }}>// Identical (value AND type)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$a</span> !== <span style={{ color: "#ff79c6" }}>$b</span>    <span style={{ color: "#6272a4" }}>// Not identical</span>{"\n"}
                <span style={{ color: "#f1fa8c" }}>"5"</span> === <span style={{ color: "#bd93f9" }}>5</span>     <span style={{ color: "#6272a4" }}>// false (different types)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Relational operators</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$a</span> {">"} <span style={{ color: "#ff79c6" }}>$b</span>      <span style={{ color: "#6272a4" }}>// Greater than</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$a</span> {"<"} <span style={{ color: "#ff79c6" }}>$b</span>      <span style={{ color: "#6272a4" }}>// Less than</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$a</span> {">"}= <span style={{ color: "#ff79c6" }}>$b</span>     <span style={{ color: "#6272a4" }}>// Greater than or equal</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$a</span> {"<"}= <span style={{ color: "#ff79c6" }}>$b</span>     <span style={{ color: "#6272a4" }}>// Less than or equal</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Spaceship operator (PHP 7+) - returns -1, 0, or 1</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$a</span> {"<"}={">"} <span style={{ color: "#ff79c6" }}>$b</span>    <span style={{ color: "#6272a4" }}>// 1 (a {">"} b), 0 (a == b), -1 (a {"<"} b)</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Logical Operators
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>$x</span> && <span style={{ color: "#ff79c6" }}>$y</span>     <span style={{ color: "#6272a4" }}>// AND - both must be true</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$x</span> || <span style={{ color: "#ff79c6" }}>$y</span>     <span style={{ color: "#6272a4" }}>// OR - at least one true</span>{"\n"}
                !<span style={{ color: "#ff79c6" }}>$x</span>         <span style={{ color: "#6272a4" }}>// NOT - inverts value</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Word-based (lower precedence than && and ||)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$x</span> <span style={{ color: "#ff79c6" }}>and</span> <span style={{ color: "#ff79c6" }}>$y</span>   <span style={{ color: "#6272a4" }}>// Logical AND</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$x</span> <span style={{ color: "#ff79c6" }}>or</span> <span style={{ color: "#ff79c6" }}>$y</span>    <span style={{ color: "#6272a4" }}>// Logical OR</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$x</span> <span style={{ color: "#ff79c6" }}>xor</span> <span style={{ color: "#ff79c6" }}>$y</span>   <span style={{ color: "#6272a4" }}>// Exclusive OR (one true, not both)</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              Null Coalescing & Elvis Operators
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Null coalescing operator (PHP 7+)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$username</span> = <span style={{ color: "#ff79c6" }}>$_GET</span>[<span style={{ color: "#f1fa8c" }}>'user'</span>] ?? <span style={{ color: "#f1fa8c" }}>'Guest'</span>;{"\n"}
                <span style={{ color: "#6272a4" }}>// Returns 'Guest' if $_GET['user'] is null or doesn't exist</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Null coalescing assignment (PHP 7.4+)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$data</span>[<span style={{ color: "#f1fa8c" }}>'count'</span>] ??= <span style={{ color: "#bd93f9" }}>0</span>;{"\n"}
                <span style={{ color: "#6272a4" }}>// Sets to 0 only if null or not set</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Elvis operator (ternary shorthand)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$name</span> = <span style={{ color: "#ff79c6" }}>$username</span> ?: <span style={{ color: "#f1fa8c" }}>'Anonymous'</span>;{"\n"}
                <span style={{ color: "#6272a4" }}>// Returns 'Anonymous' if $username is falsy</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Nullsafe operator (PHP 8+)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$country</span> = <span style={{ color: "#ff79c6" }}>$user</span>?-{">"}getAddress()?-{">"}getCountry();{"\n"}
                <span style={{ color: "#6272a4" }}>// Returns null if any part is null (no errors)</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ED8936" }}>
              String Operators
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Concatenation</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$full</span> = <span style={{ color: "#f1fa8c" }}>"Hello"</span> . <span style={{ color: "#f1fa8c" }}>" "</span> . <span style={{ color: "#f1fa8c" }}>"World"</span>;  <span style={{ color: "#6272a4" }}>// "Hello World"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Concatenation assignment</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$text</span> = <span style={{ color: "#f1fa8c" }}>"Hello"</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>$text</span> .= <span style={{ color: "#f1fa8c" }}>" World"</span>;           <span style={{ color: "#6272a4" }}>// "Hello World"</span>
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
              Control flow statements determine the order in which code is executed. PHP provides
              conditional statements, loops, and other control structures similar to other C-style languages.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              If-Else Statements
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>$score</span> = <span style={{ color: "#bd93f9" }}>85</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> (<span style={{ color: "#ff79c6" }}>$score</span> {">"}= <span style={{ color: "#bd93f9" }}>90</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"A - Excellent!"</span>;{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>elseif</span> (<span style={{ color: "#ff79c6" }}>$score</span> {">"}= <span style={{ color: "#bd93f9" }}>80</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"B - Good job!"</span>;{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>elseif</span> (<span style={{ color: "#ff79c6" }}>$score</span> {">"}= <span style={{ color: "#bd93f9" }}>70</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"C - Satisfactory"</span>;{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>else</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"Need improvement"</span>;{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Ternary operator</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$status</span> = <span style={{ color: "#ff79c6" }}>$score</span> {">"}= <span style={{ color: "#bd93f9" }}>60</span> ? <span style={{ color: "#f1fa8c" }}>"Pass"</span> : <span style={{ color: "#f1fa8c" }}>"Fail"</span>;
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              Switch & Match Statements
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Traditional switch</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>switch</span> (<span style={{ color: "#ff79c6" }}>$day</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> <span style={{ color: "#f1fa8c" }}>'Monday'</span>:{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> <span style={{ color: "#f1fa8c" }}>'Tuesday'</span>:{"\n"}
                {"        "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"Weekday"</span>;{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>break</span>;{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> <span style={{ color: "#f1fa8c" }}>'Saturday'</span>:{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> <span style={{ color: "#f1fa8c" }}>'Sunday'</span>:{"\n"}
                {"        "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"Weekend"</span>;{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>break</span>;{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>default</span>:{"\n"}
                {"        "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"Invalid day"</span>;{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Match expression (PHP 8+) - recommended!</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$result</span> = <span style={{ color: "#ff79c6" }}>match</span>(<span style={{ color: "#ff79c6" }}>$day</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>'Monday'</span>, <span style={{ color: "#f1fa8c" }}>'Tuesday'</span> ={">"} <span style={{ color: "#f1fa8c" }}>'Weekday'</span>,{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>'Saturday'</span>, <span style={{ color: "#f1fa8c" }}>'Sunday'</span> ={">"} <span style={{ color: "#f1fa8c" }}>'Weekend'</span>,{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>default</span> ={">"} <span style={{ color: "#f1fa8c" }}>'Invalid'</span>,{"\n"}
                {"}"};
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              Loops
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// For loop</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> (<span style={{ color: "#ff79c6" }}>$i</span> = <span style={{ color: "#bd93f9" }}>0</span>; <span style={{ color: "#ff79c6" }}>$i</span> {"<"} <span style={{ color: "#bd93f9" }}>5</span>; <span style={{ color: "#ff79c6" }}>$i</span>++) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#ff79c6" }}>$i</span>;  <span style={{ color: "#6272a4" }}>// 0, 1, 2, 3, 4</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// While loop</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$i</span> = <span style={{ color: "#bd93f9" }}>0</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>while</span> (<span style={{ color: "#ff79c6" }}>$i</span> {"<"} <span style={{ color: "#bd93f9" }}>5</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#ff79c6" }}>$i</span>++;{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Do-while loop (executes at least once)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>do</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#ff79c6" }}>$i</span>--;{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>while</span> (<span style={{ color: "#ff79c6" }}>$i</span> {">"} <span style={{ color: "#bd93f9" }}>0</span>);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Foreach - iterating arrays (most common!)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$colors</span> = [<span style={{ color: "#f1fa8c" }}>'red'</span>, <span style={{ color: "#f1fa8c" }}>'green'</span>, <span style={{ color: "#f1fa8c" }}>'blue'</span>];{"\n"}
                <span style={{ color: "#ff79c6" }}>foreach</span> (<span style={{ color: "#ff79c6" }}>$colors</span> <span style={{ color: "#ff79c6" }}>as</span> <span style={{ color: "#ff79c6" }}>$color</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#ff79c6" }}>$color</span>;{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Foreach with key ={">"} value</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$user</span> = [<span style={{ color: "#f1fa8c" }}>'name'</span> ={">"} <span style={{ color: "#f1fa8c" }}>'John'</span>, <span style={{ color: "#f1fa8c" }}>'age'</span> ={">"} <span style={{ color: "#bd93f9" }}>25</span>];{"\n"}
                <span style={{ color: "#ff79c6" }}>foreach</span> (<span style={{ color: "#ff79c6" }}>$user</span> <span style={{ color: "#ff79c6" }}>as</span> <span style={{ color: "#ff79c6" }}>$key</span> ={">"} <span style={{ color: "#ff79c6" }}>$value</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"$key: $value"</span>;{"\n"}
                {"}"}
              </Typography>
            </Paper>
          </Paper>

          {/* Arrays & Strings Section */}
          <Paper id="arrays" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <StorageIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Arrays & Strings
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Arrays are one of PHP's most versatile data structures. Unlike many languages, PHP arrays can be
              used as lists, hash maps, dictionaries, collections, stacks, and queues. Strings in PHP are
              essentially arrays of characters with a rich set of manipulation functions.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Indexed Arrays
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Creating indexed arrays</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$fruits</span> = [<span style={{ color: "#f1fa8c" }}>"apple"</span>, <span style={{ color: "#f1fa8c" }}>"banana"</span>, <span style={{ color: "#f1fa8c" }}>"cherry"</span>];{"\n"}
                <span style={{ color: "#ff79c6" }}>$numbers</span> = <span style={{ color: "#50fa7b" }}>range</span>(<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>10</span>);  <span style={{ color: "#6272a4" }}>// [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Accessing elements (0-indexed)</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#ff79c6" }}>$fruits</span>[<span style={{ color: "#bd93f9" }}>0</span>];  <span style={{ color: "#6272a4" }}>// "apple"</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#ff79c6" }}>$fruits</span>[<span style={{ color: "#bd93f9" }}>-1</span>]; <span style={{ color: "#6272a4" }}>// Error! Use end() or array_slice()</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Adding elements</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$fruits</span>[] = <span style={{ color: "#f1fa8c" }}>"date"</span>;        <span style={{ color: "#6272a4" }}>// Append to end</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>array_push</span>(<span style={{ color: "#ff79c6" }}>$fruits</span>, <span style={{ color: "#f1fa8c" }}>"elderberry"</span>);{"\n"}
                <span style={{ color: "#50fa7b" }}>array_unshift</span>(<span style={{ color: "#ff79c6" }}>$fruits</span>, <span style={{ color: "#f1fa8c" }}>"avocado"</span>); <span style={{ color: "#6272a4" }}>// Prepend</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Removing elements</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>array_pop</span>(<span style={{ color: "#ff79c6" }}>$fruits</span>);    <span style={{ color: "#6272a4" }}>// Remove last</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>array_shift</span>(<span style={{ color: "#ff79c6" }}>$fruits</span>);  <span style={{ color: "#6272a4" }}>// Remove first</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>unset</span>(<span style={{ color: "#ff79c6" }}>$fruits</span>[<span style={{ color: "#bd93f9" }}>1</span>]);    <span style={{ color: "#6272a4" }}>// Remove by index (leaves gap!)</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Associative Arrays
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Key-value pairs</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$person</span> = [{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>"name"</span> ={">"} <span style={{ color: "#f1fa8c" }}>"John Doe"</span>,{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>"email"</span> ={">"} <span style={{ color: "#f1fa8c" }}>"john@example.com"</span>,{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>"age"</span> ={">"} <span style={{ color: "#bd93f9" }}>30</span>,{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>"active"</span> ={">"} <span style={{ color: "#ff79c6" }}>true</span>{"\n"}
                ];{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Accessing values</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#ff79c6" }}>$person</span>[<span style={{ color: "#f1fa8c" }}>"name"</span>];  <span style={{ color: "#6272a4" }}>// "John Doe"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Check if key exists</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> (<span style={{ color: "#50fa7b" }}>array_key_exists</span>(<span style={{ color: "#f1fa8c" }}>"email"</span>, <span style={{ color: "#ff79c6" }}>$person</span>)) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"Email exists"</span>;{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Get all keys/values</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$keys</span> = <span style={{ color: "#50fa7b" }}>array_keys</span>(<span style={{ color: "#ff79c6" }}>$person</span>);    <span style={{ color: "#6272a4" }}>// ["name", "email", "age", "active"]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$values</span> = <span style={{ color: "#50fa7b" }}>array_values</span>(<span style={{ color: "#ff79c6" }}>$person</span>); <span style={{ color: "#6272a4" }}>// ["John Doe", "john@...", 30, true]</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Array Functions
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>$numbers</span> = [<span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>4</span>, <span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>5</span>, <span style={{ color: "#bd93f9" }}>9</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>6</span>];{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Sorting</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>sort</span>(<span style={{ color: "#ff79c6" }}>$numbers</span>);         <span style={{ color: "#6272a4" }}>// Ascending [1, 1, 2, 3, 4, 5, 6, 9]</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>rsort</span>(<span style={{ color: "#ff79c6" }}>$numbers</span>);        <span style={{ color: "#6272a4" }}>// Descending</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>usort</span>(<span style={{ color: "#ff79c6" }}>$numbers</span>, <span style={{ color: "#ff79c6" }}>fn</span>(<span style={{ color: "#ff79c6" }}>$a</span>, <span style={{ color: "#ff79c6" }}>$b</span>) ={">"} <span style={{ color: "#ff79c6" }}>$b</span> {"<"}={">"} <span style={{ color: "#ff79c6" }}>$a</span>); <span style={{ color: "#6272a4" }}>// Custom sort</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Filtering</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$evens</span> = <span style={{ color: "#50fa7b" }}>array_filter</span>(<span style={{ color: "#ff79c6" }}>$numbers</span>, <span style={{ color: "#ff79c6" }}>fn</span>(<span style={{ color: "#ff79c6" }}>$n</span>) ={">"} <span style={{ color: "#ff79c6" }}>$n</span> % <span style={{ color: "#bd93f9" }}>2</span> === <span style={{ color: "#bd93f9" }}>0</span>);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Mapping (transform each element)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$doubled</span> = <span style={{ color: "#50fa7b" }}>array_map</span>(<span style={{ color: "#ff79c6" }}>fn</span>(<span style={{ color: "#ff79c6" }}>$n</span>) ={">"} <span style={{ color: "#ff79c6" }}>$n</span> * <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#ff79c6" }}>$numbers</span>);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Reducing to single value</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$sum</span> = <span style={{ color: "#50fa7b" }}>array_reduce</span>(<span style={{ color: "#ff79c6" }}>$numbers</span>, <span style={{ color: "#ff79c6" }}>fn</span>(<span style={{ color: "#ff79c6" }}>$carry</span>, <span style={{ color: "#ff79c6" }}>$n</span>) ={">"} <span style={{ color: "#ff79c6" }}>$carry</span> + <span style={{ color: "#ff79c6" }}>$n</span>, <span style={{ color: "#bd93f9" }}>0</span>);{"\n"}
                <span style={{ color: "#ff79c6" }}>$sum</span> = <span style={{ color: "#50fa7b" }}>array_sum</span>(<span style={{ color: "#ff79c6" }}>$numbers</span>);  <span style={{ color: "#6272a4" }}>// Shorthand for sum</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Searching</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>in_array</span>(<span style={{ color: "#bd93f9" }}>5</span>, <span style={{ color: "#ff79c6" }}>$numbers</span>);      <span style={{ color: "#6272a4" }}>// true</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>array_search</span>(<span style={{ color: "#bd93f9" }}>5</span>, <span style={{ color: "#ff79c6" }}>$numbers</span>);  <span style={{ color: "#6272a4" }}>// Returns index (4)</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              String Manipulation
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>$str</span> = <span style={{ color: "#f1fa8c" }}>"  Hello, World!  "</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Common string functions</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>strlen</span>(<span style={{ color: "#ff79c6" }}>$str</span>);                <span style={{ color: "#6272a4" }}>// 17 (length)</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>trim</span>(<span style={{ color: "#ff79c6" }}>$str</span>);                  <span style={{ color: "#6272a4" }}>// "Hello, World!" (remove whitespace)</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>strtolower</span>(<span style={{ color: "#ff79c6" }}>$str</span>);            <span style={{ color: "#6272a4" }}>// "  hello, world!  "</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>strtoupper</span>(<span style={{ color: "#ff79c6" }}>$str</span>);            <span style={{ color: "#6272a4" }}>// "  HELLO, WORLD!  "</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>ucfirst</span>(<span style={{ color: "#f1fa8c" }}>"hello"</span>);            <span style={{ color: "#6272a4" }}>// "Hello"</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>ucwords</span>(<span style={{ color: "#f1fa8c" }}>"hello world"</span>);      <span style={{ color: "#6272a4" }}>// "Hello World"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Searching in strings</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>strpos</span>(<span style={{ color: "#ff79c6" }}>$str</span>, <span style={{ color: "#f1fa8c" }}>"World"</span>);       <span style={{ color: "#6272a4" }}>// 9 (position)</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>str_contains</span>(<span style={{ color: "#ff79c6" }}>$str</span>, <span style={{ color: "#f1fa8c" }}>"Hello"</span>); <span style={{ color: "#6272a4" }}>// true (PHP 8+)</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>str_starts_with</span>(<span style={{ color: "#50fa7b" }}>trim</span>(<span style={{ color: "#ff79c6" }}>$str</span>), <span style={{ color: "#f1fa8c" }}>"Hello"</span>); <span style={{ color: "#6272a4" }}>// true (PHP 8+)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Replacing</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>str_replace</span>(<span style={{ color: "#f1fa8c" }}>"World"</span>, <span style={{ color: "#f1fa8c" }}>"PHP"</span>, <span style={{ color: "#ff79c6" }}>$str</span>); <span style={{ color: "#6272a4" }}>// "  Hello, PHP!  "</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Splitting and joining</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$parts</span> = <span style={{ color: "#50fa7b" }}>explode</span>(<span style={{ color: "#f1fa8c" }}>","</span>, <span style={{ color: "#f1fa8c" }}>"a,b,c"</span>);  <span style={{ color: "#6272a4" }}>// ["a", "b", "c"]</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$joined</span> = <span style={{ color: "#50fa7b" }}>implode</span>(<span style={{ color: "#f1fa8c" }}>"-"</span>, <span style={{ color: "#ff79c6" }}>$parts</span>);  <span style={{ color: "#6272a4" }}>// "a-b-c"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Substrings</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>substr</span>(<span style={{ color: "#f1fa8c" }}>"Hello"</span>, <span style={{ color: "#bd93f9" }}>0</span>, <span style={{ color: "#bd93f9" }}>3</span>);       <span style={{ color: "#6272a4" }}>// "Hel"</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>substr</span>(<span style={{ color: "#f1fa8c" }}>"Hello"</span>, <span style={{ color: "#bd93f9" }}>-2</span>);          <span style={{ color: "#6272a4" }}>// "lo" (from end)</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Regular Expressions
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// preg_match - find first match</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$email</span> = <span style={{ color: "#f1fa8c" }}>"user@example.com"</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> (<span style={{ color: "#50fa7b" }}>preg_match</span>(<span style={{ color: "#f1fa8c" }}>'/^[\w.-]+@[\w.-]+\.\w+$/'</span>, <span style={{ color: "#ff79c6" }}>$email</span>)) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"Valid email"</span>;{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// preg_match_all - find all matches</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$text</span> = <span style={{ color: "#f1fa8c" }}>"Call 555-1234 or 555-5678"</span>;{"\n"}
                <span style={{ color: "#50fa7b" }}>preg_match_all</span>(<span style={{ color: "#f1fa8c" }}>'/\d{"{3}"}-\d{"{4}"}/'</span>, <span style={{ color: "#ff79c6" }}>$text</span>, <span style={{ color: "#ff79c6" }}>$matches</span>);{"\n"}
                <span style={{ color: "#6272a4" }}>// $matches[0] = ["555-1234", "555-5678"]</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// preg_replace - search and replace</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$clean</span> = <span style={{ color: "#50fa7b" }}>preg_replace</span>(<span style={{ color: "#f1fa8c" }}>'/[^a-zA-Z0-9]/'</span>, <span style={{ color: "#f1fa8c" }}>''</span>, <span style={{ color: "#f1fa8c" }}>"Hello! World?"</span>);{"\n"}
                <span style={{ color: "#6272a4" }}>// "HelloWorld"</span>
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColor, 0.08), border: `1px solid ${alpha(accentColor, 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                Array Best Practices
              </Typography>
              <Typography variant="body2" color="text.secondary" component="div">
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  <li>Use <code>[]</code> syntax instead of <code>array()</code> for modern PHP</li>
                  <li>Prefer <code>foreach</code> over <code>for</code> loops for iteration</li>
                  <li>Use <code>array_map/filter/reduce</code> for functional transformations</li>
                  <li>Remember <code>unset()</code> leaves gaps - use <code>array_values()</code> to reindex</li>
                  <li>Check for empty arrays with <code>empty($arr)</code> not <code>count($arr) === 0</code></li>
                </ul>
              </Typography>
            </Paper>
          </Paper>

          {/* Functions Section */}
          <Paper id="functions" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <ExtensionIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Functions
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Functions are reusable blocks of code that perform specific tasks. PHP supports traditional functions,
              anonymous functions (closures), arrow functions, and variadic functions. Modern PHP (7+) adds
              type declarations and return types for safer, more predictable code.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Basic Function Syntax
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Simple function</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>function</span> <span style={{ color: "#50fa7b" }}>greet</span>(<span style={{ color: "#ff79c6" }}>$name</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#f1fa8c" }}>"Hello, </span><span style={{ color: "#ff79c6" }}>$name</span><span style={{ color: "#f1fa8c" }}>!"</span>;{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#50fa7b" }}>greet</span>(<span style={{ color: "#f1fa8c" }}>"World"</span>);  <span style={{ color: "#6272a4" }}>// "Hello, World!"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// With type declarations (PHP 7+)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>function</span> <span style={{ color: "#50fa7b" }}>add</span>(<span style={{ color: "#8be9fd" }}>int</span> <span style={{ color: "#ff79c6" }}>$a</span>, <span style={{ color: "#8be9fd" }}>int</span> <span style={{ color: "#ff79c6" }}>$b</span>): <span style={{ color: "#8be9fd" }}>int</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#ff79c6" }}>$a</span> + <span style={{ color: "#ff79c6" }}>$b</span>;{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Nullable types (PHP 7.1+)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>function</span> <span style={{ color: "#50fa7b" }}>findUser</span>(<span style={{ color: "#8be9fd" }}>int</span> <span style={{ color: "#ff79c6" }}>$id</span>): <span style={{ color: "#8be9fd" }}>?User</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#ff79c6" }}>$id</span> {">"} <span style={{ color: "#bd93f9" }}>0</span> ? <span style={{ color: "#ff79c6" }}>new</span> User(<span style={{ color: "#ff79c6" }}>$id</span>) : <span style={{ color: "#ff79c6" }}>null</span>;{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Union types (PHP 8+)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>function</span> <span style={{ color: "#50fa7b" }}>process</span>(<span style={{ color: "#8be9fd" }}>string</span>|<span style={{ color: "#8be9fd" }}>int</span> <span style={{ color: "#ff79c6" }}>$input</span>): <span style={{ color: "#8be9fd" }}>string</span>|<span style={{ color: "#8be9fd" }}>int</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#50fa7b" }}>is_string</span>(<span style={{ color: "#ff79c6" }}>$input</span>) ? <span style={{ color: "#50fa7b" }}>strtoupper</span>(<span style={{ color: "#ff79c6" }}>$input</span>) : <span style={{ color: "#ff79c6" }}>$input</span> * <span style={{ color: "#bd93f9" }}>2</span>;{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Default & Named Arguments
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Default parameter values</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>function</span> <span style={{ color: "#50fa7b" }}>createUser</span>({"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>string</span> <span style={{ color: "#ff79c6" }}>$name</span>,{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>string</span> <span style={{ color: "#ff79c6" }}>$role</span> = <span style={{ color: "#f1fa8c" }}>"user"</span>,{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>bool</span> <span style={{ color: "#ff79c6" }}>$active</span> = <span style={{ color: "#ff79c6" }}>true</span>{"\n"}
                ): <span style={{ color: "#8be9fd" }}>array</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#50fa7b" }}>compact</span>(<span style={{ color: "#f1fa8c" }}>'name'</span>, <span style={{ color: "#f1fa8c" }}>'role'</span>, <span style={{ color: "#f1fa8c" }}>'active'</span>);{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Named arguments (PHP 8+)</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>createUser</span>({"\n"}
                {"    "}name: <span style={{ color: "#f1fa8c" }}>"John"</span>,{"\n"}
                {"    "}active: <span style={{ color: "#ff79c6" }}>false</span>  <span style={{ color: "#6272a4" }}>// Skip 'role', use default</span>{"\n"}
                );{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Variadic functions (accept any number of arguments)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>function</span> <span style={{ color: "#50fa7b" }}>sum</span>(<span style={{ color: "#8be9fd" }}>int</span> ...<span style={{ color: "#ff79c6" }}>$numbers</span>): <span style={{ color: "#8be9fd" }}>int</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#50fa7b" }}>array_sum</span>(<span style={{ color: "#ff79c6" }}>$numbers</span>);{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#50fa7b" }}>sum</span>(<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>4</span>, <span style={{ color: "#bd93f9" }}>5</span>);  <span style={{ color: "#6272a4" }}>// 15</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Anonymous Functions & Closures
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Anonymous function (closure)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$greet</span> = <span style={{ color: "#ff79c6" }}>function</span>(<span style={{ color: "#ff79c6" }}>$name</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#f1fa8c" }}>"Hello, $name!"</span>;{"\n"}
                {"}"};{"\n"}
                {"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#ff79c6" }}>$greet</span>(<span style={{ color: "#f1fa8c" }}>"World"</span>);  <span style={{ color: "#6272a4" }}>// "Hello, World!"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Closure with 'use' to capture variables from parent scope</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$multiplier</span> = <span style={{ color: "#bd93f9" }}>3</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>$multiply</span> = <span style={{ color: "#ff79c6" }}>function</span>(<span style={{ color: "#ff79c6" }}>$n</span>) <span style={{ color: "#ff79c6" }}>use</span> (<span style={{ color: "#ff79c6" }}>$multiplier</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#ff79c6" }}>$n</span> * <span style={{ color: "#ff79c6" }}>$multiplier</span>;{"\n"}
                {"}"};{"\n"}
                {"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#ff79c6" }}>$multiply</span>(<span style={{ color: "#bd93f9" }}>5</span>);  <span style={{ color: "#6272a4" }}>// 15</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Modify captured variable by reference</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$count</span> = <span style={{ color: "#bd93f9" }}>0</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>$increment</span> = <span style={{ color: "#ff79c6" }}>function</span>() <span style={{ color: "#ff79c6" }}>use</span> (<span style={{ color: "#ff79c6" }}>&$count</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>$count</span>++;{"\n"}
                {"}"};{"\n"}
                <span style={{ color: "#ff79c6" }}>$increment</span>();{"\n"}
                <span style={{ color: "#ff79c6" }}>$increment</span>();{"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#ff79c6" }}>$count</span>;  <span style={{ color: "#6272a4" }}>// 2</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Arrow Functions (PHP 7.4+)
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Arrow functions: shorter syntax, auto-capture parent scope</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$double</span> = <span style={{ color: "#ff79c6" }}>fn</span>(<span style={{ color: "#ff79c6" }}>$n</span>) ={">"} <span style={{ color: "#ff79c6" }}>$n</span> * <span style={{ color: "#bd93f9" }}>2</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#ff79c6" }}>$double</span>(<span style={{ color: "#bd93f9" }}>5</span>);  <span style={{ color: "#6272a4" }}>// 10</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Arrow functions capture variables automatically (no 'use' needed)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$factor</span> = <span style={{ color: "#bd93f9" }}>3</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>$scale</span> = <span style={{ color: "#ff79c6" }}>fn</span>(<span style={{ color: "#ff79c6" }}>$n</span>) ={">"} <span style={{ color: "#ff79c6" }}>$n</span> * <span style={{ color: "#ff79c6" }}>$factor</span>;  <span style={{ color: "#6272a4" }}>// $factor captured implicitly</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Perfect for array callbacks</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$numbers</span> = [<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>4</span>, <span style={{ color: "#bd93f9" }}>5</span>];{"\n"}
                <span style={{ color: "#ff79c6" }}>$squared</span> = <span style={{ color: "#50fa7b" }}>array_map</span>(<span style={{ color: "#ff79c6" }}>fn</span>(<span style={{ color: "#ff79c6" }}>$n</span>) ={">"} <span style={{ color: "#ff79c6" }}>$n</span> ** <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#ff79c6" }}>$numbers</span>);{"\n"}
                <span style={{ color: "#6272a4" }}>// [1, 4, 9, 16, 25]</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// With type hints</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$isEven</span> = <span style={{ color: "#ff79c6" }}>fn</span>(<span style={{ color: "#8be9fd" }}>int</span> <span style={{ color: "#ff79c6" }}>$n</span>): <span style={{ color: "#8be9fd" }}>bool</span> ={">"} <span style={{ color: "#ff79c6" }}>$n</span> % <span style={{ color: "#bd93f9" }}>2</span> === <span style={{ color: "#bd93f9" }}>0</span>;
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColor, 0.08), border: `1px solid ${alpha(accentColor, 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                Function Best Practices
              </Typography>
              <Typography variant="body2" color="text.secondary" component="div">
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  <li>Always use type declarations for parameters and return types</li>
                  <li>Use <code>declare(strict_types=1)</code> at the top of files for strict type checking</li>
                  <li>Prefer arrow functions for simple one-line callbacks</li>
                  <li>Keep functions small and focused on a single task</li>
                  <li>Use PHPDoc comments for IDE support and documentation</li>
                </ul>
              </Typography>
            </Paper>
          </Paper>

          {/* OOP in PHP Section */}
          <Paper id="oop" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <ClassIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                OOP in PHP
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              PHP's object-oriented programming (OOP) features have matured significantly since PHP 5.
              Modern PHP supports classes, interfaces, traits, abstract classes, and all major OOP concepts
              you'd find in languages like Java or C#.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Classes and Objects
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>User</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Properties</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#8be9fd" }}>string</span> <span style={{ color: "#ff79c6" }}>$name</span>;{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>private</span> <span style={{ color: "#8be9fd" }}>string</span> <span style={{ color: "#ff79c6" }}>$email</span>;{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>protected</span> <span style={{ color: "#8be9fd" }}>int</span> <span style={{ color: "#ff79c6" }}>$age</span>;{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Constructor</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>__construct</span>(<span style={{ color: "#8be9fd" }}>string</span> <span style={{ color: "#ff79c6" }}>$name</span>, <span style={{ color: "#8be9fd" }}>string</span> <span style={{ color: "#ff79c6" }}>$email</span>, <span style={{ color: "#8be9fd" }}>int</span> <span style={{ color: "#ff79c6" }}>$age</span>) {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>$this</span>-{">"}name = <span style={{ color: "#ff79c6" }}>$name</span>;{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>$this</span>-{">"}email = <span style={{ color: "#ff79c6" }}>$email</span>;{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>$this</span>-{">"}age = <span style={{ color: "#ff79c6" }}>$age</span>;{"\n"}
                {"    }"}{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Methods</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>getEmail</span>(): <span style={{ color: "#8be9fd" }}>string</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#ff79c6" }}>$this</span>-{">"}email;{"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Creating objects</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$user</span> = <span style={{ color: "#ff79c6" }}>new</span> User(<span style={{ color: "#f1fa8c" }}>"John"</span>, <span style={{ color: "#f1fa8c" }}>"john@example.com"</span>, <span style={{ color: "#bd93f9" }}>25</span>);{"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#ff79c6" }}>$user</span>-{">"}name;  <span style={{ color: "#6272a4" }}>// "John"</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Constructor Property Promotion (PHP 8+)
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// PHP 8 shorthand: declare and assign in constructor</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Product</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>__construct</span>({"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#8be9fd" }}>string</span> <span style={{ color: "#ff79c6" }}>$name</span>,{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>private</span> <span style={{ color: "#8be9fd" }}>float</span> <span style={{ color: "#ff79c6" }}>$price</span>,{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#8be9fd" }}>int</span> <span style={{ color: "#ff79c6" }}>$stock</span> = <span style={{ color: "#bd93f9" }}>0</span>  <span style={{ color: "#6272a4" }}>// Default value</span>{"\n"}
                {"    ) {}"}{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>getPrice</span>(): <span style={{ color: "#8be9fd" }}>float</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#ff79c6" }}>$this</span>-{">"}price;{"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>$product</span> = <span style={{ color: "#ff79c6" }}>new</span> Product(<span style={{ color: "#f1fa8c" }}>"Widget"</span>, <span style={{ color: "#bd93f9" }}>19.99</span>, <span style={{ color: "#bd93f9" }}>100</span>);
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Static Members & Constants
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Counter</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Class constants</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public const</span> MAX_COUNT = <span style={{ color: "#bd93f9" }}>1000</span>;{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Static property</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>private static</span> <span style={{ color: "#8be9fd" }}>int</span> <span style={{ color: "#ff79c6" }}>$count</span> = <span style={{ color: "#bd93f9" }}>0</span>;{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Static method</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public static function</span> <span style={{ color: "#50fa7b" }}>increment</span>(): <span style={{ color: "#8be9fd" }}>void</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>if</span> (<span style={{ color: "#ff79c6" }}>self</span>::<span style={{ color: "#ff79c6" }}>$count</span> {"<"} <span style={{ color: "#ff79c6" }}>self</span>::MAX_COUNT) {"{"}{"\n"}
                {"            "}<span style={{ color: "#ff79c6" }}>self</span>::<span style={{ color: "#ff79c6" }}>$count</span>++;{"\n"}
                {"        }"}{"\n"}
                {"    }"}{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public static function</span> <span style={{ color: "#50fa7b" }}>getCount</span>(): <span style={{ color: "#8be9fd" }}>int</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#ff79c6" }}>self</span>::<span style={{ color: "#ff79c6" }}>$count</span>;{"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                Counter::<span style={{ color: "#50fa7b" }}>increment</span>();{"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> Counter::<span style={{ color: "#50fa7b" }}>getCount</span>();  <span style={{ color: "#6272a4" }}>// 1</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> Counter::MAX_COUNT;   <span style={{ color: "#6272a4" }}>// 1000</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Visibility Modifiers
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { mod: "public", desc: "Accessible from anywhere - inside the class, child classes, and outside code.", color: "#10b981" },
                { mod: "protected", desc: "Accessible only from the class itself and its child classes (subclasses).", color: "#f59e0b" },
                { mod: "private", desc: "Accessible only from within the class itself. Not inherited by child classes.", color: "#ef4444" },
              ].map((item) => (
                <Grid item xs={12} md={4} key={item.mod}>
                  <Paper sx={{ p: 2, height: "100%", borderRadius: 2, border: `1px solid ${alpha(item.color, 0.3)}` }}>
                    <Chip label={item.mod} size="small" sx={{ mb: 1, bgcolor: alpha(item.color, 0.15), color: item.color, fontWeight: 700 }} />
                    <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColor, 0.08), border: `1px solid ${alpha(accentColor, 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                OOP Best Practices
              </Typography>
              <Typography variant="body2" color="text.secondary" component="div">
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  <li>Use constructor property promotion in PHP 8+ for cleaner code</li>
                  <li>Prefer <code>private</code> by default, expose only what's necessary</li>
                  <li>Use <code>readonly</code> (PHP 8.1+) for immutable properties</li>
                  <li>Follow PSR-4 autoloading standards for class file organization</li>
                </ul>
              </Typography>
            </Paper>
          </Paper>

          {/* Inheritance & Traits Section */}
          <Paper id="inheritance" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <LayersIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Inheritance & Traits
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              PHP supports single inheritance (a class can only extend one parent class), but provides interfaces
              and traits for flexible code reuse. Traits are PHP's solution to the "diamond problem" found in
              languages with multiple inheritance.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Class Inheritance
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Animal</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>protected</span> <span style={{ color: "#8be9fd" }}>string</span> <span style={{ color: "#ff79c6" }}>$name</span>;{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>__construct</span>(<span style={{ color: "#8be9fd" }}>string</span> <span style={{ color: "#ff79c6" }}>$name</span>) {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>$this</span>-{">"}name = <span style={{ color: "#ff79c6" }}>$name</span>;{"\n"}
                {"    }"}{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>speak</span>(): <span style={{ color: "#8be9fd" }}>string</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#f1fa8c" }}>"..."</span>;{"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Dog</span> <span style={{ color: "#ff79c6" }}>extends</span> <span style={{ color: "#8be9fd" }}>Animal</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Override parent method</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>speak</span>(): <span style={{ color: "#8be9fd" }}>string</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#f1fa8c" }}>"</span><span style={{ color: "#ff79c6" }}>{"{"}</span><span style={{ color: "#ff79c6" }}>$this-</span><span style={{ color: "#ff79c6" }}>{">"}name</span><span style={{ color: "#ff79c6" }}>{"}"}</span><span style={{ color: "#f1fa8c" }}> says: Woof!"</span>;{"\n"}
                {"    }"}{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Call parent method</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>fetch</span>(): <span style={{ color: "#8be9fd" }}>string</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#ff79c6" }}>parent</span>::<span style={{ color: "#50fa7b" }}>speak</span>() . <span style={{ color: "#f1fa8c" }}>" *fetches ball*"</span>;{"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>$dog</span> = <span style={{ color: "#ff79c6" }}>new</span> Dog(<span style={{ color: "#f1fa8c" }}>"Buddy"</span>);{"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#ff79c6" }}>$dog</span>-{">"}<span style={{ color: "#50fa7b" }}>speak</span>();  <span style={{ color: "#6272a4" }}>// "Buddy says: Woof!"</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Abstract Classes
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>abstract class</span> <span style={{ color: "#8be9fd" }}>Shape</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Abstract method - must be implemented by child classes</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>abstract public function</span> <span style={{ color: "#50fa7b" }}>area</span>(): <span style={{ color: "#8be9fd" }}>float</span>;{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Concrete method - shared by all children</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>describe</span>(): <span style={{ color: "#8be9fd" }}>string</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#f1fa8c" }}>"Area: "</span> . <span style={{ color: "#ff79c6" }}>$this</span>-{">"}<span style={{ color: "#50fa7b" }}>area</span>();{"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Circle</span> <span style={{ color: "#ff79c6" }}>extends</span> <span style={{ color: "#8be9fd" }}>Shape</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>__construct</span>(<span style={{ color: "#ff79c6" }}>private</span> <span style={{ color: "#8be9fd" }}>float</span> <span style={{ color: "#ff79c6" }}>$radius</span>) {"{}"}{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>area</span>(): <span style={{ color: "#8be9fd" }}>float</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> M_PI * <span style={{ color: "#ff79c6" }}>$this</span>-{">"}radius ** <span style={{ color: "#bd93f9" }}>2</span>;{"\n"}
                {"    }"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Interfaces
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>interface</span> <span style={{ color: "#8be9fd" }}>Printable</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>print</span>(): <span style={{ color: "#8be9fd" }}>string</span>;{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>interface</span> <span style={{ color: "#8be9fd" }}>Serializable</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>serialize</span>(): <span style={{ color: "#8be9fd" }}>string</span>;{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// A class can implement multiple interfaces</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Report</span> <span style={{ color: "#ff79c6" }}>implements</span> <span style={{ color: "#8be9fd" }}>Printable</span>, <span style={{ color: "#8be9fd" }}>Serializable</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>print</span>(): <span style={{ color: "#8be9fd" }}>string</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#f1fa8c" }}>"Report content..."</span>;{"\n"}
                {"    }"}{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>serialize</span>(): <span style={{ color: "#8be9fd" }}>string</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#50fa7b" }}>json_encode</span>([<span style={{ color: "#f1fa8c" }}>'type'</span> ={">"} <span style={{ color: "#f1fa8c" }}>'report'</span>]);{"\n"}
                {"    }"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Traits
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Traits allow horizontal code reuse</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>trait</span> <span style={{ color: "#8be9fd" }}>Timestampable</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#8be9fd" }}>?DateTime</span> <span style={{ color: "#ff79c6" }}>$createdAt</span> = <span style={{ color: "#ff79c6" }}>null</span>;{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#8be9fd" }}>?DateTime</span> <span style={{ color: "#ff79c6" }}>$updatedAt</span> = <span style={{ color: "#ff79c6" }}>null</span>;{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>touch</span>(): <span style={{ color: "#8be9fd" }}>void</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>$this</span>-{">"}updatedAt = <span style={{ color: "#ff79c6" }}>new</span> DateTime();{"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>trait</span> <span style={{ color: "#8be9fd" }}>SoftDeletes</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#8be9fd" }}>?DateTime</span> <span style={{ color: "#ff79c6" }}>$deletedAt</span> = <span style={{ color: "#ff79c6" }}>null</span>;{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>delete</span>(): <span style={{ color: "#8be9fd" }}>void</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>$this</span>-{">"}deletedAt = <span style={{ color: "#ff79c6" }}>new</span> DateTime();{"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Use multiple traits in a class</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Post</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>use</span> Timestampable, SoftDeletes;{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>__construct</span>(<span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#8be9fd" }}>string</span> <span style={{ color: "#ff79c6" }}>$title</span>) {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>$this</span>-{">"}createdAt = <span style={{ color: "#ff79c6" }}>new</span> DateTime();{"\n"}
                {"    }"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColor, 0.08), border: `1px solid ${alpha(accentColor, 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                When to Use Each
              </Typography>
              <Typography variant="body2" color="text.secondary" component="div">
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  <li><strong>Inheritance:</strong> "is-a" relationship (Dog is an Animal)</li>
                  <li><strong>Interface:</strong> Define a contract that classes must follow</li>
                  <li><strong>Trait:</strong> Share common functionality across unrelated classes</li>
                  <li><strong>Abstract class:</strong> Provide partial implementation with some required methods</li>
                </ul>
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

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              PHP uses exceptions for error handling, allowing you to gracefully handle errors and maintain
              clean control flow. Exceptions can be caught, thrown, and even rethrown with additional context.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Try-Catch Basics
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>try</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Code that might throw an exception</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>$file</span> = <span style={{ color: "#50fa7b" }}>fopen</span>(<span style={{ color: "#f1fa8c" }}>'nonexistent.txt'</span>, <span style={{ color: "#f1fa8c" }}>'r'</span>);{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>if</span> (!<span style={{ color: "#ff79c6" }}>$file</span>) {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>throw new</span> Exception(<span style={{ color: "#f1fa8c" }}>'Could not open file'</span>);{"\n"}
                {"    }"}{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>catch</span> (Exception <span style={{ color: "#ff79c6" }}>$e</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Handle the exception</span>{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"Error: "</span> . <span style={{ color: "#ff79c6" }}>$e</span>-{">"}<span style={{ color: "#50fa7b" }}>getMessage</span>();{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"File: "</span> . <span style={{ color: "#ff79c6" }}>$e</span>-{">"}<span style={{ color: "#50fa7b" }}>getFile</span>();{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"Line: "</span> . <span style={{ color: "#ff79c6" }}>$e</span>-{">"}<span style={{ color: "#50fa7b" }}>getLine</span>();{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>finally</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Always executed, even if exception thrown</span>{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"Cleanup complete"</span>;{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Multiple Catch Blocks
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>try</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>$result</span> = <span style={{ color: "#50fa7b" }}>divide</span>(<span style={{ color: "#bd93f9" }}>10</span>, <span style={{ color: "#bd93f9" }}>0</span>);{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>catch</span> (DivisionByZeroError <span style={{ color: "#ff79c6" }}>$e</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"Cannot divide by zero!"</span>;{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>catch</span> (TypeError <span style={{ color: "#ff79c6" }}>$e</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"Invalid argument types!"</span>;{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>catch</span> (Exception <span style={{ color: "#ff79c6" }}>$e</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Catch-all for other exceptions</span>{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"An error occurred: "</span> . <span style={{ color: "#ff79c6" }}>$e</span>-{">"}<span style={{ color: "#50fa7b" }}>getMessage</span>();{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// PHP 8: Catch multiple exception types</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>try</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// ...</span>{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>catch</span> (InvalidArgumentException | OutOfRangeException <span style={{ color: "#ff79c6" }}>$e</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"Argument error: "</span> . <span style={{ color: "#ff79c6" }}>$e</span>-{">"}<span style={{ color: "#50fa7b" }}>getMessage</span>();{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Custom Exceptions
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>ValidationException</span> <span style={{ color: "#ff79c6" }}>extends</span> <span style={{ color: "#8be9fd" }}>Exception</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>private array</span> <span style={{ color: "#ff79c6" }}>$errors</span>;{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>__construct</span>({"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>string</span> <span style={{ color: "#ff79c6" }}>$message</span>,{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>array</span> <span style={{ color: "#ff79c6" }}>$errors</span> = [],{"\n"}
                {"        "}<span style={{ color: "#8be9fd" }}>int</span> <span style={{ color: "#ff79c6" }}>$code</span> = <span style={{ color: "#bd93f9" }}>0</span>,{"\n"}
                {"        "}?Throwable <span style={{ color: "#ff79c6" }}>$previous</span> = <span style={{ color: "#ff79c6" }}>null</span>{"\n"}
                {"    ) {"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>$this</span>-{">"}errors = <span style={{ color: "#ff79c6" }}>$errors</span>;{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>parent</span>::<span style={{ color: "#50fa7b" }}>__construct</span>(<span style={{ color: "#ff79c6" }}>$message</span>, <span style={{ color: "#ff79c6" }}>$code</span>, <span style={{ color: "#ff79c6" }}>$previous</span>);{"\n"}
                {"    }"}{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>getErrors</span>(): <span style={{ color: "#8be9fd" }}>array</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#ff79c6" }}>$this</span>-{">"}errors;{"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Usage</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>throw new</span> ValidationException(<span style={{ color: "#f1fa8c" }}>'Invalid input'</span>, [{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>'email'</span> ={">"} <span style={{ color: "#f1fa8c" }}>'Invalid email format'</span>,{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>'password'</span> ={">"} <span style={{ color: "#f1fa8c" }}>'Password too short'</span>{"\n"}
                ]);
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColor, 0.08), border: `1px solid ${alpha(accentColor, 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                Exception Best Practices
              </Typography>
              <Typography variant="body2" color="text.secondary" component="div">
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  <li>Catch specific exceptions, not just the base <code>Exception</code> class</li>
                  <li>Use <code>finally</code> for cleanup code that must run regardless of exceptions</li>
                  <li>Create custom exceptions for domain-specific errors</li>
                  <li>Log exceptions with full stack traces in production</li>
                  <li>Never swallow exceptions silently (empty catch blocks)</li>
                </ul>
              </Typography>
            </Paper>
          </Paper>

          {/* Forms & Superglobals Section */}
          <Paper id="forms" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <WebIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Forms & Superglobals
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              PHP provides superglobal arrays that are accessible from anywhere in your code. These include
              <code>$_GET</code>, <code>$_POST</code>, <code>$_SESSION</code>, and <code>$_COOKIE</code>
              for handling HTTP requests and maintaining state.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Handling Form Data
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// HTML form</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>&lt;form</span> method=<span style={{ color: "#f1fa8c" }}>"POST"</span> action=<span style={{ color: "#f1fa8c" }}>"process.php"</span><span style={{ color: "#ff79c6" }}>&gt;</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>&lt;input</span> type=<span style={{ color: "#f1fa8c" }}>"text"</span> name=<span style={{ color: "#f1fa8c" }}>"username"</span><span style={{ color: "#ff79c6" }}>&gt;</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>&lt;input</span> type=<span style={{ color: "#f1fa8c" }}>"email"</span> name=<span style={{ color: "#f1fa8c" }}>"email"</span><span style={{ color: "#ff79c6" }}>&gt;</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>&lt;button</span> type=<span style={{ color: "#f1fa8c" }}>"submit"</span><span style={{ color: "#ff79c6" }}>&gt;</span>Submit<span style={{ color: "#ff79c6" }}>&lt;/button&gt;</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>&lt;/form&gt;</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// process.php - Handle POST data</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> (<span style={{ color: "#ff79c6" }}>$_SERVER</span>[<span style={{ color: "#f1fa8c" }}>'REQUEST_METHOD'</span>] === <span style={{ color: "#f1fa8c" }}>'POST'</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>$username</span> = <span style={{ color: "#ff79c6" }}>$_POST</span>[<span style={{ color: "#f1fa8c" }}>'username'</span>] ?? <span style={{ color: "#f1fa8c" }}>''</span>;{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>$email</span> = <span style={{ color: "#ff79c6" }}>$_POST</span>[<span style={{ color: "#f1fa8c" }}>'email'</span>] ?? <span style={{ color: "#f1fa8c" }}>''</span>;{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// $_GET for URL parameters (?id=123)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$id</span> = <span style={{ color: "#ff79c6" }}>$_GET</span>[<span style={{ color: "#f1fa8c" }}>'id'</span>] ?? <span style={{ color: "#ff79c6" }}>null</span>;
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Sessions & Cookies
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Start a session (must be first line before any output)</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>session_start</span>();{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Store session data</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$_SESSION</span>[<span style={{ color: "#f1fa8c" }}>'user_id'</span>] = <span style={{ color: "#bd93f9" }}>123</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>$_SESSION</span>[<span style={{ color: "#f1fa8c" }}>'username'</span>] = <span style={{ color: "#f1fa8c" }}>'john'</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Read session data</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$userId</span> = <span style={{ color: "#ff79c6" }}>$_SESSION</span>[<span style={{ color: "#f1fa8c" }}>'user_id'</span>] ?? <span style={{ color: "#ff79c6" }}>null</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Destroy session (logout)</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>session_destroy</span>();{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Set a cookie (expires in 7 days)</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>setcookie</span>(<span style={{ color: "#f1fa8c" }}>'remember_me'</span>, <span style={{ color: "#f1fa8c" }}>'token123'</span>, [{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>'expires'</span> ={">"} <span style={{ color: "#50fa7b" }}>time</span>() + (<span style={{ color: "#bd93f9" }}>86400</span> * <span style={{ color: "#bd93f9" }}>7</span>),{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>'path'</span> ={">"} <span style={{ color: "#f1fa8c" }}>'/'</span>,{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>'secure'</span> ={">"} <span style={{ color: "#ff79c6" }}>true</span>,{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>'httponly'</span> ={">"} <span style={{ color: "#ff79c6" }}>true</span>,{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>'samesite'</span> ={">"} <span style={{ color: "#f1fa8c" }}>'Strict'</span>{"\n"}
                ]);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Read cookie</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$token</span> = <span style={{ color: "#ff79c6" }}>$_COOKIE</span>[<span style={{ color: "#f1fa8c" }}>'remember_me'</span>] ?? <span style={{ color: "#ff79c6" }}>null</span>;
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Input Validation & Sanitization
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Filter and validate input</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$email</span> = <span style={{ color: "#50fa7b" }}>filter_input</span>(INPUT_POST, <span style={{ color: "#f1fa8c" }}>'email'</span>, FILTER_VALIDATE_EMAIL);{"\n"}
                <span style={{ color: "#ff79c6" }}>$age</span> = <span style={{ color: "#50fa7b" }}>filter_input</span>(INPUT_POST, <span style={{ color: "#f1fa8c" }}>'age'</span>, FILTER_VALIDATE_INT);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Sanitize (clean) input</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$username</span> = <span style={{ color: "#50fa7b" }}>filter_input</span>(INPUT_POST, <span style={{ color: "#f1fa8c" }}>'username'</span>, FILTER_SANITIZE_SPECIAL_CHARS);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Manual validation</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$errors</span> = [];{"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> (<span style={{ color: "#50fa7b" }}>empty</span>(<span style={{ color: "#ff79c6" }}>$username</span>)) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>$errors</span>[] = <span style={{ color: "#f1fa8c" }}>'Username is required'</span>;{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> (!<span style={{ color: "#ff79c6" }}>$email</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>$errors</span>[] = <span style={{ color: "#f1fa8c" }}>'Valid email is required'</span>;{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Escape output to prevent XSS</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#50fa7b" }}>htmlspecialchars</span>(<span style={{ color: "#ff79c6" }}>$username</span>, ENT_QUOTES, <span style={{ color: "#f1fa8c" }}>'UTF-8'</span>);
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#ef4444", 0.08), border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
                Security Warning
              </Typography>
              <Typography variant="body2" color="text.secondary" component="div">
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  <li>Never trust user input - always validate and sanitize</li>
                  <li>Use <code>htmlspecialchars()</code> when outputting user data to prevent XSS</li>
                  <li>Implement CSRF tokens for all forms that change state</li>
                  <li>Set <code>httponly</code> and <code>secure</code> flags on cookies</li>
                </ul>
              </Typography>
            </Paper>
          </Paper>

          {/* Database Access (PDO) Section */}
          <Paper id="database" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <StorageIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Database Access (PDO)
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              PDO (PHP Data Objects) provides a unified interface for accessing different databases.
              It supports prepared statements which prevent SQL injection attacks, making it the
              recommended way to interact with databases in PHP.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Connecting to a Database
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>try</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>$pdo</span> = <span style={{ color: "#ff79c6" }}>new</span> PDO({"\n"}
                {"        "}<span style={{ color: "#f1fa8c" }}>'mysql:host=localhost;dbname=myapp;charset=utf8mb4'</span>,{"\n"}
                {"        "}<span style={{ color: "#f1fa8c" }}>'username'</span>,{"\n"}
                {"        "}<span style={{ color: "#f1fa8c" }}>'password'</span>,{"\n"}
                {"        "}[{"\n"}
                {"            "}PDO::ATTR_ERRMODE ={">"} PDO::ERRMODE_EXCEPTION,{"\n"}
                {"            "}PDO::ATTR_DEFAULT_FETCH_MODE ={">"} PDO::FETCH_ASSOC,{"\n"}
                {"            "}PDO::ATTR_EMULATE_PREPARES ={">"} <span style={{ color: "#ff79c6" }}>false</span>,{"\n"}
                {"        "}]{"\n"}
                {"    );"}{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>catch</span> (PDOException <span style={{ color: "#ff79c6" }}>$e</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>die</span>(<span style={{ color: "#f1fa8c" }}>'Connection failed: '</span> . <span style={{ color: "#ff79c6" }}>$e</span>-{">"}<span style={{ color: "#50fa7b" }}>getMessage</span>());{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Prepared Statements (CRUD)
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// CREATE - Insert data</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$stmt</span> = <span style={{ color: "#ff79c6" }}>$pdo</span>-{">"}<span style={{ color: "#50fa7b" }}>prepare</span>(<span style={{ color: "#f1fa8c" }}>'INSERT INTO users (name, email) VALUES (?, ?)'</span>);{"\n"}
                <span style={{ color: "#ff79c6" }}>$stmt</span>-{">"}<span style={{ color: "#50fa7b" }}>execute</span>([<span style={{ color: "#f1fa8c" }}>'John Doe'</span>, <span style={{ color: "#f1fa8c" }}>'john@example.com'</span>]);{"\n"}
                <span style={{ color: "#ff79c6" }}>$lastId</span> = <span style={{ color: "#ff79c6" }}>$pdo</span>-{">"}<span style={{ color: "#50fa7b" }}>lastInsertId</span>();{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Named placeholders (more readable)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$stmt</span> = <span style={{ color: "#ff79c6" }}>$pdo</span>-{">"}<span style={{ color: "#50fa7b" }}>prepare</span>(<span style={{ color: "#f1fa8c" }}>'INSERT INTO users (name, email) VALUES (:name, :email)'</span>);{"\n"}
                <span style={{ color: "#ff79c6" }}>$stmt</span>-{">"}<span style={{ color: "#50fa7b" }}>execute</span>([<span style={{ color: "#f1fa8c" }}>':name'</span> ={">"} <span style={{ color: "#f1fa8c" }}>'Jane'</span>, <span style={{ color: "#f1fa8c" }}>':email'</span> ={">"} <span style={{ color: "#f1fa8c" }}>'jane@example.com'</span>]);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// READ - Fetch single row</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$stmt</span> = <span style={{ color: "#ff79c6" }}>$pdo</span>-{">"}<span style={{ color: "#50fa7b" }}>prepare</span>(<span style={{ color: "#f1fa8c" }}>'SELECT * FROM users WHERE id = ?'</span>);{"\n"}
                <span style={{ color: "#ff79c6" }}>$stmt</span>-{">"}<span style={{ color: "#50fa7b" }}>execute</span>([<span style={{ color: "#bd93f9" }}>1</span>]);{"\n"}
                <span style={{ color: "#ff79c6" }}>$user</span> = <span style={{ color: "#ff79c6" }}>$stmt</span>-{">"}<span style={{ color: "#50fa7b" }}>fetch</span>();  <span style={{ color: "#6272a4" }}>// Returns associative array or false</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// READ - Fetch all rows</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$stmt</span> = <span style={{ color: "#ff79c6" }}>$pdo</span>-{">"}<span style={{ color: "#50fa7b" }}>prepare</span>(<span style={{ color: "#f1fa8c" }}>'SELECT * FROM users WHERE active = ?'</span>);{"\n"}
                <span style={{ color: "#ff79c6" }}>$stmt</span>-{">"}<span style={{ color: "#50fa7b" }}>execute</span>([<span style={{ color: "#ff79c6" }}>true</span>]);{"\n"}
                <span style={{ color: "#ff79c6" }}>$users</span> = <span style={{ color: "#ff79c6" }}>$stmt</span>-{">"}<span style={{ color: "#50fa7b" }}>fetchAll</span>();{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// UPDATE</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$stmt</span> = <span style={{ color: "#ff79c6" }}>$pdo</span>-{">"}<span style={{ color: "#50fa7b" }}>prepare</span>(<span style={{ color: "#f1fa8c" }}>'UPDATE users SET email = ? WHERE id = ?'</span>);{"\n"}
                <span style={{ color: "#ff79c6" }}>$stmt</span>-{">"}<span style={{ color: "#50fa7b" }}>execute</span>([<span style={{ color: "#f1fa8c" }}>'new@example.com'</span>, <span style={{ color: "#bd93f9" }}>1</span>]);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// DELETE</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$stmt</span> = <span style={{ color: "#ff79c6" }}>$pdo</span>-{">"}<span style={{ color: "#50fa7b" }}>prepare</span>(<span style={{ color: "#f1fa8c" }}>'DELETE FROM users WHERE id = ?'</span>);{"\n"}
                <span style={{ color: "#ff79c6" }}>$stmt</span>-{">"}<span style={{ color: "#50fa7b" }}>execute</span>([<span style={{ color: "#bd93f9" }}>1</span>]);
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Transactions
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>try</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>$pdo</span>-{">"}<span style={{ color: "#50fa7b" }}>beginTransaction</span>();{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Multiple operations that must all succeed</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>$pdo</span>-{">"}<span style={{ color: "#50fa7b" }}>exec</span>(<span style={{ color: "#f1fa8c" }}>"UPDATE accounts SET balance = balance - 100 WHERE id = 1"</span>);{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>$pdo</span>-{">"}<span style={{ color: "#50fa7b" }}>exec</span>(<span style={{ color: "#f1fa8c" }}>"UPDATE accounts SET balance = balance + 100 WHERE id = 2"</span>);{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>$pdo</span>-{">"}<span style={{ color: "#50fa7b" }}>commit</span>();  <span style={{ color: "#6272a4" }}>// All succeeded</span>{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>catch</span> (Exception <span style={{ color: "#ff79c6" }}>$e</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>$pdo</span>-{">"}<span style={{ color: "#50fa7b" }}>rollBack</span>();  <span style={{ color: "#6272a4" }}>// Something failed, undo all</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>throw</span> <span style={{ color: "#ff79c6" }}>$e</span>;{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#10b981", 0.08), border: `1px solid ${alpha("#10b981", 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#10b981" }}>
                PDO Best Practices
              </Typography>
              <Typography variant="body2" color="text.secondary" component="div">
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  <li><strong>Always use prepared statements</strong> - Never concatenate user input into SQL</li>
                  <li>Set <code>ERRMODE_EXCEPTION</code> to catch database errors properly</li>
                  <li>Use <code>FETCH_ASSOC</code> for cleaner array keys</li>
                  <li>Store credentials in environment variables, not in code</li>
                </ul>
              </Typography>
            </Paper>
          </Paper>

          {/* Security Best Practices Section */}
          <Paper id="security" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#ef4444", 0.15), color: "#ef4444", width: 48, height: 48 }}>
                <SecurityIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Security Best Practices
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Security is critical in PHP web applications. Understanding common vulnerabilities and how
              to prevent them is essential for every PHP developer. The OWASP Top 10 outlines the most
              critical web application security risks.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
              Password Hashing
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Hash password for storage (bcrypt by default)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$password</span> = <span style={{ color: "#f1fa8c" }}>'user_password'</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>$hash</span> = <span style={{ color: "#50fa7b" }}>password_hash</span>(<span style={{ color: "#ff79c6" }}>$password</span>, PASSWORD_DEFAULT);{"\n"}
                <span style={{ color: "#6272a4" }}>// Store $hash in database</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Verify password during login</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$submitted</span> = <span style={{ color: "#ff79c6" }}>$_POST</span>[<span style={{ color: "#f1fa8c" }}>'password'</span>];{"\n"}
                <span style={{ color: "#ff79c6" }}>$storedHash</span> = <span style={{ color: "#ff79c6" }}>$user</span>[<span style={{ color: "#f1fa8c" }}>'password_hash'</span>];  <span style={{ color: "#6272a4" }}>// From database</span>{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> (<span style={{ color: "#50fa7b" }}>password_verify</span>(<span style={{ color: "#ff79c6" }}>$submitted</span>, <span style={{ color: "#ff79c6" }}>$storedHash</span>)) {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Password correct</span>{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>else</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Password incorrect</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Check if rehash needed (when algorithm improves)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> (<span style={{ color: "#50fa7b" }}>password_needs_rehash</span>(<span style={{ color: "#ff79c6" }}>$storedHash</span>, PASSWORD_DEFAULT)) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>$newHash</span> = <span style={{ color: "#50fa7b" }}>password_hash</span>(<span style={{ color: "#ff79c6" }}>$submitted</span>, PASSWORD_DEFAULT);{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Update hash in database</span>{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
              CSRF Protection
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Generate CSRF token</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>session_start</span>();{"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> (<span style={{ color: "#50fa7b" }}>empty</span>(<span style={{ color: "#ff79c6" }}>$_SESSION</span>[<span style={{ color: "#f1fa8c" }}>'csrf_token'</span>])) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>$_SESSION</span>[<span style={{ color: "#f1fa8c" }}>'csrf_token'</span>] = <span style={{ color: "#50fa7b" }}>bin2hex</span>(<span style={{ color: "#50fa7b" }}>random_bytes</span>(<span style={{ color: "#bd93f9" }}>32</span>));{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Include in form</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>&lt;input</span> type=<span style={{ color: "#f1fa8c" }}>"hidden"</span> name=<span style={{ color: "#f1fa8c" }}>"csrf_token"</span>{"\n"}
                {"       "}value=<span style={{ color: "#f1fa8c" }}>"&lt;?= $_SESSION['csrf_token'] ?&gt;"</span><span style={{ color: "#ff79c6" }}>&gt;</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Validate on form submission</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> (!<span style={{ color: "#50fa7b" }}>hash_equals</span>(<span style={{ color: "#ff79c6" }}>$_SESSION</span>[<span style={{ color: "#f1fa8c" }}>'csrf_token'</span>], <span style={{ color: "#ff79c6" }}>$_POST</span>[<span style={{ color: "#f1fa8c" }}>'csrf_token'</span>] ?? <span style={{ color: "#f1fa8c" }}>''</span>)) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>die</span>(<span style={{ color: "#f1fa8c" }}>'CSRF token validation failed'</span>);{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
              XSS Prevention
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// ALWAYS escape user output</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$userInput</span> = <span style={{ color: "#ff79c6" }}>$_GET</span>[<span style={{ color: "#f1fa8c" }}>'search'</span>];{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// WRONG - XSS vulnerable!</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"Search results for: $userInput"</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// CORRECT - Escaped output</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#f1fa8c" }}>"Search results for: "</span> . <span style={{ color: "#50fa7b" }}>htmlspecialchars</span>(<span style={{ color: "#ff79c6" }}>$userInput</span>, ENT_QUOTES, <span style={{ color: "#f1fa8c" }}>'UTF-8'</span>);{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// For JSON responses</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>header</span>(<span style={{ color: "#f1fa8c" }}>'Content-Type: application/json'</span>);{"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#50fa7b" }}>json_encode</span>(<span style={{ color: "#ff79c6" }}>$data</span>, JSON_HEX_TAG | JSON_HEX_AMP);
              </Typography>
            </Paper>

            <Grid container spacing={2}>
              {[
                { vuln: "SQL Injection", fix: "Use prepared statements with PDO or MySQLi", color: "#ef4444" },
                { vuln: "XSS", fix: "Use htmlspecialchars() on all user output", color: "#f59e0b" },
                { vuln: "CSRF", fix: "Implement token-based verification for forms", color: "#8b5cf6" },
                { vuln: "Password Storage", fix: "Use password_hash() with PASSWORD_DEFAULT", color: "#10b981" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.vuln}>
                  <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha(item.color, 0.3)}` }}>
                    <Chip label={item.vuln} size="small" sx={{ mb: 1, bgcolor: alpha(item.color, 0.15), color: item.color, fontWeight: 700 }} />
                    <Typography variant="body2" color="text.secondary">{item.fix}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Modern PHP (8.x) Section */}
          <Paper id="modern" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <AutoFixHighIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Modern PHP (8.x)
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              PHP 8.x brings significant improvements including JIT compilation, union types, attributes,
              named arguments, and many quality-of-life enhancements that make code cleaner and more expressive.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Match Expression (PHP 8.0+)
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// match - more powerful than switch</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$status</span> = <span style={{ color: "#bd93f9" }}>200</span>;{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>$message</span> = <span style={{ color: "#ff79c6" }}>match</span>(<span style={{ color: "#ff79c6" }}>$status</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#bd93f9" }}>200</span>, <span style={{ color: "#bd93f9" }}>201</span> ={">"} <span style={{ color: "#f1fa8c" }}>'Success'</span>,{"\n"}
                {"    "}<span style={{ color: "#bd93f9" }}>400</span> ={">"} <span style={{ color: "#f1fa8c" }}>'Bad Request'</span>,{"\n"}
                {"    "}<span style={{ color: "#bd93f9" }}>404</span> ={">"} <span style={{ color: "#f1fa8c" }}>'Not Found'</span>,{"\n"}
                {"    "}<span style={{ color: "#bd93f9" }}>500</span> ={">"} <span style={{ color: "#f1fa8c" }}>'Server Error'</span>,{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>default</span> ={">"} <span style={{ color: "#f1fa8c" }}>'Unknown Status'</span>,{"\n"}
                {"}"};{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// match returns a value and uses strict comparison</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Nullsafe Operator (PHP 8.0+)
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Old way - null checks everywhere</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$country</span> = <span style={{ color: "#ff79c6" }}>null</span>;{"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> (<span style={{ color: "#ff79c6" }}>$user</span> !== <span style={{ color: "#ff79c6" }}>null</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>if</span> (<span style={{ color: "#ff79c6" }}>$user</span>-{">"}address !== <span style={{ color: "#ff79c6" }}>null</span>) {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>$country</span> = <span style={{ color: "#ff79c6" }}>$user</span>-{">"}address-{">"}country;{"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// PHP 8 - Nullsafe operator ?-{">"}</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$country</span> = <span style={{ color: "#ff79c6" }}>$user</span>?-{">"}address?-{">"}country;  <span style={{ color: "#6272a4" }}>// Returns null if any is null</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Works with method calls too</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$name</span> = <span style={{ color: "#ff79c6" }}>$user</span>?-{">"}<span style={{ color: "#50fa7b" }}>getProfile</span>()?-{">"}<span style={{ color: "#50fa7b" }}>getName</span>();
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Enums (PHP 8.1+)
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Basic enum</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>enum</span> <span style={{ color: "#8be9fd" }}>Status</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> Pending;{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> Active;{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> Archived;{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Backed enum (with values)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>enum</span> <span style={{ color: "#8be9fd" }}>Role</span>: <span style={{ color: "#8be9fd" }}>string</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> Admin = <span style={{ color: "#f1fa8c" }}>'admin'</span>;{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> Editor = <span style={{ color: "#f1fa8c" }}>'editor'</span>;{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>case</span> Viewer = <span style={{ color: "#f1fa8c" }}>'viewer'</span>;{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>canEdit</span>(): <span style={{ color: "#8be9fd" }}>bool</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#ff79c6" }}>$this</span> !== <span style={{ color: "#ff79c6" }}>self</span>::Viewer;{"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>$role</span> = Role::Admin;{"\n"}
                <span style={{ color: "#50fa7b" }}>echo</span> <span style={{ color: "#ff79c6" }}>$role</span>-{">"}value;  <span style={{ color: "#6272a4" }}>// "admin"</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Readonly Properties (PHP 8.1+)
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>User</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>__construct</span>({"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>public readonly</span> <span style={{ color: "#8be9fd" }}>string</span> <span style={{ color: "#ff79c6" }}>$id</span>,{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>public readonly</span> <span style={{ color: "#8be9fd" }}>string</span> <span style={{ color: "#ff79c6" }}>$email</span>,{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#8be9fd" }}>string</span> <span style={{ color: "#ff79c6" }}>$name</span>  <span style={{ color: "#6272a4" }}>// This one can be modified</span>{"\n"}
                {"    ) {}"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>$user</span> = <span style={{ color: "#ff79c6" }}>new</span> User(<span style={{ color: "#f1fa8c" }}>'123'</span>, <span style={{ color: "#f1fa8c" }}>'john@example.com'</span>, <span style={{ color: "#f1fa8c" }}>'John'</span>);{"\n"}
                <span style={{ color: "#ff79c6" }}>$user</span>-{">"}name = <span style={{ color: "#f1fa8c" }}>'Jane'</span>;  <span style={{ color: "#6272a4" }}>// OK</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$user</span>-{">"}id = <span style={{ color: "#f1fa8c" }}>'456'</span>;     <span style={{ color: "#6272a4" }}>// Error! Cannot modify readonly</span>
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColor, 0.08), border: `1px solid ${alpha(accentColor, 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                Other PHP 8+ Features
              </Typography>
              <Typography variant="body2" color="text.secondary" component="div">
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  <li><strong>Union Types:</strong> <code>function foo(int|string $value)</code></li>
                  <li><strong>Attributes:</strong> <code>#[Route('/api')]</code> instead of docblocks</li>
                  <li><strong>Fibers:</strong> Lightweight cooperative multitasking (PHP 8.1+)</li>
                  <li><strong>JIT Compilation:</strong> Just-in-time compilation for performance</li>
                </ul>
              </Typography>
            </Paper>
          </Paper>

          {/* Frameworks & Ecosystem Section */}
          <Paper id="frameworks" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <IntegrationInstructionsIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Frameworks & Ecosystem
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Modern PHP development relies heavily on frameworks and tools that provide structure, security,
              and productivity. The PHP ecosystem has matured with PSR standards, Composer, and world-class frameworks.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Popular Frameworks
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { name: "Laravel", desc: "Full-featured framework with elegant syntax, Eloquent ORM, Blade templating, queues, and extensive ecosystem.", color: "#FF2D20", type: "Full-Stack" },
                { name: "Symfony", desc: "Enterprise-grade framework with reusable components. Powers many apps and other frameworks including Laravel.", color: "#000000", type: "Enterprise" },
                { name: "Slim", desc: "Micro-framework for APIs and small apps. Minimal overhead, PSR-7 compliant, perfect for microservices.", color: "#719e40", type: "Micro" },
                { name: "CodeIgniter", desc: "Lightweight MVC framework. Fast, simple, minimal configuration. Great for beginners.", color: "#EF4423", type: "Lightweight" },
              ].map((fw) => (
                <Grid item xs={12} sm={6} key={fw.name}>
                  <Paper sx={{ p: 2, height: "100%", borderRadius: 2, border: `1px solid ${alpha(fw.color, 0.3)}` }}>
                    <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                      <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{fw.name}</Typography>
                      <Chip label={fw.type} size="small" sx={{ bgcolor: alpha(fw.color, 0.15), color: fw.color, fontWeight: 600 }} />
                    </Box>
                    <Typography variant="body2" color="text.secondary">{fw.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Essential Tools
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}># Composer - Dependency management</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>composer</span> require monolog/monolog{"\n"}
                <span style={{ color: "#8be9fd" }}>composer</span> install{"\n"}
                <span style={{ color: "#8be9fd" }}>composer</span> update{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># PHPUnit - Testing</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>./vendor/bin/phpunit</span> tests/{"\n"}
                <span style={{ color: "#8be9fd" }}>./vendor/bin/phpunit</span> --coverage-html coverage/{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># PHP CS Fixer - Code style</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>./vendor/bin/php-cs-fixer</span> fix src/{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># PHPStan - Static analysis</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>./vendor/bin/phpstan</span> analyse src/
              </Typography>
            </Paper>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColor, 0.08), border: `1px solid ${alpha(accentColor, 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                PSR Standards
              </Typography>
              <Typography variant="body2" color="text.secondary" component="div">
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  <li><strong>PSR-4:</strong> Autoloading standard - how classes map to files</li>
                  <li><strong>PSR-7:</strong> HTTP Message interfaces for interoperability</li>
                  <li><strong>PSR-12:</strong> Extended coding style guide</li>
                  <li><strong>PSR-15:</strong> HTTP Server Request Handlers (middleware)</li>
                </ul>
              </Typography>
            </Paper>
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

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Advanced PHP development involves design patterns, dependency injection, and architectural
              patterns that enable building scalable, maintainable applications.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Dependency Injection
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Without DI - tightly coupled, hard to test</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>UserService</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>private</span> <span style={{ color: "#ff79c6" }}>$db</span>;{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>__construct</span>() {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>$this</span>-{">"}db = <span style={{ color: "#ff79c6" }}>new</span> Database();  <span style={{ color: "#6272a4" }}>// Bad!</span>{"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// With DI - loosely coupled, testable</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>UserService</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>__construct</span>({"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>private</span> <span style={{ color: "#8be9fd" }}>DatabaseInterface</span> <span style={{ color: "#ff79c6" }}>$db</span>{"\n"}
                {"    ) {}"}{"\n"}
                {"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public function</span> <span style={{ color: "#50fa7b" }}>findUser</span>(<span style={{ color: "#8be9fd" }}>int</span> <span style={{ color: "#ff79c6" }}>$id</span>): <span style={{ color: "#8be9fd" }}>?User</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#ff79c6" }}>$this</span>-{">"}db-{">"}<span style={{ color: "#50fa7b" }}>find</span>(<span style={{ color: "#f1fa8c" }}>'users'</span>, <span style={{ color: "#ff79c6" }}>$id</span>);{"\n"}
                {"    }"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Usage</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>$service</span> = <span style={{ color: "#ff79c6" }}>new</span> UserService(<span style={{ color: "#ff79c6" }}>new</span> MySQLDatabase());
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Common Design Patterns
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { pattern: "Singleton", desc: "Ensures only one instance of a class exists globally.", use: "Database connections, logging" },
                { pattern: "Factory", desc: "Creates objects without specifying exact class.", use: "Creating related objects dynamically" },
                { pattern: "Repository", desc: "Abstracts data layer from business logic.", use: "Database access, API clients" },
                { pattern: "Strategy", desc: "Defines family of algorithms, makes them interchangeable.", use: "Payment processing, sorting" },
              ].map((p) => (
                <Grid item xs={12} sm={6} key={p.pattern}>
                  <Paper sx={{ p: 2, height: "100%", borderRadius: 2, border: `1px solid ${alpha(accentColor, 0.2)}` }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 0.5 }}>{p.pattern}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{p.desc}</Typography>
                    <Typography variant="caption" color="text.secondary"><strong>Use case:</strong> {p.use}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColor, 0.08), border: `1px solid ${alpha(accentColor, 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                Additional Advanced Topics
              </Typography>
              <Typography variant="body2" color="text.secondary" component="div">
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  <li><strong>Queue Systems:</strong> Redis, RabbitMQ, Laravel Horizon for background jobs</li>
                  <li><strong>API Development:</strong> RESTful APIs, GraphQL with webonyx/graphql-php</li>
                  <li><strong>WebSockets:</strong> Ratchet, Laravel WebSockets for real-time apps</li>
                  <li><strong>Microservices:</strong> Slim Framework, Swoole for high-performance services</li>
                </ul>
              </Typography>
            </Paper>
          </Paper>

          {/* PHP Quiz Section */}
          <PHPQuiz />
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
