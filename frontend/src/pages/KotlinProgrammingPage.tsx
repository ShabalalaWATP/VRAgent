import React, { useState, useMemo, useEffect, useCallback } from "react";
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
  Radio,
  RadioGroup,
  FormControlLabel,
  FormControl,
  Button,
  LinearProgress,
  Collapse,
  IconButton,
  Tooltip,
  ToggleButton,
  ToggleButtonGroup,
  Badge,
  Fade,
  Zoom,
} from "@mui/material";
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
import CloudIcon from "@mui/icons-material/Cloud";
import SyncIcon from "@mui/icons-material/Sync";
import DataObjectIcon from "@mui/icons-material/DataObject";
import SwapHorizIcon from "@mui/icons-material/SwapHoriz";
import CategoryIcon from "@mui/icons-material/Category";
import ClassIcon from "@mui/icons-material/Class";
import IntegrationInstructionsIcon from "@mui/icons-material/IntegrationInstructions";
import AndroidIcon from "@mui/icons-material/Android";
import PhoneAndroidIcon from "@mui/icons-material/PhoneAndroid";
import SpeedIcon from "@mui/icons-material/Speed";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import TimerIcon from "@mui/icons-material/Timer";
import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutline";
import CancelOutlinedIcon from "@mui/icons-material/CancelOutlined";
import FilterListIcon from "@mui/icons-material/FilterList";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import StarIcon from "@mui/icons-material/Star";
import StarBorderIcon from "@mui/icons-material/StarBorder";
import StarHalfIcon from "@mui/icons-material/StarHalf";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import LearnPageLayout from "../components/LearnPageLayout";

const accentColor = "#7F52FF"; // Kotlin's official purple
const accentColorDark = "#E44857"; // Kotlin's secondary orange/red

// Quiz Types and Interfaces
interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  category: string;
  difficulty: 'easy' | 'medium' | 'hard';
}

type QuizCategory = 'all' | 'basics' | 'null-safety' | 'functions' | 'collections' | 'oop' | 'coroutines' | 'advanced';
type QuizDifficulty = 'all' | 'easy' | 'medium' | 'hard';

// 75-Question Bank for Kotlin
const kotlinQuestionBank: QuizQuestion[] = [
  // BASICS (1-15)
  { id: 1, question: "What keyword is used to declare an immutable variable in Kotlin?", options: ["var", "val", "const", "let"], correctAnswer: 1, explanation: "'val' declares a read-only (immutable) variable in Kotlin. Once assigned, it cannot be reassigned. 'var' is for mutable variables.", category: "basics", difficulty: "easy" },
  { id: 2, question: "How do you declare a nullable String in Kotlin?", options: ["String?", "String!", "Optional<String>", "Nullable<String>"], correctAnswer: 0, explanation: "In Kotlin, you append '?' to a type to make it nullable. 'String?' can hold a String or null, while 'String' cannot be null.", category: "basics", difficulty: "easy" },
  { id: 3, question: "What is the entry point of a Kotlin program?", options: ["class Main", "public static void main", "fun main()", "def main():"], correctAnswer: 2, explanation: "The entry point is 'fun main()' or 'fun main(args: Array<String>)'. Unlike Java, it doesn't need to be inside a class.", category: "basics", difficulty: "easy" },
  { id: 4, question: "How do you use string interpolation in Kotlin?", options: ["\"Hello \" + name", "\"Hello ${name}\"", "f\"Hello {name}\"", "\"Hello %s\" % name"], correctAnswer: 1, explanation: "Kotlin uses string templates with $ for simple variables ($name) or ${} for expressions (${name.length}).", category: "basics", difficulty: "easy" },
  { id: 5, question: "Which statement is true about Kotlin classes?", options: ["Classes are open by default", "Classes are final by default", "Classes must extend Object", "Classes require public modifier"], correctAnswer: 1, explanation: "Kotlin classes are final by default. You must use the 'open' modifier to allow inheritance, promoting composition over inheritance.", category: "basics", difficulty: "medium" },
  { id: 6, question: "What does the 'when' expression replace from Java?", options: ["if-else", "switch", "try-catch", "for loop"], correctAnswer: 1, explanation: "'when' is Kotlin's replacement for switch statements, but is more powerful - it's an expression, supports pattern matching, ranges, and type checking.", category: "basics", difficulty: "easy" },
  { id: 7, question: "How do you create a range from 1 to 10 in Kotlin?", options: ["[1:10]", "range(1, 10)", "1..10", "1 to 10"], correctAnswer: 2, explanation: "The '..' operator creates an inclusive range. '1..10' creates IntRange from 1 to 10 inclusive. Use 'until' for exclusive end.", category: "basics", difficulty: "easy" },
  { id: 8, question: "What is the default visibility modifier in Kotlin?", options: ["private", "protected", "internal", "public"], correctAnswer: 3, explanation: "Unlike Java where default is package-private, Kotlin's default visibility is 'public'. This makes declarations visible everywhere.", category: "basics", difficulty: "medium" },
  { id: 9, question: "How do you define a constant in Kotlin?", options: ["const val", "static final", "final val", "constant"], correctAnswer: 0, explanation: "'const val' defines compile-time constants. They must be top-level or in companion objects, and can only be String or primitives.", category: "basics", difficulty: "medium" },
  { id: 10, question: "What is Unit in Kotlin?", options: ["A testing framework", "A measurement class", "Equivalent to void in Java", "A singleton pattern"], correctAnswer: 2, explanation: "Unit is Kotlin's equivalent to Java's void. It's a type with exactly one value (Unit). Functions that don't return anything return Unit.", category: "basics", difficulty: "easy" },
  { id: 11, question: "Which loop syntax iterates with index in Kotlin?", options: ["for (i = 0; i < n; i++)", "for i in range(n)", "for ((index, value) in list.withIndex())", "foreach (var item in list)"], correctAnswer: 2, explanation: "Use 'withIndex()' to get both index and value: for ((index, value) in list.withIndex()). This is cleaner than manual index tracking.", category: "basics", difficulty: "medium" },
  { id: 12, question: "How do you check if a value is in a range?", options: ["range.contains(x)", "x in range", "range.has(x)", "Both A and B"], correctAnswer: 3, explanation: "Both 'x in range' and 'range.contains(x)' work. The 'in' operator calls contains() internally but is more idiomatic.", category: "basics", difficulty: "easy" },
  { id: 13, question: "What does 'internal' visibility modifier mean?", options: ["Only this file", "Only this class", "Visible within the same module", "Visible to subclasses"], correctAnswer: 2, explanation: "'internal' makes declarations visible throughout the same module (a set of Kotlin files compiled together). Useful for library APIs.", category: "basics", difficulty: "medium" },
  { id: 14, question: "How do you convert a String to Int safely?", options: ["String.toInt()", "String.toIntOrNull()", "parseInt(String)", "Int(String)"], correctAnswer: 1, explanation: "'toIntOrNull()' returns null instead of throwing an exception if the string can't be parsed. Use it for safe parsing.", category: "basics", difficulty: "easy" },
  { id: 15, question: "What's the difference between == and === in Kotlin?", options: ["No difference", "== is structural, === is referential", "== is reference, === is value", "=== doesn't exist in Kotlin"], correctAnswer: 1, explanation: "'==' checks structural equality (calls equals()). '===' checks referential equality (same object in memory). Unlike Java where == is reference.", category: "basics", difficulty: "medium" },

  // NULL SAFETY (16-30)
  { id: 16, question: "What does the safe call operator (?.) do?", options: ["Throws if null", "Returns null if receiver is null", "Converts to non-null", "Creates nullable type"], correctAnswer: 1, explanation: "The safe call (?.) returns null if the receiver is null instead of throwing NPE. 'name?.length' returns null if name is null.", category: "null-safety", difficulty: "easy" },
  { id: 17, question: "What is the Elvis operator in Kotlin?", options: ["!!", "?.", "?:", "?.let"], correctAnswer: 2, explanation: "The Elvis operator (?:) provides a default value when the left side is null. 'name ?: \"Unknown\"' returns \"Unknown\" if name is null.", category: "null-safety", difficulty: "easy" },
  { id: 18, question: "What does the !! operator do?", options: ["Null check", "Converts to non-null, throws NPE if null", "Safe cast", "Optional unwrap"], correctAnswer: 1, explanation: "The not-null assertion operator (!!) converts a nullable to non-nullable, but throws NullPointerException if the value is null.", category: "null-safety", difficulty: "easy" },
  { id: 19, question: "What is a smart cast in Kotlin?", options: ["Automatic type inference", "Compiler tracks null checks and auto-casts", "Runtime type conversion", "Generic type casting"], correctAnswer: 1, explanation: "Smart cast means the compiler automatically casts types after null/type checks. After 'if (x != null)', x is treated as non-nullable.", category: "null-safety", difficulty: "medium" },
  { id: 20, question: "What does 'as?' do in Kotlin?", options: ["Unsafe cast", "Safe cast (returns null on failure)", "Type check", "Null assertion"], correctAnswer: 1, explanation: "'as?' is a safe cast that returns null instead of throwing ClassCastException if the cast fails. Use for defensive casting.", category: "null-safety", difficulty: "medium" },
  { id: 21, question: "How do you execute code only if a value is not null?", options: ["if (value != null) {}", "value?.let { }", "value.ifNotNull { }", "Both A and B"], correctAnswer: 3, explanation: "Both work! 'if (value != null)' uses smart cast. 'value?.let { }' is more idiomatic and scopes the non-null value as 'it'.", category: "null-safety", difficulty: "easy" },
  { id: 22, question: "What's the purpose of 'lateinit var'?", options: ["Lazy initialization", "Delayed initialization of non-null property", "Constant declaration", "Thread-safe initialization"], correctAnswer: 1, explanation: "'lateinit' allows delaying initialization of a non-null property. Useful for dependency injection. Access before init throws UninitializedPropertyAccessException.", category: "null-safety", difficulty: "medium" },
  { id: 23, question: "Can 'lateinit' be used with val?", options: ["Yes", "No", "Only with primitives", "Only in constructors"], correctAnswer: 1, explanation: "'lateinit' can only be used with 'var', not 'val'. Since lateinit values are assigned later, they must be mutable.", category: "null-safety", difficulty: "medium" },
  { id: 24, question: "What does 'value?.let { } ?: run { }' pattern do?", options: ["Null check only", "Execute different code for null vs non-null", "Type casting", "Error handling"], correctAnswer: 1, explanation: "This pattern executes the let block if value is non-null, otherwise executes the run block. It's like if-else for nullable values.", category: "null-safety", difficulty: "hard" },
  { id: 25, question: "How do you check if a lateinit property is initialized?", options: ["property != null", "::property.isInitialized", "property.initialized", "isInitialized(property)"], correctAnswer: 1, explanation: "Use '::propertyName.isInitialized' to check if a lateinit property has been initialized before accessing it.", category: "null-safety", difficulty: "hard" },
  { id: 26, question: "What's the difference between 'let' and 'also'?", options: ["let returns lambda result, also returns context", "also returns lambda result, let returns context", "No difference", "let is for nullables only"], correctAnswer: 0, explanation: "'let' returns the lambda result (good for transformations). 'also' returns the context object (good for side effects like logging).", category: "null-safety", difficulty: "medium" },
  { id: 27, question: "What does 'apply' scope function do?", options: ["Transforms and returns result", "Configures object and returns it", "Performs side effect", "Null check"], correctAnswer: 1, explanation: "'apply' configures an object using 'this' context and returns the object itself. Perfect for object configuration/initialization.", category: "null-safety", difficulty: "medium" },
  { id: 28, question: "When should you use 'run' scope function?", options: ["Object configuration", "When you need 'this' context and want the lambda result", "Side effects only", "Null checks only"], correctAnswer: 1, explanation: "'run' provides 'this' context (like apply) but returns the lambda result (like let). Use for computing a value with object context.", category: "null-safety", difficulty: "hard" },
  { id: 29, question: "What's the safest way to chain nullable calls?", options: ["Multiple null checks", "Safe calls: a?.b?.c?.d", "Not-null assertions: a!!.b!!.c!!.d!!", "Try-catch blocks"], correctAnswer: 1, explanation: "Chain safe calls: 'a?.b?.c?.d' safely returns null if any part is null. Never chain !! as it defeats null safety.", category: "null-safety", difficulty: "easy" },
  { id: 30, question: "What does 'requireNotNull(value)' do?", options: ["Returns value or null", "Returns value or throws IllegalArgumentException", "Converts to nullable", "Checks at compile time"], correctAnswer: 1, explanation: "'requireNotNull()' returns the value if non-null, otherwise throws IllegalArgumentException. Use for parameter validation.", category: "null-safety", difficulty: "medium" },

  // FUNCTIONS (31-45)
  { id: 31, question: "How do you define a single-expression function?", options: ["fun add(a: Int, b: Int) { return a + b }", "fun add(a: Int, b: Int) = a + b", "def add(a, b) = a + b", "function add(a, b) => a + b"], correctAnswer: 1, explanation: "Single-expression functions use '=' instead of braces and 'return'. The return type is inferred. Much more concise for simple functions.", category: "functions", difficulty: "easy" },
  { id: 32, question: "What are default arguments in Kotlin?", options: ["Arguments that must be provided", "Arguments with predefined values if not passed", "Arguments with null values", "Variable arguments"], correctAnswer: 1, explanation: "Default arguments have predefined values: 'fun greet(name: String = \"World\")'. Callers can omit them, reducing overload explosion.", category: "functions", difficulty: "easy" },
  { id: 33, question: "What are named arguments?", options: ["Arguments passed by position", "Arguments specified by parameter name", "Arguments with default values", "Variable length arguments"], correctAnswer: 1, explanation: "Named arguments specify parameter names: 'greet(name = \"Alice\")'. They allow any order and improve readability for many parameters.", category: "functions", difficulty: "easy" },
  { id: 34, question: "What is an extension function?", options: ["A function in an extended class", "A function added to existing class without inheriting", "A function with variable arguments", "A recursive function"], correctAnswer: 1, explanation: "Extension functions add methods to existing classes: 'fun String.addBang() = this + \"!\"'. Called like member functions but defined outside.", category: "functions", difficulty: "medium" },
  { id: 35, question: "What is an infix function?", options: ["A prefix function", "A function called between two values without dot/parentheses", "A function with two parameters", "An operator function"], correctAnswer: 1, explanation: "Infix functions are called without dot/parentheses: '1 to 2'. Must be member/extension, have single parameter, and use 'infix' modifier.", category: "functions", difficulty: "medium" },
  { id: 36, question: "What does 'vararg' do in Kotlin?", options: ["Creates variable", "Allows variable number of arguments", "Creates array", "Defines variance"], correctAnswer: 1, explanation: "'vararg' allows passing variable number of arguments: 'fun printAll(vararg items: String)'. Internally treated as an array.", category: "functions", difficulty: "easy" },
  { id: 37, question: "How do you pass an array to a vararg parameter?", options: ["Just pass the array", "Use spread operator: *array", "Use arrayOf()", "Convert to list first"], correctAnswer: 1, explanation: "Use the spread operator (*) to unpack an array into vararg: 'printAll(*myArray)'. Otherwise, the array itself is one argument.", category: "functions", difficulty: "medium" },
  { id: 38, question: "What is a higher-order function?", options: ["A function that returns Int", "A function that takes or returns functions", "A function in a parent class", "A recursive function"], correctAnswer: 1, explanation: "Higher-order functions take functions as parameters or return functions. They enable functional programming patterns like map, filter.", category: "functions", difficulty: "medium" },
  { id: 39, question: "What is the 'inline' modifier used for?", options: ["Inline comments", "Inline a function's body at call site", "Single-line functions", "Private functions"], correctAnswer: 1, explanation: "'inline' copies the function body to the call site, avoiding function call overhead. Essential for lambdas to avoid object creation.", category: "functions", difficulty: "hard" },
  { id: 40, question: "What does 'noinline' do?", options: ["Prevents inlining of specific lambda parameter", "Prevents function inlining", "Disables null checks", "Forces synchronous execution"], correctAnswer: 0, explanation: "'noinline' prevents inlining a specific lambda parameter in an inline function. Needed if you want to store the lambda.", category: "functions", difficulty: "hard" },
  { id: 41, question: "What is a local function?", options: ["A function in local scope", "A function defined inside another function", "A private function", "An anonymous function"], correctAnswer: 1, explanation: "Local functions are defined inside other functions. They can access outer function's variables (closure) and help organize code.", category: "functions", difficulty: "medium" },
  { id: 42, question: "How do you declare a lambda in Kotlin?", options: ["lambda x: x + 1", "{ x -> x + 1 }", "(x) => x + 1", "function(x) { x + 1 }"], correctAnswer: 1, explanation: "Lambdas use braces with parameters before '->': { x -> x + 1 }. Single parameter can use implicit 'it': { it + 1 }.", category: "functions", difficulty: "easy" },
  { id: 43, question: "What is 'it' in a lambda?", options: ["Iterator variable", "Implicit name for single parameter", "Current object reference", "Loop index"], correctAnswer: 1, explanation: "'it' is the implicit name for a lambda's single parameter. Instead of { x -> x * 2 }, you can write { it * 2 }.", category: "functions", difficulty: "easy" },
  { id: 44, question: "What does 'crossinline' modifier do?", options: ["Allows non-local returns", "Prevents non-local returns in inlined lambda", "Creates inline function", "Enables recursion"], correctAnswer: 1, explanation: "'crossinline' prevents non-local returns from a lambda that might be called in a different context (like another thread).", category: "functions", difficulty: "hard" },
  { id: 45, question: "How do you reference a function?", options: ["functionName()", "::functionName", "&functionName", "ref(functionName)"], correctAnswer: 1, explanation: "Use '::functionName' to get a function reference. Can pass to higher-order functions: 'list.map(::transform)'.", category: "functions", difficulty: "medium" },

  // COLLECTIONS (46-55)
  { id: 46, question: "What's the difference between listOf() and mutableListOf()?", options: ["listOf creates array, mutableListOf creates list", "listOf is read-only, mutableListOf is modifiable", "No difference", "listOf is faster"], correctAnswer: 1, explanation: "'listOf()' creates an immutable list (read-only view). 'mutableListOf()' creates a MutableList that can be modified.", category: "collections", difficulty: "easy" },
  { id: 47, question: "How do you transform each element in a collection?", options: ["forEach { }", "map { }", "transform { }", "convert { }"], correctAnswer: 1, explanation: "'map' transforms each element and returns a new list: list.map { it * 2 }. Use 'forEach' for side effects without new list.", category: "collections", difficulty: "easy" },
  { id: 48, question: "What does 'filter' return?", options: ["Boolean", "Single element", "New collection with matching elements", "Modified original collection"], correctAnswer: 2, explanation: "'filter' returns a new collection containing only elements that match the predicate. Original collection is unchanged.", category: "collections", difficulty: "easy" },
  { id: 49, question: "What's the difference between 'find' and 'firstOrNull'?", options: ["find throws, firstOrNull returns null", "No difference", "find uses predicate, firstOrNull doesn't", "firstOrNull is deprecated"], correctAnswer: 1, explanation: "'find { predicate }' and 'firstOrNull { predicate }' are equivalent. Both return the first matching element or null.", category: "collections", difficulty: "medium" },
  { id: 50, question: "What does 'reduce' do?", options: ["Removes elements", "Accumulates elements into single value", "Decreases collection size", "Filters duplicates"], correctAnswer: 1, explanation: "'reduce' accumulates elements: list.reduce { acc, x -> acc + x }. Uses first element as initial accumulator. 'fold' allows custom initial value.", category: "collections", difficulty: "medium" },
  { id: 51, question: "What is a Sequence in Kotlin?", options: ["Ordered list", "Lazy collection for efficient processing", "Immutable list", "Thread-safe collection"], correctAnswer: 1, explanation: "Sequences process elements lazily, one at a time. More efficient for large collections with multiple operations (no intermediate lists).", category: "collections", difficulty: "medium" },
  { id: 52, question: "How do you create a Map in Kotlin?", options: ["Map()", "mapOf(\"key\" to \"value\")", "new HashMap()", "createMap()"], correctAnswer: 1, explanation: "Use 'mapOf(\"key\" to \"value\")' for immutable maps. 'to' is an infix function creating Pair. 'mutableMapOf()' for mutable.", category: "collections", difficulty: "easy" },
  { id: 53, question: "What does 'groupBy' return?", options: ["List of groups", "Map<Key, List<Elements>>", "Set of keys", "Single grouped element"], correctAnswer: 1, explanation: "'groupBy' returns Map where keys are from the selector and values are lists of elements with that key.", category: "collections", difficulty: "medium" },
  { id: 54, question: "How do you check if any element matches a condition?", options: ["has { }", "contains { }", "any { }", "exists { }"], correctAnswer: 2, explanation: "'any { predicate }' returns true if at least one element matches. 'all { }' checks if all match. 'none { }' checks if none match.", category: "collections", difficulty: "easy" },
  { id: 55, question: "What does 'flatMap' do?", options: ["Flattens nested maps", "Maps and flattens results into single list", "Creates flat structure", "Removes nested elements"], correctAnswer: 1, explanation: "'flatMap' maps each element to a collection and flattens all results into a single list. Useful for one-to-many transformations.", category: "collections", difficulty: "medium" },

  // OOP (56-65)
  { id: 56, question: "What is a data class in Kotlin?", options: ["Database model", "Class with auto-generated equals, hashCode, copy, toString", "Immutable class", "Serializable class"], correctAnswer: 1, explanation: "Data classes auto-generate equals(), hashCode(), toString(), copy(), and componentN() functions. Just add 'data' before 'class'.", category: "oop", difficulty: "easy" },
  { id: 57, question: "What is a sealed class?", options: ["Final class", "Class with restricted subclass hierarchy", "Private class", "Abstract class"], correctAnswer: 1, explanation: "Sealed classes restrict which classes can inherit from them (must be in same file/package). Enables exhaustive 'when' expressions.", category: "oop", difficulty: "medium" },
  { id: 58, question: "What is an object declaration?", options: ["Variable declaration", "Singleton pattern implementation", "Class instantiation", "Anonymous class"], correctAnswer: 1, explanation: "'object' declaration creates a singleton. 'object Database { }' defines a class and its single instance together.", category: "oop", difficulty: "medium" },
  { id: 59, question: "What is a companion object?", options: ["Object inside another object", "Object associated with a class (like static in Java)", "Paired objects", "Helper object"], correctAnswer: 1, explanation: "Companion objects hold members accessible via class name (like static). Can implement interfaces and be named.", category: "oop", difficulty: "medium" },
  { id: 60, question: "How do you implement an interface in Kotlin?", options: ["class A implements B", "class A extends B", "class A : B", "class A -> B"], correctAnswer: 2, explanation: "Use ':' for both inheritance and interface implementation: 'class A : Interface, ParentClass()'. No 'implements' keyword.", category: "oop", difficulty: "easy" },
  { id: 61, question: "What does 'by' keyword do in class declaration?", options: ["Defines by-reference", "Delegates interface implementation", "Creates alias", "Enables lazy loading"], correctAnswer: 1, explanation: "'by' delegates interface implementation to another object: 'class A(b: B) : Interface by b'. A's Interface methods delegate to b.", category: "oop", difficulty: "hard" },
  { id: 62, question: "What is an enum class in Kotlin?", options: ["Error enumeration", "Type-safe enumeration with properties and methods", "Collection of constants", "Interface type"], correctAnswer: 1, explanation: "Enum classes define type-safe enumerations. Can have properties, methods, implement interfaces. Each constant is an instance.", category: "oop", difficulty: "easy" },
  { id: 63, question: "What's the difference between 'open' and 'abstract'?", options: ["No difference", "open allows subclassing, abstract requires it", "abstract allows subclassing, open requires it", "open is for functions, abstract for classes"], correctAnswer: 1, explanation: "'open' allows inheritance/overriding but doesn't require it. 'abstract' requires implementation in subclasses (no body allowed).", category: "oop", difficulty: "medium" },
  { id: 64, question: "What is a nested class vs inner class?", options: ["Same thing", "Nested doesn't access outer class, inner does", "Inner doesn't access outer class, nested does", "Nested is private, inner is public"], correctAnswer: 1, explanation: "Nested class (default) doesn't have reference to outer class. 'inner class' has access to outer class members.", category: "oop", difficulty: "medium" },
  { id: 65, question: "What does 'copy()' do on a data class?", options: ["Deep copy", "Creates new instance with optional modified properties", "Copies to clipboard", "Clones object"], correctAnswer: 1, explanation: "'copy()' creates a new instance. You can modify specific properties: 'person.copy(name = \"New Name\")'. Others keep original values.", category: "oop", difficulty: "easy" },

  // COROUTINES & ADVANCED (66-75)
  { id: 66, question: "What is a coroutine in Kotlin?", options: ["A routine function", "Lightweight thread for async programming", "Error handler", "Memory manager"], correctAnswer: 1, explanation: "Coroutines are lightweight, suspendable computations. They enable async programming without callbacks, using sequential code style.", category: "coroutines", difficulty: "medium" },
  { id: 67, question: "What does 'suspend' modifier do?", options: ["Pauses execution permanently", "Marks function that can be paused and resumed", "Stops coroutine", "Delays execution"], correctAnswer: 1, explanation: "'suspend' marks functions that can suspend (pause) coroutine execution without blocking the thread. Can only be called from coroutines.", category: "coroutines", difficulty: "medium" },
  { id: 68, question: "What is the difference between 'launch' and 'async'?", options: ["launch is sync, async is async", "launch returns Job, async returns Deferred with result", "No difference", "async is deprecated"], correctAnswer: 1, explanation: "'launch' starts coroutine and returns Job (fire-and-forget). 'async' returns Deferred, which you can await for a result.", category: "coroutines", difficulty: "medium" },
  { id: 69, question: "What is Flow in Kotlin?", options: ["Control flow statement", "Asynchronous stream of values", "Data pipeline", "Thread pool"], correctAnswer: 1, explanation: "Flow is a cold asynchronous stream that emits multiple values over time. It's Kotlin's reactive streams implementation.", category: "coroutines", difficulty: "hard" },
  { id: 70, question: "What is structured concurrency?", options: ["Organized code structure", "Coroutines are bound to a scope and cancelled together", "Thread synchronization", "Parallel execution"], correctAnswer: 1, explanation: "Structured concurrency means coroutines are launched in a scope. When scope is cancelled, all its coroutines are cancelled. Prevents leaks.", category: "coroutines", difficulty: "hard" },
  { id: 71, question: "What is a type alias in Kotlin?", options: ["Alternative name for a type", "Type inheritance", "Generic constraint", "Interface alias"], correctAnswer: 0, explanation: "'typealias StringList = List<String>' creates an alternative name for a type. Useful for long generic types or function types.", category: "advanced", difficulty: "medium" },
  { id: 72, question: "What is 'reified' keyword used for?", options: ["Making type parameters accessible at runtime in inline functions", "Creating interfaces", "Type casting", "Reflection"], correctAnswer: 0, explanation: "'reified' in inline functions preserves type information at runtime. Allows 'is T' checks and 'T::class' that normally aren't possible.", category: "advanced", difficulty: "hard" },
  { id: 73, question: "What is delegation property in Kotlin?", options: ["Property in delegate class", "Property whose getter/setter are delegated to another object", "Inherited property", "Static property"], correctAnswer: 1, explanation: "Delegated properties delegate get/set to a delegate object: 'val x by lazy { }'. Kotlin provides lazy, observable, and map delegates.", category: "advanced", difficulty: "hard" },
  { id: 74, question: "What does 'out' variance modifier mean?", options: ["Output parameter", "Covariant - can only produce T, not consume", "External visibility", "Output stream"], correctAnswer: 1, explanation: "'out T' makes type covariant (producer). List<out Animal> can hold List<Cat>. Cannot have T in 'in' positions (parameters).", category: "advanced", difficulty: "hard" },
  { id: 75, question: "What is a DSL in Kotlin context?", options: ["Domain Specific Language built using Kotlin features", "Data Structure Library", "Debug Symbol Log", "Dynamic Script Loader"], correctAnswer: 0, explanation: "DSLs use Kotlin features (lambdas with receivers, infix functions, operator overloading) to create type-safe builders like HTML, Gradle.", category: "advanced", difficulty: "hard" },
];

// Fisher-Yates shuffle algorithm
function shuffleArray<T>(array: T[]): T[] {
  const shuffled = [...array];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

// Get difficulty icon
function DifficultyStars({ difficulty }: { difficulty: 'easy' | 'medium' | 'hard' }) {
  switch (difficulty) {
    case 'easy':
      return (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <StarIcon sx={{ fontSize: 16, color: '#48BB78' }} />
          <StarBorderIcon sx={{ fontSize: 16, color: '#48BB78' }} />
          <StarBorderIcon sx={{ fontSize: 16, color: '#48BB78' }} />
        </Box>
      );
    case 'medium':
      return (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <StarIcon sx={{ fontSize: 16, color: '#ECC94B' }} />
          <StarIcon sx={{ fontSize: 16, color: '#ECC94B' }} />
          <StarBorderIcon sx={{ fontSize: 16, color: '#ECC94B' }} />
        </Box>
      );
    case 'hard':
      return (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <StarIcon sx={{ fontSize: 16, color: '#F56565' }} />
          <StarIcon sx={{ fontSize: 16, color: '#F56565' }} />
          <StarIcon sx={{ fontSize: 16, color: '#F56565' }} />
        </Box>
      );
  }
}

// Category labels
const categoryLabels: Record<string, string> = {
  'all': 'All Topics',
  'basics': 'Kotlin Basics',
  'null-safety': 'Null Safety',
  'functions': 'Functions',
  'collections': 'Collections',
  'oop': 'OOP',
  'coroutines': 'Coroutines',
  'advanced': 'Advanced',
};

// Enhanced Quiz Component
function KotlinQuiz() {
  const [quizStarted, setQuizStarted] = useState(false);
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<(number | null)[]>([]);
  const [showResults, setShowResults] = useState(false);
  const [quizQuestions, setQuizQuestions] = useState<QuizQuestion[]>([]);
  const [expandedExplanation, setExpandedExplanation] = useState<number | null>(null);
  
  // Quiz settings
  const [selectedCategory, setSelectedCategory] = useState<QuizCategory>('all');
  const [selectedDifficulty, setSelectedDifficulty] = useState<QuizDifficulty>('all');
  const [questionCount, setQuestionCount] = useState(10);
  
  // Timer
  const [timeElapsed, setTimeElapsed] = useState(0);
  const [timerActive, setTimerActive] = useState(false);
  
  // Stats
  const [quizHistory, setQuizHistory] = useState<{ score: number; total: number; time: number }[]>([]);

  // Timer effect
  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (timerActive && !showResults) {
      interval = setInterval(() => {
        setTimeElapsed(prev => prev + 1);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [timerActive, showResults]);

  // Format time
  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  // Filter and prepare questions
  const prepareQuiz = useCallback(() => {
    let filteredQuestions = [...kotlinQuestionBank];
    
    if (selectedCategory !== 'all') {
      filteredQuestions = filteredQuestions.filter(q => q.category === selectedCategory);
    }
    
    if (selectedDifficulty !== 'all') {
      filteredQuestions = filteredQuestions.filter(q => q.difficulty === selectedDifficulty);
    }
    
    const shuffled = shuffleArray(filteredQuestions);
    const selected = shuffled.slice(0, Math.min(questionCount, shuffled.length));
    
    setQuizQuestions(selected);
    setSelectedAnswers(new Array(selected.length).fill(null));
    setCurrentQuestion(0);
    setShowResults(false);
    setTimeElapsed(0);
    setTimerActive(true);
    setQuizStarted(true);
    setExpandedExplanation(null);
  }, [selectedCategory, selectedDifficulty, questionCount]);

  const handleAnswerSelect = (answerIndex: number) => {
    if (showResults) return;
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
    setTimerActive(false);
    setShowResults(true);
    const score = quizQuestions.reduce((acc, q, idx) => 
      selectedAnswers[idx] === q.correctAnswer ? acc + 1 : acc, 0
    );
    setQuizHistory(prev => [...prev, { score, total: quizQuestions.length, time: timeElapsed }]);
  };

  const handleRestart = () => {
    setQuizStarted(false);
    setShowResults(false);
    setTimeElapsed(0);
    setTimerActive(false);
  };

  const score = quizQuestions.reduce((acc, q, idx) => 
    selectedAnswers[idx] === q.correctAnswer ? acc + 1 : acc, 0
  );
  const percentage = quizQuestions.length > 0 ? Math.round((score / quizQuestions.length) * 100) : 0;
  const answeredCount = selectedAnswers.filter(a => a !== null).length;

  // Quiz setup screen
  if (!quizStarted) {
    return (
      <Box>
        <Paper
          sx={{
            p: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha(accentColor, 0.05)} 0%, ${alpha(accentColorDark, 0.05)} 100%)`,
            border: `2px solid ${alpha(accentColor, 0.2)}`,
          }}
        >
          <Box sx={{ textAlign: 'center', mb: 4 }}>
            <Avatar sx={{ bgcolor: accentColor, width: 80, height: 80, mx: 'auto', mb: 2 }}>
              <QuizIcon sx={{ fontSize: 40 }} />
            </Avatar>
            <Typography variant="h4" sx={{ fontWeight: 900, mb: 1 }}>
              Kotlin Knowledge Quiz
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Test your Kotlin programming knowledge with customizable quizzes
            </Typography>
          </Box>

          {/* Category Selection */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
              <FilterListIcon fontSize="small" /> Select Category
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
              {(Object.keys(categoryLabels) as QuizCategory[]).map((cat) => (
                <Chip
                  key={cat}
                  label={categoryLabels[cat]}
                  onClick={() => setSelectedCategory(cat)}
                  sx={{
                    fontWeight: 600,
                    bgcolor: selectedCategory === cat ? accentColor : alpha(accentColor, 0.1),
                    color: selectedCategory === cat ? 'white' : 'text.primary',
                    '&:hover': { bgcolor: selectedCategory === cat ? accentColor : alpha(accentColor, 0.2) },
                  }}
                />
              ))}
            </Box>
          </Box>

          {/* Difficulty Selection */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
              <TrendingUpIcon fontSize="small" /> Select Difficulty
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
              {[
                { value: 'all', label: 'All Levels', color: accentColor },
                { value: 'easy', label: 'Easy', color: '#48BB78' },
                { value: 'medium', label: 'Medium', color: '#ECC94B' },
                { value: 'hard', label: 'Hard', color: '#F56565' },
              ].map((diff) => (
                <Chip
                  key={diff.value}
                  label={diff.label}
                  onClick={() => setSelectedDifficulty(diff.value as QuizDifficulty)}
                  sx={{
                    fontWeight: 600,
                    bgcolor: selectedDifficulty === diff.value ? diff.color : alpha(diff.color, 0.1),
                    color: selectedDifficulty === diff.value ? 'white' : 'text.primary',
                    '&:hover': { bgcolor: selectedDifficulty === diff.value ? diff.color : alpha(diff.color, 0.2) },
                  }}
                />
              ))}
            </Box>
          </Box>

          {/* Question Count */}
          <Box sx={{ mb: 4 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
              <QuizIcon fontSize="small" /> Number of Questions
            </Typography>
            <ToggleButtonGroup
              value={questionCount}
              exclusive
              onChange={(_, value) => value && setQuestionCount(value)}
              sx={{ flexWrap: 'wrap' }}
            >
              {[5, 10, 15, 20, 25].map((count) => (
                <ToggleButton 
                  key={count} 
                  value={count}
                  sx={{ 
                    px: 3,
                    fontWeight: 600,
                    '&.Mui-selected': { bgcolor: alpha(accentColor, 0.2), color: accentColor },
                  }}
                >
                  {count}
                </ToggleButton>
              ))}
            </ToggleButtonGroup>
          </Box>

          {/* Available Questions Info */}
          <Paper sx={{ p: 2, mb: 4, borderRadius: 2, bgcolor: alpha(accentColor, 0.05) }}>
            <Typography variant="body2" color="text.secondary">
              <strong>Available Questions:</strong>{' '}
              {kotlinQuestionBank.filter(q => 
                (selectedCategory === 'all' || q.category === selectedCategory) &&
                (selectedDifficulty === 'all' || q.difficulty === selectedDifficulty)
              ).length} questions match your filters
            </Typography>
          </Paper>

          {/* Quiz History */}
          {quizHistory.length > 0 && (
            <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha(accentColorDark, 0.05) }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                <EmojiEventsIcon fontSize="small" color="warning" /> Recent Attempts
              </Typography>
              <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                {quizHistory.slice(-5).reverse().map((h, idx) => (
                  <Chip
                    key={idx}
                    label={`${h.score}/${h.total} (${formatTime(h.time)})`}
                    size="small"
                    sx={{
                      bgcolor: h.score / h.total >= 0.7 ? alpha('#48BB78', 0.2) : alpha('#F56565', 0.2),
                      fontWeight: 600,
                    }}
                  />
                ))}
              </Box>
            </Paper>
          )}

          <Button
            variant="contained"
            size="large"
            startIcon={<PlayArrowIcon />}
            onClick={prepareQuiz}
            sx={{
              width: '100%',
              py: 2,
              bgcolor: accentColor,
              fontWeight: 700,
              fontSize: '1.1rem',
              '&:hover': { bgcolor: alpha(accentColor, 0.9) },
            }}
          >
            Start Quiz
          </Button>
        </Paper>
      </Box>
    );
  }

  // Results screen
  if (showResults) {
    return (
      <Box>
        <Paper
          sx={{
            p: 4,
            borderRadius: 4,
            background: percentage >= 70 
              ? `linear-gradient(135deg, ${alpha('#48BB78', 0.1)} 0%, ${alpha('#38A169', 0.1)} 100%)`
              : `linear-gradient(135deg, ${alpha('#F56565', 0.1)} 0%, ${alpha('#E53E3E', 0.1)} 100%)`,
            border: `2px solid ${percentage >= 70 ? alpha('#48BB78', 0.3) : alpha('#F56565', 0.3)}`,
            textAlign: 'center',
            mb: 4,
          }}
        >
          <Zoom in timeout={500}>
            <Avatar
              sx={{
                bgcolor: percentage >= 70 ? '#48BB78' : '#F56565',
                width: 100,
                height: 100,
                mx: 'auto',
                mb: 3,
              }}
            >
              <EmojiEventsIcon sx={{ fontSize: 50 }} />
            </Avatar>
          </Zoom>
          
          <Typography variant="h3" sx={{ fontWeight: 900, mb: 1 }}>
            {percentage}%
          </Typography>
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
            {score} / {quizQuestions.length} Correct
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
            {percentage >= 90 ? "🎉 Outstanding! You're a Kotlin master!" :
             percentage >= 70 ? "👏 Great job! You have solid Kotlin knowledge!" :
             percentage >= 50 ? "📚 Good effort! Keep practicing to improve!" :
             "💪 Keep learning! Review the explanations below."}
          </Typography>
          
          <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2, mb: 3 }}>
            <Chip
              icon={<TimerIcon />}
              label={`Time: ${formatTime(timeElapsed)}`}
              sx={{ fontWeight: 600 }}
            />
            <Chip
              icon={<TrendingUpIcon />}
              label={`Avg: ${Math.round(timeElapsed / quizQuestions.length)}s/question`}
              sx={{ fontWeight: 600 }}
            />
          </Box>

          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center' }}>
            <Button
              variant="contained"
              startIcon={<RefreshIcon />}
              onClick={handleRestart}
              sx={{ bgcolor: accentColor, '&:hover': { bgcolor: alpha(accentColor, 0.9) } }}
            >
              New Quiz
            </Button>
          </Box>
        </Paper>

        {/* Detailed Review */}
        <Typography variant="h6" sx={{ fontWeight: 800, mb: 3, display: 'flex', alignItems: 'center', gap: 1 }}>
          <LightbulbIcon color="warning" /> Review Your Answers
        </Typography>
        
        {quizQuestions.map((q, idx) => {
          const isCorrect = selectedAnswers[idx] === q.correctAnswer;
          const isExpanded = expandedExplanation === idx;
          
          return (
            <Paper
              key={q.id}
              sx={{
                p: 3,
                mb: 2,
                borderRadius: 3,
                border: `2px solid ${isCorrect ? alpha('#48BB78', 0.3) : alpha('#F56565', 0.3)}`,
                bgcolor: isCorrect ? alpha('#48BB78', 0.03) : alpha('#F56565', 0.03),
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
                <Avatar
                  sx={{
                    bgcolor: isCorrect ? '#48BB78' : '#F56565',
                    width: 32,
                    height: 32,
                    fontSize: 14,
                    fontWeight: 700,
                  }}
                >
                  {idx + 1}
                </Avatar>
                <Box sx={{ flex: 1 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                    <Chip label={categoryLabels[q.category]} size="small" sx={{ fontSize: 11 }} />
                    <DifficultyStars difficulty={q.difficulty} />
                    {isCorrect ? (
                      <CheckCircleOutlineIcon sx={{ color: '#48BB78', fontSize: 20 }} />
                    ) : (
                      <CancelOutlinedIcon sx={{ color: '#F56565', fontSize: 20 }} />
                    )}
                  </Box>
                  
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 2 }}>
                    {q.question}
                  </Typography>
                  
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 2 }}>
                    {q.options.map((opt, optIdx) => (
                      <Chip
                        key={optIdx}
                        label={opt}
                        size="small"
                        sx={{
                          bgcolor: optIdx === q.correctAnswer 
                            ? alpha('#48BB78', 0.2)
                            : optIdx === selectedAnswers[idx] && optIdx !== q.correctAnswer
                              ? alpha('#F56565', 0.2)
                              : alpha(accentColor, 0.05),
                          fontWeight: optIdx === q.correctAnswer || optIdx === selectedAnswers[idx] ? 700 : 400,
                          border: optIdx === q.correctAnswer ? `2px solid #48BB78` : 'none',
                        }}
                      />
                    ))}
                  </Box>
                  
                  <Box
                    onClick={() => setExpandedExplanation(isExpanded ? null : idx)}
                    sx={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 1 }}
                  >
                    <Typography variant="body2" color="primary" sx={{ fontWeight: 600 }}>
                      {isExpanded ? 'Hide' : 'Show'} Explanation
                    </Typography>
                    {isExpanded ? <ExpandLessIcon fontSize="small" /> : <ExpandMoreIcon fontSize="small" />}
                  </Box>
                  
                  <Collapse in={isExpanded}>
                    <Paper sx={{ p: 2, mt: 2, borderRadius: 2, bgcolor: alpha(accentColor, 0.05) }}>
                      <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
                        {q.explanation}
                      </Typography>
                    </Paper>
                  </Collapse>
                </Box>
              </Box>
            </Paper>
          );
        })}
      </Box>
    );
  }

  // Quiz in progress
  const currentQ = quizQuestions[currentQuestion];

  return (
    <Box>
      {/* Progress Header */}
      <Paper sx={{ p: 3, mb: 3, borderRadius: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 800 }}>
              Question {currentQuestion + 1} of {quizQuestions.length}
            </Typography>
            <Chip label={categoryLabels[currentQ.category]} size="small" sx={{ fontWeight: 600 }} />
            <DifficultyStars difficulty={currentQ.difficulty} />
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Chip
              icon={<TimerIcon />}
              label={formatTime(timeElapsed)}
              sx={{ fontWeight: 700, bgcolor: alpha(accentColor, 0.1) }}
            />
            <Badge badgeContent={answeredCount} color="primary">
              <Chip label="Answered" size="small" />
            </Badge>
          </Box>
        </Box>
        
        <LinearProgress
          variant="determinate"
          value={(answeredCount / quizQuestions.length) * 100}
          sx={{
            height: 8,
            borderRadius: 4,
            bgcolor: alpha(accentColor, 0.1),
            '& .MuiLinearProgress-bar': { bgcolor: accentColor, borderRadius: 4 },
          }}
        />
        
        {/* Question Navigation Dots */}
        <Box sx={{ display: 'flex', gap: 0.5, mt: 2, flexWrap: 'wrap' }}>
          {quizQuestions.map((_, idx) => (
            <Tooltip key={idx} title={`Question ${idx + 1}`}>
              <Box
                onClick={() => setCurrentQuestion(idx)}
                sx={{
                  width: 24,
                  height: 24,
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: 11,
                  fontWeight: 700,
                  cursor: 'pointer',
                  bgcolor: idx === currentQuestion 
                    ? accentColor 
                    : selectedAnswers[idx] !== null 
                      ? alpha(accentColor, 0.3)
                      : alpha(accentColor, 0.1),
                  color: idx === currentQuestion ? 'white' : 'text.primary',
                  '&:hover': { bgcolor: idx === currentQuestion ? accentColor : alpha(accentColor, 0.2) },
                }}
              >
                {idx + 1}
              </Box>
            </Tooltip>
          ))}
        </Box>
      </Paper>

      {/* Question Card */}
      <Fade in key={currentQuestion}>
        <Paper
          sx={{
            p: 4,
            mb: 3,
            borderRadius: 4,
            border: `2px solid ${alpha(accentColor, 0.2)}`,
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 4, lineHeight: 1.6 }}>
            {currentQ.question}
          </Typography>

          <FormControl component="fieldset" sx={{ width: '100%' }}>
            <RadioGroup
              value={selectedAnswers[currentQuestion] ?? ''}
              onChange={(e) => handleAnswerSelect(parseInt(e.target.value))}
            >
              {currentQ.options.map((option, idx) => (
                <Paper
                  key={idx}
                  sx={{
                    mb: 2,
                    p: 2,
                    borderRadius: 2,
                    cursor: 'pointer',
                    border: `2px solid ${selectedAnswers[currentQuestion] === idx ? accentColor : 'transparent'}`,
                    bgcolor: selectedAnswers[currentQuestion] === idx ? alpha(accentColor, 0.08) : alpha(accentColor, 0.02),
                    '&:hover': { bgcolor: alpha(accentColor, 0.08), borderColor: alpha(accentColor, 0.3) },
                    transition: 'all 0.2s ease',
                  }}
                  onClick={() => handleAnswerSelect(idx)}
                >
                  <FormControlLabel
                    value={idx}
                    control={
                      <Radio 
                        sx={{ 
                          color: accentColor,
                          '&.Mui-checked': { color: accentColor },
                        }} 
                      />
                    }
                    label={
                      <Typography sx={{ fontWeight: selectedAnswers[currentQuestion] === idx ? 600 : 400 }}>
                        {option}
                      </Typography>
                    }
                    sx={{ width: '100%', m: 0 }}
                  />
                </Paper>
              ))}
            </RadioGroup>
          </FormControl>
        </Paper>
      </Fade>

      {/* Navigation Buttons */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 2 }}>
        <Button
          variant="outlined"
          onClick={handlePrevious}
          disabled={currentQuestion === 0}
          sx={{ borderColor: accentColor, color: accentColor }}
        >
          Previous
        </Button>
        
        <Box sx={{ display: 'flex', gap: 2 }}>
          {currentQuestion < quizQuestions.length - 1 ? (
            <Button
              variant="contained"
              onClick={handleNext}
              sx={{ bgcolor: accentColor, '&:hover': { bgcolor: alpha(accentColor, 0.9) } }}
            >
              Next
            </Button>
          ) : (
            <Button
              variant="contained"
              onClick={handleSubmit}
              startIcon={<EmojiEventsIcon />}
              disabled={answeredCount < quizQuestions.length}
              sx={{ 
                bgcolor: answeredCount === quizQuestions.length ? '#48BB78' : accentColor,
                '&:hover': { bgcolor: answeredCount === quizQuestions.length ? '#38A169' : alpha(accentColor, 0.9) },
              }}
            >
              Submit Quiz ({answeredCount}/{quizQuestions.length})
            </Button>
          )}
        </Box>
      </Box>
    </Box>
  );
}

// Module navigation items for sidebar
const moduleNavItems = [
  { id: "introduction", label: "Introduction", icon: <SchoolIcon /> },
  { id: "history", label: "History & Evolution", icon: <HistoryIcon /> },
  { id: "setup", label: "Environment Setup", icon: <BuildIcon /> },
  { id: "basics", label: "Kotlin Basics & Syntax", icon: <CodeIcon /> },
  { id: "variables", label: "Variables & Data Types", icon: <DataObjectIcon /> },
  { id: "operators", label: "Operators & Expressions", icon: <SwapHorizIcon /> },
  { id: "control-flow", label: "Control Flow", icon: <AccountTreeIcon /> },
  { id: "functions", label: "Functions", icon: <ExtensionIcon /> },
  { id: "null-safety", label: "Null Safety", icon: <SecurityIcon /> },
  { id: "collections", label: "Collections", icon: <StorageIcon /> },
  { id: "oop", label: "OOP in Kotlin", icon: <ClassIcon /> },
  { id: "inheritance", label: "Inheritance & Interfaces", icon: <LayersIcon /> },
  { id: "data-classes", label: "Data Classes & Sealed Classes", icon: <ViewModuleIcon /> },
  { id: "lambdas", label: "Lambdas & Higher-Order Functions", icon: <AutoFixHighIcon /> },
  { id: "coroutines", label: "Coroutines", icon: <SyncIcon /> },
  { id: "android", label: "Android Development", icon: <AndroidIcon /> },
  { id: "multiplatform", label: "Kotlin Multiplatform", icon: <CloudIcon /> },
  { id: "advanced", label: "Advanced Topics", icon: <DeveloperBoardIcon /> },
  { id: "quiz", label: "Knowledge Quiz", icon: <QuizIcon /> },
];

// Quick stats for hero section
const quickStats = [
  { label: "Created", value: "2011", color: "#7F52FF" },
  { label: "Creator", value: "JetBrains", color: "#E44857" },
  { label: "Paradigm", value: "Multi", color: "#4A90D9" },
  { label: "Latest Ver", value: "2.0", color: "#48BB78" },
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

export default function KotlinProgrammingPage() {
  const navigate = useNavigate();

  return (
    <LearnPageLayout pageTitle="Kotlin Programming" pageContext="Comprehensive Kotlin programming course covering modern Android development, null safety, coroutines, and multiplatform development.">
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
                K
              </Avatar>
              <Box>
                <Typography variant="h4" sx={{ fontWeight: 900 }}>
                  Kotlin Programming
                </Typography>
                <Typography variant="body1" color="text.secondary">
                  Modern, Concise, Safe — The Preferred Language for Android
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
              {["Android", "JVM", "Null Safety", "Coroutines", "Multiplatform", "Concise", "Interop", "Modern"].map((tag) => (
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
              What is Kotlin?
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Kotlin is a modern, statically-typed programming language developed by <strong>JetBrains</strong>,
              the company behind IntelliJ IDEA, PyCharm, and other popular development tools. First unveiled
              in 2011 and reaching version 1.0 in 2016, Kotlin was designed to address the pain points of
              Java while maintaining full interoperability with existing Java code. In 2017, Google announced
              Kotlin as an officially supported language for Android development, and in 2019, declared it
              the <strong>preferred language</strong> for Android apps. Today, Kotlin is used by millions
              of developers worldwide, not just for Android, but for server-side applications, web frontends,
              and even iOS through Kotlin Multiplatform.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Kotlin's design philosophy centers on <strong>pragmatism, conciseness, and safety</strong>.
              The language significantly reduces boilerplate compared to Java—what takes 10 lines in Java
              often takes 1-2 lines in Kotlin. Its null safety system eliminates the infamous
              <code> NullPointerException</code> by distinguishing between nullable and non-nullable types
              at compile time. Kotlin supports both object-oriented and functional programming paradigms,
              with first-class functions, lambda expressions, and powerful collection operations that make
              code expressive and readable.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              What makes Kotlin especially powerful is its <strong>100% interoperability with Java</strong>.
              You can call Kotlin code from Java and vice versa seamlessly. This means you can gradually
              migrate an existing Java codebase to Kotlin, use Java libraries in Kotlin projects, and
              leverage decades of Java ecosystem investments. Kotlin compiles to JVM bytecode (like Java),
              JavaScript, or native code (for iOS, Linux, Windows, macOS), enabling true cross-platform
              development with shared business logic.
            </Typography>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Why Learn Kotlin in 2024?
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Kotlin has rapidly become one of the most beloved programming languages. Stack Overflow's
              developer surveys consistently rank it among the most loved languages. For Android development,
              Kotlin isn't just preferred—it's becoming essential, as Google builds new Android libraries
              and features with Kotlin-first APIs. Here's why learning Kotlin is a smart career move:
            </Typography>

            <Grid container spacing={3} sx={{ mb: 4 }}>
              {[
                {
                  title: "Android Development",
                  description: "Google's preferred language for Android. Over 60% of professional Android developers use Kotlin. New Jetpack libraries (Compose, Room, WorkManager) are designed Kotlin-first. Most new Android tutorials and documentation use Kotlin.",
                  icon: <AndroidIcon />,
                },
                {
                  title: "Developer Productivity",
                  description: "Kotlin dramatically reduces boilerplate. Data classes, null safety, extension functions, and smart casts make code shorter and safer. What takes hours in Java takes minutes in Kotlin. More features, fewer lines, fewer bugs.",
                  icon: <SpeedIcon />,
                },
                {
                  title: "Null Safety",
                  description: "Kotlin's type system distinguishes nullable and non-nullable types. The compiler catches null-related errors at compile time, eliminating the #1 cause of crashes in production apps. This alone saves countless debugging hours.",
                  icon: <SecurityIcon />,
                },
                {
                  title: "Multiplatform Future",
                  description: "Kotlin Multiplatform (KMP) lets you share code across Android, iOS, web, and desktop. Compose Multiplatform extends this to UI. Write business logic once, deploy everywhere. It's the future of cross-platform development.",
                  icon: <CloudIcon />,
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
              How Kotlin Works: Compilation Targets
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Kotlin is a versatile language that can compile to multiple targets. This flexibility is
              key to its multiplatform capabilities and ecosystem integration:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Kotlin compilation targets:</span>{"\n"}
                {"\n"}
                <span style={{ color: "#50fa7b" }}>1. Kotlin/JVM</span>{"\n"}
                {"   "}Main.kt → <span style={{ color: "#8be9fd" }}>kotlinc</span> → Main.class (JVM bytecode){"\n"}
                {"   "}<span style={{ color: "#6272a4" }}>// For Android, server-side, desktop JVM apps</span>{"\n"}
                {"   "}<span style={{ color: "#6272a4" }}>// 100% Java interoperability</span>{"\n"}
                {"\n"}
                <span style={{ color: "#50fa7b" }}>2. Kotlin/JS</span>{"\n"}
                {"   "}Main.kt → <span style={{ color: "#8be9fd" }}>kotlinc-js</span> → main.js (JavaScript){"\n"}
                {"   "}<span style={{ color: "#6272a4" }}>// For web frontends, Node.js</span>{"\n"}
                {"   "}<span style={{ color: "#6272a4" }}>// Can use React, create TypeScript definitions</span>{"\n"}
                {"\n"}
                <span style={{ color: "#50fa7b" }}>3. Kotlin/Native</span>{"\n"}
                {"   "}Main.kt → <span style={{ color: "#8be9fd" }}>konanc</span> → executable (native binary){"\n"}
                {"   "}<span style={{ color: "#6272a4" }}>// For iOS, macOS, Linux, Windows</span>{"\n"}
                {"   "}<span style={{ color: "#6272a4" }}>// No JVM required, direct machine code</span>{"\n"}
                {"\n"}
                <span style={{ color: "#50fa7b" }}>4. Kotlin/Wasm</span> <span style={{ color: "#6272a4" }}>(experimental)</span>{"\n"}
                {"   "}Main.kt → <span style={{ color: "#8be9fd" }}>kotlinc-wasm</span> → main.wasm{"\n"}
                {"   "}<span style={{ color: "#6272a4" }}>// For WebAssembly, high-performance web apps</span>
              </Typography>
            </Paper>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              For most developers, <strong>Kotlin/JVM</strong> is the primary target, especially for Android
              development. Kotlin compiles to the same bytecode as Java, running on the JVM with the same
              performance characteristics. The Kotlin compiler (kotlinc) produces .class files that can be
              mixed with Java classes in the same project. This means you get all the benefits of the JVM
              ecosystem—mature garbage collection, JIT compilation, extensive libraries—while writing more
              expressive code.
            </Typography>

            <Divider sx={{ my: 4 }} />

            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Core Principles of Kotlin
            </Typography>

            <List sx={{ mb: 3 }}>
              {[
                {
                  title: "Conciseness",
                  desc: "Kotlin eliminates boilerplate. Data classes auto-generate equals(), hashCode(), toString(), and copy(). Type inference reduces redundant type declarations. Smart casts eliminate explicit casting. Extension functions add methods to existing classes without inheritance.",
                },
                {
                  title: "Null Safety",
                  desc: "The type system distinguishes nullable (String?) from non-nullable (String) types. The compiler forces you to handle null cases, preventing NullPointerException at runtime. Safe calls (?.), Elvis operator (?:), and not-null assertions (!!) provide elegant null handling.",
                },
                {
                  title: "Interoperability",
                  desc: "Kotlin is 100% interoperable with Java. Call Java from Kotlin and Kotlin from Java seamlessly. Use any Java library. Gradually migrate Java projects to Kotlin. The @JvmStatic, @JvmOverloads, and other annotations fine-tune Java interop.",
                },
                {
                  title: "Functional Programming",
                  desc: "Functions are first-class citizens. Higher-order functions, lambdas, and inline functions enable functional programming. The standard library includes map, filter, reduce, and other functional operations on collections. Immutability is encouraged with val.",
                },
                {
                  title: "Coroutines",
                  desc: "Kotlin's coroutines provide lightweight concurrency without callback hell. Write asynchronous code that looks synchronous. Suspend functions, structured concurrency, and Flow make async programming intuitive. Better than threads, simpler than RxJava.",
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
                Begin with <strong>IntelliJ IDEA Community Edition</strong> (free) or <strong>Android Studio</strong>
                for Android development—both have excellent Kotlin support built in. Try the
                <strong> Kotlin Playground</strong> at play.kotlinlang.org for quick experiments. The official
                <strong> Kotlin Koans</strong> (koans.kotlinlang.org) provide interactive exercises to learn Kotlin
                syntax hands-on. For Android, start with Jetpack Compose tutorials.
              </Typography>
            </Paper>
          </Paper>

          {/* Your First Kotlin Program */}
          <Paper sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Typography variant="h5" sx={{ fontWeight: 800, mb: 3, color: accentColor }}>
              Your First Kotlin Program
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Kotlin is famous for its conciseness. Here's "Hello, World!" in Kotlin—notice there's no
              class required for a simple program:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// hello.kt - That's it, no class needed!</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>main</span>() {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"Hello, World!"</span>){"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Compare this to Java's version with a public class, static modifier, String[] args, and
              System.out.println(). Kotlin cuts the noise. Let's see a slightly more complete example:
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// A more complete example</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>main</span>(args: <span style={{ color: "#8be9fd" }}>Array</span>{"<"}<span style={{ color: "#8be9fd" }}>String</span>{">"}) {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Variables</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>val</span> name = <span style={{ color: "#f1fa8c" }}>"Kotlin"</span>      <span style={{ color: "#6272a4" }}>// Immutable (like final in Java)</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> version = <span style={{ color: "#bd93f9" }}>2.0</span>        <span style={{ color: "#6272a4" }}>// Mutable</span>{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// String template (interpolation)</span>{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"Hello, $name $version!"</span>){"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Expression in template</span>{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"Length: </span>${"{"}<span style={{ color: "#ff79c6" }}>name</span>.length{"}"}<span style={{ color: "#f1fa8c" }}>"</span>){"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Call a function</span>{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>greet</span>(<span style={{ color: "#f1fa8c" }}>"Developer"</span>){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Function declaration</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>greet</span>(name: <span style={{ color: "#8be9fd" }}>String</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"Welcome, $name!"</span>){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Single-expression function</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>add</span>(a: <span style={{ color: "#8be9fd" }}>Int</span>, b: <span style={{ color: "#8be9fd" }}>Int</span>) = a + b
              </Typography>
            </Paper>

            <List>
              {[
                { code: "fun main()", desc: "The entry point. 'fun' declares a function. Unlike Java, main() doesn't need to be in a class and doesn't require the args parameter if unused." },
                { code: "val / var", desc: "val declares an immutable variable (read-only, like Java's final). var declares a mutable variable. Prefer val for safer, more predictable code." },
                { code: '"Hello, $name"', desc: "String templates. Use $ to embed variables directly in strings. Use ${expression} for complex expressions. Much cleaner than concatenation." },
                { code: "fun greet(name: String)", desc: "Functions declare parameters as name: Type. Return type comes after the parameter list (: ReturnType) and can be omitted if Unit (void)." },
                { code: "fun add(a, b) = a + b", desc: "Single-expression functions can use = instead of braces. The return type is inferred. This concise syntax is common for simple functions." },
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
              Kotlin was created by <strong>JetBrains</strong>, the Czech company famous for IntelliJ IDEA.
              In 2010, JetBrains engineers, led by <strong>Andrey Breslav</strong>, began developing a new
              language for the JVM. They used Java extensively in their products but found it verbose and
              lacking modern features. Rather than wait for Java to evolve, they decided to create a new
              language that would be more expressive while remaining fully compatible with Java.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              The language was unveiled publicly in July 2011. The name "Kotlin" comes from <strong>Kotlin
              Island</strong> near St. Petersburg, Russia, where part of the JetBrains team is based. (This
              mirrors Java being named after the Indonesian island.) After years of development and community
              feedback, <strong>Kotlin 1.0</strong> was released in February 2016, marking the language as
              production-ready with a commitment to backward compatibility.
            </Typography>

            <Grid container spacing={2} sx={{ mb: 3 }}>
              {[
                { year: "2010", event: "Development Begins", desc: "JetBrains starts project Kotlin to create a modern JVM language" },
                { year: "2011", event: "Public Announcement", desc: "Kotlin unveiled at JVM Language Summit" },
                { year: "2016", event: "Kotlin 1.0 Released", desc: "First stable release, production-ready with backward compatibility promise" },
                { year: "2017", event: "Google I/O", desc: "Google announces official support for Kotlin on Android" },
                { year: "2018", event: "Kotlin 1.3", desc: "Coroutines become stable, enabling modern async programming" },
                { year: "2019", event: "Kotlin-first", desc: "Google declares Kotlin the preferred language for Android development" },
                { year: "2021", event: "Kotlin 1.5", desc: "JVM records support, sealed interfaces, inline classes stable" },
                { year: "2023", event: "Kotlin 2.0 Preview", desc: "New K2 compiler with major performance improvements" },
                { year: "2024", event: "Kotlin 2.0", desc: "K2 compiler stable, Compose Multiplatform grows" },
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
              The turning point came at <strong>Google I/O 2017</strong> when Google announced official
              Android support for Kotlin. This endorsement from the world's largest mobile platform
              immediately elevated Kotlin from a niche JVM language to a mainstream choice. Two years later,
              Google went further, declaring Kotlin the <strong>preferred language</strong> for Android
              development. New Android libraries, samples, and documentation are now Kotlin-first.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha(accentColorDark, 0.08), border: `1px solid ${alpha(accentColorDark, 0.2)}` }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1 }}>
                Kotlin's Impact
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Kotlin has influenced the broader Java ecosystem. Many features that appeared first in Kotlin
                (like records, sealed classes, and pattern matching) have since been added to Java. The success
                of Kotlin's coroutines influenced Project Loom (virtual threads) in Java. Kotlin demonstrated
                that a new JVM language could gain mainstream adoption, paving the way for others to innovate
                on the platform.
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
              Setting up Kotlin is straightforward. For most developers, using an IDE with built-in
              Kotlin support is the easiest path. If you're doing Android development, Android Studio
              has everything you need out of the box.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColorDark }}>
              IDE Options
            </Typography>

            <Grid container spacing={2} sx={{ mb: 4 }}>
              {[
                {
                  name: "IntelliJ IDEA",
                  desc: "JetBrains' flagship IDE. Community Edition is free and includes full Kotlin support. Since JetBrains makes both, the Kotlin experience is superb. Best for server-side and general Kotlin development.",
                  color: "#000000",
                },
                {
                  name: "Android Studio",
                  desc: "Google's official Android IDE, based on IntelliJ. Includes Kotlin support, Android SDK, emulators, and all Android tooling. The go-to choice for Android development.",
                  color: "#3DDC84",
                },
                {
                  name: "VS Code",
                  desc: "Lightweight editor with Kotlin extension. Good for quick edits and learning, but lacks the deep refactoring and analysis of IntelliJ-based IDEs.",
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
              Command-Line Installation
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}># macOS (using Homebrew):</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>brew</span> install kotlin{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Using SDKMAN (recommended for managing versions):</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>curl</span> -s <span style={{ color: "#f1fa8c" }}>"https://get.sdkman.io"</span> | bash{"\n"}
                <span style={{ color: "#8be9fd" }}>sdk</span> install kotlin{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Verify installation:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>kotlin</span> -version{"\n"}
                <span style={{ color: "#6272a4" }}># Kotlin version 2.0.x (...)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Compile and run:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>kotlinc</span> hello.kt -include-runtime -d hello.jar{"\n"}
                <span style={{ color: "#8be9fd" }}>java</span> -jar hello.jar{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}># Or use the Kotlin REPL:</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>kotlin</span>{"\n"}
                <span style={{ color: "#6272a4" }}>{">>>"} println("Hello from REPL!")</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColorDark }}>
              Project Setup with Gradle
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// build.gradle.kts (Kotlin DSL)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>plugins</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>kotlin</span>(<span style={{ color: "#f1fa8c" }}>"jvm"</span>) version <span style={{ color: "#f1fa8c" }}>"2.0.0"</span>{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>application</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>repositories</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>mavenCentral</span>(){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>dependencies</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>implementation</span>(<span style={{ color: "#f1fa8c" }}>"org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0"</span>){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>application</span> {"{"}{"\n"}
                {"    "}mainClass.<span style={{ color: "#50fa7b" }}>set</span>(<span style={{ color: "#f1fa8c" }}>"MainKt"</span>){"\n"}
                {"}"}
              </Typography>
            </Paper>
          </Paper>

          {/* Kotlin Basics & Syntax Section */}
          <Paper id="basics" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha("#48BB78", 0.15), color: "#48BB78", width: 48, height: 48 }}>
                <CodeIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Kotlin Basics & Syntax
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Kotlin's syntax is clean and concise while remaining expressive. If you know Java, you'll
              find Kotlin familiar but significantly less verbose. Semicolons are optional (and typically
              omitted), and many Java patterns are simplified. **The fundamental principle of Kotlin's
              syntax design is reducing ceremony without sacrificing clarity.** Where Java requires explicit
              type declarations, access modifiers, and boilerplate code, Kotlin infers types, provides
              sensible defaults, and eliminates redundancy. This doesn't make the code less readable—quite
              the opposite. By removing noise, Kotlin lets you focus on the actual logic rather than
              language formalities.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              One of the first things you'll notice is **type inference**. You rarely need to explicitly
              declare types because the compiler is smart enough to figure them out from context. This isn't
              dynamic typing (like Python or JavaScript)—it's still statically typed with full compile-time
              checks. The difference is the compiler does the work for you. When you write{" "}
              <code>val name = "Kotlin"</code>, the compiler knows it's a String. When you write{" "}
              <code>val numbers = listOf(1, 2, 3)</code>, it knows it's <code>List{"<"}Int{">"}</code>.
              You can always add explicit types for clarity, but most of the time it's unnecessary. This
              significantly reduces code verbosity without any loss of type safety.
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              The distinction between **val (read-only) and var (mutable)** is central to Kotlin's design.
              <code> val</code> declares an immutable variable—once assigned, it cannot be reassigned.
              <code> var</code> declares a mutable variable that can be changed. The Kotlin philosophy
              strongly encourages using <code>val</code> by default and only using <code>var</code> when
              mutation is truly necessary. This functional programming influence makes code safer and easier
              to reason about. When you see a <code>val</code>, you know its value never changes after
              initialization. This eliminates entire classes of bugs caused by unexpected mutations. Modern
              Kotlin code often has 80-90% <code>val</code> declarations, reserving <code>var</code> for
              accumulators, counters, and truly mutable state. IDEs like IntelliJ IDEA even warn you when
              you use <code>var</code> unnecessarily and suggest converting to <code>val</code>.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Variables and Type Inference
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Immutable (read-only) - prefer this!</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> name = <span style={{ color: "#f1fa8c" }}>"Kotlin"</span>        <span style={{ color: "#6272a4" }}>// Type inferred as String</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> count: <span style={{ color: "#8be9fd" }}>Int</span> = <span style={{ color: "#bd93f9" }}>42</span>      <span style={{ color: "#6272a4" }}>// Explicit type</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// name = "Java"              // Error! val cannot be reassigned</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Mutable</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> score = <span style={{ color: "#bd93f9" }}>0</span>{"\n"}
                score = <span style={{ color: "#bd93f9" }}>100</span>                   <span style={{ color: "#6272a4" }}>// OK, var can be reassigned</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// score = "hundred"          // Error! Type is Int, not String</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Type inference works with complex types</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> list = <span style={{ color: "#50fa7b" }}>listOf</span>(<span style={{ color: "#f1fa8c" }}>"a"</span>, <span style={{ color: "#f1fa8c" }}>"b"</span>, <span style={{ color: "#f1fa8c" }}>"c"</span>)  <span style={{ color: "#6272a4" }}>// List{"<"}String{">"}</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> map = <span style={{ color: "#50fa7b" }}>mapOf</span>(<span style={{ color: "#f1fa8c" }}>"a"</span> <span style={{ color: "#ff79c6" }}>to</span> <span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#f1fa8c" }}>"b"</span> <span style={{ color: "#ff79c6" }}>to</span> <span style={{ color: "#bd93f9" }}>2</span>)  <span style={{ color: "#6272a4" }}>// Map{"<"}String, Int{">"}</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              Basic Types
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Numbers</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> byte: <span style={{ color: "#8be9fd" }}>Byte</span> = <span style={{ color: "#bd93f9" }}>127</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> short: <span style={{ color: "#8be9fd" }}>Short</span> = <span style={{ color: "#bd93f9" }}>32767</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> int: <span style={{ color: "#8be9fd" }}>Int</span> = <span style={{ color: "#bd93f9" }}>2_147_483_647</span>  <span style={{ color: "#6272a4" }}>// Underscores for readability</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> long: <span style={{ color: "#8be9fd" }}>Long</span> = <span style={{ color: "#bd93f9" }}>9_000_000_000L</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> float: <span style={{ color: "#8be9fd" }}>Float</span> = <span style={{ color: "#bd93f9" }}>3.14f</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> double: <span style={{ color: "#8be9fd" }}>Double</span> = <span style={{ color: "#bd93f9" }}>3.14159265359</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Boolean and Char</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> isKotlin: <span style={{ color: "#8be9fd" }}>Boolean</span> = <span style={{ color: "#ff79c6" }}>true</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> letter: <span style={{ color: "#8be9fd" }}>Char</span> = <span style={{ color: "#f1fa8c" }}>'K'</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// String</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> str: <span style={{ color: "#8be9fd" }}>String</span> = <span style={{ color: "#f1fa8c" }}>"Hello"</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> multiline = <span style={{ color: "#f1fa8c" }}>"""</span>{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>Line 1</span>{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>Line 2</span>{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>Line 3</span>{"\n"}
                <span style={{ color: "#f1fa8c" }}>"""</span>.<span style={{ color: "#50fa7b" }}>trimIndent</span>(){"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Arrays</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> numbers = <span style={{ color: "#50fa7b" }}>arrayOf</span>(<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> intArray = <span style={{ color: "#50fa7b" }}>intArrayOf</span>(<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>)  <span style={{ color: "#6272a4" }}>// Primitive array</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#48BB78" }}>
              String Templates
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              **String templates are one of Kotlin's most delightful features** for anyone coming from Java's
              verbose string concatenation or Python's f-strings. Instead of writing{" "}
              <code>"Hello, " + name + "!"</code>, you simply write <code>"Hello, $name!"</code>. The <code>$</code>{" "}
              symbol indicates a template expression. For simple variable references, just <code>$variableName</code>.{" "}
              For more complex expressions—function calls, property access, arithmetic—wrap them in braces:{" "}
              <code>${"{"}expression{"}"}  </code>. This makes string building dramatically more readable, especially
              for longer strings with multiple substitutions. Under the hood, string templates compile to efficient
              <code> StringBuilder</code> operations, so there's no performance penalty. **String templates also work
              with raw strings (triple-quoted)**, which are perfect for multi-line text like JSON, SQL queries, or
              formatted output. You can embed expressions directly in multi-line strings without breaking the flow.
              This feature alone eliminates countless lines of tedious string manipulation code that plagues Java projects.
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>val</span> name = <span style={{ color: "#f1fa8c" }}>"Kotlin"</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> version = <span style={{ color: "#bd93f9" }}>2.0</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Simple variable reference</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"Hello, $name!"</span>)         <span style={{ color: "#6272a4" }}>// Hello, Kotlin!</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Expression in braces</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"</span>${"{"}<span style={{ color: "#ff79c6" }}>name</span>.uppercase(){"}"} <span style={{ color: "#f1fa8c" }}>$version"</span>)  <span style={{ color: "#6272a4" }}>// KOTLIN 2.0</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Calculations</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"1 + 1 = </span>${"{"}<span style={{ color: "#bd93f9" }}>1</span> + <span style={{ color: "#bd93f9" }}>1</span>{"}"}<span style={{ color: "#f1fa8c" }}>"</span>)       <span style={{ color: "#6272a4" }}>// 1 + 1 = 2</span>
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
              Kotlin has a rich type system built on the principle that "everything is an object."
              Unlike Java, there are no primitive types in Kotlin's syntax—even Int and Boolean are
              objects with methods. However, the compiler optimizes these to JVM primitives when possible.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Nullable vs Non-Nullable Types
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              **This is THE killer feature of Kotlin**—the one that prevents billions of dollars in bugs and countless
              hours of debugging. In Java, <code>NullPointerException</code> is the #1 cause of production crashes.
              Every reference can be null, and the compiler doesn't warn you when you might dereference a null value.
              Kotlin solves this at the language level by splitting types into **nullable** (<code>String?</code>) and{" "}
              **non-nullable** (<code>String</code>). By default, variables cannot be null. If you want to allow null,
              you must explicitly add <code>?</code> to the type. This forces you to think about nullability upfront
              rather than discovering it through runtime crashes. **The compiler tracks nullability through your entire
              program.** If you have a <code>String?</code> and try to call <code>.length</code> on it without checking
              for null, you get a compile error. This compile-time guarantee eliminates an entire class of bugs. The
              safe call operator <code>?.</code> returns null if the receiver is null (instead of crashing). The Elvis
              operator <code>?:</code> provides fallback values. Together, these operators make null handling concise
              and safe. Once you've worked in Kotlin, going back to Java's null handling feels reckless.
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Non-nullable - cannot be null</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> name: <span style={{ color: "#8be9fd" }}>String</span> = <span style={{ color: "#f1fa8c" }}>"Kotlin"</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// name = null  // Error! Null cannot be assigned</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Nullable - can be null (note the ?)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> nullableName: <span style={{ color: "#8be9fd" }}>String</span>? = <span style={{ color: "#f1fa8c" }}>"Kotlin"</span>{"\n"}
                nullableName = <span style={{ color: "#ff79c6" }}>null</span>  <span style={{ color: "#6272a4" }}>// OK</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Safe call operator (?.) - returns null if object is null</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> length: <span style={{ color: "#8be9fd" }}>Int</span>? = nullableName?.length  <span style={{ color: "#6272a4" }}>// null</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Elvis operator (?:) - provide default if null</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> len: <span style={{ color: "#8be9fd" }}>Int</span> = nullableName?.length ?: <span style={{ color: "#bd93f9" }}>0</span>  <span style={{ color: "#6272a4" }}>// 0</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Not-null assertion (!!) - throws NPE if null</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// val riskyLen = nullableName!!.length  // NPE!</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Safe cast (as?) - returns null instead of throwing</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> str: <span style={{ color: "#8be9fd" }}>String</span>? = something <span style={{ color: "#ff79c6" }}>as</span>? <span style={{ color: "#8be9fd" }}>String</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#667EEA" }}>
              Type Conversions
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// No implicit conversion - must be explicit</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> intVal: <span style={{ color: "#8be9fd" }}>Int</span> = <span style={{ color: "#bd93f9" }}>42</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> longVal: <span style={{ color: "#8be9fd" }}>Long</span> = intVal.<span style={{ color: "#50fa7b" }}>toLong</span>()  <span style={{ color: "#6272a4" }}>// Explicit conversion</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> doubleVal: <span style={{ color: "#8be9fd" }}>Double</span> = intVal.<span style={{ color: "#50fa7b" }}>toDouble</span>(){"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> strVal: <span style={{ color: "#8be9fd" }}>String</span> = intVal.<span style={{ color: "#50fa7b" }}>toString</span>(){"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Parse strings to numbers</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> parsed: <span style={{ color: "#8be9fd" }}>Int</span> = <span style={{ color: "#f1fa8c" }}>"123"</span>.<span style={{ color: "#50fa7b" }}>toInt</span>(){"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> safeParsed: <span style={{ color: "#8be9fd" }}>Int</span>? = <span style={{ color: "#f1fa8c" }}>"abc"</span>.<span style={{ color: "#50fa7b" }}>toIntOrNull</span>()  <span style={{ color: "#6272a4" }}>// null instead of exception</span>
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
              Kotlin's control flow is similar to other languages, but with important improvements:
              if and when are expressions (they return values), and there's no traditional switch
              statement—when is much more powerful.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              If Expression
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              In Kotlin, **if is not just a statement—it's an expression that returns a value**. This is a subtle but
              profound difference from Java. In Java, <code>if</code> is a statement that executes code but doesn't
              produce a value. You need the ternary operator (<code>? :</code>) for conditional expressions. Kotlin
              eliminates the ternary operator because <code>if</code> itself can return values. Write{" "}
              <code>val max = if (a {">"}  b) a else b</code> instead of Java's{" "}
              <code>int max = (a {">"}  b) ? a : b</code>. The syntax is clearer and more consistent. **This expression
              nature extends to blocks too.** The last expression in an <code>if</code> block becomes the return value.
              This eliminates the need for explicit <code>return</code> statements in many cases and makes code more
              concise. You can have multi-line logic in each branch, and the final line determines what the whole{" "}
              <code>if</code> expression evaluates to. This functional programming influence makes Kotlin code more
              declarative—you describe WHAT you want ("give me the max value") rather than HOW to get it ("assign
              this variable conditionally"). It's a small change that significantly improves code readability.
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Traditional if</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> (score {">"}= <span style={{ color: "#bd93f9" }}>90</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"A"</span>){"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>else if</span> (score {">"}= <span style={{ color: "#bd93f9" }}>80</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"B"</span>){"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>else</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"C"</span>){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// If as expression (returns a value!)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> grade = <span style={{ color: "#ff79c6" }}>if</span> (score {">"}= <span style={{ color: "#bd93f9" }}>90</span>) <span style={{ color: "#f1fa8c" }}>"A"</span> <span style={{ color: "#ff79c6" }}>else if</span> (score {">"}= <span style={{ color: "#bd93f9" }}>80</span>) <span style={{ color: "#f1fa8c" }}>"B"</span> <span style={{ color: "#ff79c6" }}>else</span> <span style={{ color: "#f1fa8c" }}>"C"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Multi-line if expression</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> max = <span style={{ color: "#ff79c6" }}>if</span> (a {">"} b) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"a is larger"</span>){"\n"}
                {"    "}a  <span style={{ color: "#6272a4" }}>// Last expression is the return value</span>{"\n"}
                {"}"} <span style={{ color: "#ff79c6" }}>else</span> {"{"}{"\n"}
                {"    "}b{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              When Expression (Pattern Matching)
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              **When expressions are Kotlin's supercharged replacement for Java's <code>switch</code> statement**, and
              they're vastly more powerful. First, like <code>if</code>, <code>when</code> is an expression that returns
              a value, so you can write <code>val result = when (x) {"{"} ... {"}"}</code>. Second, <code>when</code> branches can
              match on any type, not just integers and enums like Java. **You can match on strings, ranges, collections,
              type checks, and even arbitrary boolean conditions.** Write <code>when (x) {"{"} in 1..10 → ... {"}"}</code>{" "}
              to match ranges, or <code>is String → ...</code> to match types. Third, you can omit the subject entirely
              and use <code>when</code> as a more readable replacement for <code>if-else-if</code> chains:{" "}
              <code>when {"{"} x.isOdd() → ... ; x.isEven() → ... {"}"}</code>. **When expressions also enforce
              exhaustiveness when used as expressions**, meaning the compiler ensures you've handled all cases. For sealed
              classes (covered later), this creates a powerful pattern-matching system that catches missing cases at
              compile time. The arrow syntax (<code>→</code>) is cleaner than <code>case:</code> and doesn't require{" "}
              <code>break</code> statements (no fall-through by default). Combined with smart casts, <code>when</code>{" "}
              expressions make complex branching logic elegant and safe.
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Basic when (like switch)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>when</span> (x) {"{"}{"\n"}
                {"    "}<span style={{ color: "#bd93f9" }}>1</span> -{">"} <span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"One"</span>){"\n"}
                {"    "}<span style={{ color: "#bd93f9" }}>2</span> -{">"} <span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"Two"</span>){"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>else</span> -{">"} <span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"Other"</span>){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// When as expression</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> description = <span style={{ color: "#ff79c6" }}>when</span> (x) {"{"}{"\n"}
                {"    "}<span style={{ color: "#bd93f9" }}>0</span> -{">"} <span style={{ color: "#f1fa8c" }}>"Zero"</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>in</span> <span style={{ color: "#bd93f9" }}>1</span>..<span style={{ color: "#bd93f9" }}>10</span> -{">"} <span style={{ color: "#f1fa8c" }}>"Small"</span>        <span style={{ color: "#6272a4" }}>// Range check</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>in</span> <span style={{ color: "#50fa7b" }}>listOf</span>(<span style={{ color: "#bd93f9" }}>100</span>, <span style={{ color: "#bd93f9" }}>200</span>) -{">"} <span style={{ color: "#f1fa8c" }}>"Special"</span>  <span style={{ color: "#6272a4" }}>// Collection check</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>else</span> -{">"} <span style={{ color: "#f1fa8c" }}>"Large"</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Type checking with when</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> result = <span style={{ color: "#ff79c6" }}>when</span> (obj) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>is</span> <span style={{ color: "#8be9fd" }}>String</span> -{">"} obj.length      <span style={{ color: "#6272a4" }}>// Smart cast!</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>is</span> <span style={{ color: "#8be9fd" }}>Int</span> -{">"} obj * <span style={{ color: "#bd93f9" }}>2</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>is</span> <span style={{ color: "#8be9fd" }}>List</span>{"<"}*{">"} -{">"} obj.size{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>else</span> -{">"} <span style={{ color: "#bd93f9" }}>0</span>{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#38B2AC" }}>
              Loops
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Kotlin's <code>for</code> loops are **range-based and collection-focused**, eliminating Java's traditional
              C-style <code>for (int i = 0; i {"<"} n; i++)</code> syntax. Instead, you iterate over ranges:{" "}
              <code>for (i in 1..10)</code>, or collections: <code>for (item in list)</code>. This makes loops more
              declarative and less error-prone—you can't accidentally write <code>i {"<"}= n</code> when you meant{" "}
              <code>i {"<"} n</code>, a classic off-by-one bug. **Ranges in Kotlin are powerful and expressive**: use{" "}
              <code>1..10</code> for inclusive ranges, <code>1 until 10</code> for exclusive upper bounds, or{" "}
              <code>10 downTo 1 step 2</code> for descending ranges with custom steps. When you need the index while
              iterating, <code>.withIndex()</code> provides elegant tuples: <code>for ((index, value) in list.withIndex())</code>.
              This destructuring syntax is much cleaner than Java's manual index tracking. **For loops also work with any
              type that defines an <code>iterator()</code> function**, making them extensible. While loops work exactly as
              you'd expect, but in modern Kotlin code you'll see fewer explicit loops overall—higher-order functions like{" "}
              <code>map</code>, <code>filter</code>, and <code>forEach</code> often express intent more clearly than
              imperative loops.
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// For loop with range</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> (i <span style={{ color: "#ff79c6" }}>in</span> <span style={{ color: "#bd93f9" }}>1</span>..<span style={{ color: "#bd93f9" }}>5</span>) <span style={{ color: "#50fa7b" }}>println</span>(i)       <span style={{ color: "#6272a4" }}>// 1, 2, 3, 4, 5</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> (i <span style={{ color: "#ff79c6" }}>in</span> <span style={{ color: "#bd93f9" }}>1</span> <span style={{ color: "#ff79c6" }}>until</span> <span style={{ color: "#bd93f9" }}>5</span>) <span style={{ color: "#50fa7b" }}>println</span>(i)   <span style={{ color: "#6272a4" }}>// 1, 2, 3, 4 (excludes 5)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> (i <span style={{ color: "#ff79c6" }}>in</span> <span style={{ color: "#bd93f9" }}>5</span> <span style={{ color: "#ff79c6" }}>downTo</span> <span style={{ color: "#bd93f9" }}>1</span>) <span style={{ color: "#50fa7b" }}>println</span>(i)  <span style={{ color: "#6272a4" }}>// 5, 4, 3, 2, 1</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> (i <span style={{ color: "#ff79c6" }}>in</span> <span style={{ color: "#bd93f9" }}>1</span>..<span style={{ color: "#bd93f9" }}>10</span> <span style={{ color: "#ff79c6" }}>step</span> <span style={{ color: "#bd93f9" }}>2</span>) <span style={{ color: "#50fa7b" }}>println</span>(i) <span style={{ color: "#6272a4" }}>// 1, 3, 5, 7, 9</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// For each with collection</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> (item <span style={{ color: "#ff79c6" }}>in</span> items) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>println</span>(item){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// With index</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>for</span> ((index, value) <span style={{ color: "#ff79c6" }}>in</span> items.<span style={{ color: "#50fa7b" }}>withIndex</span>()) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"$index: $value"</span>){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// While and do-while</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>while</span> (x {">"} <span style={{ color: "#bd93f9" }}>0</span>) {"{"} x-- {"}"}{"\n"}
                <span style={{ color: "#ff79c6" }}>do</span> {"{"} x++ {"}"} <span style={{ color: "#ff79c6" }}>while</span> (x {"<"} <span style={{ color: "#bd93f9" }}>10</span>)
              </Typography>
            </Paper>
          </Paper>

          {/* Operators & Expressions Section */}
          <Paper id="operators" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <SwapHorizIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Operators & Expressions
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Kotlin supports all standard operators and adds several powerful ones unique to the language.
              Unlike Java, Kotlin allows **operator overloading**—you can define what <code>+</code> or <code>*</code>
              means for your custom classes. Many operators are actually translated to method calls,
              making the language extensible yet readable. **This convention-over-configuration approach means that
              operators like <code>[]</code> translate to <code>get()</code> and <code>set()</code> calls**, allowing
              your classes to support array-like syntax. Similarly, the <code>in</code> operator translates to{" "}
              <code>contains()</code>, and comparison operators translate to <code>compareTo()</code>. This design
              keeps the syntax clean while remaining predictable and discoverable. **Kotlin also introduces several
              null-safe operators** (<code>?.</code>, <code>?:</code>, <code>!!</code>) that fundamentally change how
              you handle nullable values. The range operator (<code>..</code>) creates ranges that work seamlessly with
              loops and collections. Understanding operator precedence and associativity remains important, but Kotlin's
              expression-based nature means operators can be chained and composed more naturally than in Java.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Arithmetic & Assignment Operators
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Arithmetic</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> sum = <span style={{ color: "#bd93f9" }}>10</span> + <span style={{ color: "#bd93f9" }}>5</span>    <span style={{ color: "#6272a4" }}>// 15</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> diff = <span style={{ color: "#bd93f9" }}>10</span> - <span style={{ color: "#bd93f9" }}>5</span>   <span style={{ color: "#6272a4" }}>// 5</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> prod = <span style={{ color: "#bd93f9" }}>10</span> * <span style={{ color: "#bd93f9" }}>5</span>   <span style={{ color: "#6272a4" }}>// 50</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> quot = <span style={{ color: "#bd93f9" }}>10</span> / <span style={{ color: "#bd93f9" }}>3</span>   <span style={{ color: "#6272a4" }}>// 3 (integer division)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> rem = <span style={{ color: "#bd93f9" }}>10</span> % <span style={{ color: "#bd93f9" }}>3</span>    <span style={{ color: "#6272a4" }}>// 1 (remainder)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Augmented assignment</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> x = <span style={{ color: "#bd93f9" }}>10</span>{"\n"}
                x += <span style={{ color: "#bd93f9" }}>5</span>   <span style={{ color: "#6272a4" }}>// x = x + 5 → 15</span>{"\n"}
                x -= <span style={{ color: "#bd93f9" }}>3</span>   <span style={{ color: "#6272a4" }}>// x = x - 3 → 12</span>{"\n"}
                x *= <span style={{ color: "#bd93f9" }}>2</span>   <span style={{ color: "#6272a4" }}>// x = x * 2 → 24</span>{"\n"}
                x /= <span style={{ color: "#bd93f9" }}>4</span>   <span style={{ color: "#6272a4" }}>// x = x / 4 → 6</span>{"\n"}
                x %= <span style={{ color: "#bd93f9" }}>4</span>   <span style={{ color: "#6272a4" }}>// x = x % 4 → 2</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// No ++ or -- statements - only expressions</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> n = <span style={{ color: "#bd93f9" }}>5</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>println</span>(n++)  <span style={{ color: "#6272a4" }}>// Prints 5, then n = 6</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>println</span>(++n)  <span style={{ color: "#6272a4" }}>// n = 7, then prints 7</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Comparison & Equality
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Comparison operators</span>{"\n"}
                <span style={{ color: "#bd93f9" }}>5</span> {">"} <span style={{ color: "#bd93f9" }}>3</span>    <span style={{ color: "#6272a4" }}>// true</span>{"\n"}
                <span style={{ color: "#bd93f9" }}>5</span> {"<"} <span style={{ color: "#bd93f9" }}>3</span>    <span style={{ color: "#6272a4" }}>// false</span>{"\n"}
                <span style={{ color: "#bd93f9" }}>5</span> {">"}= <span style={{ color: "#bd93f9" }}>5</span>   <span style={{ color: "#6272a4" }}>// true</span>{"\n"}
                <span style={{ color: "#bd93f9" }}>5</span> {"<"}= <span style={{ color: "#bd93f9" }}>4</span>   <span style={{ color: "#6272a4" }}>// false</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Structural equality (== calls equals())</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> a = <span style={{ color: "#f1fa8c" }}>"hello"</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> b = <span style={{ color: "#f1fa8c" }}>"hello"</span>{"\n"}
                a == b    <span style={{ color: "#6272a4" }}>// true - content is equal</span>{"\n"}
                a != b    <span style={{ color: "#6272a4" }}>// false</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Referential equality (same object in memory)</span>{"\n"}
                a === b   <span style={{ color: "#6272a4" }}>// may be true due to string interning</span>{"\n"}
                a !== b   <span style={{ color: "#6272a4" }}>// false</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Null-safe comparison</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>null</span> == <span style={{ color: "#ff79c6" }}>null</span>   <span style={{ color: "#6272a4" }}>// true</span>{"\n"}
                <span style={{ color: "#f1fa8c" }}>"a"</span> == <span style={{ color: "#ff79c6" }}>null</span>    <span style={{ color: "#6272a4" }}>// false, no NPE!</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Kotlin-Specific Operators
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Range operator (..)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> range = <span style={{ color: "#bd93f9" }}>1</span>..<span style={{ color: "#bd93f9" }}>10</span>     <span style={{ color: "#6272a4" }}>// 1 to 10 inclusive</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> until = <span style={{ color: "#bd93f9" }}>1</span> <span style={{ color: "#ff79c6" }}>until</span> <span style={{ color: "#bd93f9" }}>10</span>  <span style={{ color: "#6272a4" }}>// 1 to 9 (excludes 10)</span>{"\n"}
                <span style={{ color: "#bd93f9" }}>5</span> <span style={{ color: "#ff79c6" }}>in</span> range       <span style={{ color: "#6272a4" }}>// true - membership check</span>{"\n"}
                <span style={{ color: "#bd93f9" }}>15</span> !<span style={{ color: "#ff79c6" }}>in</span> range     <span style={{ color: "#6272a4" }}>// true - not in range</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Safe call operator (?.)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> name: <span style={{ color: "#8be9fd" }}>String</span>? = <span style={{ color: "#ff79c6" }}>null</span>{"\n"}
                name?.length       <span style={{ color: "#6272a4" }}>// null (doesn't crash)</span>{"\n"}
                name?.uppercase()  <span style={{ color: "#6272a4" }}>// null</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Elvis operator (?:)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> len = name?.length ?: <span style={{ color: "#bd93f9" }}>0</span>     <span style={{ color: "#6272a4" }}>// 0 if null</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> safe = name ?: <span style={{ color: "#f1fa8c" }}>"default"</span>     <span style={{ color: "#6272a4" }}>// "default" if null</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Not-null assertion (!!)</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// val crash = name!!.length  // NPE if null!</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Spread operator (*)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> arr = <span style={{ color: "#50fa7b" }}>intArrayOf</span>(<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>){"\n"}
                <span style={{ color: "#50fa7b" }}>printAll</span>(*arr)  <span style={{ color: "#6272a4" }}>// Expands array to vararg</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Operator Overloading
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Define what + means for your class</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>data class</span> <span style={{ color: "#8be9fd" }}>Point</span>(<span style={{ color: "#ff79c6" }}>val</span> x: <span style={{ color: "#8be9fd" }}>Int</span>, <span style={{ color: "#ff79c6" }}>val</span> y: <span style={{ color: "#8be9fd" }}>Int</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>operator fun</span> <span style={{ color: "#50fa7b" }}>plus</span>(other: <span style={{ color: "#8be9fd" }}>Point</span>) = <span style={{ color: "#8be9fd" }}>Point</span>(x + other.x, y + other.y){"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>operator fun</span> <span style={{ color: "#50fa7b" }}>minus</span>(other: <span style={{ color: "#8be9fd" }}>Point</span>) = <span style={{ color: "#8be9fd" }}>Point</span>(x - other.x, y - other.y){"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>operator fun</span> <span style={{ color: "#50fa7b" }}>times</span>(scale: <span style={{ color: "#8be9fd" }}>Int</span>) = <span style={{ color: "#8be9fd" }}>Point</span>(x * scale, y * scale){"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>operator fun</span> <span style={{ color: "#50fa7b" }}>unaryMinus</span>() = <span style={{ color: "#8be9fd" }}>Point</span>(-x, -y){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> p1 = <span style={{ color: "#8be9fd" }}>Point</span>(<span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>4</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> p2 = <span style={{ color: "#8be9fd" }}>Point</span>(<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>){"\n"}
                {"\n"}
                p1 + p2   <span style={{ color: "#6272a4" }}>// Point(4, 6)</span>{"\n"}
                p1 - p2   <span style={{ color: "#6272a4" }}>// Point(2, 2)</span>{"\n"}
                p1 * <span style={{ color: "#bd93f9" }}>2</span>    <span style={{ color: "#6272a4" }}>// Point(6, 8)</span>{"\n"}
                -p1       <span style={{ color: "#6272a4" }}>// Point(-3, -4)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Common operator functions:</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// plus(+), minus(-), times(*), div(/), rem(%)</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// unaryPlus(+a), unaryMinus(-a), not(!a)</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// inc(++), dec(--)</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// get([]), set([]=), contains(in), invoke()</span>
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
              Kotlin functions are **first-class citizens**—they can be stored in variables, passed as arguments,
              and returned from other functions. This functional programming influence makes Kotlin dramatically more
              expressive than Java. **Every function is declared with the <code>fun</code> keyword**, and parameter
              types are specified using Pascal notation (<code>name: Type</code>) rather than Java's C-style{" "}
              (<code>Type name</code>). Return types come after the parameter list, separated by a colon. Functions
              can have default argument values, eliminating the need for multiple overloaded variants. **Named arguments
              allow you to skip optional parameters and call functions with arguments in any order**, making APIs more
              flexible and readable. Extension functions let you add methods to existing classes without inheritance,
              which is incredibly powerful for building DSLs and improving API ergonomics. Inline functions, higher-order
              functions, and lambdas give you the power of functional programming without sacrificing performance or
              readability. Together, these features make Kotlin function definitions shorter, clearer, and more
              maintainable than their Java equivalents.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Function Basics
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Standard function declaration</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>greet</span>(name: <span style={{ color: "#8be9fd" }}>String</span>): <span style={{ color: "#8be9fd" }}>String</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#f1fa8c" }}>"Hello, $name!"</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Single-expression function (return type inferred)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>greet</span>(name: <span style={{ color: "#8be9fd" }}>String</span>) = <span style={{ color: "#f1fa8c" }}>"Hello, $name!"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Unit return type (like void) - can be omitted</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>logMessage</span>(msg: <span style={{ color: "#8be9fd" }}>String</span>): <span style={{ color: "#8be9fd" }}>Unit</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>println</span>(msg){"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>logMessage</span>(msg: <span style={{ color: "#8be9fd" }}>String</span>) {"{"} <span style={{ color: "#50fa7b" }}>println</span>(msg) {"}"}  <span style={{ color: "#6272a4" }}>// Same thing</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Vararg parameters</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>printAll</span>(<span style={{ color: "#ff79c6" }}>vararg</span> items: <span style={{ color: "#8be9fd" }}>String</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>for</span> (item <span style={{ color: "#ff79c6" }}>in</span> items) <span style={{ color: "#50fa7b" }}>println</span>(item){"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#50fa7b" }}>printAll</span>(<span style={{ color: "#f1fa8c" }}>"a"</span>, <span style={{ color: "#f1fa8c" }}>"b"</span>, <span style={{ color: "#f1fa8c" }}>"c"</span>)
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Default & Named Arguments
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Default argument values</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>connect</span>({"\n"}
                {"    "}host: <span style={{ color: "#8be9fd" }}>String</span> = <span style={{ color: "#f1fa8c" }}>"localhost"</span>,{"\n"}
                {"    "}port: <span style={{ color: "#8be9fd" }}>Int</span> = <span style={{ color: "#bd93f9" }}>8080</span>,{"\n"}
                {"    "}useSSL: <span style={{ color: "#8be9fd" }}>Boolean</span> = <span style={{ color: "#ff79c6" }}>false</span>{"\n"}
                {")"}: <span style={{ color: "#8be9fd" }}>Connection</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// ...</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Call with defaults</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>connect</span>()                        <span style={{ color: "#6272a4" }}>// All defaults</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>connect</span>(<span style={{ color: "#f1fa8c" }}>"api.server.com"</span>)           <span style={{ color: "#6272a4" }}>// Custom host</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>connect</span>(<span style={{ color: "#f1fa8c" }}>"api.server.com"</span>, <span style={{ color: "#bd93f9" }}>443</span>)      <span style={{ color: "#6272a4" }}>// Custom host and port</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Named arguments (order doesn't matter!)</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>connect</span>(useSSL = <span style={{ color: "#ff79c6" }}>true</span>)            <span style={{ color: "#6272a4" }}>// Skip to later param</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>connect</span>(port = <span style={{ color: "#bd93f9" }}>443</span>, useSSL = <span style={{ color: "#ff79c6" }}>true</span>) <span style={{ color: "#6272a4" }}>// Any order</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>connect</span>({"\n"}
                {"    "}host = <span style={{ color: "#f1fa8c" }}>"secure.api.com"</span>,{"\n"}
                {"    "}useSSL = <span style={{ color: "#ff79c6" }}>true</span>,{"\n"}
                {"    "}port = <span style={{ color: "#bd93f9" }}>443</span>{"\n"}
                {")"})
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Extension Functions
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Add methods to existing classes without inheriting!</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#8be9fd" }}>String</span>.<span style={{ color: "#50fa7b" }}>addExclamation</span>(): <span style={{ color: "#8be9fd" }}>String</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#ff79c6" }}>this</span> + <span style={{ color: "#f1fa8c" }}>"!"</span>  <span style={{ color: "#6272a4" }}>// 'this' refers to the String</span>{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#f1fa8c" }}>"Hello"</span>.<span style={{ color: "#50fa7b" }}>addExclamation</span>()  <span style={{ color: "#6272a4" }}>// "Hello!"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Extension on nullable type</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#8be9fd" }}>String</span>?.<span style={{ color: "#50fa7b" }}>orEmpty</span>(): <span style={{ color: "#8be9fd" }}>String</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#ff79c6" }}>this</span> ?: <span style={{ color: "#f1fa8c" }}>""</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Powerful List extensions</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fun</span> {"<"}<span style={{ color: "#8be9fd" }}>T</span>{">"} <span style={{ color: "#8be9fd" }}>List</span>{"<"}<span style={{ color: "#8be9fd" }}>T</span>{">"}.<span style={{ color: "#50fa7b" }}>secondOrNull</span>(): <span style={{ color: "#8be9fd" }}>T</span>? {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>return</span> <span style={{ color: "#ff79c6" }}>if</span> (size {">"}= <span style={{ color: "#bd93f9" }}>2</span>) <span style={{ color: "#ff79c6" }}>this</span>[<span style={{ color: "#bd93f9" }}>1</span>] <span style={{ color: "#ff79c6" }}>else null</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#50fa7b" }}>listOf</span>(<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>).<span style={{ color: "#50fa7b" }}>secondOrNull</span>()  <span style={{ color: "#6272a4" }}>// 2</span>{"\n"}
                <span style={{ color: "#50fa7b" }}>listOf</span>(<span style={{ color: "#bd93f9" }}>1</span>).<span style={{ color: "#50fa7b" }}>secondOrNull</span>()        <span style={{ color: "#6272a4" }}>// null</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Infix Functions
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Infix notation for readable code</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>infix fun</span> <span style={{ color: "#8be9fd" }}>Int</span>.<span style={{ color: "#50fa7b" }}>times</span>(str: <span style={{ color: "#8be9fd" }}>String</span>) = str.<span style={{ color: "#50fa7b" }}>repeat</span>(<span style={{ color: "#ff79c6" }}>this</span>){"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Call like this</span>{"\n"}
                <span style={{ color: "#bd93f9" }}>3</span> times <span style={{ color: "#f1fa8c" }}>"Hello "</span>  <span style={{ color: "#6272a4" }}>// "Hello Hello Hello "</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// Or traditional</span>{"\n"}
                <span style={{ color: "#bd93f9" }}>3</span>.<span style={{ color: "#50fa7b" }}>times</span>(<span style={{ color: "#f1fa8c" }}>"Hello "</span>){"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Built-in infix functions</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> pair = <span style={{ color: "#f1fa8c" }}>"key"</span> <span style={{ color: "#ff79c6" }}>to</span> <span style={{ color: "#f1fa8c" }}>"value"</span>   <span style={{ color: "#6272a4" }}>// Pair("key", "value")</span>{"\n"}
                <span style={{ color: "#bd93f9" }}>1</span> <span style={{ color: "#ff79c6" }}>until</span> <span style={{ color: "#bd93f9" }}>10</span>              <span style={{ color: "#6272a4" }}>// IntRange 1..9</span>{"\n"}
                <span style={{ color: "#bd93f9" }}>5</span> <span style={{ color: "#ff79c6" }}>downTo</span> <span style={{ color: "#bd93f9" }}>1</span>             <span style={{ color: "#6272a4" }}>// IntProgression 5, 4, 3, 2, 1</span>{"\n"}
                <span style={{ color: "#bd93f9" }}>1</span>..<span style={{ color: "#bd93f9" }}>10</span> <span style={{ color: "#ff79c6" }}>step</span> <span style={{ color: "#bd93f9" }}>2</span>           <span style={{ color: "#6272a4" }}>// 1, 3, 5, 7, 9</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Local Functions
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Functions can be nested inside other functions</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>processUser</span>(user: <span style={{ color: "#8be9fd" }}>User</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Local function - only visible inside processUser</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>validate</span>() {"{"}{"\n"}
                {"        "}<span style={{ color: "#6272a4" }}>// Can access outer function's parameters!</span>{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>if</span> (user.name.<span style={{ color: "#50fa7b" }}>isBlank</span>()) {"{"}{"\n"}
                {"            "}<span style={{ color: "#ff79c6" }}>throw</span> <span style={{ color: "#8be9fd" }}>IllegalArgumentException</span>(<span style={{ color: "#f1fa8c" }}>"Name required"</span>){"\n"}
                {"        "}{"}"}{"\n"}
                {"    "}{"}"}{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>validate</span>()  <span style={{ color: "#6272a4" }}>// Call local function</span>{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// ... rest of processing</span>{"\n"}
                {"}"}
              </Typography>
            </Paper>
          </Paper>

          {/* Null Safety Section */}
          <Paper id="null-safety" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <SecurityIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Null Safety
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              **Kotlin's null safety is one of its killer features**—arguably THE feature that convinced Google to adopt
              Kotlin for Android. The type system distinguishes between **nullable** and **non-nullable** references at
              compile time, eliminating the dreaded <code>NullPointerException</code> before your code ever runs. In Java,
              every reference can be null, and <code>NullPointerException</code> accounts for billions of dollars in
              production bugs annually. Kotlin solves this by making nullability explicit in the type system. **By default,
              variables cannot be null.** If you want to allow null, you must explicitly add <code>?</code> to the type
              (<code>String?</code> instead of <code>String</code>). This forces you to think about nullability upfront
              rather than discovering it through runtime crashes. The compiler tracks nullability through your entire
              program, giving you compile-time safety. If you try to call a method on a nullable type without checking for
              null first, you get a compile error. **The language provides elegant operators for handling nullability**:
              safe calls (<code>?.</code>), Elvis operators (<code>?:</code>), and smart casts that automatically treat
              values as non-null after null checks. This combination of type-system enforcement and convenient operators
              makes null handling both safe and concise. Once you've worked in Kotlin, going back to Java's null handling
              feels reckless and primitive.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Nullable vs Non-Nullable
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Non-nullable - CANNOT be null</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> name: <span style={{ color: "#8be9fd" }}>String</span> = <span style={{ color: "#f1fa8c" }}>"Kotlin"</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// name = null  // Compile error!</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Nullable - CAN be null (note the ?)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>var</span> nullableName: <span style={{ color: "#8be9fd" }}>String</span>? = <span style={{ color: "#f1fa8c" }}>"Kotlin"</span>{"\n"}
                nullableName = <span style={{ color: "#ff79c6" }}>null</span>  <span style={{ color: "#6272a4" }}>// OK!</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Must handle nullability before use</span>{"\n"}
                <span style={{ color: "#6272a4" }}>// println(nullableName.length)  // Error! Could be null</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Check first</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>if</span> (nullableName != <span style={{ color: "#ff79c6" }}>null</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>println</span>(nullableName.length)  <span style={{ color: "#6272a4" }}>// Smart cast to String</span>{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Null-Safe Operators
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>val</span> name: <span style={{ color: "#8be9fd" }}>String</span>? = <span style={{ color: "#50fa7b" }}>getNameOrNull</span>(){"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Safe call (?.) - returns null if receiver is null</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> length: <span style={{ color: "#8be9fd" }}>Int</span>? = name?.length{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> upper: <span style={{ color: "#8be9fd" }}>String</span>? = name?.uppercase(){"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Chain safe calls</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> firstChar: <span style={{ color: "#8be9fd" }}>Char</span>? = name?.uppercase()?.firstOrNull(){"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Elvis operator (?:) - provide default if null</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> len: <span style={{ color: "#8be9fd" }}>Int</span> = name?.length ?: <span style={{ color: "#bd93f9" }}>0</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> safeName: <span style={{ color: "#8be9fd" }}>String</span> = name ?: <span style={{ color: "#f1fa8c" }}>"Unknown"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Elvis with throw or return</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> required = name ?: <span style={{ color: "#ff79c6" }}>throw</span> <span style={{ color: "#8be9fd" }}>IllegalStateException</span>(<span style={{ color: "#f1fa8c" }}>"Name required"</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> orReturn = name ?: <span style={{ color: "#ff79c6" }}>return</span>  <span style={{ color: "#6272a4" }}>// Early return from function</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Not-null assertion (!!) - throws NPE if null</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> forced: <span style={{ color: "#8be9fd" }}>String</span> = name!!  <span style={{ color: "#6272a4" }}>// Use sparingly!</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Safe cast (as?) - returns null instead of ClassCastException</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> str: <span style={{ color: "#8be9fd" }}>String</span>? = value <span style={{ color: "#ff79c6" }}>as</span>? <span style={{ color: "#8be9fd" }}>String</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Scope Functions
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// let - execute block if not null</span>{"\n"}
                name?.<span style={{ color: "#50fa7b" }}>let</span> {"{"} nonNullName -{">"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"Name is $nonNullName"</span>){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// also - perform side effect, return original</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> user = <span style={{ color: "#8be9fd" }}>User</span>(<span style={{ color: "#f1fa8c" }}>"Alice"</span>).<span style={{ color: "#50fa7b" }}>also</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"Created user: </span>${"{"}<span style={{ color: "#ff79c6" }}>it</span>.name{"}"}<span style={{ color: "#f1fa8c" }}>"</span>){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// apply - configure object, return it</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> user = <span style={{ color: "#8be9fd" }}>User</span>().<span style={{ color: "#50fa7b" }}>apply</span> {"{"}{"\n"}
                {"    "}name = <span style={{ color: "#f1fa8c" }}>"Bob"</span>       <span style={{ color: "#6272a4" }}>// this.name</span>{"\n"}
                {"    "}age = <span style={{ color: "#bd93f9" }}>25</span>           <span style={{ color: "#6272a4" }}>// this.age</span>{"\n"}
                {"    "}email = <span style={{ color: "#f1fa8c" }}>"bob@x.com"</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// run - execute block, return result</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> result = name?.<span style={{ color: "#50fa7b" }}>run</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>"Processed: </span>${"{"}<span style={{ color: "#ff79c6" }}>this</span>.uppercase(){"}"}<span style={{ color: "#f1fa8c" }}>"</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// with - call methods on object</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> info = <span style={{ color: "#50fa7b" }}>with</span>(user) {"{"}{"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>"Name: $name, Age: $age"</span>{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Grid container spacing={2}>
              {[
                { func: "let", context: "it", returns: "Lambda result", use: "Null checks, transformations" },
                { func: "also", context: "it", returns: "Context object", use: "Side effects, logging" },
                { func: "apply", context: "this", returns: "Context object", use: "Object configuration" },
                { func: "run", context: "this", returns: "Lambda result", use: "Object scope + result" },
                { func: "with", context: "this", returns: "Lambda result", use: "Grouping calls" },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.func}>
                  <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: alpha(accentColor, 0.03) }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 800, color: accentColor, fontFamily: "monospace" }}>
                      {item.func}
                    </Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                      Context: <strong>{item.context}</strong> | Returns: <strong>{item.returns}</strong>
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {item.use}
                    </Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Collections Section */}
          <Paper id="collections" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <StorageIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Collections
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Kotlin's collection framework distinguishes between **read-only** and **mutable** collections at the type
              level. This prevents accidental modification and makes code intent clearer. **The type system enforces
              immutability**: a <code>List{"<"}T{">"}</code> reference provides no mutation methods, while{" "}
              <code>MutableList{"<"}T{">"}</code> explicitly indicates that the collection can change. This is a
              compile-time guarantee, unlike Java's convention-based approach with{" "}
              <code>Collections.unmodifiableList()</code>. The standard library provides powerful functional operations
              that make collection manipulation concise and expressive. **Operations like <code>map</code>,{" "}
              <code>filter</code>, <code>flatMap</code>, <code>groupBy</code>, and <code>fold</code> eliminate the
              need for explicit loops**, making code more declarative and easier to reason about. These operations are
              also optimized—using sequences (<code>.asSequence()</code>) makes them lazy and efficient for large
              datasets. Kotlin's collections interoperate seamlessly with Java collections, so you can use existing
              libraries without friction. The distinction between read-only and mutable, combined with rich functional
              operators, makes Kotlin's collection API one of its strongest features for everyday programming.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Creating Collections
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Read-only collections (immutable interface)</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> list: <span style={{ color: "#8be9fd" }}>List</span>{"<"}<span style={{ color: "#8be9fd" }}>Int</span>{">"} = <span style={{ color: "#50fa7b" }}>listOf</span>(<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> set: <span style={{ color: "#8be9fd" }}>Set</span>{"<"}<span style={{ color: "#8be9fd" }}>String</span>{">"} = <span style={{ color: "#50fa7b" }}>setOf</span>(<span style={{ color: "#f1fa8c" }}>"a"</span>, <span style={{ color: "#f1fa8c" }}>"b"</span>, <span style={{ color: "#f1fa8c" }}>"c"</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> map: <span style={{ color: "#8be9fd" }}>Map</span>{"<"}<span style={{ color: "#8be9fd" }}>String</span>, <span style={{ color: "#8be9fd" }}>Int</span>{">"} = <span style={{ color: "#50fa7b" }}>mapOf</span>(<span style={{ color: "#f1fa8c" }}>"a"</span> <span style={{ color: "#ff79c6" }}>to</span> <span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#f1fa8c" }}>"b"</span> <span style={{ color: "#ff79c6" }}>to</span> <span style={{ color: "#bd93f9" }}>2</span>){"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Mutable collections</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> mutableList = <span style={{ color: "#50fa7b" }}>mutableListOf</span>(<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>){"\n"}
                mutableList.<span style={{ color: "#50fa7b" }}>add</span>(<span style={{ color: "#bd93f9" }}>4</span>)            <span style={{ color: "#6272a4" }}>// [1, 2, 3, 4]</span>{"\n"}
                mutableList.<span style={{ color: "#50fa7b" }}>removeAt</span>(<span style={{ color: "#bd93f9" }}>0</span>)       <span style={{ color: "#6272a4" }}>// [2, 3, 4]</span>{"\n"}
                mutableList[<span style={{ color: "#bd93f9" }}>0</span>] = <span style={{ color: "#bd93f9" }}>10</span>          <span style={{ color: "#6272a4" }}>// [10, 3, 4]</span>{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> mutableSet = <span style={{ color: "#50fa7b" }}>mutableSetOf</span>(<span style={{ color: "#f1fa8c" }}>"a"</span>, <span style={{ color: "#f1fa8c" }}>"b"</span>){"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> mutableMap = <span style={{ color: "#50fa7b" }}>mutableMapOf</span>(<span style={{ color: "#f1fa8c" }}>"key"</span> <span style={{ color: "#ff79c6" }}>to</span> <span style={{ color: "#f1fa8c" }}>"value"</span>){"\n"}
                mutableMap[<span style={{ color: "#f1fa8c" }}>"newKey"</span>] = <span style={{ color: "#f1fa8c" }}>"newValue"</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Empty collections</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> empty = <span style={{ color: "#50fa7b" }}>emptyList</span>{"<"}<span style={{ color: "#8be9fd" }}>Int</span>{">"}(){"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> emptyMap = <span style={{ color: "#50fa7b" }}>emptyMap</span>{"<"}<span style={{ color: "#8be9fd" }}>String</span>, <span style={{ color: "#8be9fd" }}>Any</span>{">"}()
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Collection Operations
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>val</span> numbers = <span style={{ color: "#50fa7b" }}>listOf</span>(<span style={{ color: "#bd93f9" }}>1</span>, <span style={{ color: "#bd93f9" }}>2</span>, <span style={{ color: "#bd93f9" }}>3</span>, <span style={{ color: "#bd93f9" }}>4</span>, <span style={{ color: "#bd93f9" }}>5</span>){"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Transform</span>{"\n"}
                numbers.<span style={{ color: "#50fa7b" }}>map</span> {"{"} it * <span style={{ color: "#bd93f9" }}>2</span> {"}"}           <span style={{ color: "#6272a4" }}>// [2, 4, 6, 8, 10]</span>{"\n"}
                numbers.<span style={{ color: "#50fa7b" }}>filter</span> {"{"} it % <span style={{ color: "#bd93f9" }}>2</span> == <span style={{ color: "#bd93f9" }}>0</span> {"}"}   <span style={{ color: "#6272a4" }}>// [2, 4]</span>{"\n"}
                numbers.<span style={{ color: "#50fa7b" }}>flatMap</span> {"{"} <span style={{ color: "#50fa7b" }}>listOf</span>(it, it) {"}"} <span style={{ color: "#6272a4" }}>// [1, 1, 2, 2, ...]</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Aggregate</span>{"\n"}
                numbers.<span style={{ color: "#50fa7b" }}>sum</span>()                   <span style={{ color: "#6272a4" }}>// 15</span>{"\n"}
                numbers.<span style={{ color: "#50fa7b" }}>average</span>()               <span style={{ color: "#6272a4" }}>// 3.0</span>{"\n"}
                numbers.<span style={{ color: "#50fa7b" }}>reduce</span> {"{"} acc, n -{">"} acc + n {"}"} <span style={{ color: "#6272a4" }}>// 15</span>{"\n"}
                numbers.<span style={{ color: "#50fa7b" }}>fold</span>(<span style={{ color: "#bd93f9" }}>10</span>) {"{"} acc, n -{">"} acc + n {"}"} <span style={{ color: "#6272a4" }}>// 25</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Find</span>{"\n"}
                numbers.<span style={{ color: "#50fa7b" }}>first</span>()                 <span style={{ color: "#6272a4" }}>// 1</span>{"\n"}
                numbers.<span style={{ color: "#50fa7b" }}>last</span>()                  <span style={{ color: "#6272a4" }}>// 5</span>{"\n"}
                numbers.<span style={{ color: "#50fa7b" }}>find</span> {"{"} it {">"} <span style={{ color: "#bd93f9" }}>3</span> {"}"}        <span style={{ color: "#6272a4" }}>// 4 (or null)</span>{"\n"}
                numbers.<span style={{ color: "#50fa7b" }}>firstOrNull</span> {"{"} it {">"} <span style={{ color: "#bd93f9" }}>10</span> {"}"} <span style={{ color: "#6272a4" }}>// null</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Check</span>{"\n"}
                numbers.<span style={{ color: "#50fa7b" }}>any</span> {"{"} it {">"} <span style={{ color: "#bd93f9" }}>3</span> {"}"}         <span style={{ color: "#6272a4" }}>// true</span>{"\n"}
                numbers.<span style={{ color: "#50fa7b" }}>all</span> {"{"} it {">"} <span style={{ color: "#bd93f9" }}>0</span> {"}"}         <span style={{ color: "#6272a4" }}>// true</span>{"\n"}
                numbers.<span style={{ color: "#50fa7b" }}>none</span> {"{"} it {"<"} <span style={{ color: "#bd93f9" }}>0</span> {"}"}        <span style={{ color: "#6272a4" }}>// true</span>{"\n"}
                <span style={{ color: "#bd93f9" }}>3</span> <span style={{ color: "#ff79c6" }}>in</span> numbers                <span style={{ color: "#6272a4" }}>// true</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Grouping & Sorting
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>val</span> words = <span style={{ color: "#50fa7b" }}>listOf</span>(<span style={{ color: "#f1fa8c" }}>"apple"</span>, <span style={{ color: "#f1fa8c" }}>"banana"</span>, <span style={{ color: "#f1fa8c" }}>"apricot"</span>, <span style={{ color: "#f1fa8c" }}>"blueberry"</span>){"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Group by first letter</span>{"\n"}
                words.<span style={{ color: "#50fa7b" }}>groupBy</span> {"{"} it.<span style={{ color: "#50fa7b" }}>first</span>() {"}"}{"\n"}
                <span style={{ color: "#6272a4" }}>// {"{"}a=[apple, apricot], b=[banana, blueberry]{"}"}</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Associate</span>{"\n"}
                words.<span style={{ color: "#50fa7b" }}>associateWith</span> {"{"} it.length {"}"}  <span style={{ color: "#6272a4" }}>// {"{"}apple=5, banana=6, ...{"}"}</span>{"\n"}
                words.<span style={{ color: "#50fa7b" }}>associateBy</span> {"{"} it.<span style={{ color: "#50fa7b" }}>first</span>() {"}"}    <span style={{ color: "#6272a4" }}>// {"{"}a=apricot, b=blueberry{"}"}</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Sort</span>{"\n"}
                words.<span style={{ color: "#50fa7b" }}>sorted</span>()                   <span style={{ color: "#6272a4" }}>// [apple, apricot, ...]</span>{"\n"}
                words.<span style={{ color: "#50fa7b" }}>sortedDescending</span>()          <span style={{ color: "#6272a4" }}>// [..., apple]</span>{"\n"}
                words.<span style={{ color: "#50fa7b" }}>sortedBy</span> {"{"} it.length {"}"}      <span style={{ color: "#6272a4" }}>// by length</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Partition</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> (short, long) = words.<span style={{ color: "#50fa7b" }}>partition</span> {"{"} it.length {"<"} <span style={{ color: "#bd93f9" }}>6</span> {"}"}{"\n"}
                <span style={{ color: "#6272a4" }}>// short = [apple], long = [banana, apricot, blueberry]</span>
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Sequences (Lazy Evaluation)
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// For large collections, use sequences for better performance</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> result = (<span style={{ color: "#bd93f9" }}>1</span>..<span style={{ color: "#bd93f9" }}>1_000_000</span>){"\n"}
                {"    "}.<span style={{ color: "#50fa7b" }}>asSequence</span>()           <span style={{ color: "#6272a4" }}>// Convert to sequence</span>{"\n"}
                {"    "}.<span style={{ color: "#50fa7b" }}>filter</span> {"{"} it % <span style={{ color: "#bd93f9" }}>2</span> == <span style={{ color: "#bd93f9" }}>0</span> {"}"} <span style={{ color: "#6272a4" }}>// Lazy filter</span>{"\n"}
                {"    "}.<span style={{ color: "#50fa7b" }}>map</span> {"{"} it * <span style={{ color: "#bd93f9" }}>2</span> {"}"}          <span style={{ color: "#6272a4" }}>// Lazy map</span>{"\n"}
                {"    "}.<span style={{ color: "#50fa7b" }}>take</span>(<span style={{ color: "#bd93f9" }}>10</span>)               <span style={{ color: "#6272a4" }}>// Take first 10</span>{"\n"}
                {"    "}.<span style={{ color: "#50fa7b" }}>toList</span>()              <span style={{ color: "#6272a4" }}>// Terminal operation</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Generate sequence</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> fibonacci = <span style={{ color: "#50fa7b" }}>generateSequence</span>(<span style={{ color: "#8be9fd" }}>Pair</span>(<span style={{ color: "#bd93f9" }}>0</span>, <span style={{ color: "#bd93f9" }}>1</span>)) {"{"} (a, b) -{">"}{"\n"}
                {"    "}<span style={{ color: "#8be9fd" }}>Pair</span>(b, a + b){"\n"}
                {"}"}.<span style={{ color: "#50fa7b" }}>map</span> {"{"} it.first {"}"}{"\n"}
                {"\n"}
                fibonacci.<span style={{ color: "#50fa7b" }}>take</span>(<span style={{ color: "#bd93f9" }}>10</span>).<span style={{ color: "#50fa7b" }}>toList</span>()  <span style={{ color: "#6272a4" }}>// [0, 1, 1, 2, 3, 5, 8, 13, 21, 34]</span>
              </Typography>
            </Paper>
          </Paper>

          {/* OOP in Kotlin Section */}
          <Paper id="oop" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <ClassIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                OOP in Kotlin
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Kotlin's OOP model is **cleaner and more concise than Java's**, eliminating much of the ceremony that
              makes Java class definitions verbose. Classes are **final by default**, which promotes composition over
              inheritance and prevents common mistakes like inadvertently allowing subclassing. If you want inheritance,
              you must explicitly mark classes and methods as <code>open</code>. **Properties replace Java's
              getter/setter boilerplate**—instead of writing <code>private String name; public String getName() {"{"} ...
              {"}"}</code>, you simply write <code>val name: String</code>. Kotlin generates the accessor methods
              automatically, and you can customize them if needed. Constructors are declared directly in the class
              header, which dramatically reduces the amount of code you need to write. **Primary constructors define
              parameters right after the class name**, and those parameters can be automatically turned into properties
              by adding <code>val</code> or <code>var</code>. Secondary constructors exist for more complex initialization
              scenarios, but primary constructors cover 90% of use cases. Data classes automatically generate{" "}
              <code>equals()</code>, <code>hashCode()</code>, <code>toString()</code>, and <code>copy()</code> methods,
              eliminating hundreds of lines of boilerplate. **Sealed classes and interfaces create restricted type
              hierarchies**, perfect for modeling state machines and ADTs (algebraic data types). Combined with{" "}
              <code>when</code> expressions, sealed classes enable exhaustive pattern matching at compile time. Kotlin's
              OOP is pragmatic—it takes the best parts of Java's class system and removes the pain points.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Classes & Constructors
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Primary constructor in class header</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Person</span>(<span style={{ color: "#ff79c6" }}>val</span> name: <span style={{ color: "#8be9fd" }}>String</span>, <span style={{ color: "#ff79c6" }}>var</span> age: <span style={{ color: "#8be9fd" }}>Int</span>){"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> person = <span style={{ color: "#8be9fd" }}>Person</span>(<span style={{ color: "#f1fa8c" }}>"Alice"</span>, <span style={{ color: "#bd93f9" }}>30</span>){"\n"}
                person.name   <span style={{ color: "#6272a4" }}>// "Alice" (val = read-only)</span>{"\n"}
                person.age = <span style={{ color: "#bd93f9" }}>31</span>  <span style={{ color: "#6272a4" }}>// OK (var = mutable)</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// With init block and secondary constructor</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>User</span>(<span style={{ color: "#ff79c6" }}>val</span> name: <span style={{ color: "#8be9fd" }}>String</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> email: <span style={{ color: "#8be9fd" }}>String</span> = <span style={{ color: "#f1fa8c" }}>""</span>{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Init block runs after primary constructor</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>init</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"Creating user: $name"</span>){"\n"}
                {"    "}{"}"}{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Secondary constructor</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>constructor</span>(name: <span style={{ color: "#8be9fd" }}>String</span>, email: <span style={{ color: "#8be9fd" }}>String</span>) : <span style={{ color: "#ff79c6" }}>this</span>(name) {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>this</span>.email = email{"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Properties
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Rectangle</span>(<span style={{ color: "#ff79c6" }}>val</span> width: <span style={{ color: "#8be9fd" }}>Int</span>, <span style={{ color: "#ff79c6" }}>val</span> height: <span style={{ color: "#8be9fd" }}>Int</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Computed property (no backing field)</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>val</span> area: <span style={{ color: "#8be9fd" }}>Int</span>{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>get</span>() = width * height{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Property with custom getter and setter</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> label: <span style={{ color: "#8be9fd" }}>String</span> = <span style={{ color: "#f1fa8c" }}>""</span>{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>get</span>() = <span style={{ color: "#ff79c6" }}>field</span>.uppercase()  <span style={{ color: "#6272a4" }}>// 'field' = backing field</span>{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>set</span>(value) {"{"}{"\n"}
                {"            "}<span style={{ color: "#ff79c6" }}>field</span> = value.trim(){"\n"}
                {"        "}{"}"}{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Late-initialized property</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>lateinit var</span> description: <span style={{ color: "#8be9fd" }}>String</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Lazy property - computed once on first access</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> expensive: <span style={{ color: "#8be9fd" }}>String</span> <span style={{ color: "#ff79c6" }}>by</span> <span style={{ color: "#50fa7b" }}>lazy</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"Computing..."</span>){"\n"}
                {"    "}<span style={{ color: "#f1fa8c" }}>"expensive value"</span>{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Visibility Modifiers
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Example</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>public</span> <span style={{ color: "#ff79c6" }}>val</span> a = <span style={{ color: "#bd93f9" }}>1</span>     <span style={{ color: "#6272a4" }}>// Default, visible everywhere</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>private</span> <span style={{ color: "#ff79c6" }}>val</span> b = <span style={{ color: "#bd93f9" }}>2</span>    <span style={{ color: "#6272a4" }}>// Only in this class</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>protected</span> <span style={{ color: "#ff79c6" }}>val</span> c = <span style={{ color: "#bd93f9" }}>3</span>  <span style={{ color: "#6272a4" }}>// This class + subclasses</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>internal</span> <span style={{ color: "#ff79c6" }}>val</span> d = <span style={{ color: "#bd93f9" }}>4</span>   <span style={{ color: "#6272a4" }}>// Same module</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Private setter, public getter</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Counter</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>var</span> count: <span style={{ color: "#8be9fd" }}>Int</span> = <span style={{ color: "#bd93f9" }}>0</span>{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>private set</span>  <span style={{ color: "#6272a4" }}>// Can only set internally</span>{"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>increment</span>() {"{"} count++ {"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Companion Objects & Object Declarations
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Companion object - like static in Java</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>MyClass</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>companion object</span> {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>const val</span> <span style={{ color: "#50fa7b" }}>TAG</span> = <span style={{ color: "#f1fa8c" }}>"MyClass"</span>{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>create</span>(): <span style={{ color: "#8be9fd" }}>MyClass</span> = <span style={{ color: "#8be9fd" }}>MyClass</span>(){"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#8be9fd" }}>MyClass</span>.TAG      <span style={{ color: "#6272a4" }}>// "MyClass"</span>{"\n"}
                <span style={{ color: "#8be9fd" }}>MyClass</span>.<span style={{ color: "#50fa7b" }}>create</span>()  <span style={{ color: "#6272a4" }}>// Factory method</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Object declaration - singleton</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>object</span> <span style={{ color: "#8be9fd" }}>Database</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>val</span> url = <span style={{ color: "#f1fa8c" }}>"jdbc:..."</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>connect</span>() {"{"} <span style={{ color: "#6272a4" }}>/* ... */</span> {"}"}{"\n"}
                {"}"}{"\n"}
                <span style={{ color: "#8be9fd" }}>Database</span>.<span style={{ color: "#50fa7b" }}>connect</span>()  <span style={{ color: "#6272a4" }}>// Access singleton directly</span>{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Object expression - anonymous object</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> listener = <span style={{ color: "#ff79c6" }}>object</span> : <span style={{ color: "#8be9fd" }}>ClickListener</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>override fun</span> <span style={{ color: "#50fa7b" }}>onClick</span>() {"{"} <span style={{ color: "#6272a4" }}>/* ... */</span> {"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>
          </Paper>

          {/* Inheritance & Interfaces Section */}
          <Paper id="inheritance" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <LayersIcon />
              </Avatar>
              <Typography variant="h5" sx={{ fontWeight: 800 }}>
                Inheritance & Interfaces
              </Typography>
            </Box>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Kotlin classes are <strong>final by default</strong>—you must explicitly mark a class as
              <code> open</code> to allow inheritance. This design choice promotes composition over
              inheritance and prevents fragile base class issues. Interfaces in Kotlin can contain
              default implementations, making them more powerful than Java 7 interfaces.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Inheritance
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Must be 'open' to allow inheritance</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>open class</span> <span style={{ color: "#8be9fd" }}>Animal</span>(<span style={{ color: "#ff79c6" }}>val</span> name: <span style={{ color: "#8be9fd" }}>String</span>) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>open fun</span> <span style={{ color: "#50fa7b" }}>sound</span>() = <span style={{ color: "#f1fa8c" }}>"Some sound"</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>eat</span>() = <span style={{ color: "#f1fa8c" }}>"$name is eating"</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Extend with : and call super constructor</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Dog</span>(name: <span style={{ color: "#8be9fd" }}>String</span>) : <span style={{ color: "#8be9fd" }}>Animal</span>(name) {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>override fun</span> <span style={{ color: "#50fa7b" }}>sound</span>() = <span style={{ color: "#f1fa8c" }}>"Woof!"</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Abstract classes</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>abstract class</span> <span style={{ color: "#8be9fd" }}>Shape</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>abstract val</span> area: <span style={{ color: "#8be9fd" }}>Double</span>  <span style={{ color: "#6272a4" }}>// Must be overridden</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>abstract fun</span> <span style={{ color: "#50fa7b" }}>draw</span>(){"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Concrete method</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>describe</span>() = <span style={{ color: "#f1fa8c" }}>"Shape with area $area"</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Circle</span>(<span style={{ color: "#ff79c6" }}>val</span> radius: <span style={{ color: "#8be9fd" }}>Double</span>) : <span style={{ color: "#8be9fd" }}>Shape</span>() {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>override val</span> area = <span style={{ color: "#8be9fd" }}>Math</span>.PI * radius * radius{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>override fun</span> <span style={{ color: "#50fa7b" }}>draw</span>() {"{"} <span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"Drawing circle"</span>) {"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Interfaces
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Interface with abstract and default methods</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>interface</span> <span style={{ color: "#8be9fd" }}>Clickable</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>click</span>()  <span style={{ color: "#6272a4" }}>// Abstract</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>showOff</span>() = <span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"I'm clickable!"</span>)  <span style={{ color: "#6272a4" }}>// Default impl</span>{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>interface</span> <span style={{ color: "#8be9fd" }}>Focusable</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>focus</span>(){"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>showOff</span>() = <span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"I'm focusable!"</span>){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// Implement multiple interfaces</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Button</span> : <span style={{ color: "#8be9fd" }}>Clickable</span>, <span style={{ color: "#8be9fd" }}>Focusable</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>override fun</span> <span style={{ color: "#50fa7b" }}>click</span>() = <span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"Clicked!"</span>){"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>override fun</span> <span style={{ color: "#50fa7b" }}>focus</span>() = <span style={{ color: "#50fa7b" }}>println</span>(<span style={{ color: "#f1fa8c" }}>"Focused!"</span>){"\n"}
                {"    "}{"\n"}
                {"    "}<span style={{ color: "#6272a4" }}>// Must override when conflict exists</span>{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>override fun</span> <span style={{ color: "#50fa7b" }}>showOff</span>() {"{"}{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>super</span>{"<"}<span style={{ color: "#8be9fd" }}>Clickable</span>{">"}.<span style={{ color: "#50fa7b" }}>showOff</span>()  <span style={{ color: "#6272a4" }}>// Call specific super</span>{"\n"}
                {"        "}<span style={{ color: "#ff79c6" }}>super</span>{"<"}<span style={{ color: "#8be9fd" }}>Focusable</span>{">"}.<span style={{ color: "#50fa7b" }}>showOff</span>(){"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}
              </Typography>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: accentColor }}>
              Delegation
            </Typography>

            <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: "#1a1a2e", fontFamily: "monospace" }}>
              <Typography variant="body2" sx={{ color: "#f8f8f2" }}>
                <span style={{ color: "#6272a4" }}>// Delegate interface implementation to another object</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>interface</span> <span style={{ color: "#8be9fd" }}>Logger</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>log</span>(message: <span style={{ color: "#8be9fd" }}>String</span>){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>ConsoleLogger</span> : <span style={{ color: "#8be9fd" }}>Logger</span> {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>override fun</span> <span style={{ color: "#50fa7b" }}>log</span>(message: <span style={{ color: "#8be9fd" }}>String</span>) = <span style={{ color: "#50fa7b" }}>println</span>(message){"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#6272a4" }}>// 'by' delegates Logger implementation to logger parameter</span>{"\n"}
                <span style={{ color: "#ff79c6" }}>class</span> <span style={{ color: "#8be9fd" }}>Service</span>(logger: <span style={{ color: "#8be9fd" }}>Logger</span>) : <span style={{ color: "#8be9fd" }}>Logger</span> <span style={{ color: "#ff79c6" }}>by</span> logger {"{"}{"\n"}
                {"    "}<span style={{ color: "#ff79c6" }}>fun</span> <span style={{ color: "#50fa7b" }}>doWork</span>() {"{"}{"\n"}
                {"        "}<span style={{ color: "#50fa7b" }}>log</span>(<span style={{ color: "#f1fa8c" }}>"Working..."</span>)  <span style={{ color: "#6272a4" }}>// Delegated to logger</span>{"\n"}
                {"    "}{"}"}{"\n"}
                {"}"}{"\n"}
                {"\n"}
                <span style={{ color: "#ff79c6" }}>val</span> service = <span style={{ color: "#8be9fd" }}>Service</span>(<span style={{ color: "#8be9fd" }}>ConsoleLogger</span>()){"\n"}
                service.<span style={{ color: "#50fa7b" }}>log</span>(<span style={{ color: "#f1fa8c" }}>"Hello"</span>)  <span style={{ color: "#6272a4" }}>// Prints "Hello" via ConsoleLogger</span>
              </Typography>
            </Paper>
          </Paper>

          <TopicPlaceholder
            id="data-classes"
            title="Data Classes & Sealed Classes"
            icon={<ViewModuleIcon />}
            color={accentColor}
            description="Data classes (automatic equals, hashCode, copy, componentN), sealed classes/interfaces for restricted hierarchies, enum classes, and inline/value classes."
          />

          <TopicPlaceholder
            id="lambdas"
            title="Lambdas & Higher-Order Functions"
            icon={<AutoFixHighIcon />}
            color={accentColor}
            description="Lambda expressions, higher-order functions, function types, inline functions, crossinline/noinline, and functional programming patterns in Kotlin."
          />

          <TopicPlaceholder
            id="coroutines"
            title="Coroutines"
            icon={<SyncIcon />}
            color={accentColor}
            description="Kotlin's coroutines for async programming: suspend functions, coroutine builders (launch, async), scopes, contexts, Flow for reactive streams, and structured concurrency."
          />

          <TopicPlaceholder
            id="android"
            title="Android Development"
            icon={<AndroidIcon />}
            color={accentColor}
            description="Kotlin for Android: Jetpack Compose, ViewModels, LiveData/StateFlow, Room database, Navigation, Hilt dependency injection, and Android-specific Kotlin extensions."
          />

          <TopicPlaceholder
            id="multiplatform"
            title="Kotlin Multiplatform"
            icon={<CloudIcon />}
            color={accentColor}
            description="Kotlin Multiplatform Mobile (KMM) and Compose Multiplatform: sharing code between Android, iOS, web, and desktop. expect/actual declarations and platform-specific implementations."
          />

          <TopicPlaceholder
            id="advanced"
            title="Advanced Topics"
            icon={<DeveloperBoardIcon />}
            color={accentColor}
            description="DSL construction, delegation, generics with variance (in/out), reflection, annotations, type aliases, contracts, and advanced Kotlin patterns."
          />

          {/* Knowledge Quiz Section */}
          <Paper id="quiz" sx={{ p: 4, mb: 4, borderRadius: 4 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
              <Avatar sx={{ bgcolor: alpha(accentColor, 0.15), color: accentColor, width: 48, height: 48 }}>
                <QuizIcon />
              </Avatar>
              <Box>
                <Typography variant="h5" sx={{ fontWeight: 800 }}>
                  Knowledge Quiz
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Test your Kotlin knowledge with 75 questions across 7 categories
                </Typography>
              </Box>
            </Box>
            <KotlinQuiz />
          </Paper>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}
