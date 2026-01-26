import React, { useState, useEffect } from "react";
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
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import CodeIcon from "@mui/icons-material/Code";
import SchoolIcon from "@mui/icons-material/School";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import TerminalIcon from "@mui/icons-material/Terminal";
import BuildIcon from "@mui/icons-material/Build";
import WebIcon from "@mui/icons-material/Web";
import StorageIcon from "@mui/icons-material/Storage";
import SpeedIcon from "@mui/icons-material/Speed";
import ExtensionIcon from "@mui/icons-material/Extension";
import CloudIcon from "@mui/icons-material/Cloud";
import PhoneIphoneIcon from "@mui/icons-material/PhoneIphone";
import ConstructionIcon from "@mui/icons-material/Construction";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import ListAltIcon from "@mui/icons-material/ListAlt";
import { Link, useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";

export default function JavaScriptFundamentalsPage() {
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");

  const pageContext = `JavaScript Fundamentals learning page - comprehensive guide covering JavaScript basics, ES6+ features, DOM manipulation, async programming, and popular frameworks like React, Node.js, Vue, and build tools like Vite and Webpack.`;

  const accentColor = "#f7df1e"; // JavaScript yellow
  const accentDark = "#c7b200";

  const quickStats = [
    { label: "Modules", value: "26", color: "#f7df1e" },
    { label: "Frameworks", value: "6+", color: "#61dafb" },
    { label: "Quiz Questions", value: "75", color: "#22c55e" },
    { label: "Difficulty", value: "Beginner+", color: "#8b5cf6" },
  ];

  const moduleNavItems = [
    { id: "introduction", label: "Introduction", icon: "📖" },
    { id: "basics", label: "JS Basics", icon: "🚀" },
    { id: "variables", label: "Variables & Types", icon: "📦" },
    { id: "functions", label: "Functions", icon: "⚡" },
    { id: "objects-arrays", label: "Objects & Arrays", icon: "🗂️" },
    { id: "dom", label: "DOM Manipulation", icon: "🌐" },
    { id: "async", label: "Async JavaScript", icon: "⏳" },
    { id: "es6", label: "ES6+ Features", icon: "✨" },
    { id: "modules", label: "Modules & Imports", icon: "📚" },
    { id: "react", label: "React", icon: "⚛️" },
    { id: "nodejs", label: "Node.js", icon: "🟢" },
    { id: "vue", label: "Vue.js", icon: "💚" },
    { id: "vite", label: "Vite", icon: "⚡" },
    { id: "webpack", label: "Webpack", icon: "📦" },
    { id: "typescript", label: "TypeScript", icon: "🔷" },
    { id: "testing", label: "Testing", icon: "🧪" },
    { id: "js-engine", label: "JS Engine Deep Dive", icon: "🔧" },
    { id: "closures-scope", label: "Closures & Scope", icon: "🔒" },
    { id: "this-keyword", label: "The 'this' Keyword", icon: "👆" },
    { id: "prototypes", label: "Prototypes & Inheritance", icon: "🧬" },
    { id: "error-handling", label: "Error Handling", icon: "🛡️" },
    { id: "web-apis", label: "Web APIs", icon: "🌍" },
    { id: "performance", label: "Performance Optimization", icon: "⚡" },
    { id: "security", label: "Security Best Practices", icon: "🔐" },
    { id: "debugging", label: "Debugging Mastery", icon: "🐛" },
    { id: "design-patterns", label: "Design Patterns", icon: "🏗️" },
    { id: "quiz", label: "Quiz", icon: "📝" },
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

  return (
    <LearnPageLayout pageTitle="JavaScript Fundamentals" pageContext={pageContext}>
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
            color: "#000",
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
              background: `linear-gradient(135deg, ${alpha(accentColor, 0.15)} 0%, ${alpha("#000", 0.1)} 100%)`,
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
                    background: `linear-gradient(135deg, ${accentColor}, #000)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    boxShadow: `0 8px 32px ${alpha(accentColor, 0.35)}`,
                  }}
                >
                  <Typography sx={{ fontSize: 36, fontWeight: 900, color: "#000" }}>JS</Typography>
                </Box>
                <Box>
                  <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                    JavaScript Fundamentals
                  </Typography>
                  <Typography variant="h6" color="text.secondary">
                    The language of the web and beyond
                  </Typography>
                </Box>
              </Box>

              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                <Chip label="Beginner" color="success" />
                <Chip label="Web Development" sx={{ bgcolor: alpha("#61dafb", 0.15), color: "#61dafb", fontWeight: 600 }} />
                <Chip label="Full Stack" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
                <Chip label="Frameworks" sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }} />
              </Box>

              <Grid container spacing={2}>
                {quickStats.map((stat) => (
                  <Grid item xs={6} sm={3} key={stat.label}>
                    <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, bgcolor: alpha(stat.color, 0.1), border: `1px solid ${alpha(stat.color, 0.2)}` }}>
                      <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>{stat.value}</Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>{stat.label}</Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Box>
          </Paper>

          {/* Introduction */}
          <Paper id="introduction" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha(accentColor, 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <SchoolIcon sx={{ color: accentColor, fontSize: 32 }} />
              Introduction to JavaScript
            </Typography>
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              JavaScript is the programming language that powers the modern web. Originally created in just 10 days by Brendan Eich in 1995, 
              it has evolved from a simple scripting language for adding interactivity to web pages into one of the most versatile and 
              widely-used programming languages in the world. Today, JavaScript runs everywhere—in browsers, on servers, in mobile apps, 
              desktop applications, IoT devices, and even in space (NASA uses Node.js for certain applications).
            </Typography>
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              At its core, JavaScript is a high-level, interpreted, dynamically-typed language that supports multiple programming paradigms 
              including object-oriented, functional, and event-driven programming. Unlike languages like C++ or Java that require compilation, 
              JavaScript code is executed directly by the JavaScript engine (like V8 in Chrome or SpiderMonkey in Firefox), making development 
              fast and iterative. The language features first-class functions, closures, prototypal inheritance, and a powerful event loop 
              that enables non-blocking asynchronous operations—a key feature that makes JavaScript excel at handling I/O-intensive tasks.
            </Typography>
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              The JavaScript ecosystem is massive and constantly evolving. ECMAScript (ES) standards define the language specification, with 
              ES6 (2015) introducing game-changing features like arrow functions, classes, modules, promises, template literals, and 
              destructuring. Modern JavaScript (ES2020+) continues to add powerful features like optional chaining, nullish coalescing, 
              private class fields, and top-level await. The npm registry hosts over 2 million packages, making it the largest software 
              registry in the world and providing solutions for virtually any programming challenge you might face.
            </Typography>
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              On the frontend, JavaScript frameworks like React, Vue, Angular, and Svelte have revolutionized how we build user interfaces, 
              enabling the creation of complex, interactive single-page applications (SPAs) with component-based architectures. React, 
              developed by Facebook, introduced the virtual DOM concept and declarative UI patterns that have influenced the entire industry. 
              Vue offers a progressive framework that's easy to adopt incrementally, while Angular provides a full-featured enterprise solution 
              with dependency injection and TypeScript integration out of the box.
            </Typography>
            <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
              Node.js brought JavaScript to the server side in 2009, enabling full-stack JavaScript development and spawning an entire 
              ecosystem of backend frameworks like Express, Fastify, NestJS, and Koa. This means you can use a single language across your 
              entire application stack, share code between frontend and backend, and leverage your JavaScript knowledge to build APIs, 
              real-time applications with WebSockets, command-line tools, and microservices. Companies like Netflix, LinkedIn, PayPal, and 
              Uber rely heavily on Node.js for their backend infrastructure.
            </Typography>
            <Typography variant="body1" sx={{ lineHeight: 1.8 }}>
              Build tools and bundlers like Vite, Webpack, Rollup, and esbuild have transformed the development experience, offering hot 
              module replacement (HMR), code splitting, tree shaking, and optimized production builds. TypeScript, a superset of JavaScript 
              that adds static typing, has become increasingly popular for large-scale applications, catching errors at compile time and 
              improving developer productivity through better tooling and IDE support. Whether you're building a simple website, a complex 
              web application, a mobile app with React Native, or a desktop application with Electron, JavaScript provides the foundation 
              for modern software development.
            </Typography>
          </Paper>

          {/* Section 1: JavaScript Basics */}
          <Paper id="basics" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha(accentColor, 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha(accentColor, 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <CodeIcon sx={{ color: accentColor }} />
              </Box>
              JavaScript Basics
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              JavaScript code can be included in HTML pages using the <code>&lt;script&gt;</code> tag, either inline or by linking to external files. 
              Modern best practice is to place scripts at the end of the body or use the <code>defer</code> attribute to ensure the DOM is loaded first.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha(accentColor, 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: accentColor, fontWeight: 700, mb: 1 }}>Hello World</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Your first JavaScript program
console.log("Hello, World!");

// Variables
let message = "Welcome to JS";
const PI = 3.14159;

// Output to console
console.log(message);
console.log("PI is:", PI);`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha(accentColor, 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: accentColor, fontWeight: 700, mb: 1 }}>Basic Operators</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Arithmetic operators
let sum = 10 + 5;      // 15
let diff = 10 - 5;     // 5
let product = 10 * 5;  // 50
let quotient = 10 / 5; // 2
let remainder = 10 % 3; // 1

// String concatenation
let greeting = "Hello" + " " + "World";`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Key Concepts</Typography>
            <Grid container spacing={2}>
              {[
                { title: "Statements", desc: "Instructions that perform actions, ending with semicolons (optional but recommended)" },
                { title: "Comments", desc: "Single-line (//) or multi-line (/* */) annotations ignored by the interpreter" },
                { title: "Case Sensitivity", desc: "JavaScript is case-sensitive: myVar and MyVar are different variables" },
                { title: "Console", desc: "console.log() outputs to the browser's developer tools for debugging" },
              ].map((item) => (
                <Grid item xs={12} sm={6} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(accentColor, 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>{item.title}</Typography>
                    <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 2: Variables & Data Types */}
          <Paper id="variables" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <StorageIcon sx={{ color: "#3b82f6" }} />
              </Box>
              Variables & Data Types
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              JavaScript has three ways to declare variables: <code>var</code> (function-scoped, legacy), <code>let</code> (block-scoped, reassignable), 
              and <code>const</code> (block-scoped, cannot be reassigned). Modern JavaScript prefers <code>const</code> by default and <code>let</code> when reassignment is needed.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#3b82f6", fontWeight: 700, mb: 1 }}>Variable Declarations</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// const - cannot be reassigned
const API_URL = "https://api.example.com";
const user = { name: "Alex" }; // object ref is const
user.name = "Bob"; // ✓ properties can change

// let - can be reassigned
let count = 0;
count = count + 1; // ✓ allowed

// var - legacy, function-scoped (avoid)
var oldWay = "don't use this";`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#3b82f6", fontWeight: 700, mb: 1 }}>Primitive Types</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// 7 primitive types
let str = "Hello";        // String
let num = 42;             // Number
let big = 9007199254740991n; // BigInt
let bool = true;          // Boolean
let undef = undefined;    // Undefined
let empty = null;         // Null
let sym = Symbol("id");   // Symbol

// Check type with typeof
console.log(typeof str);  // "string"
console.log(typeof num);  // "number"`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Type Coercion</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#3b82f6", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// JavaScript automatically converts types (coercion)
console.log("5" + 3);      // "53" (string concat)
console.log("5" - 3);      // 2 (numeric subtraction)
console.log("5" * "2");    // 10 (both converted to numbers)

// Explicit conversion
let str = "42";
let num = Number(str);     // 42
let parsed = parseInt("42px"); // 42

// Equality comparisons
console.log(5 == "5");     // true (loose equality, coerces)
console.log(5 === "5");    // false (strict equality, no coercion)
// Always prefer === for comparisons!`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { type: "String", example: '"Hello"', desc: "Text data, use quotes" },
                { type: "Number", example: "42, 3.14", desc: "Integers and floats" },
                { type: "Boolean", example: "true, false", desc: "Logical values" },
                { type: "null", example: "null", desc: "Intentional absence" },
                { type: "undefined", example: "undefined", desc: "Uninitialized value" },
                { type: "Object", example: "{ }, [ ]", desc: "Collections of data" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.type}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6" }}>{item.type}</Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace" }}>{item.example}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 3: Functions */}
          <Paper id="functions" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#22c55e", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <TerminalIcon sx={{ color: "#22c55e" }} />
              </Box>
              Functions
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Functions are reusable blocks of code that perform specific tasks. JavaScript supports multiple ways to define functions, 
              each with different behaviors for scope and the <code>this</code> keyword. Functions are first-class citizens, meaning they can be 
              assigned to variables, passed as arguments, and returned from other functions.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#22c55e", fontWeight: 700, mb: 1 }}>Function Declaration</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Traditional function declaration
function greet(name) {
  return "Hello, " + name + "!";
}

// With default parameters
function greet(name = "World") {
  return \`Hello, \${name}!\`;
}

// Multiple parameters
function add(a, b) {
  return a + b;
}

console.log(greet("Alex")); // "Hello, Alex!"
console.log(add(5, 3));     // 8`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#22c55e", fontWeight: 700, mb: 1 }}>Arrow Functions (ES6)</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Arrow function syntax
const greet = (name) => {
  return "Hello, " + name + "!";
};

// Concise body (implicit return)
const greet = (name) => "Hello, " + name;

// Single parameter (no parentheses needed)
const double = n => n * 2;

// No parameters
const sayHi = () => "Hi!";

// Arrow functions don't have their own 'this'
const obj = {
  name: "Alex",
  greet: () => this.name // ✗ won't work!
};`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Higher-Order Functions</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#22c55e", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Functions that take functions as arguments or return functions
const numbers = [1, 2, 3, 4, 5];

// map - transform each element
const doubled = numbers.map(n => n * 2);
// [2, 4, 6, 8, 10]

// filter - keep elements that pass a test
const evens = numbers.filter(n => n % 2 === 0);
// [2, 4]

// reduce - accumulate to single value
const sum = numbers.reduce((acc, n) => acc + n, 0);
// 15

// forEach - execute for each element (no return)
numbers.forEach(n => console.log(n));`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "Declaration", desc: "Hoisted, can be called before definition" },
                { title: "Expression", desc: "Assigned to variable, not hoisted" },
                { title: "Arrow", desc: "Concise syntax, lexical 'this' binding" },
                { title: "Closure", desc: "Functions that remember their outer scope" },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={3} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 0.5 }}>{item.title}</Typography>
                    <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 4: Objects & Arrays */}
          <Paper id="objects-arrays" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <BuildIcon sx={{ color: "#f59e0b" }} />
              </Box>
              Objects & Arrays
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Objects and arrays are the fundamental data structures in JavaScript. Objects store data as key-value pairs, making them perfect 
              for representing real-world entities. Arrays are ordered collections, ideal for lists and sequences. Modern JavaScript provides 
              powerful methods for manipulating these structures, including destructuring and the spread operator.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#f59e0b", fontWeight: 700, mb: 1 }}>Objects</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Object literal
const user = {
  name: "Alex",
  age: 25,
  email: "alex@example.com",
  isActive: true
};

// Accessing properties
console.log(user.name);       // "Alex"
console.log(user["email"]);   // "alex@example.com"

// Adding/modifying properties
user.role = "admin";
user.age = 26;

// Object methods
const keys = Object.keys(user);   // ["name", "age", ...]
const values = Object.values(user);
const entries = Object.entries(user);`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#f59e0b", fontWeight: 700, mb: 1 }}>Arrays</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Array literal
const fruits = ["apple", "banana", "orange"];

// Accessing elements (0-indexed)
console.log(fruits[0]);      // "apple"
console.log(fruits.length);  // 3

// Modifying arrays
fruits.push("grape");        // Add to end
fruits.pop();                // Remove from end
fruits.unshift("mango");     // Add to start
fruits.shift();              // Remove from start

// Useful array methods
fruits.includes("banana");   // true
fruits.indexOf("orange");    // 2
fruits.slice(0, 2);          // ["apple", "banana"]
fruits.splice(1, 1, "kiwi"); // Replace at index`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Destructuring & Spread</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#f59e0b", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Object destructuring
const { name, age, email } = user;
const { name: userName, age: userAge } = user; // Rename

// Array destructuring
const [first, second, ...rest] = fruits;

// Spread operator - copy/merge
const userCopy = { ...user };
const merged = { ...user, ...defaults };
const allFruits = [...fruits, ...moreFruits];

// Default values
const { role = "user" } = user;
const [a = 0, b = 0] = numbers;

// Nested destructuring
const { address: { city, zip } } = person;`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "map()", desc: "Transform each element", example: "arr.map(x => x * 2)" },
                { title: "filter()", desc: "Keep matching elements", example: "arr.filter(x => x > 5)" },
                { title: "find()", desc: "Find first match", example: "arr.find(x => x.id === 1)" },
                { title: "some()", desc: "Any match exists?", example: "arr.some(x => x > 10)" },
                { title: "every()", desc: "All elements match?", example: "arr.every(x => x > 0)" },
                { title: "reduce()", desc: "Accumulate to one value", example: "arr.reduce((a,b) => a+b)" },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", fontFamily: "monospace" }}>{item.title}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>{item.desc}</Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", color: "text.disabled" }}>{item.example}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 5: DOM Manipulation */}
          <Paper id="dom" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#ec4899", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#ec4899", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <WebIcon sx={{ color: "#ec4899" }} />
              </Box>
              DOM Manipulation
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              The Document Object Model (DOM) is a programming interface that represents HTML as a tree of objects. JavaScript can read and 
              modify this tree to dynamically update web pages without reloading. Understanding DOM manipulation is essential for interactive 
              web development, though modern frameworks like React abstract much of this away.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#ec4899", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#ec4899", fontWeight: 700, mb: 1 }}>Selecting Elements</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// By ID (returns single element)
const header = document.getElementById("header");

// By CSS selector (returns first match)
const btn = document.querySelector(".submit-btn");
const input = document.querySelector("input[type='email']");

// By CSS selector (returns all matches)
const items = document.querySelectorAll(".list-item");

// By class/tag (older methods)
const divs = document.getElementsByClassName("card");
const paragraphs = document.getElementsByTagName("p");

// Traversing the DOM
element.parentElement;
element.children;
element.nextElementSibling;
element.previousElementSibling;`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#ec4899", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#ec4899", fontWeight: 700, mb: 1 }}>Modifying Elements</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Content
element.textContent = "New text";
element.innerHTML = "<strong>Bold</strong>";

// Attributes
element.setAttribute("class", "active");
element.getAttribute("href");
element.removeAttribute("disabled");

// Classes
element.classList.add("highlight");
element.classList.remove("hidden");
element.classList.toggle("active");
element.classList.contains("visible");

// Styles
element.style.color = "red";
element.style.backgroundColor = "#f0f0f0";
element.style.display = "none";`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Event Handling</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#ec4899", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Adding event listeners
button.addEventListener("click", function(event) {
  console.log("Button clicked!");
  console.log(event.target); // The clicked element
});

// Arrow function version
button.addEventListener("click", (e) => {
  e.preventDefault(); // Prevent default action
  e.stopPropagation(); // Stop event bubbling
});

// Common events
// "click", "dblclick", "mouseenter", "mouseleave"
// "keydown", "keyup", "input", "change"
// "submit", "focus", "blur", "scroll"

// Removing event listeners
const handler = () => console.log("clicked");
button.addEventListener("click", handler);
button.removeEventListener("click", handler);`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "createElement()", desc: "Create new DOM elements" },
                { title: "appendChild()", desc: "Add child to element" },
                { title: "remove()", desc: "Remove element from DOM" },
                { title: "cloneNode()", desc: "Duplicate an element" },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={3} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ec4899", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ec4899", fontFamily: "monospace" }}>{item.title}</Typography>
                    <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 6: Asynchronous JavaScript */}
          <Paper id="async" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <SpeedIcon sx={{ color: "#8b5cf6" }} />
              </Box>
              Asynchronous JavaScript
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              JavaScript is single-threaded, but it handles async operations through the event loop. Understanding Promises and async/await 
              is crucial for working with APIs, file operations, and timers. Async code allows your program to continue executing while 
              waiting for operations like network requests to complete.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#8b5cf6", fontWeight: 700, mb: 1 }}>Promises</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Creating a Promise
const myPromise = new Promise((resolve, reject) => {
  // Async operation
  setTimeout(() => {
    const success = true;
    if (success) {
      resolve("Data loaded!");
    } else {
      reject("Error occurred");
    }
  }, 1000);
});

// Consuming a Promise
myPromise
  .then(result => console.log(result))
  .catch(error => console.error(error))
  .finally(() => console.log("Done"));

// Chaining promises
fetch("/api/user")
  .then(res => res.json())
  .then(user => fetch(\`/api/posts/\${user.id}\`))
  .then(res => res.json())
  .then(posts => console.log(posts));`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#8b5cf6", fontWeight: 700, mb: 1 }}>Async/Await (ES2017)</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Async function declaration
async function fetchUser() {
  try {
    const response = await fetch("/api/user");
    const user = await response.json();
    return user;
  } catch (error) {
    console.error("Failed to fetch:", error);
    throw error;
  }
}

// Arrow function version
const fetchData = async () => {
  const data = await fetch("/api/data");
  return data.json();
};

// Parallel requests with Promise.all
const [users, posts] = await Promise.all([
  fetch("/api/users").then(r => r.json()),
  fetch("/api/posts").then(r => r.json())
]);`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>The Event Loop</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#8b5cf6", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Understanding execution order
console.log("1");              // Sync - runs first

setTimeout(() => {
  console.log("2");            // Macro task - runs last
}, 0);

Promise.resolve().then(() => {
  console.log("3");            // Micro task - runs second
});

console.log("4");              // Sync - runs first

// Output: 1, 4, 3, 2
// Sync code → Microtasks (Promises) → Macrotasks (setTimeout)`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "Promise.all()", desc: "Wait for all promises", use: "Parallel requests" },
                { title: "Promise.race()", desc: "First to settle wins", use: "Timeouts" },
                { title: "Promise.allSettled()", desc: "Wait for all, ignore errors", use: "Batch operations" },
                { title: "Promise.any()", desc: "First fulfilled wins", use: "Fallback sources" },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={3} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6", fontFamily: "monospace" }}>{item.title}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>{item.desc}</Typography>
                    <Typography variant="caption" color="text.disabled">{item.use}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 7: ES6+ Features */}
          <Paper id="es6" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#06b6d4", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <ExtensionIcon sx={{ color: "#06b6d4" }} />
              </Box>
              ES6+ Features
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              ECMAScript 6 (ES2015) and subsequent versions introduced major improvements to JavaScript. These modern features make code 
              more readable, concise, and powerful. Understanding ES6+ is essential as it's the standard for modern JavaScript development 
              and is used extensively in frameworks like React and Vue.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#06b6d4", fontWeight: 700, mb: 1 }}>Template Literals & Strings</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Template literals (backticks)
const name = "Alex";
const greeting = \`Hello, \${name}!\`;

// Multi-line strings
const html = \`
  <div class="card">
    <h2>\${title}</h2>
    <p>\${description}</p>
  </div>
\`;

// Tagged templates
const highlight = (strings, ...values) => {
  return strings.reduce((acc, str, i) => 
    acc + str + (values[i] ? \`<b>\${values[i]}</b>\` : ""), "");
};

// String methods
"hello".includes("ell");     // true
"hello".startsWith("he");    // true
"hello".endsWith("lo");      // true
"ha".repeat(3);              // "hahaha"
"  trim  ".trim();           // "trim"`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#06b6d4", fontWeight: 700, mb: 1 }}>Classes</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Class declaration
class User {
  constructor(name, email) {
    this.name = name;
    this.email = email;
  }

  greet() {
    return \`Hello, I'm \${this.name}\`;
  }

  static create(data) {
    return new User(data.name, data.email);
  }
}

// Inheritance
class Admin extends User {
  constructor(name, email, role) {
    super(name, email);
    this.role = role;
  }

  greet() {
    return \`\${super.greet()} (\${this.role})\`;
  }
}

const admin = new Admin("Alex", "alex@ex.com", "admin");`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>More ES6+ Features</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#06b6d4", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Optional chaining (?.)
const city = user?.address?.city;  // undefined if any is null

// Nullish coalescing (??)
const name = user.name ?? "Anonymous";  // Only for null/undefined

// Logical assignment operators
x ||= y;   // x = x || y
x &&= y;   // x = x && y
x ??= y;   // x = x ?? y

// Object shorthand
const x = 1, y = 2;
const point = { x, y };  // { x: 1, y: 2 }

// Computed property names
const key = "dynamic";
const obj = { [key]: "value" };  // { dynamic: "value" }

// Symbol - unique identifiers
const id = Symbol("id");
const user = { [id]: 123, name: "Alex" };`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "let/const", desc: "Block-scoped variables", year: "ES6" },
                { title: "Arrow =>", desc: "Concise function syntax", year: "ES6" },
                { title: "Spread ...", desc: "Expand iterables", year: "ES6" },
                { title: "for...of", desc: "Iterate over values", year: "ES6" },
                { title: "async/await", desc: "Cleaner async code", year: "ES2017" },
                { title: "?. ??", desc: "Safe property access", year: "ES2020" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.title}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4", fontFamily: "monospace" }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary" display="block">{item.desc}</Typography>
                    <Chip label={item.year} size="small" sx={{ mt: 0.5, height: 18, fontSize: "0.65rem" }} />
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 8: Modules & Imports */}
          <Paper id="modules" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#14b8a6", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#14b8a6", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <StorageIcon sx={{ color: "#14b8a6" }} />
              </Box>
              Modules & Imports
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              JavaScript modules allow you to split code into separate files with their own scope. ES Modules (ESM) is the official standard, 
              while CommonJS is used in Node.js. Modules promote code reusability, maintainability, and help manage dependencies effectively.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#14b8a6", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#14b8a6", fontWeight: 700, mb: 1 }}>ES Modules (ESM)</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// utils.js - Exporting
export const PI = 3.14159;

export function add(a, b) {
  return a + b;
}

export default class Calculator {
  // default export (one per file)
}

// main.js - Importing
import Calculator from "./utils.js";
import { PI, add } from "./utils.js";
import { add as sum } from "./utils.js";
import * as utils from "./utils.js";

// Dynamic import (code splitting)
const module = await import("./heavy-module.js");

// Re-exporting
export { default } from "./Calculator.js";
export * from "./math-utils.js";`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#14b8a6", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#14b8a6", fontWeight: 700, mb: 1 }}>CommonJS (Node.js)</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// utils.js - Exporting
const PI = 3.14159;

function add(a, b) {
  return a + b;
}

module.exports = { PI, add };
// or
module.exports.PI = PI;
exports.add = add;

// main.js - Importing
const { PI, add } = require("./utils");
const utils = require("./utils");

// Conditional require
if (condition) {
  const extra = require("./extra");
}

// Node.js built-in modules
const fs = require("fs");
const path = require("path");`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Module Patterns</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#14b8a6", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Barrel exports (index.js)
// Consolidate exports from multiple files
export { Button } from "./Button";
export { Input } from "./Input";
export { Modal } from "./Modal";

// Usage: import { Button, Input } from "./components";

// package.json for ESM in Node.js
{
  "type": "module",  // Enable ESM syntax
  "exports": {
    ".": "./dist/index.js",
    "./utils": "./dist/utils.js"
  }
}`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "Named Export", desc: "Multiple per file, explicit names", syntax: "export { x }" },
                { title: "Default Export", desc: "One per file, any import name", syntax: "export default" },
                { title: "Dynamic Import", desc: "Load on demand, code splitting", syntax: "import()" },
                { title: "Side Effects", desc: "Execute module code only", syntax: "import './init'" },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={3} key={item.title}>
                  <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#14b8a6", 0.05), height: "100%" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#14b8a6" }}>{item.title}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>{item.desc}</Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", color: "text.disabled" }}>{item.syntax}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 9: React */}
          <Paper id="react" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#61dafb", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#61dafb", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <WebIcon sx={{ color: "#61dafb" }} />
              </Box>
              React
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              React is a declarative, component-based library for building user interfaces. Created by Facebook, it uses a virtual DOM 
              for efficient updates and JSX for writing HTML-like syntax in JavaScript. React's component model and hooks system make it 
              easy to build complex, interactive UIs with reusable code.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#61dafb", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#61dafb", fontWeight: 700, mb: 1 }}>Components & JSX</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Function component with JSX
function Welcome({ name }) {
  return (
    <div className="welcome">
      <h1>Hello, {name}!</h1>
      <p>Welcome to React</p>
    </div>
  );
}

// Using the component
<Welcome name="Alex" />

// Conditional rendering
function Greeting({ isLoggedIn }) {
  return isLoggedIn 
    ? <UserDashboard /> 
    : <LoginForm />;
}

// List rendering
function TodoList({ items }) {
  return (
    <ul>
      {items.map(item => (
        <li key={item.id}>{item.text}</li>
      ))}
    </ul>
  );
}`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#61dafb", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#61dafb", fontWeight: 700, mb: 1 }}>Hooks</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`import { useState, useEffect, useCallback } from "react";

function Counter() {
  // State hook
  const [count, setCount] = useState(0);

  // Effect hook (side effects)
  useEffect(() => {
    document.title = \`Count: \${count}\`;
    
    // Cleanup function
    return () => console.log("Cleanup");
  }, [count]); // Dependency array

  // Memoized callback
  const increment = useCallback(() => {
    setCount(prev => prev + 1);
  }, []);

  return (
    <button onClick={increment}>
      Count: {count}
    </button>
  );
}

// Custom hook
function useLocalStorage(key, initial) {
  const [value, setValue] = useState(
    () => localStorage.getItem(key) ?? initial
  );
  // ... return [value, setValue];
}`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>State Management & Props</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#61dafb", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Props drilling alternative: Context API
const ThemeContext = React.createContext("light");

function App() {
  const [theme, setTheme] = useState("dark");
  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      <MainContent />
    </ThemeContext.Provider>
  );
}

function ThemedButton() {
  const { theme, setTheme } = useContext(ThemeContext);
  return <button className={theme}>Toggle</button>;
}

// useReducer for complex state
const [state, dispatch] = useReducer(reducer, initialState);
dispatch({ type: "INCREMENT", payload: 5 });`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "useState", desc: "Local component state", color: "#61dafb" },
                { title: "useEffect", desc: "Side effects & lifecycle", color: "#61dafb" },
                { title: "useContext", desc: "Consume context values", color: "#61dafb" },
                { title: "useReducer", desc: "Complex state logic", color: "#61dafb" },
                { title: "useMemo", desc: "Memoize expensive values", color: "#61dafb" },
                { title: "useRef", desc: "Mutable refs, DOM access", color: "#61dafb" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.title}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha("#61dafb", 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#61dafb", fontFamily: "monospace", fontSize: "0.8rem" }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 10: Node.js */}
          <Paper id="nodejs" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#68a063", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#68a063", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <CloudIcon sx={{ color: "#68a063" }} />
              </Box>
              Node.js
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Node.js is a JavaScript runtime built on Chrome's V8 engine that allows you to run JavaScript on the server. It's event-driven 
              and non-blocking, making it excellent for building scalable network applications. Node.js revolutionized web development by 
              enabling full-stack JavaScript development.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#68a063", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#68a063", fontWeight: 700, mb: 1 }}>Core Modules & File System</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Built-in modules
const fs = require("fs");
const path = require("path");
const http = require("http");

// Reading files
const data = fs.readFileSync("file.txt", "utf8");

// Async file read
fs.readFile("file.txt", "utf8", (err, data) => {
  if (err) throw err;
  console.log(data);
});

// Promise-based (modern)
const fsPromises = require("fs").promises;
const content = await fsPromises.readFile("file.txt", "utf8");

// Path utilities
const fullPath = path.join(__dirname, "data", "file.txt");
const ext = path.extname("file.txt");  // ".txt"
path.basename("/foo/bar.txt");         // "bar.txt"`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#68a063", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#68a063", fontWeight: 700, mb: 1 }}>Express.js Server</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`const express = require("express");
const app = express();

// Middleware
app.use(express.json());
app.use(express.static("public"));

// Routes
app.get("/api/users", (req, res) => {
  res.json({ users: [] });
});

app.post("/api/users", (req, res) => {
  const { name, email } = req.body;
  // Create user...
  res.status(201).json({ id: 1, name, email });
});

app.get("/api/users/:id", (req, res) => {
  const { id } = req.params;
  res.json({ id, name: "Alex" });
});

// Start server
app.listen(3000, () => {
  console.log("Server running on port 3000");
});`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>npm & Package Management</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#68a063", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`# Initialize a project
npm init -y

# Install dependencies
npm install express           # Production dependency
npm install -D nodemon        # Dev dependency
npm install -g typescript     # Global install

# package.json scripts
{
  "scripts": {
    "start": "node index.js",
    "dev": "nodemon index.js",
    "test": "jest"
  }
}

# Run scripts
npm run dev
npm start
npm test`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "fs", desc: "File system operations" },
                { title: "path", desc: "Path manipulation" },
                { title: "http", desc: "HTTP server/client" },
                { title: "crypto", desc: "Cryptographic functions" },
                { title: "events", desc: "Event emitter pattern" },
                { title: "stream", desc: "Streaming data" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.title}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha("#68a063", 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#68a063", fontFamily: "monospace" }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 11: Vue.js */}
          <Paper id="vue" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#42b883", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#42b883", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <WebIcon sx={{ color: "#42b883" }} />
              </Box>
              Vue.js
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Vue.js is a progressive JavaScript framework for building user interfaces. It's designed to be incrementally adoptable—you can 
              use as little or as much as you need. Vue combines the best ideas from React and Angular with an approachable API and excellent 
              documentation, making it great for beginners and experts alike.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#42b883", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#42b883", fontWeight: 700, mb: 1 }}>Composition API (Vue 3)</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`<script setup>
import { ref, computed, onMounted } from "vue";

// Reactive state
const count = ref(0);
const name = ref("Alex");

// Computed property
const doubled = computed(() => count.value * 2);

// Methods
function increment() {
  count.value++;
}

// Lifecycle hook
onMounted(() => {
  console.log("Component mounted");
});
</script>

<template>
  <div>
    <h1>Hello, {{ name }}!</h1>
    <p>Count: {{ count }} (doubled: {{ doubled }})</p>
    <button @click="increment">+1</button>
  </div>
</template>`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#42b883", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#42b883", fontWeight: 700, mb: 1 }}>Template Directives</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`<template>
  <!-- Conditional rendering -->
  <div v-if="isLoggedIn">Welcome back!</div>
  <div v-else-if="isGuest">Hello, Guest</div>
  <div v-else>Please log in</div>

  <!-- Show/hide (CSS display) -->
  <div v-show="isVisible">I toggle visibility</div>

  <!-- List rendering -->
  <ul>
    <li v-for="item in items" :key="item.id">
      {{ item.name }}
    </li>
  </ul>

  <!-- Two-way binding -->
  <input v-model="searchQuery" />

  <!-- Event handling -->
  <button @click="handleClick">Click</button>
  <form @submit.prevent="onSubmit">...</form>

  <!-- Attribute binding -->
  <img :src="imageUrl" :alt="imageAlt" />
  <div :class="{ active: isActive }"></div>
</template>`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Props & Events</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#42b883", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`<!-- ChildComponent.vue -->
<script setup>
// Define props
const props = defineProps({
  title: String,
  count: { type: Number, default: 0 }
});

// Define emits
const emit = defineEmits(["update", "delete"]);

function handleUpdate() {
  emit("update", { id: 1, value: "new" });
}
</script>

<!-- ParentComponent.vue -->
<ChildComponent 
  :title="myTitle"
  :count="5"
  @update="handleUpdate"
  @delete="handleDelete"
/>`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "ref()", desc: "Reactive primitive values" },
                { title: "reactive()", desc: "Reactive objects" },
                { title: "computed()", desc: "Derived reactive values" },
                { title: "watch()", desc: "React to changes" },
                { title: "Pinia", desc: "State management" },
                { title: "Vue Router", desc: "Client-side routing" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.title}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha("#42b883", 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#42b883", fontFamily: "monospace", fontSize: "0.8rem" }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 12: Vite */}
          <Paper id="vite" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#646cff", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#646cff", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <SpeedIcon sx={{ color: "#646cff" }} />
              </Box>
              Vite
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Vite (French for "fast") is a next-generation build tool that significantly improves the frontend development experience. 
              It leverages native ES modules for instant server start and lightning-fast Hot Module Replacement (HMR). Created by Evan You 
              (creator of Vue), Vite works with React, Vue, Svelte, and vanilla JS.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#646cff", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#646cff", fontWeight: 700, mb: 1 }}>Getting Started</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`# Create a new project
npm create vite@latest my-app
# Select framework: React, Vue, Svelte, etc.
# Select variant: JavaScript or TypeScript

cd my-app
npm install
npm run dev      # Start dev server
npm run build    # Production build
npm run preview  # Preview production build

# Project structure
my-app/
├── index.html        # Entry point
├── vite.config.js    # Vite configuration
├── package.json
├── public/           # Static assets
└── src/
    ├── main.jsx      # App entry
    ├── App.jsx
    └── assets/       # Processed assets`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#646cff", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#646cff", fontWeight: 700, mb: 1 }}>Configuration</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// vite.config.js
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  
  // Dev server options
  server: {
    port: 3000,
    open: true,
    proxy: {
      "/api": "http://localhost:8000"
    }
  },

  // Build options
  build: {
    outDir: "dist",
    sourcemap: true,
    minify: "terser"
  },

  // Path aliases
  resolve: {
    alias: {
      "@": "/src",
      "@components": "/src/components"
    }
  }
});`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Environment Variables & Features</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#646cff", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// .env files
.env                # Loaded in all cases
.env.local          # Loaded in all cases, ignored by git
.env.development    # Only in development mode
.env.production     # Only in production mode

// .env file content (must prefix with VITE_)
VITE_API_URL=https://api.example.com
VITE_APP_TITLE=My App

// Access in code
console.log(import.meta.env.VITE_API_URL);
console.log(import.meta.env.MODE);  // "development" or "production"
console.log(import.meta.env.DEV);   // true in dev mode`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "Native ESM", desc: "No bundling in dev" },
                { title: "HMR", desc: "Instant updates" },
                { title: "Rollup", desc: "Optimized prod builds" },
                { title: "CSS", desc: "PostCSS, Sass, Less" },
                { title: "TypeScript", desc: "Built-in support" },
                { title: "Plugins", desc: "Rich ecosystem" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.title}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha("#646cff", 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#646cff" }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 13: Webpack */}
          <Paper id="webpack" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#8dd6f9", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#8dd6f9", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <ConstructionIcon sx={{ color: "#8dd6f9" }} />
              </Box>
              Webpack
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Webpack is a powerful static module bundler for JavaScript applications. It builds a dependency graph of your project and 
              bundles all modules into one or more optimized bundles. While newer tools like Vite offer faster development, Webpack remains 
              widely used and provides extensive configuration options for complex build requirements.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#8dd6f9", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#8dd6f9", fontWeight: 700, mb: 1 }}>Basic Configuration</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// webpack.config.js
const path = require("path");
const HtmlWebpackPlugin = require("html-webpack-plugin");

module.exports = {
  mode: "development", // or "production"
  entry: "./src/index.js",
  output: {
    path: path.resolve(__dirname, "dist"),
    filename: "[name].[contenthash].js",
    clean: true
  },
  devServer: {
    port: 3000,
    hot: true,
    open: true
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: "./src/index.html"
    })
  ]
};`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#8dd6f9", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#8dd6f9", fontWeight: 700, mb: 1 }}>Loaders</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Loaders transform files before bundling
module.exports = {
  module: {
    rules: [
      // JavaScript/JSX with Babel
      {
        test: /\\.jsx?$/,
        exclude: /node_modules/,
        use: "babel-loader"
      },
      // CSS
      {
        test: /\\.css$/,
        use: ["style-loader", "css-loader"]
      },
      // Images
      {
        test: /\\.(png|jpg|gif|svg)$/,
        type: "asset/resource"
      },
      // Fonts
      {
        test: /\\.(woff|woff2|eot|ttf)$/,
        type: "asset/resource"
      }
    ]
  }
};`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Code Splitting & Optimization</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#8dd6f9", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`module.exports = {
  optimization: {
    splitChunks: {
      chunks: "all",  // Split vendor code
      cacheGroups: {
        vendor: {
          test: /[\\\\/]node_modules[\\\\/]/,
          name: "vendors",
          chunks: "all"
        }
      }
    },
    minimize: true,
    minimizer: [new TerserPlugin()]
  }
};

// Dynamic imports for code splitting
const MyComponent = React.lazy(() => import("./MyComponent"));

// In your code
import("./module").then(module => {
  module.doSomething();
});`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "Entry", desc: "Starting point(s)" },
                { title: "Output", desc: "Bundle destination" },
                { title: "Loaders", desc: "Transform files" },
                { title: "Plugins", desc: "Extend functionality" },
                { title: "Mode", desc: "Dev or production" },
                { title: "DevServer", desc: "Local development" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.title}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha("#8dd6f9", 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8dd6f9" }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 14: TypeScript */}
          <Paper id="typescript" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#3178c6", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#3178c6", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <CodeIcon sx={{ color: "#3178c6" }} />
              </Box>
              TypeScript
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              TypeScript is a strongly typed superset of JavaScript that compiles to plain JavaScript. It adds optional static typing, 
              classes, interfaces, and other features that help catch errors at compile time rather than runtime. TypeScript has become 
              the standard for large-scale JavaScript applications and is widely used with React, Angular, and Node.js.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#3178c6", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#3178c6", fontWeight: 700, mb: 1 }}>Basic Types</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Primitive types
let name: string = "Alex";
let age: number = 25;
let isActive: boolean = true;

// Arrays
let numbers: number[] = [1, 2, 3];
let names: Array<string> = ["a", "b"];

// Tuple (fixed-length array)
let tuple: [string, number] = ["hello", 42];

// Object type
let user: { name: string; age: number } = {
  name: "Alex",
  age: 25
};

// Union types
let id: string | number = "abc";
id = 123;  // Also valid

// Literal types
let direction: "left" | "right" | "up" | "down";

// any, unknown, never, void
let anything: any = "can be anything";
let unknown: unknown = 4;  // Safer than any
function fail(): never { throw new Error(); }
function log(): void { console.log("hi"); }`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#3178c6", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#3178c6", fontWeight: 700, mb: 1 }}>Interfaces & Types</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Interface
interface User {
  id: number;
  name: string;
  email?: string;  // Optional
  readonly createdAt: Date;  // Immutable
}

// Extending interfaces
interface Admin extends User {
  role: "admin" | "superadmin";
  permissions: string[];
}

// Type alias
type ID = string | number;
type Point = { x: number; y: number };

// Function types
type Callback = (data: string) => void;

interface ApiResponse<T> {
  data: T;
  status: number;
  message: string;
}

// Using generics
const response: ApiResponse<User[]> = {
  data: [{ id: 1, name: "Alex", createdAt: new Date() }],
  status: 200,
  message: "Success"
};`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Generics & Utility Types</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#3178c6", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Generic function
function identity<T>(value: T): T {
  return value;
}
const str = identity<string>("hello");
const num = identity(42);  // Type inferred

// Generic constraints
function getLength<T extends { length: number }>(item: T): number {
  return item.length;
}

// Built-in utility types
type PartialUser = Partial<User>;      // All props optional
type RequiredUser = Required<User>;    // All props required
type ReadonlyUser = Readonly<User>;    // All props readonly
type UserName = Pick<User, "name">;    // Pick specific props
type NoEmail = Omit<User, "email">;    // Omit specific props
type IdType = User["id"];              // Index access type

// Record type
const users: Record<string, User> = {
  "abc": { id: 1, name: "Alex", createdAt: new Date() }
};`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "string", desc: "Text values" },
                { title: "number", desc: "All numbers" },
                { title: "boolean", desc: "true/false" },
                { title: "interface", desc: "Object shapes" },
                { title: "type", desc: "Type aliases" },
                { title: "generic<T>", desc: "Reusable types" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.title}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha("#3178c6", 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3178c6", fontFamily: "monospace", fontSize: "0.75rem" }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 15: Testing */}
          <Paper id="testing" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#c21325", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#c21325", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <CheckCircleIcon sx={{ color: "#c21325" }} />
              </Box>
              Testing
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.8 }}>
              Testing is crucial for maintaining code quality and preventing regressions. JavaScript has excellent testing tools including 
              Jest, Vitest, and React Testing Library. Good tests give you confidence to refactor and add features without breaking 
              existing functionality. The testing pyramid suggests having many unit tests, fewer integration tests, and minimal E2E tests.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#c21325", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#c21325", fontWeight: 700, mb: 1 }}>Jest / Vitest Basics</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// math.test.js
import { add, multiply } from "./math";

describe("Math functions", () => {
  test("adds two numbers", () => {
    expect(add(2, 3)).toBe(5);
    expect(add(-1, 1)).toBe(0);
  });

  test("multiplies two numbers", () => {
    expect(multiply(3, 4)).toBe(12);
  });

  // Common matchers
  expect(value).toBe(exact);
  expect(value).toEqual(deepEqual);
  expect(value).toBeTruthy();
  expect(value).toBeNull();
  expect(array).toContain(item);
  expect(fn).toThrow(Error);
  
  // Async testing
  test("fetches data", async () => {
    const data = await fetchData();
    expect(data).toHaveProperty("id");
  });
});`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#c21325", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#c21325", fontWeight: 700, mb: 1 }}>React Testing Library</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import Counter from "./Counter";

describe("Counter component", () => {
  test("renders initial count", () => {
    render(<Counter initialCount={5} />);
    expect(screen.getByText("Count: 5")).toBeInTheDocument();
  });

  test("increments on click", async () => {
    render(<Counter initialCount={0} />);
    const button = screen.getByRole("button", { name: /increment/i });
    
    await userEvent.click(button);
    
    expect(screen.getByText("Count: 1")).toBeInTheDocument();
  });

  test("handles form input", async () => {
    render(<SearchForm />);
    const input = screen.getByPlaceholderText("Search...");
    
    await userEvent.type(input, "hello");
    
    expect(input).toHaveValue("hello");
  });
});`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Mocking & Test Setup</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#c21325", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Mocking functions
const mockFn = jest.fn();
mockFn.mockReturnValue(42);
mockFn.mockResolvedValue({ data: "async" });

// Mocking modules
jest.mock("./api", () => ({
  fetchUser: jest.fn(() => Promise.resolve({ id: 1, name: "Alex" }))
}));

// Setup and teardown
beforeAll(() => { /* Run once before all tests */ });
beforeEach(() => { /* Run before each test */ });
afterEach(() => { /* Cleanup after each test */ });
afterAll(() => { /* Run once after all tests */ });

// Vitest-specific: in-source testing
// In your actual source file
if (import.meta.vitest) {
  const { test, expect } = import.meta.vitest;
  test("add", () => expect(add(1, 2)).toBe(3));
}`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "Unit", desc: "Test functions in isolation" },
                { title: "Integration", desc: "Test components together" },
                { title: "E2E", desc: "Test full user flows" },
                { title: "Snapshot", desc: "Detect UI changes" },
                { title: "Coverage", desc: "Measure test completeness" },
                { title: "TDD", desc: "Write tests first" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.title}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha("#c21325", 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#c21325" }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 17: JavaScript Engine Deep Dive */}
          <Paper id="js-engine" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#ff6b6b", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#ff6b6b", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <BuildIcon sx={{ color: "#ff6b6b" }} />
              </Box>
              JavaScript Engine Deep Dive
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Understanding how JavaScript engines work under the hood will make you a significantly better developer. When you write 
              JavaScript code, it doesn't run directly on your computer's hardware—it's executed by a <strong>JavaScript engine</strong>. 
              The most famous engine is Google's <strong>V8</strong>, which powers both Chrome and Node.js. Other engines include 
              SpiderMonkey (Firefox), JavaScriptCore (Safari), and Chakra (old Edge). These engines are marvels of engineering that 
              transform your human-readable code into machine instructions that computers can execute at near-native speeds.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff6b6b" }}>How Code Execution Works</Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              When JavaScript code enters an engine, it goes through several stages. First, the <strong>parser</strong> reads your code 
              and converts it into an <strong>Abstract Syntax Tree (AST)</strong>—a tree-like data structure that represents your code's 
              structure. Think of the AST as a detailed blueprint that the engine can work with. Next, the <strong>interpreter</strong> 
              (like V8's "Ignition") walks through this AST and generates <strong>bytecode</strong>—an intermediate representation that's 
              faster to execute than parsing the original code repeatedly.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#ff6b6b", 0.2)}`, mb: 3 }}>
              <Typography variant="subtitle2" sx={{ color: "#ff6b6b", fontWeight: 700, mb: 2 }}>The Execution Pipeline</Typography>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`JavaScript Code
      ↓
   Parser → Lexical Analysis (Tokenization)
      ↓
Abstract Syntax Tree (AST)
      ↓
Interpreter (Ignition in V8) → Bytecode
      ↓
Execution + Profiling (tracking "hot" code)
      ↓
JIT Compiler (TurboFan in V8) → Optimized Machine Code
      ↓
Deoptimization (if assumptions fail) → Back to Bytecode

Example: Your code "const x = 5 + 3;"
Tokens: [const] [x] [=] [5] [+] [3] [;]
AST: VariableDeclaration
       └── VariableDeclarator
             ├── Identifier (x)
             └── BinaryExpression
                   ├── Literal (5)
                   ├── Operator (+)
                   └── Literal (3)`}
              </Box>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff6b6b" }}>Just-In-Time (JIT) Compilation</Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Here's where the magic happens. Early JavaScript was purely interpreted, which was slow. Modern engines use 
              <strong> Just-In-Time (JIT) compilation</strong>—a hybrid approach that combines interpretation and compilation. The engine 
              starts by interpreting your code (fast startup), but it also monitors which functions are called frequently ("hot" code). 
              When it detects hot code, the <strong>optimizing compiler</strong> (TurboFan in V8) compiles it to highly optimized machine 
              code. This is why JavaScript can be surprisingly fast—frequently executed code runs at near-native speeds!
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              However, JIT optimization makes assumptions. If you have a function that always receives numbers, the compiler optimizes 
              for numbers. But if you suddenly pass a string, those assumptions break, triggering <strong>deoptimization</strong>—the 
              engine throws away the optimized code and falls back to interpreted bytecode. This is why <strong>consistent types</strong> 
              lead to faster JavaScript: `add(1, 2)` then `add(3, 4)` is faster than `add(1, 2)` then `add("hello", "world")`.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#ff6b6b", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#22c55e", fontWeight: 700, mb: 1 }}>✓ Optimization-Friendly Code</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Consistent types - engine can optimize
function add(a, b) {
  return a + b;
}

// Always called with numbers
add(1, 2);    // Engine: "a and b are numbers"
add(10, 20);  // Engine: "Still numbers, I'll optimize!"
add(5, 7);    // Runs on optimized machine code

// Monomorphic (single shape) objects
const users = [
  { name: "Alex", age: 25 },
  { name: "Sam", age: 30 },
  { name: "Jordan", age: 28 }
];
// All objects have same "shape" - fast property access`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#ff6b6b", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#ef4444", fontWeight: 700, mb: 1 }}>✗ Deoptimization Triggers</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Type inconsistency - forces deoptimization
function add(a, b) {
  return a + b;
}

add(1, 2);         // Engine optimizes for numbers
add("hi", "bye");  // DEOPT! Falls back to bytecode

// Polymorphic (multiple shapes) objects
const users = [
  { name: "Alex", age: 25 },
  { name: "Sam", age: 30, admin: true },  // Different shape!
  { name: "Jordan" }  // Another shape!
];
// Engine can't optimize property access

// Avoid: delete, arguments, with, eval
delete obj.prop;  // Changes object shape
eval("code");     // Can't optimize`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ff6b6b" }}>Memory Management & Garbage Collection</Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              JavaScript automatically manages memory through <strong>garbage collection (GC)</strong>. When you create objects, arrays, 
              or functions, memory is allocated from the <strong>heap</strong>. When those values are no longer reachable (no references 
              point to them), the garbage collector reclaims that memory. V8 uses a <strong>generational garbage collector</strong> with 
              two main areas: the "young generation" (newly created objects) and the "old generation" (objects that survived multiple GC cycles). 
              Young objects are collected frequently and quickly; old objects are collected less often but more thoroughly.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#ff6b6b", 0.05), border: `1px solid ${alpha("#ff6b6b", 0.2)}`, mb: 3 }}>
              <Typography variant="subtitle2" sx={{ color: "#ff6b6b", fontWeight: 700, mb: 2 }}>Memory Lifecycle Visualization</Typography>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`┌────────────────────────────────────────────────────────┐
│                    HEAP MEMORY                          │
├──────────────────────┬─────────────────────────────────┤
│   Young Generation   │        Old Generation           │
│   (Scavenger GC)     │        (Mark-Sweep GC)          │
│                      │                                  │
│  ┌──────┐ ┌──────┐  │   ┌──────┐ ┌──────┐ ┌──────┐   │
│  │New   │ │Short-│  │   │Long- │ │Global│ │Cached│   │
│  │Object│ │lived │  │   │lived │ │State │ │Data  │   │
│  └──────┘ └──────┘  │   └──────┘ └──────┘ └──────┘   │
│                      │                                  │
│  Collected every     │   Collected less often          │
│  few milliseconds    │   (when young gen fills up)     │
└──────────────────────┴─────────────────────────────────┘

Memory Leak Pattern:
let cache = {};
function process(data) {
  cache[data.id] = data;  // Never cleared!
  // Cache grows forever → Memory leak
}

Prevention:
const cache = new Map();
function process(data) {
  if (cache.size > 1000) cache.clear();  // Limit size
  cache.set(data.id, data);
}`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "V8", desc: "Chrome & Node.js engine", color: "#4285f4" },
                { title: "SpiderMonkey", desc: "Firefox engine", color: "#ff7139" },
                { title: "JavaScriptCore", desc: "Safari engine", color: "#999" },
                { title: "JIT", desc: "Just-In-Time compilation", color: "#22c55e" },
                { title: "GC", desc: "Garbage Collection", color: "#8b5cf6" },
                { title: "AST", desc: "Abstract Syntax Tree", color: "#f59e0b" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.title}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha(item.color, 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 18: Closures & Scope */}
          <Paper id="closures-scope" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#a855f7", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#a855f7", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <CodeIcon sx={{ color: "#a855f7" }} />
              </Box>
              Closures & Scope Explained
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Closures and scope are fundamental concepts that separate JavaScript beginners from intermediate developers. Understanding 
              them deeply will help you write cleaner code, debug mysterious bugs, and ace technical interviews. Don't worry if this 
              seems complex at first—we'll break it down step by step with plenty of examples.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>Understanding Scope</Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              <strong>Scope</strong> determines where variables are accessible in your code. Think of it like rooms in a house—you can 
              see everything in your current room, and you can look out into the hallway, but you can't see into other closed rooms. 
              JavaScript has three types of scope: <strong>global scope</strong> (the whole house), <strong>function scope</strong> 
              (individual rooms), and <strong>block scope</strong> (closets within rooms, created by `{}` with `let` and `const`).
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#a855f7", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#a855f7", fontWeight: 700, mb: 1 }}>Scope Chain Visualization</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Global Scope (accessible everywhere)
const globalVar = "I'm global";

function outerFunction() {
  // Function Scope (outer)
  const outerVar = "I'm in outer";
  
  function innerFunction() {
    // Function Scope (inner)
    const innerVar = "I'm in inner";
    
    if (true) {
      // Block Scope
      const blockVar = "I'm in block";
      
      // Can access: blockVar, innerVar, 
      // outerVar, globalVar
      console.log(globalVar);  // ✓
      console.log(outerVar);   // ✓
      console.log(innerVar);   // ✓
      console.log(blockVar);   // ✓
    }
    
    // Cannot access blockVar here!
    // console.log(blockVar); // ReferenceError
  }
  
  // Cannot access innerVar here
  innerFunction();
}

outerFunction();`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#a855f7", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#a855f7", fontWeight: 700, mb: 1 }}>var vs let vs const Scope</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// var is FUNCTION-scoped (ignores blocks!)
function varExample() {
  if (true) {
    var x = 10;  // Function-scoped
  }
  console.log(x);  // 10 - Still accessible!
}

// let and const are BLOCK-scoped
function letExample() {
  if (true) {
    let y = 20;     // Block-scoped
    const z = 30;   // Block-scoped
  }
  // console.log(y);  // ReferenceError
  // console.log(z);  // ReferenceError
}

// Loop behavior difference
for (var i = 0; i < 3; i++) {
  setTimeout(() => console.log(i), 100);
}
// Prints: 3, 3, 3 (var is shared!)

for (let j = 0; j < 3; j++) {
  setTimeout(() => console.log(j), 100);
}
// Prints: 0, 1, 2 (let creates new binding)`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>What is a Closure?</Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              A <strong>closure</strong> is a function that "remembers" the variables from its outer scope even after the outer function 
              has finished executing. This is possible because when a function is created, it maintains a reference to its 
              <strong> lexical environment</strong>—the variables that were in scope at the time of creation. Closures are not a special 
              syntax; they happen automatically whenever you define a function inside another function and reference outer variables.
            </Typography>

            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#a855f7", 0.05), border: `1px solid ${alpha("#a855f7", 0.2)}`, mb: 3 }}>
              <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Closure: The Mental Model</Typography>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`Imagine a closure as a backpack:
┌─────────────────────────────────────────────────────────┐
│  When innerFunction is created inside outerFunction,    │
│  it packs a backpack with all variables it might need:  │
│                                                         │
│  🎒 innerFunction's Backpack (Closure):                 │
│     ├── outerVar: "I'm from outer"                      │
│     ├── anotherOuterVar: 42                             │
│     └── reference to global scope                       │
│                                                         │
│  Even after outerFunction finishes and its local        │
│  variables would normally be garbage collected,         │
│  innerFunction keeps them alive in its backpack!        │
└─────────────────────────────────────────────────────────┘

function outerFunction() {
  const outerVar = "I'm from outer";  // Normally dies after outerFunction ends
  
  return function innerFunction() {
    // But innerFunction has outerVar in its closure backpack!
    console.log(outerVar);  // Still works!
  };
}

const myFunc = outerFunction();  // outerFunction finishes
myFunc();  // "I'm from outer" - closure keeps outerVar alive!`}
              </Box>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>Practical Closure Examples</Typography>
            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#a855f7", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#22c55e", fontWeight: 700, mb: 1 }}>Private Variables (Data Encapsulation)</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Closures enable private state
function createCounter() {
  let count = 0;  // Private! Can't access from outside
  
  return {
    increment() {
      count++;
      return count;
    },
    decrement() {
      count--;
      return count;
    },
    getCount() {
      return count;
    }
  };
}

const counter = createCounter();
console.log(counter.increment());  // 1
console.log(counter.increment());  // 2
console.log(counter.getCount());   // 2
// console.log(counter.count);     // undefined!
// count is truly private`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#a855f7", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#3b82f6", fontWeight: 700, mb: 1 }}>Function Factories</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Create specialized functions
function createMultiplier(factor) {
  // factor is "closed over"
  return function(number) {
    return number * factor;
  };
}

const double = createMultiplier(2);
const triple = createMultiplier(3);
const tenX = createMultiplier(10);

console.log(double(5));   // 10
console.log(triple(5));   // 15
console.log(tenX(5));     // 50

// Real-world: API endpoint factories
function createFetcher(baseUrl) {
  return async function(endpoint) {
    const response = await fetch(baseUrl + endpoint);
    return response.json();
  };
}

const api = createFetcher("https://api.example.com");
const data = await api("/users");  // Fetches /users`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>Common Closure Pitfalls</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#a855f7", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// PITFALL: Loop variable closure (classic interview question!)

// ❌ Problem: All callbacks share the same 'i'
for (var i = 0; i < 3; i++) {
  setTimeout(function() {
    console.log(i);  // 3, 3, 3 (not 0, 1, 2!)
  }, 1000);
}
// By the time callbacks run, loop is done and i === 3

// ✅ Solution 1: Use let (creates new binding per iteration)
for (let i = 0; i < 3; i++) {
  setTimeout(function() {
    console.log(i);  // 0, 1, 2 ✓
  }, 1000);
}

// ✅ Solution 2: IIFE creates new scope per iteration
for (var i = 0; i < 3; i++) {
  (function(capturedI) {
    setTimeout(function() {
      console.log(capturedI);  // 0, 1, 2 ✓
    }, 1000);
  })(i);  // Pass current i value
}

// ✅ Solution 3: Use forEach (creates closure naturally)
[0, 1, 2].forEach(function(i) {
  setTimeout(function() {
    console.log(i);  // 0, 1, 2 ✓
  }, 1000);
});`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "Lexical Scope", desc: "Where code is written determines scope", color: "#a855f7" },
                { title: "Closure", desc: "Function + its lexical environment", color: "#22c55e" },
                { title: "Block Scope", desc: "let/const respect {} blocks", color: "#3b82f6" },
                { title: "Function Scope", desc: "var is function-scoped", color: "#f59e0b" },
                { title: "Global Scope", desc: "Top-level, accessible everywhere", color: "#ef4444" },
                { title: "Scope Chain", desc: "Looking up variables outward", color: "#8b5cf6" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.title}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha(item.color, 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, fontSize: "0.75rem" }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.7rem" }}>{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 19: The 'this' Keyword */}
          <Paper id="this-keyword" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#06b6d4", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <CodeIcon sx={{ color: "#06b6d4" }} />
              </Box>
              The 'this' Keyword Demystified
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              The <code style={{ background: alpha("#06b6d4", 0.2), padding: "2px 6px", borderRadius: 4 }}>this</code> keyword is one 
              of the most confusing aspects of JavaScript for beginners and even experienced developers. Unlike most languages where 
              `this` always refers to the current instance, JavaScript's `this` is determined by <strong>how a function is called</strong>, 
              not where it's defined. Once you understand the four rules that govern `this`, it becomes predictable and powerful.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>The Four Rules of 'this'</Typography>
            
            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.2)}`, mb: 3 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Rule Priority (Highest to Lowest):</Typography>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`1. new Binding     → this = newly created object
2. Explicit Binding → this = specified by call/apply/bind
3. Implicit Binding → this = object that owns the method
4. Default Binding  → this = globalThis (or undefined in strict mode)

Ask these questions in order:
1. Was the function called with 'new'?           → this = new object
2. Was it called with call/apply/bind?           → this = specified object
3. Was it called as a method (obj.method())?     → this = obj
4. None of the above?                            → this = global/undefined`}
              </Box>
            </Paper>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#06b6d4", fontWeight: 700, mb: 1 }}>Rule 1: new Binding</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// When using 'new', this = new empty object
function Person(name) {
  // this = {} (new empty object)
  this.name = name;
  // return this (implicitly)
}

const alex = new Person("Alex");
console.log(alex.name);  // "Alex"

// What 'new' does behind the scenes:
// 1. Creates new empty object: {}
// 2. Sets this = that object
// 3. Links prototype
// 4. Returns the object (unless you return something else)`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#06b6d4", fontWeight: 700, mb: 1 }}>Rule 2: Explicit Binding</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// call, apply, bind let you specify 'this'
function greet(greeting, punctuation) {
  console.log(greeting + ", " + this.name + punctuation);
}

const user = { name: "Alex" };

// call: pass arguments individually
greet.call(user, "Hello", "!");    // "Hello, Alex!"

// apply: pass arguments as array
greet.apply(user, ["Hi", "?"]);    // "Hi, Alex?"

// bind: returns NEW function with fixed 'this'
const boundGreet = greet.bind(user);
boundGreet("Hey", ".");            // "Hey, Alex."

// bind with partial application
const sayHi = greet.bind(user, "Hi");
sayHi("!");  // "Hi, Alex!"`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#06b6d4", fontWeight: 700, mb: 1 }}>Rule 3: Implicit Binding</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// When called as method, this = owner object
const user = {
  name: "Alex",
  greet() {
    console.log("Hello, " + this.name);
  }
};

user.greet();  // "Hello, Alex" (this = user)

// ⚠️ PITFALL: Losing implicit binding
const greetFn = user.greet;  // Extract method
greetFn();  // "Hello, undefined" - this is lost!

// The object "owning" the method matters:
const anotherUser = {
  name: "Sam",
  greet: user.greet  // Borrowed method
};
anotherUser.greet();  // "Hello, Sam" (this = anotherUser)`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#06b6d4", fontWeight: 700, mb: 1 }}>Rule 4: Default Binding</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Plain function call: this = global or undefined

function showThis() {
  console.log(this);
}

showThis();  // In browser: Window object
             // In Node: global object
             // In strict mode: undefined

"use strict";
function strictShowThis() {
  console.log(this);
}
strictShowThis();  // undefined (strict mode)

// This is why you might see errors like:
// "Cannot read property 'x' of undefined"
// The function lost its 'this' context`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>Arrow Functions & 'this'</Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Arrow functions are special: they <strong>don't have their own 'this'</strong>. Instead, they inherit 'this' from their 
              enclosing scope (lexical this). This makes them perfect for callbacks and event handlers where you want to preserve the 
              outer 'this' context.
            </Typography>

            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#06b6d4", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Arrow functions inherit 'this' from enclosing scope

const user = {
  name: "Alex",
  
  // Regular function: this = user
  regularGreet: function() {
    console.log("Regular:", this.name);
    
    // ❌ Problem: Nested function loses 'this'
    setTimeout(function() {
      console.log("Timeout:", this.name);  // undefined!
    }, 100);
    
    // ✅ Solution 1: Arrow function inherits 'this'
    setTimeout(() => {
      console.log("Arrow:", this.name);    // "Alex" ✓
    }, 100);
    
    // ✅ Solution 2: Save 'this' to variable (old pattern)
    const self = this;
    setTimeout(function() {
      console.log("Self:", self.name);     // "Alex" ✓
    }, 100);
    
    // ✅ Solution 3: bind
    setTimeout(function() {
      console.log("Bound:", this.name);    // "Alex" ✓
    }.bind(this), 100);
  },
  
  // ⚠️ CAUTION: Arrow function as method
  arrowGreet: () => {
    // 'this' is NOT user! It's the enclosing scope (global/module)
    console.log("Arrow method:", this.name);  // undefined!
  }
};

user.regularGreet();
user.arrowGreet();  // undefined - don't use arrows as methods!`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "new", desc: "Creates new object for 'this'", color: "#22c55e" },
                { title: "call()", desc: "Invoke with specified 'this'", color: "#3b82f6" },
                { title: "apply()", desc: "Like call, args as array", color: "#8b5cf6" },
                { title: "bind()", desc: "Returns function with fixed 'this'", color: "#f59e0b" },
                { title: "Arrow =>", desc: "Inherits 'this' lexically", color: "#06b6d4" },
                { title: "globalThis", desc: "Global object reference", color: "#ef4444" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.title}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha(item.color, 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, fontFamily: "monospace" }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.7rem" }}>{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 20: Prototypes & Inheritance */}
          <Paper id="prototypes" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#10b981", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#10b981", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <ExtensionIcon sx={{ color: "#10b981" }} />
              </Box>
              Prototypes & Inheritance
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              JavaScript uses <strong>prototypal inheritance</strong>, which is fundamentally different from classical inheritance in 
              languages like Java or C++. Instead of classes being blueprints for objects, objects directly inherit from other objects. 
              Every object in JavaScript has an internal link to another object called its <strong>prototype</strong>. When you access a 
              property that doesn't exist on an object, JavaScript looks up the prototype chain to find it.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>The Prototype Chain</Typography>
            <Paper sx={{ p: 3, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#10b981", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Every object has a prototype (accessed via __proto__ or Object.getPrototypeOf)

const animal = {
  eats: true,
  walk() {
    console.log("Walking...");
  }
};

const dog = {
  barks: true,
  __proto__: animal  // dog's prototype is animal
};

console.log(dog.barks);  // true (own property)
console.log(dog.eats);   // true (inherited from animal)
dog.walk();              // "Walking..." (inherited method)

// The prototype chain:
// dog → animal → Object.prototype → null

// Visualized:
┌─────────────────┐     ┌─────────────────┐     ┌───────────────────┐
│      dog        │────▶│     animal      │────▶│ Object.prototype  │────▶ null
│  barks: true    │     │  eats: true     │     │  toString()       │
│  [[Prototype]]  │     │  walk()         │     │  hasOwnProperty() │
└─────────────────┘     │  [[Prototype]]  │     │  [[Prototype]]    │
                        └─────────────────┘     └───────────────────┘

// Property lookup:
dog.toString();  // Found on Object.prototype
dog.fly();       // undefined (not found anywhere in chain)`}
              </Box>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>Constructor Functions & prototype</Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Before ES6 classes, constructor functions were the primary way to create objects with shared behavior. Every function has 
              a <code style={{ background: alpha("#10b981", 0.2), padding: "2px 6px", borderRadius: 4 }}>prototype</code> property that 
              becomes the prototype of objects created with <code>new</code>.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#10b981", fontWeight: 700, mb: 1 }}>Constructor Pattern</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Constructor function (capitalize by convention)
function Person(name, age) {
  // Instance properties (unique to each object)
  this.name = name;
  this.age = age;
}

// Prototype methods (shared by all instances)
Person.prototype.greet = function() {
  return "Hi, I'm " + this.name;
};

Person.prototype.birthday = function() {
  this.age++;
};

// Create instances
const alex = new Person("Alex", 25);
const sam = new Person("Sam", 30);

console.log(alex.greet());  // "Hi, I'm Alex"
console.log(sam.greet());   // "Hi, I'm Sam"

// Both share the SAME greet function
alex.greet === sam.greet;  // true (memory efficient!)

// Check prototype chain
alex.__proto__ === Person.prototype;  // true
Person.prototype.__proto__ === Object.prototype;  // true`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#10b981", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#10b981", fontWeight: 700, mb: 1 }}>ES6 Classes (Syntactic Sugar)</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// ES6 class is syntactic sugar over prototypes
class Person {
  // Constructor for instance properties
  constructor(name, age) {
    this.name = name;
    this.age = age;
  }
  
  // Methods go on prototype automatically
  greet() {
    return "Hi, I'm " + this.name;
  }
  
  birthday() {
    this.age++;
  }
  
  // Static method (on class itself, not instances)
  static species() {
    return "Homo sapiens";
  }
}

const alex = new Person("Alex", 25);
alex.greet();        // "Hi, I'm Alex"
Person.species();    // "Homo sapiens"

// Under the hood, it's still prototypes:
typeof Person;  // "function"
alex.__proto__ === Person.prototype;  // true`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>Inheritance with Classes</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#10b981", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Parent class
class Animal {
  constructor(name) {
    this.name = name;
  }
  
  speak() {
    console.log(this.name + " makes a sound.");
  }
}

// Child class extends parent
class Dog extends Animal {
  constructor(name, breed) {
    super(name);  // MUST call super() first!
    this.breed = breed;
  }
  
  // Override parent method
  speak() {
    console.log(this.name + " barks!");
  }
  
  // New method
  fetch() {
    console.log(this.name + " fetches the ball!");
  }
}

const buddy = new Dog("Buddy", "Golden Retriever");
buddy.speak();   // "Buddy barks!" (overridden method)
buddy.fetch();   // "Buddy fetches the ball!"
buddy.name;      // "Buddy" (inherited from Animal)

// Prototype chain:
// buddy → Dog.prototype → Animal.prototype → Object.prototype → null

// instanceof checks the chain
buddy instanceof Dog;     // true
buddy instanceof Animal;  // true
buddy instanceof Object;  // true`}
              </Box>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>Object.create() & Pure Prototypal Inheritance</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#10b981", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Object.create() - direct prototypal inheritance
const personProto = {
  greet() {
    return "Hi, I'm " + this.name;
  },
  
  init(name, age) {
    this.name = name;
    this.age = age;
    return this;
  }
};

// Create object with personProto as its prototype
const alex = Object.create(personProto).init("Alex", 25);
alex.greet();  // "Hi, I'm Alex"

// Useful for:
// 1. Creating objects without constructors
// 2. Setting up inheritance chains manually
// 3. Creating objects with null prototype (no inherited methods)

const pureObject = Object.create(null);
pureObject.toString;  // undefined (no Object.prototype!)
// Good for dictionary/map objects without prototype pollution

// Check if property is own vs inherited
alex.hasOwnProperty("name");   // true (own)
alex.hasOwnProperty("greet");  // false (inherited)
"greet" in alex;               // true (checks whole chain)`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "[[Prototype]]", desc: "Internal prototype link", color: "#10b981" },
                { title: "__proto__", desc: "Accessor for prototype", color: "#3b82f6" },
                { title: ".prototype", desc: "Function's prototype property", color: "#8b5cf6" },
                { title: "extends", desc: "Class inheritance keyword", color: "#f59e0b" },
                { title: "super", desc: "Call parent constructor/methods", color: "#ef4444" },
                { title: "instanceof", desc: "Check prototype chain", color: "#06b6d4" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.title}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha(item.color, 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, fontFamily: "monospace", fontSize: "0.75rem" }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.7rem" }}>{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 21: Error Handling */}
          <Paper id="error-handling" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#ef4444", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#ef4444", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <BuildIcon sx={{ color: "#ef4444" }} />
              </Box>
              Error Handling Best Practices
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Proper error handling separates production-quality code from amateur scripts. In JavaScript, errors are objects that 
              represent something going wrong during execution. Understanding how to catch, throw, and manage errors effectively will 
              make your applications more robust and easier to debug. Remember: errors aren't failures—they're information about what 
              went wrong.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>try...catch...finally</Typography>
            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#ef4444", fontWeight: 700, mb: 1 }}>Basic Error Handling</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`try {
  // Code that might throw an error
  const result = riskyOperation();
  console.log("Success:", result);
  
} catch (error) {
  // Handle the error
  console.error("Error occurred:", error.message);
  
  // Error object properties:
  console.log(error.name);     // "TypeError", "ReferenceError", etc.
  console.log(error.message);  // Human-readable description
  console.log(error.stack);    // Stack trace for debugging
  
} finally {
  // ALWAYS runs, whether error or not
  // Perfect for cleanup code
  cleanup();
  closeConnection();
}

// Code continues here (if error was caught)`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#ef4444", fontWeight: 700, mb: 1 }}>Throwing Custom Errors</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Throw built-in error types
throw new Error("Something went wrong");
throw new TypeError("Expected a string");
throw new RangeError("Value out of range");

// Throw with validation
function divide(a, b) {
  if (typeof a !== "number" || typeof b !== "number") {
    throw new TypeError("Arguments must be numbers");
  }
  if (b === 0) {
    throw new RangeError("Cannot divide by zero");
  }
  return a / b;
}

try {
  divide(10, 0);
} catch (error) {
  if (error instanceof RangeError) {
    console.log("Division error:", error.message);
  } else if (error instanceof TypeError) {
    console.log("Type error:", error.message);
  } else {
    throw error;  // Re-throw unknown errors
  }
}`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>Custom Error Classes</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#ef4444", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Create custom error classes for your application
class ValidationError extends Error {
  constructor(message, field) {
    super(message);
    this.name = "ValidationError";
    this.field = field;
  }
}

class NetworkError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.name = "NetworkError";
    this.statusCode = statusCode;
  }
}

class AuthenticationError extends Error {
  constructor(message) {
    super(message);
    this.name = "AuthenticationError";
  }
}

// Usage
function validateUser(user) {
  if (!user.email) {
    throw new ValidationError("Email is required", "email");
  }
  if (!user.email.includes("@")) {
    throw new ValidationError("Invalid email format", "email");
  }
  if (user.age < 0) {
    throw new ValidationError("Age cannot be negative", "age");
  }
}

try {
  validateUser({ name: "Alex", age: -5 });
} catch (error) {
  if (error instanceof ValidationError) {
    console.log("Validation failed for field:", error.field);
    console.log("Message:", error.message);
    // Show error to user for specific field
  }
}`}
              </Box>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>Async Error Handling</Typography>
            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#ef4444", fontWeight: 700, mb: 1 }}>Promises</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Promise error handling with .catch()
fetch("/api/users")
  .then(response => {
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }
    return response.json();
  })
  .then(data => {
    console.log("Users:", data);
  })
  .catch(error => {
    // Catches any error in the chain
    console.error("Failed to fetch:", error);
  })
  .finally(() => {
    // Always runs
    hideLoadingSpinner();
  });

// Promise.all error handling
Promise.all([fetch("/api/a"), fetch("/api/b")])
  .then(responses => /* handle */)
  .catch(error => {
    // If ANY promise rejects
    console.error("One or more failed:", error);
  });`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#ef4444", fontWeight: 700, mb: 1 }}>async/await</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// async/await with try...catch
async function fetchUsers() {
  try {
    const response = await fetch("/api/users");
    
    if (!response.ok) {
      throw new NetworkError(
        "Failed to fetch users",
        response.status
      );
    }
    
    const data = await response.json();
    return data;
    
  } catch (error) {
    if (error instanceof NetworkError) {
      console.error("Network issue:", error.statusCode);
    } else {
      console.error("Unexpected error:", error);
    }
    throw error;  // Re-throw to let caller handle
  } finally {
    hideLoadingSpinner();
  }
}

// Calling async function
fetchUsers()
  .then(users => console.log(users))
  .catch(error => showErrorToast(error.message));`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>Global Error Handling</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#ef4444", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Browser: Catch uncaught errors globally
window.addEventListener("error", (event) => {
  console.error("Uncaught error:", event.error);
  // Send to error tracking service (Sentry, LogRocket, etc.)
  trackError(event.error);
  // Don't show ugly browser error to user
  event.preventDefault();
});

// Catch unhandled Promise rejections
window.addEventListener("unhandledrejection", (event) => {
  console.error("Unhandled promise rejection:", event.reason);
  trackError(event.reason);
  event.preventDefault();
});

// Node.js global error handling
process.on("uncaughtException", (error) => {
  console.error("Uncaught exception:", error);
  // Log error, notify team, then exit gracefully
  process.exit(1);
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled rejection:", reason);
});

// React Error Boundaries (class component)
class ErrorBoundary extends React.Component {
  state = { hasError: false };
  
  static getDerivedStateFromError(error) {
    return { hasError: true };
  }
  
  componentDidCatch(error, info) {
    trackError(error, info.componentStack);
  }
  
  render() {
    if (this.state.hasError) {
      return <h1>Something went wrong.</h1>;
    }
    return this.props.children;
  }
}`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "Error", desc: "Base error class", color: "#ef4444" },
                { title: "TypeError", desc: "Wrong type used", color: "#f59e0b" },
                { title: "ReferenceError", desc: "Undefined variable", color: "#8b5cf6" },
                { title: "SyntaxError", desc: "Invalid syntax", color: "#ec4899" },
                { title: "RangeError", desc: "Value out of range", color: "#06b6d4" },
                { title: "try/catch", desc: "Error handling block", color: "#22c55e" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.title}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha(item.color, 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, fontFamily: "monospace", fontSize: "0.75rem" }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ fontSize: "0.7rem" }}>{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 22: Web APIs */}
          <Paper id="web-apis" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <CloudIcon sx={{ color: "#3b82f6" }} />
              </Box>
              Essential Web APIs
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Web APIs are interfaces provided by browsers that let JavaScript interact with the browser and the user's device. They're 
              not part of the JavaScript language itself—they're provided by the browser environment. Understanding these APIs is 
              essential for building modern web applications that can store data, make network requests, handle media, and more.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>Fetch API</Typography>
            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#3b82f6", fontWeight: 700, mb: 1 }}>Making HTTP Requests</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// GET request
const response = await fetch("/api/users");
const users = await response.json();

// POST request with body
const newUser = await fetch("/api/users", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token
  },
  body: JSON.stringify({
    name: "Alex",
    email: "alex@example.com"
  })
});

// Check response status
if (!response.ok) {
  throw new Error("HTTP " + response.status);
}

// Response methods
await response.json();   // Parse as JSON
await response.text();   // Get as text
await response.blob();   // Get as binary blob
await response.formData(); // Get as FormData`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#3b82f6", fontWeight: 700, mb: 1 }}>Advanced Fetch Patterns</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Upload file
const formData = new FormData();
formData.append("file", fileInput.files[0]);
await fetch("/upload", {
  method: "POST",
  body: formData
});

// Abort a request
const controller = new AbortController();
setTimeout(() => controller.abort(), 5000); // 5s timeout

try {
  const response = await fetch("/api/slow", {
    signal: controller.signal
  });
} catch (error) {
  if (error.name === "AbortError") {
    console.log("Request was cancelled");
  }
}

// Parallel requests
const [users, posts] = await Promise.all([
  fetch("/api/users").then(r => r.json()),
  fetch("/api/posts").then(r => r.json())
]);`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>Storage APIs</Typography>
            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#22c55e", fontWeight: 700, mb: 1 }}>localStorage & sessionStorage</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// localStorage: Persists until manually cleared
localStorage.setItem("theme", "dark");
const theme = localStorage.getItem("theme");
localStorage.removeItem("theme");
localStorage.clear();  // Remove all

// Store objects (must stringify)
const user = { name: "Alex", age: 25 };
localStorage.setItem("user", JSON.stringify(user));
const stored = JSON.parse(localStorage.getItem("user"));

// sessionStorage: Cleared when tab closes
sessionStorage.setItem("tempData", "value");

// Check storage availability
function storageAvailable() {
  try {
    localStorage.setItem("test", "test");
    localStorage.removeItem("test");
    return true;
  } catch (e) {
    return false;
  }
}

// Storage event (cross-tab communication!)
window.addEventListener("storage", (event) => {
  console.log("Storage changed:", event.key, event.newValue);
});`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#3b82f6", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#f59e0b", fontWeight: 700, mb: 1 }}>IndexedDB (Advanced Storage)</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// IndexedDB: For large structured data
const request = indexedDB.open("MyDatabase", 1);

request.onupgradeneeded = (event) => {
  const db = event.target.result;
  // Create object store (like a table)
  const store = db.createObjectStore("users", {
    keyPath: "id",
    autoIncrement: true
  });
  store.createIndex("email", "email", { unique: true });
};

request.onsuccess = (event) => {
  const db = event.target.result;
  
  // Add data
  const tx = db.transaction("users", "readwrite");
  const store = tx.objectStore("users");
  store.add({ name: "Alex", email: "alex@example.com" });
  
  // Read data
  const getRequest = store.get(1);
  getRequest.onsuccess = () => {
    console.log("User:", getRequest.result);
  };
};

// Consider using idb library for Promise-based API`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>Other Essential APIs</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#3b82f6", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// URL API - Parse and manipulate URLs
const url = new URL("https://example.com/path?name=alex&page=2");
url.searchParams.get("name");        // "alex"
url.searchParams.set("page", "3");   // Update param
url.searchParams.append("sort", "asc"); // Add param
url.href;  // Full URL string

// History API - Manipulate browser history
history.pushState({ page: 2 }, "Page 2", "/page-2");
history.replaceState({ page: 3 }, "Page 3", "/page-3");
history.back();
window.addEventListener("popstate", (event) => {
  console.log("Navigated to:", event.state);
});

// Clipboard API - Copy/paste
await navigator.clipboard.writeText("Hello, clipboard!");
const text = await navigator.clipboard.readText();

// Geolocation API - Get user location
navigator.geolocation.getCurrentPosition(
  (position) => {
    console.log("Lat:", position.coords.latitude);
    console.log("Long:", position.coords.longitude);
  },
  (error) => console.error("Location error:", error),
  { enableHighAccuracy: true }
);

// Intersection Observer - Lazy loading, infinite scroll
const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      entry.target.src = entry.target.dataset.src; // Lazy load
      observer.unobserve(entry.target);
    }
  });
}, { rootMargin: "100px" });

document.querySelectorAll("img[data-src]").forEach(img => {
  observer.observe(img);
});`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "Fetch", desc: "HTTP requests", color: "#3b82f6" },
                { title: "localStorage", desc: "Persistent storage", color: "#22c55e" },
                { title: "IndexedDB", desc: "Large data storage", color: "#f59e0b" },
                { title: "History", desc: "Browser navigation", color: "#8b5cf6" },
                { title: "Geolocation", desc: "User location", color: "#ef4444" },
                { title: "Clipboard", desc: "Copy/paste access", color: "#06b6d4" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.title}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha(item.color, 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 23: Performance Optimization */}
          <Paper id="performance" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <SpeedIcon sx={{ color: "#f59e0b" }} />
              </Box>
              Performance Optimization
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Fast applications create better user experiences and improve business metrics. Understanding JavaScript performance 
              optimization helps you write efficient code from the start and diagnose bottlenecks when they occur. Performance isn't 
              just about speed—it's about responsiveness, memory efficiency, and efficient resource usage.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>Debouncing & Throttling</Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              When handling frequent events like scrolling, resizing, or typing, running your handler on every event can cause 
              performance issues. <strong>Debouncing</strong> waits until events stop firing before executing, while 
              <strong> throttling</strong> limits execution to once per time period.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#f59e0b", fontWeight: 700, mb: 1 }}>Debounce</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Debounce: Execute AFTER events stop
// Use for: search input, window resize, form validation

function debounce(func, delay) {
  let timeoutId;
  return function(...args) {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => {
      func.apply(this, args);
    }, delay);
  };
}

// Example: Search as you type
const searchInput = document.getElementById("search");
const debouncedSearch = debounce((query) => {
  console.log("Searching for:", query);
  // Make API call here
}, 300);

searchInput.addEventListener("input", (e) => {
  debouncedSearch(e.target.value);
});
// Only searches 300ms after user stops typing`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#f59e0b", fontWeight: 700, mb: 1 }}>Throttle</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Throttle: Execute at most once per interval
// Use for: scroll handlers, mouse move, game loops

function throttle(func, limit) {
  let inThrottle;
  return function(...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

// Example: Scroll position tracking
const throttledScroll = throttle(() => {
  console.log("Scroll position:", window.scrollY);
  // Update UI, check infinite scroll, etc.
}, 100);

window.addEventListener("scroll", throttledScroll);
// Executes at most every 100ms during scroll

// Leading edge vs trailing edge versions exist
// Libraries like lodash have more options`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>DOM Performance</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#f59e0b", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// ❌ BAD: Multiple DOM updates cause reflows
for (let i = 0; i < 1000; i++) {
  document.body.innerHTML += "<div>" + i + "</div>";  // 1000 reflows!
}

// ✅ GOOD: Batch DOM updates with DocumentFragment
const fragment = document.createDocumentFragment();
for (let i = 0; i < 1000; i++) {
  const div = document.createElement("div");
  div.textContent = i;
  fragment.appendChild(div);
}
document.body.appendChild(fragment);  // Single reflow!

// ✅ GOOD: Use innerHTML for bulk updates
const html = Array.from({ length: 1000 }, (_, i) => 
  "<div>" + i + "</div>"
).join("");
document.body.innerHTML = html;

// ❌ BAD: Reading layout during writes causes forced reflow
elements.forEach(el => {
  el.style.width = el.offsetWidth + 10 + "px";  // Read + Write loop!
});

// ✅ GOOD: Batch reads, then batch writes
const widths = elements.map(el => el.offsetWidth);  // All reads
elements.forEach((el, i) => {
  el.style.width = widths[i] + 10 + "px";  // All writes
});

// Use requestAnimationFrame for visual updates
function animate() {
  element.style.transform = "translateX(" + x + "px)";
  if (x < 100) {
    x++;
    requestAnimationFrame(animate);
  }
}
requestAnimationFrame(animate);`}
              </Box>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>Memory Management</Typography>
            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#ef4444", fontWeight: 700, mb: 1 }}>Common Memory Leaks</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// ❌ Leak: Forgotten event listeners
function setup() {
  const btn = document.getElementById("btn");
  btn.addEventListener("click", handleClick);
  // Listener keeps handleClick in memory!
}

// ❌ Leak: Growing closures
let data = [];
setInterval(() => {
  data.push(new Array(10000));
  // data grows forever!
}, 1000);

// ❌ Leak: Detached DOM nodes
let elements = [];
function addElement() {
  const div = document.createElement("div");
  document.body.appendChild(div);
  elements.push(div);  // Reference kept
  document.body.removeChild(div);
  // div removed from DOM but still in memory!
}`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#f59e0b", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#22c55e", fontWeight: 700, mb: 1 }}>Memory Leak Prevention</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// ✅ Clean up event listeners
function setup() {
  const btn = document.getElementById("btn");
  btn.addEventListener("click", handleClick);
  
  return function cleanup() {
    btn.removeEventListener("click", handleClick);
  };
}

// ✅ Use WeakMap/WeakSet for metadata
const metadata = new WeakMap();
function setMetadata(element, data) {
  metadata.set(element, data);
  // When element is removed, metadata is GC'd too!
}

// ✅ Clear references when done
let cache = {};
function processData(data) {
  cache[data.id] = data;
  
  // Clean up old entries
  if (Object.keys(cache).length > 100) {
    const oldestKey = Object.keys(cache)[0];
    delete cache[oldestKey];
  }
}

// ✅ AbortController for cleanup
const controller = new AbortController();
element.addEventListener("click", handler, {
  signal: controller.signal
});
// Later: controller.abort(); removes all listeners`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>Code Splitting & Lazy Loading</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#f59e0b", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Dynamic imports for code splitting
// Bundlers (Webpack, Vite) create separate chunks

// Load module only when needed
async function loadChart() {
  const { Chart } = await import("./chartLibrary.js");
  return new Chart(data);
}

// React lazy loading
const HeavyComponent = React.lazy(() => import("./HeavyComponent"));

function App() {
  return (
    <Suspense fallback={<Spinner />}>
      <HeavyComponent />
    </Suspense>
  );
}

// Route-based code splitting (React Router)
const Dashboard = React.lazy(() => import("./pages/Dashboard"));
const Settings = React.lazy(() => import("./pages/Settings"));

<Routes>
  <Route path="/dashboard" element={
    <Suspense fallback={<Spinner />}>
      <Dashboard />
    </Suspense>
  } />
</Routes>

// Intersection Observer for lazy loading images/content
const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) {
      loadContent(entry.target);
      observer.unobserve(entry.target);
    }
  });
});`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "Debounce", desc: "Wait for events to stop", color: "#f59e0b" },
                { title: "Throttle", desc: "Limit execution rate", color: "#22c55e" },
                { title: "RAF", desc: "requestAnimationFrame", color: "#3b82f6" },
                { title: "WeakMap", desc: "GC-friendly maps", color: "#8b5cf6" },
                { title: "Lazy Load", desc: "Load on demand", color: "#ef4444" },
                { title: "Profiler", desc: "DevTools Performance", color: "#06b6d4" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.title}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha(item.color, 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 24: Security Best Practices */}
          <Paper id="security" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#dc2626", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#dc2626", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <BuildIcon sx={{ color: "#dc2626" }} />
              </Box>
              Security Best Practices
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Security vulnerabilities in JavaScript applications can lead to data breaches, account takeovers, and reputation damage. 
              While you can't prevent all attacks from the frontend alone, understanding common vulnerabilities and defensive techniques 
              is essential. Always remember: <strong>never trust user input</strong> and <strong>defense in depth</strong>.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>XSS (Cross-Site Scripting)</Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              XSS attacks inject malicious scripts into your web pages. When other users view those pages, the scripts execute in their 
              browsers, potentially stealing cookies, session tokens, or sensitive data.
            </Typography>

            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#ef4444", fontWeight: 700, mb: 1 }}>❌ Vulnerable Code</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// ❌ DANGEROUS: innerHTML with user input
const userInput = "<img src=x onerror=alert('XSS')>";
element.innerHTML = userInput;  // Script executes!

// ❌ DANGEROUS: Direct DOM manipulation
document.write(userInput);
element.outerHTML = userInput;

// ❌ DANGEROUS: eval with user input
const userCode = "alert('XSS')";
eval(userCode);  // Never use eval!

// ❌ DANGEROUS: URL without validation
const url = getUserInput();
window.location.href = url;  // javascript:alert('XSS')

// ❌ DANGEROUS: React dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{ __html: userInput }} />`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#22c55e", fontWeight: 700, mb: 1 }}>✅ Safe Code</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// ✅ SAFE: textContent doesn't execute scripts
element.textContent = userInput;

// ✅ SAFE: Use createElement for dynamic content
const div = document.createElement("div");
div.textContent = userInput;
parent.appendChild(div);

// ✅ SAFE: Sanitize HTML if you MUST use innerHTML
import DOMPurify from "dompurify";
element.innerHTML = DOMPurify.sanitize(userInput);

// ✅ SAFE: Validate URLs
function isValidUrl(string) {
  try {
    const url = new URL(string);
    return ["http:", "https:"].includes(url.protocol);
  } catch { return false; }
}

// ✅ SAFE: React escapes by default
<div>{userInput}</div>  // Auto-escaped`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>CSRF & Secure Data Handling</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#dc2626", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// CSRF Protection: Include tokens with requests
// Server provides token in cookie or meta tag

// Get CSRF token from meta tag
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;

// Include in fetch requests
fetch("/api/transfer", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-Token": csrfToken  // Server validates this
  },
  credentials: "same-origin",  // Important for cookies
  body: JSON.stringify({ amount: 100 })
});

// Secure cookie handling
document.cookie = "session=abc123; Secure; HttpOnly; SameSite=Strict";
// Secure: Only HTTPS
// HttpOnly: Not accessible via JavaScript (prevents XSS theft)
// SameSite: Prevents CSRF

// NEVER store sensitive data in localStorage
// ❌ localStorage.setItem("authToken", token);
// ✅ Use HttpOnly cookies for auth tokens

// Sensitive data handling
// Clear sensitive data when done
let creditCard = "1234-5678-9012-3456";
// ... use it ...
creditCard = null;  // Clear reference
// Still in memory until GC, but helps`}
              </Box>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#dc2626" }}>Input Validation & Secure Coding</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#dc2626", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Always validate on BOTH frontend AND backend
// Frontend validation is for UX, backend is for security

function validateEmail(email) {
  const re = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;
  return re.test(email);
}

function validatePassword(password) {
  return password.length >= 8 &&
         /[A-Z]/.test(password) &&
         /[a-z]/.test(password) &&
         /[0-9]/.test(password);
}

// Prototype pollution prevention
// ❌ VULNERABLE
function merge(target, source) {
  for (let key in source) {
    target[key] = source[key];  // Can modify __proto__!
  }
}

// ✅ SAFE
function safeMerge(target, source) {
  for (let key in source) {
    if (source.hasOwnProperty(key) && key !== "__proto__" && key !== "constructor") {
      target[key] = source[key];
    }
  }
}

// Object.freeze for constants
const CONFIG = Object.freeze({
  API_URL: "https://api.example.com",
  MAX_RETRIES: 3
});
CONFIG.API_URL = "https://evil.com";  // Silently fails (or throws in strict mode)

// Content Security Policy (CSP) - Set in server headers
// Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-abc123'`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "XSS", desc: "Script injection attack", color: "#dc2626" },
                { title: "CSRF", desc: "Cross-site request forgery", color: "#f59e0b" },
                { title: "CSP", desc: "Content Security Policy", color: "#22c55e" },
                { title: "Sanitize", desc: "Clean user input", color: "#3b82f6" },
                { title: "HttpOnly", desc: "Cookie JS protection", color: "#8b5cf6" },
                { title: "SameSite", desc: "Cookie CSRF protection", color: "#06b6d4" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.title}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha(item.color, 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 25: Debugging Mastery */}
          <Paper id="debugging" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <TerminalIcon sx={{ color: "#8b5cf6" }} />
              </Box>
              Debugging Mastery
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Effective debugging is a superpower. While `console.log` is everyone's first debugging tool, browser DevTools offer 
              powerful features that can save you hours. Learning these tools properly will make you dramatically more productive 
              at finding and fixing bugs.
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>Console Methods</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#8b5cf6", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Beyond console.log - there's a whole toolkit!

// Styled console output
console.log("%cHello", "color: blue; font-size: 20px");

// Object/array display
console.table([{name: "Alex", age: 25}, {name: "Sam", age: 30}]);
console.dir(document.body);  // Interactive object tree

// Grouping related logs
console.group("User Processing");
console.log("Fetching user...");
console.log("Validating...");
console.groupEnd();

// Conditional logging
console.assert(x > 0, "x should be positive!");  // Only logs if false

// Timing
console.time("operation");
// ... code to measure ...
console.timeEnd("operation");  // "operation: 12.345ms"

// Stack trace
console.trace("Where am I?");  // Shows call stack

// Count executions
function process() {
  console.count("process called");  // "process called: 1", 2, 3...
}

// Clear console
console.clear();`}
              </Box>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>Breakpoints & Stepping</Typography>
            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#8b5cf6", fontWeight: 700, mb: 1 }}>Breakpoint Types</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// In DevTools Sources tab:

1. LINE BREAKPOINTS
   - Click line number to add
   - Right-click for conditional: x > 10

2. debugger STATEMENT
   function buggyCode() {
     debugger;  // Pauses here when DevTools open
     // Inspect state...
   }

3. DOM BREAKPOINTS (Elements tab)
   - Break on subtree modifications
   - Break on attribute changes  
   - Break on node removal

4. EVENT LISTENER BREAKPOINTS
   - Pause on click, keydown, etc.
   - Useful for finding event handlers

5. XHR/FETCH BREAKPOINTS
   - Pause when URL contains string
   - Great for debugging API calls`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#8b5cf6", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#8b5cf6", fontWeight: 700, mb: 1 }}>Stepping Controls</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// When paused at breakpoint:

F8 / Resume (▶)
   Continue until next breakpoint

F10 / Step Over (⤵)
   Execute current line, move to next
   Don't enter function calls

F11 / Step Into (↓)
   Enter the function being called
   Go deeper into execution

Shift+F11 / Step Out (↑)
   Finish current function
   Return to caller

// Useful panels while paused:
- Scope: Local, closure, global variables
- Call Stack: How you got here
- Watch: Track specific expressions
- Breakpoints: Manage all breakpoints

// In Console while paused:
// Access local variables directly!
> localVar
> this
> arguments`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>Network & Performance Debugging</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#8b5cf6", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// NETWORK TAB
- See all HTTP requests
- Inspect headers, payload, response
- Right-click → "Copy as fetch" to reproduce
- Throttle network to test slow connections
- "Preserve log" to keep requests across navigations

// PERFORMANCE TAB
1. Click Record, do action, Stop
2. Analyze flame chart:
   - Yellow: JavaScript execution
   - Purple: Rendering/layout
   - Green: Painting
3. Look for long tasks (>50ms)
4. Find functions taking the most time

// MEMORY TAB
1. Take heap snapshot
2. Perform action
3. Take another snapshot
4. Compare to find memory leaks
5. Look for detached DOM nodes

// LIGHTHOUSE TAB
- Automated performance audit
- Accessibility checks
- Best practices
- SEO recommendations

// Useful keyboard shortcuts (Chrome DevTools):
Ctrl+Shift+P  - Command menu (like VS Code)
Ctrl+P        - Open file
Ctrl+Shift+F  - Search across all sources
Esc           - Toggle console drawer`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "console.*", desc: "Logging methods", color: "#8b5cf6" },
                { title: "debugger", desc: "Pause execution", color: "#22c55e" },
                { title: "Breakpoints", desc: "Pause at conditions", color: "#3b82f6" },
                { title: "Call Stack", desc: "Execution history", color: "#f59e0b" },
                { title: "Network", desc: "HTTP debugging", color: "#ef4444" },
                { title: "Performance", desc: "Timing analysis", color: "#06b6d4" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.title}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha(item.color, 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 26: Design Patterns */}
          <Paper id="design-patterns" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha("#ec4899", 0.15)}` }}>
            <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
              <Box sx={{ width: 48, height: 48, borderRadius: 2, bgcolor: alpha("#ec4899", 0.15), display: "flex", alignItems: "center", justifyContent: "center" }}>
                <ExtensionIcon sx={{ color: "#ec4899" }} />
              </Box>
              JavaScript Design Patterns
            </Typography>

            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              Design patterns are reusable solutions to common programming problems. They're like recipes that experienced developers 
              have refined over time. Learning these patterns will help you write more maintainable, scalable code and communicate 
              better with other developers (since patterns provide a shared vocabulary).
            </Typography>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>Module Pattern</Typography>
            <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
              The Module pattern provides encapsulation, creating private state and exposing only a public API. Before ES6 modules, 
              this was the primary way to avoid polluting the global namespace.
            </Typography>

            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#ec4899", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Module Pattern (IIFE-based)
const Counter = (function() {
  // Private state
  let count = 0;
  
  // Private function
  function log(message) {
    console.log("[Counter]", message);
  }
  
  // Public API (returned object)
  return {
    increment() {
      count++;
      log("Incremented to " + count);
    },
    decrement() {
      count--;
      log("Decremented to " + count);
    },
    getCount() {
      return count;
    }
  };
})();

Counter.increment();  // [Counter] Incremented to 1
Counter.getCount();   // 1
Counter.count;        // undefined (private!)

// Modern ES6 Module (file-based)
// counter.js
let count = 0;  // Private to this module

export function increment() { count++; }
export function getCount() { return count; }`}
              </Box>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>Singleton Pattern</Typography>
            <Grid container spacing={3} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#ec4899", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#ec4899", fontWeight: 700, mb: 1 }}>Singleton</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Singleton: Only one instance exists
class Database {
  constructor() {
    if (Database.instance) {
      return Database.instance;
    }
    this.connection = null;
    Database.instance = this;
  }
  
  connect(url) {
    this.connection = { url, connected: true };
    console.log("Connected to", url);
  }
  
  query(sql) {
    if (!this.connection) throw new Error("Not connected");
    return { sql, result: [] };
  }
}

const db1 = new Database();
const db2 = new Database();
console.log(db1 === db2);  // true - same instance!

// ES6 Module Singleton (simpler)
// database.js
let connection = null;
export function connect(url) { connection = url; }
export function query(sql) { /* use connection */ }`}
                  </Box>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#ec4899", 0.2)}` }}>
                  <Typography variant="subtitle2" sx={{ color: "#ec4899", fontWeight: 700, mb: 1 }}>Factory Pattern</Typography>
                  <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Factory: Create objects without specifying exact class
class Car { drive() { console.log("Driving car"); } }
class Truck { drive() { console.log("Driving truck"); } }
class Motorcycle { drive() { console.log("Riding motorcycle"); } }

class VehicleFactory {
  create(type) {
    switch (type) {
      case "car": return new Car();
      case "truck": return new Truck();
      case "motorcycle": return new Motorcycle();
      default: throw new Error("Unknown vehicle");
    }
  }
}

const factory = new VehicleFactory();
const myCar = factory.create("car");
myCar.drive();  // "Driving car"

// Functional factory (simpler)
function createUser(type, name) {
  const base = { name, createdAt: new Date() };
  if (type === "admin") {
    return { ...base, role: "admin", permissions: ["all"] };
  }
  return { ...base, role: "user", permissions: ["read"] };
}`}
                  </Box>
                </Paper>
              </Grid>
            </Grid>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>Observer Pattern</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#ec4899", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// Observer: Objects subscribe to events from a subject
// (This is how event emitters, React state, and pub/sub work!)

class EventEmitter {
  constructor() {
    this.events = {};
  }
  
  on(event, callback) {
    if (!this.events[event]) {
      this.events[event] = [];
    }
    this.events[event].push(callback);
    
    // Return unsubscribe function
    return () => this.off(event, callback);
  }
  
  off(event, callback) {
    if (this.events[event]) {
      this.events[event] = this.events[event]
        .filter(cb => cb !== callback);
    }
  }
  
  emit(event, data) {
    if (this.events[event]) {
      this.events[event].forEach(callback => callback(data));
    }
  }
}

// Usage
const emitter = new EventEmitter();

const unsubscribe = emitter.on("userLoggedIn", (user) => {
  console.log("Welcome,", user.name);
});

emitter.on("userLoggedIn", (user) => {
  sendAnalytics("login", user.id);
});

emitter.emit("userLoggedIn", { id: 1, name: "Alex" });
// "Welcome, Alex"
// Analytics sent

unsubscribe();  // Remove first listener`}
              </Box>
            </Paper>

            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>More Essential Patterns</Typography>
            <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: "#1e1e1e", border: `1px solid ${alpha("#ec4899", 0.2)}`, mb: 3 }}>
              <Box component="pre" sx={{ m: 0, fontFamily: "monospace", fontSize: "0.85rem", color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
{`// DECORATOR: Add behavior to objects dynamically
function withLogging(fn) {
  return function(...args) {
    console.log("Calling", fn.name, "with", args);
    const result = fn.apply(this, args);
    console.log("Result:", result);
    return result;
  };
}

const add = (a, b) => a + b;
const loggedAdd = withLogging(add);
loggedAdd(2, 3);  // Logs: Calling add with [2, 3], Result: 5

// STRATEGY: Define family of algorithms, make them interchangeable
const strategies = {
  add: (a, b) => a + b,
  subtract: (a, b) => a - b,
  multiply: (a, b) => a * b
};

function calculate(strategy, a, b) {
  return strategies[strategy](a, b);
}

calculate("add", 5, 3);       // 8
calculate("multiply", 5, 3);  // 15

// PROXY: Control access to an object
const user = { name: "Alex", _password: "secret" };

const safeUser = new Proxy(user, {
  get(target, prop) {
    if (prop.startsWith("_")) {
      throw new Error("Access denied to private property");
    }
    return target[prop];
  },
  set(target, prop, value) {
    if (prop === "_password") {
      throw new Error("Cannot modify password directly");
    }
    target[prop] = value;
    return true;
  }
});

safeUser.name;      // "Alex"
safeUser._password; // Error: Access denied`}
              </Box>
            </Paper>

            <Grid container spacing={2}>
              {[
                { title: "Module", desc: "Encapsulation & privacy", color: "#ec4899" },
                { title: "Singleton", desc: "Single instance only", color: "#8b5cf6" },
                { title: "Factory", desc: "Object creation", color: "#3b82f6" },
                { title: "Observer", desc: "Event subscription", color: "#22c55e" },
                { title: "Decorator", desc: "Add behavior", color: "#f59e0b" },
                { title: "Proxy", desc: "Control access", color: "#06b6d4" },
              ].map((item) => (
                <Grid item xs={6} sm={4} md={2} key={item.title}>
                  <Paper sx={{ p: 1.5, borderRadius: 2, bgcolor: alpha(item.color, 0.05), textAlign: "center" }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color }}>{item.title}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </Paper>

          {/* Section 27: Quiz */}
          <QuizSection accentColor={accentColor} accentDark={accentDark} />

          <Divider sx={{ my: 4 }} />

          <Box sx={{ display: "flex", justifyContent: "center" }}>
            <Button
              variant="contained"
              startIcon={<ArrowBackIcon />}
              onClick={() => navigate("/learn")}
              sx={{ bgcolor: accentColor, color: "#000", "&:hover": { bgcolor: accentDark }, px: 4, py: 1.5, fontWeight: 700 }}
            >
              Back to Learning Hub
            </Button>
          </Box>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}

// Quiz Section Component
function QuizSection({ accentColor, accentDark }: { accentColor: string; accentDark: string }) {
  const [quizStarted, setQuizStarted] = useState(false);
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<(number | null)[]>(Array(10).fill(null));
  const [showResults, setShowResults] = useState(false);
  const [quizQuestions, setQuizQuestions] = useState<typeof questionBank>([]);

  const questionBank = [
    // JavaScript Basics (1-15)
    { q: "What does 'var' stand for in JavaScript?", options: ["Variable", "Variant", "Various", "Variation"], correct: 0 },
    { q: "Which symbol is used for single-line comments in JavaScript?", options: ["/* */", "#", "//", "--"], correct: 2 },
    { q: "What is the correct way to declare a constant in JavaScript?", options: ["var x = 5", "let x = 5", "const x = 5", "constant x = 5"], correct: 2 },
    { q: "Which operator is used for strict equality comparison?", options: ["==", "===", "=", "!="], correct: 1 },
    { q: "What will typeof null return?", options: ["null", "undefined", "object", "boolean"], correct: 2 },
    { q: "Which method converts a string to an integer?", options: ["parseFloat()", "parseInt()", "toInteger()", "Number.int()"], correct: 1 },
    { q: "What is the result of 5 + '5' in JavaScript?", options: ["10", "'55'", "55", "Error"], correct: 1 },
    { q: "Which keyword declares a block-scoped variable?", options: ["var", "let", "const", "Both let and const"], correct: 3 },
    { q: "What does NaN stand for?", options: ["Not a Null", "Not a Number", "Null and None", "New assigned Number"], correct: 1 },
    { q: "Which method adds an element to the end of an array?", options: ["push()", "pop()", "shift()", "unshift()"], correct: 0 },
    { q: "What is the output of Boolean('')?", options: ["true", "false", "undefined", "null"], correct: 1 },
    { q: "Which loop is guaranteed to execute at least once?", options: ["for", "while", "do...while", "for...in"], correct: 2 },
    { q: "What does the 'break' statement do?", options: ["Pauses execution", "Exits the loop", "Skips iteration", "Restarts loop"], correct: 1 },
    { q: "Which method removes the last element from an array?", options: ["push()", "pop()", "shift()", "splice()"], correct: 1 },
    { q: "What is the default value of an uninitialized variable?", options: ["null", "0", "undefined", "false"], correct: 2 },

    // Functions (16-25)
    { q: "What is a function that is passed to another function called?", options: ["Nested function", "Callback function", "Arrow function", "Anonymous function"], correct: 1 },
    { q: "Which syntax is correct for an arrow function?", options: ["function => {}", "() => {}", "=> function()", "arrow() => {}"], correct: 1 },
    { q: "What does the 'return' statement do?", options: ["Logs output", "Ends function and returns value", "Declares variable", "Creates loop"], correct: 1 },
    { q: "What are default parameters?", options: ["Required parameters", "Parameters with preset values", "Global variables", "Return values"], correct: 1 },
    { q: "What is a closure in JavaScript?", options: ["A syntax error", "Function with access to outer scope", "A loop structure", "A class method"], correct: 1 },
    { q: "What does the rest parameter (...args) do?", options: ["Spreads array", "Collects arguments into array", "Removes elements", "Copies objects"], correct: 1 },
    { q: "Which array method creates a new array by transforming each element?", options: ["filter()", "map()", "reduce()", "forEach()"], correct: 1 },
    { q: "What does filter() return?", options: ["Single value", "Boolean", "New filtered array", "Modified original array"], correct: 2 },
    { q: "What does reduce() do?", options: ["Filters array", "Maps array", "Accumulates to single value", "Sorts array"], correct: 2 },
    { q: "Are arrow functions hoisted?", options: ["Yes, always", "No, never", "Only in strict mode", "Only with var"], correct: 1 },

    // Objects & Arrays (26-35)
    { q: "How do you access an object property using a variable?", options: ["obj.variable", "obj[variable]", "obj->variable", "obj::variable"], correct: 1 },
    { q: "What does Object.keys() return?", options: ["Array of values", "Array of keys", "Object copy", "Boolean"], correct: 1 },
    { q: "Which method checks if an array includes a value?", options: ["has()", "contains()", "includes()", "exists()"], correct: 2 },
    { q: "What is destructuring?", options: ["Deleting objects", "Extracting values from objects/arrays", "Creating objects", "Copying arrays"], correct: 1 },
    { q: "What does the spread operator (...) do?", options: ["Collects elements", "Expands iterable elements", "Deletes elements", "Filters elements"], correct: 1 },
    { q: "How do you create a shallow copy of an object?", options: ["obj.copy()", "Object.assign({}, obj)", "obj.clone()", "new Object(obj)"], correct: 1 },
    { q: "What does Array.isArray() check?", options: ["If empty", "If array type", "Array length", "Array contents"], correct: 1 },
    { q: "Which method finds the first matching element?", options: ["filter()", "find()", "search()", "get()"], correct: 1 },
    { q: "What does slice() return?", options: ["Modified array", "New array portion", "Single element", "Boolean"], correct: 1 },
    { q: "Does splice() modify the original array?", options: ["Yes", "No", "Only sometimes", "Only with numbers"], correct: 0 },

    // DOM Manipulation (36-45)
    { q: "What does DOM stand for?", options: ["Document Object Model", "Data Object Management", "Dynamic Object Method", "Document Oriented Model"], correct: 0 },
    { q: "Which method selects an element by ID?", options: ["querySelector()", "getElementById()", "getElement()", "selectById()"], correct: 1 },
    { q: "What does querySelectorAll() return?", options: ["Single element", "Array", "NodeList", "HTMLCollection"], correct: 2 },
    { q: "How do you add an event listener?", options: ["on.click()", "addEventListener()", "addEvent()", "onClick()"], correct: 1 },
    { q: "What does event.preventDefault() do?", options: ["Stops propagation", "Prevents default browser action", "Removes event", "Logs event"], correct: 1 },
    { q: "Which property gets/sets element text content?", options: ["innerHTML", "textContent", "innerText", "All of the above"], correct: 1 },
    { q: "How do you add a CSS class to an element?", options: ["addClass()", "classList.add()", "className.add()", "style.addClass()"], correct: 1 },
    { q: "What does document.createElement() do?", options: ["Selects element", "Creates new element", "Deletes element", "Copies element"], correct: 1 },
    { q: "Which method appends a child element?", options: ["append()", "appendChild()", "addChild()", "Both A and B"], correct: 3 },
    { q: "What is event bubbling?", options: ["Events propagate up the DOM", "Events go down", "Events stop", "Events repeat"], correct: 0 },

    // Async JavaScript (46-55)
    { q: "What is a Promise in JavaScript?", options: ["A guarantee", "Object representing eventual completion", "A callback", "A timer"], correct: 1 },
    { q: "Which Promise method handles errors?", options: [".then()", ".catch()", ".finally()", ".error()"], correct: 1 },
    { q: "What keyword makes a function asynchronous?", options: ["await", "async", "promise", "defer"], correct: 1 },
    { q: "Where can you use the 'await' keyword?", options: ["Anywhere", "Only in async functions", "Only in loops", "Only in callbacks"], correct: 1 },
    { q: "What does Promise.all() do?", options: ["Runs first promise", "Waits for all promises", "Cancels promises", "Creates promise"], correct: 1 },
    { q: "What happens if one Promise in Promise.all() rejects?", options: ["Others continue", "All reject", "Nothing", "Retry occurs"], correct: 1 },
    { q: "What is the event loop?", options: ["A for loop", "Mechanism handling async operations", "An array method", "A DOM event"], correct: 1 },
    { q: "Which runs first: setTimeout or Promise.then?", options: ["setTimeout", "Promise.then", "Same time", "Random"], correct: 1 },
    { q: "What does fetch() return?", options: ["Data directly", "Promise", "JSON", "String"], correct: 1 },
    { q: "How do you handle errors in async/await?", options: [".catch()", "try...catch", "if...else", ".error()"], correct: 1 },

    // ES6+ Features (56-65)
    { q: "What are template literals enclosed in?", options: ["Single quotes", "Double quotes", "Backticks", "Parentheses"], correct: 2 },
    { q: "How do you embed expressions in template literals?", options: ["{expr}", "${expr}", "#{expr}", "@{expr}"], correct: 1 },
    { q: "What does the optional chaining operator (?.) do?", options: ["Throws error", "Returns undefined if null/undefined", "Creates chain", "Validates type"], correct: 1 },
    { q: "What is the nullish coalescing operator?", options: ["&&", "||", "??", "?:"], correct: 2 },
    { q: "Which ES6 feature allows default exports?", options: ["CommonJS", "ES Modules", "RequireJS", "AMD"], correct: 1 },
    { q: "What keyword is used to inherit from a class?", options: ["inherits", "extends", "implements", "derives"], correct: 1 },
    { q: "What does Symbol() create?", options: ["String", "Number", "Unique identifier", "Object"], correct: 2 },
    { q: "What is a Set in JavaScript?", options: ["Array of objects", "Collection of unique values", "Key-value pairs", "Ordered list"], correct: 1 },
    { q: "What is a Map in JavaScript?", options: ["Array method", "Key-value collection", "Transformation", "Location API"], correct: 1 },
    { q: "What does for...of iterate over?", options: ["Object keys", "Iterable values", "Object properties", "Array indices"], correct: 1 },

    // React (66-70)
    { q: "What hook manages state in React?", options: ["useEffect", "useState", "useContext", "useRef"], correct: 1 },
    { q: "What does useEffect do?", options: ["Manages state", "Handles side effects", "Creates refs", "Memoizes values"], correct: 1 },
    { q: "What is JSX?", options: ["JavaScript XML syntax", "Java extension", "JSON format", "jQuery syntax"], correct: 0 },
    { q: "How are props passed to components?", options: ["As global variables", "As function arguments", "Through state", "Via context only"], correct: 1 },
    { q: "What is the Virtual DOM?", options: ["Browser DOM", "In-memory DOM representation", "CSS framework", "Server-side DOM"], correct: 1 },

    // Node.js, TypeScript & Tools (71-75)
    { q: "What is Node.js?", options: ["Browser", "JavaScript runtime", "Database", "Framework"], correct: 1 },
    { q: "What does npm stand for?", options: ["Node Package Manager", "New Programming Module", "Network Protocol Manager", "Node Program Method"], correct: 0 },
    { q: "What does TypeScript add to JavaScript?", options: ["Speed", "Static typing", "DOM manipulation", "Async support"], correct: 1 },
    { q: "What is Vite primarily used for?", options: ["Testing", "Fast build tooling", "State management", "API development"], correct: 1 },
    { q: "What testing function groups related tests?", options: ["test()", "it()", "describe()", "expect()"], correct: 2 },
  ];

  const startQuiz = () => {
    // Randomly select 10 questions from the bank
    const shuffled = [...questionBank].sort(() => Math.random() - 0.5);
    setQuizQuestions(shuffled.slice(0, 10));
    setQuizStarted(true);
    setCurrentQuestion(0);
    setSelectedAnswers(Array(10).fill(null));
    setShowResults(false);
  };

  const handleAnswer = (optionIndex: number) => {
    const newAnswers = [...selectedAnswers];
    newAnswers[currentQuestion] = optionIndex;
    setSelectedAnswers(newAnswers);
  };

  const nextQuestion = () => {
    if (currentQuestion < 9) {
      setCurrentQuestion(currentQuestion + 1);
    } else {
      setShowResults(true);
    }
  };

  const prevQuestion = () => {
    if (currentQuestion > 0) {
      setCurrentQuestion(currentQuestion - 1);
    }
  };

  const calculateScore = (): number => {
    let score = 0;
    for (let i = 0; i < selectedAnswers.length; i++) {
      if (selectedAnswers[i] !== null && selectedAnswers[i] === quizQuestions[i]?.correct) {
        score++;
      }
    }
    return score;
  };

  const resetQuiz = () => {
    setQuizStarted(false);
    setShowResults(false);
    setCurrentQuestion(0);
    setSelectedAnswers(Array(10).fill(null));
  };

  if (!quizStarted) {
    return (
      <Paper id="quiz" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha(accentColor, 0.2)}`, textAlign: "center" }}>
        <Box sx={{ width: 64, height: 64, borderRadius: 3, bgcolor: alpha(accentColor, 0.15), display: "flex", alignItems: "center", justifyContent: "center", mx: "auto", mb: 3 }}>
          <SchoolIcon sx={{ fontSize: 32, color: accentColor }} />
        </Box>
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 2 }}>JavaScript Knowledge Quiz</Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 500, mx: "auto" }}>
          Test your understanding with a 10-question quiz randomly selected from a bank of 75 questions 
          covering all topics from JavaScript basics to frameworks and testing.
        </Typography>
        <Box sx={{ display: "flex", gap: 2, justifyContent: "center", flexWrap: "wrap", mb: 4 }}>
          <Chip label="10 Questions" sx={{ bgcolor: alpha(accentColor, 0.1) }} />
          <Chip label="Multiple Choice" sx={{ bgcolor: alpha("#3b82f6", 0.1) }} />
          <Chip label="Randomized" sx={{ bgcolor: alpha("#22c55e", 0.1) }} />
          <Chip label="Instant Results" sx={{ bgcolor: alpha("#8b5cf6", 0.1) }} />
        </Box>
        <Button
          variant="contained"
          size="large"
          onClick={startQuiz}
          sx={{ bgcolor: accentColor, color: "#000", "&:hover": { bgcolor: accentDark }, px: 5, py: 1.5, fontWeight: 700 }}
        >
          Start Quiz
        </Button>
      </Paper>
    );
  }

  if (showResults) {
    const score = calculateScore();
    const percentage = (score / 10) * 100;
    return (
      <Paper id="quiz" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha(accentColor, 0.2)}` }}>
        <Box sx={{ textAlign: "center", mb: 4 }}>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 2 }}>Quiz Complete!</Typography>
          <Box sx={{ width: 120, height: 120, borderRadius: "50%", bgcolor: alpha(percentage >= 70 ? "#22c55e" : percentage >= 50 ? "#f59e0b" : "#ef4444", 0.15), display: "flex", alignItems: "center", justifyContent: "center", mx: "auto", mb: 2 }}>
            <Typography variant="h3" sx={{ fontWeight: 800, color: percentage >= 70 ? "#22c55e" : percentage >= 50 ? "#f59e0b" : "#ef4444" }}>
              {score}/10
            </Typography>
          </Box>
          <Typography variant="h6" sx={{ color: percentage >= 70 ? "#22c55e" : percentage >= 50 ? "#f59e0b" : "#ef4444", fontWeight: 600 }}>
            {percentage >= 80 ? "Excellent!" : percentage >= 70 ? "Great job!" : percentage >= 50 ? "Good effort!" : "Keep learning!"}
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            You answered {score} out of 10 questions correctly ({percentage}%)
          </Typography>
        </Box>

        <Divider sx={{ my: 3 }} />

        <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>Review Answers</Typography>
        {quizQuestions.map((question, index) => (
          <Paper key={index} sx={{ p: 2, mb: 2, borderRadius: 2, bgcolor: alpha(selectedAnswers[index] === question.correct ? "#22c55e" : "#ef4444", 0.05), border: `1px solid ${alpha(selectedAnswers[index] === question.correct ? "#22c55e" : "#ef4444", 0.2)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 600, mb: 1 }}>
              {index + 1}. {question.q}
            </Typography>
            <Typography variant="body2" sx={{ color: selectedAnswers[index] === question.correct ? "#22c55e" : "#ef4444" }}>
              Your answer: {question.options[selectedAnswers[index] ?? 0]}
              {selectedAnswers[index] !== question.correct && (
                <Typography component="span" sx={{ color: "#22c55e", ml: 2 }}>
                  ✓ Correct: {question.options[question.correct]}
                </Typography>
              )}
            </Typography>
          </Paper>
        ))}

        <Box sx={{ display: "flex", gap: 2, justifyContent: "center", mt: 4 }}>
          <Button variant="outlined" onClick={resetQuiz} sx={{ borderColor: accentColor, color: accentColor }}>
            Back to Quiz Start
          </Button>
          <Button variant="contained" onClick={startQuiz} sx={{ bgcolor: accentColor, color: "#000", "&:hover": { bgcolor: accentDark } }}>
            Try Again (New Questions)
          </Button>
        </Box>
      </Paper>
    );
  }

  const question = quizQuestions[currentQuestion];
  return (
    <Paper id="quiz" sx={{ p: 4, mb: 4, borderRadius: 4, border: `1px solid ${alpha(accentColor, 0.2)}` }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Typography variant="subtitle2" color="text.secondary">
          Question {currentQuestion + 1} of 10
        </Typography>
        <Chip label={`${Math.round(((currentQuestion + 1) / 10) * 100)}% Complete`} size="small" sx={{ bgcolor: alpha(accentColor, 0.1) }} />
      </Box>

      <LinearProgress
        variant="determinate"
        value={((currentQuestion + 1) / 10) * 100}
        sx={{ mb: 3, height: 8, borderRadius: 4, bgcolor: alpha(accentColor, 0.1), "& .MuiLinearProgress-bar": { bgcolor: accentColor } }}
      />

      <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
        {question?.q}
      </Typography>

      <Grid container spacing={2} sx={{ mb: 4 }}>
        {question?.options.map((option, index) => (
          <Grid item xs={12} sm={6} key={index}>
            <Paper
              onClick={() => handleAnswer(index)}
              sx={{
                p: 2,
                borderRadius: 2,
                cursor: "pointer",
                border: `2px solid ${selectedAnswers[currentQuestion] === index ? accentColor : alpha("#fff", 0.1)}`,
                bgcolor: selectedAnswers[currentQuestion] === index ? alpha(accentColor, 0.1) : "transparent",
                "&:hover": { bgcolor: alpha(accentColor, 0.05), borderColor: alpha(accentColor, 0.5) },
                transition: "all 0.15s ease",
              }}
            >
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                <Box
                  sx={{
                    width: 28,
                    height: 28,
                    borderRadius: "50%",
                    border: `2px solid ${selectedAnswers[currentQuestion] === index ? accentColor : alpha("#fff", 0.3)}`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    bgcolor: selectedAnswers[currentQuestion] === index ? accentColor : "transparent",
                    color: selectedAnswers[currentQuestion] === index ? "#000" : "inherit",
                    fontWeight: 700,
                    fontSize: "0.8rem",
                  }}
                >
                  {String.fromCharCode(65 + index)}
                </Box>
                <Typography variant="body2">{option}</Typography>
              </Box>
            </Paper>
          </Grid>
        ))}
      </Grid>

      <Box sx={{ display: "flex", justifyContent: "space-between" }}>
        <Button
          variant="outlined"
          onClick={prevQuestion}
          disabled={currentQuestion === 0}
          sx={{ borderColor: alpha(accentColor, 0.5), color: accentColor, "&:disabled": { opacity: 0.5 } }}
        >
          Previous
        </Button>
        <Button
          variant="contained"
          onClick={nextQuestion}
          disabled={selectedAnswers[currentQuestion] === null}
          sx={{ bgcolor: accentColor, color: "#000", "&:hover": { bgcolor: accentDark }, "&:disabled": { bgcolor: alpha(accentColor, 0.3) } }}
        >
          {currentQuestion === 9 ? "Finish Quiz" : "Next Question"}
        </Button>
      </Box>
    </Paper>
  );
}
