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
    { label: "Modules", value: "16", color: "#f7df1e" },
    { label: "Frameworks", value: "6+", color: "#61dafb" },
    { label: "Quiz Questions", value: "75", color: "#22c55e" },
    { label: "Difficulty", value: "Beginner", color: "#8b5cf6" },
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

          {/* Section 16: Quiz */}
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
