import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
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
  Alert,
  AlertTitle,
  Divider,
  alpha,
  useTheme,
  Fab,
  Drawer,
  IconButton,
  Tooltip,
  useMediaQuery,
  Radio,
  RadioGroup,
  FormControlLabel,
  LinearProgress,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import CodeIcon from "@mui/icons-material/Code";
import SchoolIcon from "@mui/icons-material/School";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import BrushIcon from "@mui/icons-material/Brush";
import WebIcon from "@mui/icons-material/Web";
import DesignServicesIcon from "@mui/icons-material/DesignServices";
import DevicesIcon from "@mui/icons-material/Devices";
import LayersIcon from "@mui/icons-material/Layers";
import PaletteIcon from "@mui/icons-material/Palette";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import ConstructionIcon from "@mui/icons-material/Construction";
import ViewQuiltIcon from "@mui/icons-material/ViewQuilt";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import TimerIcon from "@mui/icons-material/Timer";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import NavigateNextIcon from "@mui/icons-material/NavigateNext";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import { useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";

// Code block component for displaying code examples
const CodeBlock: React.FC<{ code: string; title?: string }> = ({ code, title }) => (
  <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#1e1e1e", 0.03), border: `1px solid ${alpha("#7952b3", 0.15)}` }}>
    {title && (
      <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#7952b3", mb: 1.5 }}>
        {title}
      </Typography>
    )}
    <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "Consolas, Monaco, 'Courier New', monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto", m: 0 }}>
      {code}
    </Box>
  </Paper>
);

// Quiz question interface
interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  topic: string;
}

// 75-question bank covering all HTML & CSS topics
const questionBank: QuizQuestion[] = [
  // HTML Basics (1-15)
  { id: 1, question: "What does HTML stand for?", options: ["Hyper Text Markup Language", "High Tech Modern Language", "Hyper Transfer Markup Language", "Home Tool Markup Language"], correctAnswer: 0, explanation: "HTML stands for HyperText Markup Language, the standard markup language for creating web pages.", topic: "HTML Basics" },
  { id: 2, question: "Which tag is used for the largest heading?", options: ["<heading>", "<h6>", "<h1>", "<head>"], correctAnswer: 2, explanation: "The <h1> tag defines the largest heading, with <h6> being the smallest.", topic: "HTML Basics" },
  { id: 3, question: "What is the correct HTML element for inserting a line break?", options: ["<break>", "<br>", "<lb>", "<newline>"], correctAnswer: 1, explanation: "The <br> tag inserts a single line break and is an empty/void element.", topic: "HTML Basics" },
  { id: 4, question: "Which attribute specifies an alternate text for an image?", options: ["title", "src", "alt", "longdesc"], correctAnswer: 2, explanation: "The alt attribute provides alternative text when an image cannot be displayed and is important for accessibility.", topic: "HTML Basics" },
  { id: 5, question: "What does the <head> section contain?", options: ["Visible page content", "Metadata and links to resources", "Navigation menus", "Footer information"], correctAnswer: 1, explanation: "The <head> section contains metadata, title, links to CSS, scripts, and other non-visible information.", topic: "HTML Basics" },
  { id: 6, question: "Which HTML element defines the title of a document?", options: ["<meta>", "<head>", "<title>", "<header>"], correctAnswer: 2, explanation: "The <title> element defines the document's title shown in the browser tab.", topic: "HTML Basics" },
  { id: 7, question: "What is the correct HTML for creating a hyperlink?", options: ["<a url='http://example.com'>", "<a href='http://example.com'>", "<link href='http://example.com'>", "<hyperlink>http://example.com</hyperlink>"], correctAnswer: 1, explanation: "The <a> tag with href attribute creates a hyperlink to another page.", topic: "HTML Basics" },
  { id: 8, question: "Which is a self-closing (void) element?", options: ["<div>", "<span>", "<img>", "<p>"], correctAnswer: 2, explanation: "The <img> tag is self-closing as it doesn't have any content between opening and closing tags.", topic: "HTML Basics" },
  { id: 9, question: "What is the purpose of the DOCTYPE declaration?", options: ["To define CSS styles", "To specify HTML version", "To create a comment", "To import JavaScript"], correctAnswer: 1, explanation: "DOCTYPE tells the browser which HTML version the page uses, ensuring proper rendering.", topic: "HTML Basics" },
  { id: 10, question: "Which tag is used to create a numbered list?", options: ["<ul>", "<ol>", "<li>", "<nl>"], correctAnswer: 1, explanation: "The <ol> (ordered list) tag creates a numbered list, while <ul> creates bullets.", topic: "HTML Basics" },
  { id: 11, question: "What attribute opens a link in a new tab?", options: ["target='_self'", "target='_blank'", "new='tab'", "open='new'"], correctAnswer: 1, explanation: "target='_blank' opens the linked page in a new browser tab or window.", topic: "HTML Basics" },
  { id: 12, question: "Which element represents a paragraph?", options: ["<para>", "<p>", "<paragraph>", "<text>"], correctAnswer: 1, explanation: "The <p> tag defines a paragraph of text in HTML.", topic: "HTML Basics" },
  { id: 13, question: "What tag creates a table row?", options: ["<td>", "<tr>", "<th>", "<table>"], correctAnswer: 1, explanation: "The <tr> (table row) tag creates a row within a table.", topic: "HTML Basics" },
  { id: 14, question: "Which input type creates a checkbox?", options: ["type='check'", "type='checkbox'", "type='box'", "type='tick'"], correctAnswer: 1, explanation: "The input type='checkbox' creates a checkbox that can be toggled on/off.", topic: "HTML Basics" },
  { id: 15, question: "What is semantic HTML?", options: ["HTML with JavaScript", "HTML that describes meaning", "Encrypted HTML", "Compressed HTML"], correctAnswer: 1, explanation: "Semantic HTML uses meaningful tags like <article>, <nav>, <header> that describe content purpose.", topic: "HTML Basics" },

  // CSS Basics (16-30)
  { id: 16, question: "What does CSS stand for?", options: ["Computer Style Sheets", "Creative Style System", "Cascading Style Sheets", "Colorful Style Sheets"], correctAnswer: 2, explanation: "CSS stands for Cascading Style Sheets, used to style HTML documents.", topic: "CSS Basics" },
  { id: 17, question: "Which property changes text color?", options: ["text-color", "font-color", "color", "foreground"], correctAnswer: 2, explanation: "The 'color' property sets the color of text content.", topic: "CSS Basics" },
  { id: 18, question: "How do you select an element with id 'header'?", options: [".header", "#header", "header", "*header"], correctAnswer: 1, explanation: "The # symbol selects elements by their ID attribute.", topic: "CSS Basics" },
  { id: 19, question: "How do you select elements with class 'nav'?", options: ["#nav", ".nav", "nav", "@nav"], correctAnswer: 1, explanation: "The . (dot) selects elements by their class attribute.", topic: "CSS Basics" },
  { id: 20, question: "Which property changes the background color?", options: ["bgcolor", "background-color", "color-background", "bg"], correctAnswer: 1, explanation: "The background-color property sets the background color of an element.", topic: "CSS Basics" },
  { id: 21, question: "What is the default position value?", options: ["relative", "absolute", "static", "fixed"], correctAnswer: 2, explanation: "By default, all elements have position: static and follow normal document flow.", topic: "CSS Basics" },
  { id: 22, question: "Which property adds space inside an element?", options: ["margin", "padding", "border", "spacing"], correctAnswer: 1, explanation: "Padding adds space between content and the element's border.", topic: "CSS Basics" },
  { id: 23, question: "Which property adds space outside an element?", options: ["padding", "margin", "border", "gap"], correctAnswer: 1, explanation: "Margin adds space outside the element's border, between elements.", topic: "CSS Basics" },
  { id: 24, question: "What does 'display: none' do?", options: ["Makes element invisible but takes space", "Removes element completely", "Hides only text", "Fades element out"], correctAnswer: 1, explanation: "display: none removes the element from the document flow entirely.", topic: "CSS Basics" },
  { id: 25, question: "Which CSS property makes text bold?", options: ["text-weight", "font-weight", "bold", "text-style"], correctAnswer: 1, explanation: "font-weight controls the boldness of text, with values like 'bold' or numeric 700.", topic: "CSS Basics" },
  { id: 26, question: "What unit is relative to the parent font size?", options: ["px", "em", "vh", "cm"], correctAnswer: 1, explanation: "em is relative to the font-size of the parent element.", topic: "CSS Basics" },
  { id: 27, question: "What unit is relative to the root font size?", options: ["em", "rem", "%", "vw"], correctAnswer: 1, explanation: "rem (root em) is relative to the root element's font-size (usually <html>).", topic: "CSS Basics" },
  { id: 28, question: "Which selector has highest specificity?", options: ["Class", "ID", "Element", "Universal"], correctAnswer: 1, explanation: "ID selectors (#id) have higher specificity than class (.class) or element selectors.", topic: "CSS Basics" },
  { id: 29, question: "How do you add a comment in CSS?", options: ["// comment", "/* comment */", "<!-- comment -->", "# comment"], correctAnswer: 1, explanation: "CSS comments use /* */ syntax, unlike HTML (<!-- -->) or JavaScript (//).", topic: "CSS Basics" },
  { id: 30, question: "What is the CSS box model order from inside out?", options: ["Margin, Border, Padding, Content", "Content, Padding, Border, Margin", "Border, Padding, Content, Margin", "Padding, Content, Border, Margin"], correctAnswer: 1, explanation: "The box model layers are: Content → Padding → Border → Margin.", topic: "CSS Basics" },

  // Layout & Flexbox (31-45)
  { id: 31, question: "What display value creates a flex container?", options: ["display: flexbox", "display: flex", "display: flexible", "display: flex-container"], correctAnswer: 1, explanation: "display: flex creates a flex container for flexible layouts.", topic: "Flexbox" },
  { id: 32, question: "Which property aligns flex items on the main axis?", options: ["align-items", "justify-content", "align-content", "flex-align"], correctAnswer: 1, explanation: "justify-content aligns items along the main axis (horizontal by default).", topic: "Flexbox" },
  { id: 33, question: "Which property aligns flex items on the cross axis?", options: ["justify-content", "align-items", "flex-direction", "align-self"], correctAnswer: 1, explanation: "align-items aligns items along the cross axis (vertical by default).", topic: "Flexbox" },
  { id: 34, question: "What is the default flex-direction?", options: ["column", "row", "row-reverse", "column-reverse"], correctAnswer: 1, explanation: "The default flex-direction is 'row', laying items out horizontally.", topic: "Flexbox" },
  { id: 35, question: "Which property allows flex items to wrap?", options: ["flex-wrap", "flex-flow", "flex-break", "flex-line"], correctAnswer: 0, explanation: "flex-wrap: wrap allows items to wrap onto multiple lines.", topic: "Flexbox" },
  { id: 36, question: "What does 'flex: 1' mean?", options: ["Width of 1px", "Grow to fill available space", "Fixed size", "Shrink by 1"], correctAnswer: 1, explanation: "flex: 1 is shorthand for flex-grow: 1, making the item grow to fill space.", topic: "Flexbox" },
  { id: 37, question: "Which creates space between flex items?", options: ["margin", "gap", "spacing", "Both A and B"], correctAnswer: 3, explanation: "Both margin on items and gap on the container can create space between flex items.", topic: "Flexbox" },
  { id: 38, question: "What does display: inline-block do?", options: ["Creates a block that floats", "Inline element with block properties", "Invisible block", "Animated block"], correctAnswer: 1, explanation: "inline-block elements flow inline but can have width, height, padding, and margin.", topic: "Layout" },
  { id: 39, question: "How do you center a block element horizontally?", options: ["text-align: center", "margin: 0 auto", "align: center", "center: true"], correctAnswer: 1, explanation: "margin: 0 auto centers a block element with defined width horizontally.", topic: "Layout" },
  { id: 40, question: "What property creates a CSS Grid container?", options: ["display: grid-container", "display: grid", "display: table", "grid: true"], correctAnswer: 1, explanation: "display: grid creates a grid container for two-dimensional layouts.", topic: "Grid" },
  { id: 41, question: "Which defines grid column sizes?", options: ["grid-rows", "grid-template-columns", "column-template", "grid-columns"], correctAnswer: 1, explanation: "grid-template-columns defines the number and size of columns.", topic: "Grid" },
  { id: 42, question: "What does 'fr' unit represent in Grid?", options: ["Frame", "Fraction of available space", "Fixed ratio", "Full row"], correctAnswer: 1, explanation: "The fr unit represents a fraction of the available space in the grid container.", topic: "Grid" },
  { id: 43, question: "Which property sets grid gap?", options: ["grid-gap or gap", "grid-space", "grid-margin", "cell-spacing"], correctAnswer: 0, explanation: "The gap property (formerly grid-gap) sets space between grid items.", topic: "Grid" },
  { id: 44, question: "What does 'repeat(3, 1fr)' create?", options: ["3 rows", "3 equal columns", "3px width", "3 auto columns"], correctAnswer: 1, explanation: "repeat(3, 1fr) creates 3 columns of equal width (each 1 fraction).", topic: "Grid" },
  { id: 45, question: "Which is for 2D layouts?", options: ["Flexbox", "CSS Grid", "Float", "Inline-block"], correctAnswer: 1, explanation: "CSS Grid is designed for 2D layouts (rows AND columns), while Flexbox is 1D.", topic: "Grid" },

  // Responsive Design (46-55)
  { id: 46, question: "What makes a design responsive?", options: ["Fixed widths", "Adapting to screen sizes", "Only desktop support", "JavaScript animations"], correctAnswer: 1, explanation: "Responsive design adapts layouts to different screen sizes and devices.", topic: "Responsive" },
  { id: 47, question: "Which meta tag enables responsive design?", options: ["<meta charset>", "<meta viewport>", "<meta responsive>", "<meta mobile>"], correctAnswer: 1, explanation: "The viewport meta tag controls how the page scales on mobile devices.", topic: "Responsive" },
  { id: 48, question: "What is a media query?", options: ["Database query", "CSS rules for specific conditions", "HTML form", "JavaScript function"], correctAnswer: 1, explanation: "Media queries apply CSS rules only when certain conditions (like screen width) are met.", topic: "Responsive" },
  { id: 49, question: "What is mobile-first design?", options: ["Only mobile support", "Design mobile first, enhance for larger", "Mobile app design", "Smallest images first"], correctAnswer: 1, explanation: "Mobile-first means designing for small screens first, then adding styles for larger screens.", topic: "Responsive" },
  { id: 50, question: "Which unit is relative to viewport width?", options: ["em", "px", "vw", "rem"], correctAnswer: 2, explanation: "vw (viewport width) is 1% of the viewport's width.", topic: "Responsive" },
  { id: 51, question: "What does min-width in media query mean?", options: ["Minimum element width", "Applies when screen is at least this wide", "Minimum font size", "Minimum padding"], correctAnswer: 1, explanation: "min-width applies styles when viewport is at least the specified width.", topic: "Responsive" },
  { id: 52, question: "What is a breakpoint?", options: ["Code error", "Screen width where layout changes", "Page break for printing", "Network timeout"], correctAnswer: 1, explanation: "Breakpoints are specific screen widths where the design changes to fit better.", topic: "Responsive" },
  { id: 53, question: "Which makes images responsive?", options: ["width: 100px", "max-width: 100%", "display: block", "position: absolute"], correctAnswer: 1, explanation: "max-width: 100% ensures images scale down but never exceed their container.", topic: "Responsive" },
  { id: 54, question: "What is clamp() used for?", options: ["Clamping elements to position", "Setting min, preferred, max values", "Gripping animations", "Database operations"], correctAnswer: 1, explanation: "clamp(min, preferred, max) sets a value that adapts between min and max bounds.", topic: "Responsive" },
  { id: 55, question: "What does 'auto-fit' do in Grid?", options: ["Auto-sizes fonts", "Fits columns to content", "Creates columns that fit container", "Auto formats code"], correctAnswer: 2, explanation: "auto-fit creates as many columns as will fit in the container width.", topic: "Responsive" },

  // CSS Advanced (56-65)
  { id: 56, question: "What are CSS custom properties?", options: ["Built-in properties", "Variables defined with --", "Browser-specific properties", "Deprecated properties"], correctAnswer: 1, explanation: "CSS custom properties (variables) are defined with -- prefix and used with var().", topic: "CSS Advanced" },
  { id: 57, question: "How do you use a CSS variable?", options: ["variable(--name)", "var(--name)", "$name", "@name"], correctAnswer: 1, explanation: "CSS variables are used with var(--variable-name) syntax.", topic: "CSS Advanced" },
  { id: 58, question: "What property creates rounded corners?", options: ["corner-radius", "border-radius", "round-corners", "border-curve"], correctAnswer: 1, explanation: "border-radius creates rounded corners on elements.", topic: "CSS Advanced" },
  { id: 59, question: "Which property adds shadow to elements?", options: ["shadow", "box-shadow", "element-shadow", "drop-shadow"], correctAnswer: 1, explanation: "box-shadow adds shadow effects to elements.", topic: "CSS Advanced" },
  { id: 60, question: "What does 'transition' property do?", options: ["Moves element", "Animates property changes", "Transforms shape", "Translates text"], correctAnswer: 1, explanation: "transition creates smooth animations when CSS properties change.", topic: "CSS Advanced" },
  { id: 61, question: "Which property rotates an element?", options: ["rotate", "transform: rotate()", "rotation", "spin"], correctAnswer: 1, explanation: "transform: rotate(45deg) rotates an element by the specified angle.", topic: "CSS Advanced" },
  { id: 62, question: "What is a keyframe animation?", options: ["Video frame", "CSS animation with multiple steps", "Image format", "Browser event"], correctAnswer: 1, explanation: "@keyframes defines animation steps that elements transition through.", topic: "CSS Advanced" },
  { id: 63, question: "What does 'opacity: 0' do?", options: ["Removes element", "Makes fully transparent", "Disables clicks", "Hides from screen readers"], correctAnswer: 1, explanation: "opacity: 0 makes an element fully transparent but it still takes space.", topic: "CSS Advanced" },
  { id: 64, question: "Which pseudo-class targets hover state?", options: [":active", ":focus", ":hover", ":visited"], correctAnswer: 2, explanation: ":hover applies styles when the user hovers over an element.", topic: "CSS Advanced" },
  { id: 65, question: "What is the ::before pseudo-element?", options: ["Previous sibling", "Content inserted before element content", "First child", "Header element"], correctAnswer: 1, explanation: "::before inserts generated content before an element's actual content.", topic: "CSS Advanced" },

  // Frameworks & Best Practices (66-75)
  { id: 66, question: "What is Bootstrap primarily?", options: ["JavaScript library", "CSS framework", "Backend framework", "Database system"], correctAnswer: 1, explanation: "Bootstrap is a popular CSS framework with pre-built components and grid system.", topic: "Frameworks" },
  { id: 67, question: "How many columns in Bootstrap's grid?", options: ["10", "12", "16", "24"], correctAnswer: 1, explanation: "Bootstrap uses a 12-column responsive grid system.", topic: "Frameworks" },
  { id: 68, question: "What is TailwindCSS approach?", options: ["Component-based", "Utility-first", "BEM methodology", "Object-oriented"], correctAnswer: 1, explanation: "Tailwind uses utility-first approach with small, single-purpose classes.", topic: "Frameworks" },
  { id: 69, question: "What does 'col-md-6' mean in Bootstrap?", options: ["6 columns on all screens", "6 columns on medium+ screens", "6px margin", "Column 6"], correctAnswer: 1, explanation: "col-md-6 means the element spans 6 columns on medium screens and up.", topic: "Frameworks" },
  { id: 70, question: "What is BEM in CSS?", options: ["Best Element Method", "Block Element Modifier", "Basic Element Model", "Browser Extension Module"], correctAnswer: 1, explanation: "BEM (Block Element Modifier) is a naming convention for CSS classes.", topic: "Best Practices" },
  { id: 71, question: "Why use external stylesheets?", options: ["Faster loading", "Caching and separation of concerns", "Required by HTML5", "Better colors"], correctAnswer: 1, explanation: "External stylesheets allow caching and separate concerns between HTML and CSS.", topic: "Best Practices" },
  { id: 72, question: "What is CSS specificity?", options: ["File size", "How specific selectors determine which rules apply", "Loading speed", "Color depth"], correctAnswer: 1, explanation: "Specificity determines which CSS rules apply when multiple rules target the same element.", topic: "Best Practices" },
  { id: 73, question: "Which deployment platform is free for static sites?", options: ["AWS Lambda", "GitHub Pages", "Heroku Dynos", "All of the above"], correctAnswer: 1, explanation: "GitHub Pages provides free hosting for static websites directly from repositories.", topic: "Deployment" },
  { id: 74, question: "What is the purpose of a CSS reset?", options: ["Delete all CSS", "Normalize browser defaults", "Speed up loading", "Add animations"], correctAnswer: 1, explanation: "CSS resets normalize default browser styles for consistent cross-browser appearance.", topic: "Best Practices" },
  { id: 75, question: "What makes a good portfolio project?", options: ["Only design", "Responsive, accessible, well-coded", "Maximum animations", "Copied from others"], correctAnswer: 1, explanation: "Good portfolios demonstrate responsive design, accessibility, and clean code.", topic: "Best Practices" },
];

const QUESTIONS_PER_QUIZ = 15;

const HtmlCssGuidePage: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();

  const pageContext = `HTML & CSS Fundamentals Guide - A comprehensive learning resource for understanding web development foundations. This guide covers HTML document structure, semantic markup, CSS styling, layout systems including Flexbox and Grid, responsive design, animations, and modern CSS features. Essential knowledge for frontend development, web security testing, and understanding how web applications are built. Part of the Software Engineering section.`;

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  // Quiz state
  const [quizState, setQuizState] = useState<"start" | "active" | "results">("start");
  const [quizQuestions, setQuizQuestions] = useState<QuizQuestion[]>([]);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<Record<number, number>>({});
  const [showExplanation, setShowExplanation] = useState(false);
  const [quizScore, setQuizScore] = useState(0);

  // Quiz functions
  const startQuiz = () => {
    const shuffled = [...questionBank].sort(() => Math.random() - 0.5);
    setQuizQuestions(shuffled.slice(0, QUESTIONS_PER_QUIZ));
    setCurrentQuestionIndex(0);
    setSelectedAnswers({});
    setShowExplanation(false);
    setQuizScore(0);
    setQuizState("active");
  };

  const handleAnswerSelect = (answerIndex: number) => {
    if (showExplanation) return;
    setSelectedAnswers({ ...selectedAnswers, [currentQuestionIndex]: answerIndex });
  };

  const handleCheckAnswer = () => {
    setShowExplanation(true);
    if (selectedAnswers[currentQuestionIndex] === quizQuestions[currentQuestionIndex].correctAnswer) {
      setQuizScore(prev => prev + 1);
    }
  };

  const handleNextQuestion = () => {
    if (currentQuestionIndex < quizQuestions.length - 1) {
      setCurrentQuestionIndex(prev => prev + 1);
      setShowExplanation(false);
    } else {
      setQuizState("results");
    }
  };

  const resetQuiz = () => {
    setQuizState("start");
    setQuizQuestions([]);
    setCurrentQuestionIndex(0);
    setSelectedAnswers({});
    setShowExplanation(false);
    setQuizScore(0);
  };

  // Module navigation items
  const moduleNavItems = [
    { id: "introduction", label: "Introduction", icon: "📖" },
    { id: "module-1", label: "1. Your First Web Page", icon: "🎯" },
    { id: "module-2", label: "2. HTML Basics", icon: "📄" },
    { id: "module-3", label: "3. Text & Links", icon: "🔗" },
    { id: "module-4", label: "4. Lists & Tables", icon: "📋" },
    { id: "module-5", label: "5. Images & Media", icon: "🖼️" },
    { id: "module-6", label: "6. Forms & Inputs", icon: "📝" },
    { id: "module-7", label: "7. CSS Basics", icon: "🎨" },
    { id: "module-8", label: "8. Box Model & Layout", icon: "📦" },
    { id: "module-9", label: "9. Flexbox", icon: "↔️" },
    { id: "module-10", label: "10. CSS Grid", icon: "⊞" },
    { id: "module-11", label: "11. Responsive Design", icon: "📱" },
    { id: "module-12", label: "12. Animations", icon: "✨" },
    { id: "module-13", label: "13. Bootstrap", icon: "🅱️" },
    { id: "module-14", label: "14. TailwindCSS", icon: "🌊" },
    { id: "module-15", label: "15. Real Projects", icon: "🚀" },
    { id: "quiz-section", label: "Quiz", icon: "❓" },
  ];

  // Scroll to section
  const scrollToSection = (sectionId: string) => {
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
      setNavDrawerOpen(false);
    }
  };

  // Track active section on scroll
  useEffect(() => {
    const handleScroll = () => {
      const sections = moduleNavItems.map(item => item.id);
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

  // Scroll helpers
  const scrollToTop = () => window.scrollTo({ top: 0, behavior: "smooth" });
  const scrollToBottom = () => window.scrollTo({ top: document.body.scrollHeight, behavior: "smooth" });

  const quickStats = [
    { label: "Modules", value: "15", color: "#e91e63" },
    { label: "Exercises", value: "TBD", color: "#3b82f6" },
    { label: "Quiz Questions", value: "75", color: "#22c55e" },
    { label: "Difficulty", value: "Beginner → Advanced", color: "#8b5cf6" },
  ];

  // Calculate progress based on active section
  const currentIndex = moduleNavItems.findIndex(item => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / moduleNavItems.length) * 100 : 0;

  // Desktop sidebar navigation component
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
        border: `1px solid ${alpha("#e91e63", 0.15)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        display: { xs: "none", lg: "block" },
        "&::-webkit-scrollbar": {
          width: 6,
        },
        "&::-webkit-scrollbar-thumb": {
          bgcolor: alpha("#e91e63", 0.3),
          borderRadius: 3,
        },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#e91e63", display: "flex", alignItems: "center", gap: 1 }}>
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">Progress</Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: "#e91e63" }}>{Math.round(progressPercent)}%</Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha("#e91e63", 0.1),
              "& .MuiLinearProgress-bar": {
                bgcolor: "#e91e63",
                borderRadius: 3,
              },
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
                bgcolor: activeSection === item.id ? alpha("#e91e63", 0.15) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid #e91e63` : "3px solid transparent",
                "&:hover": {
                  bgcolor: alpha("#e91e63", 0.08),
                },
                transition: "all 0.15s ease",
              }}
            >
              <ListItemIcon sx={{ minWidth: 24, fontSize: "0.9rem" }}>
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={
                  <Typography
                    variant="caption"
                    sx={{
                      fontWeight: activeSection === item.id ? 700 : 500,
                      color: activeSection === item.id ? "#e91e63" : "text.secondary",
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
    <LearnPageLayout pageTitle="HTML & CSS Fundamentals" pageContext={pageContext}>
      {/* Floating Navigation Button - Mobile Only */}
      <Tooltip title="Navigate Modules" placement="left">
        <Fab
          color="primary"
          onClick={() => setNavDrawerOpen(true)}
          sx={{
            position: "fixed",
            bottom: 90,
            right: 24,
            zIndex: 1000,
            bgcolor: "#e91e63",
            "&:hover": { bgcolor: "#c2185b" },
            boxShadow: `0 4px 20px ${alpha("#e91e63", 0.4)}`,
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
            bottom: 150,
            right: 28,
            zIndex: 1000,
            bgcolor: alpha("#e91e63", 0.15),
            color: "#e91e63",
            "&:hover": { bgcolor: alpha("#e91e63", 0.25) },
            display: { xs: "flex", lg: "none" },
          }}
        >
          <KeyboardArrowUpIcon />
        </Fab>
      </Tooltip>

      {/* Scroll to Bottom Button - Mobile Only */}
      <Tooltip title="Scroll to Bottom" placement="left">
        <Fab
          size="small"
          onClick={scrollToBottom}
          sx={{
            position: "fixed",
            bottom: 32,
            right: 28,
            zIndex: 1000,
            bgcolor: alpha("#e91e63", 0.15),
            color: "#e91e63",
            "&:hover": { bgcolor: alpha("#e91e63", 0.25) },
            display: { xs: "flex", lg: "none" },
          }}
        >
          <KeyboardArrowDownIcon />
        </Fab>
      </Tooltip>

      {/* Navigation Drawer */}
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
              <MenuBookIcon sx={{ color: "#e91e63" }} />
              Course Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} size="small">
              <CloseIcon />
            </IconButton>
          </Box>
          
          <Divider sx={{ mb: 2 }} />

          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha("#e91e63", 0.05) }}>
            <Typography variant="caption" color="text.secondary">
              15 Modules • Beginner → Advanced
            </Typography>
          </Box>

          <List dense sx={{ mx: -1 }}>
            {moduleNavItems.map((item) => (
              <ListItem
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                sx={{
                  borderRadius: 2,
                  mb: 0.5,
                  cursor: "pointer",
                  bgcolor: activeSection === item.id ? alpha("#e91e63", 0.15) : "transparent",
                  borderLeft: activeSection === item.id ? `3px solid #e91e63` : "3px solid transparent",
                  "&:hover": { bgcolor: alpha("#e91e63", 0.1) },
                  transition: "all 0.2s ease",
                }}
              >
                <ListItemIcon sx={{ minWidth: 32, fontSize: "1.1rem" }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Typography
                      variant="body2"
                      sx={{
                        fontWeight: activeSection === item.id ? 700 : 500,
                        color: activeSection === item.id ? "#e91e63" : "text.primary",
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
                      bgcolor: alpha("#e91e63", 0.2),
                      color: "#e91e63",
                    }}
                  />
                )}
              </ListItem>
            ))}
          </List>

          <Divider sx={{ my: 2 }} />

          <Box sx={{ display: "flex", gap: 1 }}>
            <Button
              size="small"
              variant="outlined"
              onClick={scrollToTop}
              startIcon={<KeyboardArrowUpIcon />}
              sx={{ flex: 1, borderColor: alpha("#e91e63", 0.3), color: "#e91e63" }}
            >
              Top
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => scrollToSection("quiz-section")}
              sx={{ flex: 1, borderColor: alpha("#e91e63", 0.3), color: "#e91e63" }}
            >
              Quiz
            </Button>
          </Box>
        </Box>
      </Drawer>

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
            background: `linear-gradient(135deg, ${alpha("#e91e63", 0.15)} 0%, ${alpha("#9c27b0", 0.15)} 50%, ${alpha("#673ab7", 0.15)} 100%)`,
            border: `1px solid ${alpha("#e91e63", 0.2)}`,
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
              background: `radial-gradient(circle, ${alpha("#e91e63", 0.1)} 0%, transparent 70%)`,
            }}
          />
          <Box
            sx={{
              position: "absolute",
              bottom: -30,
              left: "30%",
              width: 150,
              height: 150,
              borderRadius: "50%",
              background: `radial-gradient(circle, ${alpha("#673ab7", 0.1)} 0%, transparent 70%)`,
            }}
          />
          
          <Box sx={{ position: "relative", zIndex: 1 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
              <Box
                sx={{
                  width: 80,
                  height: 80,
                  borderRadius: 3,
                  background: `linear-gradient(135deg, #e91e63, #673ab7)`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  boxShadow: `0 8px 32px ${alpha("#e91e63", 0.3)}`,
                }}
              >
                <WebIcon sx={{ fontSize: 44, color: "white" }} />
              </Box>
              <Box>
                <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                  HTML & CSS Fundamentals
                </Typography>
                <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                  Build the foundation of the web
                </Typography>
              </Box>
            </Box>
            
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
              <Chip label="Beginner Friendly" color="success" />
              <Chip label="HTML5" sx={{ bgcolor: alpha("#e44d26", 0.15), color: "#e44d26", fontWeight: 600 }} />
              <Chip label="CSS3" sx={{ bgcolor: alpha("#264de4", 0.15), color: "#264de4", fontWeight: 600 }} />
              <Chip label="TailwindCSS" sx={{ bgcolor: alpha("#06b6d4", 0.15), color: "#06b6d4", fontWeight: 600 }} />
              <Chip label="Bootstrap" sx={{ bgcolor: alpha("#7952b3", 0.15), color: "#7952b3", fontWeight: 600 }} />
              <Chip label="Responsive" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
            </Box>

            <Grid container spacing={2}>
              {quickStats.map((stat) => (
                <Grid item xs={6} sm={3} key={stat.label}>
                  <Paper
                    sx={{
                      p: 2,
                      textAlign: "center",
                      borderRadius: 2,
                      bgcolor: alpha(theme.palette.background.paper, 0.6),
                      border: `1px solid ${alpha(stat.color, 0.2)}`,
                    }}
                  >
                    <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>
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

        {/* ==================== DETAILED INTRODUCTION ==================== */}
        <Paper
          id="introduction"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                background: `linear-gradient(135deg, #e91e63, #673ab7)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <SchoolIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            The Language of the Web
          </Typography>
          
          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            Every website you've ever visited, every web application you've used, every online store you've shopped at—they all 
            share a common foundation: <strong>HTML</strong> (HyperText Markup Language) and <strong>CSS</strong> (Cascading Style 
            Sheets). These two technologies are the absolute bedrock of the World Wide Web, and understanding them is essential 
            for anyone who wants to work in web development, web security, or simply understand how the modern internet works.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            Think of building a website like constructing a house. <strong>HTML is the skeleton and structure</strong>—the walls, 
            floors, doors, and windows. It defines <em>what</em> content exists on your page: headings, paragraphs, images, links, 
            forms, tables, and more. HTML tells the browser "here is a heading," "here is a paragraph of text," "here is an image." 
            Without HTML, there would be no content to display—just a blank screen.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            <strong>CSS is the paint, furniture, and interior design</strong>—it makes things look beautiful and controls the 
            presentation. CSS defines <em>how</em> content should appear: colors, fonts, sizes, spacing, layouts, animations, 
            and responsive behaviors. Without CSS, websites would be plain black text on white backgrounds with default blue 
            links—functional but utterly boring. CSS transforms that raw structure into the visually rich, engaging experiences 
            we expect from modern websites.
          </Typography>

          <Alert severity="info" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>The Holy Trinity of Web Development</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              While HTML provides structure and CSS provides style, <strong>JavaScript</strong> adds interactivity and behavior. 
              Together, these three technologies form the foundation of all frontend web development. In this course, we focus 
              on HTML and CSS—mastering these is essential before moving on to JavaScript.
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#e91e63" }}>
            A Brief History
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            HTML was invented by <strong>Tim Berners-Lee</strong> in 1991 at CERN, along with the first web browser and web server. 
            The original HTML was incredibly simple—just 18 elements! Over the decades, it evolved through HTML 2.0, 3.2, 4.01, 
            XHTML, and finally <strong>HTML5</strong> (2014), which added semantic elements, multimedia support, and APIs for 
            modern web applications. CSS emerged in 1996 to separate presentation from content, evolving through CSS2, CSS2.1, 
            and the modular <strong>CSS3</strong> specification that continues to grow with new features like Grid, Flexbox, 
            Custom Properties, and Container Queries.
          </Typography>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#9c27b0" }}>
            Why Learn HTML & CSS?
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { title: "Foundation of Web Dev", desc: "Every web technology—React, Vue, Angular, WordPress—outputs HTML and CSS. You must understand the fundamentals.", icon: <LayersIcon sx={{ color: "#e91e63" }} /> },
              { title: "Security Research", desc: "XSS attacks, CSS injection, clickjacking—understanding HTML/CSS is essential for finding and preventing web vulnerabilities.", icon: <CodeIcon sx={{ color: "#f44336" }} /> },
              { title: "Career Opportunities", desc: "Web development is one of the most in-demand skills. Even backend developers need HTML/CSS knowledge.", icon: <WebIcon sx={{ color: "#2196f3" }} /> },
              { title: "Creative Expression", desc: "Build portfolios, personal sites, landing pages. Bring your ideas to life on the web.", icon: <PaletteIcon sx={{ color: "#9c27b0" }} /> },
            ].map((item) => (
              <Grid item xs={12} sm={6} key={item.title}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#e91e63", 0.03), border: `1px solid ${alpha("#e91e63", 0.1)}` }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 1 }}>
                    {item.icon}
                    <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#673ab7" }}>
            How the Web Works
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            When you type a URL into your browser and press Enter, a fascinating process unfolds. Your browser sends an 
            <strong> HTTP request</strong> to a web server. The server responds with HTML—the structure of the page. The browser 
            then <strong>parses</strong> this HTML, building a <strong>Document Object Model (DOM)</strong>—a tree-like 
            representation of the page structure. As it parses, it discovers CSS files (linked via <code style={{ background: alpha("#e91e63", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;link&gt;</code> tags 
            or embedded in <code style={{ background: alpha("#e91e63", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;style&gt;</code> blocks) and JavaScript files.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            The browser constructs a <strong>CSSOM</strong> (CSS Object Model) from the stylesheets, then combines the DOM and 
            CSSOM into a <strong>Render Tree</strong>. This render tree is then used for <strong>layout</strong> (calculating 
            where everything goes on the screen) and <strong>paint</strong> (drawing the actual pixels). Understanding this 
            pipeline helps you write more performant websites and debug rendering issues.
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#673ab7", 0.05), border: `1px solid ${alpha("#673ab7", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#673ab7", mb: 2 }}>Browser Rendering Pipeline</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: alpha("#673ab7", 0.1), p: 2, borderRadius: 1, overflowX: "auto" }}>
{`┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Request    │───▶│    Parse     │───▶│  Build DOM   │
│   HTML       │    │    HTML      │    │    Tree      │
└──────────────┘    └──────────────┘    └──────┬───────┘
                                               │
┌──────────────┐    ┌──────────────┐    ┌──────▼───────┐
│   Request    │───▶│    Parse     │───▶│ Build CSSOM  │
│    CSS       │    │    CSS       │    │    Tree      │
└──────────────┘    └──────────────┘    └──────┬───────┘
                                               │
                    ┌──────────────┐    ┌──────▼───────┐
                    │    Paint     │◀───│ Render Tree  │
                    │   Pixels     │    │ DOM + CSSOM  │
                    └──────────────┘    └──────────────┘`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#e91e63" }}>
            What You'll Learn in This Course
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            This comprehensive course takes you from absolute beginner to confident web developer. We start with the 
            very basics—what is a web page, how to create your first HTML file—and progressively build toward advanced topics 
            like Flexbox, CSS Grid, responsive design, animations, and modern frameworks like <strong>TailwindCSS</strong> and 
            <strong> Bootstrap</strong>. By the end, you'll be able to build beautiful, responsive, professional websites from scratch.
          </Typography>

          <Grid container spacing={2}>
            {[
              "Create your very first web page from scratch",
              "Understand HTML tags, elements, and attributes",
              "Build forms, tables, and embed multimedia",
              "Master CSS selectors, properties, and the cascade",
              "The box model: margin, padding, border, content",
              "Modern layout with Flexbox and CSS Grid",
              "Responsive design for mobile, tablet, and desktop",
              "CSS animations, transitions, and transforms",
              "Build with Bootstrap components and utilities",
              "Style rapidly with TailwindCSS utility classes",
              "Real-world projects: portfolio, landing page, dashboard",
              "Best practices and performance optimization",
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} key={idx}>
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5 }}>
                  <CheckCircleIcon sx={{ color: "#22c55e", fontSize: 20, mt: 0.3 }} />
                  <Typography variant="body2" sx={{ lineHeight: 1.6 }}>{item}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== DEEP DIVE: SEMANTIC HTML ==================== */}
        <Paper
          id="semantic-html"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.08)} 0%, ${alpha("#06b6d4", 0.08)} 100%)`,
            border: `1px solid ${alpha("#8b5cf6", 0.3)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Deep Dive" sx={{ bgcolor: alpha("#8b5cf6", 0.2), color: "#8b5cf6", fontWeight: 700 }} />
            <Chip label="Best Practices" size="small" sx={{ bgcolor: alpha("#06b6d4", 0.2), color: "#06b6d4", fontWeight: 600 }} />
          </Box>

          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#8b5cf6" }}>
            📐 Semantic HTML: Writing Meaningful Code
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            <strong>Semantic HTML</strong> is the practice of using HTML elements that convey meaning about the content they 
            contain, rather than just describing how that content should look. When you use semantic HTML, you create documents 
            that are understandable by machines (search engines, screen readers, web crawlers) and humans alike. This is one of 
            the most fundamental skills separating amateur developers from professionals.
          </Typography>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Why Semantic HTML Matters
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Consider the difference between a {"<div>"} with a class of "header" and the actual {"<header>"} element. 
            To a browser's styling engine, they might look identical—you can apply the same CSS to both. But to screen readers, 
            search engines, and assistive technologies, the {"<header>"} element immediately communicates "this is the introduction 
            to the page or section." This communication without CSS is what semantic HTML provides.
          </Typography>

          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>The Semantic Test:</strong> If you removed all CSS from your page, would the document structure still make sense? 
              Would a screen reader be able to navigate logically? If yes, you've written semantic HTML.
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Structural Semantic Elements
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            HTML5 introduced a suite of structural elements that replace the generic {"<div>"} soup of earlier web development. 
            Each element has a specific purpose and helps browsers and assistive technologies understand your page layout:
          </Typography>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`<!-- ❌ Non-semantic (div soup) -->
<div class="header">
  <div class="nav">
    <div class="nav-item">Home</div>
    <div class="nav-item">About</div>
  </div>
</div>
<div class="main-content">
  <div class="article">
    <div class="article-header">My Blog Post</div>
    <div class="article-content">Content here...</div>
  </div>
  <div class="sidebar">Related posts...</div>
</div>
<div class="footer">Copyright 2024</div>

<!-- ✅ Semantic (meaningful elements) -->
<header>
  <nav>
    <ul>
      <li><a href="/">Home</a></li>
      <li><a href="/about">About</a></li>
    </ul>
  </nav>
</header>
<main>
  <article>
    <header>
      <h1>My Blog Post</h1>
      <time datetime="2024-01-15">January 15, 2024</time>
    </header>
    <p>Content here...</p>
  </article>
  <aside>Related posts...</aside>
</main>
<footer>
  <p>&copy; 2024 My Website</p>
</footer>`}
              
            />
          </Box>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Key Semantic Elements Explained
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { tag: "<header>", desc: "Introductory content for its nearest sectioning ancestor. Can be used multiple times per page (page header, article header, section header)." },
              { tag: "<nav>", desc: "Section containing navigation links. Should be used for major navigation blocks, not every group of links." },
              { tag: "<main>", desc: "The dominant content of the document. Only one <main> per page. Should not be nested inside other semantic elements." },
              { tag: "<article>", desc: "Self-contained, independently distributable content. Ask: 'Would this make sense in an RSS feed?' If yes, use <article>." },
              { tag: "<section>", desc: "Generic section of a document. Should almost always have a heading. Use when content groups logically." },
              { tag: "<aside>", desc: "Content tangentially related to surrounding content. Sidebars, pull quotes, advertising—things that could be removed without affecting main content." },
              { tag: "<footer>", desc: "Footer for its nearest sectioning ancestor. Contains metadata, copyright, contact info, related links." },
              { tag: "<figure>/<figcaption>", desc: "Self-contained content with optional caption. Perfect for images, diagrams, code snippets with explanations." },
            ].map((item, idx) => (
              <Grid item xs={12} md={6} key={idx}>
                <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.2)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, fontFamily: "monospace", color: "#8b5cf6", mb: 1 }}>
                    {item.tag}
                  </Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.6 }}>{item.desc}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Text-Level Semantics
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            Beyond structural elements, HTML provides many text-level semantic elements. These are often misused or 
            confused with presentational choices:
          </Typography>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`<!-- Text-level semantics -->
<p>
  The term <strong>semantic HTML</strong> refers to meaningful markup.
  <!-- strong = strong importance, usually bold visually -->
  
  <em>Emphasis</em> changes the meaning of a sentence.
  <!-- em = stress emphasis, usually italic. Compare:
       "I <em>love</em> pizza" vs "I love <em>pizza</em>" -->
  
  The <mark>highlighted text</mark> is relevant to the user's search.
  <!-- mark = highlighted for reference purposes -->
  
  The event starts at <time datetime="2024-03-15T14:30">2:30 PM on March 15th</time>.
  <!-- time = machine-readable date/time -->
  
  Water's chemical formula is H<sub>2</sub>O.
  E = mc<sup>2</sup>
  <!-- sub/sup = subscript/superscript -->
  
  The <abbr title="World Wide Web Consortium">W3C</abbr> sets web standards.
  <!-- abbr = abbreviation with expansion -->
  
  Press <kbd>Ctrl</kbd> + <kbd>C</kbd> to copy.
  <!-- kbd = keyboard input -->
  
  The function returns <code>undefined</code> if no value is found.
  <!-- code = inline code -->
  
  <del>$99.99</del> <ins>$79.99</ins> - Sale Price!
  <!-- del/ins = deleted/inserted content -->
</p>`}
              
            />
          </Box>

          <Alert severity="warning" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>Common Mistake:</strong> Don't use {"<b>"} and {"<i>"} for bold and italic styling—they have no semantic meaning. 
              Use CSS for visual styling (font-weight: bold) and semantic elements ({"<strong>"}, {"<em>"}) for meaning.
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            A Complete Semantic Page Structure
          </Typography>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Learn semantic HTML with practical examples">
  <title>Understanding Semantic HTML | Web Dev Guide</title>
</head>
<body>
  <header>
    <nav aria-label="Main navigation">
      <ul>
        <li><a href="/" aria-current="page">Home</a></li>
        <li><a href="/tutorials">Tutorials</a></li>
        <li><a href="/about">About</a></li>
        <li><a href="/contact">Contact</a></li>
      </ul>
    </nav>
  </header>

  <main>
    <article>
      <header>
        <h1>Understanding Semantic HTML</h1>
        <p>
          By <a href="/author/jane" rel="author">Jane Developer</a>
          <time datetime="2024-01-15" pubdate>Published January 15, 2024</time>
        </p>
      </header>

      <section>
        <h2>Introduction</h2>
        <p>Semantic HTML provides meaning to your content...</p>
      </section>

      <section>
        <h2>Key Elements</h2>
        <p>The most important semantic elements include...</p>
        
        <figure>
          <img src="semantic-diagram.png" alt="Diagram showing semantic HTML structure">
          <figcaption>Figure 1: Semantic HTML document structure</figcaption>
        </figure>
      </section>

      <section>
        <h2>Conclusion</h2>
        <p>By using semantic HTML, you improve accessibility...</p>
      </section>

      <footer>
        <p>Tags: <a href="/tag/html" rel="tag">HTML</a>, <a href="/tag/semantics" rel="tag">Semantics</a></p>
      </footer>
    </article>

    <aside>
      <section>
        <h2>Related Articles</h2>
        <ul>
          <li><a href="/css-basics">CSS Basics</a></li>
          <li><a href="/accessibility">Web Accessibility</a></li>
        </ul>
      </section>
      
      <section>
        <h2>About the Author</h2>
        <p>Jane has been teaching web development for 10 years...</p>
      </section>
    </aside>
  </main>

  <footer>
    <nav aria-label="Footer navigation">
      <ul>
        <li><a href="/privacy">Privacy Policy</a></li>
        <li><a href="/terms">Terms of Service</a></li>
      </ul>
    </nav>
    <p><small>&copy; 2024 Web Dev Guide. All rights reserved.</small></p>
  </footer>
</body>
</html>`}
              
            />
          </Box>
        </Paper>

        {/* ==================== DEEP DIVE: ACCESSIBILITY (A11Y) ==================== */}
        <Paper
          id="accessibility"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#22c55e", 0.08)} 0%, ${alpha("#14b8a6", 0.08)} 100%)`,
            border: `1px solid ${alpha("#22c55e", 0.3)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Deep Dive" sx={{ bgcolor: alpha("#22c55e", 0.2), color: "#22c55e", fontWeight: 700 }} />
            <Chip label="Essential" size="small" sx={{ bgcolor: alpha("#14b8a6", 0.2), color: "#14b8a6", fontWeight: 600 }} />
          </Box>

          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#22c55e" }}>
            ♿ Web Accessibility (A11y) Best Practices
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            Web accessibility means designing and developing websites that everyone can use, including people with disabilities. 
            This includes users who are blind or have low vision, deaf or hard of hearing, have motor impairments, cognitive 
            disabilities, or temporary impairments (like a broken arm). Approximately <strong>15-20% of the world's population</strong> has 
            some form of disability—ignoring accessibility means ignoring a massive portion of your potential audience.
          </Typography>

          <Alert severity="success" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>Business Case:</strong> Accessible websites also benefit everyone—they're easier to navigate, work better 
              on mobile devices, have better SEO, and are often legally required for government and enterprise clients.
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            The POUR Principles (WCAG Foundation)
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            The Web Content Accessibility Guidelines (WCAG) are organized around four principles, known by the acronym POUR:
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { 
                letter: "P", 
                title: "Perceivable", 
                desc: "Information must be presentable in ways users can perceive. This means providing text alternatives for images, captions for videos, and not relying solely on color to convey meaning.", 
                color: "#ef4444" 
              },
              { 
                letter: "O", 
                title: "Operable", 
                desc: "User interface components must be operable. All functionality must be available from a keyboard, users must have enough time to read content, and content shouldn't cause seizures.", 
                color: "#f59e0b" 
              },
              { 
                letter: "U", 
                title: "Understandable", 
                desc: "Information and UI operation must be understandable. Text must be readable, web pages must operate in predictable ways, and users need help avoiding and correcting mistakes.", 
                color: "#22c55e" 
              },
              { 
                letter: "R", 
                title: "Robust", 
                desc: "Content must be robust enough to be interpreted by a wide variety of user agents, including assistive technologies. This means using valid, semantic HTML.", 
                color: "#3b82f6" 
              },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} key={idx}>
                <Box sx={{ 
                  p: 3, 
                  borderRadius: 2, 
                  bgcolor: alpha(item.color, 0.1), 
                  border: `1px solid ${alpha(item.color, 0.3)}`,
                  height: "100%",
                  display: "flex",
                  gap: 2
                }}>
                  <Box sx={{ 
                    width: 48, 
                    height: 48, 
                    borderRadius: "50%", 
                    bgcolor: item.color, 
                    display: "flex", 
                    alignItems: "center", 
                    justifyContent: "center",
                    flexShrink: 0
                  }}>
                    <Typography sx={{ color: "white", fontWeight: 800, fontSize: "1.5rem" }}>{item.letter}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: item.color, mb: 1 }}>{item.title}</Typography>
                    <Typography variant="body2" sx={{ lineHeight: 1.6 }}>{item.desc}</Typography>
                  </Box>
                </Box>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Essential Accessibility Practices
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, mt: 3, color: "#22c55e" }}>
            1. Alternative Text for Images
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            Every meaningful image needs descriptive alt text. Screen readers read this text aloud, and it displays when 
            images fail to load. The art of writing good alt text is describing the content AND function of an image:
          </Typography>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`<!-- ❌ Bad alt text -->
<img src="dog.jpg" alt="dog">
<img src="dog.jpg" alt="image">
<img src="dog.jpg" alt="photo of dog">
<img src="chart.png" alt="chart">

<!-- ✅ Good alt text - describes content and meaning -->
<img src="dog.jpg" alt="Golden retriever puppy playing fetch in a sunny park">

<!-- ✅ For functional images, describe the function -->
<img src="search-icon.png" alt="Search">
<a href="/">
  <img src="logo.png" alt="Company Name - Return to homepage">
</a>

<!-- ✅ For complex images like charts, provide detailed descriptions -->
<figure>
  <img src="sales-chart.png" 
       alt="Bar chart showing quarterly sales: Q1 $100K, Q2 $150K, Q3 $125K, Q4 $200K">
  <figcaption>2024 Quarterly Sales Performance</figcaption>
</figure>

<!-- ✅ Decorative images should have empty alt -->
<img src="decorative-swirl.png" alt="">
<!-- Or use CSS background images for decorative content -->

<!-- ✅ For complex images, use aria-describedby for long descriptions -->
<img src="complex-diagram.png" 
     alt="System architecture diagram"
     aria-describedby="diagram-description">
<div id="diagram-description" class="sr-only">
  The diagram shows three main components: the frontend React application 
  connects to a Node.js API server, which in turn connects to a PostgreSQL 
  database. All components are deployed on AWS with load balancing.
</div>`}
              
            />
          </Box>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            2. Keyboard Navigation
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            Many users can't use a mouse—they navigate entirely with keyboards. All interactive elements must be 
            focusable and operable with keyboard alone:
          </Typography>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`<!-- ❌ Bad: Non-focusable interactive elements -->
<div onclick="handleClick()">Click me</div>
<span class="link" onclick="navigate()">Go to page</span>

<!-- ✅ Good: Use proper interactive elements -->
<button onclick="handleClick()">Click me</button>
<a href="/page">Go to page</a>

<!-- If you MUST use a div, add keyboard support -->
<div role="button" 
     tabindex="0" 
     onclick="handleClick()"
     onkeydown="if(event.key === 'Enter' || event.key === ' ') handleClick()">
  Click me
</div>

<!-- ✅ Visible focus indicators (NEVER remove these without replacement) -->
<style>
  /* ❌ Don't do this */
  *:focus { outline: none; }
  
  /* ✅ Do this instead - custom but visible focus */
  *:focus {
    outline: none;
    box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.5);
  }
  
  /* ✅ Even better - use :focus-visible for keyboard-only focus */
  *:focus { outline: none; }
  *:focus-visible {
    outline: 3px solid #3b82f6;
    outline-offset: 2px;
  }
</style>

<!-- ✅ Skip links for keyboard users -->
<body>
  <a href="#main-content" class="skip-link">Skip to main content</a>
  <header><!-- Long navigation here --></header>
  <main id="main-content">
    <!-- Main content -->
  </main>
</body>

<style>
.skip-link {
  position: absolute;
  left: -9999px;
  z-index: 999;
  padding: 1em;
  background: #000;
  color: #fff;
}
.skip-link:focus {
  left: 0;
}
</style>`}
              
            />
          </Box>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            3. Color Contrast
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            Text must have sufficient contrast against its background. WCAG requires a minimum contrast ratio of 
            4.5:1 for normal text and 3:1 for large text (18px+ bold or 24px+ regular):
          </Typography>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`/* ❌ Poor contrast - hard to read */
.bad-example {
  color: #999999;        /* Light gray */
  background: #ffffff;   /* White background */
  /* Contrast ratio: ~2.8:1 - FAILS */
}

/* ✅ Good contrast - easy to read */
.good-example {
  color: #374151;        /* Dark gray */
  background: #ffffff;   /* White background */
  /* Contrast ratio: ~10:1 - PASSES */
}

/* ✅ Tools to check contrast:
   - Chrome DevTools (Inspect > color picker shows contrast)
   - webaim.org/resources/contrastchecker
   - Firefox Accessibility Inspector
*/

/* ❌ Don't rely on color alone */
.error-bad {
  color: red;  /* Only color indicates error */
}

/* ✅ Use multiple indicators */
.error-good {
  color: #dc2626;
  font-weight: bold;
  /* Plus an icon or text prefix */
}

<span class="error-good">
  ⚠️ Error: Please enter a valid email address
</span>`}
              
            />
          </Box>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            4. Accessible Forms
          </Typography>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`<!-- ❌ Inaccessible form -->
<input type="text" placeholder="Enter your name">
<input type="email" placeholder="Email">
<select>
  <option>Select country</option>
</select>

<!-- ✅ Accessible form -->
<form>
  <div class="form-group">
    <label for="name">Full Name <span aria-hidden="true">*</span></label>
    <input type="text" 
           id="name" 
           name="name" 
           required 
           aria-required="true"
           autocomplete="name">
  </div>

  <div class="form-group">
    <label for="email">Email Address <span aria-hidden="true">*</span></label>
    <input type="email" 
           id="email" 
           name="email" 
           required
           aria-required="true"
           aria-describedby="email-hint"
           autocomplete="email">
    <span id="email-hint" class="hint">We'll never share your email</span>
  </div>

  <fieldset>
    <legend>Preferred Contact Method</legend>
    <div>
      <input type="radio" id="contact-email" name="contact" value="email">
      <label for="contact-email">Email</label>
    </div>
    <div>
      <input type="radio" id="contact-phone" name="contact" value="phone">
      <label for="contact-phone">Phone</label>
    </div>
  </fieldset>

  <div class="form-group">
    <label for="country">Country</label>
    <select id="country" name="country" autocomplete="country">
      <option value="">Select your country</option>
      <option value="us">United States</option>
      <option value="uk">United Kingdom</option>
    </select>
  </div>

  <!-- Error messages -->
  <div class="form-group" aria-live="polite">
    <label for="password">Password</label>
    <input type="password" 
           id="password"
           name="password"
           aria-invalid="true"
           aria-describedby="password-error">
    <span id="password-error" class="error" role="alert">
      Password must be at least 8 characters
    </span>
  </div>

  <button type="submit">Create Account</button>
</form>`}
              
            />
          </Box>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            5. ARIA (Accessible Rich Internet Applications)
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            ARIA attributes provide extra accessibility information when native HTML isn't sufficient. The first rule 
            of ARIA: <strong>don't use ARIA if you can use native HTML</strong>. ARIA is a last resort.
          </Typography>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`<!-- ARIA Roles - tell assistive tech what an element is -->
<div role="navigation">...</div>  <!-- Better: just use <nav> -->
<div role="button">...</div>      <!-- Better: just use <button> -->
<div role="dialog">...</div>      <!-- For modal dialogs -->
<div role="alert">...</div>       <!-- For important messages -->
<div role="tablist">...</div>     <!-- For tab interfaces -->

<!-- ARIA States - tell assistive tech the current state -->
<button aria-expanded="false">Menu</button>
<button aria-pressed="true">Bold</button>
<input aria-invalid="true">
<div aria-hidden="true">Decorative content</div>
<div aria-busy="true">Loading...</div>

<!-- ARIA Properties - additional info about elements -->
<input aria-label="Search">
<input aria-labelledby="search-label">
<input aria-describedby="search-hint">
<div aria-live="polite">Dynamic content area</div>

<!-- ✅ Practical Example: Custom Dropdown -->
<div class="dropdown">
  <button id="menu-button"
          aria-haspopup="true"
          aria-expanded="false"
          aria-controls="menu-list">
    Options ▼
  </button>
  <ul id="menu-list"
      role="menu"
      aria-labelledby="menu-button"
      hidden>
    <li role="menuitem"><a href="/edit">Edit</a></li>
    <li role="menuitem"><a href="/delete">Delete</a></li>
    <li role="menuitem"><a href="/share">Share</a></li>
  </ul>
</div>

<!-- ✅ Live Regions - announce dynamic changes -->
<div aria-live="polite">
  <!-- Content changes here are announced to screen readers -->
  <p>3 items in your cart</p>
</div>

<div aria-live="assertive" role="alert">
  <!-- Urgent messages interrupt whatever screen reader is doing -->
  <p>Error: Your session has expired</p>
</div>`}
              
            />
          </Box>

          <Alert severity="warning" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>Testing Tip:</strong> Test your site with a screen reader! Try NVDA (free, Windows), VoiceOver (built into Mac/iOS), 
              or TalkBack (Android). Navigate using only your keyboard. You'll quickly find accessibility issues.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== DEEP DIVE: CSS CUSTOM PROPERTIES ==================== */}
        <Paper
          id="css-variables"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.08)} 0%, ${alpha("#ef4444", 0.08)} 100%)`,
            border: `1px solid ${alpha("#f59e0b", 0.3)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Deep Dive" sx={{ bgcolor: alpha("#f59e0b", 0.2), color: "#f59e0b", fontWeight: 700 }} />
            <Chip label="Modern CSS" size="small" sx={{ bgcolor: alpha("#ef4444", 0.2), color: "#ef4444", fontWeight: 600 }} />
          </Box>

          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#f59e0b" }}>
            🎨 CSS Custom Properties (Variables)
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            CSS Custom Properties, commonly called CSS Variables, revolutionized how we write maintainable stylesheets. 
            Unlike preprocessor variables (Sass, Less), CSS variables are <strong>live and dynamic</strong>—they exist in the browser, 
            can be changed with JavaScript, respond to media queries, and cascade through the DOM. They're essential for 
            building design systems, theme switching, and component-based architectures.
          </Typography>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            Basic Syntax and Usage
          </Typography>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`/* Defining CSS Custom Properties */
:root {
  /* The :root selector = <html>, but with higher specificity */
  /* Convention: prefix with -- (required) */
  
  /* Colors */
  --color-primary: #3b82f6;
  --color-primary-dark: #1d4ed8;
  --color-secondary: #8b5cf6;
  --color-success: #22c55e;
  --color-warning: #f59e0b;
  --color-error: #ef4444;
  
  /* Typography */
  --font-family-base: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  --font-family-mono: 'Fira Code', monospace;
  --font-size-base: 16px;
  --font-size-sm: 0.875rem;
  --font-size-lg: 1.125rem;
  --font-size-xl: 1.25rem;
  --font-size-2xl: 1.5rem;
  --line-height-base: 1.6;
  
  /* Spacing (using 4px grid) */
  --spacing-1: 0.25rem;   /* 4px */
  --spacing-2: 0.5rem;    /* 8px */
  --spacing-3: 0.75rem;   /* 12px */
  --spacing-4: 1rem;      /* 16px */
  --spacing-6: 1.5rem;    /* 24px */
  --spacing-8: 2rem;      /* 32px */
  
  /* Border radius */
  --radius-sm: 0.25rem;
  --radius-md: 0.5rem;
  --radius-lg: 1rem;
  --radius-full: 9999px;
  
  /* Shadows */
  --shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.05);
  --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
  --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
  
  /* Transitions */
  --transition-fast: 150ms ease;
  --transition-base: 300ms ease;
  --transition-slow: 500ms ease;
}

/* Using CSS Custom Properties with var() */
.button {
  font-family: var(--font-family-base);
  font-size: var(--font-size-base);
  padding: var(--spacing-2) var(--spacing-4);
  border-radius: var(--radius-md);
  background-color: var(--color-primary);
  transition: background-color var(--transition-fast);
}

.button:hover {
  background-color: var(--color-primary-dark);
}

/* Fallback values */
.element {
  /* If --undefined-var doesn't exist, use #333 */
  color: var(--undefined-var, #333);
  
  /* Nested fallbacks */
  background: var(--theme-bg, var(--color-primary, blue));
}`}
              
            />
          </Box>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            Implementing Dark Mode with CSS Variables
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            CSS variables make dark mode implementation elegant. Define your theme colors as variables and swap them 
            based on a class or attribute:
          </Typography>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`/* Light theme (default) */
:root {
  --color-bg: #ffffff;
  --color-bg-secondary: #f9fafb;
  --color-text: #111827;
  --color-text-secondary: #6b7280;
  --color-border: #e5e7eb;
  --color-link: #3b82f6;
  --shadow-color: rgba(0, 0, 0, 0.1);
}

/* Dark theme - applied when .dark class is on html/body */
.dark {
  --color-bg: #111827;
  --color-bg-secondary: #1f2937;
  --color-text: #f9fafb;
  --color-text-secondary: #9ca3af;
  --color-border: #374151;
  --color-link: #60a5fa;
  --shadow-color: rgba(0, 0, 0, 0.4);
}

/* Or use data attribute */
[data-theme="dark"] {
  --color-bg: #111827;
  /* ... */
}

/* Or respect system preference */
@media (prefers-color-scheme: dark) {
  :root {
    --color-bg: #111827;
    --color-text: #f9fafb;
    /* ... */
  }
}

/* Components use variables - theme changes automatically */
body {
  background-color: var(--color-bg);
  color: var(--color-text);
  transition: background-color var(--transition-base), color var(--transition-base);
}

.card {
  background-color: var(--color-bg-secondary);
  border: 1px solid var(--color-border);
  box-shadow: 0 4px 6px var(--shadow-color);
}

a {
  color: var(--color-link);
}

/* Theme toggle with JavaScript */
<script>
const toggle = document.getElementById('theme-toggle');
const html = document.documentElement;

toggle.addEventListener('click', () => {
  html.classList.toggle('dark');
  // Save preference
  localStorage.setItem('theme', html.classList.contains('dark') ? 'dark' : 'light');
});

// Load saved preference
const savedTheme = localStorage.getItem('theme');
if (savedTheme === 'dark' || (!savedTheme && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
  html.classList.add('dark');
}
</script>`}
              
            />
          </Box>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            Scoped Variables in Components
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            Unlike preprocessor variables which are compiled away, CSS custom properties cascade. This means you can 
            redefine them at any level and create component-scoped design tokens:
          </Typography>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`/* Button component with scoped variables */
.btn {
  /* Component-level defaults */
  --btn-padding-x: var(--spacing-4);
  --btn-padding-y: var(--spacing-2);
  --btn-font-size: var(--font-size-base);
  --btn-radius: var(--radius-md);
  --btn-bg: var(--color-primary);
  --btn-color: white;
  --btn-border: transparent;
  
  /* Use scoped variables */
  display: inline-flex;
  align-items: center;
  gap: var(--spacing-2);
  padding: var(--btn-padding-y) var(--btn-padding-x);
  font-size: var(--btn-font-size);
  border-radius: var(--btn-radius);
  background-color: var(--btn-bg);
  color: var(--btn-color);
  border: 2px solid var(--btn-border);
}

/* Variants just override the scoped variables */
.btn--secondary {
  --btn-bg: transparent;
  --btn-color: var(--color-primary);
  --btn-border: var(--color-primary);
}

.btn--danger {
  --btn-bg: var(--color-error);
}

.btn--sm {
  --btn-padding-x: var(--spacing-3);
  --btn-padding-y: var(--spacing-1);
  --btn-font-size: var(--font-size-sm);
}

.btn--lg {
  --btn-padding-x: var(--spacing-6);
  --btn-padding-y: var(--spacing-3);
  --btn-font-size: var(--font-size-lg);
}

/* Hover state */
.btn:hover {
  --btn-bg: var(--color-primary-dark);
}

.btn--secondary:hover {
  --btn-bg: var(--color-primary);
  --btn-color: white;
}

/* Usage in HTML */
<button class="btn">Default Button</button>
<button class="btn btn--secondary">Secondary</button>
<button class="btn btn--danger btn--lg">Delete</button>`}
              
            />
          </Box>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            Manipulating CSS Variables with JavaScript
          </Typography>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`// Read a CSS variable
const root = document.documentElement;
const primaryColor = getComputedStyle(root).getPropertyValue('--color-primary');
console.log(primaryColor); // "#3b82f6"

// Set a CSS variable
root.style.setProperty('--color-primary', '#8b5cf6');

// Set on a specific element
const card = document.querySelector('.card');
card.style.setProperty('--card-bg', 'linear-gradient(135deg, #667eea, #764ba2)');

// Dynamic theming based on user input
const colorPicker = document.getElementById('color-picker');
colorPicker.addEventListener('input', (e) => {
  root.style.setProperty('--color-primary', e.target.value);
});

// Responsive variables with ResizeObserver
const observer = new ResizeObserver(entries => {
  for (let entry of entries) {
    const width = entry.contentRect.width;
    entry.target.style.setProperty('--container-width', width + 'px');
  }
});
observer.observe(document.querySelector('.container'));

// Animate with CSS variables
const box = document.querySelector('.animated-box');
box.style.setProperty('--rotation', '0deg');
box.style.setProperty('--scale', '1');

box.addEventListener('mouseenter', () => {
  box.style.setProperty('--rotation', '10deg');
  box.style.setProperty('--scale', '1.1');
});

/* In CSS */
.animated-box {
  transform: rotate(var(--rotation)) scale(var(--scale));
  transition: transform 0.3s ease;
}`}
              
            />
          </Box>

          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>Pro Tip:</strong> CSS variables are incredibly powerful for creating accessible, themeable design systems. 
              Combined with prefers-color-scheme, prefers-reduced-motion, and other media queries, you can create interfaces 
              that adapt to user preferences automatically.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== DEEP DIVE: BEM METHODOLOGY ==================== */}
        <Paper
          id="bem-methodology"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#ec4899", 0.08)} 0%, ${alpha("#8b5cf6", 0.08)} 100%)`,
            border: `1px solid ${alpha("#ec4899", 0.3)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Deep Dive" sx={{ bgcolor: alpha("#ec4899", 0.2), color: "#ec4899", fontWeight: 700 }} />
            <Chip label="Architecture" size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.2), color: "#8b5cf6", fontWeight: 600 }} />
          </Box>

          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#ec4899" }}>
            🏗️ BEM Methodology: Scalable CSS Architecture
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            <strong>BEM (Block Element Modifier)</strong> is a naming convention for CSS classes that makes your code more 
            readable, maintainable, and scalable. Developed by Yandex, BEM solves the classic CSS problems: specificity 
            wars, naming collisions, and unclear relationships between styles. While it might look verbose at first, 
            BEM saves countless hours of debugging in larger projects.
          </Typography>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            The BEM Convention
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.1), border: `1px solid ${alpha("#3b82f6", 0.3)}`, height: "100%" }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Block</Typography>
                <Typography variant="body2" sx={{ fontFamily: "monospace", mb: 1 }}>.block</Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.6 }}>
                  A standalone component that is meaningful on its own. Examples: header, menu, card, form.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#22c55e", 0.1), border: `1px solid ${alpha("#22c55e", 0.3)}`, height: "100%" }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Element</Typography>
                <Typography variant="body2" sx={{ fontFamily: "monospace", mb: 1 }}>.block__element</Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.6 }}>
                  A part of a block that has no standalone meaning. Examples: menu__item, card__title, form__input.
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.1), border: `1px solid ${alpha("#f59e0b", 0.3)}`, height: "100%" }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>Modifier</Typography>
                <Typography variant="body2" sx={{ fontFamily: "monospace", mb: 1 }}>.block--modifier</Typography>
                <Typography variant="body2" sx={{ lineHeight: 1.6 }}>
                  A flag that changes appearance or behavior. Examples: button--large, card--featured, input--disabled.
                </Typography>
              </Box>
            </Grid>
          </Grid>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`/* BEM Naming Examples */

/* BLOCK: A standalone component */
.card { }
.navbar { }
.search-form { }  /* Blocks can have multi-word names with single hyphen */

/* ELEMENT: Part of a block (double underscore) */
.card__header { }
.card__image { }
.card__title { }
.card__body { }
.card__footer { }
.navbar__logo { }
.navbar__menu { }
.search-form__input { }
.search-form__button { }

/* MODIFIER: Variation of block or element (double hyphen) */
.card--featured { }           /* Block modifier */
.card--horizontal { }
.card__title--large { }       /* Element modifier */
.navbar--sticky { }
.navbar__menu--expanded { }
.search-form--compact { }
.search-form__button--loading { }

/* ❌ Avoid: element of element (too deeply nested) */
.card__header__title { }      /* Wrong! */

/* ✅ Keep it flat */
.card__title { }              /* Title can be anywhere in card */`}
              
            />
          </Box>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            Complete BEM Example: Card Component
          </Typography>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`<!-- HTML with BEM classes -->
<article class="card card--featured">
  <div class="card__image-container">
    <img class="card__image" src="photo.jpg" alt="Article photo">
    <span class="card__badge">Featured</span>
  </div>
  <div class="card__content">
    <header class="card__header">
      <span class="card__category">Technology</span>
      <h2 class="card__title card__title--large">Understanding BEM Methodology</h2>
    </header>
    <p class="card__excerpt">
      BEM is a naming convention that makes CSS more maintainable...
    </p>
    <footer class="card__footer">
      <div class="card__author">
        <img class="card__author-avatar" src="avatar.jpg" alt="">
        <span class="card__author-name">Jane Developer</span>
      </div>
      <a href="/article" class="card__link">Read More →</a>
    </footer>
  </div>
</article>`}
              
            />
          </Box>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`/* CSS with BEM */
.card {
  display: flex;
  flex-direction: column;
  background: white;
  border-radius: 8px;
  overflow: hidden;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.card:hover {
  transform: translateY(-4px);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.15);
}

/* Block modifier */
.card--featured {
  border: 2px solid #3b82f6;
}

.card--horizontal {
  flex-direction: row;
}

/* Elements */
.card__image-container {
  position: relative;
  overflow: hidden;
}

.card__image {
  width: 100%;
  height: 200px;
  object-fit: cover;
}

.card--horizontal .card__image {
  height: 100%;
  width: 200px;
}

.card__badge {
  position: absolute;
  top: 12px;
  right: 12px;
  padding: 4px 12px;
  background: #3b82f6;
  color: white;
  border-radius: 16px;
  font-size: 12px;
  font-weight: 600;
}

.card__content {
  padding: 20px;
  display: flex;
  flex-direction: column;
  flex: 1;
}

.card__header {
  margin-bottom: 12px;
}

.card__category {
  display: inline-block;
  color: #6b7280;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  margin-bottom: 8px;
}

.card__title {
  font-size: 18px;
  font-weight: 700;
  color: #111827;
  line-height: 1.3;
}

/* Element modifier */
.card__title--large {
  font-size: 22px;
}

.card__excerpt {
  color: #6b7280;
  line-height: 1.6;
  flex: 1;
}

.card__footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 16px;
  padding-top: 16px;
  border-top: 1px solid #e5e7eb;
}

.card__author {
  display: flex;
  align-items: center;
  gap: 8px;
}

.card__author-avatar {
  width: 32px;
  height: 32px;
  border-radius: 50%;
}

.card__author-name {
  font-size: 14px;
  color: #374151;
}

.card__link {
  color: #3b82f6;
  font-weight: 500;
  text-decoration: none;
}

.card__link:hover {
  text-decoration: underline;
}`}
              
            />
          </Box>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            BEM Best Practices
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { title: "Flat structure", desc: "Never nest selectors based on BEM hierarchy. .card__title should work anywhere inside .card, not just under .card__header." },
              { title: "No tag selectors", desc: "Use .card__title, not .card h2. This prevents specificity issues and allows flexibility in HTML structure." },
              { title: "Modifiers add to base", desc: "Always use .card.card--featured (both classes). Modifiers extend, not replace, the base block styles." },
              { title: "No ID selectors", desc: "IDs are for JavaScript hooks and anchor links. Keep all styling in classes to maintain low specificity." },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} key={idx}>
                <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ec4899", 0.05), border: `1px solid ${alpha("#ec4899", 0.2)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ec4899", mb: 1 }}>{item.title}</Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.6 }}>{item.desc}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Paper>

        {/* ==================== DEEP DIVE: BROWSER DEVTOOLS ==================== */}
        <Paper
          id="devtools"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.08)} 0%, ${alpha("#3b82f6", 0.08)} 100%)`,
            border: `1px solid ${alpha("#06b6d4", 0.3)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Deep Dive" sx={{ bgcolor: alpha("#06b6d4", 0.2), color: "#06b6d4", fontWeight: 700 }} />
            <Chip label="Essential Tools" size="small" sx={{ bgcolor: alpha("#3b82f6", 0.2), color: "#3b82f6", fontWeight: 600 }} />
          </Box>

          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#06b6d4" }}>
            🔧 Mastering Browser Developer Tools
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            Browser DevTools are indispensable for web development. Whether you're debugging layout issues, optimizing 
            performance, or experimenting with styles, mastering these tools will make you 10x more productive. 
            Every modern browser has DevTools—we'll focus on Chrome DevTools, but Firefox, Safari, and Edge have 
            similar features.
          </Typography>

          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>Open DevTools:</strong> Press <kbd>F12</kbd>, <kbd>Ctrl+Shift+I</kbd> (Windows/Linux), or <kbd>Cmd+Option+I</kbd> (Mac). 
              Or right-click any element and select "Inspect".
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            The Elements Panel
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            The Elements panel shows the live DOM tree and lets you inspect and modify HTML and CSS in real-time. 
            Changes you make are temporary (refresh to reset) but invaluable for experimentation.
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { 
                title: "Inspect Element", 
                shortcut: "Ctrl+Shift+C", 
                desc: "Click the inspect icon (cursor in box) then hover over elements to see their box model highlighted. Click to select and view styles." 
              },
              { 
                title: "Edit HTML", 
                shortcut: "Double-click or F2", 
                desc: "Double-click any element in the DOM tree to edit its content or attributes. Right-click for more options: delete, duplicate, copy." 
              },
              { 
                title: "Search DOM", 
                shortcut: "Ctrl+F in Elements", 
                desc: "Search by text content, tag name, CSS selector, or XPath. Great for finding specific elements in large pages." 
              },
              { 
                title: "Force State", 
                shortcut: ":hov button", 
                desc: "Force :hover, :active, :focus, :visited states on elements to debug pseudo-class styles without actually triggering them." 
              },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} key={idx}>
                <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.2)}`, height: "100%" }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#06b6d4" }}>{item.title}</Typography>
                    <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: alpha("#06b6d4", 0.1), px: 1, borderRadius: 1 }}>{item.shortcut}</Typography>
                  </Box>
                  <Typography variant="body2" sx={{ lineHeight: 1.6 }}>{item.desc}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            The Styles Pane
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            Located to the right of the DOM tree, the Styles pane shows all CSS applied to the selected element, 
            including inherited styles, user agent styles, and the cascade order:
          </Typography>

          <Box sx={{ mb: 3, p: 3, bgcolor: alpha("#06b6d4", 0.05), borderRadius: 2, border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
            <Typography variant="body2" component="div" sx={{ lineHeight: 2 }}>
              <strong>Key Features:</strong>
              <ul style={{ margin: "8px 0", paddingLeft: 24 }}>
                <li><strong>Add properties:</strong> Click inside any rule to add new CSS properties with autocomplete</li>
                <li><strong>Toggle properties:</strong> Click the checkbox next to any property to disable it temporarily</li>
                <li><strong>Edit values:</strong> Click on any value to edit. Use ↑/↓ to increment numbers, Shift+↑/↓ for ×10</li>
                <li><strong>Color picker:</strong> Click the color square next to any color value for a visual picker</li>
                <li><strong>View computed:</strong> "Computed" tab shows final values after cascade resolution</li>
                <li><strong>Source links:</strong> Click filename:line to jump directly to that CSS file</li>
              </ul>
            </Typography>
          </Box>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            The Box Model Diagram
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            At the bottom of the Styles pane is an interactive box model diagram showing the selected element's 
            dimensions, padding, border, and margin. You can click on any value to edit it directly:
          </Typography>

          <Box sx={{ fontFamily: "monospace", fontSize: "0.85rem", p: 3, bgcolor: "#111827", borderRadius: 2, color: "#f9fafb", mb: 3, whiteSpace: "pre" }}>
{`┌─────────────────────── margin (orange) ───────────────────────┐
│                              20                               │
│   ┌─────────────────── border (yellow) ─────────────────┐    │
│   │                        2px                           │    │
│ 20│   ┌─────────────── padding (green) ────────────┐   │ 20│
│   │ 2px│                  16                        │2px│    │
│   │   │   ┌─────────── content (blue) ──────────┐  │   │    │
│   │ 16│   │                                     │16│   │    │
│   │   │   │        320 × 200                    │  │   │    │
│   │   │   │                                     │  │   │    │
│   │   │   └─────────────────────────────────────┘  │   │    │
│   │   │                  16                        │   │    │
│   │   └────────────────────────────────────────────┘   │    │
│   │                        2px                           │    │
│   └─────────────────────────────────────────────────────┘    │
│                              20                               │
└───────────────────────────────────────────────────────────────┘`}
          </Box>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            Device Mode (Responsive Testing)
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            Click the device toggle icon (📱💻) or press <kbd>Ctrl+Shift+M</kbd> to enter device mode. This lets you 
            test responsive designs without actual devices:
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { title: "Device presets", desc: "Choose from popular devices (iPhone, iPad, Pixel) with accurate dimensions and pixel ratios." },
              { title: "Responsive mode", desc: "Drag the viewport edges to test at any arbitrary size. Width×height shown in corner." },
              { title: "Throttle network", desc: "Simulate slow connections (3G, offline) to test loading states and performance." },
              { title: "Orientation", desc: "Toggle between portrait and landscape to test orientation-responsive designs." },
            ].map((item, idx) => (
              <Grid item xs={12} sm={6} key={idx}>
                <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.2)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#06b6d4", mb: 0.5 }}>{item.title}</Typography>
                  <Typography variant="body2" sx={{ lineHeight: 1.6 }}>{item.desc}</Typography>
                </Box>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            Debugging Flexbox and Grid
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            Chrome and Firefox have amazing tools for visualizing Flexbox and Grid layouts:
          </Typography>

          <Box sx={{ mb: 3, p: 3, bgcolor: alpha("#06b6d4", 0.05), borderRadius: 2, border: `1px solid ${alpha("#06b6d4", 0.2)}` }}>
            <Typography variant="body2" component="div" sx={{ lineHeight: 2 }}>
              <strong>Flexbox Tools:</strong>
              <ul style={{ margin: "8px 0", paddingLeft: 24 }}>
                <li>Look for the "flex" badge next to flex containers in the Elements panel</li>
                <li>Click the badge to toggle a visual overlay showing axes and spacing</li>
                <li>In the Styles pane, flex properties show icon buttons for value options</li>
              </ul>
              <strong>Grid Tools:</strong>
              <ul style={{ margin: "8px 0", paddingLeft: 24 }}>
                <li>Look for the "grid" badge next to grid containers</li>
                <li>Click to overlay grid lines, track sizes, and area names</li>
                <li>Multiple grids can be visualized simultaneously in different colors</li>
                <li>The Layout panel (sidebar tab) lists all grids on the page</li>
              </ul>
            </Typography>
          </Box>
        </Paper>

        {/* ==================== DEEP DIVE: COMMON MISTAKES ==================== */}
        <Paper
          id="common-mistakes"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#ef4444", 0.08)} 0%, ${alpha("#f59e0b", 0.08)} 100%)`,
            border: `1px solid ${alpha("#ef4444", 0.3)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Deep Dive" sx={{ bgcolor: alpha("#ef4444", 0.2), color: "#ef4444", fontWeight: 700 }} />
            <Chip label="Avoid These!" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.2), color: "#f59e0b", fontWeight: 600 }} />
          </Box>

          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#ef4444" }}>
            ⚠️ Common HTML & CSS Mistakes (and How to Fix Them)
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            Even experienced developers make these mistakes. Learning to recognize and avoid them will save you hours 
            of debugging and result in cleaner, more maintainable code. Let's examine the most common pitfalls:
          </Typography>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
            HTML Mistakes
          </Typography>

          <Box sx={{ mb: 3 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
              1. Missing or Wrong DOCTYPE
            </Typography>
            <CodeBlock
              code={`<!-- ❌ Missing DOCTYPE - browser enters quirks mode -->
<html>
<head>...</head>
</html>

<!-- ❌ Old XHTML DOCTYPE - verbose and unnecessary -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" 
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">

<!-- ✅ HTML5 DOCTYPE - simple and correct -->
<!DOCTYPE html>
<html lang="en">
<head>...</head>
</html>`}
              
            />
          </Box>

          <Box sx={{ mb: 3 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
              2. Improper Heading Hierarchy
            </Typography>
            <CodeBlock
              code={`<!-- ❌ Bad: Skipped heading levels, multiple h1s, style-based selection -->
<h1>My Website</h1>
<h1>Welcome!</h1>           <!-- Two h1s on one page -->
<h4>About Us</h4>           <!-- Skipped h2, h3 -->
<h2>Big text I want</h2>    <!-- Used h2 for styling, not structure -->

<!-- ✅ Good: Logical hierarchy, one h1, no skips -->
<h1>My Website</h1>         <!-- One h1 per page -->
<main>
  <h2>Welcome</h2>
  <section>
    <h3>About Us</h3>
    <h4>Our History</h4>
    <h4>Our Team</h4>
  </section>
  <section>
    <h3>Services</h3>      <!-- h3 can restart in new section -->
  </section>
</main>

/* For visual sizing, use CSS, not heading levels */
.large-text { font-size: 2rem; font-weight: bold; }`}
              
            />
          </Box>

          <Box sx={{ mb: 3 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
              3. Inline Styles and Deprecated Attributes
            </Typography>
            <CodeBlock
              code={`<!-- ❌ Bad: Inline styles, deprecated attributes -->
<p style="color: red; font-size: 14px;">Text</p>
<table border="1" cellpadding="10">
<font color="blue">Old school</font>
<center>Centered text</center>
<body bgcolor="#fff">

<!-- ✅ Good: Separate CSS -->
<p class="error-text">Text</p>
<table class="data-table">

/* In CSS file */
.error-text {
  color: #dc2626;
  font-size: 0.875rem;
}
.data-table {
  border-collapse: collapse;
}
.data-table td {
  border: 1px solid #e5e7eb;
  padding: 10px;
}`}
              
            />
          </Box>

          <Box sx={{ mb: 3 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
              4. Missing Form Labels
            </Typography>
            <CodeBlock
              code={`<!-- ❌ Bad: No labels, placeholder as label -->
<input type="text" placeholder="Enter your name">
<input type="email" placeholder="Email">

<!-- ✅ Good: Proper labels (required for accessibility) -->
<div class="form-field">
  <label for="name">Full Name</label>
  <input type="text" id="name" name="name" placeholder="John Doe">
</div>

<!-- If you MUST hide the label visually, use screen-reader-only class -->
<label for="search" class="sr-only">Search</label>
<input type="search" id="search" placeholder="Search...">

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}`}
              
            />
          </Box>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, mt: 4, color: "#ef4444" }}>
            CSS Mistakes
          </Typography>

          <Box sx={{ mb: 3 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
              1. Over-Specific Selectors
            </Typography>
            <CodeBlock
              code={`/* ❌ Bad: Over-specific, hard to override, brittle */
body div.container main article.post div.content p.intro span {
  color: blue;
}
#header #nav ul li a.active {  /* IDs make this almost impossible to override */
  color: red;
}

/* ✅ Good: Low specificity, easy to maintain */
.post-intro {
  color: blue;
}
.nav-link--active {
  color: red;
}

/* Rule of thumb: aim for specificity of 0-1-0 (one class)
   ID selectors (1-0-0) should be avoided in CSS */`}
              
            />
          </Box>

          <Box sx={{ mb: 3 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
              2. Using !important
            </Typography>
            <CodeBlock
              code={`/* ❌ Bad: !important wars */
.button {
  background: blue !important;
}
.button-red {
  background: red !important; /* Need to override the above */
}
.button-red-dark {
  background: darkred !important !important; /* Doesn't work this way! */
}

/* ✅ Good: Proper specificity management */
.button {
  background: blue;
}
.button.button--danger {  /* Slightly higher specificity */
  background: red;
}

/* Only acceptable uses of !important:
   1. Utility classes that MUST override (like .hidden { display: none !important; })
   2. Overriding third-party CSS you can't modify
   3. Accessibility overrides (forced high contrast)
*/`}
              
            />
          </Box>

          <Box sx={{ mb: 3 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
              3. Forgetting box-sizing
            </Typography>
            <CodeBlock
              code={`/* ❌ Default box-sizing: content-box causes layout issues */
.sidebar {
  width: 300px;
  padding: 20px;        /* Total width is now 340px! (300 + 20 + 20) */
  border: 1px solid;    /* Actually 342px */
}

/* ✅ Fix: Set border-box globally */
*, *::before, *::after {
  box-sizing: border-box;  /* Padding & border included in width */
}

.sidebar {
  width: 300px;
  padding: 20px;        /* Width stays 300px, padding is inside */
  border: 1px solid;    /* Still 300px total */
}`}
              
            />
          </Box>

          <Box sx={{ mb: 3 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
              4. Collapsing Margins Confusion
            </Typography>
            <CodeBlock
              code={`/* ❌ Common surprise: margins collapse */
<style>
.parent { background: lightblue; }
.child { margin-top: 50px; }
</style>
<div class="parent">
  <div class="child">Why does parent have no top padding?!</div>
</div>
/* The child's margin collapses through the parent! */

/* ✅ Fix options: */

/* 1. Add padding or border to parent */
.parent {
  padding-top: 1px;  /* or border-top: 1px solid transparent */
}

/* 2. Create a Block Formatting Context */
.parent {
  overflow: hidden;  /* or auto */
}

/* 3. Use Flexbox or Grid (doesn't collapse) */
.parent {
  display: flex;
  flex-direction: column;
}

/* 4. Modern: Use gap instead of margins */
.parent {
  display: flex;
  flex-direction: column;
  gap: 50px;
}`}
              
            />
          </Box>

          <Box sx={{ mb: 3 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
              5. Fixed Heights on Content
            </Typography>
            <CodeBlock
              code={`/* ❌ Bad: Fixed height clips content */
.card {
  height: 200px;  /* What if content is longer? */
}

.hero {
  height: 500px;  /* Breaks on mobile or with more content */
}

/* ✅ Good: Use min-height and flexible sizing */
.card {
  min-height: 200px;  /* At least 200px, but can grow */
}

.hero {
  min-height: 500px;  /* Minimum height */
  /* Or responsive: */
  min-height: 70vh;   /* 70% of viewport */
}

/* If you need fixed height with overflow: */
.scrollable-list {
  height: 300px;      /* Fixed */
  overflow-y: auto;   /* Scrollable */
}`}
              
            />
          </Box>

          <Box sx={{ mb: 3 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: "#ef4444" }}>
              6. Not Using Relative Units
            </Typography>
            <CodeBlock
              code={`/* ❌ Bad: Fixed pixel values don't scale */
body {
  font-size: 16px;
}
h1 {
  font-size: 32px;
  margin-bottom: 20px;
}
.container {
  width: 1200px;
  padding: 30px;
}

/* ✅ Good: Relative units adapt */
:root {
  font-size: 16px;  /* Base size (can use 62.5% trick for 10px base) */
}
body {
  font-size: 1rem;  /* 16px, scales with user preference */
}
h1 {
  font-size: 2rem;       /* 32px relative to root */
  margin-bottom: 1.25em; /* Relative to element's font-size */
}
.container {
  max-width: 75rem;      /* 1200px but responsive */
  width: 100%;
  padding: 1.875rem;
}

/* When to use which unit:
   - font-size: rem (scales with user preference)
   - margin/padding: rem or em
   - width: %, vw, or rem with max-width
   - height: vh, %, auto, or min-height in rem
   - borders/shadows: px is fine (they don't need to scale)
*/`}
              
            />
          </Box>
        </Paper>

        {/* ==================== DEEP DIVE: CSS PERFORMANCE ==================== */}
        <Paper
          id="css-performance"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#10b981", 0.08)} 0%, ${alpha("#22c55e", 0.08)} 100%)`,
            border: `1px solid ${alpha("#10b981", 0.3)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Deep Dive" sx={{ bgcolor: alpha("#10b981", 0.2), color: "#10b981", fontWeight: 700 }} />
            <Chip label="Performance" size="small" sx={{ bgcolor: alpha("#22c55e", 0.2), color: "#22c55e", fontWeight: 600 }} />
          </Box>

          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#10b981" }}>
            ⚡ CSS Performance Best Practices
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            CSS performance might seem negligible, but on large sites with complex stylesheets, poor CSS practices can 
            significantly impact rendering speed and user experience. Understanding how browsers process CSS helps you 
            write more efficient styles and avoid common performance pitfalls.
          </Typography>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            How Browsers Process CSS
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            When a browser renders a page, it builds two trees: the DOM (from HTML) and the CSSOM (from CSS). 
            These combine into a render tree. Understanding this process reveals why certain CSS patterns are slower:
          </Typography>

          <Box sx={{ fontFamily: "monospace", fontSize: "0.85rem", p: 3, bgcolor: "#111827", borderRadius: 2, color: "#f9fafb", mb: 3, whiteSpace: "pre" }}>
{`HTML Document             CSS Stylesheets
      │                          │
      ▼                          ▼
┌──────────┐              ┌──────────┐
│   DOM    │              │  CSSOM   │
│   Tree   │              │   Tree   │
└────┬─────┘              └────┬─────┘
     │                          │
     └──────────┬───────────────┘
                │
                ▼
        ┌───────────────┐
        │  Render Tree  │
        │ (visible only)│
        └───────┬───────┘
                │
        ┌───────┴───────┐
        │    Layout     │ ← Calculate positions & sizes
        └───────┬───────┘
                │
        ┌───────┴───────┐
        │    Paint      │ ← Fill in pixels
        └───────┬───────┘
                │
        ┌───────┴───────┐
        │  Composite    │ ← Layer composition
        └───────────────┘`}
          </Box>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Efficient Selectors
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            Browsers match selectors from <strong>right to left</strong>. This means the rightmost part (the "key selector") 
            is evaluated first. A selector like "div.container p span" first finds ALL spans, then filters.
          </Typography>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`/* ❌ Slow: Browser must check every element */
* { 
  box-sizing: border-box; 
}
/* Slightly better but still touches everything */
*, *::before, *::after { 
  box-sizing: border-box; 
}
/* In practice, this is acceptable for box-sizing reset */

/* ❌ Slow: Universal key selector */
.header * { color: white; }
[data-active] * { opacity: 1; }

/* ❌ Slow: Very general key selector */
div { }           /* Matches EVERY div */
a { }             /* Matches EVERY anchor */
.container div { }  /* Still matches every div, then checks parent */

/* ✅ Fast: Specific class selectors */
.header-text { color: white; }
.nav-link { }
.card { }

/* ❌ Slow: Deep descendant selectors */
.page .main .article .content .text p span { }
/* Browser: find spans → check parent is p → check parent is .text → ... */

/* ✅ Fast: Direct class */
.article-highlight { }

/* ❌ Avoid: Overly qualified selectors */
div.card { }        /* The div adds nothing */
a.nav-link { }      /* a is redundant */

/* ✅ Just the class */
.card { }
.nav-link { }`}
              
            />
          </Box>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Avoid Layout Thrashing
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            <strong>Layout thrashing</strong> (or forced synchronous layout) occurs when you read layout properties 
            and then write styles in a loop, forcing the browser to recalculate layout repeatedly:
          </Typography>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`// ❌ Bad: Reading and writing in a loop causes layout thrashing
const boxes = document.querySelectorAll('.box');
boxes.forEach(box => {
  const height = box.offsetHeight;  // READ - forces layout
  box.style.height = height + 10 + 'px';  // WRITE - invalidates layout
  // Next iteration: browser must recalculate layout again!
});

// ✅ Good: Batch reads, then batch writes
const boxes = document.querySelectorAll('.box');
const heights = [];

// Phase 1: Read all values
boxes.forEach(box => {
  heights.push(box.offsetHeight);  // All reads together
});

// Phase 2: Write all values
boxes.forEach((box, i) => {
  box.style.height = heights[i] + 10 + 'px';  // All writes together
});
// Only one layout recalculation!

// ✅ Even better: Use CSS transforms for animations
// Transforms don't trigger layout
.animate {
  transition: transform 0.3s;
}
.animate:hover {
  transform: scale(1.1);  /* GPU-accelerated, no layout */
}`}
              
            />
          </Box>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Efficient Animations
          </Typography>

          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.9 }}>
            Not all CSS properties are equal for animation performance. Properties that trigger layout or paint 
            are expensive; those that only trigger compositing are cheap:
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ef4444", 0.1), border: `1px solid ${alpha("#ef4444", 0.3)}`, height: "100%" }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>❌ Trigger Layout</Typography>
                <Typography variant="body2" sx={{ fontFamily: "monospace", lineHeight: 2 }}>
                  width, height<br/>
                  padding, margin<br/>
                  top, left, right, bottom<br/>
                  font-size<br/>
                  border-width
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.1), border: `1px solid ${alpha("#f59e0b", 0.3)}`, height: "100%" }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>⚠️ Trigger Paint</Typography>
                <Typography variant="body2" sx={{ fontFamily: "monospace", lineHeight: 2 }}>
                  color<br/>
                  background-color<br/>
                  border-color<br/>
                  box-shadow<br/>
                  visibility
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={12} md={4}>
              <Box sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.1), border: `1px solid ${alpha("#22c55e", 0.3)}`, height: "100%" }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>✅ Composite Only</Typography>
                <Typography variant="body2" sx={{ fontFamily: "monospace", lineHeight: 2 }}>
                  transform<br/>
                  opacity<br/>
                  filter<br/>
                  <br/>
                  <em>(GPU accelerated)</em>
                </Typography>
              </Box>
            </Grid>
          </Grid>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`/* ❌ Expensive: Animating layout properties */
.slide-in {
  transition: left 0.3s, width 0.3s;
}
.slide-in.active {
  left: 0;
  width: 100%;
}

/* ✅ Cheap: Use transforms instead */
.slide-in {
  transform: translateX(-100%);
  transition: transform 0.3s;
  will-change: transform;  /* Hint to browser to optimize */
}
.slide-in.active {
  transform: translateX(0);
}

/* ❌ Expensive: Animating background-color */
.button {
  transition: background-color 0.3s;
}

/* Alternative: Use pseudo-element with opacity */
.button {
  position: relative;
  z-index: 1;
}
.button::before {
  content: '';
  position: absolute;
  inset: 0;
  background: var(--hover-color);
  opacity: 0;
  transition: opacity 0.3s;
  z-index: -1;
}
.button:hover::before {
  opacity: 1;
}`}
              
            />
          </Box>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Reduce File Size
          </Typography>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`/* ❌ Verbose: Longhand properties */
.element {
  margin-top: 10px;
  margin-right: 20px;
  margin-bottom: 10px;
  margin-left: 20px;
  padding-top: 5px;
  padding-right: 10px;
  padding-bottom: 5px;
  padding-left: 10px;
  background-image: url('bg.jpg');
  background-repeat: no-repeat;
  background-position: center;
  background-size: cover;
}

/* ✅ Concise: Shorthand properties */
.element {
  margin: 10px 20px;
  padding: 5px 10px;
  background: url('bg.jpg') no-repeat center / cover;
}

/* Additional tips:
   - Minify CSS in production (build tools do this)
   - Remove unused CSS (PurgeCSS, UnCSS)
   - Use CSS Grid/Flexbox instead of frameworks when possible
   - Avoid @import (use <link> or bundlers)
   - Critical CSS: inline above-fold styles, defer the rest
*/

/* Modern CSS reduces need for preprocessors */
/* Instead of: */
$blue: #3b82f6;
.btn { background: darken($blue, 10%); }

/* Use: */
.btn {
  --btn-color: #3b82f6;
  background: color-mix(in oklch, var(--btn-color), black 10%);
}`}
              
            />
          </Box>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Font Loading Performance
          </Typography>

          <Box sx={{ mb: 3 }}>
            <CodeBlock
              code={`<!-- ❌ Slow: Blocking font load -->
<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap" rel="stylesheet">

<!-- ✅ Faster: Preconnect to font origin -->
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap" rel="stylesheet">

<!-- ✅ Even better: Self-host fonts for full control -->
<style>
@font-face {
  font-family: 'Roboto';
  src: url('/fonts/roboto-400.woff2') format('woff2');
  font-weight: 400;
  font-style: normal;
  font-display: swap;  /* Show fallback immediately, swap when loaded */
}
</style>

/* font-display values:
   - auto: Browser default (usually block)
   - block: Brief invisible text, then custom font
   - swap: Fallback immediately, swap when ready (recommended)
   - fallback: Very brief block, then fallback if slow
   - optional: Use if available, otherwise fallback forever
*/

/* Subset fonts to only needed characters */
/* Use tools like glyphhanger or transfonter.org */`}
              
            />
          </Box>

          <Alert severity="success" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>Performance Testing:</strong> Use Chrome DevTools Performance panel, Lighthouse, and WebPageTest 
              to measure CSS performance. Look for "Recalculate Style" in the flame chart—if it's taking too long, 
              investigate your selectors and layout patterns.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== MODULE 1: YOUR FIRST WEB PAGE ==================== */}
        <Paper
          id="module-1"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#3b82f6", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 1" sx={{ bgcolor: alpha("#3b82f6", 0.15), color: "#3b82f6", fontWeight: 700 }} />
            <Chip label="Beginner" size="small" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
          </Box>
          
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#3b82f6" }}>
            🎯 Your First Web Page
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            Welcome to web development! In this module, you'll create your very first web page. Don't worry if you've never 
            written a line of code before—we'll start from the absolute beginning. By the end of this module, you'll have 
            a working web page that you built yourself!
          </Typography>

          <Alert severity="info" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>What You'll Need</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              • A computer (Windows, Mac, or Linux)<br />
              • A text editor (we recommend <strong>Visual Studio Code</strong>—it's free!)<br />
              • A web browser (Chrome, Firefox, Edge, or Safari)
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            What is HTML?
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            <strong>HTML</strong> stands for <strong>HyperText Markup Language</strong>. It's the standard language used to 
            create web pages. Think of HTML as the skeleton of a website—it defines the structure and content of a page.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            HTML uses <strong>tags</strong> to mark up content. Tags are special keywords surrounded by angle brackets, 
            like <code style={{ background: alpha("#3b82f6", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;html&gt;</code> or 
            <code style={{ background: alpha("#3b82f6", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;p&gt;</code>. Most tags 
            come in pairs: an opening tag and a closing tag (with a forward slash).
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 2 }}>Example: A Simple Tag Pair</Typography>
            <Box component="pre" sx={{ fontSize: "0.9rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<p>This is a paragraph of text.</p>
 ↑                              ↑
Opening tag              Closing tag`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            Setting Up Visual Studio Code
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Visual Studio Code (VS Code) is a free, powerful code editor from Microsoft. It's perfect for beginners and 
            professionals alike.
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { step: "1", title: "Download VS Code", desc: "Go to code.visualstudio.com and download the version for your operating system" },
              { step: "2", title: "Install It", desc: "Run the installer and follow the prompts (defaults are fine)" },
              { step: "3", title: "Open VS Code", desc: "Launch VS Code—you'll see a welcome screen" },
              { step: "4", title: "Create a Folder", desc: "Create a folder on your computer called 'my-first-website'" },
            ].map((item) => (
              <Grid item xs={12} sm={6} key={item.step}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.1)}` }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Box sx={{ width: 28, height: 28, borderRadius: "50%", bgcolor: "#3b82f6", color: "white", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, fontSize: "0.85rem" }}>
                      {item.step}
                    </Box>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.title}</Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            Creating Your First HTML File
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Let's create your first web page! Follow these steps:
          </Typography>

          <List sx={{ mb: 3 }}>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
              <ListItemText primary="In VS Code, go to File → Open Folder and select your 'my-first-website' folder" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
              <ListItemText primary="Click the 'New File' icon or press Ctrl+N (Cmd+N on Mac)" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
              <ListItemText primary="Save the file as 'index.html' (File → Save or Ctrl+S)" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
              <ListItemText primary="Type the code below into your file" />
            </ListItem>
          </List>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 2 }}>Your First Web Page (index.html)</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!DOCTYPE html>
<html>
<head>
    <title>My First Web Page</title>
</head>
<body>
    <h1>Hello, World!</h1>
    <p>This is my very first web page.</p>
    <p>I'm learning HTML!</p>
</body>
</html>`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            Viewing Your Web Page
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Now let's see your creation in a web browser:
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { method: "Method 1", desc: "Find your index.html file in your file explorer and double-click it" },
              { method: "Method 2", desc: "Right-click index.html and select 'Open with' → your browser" },
              { method: "Method 3", desc: "In VS Code, install the 'Live Server' extension, then right-click and select 'Open with Live Server'" },
            ].map((item) => (
              <Grid item xs={12} md={4} key={item.method}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>{item.method}</Typography>
                  <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="success" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>🎉 Congratulations!</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              You've just created and viewed your first web page! You should see a heading that says "Hello, World!" 
              and two paragraphs below it. This is the foundation of every website on the internet!
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            Understanding the Code
          </Typography>

          <Paper sx={{ p: 3, mb: 3, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 2 }}>Line by Line Breakdown</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!DOCTYPE html>     → Tells the browser this is an HTML5 document
<html>              → The root element that contains everything
<head>              → Contains metadata (info about the page)
    <title>         → The text shown in the browser tab
</head>
<body>              → Contains all visible content
    <h1>            → A main heading (largest)
    <p>             → A paragraph of text
</body>
</html>             → Closes the root element`}
            </Box>
          </Paper>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            ✏️ Try It Yourself
          </Typography>
          
          <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
            Modify your index.html file:
          </Typography>
          
          <List dense>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#3b82f6" }} /></ListItemIcon>
              <ListItemText primary="Change 'Hello, World!' to your own greeting" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#3b82f6" }} /></ListItemIcon>
              <ListItemText primary="Add a third paragraph about what you want to learn" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#3b82f6" }} /></ListItemIcon>
              <ListItemText primary="Change the page title to something creative" />
            </ListItem>
          </List>
        </Paper>

        {/* ==================== MODULE 2: HTML BASICS & STRUCTURE ==================== */}
        <Paper
          id="module-2"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#e44d26", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 2" sx={{ bgcolor: alpha("#e44d26", 0.15), color: "#e44d26", fontWeight: 700 }} />
            <Chip label="Beginner" size="small" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
          </Box>
          
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#e44d26" }}>
            📄 HTML Basics & Document Structure
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            Now that you've created your first web page, let's dive deeper into understanding how HTML documents are structured. 
            Every HTML page follows a specific structure that browsers expect. Understanding this structure is essential for 
            building proper websites.
          </Typography>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#e44d26" }}>
            The DOCTYPE Declaration
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Every HTML document must start with a <strong>DOCTYPE</strong> declaration. This tells the browser what version 
            of HTML the page is using. For HTML5 (the current standard), it's simply:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#e44d26", 0.05), border: `1px solid ${alpha("#e44d26", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.9rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!DOCTYPE html>

<!-- This must ALWAYS be the very first line of your HTML file -->
<!-- It's not actually an HTML tag - it's a declaration -->`}
            </Box>
          </Paper>

          <Alert severity="warning" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Why It Matters</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Without DOCTYPE, browsers enter "quirks mode" which can cause inconsistent rendering across different browsers. 
              Always include it as the first line!
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#e44d26" }}>
            The HTML Element
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            The <code style={{ background: alpha("#e44d26", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;html&gt;</code> element 
            is the root of your document. Everything else goes inside it. You can also specify the language of your page:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#e44d26", 0.05), border: `1px solid ${alpha("#e44d26", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.9rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!DOCTYPE html>
<html lang="en">
    <!-- Everything goes in here -->
</html>

<!-- Common language codes:
     en = English
     es = Spanish  
     fr = French
     de = German
     zh = Chinese
     ja = Japanese -->`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#e44d26" }}>
            The Head Section
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            The <code style={{ background: alpha("#e44d26", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;head&gt;</code> section 
            contains <strong>metadata</strong>—information about your page that isn't displayed directly on the page. This includes 
            the page title, character encoding, links to CSS files, and more.
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#e44d26", 0.05), border: `1px solid ${alpha("#e44d26", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#e44d26", mb: 2 }}>Essential Head Elements</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<head>
    <!-- Character encoding (always include this!) -->
    <meta charset="UTF-8">
    
    <!-- Makes the page responsive on mobile devices -->
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    
    <!-- Page title (shown in browser tab) -->
    <title>My Amazing Website</title>
    
    <!-- Page description (shown in search results) -->
    <meta name="description" content="A brief description of your page">
    
    <!-- Link to external CSS stylesheet -->
    <link rel="stylesheet" href="styles.css">
    
    <!-- Favicon (the small icon in the browser tab) -->
    <link rel="icon" href="favicon.ico">
</head>`}
            </Box>
          </Paper>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { tag: "<meta charset>", purpose: "Ensures special characters display correctly (emojis, accents, etc.)", essential: true },
              { tag: "<meta viewport>", purpose: "Makes your page look good on phones and tablets", essential: true },
              { tag: "<title>", purpose: "Sets the text in the browser tab and bookmarks", essential: true },
              { tag: "<meta description>", purpose: "Shows up in Google search results", essential: false },
              { tag: "<link rel=\"stylesheet\">", purpose: "Connects your CSS file for styling", essential: false },
              { tag: "<link rel=\"icon\">", purpose: "Sets the tiny icon in the browser tab", essential: false },
            ].map((item) => (
              <Grid item xs={12} sm={6} key={item.tag}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: item.essential ? alpha("#22c55e", 0.05) : alpha("#e44d26", 0.03), border: `1px solid ${alpha(item.essential ? "#22c55e" : "#e44d26", 0.15)}` }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, fontFamily: "monospace", color: item.essential ? "#22c55e" : "#e44d26" }}>{item.tag}</Typography>
                    {item.essential && <Chip label="Essential" size="small" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontSize: "0.65rem", height: 20 }} />}
                  </Box>
                  <Typography variant="body2" color="text.secondary">{item.purpose}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#e44d26" }}>
            The Body Section
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            The <code style={{ background: alpha("#e44d26", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;body&gt;</code> section 
            contains everything that users actually see on the page—text, images, buttons, videos, forms, etc.
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#e44d26", 0.05), border: `1px solid ${alpha("#e44d26", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#e44d26", mb: 2 }}>Complete HTML5 Template</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Page Title Here</title>
</head>
<body>
    <!-- All visible content goes here -->
    <h1>Welcome to My Website</h1>
    <p>This is the content users will see.</p>
</body>
</html>`}
            </Box>
          </Paper>

          <Alert severity="info" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>💡 Pro Tip: Emmet Shortcut</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              In VS Code, type <code style={{ background: alpha("#2196f3", 0.1), padding: "2px 6px", borderRadius: 4 }}>!</code> and 
              press <strong>Tab</strong> or <strong>Enter</strong>. This will automatically generate a complete HTML5 template!
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#e44d26" }}>
            HTML Comments
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Comments are notes in your code that browsers ignore. They're useful for explaining your code or temporarily 
            disabling elements:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#e44d26", 0.05), border: `1px solid ${alpha("#e44d26", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.9rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!-- This is a comment - browsers will ignore it -->

<!-- 
    This is a multi-line comment.
    You can write as much as you want here.
    Very useful for explaining complex sections!
-->

<p>This paragraph is visible.</p>
<!-- <p>This paragraph is hidden (commented out)</p> -->`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#e44d26" }}>
            Indentation Best Practices
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Good indentation makes your code readable. Each nested element should be indented (usually 2 or 4 spaces):
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>❌ Bad (Hard to Read)</Typography>
                <Box component="pre" sx={{ fontSize: "0.8rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<html><head><title>Page</title></head>
<body><h1>Title</h1><p>Text</p></body></html>`}
                </Box>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.2)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>✅ Good (Easy to Read)</Typography>
                <Box component="pre" sx={{ fontSize: "0.8rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<html>
  <head>
    <title>Page</title>
  </head>
  <body>
    <h1>Title</h1>
    <p>Text</p>
  </body>
</html>`}
                </Box>
              </Paper>
            </Grid>
          </Grid>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            ✏️ Try It Yourself
          </Typography>
          
          <List dense>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#e44d26" }} /></ListItemIcon>
              <ListItemText primary="Add all the essential meta tags to your index.html file" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#e44d26" }} /></ListItemIcon>
              <ListItemText primary="Add a description meta tag for your page" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#e44d26" }} /></ListItemIcon>
              <ListItemText primary="Add comments explaining each section of your HTML" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#e44d26" }} /></ListItemIcon>
              <ListItemText primary="Practice the ! Emmet shortcut in VS Code" />
            </ListItem>
          </List>
        </Paper>

        {/* ==================== MODULE 3: TEXT & LINKS ==================== */}
        <Paper
          id="module-3"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#22c55e", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 3" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 700 }} />
            <Chip label="Beginner" size="small" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
          </Box>
          
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#22c55e" }}>
            🔗 Text Content & Links
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            Text is the foundation of most web pages. In this module, you'll learn how to structure text content with 
            headings and paragraphs, format text with bold and italic, and create links to other pages—the very thing 
            that makes the web a "web"!
          </Typography>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Headings (h1 - h6)
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            HTML provides six levels of headings, from <code style={{ background: alpha("#22c55e", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;h1&gt;</code> (most important) 
            to <code style={{ background: alpha("#22c55e", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;h6&gt;</code> (least important). 
            Think of them like a document outline:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>All Six Heading Levels</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<h1>Main Page Title</h1>        <!-- Use only ONE h1 per page -->
<h2>Major Section</h2>          <!-- Chapter-level headings -->
<h3>Subsection</h3>             <!-- Subtopics within a section -->
<h4>Minor Heading</h4>          <!-- Rarely used in simple pages -->
<h5>Even Smaller</h5>           <!-- Very specific sub-points -->
<h6>Smallest Heading</h6>       <!-- Hardly ever needed -->`}
            </Box>
          </Paper>

          <Alert severity="warning" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Important: Heading Hierarchy</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              • Use only <strong>one &lt;h1&gt;</strong> per page (it's your main title)<br />
              • Don't skip levels (don't go from h1 to h3—use h2 first)<br />
              • Headings aren't just for making text bigger—they define document structure<br />
              • Screen readers use headings to navigate, so proper order matters for accessibility!
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Paragraphs and Line Breaks
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            The <code style={{ background: alpha("#22c55e", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;p&gt;</code> tag creates paragraphs. 
            Browsers automatically add space before and after paragraphs. For a line break without starting a new paragraph, 
            use <code style={{ background: alpha("#22c55e", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;br&gt;</code>:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<p>This is the first paragraph. It has some text in it.</p>

<p>This is a second paragraph. Notice the automatic 
spacing between paragraphs.</p>

<p>
    This paragraph has<br>
    a line break in<br>
    the middle.
</p>

<!-- Note: <br> is a self-closing tag (no </br> needed) -->`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Text Formatting
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            HTML provides several tags for formatting text. Here are the most common ones:
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { tag: "<strong>", display: "Bold text", desc: "Important text (screen readers emphasize it)", example: "<strong>important</strong>" },
              { tag: "<em>", display: "Italic text", desc: "Emphasized text (slight stress)", example: "<em>emphasized</em>" },
              { tag: "<b>", display: "Bold text", desc: "Visually bold (no special importance)", example: "<b>bold</b>" },
              { tag: "<i>", display: "Italic text", desc: "Visually italic (technical terms, foreign words)", example: "<i>italic</i>" },
              { tag: "<u>", display: "Underlined", desc: "Underlined text (use sparingly—looks like links!)", example: "<u>underlined</u>" },
              { tag: "<mark>", display: "Highlighted", desc: "Highlighted/marked text", example: "<mark>highlighted</mark>" },
              { tag: "<del>", display: "Strikethrough", desc: "Deleted/removed text", example: "<del>deleted</del>" },
              { tag: "<small>", display: "Smaller text", desc: "Fine print, side comments", example: "<small>small print</small>" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.tag}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.1)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, fontFamily: "monospace", color: "#22c55e", mb: 0.5 }}>{item.tag}</Typography>
                  <Typography variant="body2" sx={{ mb: 1, fontWeight: item.tag.includes("strong") || item.tag.includes("b") ? 700 : 400, fontStyle: item.tag.includes("em") || item.tag.includes("i") ? "italic" : "normal" }}>
                    {item.display}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>Combining Formatting Tags</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<p>
    This is <strong>very important</strong> text.
    This is <em>emphasized</em> text.
    You can even <strong><em>combine them</em></strong>!
</p>

<p>
    The price was <del>$100</del> <strong>$75</strong> today!
</p>

<p>
    Please read the <mark>highlighted section</mark> carefully.
</p>

<p>
    <small>© 2025 My Website. All rights reserved.</small>
</p>`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Links (The Heart of the Web!)
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Links are created with the <code style={{ background: alpha("#22c55e", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;a&gt;</code> (anchor) tag. 
            The <code style={{ background: alpha("#22c55e", 0.1), padding: "2px 6px", borderRadius: 4 }}>href</code> attribute specifies where the link goes:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>Types of Links</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!-- External link (to another website) -->
<a href="https://www.google.com">Go to Google</a>

<!-- Open in new tab (recommended for external links) -->
<a href="https://www.google.com" target="_blank">Google (new tab)</a>

<!-- Internal link (to another page on your site) -->
<a href="about.html">About Us</a>
<a href="pages/contact.html">Contact Page</a>

<!-- Link to a section on the same page (using ID) -->
<a href="#section2">Jump to Section 2</a>
<!-- ... somewhere else on the page: -->
<h2 id="section2">Section 2</h2>

<!-- Email link (opens email client) -->
<a href="mailto:hello@example.com">Email Us</a>

<!-- Phone link (opens phone dialer on mobile) -->
<a href="tel:+1234567890">Call Us</a>

<!-- Download link -->
<a href="files/document.pdf" download>Download PDF</a>`}
            </Box>
          </Paper>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { type: "External Links", example: "href=\"https://...\"", tip: "Always use https:// for security", color: "#3b82f6" },
              { type: "Internal Links", example: "href=\"page.html\"", tip: "Use relative paths within your site", color: "#22c55e" },
              { type: "Section Links", example: "href=\"#id\"", tip: "Add id=\"name\" to your target element", color: "#f59e0b" },
              { type: "Email Links", example: "href=\"mailto:...\"", tip: "Opens user's email client", color: "#ec4899" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.type}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: alpha(item.color, 0.05), border: `1px solid ${alpha(item.color, 0.15)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, mb: 0.5 }}>{item.type}</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.75rem", mb: 1 }}>{item.example}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.tip}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="info" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>💡 The target="_blank" Security Tip</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              When using <code>target="_blank"</code>, also add <code>rel="noopener noreferrer"</code> for security. 
              This prevents the new page from accessing your page's window object:<br /><br />
              <code style={{ background: alpha("#2196f3", 0.1), padding: "4px 8px", borderRadius: 4, display: "inline-block" }}>
                &lt;a href="https://example.com" target="_blank" rel="noopener noreferrer"&gt;Safe Link&lt;/a&gt;
              </code>
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Horizontal Rules and Special Characters
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            A few more useful elements for text content:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!-- Horizontal rule (divider line) -->
<p>Section 1 content here...</p>
<hr>
<p>Section 2 content here...</p>

<!-- Special characters (HTML entities) -->
<p>Copyright &copy; 2025</p>          <!-- © -->
<p>5 &lt; 10 and 10 &gt; 5</p>       <!-- < and > -->
<p>This &amp; that</p>               <!-- & -->
<p>Use &nbsp; for non-breaking space</p>
<p>&quot;Quoted text&quot;</p>       <!-- " -->
<p>Price: &euro;50 or &pound;45</p>  <!-- € and £ -->`}
            </Box>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            Common HTML Entities Reference
          </Typography>

          <Grid container spacing={1} sx={{ mb: 4 }}>
            {[
              { entity: "&lt;", displays: "<", name: "Less than" },
              { entity: "&gt;", displays: ">", name: "Greater than" },
              { entity: "&amp;", displays: "&", name: "Ampersand" },
              { entity: "&copy;", displays: "©", name: "Copyright" },
              { entity: "&reg;", displays: "®", name: "Registered" },
              { entity: "&trade;", displays: "™", name: "Trademark" },
              { entity: "&nbsp;", displays: " ", name: "Non-breaking space" },
              { entity: "&quot;", displays: '"', name: "Quotation mark" },
            ].map((item) => (
              <Grid item xs={6} sm={3} key={item.entity}>
                <Paper sx={{ p: 1.5, borderRadius: 1, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.1)}`, textAlign: "center" }}>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#22c55e" }}>{item.entity}</Typography>
                  <Typography variant="h6" sx={{ fontWeight: 700 }}>{item.displays}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.name}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            ✏️ Try It Yourself
          </Typography>
          
          <List dense>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
              <ListItemText primary="Create a page with an h1 title and h2 section headings" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
              <ListItemText primary="Add paragraphs with bold and italic text" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
              <ListItemText primary="Create a link to your favorite website (opens in new tab)" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
              <ListItemText primary={'Add a \'Back to top\' link using href="#" or an ID'} />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#22c55e" }} /></ListItemIcon>
              <ListItemText primary="Add a copyright notice with the © symbol" />
            </ListItem>
          </List>
        </Paper>

        {/* ==================== MODULE 4: LISTS & TABLES ==================== */}
        <Paper
          id="module-4"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#f97316", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 4" sx={{ bgcolor: alpha("#f97316", 0.15), color: "#f97316", fontWeight: 700 }} />
            <Chip label="Beginner" size="small" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
          </Box>
          
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#f97316" }}>
            📋 Lists & Tables
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            Lists and tables are essential for organizing information on web pages. Whether you're creating a navigation menu, 
            a to-do list, or displaying data in rows and columns, these HTML elements are your go-to tools.
          </Typography>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            Unordered Lists (Bullet Points)
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Use <code style={{ background: alpha("#f97316", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;ul&gt;</code> for 
            bullet-point lists when the order doesn't matter. Each item uses <code style={{ background: alpha("#f97316", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;li&gt;</code> (list item):
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 2 }}>Unordered List Example</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<h3>My Favorite Fruits</h3>
<ul>
    <li>Apples</li>
    <li>Bananas</li>
    <li>Oranges</li>
    <li>Strawberries</li>
</ul>

<!-- Result:
• Apples
• Bananas
• Oranges
• Strawberries
-->`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            Ordered Lists (Numbered)
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Use <code style={{ background: alpha("#f97316", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;ol&gt;</code> when 
            the order matters (like steps in a recipe or rankings):
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 2 }}>Ordered List Example</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<h3>How to Make Tea</h3>
<ol>
    <li>Boil water</li>
    <li>Add tea bag to cup</li>
    <li>Pour hot water into cup</li>
    <li>Steep for 3-5 minutes</li>
    <li>Remove tea bag and enjoy!</li>
</ol>

<!-- Result:
1. Boil water
2. Add tea bag to cup
3. Pour hot water into cup
4. Steep for 3-5 minutes
5. Remove tea bag and enjoy!
-->`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            Nested Lists
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            You can put lists inside lists to create sub-items. This is perfect for outlines, menus, or hierarchical data:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 2 }}>Nested List Example</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<h3>Web Development Skills</h3>
<ul>
    <li>Frontend
        <ul>
            <li>HTML</li>
            <li>CSS</li>
            <li>JavaScript</li>
        </ul>
    </li>
    <li>Backend
        <ul>
            <li>Python</li>
            <li>Node.js</li>
            <li>Databases</li>
        </ul>
    </li>
    <li>DevOps
        <ul>
            <li>Git</li>
            <li>Docker</li>
        </ul>
    </li>
</ul>`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            Description Lists
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Use <code style={{ background: alpha("#f97316", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;dl&gt;</code> for 
            term-definition pairs, like glossaries or FAQs:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<h3>Web Terms Glossary</h3>
<dl>
    <dt>HTML</dt>
    <dd>HyperText Markup Language - the structure of web pages</dd>
    
    <dt>CSS</dt>
    <dd>Cascading Style Sheets - the styling of web pages</dd>
    
    <dt>JavaScript</dt>
    <dd>A programming language for web interactivity</dd>
</dl>

<!-- dt = definition term (the word being defined) -->
<!-- dd = definition description (the definition itself) -->`}
            </Box>
          </Paper>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            HTML Tables
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Tables organize data into rows and columns. They're perfect for schedules, pricing, comparisons, and any tabular data:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 2 }}>Basic Table Structure</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<table>
    <thead>
        <tr>
            <th>Name</th>
            <th>Age</th>
            <th>City</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>Alice</td>
            <td>25</td>
            <td>New York</td>
        </tr>
        <tr>
            <td>Bob</td>
            <td>30</td>
            <td>Los Angeles</td>
        </tr>
        <tr>
            <td>Charlie</td>
            <td>35</td>
            <td>Chicago</td>
        </tr>
    </tbody>
</table>`}
            </Box>
          </Paper>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { tag: "<table>", desc: "The container for the entire table", color: "#f97316" },
              { tag: "<thead>", desc: "Table header section (column titles)", color: "#3b82f6" },
              { tag: "<tbody>", desc: "Table body (the main data rows)", color: "#22c55e" },
              { tag: "<tr>", desc: "Table row (horizontal row)", color: "#8b5cf6" },
              { tag: "<th>", desc: "Table header cell (bold, centered)", color: "#ec4899" },
              { tag: "<td>", desc: "Table data cell (normal cell)", color: "#14b8a6" },
            ].map((item) => (
              <Grid item xs={6} sm={4} key={item.tag}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: alpha(item.color, 0.05), border: `1px solid ${alpha(item.color, 0.15)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, fontFamily: "monospace", color: item.color, mb: 0.5 }}>{item.tag}</Typography>
                  <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            Spanning Rows and Columns
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Use <code style={{ background: alpha("#f97316", 0.1), padding: "2px 6px", borderRadius: 4 }}>colspan</code> to span 
            multiple columns and <code style={{ background: alpha("#f97316", 0.1), padding: "2px 6px", borderRadius: 4 }}>rowspan</code> to span multiple rows:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 2 }}>Colspan and Rowspan Example</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<table border="1">
    <tr>
        <th colspan="3">Student Schedule</th>  <!-- Spans 3 columns -->
    </tr>
    <tr>
        <th>Time</th>
        <th>Monday</th>
        <th>Tuesday</th>
    </tr>
    <tr>
        <td>9:00 AM</td>
        <td rowspan="2">Math</td>  <!-- Spans 2 rows -->
        <td>English</td>
    </tr>
    <tr>
        <td>10:00 AM</td>
        <!-- No cell here - Math spans into this row -->
        <td>Science</td>
    </tr>
</table>`}
            </Box>
          </Paper>

          <Alert severity="warning" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Tables Are for Data, Not Layout!</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              In the old days, developers used tables to create page layouts. <strong>Don't do this!</strong> Tables should only 
              be used for actual tabular data. For page layout, use CSS Flexbox or Grid (we'll learn those in later modules).
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            Table Caption and Footer
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<table>
    <caption>Quarterly Sales Report</caption>
    <thead>
        <tr>
            <th>Product</th>
            <th>Q1</th>
            <th>Q2</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td>Widgets</td>
            <td>$1,000</td>
            <td>$1,500</td>
        </tr>
        <tr>
            <td>Gadgets</td>
            <td>$2,000</td>
            <td>$2,500</td>
        </tr>
    </tbody>
    <tfoot>
        <tr>
            <td>Total</td>
            <td>$3,000</td>
            <td>$4,000</td>
        </tr>
    </tfoot>
</table>`}
            </Box>
          </Paper>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            ✏️ Try It Yourself
          </Typography>
          
          <List dense>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#f97316" }} /></ListItemIcon>
              <ListItemText primary="Create a shopping list using an unordered list" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#f97316" }} /></ListItemIcon>
              <ListItemText primary="Create a 'Top 5 Movies' ranked list using an ordered list" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#f97316" }} /></ListItemIcon>
              <ListItemText primary="Create a nested list showing your skills and sub-skills" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#f97316" }} /></ListItemIcon>
              <ListItemText primary="Build a table showing your weekly schedule" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#f97316" }} /></ListItemIcon>
              <ListItemText primary="Try using colspan to create a table header that spans all columns" />
            </ListItem>
          </List>
        </Paper>

        {/* ==================== MODULE 5: IMAGES & MEDIA ==================== */}
        <Paper
          id="module-5"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 5" sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 700 }} />
            <Chip label="Beginner" size="small" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
          </Box>
          
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#8b5cf6" }}>
            🖼️ Images & Media
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            A picture is worth a thousand words! In this module, you'll learn how to add images, videos, and audio to your 
            web pages. We'll also cover image formats, accessibility, and embedding content from other sites like YouTube.
          </Typography>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Adding Images
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            The <code style={{ background: alpha("#8b5cf6", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;img&gt;</code> tag 
            displays images. It's a <strong>self-closing tag</strong> (no closing tag needed):
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 2 }}>Basic Image Syntax</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!-- Basic image -->
<img src="photo.jpg" alt="A beautiful sunset">

<!-- Image with specific dimensions -->
<img src="logo.png" alt="Company Logo" width="200" height="100">

<!-- Image from the internet -->
<img src="https://example.com/images/cat.jpg" alt="A cute cat">

<!-- Image in a subfolder -->
<img src="images/profile.jpg" alt="My profile photo">`}
            </Box>
          </Paper>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { attr: "src", desc: "The path or URL to the image file (required)", required: true },
              { attr: "alt", desc: "Alternative text if image can't load + screen readers (required for accessibility)", required: true },
              { attr: "width", desc: "Width in pixels (or use CSS instead)", required: false },
              { attr: "height", desc: "Height in pixels (or use CSS instead)", required: false },
              { attr: "loading", desc: "'lazy' delays loading until image is near viewport", required: false },
              { attr: "title", desc: "Tooltip text shown on hover", required: false },
            ].map((item) => (
              <Grid item xs={12} sm={6} key={item.attr}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: item.required ? alpha("#22c55e", 0.05) : alpha("#8b5cf6", 0.03), border: `1px solid ${alpha(item.required ? "#22c55e" : "#8b5cf6", 0.15)}` }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                    <Typography variant="subtitle2" sx={{ fontWeight: 700, fontFamily: "monospace", color: item.required ? "#22c55e" : "#8b5cf6" }}>{item.attr}</Typography>
                    {item.required && <Chip label="Required" size="small" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontSize: "0.6rem", height: 18 }} />}
                  </Box>
                  <Typography variant="body2" color="text.secondary">{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="error" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Always Use Alt Text!</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              The <code>alt</code> attribute is <strong>crucial for accessibility</strong>. Screen readers read this text to 
              visually impaired users. It also displays if the image fails to load. Write descriptive alt text that explains 
              what's in the image!
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Image Formats
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Different image formats are best for different use cases:
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { format: "JPEG (.jpg)", best: "Photos, complex images", pros: "Small file size, great for photos", cons: "Loses quality when compressed, no transparency", color: "#ef4444" },
              { format: "PNG (.png)", best: "Logos, icons, screenshots", pros: "Supports transparency, lossless quality", cons: "Larger file size than JPEG", color: "#3b82f6" },
              { format: "GIF (.gif)", best: "Simple animations", pros: "Supports animation, small for simple graphics", cons: "Limited to 256 colors, poor for photos", color: "#22c55e" },
              { format: "SVG (.svg)", best: "Logos, icons, illustrations", pros: "Scales to any size without blur, tiny file size", cons: "Not for photos, can be complex", color: "#f59e0b" },
              { format: "WebP (.webp)", best: "Modern web images", pros: "Best compression, supports transparency & animation", cons: "Older browsers may not support it", color: "#8b5cf6" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.format}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: alpha(item.color, 0.05), border: `1px solid ${alpha(item.color, 0.15)}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color, mb: 1 }}>{item.format}</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}><strong>Best for:</strong> {item.best}</Typography>
                  <Typography variant="body2" sx={{ mb: 0.5, color: "#22c55e" }}>✓ {item.pros}</Typography>
                  <Typography variant="body2" sx={{ color: "#ef4444" }}>✗ {item.cons}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Figure and Figcaption
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Use <code style={{ background: alpha("#8b5cf6", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;figure&gt;</code> and 
            <code style={{ background: alpha("#8b5cf6", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;figcaption&gt;</code> to 
            add captions to images:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<figure>
    <img src="sunset.jpg" alt="A colorful sunset over the ocean">
    <figcaption>Sunset at Malibu Beach, California</figcaption>
</figure>

<!-- Great for:
     - Photos with captions
     - Diagrams with explanations
     - Charts with descriptions
-->`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Lazy Loading Images
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            For better page performance, use <code style={{ background: alpha("#8b5cf6", 0.1), padding: "2px 6px", borderRadius: 4 }}>loading="lazy"</code> to 
            delay loading images until they're about to scroll into view:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!-- Lazy load images below the fold -->
<img src="photo1.jpg" alt="Photo 1" loading="lazy">
<img src="photo2.jpg" alt="Photo 2" loading="lazy">
<img src="photo3.jpg" alt="Photo 3" loading="lazy">

<!-- Don't lazy load images that are immediately visible! -->
<img src="hero-banner.jpg" alt="Welcome banner" loading="eager">`}
            </Box>
          </Paper>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Video Element
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            The <code style={{ background: alpha("#8b5cf6", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;video&gt;</code> tag 
            embeds video files directly on your page:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 2 }}>Video Examples</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!-- Basic video with controls -->
<video src="movie.mp4" controls width="640" height="360">
    Your browser doesn't support video.
</video>

<!-- Video with multiple sources (fallbacks) -->
<video controls width="640" height="360">
    <source src="movie.webm" type="video/webm">
    <source src="movie.mp4" type="video/mp4">
    Your browser doesn't support video.
</video>

<!-- Video with all options -->
<video 
    controls           <!-- Show play/pause controls -->
    autoplay           <!-- Start playing automatically -->
    muted              <!-- Start muted (required for autoplay) -->
    loop               <!-- Loop the video -->
    poster="thumb.jpg" <!-- Thumbnail before playing -->
    width="640"
    height="360"
>
    <source src="movie.mp4" type="video/mp4">
</video>`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Audio Element
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!-- Basic audio with controls -->
<audio src="song.mp3" controls>
    Your browser doesn't support audio.
</audio>

<!-- Audio with multiple sources -->
<audio controls>
    <source src="song.ogg" type="audio/ogg">
    <source src="song.mp3" type="audio/mpeg">
    Your browser doesn't support audio.
</audio>`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Embedding YouTube Videos
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            To embed YouTube (or Vimeo) videos, use an <code style={{ background: alpha("#8b5cf6", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;iframe&gt;</code>. 
            YouTube provides the embed code for you:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 2 }}>YouTube Embed Example</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!-- YouTube embed (get this from Share → Embed on YouTube) -->
<iframe 
    width="560" 
    height="315" 
    src="https://www.youtube.com/embed/VIDEO_ID_HERE"
    title="YouTube video player"
    frameborder="0"
    allow="accelerometer; autoplay; clipboard-write; encrypted-media; 
           gyroscope; picture-in-picture"
    allowfullscreen>
</iframe>

<!-- How to get the embed code:
     1. Go to the YouTube video
     2. Click "Share" button
     3. Click "Embed"
     4. Copy the iframe code
-->`}
            </Box>
          </Paper>

          <Alert severity="info" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>💡 Responsive Embeds</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Iframes have fixed sizes by default. To make them responsive, wrap them in a container with CSS (we'll cover this 
              in the responsive design module) or use percentage widths like <code>width="100%"</code>.
            </Typography>
          </Alert>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            ✏️ Try It Yourself
          </Typography>
          
          <List dense>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#8b5cf6" }} /></ListItemIcon>
              <ListItemText primary="Add an image to your page with proper alt text" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#8b5cf6" }} /></ListItemIcon>
              <ListItemText primary="Create a figure with an image and caption" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#8b5cf6" }} /></ListItemIcon>
              <ListItemText primary="Embed a YouTube video using an iframe" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#8b5cf6" }} /></ListItemIcon>
              <ListItemText primary="Add the loading='lazy' attribute to images below the first screen" />
            </ListItem>
          </List>
        </Paper>

        {/* ==================== MODULE 6: FORMS & USER INPUT ==================== */}
        <Paper
          id="module-6"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#ec4899", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 6" sx={{ bgcolor: alpha("#ec4899", 0.15), color: "#ec4899", fontWeight: 700 }} />
            <Chip label="Beginner" size="small" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
          </Box>
          
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#ec4899" }}>
            📝 Forms & User Input
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            Forms are how users interact with websites—login pages, search bars, contact forms, surveys, and checkout pages 
            all use HTML forms. This is one of the most important HTML concepts to master!
          </Typography>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            Basic Form Structure
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Every form starts with the <code style={{ background: alpha("#ec4899", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;form&gt;</code> tag:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#ec4899", 0.05), border: `1px solid ${alpha("#ec4899", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ec4899", mb: 2 }}>Basic Form Example</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<form action="/submit" method="POST">
    <label for="name">Your Name:</label>
    <input type="text" id="name" name="name">
    
    <label for="email">Email:</label>
    <input type="email" id="email" name="email">
    
    <button type="submit">Submit</button>
</form>

<!-- action: Where the form data is sent -->
<!-- method: How data is sent (GET or POST) -->`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            Labels and Inputs
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Always pair inputs with <code style={{ background: alpha("#ec4899", 0.1), padding: "2px 6px", borderRadius: 4 }}>&lt;label&gt;</code> tags! 
            Labels improve accessibility and let users click the label to focus the input:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#ec4899", 0.05), border: `1px solid ${alpha("#ec4899", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!-- Method 1: Using "for" attribute (recommended) -->
<label for="username">Username:</label>
<input type="text" id="username" name="username">

<!-- Method 2: Wrapping the input inside the label -->
<label>
    Username:
    <input type="text" name="username">
</label>

<!-- The "for" attribute must match the input's "id" -->`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            Input Types
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            HTML5 provides many input types. Using the right type gives you built-in validation and better mobile keyboards:
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { type: "text", desc: "Single line text", example: 'type="text"' },
              { type: "email", desc: "Email with validation", example: 'type="email"' },
              { type: "password", desc: "Hidden characters", example: 'type="password"' },
              { type: "number", desc: "Numeric input", example: 'type="number"' },
              { type: "tel", desc: "Phone number", example: 'type="tel"' },
              { type: "url", desc: "Website URL", example: 'type="url"' },
              { type: "date", desc: "Date picker", example: 'type="date"' },
              { type: "time", desc: "Time picker", example: 'type="time"' },
              { type: "color", desc: "Color picker", example: 'type="color"' },
              { type: "range", desc: "Slider", example: 'type="range"' },
              { type: "file", desc: "File upload", example: 'type="file"' },
              { type: "search", desc: "Search box", example: 'type="search"' },
            ].map((item) => (
              <Grid item xs={6} sm={4} md={3} key={item.type}>
                <Paper sx={{ p: 1.5, height: "100%", borderRadius: 2, bgcolor: alpha("#ec4899", 0.03), border: `1px solid ${alpha("#ec4899", 0.1)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ec4899", mb: 0.5 }}>{item.type}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.75rem" }}>{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#ec4899", 0.05), border: `1px solid ${alpha("#ec4899", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ec4899", mb: 2 }}>Input Types in Action</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<label for="email">Email:</label>
<input type="email" id="email" name="email" placeholder="you@example.com">

<label for="password">Password:</label>
<input type="password" id="password" name="password">

<label for="age">Age:</label>
<input type="number" id="age" name="age" min="18" max="100">

<label for="birthday">Birthday:</label>
<input type="date" id="birthday" name="birthday">

<label for="website">Website:</label>
<input type="url" id="website" name="website" placeholder="https://">

<label for="volume">Volume:</label>
<input type="range" id="volume" name="volume" min="0" max="100">

<label for="color">Favorite Color:</label>
<input type="color" id="color" name="color" value="#ff0000">`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            Input Attributes
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { attr: "placeholder", desc: "Hint text shown when empty", example: 'placeholder="Enter name"' },
              { attr: "required", desc: "Field must be filled", example: "required" },
              { attr: "disabled", desc: "Cannot be edited", example: "disabled" },
              { attr: "readonly", desc: "Can't edit but can select", example: "readonly" },
              { attr: "value", desc: "Default/initial value", example: 'value="Default"' },
              { attr: "maxlength", desc: "Maximum characters", example: "maxlength=\"50\"" },
              { attr: "min / max", desc: "Number range limits", example: 'min="0" max="100"' },
              { attr: "pattern", desc: "Regex validation", example: 'pattern="[A-Za-z]+"' },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.attr}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: alpha("#ec4899", 0.03), border: `1px solid ${alpha("#ec4899", 0.1)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, fontFamily: "monospace", color: "#ec4899", mb: 0.5 }}>{item.attr}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.75rem", mb: 1 }}>{item.desc}</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#8b5cf6" }}>{item.example}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            Checkboxes and Radio Buttons
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#ec4899", 0.05), border: `1px solid ${alpha("#ec4899", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!-- Checkboxes (select multiple) -->
<p>Choose your interests:</p>
<label>
    <input type="checkbox" name="interests" value="coding"> Coding
</label>
<label>
    <input type="checkbox" name="interests" value="music"> Music
</label>
<label>
    <input type="checkbox" name="interests" value="sports"> Sports
</label>

<!-- Radio Buttons (select ONE only) -->
<p>Choose your experience level:</p>
<label>
    <input type="radio" name="level" value="beginner"> Beginner
</label>
<label>
    <input type="radio" name="level" value="intermediate"> Intermediate
</label>
<label>
    <input type="radio" name="level" value="advanced"> Advanced
</label>

<!-- Note: Radio buttons with the same "name" are grouped together -->`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            Dropdown Selects
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#ec4899", 0.05), border: `1px solid ${alpha("#ec4899", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!-- Basic dropdown -->
<label for="country">Country:</label>
<select id="country" name="country">
    <option value="">-- Select a country --</option>
    <option value="us">United States</option>
    <option value="uk">United Kingdom</option>
    <option value="ca">Canada</option>
    <option value="au">Australia</option>
</select>

<!-- Dropdown with groups -->
<label for="car">Choose a car:</label>
<select id="car" name="car">
    <optgroup label="Swedish Cars">
        <option value="volvo">Volvo</option>
        <option value="saab">Saab</option>
    </optgroup>
    <optgroup label="German Cars">
        <option value="mercedes">Mercedes</option>
        <option value="audi">Audi</option>
    </optgroup>
</select>

<!-- Multi-select (hold Ctrl/Cmd to select multiple) -->
<select name="skills" multiple size="4">
    <option value="html">HTML</option>
    <option value="css">CSS</option>
    <option value="js">JavaScript</option>
    <option value="python">Python</option>
</select>`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            Textareas (Multi-line Text)
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#ec4899", 0.05), border: `1px solid ${alpha("#ec4899", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<label for="message">Your Message:</label>
<textarea 
    id="message" 
    name="message" 
    rows="5" 
    cols="40"
    placeholder="Write your message here..."
></textarea>

<!-- rows = visible height (lines) -->
<!-- cols = visible width (characters) -->`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            Buttons
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#ec4899", 0.05), border: `1px solid ${alpha("#ec4899", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!-- Submit button (submits the form) -->
<button type="submit">Submit Form</button>

<!-- Reset button (clears all form fields) -->
<button type="reset">Clear Form</button>

<!-- Regular button (for JavaScript actions) -->
<button type="button">Click Me</button>

<!-- Alternative: input-style buttons -->
<input type="submit" value="Submit">
<input type="reset" value="Reset">
<input type="button" value="Click Me">`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            Organizing Forms with Fieldset
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#ec4899", 0.05), border: `1px solid ${alpha("#ec4899", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<form>
    <fieldset>
        <legend>Personal Information</legend>
        
        <label for="fname">First Name:</label>
        <input type="text" id="fname" name="fname"><br><br>
        
        <label for="lname">Last Name:</label>
        <input type="text" id="lname" name="lname">
    </fieldset>
    
    <fieldset>
        <legend>Contact Information</legend>
        
        <label for="email">Email:</label>
        <input type="email" id="email" name="email"><br><br>
        
        <label for="phone">Phone:</label>
        <input type="tel" id="phone" name="phone">
    </fieldset>
    
    <button type="submit">Register</button>
</form>`}
            </Box>
          </Paper>

          <Alert severity="success" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Complete Contact Form Example</AlertTitle>
            <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
              <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#22c55e", 0.1), p: 2, borderRadius: 1, mt: 1, overflowX: "auto" }}>
{`<form action="/contact" method="POST">
    <label for="name">Name: *</label>
    <input type="text" id="name" name="name" required>
    
    <label for="email">Email: *</label>
    <input type="email" id="email" name="email" required>
    
    <label for="subject">Subject:</label>
    <select id="subject" name="subject">
        <option value="general">General Inquiry</option>
        <option value="support">Support</option>
        <option value="feedback">Feedback</option>
    </select>
    
    <label for="message">Message: *</label>
    <textarea id="message" name="message" rows="5" required></textarea>
    
    <label>
        <input type="checkbox" name="newsletter" value="yes">
        Subscribe to newsletter
    </label>
    
    <button type="submit">Send Message</button>
</form>`}
              </Box>
            </Typography>
          </Alert>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            ✏️ Try It Yourself
          </Typography>
          
          <List dense>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#ec4899" }} /></ListItemIcon>
              <ListItemText primary="Create a login form with email, password, and submit button" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#ec4899" }} /></ListItemIcon>
              <ListItemText primary="Build a survey form with radio buttons for rating (1-5 stars)" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#ec4899" }} /></ListItemIcon>
              <ListItemText primary="Create a registration form with fieldsets for 'Account' and 'Profile' sections" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#ec4899" }} /></ListItemIcon>
              <ListItemText primary="Add validation with required, minlength, and pattern attributes" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#ec4899" }} /></ListItemIcon>
              <ListItemText primary="Create a dropdown to select your country" />
            </ListItem>
          </List>
        </Paper>

        {/* ==================== MODULE 7: CSS BASICS ==================== */}
        <Paper
          id="module-7"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#264de4", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 7" sx={{ bgcolor: alpha("#264de4", 0.15), color: "#264de4", fontWeight: 700 }} />
            <Chip label="Beginner" size="small" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
          </Box>
          
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#264de4" }}>
            🎨 CSS Basics
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            CSS (Cascading Style Sheets) is what makes websites beautiful! While HTML provides structure, CSS controls the 
            visual presentation—colors, fonts, spacing, layout, and more. Let's transform your plain HTML into stunning web pages!
          </Typography>

          <Alert severity="info" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>What CSS Does</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              <strong>HTML = Structure</strong> (the skeleton) → <strong>CSS = Style</strong> (the clothing, makeup, and accessories)
              <br />
              Think of HTML as building a house's frame, and CSS as painting the walls, choosing furniture, and decorating!
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#264de4" }}>
            Three Ways to Add CSS
          </Typography>

          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444", mb: 2 }}>1. Inline CSS</Typography>
                <Typography variant="body2" sx={{ mb: 2, color: "text.secondary" }}>
                  Styles directly on an element using the <code>style</code> attribute. Quick but not recommended for large projects.
                </Typography>
                <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1.5, borderRadius: 1, overflowX: "auto" }}>
{`<p style="color: red; 
   font-size: 20px;">
  Red text!
</p>`}
                </Box>
                <Chip label="❌ Not Recommended" size="small" sx={{ mt: 2, bgcolor: alpha("#ef4444", 0.15), color: "#ef4444" }} />
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b", mb: 2 }}>2. Internal CSS</Typography>
                <Typography variant="body2" sx={{ mb: 2, color: "text.secondary" }}>
                  Styles in a <code>&lt;style&gt;</code> tag inside the <code>&lt;head&gt;</code>. Good for single-page experiments.
                </Typography>
                <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1.5, borderRadius: 1, overflowX: "auto" }}>
{`<head>
  <style>
    p {
      color: blue;
    }
  </style>
</head>`}
                </Box>
                <Chip label="⚠️ OK for Learning" size="small" sx={{ mt: 2, bgcolor: alpha("#f59e0b", 0.15), color: "#f59e0b" }} />
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>3. External CSS</Typography>
                <Typography variant="body2" sx={{ mb: 2, color: "text.secondary" }}>
                  Styles in a separate <code>.css</code> file linked to HTML. Best practice for real projects!
                </Typography>
                <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 1.5, borderRadius: 1, overflowX: "auto" }}>
{`<!-- In HTML -->
<link rel="stylesheet" 
      href="styles.css">

/* In styles.css */
p { color: green; }`}
                </Box>
                <Chip label="✅ Best Practice" size="small" sx={{ mt: 2, bgcolor: alpha("#22c55e", 0.15), color: "#22c55e" }} />
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#264de4" }}>
            CSS Syntax
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            CSS follows a simple pattern: <strong>selector</strong> + <strong>property</strong> + <strong>value</strong>
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#264de4", 0.05), border: `1px solid ${alpha("#264de4", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* CSS Syntax Breakdown */

selector {
    property: value;
    another-property: another-value;
}

/* Real Examples */

h1 {
    color: blue;           /* Text color */
    font-size: 32px;       /* Font size */
    text-align: center;    /* Alignment */
}

p {
    color: #333333;        /* Hex color */
    line-height: 1.6;      /* Line spacing */
    margin-bottom: 20px;   /* Space below */
}

/* Comments in CSS look like this */`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#264de4" }}>
            CSS Selectors
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Selectors tell CSS <strong>which elements</strong> to style. Here are the most common ones:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#264de4", 0.05), border: `1px solid ${alpha("#264de4", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* 1. Element Selector - targets all elements of that type */
p { color: black; }
h1 { font-size: 36px; }
a { text-decoration: none; }

/* 2. Class Selector - targets elements with that class */
/* Use class for styling multiple elements */
.highlight { background: yellow; }
.btn { padding: 10px 20px; }
.error { color: red; }

/* HTML: <p class="highlight">Highlighted text</p> */

/* 3. ID Selector - targets ONE specific element */
/* Use sparingly! IDs should be unique */
#header { background: navy; }
#main-title { font-size: 48px; }

/* HTML: <div id="header">...</div> */

/* 4. Universal Selector - targets EVERYTHING */
* { margin: 0; padding: 0; }

/* 5. Descendant Selector - targets nested elements */
nav a { color: white; }        /* Links inside nav */
.card p { font-size: 14px; }   /* Paragraphs inside .card */

/* 6. Multiple Selectors - same styles for multiple elements */
h1, h2, h3 { font-family: Arial; }

/* 7. Attribute Selector */
input[type="text"] { border: 1px solid gray; }
a[href^="https"] { color: green; }  /* Links starting with https */`}
            </Box>
          </Paper>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { selector: "element", example: "p, h1, div", specificity: "0,0,1", desc: "Targets all elements of that type" },
              { selector: ".class", example: ".btn, .card", specificity: "0,1,0", desc: "Targets elements with that class" },
              { selector: "#id", example: "#header, #nav", specificity: "1,0,0", desc: "Targets ONE unique element" },
              { selector: "*", example: "*", specificity: "0,0,0", desc: "Targets all elements" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.selector}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: alpha("#264de4", 0.03), border: `1px solid ${alpha("#264de4", 0.1)}` }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, fontFamily: "monospace", color: "#264de4", mb: 0.5 }}>{item.selector}</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", color: "text.secondary" }}>{item.example}</Typography>
                  <Typography variant="body2" sx={{ mt: 1, fontSize: "0.8rem" }}>{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#264de4" }}>
            Colors in CSS
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#264de4", 0.05), border: `1px solid ${alpha("#264de4", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* 1. Named Colors (140+ built-in names) */
color: red;
color: blue;
color: tomato;
color: rebeccapurple;

/* 2. Hexadecimal (most common) */
color: #ff0000;        /* Red */
color: #00ff00;        /* Green */
color: #0000ff;        /* Blue */
color: #333333;        /* Dark gray */
color: #f5f5f5;        /* Light gray */
color: #fff;           /* Shorthand for #ffffff (white) */

/* 3. RGB (Red, Green, Blue: 0-255) */
color: rgb(255, 0, 0);       /* Red */
color: rgb(0, 128, 0);       /* Green */
color: rgb(51, 51, 51);      /* Dark gray */

/* 4. RGBA (RGB + Alpha/Opacity: 0-1) */
color: rgba(0, 0, 0, 0.5);   /* 50% transparent black */
background: rgba(255, 255, 255, 0.9);  /* 90% opaque white */

/* 5. HSL (Hue, Saturation, Lightness) */
color: hsl(0, 100%, 50%);    /* Red */
color: hsl(120, 100%, 25%);  /* Dark green */
color: hsl(240, 100%, 50%);  /* Blue */

/* 6. HSLA (HSL + Alpha) */
color: hsla(0, 100%, 50%, 0.5);  /* 50% transparent red */`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#264de4" }}>
            Text Styling
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#264de4", 0.05), border: `1px solid ${alpha("#264de4", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Font Properties */
font-family: Arial, Helvetica, sans-serif;  /* Font stack */
font-family: 'Times New Roman', serif;
font-family: 'Courier New', monospace;

font-size: 16px;          /* Pixels */
font-size: 1.5rem;        /* Relative to root (recommended) */
font-size: 1.2em;         /* Relative to parent */

font-weight: normal;      /* 400 */
font-weight: bold;        /* 700 */
font-weight: 100;         /* Thin */
font-weight: 900;         /* Black */

font-style: normal;
font-style: italic;

/* Text Properties */
color: #333;                  /* Text color */
text-align: left;             /* left, center, right, justify */
text-decoration: none;        /* Remove underlines from links */
text-decoration: underline;
text-decoration: line-through;

text-transform: uppercase;    /* ALL CAPS */
text-transform: lowercase;    /* all lowercase */
text-transform: capitalize;   /* First Letter Caps */

line-height: 1.6;            /* Line spacing (unitless recommended) */
letter-spacing: 2px;          /* Space between letters */
word-spacing: 5px;            /* Space between words */

/* Google Fonts (free!) */
/* 1. Go to fonts.google.com
   2. Select a font
   3. Copy the <link> tag to your HTML <head>
   4. Use the font-family in CSS */
   
/* In HTML head: */
<link href="https://fonts.googleapis.com/css2?family=Roboto&display=swap" rel="stylesheet">

/* In CSS: */
body { font-family: 'Roboto', sans-serif; }`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#264de4" }}>
            Backgrounds
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#264de4", 0.05), border: `1px solid ${alpha("#264de4", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Solid Color Background */
background-color: #f5f5f5;
background-color: rgba(0, 0, 0, 0.8);

/* Background Image */
background-image: url('image.jpg');
background-image: url('../images/hero.png');

/* Background Size */
background-size: cover;      /* Cover entire element */
background-size: contain;    /* Fit without cropping */
background-size: 100px 50px; /* Specific size */

/* Background Position */
background-position: center;
background-position: top right;
background-position: 50% 50%;

/* Background Repeat */
background-repeat: no-repeat;
background-repeat: repeat-x;  /* Repeat horizontally */
background-repeat: repeat-y;  /* Repeat vertically */

/* Background Attachment */
background-attachment: fixed;   /* Parallax effect */
background-attachment: scroll;  /* Normal scrolling */

/* Shorthand (all in one line) */
background: #333 url('bg.jpg') no-repeat center/cover;

/* Gradients */
background: linear-gradient(to right, #ff0000, #0000ff);
background: linear-gradient(45deg, #e91e63, #673ab7);
background: linear-gradient(to bottom, transparent, black);
background: radial-gradient(circle, white, gray);`}
            </Box>
          </Paper>

          <Alert severity="success" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Your First External Stylesheet</AlertTitle>
            <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
              <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#22c55e", 0.1), p: 2, borderRadius: 1, mt: 1, overflowX: "auto" }}>
{`/* styles.css */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 16px;
    line-height: 1.6;
    color: #333;
    background-color: #f5f5f5;
}

h1, h2, h3 {
    color: #264de4;
    margin-bottom: 1rem;
}

a {
    color: #e91e63;
    text-decoration: none;
}

a:hover {
    text-decoration: underline;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}`}
              </Box>
            </Typography>
          </Alert>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            ✏️ Try It Yourself
          </Typography>
          
          <List dense>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#264de4" }} /></ListItemIcon>
              <ListItemText primary="Create a styles.css file and link it to your HTML page" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#264de4" }} /></ListItemIcon>
              <ListItemText primary="Style all paragraphs with a custom font, color, and line-height" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#264de4" }} /></ListItemIcon>
              <ListItemText primary="Create a .highlight class and apply it to some text" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#264de4" }} /></ListItemIcon>
              <ListItemText primary="Add a gradient background to your page body" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#264de4" }} /></ListItemIcon>
              <ListItemText primary="Import a Google Font and use it for your headings" />
            </ListItem>
          </List>
        </Paper>

        {/* ==================== MODULE 8: BOX MODEL & LAYOUT ==================== */}
        <Paper
          id="module-8"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#14b8a6", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 8" sx={{ bgcolor: alpha("#14b8a6", 0.15), color: "#14b8a6", fontWeight: 700 }} />
            <Chip label="Intermediate" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.15), color: "#f59e0b", fontWeight: 600 }} />
          </Box>
          
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#14b8a6" }}>
            📦 Box Model & Layout
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            The CSS Box Model is the foundation of all web layout. Every element on a web page is a rectangular box, and 
            understanding how these boxes work is essential for controlling spacing and positioning.
          </Typography>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
            The Box Model Explained
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Every HTML element is wrapped in a box with four layers (from inside to outside):
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { layer: "Content", desc: "The actual content (text, image, etc.)", color: "#3b82f6", order: 1 },
              { layer: "Padding", desc: "Space between content and border (inside)", color: "#22c55e", order: 2 },
              { layer: "Border", desc: "The edge/outline of the box", color: "#f59e0b", order: 3 },
              { layer: "Margin", desc: "Space outside the border (between elements)", color: "#ef4444", order: 4 },
            ].map((item) => (
              <Grid item xs={6} sm={3} key={item.layer}>
                <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, bgcolor: alpha(item.color, 0.1), border: `2px solid ${item.color}` }}>
                  <Typography variant="h3" sx={{ fontWeight: 800, color: item.color, mb: 0.5 }}>{item.order}</Typography>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: item.color }}>{item.layer}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#14b8a6", 0.05), border: `1px solid ${alpha("#14b8a6", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#14b8a6", mb: 2 }}>Visual Box Model</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`┌─────────────────────────────────────────────────┐
│                    MARGIN                       │  ← Space outside (transparent)
│  ┌───────────────────────────────────────────┐  │
│  │                  BORDER                   │  │  ← The visible edge
│  │  ┌─────────────────────────────────────┐  │  │
│  │  │              PADDING                │  │  │  ← Space inside border
│  │  │  ┌───────────────────────────────┐  │  │  │
│  │  │  │                               │  │  │  │
│  │  │  │           CONTENT             │  │  │  │  ← Your actual content
│  │  │  │        (text, images)         │  │  │  │
│  │  │  │                               │  │  │  │
│  │  │  └───────────────────────────────┘  │  │  │
│  │  └─────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
            Width and Height
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#14b8a6", 0.05), border: `1px solid ${alpha("#14b8a6", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Fixed dimensions */
width: 300px;
height: 200px;

/* Percentage (relative to parent) */
width: 50%;        /* Half of parent's width */
width: 100%;       /* Full width of parent */

/* Viewport units */
width: 100vw;      /* 100% of viewport width */
height: 100vh;     /* 100% of viewport height */
width: 50vw;       /* Half the screen width */

/* Min and Max constraints */
min-width: 200px;  /* Never smaller than 200px */
max-width: 1200px; /* Never larger than 1200px */
min-height: 100px;
max-height: 500px;

/* Auto (default behavior) */
width: auto;       /* Browser calculates */
height: auto;      /* Expands to fit content */`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
            Padding
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#14b8a6", 0.05), border: `1px solid ${alpha("#14b8a6", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Individual sides */
padding-top: 20px;
padding-right: 15px;
padding-bottom: 20px;
padding-left: 15px;

/* Shorthand - 4 values (top, right, bottom, left - clockwise) */
padding: 20px 15px 20px 15px;

/* Shorthand - 2 values (top/bottom, left/right) */
padding: 20px 15px;

/* Shorthand - 1 value (all sides) */
padding: 20px;

/* Shorthand - 3 values (top, left/right, bottom) */
padding: 10px 20px 30px;

/* Common pattern for cards/boxes */
.card {
    padding: 24px;           /* Equal padding all around */
}

.button {
    padding: 12px 24px;      /* More horizontal padding */
}`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
            Margin
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#14b8a6", 0.05), border: `1px solid ${alpha("#14b8a6", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Same syntax as padding */
margin-top: 20px;
margin-right: auto;
margin-bottom: 20px;
margin-left: auto;

/* Shorthand works the same way */
margin: 20px;              /* All sides */
margin: 20px 40px;         /* Top/bottom, left/right */
margin: 10px 20px 30px 40px; /* All four sides */

/* AUTO - The magic centering trick! */
.container {
    width: 1200px;
    margin: 0 auto;        /* Center horizontally! */
}

/* Negative margins (pull elements) */
margin-top: -20px;         /* Pull up by 20px */
margin-left: -10px;        /* Pull left by 10px */

/* Reset default margins */
h1, h2, h3, p {
    margin: 0;             /* Remove browser defaults */
}`}
            </Box>
          </Paper>

          <Alert severity="warning" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Margin Collapse!</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              When two vertical margins touch, they <strong>collapse</strong> into one margin (the larger one wins). 
              This doesn't happen horizontally or with padding. It's a common source of confusion for beginners!
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
            Border
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#14b8a6", 0.05), border: `1px solid ${alpha("#14b8a6", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Border properties */
border-width: 2px;
border-style: solid;       /* solid, dashed, dotted, double, none */
border-color: #333;

/* Shorthand (width style color) */
border: 2px solid #333;

/* Individual sides */
border-top: 3px solid red;
border-bottom: 1px dashed gray;
border-left: none;

/* Border radius (rounded corners!) */
border-radius: 8px;        /* All corners */
border-radius: 50%;        /* Perfect circle (if square element) */
border-radius: 10px 0 10px 0;  /* Diagonal corners */

/* Top-left, top-right, bottom-right, bottom-left */
border-radius: 20px 20px 0 0;  /* Rounded top only */

/* Common patterns */
.card {
    border: 1px solid #e0e0e0;
    border-radius: 12px;
}

.avatar {
    border-radius: 50%;     /* Circle image */
}

.button {
    border: none;
    border-radius: 4px;
}`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
            Box-Sizing (Important!)
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#14b8a6", 0.05), border: `1px solid ${alpha("#14b8a6", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* The Problem:
   By default, width/height only set the CONTENT size.
   Padding and border are ADDED to that!
   
   width: 300px + padding: 20px + border: 2px = 344px total! 😱
*/

/* content-box (default - confusing behavior) */
box-sizing: content-box;

/* border-box (MUCH better - use this!) */
box-sizing: border-box;
/* Now width: 300px means 300px TOTAL including padding and border */

/* Best practice: Apply to everything! */
*, *::before, *::after {
    box-sizing: border-box;
}

/* Or the newer reset: */
* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
            Display Property
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            The <code style={{ background: alpha("#14b8a6", 0.1), padding: "2px 6px", borderRadius: 4 }}>display</code> property 
            controls how an element behaves in the layout:
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { display: "block", examples: "div, p, h1-h6, section", behavior: "Takes full width, starts on new line", color: "#3b82f6" },
              { display: "inline", examples: "span, a, strong, em", behavior: "Only takes needed width, stays in line", color: "#22c55e" },
              { display: "inline-block", examples: "Custom", behavior: "Inline but can have width/height", color: "#f59e0b" },
              { display: "none", examples: "Hidden elements", behavior: "Completely hidden (not rendered)", color: "#ef4444" },
            ].map((item) => (
              <Grid item xs={12} sm={6} key={item.display}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: alpha(item.color, 0.05), border: `1px solid ${alpha(item.color, 0.15)}` }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, fontFamily: "monospace", color: item.color, mb: 1 }}>display: {item.display}</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}><strong>Examples:</strong> {item.examples}</Typography>
                  <Typography variant="body2" color="text.secondary">{item.behavior}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#14b8a6", 0.05), border: `1px solid ${alpha("#14b8a6", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Block: Full width, stacks vertically */
div { display: block; }

/* Inline: Flows with text, can't set width/height */
span { display: inline; }

/* Inline-block: Best of both! */
.nav-link {
    display: inline-block;
    padding: 10px 20px;     /* Now padding works! */
    width: 100px;           /* Now width works! */
}

/* None: Hide completely */
.hidden { display: none; }

/* Common use case: Horizontal nav */
nav li {
    display: inline-block;  /* Side by side */
    margin-right: 20px;
}`}
            </Box>
          </Paper>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            ✏️ Try It Yourself
          </Typography>
          
          <List dense>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#14b8a6" }} /></ListItemIcon>
              <ListItemText primary="Create a card with padding, border, and border-radius" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#14b8a6" }} /></ListItemIcon>
              <ListItemText primary="Center a container horizontally using margin: 0 auto" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#14b8a6" }} /></ListItemIcon>
              <ListItemText primary="Add box-sizing: border-box to your CSS reset" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#14b8a6" }} /></ListItemIcon>
              <ListItemText primary="Create a horizontal navigation using display: inline-block" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#14b8a6" }} /></ListItemIcon>
              <ListItemText primary="Open browser DevTools (F12) and inspect the box model of any element" />
            </ListItem>
          </List>
        </Paper>

        {/* ==================== MODULE 9: FLEXBOX ==================== */}
        <Paper
          id="module-9"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#f59e0b", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 9" sx={{ bgcolor: alpha("#f59e0b", 0.15), color: "#f59e0b", fontWeight: 700 }} />
            <Chip label="Intermediate" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.15), color: "#f59e0b", fontWeight: 600 }} />
          </Box>
          
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#f59e0b" }}>
            ↔️ Flexbox
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            Flexbox (Flexible Box Layout) revolutionized CSS layout. It makes centering, spacing, and aligning elements 
            incredibly easy. If you learn one layout system, make it Flexbox—you'll use it every single day!
          </Typography>

          <Alert severity="success" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Why Flexbox is Amazing</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Before Flexbox, centering a div was a nightmare of hacks. Now it's just 3 lines of CSS:
              <code style={{ display: "block", marginTop: 8, padding: "8px", background: "rgba(0,0,0,0.1)", borderRadius: 4 }}>
                display: flex; justify-content: center; align-items: center;
              </code>
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            Flex Container vs Flex Items
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Flexbox works with two concepts: the <strong>container</strong> (parent) and <strong>items</strong> (children).
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!-- HTML Structure -->
<div class="container">     <!-- Flex Container (parent) -->
    <div class="item">1</div>   <!-- Flex Item (child) -->
    <div class="item">2</div>   <!-- Flex Item (child) -->
    <div class="item">3</div>   <!-- Flex Item (child) -->
</div>

/* CSS */
.container {
    display: flex;          /* This activates Flexbox! */
}

/* Now all direct children become flex items
   and automatically line up in a row */`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            Flex Direction
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Controls the <strong>main axis</strong>—the direction items flow:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Row (default) - items go left to right */
flex-direction: row;
/* [1] [2] [3] → */

/* Row Reverse - items go right to left */
flex-direction: row-reverse;
/* ← [3] [2] [1] */

/* Column - items stack top to bottom */
flex-direction: column;
/* [1]
   [2]
   [3]
   ↓   */

/* Column Reverse - items stack bottom to top */
flex-direction: column-reverse;
/* [3]
   [2]
   [1]
   ↑   */`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            Justify Content (Main Axis)
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Aligns items along the <strong>main axis</strong> (horizontal by default):
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* flex-start (default) - pack items at the start */
justify-content: flex-start;
/* |[1][2][3]          | */

/* flex-end - pack items at the end */
justify-content: flex-end;
/* |          [1][2][3]| */

/* center - pack items in the center */
justify-content: center;
/* |     [1][2][3]     | */

/* space-between - first item at start, last at end */
justify-content: space-between;
/* |[1]    [2]    [3]| */

/* space-around - equal space around each item */
justify-content: space-around;
/* | [1]  [2]  [3] | */

/* space-evenly - equal space between everything */
justify-content: space-evenly;
/* |  [1]  [2]  [3]  | */`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            Align Items (Cross Axis)
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Aligns items along the <strong>cross axis</strong> (vertical by default):
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* stretch (default) - items stretch to fill container height */
align-items: stretch;

/* flex-start - items at the top */
align-items: flex-start;
/* [1][2][3]
            
             */

/* flex-end - items at the bottom */
align-items: flex-end;
/*
            
   [1][2][3] */

/* center - items vertically centered */
align-items: center;
/*
   [1][2][3]
             */

/* baseline - align by text baseline */
align-items: baseline;`}
            </Box>
          </Paper>

          <Alert severity="info" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>🎯 The Perfect Center</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              To center something both horizontally AND vertically:
              <Box component="pre" sx={{ fontSize: "0.8rem", fontFamily: "monospace", bgcolor: alpha("#3b82f6", 0.1), p: 1.5, borderRadius: 1, mt: 1 }}>
{`.center-me {
    display: flex;
    justify-content: center;  /* horizontal */
    align-items: center;      /* vertical */
    height: 100vh;            /* full viewport height */
}`}
              </Box>
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            Flex Wrap
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* nowrap (default) - all items on one line, may overflow */
flex-wrap: nowrap;

/* wrap - items wrap to next line when needed */
flex-wrap: wrap;
/* [1][2][3][4]
   [5][6][7]    */

/* wrap-reverse - wrap but in reverse order */
flex-wrap: wrap-reverse;
/* [5][6][7]
   [1][2][3][4] */`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            Gap
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* gap - space between items (modern CSS) */
gap: 20px;               /* Same gap everywhere */
gap: 20px 10px;          /* Row gap, column gap */
row-gap: 20px;           /* Only between rows */
column-gap: 10px;        /* Only between columns */

.container {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;           /* Clean spacing! */
}`}
            </Box>
          </Paper>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            Flex Item Properties
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            These properties go on the <strong>children</strong> (flex items), not the container:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* flex-grow: How much item grows relative to others */
flex-grow: 0;     /* Default - don't grow */
flex-grow: 1;     /* Take up available space */
flex-grow: 2;     /* Take up 2x more than flex-grow: 1 */

/* flex-shrink: How much item shrinks when space is tight */
flex-shrink: 1;   /* Default - can shrink */
flex-shrink: 0;   /* Don't shrink! */

/* flex-basis: Initial size before growing/shrinking */
flex-basis: auto;    /* Default - use width/content */
flex-basis: 200px;   /* Start at 200px */
flex-basis: 25%;     /* Start at 25% of container */

/* Shorthand: flex: grow shrink basis */
flex: 1;             /* Same as: flex: 1 1 0% */
flex: 0 0 200px;     /* Don't grow, don't shrink, stay 200px */
flex: 1 0 auto;      /* Grow, don't shrink, auto basis */

/* align-self: Override align-items for ONE item */
align-self: flex-start;
align-self: flex-end;
align-self: center;
align-self: stretch;

/* order: Change visual order (default is 0) */
order: -1;    /* Move before items with order: 0 */
order: 1;     /* Move after items with order: 0 */`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#f59e0b" }}>
            Common Flexbox Patterns
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 2 }}>1. Navigation Bar</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<nav class="navbar">
    <div class="logo">Logo</div>
    <ul class="nav-links">
        <li><a href="#">Home</a></li>
        <li><a href="#">About</a></li>
        <li><a href="#">Contact</a></li>
    </ul>
</nav>

.navbar {
    display: flex;
    justify-content: space-between;  /* Logo left, links right */
    align-items: center;
    padding: 1rem 2rem;
}

.nav-links {
    display: flex;
    gap: 2rem;
    list-style: none;
}`}
            </Box>
          </Paper>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 2 }}>2. Card Grid</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`.card-container {
    display: flex;
    flex-wrap: wrap;
    gap: 20px;
}

.card {
    flex: 1 1 300px;      /* Grow, shrink, min 300px */
    max-width: 400px;
    padding: 20px;
    border: 1px solid #ddd;
    border-radius: 8px;
}`}
            </Box>
          </Paper>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 2 }}>3. Footer with Columns</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`.footer {
    display: flex;
    justify-content: space-around;
    flex-wrap: wrap;
    gap: 2rem;
    padding: 2rem;
}

.footer-column {
    flex: 1 1 200px;
    min-width: 150px;
}`}
            </Box>
          </Paper>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f59e0b", 0.05), border: `1px solid ${alpha("#f59e0b", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 2 }}>4. Sticky Footer (Push to Bottom)</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`body {
    display: flex;
    flex-direction: column;
    min-height: 100vh;
}

main {
    flex: 1;             /* Takes all available space */
}

footer {
    /* Footer stays at bottom even with little content */
}`}
            </Box>
          </Paper>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            ✏️ Try It Yourself
          </Typography>
          
          <List dense>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#f59e0b" }} /></ListItemIcon>
              <ListItemText primary="Center a box perfectly in the viewport using Flexbox" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#f59e0b" }} /></ListItemIcon>
              <ListItemText primary="Create a horizontal navigation bar with logo on left, links on right" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#f59e0b" }} /></ListItemIcon>
              <ListItemText primary="Build a card layout that wraps to multiple rows" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#f59e0b" }} /></ListItemIcon>
              <ListItemText primary="Use flex-grow to make one item take up remaining space" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#f59e0b" }} /></ListItemIcon>
              <ListItemText primary="Play Flexbox Froggy (flexboxfroggy.com) to practice!" />
            </ListItem>
          </List>
        </Paper>

        {/* ==================== MODULE 10: CSS GRID ==================== */}
        <Paper
          id="module-10"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#06b6d4", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 10" sx={{ bgcolor: alpha("#06b6d4", 0.15), color: "#06b6d4", fontWeight: 700 }} />
            <Chip label="Intermediate" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.15), color: "#f59e0b", fontWeight: 600 }} />
          </Box>
          
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#06b6d4" }}>
            ⊞ CSS Grid
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            CSS Grid is a powerful two-dimensional layout system. While Flexbox is great for one-dimensional layouts (rows OR columns), 
            Grid excels at creating complex layouts with rows AND columns simultaneously. Think of it as a spreadsheet for your webpage!
          </Typography>

          <Alert severity="info" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Flexbox vs Grid</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              <strong>Flexbox</strong> = One-dimensional (row OR column) — great for navbars, card rows, centering
              <br />
              <strong>Grid</strong> = Two-dimensional (rows AND columns) — great for page layouts, galleries, dashboards
              <br /><br />
              They work together! Use Grid for the overall page layout, Flexbox for components within.
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            Creating a Grid
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!-- HTML Structure -->
<div class="grid-container">
    <div class="item">1</div>
    <div class="item">2</div>
    <div class="item">3</div>
    <div class="item">4</div>
    <div class="item">5</div>
    <div class="item">6</div>
</div>

/* CSS */
.grid-container {
    display: grid;                    /* Activate Grid! */
    grid-template-columns: 200px 200px 200px;  /* 3 columns, 200px each */
    grid-template-rows: 100px 100px;           /* 2 rows, 100px each */
    gap: 10px;                        /* Space between cells */
}

/* Result:
┌────────┬────────┬────────┐
│   1    │   2    │   3    │  ← Row 1 (100px)
├────────┼────────┼────────┤
│   4    │   5    │   6    │  ← Row 2 (100px)
└────────┴────────┴────────┘
  200px    200px    200px
*/`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            The fr Unit (Fraction)
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            The <code style={{ background: alpha("#06b6d4", 0.1), padding: "2px 6px", borderRadius: 4 }}>fr</code> unit represents 
            a fraction of the available space. It's the most useful unit for responsive grids!
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Equal columns */
grid-template-columns: 1fr 1fr 1fr;    /* 3 equal columns */
/* [  33%  ][  33%  ][  33%  ] */

/* Different proportions */
grid-template-columns: 1fr 2fr 1fr;    /* Middle is 2x wider */
/* [  25%  ][   50%   ][  25%  ] */

/* Mix fixed and flexible */
grid-template-columns: 250px 1fr;      /* Sidebar + flexible main */
/* [ Sidebar ][     Main Content     ] */

grid-template-columns: 1fr 300px;      /* Flexible + fixed sidebar */
/* [     Main Content     ][ Sidebar ] */

/* Common layout: sidebar + content + sidebar */
grid-template-columns: 200px 1fr 200px;`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            repeat() Function
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Instead of: */
grid-template-columns: 1fr 1fr 1fr 1fr;

/* Use repeat(): */
grid-template-columns: repeat(4, 1fr);      /* 4 equal columns */

/* Mix repeat with other values */
grid-template-columns: 200px repeat(3, 1fr);  /* Fixed + 3 flexible */

/* repeat() for rows too */
grid-template-rows: repeat(3, 100px);         /* 3 rows, 100px each */`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            auto-fit and auto-fill
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            These are magic keywords that create responsive grids without media queries!
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* auto-fit: Fit as many columns as possible, stretch to fill space */
grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));

/* This means:
   - Create columns that are at least 250px
   - Fit as many as possible in the container
   - Stretch them to fill any remaining space
   - AUTOMATICALLY RESPONSIVE! 🎉
*/

/* auto-fill: Similar but keeps empty column spaces */
grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));

/* The most useful responsive grid pattern: */
.card-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 20px;
}
/* Cards will automatically reflow as the screen resizes! */`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            Gap (Spacing)
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* gap (same for rows and columns) */
gap: 20px;

/* Different row and column gaps */
gap: 20px 10px;          /* row-gap column-gap */
row-gap: 20px;
column-gap: 10px;`}
            </Box>
          </Paper>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            Placing Items on the Grid
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Grid items can span multiple rows and columns using line numbers:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#06b6d4", mb: 2 }}>Understanding Grid Lines</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Grid lines are numbered starting at 1 */

Column Lines:  1      2      3      4
               │      │      │      │
               ▼      ▼      ▼      ▼
             ┌──────┬──────┬──────┐
Row Line 1 → │  A   │  B   │  C   │
             ├──────┼──────┼──────┤
Row Line 2 → │  D   │  E   │  F   │
             ├──────┼──────┼──────┤
Row Line 3 → │  G   │  H   │  I   │
             └──────┴──────┴──────┘
Row Line 4 →`}
            </Box>
          </Paper>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#06b6d4", mb: 2 }}>Spanning Columns and Rows</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Position by line numbers */
.item {
    grid-column-start: 1;
    grid-column-end: 3;        /* Spans columns 1-2 */
    grid-row-start: 1;
    grid-row-end: 2;
}

/* Shorthand: grid-column: start / end */
.header {
    grid-column: 1 / 4;        /* Span all 3 columns */
    grid-row: 1 / 2;
}

/* Using span keyword */
.sidebar {
    grid-column: span 1;       /* Span 1 column */
    grid-row: span 3;          /* Span 3 rows */
}

/* Negative numbers (count from end) */
.footer {
    grid-column: 1 / -1;       /* Span from first to last line */
}`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            Grid Template Areas
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            The most visual way to define layouts—name areas and place items by name!
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Define the layout visually! */
.container {
    display: grid;
    grid-template-columns: 200px 1fr 200px;
    grid-template-rows: 80px 1fr 60px;
    grid-template-areas:
        "header header header"
        "sidebar main aside"
        "footer footer footer";
    min-height: 100vh;
    gap: 10px;
}

/* Assign items to areas by name */
.header  { grid-area: header; }
.sidebar { grid-area: sidebar; }
.main    { grid-area: main; }
.aside   { grid-area: aside; }
.footer  { grid-area: footer; }

/* Use . for empty cells */
grid-template-areas:
    "header header header"
    "sidebar main ."
    "footer footer footer";`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            Alignment in Grid
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Align ALL items in the container */

/* Horizontal alignment of items within their cells */
justify-items: start | center | end | stretch;

/* Vertical alignment of items within their cells */
align-items: start | center | end | stretch;

/* Shorthand: place-items: align-items justify-items */
place-items: center;           /* Center both ways */

/* Align the entire grid within the container */
justify-content: start | center | end | space-between | space-around;
align-content: start | center | end | space-between | space-around;

/* Align individual items (override container alignment) */
.special-item {
    justify-self: center;
    align-self: end;
    /* or */ place-self: end center;
}`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            Common Grid Patterns
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#06b6d4", mb: 2 }}>1. Holy Grail Layout</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`.page {
    display: grid;
    grid-template-areas:
        "header header header"
        "nav    main   aside"
        "footer footer footer";
    grid-template-columns: 200px 1fr 200px;
    grid-template-rows: auto 1fr auto;
    min-height: 100vh;
}`}
            </Box>
          </Paper>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#06b6d4", mb: 2 }}>2. Responsive Card Grid</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`.card-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 24px;
    padding: 24px;
}`}
            </Box>
          </Paper>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#06b6d4", mb: 2 }}>3. Image Gallery with Featured Image</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`.gallery {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    grid-template-rows: repeat(2, 200px);
    gap: 10px;
}

.featured {
    grid-column: span 2;
    grid-row: span 2;
}`}
            </Box>
          </Paper>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            ✏️ Try It Yourself
          </Typography>
          
          <List dense>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#06b6d4" }} /></ListItemIcon>
              <ListItemText primary="Create a 3-column layout using CSS Grid" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#06b6d4" }} /></ListItemIcon>
              <ListItemText primary="Build a responsive card grid using auto-fit and minmax()" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#06b6d4" }} /></ListItemIcon>
              <ListItemText primary="Create a page layout using grid-template-areas" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#06b6d4" }} /></ListItemIcon>
              <ListItemText primary="Make an image gallery with one large featured image" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#06b6d4" }} /></ListItemIcon>
              <ListItemText primary="Play Grid Garden (cssgridgarden.com) to master Grid!" />
            </ListItem>
          </List>
        </Paper>

        {/* ==================== MODULE 11: RESPONSIVE DESIGN ==================== */}
        <Paper
          id="module-11"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#10b981", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 11" sx={{ bgcolor: alpha("#10b981", 0.15), color: "#10b981", fontWeight: 700 }} />
            <Chip label="Intermediate" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.15), color: "#f59e0b", fontWeight: 600 }} />
          </Box>
          
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#10b981" }}>
            📱 Responsive Design
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            Responsive design ensures your website looks great on all devices—from small phones to large desktop monitors. 
            With over 50% of web traffic coming from mobile devices, this is essential knowledge for every web developer!
          </Typography>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            The Viewport Meta Tag
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            This tag is <strong>essential</strong> for responsive design. Without it, mobile browsers will render your page at desktop width and zoom out!
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`<!-- Add this to your <head> section -->
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<!-- What it means:
     width=device-width  → Page width matches the device screen width
     initial-scale=1.0   → No zoom by default (1:1 scale)
-->`}
            </Box>
          </Paper>

          <Alert severity="error" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Never Forget the Viewport Tag!</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              If your responsive design isn't working on mobile, the viewport meta tag is usually the culprit. 
              It should be in every single HTML file you create!
            </Typography>
          </Alert>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Media Queries
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Media queries let you apply different CSS rules based on screen size, device type, or other conditions:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Basic syntax */
@media (condition) {
    /* CSS rules that apply when condition is true */
}

/* Max-width: applies BELOW this width */
@media (max-width: 768px) {
    /* Styles for screens 768px and smaller */
    .sidebar {
        display: none;
    }
}

/* Min-width: applies ABOVE this width */
@media (min-width: 1024px) {
    /* Styles for screens 1024px and larger */
    .container {
        max-width: 1200px;
    }
}

/* Combining conditions with AND */
@media (min-width: 768px) and (max-width: 1024px) {
    /* Tablets only */
}

/* Multiple conditions with OR (comma) */
@media (max-width: 600px), (orientation: portrait) {
    /* Small screens OR portrait orientation */
}`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Common Breakpoints
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { device: "Mobile (Small)", width: "< 576px", use: "max-width: 575px", color: "#ef4444" },
              { device: "Mobile (Large)", width: "≥ 576px", use: "min-width: 576px", color: "#f97316" },
              { device: "Tablet", width: "≥ 768px", use: "min-width: 768px", color: "#f59e0b" },
              { device: "Laptop", width: "≥ 992px", use: "min-width: 992px", color: "#22c55e" },
              { device: "Desktop", width: "≥ 1200px", use: "min-width: 1200px", color: "#3b82f6" },
              { device: "Large Desktop", width: "≥ 1400px", use: "min-width: 1400px", color: "#8b5cf6" },
            ].map((item) => (
              <Grid item xs={6} sm={4} md={2} key={item.device}>
                <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, bgcolor: alpha(item.color, 0.05), border: `1px solid ${alpha(item.color, 0.15)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color }}>{item.device}</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>{item.width}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Mobile-First Design
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            The <strong>mobile-first</strong> approach means writing CSS for mobile devices first, then adding styles for larger screens. 
            This is the recommended approach because:
          </Typography>

          <List dense sx={{ mb: 3 }}>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#10b981" }} /></ListItemIcon>
              <ListItemText primary="Simpler mobile styles (single column) are the base" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#10b981" }} /></ListItemIcon>
              <ListItemText primary="You add complexity for larger screens instead of removing it" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#10b981" }} /></ListItemIcon>
              <ListItemText primary="Better performance on mobile (loads only needed CSS)" />
            </ListItem>
          </List>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#10b981", mb: 2 }}>Mobile-First Example</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Mobile styles first (no media query) */
.container {
    padding: 15px;
}

.card-grid {
    display: grid;
    grid-template-columns: 1fr;    /* Single column on mobile */
    gap: 16px;
}

.sidebar {
    display: none;                  /* Hidden on mobile */
}

/* Tablet and up */
@media (min-width: 768px) {
    .container {
        padding: 30px;
    }
    
    .card-grid {
        grid-template-columns: repeat(2, 1fr);  /* 2 columns */
    }
    
    .sidebar {
        display: block;             /* Show sidebar */
    }
}

/* Desktop and up */
@media (min-width: 1024px) {
    .container {
        max-width: 1200px;
        margin: 0 auto;
    }
    
    .card-grid {
        grid-template-columns: repeat(3, 1fr);  /* 3 columns */
    }
}`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Responsive Units
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Viewport Units */
width: 100vw;      /* 100% of viewport width */
height: 100vh;     /* 100% of viewport height */
width: 50vw;       /* Half the screen width */
font-size: 5vw;    /* Font scales with viewport */

/* Percentage */
width: 100%;       /* 100% of parent element */
max-width: 90%;    /* Never wider than 90% of parent */

/* rem (relative to root font-size) */
font-size: 1rem;   /* Usually 16px (browser default) */
padding: 1.5rem;   /* 24px if root is 16px */
margin: 2rem;      /* 32px if root is 16px */

/* em (relative to parent font-size) */
font-size: 1.2em;  /* 1.2x the parent's font size */

/* Clamp - responsive with min/max limits! */
font-size: clamp(1rem, 2.5vw, 2rem);
/* At minimum: 1rem (16px)
   Scales with: 2.5vw
   At maximum: 2rem (32px)
*/

width: clamp(300px, 50%, 600px);
/* Never smaller than 300px, never larger than 600px */`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Responsive Images
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Make all images responsive by default */
img {
    max-width: 100%;     /* Never wider than container */
    height: auto;        /* Maintain aspect ratio */
    display: block;      /* Remove bottom gap */
}

/* Background image that covers container */
.hero {
    background-image: url('hero.jpg');
    background-size: cover;       /* Cover entire area */
    background-position: center;  /* Center the image */
    min-height: 50vh;
}

/* Picture element for art direction (different images for different sizes) */
<picture>
    <source media="(max-width: 600px)" srcset="small.jpg">
    <source media="(max-width: 1200px)" srcset="medium.jpg">
    <img src="large.jpg" alt="Responsive image">
</picture>`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Responsive Typography
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Fluid typography with clamp() */
h1 {
    font-size: clamp(2rem, 5vw, 4rem);
    /* Minimum 2rem, maximum 4rem, scales with viewport */
}

h2 {
    font-size: clamp(1.5rem, 4vw, 3rem);
}

p {
    font-size: clamp(1rem, 2vw, 1.25rem);
}

/* Or use media queries */
h1 {
    font-size: 2rem;       /* Mobile */
}

@media (min-width: 768px) {
    h1 {
        font-size: 3rem;   /* Tablet */
    }
}

@media (min-width: 1024px) {
    h1 {
        font-size: 4rem;   /* Desktop */
    }
}`}
            </Box>
          </Paper>

          <Alert severity="success" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Complete Responsive Template</AlertTitle>
            <Typography variant="body2" component="div" sx={{ lineHeight: 1.8 }}>
              <Box component="pre" sx={{ fontSize: "0.7rem", fontFamily: "monospace", bgcolor: alpha("#22c55e", 0.1), p: 2, borderRadius: 1, mt: 1, overflowX: "auto" }}>
{`/* Base styles (mobile-first) */
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: system-ui, sans-serif;
    font-size: 16px;
    line-height: 1.6;
}

.container {
    width: 100%;
    padding: 0 15px;
    margin: 0 auto;
}

img { max-width: 100%; height: auto; }

/* Tablet */
@media (min-width: 768px) {
    .container { max-width: 720px; padding: 0 20px; }
}

/* Desktop */
@media (min-width: 1024px) {
    .container { max-width: 960px; }
}

/* Large Desktop */
@media (min-width: 1200px) {
    .container { max-width: 1140px; }
}`}
              </Box>
            </Typography>
          </Alert>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            ✏️ Try It Yourself
          </Typography>
          
          <List dense>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#10b981" }} /></ListItemIcon>
              <ListItemText primary="Add the viewport meta tag to your HTML page" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#10b981" }} /></ListItemIcon>
              <ListItemText primary="Create a navigation that collapses to a hamburger on mobile" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#10b981" }} /></ListItemIcon>
              <ListItemText primary="Use clamp() to create fluid typography" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#10b981" }} /></ListItemIcon>
              <ListItemText primary="Make a card grid that's 1 column on mobile, 2 on tablet, 3 on desktop" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#10b981" }} /></ListItemIcon>
              <ListItemText primary="Test your page by resizing the browser window" />
            </ListItem>
          </List>
        </Paper>

        {/* ==================== MODULE 12: ANIMATIONS & EFFECTS ==================== */}
        <Paper
          id="module-12"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#a855f7", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 12" sx={{ bgcolor: alpha("#a855f7", 0.15), color: "#a855f7", fontWeight: 700 }} />
            <Chip label="Intermediate" size="small" sx={{ bgcolor: alpha("#f59e0b", 0.15), color: "#f59e0b", fontWeight: 600 }} />
          </Box>
          
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, color: "#a855f7" }}>
            ✨ Animations & Effects
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            Animations bring your website to life! From subtle hover effects to complex animated sequences, CSS animations 
            can make your site feel polished and professional. Let's learn how to add motion and interactivity.
          </Typography>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>
            CSS Transitions
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Transitions animate changes between two states (like hover). They're the simplest way to add animation:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#a855f7", 0.05), border: `1px solid ${alpha("#a855f7", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Basic syntax */
transition: property duration timing-function delay;

/* Example: Smooth color change on hover */
.button {
    background: #3b82f6;
    color: white;
    padding: 12px 24px;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    transition: background 0.3s ease;
}

.button:hover {
    background: #1d4ed8;
}

/* Multiple properties */
.card {
    transition: transform 0.3s ease, box-shadow 0.3s ease;
}

.card:hover {
    transform: translateY(-5px);
    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
}

/* Transition all properties */
.element {
    transition: all 0.3s ease;
    /* Be careful - this can be less performant */
}`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>
            Timing Functions
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { name: "ease", desc: "Start slow, fast middle, slow end (default)", visual: "⬜🟦🟦🟦⬜" },
              { name: "linear", desc: "Constant speed throughout", visual: "🟦🟦🟦🟦🟦" },
              { name: "ease-in", desc: "Start slow, speed up", visual: "⬜⬜🟦🟦🟦" },
              { name: "ease-out", desc: "Start fast, slow down", visual: "🟦🟦🟦⬜⬜" },
              { name: "ease-in-out", desc: "Slow start and end", visual: "⬜🟦🟦🟦⬜" },
              { name: "cubic-bezier()", desc: "Custom curve", visual: "⬜🟦⬜🟦🟦" },
            ].map((item) => (
              <Grid item xs={6} sm={4} key={item.name}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: alpha("#a855f7", 0.03), border: `1px solid ${alpha("#a855f7", 0.1)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, fontFamily: "monospace", color: "#a855f7" }}>{item.name}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.75rem", mt: 0.5 }}>{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>
            CSS Transform
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Transform lets you move, rotate, scale, and skew elements without affecting layout:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#a855f7", 0.05), border: `1px solid ${alpha("#a855f7", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Translate (move) */
transform: translateX(50px);     /* Move right 50px */
transform: translateY(-20px);    /* Move up 20px */
transform: translate(50px, -20px); /* Both X and Y */

/* Scale (resize) */
transform: scale(1.2);           /* 120% size */
transform: scale(0.8);           /* 80% size */
transform: scaleX(1.5);          /* Stretch horizontally */
transform: scaleY(0.5);          /* Squish vertically */

/* Rotate */
transform: rotate(45deg);        /* Rotate 45 degrees clockwise */
transform: rotate(-90deg);       /* Rotate counter-clockwise */
transform: rotateX(180deg);      /* Flip on X axis (3D) */
transform: rotateY(180deg);      /* Flip on Y axis (3D) */

/* Skew */
transform: skewX(10deg);         /* Slant horizontally */
transform: skewY(10deg);         /* Slant vertically */
transform: skew(10deg, 5deg);    /* Both */

/* Combine multiple transforms */
transform: translateY(-10px) scale(1.05) rotate(2deg);

/* Transform origin (pivot point) */
transform-origin: center;        /* Default */
transform-origin: top left;
transform-origin: 50% 100%;      /* Bottom center */`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>
            Common Hover Effects
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#a855f7", 0.05), border: `1px solid ${alpha("#a855f7", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#a855f7", mb: 2 }}>Button Effects</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Grow on hover */
.btn-grow {
    transition: transform 0.2s ease;
}
.btn-grow:hover {
    transform: scale(1.05);
}

/* Lift effect (shadow + move) */
.btn-lift {
    transition: transform 0.2s ease, box-shadow 0.2s ease;
}
.btn-lift:hover {
    transform: translateY(-3px);
    box-shadow: 0 6px 20px rgba(0,0,0,0.15);
}

/* Glow effect */
.btn-glow {
    transition: box-shadow 0.3s ease;
}
.btn-glow:hover {
    box-shadow: 0 0 20px rgba(59, 130, 246, 0.5);
}

/* Fill effect (background from left) */
.btn-fill {
    position: relative;
    overflow: hidden;
    z-index: 1;
}
.btn-fill::before {
    content: '';
    position: absolute;
    left: 0;
    top: 0;
    width: 0;
    height: 100%;
    background: #1d4ed8;
    transition: width 0.3s ease;
    z-index: -1;
}
.btn-fill:hover::before {
    width: 100%;
}`}
            </Box>
          </Paper>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#a855f7", 0.05), border: `1px solid ${alpha("#a855f7", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#a855f7", mb: 2 }}>Card Effects</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Lift card */
.card {
    transition: transform 0.3s ease, box-shadow 0.3s ease;
}
.card:hover {
    transform: translateY(-8px);
    box-shadow: 0 12px 40px rgba(0,0,0,0.15);
}

/* Image zoom inside card */
.card img {
    transition: transform 0.3s ease;
}
.card:hover img {
    transform: scale(1.1);
}

/* Card with overflow hidden for zoom effect */
.card {
    overflow: hidden;
    border-radius: 12px;
}

/* Border highlight */
.card {
    border: 2px solid transparent;
    transition: border-color 0.3s ease;
}
.card:hover {
    border-color: #a855f7;
}`}
            </Box>
          </Paper>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>
            CSS Keyframe Animations
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9 }}>
            Keyframe animations allow complex, multi-step animations that can run automatically (not just on hover):
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#a855f7", 0.05), border: `1px solid ${alpha("#a855f7", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Define the animation */
@keyframes bounce {
    0% {
        transform: translateY(0);
    }
    50% {
        transform: translateY(-20px);
    }
    100% {
        transform: translateY(0);
    }
}

/* Apply the animation */
.bouncing-element {
    animation: bounce 1s ease infinite;
}

/* Animation properties */
animation-name: bounce;           /* Name of keyframes */
animation-duration: 1s;           /* How long one cycle takes */
animation-timing-function: ease;  /* Speed curve */
animation-delay: 0.5s;            /* Wait before starting */
animation-iteration-count: infinite; /* How many times (or infinite) */
animation-direction: alternate;   /* normal, reverse, alternate */
animation-fill-mode: forwards;    /* Keep end state after animation */
animation-play-state: running;    /* running or paused */

/* Shorthand */
animation: bounce 1s ease 0.5s infinite alternate;`}
            </Box>
          </Paper>

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>
            Useful Animation Examples
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#a855f7", 0.05), border: `1px solid ${alpha("#a855f7", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#a855f7", mb: 2 }}>1. Fade In</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`@keyframes fadeIn {
    from {
        opacity: 0;
    }
    to {
        opacity: 1;
    }
}

.fade-in {
    animation: fadeIn 0.5s ease forwards;
}`}
            </Box>
          </Paper>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#a855f7", 0.05), border: `1px solid ${alpha("#a855f7", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#a855f7", mb: 2 }}>2. Slide In from Left</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`@keyframes slideInLeft {
    from {
        transform: translateX(-100%);
        opacity: 0;
    }
    to {
        transform: translateX(0);
        opacity: 1;
    }
}

.slide-in {
    animation: slideInLeft 0.5s ease forwards;
}`}
            </Box>
          </Paper>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#a855f7", 0.05), border: `1px solid ${alpha("#a855f7", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#a855f7", mb: 2 }}>3. Pulse Effect</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`@keyframes pulse {
    0% {
        transform: scale(1);
    }
    50% {
        transform: scale(1.05);
    }
    100% {
        transform: scale(1);
    }
}

.pulse {
    animation: pulse 2s ease infinite;
}`}
            </Box>
          </Paper>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#a855f7", 0.05), border: `1px solid ${alpha("#a855f7", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#a855f7", mb: 2 }}>4. Loading Spinner</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`@keyframes spin {
    from {
        transform: rotate(0deg);
    }
    to {
        transform: rotate(360deg);
    }
}

.spinner {
    width: 40px;
    height: 40px;
    border: 4px solid #f3f3f3;
    border-top: 4px solid #a855f7;
    border-radius: 50%;
    animation: spin 1s linear infinite;
}`}
            </Box>
          </Paper>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#a855f7", 0.05), border: `1px solid ${alpha("#a855f7", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#a855f7", mb: 2 }}>5. Shake Effect</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`@keyframes shake {
    0%, 100% { transform: translateX(0); }
    10%, 30%, 50%, 70%, 90% { transform: translateX(-5px); }
    20%, 40%, 60%, 80% { transform: translateX(5px); }
}

.error-shake {
    animation: shake 0.5s ease;
}

/* Apply on invalid form input */
input:invalid {
    animation: shake 0.3s ease;
    border-color: red;
}`}
            </Box>
          </Paper>

          <Alert severity="warning" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Performance Tips</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              • <strong>Only animate transform and opacity</strong> — these are GPU-accelerated and smooth
              <br />
              • Avoid animating <code>width</code>, <code>height</code>, <code>margin</code>, <code>top/left</code> — causes layout recalculation
              <br />
              • Use <code>will-change: transform</code> to hint browser for optimization
              <br />
              • Respect <code>prefers-reduced-motion</code> for users who dislike animations
            </Typography>
          </Alert>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#a855f7", 0.05), border: `1px solid ${alpha("#a855f7", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#a855f7", mb: 2 }}>Respecting User Preferences</Typography>
            <Box component="pre" sx={{ fontSize: "0.85rem", fontFamily: "monospace", bgcolor: "#1e1e1e", color: "#d4d4d4", p: 2, borderRadius: 1, overflowX: "auto" }}>
{`/* Disable animations for users who prefer reduced motion */
@media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
    }
}`}
            </Box>
          </Paper>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2 }}>
            ✏️ Try It Yourself
          </Typography>
          
          <List dense>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#a855f7" }} /></ListItemIcon>
              <ListItemText primary="Add a smooth hover effect to your buttons (scale or shadow)" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#a855f7" }} /></ListItemIcon>
              <ListItemText primary="Create a card that lifts up on hover with a shadow" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#a855f7" }} /></ListItemIcon>
              <ListItemText primary="Build a CSS-only loading spinner" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#a855f7" }} /></ListItemIcon>
              <ListItemText primary="Create a fade-in animation for page content" />
            </ListItem>
            <ListItem>
              <ListItemIcon><BrushIcon sx={{ color: "#a855f7" }} /></ListItemIcon>
              <ListItemText primary="Add prefers-reduced-motion support to your animations" />
            </ListItem>
          </List>
        </Paper>

        {/* ==================== MODULE 13: BOOTSTRAP FRAMEWORK ==================== */}
        <Paper
          id="module-13-content"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha("#7952b3", 0.03),
            border: `1px solid ${alpha("#7952b3", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3, flexWrap: "wrap" }}>
            <ViewQuiltIcon sx={{ fontSize: 36, color: "#7952b3" }} />
            <Typography variant="h4" sx={{ fontWeight: 800, color: "#7952b3" }}>
              Module 13: Bootstrap Framework
            </Typography>
            <Chip label="Advanced" sx={{ bgcolor: alpha("#ef4444", 0.15), color: "#ef4444", fontWeight: 600 }} />
          </Box>

          <Typography variant="body1" color="text.secondary" sx={{ mb: 4, fontSize: "1.1rem", lineHeight: 1.8 }}>
            Bootstrap is the world's most popular CSS framework. It provides pre-built components, a powerful grid system, 
            and utility classes that let you build responsive websites quickly without writing much custom CSS.
          </Typography>

          {/* What is Bootstrap */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#7952b3" }}>
            What is Bootstrap?
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3, lineHeight: 1.8 }}>
            Bootstrap is a free, open-source CSS framework created by Twitter. It includes:
          </Typography>
          <List dense sx={{ mb: 3 }}>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#7952b3" }} /></ListItemIcon>
              <ListItemText primary="Pre-styled components (buttons, cards, navbars, modals)" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#7952b3" }} /></ListItemIcon>
              <ListItemText primary="A 12-column responsive grid system" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#7952b3" }} /></ListItemIcon>
              <ListItemText primary="Utility classes for spacing, colors, display, and more" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#7952b3" }} /></ListItemIcon>
              <ListItemText primary="JavaScript components (dropdowns, carousels, tooltips)" />
            </ListItem>
          </List>

          {/* Installing Bootstrap */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#7952b3" }}>
            Installing Bootstrap
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2, lineHeight: 1.8 }}>
            The easiest way to add Bootstrap is via CDN. Add these links to your HTML:
          </Typography>
          <CodeBlock
            title="Adding Bootstrap via CDN"
            code={`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>My Bootstrap Page</title>
  
  <!-- Bootstrap CSS -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" 
        rel="stylesheet">
</head>
<body>
  <h1 class="text-primary">Hello Bootstrap!</h1>
  
  <!-- Bootstrap JS (optional, for interactive components) -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js">
  </script>
</body>
</html>`}
          />

          {/* The Grid System */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#7952b3" }}>
            The Bootstrap Grid System
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2, lineHeight: 1.8 }}>
            Bootstrap uses a 12-column grid. Wrap content in a <code>.container</code>, then use <code>.row</code> and <code>.col-*</code> classes:
          </Typography>
          <CodeBlock
            title="Basic Grid Layout"
            code={`<div class="container">
  <div class="row">
    <!-- Full width on mobile, half width on medium screens -->
    <div class="col-12 col-md-6">
      <p>Left column</p>
    </div>
    <div class="col-12 col-md-6">
      <p>Right column</p>
    </div>
  </div>
  
  <!-- Three equal columns on large screens -->
  <div class="row">
    <div class="col-lg-4">Column 1</div>
    <div class="col-lg-4">Column 2</div>
    <div class="col-lg-4">Column 3</div>
  </div>
</div>`}
          />

          <Alert severity="info" sx={{ my: 3 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Grid Breakpoints</AlertTitle>
            <Typography variant="body2">
              <strong>col-</strong> = extra small (all sizes)<br />
              <strong>col-sm-</strong> = small (≥576px)<br />
              <strong>col-md-</strong> = medium (≥768px)<br />
              <strong>col-lg-</strong> = large (≥992px)<br />
              <strong>col-xl-</strong> = extra large (≥1200px)<br />
              <strong>col-xxl-</strong> = extra extra large (≥1400px)
            </Typography>
          </Alert>

          {/* Bootstrap Components */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#7952b3" }}>
            Common Bootstrap Components
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 600, mt: 3, mb: 2, color: "#7952b3" }}>
            Buttons
          </Typography>
          <CodeBlock
            title="Bootstrap Buttons"
            code={`<!-- Primary button -->
<button class="btn btn-primary">Primary</button>

<!-- Secondary button -->
<button class="btn btn-secondary">Secondary</button>

<!-- Outline button -->
<button class="btn btn-outline-primary">Outline</button>

<!-- Different sizes -->
<button class="btn btn-primary btn-lg">Large</button>
<button class="btn btn-primary btn-sm">Small</button>

<!-- Disabled button -->
<button class="btn btn-primary" disabled>Disabled</button>`}
          />

          <Typography variant="h6" sx={{ fontWeight: 600, mt: 4, mb: 2, color: "#7952b3" }}>
            Cards
          </Typography>
          <CodeBlock
            title="Bootstrap Card"
            code={`<div class="card" style="width: 18rem;">
  <img src="image.jpg" class="card-img-top" alt="Card image">
  <div class="card-body">
    <h5 class="card-title">Card Title</h5>
    <p class="card-text">
      Some quick example text to build on the card title.
    </p>
    <a href="#" class="btn btn-primary">Go somewhere</a>
  </div>
</div>`}
          />

          <Typography variant="h6" sx={{ fontWeight: 600, mt: 4, mb: 2, color: "#7952b3" }}>
            Navbar
          </Typography>
          <CodeBlock
            title="Responsive Navbar"
            code={`<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
  <div class="container">
    <a class="navbar-brand" href="#">MyBrand</a>
    
    <!-- Hamburger menu for mobile -->
    <button class="navbar-toggler" type="button" 
            data-bs-toggle="collapse" data-bs-target="#navbarNav">
      <span class="navbar-toggler-icon"></span>
    </button>
    
    <!-- Nav links -->
    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav ms-auto">
        <li class="nav-item">
          <a class="nav-link active" href="#">Home</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" href="#">About</a>
        </li>
        <li class="nav-item">
          <a class="nav-link" href="#">Contact</a>
        </li>
      </ul>
    </div>
  </div>
</nav>`}
          />

          <Typography variant="h6" sx={{ fontWeight: 600, mt: 4, mb: 2, color: "#7952b3" }}>
            Alerts
          </Typography>
          <CodeBlock
            title="Bootstrap Alerts"
            code={`<!-- Success alert -->
<div class="alert alert-success" role="alert">
  Operation completed successfully!
</div>

<!-- Warning alert -->
<div class="alert alert-warning" role="alert">
  Please check your input.
</div>

<!-- Danger alert -->
<div class="alert alert-danger" role="alert">
  Something went wrong!
</div>

<!-- Dismissible alert -->
<div class="alert alert-info alert-dismissible fade show" role="alert">
  This alert can be dismissed.
  <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
</div>`}
          />

          <Typography variant="h6" sx={{ fontWeight: 600, mt: 4, mb: 2, color: "#7952b3" }}>
            Modals
          </Typography>
          <CodeBlock
            title="Bootstrap Modal"
            code={`<!-- Button to trigger modal -->
<button class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#myModal">
  Open Modal
</button>

<!-- Modal structure -->
<div class="modal fade" id="myModal" tabindex="-1">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title">Modal Title</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <p>Modal body content goes here.</p>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
        <button class="btn btn-primary">Save changes</button>
      </div>
    </div>
  </div>
</div>`}
          />

          {/* Utility Classes */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#7952b3" }}>
            Bootstrap Utility Classes
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2, lineHeight: 1.8 }}>
            Bootstrap includes utility classes for quick styling without custom CSS:
          </Typography>
          <CodeBlock
            title="Common Utility Classes"
            code={`<!-- Spacing: m = margin, p = padding -->
<!-- t/b/s/e = top/bottom/start/end, x/y = horizontal/vertical -->
<div class="mt-3">Margin top 3</div>
<div class="p-4">Padding all sides 4</div>
<div class="mx-auto">Center horizontally</div>
<div class="py-2 px-3">Padding y:2, x:3</div>

<!-- Text utilities -->
<p class="text-center">Centered text</p>
<p class="text-end">Right-aligned text</p>
<p class="text-primary">Primary color text</p>
<p class="text-muted">Muted/gray text</p>
<p class="fw-bold">Bold text</p>
<p class="fs-4">Font size 4</p>

<!-- Background colors -->
<div class="bg-primary text-white">Primary background</div>
<div class="bg-light">Light background</div>
<div class="bg-dark text-white">Dark background</div>

<!-- Display utilities -->
<div class="d-none">Hidden</div>
<div class="d-block">Block element</div>
<div class="d-flex">Flex container</div>
<div class="d-none d-md-block">Hidden on mobile, visible on md+</div>

<!-- Flexbox utilities -->
<div class="d-flex justify-content-between">Space between</div>
<div class="d-flex align-items-center">Vertically centered</div>
<div class="d-flex flex-column">Column direction</div>

<!-- Border and rounded -->
<div class="border">Has border</div>
<div class="rounded">Rounded corners</div>
<div class="rounded-pill">Pill shape</div>
<div class="shadow">Box shadow</div>`}
          />

          {/* Forms */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#7952b3" }}>
            Bootstrap Forms
          </Typography>
          <CodeBlock
            title="Styled Form"
            code={`<form>
  <div class="mb-3">
    <label for="email" class="form-label">Email address</label>
    <input type="email" class="form-control" id="email" 
           placeholder="name@example.com">
  </div>
  
  <div class="mb-3">
    <label for="password" class="form-label">Password</label>
    <input type="password" class="form-control" id="password">
  </div>
  
  <div class="mb-3">
    <label for="country" class="form-label">Country</label>
    <select class="form-select" id="country">
      <option selected>Choose...</option>
      <option value="us">United States</option>
      <option value="uk">United Kingdom</option>
      <option value="ca">Canada</option>
    </select>
  </div>
  
  <div class="mb-3 form-check">
    <input type="checkbox" class="form-check-input" id="terms">
    <label class="form-check-label" for="terms">
      I agree to the terms
    </label>
  </div>
  
  <button type="submit" class="btn btn-primary">Submit</button>
</form>`}
          />

          {/* Practice Exercises */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#7952b3" }}>
            ✏️ Practice Exercises
          </Typography>
          <List dense>
            <ListItem>
              <ListItemIcon><ViewQuiltIcon sx={{ color: "#7952b3" }} /></ListItemIcon>
              <ListItemText primary="Build a responsive navbar with a logo and 4 nav links" />
            </ListItem>
            <ListItem>
              <ListItemIcon><ViewQuiltIcon sx={{ color: "#7952b3" }} /></ListItemIcon>
              <ListItemText primary="Create a 3-column grid that stacks on mobile" />
            </ListItem>
            <ListItem>
              <ListItemIcon><ViewQuiltIcon sx={{ color: "#7952b3" }} /></ListItemIcon>
              <ListItemText primary="Build a card grid with 4 product cards" />
            </ListItem>
            <ListItem>
              <ListItemIcon><ViewQuiltIcon sx={{ color: "#7952b3" }} /></ListItemIcon>
              <ListItemText primary="Create a contact form with Bootstrap styling" />
            </ListItem>
            <ListItem>
              <ListItemIcon><ViewQuiltIcon sx={{ color: "#7952b3" }} /></ListItemIcon>
              <ListItemText primary="Add a modal that opens when clicking a button" />
            </ListItem>
          </List>
        </Paper>

        {/* ==================== MODULE 14: TAILWINDCSS ==================== */}
        <Paper
          id="module-14-content"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha("#06b6d4", 0.03),
            border: `1px solid ${alpha("#06b6d4", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3, flexWrap: "wrap" }}>
            <AutoAwesomeIcon sx={{ fontSize: 36, color: "#06b6d4" }} />
            <Typography variant="h4" sx={{ fontWeight: 800, color: "#06b6d4" }}>
              Module 14: TailwindCSS
            </Typography>
            <Chip label="Advanced" sx={{ bgcolor: alpha("#ef4444", 0.15), color: "#ef4444", fontWeight: 600 }} />
          </Box>

          <Typography variant="body1" color="text.secondary" sx={{ mb: 4, fontSize: "1.1rem", lineHeight: 1.8 }}>
            TailwindCSS is a utility-first CSS framework that lets you build designs directly in your HTML 
            using small, single-purpose utility classes. It's highly customizable and produces very small 
            production builds by removing unused CSS.
          </Typography>

          {/* What is Tailwind */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            What Makes Tailwind Different?
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3, lineHeight: 1.8 }}>
            Unlike Bootstrap's pre-built components, Tailwind gives you low-level utility classes that you 
            combine to create any design:
          </Typography>
          <CodeBlock
            title="Traditional CSS vs Tailwind"
            code={`/* Traditional CSS approach */
.card {
  background-color: white;
  border-radius: 8px;
  padding: 24px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

/* With Tailwind - same result, no CSS file needed */
<div class="bg-white rounded-lg p-6 shadow-md">
  Card content
</div>`}
          />

          {/* Installing Tailwind */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#06b6d4" }}>
            Getting Started with Tailwind
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2, lineHeight: 1.8 }}>
            For quick prototyping, you can use the Tailwind CDN (not recommended for production):
          </Typography>
          <CodeBlock
            title="Quick Start with CDN"
            code={`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Tailwind Demo</title>
  <!-- Tailwind CDN (for development only) -->
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100">
  <h1 class="text-3xl font-bold text-blue-600">
    Hello Tailwind!
  </h1>
</body>
</html>`}
          />

          <Alert severity="warning" sx={{ my: 3 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Production Setup</AlertTitle>
            <Typography variant="body2">
              For real projects, install Tailwind via npm with <code>npm install tailwindcss</code> and configure 
              it properly. The CDN includes all classes which makes it large. The proper setup removes unused 
              CSS, resulting in tiny file sizes.
            </Typography>
          </Alert>

          {/* Core Utilities */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#06b6d4" }}>
            Core Tailwind Utilities
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 600, mt: 3, mb: 2, color: "#06b6d4" }}>
            Colors
          </Typography>
          <CodeBlock
            title="Color Utilities"
            code={`<!-- Text colors: text-{color}-{shade} -->
<p class="text-blue-500">Blue text</p>
<p class="text-red-600">Red text</p>
<p class="text-gray-700">Gray text</p>
<p class="text-green-400">Light green text</p>

<!-- Background colors: bg-{color}-{shade} -->
<div class="bg-blue-500">Blue background</div>
<div class="bg-slate-100">Light slate background</div>
<div class="bg-emerald-600">Emerald background</div>

<!-- Shades go from 50 (lightest) to 950 (darkest) -->
<!-- Common: 100, 200, 300, 400, 500, 600, 700, 800, 900 -->

<!-- Special colors -->
<div class="bg-white">White</div>
<div class="bg-black text-white">Black</div>
<div class="bg-transparent">Transparent</div>`}
          />

          <Typography variant="h6" sx={{ fontWeight: 600, mt: 4, mb: 2, color: "#06b6d4" }}>
            Spacing (Padding & Margin)
          </Typography>
          <CodeBlock
            title="Spacing Utilities"
            code={`<!-- Padding: p-{size} -->
<div class="p-4">Padding all sides (1rem)</div>
<div class="px-4">Padding left & right</div>
<div class="py-2">Padding top & bottom</div>
<div class="pt-8">Padding top only</div>
<div class="pb-4">Padding bottom only</div>
<div class="pl-6">Padding left only</div>
<div class="pr-2">Padding right only</div>

<!-- Margin: m-{size} -->
<div class="m-4">Margin all sides</div>
<div class="mx-auto">Center horizontally</div>
<div class="my-8">Margin top & bottom</div>
<div class="mt-4">Margin top only</div>
<div class="mb-6">Margin bottom only</div>

<!-- Size scale: 0, 1, 2, 3, 4, 5, 6, 8, 10, 12, 16, 20, 24... -->
<!-- 1 = 0.25rem (4px), 4 = 1rem (16px), 8 = 2rem (32px) -->

<!-- Negative margins -->
<div class="-mt-4">Negative margin top</div>`}
          />

          <Typography variant="h6" sx={{ fontWeight: 600, mt: 4, mb: 2, color: "#06b6d4" }}>
            Typography
          </Typography>
          <CodeBlock
            title="Typography Utilities"
            code={`<!-- Font size: text-{size} -->
<p class="text-xs">Extra small (0.75rem)</p>
<p class="text-sm">Small (0.875rem)</p>
<p class="text-base">Base (1rem) - default</p>
<p class="text-lg">Large (1.125rem)</p>
<p class="text-xl">Extra large (1.25rem)</p>
<p class="text-2xl">2XL (1.5rem)</p>
<p class="text-3xl">3XL (1.875rem)</p>
<p class="text-4xl">4XL (2.25rem)</p>

<!-- Font weight: font-{weight} -->
<p class="font-light">Light (300)</p>
<p class="font-normal">Normal (400)</p>
<p class="font-medium">Medium (500)</p>
<p class="font-semibold">Semibold (600)</p>
<p class="font-bold">Bold (700)</p>

<!-- Text alignment -->
<p class="text-left">Left aligned</p>
<p class="text-center">Centered</p>
<p class="text-right">Right aligned</p>

<!-- Other text utilities -->
<p class="uppercase">Uppercase text</p>
<p class="lowercase">Lowercase text</p>
<p class="capitalize">Capitalize Each Word</p>
<p class="underline">Underlined</p>
<p class="line-through">Strikethrough</p>
<p class="leading-loose">Loose line height</p>`}
          />

          <Typography variant="h6" sx={{ fontWeight: 600, mt: 4, mb: 2, color: "#06b6d4" }}>
            Flexbox
          </Typography>
          <CodeBlock
            title="Flexbox Utilities"
            code={`<!-- Enable flex -->
<div class="flex">Flex container</div>
<div class="inline-flex">Inline flex</div>

<!-- Direction -->
<div class="flex flex-row">Row (default)</div>
<div class="flex flex-col">Column</div>

<!-- Justify content (main axis) -->
<div class="flex justify-start">Start</div>
<div class="flex justify-center">Center</div>
<div class="flex justify-end">End</div>
<div class="flex justify-between">Space between</div>
<div class="flex justify-around">Space around</div>
<div class="flex justify-evenly">Space evenly</div>

<!-- Align items (cross axis) -->
<div class="flex items-start">Top</div>
<div class="flex items-center">Center</div>
<div class="flex items-end">Bottom</div>
<div class="flex items-stretch">Stretch</div>

<!-- Gap -->
<div class="flex gap-4">Gap between items</div>
<div class="flex gap-x-4 gap-y-2">Different x/y gaps</div>

<!-- Wrap -->
<div class="flex flex-wrap">Wrap items</div>

<!-- Flex item utilities -->
<div class="flex-1">Grow to fill</div>
<div class="flex-none">Don't grow or shrink</div>
<div class="flex-grow">Grow</div>
<div class="flex-shrink-0">Don't shrink</div>`}
          />

          <Typography variant="h6" sx={{ fontWeight: 600, mt: 4, mb: 2, color: "#06b6d4" }}>
            Grid
          </Typography>
          <CodeBlock
            title="Grid Utilities"
            code={`<!-- Basic grid -->
<div class="grid grid-cols-3 gap-4">
  <div>Column 1</div>
  <div>Column 2</div>
  <div>Column 3</div>
</div>

<!-- Different column counts -->
<div class="grid grid-cols-2">2 columns</div>
<div class="grid grid-cols-4">4 columns</div>
<div class="grid grid-cols-12">12 columns</div>

<!-- Column span -->
<div class="grid grid-cols-4 gap-4">
  <div class="col-span-2">Spans 2 columns</div>
  <div>1 column</div>
  <div>1 column</div>
</div>

<!-- Auto columns -->
<div class="grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-4">
  <!-- Auto-fit with min 200px -->
</div>`}
          />

          {/* Responsive Design */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#06b6d4" }}>
            Responsive Design in Tailwind
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2, lineHeight: 1.8 }}>
            Tailwind uses a mobile-first approach. Prefix any utility with a breakpoint to apply it at that size and up:
          </Typography>
          <CodeBlock
            title="Responsive Utilities"
            code={`<!-- Breakpoints: sm (640px), md (768px), lg (1024px), xl (1280px), 2xl (1536px) -->

<!-- Full width on mobile, half on medium, third on large -->
<div class="w-full md:w-1/2 lg:w-1/3">
  Responsive width
</div>

<!-- Stack on mobile, row on tablet -->
<div class="flex flex-col md:flex-row gap-4">
  <div>Item 1</div>
  <div>Item 2</div>
</div>

<!-- Hide on mobile, show on desktop -->
<div class="hidden lg:block">
  Only visible on large screens
</div>

<!-- Show on mobile, hide on desktop -->
<div class="block lg:hidden">
  Only visible on small screens
</div>

<!-- Different text sizes per breakpoint -->
<h1 class="text-2xl md:text-4xl lg:text-6xl">
  Responsive heading
</h1>

<!-- Different padding per breakpoint -->
<div class="p-4 md:p-6 lg:p-8">
  Responsive padding
</div>

<!-- Different grid columns per breakpoint -->
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
  <div>Card 1</div>
  <div>Card 2</div>
  <div>Card 3</div>
  <div>Card 4</div>
</div>`}
          />

          {/* Hover, Focus, and State */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#06b6d4" }}>
            Hover, Focus & Other States
          </Typography>
          <CodeBlock
            title="State Modifiers"
            code={`<!-- Hover state -->
<button class="bg-blue-500 hover:bg-blue-700 text-white px-4 py-2">
  Hover me
</button>

<!-- Focus state -->
<input class="border focus:border-blue-500 focus:ring-2 focus:ring-blue-200" />

<!-- Active state -->
<button class="bg-blue-500 active:bg-blue-800">
  Click me
</button>

<!-- Disabled state -->
<button class="bg-gray-300 disabled:opacity-50 disabled:cursor-not-allowed">
  Disabled
</button>

<!-- Group hover (hover parent, style child) -->
<div class="group">
  <h3 class="group-hover:text-blue-500">Hover the card</h3>
  <p class="group-hover:underline">This text changes too</p>
</div>

<!-- First/last child -->
<div class="first:pt-0 last:pb-0">
  No padding on first/last
</div>

<!-- Odd/even (for lists) -->
<tr class="odd:bg-gray-100 even:bg-white">
  Table row
</tr>`}
          />

          {/* Dark Mode */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#06b6d4" }}>
            Dark Mode
          </Typography>
          <CodeBlock
            title="Dark Mode Utilities"
            code={`<!-- Dark mode uses the 'dark:' prefix -->
<div class="bg-white dark:bg-gray-800">
  <h1 class="text-gray-900 dark:text-white">
    Works in light and dark mode
  </h1>
  <p class="text-gray-600 dark:text-gray-300">
    Text automatically adapts
  </p>
</div>

<!-- Card example with dark mode -->
<div class="bg-white dark:bg-slate-800 
            border border-gray-200 dark:border-slate-700 
            rounded-lg p-6 shadow-md">
  <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
    Card Title
  </h3>
  <p class="text-gray-600 dark:text-gray-300">
    Card content that looks great in both modes.
  </p>
</div>`}
          />

          {/* ==================== PROPER INSTALLATION WITH NPM/VITE ==================== */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#06b6d4" }}>
            🔧 Proper Installation with npm & Vite
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2, lineHeight: 1.8 }}>
            While the CDN is great for learning, real projects need a proper build setup. Here's how to set up 
            Tailwind with Vite, the modern build tool that's incredibly fast. This setup removes unused CSS, 
            resulting in tiny production files (often under 10KB).
          </Typography>
          <CodeBlock
            title="Step 1: Create a Vite Project"
            code={`# Create a new Vite project (choose vanilla or react)
npm create vite@latest my-tailwind-project
cd my-tailwind-project

# Or with React
npm create vite@latest my-react-app -- --template react

# Install dependencies
npm install`}
          />
          <CodeBlock
            title="Step 2: Install Tailwind CSS"
            code={`# Install Tailwind and its dependencies
npm install -D tailwindcss postcss autoprefixer

# Generate config files
npx tailwindcss init -p

# This creates:
# - tailwind.config.js (Tailwind configuration)
# - postcss.config.js (PostCSS configuration)`}
          />
          <CodeBlock
            title="Step 3: Configure Template Paths"
            code={`// tailwind.config.js
/** @type {import('tailwindcss').Config} */
export default {
  // Tell Tailwind which files to scan for classes
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",  // All JS/TS files in src
  ],
  theme: {
    extend: {},  // We'll customize this later
  },
  plugins: [],
}`}
          />
          <CodeBlock
            title="Step 4: Add Tailwind Directives to CSS"
            code={`/* src/index.css (or src/style.css) */

/* These directives inject Tailwind's styles */
@tailwind base;       /* Preflight reset + base styles */
@tailwind components; /* Component classes */
@tailwind utilities;  /* Utility classes */

/* Your custom CSS can go below */`}
          />
          <CodeBlock
            title="Step 5: Import CSS and Start Dev Server"
            code={`// main.js or main.jsx
import './index.css'  // Import your CSS file

// For React:
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)

// Then run:
// npm run dev`}
          />

          <Alert severity="success" sx={{ my: 3 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Why This Setup Matters</AlertTitle>
            <Typography variant="body2">
              <strong>Tree-shaking:</strong> Tailwind scans your files and only includes the CSS classes you actually use. 
              A CDN includes ALL classes (megabytes of CSS). A proper build might only include 5-20KB of CSS.
              <br /><br />
              <strong>IntelliSense:</strong> VS Code's Tailwind CSS IntelliSense extension provides autocomplete, 
              syntax highlighting, and linting for Tailwind classes.
            </Typography>
          </Alert>

          {/* ==================== TAILWIND CONFIG DEEP DIVE ==================== */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#06b6d4" }}>
            ⚙️ Tailwind Configuration Deep Dive
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2, lineHeight: 1.8 }}>
            The <code>tailwind.config.js</code> file is where the magic happens. You can customize colors, 
            fonts, spacing, breakpoints, and add your own utilities. Think of it as your design system in code.
          </Typography>
          <CodeBlock
            title="Custom Colors & Design Tokens"
            code={`// tailwind.config.js
export default {
  content: ["./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      // Add custom colors (these ADD to defaults)
      colors: {
        // Single color
        brand: '#3b82f6',
        
        // Color palette with shades
        primary: {
          50: '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6',  // Main shade
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a',
          950: '#172554',
        },
        
        // Use CSS variables for theming
        accent: 'var(--accent-color)',
        surface: 'rgb(var(--surface-rgb) / <alpha-value>)',
      },
      
      // Custom fonts
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        display: ['Poppins', 'sans-serif'],
        mono: ['Fira Code', 'monospace'],
      },
      
      // Custom spacing (adds to default 0-96 scale)
      spacing: {
        '18': '4.5rem',
        '88': '22rem',
        '128': '32rem',
      },
      
      // Custom breakpoints
      screens: {
        'xs': '475px',      // Extra small
        '3xl': '1920px',    // Ultra wide
      },
      
      // Custom border radius
      borderRadius: {
        '4xl': '2rem',
        '5xl': '3rem',
      },
      
      // Custom shadows
      boxShadow: {
        'glow': '0 0 20px rgba(59, 130, 246, 0.5)',
        'inner-lg': 'inset 0 4px 6px rgba(0, 0, 0, 0.1)',
      },
      
      // Custom animations
      animation: {
        'fade-in': 'fadeIn 0.5s ease-out',
        'slide-up': 'slideUp 0.3s ease-out',
        'bounce-slow': 'bounce 3s infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { transform: 'translateY(20px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}`}
          />
          <CodeBlock
            title="Using Custom Config Values"
            code={`<!-- Now you can use your custom values! -->

<!-- Custom colors -->
<div class="bg-primary-500 text-white">Primary button</div>
<div class="bg-brand hover:bg-primary-600">Brand color</div>

<!-- Custom fonts -->
<h1 class="font-display text-4xl">Display heading</h1>
<p class="font-sans">Body text with Inter</p>
<code class="font-mono">Code with Fira</code>

<!-- Custom spacing -->
<div class="p-18 mb-88">Extra spacing values</div>

<!-- Custom breakpoints -->
<div class="hidden xs:block 3xl:text-2xl">
  Shows on extra small, bigger text on ultra-wide
</div>

<!-- Custom shadows -->
<button class="shadow-glow hover:shadow-lg">Glowing button</button>

<!-- Custom animations -->
<div class="animate-fade-in">Fades in on load</div>
<div class="animate-slide-up">Slides up on load</div>`}
          />

          {/* ==================== CUSTOM UTILITIES WITH @APPLY ==================== */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#06b6d4" }}>
            🎨 Custom Utilities with @apply
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2, lineHeight: 1.8 }}>
            When you find yourself repeating the same combination of utilities, you can extract them into 
            custom CSS classes using <code>@apply</code>. This is perfect for buttons, cards, and other 
            reusable components.
          </Typography>
          <CodeBlock
            title="Creating Reusable Component Classes"
            code={`/* src/index.css */
@tailwind base;
@tailwind components;
@tailwind utilities;

/* Custom component classes using @apply */
@layer components {
  /* Button variants */
  .btn {
    @apply px-4 py-2 rounded-lg font-semibold transition-all duration-200;
    @apply focus:outline-none focus:ring-2 focus:ring-offset-2;
  }
  
  .btn-primary {
    @apply btn bg-blue-600 text-white;
    @apply hover:bg-blue-700 active:bg-blue-800;
    @apply focus:ring-blue-500;
  }
  
  .btn-secondary {
    @apply btn bg-gray-200 text-gray-800;
    @apply hover:bg-gray-300 active:bg-gray-400;
    @apply focus:ring-gray-500;
  }
  
  .btn-danger {
    @apply btn bg-red-600 text-white;
    @apply hover:bg-red-700 active:bg-red-800;
    @apply focus:ring-red-500;
  }
  
  .btn-outline {
    @apply btn border-2 border-blue-600 text-blue-600 bg-transparent;
    @apply hover:bg-blue-600 hover:text-white;
    @apply focus:ring-blue-500;
  }
  
  /* Card component */
  .card {
    @apply bg-white dark:bg-slate-800 rounded-xl shadow-md;
    @apply border border-gray-200 dark:border-slate-700;
    @apply overflow-hidden;
  }
  
  .card-body {
    @apply p-6;
  }
  
  .card-title {
    @apply text-xl font-bold text-gray-900 dark:text-white mb-2;
  }
  
  /* Input styling */
  .input {
    @apply w-full px-4 py-2 rounded-lg border border-gray-300;
    @apply focus:border-blue-500 focus:ring-2 focus:ring-blue-200;
    @apply dark:bg-slate-800 dark:border-slate-600 dark:text-white;
    @apply transition-colors duration-200;
  }
  
  .input-error {
    @apply input border-red-500 focus:border-red-500 focus:ring-red-200;
  }
  
  /* Badge variants */
  .badge {
    @apply inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium;
  }
  
  .badge-success {
    @apply badge bg-green-100 text-green-800;
  }
  
  .badge-warning {
    @apply badge bg-yellow-100 text-yellow-800;
  }
  
  .badge-error {
    @apply badge bg-red-100 text-red-800;
  }
}

/* Custom utilities */
@layer utilities {
  /* Text gradient utility */
  .text-gradient {
    @apply bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-purple-600;
  }
  
  /* Hide scrollbar */
  .scrollbar-hide {
    -ms-overflow-style: none;
    scrollbar-width: none;
  }
  .scrollbar-hide::-webkit-scrollbar {
    display: none;
  }
}`}
          />
          <CodeBlock
            title="Using Custom Component Classes"
            code={`<!-- Now your HTML is much cleaner! -->

<!-- Buttons -->
<button class="btn-primary">Save Changes</button>
<button class="btn-secondary">Cancel</button>
<button class="btn-danger">Delete</button>
<button class="btn-outline">Learn More</button>

<!-- Cards -->
<div class="card">
  <img src="image.jpg" class="w-full h-48 object-cover" />
  <div class="card-body">
    <h3 class="card-title">Card Title</h3>
    <p class="text-gray-600 dark:text-gray-300">Card content...</p>
  </div>
</div>

<!-- Forms -->
<input type="email" class="input" placeholder="Enter email" />
<input type="text" class="input-error" placeholder="Invalid input" />

<!-- Badges -->
<span class="badge-success">Active</span>
<span class="badge-warning">Pending</span>
<span class="badge-error">Failed</span>

<!-- Custom utilities -->
<h1 class="text-4xl font-bold text-gradient">
  Gradient Text!
</h1>`}
          />

          <Alert severity="info" sx={{ my: 3 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>When to Use @apply vs Utilities</AlertTitle>
            <Typography variant="body2">
              <strong>Use @apply when:</strong> You have truly reusable components (buttons, cards) that appear 
              many times with the exact same styling.
              <br /><br />
              <strong>Use utilities directly when:</strong> The styling varies (different padding, colors) or 
              the element is unique. The Tailwind team recommends using utilities directly most of the time.
            </Typography>
          </Alert>

          {/* ==================== GRADIENT & DECORATION UTILITIES ==================== */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#06b6d4" }}>
            🌈 Gradients & Visual Effects
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2, lineHeight: 1.8 }}>
            Tailwind has powerful utilities for gradients, shadows, filters, and other visual effects that 
            can make your designs pop without writing any custom CSS.
          </Typography>
          <CodeBlock
            title="Gradient Utilities"
            code={`<!-- Linear gradients: bg-gradient-to-{direction} -->
<!-- Directions: t(top), b(bottom), l(left), r(right), tl, tr, bl, br -->

<!-- Simple two-color gradient -->
<div class="bg-gradient-to-r from-blue-500 to-purple-500">
  Left to right: blue → purple
</div>

<!-- Three-color gradient with 'via' -->
<div class="bg-gradient-to-r from-pink-500 via-red-500 to-yellow-500">
  Pink → Red → Yellow
</div>

<!-- Diagonal gradient -->
<div class="bg-gradient-to-br from-green-400 to-blue-600">
  Top-left to bottom-right
</div>

<!-- Gradient text (combine with text-transparent and bg-clip-text) -->
<h1 class="text-5xl font-bold bg-gradient-to-r from-cyan-500 to-blue-500 
           bg-clip-text text-transparent">
  Gradient Text Effect
</h1>

<!-- Gradient button -->
<button class="bg-gradient-to-r from-purple-500 to-pink-500 
               hover:from-purple-600 hover:to-pink-600 
               text-white px-6 py-3 rounded-lg font-semibold
               transition-all duration-300">
  Gradient Button
</button>

<!-- Gradient border (using a wrapper) -->
<div class="bg-gradient-to-r from-pink-500 via-purple-500 to-blue-500 p-0.5 rounded-lg">
  <div class="bg-white dark:bg-gray-900 rounded-lg p-4">
    Content with gradient border
  </div>
</div>

<!-- Gradient overlay on image -->
<div class="relative">
  <img src="hero.jpg" class="w-full h-96 object-cover" />
  <div class="absolute inset-0 bg-gradient-to-t from-black/80 to-transparent"></div>
  <h2 class="absolute bottom-4 left-4 text-white text-3xl font-bold">
    Text over gradient overlay
  </h2>
</div>`}
          />
          <CodeBlock
            title="Shadows & Effects"
            code={`<!-- Box shadows: shadow-{size} -->
<div class="shadow-sm">Small shadow</div>
<div class="shadow">Default shadow</div>
<div class="shadow-md">Medium shadow</div>
<div class="shadow-lg">Large shadow</div>
<div class="shadow-xl">Extra large shadow</div>
<div class="shadow-2xl">2XL shadow</div>
<div class="shadow-inner">Inner shadow</div>
<div class="shadow-none">No shadow</div>

<!-- Colored shadows -->
<div class="shadow-lg shadow-blue-500/50">Blue shadow (50% opacity)</div>
<div class="shadow-xl shadow-red-500/30">Red shadow (30% opacity)</div>

<!-- Ring (like an outline, but better) -->
<button class="ring-2 ring-blue-500">Ring utility</button>
<button class="ring-4 ring-offset-2 ring-purple-500">Ring with offset</button>

<!-- Backdrop blur (for glassmorphism) -->
<div class="bg-white/30 backdrop-blur-lg rounded-xl p-6">
  <h3 class="text-lg font-semibold">Glassmorphism Card</h3>
  <p>Content with frosted glass effect</p>
</div>

<!-- Blur filter -->
<img class="blur-sm hover:blur-none transition-all" src="..." />

<!-- Brightness, contrast, saturation -->
<img class="brightness-110 contrast-125 saturate-150" src="..." />

<!-- Grayscale and sepia -->
<img class="grayscale hover:grayscale-0 transition-all" src="..." />
<img class="sepia" src="..." />

<!-- Drop shadow (for images with transparency) -->
<img class="drop-shadow-lg" src="logo.png" />
<img class="drop-shadow-[0_10px_20px_rgba(0,0,0,0.25)]" src="..." />`}
          />

          {/* ==================== ANIMATION UTILITIES ==================== */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#06b6d4" }}>
            ✨ Animation & Transitions
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2, lineHeight: 1.8 }}>
            Tailwind includes built-in animations and comprehensive transition utilities for smooth, 
            polished interactions without writing @keyframes.
          </Typography>
          <CodeBlock
            title="Built-in Animations"
            code={`<!-- Pre-built animations -->
<div class="animate-spin">🔄</div>     <!-- Continuous rotation -->
<div class="animate-ping">📡</div>     <!-- Ping effect (like notification) -->
<div class="animate-pulse">💓</div>    <!-- Pulse/fade effect -->
<div class="animate-bounce">⬆️</div>   <!-- Bouncing up and down -->

<!-- Practical uses -->

<!-- Loading spinner -->
<svg class="animate-spin h-5 w-5 text-blue-500" viewBox="0 0 24 24">
  <circle class="opacity-25" cx="12" cy="12" r="10" 
          stroke="currentColor" stroke-width="4" fill="none"/>
  <path class="opacity-75" fill="currentColor" 
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
</svg>

<!-- Notification badge ping -->
<span class="relative flex h-3 w-3">
  <span class="animate-ping absolute inline-flex h-full w-full 
               rounded-full bg-red-400 opacity-75"></span>
  <span class="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
</span>

<!-- Skeleton loading -->
<div class="animate-pulse space-y-4">
  <div class="h-4 bg-gray-300 rounded w-3/4"></div>
  <div class="h-4 bg-gray-300 rounded"></div>
  <div class="h-4 bg-gray-300 rounded w-5/6"></div>
</div>`}
          />
          <CodeBlock
            title="Transition Utilities"
            code={`<!-- Transition property: transition-{property} -->
<button class="transition-colors">Colors only</button>
<button class="transition-opacity">Opacity only</button>
<button class="transition-shadow">Shadow only</button>
<button class="transition-transform">Transform only</button>
<button class="transition-all">All properties (careful: can be heavy)</button>

<!-- Duration: duration-{ms} -->
<button class="transition-colors duration-75">75ms (very fast)</button>
<button class="transition-colors duration-150">150ms (fast)</button>
<button class="transition-colors duration-300">300ms (default)</button>
<button class="transition-colors duration-500">500ms (slow)</button>
<button class="transition-colors duration-1000">1000ms (very slow)</button>

<!-- Timing function: ease-{type} -->
<div class="transition-all ease-linear">Linear</div>
<div class="transition-all ease-in">Ease in (slow start)</div>
<div class="transition-all ease-out">Ease out (slow end)</div>
<div class="transition-all ease-in-out">Ease in-out</div>

<!-- Delay: delay-{ms} -->
<div class="transition-all delay-150">Waits 150ms before animating</div>

<!-- Complete hover animation -->
<button class="bg-blue-500 text-white px-6 py-3 rounded-lg
               transition-all duration-300 ease-out
               hover:bg-blue-600 hover:scale-105 hover:shadow-lg
               active:scale-95">
  Animated Button
</button>

<!-- Card hover effect -->
<div class="bg-white rounded-xl shadow-md p-6
            transition-all duration-300
            hover:shadow-xl hover:-translate-y-1">
  <h3 class="text-lg font-semibold">Hover Card</h3>
  <p class="text-gray-600">Lifts up on hover</p>
</div>`}
          />
          <CodeBlock
            title="Transform Utilities"
            code={`<!-- Scale -->
<div class="scale-50">50% size</div>
<div class="scale-100">Normal size</div>
<div class="scale-150">150% size</div>
<div class="hover:scale-110 transition-transform">Grows on hover</div>

<!-- Rotate -->
<div class="rotate-45">Rotated 45°</div>
<div class="rotate-90">Rotated 90°</div>
<div class="-rotate-12">Rotated -12°</div>
<div class="hover:rotate-180 transition-transform duration-500">Spins on hover</div>

<!-- Translate (move) -->
<div class="translate-x-4">Move right 1rem</div>
<div class="-translate-y-2">Move up 0.5rem</div>
<div class="hover:-translate-y-1 transition-transform">Lifts on hover</div>

<!-- Skew -->
<div class="skew-x-12">Skewed horizontally</div>
<div class="skew-y-6">Skewed vertically</div>

<!-- Transform origin -->
<div class="origin-top-left rotate-45">Rotates from top-left corner</div>
<div class="origin-center scale-150">Scales from center</div>

<!-- Combining transforms -->
<button class="hover:scale-105 hover:-translate-y-1 hover:rotate-1 
               transition-all duration-300">
  Multiple transforms on hover
</button>`}
          />

          {/* ==================== TAILWIND PLUGINS ==================== */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#06b6d4" }}>
            🔌 Official Tailwind Plugins
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2, lineHeight: 1.8 }}>
            Tailwind has official plugins that add commonly needed utilities. Install them via npm and 
            add to your config.
          </Typography>
          <CodeBlock
            title="Installing & Configuring Plugins"
            code={`# Install official plugins
npm install -D @tailwindcss/typography
npm install -D @tailwindcss/forms
npm install -D @tailwindcss/aspect-ratio
npm install -D @tailwindcss/container-queries

// tailwind.config.js
export default {
  content: ["./src/**/*.{js,jsx,ts,tsx}"],
  theme: { extend: {} },
  plugins: [
    require('@tailwindcss/typography'),
    require('@tailwindcss/forms'),
    require('@tailwindcss/aspect-ratio'),
    require('@tailwindcss/container-queries'),
  ],
}`}
          />
          <CodeBlock
            title="@tailwindcss/typography - Beautiful Prose"
            code={`<!-- The Typography plugin styles markdown/rich text content -->
<!-- Just add the 'prose' class to a container -->

<article class="prose lg:prose-xl dark:prose-invert mx-auto">
  <h1>My Blog Post Title</h1>
  <p>This paragraph will have beautiful typography with proper 
     line-height, spacing, and font sizes automatically applied.</p>
  
  <h2>A Subheading</h2>
  <p>All headings, paragraphs, lists, code blocks, and more are 
     styled consistently.</p>
  
  <ul>
    <li>Lists look great too</li>
    <li>No custom CSS needed</li>
    <li>Responsive by default</li>
  </ul>
  
  <blockquote>
    Blockquotes are styled beautifully with a left border.
  </blockquote>
  
  <pre><code>Code blocks are properly styled</code></pre>
</article>

<!-- Prose modifiers -->
<article class="prose prose-sm">Small size</article>
<article class="prose prose-lg">Large size</article>
<article class="prose prose-xl">Extra large</article>

<!-- Color themes -->
<article class="prose prose-slate">Slate gray text</article>
<article class="prose prose-blue">Blue accents</article>
<article class="prose dark:prose-invert">Dark mode support</article>`}
          />
          <CodeBlock
            title="@tailwindcss/forms - Better Form Styling"
            code={`<!-- The Forms plugin resets form elements to be easily styled -->
<!-- No special classes needed - just use normal form elements -->

<form class="space-y-4 max-w-md mx-auto">
  <!-- Text input - already looks good! -->
  <input type="text" placeholder="Your name" 
         class="w-full rounded-lg border-gray-300 
                focus:border-blue-500 focus:ring-blue-500" />
  
  <!-- Email input -->
  <input type="email" placeholder="Email address"
         class="w-full rounded-lg border-gray-300
                focus:border-blue-500 focus:ring-blue-500" />
  
  <!-- Select dropdown -->
  <select class="w-full rounded-lg border-gray-300
                 focus:border-blue-500 focus:ring-blue-500">
    <option>Option 1</option>
    <option>Option 2</option>
    <option>Option 3</option>
  </select>
  
  <!-- Textarea -->
  <textarea rows="4" placeholder="Your message"
            class="w-full rounded-lg border-gray-300
                   focus:border-blue-500 focus:ring-blue-500">
  </textarea>
  
  <!-- Checkbox -->
  <label class="flex items-center gap-2">
    <input type="checkbox" 
           class="rounded border-gray-300 text-blue-600 
                  focus:ring-blue-500" />
    <span>I agree to the terms</span>
  </label>
  
  <!-- Radio buttons -->
  <div class="space-y-2">
    <label class="flex items-center gap-2">
      <input type="radio" name="plan" value="free"
             class="border-gray-300 text-blue-600 focus:ring-blue-500" />
      <span>Free Plan</span>
    </label>
    <label class="flex items-center gap-2">
      <input type="radio" name="plan" value="pro"
             class="border-gray-300 text-blue-600 focus:ring-blue-500" />
      <span>Pro Plan</span>
    </label>
  </div>
  
  <button type="submit" 
          class="w-full bg-blue-600 text-white py-2 rounded-lg
                 hover:bg-blue-700 transition-colors">
    Submit
  </button>
</form>`}
          />
          <CodeBlock
            title="@tailwindcss/aspect-ratio - Responsive Embeds"
            code={`<!-- Maintain aspect ratios for videos, images, embeds -->

<!-- 16:9 aspect ratio (standard video) -->
<div class="aspect-w-16 aspect-h-9">
  <iframe src="https://youtube.com/embed/..." 
          class="w-full h-full object-cover"></iframe>
</div>

<!-- 4:3 aspect ratio (classic) -->
<div class="aspect-w-4 aspect-h-3">
  <img src="photo.jpg" class="w-full h-full object-cover" />
</div>

<!-- Square aspect ratio -->
<div class="aspect-w-1 aspect-h-1">
  <img src="profile.jpg" class="w-full h-full object-cover rounded-full" />
</div>

<!-- NEW: Native aspect-ratio (Tailwind 3.0+, no plugin needed) -->
<div class="aspect-video">16:9 aspect ratio</div>
<div class="aspect-square">1:1 aspect ratio</div>
<div class="aspect-[4/3]">Custom 4:3 ratio</div>
<div class="aspect-[21/9]">Ultra-wide 21:9</div>`}
          />

          {/* ==================== FORMS DEEP DIVE ==================== */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#06b6d4" }}>
            📝 Forms Deep Dive
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2, lineHeight: 1.8 }}>
            Forms are critical for any web application. Here's how to build beautiful, accessible forms 
            with Tailwind, including validation states and custom styling.
          </Typography>
          <CodeBlock
            title="Complete Form Example with Validation States"
            code={`<form class="max-w-lg mx-auto p-6 bg-white dark:bg-slate-800 rounded-xl shadow-lg">
  <h2 class="text-2xl font-bold mb-6 text-gray-900 dark:text-white">
    Contact Us
  </h2>
  
  <!-- Name field -->
  <div class="mb-4">
    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
      Full Name
    </label>
    <input type="text" 
           class="w-full px-4 py-2 rounded-lg border border-gray-300 
                  dark:border-slate-600 dark:bg-slate-700 dark:text-white
                  focus:border-blue-500 focus:ring-2 focus:ring-blue-200 
                  dark:focus:ring-blue-800 transition-colors"
           placeholder="John Doe" />
  </div>
  
  <!-- Email field with error state -->
  <div class="mb-4">
    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
      Email Address
    </label>
    <input type="email" 
           class="w-full px-4 py-2 rounded-lg border 
                  border-red-500 bg-red-50 dark:bg-red-900/20
                  focus:border-red-500 focus:ring-2 focus:ring-red-200 
                  transition-colors"
           value="invalid-email" />
    <p class="mt-1 text-sm text-red-600 flex items-center gap-1">
      <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/>
      </svg>
      Please enter a valid email address
    </p>
  </div>
  
  <!-- Success state example -->
  <div class="mb-4">
    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
      Username
    </label>
    <div class="relative">
      <input type="text" 
             class="w-full px-4 py-2 pr-10 rounded-lg border 
                    border-green-500 bg-green-50 dark:bg-green-900/20
                    focus:border-green-500 focus:ring-2 focus:ring-green-200 
                    transition-colors"
             value="johndoe123" />
      <svg class="absolute right-3 top-1/2 -translate-y-1/2 w-5 h-5 text-green-500" 
           fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
      </svg>
    </div>
    <p class="mt-1 text-sm text-green-600">Username is available!</p>
  </div>
  
  <!-- Select with icon -->
  <div class="mb-4">
    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
      Subject
    </label>
    <select class="w-full px-4 py-2 rounded-lg border border-gray-300 
                   dark:border-slate-600 dark:bg-slate-700 dark:text-white
                   focus:border-blue-500 focus:ring-2 focus:ring-blue-200 
                   transition-colors">
      <option value="">Select a subject...</option>
      <option value="general">General Inquiry</option>
      <option value="support">Technical Support</option>
      <option value="sales">Sales Question</option>
      <option value="feedback">Feedback</option>
    </select>
  </div>
  
  <!-- Textarea -->
  <div class="mb-4">
    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
      Message
    </label>
    <textarea rows="4"
              class="w-full px-4 py-2 rounded-lg border border-gray-300 
                     dark:border-slate-600 dark:bg-slate-700 dark:text-white
                     focus:border-blue-500 focus:ring-2 focus:ring-blue-200 
                     transition-colors resize-none"
              placeholder="How can we help you?"></textarea>
    <p class="mt-1 text-sm text-gray-500">Max 500 characters</p>
  </div>
  
  <!-- Checkbox group -->
  <div class="mb-6">
    <label class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
      Interests
    </label>
    <div class="space-y-2">
      <label class="flex items-center gap-3 cursor-pointer">
        <input type="checkbox" 
               class="w-5 h-5 rounded border-gray-300 text-blue-600 
                      focus:ring-blue-500 cursor-pointer" />
        <span class="text-gray-700 dark:text-gray-300">Web Development</span>
      </label>
      <label class="flex items-center gap-3 cursor-pointer">
        <input type="checkbox" 
               class="w-5 h-5 rounded border-gray-300 text-blue-600 
                      focus:ring-blue-500 cursor-pointer" checked />
        <span class="text-gray-700 dark:text-gray-300">Mobile Apps</span>
      </label>
      <label class="flex items-center gap-3 cursor-pointer">
        <input type="checkbox" 
               class="w-5 h-5 rounded border-gray-300 text-blue-600 
                      focus:ring-blue-500 cursor-pointer" />
        <span class="text-gray-700 dark:text-gray-300">UI/UX Design</span>
      </label>
    </div>
  </div>
  
  <!-- Submit button -->
  <button type="submit"
          class="w-full bg-blue-600 text-white py-3 rounded-lg font-semibold
                 hover:bg-blue-700 active:bg-blue-800 
                 focus:ring-4 focus:ring-blue-200 dark:focus:ring-blue-800
                 transition-all duration-200
                 disabled:bg-gray-400 disabled:cursor-not-allowed">
    Send Message
  </button>
</form>`}
          />

          {/* ==================== BUILDING REAL COMPONENTS ==================== */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#06b6d4" }}>
            🏗️ Building Real UI Components
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2, lineHeight: 1.8 }}>
            Let's build professional-quality UI components that you'll actually use in real projects. 
            These are production-ready patterns.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 600, mt: 3, mb: 2, color: "#06b6d4" }}>
            Responsive Navigation Bar
          </Typography>
          <CodeBlock
            title="Modern Navbar with Mobile Menu"
            code={`<nav class="bg-white dark:bg-slate-900 shadow-sm sticky top-0 z-50">
  <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
    <div class="flex justify-between h-16">
      <!-- Logo -->
      <div class="flex items-center">
        <a href="/" class="flex items-center gap-2">
          <div class="w-8 h-8 bg-gradient-to-r from-blue-600 to-purple-600 
                      rounded-lg flex items-center justify-center">
            <span class="text-white font-bold">A</span>
          </div>
          <span class="text-xl font-bold text-gray-900 dark:text-white">
            AppName
          </span>
        </a>
      </div>
      
      <!-- Desktop Navigation -->
      <div class="hidden md:flex items-center gap-8">
        <a href="#" class="text-gray-600 hover:text-blue-600 dark:text-gray-300 
                          dark:hover:text-blue-400 font-medium transition-colors">
          Features
        </a>
        <a href="#" class="text-gray-600 hover:text-blue-600 dark:text-gray-300 
                          dark:hover:text-blue-400 font-medium transition-colors">
          Pricing
        </a>
        <a href="#" class="text-gray-600 hover:text-blue-600 dark:text-gray-300 
                          dark:hover:text-blue-400 font-medium transition-colors">
          About
        </a>
        <a href="#" class="text-gray-600 hover:text-blue-600 dark:text-gray-300 
                          dark:hover:text-blue-400 font-medium transition-colors">
          Contact
        </a>
      </div>
      
      <!-- CTA Buttons -->
      <div class="hidden md:flex items-center gap-4">
        <a href="#" class="text-gray-600 hover:text-gray-900 dark:text-gray-300 
                          font-medium transition-colors">
          Sign In
        </a>
        <a href="#" class="bg-blue-600 text-white px-4 py-2 rounded-lg 
                          font-semibold hover:bg-blue-700 transition-colors">
          Get Started
        </a>
      </div>
      
      <!-- Mobile menu button -->
      <div class="flex md:hidden items-center">
        <button class="p-2 rounded-lg text-gray-600 hover:bg-gray-100 
                       dark:text-gray-300 dark:hover:bg-slate-800">
          <!-- Hamburger icon -->
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                  d="M4 6h16M4 12h16M4 18h16"/>
          </svg>
        </button>
      </div>
    </div>
  </div>
  
  <!-- Mobile menu (toggle with JS) -->
  <div class="md:hidden border-t border-gray-200 dark:border-slate-700">
    <div class="px-4 py-4 space-y-3">
      <a href="#" class="block text-gray-600 hover:text-blue-600 font-medium">Features</a>
      <a href="#" class="block text-gray-600 hover:text-blue-600 font-medium">Pricing</a>
      <a href="#" class="block text-gray-600 hover:text-blue-600 font-medium">About</a>
      <a href="#" class="block text-gray-600 hover:text-blue-600 font-medium">Contact</a>
      <hr class="border-gray-200 dark:border-slate-700" />
      <a href="#" class="block text-gray-600 font-medium">Sign In</a>
      <a href="#" class="block bg-blue-600 text-white text-center py-2 rounded-lg font-semibold">
        Get Started
      </a>
    </div>
  </div>
</nav>`}
          />

          <Typography variant="h6" sx={{ fontWeight: 600, mt: 4, mb: 2, color: "#06b6d4" }}>
            Hero Section with CTA
          </Typography>
          <CodeBlock
            title="Modern Hero Section"
            code={`<section class="relative overflow-hidden bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
  <!-- Background decoration -->
  <div class="absolute inset-0 bg-[url('/grid.svg')] bg-center opacity-20"></div>
  <div class="absolute top-20 left-10 w-72 h-72 bg-purple-500 rounded-full 
              mix-blend-multiply filter blur-3xl opacity-20 animate-pulse"></div>
  <div class="absolute bottom-20 right-10 w-72 h-72 bg-blue-500 rounded-full 
              mix-blend-multiply filter blur-3xl opacity-20 animate-pulse"></div>
  
  <div class="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24 md:py-32">
    <div class="text-center">
      <!-- Badge -->
      <span class="inline-flex items-center gap-2 px-4 py-1.5 rounded-full 
                   bg-blue-500/10 text-blue-400 text-sm font-medium mb-6
                   border border-blue-500/20">
        <span class="relative flex h-2 w-2">
          <span class="animate-ping absolute inline-flex h-full w-full 
                       rounded-full bg-blue-400 opacity-75"></span>
          <span class="relative inline-flex rounded-full h-2 w-2 bg-blue-500"></span>
        </span>
        Now in Public Beta
      </span>
      
      <!-- Headline -->
      <h1 class="text-4xl md:text-6xl lg:text-7xl font-bold text-white mb-6">
        Build amazing products
        <span class="block bg-gradient-to-r from-blue-400 via-purple-400 to-pink-400 
                     bg-clip-text text-transparent">
          faster than ever
        </span>
      </h1>
      
      <!-- Subheadline -->
      <p class="text-lg md:text-xl text-gray-300 max-w-2xl mx-auto mb-10">
        The modern development platform that helps you ship products 10x faster. 
        Stop wasting time on boilerplate and focus on what matters.
      </p>
      
      <!-- CTA Buttons -->
      <div class="flex flex-col sm:flex-row items-center justify-center gap-4">
        <a href="#" class="w-full sm:w-auto px-8 py-4 bg-white text-gray-900 
                          rounded-xl font-semibold text-lg
                          hover:bg-gray-100 transition-colors
                          flex items-center justify-center gap-2">
          Get Started Free
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                  d="M13 7l5 5m0 0l-5 5m5-5H6"/>
          </svg>
        </a>
        <a href="#" class="w-full sm:w-auto px-8 py-4 bg-white/10 text-white 
                          rounded-xl font-semibold text-lg border border-white/20
                          hover:bg-white/20 transition-colors
                          flex items-center justify-center gap-2">
          <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
            <path d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z"/>
          </svg>
          Watch Demo
        </a>
      </div>
      
      <!-- Trust badges -->
      <div class="mt-12 flex flex-wrap items-center justify-center gap-8 opacity-60">
        <span class="text-gray-400 text-sm">Trusted by teams at</span>
        <img src="/logos/google.svg" alt="Google" class="h-6" />
        <img src="/logos/meta.svg" alt="Meta" class="h-6" />
        <img src="/logos/stripe.svg" alt="Stripe" class="h-6" />
      </div>
    </div>
  </div>
</section>`}
          />

          <Typography variant="h6" sx={{ fontWeight: 600, mt: 4, mb: 2, color: "#06b6d4" }}>
            Feature Cards Grid
          </Typography>
          <CodeBlock
            title="Responsive Feature Cards"
            code={`<section class="py-20 bg-gray-50 dark:bg-slate-900">
  <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
    <div class="text-center mb-16">
      <h2 class="text-3xl md:text-4xl font-bold text-gray-900 dark:text-white mb-4">
        Everything you need to succeed
      </h2>
      <p class="text-lg text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
        Our platform provides all the tools and features you need to build, 
        deploy, and scale your applications.
      </p>
    </div>
    
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
      <!-- Feature Card 1 -->
      <div class="bg-white dark:bg-slate-800 rounded-2xl p-8 shadow-sm
                  hover:shadow-xl transition-shadow duration-300
                  border border-gray-100 dark:border-slate-700">
        <div class="w-12 h-12 bg-blue-100 dark:bg-blue-900/30 rounded-xl 
                    flex items-center justify-center mb-6">
          <svg class="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                  d="M13 10V3L4 14h7v7l9-11h-7z"/>
          </svg>
        </div>
        <h3 class="text-xl font-semibold text-gray-900 dark:text-white mb-3">
          Lightning Fast
        </h3>
        <p class="text-gray-600 dark:text-gray-400">
          Our platform is optimized for speed. Pages load in milliseconds, 
          keeping your users engaged.
        </p>
      </div>
      
      <!-- Feature Card 2 -->
      <div class="bg-white dark:bg-slate-800 rounded-2xl p-8 shadow-sm
                  hover:shadow-xl transition-shadow duration-300
                  border border-gray-100 dark:border-slate-700">
        <div class="w-12 h-12 bg-purple-100 dark:bg-purple-900/30 rounded-xl 
                    flex items-center justify-center mb-6">
          <svg class="w-6 h-6 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                  d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
          </svg>
        </div>
        <h3 class="text-xl font-semibold text-gray-900 dark:text-white mb-3">
          Enterprise Security
        </h3>
        <p class="text-gray-600 dark:text-gray-400">
          Bank-level encryption and security protocols keep your data safe 
          and compliant.
        </p>
      </div>
      
      <!-- Feature Card 3 -->
      <div class="bg-white dark:bg-slate-800 rounded-2xl p-8 shadow-sm
                  hover:shadow-xl transition-shadow duration-300
                  border border-gray-100 dark:border-slate-700">
        <div class="w-12 h-12 bg-green-100 dark:bg-green-900/30 rounded-xl 
                    flex items-center justify-center mb-6">
          <svg class="w-6 h-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
          </svg>
        </div>
        <h3 class="text-xl font-semibold text-gray-900 dark:text-white mb-3">
          99.9% Uptime
        </h3>
        <p class="text-gray-600 dark:text-gray-400">
          Our infrastructure is built for reliability. Your applications 
          stay online, always.
        </p>
      </div>
    </div>
  </div>
</section>`}
          />

          <Typography variant="h6" sx={{ fontWeight: 600, mt: 4, mb: 2, color: "#06b6d4" }}>
            Modal / Dialog
          </Typography>
          <CodeBlock
            title="Accessible Modal Component"
            code={`<!-- Modal backdrop -->
<div class="fixed inset-0 z-50 overflow-y-auto" aria-modal="true" role="dialog">
  <!-- Overlay -->
  <div class="fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity"></div>
  
  <!-- Modal container -->
  <div class="flex min-h-full items-center justify-center p-4">
    <!-- Modal panel -->
    <div class="relative w-full max-w-lg transform overflow-hidden rounded-2xl 
                bg-white dark:bg-slate-800 shadow-2xl transition-all
                animate-[fadeIn_0.2s_ease-out]">
      
      <!-- Close button -->
      <button class="absolute top-4 right-4 p-1 rounded-lg text-gray-400 
                     hover:text-gray-600 hover:bg-gray-100 
                     dark:hover:text-gray-300 dark:hover:bg-slate-700 
                     transition-colors">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                d="M6 18L18 6M6 6l12 12"/>
        </svg>
      </button>
      
      <!-- Modal content -->
      <div class="p-6">
        <!-- Icon -->
        <div class="mx-auto w-12 h-12 rounded-full bg-blue-100 dark:bg-blue-900/30 
                    flex items-center justify-center mb-4">
          <svg class="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                  d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
        </div>
        
        <!-- Title -->
        <h3 class="text-xl font-semibold text-gray-900 dark:text-white text-center mb-2">
          Confirm Action
        </h3>
        
        <!-- Description -->
        <p class="text-gray-600 dark:text-gray-400 text-center mb-6">
          Are you sure you want to perform this action? This cannot be undone.
        </p>
        
        <!-- Actions -->
        <div class="flex gap-3">
          <button class="flex-1 px-4 py-2.5 bg-gray-100 dark:bg-slate-700 
                         text-gray-700 dark:text-gray-300 rounded-lg font-medium
                         hover:bg-gray-200 dark:hover:bg-slate-600 transition-colors">
            Cancel
          </button>
          <button class="flex-1 px-4 py-2.5 bg-blue-600 text-white rounded-lg font-medium
                         hover:bg-blue-700 transition-colors">
            Confirm
          </button>
        </div>
      </div>
    </div>
  </div>
</div>

<!-- Delete confirmation variant -->
<div class="p-6">
  <div class="mx-auto w-12 h-12 rounded-full bg-red-100 dark:bg-red-900/30 
              flex items-center justify-center mb-4">
    <svg class="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
    </svg>
  </div>
  <h3 class="text-xl font-semibold text-gray-900 text-center mb-2">Delete Item?</h3>
  <p class="text-gray-600 text-center mb-6">
    This will permanently delete this item. This action cannot be undone.
  </p>
  <div class="flex gap-3">
    <button class="flex-1 px-4 py-2.5 bg-gray-100 rounded-lg font-medium">Cancel</button>
    <button class="flex-1 px-4 py-2.5 bg-red-600 text-white rounded-lg font-medium
                   hover:bg-red-700">Delete</button>
  </div>
</div>`}
          />

          <Typography variant="h6" sx={{ fontWeight: 600, mt: 4, mb: 2, color: "#06b6d4" }}>
            Footer
          </Typography>
          <CodeBlock
            title="Professional Footer"
            code={`<footer class="bg-slate-900 text-gray-300">
  <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
    <div class="grid grid-cols-2 md:grid-cols-4 gap-8 mb-12">
      <!-- Company -->
      <div>
        <h4 class="text-white font-semibold mb-4">Company</h4>
        <ul class="space-y-2">
          <li><a href="#" class="hover:text-white transition-colors">About</a></li>
          <li><a href="#" class="hover:text-white transition-colors">Careers</a></li>
          <li><a href="#" class="hover:text-white transition-colors">Press</a></li>
          <li><a href="#" class="hover:text-white transition-colors">Blog</a></li>
        </ul>
      </div>
      
      <!-- Product -->
      <div>
        <h4 class="text-white font-semibold mb-4">Product</h4>
        <ul class="space-y-2">
          <li><a href="#" class="hover:text-white transition-colors">Features</a></li>
          <li><a href="#" class="hover:text-white transition-colors">Pricing</a></li>
          <li><a href="#" class="hover:text-white transition-colors">Integrations</a></li>
          <li><a href="#" class="hover:text-white transition-colors">Changelog</a></li>
        </ul>
      </div>
      
      <!-- Resources -->
      <div>
        <h4 class="text-white font-semibold mb-4">Resources</h4>
        <ul class="space-y-2">
          <li><a href="#" class="hover:text-white transition-colors">Documentation</a></li>
          <li><a href="#" class="hover:text-white transition-colors">Guides</a></li>
          <li><a href="#" class="hover:text-white transition-colors">API Reference</a></li>
          <li><a href="#" class="hover:text-white transition-colors">Community</a></li>
        </ul>
      </div>
      
      <!-- Legal -->
      <div>
        <h4 class="text-white font-semibold mb-4">Legal</h4>
        <ul class="space-y-2">
          <li><a href="#" class="hover:text-white transition-colors">Privacy</a></li>
          <li><a href="#" class="hover:text-white transition-colors">Terms</a></li>
          <li><a href="#" class="hover:text-white transition-colors">Cookies</a></li>
          <li><a href="#" class="hover:text-white transition-colors">Licenses</a></li>
        </ul>
      </div>
    </div>
    
    <!-- Divider -->
    <div class="border-t border-slate-800 pt-8">
      <div class="flex flex-col md:flex-row justify-between items-center gap-4">
        <!-- Logo & copyright -->
        <div class="flex items-center gap-3">
          <div class="w-8 h-8 bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg"></div>
          <span class="text-sm">© 2024 AppName. All rights reserved.</span>
        </div>
        
        <!-- Social links -->
        <div class="flex items-center gap-4">
          <a href="#" class="hover:text-white transition-colors">
            <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
              <path d="M24 4.557c-.883.392-1.832.656-2.828.775 1.017-.609 1.798-1.574 2.165-2.724-.951.564-2.005.974-3.127 1.195-.897-.957-2.178-1.555-3.594-1.555-3.179 0-5.515 2.966-4.797 6.045-4.091-.205-7.719-2.165-10.148-5.144-1.29 2.213-.669 5.108 1.523 6.574-.806-.026-1.566-.247-2.229-.616-.054 2.281 1.581 4.415 3.949 4.89-.693.188-1.452.232-2.224.084.626 1.956 2.444 3.379 4.6 3.419-2.07 1.623-4.678 2.348-7.29 2.04 2.179 1.397 4.768 2.212 7.548 2.212 9.142 0 14.307-7.721 13.995-14.646.962-.695 1.797-1.562 2.457-2.549z"/>
            </svg>
          </a>
          <a href="#" class="hover:text-white transition-colors">
            <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
            </svg>
          </a>
          <a href="#" class="hover:text-white transition-colors">
            <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
              <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
            </svg>
          </a>
        </div>
      </div>
    </div>
  </div>
</footer>`}
          />

          {/* ==================== TAILWIND WITH REACT ==================== */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#06b6d4" }}>
            ⚛️ Tailwind with React
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2, lineHeight: 1.8 }}>
            Tailwind and React are a perfect match. Here's how to build reusable React components with 
            Tailwind, including patterns for handling dynamic classes and component variants.
          </Typography>
          <CodeBlock
            title="React Component Patterns with Tailwind"
            code={`// Button.jsx - Reusable button component with variants
import { clsx } from 'clsx';  // npm install clsx (helps combine classes)

const Button = ({ 
  children, 
  variant = 'primary', 
  size = 'md', 
  disabled = false,
  className,
  ...props 
}) => {
  // Base styles that apply to all buttons
  const baseStyles = \`
    inline-flex items-center justify-center font-semibold rounded-lg
    transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2
    disabled:opacity-50 disabled:cursor-not-allowed
  \`;
  
  // Variant styles
  const variants = {
    primary: 'bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500',
    secondary: 'bg-gray-200 text-gray-800 hover:bg-gray-300 focus:ring-gray-500',
    danger: 'bg-red-600 text-white hover:bg-red-700 focus:ring-red-500',
    outline: 'border-2 border-blue-600 text-blue-600 hover:bg-blue-50 focus:ring-blue-500',
    ghost: 'text-gray-600 hover:bg-gray-100 focus:ring-gray-500',
  };
  
  // Size styles
  const sizes = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-4 py-2 text-base',
    lg: 'px-6 py-3 text-lg',
  };
  
  return (
    <button
      className={clsx(baseStyles, variants[variant], sizes[size], className)}
      disabled={disabled}
      {...props}
    >
      {children}
    </button>
  );
};

// Usage
<Button variant="primary" size="lg">Click Me</Button>
<Button variant="outline">Learn More</Button>
<Button variant="danger" size="sm">Delete</Button>`}
          />
          <CodeBlock
            title="Card Component with Tailwind"
            code={`// Card.jsx - Composable card component
const Card = ({ children, className, ...props }) => (
  <div 
    className={clsx(
      'bg-white dark:bg-slate-800 rounded-xl shadow-md',
      'border border-gray-200 dark:border-slate-700',
      'overflow-hidden',
      className
    )}
    {...props}
  >
    {children}
  </div>
);

Card.Header = ({ children, className }) => (
  <div className={clsx('px-6 py-4 border-b border-gray-200 dark:border-slate-700', className)}>
    {children}
  </div>
);

Card.Body = ({ children, className }) => (
  <div className={clsx('p-6', className)}>
    {children}
  </div>
);

Card.Footer = ({ children, className }) => (
  <div className={clsx('px-6 py-4 bg-gray-50 dark:bg-slate-700/50', className)}>
    {children}
  </div>
);

// Usage
<Card>
  <Card.Header>
    <h3 className="text-lg font-semibold">Card Title</h3>
  </Card.Header>
  <Card.Body>
    <p className="text-gray-600 dark:text-gray-300">
      Card content goes here...
    </p>
  </Card.Body>
  <Card.Footer>
    <Button variant="primary">Action</Button>
  </Card.Footer>
</Card>`}
          />
          <CodeBlock
            title="Conditional Classes with clsx"
            code={`// npm install clsx (or use classnames package)
import { clsx } from 'clsx';

// Simple conditional
<div className={clsx(
  'base-class',
  isActive && 'active-class',
  isDisabled && 'disabled-class'
)}>

// Object syntax
<div className={clsx({
  'bg-blue-500': isPrimary,
  'bg-gray-500': !isPrimary,
  'opacity-50': isDisabled,
  'cursor-pointer': !isDisabled,
})}>

// Array syntax
<div className={clsx([
  'base',
  condition1 && 'class1',
  condition2 && 'class2',
])}>

// Real example: Status badge
const StatusBadge = ({ status }) => {
  const statusStyles = {
    active: 'bg-green-100 text-green-800',
    pending: 'bg-yellow-100 text-yellow-800',
    inactive: 'bg-gray-100 text-gray-800',
    error: 'bg-red-100 text-red-800',
  };
  
  return (
    <span className={clsx(
      'px-2.5 py-0.5 rounded-full text-xs font-medium',
      statusStyles[status]
    )}>
      {status}
    </span>
  );
};`}
          />

          {/* ==================== TAILWIND VS BOOTSTRAP ==================== */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#06b6d4" }}>
            🥊 Tailwind vs Bootstrap: When to Use Which
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 2, lineHeight: 1.8 }}>
            Both are excellent frameworks, but they have different philosophies and use cases. 
            Understanding when to use each will make you a more effective developer.
          </Typography>
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: alpha("#06b6d4", 0.05), border: `1px solid ${alpha("#06b6d4", 0.2)}`, height: "100%" }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#06b6d4", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                  🌊 Choose Tailwind When:
                </Typography>
                <List dense>
                  <ListItem sx={{ py: 0.5 }}><ListItemText primary="You want complete design freedom and custom aesthetics" /></ListItem>
                  <ListItem sx={{ py: 0.5 }}><ListItemText primary="Building a unique brand identity is important" /></ListItem>
                  <ListItem sx={{ py: 0.5 }}><ListItemText primary="You're working with a design system or Figma designs" /></ListItem>
                  <ListItem sx={{ py: 0.5 }}><ListItemText primary="You want the smallest possible CSS bundle size" /></ListItem>
                  <ListItem sx={{ py: 0.5 }}><ListItemText primary="You prefer keeping styles in your HTML/JSX" /></ListItem>
                  <ListItem sx={{ py: 0.5 }}><ListItemText primary="You're building modern SPAs with React/Vue" /></ListItem>
                  <ListItem sx={{ py: 0.5 }}><ListItemText primary="You want to avoid 'Bootstrap look'" /></ListItem>
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, bgcolor: alpha("#7952b3", 0.05), border: `1px solid ${alpha("#7952b3", 0.2)}`, height: "100%" }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#7952b3", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                  🅱️ Choose Bootstrap When:
                </Typography>
                <List dense>
                  <ListItem sx={{ py: 0.5 }}><ListItemText primary="You need to prototype quickly with pre-built components" /></ListItem>
                  <ListItem sx={{ py: 0.5 }}><ListItemText primary="Working on admin dashboards or internal tools" /></ListItem>
                  <ListItem sx={{ py: 0.5 }}><ListItemText primary="Your team is already familiar with Bootstrap" /></ListItem>
                  <ListItem sx={{ py: 0.5 }}><ListItemText primary="You need extensive JavaScript components (modals, dropdowns)" /></ListItem>
                  <ListItem sx={{ py: 0.5 }}><ListItemText primary="Design consistency is more important than uniqueness" /></ListItem>
                  <ListItem sx={{ py: 0.5 }}><ListItemText primary="You prefer separation of HTML and CSS" /></ListItem>
                  <ListItem sx={{ py: 0.5 }}><ListItemText primary="Working with server-rendered apps (Django, Rails, PHP)" /></ListItem>
                </List>
              </Paper>
            </Grid>
          </Grid>
          <CodeBlock
            title="Same Button: Tailwind vs Bootstrap"
            code={`<!-- Tailwind: Explicit, customizable -->
<button class="px-4 py-2 bg-blue-600 text-white font-semibold rounded-lg 
               hover:bg-blue-700 focus:ring-2 focus:ring-blue-500 focus:ring-offset-2
               transition-colors">
  Click Me
</button>

<!-- Bootstrap: Pre-built, consistent -->
<button class="btn btn-primary">
  Click Me
</button>

<!-- The difference:
- Tailwind: You control everything, but you write more
- Bootstrap: Less code, but less control -->

<!-- Tailwind excels when you need variations -->
<button class="px-6 py-3 bg-gradient-to-r from-purple-600 to-pink-600 
               text-white font-bold rounded-full shadow-lg
               hover:shadow-xl hover:scale-105 transition-all duration-300">
  Custom Button
</button>

<!-- This would be much harder in Bootstrap -->`}
          />

          {/* ==================== BEST PRACTICES ==================== */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#06b6d4" }}>
            ✅ Tailwind Best Practices
          </Typography>
          <List>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#06b6d4" }} /></ListItemIcon>
              <ListItemText 
                primary="Use the Tailwind CSS IntelliSense extension"
                secondary="Provides autocomplete, syntax highlighting, and linting in VS Code" 
              />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#06b6d4" }} /></ListItemIcon>
              <ListItemText 
                primary="Order classes consistently"
                secondary="Layout → Spacing → Sizing → Colors → Typography → Effects. Use Prettier plugin for auto-sorting" 
              />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#06b6d4" }} /></ListItemIcon>
              <ListItemText 
                primary="Extract components, not classes"
                secondary="Instead of @apply for everything, create React/Vue components that encapsulate Tailwind classes" 
              />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#06b6d4" }} /></ListItemIcon>
              <ListItemText 
                primary="Use design tokens in your config"
                secondary="Define colors, spacing, and fonts in tailwind.config.js for consistency" 
              />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#06b6d4" }} /></ListItemIcon>
              <ListItemText 
                primary="Embrace the utility-first mindset"
                secondary="Don't fight it - inline styles are OK in Tailwind. That's the whole point!" 
              />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#06b6d4" }} /></ListItemIcon>
              <ListItemText 
                primary="Use arbitrary values sparingly"
                secondary="[100px] or [#ff0000] should be exceptions, not the rule. Extend your config instead" 
              />
            </ListItem>
          </List>

          <Alert severity="info" sx={{ mt: 3, mb: 3 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Tailwind v4.0 Preview (Coming Soon)</AlertTitle>
            <Typography variant="body2">
              Tailwind v4 will be even faster with a new engine written in Rust, native CSS cascade layers, 
              and improved configuration. The utility classes you learn now will still work - it's mostly 
              internal improvements. Stay tuned!
            </Typography>
          </Alert>

          {/* Building a Component */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#06b6d4" }}>
            Building a Complete Component
          </Typography>
          <CodeBlock
            title="Tailwind Card Component"
            code={`<!-- Modern card with all the bells and whistles -->
<div class="max-w-sm mx-auto">
  <div class="bg-white dark:bg-gray-800 rounded-2xl shadow-lg 
              overflow-hidden hover:shadow-xl transition-shadow duration-300">
    <!-- Image -->
    <img src="product.jpg" alt="Product" 
         class="w-full h-48 object-cover" />
    
    <!-- Content -->
    <div class="p-6">
      <!-- Badge -->
      <span class="inline-block px-3 py-1 text-xs font-semibold 
                   text-green-800 bg-green-100 rounded-full mb-3">
        New Release
      </span>
      
      <!-- Title -->
      <h3 class="text-xl font-bold text-gray-900 dark:text-white mb-2">
        Product Name
      </h3>
      
      <!-- Description -->
      <p class="text-gray-600 dark:text-gray-300 text-sm mb-4">
        A brief description of this amazing product that 
        you definitely want to buy.
      </p>
      
      <!-- Price and button -->
      <div class="flex items-center justify-between">
        <span class="text-2xl font-bold text-blue-600">
          $49.99
        </span>
        <button class="px-4 py-2 bg-blue-600 text-white rounded-lg 
                       font-semibold hover:bg-blue-700 
                       active:bg-blue-800 transition-colors">
          Add to Cart
        </button>
      </div>
    </div>
  </div>
</div>`}
          />

          {/* Practice Exercises */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#06b6d4" }}>
            ✏️ Practice Exercises
          </Typography>
          <List dense>
            <ListItem>
              <ListItemIcon><AutoAwesomeIcon sx={{ color: "#06b6d4" }} /></ListItemIcon>
              <ListItemText primary="Build a responsive navigation bar with Tailwind" />
            </ListItem>
            <ListItem>
              <ListItemIcon><AutoAwesomeIcon sx={{ color: "#06b6d4" }} /></ListItemIcon>
              <ListItemText primary="Create a hero section with a gradient background" />
            </ListItem>
            <ListItem>
              <ListItemIcon><AutoAwesomeIcon sx={{ color: "#06b6d4" }} /></ListItemIcon>
              <ListItemText primary="Build a pricing table with 3 tiers that stack on mobile" />
            </ListItem>
            <ListItem>
              <ListItemIcon><AutoAwesomeIcon sx={{ color: "#06b6d4" }} /></ListItemIcon>
              <ListItemText primary="Create a dark/light mode toggle for a card" />
            </ListItem>
            <ListItem>
              <ListItemIcon><AutoAwesomeIcon sx={{ color: "#06b6d4" }} /></ListItemIcon>
              <ListItemText primary="Build a form with focus states and validation styling" />
            </ListItem>
          </List>
        </Paper>

        {/* ==================== MODULE 15: REAL-WORLD PROJECTS ==================== */}
        <Paper
          id="module-15-content"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha("#ef4444", 0.03),
            border: `1px solid ${alpha("#ef4444", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3, flexWrap: "wrap" }}>
            <WebIcon sx={{ fontSize: 36, color: "#ef4444" }} />
            <Typography variant="h4" sx={{ fontWeight: 800, color: "#ef4444" }}>
              Module 15: Real-World Projects
            </Typography>
            <Chip label="Advanced" sx={{ bgcolor: alpha("#ef4444", 0.15), color: "#ef4444", fontWeight: 600 }} />
          </Box>

          <Typography variant="body1" color="text.secondary" sx={{ mb: 4, fontSize: "1.1rem", lineHeight: 1.8 }}>
            It's time to put everything together! In this final module, you'll build complete, real-world projects 
            and learn how to deploy them to the web. These projects will give you portfolio pieces and practical 
            experience building responsive, modern websites.
          </Typography>

          {/* Project 1: Personal Portfolio */}
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
            🎨 Project 1: Personal Portfolio Website
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3, lineHeight: 1.8 }}>
            A portfolio is essential for any developer. It showcases your skills, projects, and personality to 
            potential employers or clients.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 600, mt: 3, mb: 2, color: "#ef4444" }}>
            Portfolio Structure
          </Typography>
          <CodeBlock
            title="Portfolio HTML Structure"
            code={`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>John Doe | Web Developer</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <!-- Navigation -->
  <nav class="navbar">
    <div class="logo">JD</div>
    <ul class="nav-links">
      <li><a href="#about">About</a></li>
      <li><a href="#projects">Projects</a></li>
      <li><a href="#skills">Skills</a></li>
      <li><a href="#contact">Contact</a></li>
    </ul>
  </nav>

  <!-- Hero Section -->
  <header class="hero">
    <h1>Hi, I'm <span class="highlight">John Doe</span></h1>
    <p class="tagline">Frontend Developer & UI Designer</p>
    <a href="#projects" class="cta-button">View My Work</a>
  </header>

  <!-- About Section -->
  <section id="about" class="section">
    <h2>About Me</h2>
    <p>I'm a passionate developer who loves creating beautiful, 
       responsive websites...</p>
  </section>

  <!-- Projects Section -->
  <section id="projects" class="section">
    <h2>My Projects</h2>
    <div class="project-grid">
      <article class="project-card">
        <img src="project1.jpg" alt="Project 1">
        <h3>E-commerce Store</h3>
        <p>A fully responsive online store built with HTML, CSS, and JS.</p>
        <div class="project-links">
          <a href="#">Live Demo</a>
          <a href="#">GitHub</a>
        </div>
      </article>
      <!-- More project cards... -->
    </div>
  </section>

  <!-- Skills Section -->
  <section id="skills" class="section">
    <h2>Skills</h2>
    <div class="skills-grid">
      <div class="skill">HTML5</div>
      <div class="skill">CSS3</div>
      <div class="skill">JavaScript</div>
      <div class="skill">React</div>
      <div class="skill">Git</div>
    </div>
  </section>

  <!-- Contact Section -->
  <section id="contact" class="section">
    <h2>Get In Touch</h2>
    <form class="contact-form">
      <input type="text" placeholder="Your Name" required>
      <input type="email" placeholder="Your Email" required>
      <textarea placeholder="Your Message" required></textarea>
      <button type="submit">Send Message</button>
    </form>
  </section>

  <!-- Footer -->
  <footer>
    <p>&copy; 2024 John Doe. All rights reserved.</p>
    <div class="social-links">
      <a href="#">GitHub</a>
      <a href="#">LinkedIn</a>
      <a href="#">Twitter</a>
    </div>
  </footer>
</body>
</html>`}
          />

          <CodeBlock
            title="Portfolio CSS Styles"
            code={`/* CSS Variables for consistent theming */
:root {
  --primary: #3b82f6;
  --secondary: #1e293b;
  --accent: #f97316;
  --text: #334155;
  --light: #f8fafc;
}

/* Reset and base styles */
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: 'Inter', sans-serif;
  line-height: 1.6;
  color: var(--text);
}

/* Navigation */
.navbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem 5%;
  position: fixed;
  width: 100%;
  background: white;
  box-shadow: 0 2px 10px rgba(0,0,0,0.1);
  z-index: 1000;
}

.logo {
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--primary);
}

.nav-links {
  display: flex;
  list-style: none;
  gap: 2rem;
}

.nav-links a {
  text-decoration: none;
  color: var(--secondary);
  font-weight: 500;
  transition: color 0.3s;
}

.nav-links a:hover {
  color: var(--primary);
}

/* Hero Section */
.hero {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  text-align: center;
  background: linear-gradient(135deg, var(--light), #e2e8f0);
  padding: 0 1rem;
}

.hero h1 {
  font-size: clamp(2rem, 5vw, 4rem);
  margin-bottom: 1rem;
}

.highlight {
  color: var(--primary);
}

.tagline {
  font-size: 1.25rem;
  color: var(--text);
  margin-bottom: 2rem;
}

.cta-button {
  display: inline-block;
  padding: 1rem 2rem;
  background: var(--primary);
  color: white;
  text-decoration: none;
  border-radius: 8px;
  font-weight: 600;
  transition: transform 0.3s, box-shadow 0.3s;
}

.cta-button:hover {
  transform: translateY(-3px);
  box-shadow: 0 10px 20px rgba(59, 130, 246, 0.3);
}

/* Sections */
.section {
  padding: 5rem 10%;
}

.section h2 {
  font-size: 2rem;
  margin-bottom: 2rem;
  text-align: center;
}

/* Project Grid */
.project-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
  gap: 2rem;
}

.project-card {
  background: white;
  border-radius: 12px;
  overflow: hidden;
  box-shadow: 0 4px 20px rgba(0,0,0,0.1);
  transition: transform 0.3s;
}

.project-card:hover {
  transform: translateY(-5px);
}

.project-card img {
  width: 100%;
  height: 200px;
  object-fit: cover;
}

.project-card h3, .project-card p {
  padding: 0 1.5rem;
}

/* Skills Grid */
.skills-grid {
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 1rem;
}

.skill {
  padding: 0.75rem 1.5rem;
  background: var(--primary);
  color: white;
  border-radius: 50px;
  font-weight: 500;
}

/* Contact Form */
.contact-form {
  max-width: 500px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.contact-form input,
.contact-form textarea {
  padding: 1rem;
  border: 2px solid #e2e8f0;
  border-radius: 8px;
  font-size: 1rem;
}

.contact-form input:focus,
.contact-form textarea:focus {
  outline: none;
  border-color: var(--primary);
}

.contact-form button {
  padding: 1rem;
  background: var(--primary);
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 1rem;
  cursor: pointer;
}

/* Responsive Design */
@media (max-width: 768px) {
  .nav-links {
    display: none; /* Add hamburger menu with JS */
  }
  
  .section {
    padding: 3rem 5%;
  }
}`}
          />

          {/* Project 2: Landing Page */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 5, mb: 2, color: "#ef4444" }}>
            🚀 Project 2: SaaS Landing Page
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3, lineHeight: 1.8 }}>
            Landing pages are crucial for marketing. Learn to create conversion-focused designs with clear 
            call-to-actions, feature sections, pricing tables, and testimonials.
          </Typography>

          <CodeBlock
            title="Landing Page Key Sections"
            code={`<!-- Hero with value proposition -->
<header class="landing-hero">
  <div class="hero-content">
    <h1>Build Faster with <span>ProductName</span></h1>
    <p>The all-in-one platform that helps teams ship 10x faster.</p>
    <div class="hero-cta">
      <a href="#" class="btn-primary">Start Free Trial</a>
      <a href="#" class="btn-secondary">Watch Demo</a>
    </div>
    <p class="social-proof">Trusted by 10,000+ teams worldwide</p>
  </div>
  <div class="hero-image">
    <img src="dashboard-mockup.png" alt="Product screenshot">
  </div>
</header>

<!-- Features Section -->
<section class="features">
  <h2>Everything you need to succeed</h2>
  <div class="features-grid">
    <div class="feature">
      <div class="feature-icon">⚡</div>
      <h3>Lightning Fast</h3>
      <p>Built for speed with optimized performance.</p>
    </div>
    <div class="feature">
      <div class="feature-icon">🔒</div>
      <h3>Secure by Default</h3>
      <p>Enterprise-grade security built in.</p>
    </div>
    <div class="feature">
      <div class="feature-icon">🔄</div>
      <h3>Seamless Integration</h3>
      <p>Connect with your favorite tools.</p>
    </div>
  </div>
</section>

<!-- Pricing Section -->
<section class="pricing">
  <h2>Simple, transparent pricing</h2>
  <div class="pricing-grid">
    <div class="pricing-card">
      <h3>Starter</h3>
      <div class="price">$9<span>/month</span></div>
      <ul>
        <li>✓ 5 Projects</li>
        <li>✓ Basic Analytics</li>
        <li>✓ Email Support</li>
      </ul>
      <a href="#" class="btn-outline">Get Started</a>
    </div>
    <div class="pricing-card featured">
      <div class="badge">Most Popular</div>
      <h3>Professional</h3>
      <div class="price">$29<span>/month</span></div>
      <ul>
        <li>✓ Unlimited Projects</li>
        <li>✓ Advanced Analytics</li>
        <li>✓ Priority Support</li>
        <li>✓ Custom Integrations</li>
      </ul>
      <a href="#" class="btn-primary">Get Started</a>
    </div>
    <div class="pricing-card">
      <h3>Enterprise</h3>
      <div class="price">Custom</div>
      <ul>
        <li>✓ Everything in Pro</li>
        <li>✓ Dedicated Account Manager</li>
        <li>✓ SLA Guarantee</li>
      </ul>
      <a href="#" class="btn-outline">Contact Sales</a>
    </div>
  </div>
</section>

<!-- Testimonials -->
<section class="testimonials">
  <h2>What our customers say</h2>
  <div class="testimonial-grid">
    <blockquote class="testimonial">
      <p>"This product changed how our team works. Highly recommended!"</p>
      <cite>
        <img src="avatar1.jpg" alt="Jane Smith">
        <strong>Jane Smith</strong>
        <span>CEO, TechCorp</span>
      </cite>
    </blockquote>
  </div>
</section>`}
          />

          {/* Project 3: Dashboard UI */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 5, mb: 2, color: "#ef4444" }}>
            📊 Project 3: Admin Dashboard
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3, lineHeight: 1.8 }}>
            Dashboards are complex UIs that require good layout skills. Practice CSS Grid for the main layout 
            and Flexbox for components.
          </Typography>

          <CodeBlock
            title="Dashboard Layout with CSS Grid"
            code={`/* Dashboard Layout */
.dashboard {
  display: grid;
  grid-template-columns: 250px 1fr;
  grid-template-rows: 60px 1fr;
  grid-template-areas:
    "sidebar header"
    "sidebar main";
  min-height: 100vh;
}

/* Sidebar */
.sidebar {
  grid-area: sidebar;
  background: #1e293b;
  color: white;
  padding: 1rem;
}

.sidebar-nav {
  list-style: none;
  margin-top: 2rem;
}

.sidebar-nav a {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 1rem;
  color: #94a3b8;
  text-decoration: none;
  border-radius: 8px;
  transition: all 0.3s;
}

.sidebar-nav a:hover,
.sidebar-nav a.active {
  background: #334155;
  color: white;
}

/* Header */
.header {
  grid-area: header;
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0 2rem;
  background: white;
  border-bottom: 1px solid #e2e8f0;
}

/* Main Content */
.main-content {
  grid-area: main;
  padding: 2rem;
  background: #f1f5f9;
  overflow-y: auto;
}

/* Stats Cards */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
}

.stat-card {
  background: white;
  padding: 1.5rem;
  border-radius: 12px;
  box-shadow: 0 1px 3px rgba(0,0,0,0.1);
}

.stat-card h3 {
  font-size: 0.875rem;
  color: #64748b;
  margin-bottom: 0.5rem;
}

.stat-card .value {
  font-size: 2rem;
  font-weight: 700;
  color: #1e293b;
}

.stat-card .trend {
  font-size: 0.875rem;
  color: #22c55e;
}

/* Responsive - Collapse sidebar on mobile */
@media (max-width: 768px) {
  .dashboard {
    grid-template-columns: 1fr;
    grid-template-areas:
      "header"
      "main";
  }
  
  .sidebar {
    position: fixed;
    left: -250px;
    height: 100%;
    transition: left 0.3s;
    z-index: 1000;
  }
  
  .sidebar.open {
    left: 0;
  }
}`}
          />

          {/* Deployment */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 5, mb: 2, color: "#ef4444" }}>
            🌐 Deploying Your Projects
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3, lineHeight: 1.8 }}>
            Once your project is ready, you need to put it on the internet! Here are three popular free 
            hosting options for static websites:
          </Typography>

          <Grid container spacing={3} sx={{ mb: 4 }}>
            {[
              { name: "GitHub Pages", desc: "Free hosting directly from your GitHub repository. Perfect for portfolios.", steps: "1. Push code to GitHub\n2. Go to Settings → Pages\n3. Select branch (main)\n4. Your site is live!" },
              { name: "Netlify", desc: "Drag-and-drop deployment with custom domains and HTTPS.", steps: "1. Create account at netlify.com\n2. Drag your project folder\n3. Get instant URL\n4. Connect custom domain" },
              { name: "Vercel", desc: "Optimized for modern web projects with automatic deployments.", steps: "1. Sign up at vercel.com\n2. Import from GitHub\n3. Auto-deploys on push\n4. Preview deployments" },
            ].map((platform) => (
              <Grid item xs={12} md={4} key={platform.name}>
                <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.15)}` }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>{platform.name}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.6 }}>{platform.desc}</Typography>
                  <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#1e1e1e", 0.05), p: 1.5, borderRadius: 1, whiteSpace: "pre-wrap" }}>
                    {platform.steps}
                  </Box>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <CodeBlock
            title="GitHub Pages Deployment Commands"
            code={`# Initialize git in your project folder
git init

# Add all files
git add .

# Commit your changes
git commit -m "Initial commit"

# Add your GitHub repository as remote
git remote add origin https://github.com/yourusername/portfolio.git

# Push to GitHub
git push -u origin main

# Then go to GitHub → Repository Settings → Pages
# Select "main" branch and save
# Your site will be at: https://yourusername.github.io/portfolio/`}
          />

          {/* Best Practices */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 5, mb: 2, color: "#ef4444" }}>
            ✅ Project Best Practices
          </Typography>
          <List dense>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#ef4444" }} /></ListItemIcon>
              <ListItemText primary="Always use semantic HTML (header, main, section, article, footer)" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#ef4444" }} /></ListItemIcon>
              <ListItemText primary="Organize CSS with comments and group related styles together" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#ef4444" }} /></ListItemIcon>
              <ListItemText primary="Use CSS custom properties (variables) for colors and fonts" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#ef4444" }} /></ListItemIcon>
              <ListItemText primary="Test on multiple browsers and devices before deploying" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#ef4444" }} /></ListItemIcon>
              <ListItemText primary="Optimize images (use WebP format, compress large images)" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#ef4444" }} /></ListItemIcon>
              <ListItemText primary="Add alt text to all images for accessibility" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#ef4444" }} /></ListItemIcon>
              <ListItemText primary="Use a consistent naming convention (BEM is popular)" />
            </ListItem>
            <ListItem>
              <ListItemIcon><CheckCircleIcon sx={{ color: "#ef4444" }} /></ListItemIcon>
              <ListItemText primary="Include a README.md file explaining your project" />
            </ListItem>
          </List>

          {/* Practice Exercises */}
          <Typography variant="h5" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#ef4444" }}>
            ✏️ Final Challenges
          </Typography>
          <List dense>
            <ListItem>
              <ListItemIcon><WebIcon sx={{ color: "#ef4444" }} /></ListItemIcon>
              <ListItemText primary="Build your own portfolio and deploy it to GitHub Pages" />
            </ListItem>
            <ListItem>
              <ListItemIcon><WebIcon sx={{ color: "#ef4444" }} /></ListItemIcon>
              <ListItemText primary="Create a landing page for a fictional product" />
            </ListItem>
            <ListItem>
              <ListItemIcon><WebIcon sx={{ color: "#ef4444" }} /></ListItemIcon>
              <ListItemText primary="Build an admin dashboard layout with sidebar navigation" />
            </ListItem>
            <ListItem>
              <ListItemIcon><WebIcon sx={{ color: "#ef4444" }} /></ListItemIcon>
              <ListItemText primary="Clone a website you admire (for practice, not deployment)" />
            </ListItem>
            <ListItem>
              <ListItemIcon><WebIcon sx={{ color: "#ef4444" }} /></ListItemIcon>
              <ListItemText primary="Create a responsive blog layout with article cards" />
            </ListItem>
          </List>

          <Alert severity="success" sx={{ mt: 4 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>🎉 Congratulations!</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              You've completed the HTML & CSS Fundamentals course! You now have the knowledge to build 
              beautiful, responsive websites from scratch. Keep practicing, build projects, and don't 
              be afraid to experiment. The best way to learn is by doing!
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== MODULE PLACEHOLDERS ==================== */}
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <ConstructionIcon sx={{ color: "#e91e63" }} />
          Course Modules
        </Typography>

        <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>
          This course is organized into 15 modules—starting from absolute basics and progressing to modern CSS frameworks. Perfect for complete beginners!
        </Typography>

        <Grid container spacing={3} sx={{ mb: 5 }}>
          {[
            { id: 1, title: "Your First Web Page", desc: "What is HTML? Setting up VS Code, creating your first .html file, viewing it in a browser, understanding the basics", color: "#3b82f6", status: "Coming Soon", level: "Beginner" },
            { id: 2, title: "HTML Basics & Structure", desc: "DOCTYPE, html, head, body tags, meta tags, page titles, comments, indentation best practices", color: "#e44d26", status: "Coming Soon", level: "Beginner" },
            { id: 3, title: "Text & Links", desc: "Headings h1-h6, paragraphs, bold, italic, line breaks, anchor tags, internal vs external links, email links", color: "#22c55e", status: "Coming Soon", level: "Beginner" },
            { id: 4, title: "Lists & Tables", desc: "Ordered lists, unordered lists, nested lists, definition lists, tables, rows, columns, headers, spanning cells", color: "#f97316", status: "Coming Soon", level: "Beginner" },
            { id: 5, title: "Images & Media", desc: "Adding images, alt text, image formats (PNG, JPG, SVG, WebP), video and audio elements, YouTube embeds", color: "#8b5cf6", status: "Coming Soon", level: "Beginner" },
            { id: 6, title: "Forms & User Input", desc: "Form basics, text inputs, passwords, checkboxes, radio buttons, dropdowns, textareas, submit buttons, labels", color: "#ec4899", status: "Coming Soon", level: "Beginner" },
            { id: 7, title: "CSS Basics", desc: "What is CSS? Inline, internal, external stylesheets, selectors, properties, values, colors, fonts, text styling", color: "#264de4", status: "Coming Soon", level: "Beginner" },
            { id: 8, title: "Box Model & Layout", desc: "Content, padding, border, margin, width, height, box-sizing, display: block vs inline vs inline-block", color: "#14b8a6", status: "Coming Soon", level: "Intermediate" },
            { id: 9, title: "Flexbox", desc: "Flex container, flex items, main axis, cross axis, justify-content, align-items, flex-wrap, flex-grow/shrink", color: "#f59e0b", status: "Coming Soon", level: "Intermediate" },
            { id: 10, title: "CSS Grid", desc: "Grid container, grid-template-columns/rows, gap, grid areas, auto-fit, minmax(), responsive grids", color: "#06b6d4", status: "Coming Soon", level: "Intermediate" },
            { id: 11, title: "Responsive Design", desc: "Viewport meta tag, media queries, mobile-first design, breakpoints, fluid typography, responsive images", color: "#10b981", status: "Coming Soon", level: "Intermediate" },
            { id: 12, title: "Animations & Effects", desc: "Transitions, transform (rotate, scale, translate), keyframe animations, hover effects, loading spinners", color: "#a855f7", status: "Coming Soon", level: "Intermediate" },
            { id: 13, title: "Bootstrap Framework", desc: "Installing Bootstrap, container, row, col grid system, buttons, cards, navbars, modals, utility classes", color: "#7952b3", status: "Coming Soon", level: "Advanced" },
            { id: 14, title: "TailwindCSS", desc: "Utility-first CSS, installing Tailwind, responsive utilities, colors, spacing, flex/grid utilities, dark mode", color: "#06b6d4", status: "Coming Soon", level: "Advanced" },
            { id: 15, title: "Real-World Projects", desc: "Build a portfolio site, landing page, dashboard UI. Deployment to GitHub Pages, Netlify, Vercel", color: "#ef4444", status: "Coming Soon", level: "Advanced" },
          ].map((module) => (
            <Grid item xs={12} sm={6} md={4} key={module.id}>
              <Paper
                id={`module-${module.id}`}
                sx={{
                  p: 3,
                  height: "100%",
                  borderRadius: 3,
                  bgcolor: alpha(module.color, 0.03),
                  border: `1px solid ${alpha(module.color, 0.2)}`,
                  transition: "all 0.3s ease",
                  "&:hover": {
                    transform: "translateY(-4px)",
                    boxShadow: `0 8px 24px ${alpha(module.color, 0.15)}`,
                  },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2, flexWrap: "wrap" }}>
                  <Chip
                    label={`Module ${module.id}`}
                    size="small"
                    sx={{ bgcolor: alpha(module.color, 0.15), color: module.color, fontWeight: 700 }}
                  />
                  <Chip
                    label={module.level}
                    size="small"
                    sx={{ 
                      bgcolor: alpha(
                        module.level === "Beginner" ? "#22c55e" : 
                        module.level === "Intermediate" ? "#f59e0b" : "#ef4444", 
                        0.15
                      ), 
                      color: module.level === "Beginner" ? "#22c55e" : 
                             module.level === "Intermediate" ? "#f59e0b" : "#ef4444",
                      fontWeight: 600,
                      fontSize: "0.7rem"
                    }}
                  />
                </Box>
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 1, color: module.color }}>
                  {module.title}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>
                  {module.desc}
                </Typography>
              </Paper>
            </Grid>
          ))}
        </Grid>

        {/* ==================== QUIZ SECTION ==================== */}
        <Paper
          id="quiz-section"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.8),
            border: `1px solid ${alpha("#e91e63", 0.3)}`,
          }}
        >
          <Typography
            variant="h4"
            sx={{
              fontWeight: 800,
              mb: 3,
              display: "flex",
              alignItems: "center",
              gap: 2,
              color: "#e91e63",
            }}
          >
            <QuizIcon sx={{ fontSize: "2rem" }} />
            HTML & CSS Knowledge Quiz
          </Typography>

          {/* Quiz Start State */}
          {quizState === "start" && (
            <Box sx={{ textAlign: "center", py: 4 }}>
              <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
                Test Your HTML & CSS Knowledge
              </Typography>
              <Typography variant="body1" color="text.secondary" sx={{ mb: 4, maxWidth: 600, mx: "auto" }}>
                This quiz contains {QUESTIONS_PER_QUIZ} randomly selected questions covering HTML basics, 
                CSS styling, layouts, Flexbox, Grid, responsive design, animations, Bootstrap, TailwindCSS, 
                and best practices. Challenge yourself and see how much you've learned!
              </Typography>
              <Grid container spacing={2} justifyContent="center" sx={{ mb: 4 }}>
                <Grid item>
                  <Chip icon={<QuizIcon />} label={`${QUESTIONS_PER_QUIZ} Questions`} sx={{ bgcolor: alpha("#e91e63", 0.15), color: "#e91e63" }} />
                </Grid>
                <Grid item>
                  <Chip icon={<TimerIcon />} label="No Time Limit" sx={{ bgcolor: alpha("#2196f3", 0.15), color: "#2196f3" }} />
                </Grid>
                <Grid item>
                  <Chip icon={<EmojiEventsIcon />} label="Track Your Score" sx={{ bgcolor: alpha("#ff9800", 0.15), color: "#ff9800" }} />
                </Grid>
              </Grid>
              <Button
                variant="contained"
                size="large"
                onClick={startQuiz}
                startIcon={<PlayArrowIcon />}
                sx={{
                  bgcolor: "#e91e63",
                  "&:hover": { bgcolor: "#c2185b" },
                  px: 6,
                  py: 2,
                  borderRadius: 3,
                  fontSize: "1.1rem",
                  fontWeight: 700,
                }}
              >
                Start Quiz
              </Button>
            </Box>
          )}

          {/* Quiz Active State */}
          {quizState === "active" && quizQuestions.length > 0 && (
            <Box>
              {/* Progress */}
              <Box sx={{ mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
                <Typography variant="body2" sx={{ fontWeight: 600, color: "#e91e63" }}>
                  Question {currentQuestionIndex + 1} of {quizQuestions.length}
                </Typography>
                <LinearProgress
                  variant="determinate"
                  value={((currentQuestionIndex + 1) / quizQuestions.length) * 100}
                  sx={{
                    flex: 1,
                    height: 8,
                    borderRadius: 4,
                    bgcolor: alpha("#e91e63", 0.15),
                    "& .MuiLinearProgress-bar": { bgcolor: "#e91e63", borderRadius: 4 },
                  }}
                />
                <Chip
                  label={quizQuestions[currentQuestionIndex].topic}
                  size="small"
                  sx={{ bgcolor: alpha("#673ab7", 0.15), color: "#673ab7", fontWeight: 600 }}
                />
              </Box>

              {/* Question */}
              <Paper
                sx={{
                  p: 3,
                  mb: 3,
                  borderRadius: 3,
                  bgcolor: alpha("#e91e63", 0.05),
                  border: `1px solid ${alpha("#e91e63", 0.2)}`,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 0 }}>
                  {quizQuestions[currentQuestionIndex].question}
                </Typography>
              </Paper>

              {/* Answer Options */}
              <RadioGroup
                value={selectedAnswers[currentQuestionIndex] ?? -1}
                onChange={(e) => handleAnswerSelect(parseInt(e.target.value))}
              >
                <Grid container spacing={2}>
                  {quizQuestions[currentQuestionIndex].options.map((option, idx) => {
                    const isSelected = selectedAnswers[currentQuestionIndex] === idx;
                    const isCorrect = idx === quizQuestions[currentQuestionIndex].correctAnswer;
                    let bgcolor = alpha(theme.palette.background.paper, 0.6);
                    let borderColor = alpha("#e91e63", 0.2);

                    if (showExplanation) {
                      if (isCorrect) {
                        bgcolor = alpha("#4caf50", 0.15);
                        borderColor = "#4caf50";
                      } else if (isSelected && !isCorrect) {
                        bgcolor = alpha("#f44336", 0.15);
                        borderColor = "#f44336";
                      }
                    } else if (isSelected) {
                      bgcolor = alpha("#e91e63", 0.15);
                      borderColor = "#e91e63";
                    }

                    return (
                      <Grid item xs={12} sm={6} key={idx}>
                        <Paper
                          sx={{
                            p: 2,
                            borderRadius: 2,
                            bgcolor,
                            border: `2px solid ${borderColor}`,
                            cursor: showExplanation ? "default" : "pointer",
                            transition: "all 0.2s ease",
                            "&:hover": showExplanation ? {} : {
                              bgcolor: alpha("#e91e63", 0.1),
                              borderColor: "#e91e63",
                            },
                          }}
                          onClick={() => !showExplanation && handleAnswerSelect(idx)}
                        >
                          <FormControlLabel
                            value={idx}
                            control={
                              <Radio
                                disabled={showExplanation}
                                sx={{
                                  color: "#e91e63",
                                  "&.Mui-checked": { color: "#e91e63" },
                                }}
                              />
                            }
                            label={
                              <Typography variant="body1" sx={{ fontWeight: isSelected ? 600 : 400 }}>
                                {option}
                              </Typography>
                            }
                            sx={{ m: 0, width: "100%" }}
                          />
                        </Paper>
                      </Grid>
                    );
                  })}
                </Grid>
              </RadioGroup>

              {/* Explanation */}
              {showExplanation && (
                <Paper
                  sx={{
                    p: 3,
                    mt: 3,
                    borderRadius: 3,
                    bgcolor: alpha("#2196f3", 0.08),
                    border: `1px solid ${alpha("#2196f3", 0.3)}`,
                  }}
                >
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#2196f3", mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                    <LightbulbIcon /> Explanation
                  </Typography>
                  <Typography variant="body1">
                    {quizQuestions[currentQuestionIndex].explanation}
                  </Typography>
                </Paper>
              )}

              {/* Action Buttons */}
              <Box sx={{ mt: 4, display: "flex", gap: 2, justifyContent: "center" }}>
                {!showExplanation ? (
                  <Button
                    variant="contained"
                    onClick={handleCheckAnswer}
                    disabled={selectedAnswers[currentQuestionIndex] === undefined}
                    sx={{
                      bgcolor: "#e91e63",
                      "&:hover": { bgcolor: "#c2185b" },
                      px: 4,
                      py: 1.5,
                      borderRadius: 2,
                    }}
                  >
                    Check Answer
                  </Button>
                ) : (
                  <Button
                    variant="contained"
                    onClick={handleNextQuestion}
                    endIcon={currentQuestionIndex < quizQuestions.length - 1 ? <NavigateNextIcon /> : <EmojiEventsIcon />}
                    sx={{
                      bgcolor: "#e91e63",
                      "&:hover": { bgcolor: "#c2185b" },
                      px: 4,
                      py: 1.5,
                      borderRadius: 2,
                    }}
                  >
                    {currentQuestionIndex < quizQuestions.length - 1 ? "Next Question" : "See Results"}
                  </Button>
                )}
              </Box>

              {/* Score Tracker */}
              <Box sx={{ mt: 3, textAlign: "center" }}>
                <Typography variant="body2" color="text.secondary">
                  Current Score: <strong style={{ color: "#4caf50" }}>{quizScore}</strong> / {currentQuestionIndex + (showExplanation ? 1 : 0)}
                </Typography>
              </Box>
            </Box>
          )}

          {/* Quiz Results State */}
          {quizState === "results" && (
            <Box sx={{ textAlign: "center", py: 4 }}>
              <EmojiEventsIcon sx={{ fontSize: 80, color: quizScore >= QUESTIONS_PER_QUIZ * 0.8 ? "#ffd700" : quizScore >= QUESTIONS_PER_QUIZ * 0.6 ? "#c0c0c0" : "#cd7f32", mb: 2 }} />
              <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
                Quiz Complete!
              </Typography>
              <Typography variant="h2" sx={{ fontWeight: 900, color: "#e91e63", mb: 2 }}>
                {quizScore} / {QUESTIONS_PER_QUIZ}
              </Typography>
              <Typography variant="h6" sx={{ mb: 1 }}>
                {quizScore >= QUESTIONS_PER_QUIZ * 0.9
                  ? "🌟 Outstanding! You're an HTML & CSS master!"
                  : quizScore >= QUESTIONS_PER_QUIZ * 0.8
                  ? "🎉 Excellent! You have strong web development skills!"
                  : quizScore >= QUESTIONS_PER_QUIZ * 0.6
                  ? "👍 Good job! Keep practicing to improve!"
                  : quizScore >= QUESTIONS_PER_QUIZ * 0.4
                  ? "📚 Not bad! Review the modules and try again."
                  : "💪 Keep learning! Review the modules and retake the quiz."}
              </Typography>
              <Typography variant="body1" color="text.secondary" sx={{ mb: 4 }}>
                Accuracy: {((quizScore / QUESTIONS_PER_QUIZ) * 100).toFixed(0)}%
              </Typography>
              <Box sx={{ display: "flex", gap: 2, justifyContent: "center", flexWrap: "wrap" }}>
                <Button
                  variant="contained"
                  startIcon={<RefreshIcon />}
                  onClick={startQuiz}
                  sx={{
                    bgcolor: "#e91e63",
                    "&:hover": { bgcolor: "#c2185b" },
                    px: 4,
                    py: 1.5,
                    borderRadius: 2,
                  }}
                >
                  Try Again (New Questions)
                </Button>
                <Button
                  variant="outlined"
                  startIcon={<ArrowBackIcon />}
                  onClick={resetQuiz}
                  sx={{
                    borderColor: "#e91e63",
                    color: "#e91e63",
                    "&:hover": { borderColor: "#c2185b", bgcolor: alpha("#e91e63", 0.05) },
                    px: 4,
                    py: 1.5,
                    borderRadius: 2,
                  }}
                >
                  Back to Start
                </Button>
              </Box>
            </Box>
          )}
        </Paper>

        {/* ==================== BACK TO LEARNING HUB ==================== */}
        <Paper
          sx={{
            p: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#e91e63", 0.1)} 0%, ${alpha("#673ab7", 0.1)} 100%)`,
            border: `1px solid ${alpha("#e91e63", 0.2)}`,
            textAlign: "center",
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
            Ready to Explore More?
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Check out other learning resources in our hub.
          </Typography>
          <Button
            variant="contained"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{
              bgcolor: "#e91e63",
              "&:hover": { bgcolor: "#c2185b" },
              px: 4,
              py: 1.5,
              borderRadius: 2,
            }}
          >
            Back to Learning Hub
          </Button>
        </Paper>
        </Box>
      </Box>
    </LearnPageLayout>
  );
};

export default HtmlCssGuidePage;
