import React, { useState, useEffect } from "react";
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  alpha,
  useTheme,
  keyframes,
  Button,
  Chip,
  Container,
  Divider,
} from "@mui/material";
import { Link } from "react-router-dom";
import FolderIcon from "@mui/icons-material/Folder";
import SecurityIcon from "@mui/icons-material/Security";
import HubIcon from "@mui/icons-material/Hub";
import MemoryIcon from "@mui/icons-material/Memory";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import PeopleIcon from "@mui/icons-material/People";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import BoltIcon from "@mui/icons-material/Bolt";
import ShieldIcon from "@mui/icons-material/Shield";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import SpeedIcon from "@mui/icons-material/Speed";
import VisibilityIcon from "@mui/icons-material/Visibility";
import CodeIcon from "@mui/icons-material/Code";
import BugReportIcon from "@mui/icons-material/BugReport";
import LockIcon from "@mui/icons-material/Lock";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import HttpsIcon from "@mui/icons-material/Https";
import SwapHorizIcon from "@mui/icons-material/SwapHoriz";
import FolderOpenIcon from "@mui/icons-material/FolderOpen";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";

// Advanced Animations
const float = keyframes`
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-12px); }
`;

const floatSlow = keyframes`
  0%, 100% { transform: translateY(0px) translateX(0px); }
  50% { transform: translateY(-20px) translateX(10px); }
`;

const shimmer = keyframes`
  0% { background-position: -200% center; }
  100% { background-position: 200% center; }
`;

const pulse = keyframes`
  0%, 100% { transform: scale(1); opacity: 1; }
  50% { transform: scale(1.05); opacity: 0.8; }
`;

const glow = keyframes`
  0%, 100% { box-shadow: 0 0 20px rgba(99, 102, 241, 0.4); }
  50% { box-shadow: 0 0 40px rgba(139, 92, 246, 0.6); }
`;

const rotate = keyframes`
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
`;

const gradientShift = keyframes`
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
`;

const fadeInUp = keyframes`
  from {
    opacity: 0;
    transform: translateY(30px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
`;

const scaleIn = keyframes`
  from {
    opacity: 0;
    transform: scale(0.95);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
`;

const textGradientShift = keyframes`
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
`;

const gridMove = keyframes`
  0% { transform: translateY(0); }
  100% { transform: translateY(-20px); }
`;

const glowPulse = keyframes`
  0%, 100% {
    box-shadow: 0 0 40px rgba(99, 102, 241, 0.3),
                0 0 80px rgba(139, 92, 246, 0.2),
                inset 0 0 60px rgba(139, 92, 246, 0.1);
  }
  50% {
    box-shadow: 0 0 60px rgba(99, 102, 241, 0.5),
                0 0 100px rgba(139, 92, 246, 0.3),
                inset 0 0 80px rgba(139, 92, 246, 0.15);
  }
`;

const borderGlow = keyframes`
  0%, 100% { opacity: 0.3; }
  50% { opacity: 1; }
`;


const glitch = keyframes`
  0% {
    transform: translate(0);
  }
  20% {
    transform: translate(-2px, 2px);
  }
  40% {
    transform: translate(-2px, -2px);
  }
  60% {
    transform: translate(2px, 2px);
  }
  80% {
    transform: translate(2px, -2px);
  }
  100% {
    transform: translate(0);
  }
`;

const holographic = keyframes`
  0% {
    background-position: 0% 50%;
  }
  50% {
    background-position: 100% 50%;
  }
  100% {
    background-position: 0% 50%;
  }
`;

const neonFlicker = keyframes`
  0%, 19%, 21%, 23%, 25%, 54%, 56%, 100% {
    opacity: 1;
    text-shadow: 0 0 10px currentColor, 0 0 20px currentColor, 0 0 40px currentColor;
  }
  20%, 24%, 55% {
    opacity: 0.8;
    text-shadow: none;
  }
`;

const radarSweep = keyframes`
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(360deg);
  }
`;

const shieldPulse = keyframes`
  0%, 100% {
    transform: scale(1);
    opacity: 0.4;
  }
  50% {
    transform: scale(1.1);
    opacity: 0.6;
  }
`;

const radarSpin = keyframes`
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(360deg);
  }
`;

const radarPing = keyframes`
  0% {
    transform: scale(1);
    opacity: 0.6;
  }
  100% {
    transform: scale(1.5);
    opacity: 0;
  }
`;

const radarRingPulse = keyframes`
  0%, 100% {
    opacity: 0.4;
    transform: scale(1);
  }
  50% {
    opacity: 0.7;
    transform: scale(1.02);
  }
`;

const neonPulse = keyframes`
  0%, 100% {
    filter: drop-shadow(0 0 5px rgba(57, 255, 20, 0.6)) drop-shadow(0 0 15px rgba(57, 255, 20, 0.4));
    opacity: 0.12;
  }
  50% {
    filter: drop-shadow(0 0 10px rgba(57, 255, 20, 0.8)) drop-shadow(0 0 25px rgba(57, 255, 20, 0.5));
    opacity: 0.18;
  }
`;

const scanLine = keyframes`
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(360deg);
  }
`;

const blipAppear = keyframes`
  0% {
    transform: scale(0);
    opacity: 0;
  }
  50% {
    transform: scale(1.2);
    opacity: 1;
  }
  100% {
    transform: scale(1);
    opacity: 0.8;
  }
`;

const blipFade = keyframes`
  0%, 100% {
    opacity: 0.9;
    transform: scale(1);
  }
  50% {
    opacity: 0.4;
    transform: scale(0.8);
  }
`;

const hexagonRotate = keyframes`
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(-360deg);
  }
`;

const dataStream = keyframes`
  0% {
    stroke-dashoffset: 100;
    opacity: 0;
  }
  50% {
    opacity: 1;
  }
  100% {
    stroke-dashoffset: 0;
    opacity: 0;
  }
`;

const scanDown = keyframes`
  0% {
    top: -2px;
    opacity: 0;
  }
  5% {
    opacity: 1;
  }
  95% {
    opacity: 1;
  }
  100% {
    top: 100%;
    opacity: 0;
  }
`;

const floatRandom = keyframes`
  0%, 100% {
    transform: translate(0, 0) rotate(0deg);
  }
  25% {
    transform: translate(10px, -10px) rotate(5deg);
  }
  50% {
    transform: translate(-5px, -20px) rotate(-5deg);
  }
  75% {
    transform: translate(-10px, -10px) rotate(3deg);
  }
`;

const codeScroll = keyframes`
  0% {
    transform: translateY(0);
  }
  100% {
    transform: translateY(-50%);
  }
`;

const meshMorph = keyframes`
  0%, 100% {
    border-radius: 60% 40% 30% 70% / 60% 30% 70% 40%;
    transform: rotate(0deg);
  }
  25% {
    border-radius: 30% 60% 70% 40% / 50% 60% 30% 60%;
  }
  50% {
    border-radius: 50% 50% 30% 60% / 30% 60% 70% 40%;
    transform: rotate(180deg);
  }
  75% {
    border-radius: 60% 40% 50% 50% / 70% 30% 50% 60%;
  }
`;

const rotateGradient = keyframes`
  0% {
    transform: rotate(0deg);
  }
  100% {
    transform: rotate(360deg);
  }
`;

const ArrowRightIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z" />
  </svg>
);

interface HubCardProps {
  title: string;
  description: string;
  icon: React.ReactNode;
  to: string;
  gradient: string;
  shadowColor: string;
  iconBg: string;
  delay?: number;
}

const HubCard: React.FC<HubCardProps> = ({ title, description, icon, to, gradient, shadowColor, iconBg, delay = 0 }) => {
  const theme = useTheme();
  const [tilt, setTilt] = useState({ x: 0, y: 0 });

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const centerX = rect.width / 2;
    const centerY = rect.height / 2;
    const tiltX = (y - centerY) / 20;
    const tiltY = (centerX - x) / 20;
    setTilt({ x: tiltX, y: tiltY });
  };

  const handleMouseLeave = () => {
    setTilt({ x: 0, y: 0 });
  };

  return (
    <Box
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      sx={{ height: "100%", display: "flex" }}
    >
    <Card
      component={Link}
      to={to}
      sx={{
        textDecoration: "none",
        display: "flex",
        flexDirection: "column",
        height: "100%",
        width: "100%",
        minHeight: 240,
        flex: 1,
        background: gradient,
        backdropFilter: "blur(20px)",
        WebkitBackdropFilter: "blur(20px)",
        border: `1px solid ${alpha(shadowColor, 0.2)}`,
        borderRadius: 4,
        position: "relative",
        overflow: "hidden",
        transition: "all 0.5s cubic-bezier(0.4, 0, 0.2, 1)",
        animation: `${fadeInUp} 0.6s ease-out ${delay}s both`,
        transform: `perspective(1000px) rotateX(${tilt.x}deg) rotateY(${tilt.y}deg)`,
        transformStyle: "preserve-3d",
        "&::before": {
          content: '""',
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          height: "2px",
          background: `linear-gradient(90deg, transparent, ${shadowColor}, transparent)`,
          opacity: 0,
          transition: "opacity 0.3s ease",
        },
        "&::after": {
          content: '""',
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: `radial-gradient(circle at 50% 0%, ${alpha(shadowColor, 0.2)}, transparent 50%)`,
          opacity: 0,
          transition: "opacity 0.3s ease",
        },
        "&:hover": {
          transform: `perspective(1000px) rotateX(${tilt.x}deg) rotateY(${tilt.y}deg) translateY(-12px) scale(1.02)`,
          boxShadow: `
            0 25px 50px ${alpha(shadowColor, 0.35)},
            0 0 0 1px ${alpha(shadowColor, 0.5)},
            0 0 80px ${alpha(shadowColor, 0.2)}
          `,
          border: `1px solid ${alpha(shadowColor, 0.5)}`,
          "&::before": {
            opacity: 1,
          },
          "&::after": {
            opacity: 1,
          },
          "& .hub-icon": {
            animation: `${float} 2s ease-in-out infinite`,
            transform: "scale(1.15) rotate(5deg) translateZ(20px)",
            boxShadow: `0 10px 30px ${alpha(shadowColor, 0.4)}, 0 0 40px ${alpha(shadowColor, 0.3)}`,
          },
          "& .hub-bg-glow": {
            opacity: 1,
            transform: "scale(1.5)",
          },
          "& .arrow-icon": {
            transform: "translateX(6px) translateZ(10px)",
          },
          "& .shimmer-effect": {
            opacity: 1,
          },
          "& .circuit-pattern": {
            opacity: 1,
          },
        },
      }}
    >
      {/* Circuit board pattern overlay */}
      <Box
        className="circuit-pattern"
        sx={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundImage: `
            repeating-linear-gradient(0deg, transparent, transparent 10px, ${alpha(shadowColor, 0.02)} 10px, ${alpha(shadowColor, 0.02)} 11px),
            repeating-linear-gradient(90deg, transparent, transparent 10px, ${alpha(shadowColor, 0.02)} 10px, ${alpha(shadowColor, 0.02)} 11px)
          `,
          opacity: 0,
          transition: "opacity 0.5s ease",
          pointerEvents: "none",
        }}
      />

      {/* Background Glow Effect */}
      <Box
        className="hub-bg-glow"
        sx={{
          position: "absolute",
          top: "50%",
          left: "50%",
          width: "200px",
          height: "200px",
          borderRadius: "50%",
          background: `radial-gradient(circle, ${alpha(shadowColor, 0.3)} 0%, transparent 70%)`,
          transform: "translate(-50%, -50%) scale(0.8)",
          opacity: 0,
          transition: "all 0.5s ease",
          pointerEvents: "none",
        }}
      />

      {/* Shimmer Effect */}
      <Box
        className="shimmer-effect"
        sx={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: `linear-gradient(90deg, transparent, ${alpha("#fff", 0.05)}, transparent)`,
          backgroundSize: "200% 100%",
          animation: `${shimmer} 3s infinite`,
          opacity: 0,
          transition: "opacity 0.3s ease",
          pointerEvents: "none",
        }}
      />

      <CardContent sx={{ p: 4, flex: 1, display: "flex", flexDirection: "column", position: "relative", zIndex: 1 }}>
        <Box
          className="hub-icon"
          sx={{
            width: 72,
            height: 72,
            borderRadius: 3,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: iconBg,
            color: "#fff",
            mb: 3,
            transition: "all 0.4s cubic-bezier(0.4, 0, 0.2, 1)",
            boxShadow: `0 4px 20px ${alpha(shadowColor, 0.3)}`,
          }}
        >
          {icon}
        </Box>
        <Typography variant="h5" fontWeight={800} sx={{ mb: 1.5, letterSpacing: "-0.01em" }}>
          {title}
        </Typography>
        <Typography
          variant="body2"
          sx={{
            mb: 3,
            flex: 1,
            color: "text.secondary",
            lineHeight: 1.7,
          }}
        >
          {description}
        </Typography>
        <Box
          className="arrow-icon"
          sx={{
            display: "flex",
            alignItems: "center",
            color: shadowColor,
            transition: "transform 0.3s ease",
            fontWeight: 600,
          }}
        >
          <Typography variant="body2" fontWeight={700} sx={{ mr: 0.5 }}>
            Explore
          </Typography>
          <ArrowRightIcon />
        </Box>
      </CardContent>
    </Card>
    </Box>
  );
};

interface FeatureCardProps {
  icon: React.ReactNode;
  title: string;
  description: string;
  color: string;
  delay?: number;
}

const FeatureCard: React.FC<FeatureCardProps> = ({ icon, title, description, color, delay = 0 }) => {
  return (
    <Box
      sx={{
        p: 3,
        borderRadius: 3,
        background: alpha(color, 0.05),
        backdropFilter: "blur(10px)",
        WebkitBackdropFilter: "blur(10px)",
        border: `1px solid ${alpha(color, 0.15)}`,
        position: "relative",
        overflow: "hidden",
        transition: "all 0.4s cubic-bezier(0.4, 0, 0.2, 1)",
        animation: `${scaleIn} 0.5s ease-out ${delay}s both`,
        "&::before": {
          content: '""',
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: `radial-gradient(circle at 0% 0%, ${alpha(color, 0.1)}, transparent 50%)`,
          opacity: 0,
          transition: "opacity 0.4s ease",
        },
        "&::after": {
          content: '""',
          position: "absolute",
          top: "-50%",
          left: "-50%",
          width: "200%",
          height: "200%",
          background: `linear-gradient(45deg, transparent 30%, ${alpha(color, 0.1)} 50%, transparent 70%)`,
          backgroundSize: "200% 200%",
          opacity: 0,
          transition: "opacity 0.4s ease",
        },
        "&:hover": {
          transform: "translateY(-8px) scale(1.02)",
          background: alpha(color, 0.1),
          border: `1px solid ${alpha(color, 0.4)}`,
          boxShadow: `
            0 20px 40px ${alpha(color, 0.25)},
            0 0 0 1px ${alpha(color, 0.1)} inset,
            0 0 60px ${alpha(color, 0.15)}
          `,
          "&::before": {
            opacity: 1,
          },
          "&::after": {
            opacity: 1,
            animation: `${holographic} 3s ease infinite`,
          },
          "& .feature-icon": {
            transform: "scale(1.15) rotate(8deg) translateY(-2px)",
            boxShadow: `0 8px 24px ${alpha(color, 0.4)}, 0 0 40px ${alpha(color, 0.3)}`,
          },
          "& .feature-title": {
            color: color,
          },
        },
      }}
    >
      <Box
        className="feature-icon"
        sx={{
          width: 56,
          height: 56,
          borderRadius: 2.5,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: `linear-gradient(135deg, ${color}, ${alpha(color, 0.7)})`,
          color: "#fff",
          mb: 2,
          transition: "all 0.4s cubic-bezier(0.4, 0, 0.2, 1)",
          boxShadow: `0 4px 16px ${alpha(color, 0.3)}`,
          position: "relative",
          "&::before": {
            content: '""',
            position: "absolute",
            inset: 0,
            borderRadius: 2.5,
            padding: "2px",
            background: `linear-gradient(135deg, ${alpha("#fff", 0.3)}, transparent)`,
            WebkitMask: "linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)",
            WebkitMaskComposite: "xor",
            maskComposite: "exclude",
          },
        }}
      >
        {icon}
      </Box>
      <Typography variant="h6" fontWeight={700} sx={{ mb: 1, transition: "color 0.3s ease" }} className="feature-title">
        {title}
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>
        {description}
      </Typography>
    </Box>
  );
};

const HomePage: React.FC = () => {
  const theme = useTheme();
  const [typedText, setTypedText] = useState("");
  const [isVisible, setIsVisible] = useState({
    features: false,
    hubs: false,
    demo: false,
  });
  const [featuresSlide, setFeaturesSlide] = useState(0);
  const [floatingIcons] = useState([
    { Icon: LockIcon, x: 8, y: 12, delay: 0, size: 32 },
    { Icon: ShieldIcon, x: 12, y: 75, delay: 2.5, size: 36 },
    { Icon: CodeIcon, x: 88, y: 20, delay: 1, size: 28 },
    { Icon: VpnKeyIcon, x: 92, y: 70, delay: 3, size: 30 },
    { Icon: HttpsIcon, x: 5, y: 45, delay: 1.5, size: 26 },
    { Icon: BugReportIcon, x: 85, y: 48, delay: 4, size: 28 },
    { Icon: MemoryIcon, x: 18, y: 88, delay: 2, size: 24 },
    { Icon: SecurityIcon, x: 78, y: 85, delay: 3.5, size: 30 },
  ]);
  const [codeSnippets] = useState([
    "CVE-2024-1234",
    "SQL Injection",
    "XSS Detected",
    "Buffer Overflow",
    "CSRF Token",
  ]);


  // Typing animation effect
  useEffect(() => {
    const fullText = "Your comprehensive security analysis platform powered by advanced AI";
    let currentIndex = 0;

    const typingInterval = setInterval(() => {
      if (currentIndex <= fullText.length) {
        setTypedText(fullText.slice(0, currentIndex));
        currentIndex++;
      } else {
        clearInterval(typingInterval);
      }
    }, 30);

    return () => clearInterval(typingInterval);
  }, []);

  // Particle constellation effect removed for performance

  // Matrix rain effect removed for performance

  // Auto-rotate carousel
  useEffect(() => {
    const featuresTimer = setInterval(() => {
      setFeaturesSlide((prev) => (prev + 1) % 6);
    }, 4000);
    return () => clearInterval(featuresTimer);
  }, []);

  // Scroll-triggered animations
  useEffect(() => {
    const observerOptions = {
      threshold: 0.2,
      rootMargin: "0px 0px -100px 0px",
    };

    const observerCallback = (entries: IntersectionObserverEntry[]) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const id = entry.target.getAttribute("data-section");
          if (id) {
            setIsVisible((prev) => ({ ...prev, [id]: true }));
          }
        }
      });
    };

    const observer = new IntersectionObserver(observerCallback, observerOptions);

    const sections = document.querySelectorAll("[data-section]");
    sections.forEach((section) => observer.observe(section));

    return () => {
      sections.forEach((section) => observer.unobserve(section));
    };
  }, []);

  // Mouse movement tracking removed for performance

  return (
    <Box sx={{ position: "relative", overflow: "hidden" }}>
      {/* Gradient Mesh Background - Optimized */}
      <Box
        sx={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          pointerEvents: "none",
          zIndex: 0,
          overflow: "hidden",
        }}
      >
        {/* Reduced to 2 morphing mesh blobs */}
        <Box
          sx={{
            position: "absolute",
            top: "-20%",
            left: "-10%",
            width: "500px",
            height: "500px",
            background: `radial-gradient(circle, ${alpha("#6366f1", 0.12)}, transparent 70%)`,
            filter: "blur(60px)",
            animation: `${meshMorph} 25s ease-in-out infinite`,
            willChange: "transform, border-radius",
          }}
        />
        <Box
          sx={{
            position: "absolute",
            bottom: "-10%",
            right: "-10%",
            width: "550px",
            height: "550px",
            background: `radial-gradient(circle, ${alpha("#8b5cf6", 0.1)}, transparent 70%)`,
            filter: "blur(65px)",
            animation: `${meshMorph} 30s ease-in-out infinite reverse`,
            animationDelay: "10s",
            willChange: "transform, border-radius",
          }}
        />
      </Box>

      {/* Code Rain Effect - Optimized */}
      <Box
        sx={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          pointerEvents: "none",
          zIndex: 0,
          overflow: "hidden",
          opacity: 0.25,
        }}
      >
        {codeSnippets.map((code, i) => (
          <Box
            key={i}
            sx={{
              position: "absolute",
              left: `${(i * 20) % 90}%`,
              color: alpha(i % 2 === 0 ? "#22c55e" : "#6366f1", 0.35),
              fontSize: "11px",
              fontFamily: "monospace",
              fontWeight: 500,
              whiteSpace: "nowrap",
              animation: `${codeScroll} ${20 + i * 3}s linear infinite`,
              animationDelay: `${i * 3}s`,
              willChange: "transform",
            }}
          >
            {code}
            <br />
            {code}
          </Box>
        ))}
      </Box>

      {/* Simplified Static Grid Background */}
      <Box
        sx={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundImage: `
            linear-gradient(${alpha("#8b5cf6", 0.02)} 1px, transparent 1px),
            linear-gradient(90deg, ${alpha("#8b5cf6", 0.02)} 1px, transparent 1px)
          `,
          backgroundSize: "50px 50px",
          pointerEvents: "none",
          zIndex: 0,
        }}
      />

      {/* Noise/Grain Texture Overlay */}
      <Box
        sx={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          pointerEvents: "none",
          zIndex: 1,
          opacity: 0.035,
          backgroundImage: `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)'/%3E%3C/svg%3E")`,
        }}
      />

      {/* Subtle Scanning Line */}
      <Box
        sx={{
          position: "fixed",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          pointerEvents: "none",
          zIndex: 2,
          overflow: "hidden",
        }}
      >
        <Box
          sx={{
            position: "absolute",
            left: 0,
            right: 0,
            height: "1px",
            background: `linear-gradient(90deg, 
              transparent 0%, 
              ${alpha("#39ff14", 0.12)} 20%, 
              ${alpha("#39ff14", 0.25)} 50%, 
              ${alpha("#39ff14", 0.12)} 80%, 
              transparent 100%
            )`,
            boxShadow: `
              0 0 8px ${alpha("#39ff14", 0.15)},
              0 0 15px ${alpha("#39ff14", 0.08)}
            `,
            animation: `${scanDown} 15s linear infinite`,
          }}
        />
      </Box>

    <Container maxWidth="xl" sx={{ py: 4, position: "relative", zIndex: 1 }}>
      {/* Live Status Indicator */}
      <Box
        sx={{
          position: "fixed",
          top: 80,
          right: 20,
          zIndex: 1000,
          display: "flex",
          alignItems: "center",
          gap: 1,
          px: 2,
          py: 1,
          borderRadius: 3,
          background: `linear-gradient(135deg, ${alpha("#0f172a", 0.95)}, ${alpha("#1e293b", 0.95)})`,
          backdropFilter: "blur(20px)",
          border: `1px solid ${alpha("#22c55e", 0.3)}`,
          boxShadow: `0 4px 16px ${alpha("#000", 0.3)}, 0 0 30px ${alpha("#22c55e", 0.2)}`,
        }}
      >
        <Box
          sx={{
            width: 8,
            height: 8,
            borderRadius: "50%",
            bgcolor: "#22c55e",
            animation: `${pulse} 2s ease-in-out infinite`,
            boxShadow: `0 0 10px #22c55e, 0 0 20px #22c55e`,
          }}
        />
        <Typography
          sx={{
            fontSize: "0.75rem",
            fontWeight: 700,
            color: "#22c55e",
            fontFamily: "monospace",
          }}
        >
          ALL SYSTEMS OPERATIONAL
        </Typography>
      </Box>

      {/* Hero Section */}
      <Box
        sx={{
          position: "relative",
          mb: 6,
          p: { xs: 6, sm: 8, md: 10 },
          pt: { xs: 12, sm: 14, md: 16 },
          borderRadius: 5,
          overflow: "visible",
          background: `linear-gradient(135deg, ${alpha("#6366f1", 0.12)} 0%, ${alpha("#8b5cf6", 0.12)} 50%, ${alpha("#ec4899", 0.12)} 100%)`,
          backgroundSize: "200% 200%",
          animation: `${gradientShift} 15s ease infinite, ${glowPulse} 8s ease-in-out infinite`,
          backdropFilter: "blur(60px) saturate(150%)",
          WebkitBackdropFilter: "blur(60px) saturate(150%)",
          border: `1px solid ${alpha("#fff", 0.1)}`,
          boxShadow: `
            0 8px 32px ${alpha("#000", 0.3)},
            0 0 0 1px ${alpha("#fff", 0.05)} inset,
            0 0 100px ${alpha("#8b5cf6", 0.3)}
          `,
          "&::before": {
            content: '""',
            position: "absolute",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            borderRadius: 5,
            padding: "2px",
            background: `linear-gradient(135deg, ${alpha("#6366f1", 0.5)}, ${alpha("#8b5cf6", 0.5)}, ${alpha("#ec4899", 0.5)})`,
            WebkitMask: "linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)",
            WebkitMaskComposite: "xor",
            maskComposite: "exclude",
            opacity: 0.3,
            animation: `${borderGlow} 3s ease-in-out infinite`,
            pointerEvents: "none",
          },
        }}
      >
        {/* Simplified Background Orbs - Reduced from 4 to 2 */}
        <Box
          sx={{
            position: "absolute",
            top: 0,
            right: 0,
            bottom: 0,
            left: 0,
            overflow: "hidden",
            opacity: 0.3,
            pointerEvents: "none",
          }}
        >
          {[...Array(2)].map((_, i) => (
            <Box
              key={i}
              sx={{
                position: "absolute",
                width: { xs: 200, md: 250 },
                height: { xs: 200, md: 250 },
                borderRadius: "50%",
                background: `radial-gradient(circle, ${alpha(
                  i % 2 === 0 ? "#6366f1" : "#8b5cf6",
                  0.12
                )} 0%, transparent 70%)`,
                right: `${i * 50}%`,
                top: `${i * 50}%`,
                animation: `${floatSlow} ${6 + i * 2}s ease-in-out infinite`,
                animationDelay: `${i * 1}s`,
                filter: "blur(40px)",
                willChange: "transform",
              }}
            />
          ))}
        </Box>

        {/* Floating Security Icons */}
        {floatingIcons.map((iconData, i) => {
          const Icon = iconData.Icon;
          return (
            <Box
              key={i}
              sx={{
                position: "absolute",
                left: `${iconData.x}%`,
                top: `${iconData.y}%`,
                color: alpha("#6366f1", 0.3),
                zIndex: 0,
                pointerEvents: "none",
                animation: `${floatRandom} ${8 + iconData.delay * 2}s ease-in-out infinite ${iconData.delay}s`,
              }}
            >
              <Icon sx={{ fontSize: iconData.size }} />
            </Box>
          );
        })}

        <Box sx={{ position: "relative", zIndex: 1, textAlign: "center" }}>
          {/* Logo with Glow Effect and Security Shield - Above Title */}
          <Box
            sx={{
              display: "flex",
              justifyContent: "center",
              mb: 5,
              animation: `${fadeInUp} 1s ease-out`,
            }}
          >
            <Box
              sx={{
                position: "relative",
                width: { xs: 140, sm: 180, md: 220 },
                height: { xs: 140, sm: 180, md: 220 },
              }}
            >
              {/* Neon Green Radar Background */}
              <Box
                sx={{
                  position: "absolute",
                  inset: { xs: -35, sm: -45, md: -55 },
                  zIndex: 0,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  opacity: 0.7,
                }}
              >
                {/* Glassmorphic backdrop */}
                <Box
                  sx={{
                    position: "absolute",
                    width: { xs: 210, sm: 270, md: 330 },
                    height: { xs: 210, sm: 270, md: 330 },
                    borderRadius: "50%",
                    background: `radial-gradient(circle, ${alpha("#0a1a0f", 0.4)} 0%, ${alpha("#051005", 0.2)} 50%, transparent 70%)`,
                    backdropFilter: "blur(4px)",
                    WebkitBackdropFilter: "blur(4px)",
                  }}
                />
                
                {/* Outer static ring with gradient */}
                <Box
                  sx={{
                    position: "absolute",
                    width: { xs: 210, sm: 270, md: 330 },
                    height: { xs: 210, sm: 270, md: 330 },
                    borderRadius: "50%",
                    border: "1px solid",
                    borderColor: alpha("#39ff14", 0.12),
                    animation: `${radarRingPulse} 4s ease-in-out infinite`,
                    "&::before": {
                      content: '""',
                      position: "absolute",
                      inset: 0,
                      borderRadius: "50%",
                      background: `conic-gradient(from 0deg, transparent 0deg, ${alpha("#39ff14", 0.06)} 90deg, transparent 180deg, ${alpha("#39ff14", 0.03)} 270deg, transparent 360deg)`,
                    },
                  }}
                />

                {/* Ping waves - expanding outward */}
                {[0, 1, 2].map((i) => (
                  <Box
                    key={`ping-${i}`}
                    sx={{
                      position: "absolute",
                      width: { xs: 150, sm: 190, md: 230 },
                      height: { xs: 150, sm: 190, md: 230 },
                      borderRadius: "50%",
                      border: "1px solid",
                      borderColor: alpha("#39ff14", 0.25),
                      animation: `${radarPing} 3s ease-out infinite`,
                      animationDelay: `${i * 1}s`,
                    }}
                  />
                ))}

                {/* Middle ring with tick marks */}
                <Box
                  sx={{
                    position: "absolute",
                    width: { xs: 170, sm: 220, md: 270 },
                    height: { xs: 170, sm: 220, md: 270 },
                    borderRadius: "50%",
                    border: "1px solid",
                    borderColor: alpha("#39ff14", 0.18),
                    animation: `${radarRingPulse} 4s ease-in-out infinite 1s`,
                  }}
                />

                {/* Inner ring */}
                <Box
                  sx={{
                    position: "absolute",
                    width: { xs: 130, sm: 165, md: 200 },
                    height: { xs: 130, sm: 165, md: 200 },
                    borderRadius: "50%",
                    border: "1px solid",
                    borderColor: alpha("#39ff14", 0.2),
                    animation: `${radarRingPulse} 4s ease-in-out infinite 2s`,
                  }}
                />

                {/* Hexagonal accent ring - slow counter-rotation */}
                <Box
                  sx={{
                    position: "absolute",
                    width: { xs: 190, sm: 245, md: 300 },
                    height: { xs: 190, sm: 245, md: 300 },
                    animation: `${hexagonRotate} 30s linear infinite`,
                    willChange: "transform",
                  }}
                >
                  <svg width="100%" height="100%" viewBox="0 0 100 100">
                    <polygon
                      points="50,2 93,25 93,75 50,98 7,75 7,25"
                      fill="none"
                      stroke={alpha("#39ff14", 0.08)}
                      strokeWidth="0.3"
                      strokeDasharray="2 4"
                    />
                  </svg>
                </Box>

                {/* Radar sweep with gradient trail */}
                <Box
                  sx={{
                    position: "absolute",
                    width: { xs: 210, sm: 270, md: 330 },
                    height: { xs: 210, sm: 270, md: 330 },
                    animation: `${scanLine} 4s linear infinite`,
                    willChange: "transform",
                  }}
                >
                  {/* Main sweep line */}
                  <Box
                    sx={{
                      position: "absolute",
                      top: "50%",
                      left: "50%",
                      width: "50%",
                      height: "1px",
                      background: `linear-gradient(90deg, ${alpha("#39ff14", 0.7)} 0%, ${alpha("#39ff14", 0.5)} 30%, ${alpha("#39ff14", 0.2)} 70%, transparent 100%)`,
                      transformOrigin: "left center",
                      boxShadow: `
                        0 0 4px ${alpha("#39ff14", 0.6)},
                        0 0 8px ${alpha("#39ff14", 0.3)}
                      `,
                      borderRadius: "1px",
                    }}
                  />
                  {/* Sweep gradient cone - the "glow" trail */}
                  <Box
                    sx={{
                      position: "absolute",
                      top: "50%",
                      left: "50%",
                      width: "50%",
                      height: "50%",
                      background: `conic-gradient(from 0deg at 0% 0%, 
                        ${alpha("#39ff14", 0.15)} 0deg,
                        ${alpha("#39ff14", 0.08)} 15deg,
                        ${alpha("#39ff14", 0.03)} 35deg,
                        transparent 55deg
                      )`,
                      transformOrigin: "left top",
                      filter: "blur(1px)",
                    }}
                  />
                </Box>

                {/* Cross-hairs with subtle gradient */}
                <Box
                  sx={{
                    position: "absolute",
                    width: { xs: 210, sm: 270, md: 330 },
                    height: "1px",
                    background: `linear-gradient(90deg, 
                      transparent 0%, 
                      ${alpha("#39ff14", 0.08)} 20%, 
                      ${alpha("#39ff14", 0.12)} 50%, 
                      ${alpha("#39ff14", 0.08)} 80%, 
                      transparent 100%
                    )`,
                  }}
                />
                <Box
                  sx={{
                    position: "absolute",
                    width: "1px",
                    height: { xs: 210, sm: 270, md: 330 },
                    background: `linear-gradient(180deg, 
                      transparent 0%, 
                      ${alpha("#39ff14", 0.08)} 20%, 
                      ${alpha("#39ff14", 0.12)} 50%, 
                      ${alpha("#39ff14", 0.08)} 80%, 
                      transparent 100%
                    )`,
                  }}
                />

                {/* Radar blips - small dots that appear and fade */}
                {[
                  { x: 25, y: 30, delay: 0.5, size: 3 },
                  { x: 70, y: 25, delay: 1.2, size: 2 },
                  { x: 75, y: 65, delay: 2.1, size: 3 },
                  { x: 30, y: 70, delay: 0.8, size: 2 },
                ].map((blip, i) => (
                  <Box
                    key={`blip-${i}`}
                    sx={{
                      position: "absolute",
                      left: `${blip.x}%`,
                      top: `${blip.y}%`,
                      width: blip.size,
                      height: blip.size,
                      borderRadius: "50%",
                      background: alpha("#39ff14", 0.7),
                      boxShadow: `0 0 4px ${alpha("#39ff14", 0.5)}`,
                      animation: `${blipFade} ${2 + i * 0.3}s ease-in-out infinite`,
                      animationDelay: `${blip.delay}s`,
                    }}
                  />
                ))}

                {/* Neon green shield icon - subtle */}
                <ShieldIcon
                  sx={{
                    position: "absolute",
                    fontSize: { xs: 160, sm: 210, md: 260 },
                    color: "#39ff14",
                    opacity: 0.08,
                    animation: `${neonPulse} 4s ease-in-out infinite`,
                    willChange: "opacity, filter",
                  }}
                />

                {/* Corner accent marks */}
                {[0, 90, 180, 270].map((angle) => (
                  <Box
                    key={`corner-${angle}`}
                    sx={{
                      position: "absolute",
                      width: { xs: 200, sm: 255, md: 310 },
                      height: { xs: 200, sm: 255, md: 310 },
                      transform: `rotate(${angle}deg)`,
                    }}
                  >
                    <Box
                      sx={{
                        position: "absolute",
                        top: 0,
                        left: "50%",
                        width: "6px",
                        height: "1px",
                        background: alpha("#39ff14", 0.25),
                        transform: "translateX(-50%)",
                      }}
                    />
                  </Box>
                ))}
              </Box>

              {/* Soft glow behind logo */}
              <Box
                sx={{
                  position: "absolute",
                  inset: -20,
                  borderRadius: "50%",
                  background: `radial-gradient(circle, ${alpha("#39ff14", 0.12)} 0%, ${alpha("#39ff14", 0.06)} 40%, transparent 70%)`,
                  animation: `${pulse} 3s ease-in-out infinite`,
                  filter: "blur(20px)",
                }}
              />

              {/* Logo */}
              <Box
                component="img"
                src="/images/logo.jpg"
                alt="VRAgent Logo"
                sx={{
                  width: "100%",
                  height: "100%",
                  borderRadius: "50%",
                  objectFit: "cover",
                  position: "relative",
                  zIndex: 1,
                  border: `2px solid ${alpha("#39ff14", 0.5)}`,
                  boxShadow: `
                    0 8px 32px ${alpha("#000", 0.5)},
                    0 0 30px ${alpha("#39ff14", 0.35)},
                    0 0 60px ${alpha("#39ff14", 0.2)},
                    inset 0 0 30px ${alpha("#39ff14", 0.1)}
                  `,
                  animation: `${float} 4s ease-in-out infinite`,
                  transition: "all 0.4s ease",
                  "&:hover": {
                    transform: "scale(1.05)",
                    border: `2px solid ${alpha("#39ff14", 0.8)}`,
                    boxShadow: `
                      0 12px 48px ${alpha("#000", 0.6)},
                      0 0 50px ${alpha("#39ff14", 0.5)},
                      0 0 80px ${alpha("#39ff14", 0.3)},
                      inset 0 0 40px ${alpha("#39ff14", 0.15)}
                    `,
                  },
                }}
              />
            </Box>
          </Box>

          {/* Main Title - Clean and Centered */}
          <Box
            sx={{
              mb: 4,
              position: "relative",
              display: "inline-block",
            }}
          >
            <Typography
              variant="h1"
              sx={{
                fontWeight: 900,
                background: `linear-gradient(135deg, #fff 0%, #e0e7ff 30%, #c7d2fe 60%, #a5b4fc 100%)`,
                backgroundSize: "200% auto",
                backgroundClip: "text",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
                letterSpacing: "-0.04em",
                fontSize: { xs: "3rem", sm: "4rem", md: "5rem", lg: "6rem" },
                lineHeight: 1,
                animation: `${textGradientShift} 8s ease infinite`,
                textShadow: "none",
                mb: 2,
              }}
            >
              VRAgent
            </Typography>

            {/* Animated underline */}
            <Box
              sx={{
                position: "absolute",
                bottom: 0,
                left: "50%",
                transform: "translateX(-50%)",
                width: { xs: "70%", md: "80%" },
                height: "5px",
                background: `linear-gradient(90deg, transparent, ${alpha("#6366f1", 0.9)}, ${alpha("#8b5cf6", 0.9)}, transparent)`,
                borderRadius: "3px",
                boxShadow: `
                  0 0 30px ${alpha("#6366f1", 0.6)},
                  0 0 60px ${alpha("#8b5cf6", 0.4)}
                `,
              }}
            />
          </Box>

          {/* Badge */}
          <Box sx={{ mb: 4, display: "flex", gap: 2, flexWrap: "wrap", justifyContent: "center" }}>
            <Chip
              icon={<AutoAwesomeIcon sx={{ fontSize: 16 }} />}
              label="AI-Powered Security"
              sx={{
                background: `linear-gradient(135deg, ${alpha("#6366f1", 0.2)}, ${alpha("#8b5cf6", 0.2)})`,
                backdropFilter: "blur(10px)",
                WebkitBackdropFilter: "blur(10px)",
                border: `1px solid ${alpha("#8b5cf6", 0.4)}`,
                color: "#e0e0e0",
                fontWeight: 600,
                fontSize: "0.9rem",
                px: 2,
                py: 2.5,
                boxShadow: `0 4px 16px ${alpha("#8b5cf6", 0.2)}`,
                transition: "all 0.3s ease",
                "&:hover": {
                  transform: "translateY(-2px)",
                  boxShadow: `0 6px 20px ${alpha("#8b5cf6", 0.3)}`,
                  background: `linear-gradient(135deg, ${alpha("#6366f1", 0.3)}, ${alpha("#8b5cf6", 0.3)})`,
                },
              }}
            />
            <Chip
              icon={<BoltIcon sx={{ fontSize: 16 }} />}
              label="Real-Time Analysis"
              sx={{
                background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.2)}, ${alpha("#ef4444", 0.2)})`,
                backdropFilter: "blur(10px)",
                WebkitBackdropFilter: "blur(10px)",
                border: `1px solid ${alpha("#f59e0b", 0.4)}`,
                color: "#e0e0e0",
                fontWeight: 600,
                fontSize: "0.9rem",
                px: 2,
                py: 2.5,
                boxShadow: `0 4px 16px ${alpha("#f59e0b", 0.2)}`,
                transition: "all 0.3s ease",
                "&:hover": {
                  transform: "translateY(-2px)",
                  boxShadow: `0 6px 20px ${alpha("#f59e0b", 0.3)}`,
                  background: `linear-gradient(135deg, ${alpha("#f59e0b", 0.3)}, ${alpha("#ef4444", 0.3)})`,
                },
              }}
            />
          </Box>

          <Typography
            variant="h5"
            sx={{
              mb: 5,
              color: alpha("#fff", 0.75),
              maxWidth: { xs: "90%", md: 700 },
              mx: "auto",
              fontWeight: 400,
              lineHeight: 1.7,
              fontSize: { xs: "1rem", sm: "1.15rem", md: "1.3rem" },
              fontFamily: "monospace",
              minHeight: { xs: "80px", sm: "70px", md: "60px" },
              position: "relative",
              display: "inline-block",
              width: "100%",
              "&::after": {
                content: '"|"',
                animation: `${pulse} 1s ease-in-out infinite`,
                marginLeft: "3px",
                color: alpha("#6366f1", 0.9),
                fontWeight: 700,
              },
            }}
          >
            {typedText}
          </Typography>

          {/* CTA Buttons */}
          <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", justifyContent: "center" }}>
            <Button
              component={Link}
              to="/projects"
              variant="contained"
              size="large"
              startIcon={<RocketLaunchIcon sx={{ fontSize: 22 }} />}
              sx={{
                py: 2,
                px: 5,
                borderRadius: 3,
                background: "linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)",
                fontWeight: 700,
                fontSize: "1.1rem",
                textTransform: "none",
                position: "relative",
                overflow: "hidden",
                boxShadow: `
                  0 10px 30px ${alpha("#6366f1", 0.5)},
                  0 0 0 1px ${alpha("#fff", 0.15)} inset
                `,
                transition: "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
                "&::before": {
                  content: '""',
                  position: "absolute",
                  top: 0,
                  left: "-100%",
                  width: "100%",
                  height: "100%",
                  background: `linear-gradient(90deg, transparent, ${alpha("#fff", 0.25)}, transparent)`,
                  transition: "left 0.5s ease",
                },
                "&:hover": {
                  transform: "translateY(-4px)",
                  boxShadow: `
                    0 16px 48px ${alpha("#6366f1", 0.6)},
                    0 0 0 1px ${alpha("#fff", 0.2)} inset,
                    0 0 60px ${alpha("#6366f1", 0.4)}
                  `,
                  background: "linear-gradient(135deg, #7c3aed 0%, #a855f7 100%)",
                  "&::before": {
                    left: "100%",
                  },
                },
                "&:active": {
                  transform: "translateY(-2px)",
                },
              }}
            >
              Get Started
            </Button>
            <Button
              component={Link}
              to="/learn"
              variant="outlined"
              size="large"
              sx={{
                py: 2,
                px: 5,
                borderRadius: 3,
                borderWidth: "2px",
                borderColor: alpha("#fff", 0.25),
                color: "#fff",
                fontWeight: 700,
                fontSize: "1.1rem",
                textTransform: "none",
                position: "relative",
                overflow: "hidden",
                backdropFilter: "blur(10px)",
                WebkitBackdropFilter: "blur(10px)",
                transition: "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
                "&::before": {
                  content: '""',
                  position: "absolute",
                  top: 0,
                  left: 0,
                  right: 0,
                  bottom: 0,
                  background: `linear-gradient(135deg, ${alpha("#fff", 0.08)}, ${alpha("#6366f1", 0.08)})`,
                  opacity: 0,
                  transition: "opacity 0.3s ease",
                },
                "&:hover": {
                  borderWidth: "2px",
                  borderColor: alpha("#fff", 0.5),
                  transform: "translateY(-4px)",
                  boxShadow: `
                    0 12px 36px ${alpha("#fff", 0.2)},
                    0 0 0 1px ${alpha("#fff", 0.15)} inset
                  `,
                  "&::before": {
                    opacity: 1,
                  },
                },
                "&:active": {
                  transform: "translateY(-2px)",
                },
              }}
            >
              Learn More
            </Button>
          </Box>
        </Box>
      </Box>

      {/* Tech Stack / Powered By Section */}
      <Box
        sx={{
          mb: 6,
          p: { xs: 3, md: 4 },
          textAlign: "center",
          borderRadius: 4,
          background: `linear-gradient(135deg, ${alpha("#7c3aed", 0.05)} 0%, ${alpha("#ec4899", 0.05)} 100%)`,
          border: `1px solid ${alpha("#8b5cf6", 0.15)}`,
        }}
      >
        <Typography variant="overline" sx={{ fontSize: "0.875rem", fontWeight: 700, color: "text.secondary", mb: 2 }}>
          Powered By Industry-Leading Technologies
        </Typography>
        <Box
          sx={{
            display: "flex",
            gap: 2,
            flexWrap: "wrap",
            justifyContent: "center",
            alignItems: "center",
          }}
        >
          {[
            { name: "Gemini", color: "#f97316" },
            { name: "GLM", color: "#ef4444" },
            { name: "FRIDA", color: "#8b5cf6" },
            { name: "AFL++", color: "#06b6d4" },
            { name: "OpenVAS", color: "#22c55e" },
            { name: "Wireshark", color: "#3b82f6" },
            { name: "OWASP ZAP", color: "#f59e0b" },
            { name: "Nmap", color: "#ec4899" },
            { name: "Ghidra", color: "#8b5cf6" },
          ].map((tech, index) => (
            <Chip
              key={tech.name}
              label={tech.name}
              sx={{
                py: 2,
                px: 1,
                fontWeight: 700,
                fontSize: "0.875rem",
                background: alpha(tech.color, 0.1),
                border: `1px solid ${alpha(tech.color, 0.3)}`,
                color: "text.primary",
                transition: "all 0.3s ease",
                animation: `${scaleIn} 0.5s ease-out ${index * 0.05}s both`,
                "&:hover": {
                  transform: "translateY(-4px) scale(1.05)",
                  background: alpha(tech.color, 0.2),
                  border: `1px solid ${alpha(tech.color, 0.5)}`,
                  boxShadow: `0 12px 24px ${alpha(tech.color, 0.3)}`,
                },
              }}
            />
          ))}
        </Box>
      </Box>

      {/* Features Section - Carousel Layout */}
      <Box
        data-section="features"
        sx={{
          mb: 6,
          opacity: isVisible.features ? 1 : 0,
          transform: isVisible.features ? "translateY(0)" : "translateY(30px)",
          transition: "all 0.8s ease-out",
        }}
      >
        <Box sx={{ position: "relative", display: "inline-block", mb: 1 }}>
          <Typography
            variant="h4"
            fontWeight={800}
            sx={{
              background: `linear-gradient(135deg, #fff 0%, ${alpha("#8b5cf6", 0.9)} 100%)`,
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              letterSpacing: "-0.03em",
              fontFeatureSettings: '"liga" 1, "calt" 1',
              position: "relative",
              "&::after": {
                content: '""',
                position: "absolute",
                left: 0,
                bottom: -8,
                width: "60px",
                height: "4px",
                borderRadius: "2px",
                background: `linear-gradient(90deg, #6366f1, #8b5cf6)`,
                boxShadow: `0 0 20px ${alpha("#8b5cf6", 0.6)}`,
              },
            }}
          >
            Why Choose VRAgent
          </Typography>
        </Box>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 4, mt: 2, maxWidth: 700, fontSize: "1.05rem", lineHeight: 1.8, letterSpacing: "0.01em" }}>
          Cutting-edge security analysis tools combined with artificial intelligence to provide comprehensive protection
        </Typography>

        {/* Carousel Container */}
        <Box sx={{ position: "relative", overflow: "visible", borderRadius: 4, py: 4 }}>
          {/* Carousel Track - Perspective Style */}
          <Box
            sx={{
              display: "flex",
              justifyContent: "center",
              alignItems: "center",
              position: "relative",
              height: { xs: 380, md: 400 },
              perspective: "1200px",
            }}
          >
            {[
              {
                title: "AI-Powered Detection",
                description: "Advanced machine learning and large language models assist security researchers in identifying vulnerabilities, understanding attack surfaces, and developing proof-of-concept exploits with intelligent context-aware analysis.",
                icon: <ShieldIcon sx={{ fontSize: 48 }} />,
                color: "#22c55e",
                tags: ["ML Models", "LLM Analysis", "Exploit Dev"],
              },
              {
                title: "Agentic MITM",
                description: "Intelligent man-in-the-middle proxy with AI-powered request analysis. Intercept, modify, and replay HTTP/HTTPS traffic with automated vulnerability detection, parameter tampering suggestions, and session hijacking analysis.",
                icon: <SwapHorizIcon sx={{ fontSize: 48 }} />,
                color: "#ec4899",
                tags: ["Traffic Interception", "Request Replay", "Session Analysis"],
              },
              {
                title: "Agentic Fuzzing",
                description: "Autonomous AI agents orchestrate intelligent fuzzing campaigns across binaries and APIs. Self-directing security tests discover edge cases and vulnerabilities that traditional tools miss.",
                icon: <AutoAwesomeIcon sx={{ fontSize: 48 }} />,
                color: "#6366f1",
                tags: ["Autonomous", "Binary Analysis", "Smart Testing"],
              },
              {
                title: "Multi-Format Analysis",
                description: "Comprehensive security scanning across diverse file types including PE/ELF binaries, Android APKs, Docker images, and entire codebase folders. Unified analysis pipeline with format-specific vulnerability detection.",
                icon: <FolderOpenIcon sx={{ fontSize: 48 }} />,
                color: "#06b6d4",
                tags: ["Binaries", "APK Analysis", "Codebase Fuzzing"],
              },
              {
                title: "Network Analysis Suite",
                description: "Full-spectrum network security analysis with integrated Wireshark packet analyzer, DNS reconnaissance, PCAP file inspection, traffic flow visualization, and protocol-level vulnerability detection.",
                icon: <NetworkCheckIcon sx={{ fontSize: 48 }} />,
                color: "#10b981",
                tags: ["Wireshark", "DNS Recon", "PCAP Analysis"],
              },
              {
                title: "Team Collaboration",
                description: "Real-time collaborative security research with shared projects, interactive whiteboards, chat annotations, and synchronized findings. Work together seamlessly across time zones on unified project workspaces.",
                icon: <PeopleIcon sx={{ fontSize: 48 }} />,
                color: "#f59e0b",
                tags: ["Shared Projects", "Whiteboard", "Team Sync"],
              },
            ].map((feature, index) => {
              const totalSlides = 6;
              const offset = (index - featuresSlide + totalSlides) % totalSlides;
              const normalizedOffset = offset > totalSlides / 2 ? offset - totalSlides : offset;
              const isActive = normalizedOffset === 0;
              const isAdjacent = Math.abs(normalizedOffset) === 1;
              const isVisible = Math.abs(normalizedOffset) <= 1;

              return (
                <Box
                  key={index}
                  onClick={() => !isActive && setFeaturesSlide(index)}
                  sx={{
                    position: "absolute",
                    width: { xs: "85%", md: "70%" },
                    maxWidth: 800,
                    transition: "all 0.5s cubic-bezier(0.4, 0, 0.2, 1)",
                    transform: isActive
                      ? "translateX(0) scale(1) rotateY(0deg)"
                      : normalizedOffset < 0
                        ? { xs: "translateX(-70%) scale(0.75)", md: "translateX(-85%) scale(0.8) rotateY(25deg)" }
                        : { xs: "translateX(70%) scale(0.75)", md: "translateX(85%) scale(0.8) rotateY(-25deg)" },
                    opacity: isActive ? 1 : isAdjacent ? 0.5 : 0,
                    zIndex: isActive ? 10 : isAdjacent ? 5 : 0,
                    pointerEvents: isVisible ? "auto" : "none",
                    cursor: isActive ? "default" : "pointer",
                    filter: isActive ? "none" : "blur(1px)",
                  }}
                >
                  <Box
                    sx={{
                      p: { xs: 3, md: 4 },
                      borderRadius: 4,
                      background: `linear-gradient(135deg, ${alpha(feature.color, 0.12)} 0%, ${alpha(feature.color, 0.03)} 100%)`,
                      backdropFilter: "blur(24px)",
                      WebkitBackdropFilter: "blur(24px)",
                      border: `1px solid ${alpha(feature.color, isActive ? 0.3 : 0.15)}`,
                      position: "relative",
                      overflow: "hidden",
                      minHeight: { xs: 280, md: 320 },
                      display: "flex",
                      flexDirection: { xs: "column", md: "row" },
                      alignItems: { xs: "flex-start", md: "center" },
                      gap: 4,
                      boxShadow: isActive
                        ? `0 25px 50px ${alpha(feature.color, 0.3)}, inset 0 1px 1px ${alpha("#fff", 0.1)}`
                        : `0 10px 30px ${alpha("#000", 0.3)}`,
                      "&::before": {
                        content: '""',
                        position: "absolute",
                        top: 0,
                        right: 0,
                        width: "50%",
                        height: "100%",
                        background: `radial-gradient(circle at 100% 0%, ${alpha(feature.color, 0.2)}, transparent 60%)`,
                        pointerEvents: "none",
                      },
                    }}
                  >
                    <Box
                      sx={{
                        width: { xs: 70, md: 100 },
                        height: { xs: 70, md: 100 },
                        borderRadius: 3,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        background: `linear-gradient(135deg, ${feature.color}, ${alpha(feature.color, 0.7)})`,
                        color: "#fff",
                        flexShrink: 0,
                        boxShadow: `0 12px 40px ${alpha(feature.color, 0.4)}`,
                      }}
                    >
                      {feature.icon}
                    </Box>
                    <Box sx={{ flex: 1 }}>
                      <Typography variant="h5" fontWeight={800} sx={{ mb: 1.5, letterSpacing: "-0.02em" }}>
                        {feature.title}
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7, maxWidth: 500, mb: 2, letterSpacing: "0.01em", display: { xs: "none", sm: "block" } }}>
                        {feature.description}
                      </Typography>
                      <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                        {feature.tags.map((tag) => (
                          <Chip
                            key={tag}
                            label={tag}
                            size="small"
                            sx={{
                              background: alpha(feature.color, 0.15),
                              border: `1px solid ${alpha(feature.color, 0.3)}`,
                              color: feature.color,
                              fontWeight: 600,
                              fontSize: "0.7rem",
                            }}
                          />
                        ))}
                      </Box>
                    </Box>
                  </Box>
                </Box>
              );
            })}
          </Box>

          {/* Navigation Arrows */}
          <Box
            onClick={() => setFeaturesSlide((prev) => (prev - 1 + 6) % 6)}
            sx={{
              position: "absolute",
              left: { xs: 8, md: 24 },
              top: "50%",
              transform: "translateY(-50%)",
              width: { xs: 40, md: 52 },
              height: { xs: 40, md: 52 },
              borderRadius: "50%",
              background: alpha("#fff", 0.15),
              backdropFilter: "blur(10px)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              cursor: "pointer",
              transition: "all 0.3s ease",
              border: `1px solid ${alpha("#fff", 0.25)}`,
              zIndex: 20,
              "&:hover": {
                background: alpha("#fff", 0.25),
                transform: "translateY(-50%) scale(1.1)",
              },
            }}
          >
            <Typography sx={{ fontSize: { xs: 20, md: 28 }, color: "#fff", fontWeight: 300 }}>‹</Typography>
          </Box>
          <Box
            onClick={() => setFeaturesSlide((prev) => (prev + 1) % 6)}
            sx={{
              position: "absolute",
              right: { xs: 8, md: 24 },
              top: "50%",
              transform: "translateY(-50%)",
              width: { xs: 40, md: 52 },
              height: { xs: 40, md: 52 },
              borderRadius: "50%",
              background: alpha("#fff", 0.15),
              backdropFilter: "blur(10px)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              cursor: "pointer",
              transition: "all 0.3s ease",
              border: `1px solid ${alpha("#fff", 0.25)}`,
              zIndex: 20,
              "&:hover": {
                background: alpha("#fff", 0.25),
                transform: "translateY(-50%) scale(1.1)",
              },
            }}
          >
            <Typography sx={{ fontSize: { xs: 20, md: 28 }, color: "#fff", fontWeight: 300 }}>›</Typography>
          </Box>

          {/* Dot Indicators */}
          <Box sx={{ display: "flex", justifyContent: "center", gap: 1, mt: 4 }}>
            {[0, 1, 2, 3, 4, 5].map((i) => (
              <Box
                key={i}
                onClick={() => setFeaturesSlide(i)}
                sx={{
                  width: featuresSlide === i ? 32 : 10,
                  height: 10,
                  borderRadius: 5,
                  background: featuresSlide === i 
                    ? `linear-gradient(90deg, #6366f1, #8b5cf6)` 
                    : alpha("#fff", 0.3),
                  cursor: "pointer",
                  transition: "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
                  "&:hover": {
                    background: featuresSlide === i 
                      ? `linear-gradient(90deg, #6366f1, #8b5cf6)` 
                      : alpha("#fff", 0.5),
                  },
                }}
              />
            ))}
          </Box>
        </Box>
      </Box>

      {/* Hub Cards Grid - Parallax removed for performance */}
      <Box
        data-section="hubs"
        sx={{
          mb: 6,
          opacity: isVisible.hubs ? 1 : 0,
          transform: isVisible.hubs ? "translateY(0)" : "translateY(30px)",
          transition: "all 0.8s ease-out",
        }}
      >
        <Box sx={{ position: "relative", display: "inline-block", mb: 1 }}>
          <Typography
            variant="h4"
            fontWeight={800}
            sx={{
              background: `linear-gradient(135deg, #fff 0%, ${alpha("#06b6d4", 0.9)} 100%)`,
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              letterSpacing: "-0.02em",
              position: "relative",
              "&::after": {
                content: '""',
                position: "absolute",
                left: 0,
                bottom: -8,
                width: "60px",
                height: "4px",
                borderRadius: "2px",
                background: `linear-gradient(90deg, #06b6d4, #0891b2)`,
                boxShadow: `0 0 20px ${alpha("#06b6d4", 0.6)}`,
              },
            }}
          >
            Security Hubs
          </Typography>
        </Box>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 4, mt: 2, maxWidth: 700, fontSize: "1.05rem", lineHeight: 1.7 }}>
          Choose a hub to begin your security analysis journey
        </Typography>

        <Grid container spacing={3}>
          {/* Projects Hub */}
          <Grid item xs={12} sm={6} md={4}>
            <HubCard
              title="Projects Hub"
              description="Manage codebases and configure security scanning. Upload code, connect Git repositories, and organize your security assessments."
              icon={<FolderIcon sx={{ fontSize: 40 }} />}
              to="/projects"
              gradient={`linear-gradient(135deg, ${alpha("#10b981", 0.08)} 0%, ${alpha("#059669", 0.05)} 100%)`}
              shadowColor="#10b981"
              iconBg="linear-gradient(135deg, #10b981 0%, #059669 100%)"
              delay={0}
            />
          </Grid>

          {/* Static Analysis Hub */}
          <Grid item xs={12} sm={6} md={4}>
            <HubCard
              title="Static Analysis Hub"
              description="AI-powered source code security scanning. Detect vulnerabilities, hardcoded secrets, and security flaws without executing code."
              icon={<SecurityIcon sx={{ fontSize: 40 }} />}
              to="/static"
              gradient={`linear-gradient(135deg, ${alpha("#22c55e", 0.08)} 0%, ${alpha("#16a34a", 0.05)} 100%)`}
              shadowColor="#22c55e"
              iconBg="linear-gradient(135deg, #22c55e 0%, #16a34a 100%)"
              delay={0.1}
            />
          </Grid>

          {/* Dynamic Analysis Hub */}
          <Grid item xs={12} sm={6} md={4}>
            <HubCard
              title="Dynamic Analysis Hub"
              description="Network traffic analysis, API testing, fuzzing, and runtime security testing. Analyze PCAP files and intercept traffic."
              icon={<HubIcon sx={{ fontSize: 40 }} />}
              to="/dynamic"
              gradient={`linear-gradient(135deg, ${alpha("#06b6d4", 0.08)} 0%, ${alpha("#0891b2", 0.05)} 100%)`}
              shadowColor="#06b6d4"
              iconBg="linear-gradient(135deg, #06b6d4 0%, #0891b2 100%)"
              delay={0.2}
            />
          </Grid>

          {/* Reverse Engineering Hub */}
          <Grid item xs={12} sm={6} md={4}>
            <HubCard
              title="Reverse Engineering Hub"
              description="Binary analysis for APKs, PE/ELF executables, and Docker images. Decompile, disassemble, and analyze with AI assistance."
              icon={<MemoryIcon sx={{ fontSize: 40 }} />}
              to="/reverse"
              gradient={`linear-gradient(135deg, ${alpha("#f97316", 0.08)} 0%, ${alpha("#ea580c", 0.05)} 100%)`}
              shadowColor="#f97316"
              iconBg="linear-gradient(135deg, #f97316 0%, #ea580c 100%)"
              delay={0.3}
            />
          </Grid>

          {/* Learning Hub */}
          <Grid item xs={12} sm={6} md={4}>
            <HubCard
              title="Learning Hub"
              description="Master security concepts, tools, and techniques. Comprehensive tutorials on OWASP, MITRE ATT&CK, and penetration testing."
              icon={<MenuBookIcon sx={{ fontSize: 40 }} />}
              to="/learn"
              gradient={`linear-gradient(135deg, ${alpha("#8b5cf6", 0.08)} 0%, ${alpha("#7c3aed", 0.05)} 100%)`}
              shadowColor="#8b5cf6"
              iconBg="linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)"
              delay={0.4}
            />
          </Grid>

          {/* Social Hub */}
          <Grid item xs={12} sm={6} md={4}>
            <HubCard
              title="Social Hub"
              description="Connect with security researchers. Find friends, share findings, collaborate on projects, and chat in real-time."
              icon={<PeopleIcon sx={{ fontSize: 40 }} />}
              to="/social"
              gradient={`linear-gradient(135deg, ${alpha("#ec4899", 0.08)} 0%, ${alpha("#db2777", 0.05)} 100%)`}
              shadowColor="#ec4899"
              iconBg="linear-gradient(135deg, #ec4899 0%, #db2777 100%)"
              delay={0.5}
            />
          </Grid>
        </Grid>
      </Box>

      {/* Divider with gradient */}
      <Box sx={{ mb: 6, position: "relative" }}>
        <Divider
          sx={{
            "&::before, &::after": {
              borderColor: alpha("#8b5cf6", 0.3),
            },
          }}
        />
        <Box
          sx={{
            position: "absolute",
            top: "50%",
            left: "50%",
            transform: "translate(-50%, -50%)",
            width: "100px",
            height: "2px",
            background: `linear-gradient(90deg, transparent, #8b5cf6, transparent)`,
            boxShadow: `0 0 20px ${alpha("#8b5cf6", 0.6)}`,
          }}
        />
      </Box>

      {/* Getting Started Guide - Modern Timeline */}
      <Box
        sx={{
          py: { xs: 4, md: 6 },
          position: "relative",
        }}
      >
        <Box sx={{ position: "relative", display: "inline-block", mb: 1 }}>
          <Typography
            variant="h4"
            fontWeight={800}
            sx={{
              background: `linear-gradient(135deg, #fff 0%, ${alpha("#3b82f6", 0.9)} 100%)`,
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              letterSpacing: "-0.02em",
              position: "relative",
              "&::after": {
                content: '""',
                position: "absolute",
                left: 0,
                bottom: -8,
                width: "60px",
                height: "4px",
                borderRadius: "2px",
                background: `linear-gradient(90deg, #3b82f6, #06b6d4)`,
                boxShadow: `0 0 20px ${alpha("#3b82f6", 0.6)}`,
              },
            }}
          >
            Getting Started
          </Typography>
        </Box>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 5, mt: 2, maxWidth: 600, fontSize: "1.05rem", lineHeight: 1.7 }}>
          Three powerful analysis approaches to secure your applications
        </Typography>

        {/* Timeline Container */}
        <Box sx={{ position: "relative" }}>
          {/* Connecting Line - Desktop Only */}
          <Box
            sx={{
              display: { xs: "none", md: "block" },
              position: "absolute",
              top: 60,
              left: "calc(16.66% + 24px)",
              right: "calc(16.66% + 24px)",
              height: 2,
              background: `linear-gradient(90deg, #22c55e, #3b82f6, #f59e0b)`,
              opacity: 0.4,
              "&::before": {
                content: '""',
                position: "absolute",
                top: -4,
                left: 0,
                right: 0,
                height: 10,
                background: `linear-gradient(90deg, ${alpha("#22c55e", 0.2)}, ${alpha("#3b82f6", 0.2)}, ${alpha("#f59e0b", 0.2)})`,
                filter: "blur(8px)",
              },
            }}
          />

          <Grid container spacing={4}>
            {[
              {
                step: "01",
                title: "Static Analysis",
                subtitle: "Source Code Security",
                description: "Upload source code and let AI scan for vulnerabilities, hardcoded secrets, and security anti-patterns across 20+ languages.",
                color: "#22c55e",
                icon: <CodeIcon sx={{ fontSize: 28 }} />,
                features: ["AI Detection", "Secret Scanning", "Code Quality"],
              },
              {
                step: "02",
                title: "Dynamic Testing",
                subtitle: "Runtime Security",
                description: "Test running applications with traffic interception, API fuzzing, and real-time vulnerability detection during execution.",
                color: "#3b82f6",
                icon: <BoltIcon sx={{ fontSize: 28 }} />,
                features: ["MITM Proxy", "API Fuzzing", "Traffic Analysis"],
              },
              {
                step: "03",
                title: "Reverse Engineering",
                subtitle: "Binary Analysis",
                description: "Decompile and analyze binaries, APKs, and container images to uncover hidden functionality and vulnerabilities.",
                color: "#f59e0b",
                icon: <MemoryIcon sx={{ fontSize: 28 }} />,
                features: ["Decompilation", "APK Analysis", "Docker Inspect"],
              },
            ].map((item, index) => (
              <Grid item xs={12} md={4} key={item.step}>
                <Box
                  sx={{
                    position: "relative",
                    height: "100%",
                    animation: `${scaleIn} 0.6s ease-out ${index * 0.15}s both`,
                  }}
                >
                  {/* Step Number Badge */}
                  <Box
                    sx={{
                      position: "relative",
                      zIndex: 2,
                      width: 80,
                      height: 80,
                      mx: "auto",
                      mb: 3,
                      borderRadius: "50%",
                      background: `linear-gradient(135deg, ${item.color}, ${alpha(item.color, 0.6)})`,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      boxShadow: `
                        0 8px 32px ${alpha(item.color, 0.4)},
                        0 0 0 4px ${alpha(item.color, 0.1)},
                        inset 0 2px 4px ${alpha("#fff", 0.2)}
                      `,
                      transition: "all 0.4s cubic-bezier(0.4, 0, 0.2, 1)",
                      cursor: "default",
                      "&:hover": {
                        transform: "scale(1.1) rotate(5deg)",
                        boxShadow: `
                          0 12px 40px ${alpha(item.color, 0.5)},
                          0 0 0 8px ${alpha(item.color, 0.15)},
                          inset 0 2px 4px ${alpha("#fff", 0.3)}
                        `,
                      },
                    }}
                  >
                    <Typography
                      sx={{
                        fontSize: "1.75rem",
                        fontWeight: 900,
                        color: "#fff",
                        textShadow: `0 2px 4px ${alpha("#000", 0.2)}`,
                        fontFamily: "monospace",
                      }}
                    >
                      {item.step}
                    </Typography>
                  </Box>

                  {/* Card Content */}
                  <Box
                    sx={{
                      p: 3,
                      borderRadius: 4,
                      background: `linear-gradient(180deg, ${alpha(item.color, 0.08)} 0%, ${alpha(item.color, 0.02)} 100%)`,
                      backdropFilter: "blur(20px)",
                      border: `1px solid ${alpha(item.color, 0.15)}`,
                      textAlign: "center",
                      transition: "all 0.5s cubic-bezier(0.4, 0, 0.2, 1)",
                      position: "relative",
                      overflow: "hidden",
                      minHeight: 320,
                      display: "flex",
                      flexDirection: "column",
                      "&::before": {
                        content: '""',
                        position: "absolute",
                        top: 0,
                        left: "50%",
                        transform: "translateX(-50%)",
                        width: 60,
                        height: 3,
                        borderRadius: "0 0 4px 4px",
                        background: item.color,
                        boxShadow: `0 4px 12px ${alpha(item.color, 0.4)}`,
                        transition: "all 0.4s ease",
                      },
                      "&::after": {
                        content: '""',
                        position: "absolute",
                        inset: 0,
                        borderRadius: 4,
                        padding: "2px",
                        background: `conic-gradient(from 0deg, ${alpha(item.color, 0.5)}, transparent 25%, transparent 75%, ${alpha(item.color, 0.5)})`,
                        WebkitMask: "linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)",
                        WebkitMaskComposite: "xor",
                        maskComposite: "exclude",
                        opacity: 0,
                        transition: "opacity 0.4s ease",
                        animation: `${rotateGradient} 4s linear infinite`,
                        animationPlayState: "paused",
                      },
                      "&:hover": {
                        transform: "translateY(-12px) scale(1.02)",
                        background: `linear-gradient(180deg, ${alpha(item.color, 0.15)} 0%, ${alpha(item.color, 0.05)} 100%)`,
                        border: `1px solid ${alpha(item.color, 0.4)}`,
                        boxShadow: `
                          0 25px 50px ${alpha(item.color, 0.3)},
                          0 0 40px ${alpha(item.color, 0.15)},
                          inset 0 1px 1px ${alpha("#fff", 0.1)}
                        `,
                        "&::before": {
                          width: "80%",
                          boxShadow: `0 6px 20px ${alpha(item.color, 0.6)}`,
                        },
                        "&::after": {
                          opacity: 1,
                          animationPlayState: "running",
                        },
                        "& .step-icon": {
                          transform: "scale(1.15) rotate(10deg)",
                          boxShadow: `0 8px 24px ${alpha(item.color, 0.5)}`,
                        },
                        "& .step-features .feature-pill": {
                          transform: "translateY(-2px)",
                        },
                      },
                    }}
                  >
                    {/* Icon */}
                    <Box
                      className="step-icon"
                      sx={{
                        width: 56,
                        height: 56,
                        mx: "auto",
                        mb: 2,
                        borderRadius: 3,
                        background: `linear-gradient(135deg, ${item.color}, ${alpha(item.color, 0.7)})`,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        color: "#fff",
                        boxShadow: `0 4px 16px ${alpha(item.color, 0.4)}`,
                        transition: "all 0.4s cubic-bezier(0.4, 0, 0.2, 1)",
                      }}
                    >
                      {item.icon}
                    </Box>

                    <Typography
                      variant="overline"
                      sx={{
                        color: item.color,
                        fontWeight: 700,
                        letterSpacing: 2,
                        fontSize: "0.7rem",
                      }}
                    >
                      {item.subtitle}
                    </Typography>
                    <Typography
                      variant="h6"
                      fontWeight={800}
                      sx={{ mb: 1.5, letterSpacing: "-0.01em" }}
                    >
                      {item.title}
                    </Typography>
                    <Typography
                      variant="body2"
                      color="text.secondary"
                      sx={{ lineHeight: 1.7, mb: 2.5, flex: 1 }}
                    >
                      {item.description}
                    </Typography>

                    {/* Feature Pills */}
                    <Box className="step-features" sx={{ display: "flex", gap: 0.75, flexWrap: "wrap", justifyContent: "center" }}>
                      {item.features.map((feature, fIndex) => (
                        <Box
                          key={feature}
                          className="feature-pill"
                          sx={{
                            px: 1.5,
                            py: 0.5,
                            borderRadius: 2,
                            background: alpha(item.color, 0.1),
                            border: `1px solid ${alpha(item.color, 0.2)}`,
                            fontSize: "0.7rem",
                            fontWeight: 600,
                            color: item.color,
                            transition: `all 0.3s ease ${fIndex * 0.05}s`,
                          }}
                        >
                          {feature}
                        </Box>
                      ))}
                    </Box>
                  </Box>
                </Box>
              </Grid>
            ))}
          </Grid>
        </Box>
      </Box>
    </Container>
    </Box>
  );
};

export default HomePage;
