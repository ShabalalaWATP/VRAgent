import { createContext, useContext, useMemo, useState, useEffect, ReactNode } from "react";
import { ThemeProvider as MuiThemeProvider, createTheme, PaletteMode } from "@mui/material";

type ThemeContextType = {
  mode: PaletteMode;
  toggleTheme: () => void;
};

const ThemeContext = createContext<ThemeContextType>({
  mode: "dark",
  toggleTheme: () => {},
});

export const useThemeMode = () => useContext(ThemeContext);

const getDesignTokens = (mode: PaletteMode) => ({
  palette: {
    mode,
    ...(mode === "dark"
      ? {
          // Dark mode palette
          primary: {
            main: "#6366f1", // Indigo
            light: "#818cf8",
            dark: "#4f46e5",
          },
          secondary: {
            main: "#22d3ee", // Cyan
            light: "#67e8f9",
            dark: "#06b6d4",
          },
          background: {
            default: "#0f172a", // Slate 900
            paper: "#1e293b", // Slate 800
          },
          error: {
            main: "#ef4444",
            light: "#f87171",
            dark: "#dc2626",
          },
          warning: {
            main: "#f59e0b",
            light: "#fbbf24",
            dark: "#d97706",
          },
          success: {
            main: "#10b981",
            light: "#34d399",
            dark: "#059669",
          },
          text: {
            primary: "#f1f5f9",
            secondary: "#94a3b8",
          },
          divider: "#334155",
        }
      : {
          // Light mode palette
          primary: {
            main: "#4f46e5", // Indigo
            light: "#6366f1",
            dark: "#4338ca",
          },
          secondary: {
            main: "#0891b2", // Cyan
            light: "#06b6d4",
            dark: "#0e7490",
          },
          background: {
            default: "#f8fafc", // Slate 50
            paper: "#ffffff",
          },
          error: {
            main: "#dc2626",
          },
          warning: {
            main: "#d97706",
          },
          success: {
            main: "#059669",
          },
          text: {
            primary: "#0f172a",
            secondary: "#475569",
          },
          divider: "#e2e8f0",
        }),
  },
  typography: {
    fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
    h1: {
      fontWeight: 700,
      letterSpacing: "-0.025em",
    },
    h2: {
      fontWeight: 700,
      letterSpacing: "-0.025em",
    },
    h3: {
      fontWeight: 600,
      letterSpacing: "-0.025em",
    },
    h4: {
      fontWeight: 600,
    },
    h5: {
      fontWeight: 600,
    },
    h6: {
      fontWeight: 600,
    },
    button: {
      textTransform: "none" as const,
      fontWeight: 500,
    },
  },
  shape: {
    borderRadius: 12,
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 8,
          padding: "8px 16px",
          fontWeight: 500,
        },
        contained: {
          boxShadow: "none",
          "&:hover": {
            boxShadow: "0 4px 12px rgba(99, 102, 241, 0.4)",
          },
        },
        outlined: {
          borderWidth: 1.5,
          "&:hover": {
            borderWidth: 1.5,
          },
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          borderRadius: 16,
          boxShadow: mode === "dark" 
            ? "0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -1px rgba(0, 0, 0, 0.2)"
            : "0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06)",
          border: mode === "dark" ? "1px solid #334155" : "1px solid #e2e8f0",
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundImage: "none",
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundImage: "none",
          backgroundColor: mode === "dark" ? "#1e293b" : "#ffffff",
          borderBottom: mode === "dark" ? "1px solid #334155" : "1px solid #e2e8f0",
          boxShadow: "none",
        },
      },
    },
    MuiTableHead: {
      styleOverrides: {
        root: {
          "& .MuiTableCell-head": {
            fontWeight: 600,
            backgroundColor: mode === "dark" ? "#1e293b" : "#f1f5f9",
            color: mode === "dark" ? "#f1f5f9" : "#0f172a",
          },
        },
      },
    },
    MuiTableRow: {
      styleOverrides: {
        root: {
          "&:hover": {
            backgroundColor: mode === "dark" ? "#334155" : "#f1f5f9",
          },
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: {
          borderBottom: mode === "dark" ? "1px solid #334155" : "1px solid #e2e8f0",
        },
      },
    },
    MuiDialog: {
      styleOverrides: {
        paper: {
          borderRadius: 16,
          border: mode === "dark" ? "1px solid #334155" : "1px solid #e2e8f0",
        },
      },
    },
    MuiTextField: {
      styleOverrides: {
        root: {
          "& .MuiOutlinedInput-root": {
            borderRadius: 8,
          },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          fontWeight: 500,
        },
      },
    },
  },
});

type Props = {
  children: ReactNode;
};

export function ThemeProvider({ children }: Props) {
  const [mode, setMode] = useState<PaletteMode>(() => {
    // Check localStorage for saved preference
    const saved = localStorage.getItem("theme-mode");
    if (saved === "light" || saved === "dark") {
      return saved;
    }
    // Default to dark mode
    return "dark";
  });

  useEffect(() => {
    localStorage.setItem("theme-mode", mode);
  }, [mode]);

  const toggleTheme = () => {
    setMode((prev: PaletteMode) => (prev === "dark" ? "light" : "dark"));
  };

  const theme = useMemo(() => createTheme(getDesignTokens(mode)), [mode]);

  return (
    <ThemeContext.Provider value={{ mode, toggleTheme }}>
      <MuiThemeProvider theme={theme}>{children}</MuiThemeProvider>
    </ThemeContext.Provider>
  );
}
