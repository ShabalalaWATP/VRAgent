import React, { useState, useEffect } from "react";
import {
  Box,
  Paper,
  Typography,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  Button,
  Chip,
  CircularProgress,
  Collapse,
  IconButton,
  Tooltip,
  Alert,
  LinearProgress,
  Divider,
  Drawer,
  Fab,
  Badge,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  alpha,
  useTheme,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from "@mui/material";
import {
  School as WalkthroughIcon,
  PlayArrow as StartIcon,
  NavigateNext as NextIcon,
  NavigateBefore as PrevIcon,
  ExpandMore as ExpandIcon,
  CheckCircle as CompleteIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  MenuBook as GlossaryIcon,
  Lightbulb as TipIcon,
  Close as CloseIcon,
  Refresh as RestartIcon,
  Help as HelpIcon,
  Security as SecurityIcon,
  Visibility as ViewIcon,
  AutoAwesome as AiIcon,
  Flag as MilestoneIcon,
  Link as LinkIcon,
} from "@mui/icons-material";
import { reverseEngineeringClient, type WalkthroughStep, type LearningResource, type UnifiedApkScanResult } from "../api/client";

interface GuidedWalkthroughProps {
  unifiedScanResult: UnifiedApkScanResult | null;
  onNavigateToTab?: (tabIndex: number) => void;
  onHighlightFinding?: (findingType: string) => void;
}

// Map walkthrough phases to tab indices
const PHASE_TAB_MAP: Record<string, number> = {
  "Basic Information": 0, // Overview/Summary
  "Permission Analysis": 0, // Permissions tab or main
  "Secret Detection": 0, // Secrets section
  "JADX Decompilation": 0, // Decompilation info
  "Code Security Scan": 0, // Code findings
  "Sensitive Data Discovery": 0, // Sensitive data
  "CVE Database Lookup": 0, // CVE findings
  "AI Vulnerability Hunt": 0, // VulnHuntr
  "AI Finding Verification": 0, // Verification
  "Component Analysis": 0, // Components
  "Protection Detection": 0, // Obfuscation/Protection
  "AI Report Generation": 0, // AI diagrams
  "Dynamic Testing Scripts": 0, // Frida scripts
  "Analysis Complete": 0, // Summary
};

export default function GuidedWalkthrough({
  unifiedScanResult,
  onNavigateToTab,
  onHighlightFinding,
}: GuidedWalkthroughProps) {
  const theme = useTheme();
  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeStep, setActiveStep] = useState(0);
  const [steps, setSteps] = useState<WalkthroughStep[]>([]);
  const [glossary, setGlossary] = useState<Record<string, string>>({});
  const [learningResources, setLearningResources] = useState<LearningResource[]>([]);
  const [nextStepsSuggestions, setNextStepsSuggestions] = useState<string[]>([]);
  const [showGlossary, setShowGlossary] = useState(false);
  const [expandedExplanations, setExpandedExplanations] = useState<Set<number>>(new Set([0]));
  const [completedSteps, setCompletedSteps] = useState<Set<number>>(new Set());
  const [showCompletionDialog, setShowCompletionDialog] = useState(false);

  const loadWalkthrough = async () => {
    if (!unifiedScanResult) return;

    setIsLoading(true);
    setError(null);

    try {
      // Build analysis context for the walkthrough
      const analysisContext: Record<string, unknown> = {
        // Basic info
        package_name: unifiedScanResult.package_name,
        version_name: unifiedScanResult.version_name,
        version_code: unifiedScanResult.version_code,
        min_sdk: unifiedScanResult.min_sdk,
        target_sdk: unifiedScanResult.target_sdk,
        
        // Permissions
        permissions: unifiedScanResult.permissions,
        dangerous_permissions_count: unifiedScanResult.dangerous_permissions_count,
        
        // Security findings
        security_issues: unifiedScanResult.security_issues,
        secrets: unifiedScanResult.secrets,
        
        // Components
        components: unifiedScanResult.components,
        
        // Native analysis
        native_libraries: unifiedScanResult.native_libraries,
        
        // Code stats
        total_classes: unifiedScanResult.total_classes,
        total_files: unifiedScanResult.total_files,
        
        // NEW: Decompiled code scan
        decompiled_code_findings: unifiedScanResult.decompiled_code_findings || [],
        decompiled_code_summary: unifiedScanResult.decompiled_code_summary || {},
        
        // NEW: Sensitive data discovery
        sensitive_data_findings: unifiedScanResult.sensitive_data_findings || {},
        
        // NEW: CVE scan
        cve_scan_results: unifiedScanResult.cve_scan_results || {},
        
        // NEW: AI vulnerability hunt (note: vuln_hunt_result not vuln_hunt_results)
        vuln_hunt_results: unifiedScanResult.vuln_hunt_result || {},
        
        // NEW: AI verification
        verification_results: unifiedScanResult.verification_results || {},
        
        // NEW: AI reports
        ai_architecture_diagram: unifiedScanResult.ai_architecture_diagram,
        ai_attack_surface_map: unifiedScanResult.ai_attack_surface_map,
        
        // Dynamic analysis & protections
        dynamic_analysis: unifiedScanResult.dynamic_analysis,
        
        // Frida vulnerability hooks
        vulnerability_frida_hooks: unifiedScanResult.vulnerability_frida_hooks,
      };

      const response = await reverseEngineeringClient.getAnalysisWalkthrough(analysisContext);
      
      setSteps(response.steps);
      setGlossary(response.glossary);
      setLearningResources(response.learning_resources || []);
      setNextStepsSuggestions(response.next_steps || []);
      setActiveStep(0);
      setCompletedSteps(new Set());
      setExpandedExplanations(new Set([0]));
    } catch (err: any) {
      setError(err.message || "Failed to load walkthrough");
    } finally {
      setIsLoading(false);
    }
  };

  // Auto-load when opened
  useEffect(() => {
    if (isOpen && unifiedScanResult && steps.length === 0) {
      loadWalkthrough();
    }
  }, [isOpen, unifiedScanResult]);

  const handleNext = () => {
    setCompletedSteps(prev => new Set([...prev, activeStep]));
    
    if (activeStep < steps.length - 1) {
      const nextStep = activeStep + 1;
      setActiveStep(nextStep);
      setExpandedExplanations(prev => new Set([...prev, nextStep]));
      
      // Navigate to relevant tab
      const step = steps[nextStep];
      if (step && onNavigateToTab) {
        const tabIndex = PHASE_TAB_MAP[step.phase] || 0;
        onNavigateToTab(tabIndex);
      }
    } else {
      // All steps completed
      setShowCompletionDialog(true);
    }
  };

  const handleBack = () => {
    if (activeStep > 0) {
      setActiveStep(activeStep - 1);
    }
  };

  const handleStepClick = (stepIndex: number) => {
    setActiveStep(stepIndex);
    setExpandedExplanations(prev => new Set([...prev, stepIndex]));
    
    // Navigate to relevant tab
    const step = steps[stepIndex];
    if (step && onNavigateToTab) {
      const tabIndex = PHASE_TAB_MAP[step.phase] || 0;
      onNavigateToTab(tabIndex);
    }
  };

  const handleRestart = () => {
    setActiveStep(0);
    setCompletedSteps(new Set());
    setExpandedExplanations(new Set([0]));
    setShowCompletionDialog(false);
  };

  const toggleExplanation = (stepIndex: number) => {
    setExpandedExplanations(prev => {
      const newSet = new Set(prev);
      if (newSet.has(stepIndex)) {
        newSet.delete(stepIndex);
      } else {
        newSet.add(stepIndex);
      }
      return newSet;
    });
  };

  const getSeverityIcon = (severity?: string) => {
    switch (severity?.toLowerCase()) {
      case "critical":
        return <ErrorIcon color="error" />;
      case "high":
        return <WarningIcon sx={{ color: theme.palette.warning.dark }} />;
      case "medium":
        return <WarningIcon color="warning" />;
      case "low":
        return <InfoIcon color="info" />;
      default:
        return <InfoIcon color="action" />;
    }
  };

  const getSeverityColor = (severity?: string) => {
    switch (severity?.toLowerCase()) {
      case "critical":
        return theme.palette.error.main;
      case "high":
        return theme.palette.warning.dark;
      case "medium":
        return theme.palette.warning.main;
      case "low":
        return theme.palette.info.main;
      default:
        return theme.palette.grey[500];
    }
  };

  const overallProgress = steps.length > 0 ? Math.round((completedSteps.size / steps.length) * 100) : 0;

  // FAB button when panel is closed
  if (!isOpen) {
    return (
      <Tooltip title="Guided Walkthrough - Learn step by step">
        <Fab
          color="secondary"
          onClick={() => setIsOpen(true)}
          disabled={!unifiedScanResult}
          sx={{
            position: "fixed",
            bottom: 24,
            right: 90, // Position to the left of chat FAB
            background: unifiedScanResult
              ? `linear-gradient(135deg, ${theme.palette.secondary.main} 0%, ${theme.palette.info.main} 100%)`
              : undefined,
          }}
        >
          <Badge badgeContent={completedSteps.size > 0 ? `${completedSteps.size}/${steps.length}` : undefined} color="primary">
            <WalkthroughIcon />
          </Badge>
        </Fab>
      </Tooltip>
    );
  }

  return (
    <>
      <Drawer
        anchor="left"
        open={isOpen}
        onClose={() => setIsOpen(false)}
        PaperProps={{
          sx: {
            width: { xs: "100%", sm: 480 },
            maxWidth: "100vw",
            display: "flex",
            flexDirection: "column",
          },
        }}
      >
        {/* Header */}
        <Box
          sx={{
            p: 2,
            background: `linear-gradient(135deg, ${theme.palette.secondary.main} 0%, ${theme.palette.info.main} 100%)`,
            color: "white",
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <WalkthroughIcon />
              <Typography variant="h6" fontWeight={600}>
                Guided Analysis Walkthrough
              </Typography>
            </Box>
            <Box sx={{ display: "flex", gap: 0.5 }}>
              <Tooltip title="Glossary">
                <IconButton size="small" sx={{ color: "white" }} onClick={() => setShowGlossary(true)}>
                  <GlossaryIcon />
                </IconButton>
              </Tooltip>
              <Tooltip title="Restart">
                <IconButton size="small" sx={{ color: "white" }} onClick={handleRestart}>
                  <RestartIcon />
                </IconButton>
              </Tooltip>
              <IconButton size="small" sx={{ color: "white" }} onClick={() => setIsOpen(false)}>
                <CloseIcon />
              </IconButton>
            </Box>
          </Box>

          {/* Progress bar */}
          {steps.length > 0 && (
            <Box sx={{ mt: 2 }}>
              <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
                <Typography variant="caption">Progress</Typography>
                <Typography variant="caption" fontWeight={600}>
                  {completedSteps.size} / {steps.length} steps
                </Typography>
              </Box>
              <LinearProgress
                variant="determinate"
                value={overallProgress}
                sx={{
                  height: 8,
                  borderRadius: 4,
                  bgcolor: alpha("#fff", 0.3),
                  "& .MuiLinearProgress-bar": {
                    bgcolor: "white",
                    borderRadius: 4,
                  },
                }}
              />
            </Box>
          )}
        </Box>

        {/* Content */}
        <Box sx={{ flex: 1, overflow: "auto", p: 2 }}>
          {isLoading && (
            <Box sx={{ textAlign: "center", py: 8 }}>
              <CircularProgress color="secondary" />
              <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                Generating personalized walkthrough...
              </Typography>
            </Box>
          )}

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
              <Button size="small" onClick={loadWalkthrough} sx={{ mt: 1 }}>
                Retry
              </Button>
            </Alert>
          )}

          {!isLoading && !error && steps.length === 0 && (
            <Box sx={{ textAlign: "center", py: 8 }}>
              <WalkthroughIcon sx={{ fontSize: 64, opacity: 0.3, mb: 2 }} />
              <Typography variant="h6" color="text.secondary">
                Ready to Start?
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1, mb: 3 }}>
                This guided walkthrough will help you understand the APK analysis results step by step.
              </Typography>
              <Button
                variant="contained"
                color="secondary"
                startIcon={<StartIcon />}
                onClick={loadWalkthrough}
              >
                Start Walkthrough
              </Button>
            </Box>
          )}

          {steps.length > 0 && (
            <Stepper activeStep={activeStep} orientation="vertical">
              {steps.map((step, index) => (
                <Step key={index} completed={completedSteps.has(index)}>
                  <StepLabel
                    onClick={() => handleStepClick(index)}
                    sx={{ cursor: "pointer" }}
                    StepIconComponent={() => (
                      <Box
                        sx={{
                          width: 32,
                          height: 32,
                          borderRadius: "50%",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          bgcolor: completedSteps.has(index)
                            ? theme.palette.success.main
                            : index === activeStep
                            ? theme.palette.secondary.main
                            : alpha(theme.palette.secondary.main, 0.3),
                          color: "white",
                          fontWeight: 600,
                          fontSize: 14,
                        }}
                      >
                        {completedSteps.has(index) ? <CompleteIcon fontSize="small" /> : index + 1}
                      </Box>
                    )}
                  >
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <Typography variant="subtitle2" fontWeight={index === activeStep ? 700 : 500}>
                        {step.title}
                      </Typography>
                      {step.severity && (
                        <Chip
                          size="small"
                          label={`${step.findings_count} findings`}
                          sx={{
                            bgcolor: alpha(getSeverityColor(step.severity), 0.2),
                            color: getSeverityColor(step.severity),
                            fontWeight: 600,
                            fontSize: 10,
                          }}
                        />
                      )}
                    </Box>
                    <Typography variant="caption" color="text.secondary">
                      {step.phase}
                    </Typography>
                  </StepLabel>
                  <StepContent>
                    <Paper
                      elevation={0}
                      sx={{
                        p: 2,
                        bgcolor: alpha(theme.palette.secondary.main, 0.05),
                        border: `1px solid ${alpha(theme.palette.secondary.main, 0.2)}`,
                        borderRadius: 2,
                      }}
                    >
                      {/* Description */}
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                        {step.description}
                      </Typography>

                      {/* Beginner Explanation - Always Visible */}
                      <Accordion
                        expanded={expandedExplanations.has(index)}
                        onChange={() => toggleExplanation(index)}
                        sx={{
                          bgcolor: alpha(theme.palette.info.main, 0.1),
                          border: `1px solid ${alpha(theme.palette.info.main, 0.3)}`,
                          "&:before": { display: "none" },
                          borderRadius: 1,
                          mb: 2,
                        }}
                      >
                        <AccordionSummary expandIcon={<ExpandIcon />}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                            <TipIcon color="info" fontSize="small" />
                            <Typography variant="subtitle2" color="info.main">
                              Beginner Explanation
                            </Typography>
                          </Box>
                        </AccordionSummary>
                        <AccordionDetails>
                          <Typography variant="body2">
                            {step.beginner_explanation}
                          </Typography>
                        </AccordionDetails>
                      </Accordion>

                      {/* Why It Matters */}
                      <Box
                        sx={{
                          p: 1.5,
                          bgcolor: alpha(theme.palette.warning.main, 0.1),
                          border: `1px solid ${alpha(theme.palette.warning.main, 0.3)}`,
                          borderRadius: 1,
                          mb: 2,
                        }}
                      >
                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, mb: 0.5 }}>
                          <SecurityIcon fontSize="small" color="warning" />
                          <Typography variant="caption" fontWeight={600} color="warning.main">
                            Why This Matters
                          </Typography>
                        </Box>
                        <Typography variant="body2" color="text.secondary">
                          {step.why_it_matters}
                        </Typography>
                      </Box>

                      {/* Technical Detail - Collapsible */}
                      <Accordion
                        sx={{
                          bgcolor: alpha(theme.palette.grey[500], 0.1),
                          "&:before": { display: "none" },
                          borderRadius: 1,
                        }}
                      >
                        <AccordionSummary expandIcon={<ExpandIcon />}>
                          <Typography variant="subtitle2" color="text.secondary">
                            🔧 Technical Details
                          </Typography>
                        </AccordionSummary>
                        <AccordionDetails>
                          <Typography
                            variant="body2"
                            sx={{
                              fontFamily: "monospace",
                              fontSize: 12,
                              whiteSpace: "pre-wrap",
                              wordBreak: "break-word",
                            }}
                          >
                            {step.technical_detail}
                          </Typography>
                        </AccordionDetails>
                      </Accordion>

                      {/* Navigation buttons */}
                      <Box sx={{ display: "flex", gap: 1, mt: 2 }}>
                        <Button
                          size="small"
                          onClick={handleBack}
                          disabled={index === 0}
                          startIcon={<PrevIcon />}
                        >
                          Back
                        </Button>
                        <Button
                          variant="contained"
                          size="small"
                          color="secondary"
                          onClick={handleNext}
                          endIcon={index === steps.length - 1 ? <CompleteIcon /> : <NextIcon />}
                        >
                          {index === steps.length - 1 ? "Complete" : "Next"}
                        </Button>
                      </Box>
                    </Paper>
                  </StepContent>
                </Step>
              ))}
            </Stepper>
          )}
        </Box>

        {/* Footer with quick actions */}
        {steps.length > 0 && (
          <Box
            sx={{
              p: 2,
              borderTop: `1px solid ${theme.palette.divider}`,
              bgcolor: theme.palette.background.paper,
            }}
          >
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
              <Chip
                icon={<MilestoneIcon />}
                label={`Step ${activeStep + 1} of ${steps.length}`}
                size="small"
                color="secondary"
              />
              <Chip
                icon={<CompleteIcon />}
                label={`${overallProgress}% Complete`}
                size="small"
                color={overallProgress === 100 ? "success" : "default"}
                variant="outlined"
              />
            </Box>
          </Box>
        )}
      </Drawer>

      {/* Glossary Dialog */}
      <Dialog
        open={showGlossary}
        onClose={() => setShowGlossary(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <GlossaryIcon color="secondary" />
            Security Terms Glossary
          </Box>
        </DialogTitle>
        <DialogContent dividers>
          {Object.keys(glossary).length === 0 ? (
            <Typography color="text.secondary" sx={{ textAlign: "center", py: 4 }}>
              Start the walkthrough to load the glossary
            </Typography>
          ) : (
            <List dense>
              {Object.entries(glossary).map(([term, definition], idx) => (
                <ListItem key={idx} sx={{ alignItems: "flex-start" }}>
                  <ListItemIcon sx={{ minWidth: 36 }}>
                    <HelpIcon fontSize="small" color="secondary" />
                  </ListItemIcon>
                  <ListItemText
                    primary={<Typography variant="subtitle2" fontWeight={600}>{term}</Typography>}
                    secondary={definition}
                  />
                </ListItem>
              ))}
            </List>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowGlossary(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Completion Dialog */}
      <Dialog
        open={showCompletionDialog}
        onClose={() => setShowCompletionDialog(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <CompleteIcon color="success" />
            Walkthrough Complete! 🎉
          </Box>
        </DialogTitle>
        <DialogContent>
          <Alert severity="success" sx={{ mb: 2 }}>
            Congratulations! You've completed the guided analysis walkthrough.
          </Alert>

          {nextStepsSuggestions.length > 0 && (
            <>
              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                Suggested Next Steps:
              </Typography>
              <List dense>
                {nextStepsSuggestions.map((suggestion, idx) => (
                  <ListItem key={idx}>
                    <ListItemIcon sx={{ minWidth: 36 }}>
                      <AiIcon fontSize="small" color="primary" />
                    </ListItemIcon>
                    <ListItemText primary={suggestion} />
                  </ListItem>
                ))}
              </List>
            </>
          )}

          {learningResources.length > 0 && (
            <>
              <Divider sx={{ my: 2 }} />
              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                Learning Resources:
              </Typography>
              <List dense>
                {learningResources.map((resource, idx) => (
                  <ListItem
                    key={idx}
                    component="a"
                    href={resource.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    sx={{
                      textDecoration: "none",
                      color: "inherit",
                      "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.1) },
                      borderRadius: 1,
                    }}
                  >
                    <ListItemIcon sx={{ minWidth: 36 }}>
                      <LinkIcon fontSize="small" color="primary" />
                    </ListItemIcon>
                    <ListItemText
                      primary={resource.title}
                      secondary={resource.description}
                    />
                  </ListItem>
                ))}
              </List>
            </>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleRestart} startIcon={<RestartIcon />}>
            Start Over
          </Button>
          <Button
            variant="contained"
            onClick={() => {
              setShowCompletionDialog(false);
              setIsOpen(false);
            }}
          >
            Done
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
