import React, { useState, useCallback } from 'react';
import {
  Box,
  Drawer,
  Tabs,
  Tab,
  Typography,
  IconButton,
  Tooltip,
  Badge,
  Chip,
  Divider,
} from '@mui/material';
import {
  Close as CloseIcon,
  AutoAwesome as AIIcon,
  EditNote as NLIcon,
  Science as TestIcon,
  VpnKey as VariableIcon,
  Security as AnalyzeIcon,
  Description as DocsIcon,
} from '@mui/icons-material';
import NLToRequestInput from './NLToRequestInput';
import AITestGenerator from './AITestGenerator';
import SmartVariableSuggester from './SmartVariableSuggester';
import ResponseAnomalyAnalyzer from './ResponseAnomalyAnalyzer';
import { AIGeneratedTest } from '../api/client';

interface AIAssistantPanelProps {
  open: boolean;
  onClose: () => void;
  // Request context
  currentRequest?: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
  };
  // Response context
  currentResponse?: {
    status_code: number;
    status_text?: string;
    headers?: Record<string, string>;
    body?: string;
    response_time_ms?: number;
    response_size_bytes?: number;
  };
  // Environment context
  baseUrl?: string;
  availableEndpoints?: string[];
  authType?: string;
  variables?: Record<string, string>;
  // Callbacks
  onRequestGenerated?: (request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
    bodyType: string;
  }) => void;
  onTestsGenerated?: (tests: AIGeneratedTest[]) => void;
  onVariableAdd?: (variable: {
    name: string;
    value: any;
    scope: string;
    jsonPath: string;
  }) => void;
  // Width
  width?: number;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index }) => (
  <Box
    role="tabpanel"
    hidden={value !== index}
    sx={{ 
      flex: 1, 
      overflow: 'auto', 
      p: 2,
      display: value === index ? 'block' : 'none',
    }}
  >
    {children}
  </Box>
);

export const AIAssistantPanel: React.FC<AIAssistantPanelProps> = ({
  open,
  onClose,
  currentRequest,
  currentResponse,
  baseUrl,
  availableEndpoints,
  authType,
  variables,
  onRequestGenerated,
  onTestsGenerated,
  onVariableAdd,
  width = 480,
}) => {
  const [activeTab, setActiveTab] = useState(0);

  const handleTabChange = useCallback((_: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  }, []);

  const hasResponse = currentResponse && currentResponse.status_code !== undefined;

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      PaperProps={{
        sx: {
          width,
          maxWidth: '100vw',
        },
      }}
    >
      {/* Header */}
      <Box 
        sx={{ 
          p: 2, 
          display: 'flex', 
          alignItems: 'center', 
          gap: 1,
          borderBottom: '1px solid',
          borderColor: 'divider',
          background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(168, 85, 247, 0.1) 100%)',
        }}
      >
        <AIIcon sx={{ color: 'primary.main' }} />
        <Typography variant="h6" fontWeight={600}>
          AI Assistant
        </Typography>
        <Chip 
          label="Powered by AI" 
          size="small" 
          color="primary" 
          variant="outlined"
          sx={{ ml: 'auto' }}
        />
        <IconButton onClick={onClose} size="small">
          <CloseIcon />
        </IconButton>
      </Box>

      {/* Tabs */}
      <Tabs 
        value={activeTab} 
        onChange={handleTabChange}
        variant="scrollable"
        scrollButtons="auto"
        sx={{ 
          borderBottom: 1, 
          borderColor: 'divider',
          '& .MuiTab-root': {
            minHeight: 48,
            textTransform: 'none',
          },
        }}
      >
        <Tab 
          icon={<NLIcon />} 
          iconPosition="start" 
          label="Generate" 
          sx={{ minWidth: 'auto' }}
        />
        <Tab 
          icon={
            <Badge badgeContent={hasResponse ? '!' : 0} color="success" variant="dot">
              <TestIcon />
            </Badge>
          } 
          iconPosition="start" 
          label="Tests"
          sx={{ minWidth: 'auto' }}
        />
        <Tab 
          icon={
            <Badge badgeContent={hasResponse ? '!' : 0} color="warning" variant="dot">
              <VariableIcon />
            </Badge>
          } 
          iconPosition="start" 
          label="Variables"
          sx={{ minWidth: 'auto' }}
        />
        <Tab 
          icon={<AnalyzeIcon />} 
          iconPosition="start" 
          label="Analyze"
          sx={{ minWidth: 'auto' }}
        />
      </Tabs>

      {/* Tab Panels */}
      <TabPanel value={activeTab} index={0}>
        <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 2 }}>
          Describe what API request you want to make in plain English
        </Typography>
        <NLToRequestInput
          onRequestGenerated={(request) => {
            if (onRequestGenerated) {
              onRequestGenerated(request);
            }
          }}
          baseUrl={baseUrl}
          availableEndpoints={availableEndpoints}
          authType={authType}
          variables={variables}
        />
      </TabPanel>

      <TabPanel value={activeTab} index={1}>
        {currentRequest && currentResponse ? (
          <AITestGenerator
            request={currentRequest}
            response={currentResponse}
            onTestsGenerated={onTestsGenerated}
          />
        ) : (
          <Box sx={{ textAlign: 'center', py: 4, color: 'text.secondary' }}>
            <TestIcon sx={{ fontSize: 48, opacity: 0.3, mb: 1 }} />
            <Typography variant="body2">
              Execute a request first to generate tests
            </Typography>
            <Typography variant="caption" display="block" sx={{ mt: 1 }}>
              The AI will analyze your response and suggest assertions
            </Typography>
          </Box>
        )}
      </TabPanel>

      <TabPanel value={activeTab} index={2}>
        {currentResponse?.body ? (
          <SmartVariableSuggester
            responseBody={currentResponse.body}
            requestContext={currentRequest}
            onVariableAdd={onVariableAdd}
          />
        ) : (
          <Box sx={{ textAlign: 'center', py: 4, color: 'text.secondary' }}>
            <VariableIcon sx={{ fontSize: 48, opacity: 0.3, mb: 1 }} />
            <Typography variant="body2">
              Execute a request first to detect variables
            </Typography>
            <Typography variant="caption" display="block" sx={{ mt: 1 }}>
              AI will identify useful values to save as variables
            </Typography>
          </Box>
        )}
      </TabPanel>

      <TabPanel value={activeTab} index={3}>
        {currentRequest && currentResponse ? (
          <ResponseAnomalyAnalyzer
            request={currentRequest}
            response={currentResponse}
          />
        ) : (
          <Box sx={{ textAlign: 'center', py: 4, color: 'text.secondary' }}>
            <AnalyzeIcon sx={{ fontSize: 48, opacity: 0.3, mb: 1 }} />
            <Typography variant="body2">
              Execute a request first to analyze the response
            </Typography>
            <Typography variant="caption" display="block" sx={{ mt: 1 }}>
              AI will detect security issues, performance concerns, and data anomalies
            </Typography>
          </Box>
        )}
      </TabPanel>

      {/* Footer */}
      <Box 
        sx={{ 
          p: 1.5, 
          borderTop: '1px solid',
          borderColor: 'divider',
          bgcolor: 'background.default',
        }}
      >
        <Typography variant="caption" color="text.secondary" sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <AIIcon fontSize="inherit" />
          AI-powered features analyze your requests and responses
        </Typography>
      </Box>
    </Drawer>
  );
};

export default AIAssistantPanel;
