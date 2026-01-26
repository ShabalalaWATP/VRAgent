import React, { Component, ErrorInfo, ReactNode } from 'react';
import { Box, Typography, Button, Paper, Alert, AlertTitle } from '@mui/material';
import { ErrorOutline as ErrorIcon, Refresh as RefreshIcon } from '@mui/icons-material';

interface Props {
  children: ReactNode;
  fallbackComponent?: ReactNode;
  componentName?: string;
  onReset?: () => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

/**
 * Error boundary for Social Hub components.
 * Catches JavaScript errors in child components and displays a fallback UI.
 */
export class SocialErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
    };
  }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    this.setState({ errorInfo });
    
    // Log error for debugging
    console.error(
      `[SocialErrorBoundary] Error in ${this.props.componentName || 'component'}:`,
      error,
      errorInfo
    );
    
    // Could send to error reporting service here
    // e.g., Sentry.captureException(error, { extra: errorInfo });
  }

  handleReset = (): void => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    this.props.onReset?.();
  };

  render(): ReactNode {
    if (this.state.hasError) {
      // Custom fallback if provided
      if (this.props.fallbackComponent) {
        return this.props.fallbackComponent;
      }

      // Default fallback UI
      return (
        <Paper
          elevation={0}
          sx={{
            p: 3,
            m: 2,
            border: '1px solid',
            borderColor: 'error.light',
            borderRadius: 2,
            bgcolor: 'error.lighter',
          }}
        >
          <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
            <ErrorIcon sx={{ fontSize: 48, color: 'error.main' }} />
            
            <Typography variant="h6" color="error.main">
              Something went wrong
            </Typography>
            
            <Alert severity="error" sx={{ width: '100%', maxWidth: 400 }}>
              <AlertTitle>
                {this.props.componentName ? `Error in ${this.props.componentName}` : 'Component Error'}
              </AlertTitle>
              {this.state.error?.message || 'An unexpected error occurred'}
            </Alert>

            <Button
              variant="contained"
              startIcon={<RefreshIcon />}
              onClick={this.handleReset}
              color="primary"
            >
              Try Again
            </Button>

            {process.env.NODE_ENV === 'development' && this.state.errorInfo && (
              <Box
                component="details"
                sx={{
                  mt: 2,
                  p: 2,
                  bgcolor: 'grey.100',
                  borderRadius: 1,
                  width: '100%',
                  maxWidth: 600,
                  overflow: 'auto',
                }}
              >
                <Typography component="summary" variant="caption" sx={{ cursor: 'pointer' }}>
                  Error Details (Development Only)
                </Typography>
                <Box
                  component="pre"
                  sx={{
                    mt: 1,
                    fontSize: '0.75rem',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                  }}
                >
                  {this.state.error?.stack}
                  {'\n\nComponent Stack:'}
                  {this.state.errorInfo.componentStack}
                </Box>
              </Box>
            )}
          </Box>
        </Paper>
      );
    }

    return this.props.children;
  }
}

/**
 * Higher-order component to wrap any component with error boundary
 */
export function withSocialErrorBoundary<P extends object>(
  WrappedComponent: React.ComponentType<P>,
  componentName?: string
): React.FC<P> {
  const WithErrorBoundary: React.FC<P> = (props) => (
    <SocialErrorBoundary componentName={componentName || WrappedComponent.displayName || WrappedComponent.name}>
      <WrappedComponent {...props} />
    </SocialErrorBoundary>
  );

  WithErrorBoundary.displayName = `WithSocialErrorBoundary(${componentName || WrappedComponent.displayName || WrappedComponent.name || 'Component'})`;
  
  return WithErrorBoundary;
}

export default SocialErrorBoundary;
