import React from "react";
import LearnAIChatWidget from "./LearnAIChatWidget";

interface LearnPageLayoutProps {
  children: React.ReactNode;
  pageTitle: string;
  pageContext: string;
}

/**
 * Wrapper component for learning pages that adds the AI chat widget.
 * 
 * Usage:
 * ```tsx
 * <LearnPageLayout
 *   pageTitle="Buffer Overflow Attacks"
 *   pageContext="This page covers stack-based buffer overflows, heap overflows..."
 * >
 *   {/* Your page content *\/}
 * </LearnPageLayout>
 * ```
 */
const LearnPageLayout: React.FC<LearnPageLayoutProps> = ({
  children,
  pageTitle,
  pageContext,
}) => {
  return (
    <>
      {children}
      <LearnAIChatWidget pageTitle={pageTitle} pageContext={pageContext} />
    </>
  );
};

export default LearnPageLayout;
