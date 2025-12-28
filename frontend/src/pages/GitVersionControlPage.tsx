import React, { useState, useEffect } from "react";
import {
  Box,
  Typography,
  Paper,
  Grid,
  Chip,
  Button,
  Alert,
  AlertTitle,
  Radio,
  RadioGroup,
  FormControlLabel,
  Divider,
  alpha,
  useTheme,
  useMediaQuery,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  IconButton,
  Drawer,
  Fab,
  Tooltip,
  LinearProgress,
} from "@mui/material";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import BuildIcon from "@mui/icons-material/Build";
import TerminalIcon from "@mui/icons-material/Terminal";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import HistoryIcon from "@mui/icons-material/History";
import MergeIcon from "@mui/icons-material/Merge";
import CloudIcon from "@mui/icons-material/Cloud";
import GroupIcon from "@mui/icons-material/Group";
import CompareArrowsIcon from "@mui/icons-material/CompareArrows";
import SaveIcon from "@mui/icons-material/Save";
import RestoreIcon from "@mui/icons-material/Restore";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import WarningIcon from "@mui/icons-material/Warning";
import InfoIcon from "@mui/icons-material/Info";
import SpeedIcon from "@mui/icons-material/Speed";
import CloseIcon from "@mui/icons-material/Close";
import ListAltIcon from "@mui/icons-material/ListAlt";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import { useNavigate } from "react-router-dom";
import LearnPageLayout from "../components/LearnPageLayout";

// ==================== QUIZ SECTION ====================
interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  topic: string;
}

// Full 75-question bank covering Git & Version Control
const questionBank: QuizQuestion[] = [
  // ==================== Topic 1: Version Control Fundamentals (Questions 1-10) ====================
  { id: 1, question: "What is version control?", options: ["A backup system", "A system that tracks changes to files over time", "A code compiler", "A file compression tool"], correctAnswer: 1, explanation: "Version control is a system that records changes to files over time so you can recall specific versions later.", topic: "Version Control Fundamentals" },
  { id: 2, question: "What type of version control system is Git?", options: ["Centralized", "Distributed", "Linear", "Hierarchical"], correctAnswer: 1, explanation: "Git is a distributed version control system where every developer has a complete copy of the repository history.", topic: "Version Control Fundamentals" },
  { id: 3, question: "What is a repository in Git?", options: ["A folder with Git tracking", "A remote server", "A backup drive", "A compiled program"], correctAnswer: 0, explanation: "A repository (repo) is a directory that Git tracks, containing all files and the complete history of changes.", topic: "Version Control Fundamentals" },
  { id: 4, question: "What does the .git folder contain?", options: ["Source code only", "All Git metadata and history", "Compiled binaries", "User credentials"], correctAnswer: 1, explanation: "The .git folder stores all the metadata, object database, and history that Git needs to track your project.", topic: "Version Control Fundamentals" },
  { id: 5, question: "What is the main advantage of distributed version control?", options: ["Faster compilation", "Work offline with full history", "Smaller file sizes", "Better graphics"], correctAnswer: 1, explanation: "In distributed VCS like Git, you have the complete repository locally, allowing you to work offline and commit changes.", topic: "Version Control Fundamentals" },
  { id: 6, question: "Which command initializes a new Git repository?", options: ["git start", "git create", "git init", "git new"], correctAnswer: 2, explanation: "git init creates a new .git directory and initializes an empty Git repository.", topic: "Version Control Fundamentals" },
  { id: 7, question: "What is a working directory in Git?", options: ["The .git folder", "The folder where you edit files", "The remote server", "The staging area"], correctAnswer: 1, explanation: "The working directory is where you actually work on your files before staging and committing them.", topic: "Version Control Fundamentals" },
  { id: 8, question: "What was the primary reason Git was created?", options: ["To replace SVN", "For Linux kernel development", "For web development", "For game development"], correctAnswer: 1, explanation: "Git was created by Linus Torvalds in 2005 for Linux kernel development after BitKeeper became proprietary.", topic: "Version Control Fundamentals" },
  { id: 9, question: "Which is NOT a version control system?", options: ["Git", "SVN", "Mercurial", "Docker"], correctAnswer: 3, explanation: "Docker is a containerization platform, not a version control system. Git, SVN, and Mercurial are all VCS.", topic: "Version Control Fundamentals" },
  { id: 10, question: "What does VCS stand for?", options: ["Virtual Code System", "Version Control System", "Visual Control Software", "Variable Code Storage"], correctAnswer: 1, explanation: "VCS stands for Version Control System, software that tracks and manages changes to code over time.", topic: "Version Control Fundamentals" },

  // ==================== Topic 2: Git Basics & Configuration (Questions 11-20) ====================
  { id: 11, question: "Which command sets your Git username?", options: ["git config --global user.name", "git set username", "git user.name =", "git --username"], correctAnswer: 0, explanation: "git config --global user.name 'Your Name' sets your identity for all repositories on your system.", topic: "Git Basics & Configuration" },
  { id: 12, question: "What does the --global flag do in git config?", options: ["Makes settings public", "Applies to all repos on your machine", "Only affects remote repos", "Creates a global branch"], correctAnswer: 1, explanation: "The --global flag applies the configuration to all repositories for the current user.", topic: "Git Basics & Configuration" },
  { id: 13, question: "Where are global Git configurations stored?", options: [".git/config", "~/.gitconfig", "/etc/git", "C:\\Git\\config"], correctAnswer: 1, explanation: "Global Git configurations are stored in ~/.gitconfig (or %USERPROFILE%\\.gitconfig on Windows).", topic: "Git Basics & Configuration" },
  { id: 14, question: "Which command shows your Git configuration?", options: ["git config --list", "git show config", "git settings", "git --config"], correctAnswer: 0, explanation: "git config --list displays all Git configuration settings from all levels.", topic: "Git Basics & Configuration" },
  { id: 15, question: "What is the purpose of .gitignore?", options: ["To ignore Git commands", "To specify files Git should not track", "To delete files", "To hide the .git folder"], correctAnswer: 1, explanation: ".gitignore specifies intentionally untracked files that Git should ignore, like build artifacts or dependencies.", topic: "Git Basics & Configuration" },
  { id: 16, question: "Which pattern in .gitignore ignores all .log files?", options: [".log", "*.log", "log.*", "all.log"], correctAnswer: 1, explanation: "*.log uses a wildcard to match any file ending with .log.", topic: "Git Basics & Configuration" },
  { id: 17, question: "What does git status show?", options: ["Commit history", "Current state of working directory and staging area", "Remote branches", "Git version"], correctAnswer: 1, explanation: "git status shows which files are staged, modified, or untracked in your working directory.", topic: "Git Basics & Configuration" },
  { id: 18, question: "Which command shows the commit history?", options: ["git history", "git log", "git commits", "git show-all"], correctAnswer: 1, explanation: "git log displays the commit history with commit hashes, authors, dates, and messages.", topic: "Git Basics & Configuration" },
  { id: 19, question: "What does git help <command> do?", options: ["Fixes errors", "Shows documentation for the command", "Undoes the command", "Reports bugs"], correctAnswer: 1, explanation: "git help opens the manual page for the specified Git command.", topic: "Git Basics & Configuration" },
  { id: 20, question: "Which scope has the highest priority in Git config?", options: ["System", "Global", "Local (repository)", "All have equal priority"], correctAnswer: 2, explanation: "Local (repository-level) config overrides global, which overrides system-level settings.", topic: "Git Basics & Configuration" },

  // ==================== Topic 3: Staging and Committing (Questions 21-35) ====================
  { id: 21, question: "What is the staging area in Git?", options: ["A temporary branch", "An intermediate area before committing", "The remote server", "The .git folder"], correctAnswer: 1, explanation: "The staging area (index) holds changes you want to include in your next commit.", topic: "Staging and Committing" },
  { id: 22, question: "Which command stages a file?", options: ["git commit", "git add", "git stage", "git save"], correctAnswer: 1, explanation: "git add moves changes from the working directory to the staging area.", topic: "Staging and Committing" },
  { id: 23, question: "What does git add . do?", options: ["Adds one file", "Stages all changes in current directory", "Creates a new branch", "Adds a remote"], correctAnswer: 1, explanation: "git add . stages all new and modified files in the current directory and subdirectories.", topic: "Staging and Committing" },
  { id: 24, question: "What does git add -A do?", options: ["Adds only new files", "Stages all changes including deletions", "Adds annotated tags", "Adds all branches"], correctAnswer: 1, explanation: "git add -A stages all changes: new files, modifications, and deletions across the entire repository.", topic: "Staging and Committing" },
  { id: 25, question: "Which command creates a commit?", options: ["git save", "git commit", "git snapshot", "git checkpoint"], correctAnswer: 1, explanation: "git commit records the staged changes as a new snapshot in the repository history.", topic: "Staging and Committing" },
  { id: 26, question: "What does the -m flag do in git commit?", options: ["Merges branches", "Specifies commit message inline", "Creates multiple commits", "Marks as milestone"], correctAnswer: 1, explanation: "git commit -m 'message' allows you to write the commit message directly in the command line.", topic: "Staging and Committing" },
  { id: 27, question: "What is a commit hash?", options: ["A password", "A unique identifier for a commit", "A branch name", "A file checksum"], correctAnswer: 1, explanation: "A commit hash (SHA-1) is a 40-character unique identifier that references a specific commit.", topic: "Staging and Committing" },
  { id: 28, question: "What does git commit --amend do?", options: ["Creates a new branch", "Modifies the most recent commit", "Deletes the last commit", "Amends all commits"], correctAnswer: 1, explanation: "git commit --amend lets you modify the most recent commit, such as changing the message or adding files.", topic: "Staging and Committing" },
  { id: 29, question: "Which command unstages a file?", options: ["git remove", "git reset HEAD <file>", "git unstage", "git delete"], correctAnswer: 1, explanation: "git reset HEAD <file> removes a file from the staging area without discarding changes.", topic: "Staging and Committing" },
  { id: 30, question: "What does git diff show?", options: ["Branch differences", "Unstaged changes in working directory", "Commit history", "Remote status"], correctAnswer: 1, explanation: "git diff shows line-by-line differences between your working directory and the staging area.", topic: "Staging and Committing" },
  { id: 31, question: "What does git diff --staged show?", options: ["Unstaged changes", "Differences between staging area and last commit", "Remote differences", "Branch differences"], correctAnswer: 1, explanation: "git diff --staged (or --cached) shows changes that are staged but not yet committed.", topic: "Staging and Committing" },
  { id: 32, question: "What makes a good commit message?", options: ["Long and technical", "Short, clear, and describes the change", "Contains the entire diff", "Just the date"], correctAnswer: 1, explanation: "Good commit messages are concise, descriptive, and explain what and why (not how) the change was made.", topic: "Staging and Committing" },
  { id: 33, question: "What does git rm do?", options: ["Removes Git entirely", "Removes and stages file deletion", "Removes from staging only", "Removes remote"], correctAnswer: 1, explanation: "git rm removes a file from the working directory and stages the deletion for the next commit.", topic: "Staging and Committing" },
  { id: 34, question: "What does git mv do?", options: ["Moves to remote", "Renames/moves a file and stages the change", "Creates multiple versions", "Moves commits"], correctAnswer: 1, explanation: "git mv renames or moves a file and automatically stages the change.", topic: "Staging and Committing" },
  { id: 35, question: "What does HEAD refer to?", options: ["The first commit", "The current commit/branch you're on", "The remote repository", "The staging area"], correctAnswer: 1, explanation: "HEAD is a pointer to the current commit or branch tip you have checked out.", topic: "Staging and Committing" },

  // ==================== Topic 4: Branching (Questions 36-50) ====================
  { id: 36, question: "What is a branch in Git?", options: ["A copy of the repository", "A lightweight movable pointer to commits", "A remote server", "A backup folder"], correctAnswer: 1, explanation: "A branch is a lightweight pointer to a specific commit, allowing parallel development.", topic: "Branching" },
  { id: 37, question: "Which command creates a new branch?", options: ["git new-branch", "git branch <name>", "git create branch", "git make branch"], correctAnswer: 1, explanation: "git branch <name> creates a new branch pointing to the current commit.", topic: "Branching" },
  { id: 38, question: "Which command switches to a branch?", options: ["git switch", "git checkout", "git move", "Both A and B"], correctAnswer: 3, explanation: "Both git switch (modern) and git checkout (traditional) can switch between branches.", topic: "Branching" },
  { id: 39, question: "What does git checkout -b <name> do?", options: ["Deletes a branch", "Creates and switches to a new branch", "Renames a branch", "Backs up a branch"], correctAnswer: 1, explanation: "git checkout -b <name> is a shortcut that creates a new branch and immediately switches to it.", topic: "Branching" },
  { id: 40, question: "Which command lists all branches?", options: ["git branches", "git branch", "git list", "git show branches"], correctAnswer: 1, explanation: "git branch without arguments lists all local branches, with * marking the current branch.", topic: "Branching" },
  { id: 41, question: "What does git branch -d <name> do?", options: ["Downloads a branch", "Deletes a merged branch", "Describes a branch", "Duplicates a branch"], correctAnswer: 1, explanation: "git branch -d safely deletes a branch that has been fully merged.", topic: "Branching" },
  { id: 42, question: "What does git branch -D <name> do?", options: ["Downloads a branch", "Force deletes a branch", "Creates a default branch", "Describes a branch"], correctAnswer: 1, explanation: "git branch -D force deletes a branch regardless of its merge status (use with caution).", topic: "Branching" },
  { id: 43, question: "What is the default branch often called?", options: ["master or main", "default", "primary", "trunk"], correctAnswer: 0, explanation: "Historically 'master', but 'main' is now the common default. Both serve as the primary branch.", topic: "Branching" },
  { id: 44, question: "What is a feature branch?", options: ["The main branch", "A branch for developing a specific feature", "A branch for bugs only", "A remote-only branch"], correctAnswer: 1, explanation: "Feature branches isolate development of a specific feature, keeping main branch stable.", topic: "Branching" },
  { id: 45, question: "What does git branch -r show?", options: ["Recent branches", "Remote-tracking branches", "Renamed branches", "Rebased branches"], correctAnswer: 1, explanation: "git branch -r lists remote-tracking branches like origin/main.", topic: "Branching" },
  { id: 46, question: "What does git branch -a show?", options: ["Active branches only", "All local and remote branches", "Archived branches", "Anonymous branches"], correctAnswer: 1, explanation: "git branch -a shows all branches, both local and remote-tracking.", topic: "Branching" },
  { id: 47, question: "How do you rename the current branch?", options: ["git branch -m <new-name>", "git rename branch", "git branch --rename", "git mv branch"], correctAnswer: 0, explanation: "git branch -m <new-name> renames the currently checked out branch.", topic: "Branching" },
  { id: 48, question: "What is a long-running branch?", options: ["A slow branch", "A branch that exists throughout the project lifecycle", "A branch with many commits", "A branch over 1 year old"], correctAnswer: 1, explanation: "Long-running branches like main or develop persist throughout the project and receive merges from other branches.", topic: "Branching" },
  { id: 49, question: "What is HEAD detached state?", options: ["An error state", "When HEAD points to a commit instead of a branch", "When HEAD is deleted", "A merge conflict"], correctAnswer: 1, explanation: "Detached HEAD means you've checked out a specific commit rather than a branch tip.", topic: "Branching" },
  { id: 50, question: "Which branching strategy uses develop and release branches?", options: ["GitHub Flow", "GitFlow", "Trunk-based", "Feature flags"], correctAnswer: 1, explanation: "GitFlow uses multiple long-running branches: main, develop, feature, release, and hotfix branches.", topic: "Branching" },

  // ==================== Topic 5: Merging and Rebasing (Questions 51-60) ====================
  { id: 51, question: "What does git merge do?", options: ["Deletes a branch", "Combines changes from one branch into another", "Creates a branch", "Splits commits"], correctAnswer: 1, explanation: "git merge integrates changes from one branch into the current branch.", topic: "Merging and Rebasing" },
  { id: 52, question: "What is a fast-forward merge?", options: ["A quick merge", "When Git just moves the branch pointer forward", "A merge with no commits", "An automatic merge"], correctAnswer: 1, explanation: "Fast-forward happens when the target branch has no new commits, so Git just moves the pointer.", topic: "Merging and Rebasing" },
  { id: 53, question: "What is a merge commit?", options: ["The first commit", "A commit that combines two branches", "A deleted commit", "A cherry-picked commit"], correctAnswer: 1, explanation: "A merge commit has two parent commits and represents the point where branches were combined.", topic: "Merging and Rebasing" },
  { id: 54, question: "What is a merge conflict?", options: ["A Git error", "When Git can't automatically merge changes", "A deleted branch", "A network error"], correctAnswer: 1, explanation: "Merge conflicts occur when the same lines were changed differently in both branches.", topic: "Merging and Rebasing" },
  { id: 55, question: "What does git rebase do?", options: ["Creates a backup", "Moves commits to a new base commit", "Deletes commits", "Renames branches"], correctAnswer: 1, explanation: "Rebase replays your commits on top of another branch, creating a linear history.", topic: "Merging and Rebasing" },
  { id: 56, question: "What is the golden rule of rebasing?", options: ["Always rebase", "Never rebase public/shared branches", "Rebase before merge", "Rebase daily"], correctAnswer: 1, explanation: "Never rebase commits that have been pushed and shared with others, as it rewrites history.", topic: "Merging and Rebasing" },
  { id: 57, question: "Which creates a cleaner history?", options: ["Merge", "Rebase", "Both equally", "Neither"], correctAnswer: 1, explanation: "Rebase creates a linear history without merge commits, which some teams prefer for clarity.", topic: "Merging and Rebasing" },
  { id: 58, question: "How do you abort a merge with conflicts?", options: ["git merge --stop", "git merge --abort", "git cancel merge", "git undo merge"], correctAnswer: 1, explanation: "git merge --abort cancels the merge and returns to the pre-merge state.", topic: "Merging and Rebasing" },
  { id: 59, question: "What does git rebase -i do?", options: ["Interactive rebase", "Immediate rebase", "Initial rebase", "Iterative rebase"], correctAnswer: 0, explanation: "Interactive rebase (-i) lets you edit, squash, reorder, or drop commits.", topic: "Merging and Rebasing" },
  { id: 60, question: "What is squashing commits?", options: ["Deleting commits", "Combining multiple commits into one", "Splitting commits", "Hiding commits"], correctAnswer: 1, explanation: "Squashing combines multiple commits into a single commit, often used to clean up history before merging.", topic: "Merging and Rebasing" },

  // ==================== Topic 6: Remote Repositories (Questions 61-70) ====================
  { id: 61, question: "What is a remote repository?", options: ["A local backup", "A version of your repo hosted elsewhere", "A deleted repo", "A private branch"], correctAnswer: 1, explanation: "A remote repository is a version of your project hosted on a server like GitHub, GitLab, or Bitbucket.", topic: "Remote Repositories" },
  { id: 62, question: "What does 'origin' typically refer to?", options: ["The first commit", "The default remote repository", "The main branch", "The original author"], correctAnswer: 1, explanation: "Origin is the conventional name for the primary remote repository you cloned from.", topic: "Remote Repositories" },
  { id: 63, question: "Which command downloads a repository?", options: ["git download", "git clone", "git copy", "git get"], correctAnswer: 1, explanation: "git clone creates a local copy of a remote repository including all history.", topic: "Remote Repositories" },
  { id: 64, question: "What does git fetch do?", options: ["Downloads changes without merging", "Uploads changes", "Deletes remote", "Creates a branch"], correctAnswer: 0, explanation: "git fetch downloads commits and refs from a remote without integrating them into your work.", topic: "Remote Repositories" },
  { id: 65, question: "What does git pull do?", options: ["Uploads changes", "Downloads and merges changes", "Creates a remote", "Deletes local changes"], correctAnswer: 1, explanation: "git pull is essentially git fetch followed by git merge, updating your local branch.", topic: "Remote Repositories" },
  { id: 66, question: "What does git push do?", options: ["Downloads changes", "Uploads commits to remote", "Creates a backup", "Merges branches"], correctAnswer: 1, explanation: "git push uploads your local commits to the remote repository.", topic: "Remote Repositories" },
  { id: 67, question: "Which command adds a new remote?", options: ["git remote add", "git add remote", "git new remote", "git create remote"], correctAnswer: 0, explanation: "git remote add <name> <url> adds a new remote repository reference.", topic: "Remote Repositories" },
  { id: 68, question: "What does git remote -v show?", options: ["Remote versions", "Remote URLs for fetch and push", "Verbose remote info", "Remote branches"], correctAnswer: 1, explanation: "git remote -v lists all remotes with their fetch and push URLs.", topic: "Remote Repositories" },
  { id: 69, question: "What is upstream in Git?", options: ["The main branch", "The remote branch your local branch tracks", "A merge direction", "The first commit"], correctAnswer: 1, explanation: "Upstream refers to the remote-tracking branch that your local branch is set to track.", topic: "Remote Repositories" },
  { id: 70, question: "What does git push -u origin main do?", options: ["Deletes main", "Pushes and sets upstream tracking", "Updates origin", "Creates origin"], correctAnswer: 1, explanation: "The -u flag sets up tracking so future git push/pull commands know which remote branch to use.", topic: "Remote Repositories" },

  // ==================== Topic 7: Advanced Git & Best Practices (Questions 71-75) ====================
  { id: 71, question: "What does git stash do?", options: ["Deletes changes", "Temporarily saves uncommitted changes", "Creates a commit", "Backs up the repo"], correctAnswer: 1, explanation: "git stash saves your uncommitted changes and reverts to a clean working directory.", topic: "Advanced Git" },
  { id: 72, question: "What does git cherry-pick do?", options: ["Deletes commits", "Applies specific commits to current branch", "Creates branches", "Reverts changes"], correctAnswer: 1, explanation: "git cherry-pick applies the changes from specific commits onto your current branch.", topic: "Advanced Git" },
  { id: 73, question: "What is a pull request (PR)?", options: ["A Git command", "A request to merge changes via a platform", "A download request", "A branch type"], correctAnswer: 1, explanation: "A pull request is a platform feature (GitHub/GitLab) to propose, review, and merge changes.", topic: "Advanced Git" },
  { id: 74, question: "What does git revert do?", options: ["Deletes commits", "Creates a new commit that undoes changes", "Reverts to first commit", "Removes the repo"], correctAnswer: 1, explanation: "git revert creates a new commit that reverses the changes of a previous commit (safe for shared history).", topic: "Advanced Git" },
  { id: 75, question: "What does git reset --hard do?", options: ["Soft reset", "Discards all changes and resets to specified commit", "Resets config", "Creates a backup"], correctAnswer: 1, explanation: "git reset --hard discards all uncommitted changes and moves HEAD to the specified commit (use with caution).", topic: "Advanced Git" },
];

// Code block component
const CodeBlock: React.FC<{ code: string; title?: string }> = ({ code, title }) => (
  <Paper
    sx={{
      p: 2,
      borderRadius: 2,
      bgcolor: "rgba(0, 0, 0, 0.4)",
      border: "1px solid rgba(241, 78, 50, 0.2)",
    }}
  >
    {title && (
      <Typography variant="caption" sx={{ color: "#f14e32", fontWeight: 600, mb: 1, display: "block" }}>
        {title}
      </Typography>
    )}
    <Box
      component="pre"
      sx={{
        m: 0,
        p: 0,
        fontFamily: "monospace",
        fontSize: "0.85rem",
        whiteSpace: "pre-wrap",
        wordBreak: "break-word",
        color: "#e0e0e0",
        "& .keyword": { color: "#569cd6" },
        "& .string": { color: "#ce9178" },
        "& .comment": { color: "#6a9955" },
        "& .number": { color: "#b5cea8" },
      }}
    >
      {code}
    </Box>
  </Paper>
);

// Difficulty badge component
const DifficultyBadge: React.FC<{ level: "beginner" | "intermediate" | "advanced" }> = ({ level }) => {
  const colors = {
    beginner: { bg: "#22c55e", text: "Beginner" },
    intermediate: { bg: "#f59e0b", text: "Intermediate" },
    advanced: { bg: "#ef4444", text: "Advanced" },
  };
  return (
    <Chip
      label={colors[level].text}
      size="small"
      sx={{
        bgcolor: alpha(colors[level].bg, 0.15),
        color: colors[level].bg,
        fontWeight: 700,
        fontSize: "0.7rem",
      }}
    />
  );
};

// Pro tip component
const ProTip: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <Paper
    sx={{
      p: 2,
      borderRadius: 2,
      bgcolor: alpha("#8b5cf6", 0.08),
      border: `1px solid ${alpha("#8b5cf6", 0.3)}`,
      display: "flex",
      gap: 1.5,
      alignItems: "flex-start",
    }}
  >
    <LightbulbIcon sx={{ color: "#8b5cf6", fontSize: 20, mt: 0.2 }} />
    <Typography variant="body2" sx={{ color: "text.primary" }}>
      {children}
    </Typography>
  </Paper>
);

// Warning box component
const WarningBox: React.FC<{ title?: string; children: React.ReactNode }> = ({ title, children }) => (
  <Paper
    sx={{
      p: 2,
      borderRadius: 2,
      bgcolor: alpha("#f59e0b", 0.08),
      border: `1px solid ${alpha("#f59e0b", 0.3)}`,
    }}
  >
    <Box sx={{ display: "flex", gap: 1.5, alignItems: "flex-start" }}>
      <WarningIcon sx={{ color: "#f59e0b", fontSize: 20, mt: 0.2 }} />
      <Box>
        {title && (
          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b", mb: 0.5 }}>
            {title}
          </Typography>
        )}
        <Typography variant="body2">{children}</Typography>
      </Box>
    </Box>
  </Paper>
);

// Info box component
const InfoBox: React.FC<{ title?: string; children: React.ReactNode }> = ({ title, children }) => (
  <Paper
    sx={{
      p: 2,
      borderRadius: 2,
      bgcolor: alpha("#3b82f6", 0.08),
      border: `1px solid ${alpha("#3b82f6", 0.3)}`,
    }}
  >
    <Box sx={{ display: "flex", gap: 1.5, alignItems: "flex-start" }}>
      <InfoIcon sx={{ color: "#3b82f6", fontSize: 20, mt: 0.2 }} />
      <Box>
        {title && (
          <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 0.5 }}>
            {title}
          </Typography>
        )}
        <Typography variant="body2">{children}</Typography>
      </Box>
    </Box>
  </Paper>
);

// Quiz Section Component
const QuizSection: React.FC = () => {
  const [quizState, setQuizState] = useState<"start" | "active" | "results">("start");
  const [questions, setQuestions] = useState<QuizQuestion[]>([]);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<{ [key: number]: number }>({});
  const [showExplanation, setShowExplanation] = useState(false);
  const [score, setScore] = useState(0);

  const QUESTIONS_PER_QUIZ = 10;

  const startQuiz = () => {
    const shuffled = [...questionBank].sort(() => Math.random() - 0.5);
    const selected = shuffled.slice(0, QUESTIONS_PER_QUIZ);
    setQuestions(selected);
    setCurrentQuestionIndex(0);
    setSelectedAnswers({});
    setShowExplanation(false);
    setScore(0);
    setQuizState("active");
  };

  const handleAnswerSelect = (answerIndex: number) => {
    if (showExplanation) return;
    setSelectedAnswers((prev) => ({
      ...prev,
      [currentQuestionIndex]: answerIndex,
    }));
  };

  const handleCheckAnswer = () => {
    setShowExplanation(true);
    if (selectedAnswers[currentQuestionIndex] === questions[currentQuestionIndex].correctAnswer) {
      setScore((prev) => prev + 1);
    }
  };

  const handleNextQuestion = () => {
    if (currentQuestionIndex < questions.length - 1) {
      setCurrentQuestionIndex((prev) => prev + 1);
      setShowExplanation(false);
    } else {
      setQuizState("results");
    }
  };

  const currentQuestion = questions[currentQuestionIndex];
  const selectedAnswer = selectedAnswers[currentQuestionIndex];
  const isCorrect = selectedAnswer === currentQuestion?.correctAnswer;

  if (quizState === "start") {
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <QuizIcon sx={{ fontSize: 64, color: "#f14e32", mb: 2 }} />
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
          Git & Version Control Quiz
        </Typography>
        <Typography variant="body1" sx={{ mb: 3, color: "text.secondary" }}>
          Test your knowledge with {QUESTIONS_PER_QUIZ} random questions from our bank of {questionBank.length} questions.
        </Typography>
        <Button variant="contained" size="large" onClick={startQuiz} sx={{ bgcolor: "#f14e32" }}>
          Start Quiz
        </Button>
      </Box>
    );
  }

  if (quizState === "results") {
    const percentage = (score / QUESTIONS_PER_QUIZ) * 100;
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <EmojiEventsIcon sx={{ fontSize: 64, color: percentage >= 70 ? "#22c55e" : "#f59e0b", mb: 2 }} />
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
          Quiz Complete!
        </Typography>
        <Typography variant="h4" sx={{ fontWeight: 700, color: percentage >= 70 ? "#22c55e" : "#f59e0b", mb: 2 }}>
          {score} / {QUESTIONS_PER_QUIZ}
        </Typography>
        <Typography variant="body1" sx={{ mb: 3, color: "text.secondary" }}>
          {percentage >= 90 ? "Outstanding! You're a Git expert!" :
           percentage >= 70 ? "Great job! You have solid Git knowledge." :
           percentage >= 50 ? "Good effort! Review the material and try again." :
           "Keep learning! Practice makes perfect."}
        </Typography>
        <Button variant="contained" startIcon={<RefreshIcon />} onClick={startQuiz} sx={{ bgcolor: "#f14e32" }}>
          Try Again
        </Button>
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Chip label={`Question ${currentQuestionIndex + 1} of ${QUESTIONS_PER_QUIZ}`} />
        <Chip label={currentQuestion.topic} variant="outlined" />
      </Box>
      <Typography variant="h6" sx={{ fontWeight: 600, mb: 3 }}>
        {currentQuestion.question}
      </Typography>
      <RadioGroup value={selectedAnswer ?? ""} onChange={(e) => handleAnswerSelect(Number(e.target.value))}>
        {currentQuestion.options.map((option, index) => (
          <Paper
            key={index}
            sx={{
              p: 2,
              mb: 1.5,
              borderRadius: 2,
              cursor: showExplanation ? "default" : "pointer",
              border: `2px solid ${
                showExplanation
                  ? index === currentQuestion.correctAnswer
                    ? "#22c55e"
                    : index === selectedAnswer
                    ? "#ef4444"
                    : "transparent"
                  : selectedAnswer === index
                  ? "#f14e32"
                  : "transparent"
              }`,
              bgcolor: showExplanation
                ? index === currentQuestion.correctAnswer
                  ? alpha("#22c55e", 0.1)
                  : index === selectedAnswer
                  ? alpha("#ef4444", 0.1)
                  : "background.paper"
                : "background.paper",
              "&:hover": {
                bgcolor: showExplanation ? undefined : alpha("#f14e32", 0.05),
              },
            }}
            onClick={() => !showExplanation && handleAnswerSelect(index)}
          >
            <FormControlLabel
              value={index}
              control={<Radio disabled={showExplanation} />}
              label={option}
              sx={{ width: "100%", m: 0 }}
            />
          </Paper>
        ))}
      </RadioGroup>
      {showExplanation && (
        <Alert severity={isCorrect ? "success" : "error"} sx={{ mt: 2, mb: 2 }}>
          <AlertTitle>{isCorrect ? "Correct!" : "Incorrect"}</AlertTitle>
          {currentQuestion.explanation}
        </Alert>
      )}
      <Box sx={{ display: "flex", justifyContent: "flex-end", gap: 2, mt: 3 }}>
        {!showExplanation ? (
          <Button variant="contained" onClick={handleCheckAnswer} disabled={selectedAnswer === undefined} sx={{ bgcolor: "#f14e32" }}>
            Check Answer
          </Button>
        ) : (
          <Button variant="contained" onClick={handleNextQuestion} sx={{ bgcolor: "#f14e32" }}>
            {currentQuestionIndex < questions.length - 1 ? "Next Question" : "See Results"}
          </Button>
        )}
      </Box>
    </Box>
  );
};

// Placeholder content component
const PlaceholderContent: React.FC<{ description: string }> = ({ description }) => (
  <Paper
    sx={{
      p: 3,
      borderRadius: 2,
      bgcolor: alpha("#f14e32", 0.05),
      border: `2px dashed ${alpha("#f14e32", 0.3)}`,
      textAlign: "center",
    }}
  >
    <Typography variant="body1" sx={{ color: "text.secondary", fontStyle: "italic" }}>
      📝 {description}
    </Typography>
  </Paper>
);

// Main component
const GitVersionControlPage: React.FC = () => {
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");

  const pageContext = `Git & Version Control learning page - comprehensive guide covering version control fundamentals, Git basics, configuration, staging, committing, branching, merging, rebasing, remote repositories, collaboration workflows, undoing changes, and advanced Git topics. Includes 75-question quiz bank. Part of the Software Engineering section.`;

  // Navigation items for sidebar
  const moduleNavItems = [
    { id: "introduction", label: "Introduction", icon: "📖" },
    { id: "why-version-control", label: "Why Version Control?", icon: "💡" },
    { id: "git-fundamentals", label: "Git Fundamentals", icon: "🌳" },
    { id: "configuration", label: "Configuration", icon: "⚙️" },
    { id: "basic-workflow", label: "Basic Workflow", icon: "🔄" },
    { id: "staging-committing", label: "Staging & Committing", icon: "💾" },
    { id: "branching", label: "Branching", icon: "🌿" },
    { id: "merging", label: "Merging & Rebasing", icon: "🔀" },
    { id: "remote-repos", label: "Remote Repositories", icon: "☁️" },
    { id: "collaboration", label: "Collaboration", icon: "👥" },
    { id: "undoing-changes", label: "Undoing Changes", icon: "⏪" },
    { id: "advanced-topics", label: "Advanced Topics", icon: "🚀" },
    { id: "github", label: "GitHub", icon: "🐙" },
    { id: "gitlab", label: "GitLab", icon: "🦊" },
    { id: "best-practices", label: "Best Practices", icon: "✅" },
    { id: "common-commands", label: "Command Reference", icon: "📋" },
    { id: "quiz", label: "Knowledge Quiz", icon: "❓" },
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

  // Navigation drawer content
  const drawerContent = (
    <Box sx={{ width: 280, p: 2 }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
        <Typography variant="h6" sx={{ fontWeight: 700, color: "#f14e32" }}>
          📘 Modules
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
              bgcolor: activeSection === item.id ? alpha("#f14e32", 0.15) : "transparent",
              "&:hover": { bgcolor: alpha("#f14e32", 0.1) },
              transition: "all 0.2s",
            }}
          >
            <ListItemIcon sx={{ minWidth: 36, fontSize: "1.1rem" }}>{item.icon}</ListItemIcon>
            <ListItemText
              primary={item.label}
              primaryTypographyProps={{
                fontSize: "0.875rem",
                fontWeight: activeSection === item.id ? 700 : 500,
                color: activeSection === item.id ? "#f14e32" : "text.primary",
              }}
            />
          </ListItem>
        ))}
      </List>
    </Box>
  );

  // Sidebar navigation for desktop
  const sidebarNav = (
    <Box
      sx={{
        position: "sticky",
        top: 80,
        maxHeight: "calc(100vh - 100px)",
        overflowY: "auto",
        pr: 1,
        "&::-webkit-scrollbar": { width: 4 },
        "&::-webkit-scrollbar-thumb": { bgcolor: alpha("#f14e32", 0.3), borderRadius: 2 },
      }}
    >
      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
        <MenuBookIcon sx={{ color: "#f14e32", fontSize: 20 }} />
        <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f14e32" }}>
          Modules
        </Typography>
      </Box>
      <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
        {moduleNavItems.map((item, index) => {
          const isActive = activeSection === item.id;
          const progress = moduleNavItems.findIndex(m => m.id === activeSection);
          const isCompleted = index < progress;
          
          return (
            <Box
              key={item.id}
              onClick={() => scrollToSection(item.id)}
              sx={{
                display: "flex",
                alignItems: "center",
                gap: 1,
                py: 0.75,
                px: 1.5,
                borderRadius: 1.5,
                cursor: "pointer",
                bgcolor: isActive ? alpha("#f14e32", 0.15) : "transparent",
                borderLeft: isActive ? `3px solid #f14e32` : "3px solid transparent",
                "&:hover": { bgcolor: alpha("#f14e32", 0.08) },
                transition: "all 0.15s ease",
              }}
            >
              <Typography sx={{ fontSize: "0.9rem", opacity: isCompleted ? 0.6 : 1 }}>
                {item.icon}
              </Typography>
              <Typography
                sx={{
                  fontSize: "0.75rem",
                  fontWeight: isActive ? 700 : 500,
                  color: isActive ? "#f14e32" : isCompleted ? "text.secondary" : "text.primary",
                  whiteSpace: "nowrap",
                  overflow: "hidden",
                  textOverflow: "ellipsis",
                }}
              >
                {item.label}
              </Typography>
            </Box>
          );
        })}
      </Box>
      
      {/* Progress indicator */}
      <Box sx={{ mt: 3, pt: 2, borderTop: `1px solid ${alpha("#f14e32", 0.1)}` }}>
        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
          Progress
        </Typography>
        <LinearProgress
          variant="determinate"
          value={((moduleNavItems.findIndex(m => m.id === activeSection) + 1) / moduleNavItems.length) * 100}
          sx={{
            height: 6,
            borderRadius: 3,
            bgcolor: alpha("#f14e32", 0.1),
            "& .MuiLinearProgress-bar": { bgcolor: "#f14e32", borderRadius: 3 },
          }}
        />
        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5, textAlign: "center" }}>
          {moduleNavItems.findIndex(m => m.id === activeSection) + 1} / {moduleNavItems.length}
        </Typography>
      </Box>
    </Box>
  );

  const quickStats = [
    { label: "Modules", value: "14", color: "#f14e32" },
    { label: "Commands", value: "50+", color: "#22c55e" },
    { label: "Quiz Questions", value: "75", color: "#f59e0b" },
    { label: "Examples", value: "30+", color: "#8b5cf6" },
  ];

  return (
    <LearnPageLayout pageTitle="Git & Version Control" pageContext={pageContext}>
      {/* Mobile Navigation Drawer */}
      <Drawer
        anchor="left"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        sx={{ 
          "& .MuiDrawer-paper": { bgcolor: theme.palette.background.default },
          display: { xs: "block", lg: "none" }
        }}
      >
        {drawerContent}
      </Drawer>

      {/* Floating Navigation Button - Mobile Only */}
      <Tooltip title="Module Navigation" placement="left">
        <Fab
          color="primary"
          onClick={() => setNavDrawerOpen(true)}
          sx={{
            position: "fixed",
            bottom: isMobile ? 80 : 32,
            right: 32,
            bgcolor: "#f14e32",
            "&:hover": { bgcolor: "#d94429" },
            zIndex: 1000,
            display: { xs: "flex", lg: "none" },
          }}
        >
          <ListAltIcon />
        </Fab>
      </Tooltip>

      {/* Main Layout with Sidebar */}
      <Box sx={{ display: "flex", gap: 4, maxWidth: 1400, mx: "auto", px: { xs: 2, md: 3 }, py: 4 }}>
        {/* Desktop Sidebar */}
        <Box
          sx={{
            display: { xs: "none", lg: "block" },
            width: 220,
            flexShrink: 0,
          }}
        >
          {sidebarNav}
        </Box>

        {/* Main Content */}
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Button startIcon={<ArrowBackIcon />} onClick={() => navigate("/learn")} sx={{ mb: 3 }}>
            Back to Learning Hub
          </Button>

          {/* ==================== HERO SECTION ==================== */}
          <Paper
            id="introduction"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              background: `linear-gradient(135deg, ${alpha("#f14e32", 0.18)} 0%, ${alpha("#f97316", 0.12)} 50%, ${alpha("#fbbf24", 0.12)} 100%)`,
              border: `1px solid ${alpha("#f14e32", 0.2)}`,
              position: "relative",
              overflow: "hidden",
              scrollMarginTop: "100px",
            }}
          >
            <Box
              sx={{
                position: "absolute",
                top: -50,
                right: -40,
                width: 220,
                height: 220,
                borderRadius: "50%",
                background: `radial-gradient(circle, ${alpha("#f14e32", 0.15)} 0%, transparent 70%)`,
              }}
            />

            <Box sx={{ position: "relative", zIndex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
                <Box
                  sx={{
                    width: 80,
                    height: 80,
                    borderRadius: 3,
                    background: "linear-gradient(135deg, #f14e32, #f97316)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    boxShadow: `0 8px 32px ${alpha("#f14e32", 0.3)}`,
                  }}
                >
                  <AccountTreeIcon sx={{ fontSize: 44, color: "white" }} />
                </Box>
                <Box>
                  <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                    Git & Version Control
                  </Typography>
                  <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                    Master the essential tools for tracking changes and collaborating on code
                  </Typography>
                </Box>
              </Box>

              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                <Chip label="Beginner Friendly" color="success" />
                <Chip label="Collaboration" sx={{ bgcolor: alpha("#f14e32", 0.15), color: "#f14e32", fontWeight: 600 }} />
                <Chip label="Essential Skill" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
                <Chip label="Software Engineering" sx={{ bgcolor: alpha("#f59e0b", 0.15), color: "#f59e0b", fontWeight: 600 }} />
              </Box>

              <Grid container spacing={2}>
                {quickStats.map((stat) => (
                  <Grid item xs={6} sm={3} key={stat.label}>
                    <Paper
                      sx={{
                        p: 2,
                        textAlign: "center",
                        borderRadius: 2,
                        bgcolor: alpha(stat.color, 0.1),
                        border: `1px solid ${alpha(stat.color, 0.2)}`,
                      }}
                    >
                      <Typography variant="h4" sx={{ fontWeight: 800, color: stat.color }}>
                        {stat.value}
                      </Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ fontWeight: 600 }}>
                        {stat.label}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Box>
          </Paper>

          {/* ==================== SECTION 2: WHY VERSION CONTROL? ==================== */}
          <Paper
            id="why-version-control"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
              <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
                <HistoryIcon sx={{ color: "#f14e32" }} />
                Why Version Control Matters
              </Typography>
              <DifficultyBadge level="beginner" />
            </Box>

            {/* The Problem Without Version Control */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              The Problem: Life Without Version Control
            </Typography>
            <Typography paragraph>
              Have you ever had files named like this?
            </Typography>
            <CodeBlock
              title="The filename nightmare"
              code={`report.doc
report_final.doc
report_final_v2.doc
report_final_v2_FINAL.doc
report_final_v2_FINAL_actually_final.doc
report_final_v2_FINAL_actually_final_USE_THIS_ONE.doc`}
            />
            <Box sx={{ mt: 2 }} />
            <WarningBox title="Real-World Disasters">
              In 2012, Knight Capital lost $440 million in 45 minutes due to deploying untested code without proper version control. 
              A simple rollback mechanism could have prevented this catastrophe.
            </WarningBox>

            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              The Solution: Version Control Benefits
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>📜 Complete History</Typography>
                  <Typography variant="body2">Every change is recorded with who made it, when, and why. You can always go back to any previous version.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.08), border: `1px solid ${alpha("#3b82f6", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>👥 Collaboration</Typography>
                  <Typography variant="body2">Multiple people can work on the same project simultaneously without overwriting each other's work.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.08), border: `1px solid ${alpha("#f59e0b", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>🔬 Experimentation</Typography>
                  <Typography variant="body2">Create branches to try new ideas safely. If they don't work out, simply delete the branch—no harm done.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.08), border: `1px solid ${alpha("#8b5cf6", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>💾 Backup & Recovery</Typography>
                  <Typography variant="body2">Your code is safely stored. Accidentally deleted something? Restore it in seconds. Laptop stolen? Clone from remote.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.08), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>🔍 Accountability</Typography>
                  <Typography variant="body2">Know exactly who changed what and when. Essential for debugging, code reviews, and compliance.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#06b6d4", 0.08), border: `1px solid ${alpha("#06b6d4", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#06b6d4", mb: 1 }}>🚀 CI/CD Integration</Typography>
                  <Typography variant="body2">Automate testing, building, and deployment. Version control is the foundation of modern DevOps.</Typography>
                </Paper>
              </Grid>
            </Grid>

            <Box sx={{ mt: 3 }} />
            <ProTip>
              Even if you're working alone, use version control! Your future self will thank you when you need to understand 
              why you made a change 6 months ago, or when you need to undo a mistake.
            </ProTip>
          </Paper>

          {/* ==================== SECTION 3: GIT FUNDAMENTALS ==================== */}
          <Paper
            id="git-fundamentals"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
              <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
                <AccountTreeIcon sx={{ color: "#f14e32" }} />
                Git Fundamentals
              </Typography>
              <DifficultyBadge level="beginner" />
            </Box>

            {/* What Makes Git Different */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              What Makes Git Different: Snapshots vs Deltas
            </Typography>
            <Typography paragraph>
              Most version control systems (like SVN) store information as a list of file-based changes (deltas). 
              Git thinks differently—it stores data as <strong>snapshots</strong> of your entire project at each commit.
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.08), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>❌ Delta-based (SVN, etc.)</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>
                    Version 1: File A (base)<br/>
                    Version 2: File A + Δ1<br/>
                    Version 3: File A + Δ1 + Δ2<br/>
                    (Must apply all deltas to reconstruct)
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>✓ Snapshot-based (Git)</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>
                    Commit 1: [Snapshot of all files]<br/>
                    Commit 2: [Snapshot of all files]<br/>
                    Commit 3: [Snapshot of all files]<br/>
                    (Each commit is complete & independent)
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* The Three States */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              The Three States of Git
            </Typography>
            <Typography paragraph>
              Understanding Git's three main states is crucial. Files in a Git project can be in one of these states:
            </Typography>
            <Box sx={{ display: "flex", flexDirection: { xs: "column", md: "row" }, gap: 2, mb: 3, alignItems: "stretch" }}>
              <Paper sx={{ flex: 1, p: 2, bgcolor: alpha("#3b82f6", 0.08), border: `1px solid ${alpha("#3b82f6", 0.2)}`, borderRadius: 2, textAlign: "center" }}>
                <Typography variant="h6" sx={{ color: "#3b82f6", fontWeight: 700 }}>1. Working Directory</Typography>
                <Typography variant="body2" sx={{ mt: 1 }}>Your local filesystem where you edit files. Changes here are "untracked" or "modified".</Typography>
                <Typography variant="caption" sx={{ display: "block", mt: 1, fontFamily: "monospace", bgcolor: alpha("#3b82f6", 0.1), p: 0.5, borderRadius: 1 }}>Where you work</Typography>
              </Paper>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", color: "#f14e32", fontWeight: 700 }}>→ git add →</Box>
              <Paper sx={{ flex: 1, p: 2, bgcolor: alpha("#f59e0b", 0.08), border: `1px solid ${alpha("#f59e0b", 0.2)}`, borderRadius: 2, textAlign: "center" }}>
                <Typography variant="h6" sx={{ color: "#f59e0b", fontWeight: 700 }}>2. Staging Area</Typography>
                <Typography variant="body2" sx={{ mt: 1 }}>A preview of your next commit. You choose exactly which changes to include.</Typography>
                <Typography variant="caption" sx={{ display: "block", mt: 1, fontFamily: "monospace", bgcolor: alpha("#f59e0b", 0.1), p: 0.5, borderRadius: 1 }}>Also called "Index"</Typography>
              </Paper>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", color: "#f14e32", fontWeight: 700 }}>→ git commit →</Box>
              <Paper sx={{ flex: 1, p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2, textAlign: "center" }}>
                <Typography variant="h6" sx={{ color: "#22c55e", fontWeight: 700 }}>3. Repository</Typography>
                <Typography variant="body2" sx={{ mt: 1 }}>The .git directory where Git stores all committed snapshots permanently.</Typography>
                <Typography variant="caption" sx={{ display: "block", mt: 1, fontFamily: "monospace", bgcolor: alpha("#22c55e", 0.1), p: 0.5, borderRadius: 1 }}>Your project history</Typography>
              </Paper>
            </Box>

            {/* The .git Folder */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              Inside the .git Folder
            </Typography>
            <Typography paragraph>
              When you run <code>git init</code>, Git creates a hidden <code>.git</code> folder. This is where all the magic happens:
            </Typography>
            <CodeBlock
              title=".git directory structure"
              code={`.git/
├── HEAD          # Points to current branch
├── config        # Repository-specific settings
├── description   # Used by GitWeb (rarely needed)
├── hooks/        # Scripts that run on events
├── index         # The staging area
├── objects/      # All content (blobs, trees, commits)
│   ├── pack/     # Compressed object storage
│   └── info/
├── refs/         # Pointers to commits
│   ├── heads/    # Local branches
│   ├── tags/     # Tags
│   └── remotes/  # Remote-tracking branches
└── logs/         # History of ref changes`}
            />
            <Box sx={{ mt: 2 }} />
            <WarningBox title="Never manually edit .git!">
              The .git folder is Git's database. Manually editing files inside can corrupt your repository. 
              Always use Git commands to interact with your repository.
            </WarningBox>

            {/* Installing Git */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Installing Git
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#f14e32", 0.2)}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>🪟 Windows</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Download from git-scm.com or use:</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", bgcolor: "rgba(0,0,0,0.2)", p: 1, borderRadius: 1, fontSize: "0.8rem" }}>winget install Git.Git</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#f14e32", 0.2)}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>🍎 macOS</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Install via Homebrew or Xcode tools:</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", bgcolor: "rgba(0,0,0,0.2)", p: 1, borderRadius: 1, fontSize: "0.8rem" }}>brew install git</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#f14e32", 0.2)}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1 }}>🐧 Linux</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Use your package manager:</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", bgcolor: "rgba(0,0,0,0.2)", p: 1, borderRadius: 1, fontSize: "0.8rem" }}>sudo apt install git</Typography>
                </Paper>
              </Grid>
            </Grid>
            <Box sx={{ mt: 2 }} />
            <CodeBlock
              title="Verify installation"
              code={`git --version
# Output: git version 2.43.0 (or similar)`}
            />
            <Box sx={{ mt: 2 }} />
            <ProTip>
              Git is a distributed version control system—every clone is a full backup of the repository with complete history. 
              This means you can work offline and still have access to the entire project history!
            </ProTip>
          </Paper>

          {/* ==================== SECTION 4: CONFIGURATION ==================== */}
          <Paper
            id="configuration"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
              <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
                <BuildIcon sx={{ color: "#f14e32" }} />
                Git Configuration
              </Typography>
              <DifficultyBadge level="beginner" />
            </Box>

            {/* Configuration Levels */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              Configuration Levels
            </Typography>
            <Typography paragraph>
              Git has three levels of configuration, each with different scope. Lower levels override higher ones:
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.08), border: `1px solid ${alpha("#3b82f6", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>1. System</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Applies to all users on the machine</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: "rgba(0,0,0,0.2)", p: 0.5, borderRadius: 1, display: "block" }}>/etc/gitconfig</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block", mt: 1 }}>git config --system</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.08), border: `1px solid ${alpha("#f59e0b", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>2. Global (User)</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Applies to all repos for current user</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: "rgba(0,0,0,0.2)", p: 0.5, borderRadius: 1, display: "block" }}>~/.gitconfig</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block", mt: 1 }}>git config --global</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>3. Local (Repo)</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Applies only to current repository</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: "rgba(0,0,0,0.2)", p: 0.5, borderRadius: 1, display: "block" }}>.git/config</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block", mt: 1 }}>git config --local</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Essential Configuration */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              Essential First-Time Setup
            </Typography>
            <Typography paragraph>
              Before you start using Git, you must set your identity. This information is baked into every commit:
            </Typography>
            <CodeBlock
              title="Set your identity (required)"
              code={`# Set your name and email (used in every commit)
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# Verify your settings
git config --list
git config user.name    # Check specific setting`}
            />
            <Box sx={{ mt: 2 }} />
            <InfoBox title="Why is this important?">
              Your name and email appear in every commit you make. Use your real name and a valid email for professional projects.
              For open source, use the email associated with your GitHub/GitLab account.
            </InfoBox>

            {/* Editor & Tools */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Editor & Default Branch
            </Typography>
            <CodeBlock
              title="Configure your preferred editor"
              code={`# Set VS Code as default editor
git config --global core.editor "code --wait"

# Other popular options:
git config --global core.editor "vim"
git config --global core.editor "nano"
git config --global core.editor "notepad++"

# Set default branch name (main instead of master)
git config --global init.defaultBranch main`}
            />

            {/* Line Endings */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Line Endings (CRLF vs LF)
            </Typography>
            <Typography paragraph>
              Windows uses CRLF (\r\n), while macOS/Linux use LF (\n). Git can handle this automatically:
            </Typography>
            <Grid container spacing={2} sx={{ mb: 2 }}>
              <Grid item xs={12} md={6}>
                <CodeBlock
                  title="Windows users"
                  code={`# Convert LF to CRLF on checkout
# Convert CRLF to LF on commit
git config --global core.autocrlf true`}
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <CodeBlock
                  title="macOS/Linux users"
                  code={`# Only convert CRLF to LF on commit
# (safety net for Windows files)
git config --global core.autocrlf input`}
                />
              </Grid>
            </Grid>

            {/* Useful Aliases */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Useful Git Aliases
            </Typography>
            <Typography paragraph>
              Aliases are shortcuts for common commands. Here are some popular ones:
            </Typography>
            <CodeBlock
              title="Recommended aliases"
              code={`# Shorter commands
git config --global alias.co checkout
git config --global alias.br branch
git config --global alias.ci commit
git config --global alias.st status

# Better log views
git config --global alias.lg "log --oneline --graph --all"
git config --global alias.last "log -1 HEAD"

# Undo shortcuts
git config --global alias.unstage "reset HEAD --"
git config --global alias.amend "commit --amend --no-edit"

# Usage: git st, git lg, git co main`}
            />

            {/* SSH Keys */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              SSH Key Setup
            </Typography>
            <Typography paragraph>
              SSH keys provide secure, password-less authentication to GitHub/GitLab:
            </Typography>
            <CodeBlock
              title="Generate and add SSH key"
              code={`# Generate a new SSH key (use your GitHub email)
ssh-keygen -t ed25519 -C "your.email@example.com"

# Start the SSH agent
eval "$(ssh-agent -s)"

# Add your key to the agent
ssh-add ~/.ssh/id_ed25519

# Copy public key to clipboard (then add to GitHub/GitLab)
cat ~/.ssh/id_ed25519.pub
# Windows: clip < ~/.ssh/id_ed25519.pub
# macOS: pbcopy < ~/.ssh/id_ed25519.pub

# Test connection
ssh -T git@github.com`}
            />
            <Box sx={{ mt: 2 }} />
            <ProTip>
              View all your Git settings with <code>git config --list --show-origin</code> to see which file each setting comes from.
              This is helpful for debugging configuration issues.
            </ProTip>
          </Paper>

          {/* ==================== SECTION 5: BASIC WORKFLOW ==================== */}
          <Paper
            id="basic-workflow"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
              <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
                <CompareArrowsIcon sx={{ color: "#f14e32" }} />
                Basic Git Workflow
              </Typography>
              <DifficultyBadge level="beginner" />
            </Box>

            {/* Starting a Repository */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              Starting a Repository
            </Typography>
            <Typography paragraph>
              There are two ways to get a Git repository: create a new one or clone an existing one.
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <CodeBlock
                  title="Option 1: Create new repository"
                  code={`# Navigate to your project folder
cd my-project

# Initialize Git (creates .git folder)
git init

# Output: Initialized empty Git repository
# in /path/to/my-project/.git/`}
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <CodeBlock
                  title="Option 2: Clone existing repository"
                  code={`# Clone from URL (creates new folder)
git clone https://github.com/user/repo.git

# Clone into specific folder
git clone https://github.com/user/repo.git my-folder

# Clone with SSH
git clone git@github.com:user/repo.git`}
                />
              </Grid>
            </Grid>

            {/* The Edit-Stage-Commit Cycle */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              The Edit-Stage-Commit Cycle
            </Typography>
            <Typography paragraph>
              This is the fundamental Git workflow you'll use hundreds of times:
            </Typography>
            <Box sx={{ display: "flex", flexDirection: { xs: "column", md: "row" }, gap: 1, mb: 3, alignItems: "center", justifyContent: "center", flexWrap: "wrap" }}>
              <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.1), borderRadius: 2, textAlign: "center", minWidth: 150 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6" }}>1. EDIT</Typography>
                <Typography variant="caption">Modify files</Typography>
              </Paper>
              <Typography sx={{ color: "#f14e32", fontWeight: 700 }}>→</Typography>
              <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.1), borderRadius: 2, textAlign: "center", minWidth: 150 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f59e0b" }}>2. STAGE</Typography>
                <Typography variant="caption">git add</Typography>
              </Paper>
              <Typography sx={{ color: "#f14e32", fontWeight: 700 }}>→</Typography>
              <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.1), borderRadius: 2, textAlign: "center", minWidth: 150 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e" }}>3. COMMIT</Typography>
                <Typography variant="caption">git commit</Typography>
              </Paper>
              <Typography sx={{ color: "#f14e32", fontWeight: 700 }}>→</Typography>
              <Paper sx={{ p: 2, bgcolor: alpha("#8b5cf6", 0.1), borderRadius: 2, textAlign: "center", minWidth: 150 }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#8b5cf6" }}>REPEAT</Typography>
                <Typography variant="caption">Continue working</Typography>
              </Paper>
            </Box>

            {/* Understanding git status */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              Understanding git status
            </Typography>
            <Typography paragraph>
              <code>git status</code> is your best friend. Run it constantly to understand what's happening:
            </Typography>
            <CodeBlock
              title="Reading git status output"
              code={`$ git status
On branch main

Changes to be committed:          # STAGED (green) - ready to commit
  (use "git restore --staged <file>..." to unstage)
        modified:   README.md
        new file:   index.html

Changes not staged for commit:    # MODIFIED (red) - need to stage
  (use "git add <file>..." to update what will be committed)
        modified:   style.css

Untracked files:                  # NEW FILES (red) - Git doesn't know about
  (use "git add <file>..." to include in what will be committed)
        script.js`}
            />
            <Box sx={{ mt: 2 }} />
            <InfoBox title="Short status">
              Use <code>git status -s</code> for a compact view: <code>M</code> = modified, <code>A</code> = added, <code>??</code> = untracked, <code>D</code> = deleted.
            </InfoBox>

            {/* Viewing History */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Viewing History with git log
            </Typography>
            <CodeBlock
              title="Useful git log variations"
              code={`# Basic log (full details)
git log

# Compact one-line format
git log --oneline

# Show last 5 commits
git log -5

# Visual branch graph
git log --oneline --graph --all

# Show changes in each commit
git log -p

# Search commits by author
git log --author="John"

# Search commits by message
git log --grep="fix bug"

# Show commits in date range
git log --since="2024-01-01" --until="2024-12-31"`}
            />

            {/* Complete Beginner Workflow */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Complete Beginner Workflow Example
            </Typography>
            <CodeBlock
              title="Your first Git project from scratch"
              code={`# 1. Create project folder and initialize Git
mkdir my-website && cd my-website
git init

# 2. Create some files
echo "<h1>Hello World</h1>" > index.html
echo "body { margin: 0; }" > style.css

# 3. Check status (files are untracked)
git status

# 4. Stage all files
git add .

# 5. Check status again (files are staged)
git status

# 6. Make your first commit
git commit -m "Initial commit: add HTML and CSS"

# 7. View your commit history
git log --oneline
# Output: a1b2c3d Initial commit: add HTML and CSS

# 8. Make changes and repeat!
echo "console.log('Hello');" > script.js
git add script.js
git commit -m "Add JavaScript file"`}
            />
            <Box sx={{ mt: 2 }} />
            <ProTip>
              Run <code>git status</code> before and after every command when learning. It helps you understand exactly what Git is doing
              and prevents mistakes.
            </ProTip>
          </Paper>

          {/* ==================== SECTION 6: STAGING & COMMITTING ==================== */}
          <Paper
            id="staging-committing"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
              <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
                <SaveIcon sx={{ color: "#f14e32" }} />
                Staging and Committing
              </Typography>
              <DifficultyBadge level="beginner" />
            </Box>

            {/* The Staging Area */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              Why the Staging Area Exists
            </Typography>
            <Typography paragraph>
              The staging area (also called "index") lets you craft your commits carefully. Instead of committing everything at once,
              you can select exactly which changes belong together logically.
            </Typography>
            <InfoBox title="Real-world example">
              You fixed a bug AND added a new feature in the same coding session. With staging, you can create two separate commits:
              one for the bug fix and one for the feature—keeping your history clean and reviewable.
            </InfoBox>

            {/* git add Variations */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              git add Variations
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#f14e32", 0.2)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, fontFamily: "monospace" }}>git add &lt;file&gt;</Typography>
                  <Typography variant="body2">Stage a specific file</Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 1 }}>git add index.html</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#f14e32", 0.2)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, fontFamily: "monospace" }}>git add .</Typography>
                  <Typography variant="body2">Stage all changes in current directory & subdirectories</Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 1 }}>Most commonly used</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#f14e32", 0.2)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, fontFamily: "monospace" }}>git add -A</Typography>
                  <Typography variant="body2">Stage ALL changes (including deletions) from entire repo</Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 1 }}>Same as git add --all</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#f14e32", 0.2)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 1, fontFamily: "monospace" }}>git add -p</Typography>
                  <Typography variant="body2">Interactive staging—choose hunks to stage</Typography>
                  <Typography variant="caption" sx={{ color: "text.secondary", display: "block", mt: 1 }}>Best for partial staging</Typography>
                </Paper>
              </Grid>
            </Grid>
            <CodeBlock
              title="Interactive staging example (git add -p)"
              code={`$ git add -p
diff --git a/file.txt b/file.txt
@@ -1,3 +1,4 @@
 line 1
+new line          # This is the change
 line 2

Stage this hunk [y,n,q,a,d,e,?]?
# y = yes, stage this hunk
# n = no, skip this hunk
# q = quit, don't stage remaining
# s = split into smaller hunks
# e = manually edit the hunk`}
            />

            {/* Viewing Changes with git diff */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Viewing Changes with git diff
            </Typography>
            <CodeBlock
              title="Different diff commands"
              code={`# See unstaged changes (working dir vs staging)
git diff

# See staged changes (staging vs last commit)
git diff --staged
# or: git diff --cached

# Compare two commits
git diff abc123 def456

# Compare with specific branch
git diff main

# Show only file names that changed
git diff --name-only

# Show stats (insertions/deletions)
git diff --stat`}
            />
            <Box sx={{ mt: 2 }} />
            <CodeBlock
              title="Reading diff output"
              code={`$ git diff
diff --git a/file.txt b/file.txt
index 1234567..abcdefg 100644
--- a/file.txt          # Old version
+++ b/file.txt          # New version
@@ -1,4 +1,5 @@         # Line numbers: old file vs new file
 unchanged line
-removed line           # Red: this line was deleted
+added line             # Green: this line was added
 unchanged line`}
            />

            {/* Writing Good Commit Messages */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Writing Good Commit Messages
            </Typography>
            <Typography paragraph>
              Good commit messages are crucial for understanding project history. Follow these conventions:
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.08), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>❌ Bad Messages</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>
                    "fix"<br/>
                    "updates"<br/>
                    "WIP"<br/>
                    "asdfasdf"<br/>
                    "changed stuff"<br/>
                    "Friday commit"
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>✓ Good Messages</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>
                    "Fix login button not responding on mobile"<br/>
                    "Add user authentication with JWT"<br/>
                    "Refactor database queries for performance"<br/>
                    "Update README with installation steps"<br/>
                    "Remove deprecated API endpoints"
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
            <CodeBlock
              title="Conventional Commits format (popular standard)"
              code={`# Format: <type>(<scope>): <description>

# Types:
# feat:     New feature
# fix:      Bug fix
# docs:     Documentation only
# style:    Formatting, semicolons, etc.
# refactor: Code change that neither fixes nor adds
# test:     Adding tests
# chore:    Maintenance tasks

# Examples:
git commit -m "feat(auth): add password reset functionality"
git commit -m "fix(api): handle null response from server"
git commit -m "docs: update API documentation"
git commit -m "refactor(utils): simplify date formatting logic"`}
            />

            {/* Anatomy of a Commit */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              The Anatomy of a Commit
            </Typography>
            <Typography paragraph>
              Every commit contains more than just your changes:
            </Typography>
            <CodeBlock
              title="What's inside a commit"
              code={`$ git show --format=fuller HEAD

commit a1b2c3d4e5f6... (HEAD -> main)  # SHA-1 hash (unique ID)
Author:     John Doe <john@example.com> # Who wrote the code
AuthorDate: Sat Dec 28 10:30:00 2024    # When it was written
Commit:     John Doe <john@example.com> # Who committed it
CommitDate: Sat Dec 28 10:30:00 2024    # When it was committed

    Fix navigation menu on mobile       # Commit message
    
    The hamburger menu wasn't opening    # Optional body
    due to a z-index conflict.
    
    Fixes #123                           # Optional footer

diff --git a/nav.css b/nav.css          # The actual changes
...`}
            />

            {/* Amending Commits */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Amending Commits
            </Typography>
            <Typography paragraph>
              Made a typo in your commit message? Forgot to add a file? Use <code>--amend</code>:
            </Typography>
            <CodeBlock
              title="Amending the last commit"
              code={`# Just change the message
git commit --amend -m "New corrected message"

# Add forgotten files to last commit
git add forgotten-file.txt
git commit --amend --no-edit   # Keep same message

# Change message AND add files
git add another-file.txt
git commit --amend -m "Updated message with new file"`}
            />
            <Box sx={{ mt: 2 }} />
            <WarningBox title="Don't amend public commits!">
              Amending rewrites history. Only amend commits that haven't been pushed yet.
              If you've already pushed, use <code>git revert</code> instead to safely undo changes.
            </WarningBox>
            <Box sx={{ mt: 2 }} />
            <ProTip>
              Use <code>git commit -v</code> to see the full diff while writing your commit message.
              This helps you write more accurate descriptions of what changed.
            </ProTip>
          </Paper>

          {/* ==================== SECTION 7: BRANCHING ==================== */}
          <Paper
            id="branching"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
              <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
                <AccountTreeIcon sx={{ color: "#f14e32" }} />
                Branching in Git
              </Typography>
              <DifficultyBadge level="intermediate" />
            </Box>

            {/* What is a Branch */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              What is a Branch?
            </Typography>
            <Typography paragraph>
              A branch is simply a lightweight, movable pointer to a commit. The default branch is usually called <code>main</code> (or <code>master</code> in older repos).
              Branches let you diverge from the main line of development and work in isolation.
            </Typography>
            <Box sx={{ textAlign: "center", my: 3, p: 3, bgcolor: alpha("#f14e32", 0.05), borderRadius: 2 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", whiteSpace: "pre", textAlign: "left", display: "inline-block" }}>
{`          feature-branch
                ↓
    C1 ← C2 ← C3 ← C4  (feature work)
         ↖
          C5 ← C6      (main continues)
               ↑
              main`}
              </Typography>
            </Box>
            <InfoBox title="Why branches are cheap">
              In Git, a branch is just a 41-byte file containing a commit hash. Creating a branch is instant and takes almost no space,
              unlike older VCS systems that copied entire directories.
            </InfoBox>

            {/* Creating and Switching Branches */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Creating and Switching Branches
            </Typography>
            <CodeBlock
              title="Branch creation commands"
              code={`# List all local branches (* marks current)
git branch

# List all branches including remote
git branch -a

# Create a new branch (stays on current branch)
git branch feature-login

# Switch to an existing branch
git checkout feature-login
# or modern way:
git switch feature-login

# Create AND switch in one command
git checkout -b feature-login
# or modern way:
git switch -c feature-login

# Create branch from specific commit
git branch bugfix-123 abc1234`}
            />
            <Box sx={{ mt: 2 }} />
            <ProTip>
              Use <code>git switch</code> (Git 2.23+) instead of <code>git checkout</code> for branch operations.
              It's clearer and less error-prone since checkout does many different things.
            </ProTip>

            {/* Branch Naming Conventions */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Branch Naming Conventions
            </Typography>
            <Typography paragraph>
              Good branch names describe the work and help organize your repository:
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>✓ Good Names</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>
                    feature/user-authentication<br/>
                    bugfix/login-validation<br/>
                    hotfix/security-patch<br/>
                    release/v2.1.0<br/>
                    docs/api-documentation<br/>
                    refactor/database-queries
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.08), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>✗ Bad Names</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>
                    fix<br/>
                    test<br/>
                    my-branch<br/>
                    stuff<br/>
                    john-working<br/>
                    new-feature-2
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Branch Types */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Common Branch Types
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.3)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Long-Running</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Permanent branches that exist throughout the project</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block" }}>main, develop, staging</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.3)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Feature</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Short-lived branches for new features</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block" }}>feature/*, feat/*</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#ef4444", 0.3)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>Hotfix</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Urgent fixes branched from production</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block" }}>hotfix/*, bugfix/*</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Branch Management */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Branch Management Commands
            </Typography>
            <CodeBlock
              title="Managing branches"
              code={`# Rename current branch
git branch -m new-name

# Rename a different branch
git branch -m old-name new-name

# Delete a merged branch
git branch -d feature-login

# Force delete unmerged branch (careful!)
git branch -D abandoned-feature

# See which branches are merged into current
git branch --merged

# See unmerged branches
git branch --no-merged

# See last commit on each branch
git branch -v`}
            />
            <Box sx={{ mt: 2 }} />
            <WarningBox title="When to create a branch">
              Create a branch whenever you start work that might take more than one commit, or work you might want to abandon.
              Branches are free—use them liberally! Never commit experimental code directly to main.
            </WarningBox>
          </Paper>

          {/* ==================== SECTION 8: MERGING ==================== */}
          <Paper
            id="merging"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
              <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
                <MergeIcon sx={{ color: "#f14e32" }} />
                Merging and Rebasing
              </Typography>
              <DifficultyBadge level="intermediate" />
            </Box>

            {/* Types of Merges */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              Types of Merges
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Fast-Forward Merge</Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}>When the target branch has no new commits, Git simply moves the pointer forward. No merge commit created.</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", whiteSpace: "pre", display: "block", bgcolor: "rgba(0,0,0,0.2)", p: 1, borderRadius: 1 }}>
{`Before:  main → A → B
         feature → A → B → C → D

After:   main → A → B → C → D`}
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.08), border: `1px solid ${alpha("#3b82f6", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Three-Way Merge</Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}>When both branches have diverged, Git creates a merge commit with two parents.</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", whiteSpace: "pre", display: "block", bgcolor: "rgba(0,0,0,0.2)", p: 1, borderRadius: 1 }}>
{`Before:  main → A → B → E
         feature → A → B → C → D

After:   main → A → B → E → M
                     ↖ C → D ↗`}
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Basic Merge Commands */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Performing a Merge
            </Typography>
            <CodeBlock
              title="Basic merge workflow"
              code={`# 1. Switch to the target branch (where you want changes)
git checkout main

# 2. Merge the feature branch into main
git merge feature-login

# 3. If fast-forward, you're done!
# Output: Fast-forward

# Force a merge commit even if fast-forward possible
git merge --no-ff feature-login

# Abort a merge in progress (if conflicts)
git merge --abort`}
            />

            {/* Merge Conflicts */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Resolving Merge Conflicts
            </Typography>
            <Typography paragraph>
              Conflicts occur when both branches modified the same lines. Git marks the conflicting sections:
            </Typography>
            <CodeBlock
              title="What a conflict looks like"
              code={`<<<<<<< HEAD
// This is the code from your current branch (main)
const greeting = "Hello World";
=======
// This is the code from the incoming branch (feature)
const greeting = "Hello Universe";
>>>>>>> feature-branch

// You must:
// 1. Remove all conflict markers (<<<, ===, >>>)
// 2. Keep the code you want (or combine both)
// 3. Save the file
// 4. Stage and commit

// Final resolved version:
const greeting = "Hello Universe";`}
            />
            <Box sx={{ mt: 2 }} />
            <CodeBlock
              title="Conflict resolution workflow"
              code={`# 1. See which files have conflicts
git status

# 2. Open each conflicted file and resolve manually
# (or use a merge tool)
git mergetool

# 3. After fixing, stage the resolved files
git add resolved-file.js

# 4. Complete the merge
git commit
# (Git auto-generates merge commit message)`}
            />
            <Box sx={{ mt: 2 }} />
            <ProTip>
              Use VS Code's built-in merge editor—it shows "Accept Current", "Accept Incoming", and "Accept Both" buttons
              above each conflict, making resolution much easier.
            </ProTip>

            {/* Rebasing */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Introduction to Rebasing
            </Typography>
            <Typography paragraph>
              Rebasing moves your commits to a new base, creating a linear history without merge commits:
            </Typography>
            <Box sx={{ textAlign: "center", my: 3, p: 3, bgcolor: alpha("#f14e32", 0.05), borderRadius: 2 }}>
              <Typography variant="body2" sx={{ fontFamily: "monospace", whiteSpace: "pre", textAlign: "left", display: "inline-block" }}>
{`Before rebase:
main:    A → B → C
feature: A → B → X → Y

After "git rebase main" on feature:
main:    A → B → C
feature: A → B → C → X' → Y'  (commits replayed)`}
              </Typography>
            </Box>
            <CodeBlock
              title="Basic rebase commands"
              code={`# Rebase current branch onto main
git checkout feature
git rebase main

# If conflicts occur during rebase:
git rebase --continue  # after resolving
git rebase --abort     # cancel the rebase
git rebase --skip      # skip problematic commit

# Interactive rebase (edit last 3 commits)
git rebase -i HEAD~3`}
            />

            {/* Merge vs Rebase */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Merge vs Rebase: When to Use Each
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Use Merge When...</Typography>
                  <List dense>
                    <ListItem><ListItemText primary="Working on shared/public branches" /></ListItem>
                    <ListItem><ListItemText primary="You want to preserve complete history" /></ListItem>
                    <ListItem><ListItemText primary="The branch has been pushed and others use it" /></ListItem>
                    <ListItem><ListItemText primary="You want explicit merge points" /></ListItem>
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.08), border: `1px solid ${alpha("#3b82f6", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Use Rebase When...</Typography>
                  <List dense>
                    <ListItem><ListItemText primary="Working on local/private branches" /></ListItem>
                    <ListItem><ListItemText primary="You want a clean, linear history" /></ListItem>
                    <ListItem><ListItemText primary="Before merging a feature branch" /></ListItem>
                    <ListItem><ListItemText primary="Cleaning up messy commit history" /></ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>
            <WarningBox title="The Golden Rule of Rebasing">
              Never rebase commits that have been pushed to a public repository. Rebasing rewrites history,
              which causes problems for anyone who has based work on those commits.
            </WarningBox>

            {/* Interactive Rebase */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Interactive Rebase (Squashing Commits)
            </Typography>
            <CodeBlock
              title="Squashing multiple commits into one"
              code={`# Start interactive rebase for last 4 commits
git rebase -i HEAD~4

# Editor opens with:
pick a1b2c3d First commit message
pick e4f5g6h WIP
pick i7j8k9l Fix typo
pick m0n1o2p Final cleanup

# Change to squash commits:
pick a1b2c3d First commit message
squash e4f5g6h WIP
squash i7j8k9l Fix typo
squash m0n1o2p Final cleanup

# Save and close - you'll then edit the combined message

# Commands:
# p, pick   = use commit as-is
# r, reword = use commit but edit message
# e, edit   = stop for amending
# s, squash = meld into previous commit
# f, fixup  = like squash but discard message
# d, drop   = remove commit entirely`}
            />
          </Paper>

          {/* ==================== SECTION 9: REMOTE REPOSITORIES ==================== */}
          <Paper
            id="remote-repos"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
              <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
                <CloudIcon sx={{ color: "#f14e32" }} />
                Remote Repositories
              </Typography>
              <DifficultyBadge level="intermediate" />
            </Box>

            {/* What is a Remote */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              What is a Remote?
            </Typography>
            <Typography paragraph>
              A remote is a version of your repository hosted on the internet or network. It allows collaboration—multiple developers can push and pull changes from the same remote repository.
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.08), border: `1px solid ${alpha("#3b82f6", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>origin</Typography>
                  <Typography variant="body2">The default name for the remote you cloned from. This is usually your main remote.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>upstream</Typography>
                  <Typography variant="body2">Common name for the original repo when you've forked. Used to sync with the source project.</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Managing Remotes */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Managing Remotes
            </Typography>
            <CodeBlock
              title="Remote management commands"
              code={`# List all remotes
git remote
git remote -v   # with URLs

# Add a new remote
git remote add origin https://github.com/user/repo.git
git remote add upstream https://github.com/original/repo.git

# Change remote URL
git remote set-url origin git@github.com:user/repo.git

# Remove a remote
git remote remove upstream

# Rename a remote
git remote rename origin main-remote

# Show detailed info about a remote
git remote show origin`}
            />

            {/* Fetch, Pull, Push */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Fetch, Pull, and Push
            </Typography>
            <Typography paragraph>
              These are the three main operations for syncing with remotes:
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.3)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>git fetch</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Downloads changes from remote but doesn't merge them. Safe—won't affect your working files.</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace" }}>Remote → Local (tracking branches only)</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.3)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>git pull</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Fetches AND merges remote changes into your current branch. Shortcut for fetch + merge.</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace" }}>Remote → Local → Working Dir</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.3)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>git push</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Uploads your local commits to the remote. Shares your work with others.</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace" }}>Local → Remote</Typography>
                </Paper>
              </Grid>
            </Grid>
            <CodeBlock
              title="Fetch, pull, and push commands"
              code={`# Fetch all remotes
git fetch --all

# Fetch specific remote
git fetch origin

# Pull current branch from origin
git pull

# Pull with rebase instead of merge
git pull --rebase

# Pull specific branch
git pull origin main

# Push current branch to origin
git push

# Push and set upstream (first time)
git push -u origin feature-branch
# Now "git push" works without specifying remote/branch

# Push all branches
git push --all

# Force push (dangerous! overwrites remote)
git push --force
git push --force-with-lease  # safer version`}
            />
            <Box sx={{ mt: 2 }} />
            <WarningBox title="Never force push to shared branches">
              <code>git push --force</code> overwrites remote history. Only use it on your own branches that nobody else is using.
              Use <code>--force-with-lease</code> as a safer alternative—it fails if someone else has pushed.
            </WarningBox>

            {/* Remote Tracking Branches */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Remote Tracking Branches
            </Typography>
            <Typography paragraph>
              Remote tracking branches are local references to the state of remote branches. They're named <code>origin/main</code>, <code>origin/feature</code>, etc.
            </Typography>
            <CodeBlock
              title="Working with remote tracking branches"
              code={`# See all tracking branches
git branch -r

# See local + remote branches
git branch -a

# Compare local main with origin/main
git diff main origin/main

# See how far ahead/behind you are
git status
# Output: Your branch is ahead of 'origin/main' by 3 commits.

# Create local branch from remote
git checkout -b feature origin/feature
# or: git switch -c feature origin/feature

# Set upstream for existing branch
git branch -u origin/main`}
            />

            {/* Popular Hosting Platforms */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Popular Git Hosting Platforms
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, textAlign: "center", height: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>GitHub</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Most popular. Great for open source. Actions CI/CD, Copilot AI.</Typography>
                  <Chip label="Free for public repos" size="small" color="success" />
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, textAlign: "center", height: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>GitLab</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Full DevOps platform. Built-in CI/CD. Self-hosting option.</Typography>
                  <Chip label="Free tier available" size="small" color="success" />
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, textAlign: "center", height: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>Bitbucket</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Atlassian product. Great Jira integration. Free private repos.</Typography>
                  <Chip label="Free for small teams" size="small" color="success" />
                </Paper>
              </Grid>
            </Grid>
            <ProTip>
              Use <code>git fetch</code> before <code>git status</code> to see accurate ahead/behind counts.
              Without fetching first, you're comparing against stale remote tracking branch data.
            </ProTip>
          </Paper>

          {/* ==================== SECTION 10: COLLABORATION ==================== */}
          <Paper
            id="collaboration"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
              <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
                <GroupIcon sx={{ color: "#f14e32" }} />
                Collaboration with Git
              </Typography>
              <DifficultyBadge level="intermediate" />
            </Box>

            {/* Pull Requests */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              Pull Requests / Merge Requests
            </Typography>
            <Typography paragraph>
              A Pull Request (GitHub) or Merge Request (GitLab) is a way to propose changes and request code review before merging into the main branch.
            </Typography>
            <Box sx={{ p: 3, bgcolor: alpha("#f14e32", 0.05), borderRadius: 2, mb: 3 }}>
              <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2 }}>Pull Request Workflow</Typography>
              <Box sx={{ display: "flex", flexDirection: { xs: "column", md: "row" }, gap: 1, alignItems: "center", justifyContent: "center", flexWrap: "wrap" }}>
                <Paper sx={{ p: 1.5, bgcolor: alpha("#3b82f6", 0.1), borderRadius: 2, textAlign: "center", minWidth: 120 }}>
                  <Typography variant="caption" sx={{ fontWeight: 700, color: "#3b82f6" }}>1. Branch</Typography>
                </Paper>
                <Typography sx={{ color: "#f14e32" }}>→</Typography>
                <Paper sx={{ p: 1.5, bgcolor: alpha("#f59e0b", 0.1), borderRadius: 2, textAlign: "center", minWidth: 120 }}>
                  <Typography variant="caption" sx={{ fontWeight: 700, color: "#f59e0b" }}>2. Commit</Typography>
                </Paper>
                <Typography sx={{ color: "#f14e32" }}>→</Typography>
                <Paper sx={{ p: 1.5, bgcolor: alpha("#8b5cf6", 0.1), borderRadius: 2, textAlign: "center", minWidth: 120 }}>
                  <Typography variant="caption" sx={{ fontWeight: 700, color: "#8b5cf6" }}>3. Push</Typography>
                </Paper>
                <Typography sx={{ color: "#f14e32" }}>→</Typography>
                <Paper sx={{ p: 1.5, bgcolor: alpha("#ec4899", 0.1), borderRadius: 2, textAlign: "center", minWidth: 120 }}>
                  <Typography variant="caption" sx={{ fontWeight: 700, color: "#ec4899" }}>4. Open PR</Typography>
                </Paper>
                <Typography sx={{ color: "#f14e32" }}>→</Typography>
                <Paper sx={{ p: 1.5, bgcolor: alpha("#22c55e", 0.1), borderRadius: 2, textAlign: "center", minWidth: 120 }}>
                  <Typography variant="caption" sx={{ fontWeight: 700, color: "#22c55e" }}>5. Review & Merge</Typography>
                </Paper>
              </Box>
            </Box>
            <CodeBlock
              title="Creating a PR workflow"
              code={`# 1. Create a feature branch
git checkout -b feature/add-login

# 2. Make changes and commit
git add .
git commit -m "feat: add login functionality"

# 3. Push branch to remote
git push -u origin feature/add-login

# 4. Go to GitHub/GitLab and click "New Pull Request"
#    Or use GitHub CLI:
gh pr create --title "Add login" --body "Description here"

# 5. After review and approval, merge via UI
#    Or use CLI:
gh pr merge`}
            />

            {/* Forking */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Forking Repositories
            </Typography>
            <Typography paragraph>
              A fork is your own copy of someone else's repository. It's the standard way to contribute to projects you don't have write access to.
            </Typography>
            <CodeBlock
              title="Fork and contribute workflow"
              code={`# 1. Fork the repo on GitHub (via web UI)

# 2. Clone YOUR fork
git clone https://github.com/YOUR-USERNAME/repo.git
cd repo

# 3. Add original repo as "upstream"
git remote add upstream https://github.com/ORIGINAL-OWNER/repo.git

# 4. Keep your fork synced
git fetch upstream
git checkout main
git merge upstream/main

# 5. Create feature branch, make changes
git checkout -b fix-typo
# ... make changes ...
git push origin fix-typo

# 6. Open PR from your fork to original repo`}
            />

            {/* Branching Strategies */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Branching Strategies
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.3)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>GitHub Flow</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Simple: main + feature branches. Deploy from main.</Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0 }}><ListItemText primaryTypographyProps={{ variant: "caption" }} primary="• Great for continuous deployment" /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primaryTypographyProps={{ variant: "caption" }} primary="• Easy to understand" /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primaryTypographyProps={{ variant: "caption" }} primary="• Best for small teams" /></ListItem>
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.3)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>GitFlow</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>main, develop, feature, release, hotfix branches.</Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0 }}><ListItemText primaryTypographyProps={{ variant: "caption" }} primary="• Structured release cycles" /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primaryTypographyProps={{ variant: "caption" }} primary="• Parallel development" /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primaryTypographyProps={{ variant: "caption" }} primary="• Better for versioned releases" /></ListItem>
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.3)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>Trunk-Based</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Everyone commits to main. Short-lived branches only.</Typography>
                  <List dense sx={{ py: 0 }}>
                    <ListItem sx={{ py: 0 }}><ListItemText primaryTypographyProps={{ variant: "caption" }} primary="• Fastest integration" /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primaryTypographyProps={{ variant: "caption" }} primary="• Requires good CI/CD" /></ListItem>
                    <ListItem sx={{ py: 0 }}><ListItemText primaryTypographyProps={{ variant: "caption" }} primary="• Used by Google, Facebook" /></ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>

            {/* Code Review */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Code Review Best Practices
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>For Authors</Typography>
                  <List dense>
                    <ListItem><ListItemText primary="Keep PRs small and focused" /></ListItem>
                    <ListItem><ListItemText primary="Write clear PR descriptions" /></ListItem>
                    <ListItem><ListItemText primary="Self-review before requesting" /></ListItem>
                    <ListItem><ListItemText primary="Respond to feedback promptly" /></ListItem>
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#3b82f6", 0.08), border: `1px solid ${alpha("#3b82f6", 0.2)}`, borderRadius: 2 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>For Reviewers</Typography>
                  <List dense>
                    <ListItem><ListItemText primary="Be constructive, not critical" /></ListItem>
                    <ListItem><ListItemText primary="Explain the 'why' of suggestions" /></ListItem>
                    <ListItem><ListItemText primary="Approve when good enough" /></ListItem>
                    <ListItem><ListItemText primary="Review within 24 hours" /></ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>

            {/* Protected Branches */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Protected Branches
            </Typography>
            <Typography paragraph>
              Protected branches prevent direct pushes and require PRs with reviews. Configure in repository settings:
            </Typography>
            <List dense sx={{ mb: 2 }}>
              <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Require pull request reviews before merging" /></ListItem>
              <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Require status checks to pass (CI/CD)" /></ListItem>
              <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Require conversation resolution" /></ListItem>
              <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Require signed commits" /></ListItem>
              <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Restrict who can push" /></ListItem>
            </List>
            <ProTip>
              Always protect your main/master branch in team projects. This ensures all changes go through code review
              and prevents accidental force pushes that could lose work.
            </ProTip>
          </Paper>

          {/* ==================== SECTION 11: UNDOING CHANGES ==================== */}
          <Paper
            id="undoing-changes"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
              <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
                <RestoreIcon sx={{ color: "#f14e32" }} />
                Undoing Changes
              </Typography>
              <DifficultyBadge level="intermediate" />
            </Box>

            {/* Quick Reference */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              Quick Reference: What Do You Want to Undo?
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.3)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Uncommitted Changes</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>
                    Unstaged edits → <code>git restore</code><br/>
                    Staged files → <code>git restore --staged</code><br/>
                    All changes → <code>git checkout .</code>
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.3)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Committed Changes</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>
                    Last commit msg → <code>git commit --amend</code><br/>
                    Undo commit (keep files) → <code>git reset --soft</code><br/>
                    Undo publicly → <code>git revert</code>
                  </Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Discarding Unstaged Changes */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Discarding Unstaged Changes
            </Typography>
            <CodeBlock
              title="Discard changes in working directory"
              code={`# Discard changes in specific file
git restore file.txt
# or older way:
git checkout -- file.txt

# Discard all unstaged changes
git restore .
# or:
git checkout .

# Remove untracked files (new files Git doesn't know)
git clean -n   # Dry run - see what would be deleted
git clean -f   # Actually delete untracked files
git clean -fd  # Delete untracked files AND directories`}
            />
            <Box sx={{ mt: 2 }} />
            <WarningBox title="These operations are destructive!">
              Discarding unstaged changes is permanent. Git cannot recover these changes since they were never committed.
              Always double-check with <code>git status</code> or <code>git clean -n</code> first.
            </WarningBox>

            {/* Unstaging Files */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Unstaging Files
            </Typography>
            <CodeBlock
              title="Remove files from staging area (keep changes)"
              code={`# Unstage specific file (keep changes in working dir)
git restore --staged file.txt
# or older way:
git reset HEAD file.txt

# Unstage all files
git restore --staged .
# or:
git reset HEAD

# Unstage and discard changes (combined)
git restore --staged --worktree file.txt`}
            />

            {/* git reset Explained */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Understanding git reset
            </Typography>
            <Typography paragraph>
              <code>git reset</code> moves the HEAD pointer and optionally modifies staging area and working directory:
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>--soft</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Move HEAD only. Keep staged and working dir.</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block" }}>Safest. Good for re-committing.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.08), border: `1px solid ${alpha("#f59e0b", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>--mixed (default)</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Move HEAD, reset staging. Keep working dir.</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block" }}>Good for re-staging differently.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.08), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>--hard</Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>Move HEAD, reset staging AND working dir.</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", display: "block" }}>DANGEROUS! Loses all changes.</Typography>
                </Paper>
              </Grid>
            </Grid>
            <CodeBlock
              title="git reset examples"
              code={`# Undo last commit, keep changes staged
git reset --soft HEAD~1

# Undo last commit, unstage changes (keep in working dir)
git reset HEAD~1
git reset --mixed HEAD~1  # same thing

# Undo last commit AND discard all changes
git reset --hard HEAD~1

# Go back 3 commits
git reset --hard HEAD~3

# Reset to specific commit
git reset --hard abc1234`}
            />

            {/* git revert */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              git revert: Safe Undo for Public Commits
            </Typography>
            <Typography paragraph>
              <code>git revert</code> creates a NEW commit that undoes the changes. It's safe for shared branches because it doesn't rewrite history.
            </Typography>
            <CodeBlock
              title="git revert examples"
              code={`# Revert the last commit
git revert HEAD

# Revert a specific commit
git revert abc1234

# Revert without auto-commit (stage changes only)
git revert --no-commit abc1234

# Revert multiple commits
git revert HEAD~3..HEAD  # Revert last 3 commits

# Revert a merge commit (specify parent)
git revert -m 1 abc1234  # -m 1 keeps first parent`}
            />
            <Box sx={{ mt: 2 }} />
            <InfoBox title="reset vs revert">
              Use <code>reset</code> for local/unpushed commits (rewrites history).<br/>
              Use <code>revert</code> for pushed commits (creates new commit, safe for collaboration).
            </InfoBox>

            {/* Reflog - Recovering Lost Commits */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Recovering Lost Commits with Reflog
            </Typography>
            <Typography paragraph>
              The reflog records every time HEAD moves. Even after <code>reset --hard</code>, you can usually recover:
            </Typography>
            <CodeBlock
              title="Using reflog to recover"
              code={`# View reflog (history of HEAD movements)
git reflog
# Output:
abc1234 HEAD@{0}: reset: moving to HEAD~3
def5678 HEAD@{1}: commit: Add feature
ghi9012 HEAD@{2}: commit: Fix bug
...

# Recover by resetting to a reflog entry
git reset --hard HEAD@{1}
# or use the commit hash:
git reset --hard def5678

# Create a branch from lost commit
git branch recovered-work def5678`}
            />
            <Box sx={{ mt: 2 }} />
            <ProTip>
              The reflog is your safety net! Commits aren't truly lost until Git's garbage collection runs (usually 30+ days).
              If you accidentally reset --hard, don't panic—check the reflog immediately.
            </ProTip>
          </Paper>

          {/* ==================== SECTION 12: ADVANCED TOPICS ==================== */}
          <Paper
            id="advanced-topics"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
              <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
                <SpeedIcon sx={{ color: "#f14e32" }} />
                Advanced Git Topics
              </Typography>
              <DifficultyBadge level="advanced" />
            </Box>

            {/* Git Stash */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              Git Stash: Saving Work Temporarily
            </Typography>
            <Typography paragraph>
              Stash lets you save uncommitted changes and switch contexts. Perfect for "I need to switch branches but I'm not ready to commit."
            </Typography>
            <CodeBlock
              title="Git stash commands"
              code={`# Stash current changes (staged + unstaged)
git stash
git stash push -m "Work in progress on feature"  # with message

# Stash including untracked files
git stash -u
# or:
git stash --include-untracked

# List all stashes
git stash list
# Output:
# stash@{0}: WIP on main: abc1234 Last commit message
# stash@{1}: On feature: def5678 Another stash

# Apply most recent stash (keeps stash)
git stash apply

# Apply and remove stash
git stash pop

# Apply specific stash
git stash apply stash@{2}

# View stash contents
git stash show -p stash@{0}

# Delete stashes
git stash drop stash@{0}   # Delete specific
git stash clear            # Delete ALL stashes`}
            />
            <Box sx={{ mt: 2 }} />
            <ProTip>
              Stashes are local-only and can be lost if you're not careful. For important WIP, consider creating a temporary commit
              or WIP branch instead.
            </ProTip>

            {/* Cherry-Pick */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Cherry-Picking Commits
            </Typography>
            <Typography paragraph>
              Cherry-pick applies a specific commit from one branch to another. Useful for applying bug fixes without merging entire branches.
            </Typography>
            <CodeBlock
              title="Cherry-pick examples"
              code={`# Apply a specific commit to current branch
git cherry-pick abc1234

# Cherry-pick without auto-committing
git cherry-pick --no-commit abc1234

# Cherry-pick multiple commits
git cherry-pick abc1234 def5678 ghi9012

# Cherry-pick a range of commits
git cherry-pick abc1234..ghi9012

# If conflicts occur:
git cherry-pick --continue   # after resolving
git cherry-pick --abort      # cancel
git cherry-pick --skip       # skip this commit`}
            />

            {/* Git Bisect */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Git Bisect: Finding Bugs with Binary Search
            </Typography>
            <Typography paragraph>
              Bisect performs a binary search through your commit history to find which commit introduced a bug.
            </Typography>
            <CodeBlock
              title="Using git bisect"
              code={`# Start bisecting
git bisect start

# Mark current commit as bad (has the bug)
git bisect bad

# Mark a known good commit (before the bug existed)
git bisect good abc1234

# Git checks out a commit in the middle
# Test your code, then mark it:
git bisect good   # if bug not present
git bisect bad    # if bug is present

# Repeat until Git finds the first bad commit
# Output: abc1234 is the first bad commit

# End bisect and return to original branch
git bisect reset

# Automated bisect with a test script
git bisect run npm test
# Script should exit 0 for good, non-zero for bad`}
            />

            {/* Git Hooks */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Git Hooks: Automated Actions
            </Typography>
            <Typography paragraph>
              Hooks are scripts that run automatically at certain Git events. They live in <code>.git/hooks/</code>.
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.3)}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Client-Side Hooks</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>
                    pre-commit → Before commit is made<br/>
                    prepare-commit-msg → Edit default message<br/>
                    commit-msg → Validate commit message<br/>
                    pre-push → Before push to remote
                  </Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.3)}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Server-Side Hooks</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.8rem" }}>
                    pre-receive → Before accepting push<br/>
                    update → Per branch before update<br/>
                    post-receive → After push complete<br/>
                  </Typography>
                </Paper>
              </Grid>
            </Grid>
            <CodeBlock
              title="Example: pre-commit hook for linting"
              code={`#!/bin/sh
# .git/hooks/pre-commit

# Run linter
npm run lint

# If linter fails, prevent commit
if [ $? -ne 0 ]; then
  echo "Lint failed! Fix errors before committing."
  exit 1
fi

# Run tests
npm test
if [ $? -ne 0 ]; then
  echo "Tests failed!"
  exit 1
fi

exit 0`}
            />
            <Box sx={{ mt: 2 }} />
            <InfoBox title="Use Husky for easier hooks">
              The <code>husky</code> npm package makes managing Git hooks easier and allows committing hooks to your repo
              (normally .git/hooks isn't tracked). Install: <code>npx husky-init</code>
            </InfoBox>

            {/* Worktrees */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Git Worktrees: Multiple Working Directories
            </Typography>
            <Typography paragraph>
              Worktrees let you have multiple branches checked out simultaneously in different directories.
            </Typography>
            <CodeBlock
              title="Using worktrees"
              code={`# Create a new worktree for a branch
git worktree add ../hotfix-directory hotfix-branch

# Create worktree with new branch
git worktree add -b feature/new ../feature-dir

# List all worktrees
git worktree list

# Remove a worktree
git worktree remove ../hotfix-directory

# Use case: Review PR while keeping your work
git worktree add ../pr-review origin/pr-branch
cd ../pr-review
# Review, test, then return to main worktree`}
            />

            {/* Git LFS */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Git LFS: Large File Storage
            </Typography>
            <Typography paragraph>
              Git LFS stores large files (images, videos, binaries) on a separate server, keeping your repo fast.
            </Typography>
            <CodeBlock
              title="Setting up Git LFS"
              code={`# Install Git LFS
git lfs install

# Track large file types
git lfs track "*.psd"
git lfs track "*.zip"
git lfs track "videos/*"

# This creates/updates .gitattributes
cat .gitattributes
# *.psd filter=lfs diff=lfs merge=lfs -text

# Commit the .gitattributes file
git add .gitattributes
git commit -m "Configure Git LFS"

# Now add large files normally
git add design.psd
git commit -m "Add design file"

# View tracked patterns
git lfs track

# View LFS files
git lfs ls-files`}
            />
            <Box sx={{ mt: 2 }} />
            <WarningBox title="LFS has storage limits">
              GitHub, GitLab, and Bitbucket have LFS storage quotas (GitHub: 1GB free). Large repos may need paid plans
              or self-hosted LFS servers.
            </WarningBox>
          </Paper>

          {/* ==================== SECTION 13: GITHUB ==================== */}
          <Paper
            id="github"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
              <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
                <CloudIcon sx={{ color: "#f14e32" }} />
                GitHub
              </Typography>
              <DifficultyBadge level="beginner" />
            </Box>

            {/* What is GitHub */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              What is GitHub?
            </Typography>
            <Typography paragraph>
              GitHub is the world's largest code hosting platform, with over 100 million developers. It adds collaboration features on top of Git:
              pull requests, issues, project boards, wikis, and CI/CD with GitHub Actions.
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, height: "100%" }}>
                  <Typography variant="h4" sx={{ fontWeight: 700, color: "#f14e32" }}>100M+</Typography>
                  <Typography variant="body2">Developers</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, height: "100%" }}>
                  <Typography variant="h4" sx={{ fontWeight: 700, color: "#f14e32" }}>420M+</Typography>
                  <Typography variant="body2">Repositories</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, height: "100%" }}>
                  <Typography variant="h4" sx={{ fontWeight: 700, color: "#f14e32" }}>4B+</Typography>
                  <Typography variant="body2">Contributions/year</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={3}>
                <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, height: "100%" }}>
                  <Typography variant="h4" sx={{ fontWeight: 700, color: "#f14e32" }}>90%</Typography>
                  <Typography variant="body2">Fortune 100 use it</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Key Features */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Key GitHub Features
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.3)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Pull Requests</Typography>
                  <Typography variant="body2">Propose changes, get code reviews, discuss modifications before merging. The heart of GitHub collaboration.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.3)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>GitHub Actions</Typography>
                  <Typography variant="body2">Automate workflows with CI/CD. Run tests, build, deploy on every push or PR. Free for public repos.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.3)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>Issues & Projects</Typography>
                  <Typography variant="body2">Track bugs, features, and tasks. Kanban boards for project management. Link issues to PRs.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, border: `1px solid ${alpha("#8b5cf6", 0.3)}`, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 1 }}>GitHub Copilot</Typography>
                  <Typography variant="body2">AI pair programmer that suggests code in your editor. Trained on public repositories.</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* GitHub CLI */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              GitHub CLI (gh)
            </Typography>
            <Typography paragraph>
              The official GitHub command-line tool for managing GitHub from your terminal:
            </Typography>
            <CodeBlock
              title="GitHub CLI essentials"
              code={`# Install GitHub CLI
# macOS: brew install gh
# Windows: winget install GitHub.cli

# Authenticate with GitHub
gh auth login

# Clone a repository
gh repo clone owner/repo

# Create a new repository
gh repo create my-project --public --source=. --remote=origin

# Create a pull request
gh pr create --title "Add feature" --body "Description here"

# List open pull requests
gh pr list

# Check out a PR locally
gh pr checkout 123

# Merge a PR
gh pr merge 123 --merge

# Create an issue
gh issue create --title "Bug report" --body "Description"

# View repo in browser
gh browse`}
            />

            {/* GitHub Actions */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              GitHub Actions: CI/CD
            </Typography>
            <Typography paragraph>
              Automate testing, building, and deployment with workflow files in <code>.github/workflows/</code>:
            </Typography>
            <CodeBlock
              title=".github/workflows/ci.yml"
              code={`name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run tests
        run: npm test
      
      - name: Build
        run: npm run build`}
            />
            <Box sx={{ mt: 2 }} />
            <ProTip>
              GitHub Actions are free for public repositories and include 2,000 minutes/month for private repos on free tier.
              Use the Actions Marketplace for pre-built actions.
            </ProTip>

            {/* GitHub Pages */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              GitHub Pages
            </Typography>
            <Typography paragraph>
              Free static website hosting directly from your repository:
            </Typography>
            <List dense>
              <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Free hosting for static sites" secondary="Perfect for documentation, portfolios, project pages" /></ListItem>
              <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Custom domains supported" secondary="Use your own domain with free HTTPS" /></ListItem>
              <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Automatic deployment" secondary="Publish from main branch or gh-pages branch" /></ListItem>
              <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Jekyll integration" secondary="Built-in support for Jekyll static site generator" /></ListItem>
            </List>

            {/* GitHub Special Files */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Special GitHub Files
            </Typography>
            <Paper sx={{ overflow: "hidden", borderRadius: 2, mb: 3 }}>
              <Box component="table" sx={{ width: "100%", borderCollapse: "collapse", "& td, & th": { p: 1.5, borderBottom: "1px solid", borderColor: "divider", textAlign: "left" }, "& th": { bgcolor: alpha("#f14e32", 0.08), fontWeight: 700 } }}>
                <thead><tr><th style={{width: "30%"}}>File</th><th>Purpose</th></tr></thead>
                <tbody>
                  <tr><td><code>README.md</code></td><td>Repository description, shown on repo homepage</td></tr>
                  <tr><td><code>LICENSE</code></td><td>License for your project (MIT, Apache, GPL, etc.)</td></tr>
                  <tr><td><code>CONTRIBUTING.md</code></td><td>Contribution guidelines for collaborators</td></tr>
                  <tr><td><code>CODE_OF_CONDUCT.md</code></td><td>Community behavior expectations</td></tr>
                  <tr><td><code>SECURITY.md</code></td><td>Security policy and vulnerability reporting</td></tr>
                  <tr><td><code>.github/ISSUE_TEMPLATE/</code></td><td>Templates for bug reports, feature requests</td></tr>
                  <tr><td><code>.github/PULL_REQUEST_TEMPLATE.md</code></td><td>Default PR description template</td></tr>
                  <tr><td><code>CODEOWNERS</code></td><td>Auto-assign reviewers based on file paths</td></tr>
                </tbody>
              </Box>
            </Paper>
          </Paper>

          {/* ==================== SECTION 14: GITLAB ==================== */}
          <Paper
            id="gitlab"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
              <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
                <CloudIcon sx={{ color: "#f14e32" }} />
                GitLab
              </Typography>
              <DifficultyBadge level="beginner" />
            </Box>

            {/* What is GitLab */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              What is GitLab?
            </Typography>
            <Typography paragraph>
              GitLab is a complete DevOps platform delivered as a single application. Unlike GitHub, it provides built-in CI/CD,
              container registry, security scanning, and more—all in one place. It's popular in enterprises and can be self-hosted.
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, bgcolor: alpha("#fc6d26", 0.08), height: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#fc6d26" }}>All-in-One</Typography>
                  <Typography variant="body2">SCM, CI/CD, Security, and Monitoring in a single platform</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, bgcolor: alpha("#fc6d26", 0.08), height: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#fc6d26" }}>Self-Hosted</Typography>
                  <Typography variant="body2">Run on your own servers for complete control and privacy</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, bgcolor: alpha("#fc6d26", 0.08), height: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#fc6d26" }}>Open Core</Typography>
                  <Typography variant="body2">Open source Community Edition available for free</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* GitLab vs GitHub */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              GitLab vs GitHub
            </Typography>
            <Paper sx={{ overflow: "hidden", borderRadius: 2, mb: 3 }}>
              <Box component="table" sx={{ width: "100%", borderCollapse: "collapse", "& td, & th": { p: 1.5, borderBottom: "1px solid", borderColor: "divider", textAlign: "left" }, "& th": { bgcolor: alpha("#f14e32", 0.08), fontWeight: 700 } }}>
                <thead><tr><th>Feature</th><th>GitHub</th><th>GitLab</th></tr></thead>
                <tbody>
                  <tr><td>CI/CD</td><td>GitHub Actions (separate)</td><td>Built-in GitLab CI/CD</td></tr>
                  <tr><td>Self-Hosting</td><td>Enterprise only (paid)</td><td>Free Community Edition</td></tr>
                  <tr><td>Container Registry</td><td>GitHub Packages</td><td>Built-in registry</td></tr>
                  <tr><td>Security Scanning</td><td>Dependabot, CodeQL</td><td>SAST, DAST, Dependency Scanning</td></tr>
                  <tr><td>Issue Tracking</td><td>Issues + Projects</td><td>Issues + Boards + Epics</td></tr>
                  <tr><td>PR/MR Name</td><td>Pull Request</td><td>Merge Request</td></tr>
                  <tr><td>Best For</td><td>Open source, community</td><td>Enterprise, DevOps teams</td></tr>
                </tbody>
              </Box>
            </Paper>

            {/* GitLab CI/CD */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              GitLab CI/CD (.gitlab-ci.yml)
            </Typography>
            <Typography paragraph>
              GitLab CI/CD is configured with a <code>.gitlab-ci.yml</code> file in your repository root:
            </Typography>
            <CodeBlock
              title=".gitlab-ci.yml example"
              code={`stages:
  - build
  - test
  - deploy

variables:
  NODE_VERSION: "20"

build:
  stage: build
  image: node:$NODE_VERSION
  script:
    - npm ci
    - npm run build
  artifacts:
    paths:
      - dist/
    expire_in: 1 hour

test:
  stage: test
  image: node:$NODE_VERSION
  script:
    - npm ci
    - npm test
  coverage: '/Coverage: \\d+\\.\\d+%/'

deploy_staging:
  stage: deploy
  script:
    - echo "Deploying to staging..."
  environment:
    name: staging
    url: https://staging.example.com
  only:
    - develop

deploy_production:
  stage: deploy
  script:
    - echo "Deploying to production..."
  environment:
    name: production
    url: https://example.com
  only:
    - main
  when: manual`}
            />
            <Box sx={{ mt: 2 }} />
            <InfoBox title="GitLab CI/CD Terminology">
              <strong>Pipeline:</strong> A collection of jobs organized in stages.<br/>
              <strong>Job:</strong> Individual tasks that run scripts (build, test, deploy).<br/>
              <strong>Stage:</strong> Groups of jobs that run in sequence.<br/>
              <strong>Runner:</strong> The server that executes jobs (shared or self-hosted).
            </InfoBox>

            {/* Merge Requests */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Merge Requests (MRs)
            </Typography>
            <Typography paragraph>
              GitLab calls them Merge Requests instead of Pull Requests. The workflow is similar:
            </Typography>
            <CodeBlock
              title="Creating a Merge Request"
              code={`# Using GitLab CLI (glab)
glab mr create --title "Add feature" --description "Details here"

# List open MRs
glab mr list

# Check out an MR locally
glab mr checkout 123

# Approve an MR
glab mr approve 123

# Merge an MR
glab mr merge 123

# Using Git push options (no CLI needed)
git push -o merge_request.create \
  -o merge_request.target=main \
  -o merge_request.title="My feature"`}
            />

            {/* GitLab Features */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Unique GitLab Features
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#fc6d26", mb: 1 }}>Auto DevOps</Typography>
                  <Typography variant="body2">Automatically detects your project type and sets up CI/CD pipelines, security scanning, and deployment with zero configuration.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#fc6d26", mb: 1 }}>Built-in Security</Typography>
                  <Typography variant="body2">SAST, DAST, dependency scanning, container scanning, and secret detection built into the platform.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#fc6d26", mb: 1 }}>GitLab Pages</Typography>
                  <Typography variant="body2">Free static website hosting similar to GitHub Pages. Supports custom domains and SSL.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#fc6d26", mb: 1 }}>Kubernetes Integration</Typography>
                  <Typography variant="body2">Native Kubernetes integration for deployment, monitoring, and cluster management.</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* GitLab CLI */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              GitLab CLI (glab)
            </Typography>
            <CodeBlock
              title="GitLab CLI essentials"
              code={`# Install GitLab CLI
# macOS: brew install glab
# Windows: winget install GLab.GLab

# Authenticate
glab auth login

# Clone a repo
glab repo clone owner/repo

# Create a new project
glab repo create my-project

# Create an issue
glab issue create --title "Bug" --description "Details"

# List issues
glab issue list

# View CI pipeline status
glab ci status

# View pipeline jobs
glab ci list

# Open repo in browser
glab repo view --web`}
            />
            <Box sx={{ mt: 2 }} />
            <ProTip>
              GitLab offers a generous free tier including unlimited private repos, 5 users per group, 400 CI/CD minutes/month,
              and 5GB storage. The Community Edition can be self-hosted for free with no user limits.
            </ProTip>
          </Paper>

          {/* ==================== SECTION 15: BEST PRACTICES ==================== */}
          <Paper
            id="best-practices"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
              <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
                <CheckCircleIcon sx={{ color: "#f14e32" }} />
                Git Best Practices
              </Typography>
              <DifficultyBadge level="intermediate" />
            </Box>

            {/* Commit Practices */}
            <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f14e32" }}>
              Commit Best Practices
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>✓ Do</Typography>
                  <List dense>
                    <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Commit early and commit often" /></ListItem>
                    <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Write clear, descriptive commit messages" /></ListItem>
                    <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Keep commits atomic (one logical change)" /></ListItem>
                    <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Test before committing" /></ListItem>
                    <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Review your diff before committing" /></ListItem>
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ef4444", 0.08), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2, height: "100%" }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>✗ Don't</Typography>
                  <List dense>
                    <ListItem><ListItemIcon><WarningIcon color="error" fontSize="small" /></ListItemIcon><ListItemText primary="Commit broken code to shared branches" /></ListItem>
                    <ListItem><ListItemIcon><WarningIcon color="error" fontSize="small" /></ListItemIcon><ListItemText primary="Use vague messages like 'fix' or 'update'" /></ListItem>
                    <ListItem><ListItemIcon><WarningIcon color="error" fontSize="small" /></ListItemIcon><ListItemText primary="Bundle unrelated changes in one commit" /></ListItem>
                    <ListItem><ListItemIcon><WarningIcon color="error" fontSize="small" /></ListItemIcon><ListItemText primary="Commit sensitive data (passwords, keys)" /></ListItem>
                    <ListItem><ListItemIcon><WarningIcon color="error" fontSize="small" /></ListItemIcon><ListItemText primary="Commit generated files or dependencies" /></ListItem>
                  </List>
                </Paper>
              </Grid>
            </Grid>

            {/* .gitignore Best Practices */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              .gitignore Best Practices
            </Typography>
            <Typography paragraph>
              A well-configured .gitignore prevents unnecessary files from cluttering your repository:
            </Typography>
            <CodeBlock
              title="Common .gitignore patterns"
              code={`# Dependencies
node_modules/
vendor/
__pycache__/
venv/

# Build outputs
dist/
build/
*.exe
*.dll
*.class

# IDE & Editor files
.vscode/
.idea/
*.swp
*.swo
.DS_Store

# Environment & secrets
.env
.env.local
*.pem
*.key
secrets.json

# Logs & temporary files
*.log
logs/
tmp/
*.tmp

# OS files
Thumbs.db
.DS_Store`}
            />
            <Box sx={{ mt: 2 }} />
            <ProTip>
              Use <code>gitignore.io</code> to generate .gitignore files for your tech stack.
              Run: <code>curl -sL https://www.toptal.com/developers/gitignore/api/node,react,visualstudiocode</code>
            </ProTip>

            {/* Branch Hygiene */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Branch Hygiene
            </Typography>
            <List>
              <ListItem><ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon><ListItemText primary="Delete branches after merging" secondary="Keep your branch list clean. Use 'git branch -d' after PRs are merged." /></ListItem>
              <ListItem><ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon><ListItemText primary="Use descriptive branch names" secondary="feature/user-auth, bugfix/login-error, hotfix/security-patch" /></ListItem>
              <ListItem><ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon><ListItemText primary="Keep branches short-lived" secondary="Long-running feature branches lead to painful merges. Merge frequently." /></ListItem>
              <ListItem><ListItemIcon><CheckCircleIcon color="success" /></ListItemIcon><ListItemText primary="Protect important branches" secondary="Configure branch protection rules to require reviews and passing CI." /></ListItem>
            </List>

            {/* Collaboration Tips */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Collaboration Tips
            </Typography>
            <Grid container spacing={2} sx={{ mb: 3 }}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, height: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>Pull Before Push</Typography>
                  <Typography variant="body2">Always <code>git pull</code> before pushing to avoid conflicts and rejected pushes.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, height: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>Review Before Merge</Typography>
                  <Typography variant="body2">Never merge your own PRs without review in team projects. Fresh eyes catch bugs.</Typography>
                </Paper>
              </Grid>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 2, textAlign: "center", borderRadius: 2, height: "100%" }}>
                  <Typography variant="h6" sx={{ fontWeight: 700, color: "#f59e0b", mb: 1 }}>Communicate Changes</Typography>
                  <Typography variant="body2">Announce breaking changes. Tag releases. Keep changelog updated.</Typography>
                </Paper>
              </Grid>
            </Grid>

            {/* Security Considerations */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }}>
              Security Best Practices
            </Typography>
            <WarningBox title="Never commit secrets!">
              API keys, passwords, tokens, and private keys should NEVER be in your repository. Even if you delete them later,
              they remain in Git history. Use environment variables and secret management tools instead.
            </WarningBox>
            <Box sx={{ mt: 2 }} />
            <List dense>
              <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Use environment variables for secrets" /></ListItem>
              <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Add secret patterns to .gitignore (.env, *.pem, *.key)" /></ListItem>
              <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Use git-secrets or pre-commit hooks to prevent accidental commits" /></ListItem>
              <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Rotate any secrets that were accidentally committed" /></ListItem>
              <ListItem><ListItemIcon><CheckCircleIcon color="success" fontSize="small" /></ListItemIcon><ListItemText primary="Sign commits with GPG for verified identity" /></ListItem>
            </List>
          </Paper>

          {/* ==================== SECTION 14: COMMAND REFERENCE ==================== */}
          <Paper
            id="common-commands"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
              <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
                <TerminalIcon sx={{ color: "#f14e32" }} />
                Git Command Reference
              </Typography>
            </Box>
            <Typography paragraph>
              A comprehensive reference of essential Git commands organized by category. Bookmark this section!
            </Typography>

            {/* Setup & Config */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 3, mb: 2, color: "#f14e32" }}>
              🛠️ Setup & Configuration
            </Typography>
            <Paper sx={{ overflow: "hidden", borderRadius: 2, mb: 3 }}>
              <Box component="table" sx={{ width: "100%", borderCollapse: "collapse", "& td, & th": { p: 1.5, borderBottom: "1px solid", borderColor: "divider", textAlign: "left" }, "& th": { bgcolor: alpha("#f14e32", 0.08), fontWeight: 700 } }}>
                <thead><tr><th style={{width: "35%"}}>Command</th><th>Description</th></tr></thead>
                <tbody>
                  <tr><td><code>git config --global user.name "Name"</code></td><td>Set your name for all repos</td></tr>
                  <tr><td><code>git config --global user.email "email"</code></td><td>Set your email for all repos</td></tr>
                  <tr><td><code>git config --list</code></td><td>View all configuration settings</td></tr>
                  <tr><td><code>git init</code></td><td>Initialize a new Git repository</td></tr>
                  <tr><td><code>git clone &lt;url&gt;</code></td><td>Clone a remote repository</td></tr>
                </tbody>
              </Box>
            </Paper>

            {/* Basic Snapshotting */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 3, mb: 2, color: "#f14e32" }}>
              📸 Basic Snapshotting
            </Typography>
            <Paper sx={{ overflow: "hidden", borderRadius: 2, mb: 3 }}>
              <Box component="table" sx={{ width: "100%", borderCollapse: "collapse", "& td, & th": { p: 1.5, borderBottom: "1px solid", borderColor: "divider", textAlign: "left" }, "& th": { bgcolor: alpha("#f14e32", 0.08), fontWeight: 700 } }}>
                <thead><tr><th style={{width: "35%"}}>Command</th><th>Description</th></tr></thead>
                <tbody>
                  <tr><td><code>git status</code></td><td>Show working directory status</td></tr>
                  <tr><td><code>git add &lt;file&gt;</code></td><td>Stage a specific file</td></tr>
                  <tr><td><code>git add .</code></td><td>Stage all changes in current directory</td></tr>
                  <tr><td><code>git add -A</code></td><td>Stage all changes (entire repo)</td></tr>
                  <tr><td><code>git commit -m "message"</code></td><td>Commit staged changes with message</td></tr>
                  <tr><td><code>git commit --amend</code></td><td>Modify the last commit</td></tr>
                  <tr><td><code>git diff</code></td><td>Show unstaged changes</td></tr>
                  <tr><td><code>git diff --staged</code></td><td>Show staged changes</td></tr>
                  <tr><td><code>git restore &lt;file&gt;</code></td><td>Discard changes in working directory</td></tr>
                  <tr><td><code>git restore --staged &lt;file&gt;</code></td><td>Unstage a file</td></tr>
                </tbody>
              </Box>
            </Paper>

            {/* Branching & Merging */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 3, mb: 2, color: "#f14e32" }}>
              🌳 Branching & Merging
            </Typography>
            <Paper sx={{ overflow: "hidden", borderRadius: 2, mb: 3 }}>
              <Box component="table" sx={{ width: "100%", borderCollapse: "collapse", "& td, & th": { p: 1.5, borderBottom: "1px solid", borderColor: "divider", textAlign: "left" }, "& th": { bgcolor: alpha("#f14e32", 0.08), fontWeight: 700 } }}>
                <thead><tr><th style={{width: "35%"}}>Command</th><th>Description</th></tr></thead>
                <tbody>
                  <tr><td><code>git branch</code></td><td>List local branches</td></tr>
                  <tr><td><code>git branch &lt;name&gt;</code></td><td>Create a new branch</td></tr>
                  <tr><td><code>git branch -d &lt;name&gt;</code></td><td>Delete a merged branch</td></tr>
                  <tr><td><code>git branch -D &lt;name&gt;</code></td><td>Force delete a branch</td></tr>
                  <tr><td><code>git switch &lt;branch&gt;</code></td><td>Switch to a branch</td></tr>
                  <tr><td><code>git switch -c &lt;branch&gt;</code></td><td>Create and switch to branch</td></tr>
                  <tr><td><code>git checkout &lt;branch&gt;</code></td><td>Switch branches (legacy)</td></tr>
                  <tr><td><code>git merge &lt;branch&gt;</code></td><td>Merge branch into current</td></tr>
                  <tr><td><code>git rebase &lt;branch&gt;</code></td><td>Rebase current onto branch</td></tr>
                  <tr><td><code>git rebase -i HEAD~n</code></td><td>Interactive rebase last n commits</td></tr>
                </tbody>
              </Box>
            </Paper>

            {/* Remote Operations */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 3, mb: 2, color: "#f14e32" }}>
              ☁️ Remote Operations
            </Typography>
            <Paper sx={{ overflow: "hidden", borderRadius: 2, mb: 3 }}>
              <Box component="table" sx={{ width: "100%", borderCollapse: "collapse", "& td, & th": { p: 1.5, borderBottom: "1px solid", borderColor: "divider", textAlign: "left" }, "& th": { bgcolor: alpha("#f14e32", 0.08), fontWeight: 700 } }}>
                <thead><tr><th style={{width: "35%"}}>Command</th><th>Description</th></tr></thead>
                <tbody>
                  <tr><td><code>git remote -v</code></td><td>List remotes with URLs</td></tr>
                  <tr><td><code>git remote add &lt;name&gt; &lt;url&gt;</code></td><td>Add a new remote</td></tr>
                  <tr><td><code>git fetch</code></td><td>Download from remote (no merge)</td></tr>
                  <tr><td><code>git pull</code></td><td>Fetch and merge remote changes</td></tr>
                  <tr><td><code>git push</code></td><td>Upload commits to remote</td></tr>
                  <tr><td><code>git push -u origin &lt;branch&gt;</code></td><td>Push and set upstream</td></tr>
                  <tr><td><code>git push --force-with-lease</code></td><td>Safe force push</td></tr>
                </tbody>
              </Box>
            </Paper>

            {/* Inspection & History */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 3, mb: 2, color: "#f14e32" }}>
              🔍 Inspection & History
            </Typography>
            <Paper sx={{ overflow: "hidden", borderRadius: 2, mb: 3 }}>
              <Box component="table" sx={{ width: "100%", borderCollapse: "collapse", "& td, & th": { p: 1.5, borderBottom: "1px solid", borderColor: "divider", textAlign: "left" }, "& th": { bgcolor: alpha("#f14e32", 0.08), fontWeight: 700 } }}>
                <thead><tr><th style={{width: "35%"}}>Command</th><th>Description</th></tr></thead>
                <tbody>
                  <tr><td><code>git log</code></td><td>Show commit history</td></tr>
                  <tr><td><code>git log --oneline</code></td><td>Compact commit history</td></tr>
                  <tr><td><code>git log --graph --all</code></td><td>Visual branch history</td></tr>
                  <tr><td><code>git show &lt;commit&gt;</code></td><td>Show commit details</td></tr>
                  <tr><td><code>git blame &lt;file&gt;</code></td><td>Show who changed each line</td></tr>
                  <tr><td><code>git reflog</code></td><td>Show HEAD movement history</td></tr>
                </tbody>
              </Box>
            </Paper>

            {/* Undoing Changes */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 3, mb: 2, color: "#f14e32" }}>
              ↩️ Undoing Changes
            </Typography>
            <Paper sx={{ overflow: "hidden", borderRadius: 2, mb: 3 }}>
              <Box component="table" sx={{ width: "100%", borderCollapse: "collapse", "& td, & th": { p: 1.5, borderBottom: "1px solid", borderColor: "divider", textAlign: "left" }, "& th": { bgcolor: alpha("#f14e32", 0.08), fontWeight: 700 } }}>
                <thead><tr><th style={{width: "35%"}}>Command</th><th>Description</th></tr></thead>
                <tbody>
                  <tr><td><code>git reset --soft HEAD~1</code></td><td>Undo commit, keep staged</td></tr>
                  <tr><td><code>git reset HEAD~1</code></td><td>Undo commit, unstage changes</td></tr>
                  <tr><td><code>git reset --hard HEAD~1</code></td><td>Undo commit, discard changes</td></tr>
                  <tr><td><code>git revert &lt;commit&gt;</code></td><td>Create commit that undoes changes</td></tr>
                  <tr><td><code>git clean -fd</code></td><td>Remove untracked files/dirs</td></tr>
                </tbody>
              </Box>
            </Paper>

            {/* Advanced */}
            <Typography variant="h6" sx={{ fontWeight: 700, mt: 3, mb: 2, color: "#f14e32" }}>
              🚀 Advanced Commands
            </Typography>
            <Paper sx={{ overflow: "hidden", borderRadius: 2, mb: 3 }}>
              <Box component="table" sx={{ width: "100%", borderCollapse: "collapse", "& td, & th": { p: 1.5, borderBottom: "1px solid", borderColor: "divider", textAlign: "left" }, "& th": { bgcolor: alpha("#f14e32", 0.08), fontWeight: 700 } }}>
                <thead><tr><th style={{width: "35%"}}>Command</th><th>Description</th></tr></thead>
                <tbody>
                  <tr><td><code>git stash</code></td><td>Save uncommitted changes temporarily</td></tr>
                  <tr><td><code>git stash pop</code></td><td>Apply and remove latest stash</td></tr>
                  <tr><td><code>git cherry-pick &lt;commit&gt;</code></td><td>Apply specific commit to current branch</td></tr>
                  <tr><td><code>git bisect start</code></td><td>Start binary search for bug</td></tr>
                  <tr><td><code>git worktree add &lt;path&gt; &lt;branch&gt;</code></td><td>Create additional working directory</td></tr>
                  <tr><td><code>git tag &lt;name&gt;</code></td><td>Create a tag at current commit</td></tr>
                  <tr><td><code>git tag -a &lt;name&gt; -m "msg"</code></td><td>Create annotated tag</td></tr>
                </tbody>
              </Box>
            </Paper>

            <ProTip>
              Create aliases for commands you use frequently! For example: <code>git config --global alias.st status</code>
              lets you type <code>git st</code> instead of <code>git status</code>.
            </ProTip>
          </Paper>

          {/* ==================== SECTION 15: QUIZ ==================== */}
          <Paper
            id="quiz"
            sx={{
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }}>
              <Typography variant="h5" sx={{ fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }}>
                <QuizIcon sx={{ color: "#f14e32" }} />
                Test Your Knowledge
              </Typography>
            </Box>
            <QuizSection />
          </Paper>

        </Box>
      </Box>
    </LearnPageLayout>
  );
};

export default GitVersionControlPage;
