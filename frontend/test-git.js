// src/pages/GitVersionControlPage.tsx
import { useState, useEffect } from "react";
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
  LinearProgress
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
import { jsx, jsxs } from "react/jsx-runtime";
var questionBank = [
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
  { id: 75, question: "What does git reset --hard do?", options: ["Soft reset", "Discards all changes and resets to specified commit", "Resets config", "Creates a backup"], correctAnswer: 1, explanation: "git reset --hard discards all uncommitted changes and moves HEAD to the specified commit (use with caution).", topic: "Advanced Git" }
];
var CodeBlock = ({ code, title }) => /* @__PURE__ */ jsxs(
  Paper,
  {
    sx: {
      p: 2,
      borderRadius: 2,
      bgcolor: "rgba(0, 0, 0, 0.4)",
      border: "1px solid rgba(241, 78, 50, 0.2)"
    },
    children: [
      title && /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { color: "#f14e32", fontWeight: 600, mb: 1, display: "block" }, children: title }),
      /* @__PURE__ */ jsx(
        Box,
        {
          component: "pre",
          sx: {
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
            "& .number": { color: "#b5cea8" }
          },
          children: code
        }
      )
    ]
  }
);
var DifficultyBadge = ({ level }) => {
  const colors = {
    beginner: { bg: "#22c55e", text: "Beginner" },
    intermediate: { bg: "#f59e0b", text: "Intermediate" },
    advanced: { bg: "#ef4444", text: "Advanced" }
  };
  return /* @__PURE__ */ jsx(
    Chip,
    {
      label: colors[level].text,
      size: "small",
      sx: {
        bgcolor: alpha(colors[level].bg, 0.15),
        color: colors[level].bg,
        fontWeight: 700,
        fontSize: "0.7rem"
      }
    }
  );
};
var ProTip = ({ children }) => /* @__PURE__ */ jsxs(
  Paper,
  {
    sx: {
      p: 2,
      borderRadius: 2,
      bgcolor: alpha("#8b5cf6", 0.08),
      border: `1px solid ${alpha("#8b5cf6", 0.3)}`,
      display: "flex",
      gap: 1.5,
      alignItems: "flex-start"
    },
    children: [
      /* @__PURE__ */ jsx(LightbulbIcon, { sx: { color: "#8b5cf6", fontSize: 20, mt: 0.2 } }),
      /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { color: "text.primary" }, children })
    ]
  }
);
var WarningBox = ({ title, children }) => /* @__PURE__ */ jsx(
  Paper,
  {
    sx: {
      p: 2,
      borderRadius: 2,
      bgcolor: alpha("#f59e0b", 0.08),
      border: `1px solid ${alpha("#f59e0b", 0.3)}`
    },
    children: /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", gap: 1.5, alignItems: "flex-start" }, children: [
      /* @__PURE__ */ jsx(WarningIcon, { sx: { color: "#f59e0b", fontSize: 20, mt: 0.2 } }),
      /* @__PURE__ */ jsxs(Box, { children: [
        title && /* @__PURE__ */ jsx(Typography, { variant: "subtitle2", sx: { fontWeight: 700, color: "#f59e0b", mb: 0.5 }, children: title }),
        /* @__PURE__ */ jsx(Typography, { variant: "body2", children })
      ] })
    ] })
  }
);
var InfoBox = ({ title, children }) => /* @__PURE__ */ jsx(
  Paper,
  {
    sx: {
      p: 2,
      borderRadius: 2,
      bgcolor: alpha("#3b82f6", 0.08),
      border: `1px solid ${alpha("#3b82f6", 0.3)}`
    },
    children: /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", gap: 1.5, alignItems: "flex-start" }, children: [
      /* @__PURE__ */ jsx(InfoIcon, { sx: { color: "#3b82f6", fontSize: 20, mt: 0.2 } }),
      /* @__PURE__ */ jsxs(Box, { children: [
        title && /* @__PURE__ */ jsx(Typography, { variant: "subtitle2", sx: { fontWeight: 700, color: "#3b82f6", mb: 0.5 }, children: title }),
        /* @__PURE__ */ jsx(Typography, { variant: "body2", children })
      ] })
    ] })
  }
);
var QuizSection = () => {
  const [quizState, setQuizState] = useState("start");
  const [questions, setQuestions] = useState([]);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState({});
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
  const handleAnswerSelect = (answerIndex) => {
    if (showExplanation)
      return;
    setSelectedAnswers((prev) => ({
      ...prev,
      [currentQuestionIndex]: answerIndex
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
    return /* @__PURE__ */ jsxs(Box, { sx: { textAlign: "center", py: 4 }, children: [
      /* @__PURE__ */ jsx(QuizIcon, { sx: { fontSize: 64, color: "#f14e32", mb: 2 } }),
      /* @__PURE__ */ jsx(Typography, { variant: "h5", sx: { fontWeight: 700, mb: 2 }, children: "Git & Version Control Quiz" }),
      /* @__PURE__ */ jsxs(Typography, { variant: "body1", sx: { mb: 3, color: "text.secondary" }, children: [
        "Test your knowledge with ",
        QUESTIONS_PER_QUIZ,
        " random questions from our bank of ",
        questionBank.length,
        " questions."
      ] }),
      /* @__PURE__ */ jsx(Button, { variant: "contained", size: "large", onClick: startQuiz, sx: { bgcolor: "#f14e32" }, children: "Start Quiz" })
    ] });
  }
  if (quizState === "results") {
    const percentage = score / QUESTIONS_PER_QUIZ * 100;
    return /* @__PURE__ */ jsxs(Box, { sx: { textAlign: "center", py: 4 }, children: [
      /* @__PURE__ */ jsx(EmojiEventsIcon, { sx: { fontSize: 64, color: percentage >= 70 ? "#22c55e" : "#f59e0b", mb: 2 } }),
      /* @__PURE__ */ jsx(Typography, { variant: "h5", sx: { fontWeight: 700, mb: 2 }, children: "Quiz Complete!" }),
      /* @__PURE__ */ jsxs(Typography, { variant: "h4", sx: { fontWeight: 700, color: percentage >= 70 ? "#22c55e" : "#f59e0b", mb: 2 }, children: [
        score,
        " / ",
        QUESTIONS_PER_QUIZ
      ] }),
      /* @__PURE__ */ jsx(Typography, { variant: "body1", sx: { mb: 3, color: "text.secondary" }, children: percentage >= 90 ? "Outstanding! You're a Git expert!" : percentage >= 70 ? "Great job! You have solid Git knowledge." : percentage >= 50 ? "Good effort! Review the material and try again." : "Keep learning! Practice makes perfect." }),
      /* @__PURE__ */ jsx(Button, { variant: "contained", startIcon: /* @__PURE__ */ jsx(RefreshIcon, {}), onClick: startQuiz, sx: { bgcolor: "#f14e32" }, children: "Try Again" })
    ] });
  }
  return /* @__PURE__ */ jsxs(Box, { children: [
    /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }, children: [
      /* @__PURE__ */ jsx(Chip, { label: `Question ${currentQuestionIndex + 1} of ${QUESTIONS_PER_QUIZ}` }),
      /* @__PURE__ */ jsx(Chip, { label: currentQuestion.topic, variant: "outlined" })
    ] }),
    /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 600, mb: 3 }, children: currentQuestion.question }),
    /* @__PURE__ */ jsx(RadioGroup, { value: selectedAnswer ?? "", onChange: (e) => handleAnswerSelect(Number(e.target.value)), children: currentQuestion.options.map((option, index) => /* @__PURE__ */ jsx(
      Paper,
      {
        sx: {
          p: 2,
          mb: 1.5,
          borderRadius: 2,
          cursor: showExplanation ? "default" : "pointer",
          border: `2px solid ${showExplanation ? index === currentQuestion.correctAnswer ? "#22c55e" : index === selectedAnswer ? "#ef4444" : "transparent" : selectedAnswer === index ? "#f14e32" : "transparent"}`,
          bgcolor: showExplanation ? index === currentQuestion.correctAnswer ? alpha("#22c55e", 0.1) : index === selectedAnswer ? alpha("#ef4444", 0.1) : "background.paper" : "background.paper",
          "&:hover": {
            bgcolor: showExplanation ? void 0 : alpha("#f14e32", 0.05)
          }
        },
        onClick: () => !showExplanation && handleAnswerSelect(index),
        children: /* @__PURE__ */ jsx(
          FormControlLabel,
          {
            value: index,
            control: /* @__PURE__ */ jsx(Radio, { disabled: showExplanation }),
            label: option,
            sx: { width: "100%", m: 0 }
          }
        )
      },
      index
    )) }),
    showExplanation && /* @__PURE__ */ jsxs(Alert, { severity: isCorrect ? "success" : "error", sx: { mt: 2, mb: 2 }, children: [
      /* @__PURE__ */ jsx(AlertTitle, { children: isCorrect ? "Correct!" : "Incorrect" }),
      currentQuestion.explanation
    ] }),
    /* @__PURE__ */ jsx(Box, { sx: { display: "flex", justifyContent: "flex-end", gap: 2, mt: 3 }, children: !showExplanation ? /* @__PURE__ */ jsx(Button, { variant: "contained", onClick: handleCheckAnswer, disabled: selectedAnswer === void 0, sx: { bgcolor: "#f14e32" }, children: "Check Answer" }) : /* @__PURE__ */ jsx(Button, { variant: "contained", onClick: handleNextQuestion, sx: { bgcolor: "#f14e32" }, children: currentQuestionIndex < questions.length - 1 ? "Next Question" : "See Results" }) })
  ] });
};
var GitVersionControlPage = () => {
  const navigate = useNavigate();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState("");
  const pageContext = `Git & Version Control learning page - comprehensive guide covering version control fundamentals, Git basics, configuration, staging, committing, branching, merging, rebasing, remote repositories, collaboration workflows, undoing changes, and advanced Git topics. Includes 75-question quiz bank. Part of the Software Engineering section.`;
  const moduleNavItems = [
    { id: "introduction", label: "Introduction", icon: "\u{1F4D6}" },
    { id: "why-version-control", label: "Why Version Control?", icon: "\u{1F4A1}" },
    { id: "git-fundamentals", label: "Git Fundamentals", icon: "\u{1F333}" },
    { id: "configuration", label: "Configuration", icon: "\u2699\uFE0F" },
    { id: "basic-workflow", label: "Basic Workflow", icon: "\u{1F504}" },
    { id: "staging-committing", label: "Staging & Committing", icon: "\u{1F4BE}" },
    { id: "branching", label: "Branching", icon: "\u{1F33F}" },
    { id: "merging", label: "Merging & Rebasing", icon: "\u{1F500}" },
    { id: "remote-repos", label: "Remote Repositories", icon: "\u2601\uFE0F" },
    { id: "collaboration", label: "Collaboration", icon: "\u{1F465}" },
    { id: "undoing-changes", label: "Undoing Changes", icon: "\u23EA" },
    { id: "advanced-topics", label: "Advanced Topics", icon: "\u{1F680}" },
    { id: "github", label: "GitHub", icon: "\u{1F419}" },
    { id: "gitlab", label: "GitLab", icon: "\u{1F98A}" },
    { id: "best-practices", label: "Best Practices", icon: "\u2705" },
    { id: "common-commands", label: "Command Reference", icon: "\u{1F4CB}" },
    { id: "quiz", label: "Knowledge Quiz", icon: "\u2753" }
  ];
  const scrollToSection = (sectionId) => {
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
  const drawerContent = /* @__PURE__ */ jsxs(Box, { sx: { width: 280, p: 2 }, children: [
    /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }, children: [
      /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, color: "#f14e32" }, children: "\u{1F4D8} Modules" }),
      /* @__PURE__ */ jsx(IconButton, { onClick: () => setNavDrawerOpen(false), size: "small", children: /* @__PURE__ */ jsx(CloseIcon, {}) })
    ] }),
    /* @__PURE__ */ jsx(Divider, { sx: { mb: 2 } }),
    /* @__PURE__ */ jsx(List, { dense: true, children: moduleNavItems.map((item) => /* @__PURE__ */ jsxs(
      ListItem,
      {
        onClick: () => scrollToSection(item.id),
        sx: {
          borderRadius: 2,
          mb: 0.5,
          cursor: "pointer",
          bgcolor: activeSection === item.id ? alpha("#f14e32", 0.15) : "transparent",
          "&:hover": { bgcolor: alpha("#f14e32", 0.1) },
          transition: "all 0.2s"
        },
        children: [
          /* @__PURE__ */ jsx(ListItemIcon, { sx: { minWidth: 36, fontSize: "1.1rem" }, children: item.icon }),
          /* @__PURE__ */ jsx(
            ListItemText,
            {
              primary: item.label,
              primaryTypographyProps: {
                fontSize: "0.875rem",
                fontWeight: activeSection === item.id ? 700 : 500,
                color: activeSection === item.id ? "#f14e32" : "text.primary"
              }
            }
          )
        ]
      },
      item.id
    )) })
  ] });
  const sidebarNav = /* @__PURE__ */ jsxs(
    Box,
    {
      sx: {
        position: "sticky",
        top: 80,
        maxHeight: "calc(100vh - 100px)",
        overflowY: "auto",
        pr: 1,
        "&::-webkit-scrollbar": { width: 4 },
        "&::-webkit-scrollbar-thumb": { bgcolor: alpha("#f14e32", 0.3), borderRadius: 2 }
      },
      children: [
        /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", alignItems: "center", gap: 1, mb: 2 }, children: [
          /* @__PURE__ */ jsx(MenuBookIcon, { sx: { color: "#f14e32", fontSize: 20 } }),
          /* @__PURE__ */ jsx(Typography, { variant: "subtitle2", sx: { fontWeight: 700, color: "#f14e32" }, children: "Modules" })
        ] }),
        /* @__PURE__ */ jsx(Box, { sx: { display: "flex", flexDirection: "column", gap: 0.5 }, children: moduleNavItems.map((item, index) => {
          const isActive = activeSection === item.id;
          const progress = moduleNavItems.findIndex((m) => m.id === activeSection);
          const isCompleted = index < progress;
          return /* @__PURE__ */ jsxs(
            Box,
            {
              onClick: () => scrollToSection(item.id),
              sx: {
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
                transition: "all 0.15s ease"
              },
              children: [
                /* @__PURE__ */ jsx(Typography, { sx: { fontSize: "0.9rem", opacity: isCompleted ? 0.6 : 1 }, children: item.icon }),
                /* @__PURE__ */ jsx(
                  Typography,
                  {
                    sx: {
                      fontSize: "0.75rem",
                      fontWeight: isActive ? 700 : 500,
                      color: isActive ? "#f14e32" : isCompleted ? "text.secondary" : "text.primary",
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis"
                    },
                    children: item.label
                  }
                )
              ]
            },
            item.id
          );
        }) }),
        /* @__PURE__ */ jsxs(Box, { sx: { mt: 3, pt: 2, borderTop: `1px solid ${alpha("#f14e32", 0.1)}` }, children: [
          /* @__PURE__ */ jsx(Typography, { variant: "caption", color: "text.secondary", sx: { display: "block", mb: 1 }, children: "Progress" }),
          /* @__PURE__ */ jsx(
            LinearProgress,
            {
              variant: "determinate",
              value: (moduleNavItems.findIndex((m) => m.id === activeSection) + 1) / moduleNavItems.length * 100,
              sx: {
                height: 6,
                borderRadius: 3,
                bgcolor: alpha("#f14e32", 0.1),
                "& .MuiLinearProgress-bar": { bgcolor: "#f14e32", borderRadius: 3 }
              }
            }
          ),
          /* @__PURE__ */ jsxs(Typography, { variant: "caption", color: "text.secondary", sx: { display: "block", mt: 0.5, textAlign: "center" }, children: [
            moduleNavItems.findIndex((m) => m.id === activeSection) + 1,
            " / ",
            moduleNavItems.length
          ] })
        ] })
      ]
    }
  );
  const quickStats = [
    { label: "Modules", value: "14", color: "#f14e32" },
    { label: "Commands", value: "50+", color: "#22c55e" },
    { label: "Quiz Questions", value: "75", color: "#f59e0b" },
    { label: "Examples", value: "30+", color: "#8b5cf6" }
  ];
  return /* @__PURE__ */ jsxs(LearnPageLayout, { pageTitle: "Git & Version Control", pageContext, children: [
    /* @__PURE__ */ jsx(
      Drawer,
      {
        anchor: "left",
        open: navDrawerOpen,
        onClose: () => setNavDrawerOpen(false),
        sx: {
          "& .MuiDrawer-paper": { bgcolor: theme.palette.background.default },
          display: { xs: "block", lg: "none" }
        },
        children: drawerContent
      }
    ),
    /* @__PURE__ */ jsx(Tooltip, { title: "Module Navigation", placement: "left", children: /* @__PURE__ */ jsx(
      Fab,
      {
        color: "primary",
        onClick: () => setNavDrawerOpen(true),
        sx: {
          position: "fixed",
          bottom: isMobile ? 80 : 32,
          right: 32,
          bgcolor: "#f14e32",
          "&:hover": { bgcolor: "#d94429" },
          zIndex: 1e3,
          display: { xs: "flex", lg: "none" }
        },
        children: /* @__PURE__ */ jsx(ListAltIcon, {})
      }
    ) }),
    /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", gap: 4, maxWidth: 1400, mx: "auto", px: { xs: 2, md: 3 }, py: 4 }, children: [
      /* @__PURE__ */ jsx(
        Box,
        {
          sx: {
            display: { xs: "none", lg: "block" },
            width: 220,
            flexShrink: 0
          },
          children: sidebarNav
        }
      ),
      /* @__PURE__ */ jsxs(Box, { sx: { flex: 1, minWidth: 0 }, children: [
        /* @__PURE__ */ jsx(Button, { startIcon: /* @__PURE__ */ jsx(ArrowBackIcon, {}), onClick: () => navigate("/learn"), sx: { mb: 3 }, children: "Back to Learning Hub" }),
        /* @__PURE__ */ jsxs(
          Paper,
          {
            id: "introduction",
            sx: {
              p: 4,
              mb: 4,
              borderRadius: 4,
              background: `linear-gradient(135deg, ${alpha("#f14e32", 0.18)} 0%, ${alpha("#f97316", 0.12)} 50%, ${alpha("#fbbf24", 0.12)} 100%)`,
              border: `1px solid ${alpha("#f14e32", 0.2)}`,
              position: "relative",
              overflow: "hidden",
              scrollMarginTop: "100px"
            },
            children: [
              /* @__PURE__ */ jsx(
                Box,
                {
                  sx: {
                    position: "absolute",
                    top: -50,
                    right: -40,
                    width: 220,
                    height: 220,
                    borderRadius: "50%",
                    background: `radial-gradient(circle, ${alpha("#f14e32", 0.15)} 0%, transparent 70%)`
                  }
                }
              ),
              /* @__PURE__ */ jsxs(Box, { sx: { position: "relative", zIndex: 1 }, children: [
                /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", alignItems: "center", gap: 3, mb: 3 }, children: [
                  /* @__PURE__ */ jsx(
                    Box,
                    {
                      sx: {
                        width: 80,
                        height: 80,
                        borderRadius: 3,
                        background: "linear-gradient(135deg, #f14e32, #f97316)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        boxShadow: `0 8px 32px ${alpha("#f14e32", 0.3)}`
                      },
                      children: /* @__PURE__ */ jsx(AccountTreeIcon, { sx: { fontSize: 44, color: "white" } })
                    }
                  ),
                  /* @__PURE__ */ jsxs(Box, { children: [
                    /* @__PURE__ */ jsx(Typography, { variant: "h3", sx: { fontWeight: 800, mb: 0.5 }, children: "Git & Version Control" }),
                    /* @__PURE__ */ jsx(Typography, { variant: "h6", color: "text.secondary", sx: { fontWeight: 400 }, children: "Master the essential tools for tracking changes and collaborating on code" })
                  ] })
                ] }),
                /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }, children: [
                  /* @__PURE__ */ jsx(Chip, { label: "Beginner Friendly", color: "success" }),
                  /* @__PURE__ */ jsx(Chip, { label: "Collaboration", sx: { bgcolor: alpha("#f14e32", 0.15), color: "#f14e32", fontWeight: 600 } }),
                  /* @__PURE__ */ jsx(Chip, { label: "Essential Skill", sx: { bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 } }),
                  /* @__PURE__ */ jsx(Chip, { label: "Software Engineering", sx: { bgcolor: alpha("#f59e0b", 0.15), color: "#f59e0b", fontWeight: 600 } })
                ] }),
                /* @__PURE__ */ jsx(Grid, { container: true, spacing: 2, children: quickStats.map((stat) => /* @__PURE__ */ jsx(Grid, { item: true, xs: 6, sm: 3, children: /* @__PURE__ */ jsxs(
                  Paper,
                  {
                    sx: {
                      p: 2,
                      textAlign: "center",
                      borderRadius: 2,
                      bgcolor: alpha(stat.color, 0.1),
                      border: `1px solid ${alpha(stat.color, 0.2)}`
                    },
                    children: [
                      /* @__PURE__ */ jsx(Typography, { variant: "h4", sx: { fontWeight: 800, color: stat.color }, children: stat.value }),
                      /* @__PURE__ */ jsx(Typography, { variant: "caption", color: "text.secondary", sx: { fontWeight: 600 }, children: stat.label })
                    ]
                  }
                ) }, stat.label)) })
              ] })
            ]
          }
        ),
        /* @__PURE__ */ jsxs(
          Paper,
          {
            id: "why-version-control",
            sx: {
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px"
            },
            children: [
              /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }, children: [
                /* @__PURE__ */ jsxs(Typography, { variant: "h5", sx: { fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }, children: [
                  /* @__PURE__ */ jsx(HistoryIcon, { sx: { color: "#f14e32" } }),
                  "Why Version Control Matters"
                ] }),
                /* @__PURE__ */ jsx(DifficultyBadge, { level: "beginner" })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "The Problem: Life Without Version Control" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "Have you ever had files named like this?" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "The filename nightmare",
                  code: `report.doc
report_final.doc
report_final_v2.doc
report_final_v2_FINAL.doc
report_final_v2_FINAL_actually_final.doc
report_final_v2_FINAL_actually_final_USE_THIS_ONE.doc`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsx(WarningBox, { title: "Real-World Disasters", children: "In 2012, Knight Capital lost $440 million in 45 minutes due to deploying untested code without proper version control. A simple rollback mechanism could have prevented this catastrophe." }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "The Solution: Version Control Benefits" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2 }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#22c55e", mb: 1 }, children: "\u{1F4DC} Complete History" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Every change is recorded with who made it, when, and why. You can always go back to any previous version." })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#3b82f6", 0.08), border: `1px solid ${alpha("#3b82f6", 0.2)}`, borderRadius: 2 }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#3b82f6", mb: 1 }, children: "\u{1F465} Collaboration" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Multiple people can work on the same project simultaneously without overwriting each other's work." })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#f59e0b", 0.08), border: `1px solid ${alpha("#f59e0b", 0.2)}`, borderRadius: 2 }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#f59e0b", mb: 1 }, children: "\u{1F52C} Experimentation" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Create branches to try new ideas safely. If they don't work out, simply delete the branch\u2014no harm done." })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#8b5cf6", 0.08), border: `1px solid ${alpha("#8b5cf6", 0.2)}`, borderRadius: 2 }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#8b5cf6", mb: 1 }, children: "\u{1F4BE} Backup & Recovery" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Your code is safely stored. Accidentally deleted something? Restore it in seconds. Laptop stolen? Clone from remote." })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#ef4444", 0.08), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2 }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#ef4444", mb: 1 }, children: "\u{1F50D} Accountability" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Know exactly who changed what and when. Essential for debugging, code reviews, and compliance." })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#06b6d4", 0.08), border: `1px solid ${alpha("#06b6d4", 0.2)}`, borderRadius: 2 }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#06b6d4", mb: 1 }, children: "\u{1F680} CI/CD Integration" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Automate testing, building, and deployment. Version control is the foundation of modern DevOps." })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 3 } }),
              /* @__PURE__ */ jsx(ProTip, { children: "Even if you're working alone, use version control! Your future self will thank you when you need to understand why you made a change 6 months ago, or when you need to undo a mistake." })
            ]
          }
        ),
        /* @__PURE__ */ jsxs(
          Paper,
          {
            id: "git-fundamentals",
            sx: {
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px"
            },
            children: [
              /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }, children: [
                /* @__PURE__ */ jsxs(Typography, { variant: "h5", sx: { fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }, children: [
                  /* @__PURE__ */ jsx(AccountTreeIcon, { sx: { color: "#f14e32" } }),
                  "Git Fundamentals"
                ] }),
                /* @__PURE__ */ jsx(DifficultyBadge, { level: "beginner" })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "What Makes Git Different: Snapshots vs Deltas" }),
              /* @__PURE__ */ jsxs(Typography, { paragraph: true, children: [
                "Most version control systems (like SVN) store information as a list of file-based changes (deltas). Git thinks differently\u2014it stores data as ",
                /* @__PURE__ */ jsx("strong", { children: "snapshots" }),
                " of your entire project at each commit."
              ] }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#ef4444", 0.08), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2 }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#ef4444", mb: 1 }, children: "\u274C Delta-based (SVN, etc.)" }),
                  /* @__PURE__ */ jsxs(Typography, { variant: "body2", sx: { fontFamily: "monospace", fontSize: "0.8rem" }, children: [
                    "Version 1: File A (base)",
                    /* @__PURE__ */ jsx("br", {}),
                    "Version 2: File A + \u03941",
                    /* @__PURE__ */ jsx("br", {}),
                    "Version 3: File A + \u03941 + \u03942",
                    /* @__PURE__ */ jsx("br", {}),
                    "(Must apply all deltas to reconstruct)"
                  ] })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2 }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#22c55e", mb: 1 }, children: "\u2713 Snapshot-based (Git)" }),
                  /* @__PURE__ */ jsxs(Typography, { variant: "body2", sx: { fontFamily: "monospace", fontSize: "0.8rem" }, children: [
                    "Commit 1: [Snapshot of all files]",
                    /* @__PURE__ */ jsx("br", {}),
                    "Commit 2: [Snapshot of all files]",
                    /* @__PURE__ */ jsx("br", {}),
                    "Commit 3: [Snapshot of all files]",
                    /* @__PURE__ */ jsx("br", {}),
                    "(Each commit is complete & independent)"
                  ] })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "The Three States of Git" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "Understanding Git's three main states is crucial. Files in a Git project can be in one of these states:" }),
              /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", flexDirection: { xs: "column", md: "row" }, gap: 2, mb: 3, alignItems: "stretch" }, children: [
                /* @__PURE__ */ jsxs(Paper, { sx: { flex: 1, p: 2, bgcolor: alpha("#3b82f6", 0.08), border: `1px solid ${alpha("#3b82f6", 0.2)}`, borderRadius: 2, textAlign: "center" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { color: "#3b82f6", fontWeight: 700 }, children: "1. Working Directory" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mt: 1 }, children: 'Your local filesystem where you edit files. Changes here are "untracked" or "modified".' }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { display: "block", mt: 1, fontFamily: "monospace", bgcolor: alpha("#3b82f6", 0.1), p: 0.5, borderRadius: 1 }, children: "Where you work" })
                ] }),
                /* @__PURE__ */ jsx(Box, { sx: { display: "flex", alignItems: "center", justifyContent: "center", color: "#f14e32", fontWeight: 700 }, children: "\u2192 git add \u2192" }),
                /* @__PURE__ */ jsxs(Paper, { sx: { flex: 1, p: 2, bgcolor: alpha("#f59e0b", 0.08), border: `1px solid ${alpha("#f59e0b", 0.2)}`, borderRadius: 2, textAlign: "center" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { color: "#f59e0b", fontWeight: 700 }, children: "2. Staging Area" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mt: 1 }, children: "A preview of your next commit. You choose exactly which changes to include." }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { display: "block", mt: 1, fontFamily: "monospace", bgcolor: alpha("#f59e0b", 0.1), p: 0.5, borderRadius: 1 }, children: 'Also called "Index"' })
                ] }),
                /* @__PURE__ */ jsx(Box, { sx: { display: "flex", alignItems: "center", justifyContent: "center", color: "#f14e32", fontWeight: 700 }, children: "\u2192 git commit \u2192" }),
                /* @__PURE__ */ jsxs(Paper, { sx: { flex: 1, p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2, textAlign: "center" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { color: "#22c55e", fontWeight: 700 }, children: "3. Repository" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mt: 1 }, children: "The .git directory where Git stores all committed snapshots permanently." }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { display: "block", mt: 1, fontFamily: "monospace", bgcolor: alpha("#22c55e", 0.1), p: 0.5, borderRadius: 1 }, children: "Your project history" })
                ] })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "Inside the .git Folder" }),
              /* @__PURE__ */ jsxs(Typography, { paragraph: true, children: [
                "When you run ",
                /* @__PURE__ */ jsx("code", { children: "git init" }),
                ", Git creates a hidden ",
                /* @__PURE__ */ jsx("code", { children: ".git" }),
                " folder. This is where all the magic happens:"
              ] }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: ".git directory structure",
                  code: `.git/
\u251C\u2500\u2500 HEAD          # Points to current branch
\u251C\u2500\u2500 config        # Repository-specific settings
\u251C\u2500\u2500 description   # Used by GitWeb (rarely needed)
\u251C\u2500\u2500 hooks/        # Scripts that run on events
\u251C\u2500\u2500 index         # The staging area
\u251C\u2500\u2500 objects/      # All content (blobs, trees, commits)
\u2502   \u251C\u2500\u2500 pack/     # Compressed object storage
\u2502   \u2514\u2500\u2500 info/
\u251C\u2500\u2500 refs/         # Pointers to commits
\u2502   \u251C\u2500\u2500 heads/    # Local branches
\u2502   \u251C\u2500\u2500 tags/     # Tags
\u2502   \u2514\u2500\u2500 remotes/  # Remote-tracking branches
\u2514\u2500\u2500 logs/         # History of ref changes`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsx(WarningBox, { title: "Never manually edit .git!", children: "The .git folder is Git's database. Manually editing files inside can corrupt your repository. Always use Git commands to interact with your repository." }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Installing Git" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#f14e32", 0.2)}` }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, mb: 1 }, children: "\u{1FA9F} Windows" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Download from git-scm.com or use:" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { fontFamily: "monospace", bgcolor: "rgba(0,0,0,0.2)", p: 1, borderRadius: 1, fontSize: "0.8rem" }, children: "winget install Git.Git" })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#f14e32", 0.2)}` }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, mb: 1 }, children: "\u{1F34E} macOS" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Install via Homebrew or Xcode tools:" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { fontFamily: "monospace", bgcolor: "rgba(0,0,0,0.2)", p: 1, borderRadius: 1, fontSize: "0.8rem" }, children: "brew install git" })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#f14e32", 0.2)}` }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, mb: 1 }, children: "\u{1F427} Linux" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Use your package manager:" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { fontFamily: "monospace", bgcolor: "rgba(0,0,0,0.2)", p: 1, borderRadius: 1, fontSize: "0.8rem" }, children: "sudo apt install git" })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Verify installation",
                  code: `git --version
# Output: git version 2.43.0 (or similar)`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsx(ProTip, { children: "Git is a distributed version control system\u2014every clone is a full backup of the repository with complete history. This means you can work offline and still have access to the entire project history!" })
            ]
          }
        ),
        /* @__PURE__ */ jsxs(
          Paper,
          {
            id: "configuration",
            sx: {
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px"
            },
            children: [
              /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }, children: [
                /* @__PURE__ */ jsxs(Typography, { variant: "h5", sx: { fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }, children: [
                  /* @__PURE__ */ jsx(BuildIcon, { sx: { color: "#f14e32" } }),
                  "Git Configuration"
                ] }),
                /* @__PURE__ */ jsx(DifficultyBadge, { level: "beginner" })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "Configuration Levels" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "Git has three levels of configuration, each with different scope. Lower levels override higher ones:" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#3b82f6", 0.08), border: `1px solid ${alpha("#3b82f6", 0.2)}`, borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#3b82f6", mb: 1 }, children: "1. System" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Applies to all users on the machine" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontFamily: "monospace", bgcolor: "rgba(0,0,0,0.2)", p: 0.5, borderRadius: 1, display: "block" }, children: "/etc/gitconfig" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontFamily: "monospace", display: "block", mt: 1 }, children: "git config --system" })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#f59e0b", 0.08), border: `1px solid ${alpha("#f59e0b", 0.2)}`, borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#f59e0b", mb: 1 }, children: "2. Global (User)" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Applies to all repos for current user" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontFamily: "monospace", bgcolor: "rgba(0,0,0,0.2)", p: 0.5, borderRadius: 1, display: "block" }, children: "~/.gitconfig" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontFamily: "monospace", display: "block", mt: 1 }, children: "git config --global" })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#22c55e", mb: 1 }, children: "3. Local (Repo)" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Applies only to current repository" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontFamily: "monospace", bgcolor: "rgba(0,0,0,0.2)", p: 0.5, borderRadius: 1, display: "block" }, children: ".git/config" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontFamily: "monospace", display: "block", mt: 1 }, children: "git config --local" })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "Essential First-Time Setup" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "Before you start using Git, you must set your identity. This information is baked into every commit:" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Set your identity (required)",
                  code: `# Set your name and email (used in every commit)
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# Verify your settings
git config --list
git config user.name    # Check specific setting`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsx(InfoBox, { title: "Why is this important?", children: "Your name and email appear in every commit you make. Use your real name and a valid email for professional projects. For open source, use the email associated with your GitHub/GitLab account." }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Editor & Default Branch" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Configure your preferred editor",
                  code: `# Set VS Code as default editor
git config --global core.editor "code --wait"

# Other popular options:
git config --global core.editor "vim"
git config --global core.editor "nano"
git config --global core.editor "notepad++"

# Set default branch name (main instead of master)
git config --global init.defaultBranch main`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Line Endings (CRLF vs LF)" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "Windows uses CRLF (\\r\\n), while macOS/Linux use LF (\\n). Git can handle this automatically:" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 2 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsx(
                  CodeBlock,
                  {
                    title: "Windows users",
                    code: `# Convert LF to CRLF on checkout
# Convert CRLF to LF on commit
git config --global core.autocrlf true`
                  }
                ) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsx(
                  CodeBlock,
                  {
                    title: "macOS/Linux users",
                    code: `# Only convert CRLF to LF on commit
# (safety net for Windows files)
git config --global core.autocrlf input`
                  }
                ) })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Useful Git Aliases" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "Aliases are shortcuts for common commands. Here are some popular ones:" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Recommended aliases",
                  code: `# Shorter commands
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

# Usage: git st, git lg, git co main`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "SSH Key Setup" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "SSH keys provide secure, password-less authentication to GitHub/GitLab:" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Generate and add SSH key",
                  code: `# Generate a new SSH key (use your GitHub email)
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
ssh -T git@github.com`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsxs(ProTip, { children: [
                "View all your Git settings with ",
                /* @__PURE__ */ jsx("code", { children: "git config --list --show-origin" }),
                " to see which file each setting comes from. This is helpful for debugging configuration issues."
              ] })
            ]
          }
        ),
        /* @__PURE__ */ jsxs(
          Paper,
          {
            id: "basic-workflow",
            sx: {
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px"
            },
            children: [
              /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }, children: [
                /* @__PURE__ */ jsxs(Typography, { variant: "h5", sx: { fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }, children: [
                  /* @__PURE__ */ jsx(CompareArrowsIcon, { sx: { color: "#f14e32" } }),
                  "Basic Git Workflow"
                ] }),
                /* @__PURE__ */ jsx(DifficultyBadge, { level: "beginner" })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "Starting a Repository" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "There are two ways to get a Git repository: create a new one or clone an existing one." }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsx(
                  CodeBlock,
                  {
                    title: "Option 1: Create new repository",
                    code: `# Navigate to your project folder
cd my-project

# Initialize Git (creates .git folder)
git init

# Output: Initialized empty Git repository
# in /path/to/my-project/.git/`
                  }
                ) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsx(
                  CodeBlock,
                  {
                    title: "Option 2: Clone existing repository",
                    code: `# Clone from URL (creates new folder)
git clone https://github.com/user/repo.git

# Clone into specific folder
git clone https://github.com/user/repo.git my-folder

# Clone with SSH
git clone git@github.com:user/repo.git`
                  }
                ) })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "The Edit-Stage-Commit Cycle" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "This is the fundamental Git workflow you'll use hundreds of times:" }),
              /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", flexDirection: { xs: "column", md: "row" }, gap: 1, mb: 3, alignItems: "center", justifyContent: "center", flexWrap: "wrap" }, children: [
                /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#3b82f6", 0.1), borderRadius: 2, textAlign: "center", minWidth: 150 }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle2", sx: { fontWeight: 700, color: "#3b82f6" }, children: "1. EDIT" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", children: "Modify files" })
                ] }),
                /* @__PURE__ */ jsx(Typography, { sx: { color: "#f14e32", fontWeight: 700 }, children: "\u2192" }),
                /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#f59e0b", 0.1), borderRadius: 2, textAlign: "center", minWidth: 150 }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle2", sx: { fontWeight: 700, color: "#f59e0b" }, children: "2. STAGE" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", children: "git add" })
                ] }),
                /* @__PURE__ */ jsx(Typography, { sx: { color: "#f14e32", fontWeight: 700 }, children: "\u2192" }),
                /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#22c55e", 0.1), borderRadius: 2, textAlign: "center", minWidth: 150 }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle2", sx: { fontWeight: 700, color: "#22c55e" }, children: "3. COMMIT" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", children: "git commit" })
                ] }),
                /* @__PURE__ */ jsx(Typography, { sx: { color: "#f14e32", fontWeight: 700 }, children: "\u2192" }),
                /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#8b5cf6", 0.1), borderRadius: 2, textAlign: "center", minWidth: 150 }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle2", sx: { fontWeight: 700, color: "#8b5cf6" }, children: "REPEAT" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", children: "Continue working" })
                ] })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "Understanding git status" }),
              /* @__PURE__ */ jsxs(Typography, { paragraph: true, children: [
                /* @__PURE__ */ jsx("code", { children: "git status" }),
                " is your best friend. Run it constantly to understand what's happening:"
              ] }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Reading git status output",
                  code: `$ git status
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
        script.js`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsxs(InfoBox, { title: "Short status", children: [
                "Use ",
                /* @__PURE__ */ jsx("code", { children: "git status -s" }),
                " for a compact view: ",
                /* @__PURE__ */ jsx("code", { children: "M" }),
                " = modified, ",
                /* @__PURE__ */ jsx("code", { children: "A" }),
                " = added, ",
                /* @__PURE__ */ jsx("code", { children: "??" }),
                " = untracked, ",
                /* @__PURE__ */ jsx("code", { children: "D" }),
                " = deleted."
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Viewing History with git log" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Useful git log variations",
                  code: `# Basic log (full details)
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
git log --since="2024-01-01" --until="2024-12-31"`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Complete Beginner Workflow Example" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Your first Git project from scratch",
                  code: `# 1. Create project folder and initialize Git
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
git commit -m "Add JavaScript file"`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsxs(ProTip, { children: [
                "Run ",
                /* @__PURE__ */ jsx("code", { children: "git status" }),
                " before and after every command when learning. It helps you understand exactly what Git is doing and prevents mistakes."
              ] })
            ]
          }
        ),
        /* @__PURE__ */ jsxs(
          Paper,
          {
            id: "staging-committing",
            sx: {
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px"
            },
            children: [
              /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }, children: [
                /* @__PURE__ */ jsxs(Typography, { variant: "h5", sx: { fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }, children: [
                  /* @__PURE__ */ jsx(SaveIcon, { sx: { color: "#f14e32" } }),
                  "Staging and Committing"
                ] }),
                /* @__PURE__ */ jsx(DifficultyBadge, { level: "beginner" })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "Why the Staging Area Exists" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: 'The staging area (also called "index") lets you craft your commits carefully. Instead of committing everything at once, you can select exactly which changes belong together logically.' }),
              /* @__PURE__ */ jsx(InfoBox, { title: "Real-world example", children: "You fixed a bug AND added a new feature in the same coding session. With staging, you can create two separate commits: one for the bug fix and one for the feature\u2014keeping your history clean and reviewable." }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "git add Variations" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#f14e32", 0.2)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, mb: 1, fontFamily: "monospace" }, children: "git add <file>" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Stage a specific file" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { color: "text.secondary", display: "block", mt: 1 }, children: "git add index.html" })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#f14e32", 0.2)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, mb: 1, fontFamily: "monospace" }, children: "git add ." }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Stage all changes in current directory & subdirectories" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { color: "text.secondary", display: "block", mt: 1 }, children: "Most commonly used" })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#f14e32", 0.2)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, mb: 1, fontFamily: "monospace" }, children: "git add -A" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Stage ALL changes (including deletions) from entire repo" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { color: "text.secondary", display: "block", mt: 1 }, children: "Same as git add --all" })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#f14e32", 0.2)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, mb: 1, fontFamily: "monospace" }, children: "git add -p" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Interactive staging\u2014choose hunks to stage" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { color: "text.secondary", display: "block", mt: 1 }, children: "Best for partial staging" })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Interactive staging example (git add -p)",
                  code: `$ git add -p
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
# e = manually edit the hunk`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Viewing Changes with git diff" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Different diff commands",
                  code: `# See unstaged changes (working dir vs staging)
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
git diff --stat`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Reading diff output",
                  code: `$ git diff
diff --git a/file.txt b/file.txt
index 1234567..abcdefg 100644
--- a/file.txt          # Old version
+++ b/file.txt          # New version
@@ -1,4 +1,5 @@         # Line numbers: old file vs new file
 unchanged line
-removed line           # Red: this line was deleted
+added line             # Green: this line was added
 unchanged line`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Writing Good Commit Messages" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "Good commit messages are crucial for understanding project history. Follow these conventions:" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#ef4444", 0.08), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2 }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#ef4444", mb: 1 }, children: "\u274C Bad Messages" }),
                  /* @__PURE__ */ jsxs(Typography, { variant: "body2", sx: { fontFamily: "monospace", fontSize: "0.85rem" }, children: [
                    '"fix"',
                    /* @__PURE__ */ jsx("br", {}),
                    '"updates"',
                    /* @__PURE__ */ jsx("br", {}),
                    '"WIP"',
                    /* @__PURE__ */ jsx("br", {}),
                    '"asdfasdf"',
                    /* @__PURE__ */ jsx("br", {}),
                    '"changed stuff"',
                    /* @__PURE__ */ jsx("br", {}),
                    '"Friday commit"'
                  ] })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2 }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#22c55e", mb: 1 }, children: "\u2713 Good Messages" }),
                  /* @__PURE__ */ jsxs(Typography, { variant: "body2", sx: { fontFamily: "monospace", fontSize: "0.85rem" }, children: [
                    '"Fix login button not responding on mobile"',
                    /* @__PURE__ */ jsx("br", {}),
                    '"Add user authentication with JWT"',
                    /* @__PURE__ */ jsx("br", {}),
                    '"Refactor database queries for performance"',
                    /* @__PURE__ */ jsx("br", {}),
                    '"Update README with installation steps"',
                    /* @__PURE__ */ jsx("br", {}),
                    '"Remove deprecated API endpoints"'
                  ] })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Conventional Commits format (popular standard)",
                  code: `# Format: <type>(<scope>): <description>

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
git commit -m "refactor(utils): simplify date formatting logic"`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "The Anatomy of a Commit" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "Every commit contains more than just your changes:" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "What's inside a commit",
                  code: `$ git show --format=fuller HEAD

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
...`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Amending Commits" }),
              /* @__PURE__ */ jsxs(Typography, { paragraph: true, children: [
                "Made a typo in your commit message? Forgot to add a file? Use ",
                /* @__PURE__ */ jsx("code", { children: "--amend" }),
                ":"
              ] }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Amending the last commit",
                  code: `# Just change the message
git commit --amend -m "New corrected message"

# Add forgotten files to last commit
git add forgotten-file.txt
git commit --amend --no-edit   # Keep same message

# Change message AND add files
git add another-file.txt
git commit --amend -m "Updated message with new file"`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsxs(WarningBox, { title: "Don't amend public commits!", children: [
                "Amending rewrites history. Only amend commits that haven't been pushed yet. If you've already pushed, use ",
                /* @__PURE__ */ jsx("code", { children: "git revert" }),
                " instead to safely undo changes."
              ] }),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsxs(ProTip, { children: [
                "Use ",
                /* @__PURE__ */ jsx("code", { children: "git commit -v" }),
                " to see the full diff while writing your commit message. This helps you write more accurate descriptions of what changed."
              ] })
            ]
          }
        ),
        /* @__PURE__ */ jsxs(
          Paper,
          {
            id: "branching",
            sx: {
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px"
            },
            children: [
              /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }, children: [
                /* @__PURE__ */ jsxs(Typography, { variant: "h5", sx: { fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }, children: [
                  /* @__PURE__ */ jsx(AccountTreeIcon, { sx: { color: "#f14e32" } }),
                  "Branching in Git"
                ] }),
                /* @__PURE__ */ jsx(DifficultyBadge, { level: "intermediate" })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "What is a Branch?" }),
              /* @__PURE__ */ jsxs(Typography, { paragraph: true, children: [
                "A branch is simply a lightweight, movable pointer to a commit. The default branch is usually called ",
                /* @__PURE__ */ jsx("code", { children: "main" }),
                " (or ",
                /* @__PURE__ */ jsx("code", { children: "master" }),
                " in older repos). Branches let you diverge from the main line of development and work in isolation."
              ] }),
              /* @__PURE__ */ jsx(Box, { sx: { textAlign: "center", my: 3, p: 3, bgcolor: alpha("#f14e32", 0.05), borderRadius: 2 }, children: /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { fontFamily: "monospace", whiteSpace: "pre", textAlign: "left", display: "inline-block" }, children: `          feature-branch
                \u2193
    C1 \u2190 C2 \u2190 C3 \u2190 C4  (feature work)
         \u2196
          C5 \u2190 C6      (main continues)
               \u2191
              main` }) }),
              /* @__PURE__ */ jsx(InfoBox, { title: "Why branches are cheap", children: "In Git, a branch is just a 41-byte file containing a commit hash. Creating a branch is instant and takes almost no space, unlike older VCS systems that copied entire directories." }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Creating and Switching Branches" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Branch creation commands",
                  code: `# List all local branches (* marks current)
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
git branch bugfix-123 abc1234`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsxs(ProTip, { children: [
                "Use ",
                /* @__PURE__ */ jsx("code", { children: "git switch" }),
                " (Git 2.23+) instead of ",
                /* @__PURE__ */ jsx("code", { children: "git checkout" }),
                " for branch operations. It's clearer and less error-prone since checkout does many different things."
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Branch Naming Conventions" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "Good branch names describe the work and help organize your repository:" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2 }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#22c55e", mb: 1 }, children: "\u2713 Good Names" }),
                  /* @__PURE__ */ jsxs(Typography, { variant: "body2", sx: { fontFamily: "monospace", fontSize: "0.85rem" }, children: [
                    "feature/user-authentication",
                    /* @__PURE__ */ jsx("br", {}),
                    "bugfix/login-validation",
                    /* @__PURE__ */ jsx("br", {}),
                    "hotfix/security-patch",
                    /* @__PURE__ */ jsx("br", {}),
                    "release/v2.1.0",
                    /* @__PURE__ */ jsx("br", {}),
                    "docs/api-documentation",
                    /* @__PURE__ */ jsx("br", {}),
                    "refactor/database-queries"
                  ] })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#ef4444", 0.08), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2 }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#ef4444", mb: 1 }, children: "\u2717 Bad Names" }),
                  /* @__PURE__ */ jsxs(Typography, { variant: "body2", sx: { fontFamily: "monospace", fontSize: "0.85rem" }, children: [
                    "fix",
                    /* @__PURE__ */ jsx("br", {}),
                    "test",
                    /* @__PURE__ */ jsx("br", {}),
                    "my-branch",
                    /* @__PURE__ */ jsx("br", {}),
                    "stuff",
                    /* @__PURE__ */ jsx("br", {}),
                    "john-working",
                    /* @__PURE__ */ jsx("br", {}),
                    "new-feature-2"
                  ] })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Common Branch Types" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.3)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#3b82f6", mb: 1 }, children: "Long-Running" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Permanent branches that exist throughout the project" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontFamily: "monospace", display: "block" }, children: "main, develop, staging" })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.3)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#22c55e", mb: 1 }, children: "Feature" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Short-lived branches for new features" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontFamily: "monospace", display: "block" }, children: "feature/*, feat/*" })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#ef4444", 0.3)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#ef4444", mb: 1 }, children: "Hotfix" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Urgent fixes branched from production" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontFamily: "monospace", display: "block" }, children: "hotfix/*, bugfix/*" })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Branch Management Commands" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Managing branches",
                  code: `# Rename current branch
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
git branch -v`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsx(WarningBox, { title: "When to create a branch", children: "Create a branch whenever you start work that might take more than one commit, or work you might want to abandon. Branches are free\u2014use them liberally! Never commit experimental code directly to main." })
            ]
          }
        ),
        /* @__PURE__ */ jsxs(
          Paper,
          {
            id: "merging",
            sx: {
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px"
            },
            children: [
              /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }, children: [
                /* @__PURE__ */ jsxs(Typography, { variant: "h5", sx: { fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }, children: [
                  /* @__PURE__ */ jsx(MergeIcon, { sx: { color: "#f14e32" } }),
                  "Merging and Rebasing"
                ] }),
                /* @__PURE__ */ jsx(DifficultyBadge, { level: "intermediate" })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "Types of Merges" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#22c55e", mb: 1 }, children: "Fast-Forward Merge" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 2 }, children: "When the target branch has no new commits, Git simply moves the pointer forward. No merge commit created." }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontFamily: "monospace", whiteSpace: "pre", display: "block", bgcolor: "rgba(0,0,0,0.2)", p: 1, borderRadius: 1 }, children: `Before:  main \u2192 A \u2192 B
         feature \u2192 A \u2192 B \u2192 C \u2192 D

After:   main \u2192 A \u2192 B \u2192 C \u2192 D` })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#3b82f6", 0.08), border: `1px solid ${alpha("#3b82f6", 0.2)}`, borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#3b82f6", mb: 1 }, children: "Three-Way Merge" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 2 }, children: "When both branches have diverged, Git creates a merge commit with two parents." }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontFamily: "monospace", whiteSpace: "pre", display: "block", bgcolor: "rgba(0,0,0,0.2)", p: 1, borderRadius: 1 }, children: `Before:  main \u2192 A \u2192 B \u2192 E
         feature \u2192 A \u2192 B \u2192 C \u2192 D

After:   main \u2192 A \u2192 B \u2192 E \u2192 M
                     \u2196 C \u2192 D \u2197` })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Performing a Merge" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Basic merge workflow",
                  code: `# 1. Switch to the target branch (where you want changes)
git checkout main

# 2. Merge the feature branch into main
git merge feature-login

# 3. If fast-forward, you're done!
# Output: Fast-forward

# Force a merge commit even if fast-forward possible
git merge --no-ff feature-login

# Abort a merge in progress (if conflicts)
git merge --abort`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Resolving Merge Conflicts" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "Conflicts occur when both branches modified the same lines. Git marks the conflicting sections:" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "What a conflict looks like",
                  code: `<<<<<<< HEAD
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
const greeting = "Hello Universe";`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Conflict resolution workflow",
                  code: `# 1. See which files have conflicts
git status

# 2. Open each conflicted file and resolve manually
# (or use a merge tool)
git mergetool

# 3. After fixing, stage the resolved files
git add resolved-file.js

# 4. Complete the merge
git commit
# (Git auto-generates merge commit message)`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsx(ProTip, { children: `Use VS Code's built-in merge editor\u2014it shows "Accept Current", "Accept Incoming", and "Accept Both" buttons above each conflict, making resolution much easier.` }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Introduction to Rebasing" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "Rebasing moves your commits to a new base, creating a linear history without merge commits:" }),
              /* @__PURE__ */ jsx(Box, { sx: { textAlign: "center", my: 3, p: 3, bgcolor: alpha("#f14e32", 0.05), borderRadius: 2 }, children: /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { fontFamily: "monospace", whiteSpace: "pre", textAlign: "left", display: "inline-block" }, children: `Before rebase:
main:    A \u2192 B \u2192 C
feature: A \u2192 B \u2192 X \u2192 Y

After "git rebase main" on feature:
main:    A \u2192 B \u2192 C
feature: A \u2192 B \u2192 C \u2192 X' \u2192 Y'  (commits replayed)` }) }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Basic rebase commands",
                  code: `# Rebase current branch onto main
git checkout feature
git rebase main

# If conflicts occur during rebase:
git rebase --continue  # after resolving
git rebase --abort     # cancel the rebase
git rebase --skip      # skip problematic commit

# Interactive rebase (edit last 3 commits)
git rebase -i HEAD~3`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Merge vs Rebase: When to Use Each" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#22c55e", mb: 1 }, children: "Use Merge When..." }),
                  /* @__PURE__ */ jsxs(List, { dense: true, children: [
                    /* @__PURE__ */ jsx(ListItem, { children: /* @__PURE__ */ jsx(ListItemText, { primary: "Working on shared/public branches" }) }),
                    /* @__PURE__ */ jsx(ListItem, { children: /* @__PURE__ */ jsx(ListItemText, { primary: "You want to preserve complete history" }) }),
                    /* @__PURE__ */ jsx(ListItem, { children: /* @__PURE__ */ jsx(ListItemText, { primary: "The branch has been pushed and others use it" }) }),
                    /* @__PURE__ */ jsx(ListItem, { children: /* @__PURE__ */ jsx(ListItemText, { primary: "You want explicit merge points" }) })
                  ] })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#3b82f6", 0.08), border: `1px solid ${alpha("#3b82f6", 0.2)}`, borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#3b82f6", mb: 1 }, children: "Use Rebase When..." }),
                  /* @__PURE__ */ jsxs(List, { dense: true, children: [
                    /* @__PURE__ */ jsx(ListItem, { children: /* @__PURE__ */ jsx(ListItemText, { primary: "Working on local/private branches" }) }),
                    /* @__PURE__ */ jsx(ListItem, { children: /* @__PURE__ */ jsx(ListItemText, { primary: "You want a clean, linear history" }) }),
                    /* @__PURE__ */ jsx(ListItem, { children: /* @__PURE__ */ jsx(ListItemText, { primary: "Before merging a feature branch" }) }),
                    /* @__PURE__ */ jsx(ListItem, { children: /* @__PURE__ */ jsx(ListItemText, { primary: "Cleaning up messy commit history" }) })
                  ] })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(WarningBox, { title: "The Golden Rule of Rebasing", children: "Never rebase commits that have been pushed to a public repository. Rebasing rewrites history, which causes problems for anyone who has based work on those commits." }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Interactive Rebase (Squashing Commits)" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Squashing multiple commits into one",
                  code: `# Start interactive rebase for last 4 commits
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
# d, drop   = remove commit entirely`
                }
              )
            ]
          }
        ),
        /* @__PURE__ */ jsxs(
          Paper,
          {
            id: "remote-repos",
            sx: {
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px"
            },
            children: [
              /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }, children: [
                /* @__PURE__ */ jsxs(Typography, { variant: "h5", sx: { fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }, children: [
                  /* @__PURE__ */ jsx(CloudIcon, { sx: { color: "#f14e32" } }),
                  "Remote Repositories"
                ] }),
                /* @__PURE__ */ jsx(DifficultyBadge, { level: "intermediate" })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "What is a Remote?" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "A remote is a version of your repository hosted on the internet or network. It allows collaboration\u2014multiple developers can push and pull changes from the same remote repository." }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#3b82f6", 0.08), border: `1px solid ${alpha("#3b82f6", 0.2)}`, borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#3b82f6", mb: 1 }, children: "origin" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "The default name for the remote you cloned from. This is usually your main remote." })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#22c55e", mb: 1 }, children: "upstream" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Common name for the original repo when you've forked. Used to sync with the source project." })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Managing Remotes" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Remote management commands",
                  code: `# List all remotes
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
git remote show origin`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Fetch, Pull, and Push" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "These are the three main operations for syncing with remotes:" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.3)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#f59e0b", mb: 1 }, children: "git fetch" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Downloads changes from remote but doesn't merge them. Safe\u2014won't affect your working files." }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontFamily: "monospace" }, children: "Remote \u2192 Local (tracking branches only)" })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.3)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#22c55e", mb: 1 }, children: "git pull" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Fetches AND merges remote changes into your current branch. Shortcut for fetch + merge." }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontFamily: "monospace" }, children: "Remote \u2192 Local \u2192 Working Dir" })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.3)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#3b82f6", mb: 1 }, children: "git push" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Uploads your local commits to the remote. Shares your work with others." }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontFamily: "monospace" }, children: "Local \u2192 Remote" })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Fetch, pull, and push commands",
                  code: `# Fetch all remotes
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
git push --force-with-lease  # safer version`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsxs(WarningBox, { title: "Never force push to shared branches", children: [
                /* @__PURE__ */ jsx("code", { children: "git push --force" }),
                " overwrites remote history. Only use it on your own branches that nobody else is using. Use ",
                /* @__PURE__ */ jsx("code", { children: "--force-with-lease" }),
                " as a safer alternative\u2014it fails if someone else has pushed."
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Remote Tracking Branches" }),
              /* @__PURE__ */ jsxs(Typography, { paragraph: true, children: [
                "Remote tracking branches are local references to the state of remote branches. They're named ",
                /* @__PURE__ */ jsx("code", { children: "origin/main" }),
                ", ",
                /* @__PURE__ */ jsx("code", { children: "origin/feature" }),
                ", etc."
              ] }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Working with remote tracking branches",
                  code: `# See all tracking branches
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
git branch -u origin/main`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Popular Git Hosting Platforms" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, textAlign: "center", height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 1 }, children: "GitHub" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Most popular. Great for open source. Actions CI/CD, Copilot AI." }),
                  /* @__PURE__ */ jsx(Chip, { label: "Free for public repos", size: "small", color: "success" })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, textAlign: "center", height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 1 }, children: "GitLab" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Full DevOps platform. Built-in CI/CD. Self-hosting option." }),
                  /* @__PURE__ */ jsx(Chip, { label: "Free tier available", size: "small", color: "success" })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, textAlign: "center", height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 1 }, children: "Bitbucket" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Atlassian product. Great Jira integration. Free private repos." }),
                  /* @__PURE__ */ jsx(Chip, { label: "Free for small teams", size: "small", color: "success" })
                ] }) })
              ] }),
              /* @__PURE__ */ jsxs(ProTip, { children: [
                "Use ",
                /* @__PURE__ */ jsx("code", { children: "git fetch" }),
                " before ",
                /* @__PURE__ */ jsx("code", { children: "git status" }),
                " to see accurate ahead/behind counts. Without fetching first, you're comparing against stale remote tracking branch data."
              ] })
            ]
          }
        ),
        /* @__PURE__ */ jsxs(
          Paper,
          {
            id: "collaboration",
            sx: {
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px"
            },
            children: [
              /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }, children: [
                /* @__PURE__ */ jsxs(Typography, { variant: "h5", sx: { fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }, children: [
                  /* @__PURE__ */ jsx(GroupIcon, { sx: { color: "#f14e32" } }),
                  "Collaboration with Git"
                ] }),
                /* @__PURE__ */ jsx(DifficultyBadge, { level: "intermediate" })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "Pull Requests / Merge Requests" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "A Pull Request (GitHub) or Merge Request (GitLab) is a way to propose changes and request code review before merging into the main branch." }),
              /* @__PURE__ */ jsxs(Box, { sx: { p: 3, bgcolor: alpha("#f14e32", 0.05), borderRadius: 2, mb: 3 }, children: [
                /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, mb: 2 }, children: "Pull Request Workflow" }),
                /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", flexDirection: { xs: "column", md: "row" }, gap: 1, alignItems: "center", justifyContent: "center", flexWrap: "wrap" }, children: [
                  /* @__PURE__ */ jsx(Paper, { sx: { p: 1.5, bgcolor: alpha("#3b82f6", 0.1), borderRadius: 2, textAlign: "center", minWidth: 120 }, children: /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontWeight: 700, color: "#3b82f6" }, children: "1. Branch" }) }),
                  /* @__PURE__ */ jsx(Typography, { sx: { color: "#f14e32" }, children: "\u2192" }),
                  /* @__PURE__ */ jsx(Paper, { sx: { p: 1.5, bgcolor: alpha("#f59e0b", 0.1), borderRadius: 2, textAlign: "center", minWidth: 120 }, children: /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontWeight: 700, color: "#f59e0b" }, children: "2. Commit" }) }),
                  /* @__PURE__ */ jsx(Typography, { sx: { color: "#f14e32" }, children: "\u2192" }),
                  /* @__PURE__ */ jsx(Paper, { sx: { p: 1.5, bgcolor: alpha("#8b5cf6", 0.1), borderRadius: 2, textAlign: "center", minWidth: 120 }, children: /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontWeight: 700, color: "#8b5cf6" }, children: "3. Push" }) }),
                  /* @__PURE__ */ jsx(Typography, { sx: { color: "#f14e32" }, children: "\u2192" }),
                  /* @__PURE__ */ jsx(Paper, { sx: { p: 1.5, bgcolor: alpha("#ec4899", 0.1), borderRadius: 2, textAlign: "center", minWidth: 120 }, children: /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontWeight: 700, color: "#ec4899" }, children: "4. Open PR" }) }),
                  /* @__PURE__ */ jsx(Typography, { sx: { color: "#f14e32" }, children: "\u2192" }),
                  /* @__PURE__ */ jsx(Paper, { sx: { p: 1.5, bgcolor: alpha("#22c55e", 0.1), borderRadius: 2, textAlign: "center", minWidth: 120 }, children: /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontWeight: 700, color: "#22c55e" }, children: "5. Review & Merge" }) })
                ] })
              ] }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Creating a PR workflow",
                  code: `# 1. Create a feature branch
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
gh pr merge`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Forking Repositories" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "A fork is your own copy of someone else's repository. It's the standard way to contribute to projects you don't have write access to." }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Fork and contribute workflow",
                  code: `# 1. Fork the repo on GitHub (via web UI)

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

# 6. Open PR from your fork to original repo`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Branching Strategies" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.3)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#3b82f6", mb: 1 }, children: "GitHub Flow" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Simple: main + feature branches. Deploy from main." }),
                  /* @__PURE__ */ jsxs(List, { dense: true, sx: { py: 0 }, children: [
                    /* @__PURE__ */ jsx(ListItem, { sx: { py: 0 }, children: /* @__PURE__ */ jsx(ListItemText, { primaryTypographyProps: { variant: "caption" }, primary: "\u2022 Great for continuous deployment" }) }),
                    /* @__PURE__ */ jsx(ListItem, { sx: { py: 0 }, children: /* @__PURE__ */ jsx(ListItemText, { primaryTypographyProps: { variant: "caption" }, primary: "\u2022 Easy to understand" }) }),
                    /* @__PURE__ */ jsx(ListItem, { sx: { py: 0 }, children: /* @__PURE__ */ jsx(ListItemText, { primaryTypographyProps: { variant: "caption" }, primary: "\u2022 Best for small teams" }) })
                  ] })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.3)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#22c55e", mb: 1 }, children: "GitFlow" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "main, develop, feature, release, hotfix branches." }),
                  /* @__PURE__ */ jsxs(List, { dense: true, sx: { py: 0 }, children: [
                    /* @__PURE__ */ jsx(ListItem, { sx: { py: 0 }, children: /* @__PURE__ */ jsx(ListItemText, { primaryTypographyProps: { variant: "caption" }, primary: "\u2022 Structured release cycles" }) }),
                    /* @__PURE__ */ jsx(ListItem, { sx: { py: 0 }, children: /* @__PURE__ */ jsx(ListItemText, { primaryTypographyProps: { variant: "caption" }, primary: "\u2022 Parallel development" }) }),
                    /* @__PURE__ */ jsx(ListItem, { sx: { py: 0 }, children: /* @__PURE__ */ jsx(ListItemText, { primaryTypographyProps: { variant: "caption" }, primary: "\u2022 Better for versioned releases" }) })
                  ] })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.3)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#f59e0b", mb: 1 }, children: "Trunk-Based" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Everyone commits to main. Short-lived branches only." }),
                  /* @__PURE__ */ jsxs(List, { dense: true, sx: { py: 0 }, children: [
                    /* @__PURE__ */ jsx(ListItem, { sx: { py: 0 }, children: /* @__PURE__ */ jsx(ListItemText, { primaryTypographyProps: { variant: "caption" }, primary: "\u2022 Fastest integration" }) }),
                    /* @__PURE__ */ jsx(ListItem, { sx: { py: 0 }, children: /* @__PURE__ */ jsx(ListItemText, { primaryTypographyProps: { variant: "caption" }, primary: "\u2022 Requires good CI/CD" }) }),
                    /* @__PURE__ */ jsx(ListItem, { sx: { py: 0 }, children: /* @__PURE__ */ jsx(ListItemText, { primaryTypographyProps: { variant: "caption" }, primary: "\u2022 Used by Google, Facebook" }) })
                  ] })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Code Review Best Practices" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2 }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#22c55e", mb: 1 }, children: "For Authors" }),
                  /* @__PURE__ */ jsxs(List, { dense: true, children: [
                    /* @__PURE__ */ jsx(ListItem, { children: /* @__PURE__ */ jsx(ListItemText, { primary: "Keep PRs small and focused" }) }),
                    /* @__PURE__ */ jsx(ListItem, { children: /* @__PURE__ */ jsx(ListItemText, { primary: "Write clear PR descriptions" }) }),
                    /* @__PURE__ */ jsx(ListItem, { children: /* @__PURE__ */ jsx(ListItemText, { primary: "Self-review before requesting" }) }),
                    /* @__PURE__ */ jsx(ListItem, { children: /* @__PURE__ */ jsx(ListItemText, { primary: "Respond to feedback promptly" }) })
                  ] })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#3b82f6", 0.08), border: `1px solid ${alpha("#3b82f6", 0.2)}`, borderRadius: 2 }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#3b82f6", mb: 1 }, children: "For Reviewers" }),
                  /* @__PURE__ */ jsxs(List, { dense: true, children: [
                    /* @__PURE__ */ jsx(ListItem, { children: /* @__PURE__ */ jsx(ListItemText, { primary: "Be constructive, not critical" }) }),
                    /* @__PURE__ */ jsx(ListItem, { children: /* @__PURE__ */ jsx(ListItemText, { primary: "Explain the 'why' of suggestions" }) }),
                    /* @__PURE__ */ jsx(ListItem, { children: /* @__PURE__ */ jsx(ListItemText, { primary: "Approve when good enough" }) }),
                    /* @__PURE__ */ jsx(ListItem, { children: /* @__PURE__ */ jsx(ListItemText, { primary: "Review within 24 hours" }) })
                  ] })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Protected Branches" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "Protected branches prevent direct pushes and require PRs with reviews. Configure in repository settings:" }),
              /* @__PURE__ */ jsxs(List, { dense: true, sx: { mb: 2 }, children: [
                /* @__PURE__ */ jsxs(ListItem, { children: [
                  /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                  /* @__PURE__ */ jsx(ListItemText, { primary: "Require pull request reviews before merging" })
                ] }),
                /* @__PURE__ */ jsxs(ListItem, { children: [
                  /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                  /* @__PURE__ */ jsx(ListItemText, { primary: "Require status checks to pass (CI/CD)" })
                ] }),
                /* @__PURE__ */ jsxs(ListItem, { children: [
                  /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                  /* @__PURE__ */ jsx(ListItemText, { primary: "Require conversation resolution" })
                ] }),
                /* @__PURE__ */ jsxs(ListItem, { children: [
                  /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                  /* @__PURE__ */ jsx(ListItemText, { primary: "Require signed commits" })
                ] }),
                /* @__PURE__ */ jsxs(ListItem, { children: [
                  /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                  /* @__PURE__ */ jsx(ListItemText, { primary: "Restrict who can push" })
                ] })
              ] }),
              /* @__PURE__ */ jsx(ProTip, { children: "Always protect your main/master branch in team projects. This ensures all changes go through code review and prevents accidental force pushes that could lose work." })
            ]
          }
        ),
        /* @__PURE__ */ jsxs(
          Paper,
          {
            id: "undoing-changes",
            sx: {
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px"
            },
            children: [
              /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }, children: [
                /* @__PURE__ */ jsxs(Typography, { variant: "h5", sx: { fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }, children: [
                  /* @__PURE__ */ jsx(RestoreIcon, { sx: { color: "#f14e32" } }),
                  "Undoing Changes"
                ] }),
                /* @__PURE__ */ jsx(DifficultyBadge, { level: "intermediate" })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "Quick Reference: What Do You Want to Undo?" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.3)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#3b82f6", mb: 1 }, children: "Uncommitted Changes" }),
                  /* @__PURE__ */ jsxs(Typography, { variant: "body2", sx: { fontFamily: "monospace", fontSize: "0.85rem" }, children: [
                    "Unstaged edits \u2192 ",
                    /* @__PURE__ */ jsx("code", { children: "git restore" }),
                    /* @__PURE__ */ jsx("br", {}),
                    "Staged files \u2192 ",
                    /* @__PURE__ */ jsx("code", { children: "git restore --staged" }),
                    /* @__PURE__ */ jsx("br", {}),
                    "All changes \u2192 ",
                    /* @__PURE__ */ jsx("code", { children: "git checkout ." })
                  ] })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.3)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#22c55e", mb: 1 }, children: "Committed Changes" }),
                  /* @__PURE__ */ jsxs(Typography, { variant: "body2", sx: { fontFamily: "monospace", fontSize: "0.85rem" }, children: [
                    "Last commit msg \u2192 ",
                    /* @__PURE__ */ jsx("code", { children: "git commit --amend" }),
                    /* @__PURE__ */ jsx("br", {}),
                    "Undo commit (keep files) \u2192 ",
                    /* @__PURE__ */ jsx("code", { children: "git reset --soft" }),
                    /* @__PURE__ */ jsx("br", {}),
                    "Undo publicly \u2192 ",
                    /* @__PURE__ */ jsx("code", { children: "git revert" })
                  ] })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Discarding Unstaged Changes" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Discard changes in working directory",
                  code: `# Discard changes in specific file
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
git clean -fd  # Delete untracked files AND directories`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsxs(WarningBox, { title: "These operations are destructive!", children: [
                "Discarding unstaged changes is permanent. Git cannot recover these changes since they were never committed. Always double-check with ",
                /* @__PURE__ */ jsx("code", { children: "git status" }),
                " or ",
                /* @__PURE__ */ jsx("code", { children: "git clean -n" }),
                " first."
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Unstaging Files" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Remove files from staging area (keep changes)",
                  code: `# Unstage specific file (keep changes in working dir)
git restore --staged file.txt
# or older way:
git reset HEAD file.txt

# Unstage all files
git restore --staged .
# or:
git reset HEAD

# Unstage and discard changes (combined)
git restore --staged --worktree file.txt`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Understanding git reset" }),
              /* @__PURE__ */ jsxs(Typography, { paragraph: true, children: [
                /* @__PURE__ */ jsx("code", { children: "git reset" }),
                " moves the HEAD pointer and optionally modifies staging area and working directory:"
              ] }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#22c55e", mb: 1 }, children: "--soft" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Move HEAD only. Keep staged and working dir." }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontFamily: "monospace", display: "block" }, children: "Safest. Good for re-committing." })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#f59e0b", 0.08), border: `1px solid ${alpha("#f59e0b", 0.2)}`, borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#f59e0b", mb: 1 }, children: "--mixed (default)" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Move HEAD, reset staging. Keep working dir." }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontFamily: "monospace", display: "block" }, children: "Good for re-staging differently." })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#ef4444", 0.08), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#ef4444", mb: 1 }, children: "--hard" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", sx: { mb: 1 }, children: "Move HEAD, reset staging AND working dir." }),
                  /* @__PURE__ */ jsx(Typography, { variant: "caption", sx: { fontFamily: "monospace", display: "block" }, children: "DANGEROUS! Loses all changes." })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "git reset examples",
                  code: `# Undo last commit, keep changes staged
git reset --soft HEAD~1

# Undo last commit, unstage changes (keep in working dir)
git reset HEAD~1
git reset --mixed HEAD~1  # same thing

# Undo last commit AND discard all changes
git reset --hard HEAD~1

# Go back 3 commits
git reset --hard HEAD~3

# Reset to specific commit
git reset --hard abc1234`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "git revert: Safe Undo for Public Commits" }),
              /* @__PURE__ */ jsxs(Typography, { paragraph: true, children: [
                /* @__PURE__ */ jsx("code", { children: "git revert" }),
                " creates a NEW commit that undoes the changes. It's safe for shared branches because it doesn't rewrite history."
              ] }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "git revert examples",
                  code: `# Revert the last commit
git revert HEAD

# Revert a specific commit
git revert abc1234

# Revert without auto-commit (stage changes only)
git revert --no-commit abc1234

# Revert multiple commits
git revert HEAD~3..HEAD  # Revert last 3 commits

# Revert a merge commit (specify parent)
git revert -m 1 abc1234  # -m 1 keeps first parent`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsxs(InfoBox, { title: "reset vs revert", children: [
                "Use ",
                /* @__PURE__ */ jsx("code", { children: "reset" }),
                " for local/unpushed commits (rewrites history).",
                /* @__PURE__ */ jsx("br", {}),
                "Use ",
                /* @__PURE__ */ jsx("code", { children: "revert" }),
                " for pushed commits (creates new commit, safe for collaboration)."
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Recovering Lost Commits with Reflog" }),
              /* @__PURE__ */ jsxs(Typography, { paragraph: true, children: [
                "The reflog records every time HEAD moves. Even after ",
                /* @__PURE__ */ jsx("code", { children: "reset --hard" }),
                ", you can usually recover:"
              ] }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Using reflog to recover",
                  code: `# View reflog (history of HEAD movements)
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
git branch recovered-work def5678`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsx(ProTip, { children: "The reflog is your safety net! Commits aren't truly lost until Git's garbage collection runs (usually 30+ days). If you accidentally reset --hard, don't panic\u2014check the reflog immediately." })
            ]
          }
        ),
        /* @__PURE__ */ jsxs(
          Paper,
          {
            id: "advanced-topics",
            sx: {
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px"
            },
            children: [
              /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }, children: [
                /* @__PURE__ */ jsxs(Typography, { variant: "h5", sx: { fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }, children: [
                  /* @__PURE__ */ jsx(SpeedIcon, { sx: { color: "#f14e32" } }),
                  "Advanced Git Topics"
                ] }),
                /* @__PURE__ */ jsx(DifficultyBadge, { level: "advanced" })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "Git Stash: Saving Work Temporarily" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: `Stash lets you save uncommitted changes and switch contexts. Perfect for "I need to switch branches but I'm not ready to commit."` }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Git stash commands",
                  code: `# Stash current changes (staged + unstaged)
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
git stash clear            # Delete ALL stashes`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsx(ProTip, { children: "Stashes are local-only and can be lost if you're not careful. For important WIP, consider creating a temporary commit or WIP branch instead." }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Cherry-Picking Commits" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "Cherry-pick applies a specific commit from one branch to another. Useful for applying bug fixes without merging entire branches." }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Cherry-pick examples",
                  code: `# Apply a specific commit to current branch
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
git cherry-pick --skip       # skip this commit`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Git Bisect: Finding Bugs with Binary Search" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "Bisect performs a binary search through your commit history to find which commit introduced a bug." }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Using git bisect",
                  code: `# Start bisecting
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
# Script should exit 0 for good, non-zero for bad`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Git Hooks: Automated Actions" }),
              /* @__PURE__ */ jsxs(Typography, { paragraph: true, children: [
                "Hooks are scripts that run automatically at certain Git events. They live in ",
                /* @__PURE__ */ jsx("code", { children: ".git/hooks/" }),
                "."
              ] }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.3)}` }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#3b82f6", mb: 1 }, children: "Client-Side Hooks" }),
                  /* @__PURE__ */ jsxs(Typography, { variant: "body2", sx: { fontFamily: "monospace", fontSize: "0.8rem" }, children: [
                    "pre-commit \u2192 Before commit is made",
                    /* @__PURE__ */ jsx("br", {}),
                    "prepare-commit-msg \u2192 Edit default message",
                    /* @__PURE__ */ jsx("br", {}),
                    "commit-msg \u2192 Validate commit message",
                    /* @__PURE__ */ jsx("br", {}),
                    "pre-push \u2192 Before push to remote"
                  ] })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.3)}` }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#22c55e", mb: 1 }, children: "Server-Side Hooks" }),
                  /* @__PURE__ */ jsxs(Typography, { variant: "body2", sx: { fontFamily: "monospace", fontSize: "0.8rem" }, children: [
                    "pre-receive \u2192 Before accepting push",
                    /* @__PURE__ */ jsx("br", {}),
                    "update \u2192 Per branch before update",
                    /* @__PURE__ */ jsx("br", {}),
                    "post-receive \u2192 After push complete",
                    /* @__PURE__ */ jsx("br", {})
                  ] })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Example: pre-commit hook for linting",
                  code: `#!/bin/sh
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

exit 0`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsxs(InfoBox, { title: "Use Husky for easier hooks", children: [
                "The ",
                /* @__PURE__ */ jsx("code", { children: "husky" }),
                " npm package makes managing Git hooks easier and allows committing hooks to your repo (normally .git/hooks isn't tracked). Install: ",
                /* @__PURE__ */ jsx("code", { children: "npx husky-init" })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Git Worktrees: Multiple Working Directories" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "Worktrees let you have multiple branches checked out simultaneously in different directories." }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Using worktrees",
                  code: `# Create a new worktree for a branch
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
# Review, test, then return to main worktree`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Git LFS: Large File Storage" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "Git LFS stores large files (images, videos, binaries) on a separate server, keeping your repo fast." }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Setting up Git LFS",
                  code: `# Install Git LFS
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
git lfs ls-files`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsx(WarningBox, { title: "LFS has storage limits", children: "GitHub, GitLab, and Bitbucket have LFS storage quotas (GitHub: 1GB free). Large repos may need paid plans or self-hosted LFS servers." })
            ]
          }
        ),
        /* @__PURE__ */ jsxs(
          Paper,
          {
            id: "github",
            sx: {
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px"
            },
            children: [
              /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }, children: [
                /* @__PURE__ */ jsxs(Typography, { variant: "h5", sx: { fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }, children: [
                  /* @__PURE__ */ jsx(CloudIcon, { sx: { color: "#f14e32" } }),
                  "GitHub"
                ] }),
                /* @__PURE__ */ jsx(DifficultyBadge, { level: "beginner" })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "What is GitHub?" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "GitHub is the world's largest code hosting platform, with over 100 million developers. It adds collaboration features on top of Git: pull requests, issues, project boards, wikis, and CI/CD with GitHub Actions." }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 3, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, textAlign: "center", borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "h4", sx: { fontWeight: 700, color: "#f14e32" }, children: "100M+" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Developers" })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 3, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, textAlign: "center", borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "h4", sx: { fontWeight: 700, color: "#f14e32" }, children: "420M+" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Repositories" })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 3, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, textAlign: "center", borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "h4", sx: { fontWeight: 700, color: "#f14e32" }, children: "4B+" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Contributions/year" })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 3, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, textAlign: "center", borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "h4", sx: { fontWeight: 700, color: "#f14e32" }, children: "90%" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Fortune 100 use it" })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Key GitHub Features" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#3b82f6", 0.3)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#3b82f6", mb: 1 }, children: "Pull Requests" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Propose changes, get code reviews, discuss modifications before merging. The heart of GitHub collaboration." })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#22c55e", 0.3)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#22c55e", mb: 1 }, children: "GitHub Actions" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Automate workflows with CI/CD. Run tests, build, deploy on every push or PR. Free for public repos." })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#f59e0b", 0.3)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#f59e0b", mb: 1 }, children: "Issues & Projects" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Track bugs, features, and tasks. Kanban boards for project management. Link issues to PRs." })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, border: `1px solid ${alpha("#8b5cf6", 0.3)}`, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#8b5cf6", mb: 1 }, children: "GitHub Copilot" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "AI pair programmer that suggests code in your editor. Trained on public repositories." })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "GitHub CLI (gh)" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "The official GitHub command-line tool for managing GitHub from your terminal:" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "GitHub CLI essentials",
                  code: `# Install GitHub CLI
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
gh browse`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "GitHub Actions: CI/CD" }),
              /* @__PURE__ */ jsxs(Typography, { paragraph: true, children: [
                "Automate testing, building, and deployment with workflow files in ",
                /* @__PURE__ */ jsx("code", { children: ".github/workflows/" }),
                ":"
              ] }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: ".github/workflows/ci.yml",
                  code: `name: CI

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
        run: npm run build`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsx(ProTip, { children: "GitHub Actions are free for public repositories and include 2,000 minutes/month for private repos on free tier. Use the Actions Marketplace for pre-built actions." }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "GitHub Pages" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "Free static website hosting directly from your repository:" }),
              /* @__PURE__ */ jsxs(List, { dense: true, children: [
                /* @__PURE__ */ jsxs(ListItem, { children: [
                  /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                  /* @__PURE__ */ jsx(ListItemText, { primary: "Free hosting for static sites", secondary: "Perfect for documentation, portfolios, project pages" })
                ] }),
                /* @__PURE__ */ jsxs(ListItem, { children: [
                  /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                  /* @__PURE__ */ jsx(ListItemText, { primary: "Custom domains supported", secondary: "Use your own domain with free HTTPS" })
                ] }),
                /* @__PURE__ */ jsxs(ListItem, { children: [
                  /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                  /* @__PURE__ */ jsx(ListItemText, { primary: "Automatic deployment", secondary: "Publish from main branch or gh-pages branch" })
                ] }),
                /* @__PURE__ */ jsxs(ListItem, { children: [
                  /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                  /* @__PURE__ */ jsx(ListItemText, { primary: "Jekyll integration", secondary: "Built-in support for Jekyll static site generator" })
                ] })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Special GitHub Files" }),
              /* @__PURE__ */ jsx(Paper, { sx: { overflow: "hidden", borderRadius: 2, mb: 3 }, children: /* @__PURE__ */ jsxs(Box, { component: "table", sx: { width: "100%", borderCollapse: "collapse", "& td, & th": { p: 1.5, borderBottom: "1px solid", borderColor: "divider", textAlign: "left" }, "& th": { bgcolor: alpha("#f14e32", 0.08), fontWeight: 700 } }, children: [
                /* @__PURE__ */ jsx("thead", { children: /* @__PURE__ */ jsxs("tr", { children: [
                  /* @__PURE__ */ jsx("th", { style: { width: "30%" }, children: "File" }),
                  /* @__PURE__ */ jsx("th", { children: "Purpose" })
                ] }) }),
                /* @__PURE__ */ jsxs("tbody", { children: [
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "README.md" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Repository description, shown on repo homepage" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "LICENSE" }) }),
                    /* @__PURE__ */ jsx("td", { children: "License for your project (MIT, Apache, GPL, etc.)" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "CONTRIBUTING.md" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Contribution guidelines for collaborators" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "CODE_OF_CONDUCT.md" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Community behavior expectations" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "SECURITY.md" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Security policy and vulnerability reporting" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: ".github/ISSUE_TEMPLATE/" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Templates for bug reports, feature requests" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: ".github/PULL_REQUEST_TEMPLATE.md" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Default PR description template" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "CODEOWNERS" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Auto-assign reviewers based on file paths" })
                  ] })
                ] })
              ] }) })
            ]
          }
        ),
        /* @__PURE__ */ jsxs(
          Paper,
          {
            id: "gitlab",
            sx: {
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px"
            },
            children: [
              /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }, children: [
                /* @__PURE__ */ jsxs(Typography, { variant: "h5", sx: { fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }, children: [
                  /* @__PURE__ */ jsx(CloudIcon, { sx: { color: "#f14e32" } }),
                  "GitLab"
                ] }),
                /* @__PURE__ */ jsx(DifficultyBadge, { level: "beginner" })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "What is GitLab?" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "GitLab is a complete DevOps platform delivered as a single application. Unlike GitHub, it provides built-in CI/CD, container registry, security scanning, and more\u2014all in one place. It's popular in enterprises and can be self-hosted." }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, textAlign: "center", borderRadius: 2, bgcolor: alpha("#fc6d26", 0.08), height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, color: "#fc6d26" }, children: "All-in-One" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "SCM, CI/CD, Security, and Monitoring in a single platform" })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, textAlign: "center", borderRadius: 2, bgcolor: alpha("#fc6d26", 0.08), height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, color: "#fc6d26" }, children: "Self-Hosted" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Run on your own servers for complete control and privacy" })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, textAlign: "center", borderRadius: 2, bgcolor: alpha("#fc6d26", 0.08), height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, color: "#fc6d26" }, children: "Open Core" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Open source Community Edition available for free" })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "GitLab vs GitHub" }),
              /* @__PURE__ */ jsx(Paper, { sx: { overflow: "hidden", borderRadius: 2, mb: 3 }, children: /* @__PURE__ */ jsxs(Box, { component: "table", sx: { width: "100%", borderCollapse: "collapse", "& td, & th": { p: 1.5, borderBottom: "1px solid", borderColor: "divider", textAlign: "left" }, "& th": { bgcolor: alpha("#f14e32", 0.08), fontWeight: 700 } }, children: [
                /* @__PURE__ */ jsx("thead", { children: /* @__PURE__ */ jsxs("tr", { children: [
                  /* @__PURE__ */ jsx("th", { children: "Feature" }),
                  /* @__PURE__ */ jsx("th", { children: "GitHub" }),
                  /* @__PURE__ */ jsx("th", { children: "GitLab" })
                ] }) }),
                /* @__PURE__ */ jsxs("tbody", { children: [
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: "CI/CD" }),
                    /* @__PURE__ */ jsx("td", { children: "GitHub Actions (separate)" }),
                    /* @__PURE__ */ jsx("td", { children: "Built-in GitLab CI/CD" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: "Self-Hosting" }),
                    /* @__PURE__ */ jsx("td", { children: "Enterprise only (paid)" }),
                    /* @__PURE__ */ jsx("td", { children: "Free Community Edition" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: "Container Registry" }),
                    /* @__PURE__ */ jsx("td", { children: "GitHub Packages" }),
                    /* @__PURE__ */ jsx("td", { children: "Built-in registry" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: "Security Scanning" }),
                    /* @__PURE__ */ jsx("td", { children: "Dependabot, CodeQL" }),
                    /* @__PURE__ */ jsx("td", { children: "SAST, DAST, Dependency Scanning" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: "Issue Tracking" }),
                    /* @__PURE__ */ jsx("td", { children: "Issues + Projects" }),
                    /* @__PURE__ */ jsx("td", { children: "Issues + Boards + Epics" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: "PR/MR Name" }),
                    /* @__PURE__ */ jsx("td", { children: "Pull Request" }),
                    /* @__PURE__ */ jsx("td", { children: "Merge Request" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: "Best For" }),
                    /* @__PURE__ */ jsx("td", { children: "Open source, community" }),
                    /* @__PURE__ */ jsx("td", { children: "Enterprise, DevOps teams" })
                  ] })
                ] })
              ] }) }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "GitLab CI/CD (.gitlab-ci.yml)" }),
              /* @__PURE__ */ jsxs(Typography, { paragraph: true, children: [
                "GitLab CI/CD is configured with a ",
                /* @__PURE__ */ jsx("code", { children: ".gitlab-ci.yml" }),
                " file in your repository root:"
              ] }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: ".gitlab-ci.yml example",
                  code: `stages:
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
  when: manual`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsxs(InfoBox, { title: "GitLab CI/CD Terminology", children: [
                /* @__PURE__ */ jsx("strong", { children: "Pipeline:" }),
                " A collection of jobs organized in stages.",
                /* @__PURE__ */ jsx("br", {}),
                /* @__PURE__ */ jsx("strong", { children: "Job:" }),
                " Individual tasks that run scripts (build, test, deploy).",
                /* @__PURE__ */ jsx("br", {}),
                /* @__PURE__ */ jsx("strong", { children: "Stage:" }),
                " Groups of jobs that run in sequence.",
                /* @__PURE__ */ jsx("br", {}),
                /* @__PURE__ */ jsx("strong", { children: "Runner:" }),
                " The server that executes jobs (shared or self-hosted)."
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Merge Requests (MRs)" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "GitLab calls them Merge Requests instead of Pull Requests. The workflow is similar:" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Creating a Merge Request",
                  code: `# Using GitLab CLI (glab)
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
git push -o merge_request.create   -o merge_request.target=main   -o merge_request.title="My feature"`
                }
              ),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Unique GitLab Features" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#fc6d26", mb: 1 }, children: "Auto DevOps" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Automatically detects your project type and sets up CI/CD pipelines, security scanning, and deployment with zero configuration." })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#fc6d26", mb: 1 }, children: "Built-in Security" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "SAST, DAST, dependency scanning, container scanning, and secret detection built into the platform." })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#fc6d26", mb: 1 }, children: "GitLab Pages" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Free static website hosting similar to GitHub Pages. Supports custom domains and SSL." })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#fc6d26", mb: 1 }, children: "Kubernetes Integration" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Native Kubernetes integration for deployment, monitoring, and cluster management." })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "GitLab CLI (glab)" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "GitLab CLI essentials",
                  code: `# Install GitLab CLI
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
glab repo view --web`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsx(ProTip, { children: "GitLab offers a generous free tier including unlimited private repos, 5 users per group, 400 CI/CD minutes/month, and 5GB storage. The Community Edition can be self-hosted for free with no user limits." })
            ]
          }
        ),
        /* @__PURE__ */ jsxs(
          Paper,
          {
            id: "best-practices",
            sx: {
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px"
            },
            children: [
              /* @__PURE__ */ jsxs(Box, { sx: { display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }, children: [
                /* @__PURE__ */ jsxs(Typography, { variant: "h5", sx: { fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }, children: [
                  /* @__PURE__ */ jsx(CheckCircleIcon, { sx: { color: "#f14e32" } }),
                  "Git Best Practices"
                ] }),
                /* @__PURE__ */ jsx(DifficultyBadge, { level: "intermediate" })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mb: 2, color: "#f14e32" }, children: "Commit Best Practices" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#22c55e", 0.08), border: `1px solid ${alpha("#22c55e", 0.2)}`, borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#22c55e", mb: 1 }, children: "\u2713 Do" }),
                  /* @__PURE__ */ jsxs(List, { dense: true, children: [
                    /* @__PURE__ */ jsxs(ListItem, { children: [
                      /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                      /* @__PURE__ */ jsx(ListItemText, { primary: "Commit early and commit often" })
                    ] }),
                    /* @__PURE__ */ jsxs(ListItem, { children: [
                      /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                      /* @__PURE__ */ jsx(ListItemText, { primary: "Write clear, descriptive commit messages" })
                    ] }),
                    /* @__PURE__ */ jsxs(ListItem, { children: [
                      /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                      /* @__PURE__ */ jsx(ListItemText, { primary: "Keep commits atomic (one logical change)" })
                    ] }),
                    /* @__PURE__ */ jsxs(ListItem, { children: [
                      /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                      /* @__PURE__ */ jsx(ListItemText, { primary: "Test before committing" })
                    ] }),
                    /* @__PURE__ */ jsxs(ListItem, { children: [
                      /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                      /* @__PURE__ */ jsx(ListItemText, { primary: "Review your diff before committing" })
                    ] })
                  ] })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 6, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, bgcolor: alpha("#ef4444", 0.08), border: `1px solid ${alpha("#ef4444", 0.2)}`, borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "subtitle1", sx: { fontWeight: 700, color: "#ef4444", mb: 1 }, children: "\u2717 Don't" }),
                  /* @__PURE__ */ jsxs(List, { dense: true, children: [
                    /* @__PURE__ */ jsxs(ListItem, { children: [
                      /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(WarningIcon, { color: "error", fontSize: "small" }) }),
                      /* @__PURE__ */ jsx(ListItemText, { primary: "Commit broken code to shared branches" })
                    ] }),
                    /* @__PURE__ */ jsxs(ListItem, { children: [
                      /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(WarningIcon, { color: "error", fontSize: "small" }) }),
                      /* @__PURE__ */ jsx(ListItemText, { primary: "Use vague messages like 'fix' or 'update'" })
                    ] }),
                    /* @__PURE__ */ jsxs(ListItem, { children: [
                      /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(WarningIcon, { color: "error", fontSize: "small" }) }),
                      /* @__PURE__ */ jsx(ListItemText, { primary: "Bundle unrelated changes in one commit" })
                    ] }),
                    /* @__PURE__ */ jsxs(ListItem, { children: [
                      /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(WarningIcon, { color: "error", fontSize: "small" }) }),
                      /* @__PURE__ */ jsx(ListItemText, { primary: "Commit sensitive data (passwords, keys)" })
                    ] }),
                    /* @__PURE__ */ jsxs(ListItem, { children: [
                      /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(WarningIcon, { color: "error", fontSize: "small" }) }),
                      /* @__PURE__ */ jsx(ListItemText, { primary: "Commit generated files or dependencies" })
                    ] })
                  ] })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: ".gitignore Best Practices" }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "A well-configured .gitignore prevents unnecessary files from cluttering your repository:" }),
              /* @__PURE__ */ jsx(
                CodeBlock,
                {
                  title: "Common .gitignore patterns",
                  code: `# Dependencies
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
.DS_Store`
                }
              ),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsxs(ProTip, { children: [
                "Use ",
                /* @__PURE__ */ jsx("code", { children: "gitignore.io" }),
                " to generate .gitignore files for your tech stack. Run: ",
                /* @__PURE__ */ jsx("code", { children: "curl -sL https://www.toptal.com/developers/gitignore/api/node,react,visualstudiocode" })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Branch Hygiene" }),
              /* @__PURE__ */ jsxs(List, { children: [
                /* @__PURE__ */ jsxs(ListItem, { children: [
                  /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success" }) }),
                  /* @__PURE__ */ jsx(ListItemText, { primary: "Delete branches after merging", secondary: "Keep your branch list clean. Use 'git branch -d' after PRs are merged." })
                ] }),
                /* @__PURE__ */ jsxs(ListItem, { children: [
                  /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success" }) }),
                  /* @__PURE__ */ jsx(ListItemText, { primary: "Use descriptive branch names", secondary: "feature/user-auth, bugfix/login-error, hotfix/security-patch" })
                ] }),
                /* @__PURE__ */ jsxs(ListItem, { children: [
                  /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success" }) }),
                  /* @__PURE__ */ jsx(ListItemText, { primary: "Keep branches short-lived", secondary: "Long-running feature branches lead to painful merges. Merge frequently." })
                ] }),
                /* @__PURE__ */ jsxs(ListItem, { children: [
                  /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success" }) }),
                  /* @__PURE__ */ jsx(ListItemText, { primary: "Protect important branches", secondary: "Configure branch protection rules to require reviews and passing CI." })
                ] })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Collaboration Tips" }),
              /* @__PURE__ */ jsxs(Grid, { container: true, spacing: 2, sx: { mb: 3 }, children: [
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, textAlign: "center", borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, color: "#3b82f6", mb: 1 }, children: "Pull Before Push" }),
                  /* @__PURE__ */ jsxs(Typography, { variant: "body2", children: [
                    "Always ",
                    /* @__PURE__ */ jsx("code", { children: "git pull" }),
                    " before pushing to avoid conflicts and rejected pushes."
                  ] })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, textAlign: "center", borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, color: "#22c55e", mb: 1 }, children: "Review Before Merge" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Never merge your own PRs without review in team projects. Fresh eyes catch bugs." })
                ] }) }),
                /* @__PURE__ */ jsx(Grid, { item: true, xs: 12, md: 4, children: /* @__PURE__ */ jsxs(Paper, { sx: { p: 2, textAlign: "center", borderRadius: 2, height: "100%" }, children: [
                  /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, color: "#f59e0b", mb: 1 }, children: "Communicate Changes" }),
                  /* @__PURE__ */ jsx(Typography, { variant: "body2", children: "Announce breaking changes. Tag releases. Keep changelog updated." })
                ] }) })
              ] }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 4, mb: 2, color: "#f14e32" }, children: "Security Best Practices" }),
              /* @__PURE__ */ jsx(WarningBox, { title: "Never commit secrets!", children: "API keys, passwords, tokens, and private keys should NEVER be in your repository. Even if you delete them later, they remain in Git history. Use environment variables and secret management tools instead." }),
              /* @__PURE__ */ jsx(Box, { sx: { mt: 2 } }),
              /* @__PURE__ */ jsxs(List, { dense: true, children: [
                /* @__PURE__ */ jsxs(ListItem, { children: [
                  /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                  /* @__PURE__ */ jsx(ListItemText, { primary: "Use environment variables for secrets" })
                ] }),
                /* @__PURE__ */ jsxs(ListItem, { children: [
                  /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                  /* @__PURE__ */ jsx(ListItemText, { primary: "Add secret patterns to .gitignore (.env, *.pem, *.key)" })
                ] }),
                /* @__PURE__ */ jsxs(ListItem, { children: [
                  /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                  /* @__PURE__ */ jsx(ListItemText, { primary: "Use git-secrets or pre-commit hooks to prevent accidental commits" })
                ] }),
                /* @__PURE__ */ jsxs(ListItem, { children: [
                  /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                  /* @__PURE__ */ jsx(ListItemText, { primary: "Rotate any secrets that were accidentally committed" })
                ] }),
                /* @__PURE__ */ jsxs(ListItem, { children: [
                  /* @__PURE__ */ jsx(ListItemIcon, { children: /* @__PURE__ */ jsx(CheckCircleIcon, { color: "success", fontSize: "small" }) }),
                  /* @__PURE__ */ jsx(ListItemText, { primary: "Sign commits with GPG for verified identity" })
                ] })
              ] })
            ]
          }
        ),
        /* @__PURE__ */ jsxs(
          Paper,
          {
            id: "common-commands",
            sx: {
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px"
            },
            children: [
              /* @__PURE__ */ jsx(Box, { sx: { display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }, children: /* @__PURE__ */ jsxs(Typography, { variant: "h5", sx: { fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }, children: [
                /* @__PURE__ */ jsx(TerminalIcon, { sx: { color: "#f14e32" } }),
                "Git Command Reference"
              ] }) }),
              /* @__PURE__ */ jsx(Typography, { paragraph: true, children: "A comprehensive reference of essential Git commands organized by category. Bookmark this section!" }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 3, mb: 2, color: "#f14e32" }, children: "\u{1F6E0}\uFE0F Setup & Configuration" }),
              /* @__PURE__ */ jsx(Paper, { sx: { overflow: "hidden", borderRadius: 2, mb: 3 }, children: /* @__PURE__ */ jsxs(Box, { component: "table", sx: { width: "100%", borderCollapse: "collapse", "& td, & th": { p: 1.5, borderBottom: "1px solid", borderColor: "divider", textAlign: "left" }, "& th": { bgcolor: alpha("#f14e32", 0.08), fontWeight: 700 } }, children: [
                /* @__PURE__ */ jsx("thead", { children: /* @__PURE__ */ jsxs("tr", { children: [
                  /* @__PURE__ */ jsx("th", { style: { width: "35%" }, children: "Command" }),
                  /* @__PURE__ */ jsx("th", { children: "Description" })
                ] }) }),
                /* @__PURE__ */ jsxs("tbody", { children: [
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: 'git config --global user.name "Name"' }) }),
                    /* @__PURE__ */ jsx("td", { children: "Set your name for all repos" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: 'git config --global user.email "email"' }) }),
                    /* @__PURE__ */ jsx("td", { children: "Set your email for all repos" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git config --list" }) }),
                    /* @__PURE__ */ jsx("td", { children: "View all configuration settings" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git init" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Initialize a new Git repository" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git clone <url>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Clone a remote repository" })
                  ] })
                ] })
              ] }) }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 3, mb: 2, color: "#f14e32" }, children: "\u{1F4F8} Basic Snapshotting" }),
              /* @__PURE__ */ jsx(Paper, { sx: { overflow: "hidden", borderRadius: 2, mb: 3 }, children: /* @__PURE__ */ jsxs(Box, { component: "table", sx: { width: "100%", borderCollapse: "collapse", "& td, & th": { p: 1.5, borderBottom: "1px solid", borderColor: "divider", textAlign: "left" }, "& th": { bgcolor: alpha("#f14e32", 0.08), fontWeight: 700 } }, children: [
                /* @__PURE__ */ jsx("thead", { children: /* @__PURE__ */ jsxs("tr", { children: [
                  /* @__PURE__ */ jsx("th", { style: { width: "35%" }, children: "Command" }),
                  /* @__PURE__ */ jsx("th", { children: "Description" })
                ] }) }),
                /* @__PURE__ */ jsxs("tbody", { children: [
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git status" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Show working directory status" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git add <file>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Stage a specific file" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git add ." }) }),
                    /* @__PURE__ */ jsx("td", { children: "Stage all changes in current directory" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git add -A" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Stage all changes (entire repo)" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: 'git commit -m "message"' }) }),
                    /* @__PURE__ */ jsx("td", { children: "Commit staged changes with message" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git commit --amend" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Modify the last commit" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git diff" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Show unstaged changes" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git diff --staged" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Show staged changes" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git restore <file>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Discard changes in working directory" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git restore --staged <file>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Unstage a file" })
                  ] })
                ] })
              ] }) }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 3, mb: 2, color: "#f14e32" }, children: "\u{1F333} Branching & Merging" }),
              /* @__PURE__ */ jsx(Paper, { sx: { overflow: "hidden", borderRadius: 2, mb: 3 }, children: /* @__PURE__ */ jsxs(Box, { component: "table", sx: { width: "100%", borderCollapse: "collapse", "& td, & th": { p: 1.5, borderBottom: "1px solid", borderColor: "divider", textAlign: "left" }, "& th": { bgcolor: alpha("#f14e32", 0.08), fontWeight: 700 } }, children: [
                /* @__PURE__ */ jsx("thead", { children: /* @__PURE__ */ jsxs("tr", { children: [
                  /* @__PURE__ */ jsx("th", { style: { width: "35%" }, children: "Command" }),
                  /* @__PURE__ */ jsx("th", { children: "Description" })
                ] }) }),
                /* @__PURE__ */ jsxs("tbody", { children: [
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git branch" }) }),
                    /* @__PURE__ */ jsx("td", { children: "List local branches" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git branch <name>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Create a new branch" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git branch -d <name>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Delete a merged branch" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git branch -D <name>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Force delete a branch" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git switch <branch>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Switch to a branch" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git switch -c <branch>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Create and switch to branch" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git checkout <branch>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Switch branches (legacy)" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git merge <branch>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Merge branch into current" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git rebase <branch>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Rebase current onto branch" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git rebase -i HEAD~n" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Interactive rebase last n commits" })
                  ] })
                ] })
              ] }) }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 3, mb: 2, color: "#f14e32" }, children: "\u2601\uFE0F Remote Operations" }),
              /* @__PURE__ */ jsx(Paper, { sx: { overflow: "hidden", borderRadius: 2, mb: 3 }, children: /* @__PURE__ */ jsxs(Box, { component: "table", sx: { width: "100%", borderCollapse: "collapse", "& td, & th": { p: 1.5, borderBottom: "1px solid", borderColor: "divider", textAlign: "left" }, "& th": { bgcolor: alpha("#f14e32", 0.08), fontWeight: 700 } }, children: [
                /* @__PURE__ */ jsx("thead", { children: /* @__PURE__ */ jsxs("tr", { children: [
                  /* @__PURE__ */ jsx("th", { style: { width: "35%" }, children: "Command" }),
                  /* @__PURE__ */ jsx("th", { children: "Description" })
                ] }) }),
                /* @__PURE__ */ jsxs("tbody", { children: [
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git remote -v" }) }),
                    /* @__PURE__ */ jsx("td", { children: "List remotes with URLs" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git remote add <name> <url>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Add a new remote" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git fetch" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Download from remote (no merge)" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git pull" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Fetch and merge remote changes" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git push" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Upload commits to remote" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git push -u origin <branch>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Push and set upstream" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git push --force-with-lease" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Safe force push" })
                  ] })
                ] })
              ] }) }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 3, mb: 2, color: "#f14e32" }, children: "\u{1F50D} Inspection & History" }),
              /* @__PURE__ */ jsx(Paper, { sx: { overflow: "hidden", borderRadius: 2, mb: 3 }, children: /* @__PURE__ */ jsxs(Box, { component: "table", sx: { width: "100%", borderCollapse: "collapse", "& td, & th": { p: 1.5, borderBottom: "1px solid", borderColor: "divider", textAlign: "left" }, "& th": { bgcolor: alpha("#f14e32", 0.08), fontWeight: 700 } }, children: [
                /* @__PURE__ */ jsx("thead", { children: /* @__PURE__ */ jsxs("tr", { children: [
                  /* @__PURE__ */ jsx("th", { style: { width: "35%" }, children: "Command" }),
                  /* @__PURE__ */ jsx("th", { children: "Description" })
                ] }) }),
                /* @__PURE__ */ jsxs("tbody", { children: [
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git log" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Show commit history" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git log --oneline" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Compact commit history" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git log --graph --all" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Visual branch history" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git show <commit>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Show commit details" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git blame <file>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Show who changed each line" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git reflog" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Show HEAD movement history" })
                  ] })
                ] })
              ] }) }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 3, mb: 2, color: "#f14e32" }, children: "\u21A9\uFE0F Undoing Changes" }),
              /* @__PURE__ */ jsx(Paper, { sx: { overflow: "hidden", borderRadius: 2, mb: 3 }, children: /* @__PURE__ */ jsxs(Box, { component: "table", sx: { width: "100%", borderCollapse: "collapse", "& td, & th": { p: 1.5, borderBottom: "1px solid", borderColor: "divider", textAlign: "left" }, "& th": { bgcolor: alpha("#f14e32", 0.08), fontWeight: 700 } }, children: [
                /* @__PURE__ */ jsx("thead", { children: /* @__PURE__ */ jsxs("tr", { children: [
                  /* @__PURE__ */ jsx("th", { style: { width: "35%" }, children: "Command" }),
                  /* @__PURE__ */ jsx("th", { children: "Description" })
                ] }) }),
                /* @__PURE__ */ jsxs("tbody", { children: [
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git reset --soft HEAD~1" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Undo commit, keep staged" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git reset HEAD~1" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Undo commit, unstage changes" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git reset --hard HEAD~1" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Undo commit, discard changes" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git revert <commit>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Create commit that undoes changes" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git clean -fd" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Remove untracked files/dirs" })
                  ] })
                ] })
              ] }) }),
              /* @__PURE__ */ jsx(Typography, { variant: "h6", sx: { fontWeight: 700, mt: 3, mb: 2, color: "#f14e32" }, children: "\u{1F680} Advanced Commands" }),
              /* @__PURE__ */ jsx(Paper, { sx: { overflow: "hidden", borderRadius: 2, mb: 3 }, children: /* @__PURE__ */ jsxs(Box, { component: "table", sx: { width: "100%", borderCollapse: "collapse", "& td, & th": { p: 1.5, borderBottom: "1px solid", borderColor: "divider", textAlign: "left" }, "& th": { bgcolor: alpha("#f14e32", 0.08), fontWeight: 700 } }, children: [
                /* @__PURE__ */ jsx("thead", { children: /* @__PURE__ */ jsxs("tr", { children: [
                  /* @__PURE__ */ jsx("th", { style: { width: "35%" }, children: "Command" }),
                  /* @__PURE__ */ jsx("th", { children: "Description" })
                ] }) }),
                /* @__PURE__ */ jsxs("tbody", { children: [
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git stash" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Save uncommitted changes temporarily" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git stash pop" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Apply and remove latest stash" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git cherry-pick <commit>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Apply specific commit to current branch" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git bisect start" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Start binary search for bug" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git worktree add <path> <branch>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Create additional working directory" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: "git tag <name>" }) }),
                    /* @__PURE__ */ jsx("td", { children: "Create a tag at current commit" })
                  ] }),
                  /* @__PURE__ */ jsxs("tr", { children: [
                    /* @__PURE__ */ jsx("td", { children: /* @__PURE__ */ jsx("code", { children: 'git tag -a <name> -m "msg"' }) }),
                    /* @__PURE__ */ jsx("td", { children: "Create annotated tag" })
                  ] })
                ] })
              ] }) }),
              /* @__PURE__ */ jsxs(ProTip, { children: [
                "Create aliases for commands you use frequently! For example: ",
                /* @__PURE__ */ jsx("code", { children: "git config --global alias.st status" }),
                "lets you type ",
                /* @__PURE__ */ jsx("code", { children: "git st" }),
                " instead of ",
                /* @__PURE__ */ jsx("code", { children: "git status" }),
                "."
              ] })
            ]
          }
        ),
        /* @__PURE__ */ jsxs(
          Paper,
          {
            id: "quiz",
            sx: {
              p: 4,
              mb: 4,
              borderRadius: 4,
              border: `1px solid ${alpha("#f14e32", 0.15)}`,
              scrollMarginTop: "100px"
            },
            children: [
              /* @__PURE__ */ jsx(Box, { sx: { display: "flex", alignItems: "center", justifyContent: "space-between", mb: 3, flexWrap: "wrap", gap: 2 }, children: /* @__PURE__ */ jsxs(Typography, { variant: "h5", sx: { fontWeight: 800, display: "flex", alignItems: "center", gap: 2 }, children: [
                /* @__PURE__ */ jsx(QuizIcon, { sx: { color: "#f14e32" } }),
                "Test Your Knowledge"
              ] }) }),
              /* @__PURE__ */ jsx(QuizSection, {})
            ]
          }
        )
      ] })
    ] })
  ] });
};
var GitVersionControlPage_default = GitVersionControlPage;
export {
  GitVersionControlPage_default as default
};
