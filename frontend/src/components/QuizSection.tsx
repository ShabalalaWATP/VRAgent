import React, { useState } from "react";
import {
  Box,
  Typography,
  Paper,
  Button,
  Radio,
  RadioGroup,
  FormControlLabel,
  alpha,
  LinearProgress,
} from "@mui/material";
import QuizIcon from "@mui/icons-material/Quiz";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import RefreshIcon from "@mui/icons-material/Refresh";

export interface QuizQuestion {
  id: number;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
  topic?: string;
}

interface QuizSectionProps {
  questions: QuizQuestion[];
  accentColor?: string;
  title?: string;
  description?: string;
  questionsPerQuiz?: number;
}

const QuizSection: React.FC<QuizSectionProps> = ({
  questions: questionBank,
  accentColor = "#6366f1",
  title = "Knowledge Check",
  description = "Test your understanding with these randomly selected questions.",
  questionsPerQuiz = 10,
}) => {
  const [quizState, setQuizState] = useState<"start" | "active" | "results">("start");
  const [questions, setQuestions] = useState<QuizQuestion[]>([]);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<{ [key: number]: number }>({});
  const [showExplanation, setShowExplanation] = useState(false);
  const [score, setScore] = useState(0);

  const QUESTIONS_PER_QUIZ = Math.min(questionsPerQuiz, questionBank.length);
  const accent = accentColor;
  const accentDark = accentColor;
  const success = "#22c55e";
  const error = "#ef4444";

  // Shuffle options within a question and update correctAnswer index
  const shuffleQuestionOptions = (question: QuizQuestion): QuizQuestion => {
    const correctAnswerText = question.options[question.correctAnswer];
    
    // Create array of option indices and shuffle them
    const indices = question.options.map((_, idx) => idx);
    for (let i = indices.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [indices[i], indices[j]] = [indices[j], indices[i]];
    }
    
    // Reorder options based on shuffled indices
    const shuffledOptions = indices.map(idx => question.options[idx]);
    
    // Find new index of correct answer
    const newCorrectAnswer = shuffledOptions.indexOf(correctAnswerText);
    
    return {
      ...question,
      options: shuffledOptions,
      correctAnswer: newCorrectAnswer,
    };
  };

  const startQuiz = () => {
    // Shuffle questions
    const shuffledQuestions = [...questionBank].sort(() => Math.random() - 0.5);
    // Take subset and shuffle each question's options
    const selectedQuestions = shuffledQuestions
      .slice(0, QUESTIONS_PER_QUIZ)
      .map(shuffleQuestionOptions);
    
    setQuestions(selectedQuestions);
    setCurrentQuestionIndex(0);
    setSelectedAnswers({});
    setShowExplanation(false);
    setScore(0);
    setQuizState("active");
  };

  const handleAnswerSelect = (answerIndex: number) => {
    if (showExplanation) return;
    setSelectedAnswers(prev => ({
      ...prev,
      [currentQuestionIndex]: answerIndex,
    }));
  };

  const handleSubmitAnswer = () => {
    if (selectedAnswers[currentQuestionIndex] === undefined) return;
    setShowExplanation(true);
    if (selectedAnswers[currentQuestionIndex] === questions[currentQuestionIndex].correctAnswer) {
      setScore(prev => prev + 1);
    }
  };

  const handleNextQuestion = () => {
    if (currentQuestionIndex < questions.length - 1) {
      setCurrentQuestionIndex(prev => prev + 1);
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
        <QuizIcon sx={{ fontSize: 64, color: accent, mb: 2 }} />
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
          {title}
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 520, mx: "auto" }}>
          {description}
        </Typography>
        <Button
          variant="contained"
          size="large"
          onClick={startQuiz}
          sx={{
            bgcolor: accent,
            "&:hover": { bgcolor: accentDark },
            px: 4,
            py: 1.5,
            fontWeight: 700,
          }}
        >
          Start Quiz ({QUESTIONS_PER_QUIZ} Questions)
        </Button>
      </Box>
    );
  }

  if (quizState === "results") {
    const percentage = Math.round((score / QUESTIONS_PER_QUIZ) * 100);
    const isPassing = percentage >= 70;
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <EmojiEventsIcon sx={{ fontSize: 80, color: isPassing ? success : accent, mb: 2 }} />
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          Quiz Complete
        </Typography>
        <Typography variant="h5" sx={{ fontWeight: 700, color: isPassing ? success : accent, mb: 2 }}>
          {score} / {QUESTIONS_PER_QUIZ} ({percentage}%)
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 420, mx: "auto" }}>
          {isPassing
            ? "Excellent! You have a solid understanding of this topic."
            : "Keep learning. Review the sections above and try again."}
        </Typography>
        <Button
          variant="contained"
          size="large"
          startIcon={<RefreshIcon />}
          onClick={startQuiz}
          sx={{
            bgcolor: accent,
            "&:hover": { bgcolor: accentDark },
            px: 4,
            py: 1.5,
            fontWeight: 700,
          }}
        >
          Retry Quiz
        </Button>
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
          <Typography variant="body2" color="text.secondary">
            Question {currentQuestionIndex + 1} of {QUESTIONS_PER_QUIZ}
          </Typography>
          <Typography variant="body2" sx={{ fontWeight: 600, color: accent }}>
            Score: {score}
          </Typography>
        </Box>
        <LinearProgress
          variant="determinate"
          value={((currentQuestionIndex + 1) / QUESTIONS_PER_QUIZ) * 100}
          sx={{
            height: 8,
            borderRadius: 4,
            bgcolor: alpha(accent, 0.1),
            "& .MuiLinearProgress-bar": { bgcolor: accent },
          }}
        />
      </Box>

      <Paper
        elevation={0}
        sx={{
          p: 3,
          borderRadius: 3,
          border: `1px solid`,
          borderColor: showExplanation ? (isCorrect ? success : error) : "divider",
          bgcolor: showExplanation ? alpha(isCorrect ? success : error, 0.03) : "background.paper",
        }}
      >
        {currentQuestion?.topic && (
          <Typography variant="caption" sx={{ color: accent, fontWeight: 600, mb: 1, display: "block" }}>
            {currentQuestion.topic}
          </Typography>
        )}
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
          {currentQuestion?.question}
        </Typography>

        <RadioGroup value={selectedAnswer ?? ""} onChange={(_, val) => handleAnswerSelect(parseInt(val))}>
          {currentQuestion?.options.map((option, idx) => {
            const isSelected = selectedAnswer === idx;
            const isCorrectOption = idx === currentQuestion.correctAnswer;
            let optionColor = "inherit";
            if (showExplanation) {
              if (isCorrectOption) optionColor = success;
              else if (isSelected && !isCorrectOption) optionColor = error;
            }
            return (
              <FormControlLabel
                key={idx}
                value={idx}
                disabled={showExplanation}
                control={
                  <Radio
                    sx={{
                      color: showExplanation ? optionColor : accent,
                      "&.Mui-checked": { color: showExplanation ? optionColor : accent },
                    }}
                  />
                }
                label={
                  <Typography sx={{ color: showExplanation ? optionColor : "inherit", fontWeight: isSelected ? 600 : 400 }}>
                    {option}
                  </Typography>
                }
                sx={{
                  mb: 1,
                  p: 1.5,
                  borderRadius: 2,
                  bgcolor: showExplanation && isCorrectOption ? alpha(success, 0.1) : isSelected ? alpha(accent, 0.08) : "transparent",
                  border: `1px solid`,
                  borderColor: showExplanation && isCorrectOption ? success : isSelected ? accent : "transparent",
                  ml: 0,
                  width: "100%",
                }}
              />
            );
          })}
        </RadioGroup>

        {showExplanation && (
          <Box sx={{ mt: 3, p: 2, borderRadius: 2, bgcolor: alpha(accent, 0.05), border: `1px solid ${alpha(accent, 0.2)}` }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: accent, mb: 0.5 }}>
              Explanation
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {currentQuestion?.explanation}
            </Typography>
          </Box>
        )}

        <Box sx={{ mt: 3, display: "flex", justifyContent: "flex-end", gap: 2 }}>
          {!showExplanation ? (
            <Button
              variant="contained"
              onClick={handleSubmitAnswer}
              disabled={selectedAnswer === undefined}
              sx={{
                bgcolor: accent,
                "&:hover": { bgcolor: accentDark },
                "&:disabled": { bgcolor: alpha(accent, 0.3) },
              }}
            >
              Submit Answer
            </Button>
          ) : (
            <Button
              variant="contained"
              onClick={handleNextQuestion}
              sx={{
                bgcolor: accent,
                "&:hover": { bgcolor: accentDark },
              }}
            >
              {currentQuestionIndex < questions.length - 1 ? "Next Question" : "See Results"}
            </Button>
          )}
        </Box>
      </Paper>
    </Box>
  );
};

export default QuizSection;
