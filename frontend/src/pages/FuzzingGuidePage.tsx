import {
  Box,
  Typography,
  Container,
  Paper,
  alpha,
  useTheme,
  Tabs,
  Tab,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Grid,
  Divider,
} from "@mui/material";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import BugReportIcon from "@mui/icons-material/BugReport";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";
import SpeedIcon from "@mui/icons-material/Speed";
import CodeIcon from "@mui/icons-material/Code";
import MemoryIcon from "@mui/icons-material/Memory";
import StorageIcon from "@mui/icons-material/Storage";
import HttpIcon from "@mui/icons-material/Http";
import TerminalIcon from "@mui/icons-material/Terminal";

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

interface TopicSection {
  title: string;
  icon?: React.ReactNode;
  content: string;
  points?: string[];
  code?: string;
  codeLanguage?: string;
  warning?: string;
  tip?: string;
  table?: { headers: string[]; rows: string[][] };
}

interface FuzzingTool {
  name: string;
  target: string;
  description: string;
  installCmd: string;
  exampleCmd: string;
  bestFor: string[];
}

const fuzzingTools: FuzzingTool[] = [
  {
    name: "AFL++ (American Fuzzy Lop)",
    target: "Binaries (C/C++)",
    description: "Industry-standard coverage-guided fuzzer with genetic algorithms. Instruments code at compile time for maximum efficiency.",
    installCmd: "apt install afl++ # or build from source",
    exampleCmd: "afl-fuzz -i input_corpus -o findings -- ./target_binary @@",
    bestFor: ["Native binaries", "File parsers", "Protocol handlers", "Libraries"],
  },
  {
    name: "libFuzzer",
    target: "C/C++ Libraries",
    description: "LLVM's in-process, coverage-guided fuzzer. Links directly with target code for fast iteration.",
    installCmd: "# Included with clang/LLVM",
    exampleCmd: "clang -fsanitize=fuzzer,address target.c -o fuzzer && ./fuzzer corpus/",
    bestFor: ["API fuzzing", "Library functions", "Unit-level testing", "Memory bugs"],
  },
  {
    name: "Honggfuzz",
    target: "Binaries & Libraries",
    description: "Multi-process fuzzer with hardware-based code coverage via Intel BTS/PT. Excellent for parallel fuzzing.",
    installCmd: "apt install honggfuzz",
    exampleCmd: "honggfuzz -i input/ -o output/ -- ./target ___FILE___",
    bestFor: ["Parallel fuzzing", "Hardware coverage", "Persistent mode", "Network services"],
  },
  {
    name: "ffuf (Fuzz Faster U Fool)",
    target: "Web Applications",
    description: "Fast web fuzzer written in Go. Discovers hidden paths, parameters, virtual hosts, and more.",
    installCmd: "go install github.com/ffuf/ffuf/v2@latest",
    exampleCmd: "ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301",
    bestFor: ["Directory discovery", "Parameter fuzzing", "Subdomain enum", "API endpoints"],
  },
  {
    name: "Burp Suite Intruder",
    target: "Web Applications",
    description: "GUI-based web fuzzer with payload generation, encoding, and response analysis. Part of Burp Suite.",
    installCmd: "# Download from PortSwigger",
    exampleCmd: "# GUI-based: Capture request → Send to Intruder → Configure payloads → Start attack",
    bestFor: ["Auth bypass", "SQLi/XSS testing", "Business logic", "Parameter tampering"],
  },
  {
    name: "Radamsa",
    target: "Any Input Format",
    description: "Test case generator that mutates existing inputs. Works with any file format without instrumentation.",
    installCmd: "apt install radamsa # or compile from gitlab",
    exampleCmd: "radamsa -n 1000 -o fuzz-%n.txt sample.txt",
    bestFor: ["Quick fuzzing", "File format testing", "No source code", "Seed mutation"],
  },
  {
    name: "Jazzer",
    target: "Java/JVM Applications",
    description: "Coverage-guided fuzzer for JVM languages. Integrates with JUnit for easy adoption.",
    installCmd: "# Add jazzer-api dependency or use standalone",
    exampleCmd: "@FuzzTest void myFuzzTest(FuzzedDataProvider data) { ... }",
    bestFor: ["Java libraries", "Kotlin code", "JVM security", "Deserialization bugs"],
  },
  {
    name: "Atheris",
    target: "Python Applications",
    description: "Coverage-guided Python fuzzer from Google. Works with native extensions via libFuzzer.",
    installCmd: "pip install atheris",
    exampleCmd: "atheris.Setup(sys.argv, TestOneInput)\natheris.Fuzz()",
    bestFor: ["Python libraries", "Data parsers", "Native extensions", "Protocol implementations"],
  },
];

const mutationStrategies = [
  {
    name: "Bit Flipping",
    description: "Flip individual bits in the input to trigger off-by-one errors and boundary conditions",
    example: "0x41 → 0x40, 0x42, 0x61, 0xC1",
    finds: ["Integer overflows", "Sign confusion", "Boundary violations"],
  },
  {
    name: "Byte Replacement",
    description: "Replace bytes with interesting values (0x00, 0xFF, format strings, etc.)",
    example: "'AAAA' → '\\x00\\x00\\x00\\x00', '%s%s%s%s'",
    finds: ["Null dereferences", "Format string bugs", "Injection points"],
  },
  {
    name: "Block Operations",
    description: "Insert, delete, or duplicate chunks of data to break parsers",
    example: "Header + Data → Header + Header + Data + Data",
    finds: ["Buffer overflows", "Parser confusion", "Length mismatches"],
  },
  {
    name: "Arithmetic Mutation",
    description: "Add/subtract small values from integers to hit boundaries",
    example: "size=100 → size=99, 101, 0, -1, MAX_INT",
    finds: ["Integer overflow", "Allocation bugs", "Loop bounds"],
  },
  {
    name: "Dictionary-Based",
    description: "Insert known interesting tokens from a dictionary",
    example: "Insert: 'SELECT', '<script>', '../', '{{7*7}}'",
    finds: ["Injection flaws", "XSS", "Path traversal", "SSTI"],
  },
  {
    name: "Havoc Mode",
    description: "Combine multiple mutations randomly for chaotic testing",
    example: "Flip + Insert + Delete + Replace in one pass",
    finds: ["Complex state bugs", "Unexpected combinations", "Deep code paths"],
  },
];

const interestingPayloads = {
  integers: [
    { value: "0", reason: "Zero/null case" },
    { value: "-1", reason: "Signed underflow" },
    { value: "0x7FFFFFFF", reason: "Max 32-bit signed" },
    { value: "0x80000000", reason: "Min 32-bit signed" },
    { value: "0xFFFFFFFF", reason: "Max 32-bit unsigned / -1" },
    { value: "0x100", reason: "Just over 255 (byte overflow)" },
    { value: "0x10000", reason: "Just over 65535 (short overflow)" },
    { value: "length-1, length+1", reason: "Off-by-one boundaries" },
  ],
  strings: [
    { value: "'' (empty)", reason: "Empty string handling" },
    { value: "'A' × 10000", reason: "Buffer overflow trigger" },
    { value: "'%s%s%s%s%n'", reason: "Format string" },
    { value: "'${7*7}'", reason: "Template injection" },
    { value: "'\\x00'", reason: "Null byte injection" },
    { value: "Unicode: 'Ā' (\\u0100)", reason: "UTF-8 boundary" },
    { value: "'\\r\\n\\r\\n'", reason: "HTTP header injection" },
  ],
  formats: [
    { value: "Invalid magic bytes", reason: "File type confusion" },
    { value: "Truncated headers", reason: "Incomplete parsing" },
    { value: "Nested structures × 1000", reason: "Stack exhaustion" },
    { value: "Size field > actual data", reason: "OOB read" },
    { value: "Size field = 0", reason: "Division by zero" },
    { value: "Circular references", reason: "Infinite loops" },
  ],
};

export default function FuzzingGuidePage() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [tabValue, setTabValue] = useState(0);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const CodeBlock = ({ code, id }: { code: string; id: string }) => (
    <Box sx={{ position: "relative", mt: 1 }}>
      <Paper
        sx={{
          p: 2,
          bgcolor: alpha(theme.palette.common.black, 0.85),
          borderRadius: 2,
          fontFamily: "monospace",
          fontSize: "0.85rem",
          color: "#e2e8f0",
          overflow: "auto",
          border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
        }}
      >
        <pre style={{ margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{code}</pre>
      </Paper>
      <Tooltip title={copiedCmd === id ? "Copied!" : "Copy"}>
        <IconButton
          size="small"
          onClick={() => handleCopy(code, id)}
          sx={{
            position: "absolute",
            top: 8,
            right: 8,
            color: copiedCmd === id ? "success.main" : "grey.500",
            bgcolor: alpha(theme.palette.background.paper, 0.8),
            "&:hover": { bgcolor: alpha(theme.palette.background.paper, 0.95) },
          }}
        >
          <ContentCopyIcon fontSize="small" />
        </IconButton>
      </Tooltip>
    </Box>
  );

  const SectionAccordion = ({ section, index }: { section: TopicSection; index: number }) => (
    <Accordion
      defaultExpanded={index === 0}
      sx={{
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
        borderRadius: "12px !important",
        mb: 2,
        "&:before": { display: "none" },
        overflow: "hidden",
      }}
    >
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
          {section.icon && (
            <Box sx={{ color: "primary.main" }}>{section.icon}</Box>
          )}
          <Typography variant="h6" sx={{ fontWeight: 600 }}>
            {section.title}
          </Typography>
        </Box>
      </AccordionSummary>
      <AccordionDetails>
        <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.7, color: "text.secondary" }}>
          {section.content}
        </Typography>
        
        {section.warning && (
          <Paper
            sx={{
              p: 2,
              mb: 2,
              bgcolor: alpha(theme.palette.warning.main, 0.1),
              border: `1px solid ${alpha(theme.palette.warning.main, 0.3)}`,
              borderRadius: 2,
            }}
          >
            <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
              <WarningAmberIcon sx={{ color: "warning.main", mt: 0.25 }} />
              <Typography variant="body2" sx={{ color: "warning.main", fontWeight: 500 }}>
                {section.warning}
              </Typography>
            </Box>
          </Paper>
        )}
        
        {section.tip && (
          <Paper
            sx={{
              p: 2,
              mb: 2,
              bgcolor: alpha(theme.palette.success.main, 0.1),
              border: `1px solid ${alpha(theme.palette.success.main, 0.3)}`,
              borderRadius: 2,
            }}
          >
            <Typography variant="body2" sx={{ color: "success.main", fontWeight: 500 }}>
              💡 {section.tip}
            </Typography>
          </Paper>
        )}
        
        {section.points && (
          <Box component="ul" sx={{ pl: 2, mb: 2 }}>
            {section.points.map((point, i) => (
              <Typography component="li" variant="body2" key={i} sx={{ mb: 1, lineHeight: 1.6 }}>
                {point}
              </Typography>
            ))}
          </Box>
        )}
        
        {section.code && <CodeBlock code={section.code} id={`section-${index}`} />}
        
        {section.table && (
          <TableContainer component={Paper} sx={{ mt: 2, bgcolor: "transparent" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  {section.table.headers.map((h, i) => (
                    <TableCell key={i} sx={{ fontWeight: 700, bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                      {h}
                    </TableCell>
                  ))}
                </TableRow>
              </TableHead>
              <TableBody>
                {section.table.rows.map((row, i) => (
                  <TableRow key={i}>
                    {row.map((cell, j) => (
                      <TableCell key={j} sx={{ fontFamily: j === 0 ? "monospace" : "inherit" }}>
                        {cell}
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </AccordionDetails>
    </Accordion>
  );

  const fundamentalsSections: TopicSection[] = [
    {
      title: "What is Fuzzing?",
      icon: <BugReportIcon />,
      content: "Fuzzing (fuzz testing) is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a computer program. The goal is to find bugs, crashes, assertion failures, memory leaks, and security vulnerabilities that traditional testing misses.",
      points: [
        "Automated: Runs continuously without human intervention, testing millions of inputs",
        "Black/Grey/White Box: Can work with or without source code and internal knowledge",
        "Coverage-Guided: Modern fuzzers track code paths to maximize coverage",
        "Mutation-Based: Generates new inputs by modifying existing valid inputs",
        "Generation-Based: Creates inputs from scratch based on format specifications",
        "Finds Real Bugs: Responsible for discovering thousands of CVEs in production software",
      ],
    },
    {
      title: "Types of Fuzzing",
      icon: <SpeedIcon />,
      content: "Different fuzzing approaches suit different targets and requirements. Understanding these helps you choose the right technique.",
      table: {
        headers: ["Type", "Approach", "Best For", "Examples"],
        rows: [
          ["Dumb Fuzzing", "Random mutations, no feedback", "Quick and dirty testing", "Radamsa, zzuf"],
          ["Coverage-Guided", "Uses code coverage to guide mutations", "Finding deep bugs", "AFL++, libFuzzer"],
          ["Grammar-Based", "Generates inputs from grammar/spec", "Complex formats", "Peach, Dharma"],
          ["Protocol Fuzzing", "Understands network protocols", "Network services", "boofuzz, Sulley"],
          ["API Fuzzing", "Tests function/REST APIs", "Libraries, web APIs", "RESTler, Atheris"],
          ["Concolic/Symbolic", "Uses SMT solvers for paths", "Hitting specific code", "KLEE, Angr"],
        ],
      },
    },
    {
      title: "The Fuzzing Loop",
      icon: <MemoryIcon />,
      content: "Modern fuzzers operate in a tight feedback loop that maximizes efficiency and coverage.",
      points: [
        "1. Select Input: Pick a seed from the corpus (queue of interesting inputs)",
        "2. Mutate: Apply mutation strategies to create new test cases",
        "3. Execute: Run the target with the mutated input",
        "4. Monitor: Track crashes, hangs, coverage, and sanitizer reports",
        "5. Triage: If new coverage found, add to corpus. If crash, save for analysis",
        "6. Repeat: Continue millions of times per second",
      ],
      tip: "Coverage-guided fuzzers can execute 10,000+ test cases per second on modern hardware.",
    },
    {
      title: "Why Fuzzing Finds Bugs",
      icon: <CodeIcon />,
      content: "Fuzzing is effective because it explores the vast input space that developers and testers can't manually cover.",
      points: [
        "Explores Edge Cases: Tests inputs that humans wouldn't think to try",
        "Finds Assumption Violations: Exposes where code assumes 'this will never happen'",
        "Scales Infinitely: Can run 24/7 across distributed systems",
        "Reproducible: Every crash has an exact input to reproduce it",
        "Complements Other Testing: Finds bugs that unit tests and code review miss",
        "Proven Track Record: Found bugs in every major piece of software it's tested",
      ],
      warning: "Fuzzing alone isn't enough. It should complement code review, static analysis, and manual testing.",
    },
  ];

  const setupSections: TopicSection[] = [
    {
      title: "Preparing Your Target",
      icon: <CodeIcon />,
      content: "Proper target preparation dramatically improves fuzzing effectiveness. The goal is fast execution with good crash detection.",
      points: [
        "Compile with sanitizers: AddressSanitizer (ASan), UndefinedBehaviorSanitizer (UBSan), MemorySanitizer (MSan)",
        "Enable debug symbols (-g) for meaningful crash reports and stack traces",
        "Disable expensive features: logging, checksums, authentication during fuzzing",
        "Create a harness: Minimal code that calls your target function with fuzz input",
        "Persistent mode: Keep process alive between test cases for 10-100x speedup",
        "Remove sources of non-determinism: random seeds, timestamps, PIDs",
      ],
      code: `# Compile with AFL++ and AddressSanitizer
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export CFLAGS="-fsanitize=address,undefined -g"
export CXXFLAGS="-fsanitize=address,undefined -g"

./configure --disable-shared
make clean && make`,
    },
    {
      title: "Building a Fuzz Harness",
      icon: <TerminalIcon />,
      content: "A harness is a small program that reads fuzz input and passes it to your target code. Good harnesses are the key to effective fuzzing.",
      code: `// Example libFuzzer harness for a JSON parser
#include <stdint.h>
#include <stddef.h>
#include "json_parser.h"

// This function is called for each fuzz input
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Create null-terminated string from fuzz data
    char *json = (char *)malloc(size + 1);
    if (!json) return 0;
    
    memcpy(json, data, size);
    json[size] = '\\0';
    
    // Call the function we want to fuzz
    JsonDocument *doc = json_parse(json);
    
    // Clean up
    if (doc) json_free(doc);
    free(json);
    
    return 0;  // Always return 0 (non-zero is reserved)
}`,
      tip: "Keep harnesses simple! Only call the code you want to test. Avoid file I/O, network calls, and complex setup.",
    },
    {
      title: "Seed Corpus Creation",
      icon: <StorageIcon />,
      content: "A good seed corpus dramatically improves fuzzing efficiency. Seeds should be small, diverse, and valid.",
      points: [
        "Start with valid inputs: Working files, requests, or data your target accepts",
        "Minimize seeds: Use afl-cmin/afl-tmin to remove redundant seeds",
        "Diversity matters: Include edge cases, different features, various sizes",
        "Small is beautiful: Smaller seeds = faster mutations = more executions",
        "Use existing test suites: Unit tests often have good seed inputs",
        "Protocol samples: Capture real traffic for network protocol fuzzing",
      ],
      code: `# Minimize corpus with AFL++
afl-cmin -i large_corpus/ -o min_corpus/ -- ./target @@

# Further minimize individual files
for f in min_corpus/*; do
  afl-tmin -i "$f" -o "tiny_corpus/$(basename $f)" -- ./target @@
done

# Start fuzzing with minimized corpus
afl-fuzz -i tiny_corpus/ -o findings/ -- ./target @@`,
    },
    {
      title: "Dictionary Files",
      icon: <HttpIcon />,
      content: "Dictionaries provide tokens that are meaningful for your target format, helping the fuzzer discover interesting code paths faster.",
      code: `# Example dictionary for JSON fuzzing (json.dict)
"true"
"false"
"null"
"\\"string\\""
"[]"
"{}"
":"
","
"\\\\n"
"\\\\u0000"
"-1"
"0"
"1"
"9999999999999999999"
"1e308"
"1e-308"

# Use with AFL++
afl-fuzz -x json.dict -i seeds/ -o out/ -- ./json_parser @@`,
      tip: "AFL++ includes dictionaries for many common formats in /usr/share/afl/dictionaries/",
    },
  ];

  const advancedSections: TopicSection[] = [
    {
      title: "Parallel & Distributed Fuzzing",
      icon: <SpeedIcon />,
      content: "Scale your fuzzing across multiple cores and machines for maximum coverage.",
      code: `# AFL++ parallel fuzzing on one machine
# Master instance (does deterministic fuzzing first)
afl-fuzz -M main -i seeds/ -o sync_dir/ -- ./target @@

# Secondary instances (skip deterministic, pure havoc)
afl-fuzz -S fuzzer02 -i seeds/ -o sync_dir/ -- ./target @@
afl-fuzz -S fuzzer03 -i seeds/ -o sync_dir/ -- ./target @@

# Check status of all fuzzers
afl-whatsup sync_dir/

# Distributed: Use afl-sync or shared filesystem (NFS/CIFS)
# Each machine runs instances with unique -S names`,
      points: [
        "One -M (main) instance per campaign, does deterministic mutations first",
        "Multiple -S (secondary) instances for parallel havoc/splicing",
        "Use all available cores: CPU-bound fuzzing benefits from parallelization",
        "Sync directory: All instances share findings automatically",
        "Different strategies: Run some with different dictionaries/settings",
      ],
    },
    {
      title: "Persistent Mode",
      icon: <MemoryIcon />,
      content: "Persistent mode keeps the target process alive between test cases, avoiding fork() overhead for massive speedups.",
      code: `// AFL++ persistent mode harness
#include <unistd.h>

__AFL_FUZZ_INIT();

int main() {
    // Deferred initialization - fork happens here
    __AFL_INIT();
    
    // Get pointer to shared memory input buffer
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    
    // Persistent loop - process stays alive
    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        
        // Your target code here
        process_input(buf, len);
        
        // Reset any state for next iteration
        reset_state();
    }
    
    return 0;
}`,
      tip: "Persistent mode can increase execution speed from 1,000 to 100,000+ execs/sec!",
      warning: "Ensure your target doesn't leak memory or accumulate state between iterations.",
    },
    {
      title: "Custom Mutators",
      icon: <CodeIcon />,
      content: "When default mutations aren't effective, custom mutators can leverage format knowledge for smarter fuzzing.",
      code: `// AFL++ custom mutator example (Python)
import struct

def init(seed):
    return 0

def fuzz(buf, add_buf, max_size):
    """Called for each mutation"""
    # Parse the input as our custom format
    if len(buf) < 8:
        return buf
    
    # Mutate the length field to trigger overflows
    header = bytearray(buf[:4])
    length = struct.unpack("<I", buf[4:8])[0]
    
    # Sometimes set length to interesting values
    import random
    if random.random() < 0.3:
        new_len = random.choice([0, 0xFFFFFFFF, len(buf), len(buf)*2])
        return bytes(header) + struct.pack("<I", new_len) + buf[8:]
    
    return buf  # Default: return unchanged

# Compile and use:
# afl-fuzz -c ./my_mutator.py -i in/ -o out/ -- ./target @@`,
      points: [
        "Structure-aware: Mutate specific fields while keeping format valid",
        "Protocol-aware: Generate valid protocol messages with fuzzed payloads",
        "Grammar-based: Use grammar rules to generate syntactically valid inputs",
        "Combine with coverage: Let the fuzzer guide which mutations to keep",
      ],
    },
    {
      title: "Fuzzing Network Services",
      icon: <HttpIcon />,
      content: "Network fuzzing requires special techniques to handle state, timing, and connectivity.",
      code: `# Using AFL++ with network targets via desock
# Desocketing redirects network calls to stdin/stdout

# Compile with afl-clang-fast and link desock library
afl-clang-fast -o target target.c -ldesock

# Or use preload method
AFL_PRELOAD=libdesock.so afl-fuzz -i in/ -o out/ -- ./server

# Alternative: Use boofuzz for stateful protocol fuzzing
from boofuzz import *

session = Session(target=Target(connection=TCPSocketConnection("127.0.0.1", 8080)))

s_initialize("request")
s_string("GET", fuzzable=False)
s_delim(" ", fuzzable=False)
s_string("/", name="path")
s_static("\\r\\n\\r\\n")

session.connect(s_get("request"))
session.fuzz()`,
      warning: "Always fuzz in isolated environments. Network fuzzing can affect other systems!",
    },
    {
      title: "Crash Triage & Analysis",
      icon: <BugReportIcon />,
      content: "Finding crashes is only the beginning. Triage helps prioritize and understand each bug.",
      code: `# Deduplicate crashes by stack hash
afl-collect -r findings/ crashes_unique/ -- ./target @@

# Analyze with AddressSanitizer
ASAN_OPTIONS="symbolize=1" ./target_asan < crash_input

# Get exploitability assessment with !exploitable (GDB plugin)
gdb -ex "run < crash_input" -ex "exploitable" ./target

# Minimize crash input
afl-tmin -i crash_input -o crash_min -- ./target @@

# Create reproducer script
echo '#!/bin/bash' > repro.sh
echo './target < crash_minimized' >> repro.sh`,
      points: [
        "Stack hash deduplication: Group crashes by unique stack traces",
        "Minimization: Reduce crash input to essential bytes",
        "Exploitability: Assess if crash is security-relevant (write-what-where, etc.)",
        "Root cause analysis: Use debugger + sanitizer output to understand the bug",
        "CVE check: Compare against known vulnerabilities to avoid duplicates",
      ],
    },
  ];

  const webFuzzingSections: TopicSection[] = [
    {
      title: "Directory & File Discovery",
      icon: <StorageIcon />,
      content: "Discover hidden endpoints, backup files, and forgotten admin panels that expand your attack surface.",
      code: `# Basic directory fuzzing with ffuf
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Multiple extensions
ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.bak,.old,.txt,.zip

# Recursive scanning
ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2

# Filter by size/words/lines to reduce noise
ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 0 -fw 1 -mc 200,301,302,403

# Virtual host discovery
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w subdomains.txt -fs 0`,
      points: [
        "Use quality wordlists: SecLists, OneListForAll, custom lists from recon",
        "Try multiple extensions: .bak, .old, .swp, .git, .env, .config",
        "Check for backups: admin.php.bak, index.php~, .htaccess.old",
        "API paths: /api/v1/, /api/internal/, /swagger.json, /graphql",
        "Filter wisely: Remove false positives by size, word count, or response code",
      ],
    },
    {
      title: "Parameter Fuzzing",
      icon: <HttpIcon />,
      content: "Discover hidden parameters and test existing ones for injection vulnerabilities.",
      code: `# Discover GET parameters
ffuf -u "https://target.com/page?FUZZ=test" -w params.txt -fs 0

# Fuzz POST parameters
ffuf -u https://target.com/login -X POST \\
     -d "username=admin&FUZZ=test" -w params.txt

# Test for injection in known parameter
ffuf -u "https://target.com/search?q=FUZZ" \\
     -w /usr/share/wordlists/wfuzz/Injections/All_attack.txt \\
     -fr "error|exception|syntax"

# JSON body fuzzing
ffuf -u https://target.com/api/user \\
     -X POST -H "Content-Type: application/json" \\
     -d '{"id":"FUZZ"}' -w sqli.txt`,
      points: [
        "Hidden params: debug, test, admin, internal, token, callback",
        "Parameter pollution: Try same param twice with different values",
        "Type juggling: Replace strings with arrays, ints, objects",
        "Injection payloads: SQLi, XSS, SSTI, command injection wordlists",
        "Watch for timing: Blind injection may only show in response time",
      ],
    },
    {
      title: "Authentication Fuzzing",
      icon: <CodeIcon />,
      content: "Test login systems, password reset flows, and session handling for weaknesses.",
      code: `# Username enumeration (different response for valid/invalid users)
ffuf -u https://target.com/login -X POST \\
     -d "username=FUZZ&password=wrong" -w usernames.txt \\
     -H "Content-Type: application/x-www-form-urlencoded" \\
     -fr "Invalid password"  # Filter responses containing this

# Password spraying (few passwords, many users)
ffuf -u https://target.com/login -X POST \\
     -d "username=USER&password=PASS" \\
     -w users.txt:USER -w passwords.txt:PASS \\
     -mode clusterbomb -rate 10

# OTP/2FA bypass attempts
ffuf -u https://target.com/verify -X POST \\
     -d "code=FUZZ" -w 0000-9999.txt \\
     -H "Cookie: session=abc123"`,
      warning: "Respect rate limits and lockout policies. Brute forcing without authorization is illegal!",
      tip: "Look for response differences: size, time, headers, error messages to identify valid credentials.",
    },
    {
      title: "API Fuzzing",
      icon: <HttpIcon />,
      content: "Modern applications expose APIs that often lack the same security controls as web interfaces.",
      code: `# Fuzz API versions
ffuf -u https://api.target.com/v{FUZZ}/users -w versions.txt

# IDOR testing - enumerate IDs
ffuf -u https://api.target.com/users/FUZZ -w <(seq 1 10000)

# HTTP method fuzzing
ffuf -u https://api.target.com/users/1 -X FUZZ \\
     -w methods.txt -mc all -fc 405

# GraphQL introspection & fuzzing
# 1. Get schema
curl -X POST -H "Content-Type: application/json" \\
     -d '{"query":"{__schema{types{name}}}"}' \\
     https://target.com/graphql

# 2. Fuzz queries
ffuf -u https://target.com/graphql -X POST \\
     -H "Content-Type: application/json" \\
     -d '{"query":"FUZZ"}' -w graphql-payloads.txt`,
      points: [
        "Endpoint discovery: /api/, /v1/, /v2/, /internal/, /private/",
        "IDOR: Sequential IDs, UUIDs, encoded values",
        "Mass assignment: Add extra fields in POST/PUT requests",
        "Rate limit bypass: Different headers, IPs, encoded paths",
        "Auth bypass: Remove tokens, try default/null values",
      ],
    },
  ];

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <IconButton onClick={() => navigate("/learn")} sx={{ mb: 2 }}>
          <ArrowBackIcon />
        </IconButton>
        
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
          <Box
            sx={{
              width: 64,
              height: 64,
              borderRadius: 3,
              bgcolor: alpha("#ef4444", 0.15),
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <BugReportIcon sx={{ fontSize: 32, color: "#ef4444" }} />
          </Box>
          <Box>
            <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
              Fuzzing Deep Dive
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Master automated bug hunting with coverage-guided fuzzing
            </Typography>
          </Box>
        </Box>

        {/* Quick Stats */}
        <Paper
          sx={{
            p: 2,
            borderRadius: 3,
            display: "flex",
            flexWrap: "wrap",
            gap: 3,
            justifyContent: "center",
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          }}
        >
          {[
            { value: "8+", label: "Fuzzing Tools" },
            { value: "6", label: "Mutation Types" },
            { value: "20+", label: "Techniques" },
            { value: "∞", label: "Bugs to Find" },
          ].map((stat, i) => (
            <Box key={i} sx={{ textAlign: "center", minWidth: 80 }}>
              <Typography variant="h5" sx={{ fontWeight: 800, color: "#ef4444" }}>
                {stat.value}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {stat.label}
              </Typography>
            </Box>
          ))}
        </Paper>
      </Box>

      {/* Tabs */}
      <Paper sx={{ borderRadius: 3, overflow: "hidden", mb: 4 }}>
        <Tabs
          value={tabValue}
          onChange={(_, v) => setTabValue(v)}
          variant="scrollable"
          scrollButtons="auto"
          sx={{
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            "& .MuiTab-root": { fontWeight: 600, textTransform: "none", minHeight: 56 },
          }}
        >
          <Tab label="🎯 Fundamentals" />
          <Tab label="🔧 Setup & Harnesses" />
          <Tab label="⚡ Advanced Techniques" />
          <Tab label="🌐 Web Fuzzing" />
          <Tab label="🛠️ Tools Reference" />
          <Tab label="💣 Mutation Strategies" />
          <Tab label="🎪 Magic Values" />
        </Tabs>
      </Paper>

      {/* Tab Panels */}
      <TabPanel value={tabValue} index={0}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          Understanding Fuzzing Fundamentals
        </Typography>
        {fundamentalsSections.map((section, i) => (
          <SectionAccordion key={i} section={section} index={i} />
        ))}
      </TabPanel>

      <TabPanel value={tabValue} index={1}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          Setting Up Effective Fuzzing Campaigns
        </Typography>
        {setupSections.map((section, i) => (
          <SectionAccordion key={i} section={section} index={i} />
        ))}
      </TabPanel>

      <TabPanel value={tabValue} index={2}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          Advanced Fuzzing Techniques
        </Typography>
        {advancedSections.map((section, i) => (
          <SectionAccordion key={i} section={section} index={i} />
        ))}
      </TabPanel>

      <TabPanel value={tabValue} index={3}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          Web Application Fuzzing
        </Typography>
        {webFuzzingSections.map((section, i) => (
          <SectionAccordion key={i} section={section} index={i} />
        ))}
      </TabPanel>

      <TabPanel value={tabValue} index={4}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          Fuzzing Tools Reference
        </Typography>
        <Grid container spacing={3}>
          {fuzzingTools.map((tool, i) => (
            <Grid item xs={12} md={6} key={i}>
              <Paper
                sx={{
                  p: 3,
                  height: "100%",
                  borderRadius: 3,
                  border: `1px solid ${alpha(theme.palette.divider, 0.15)}`,
                  transition: "all 0.2s",
                  "&:hover": {
                    borderColor: "#ef4444",
                    boxShadow: `0 4px 20px ${alpha("#ef4444", 0.15)}`,
                  },
                }}
              >
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 700 }}>
                    {tool.name}
                  </Typography>
                  <Chip label={tool.target} size="small" sx={{ bgcolor: alpha("#ef4444", 0.1), color: "#ef4444" }} />
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2, lineHeight: 1.6 }}>
                  {tool.description}
                </Typography>
                <CodeBlock code={tool.installCmd} id={`tool-install-${i}`} />
                <Typography variant="caption" sx={{ display: "block", mt: 2, mb: 1, fontWeight: 600 }}>
                  Example Usage:
                </Typography>
                <CodeBlock code={tool.exampleCmd} id={`tool-example-${i}`} />
                <Box sx={{ mt: 2, display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                  {tool.bestFor.map((tag) => (
                    <Chip key={tag} label={tag} size="small" sx={{ fontSize: "0.7rem" }} />
                  ))}
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      <TabPanel value={tabValue} index={5}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          Mutation Strategies
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          Understanding how fuzzers mutate inputs helps you create better seeds and interpret results.
        </Typography>
        <Grid container spacing={3}>
          {mutationStrategies.map((strategy, i) => (
            <Grid item xs={12} md={6} key={i}>
              <Paper
                sx={{
                  p: 3,
                  height: "100%",
                  borderRadius: 3,
                  border: `1px solid ${alpha(theme.palette.divider, 0.15)}`,
                }}
              >
                <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
                  {strategy.name}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  {strategy.description}
                </Typography>
                <Paper
                  sx={{
                    p: 1.5,
                    bgcolor: alpha(theme.palette.common.black, 0.8),
                    borderRadius: 2,
                    mb: 2,
                  }}
                >
                  <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#e2e8f0" }}>
                    {strategy.example}
                  </Typography>
                </Paper>
                <Typography variant="caption" sx={{ fontWeight: 600, display: "block", mb: 1 }}>
                  Commonly Finds:
                </Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                  {strategy.finds.map((f) => (
                    <Chip key={f} label={f} size="small" sx={{ fontSize: "0.65rem", bgcolor: alpha("#ef4444", 0.1) }} />
                  ))}
                </Box>
              </Paper>
            </Grid>
          ))}
        </Grid>
      </TabPanel>

      <TabPanel value={tabValue} index={6}>
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 3 }}>
          Magic Values & Interesting Inputs
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
          These values frequently trigger bugs because they hit boundaries and edge cases.
        </Typography>

        {/* Integers */}
        <Paper sx={{ p: 3, borderRadius: 3, mb: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon /> Integer Magic Values
          </Typography>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Value</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Why It's Interesting</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {interestingPayloads.integers.map((p, i) => (
                  <TableRow key={i}>
                    <TableCell sx={{ fontFamily: "monospace", color: "#ef4444" }}>{p.value}</TableCell>
                    <TableCell>{p.reason}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>

        {/* Strings */}
        <Paper sx={{ p: 3, borderRadius: 3, mb: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <TerminalIcon /> String Magic Values
          </Typography>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Value</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Why It's Interesting</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {interestingPayloads.strings.map((p, i) => (
                  <TableRow key={i}>
                    <TableCell sx={{ fontFamily: "monospace", color: "#ef4444" }}>{p.value}</TableCell>
                    <TableCell>{p.reason}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>

        {/* File Formats */}
        <Paper sx={{ p: 3, borderRadius: 3 }}>
          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
            <StorageIcon /> File Format Anomalies
          </Typography>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Anomaly</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Why It's Interesting</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {interestingPayloads.formats.map((p, i) => (
                  <TableRow key={i}>
                    <TableCell sx={{ fontFamily: "monospace", color: "#ef4444" }}>{p.value}</TableCell>
                    <TableCell>{p.reason}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      </TabPanel>

      {/* Footer CTA */}
      <Paper
        sx={{
          mt: 4,
          p: 4,
          borderRadius: 3,
          textAlign: "center",
          background: `linear-gradient(135deg, ${alpha("#ef4444", 0.1)}, ${alpha(theme.palette.background.paper, 0.8)})`,
          border: `1px solid ${alpha("#ef4444", 0.2)}`,
        }}
      >
        <Typography variant="h6" sx={{ fontWeight: 700, mb: 1 }}>
          🐛 Start Finding Bugs Today
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Fuzzing has found thousands of security vulnerabilities. Set up AFL++ and start hunting!
        </Typography>
        <Box sx={{ display: "flex", gap: 2, justifyContent: "center", flexWrap: "wrap" }}>
          <Chip
            label="Back to Learning Hub"
            clickable
            onClick={() => navigate("/learn")}
            sx={{ fontWeight: 600 }}
          />
          <Chip
            label="Commands Reference →"
            clickable
            onClick={() => navigate("/learn/commands")}
            sx={{ bgcolor: "#ef4444", color: "white", fontWeight: 600, "&:hover": { bgcolor: "#dc2626" } }}
          />
        </Box>
      </Paper>
    </Container>
  );
}
