import React, { useState, useMemo, useEffect } from "react";
import {
  Box,
  Container,
  Typography,
  Paper,
  Chip,
  Button,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Alert,
  AlertTitle,
  Radio,
  RadioGroup,
  FormControlLabel,
  Divider,
  alpha,
  useTheme,
  Fab,
  Drawer,
  IconButton,
  Tooltip,
  useMediaQuery,
  LinearProgress,
} from "@mui/material";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import MemoryIcon from "@mui/icons-material/Memory";
import SchoolIcon from "@mui/icons-material/School";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import CodeIcon from "@mui/icons-material/Code";
import BuildIcon from "@mui/icons-material/Build";
import SecurityIcon from "@mui/icons-material/Security";
import TerminalIcon from "@mui/icons-material/Terminal";
import StorageIcon from "@mui/icons-material/Storage";
import TipsAndUpdatesIcon from "@mui/icons-material/TipsAndUpdates";
import QuizIcon from "@mui/icons-material/Quiz";
import RefreshIcon from "@mui/icons-material/Refresh";
import EmojiEventsIcon from "@mui/icons-material/EmojiEvents";
import ConstructionIcon from "@mui/icons-material/Construction";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import ListAltIcon from "@mui/icons-material/ListAlt";
import CloseIcon from "@mui/icons-material/Close";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import { useNavigate, Link } from "react-router-dom";
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

// Full 75-question bank covering Assembly Language topics
const questionBank: QuizQuestion[] = [
  // ==================== Topic 1: Assembly Basics (Questions 1-15) ====================
  { id: 1, question: "What is assembly language?", options: ["A high-level programming language", "A low-level language using human-readable mnemonics for machine code", "A markup language for web pages", "A database query language"], correctAnswer: 1, explanation: "Assembly language is a low-level programming language that uses human-readable mnemonics to represent machine code instructions that the CPU can execute directly.", topic: "Assembly Basics" },
  { id: 2, question: "What is the purpose of an assembler?", options: ["To run programs directly", "To convert assembly code into machine code", "To debug programs", "To compile high-level languages"], correctAnswer: 1, explanation: "An assembler translates assembly language mnemonics into binary machine code that the processor can execute.", topic: "Assembly Basics" },
  { id: 3, question: "What does MOV instruction do in x86 assembly?", options: ["Performs multiplication", "Copies data from source to destination", "Moves memory physically", "Compares two values"], correctAnswer: 1, explanation: "The MOV instruction copies data from a source operand to a destination operand. It's one of the most fundamental assembly instructions.", topic: "Assembly Basics" },
  { id: 4, question: "What is a register in CPU architecture?", options: ["A permanent storage device", "A small, fast storage location within the CPU", "A type of memory cache", "An input/output port"], correctAnswer: 1, explanation: "Registers are small, extremely fast storage locations built directly into the CPU that hold data being actively processed.", topic: "Assembly Basics" },
  { id: 5, question: "Which register typically holds the return value of a function in x86-64?", options: ["RBX", "RAX", "RCX", "RDX"], correctAnswer: 1, explanation: "In x86-64 calling conventions, RAX (or EAX in 32-bit) is used to hold the return value of functions.", topic: "Assembly Basics" },
  { id: 6, question: "What is the difference between x86 and x86-64?", options: ["x86 is for Intel, x86-64 is for AMD", "x86 is 32-bit, x86-64 is 64-bit architecture", "x86 is older and slower", "There is no difference"], correctAnswer: 1, explanation: "x86 refers to the 32-bit instruction set architecture, while x86-64 (also called AMD64 or Intel 64) extends it to 64 bits, allowing access to more memory and additional registers.", topic: "Assembly Basics" },
  { id: 7, question: "What is an opcode in assembly language?", options: ["A type of variable", "The numeric code representing an instruction", "A memory address", "A comment in code"], correctAnswer: 1, explanation: "An opcode (operation code) is the portion of a machine language instruction that specifies what operation to perform. Each assembly mnemonic corresponds to a specific opcode.", topic: "Assembly Basics" },
  { id: 8, question: "What is an operand in assembly?", options: ["The instruction itself", "The data or address an instruction operates on", "A type of register", "A branch label"], correctAnswer: 1, explanation: "An operand is the data or memory location that an instruction operates on. Instructions can have zero, one, two, or more operands.", topic: "Assembly Basics" },
  { id: 9, question: "What does 'little-endian' mean?", options: ["A small program", "Bytes are stored with least significant byte at lowest address", "A type of CPU", "A debugging technique"], correctAnswer: 1, explanation: "Little-endian is a byte ordering where the least significant byte is stored at the lowest memory address. x86 processors use little-endian format.", topic: "Assembly Basics" },
  { id: 10, question: "What is the hexadecimal representation of decimal 255?", options: ["0xFE", "0xFF", "0x100", "0xF0"], correctAnswer: 1, explanation: "255 in decimal equals FF in hexadecimal (15×16 + 15 = 255). Understanding hex is essential for assembly programming.", topic: "Assembly Basics" },
  { id: 11, question: "What does NOP instruction do?", options: ["Stops the program", "Does nothing (no operation)", "Jumps to the next instruction", "Clears all registers"], correctAnswer: 1, explanation: "NOP (No Operation) is an instruction that does nothing except consume one CPU cycle. It's often used for timing, padding, or as a placeholder.", topic: "Assembly Basics" },
  { id: 12, question: "What is a mnemonic in assembly language?", options: ["A memory location", "A human-readable abbreviation for an instruction", "A type of register", "A debugging symbol"], correctAnswer: 1, explanation: "A mnemonic is a human-readable abbreviation representing a machine instruction, like MOV for 'move' or ADD for 'add'.", topic: "Assembly Basics" },
  { id: 13, question: "What does the XCHG instruction do?", options: ["Executes a change", "Exchanges values between two operands", "Changes the instruction pointer", "Performs XOR and change"], correctAnswer: 1, explanation: "XCHG (exchange) swaps the values of two operands atomically. For example, XCHG EAX, EBX swaps the contents of these registers.", topic: "Assembly Basics" },
  { id: 14, question: "Which section typically contains executable code in an assembly program?", options: [".data", ".text", ".bss", ".rodata"], correctAnswer: 1, explanation: "The .text section contains the executable instructions of a program. .data contains initialized data, .bss contains uninitialized data, and .rodata contains read-only data.", topic: "Assembly Basics" },
  { id: 15, question: "What is a label in assembly language?", options: ["A type of instruction", "A named marker for a memory address or code location", "A comment", "A register alias"], correctAnswer: 1, explanation: "A label is a symbolic name that represents a memory address or code location. Labels make code more readable and allow referencing locations by name instead of hard-coded addresses.", topic: "Assembly Basics" },

  // ==================== Topic 2: Registers (Questions 16-30) ====================
  { id: 16, question: "How many general-purpose registers does x86-64 have?", options: ["8", "16", "32", "4"], correctAnswer: 1, explanation: "x86-64 has 16 general-purpose registers: RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, and R8-R15.", topic: "Registers" },
  { id: 17, question: "What is the size of RAX register?", options: ["32 bits", "64 bits", "16 bits", "128 bits"], correctAnswer: 1, explanation: "RAX is a 64-bit register in x86-64 architecture. EAX refers to its lower 32 bits, AX to the lower 16 bits.", topic: "Registers" },
  { id: 18, question: "What does RSP register point to?", options: ["The current instruction", "The top of the stack", "The base of the heap", "The return address"], correctAnswer: 1, explanation: "RSP (Stack Pointer) always points to the top of the stack, which is the most recently pushed value.", topic: "Registers" },
  { id: 19, question: "What is RIP used for?", options: ["Return instruction pointer", "Holding the address of the next instruction to execute", "Random input processing", "Register input pointer"], correctAnswer: 1, explanation: "RIP (Instruction Pointer) holds the address of the next instruction to be executed. It automatically advances after each instruction.", topic: "Registers" },
  { id: 20, question: "What does the FLAGS register contain?", options: ["Function arguments", "Status bits indicating results of operations", "Memory addresses", "Loop counters"], correctAnswer: 1, explanation: "The FLAGS (RFLAGS in 64-bit) register contains status bits like Zero Flag (ZF), Carry Flag (CF), Sign Flag (SF), and Overflow Flag (OF) that indicate results of arithmetic and logical operations.", topic: "Registers" },
  { id: 21, question: "If EAX contains 0x12345678, what does AL contain?", options: ["0x12", "0x78", "0x34", "0x56"], correctAnswer: 1, explanation: "AL is the lowest 8 bits of EAX. In 0x12345678, the bytes from lowest to highest are 78, 56, 34, 12. AL contains 0x78.", topic: "Registers" },
  { id: 22, question: "What is a callee-saved register?", options: ["A register the called function must preserve", "A register for calculating", "A register that can't be modified", "A temporary register"], correctAnswer: 0, explanation: "Callee-saved (non-volatile) registers must be preserved by the called function. If the function modifies them, it must save and restore their original values.", topic: "Registers" },
  { id: 23, question: "Which register is traditionally used as a loop counter?", options: ["RAX", "RCX", "RDX", "RBX"], correctAnswer: 1, explanation: "RCX (Counter register) is traditionally used for loop counting. Instructions like LOOP and REP use CX/ECX/RCX as the counter.", topic: "Registers" },
  { id: 24, question: "What does RBP typically point to?", options: ["The start of the program", "The base of the current stack frame", "The top of the heap", "The end of the stack"], correctAnswer: 1, explanation: "RBP (Base Pointer) typically points to the base of the current function's stack frame, providing a stable reference for accessing local variables and parameters.", topic: "Registers" },
  { id: 25, question: "What is the Zero Flag (ZF)?", options: ["A flag that's always zero", "A flag set when an operation results in zero", "A flag for zero division", "A flag indicating empty registers"], correctAnswer: 1, explanation: "The Zero Flag (ZF) is set to 1 when the result of an arithmetic or logical operation is zero. It's commonly used for conditional jumps.", topic: "Registers" },
  { id: 26, question: "In x86-64 Linux calling convention, which register holds the first argument?", options: ["RAX", "RDI", "RSI", "RCX"], correctAnswer: 1, explanation: "In the System V AMD64 ABI (Linux), RDI holds the first integer/pointer argument, RSI the second, RDX the third, RCX the fourth, R8 the fifth, and R9 the sixth.", topic: "Registers" },
  { id: 27, question: "What is the Carry Flag (CF) used for?", options: ["Carrying data between registers", "Indicating unsigned overflow/borrow", "Carrying function results", "Flag for carry instructions"], correctAnswer: 1, explanation: "The Carry Flag indicates an unsigned overflow (carry out) or borrow in arithmetic operations. It's set when the result doesn't fit in the destination.", topic: "Registers" },
  { id: 28, question: "What is the Sign Flag (SF)?", options: ["A flag for signed numbers only", "A flag set to the most significant bit of the result", "A flag indicating negative input", "A signature verification flag"], correctAnswer: 1, explanation: "The Sign Flag is set equal to the most significant bit of the result, indicating whether the result is negative (SF=1) or non-negative (SF=0) when interpreted as a signed number.", topic: "Registers" },
  { id: 29, question: "What does 'volatile register' mean in calling conventions?", options: ["A register that changes randomly", "A register the caller must assume is modified by function calls", "A dangerous register", "An unstable register"], correctAnswer: 1, explanation: "Volatile (caller-saved) registers may be modified by called functions. The caller must save these values before a call if they're needed afterward.", topic: "Registers" },
  { id: 30, question: "What is the Overflow Flag (OF) used for?", options: ["Detecting buffer overflows", "Indicating signed arithmetic overflow", "Memory overflow detection", "Stack overflow detection"], correctAnswer: 1, explanation: "The Overflow Flag indicates signed arithmetic overflow - when the result of a signed operation is too large (positive) or too small (negative) to fit in the destination.", topic: "Registers" },

  // ==================== Topic 3: Memory Addressing (Questions 31-45) ====================
  { id: 31, question: "What is direct addressing?", options: ["Using a register as address", "Specifying the actual memory address in the instruction", "Addressing through pointers", "Stack-based addressing"], correctAnswer: 1, explanation: "Direct addressing specifies the exact memory address in the instruction itself, like MOV EAX, [0x401000].", topic: "Memory Addressing" },
  { id: 32, question: "What does [RBX] mean in assembly?", options: ["The value of RBX", "The memory location pointed to by RBX", "The address of RBX", "RBX plus offset"], correctAnswer: 1, explanation: "Square brackets indicate memory access. [RBX] means 'the value at the memory address contained in RBX' - it dereferences RBX as a pointer.", topic: "Memory Addressing" },
  { id: 33, question: "What does [RBX+8] represent?", options: ["RBX plus 8", "Memory at address (RBX + 8 bytes)", "8 bytes of RBX", "RBX shifted by 8"], correctAnswer: 1, explanation: "[RBX+8] accesses the memory location at the address formed by adding 8 to the value in RBX. This is base-plus-offset addressing.", topic: "Memory Addressing" },
  { id: 34, question: "What is LEA instruction used for?", options: ["Loading a value from memory", "Computing an address without accessing memory", "Leaving a function", "Leading a branch"], correctAnswer: 1, explanation: "LEA (Load Effective Address) computes the address that would be used in a memory operation but stores the address itself, not the value at that address.", topic: "Memory Addressing" },
  { id: 35, question: "What does [RBX+RCX*4] mean?", options: ["RBX plus RCX times 4", "Memory at address (RBX + RCX × 4)", "An error", "Array access only"], correctAnswer: 1, explanation: "This is scaled indexed addressing. It accesses memory at (RBX + RCX*4), commonly used for array access where RBX is the base and RCX is the index (scaled by element size 4).", topic: "Memory Addressing" },
  { id: 36, question: "What valid scale factors can be used in x86 addressing?", options: ["1, 2, 3, 4", "1, 2, 4, 8", "Any number", "Only powers of 10"], correctAnswer: 1, explanation: "x86 addressing modes support scale factors of 1, 2, 4, and 8 only. These correspond to byte, word, dword, and qword element sizes.", topic: "Memory Addressing" },
  { id: 37, question: "What is RIP-relative addressing?", options: ["Addressing relative to the instruction pointer", "Addressing relative to RSP", "Random instruction processing", "Recursive instruction pointer"], correctAnswer: 0, explanation: "RIP-relative addressing computes addresses relative to the current instruction pointer. It's commonly used in x86-64 for accessing global data in position-independent code.", topic: "Memory Addressing" },
  { id: 38, question: "What does BYTE PTR indicate?", options: ["A byte-sized pointer", "The operation should work with a single byte", "Pointer to bytes", "A byte array"], correctAnswer: 1, explanation: "BYTE PTR specifies that the memory operand should be treated as a single byte (8 bits). Similar directives include WORD PTR (16 bits), DWORD PTR (32 bits), and QWORD PTR (64 bits).", topic: "Memory Addressing" },
  { id: 39, question: "In [RSI+RDI*2+10], what is 10?", options: ["A register", "A displacement/offset constant", "A scale factor", "An immediate operand"], correctAnswer: 1, explanation: "The 10 is a displacement (constant offset). The full address is RSI (base) + RDI×2 (scaled index) + 10 (displacement).", topic: "Memory Addressing" },
  { id: 40, question: "What is segment:offset addressing?", options: ["Modern 64-bit addressing", "Legacy addressing using segment registers and offsets", "Address segmentation", "Network addressing"], correctAnswer: 1, explanation: "Segment:offset is a legacy addressing mode from 16-bit x86 where the physical address = segment × 16 + offset. Modern 64-bit code rarely uses it except for special purposes.", topic: "Memory Addressing" },
  { id: 41, question: "What is the effective address?", options: ["The address after segment translation", "The calculated address from base, index, scale, and displacement", "The virtual address", "The physical RAM address"], correctAnswer: 1, explanation: "The effective address is the final address calculated from the addressing mode components (base register + index register × scale + displacement).", topic: "Memory Addressing" },
  { id: 42, question: "Why would you use LEA RAX, [RBX+RCX] instead of ADD?", options: ["LEA is faster", "LEA doesn't modify flags and stores result in a different register", "There's no difference", "LEA uses less memory"], correctAnswer: 1, explanation: "LEA computes the address without modifying flags and can store the result in any register. ADD modifies flags and stores in the destination operand. LEA can do three-operand addition.", topic: "Memory Addressing" },
  { id: 43, question: "What does MOV RAX, [RSP+0x20] typically access in a function?", options: ["A local variable or saved value on the stack", "A global variable", "A heap allocation", "The return address"], correctAnswer: 0, explanation: "Addresses relative to RSP access the stack. [RSP+offset] typically accesses local variables, saved registers, or function arguments passed via stack.", topic: "Memory Addressing" },
  { id: 44, question: "What is base+index addressing useful for?", options: ["Only pointer arithmetic", "Accessing array elements with a base pointer and index", "Database operations", "Network programming"], correctAnswer: 1, explanation: "Base+index addressing is ideal for arrays: the base register holds the array's starting address and the index register (optionally scaled) selects the element.", topic: "Memory Addressing" },
  { id: 45, question: "What does QWORD PTR specify?", options: ["A quad-byte (4 bytes)", "An 8-byte (64-bit) memory operand", "A quarter word", "Query word pointer"], correctAnswer: 1, explanation: "QWORD PTR specifies a quadword (8 bytes/64 bits). WORD is 2 bytes, DWORD is 4 bytes (double word), QWORD is 8 bytes (quad word).", topic: "Memory Addressing" },

  // ==================== Topic 4: Instructions (Questions 46-60) ====================
  { id: 46, question: "What does ADD RAX, RBX do?", options: ["Adds RBX to RAX, result in RAX", "Adds RAX to RBX, result in RBX", "Adds both and stores elsewhere", "Adds memory addresses"], correctAnswer: 0, explanation: "ADD dest, src adds the source to the destination and stores the result in the destination. ADD RAX, RBX computes RAX = RAX + RBX.", topic: "Instructions" },
  { id: 47, question: "What is the difference between SUB and CMP?", options: ["No difference", "SUB stores result, CMP only sets flags", "CMP is faster", "SUB works with memory"], correctAnswer: 1, explanation: "Both SUB and CMP perform subtraction, but SUB stores the result in the destination while CMP discards the result and only sets flags based on the comparison.", topic: "Instructions" },
  { id: 48, question: "What does IMUL do differently from MUL?", options: ["IMUL is faster", "IMUL handles signed multiplication", "IMUL uses immediate values", "No difference"], correctAnswer: 1, explanation: "MUL performs unsigned multiplication while IMUL performs signed multiplication. They set flags differently and interpret operands differently.", topic: "Instructions" },
  { id: 49, question: "After XOR RAX, RAX, what is in RAX?", options: ["Unchanged", "0 (zero)", "All 1s", "Random value"], correctAnswer: 1, explanation: "XORing any value with itself produces zero. XOR RAX, RAX is a common idiom to efficiently zero a register (shorter encoding than MOV RAX, 0).", topic: "Instructions" },
  { id: 50, question: "What does SHL RAX, 2 do?", options: ["Shifts RAX left by 2 bits (multiplies by 4)", "Shifts RAX right by 2 bits", "Sets high and low bits", "Subtracts 2"], correctAnswer: 0, explanation: "SHL (Shift Left) shifts all bits left by the specified count. Each left shift doubles the value, so shifting left by 2 multiplies by 4.", topic: "Instructions" },
  { id: 51, question: "What is the AND instruction commonly used for?", options: ["Adding values", "Masking bits / clearing specific bits", "Logical comparison", "Memory allocation"], correctAnswer: 1, explanation: "AND is used for bit masking - clearing specific bits while preserving others. AND with a mask keeps only the bits where the mask has 1s.", topic: "Instructions" },
  { id: 52, question: "What does TEST RAX, RAX do?", options: ["Tests if RAX is valid", "Performs AND RAX, RAX and sets flags (checks if zero)", "Tests memory access", "Tests instruction validity"], correctAnswer: 1, explanation: "TEST performs a bitwise AND and sets flags but discards the result. TEST RAX, RAX sets ZF if RAX is zero, commonly used to check if a register is zero.", topic: "Instructions" },
  { id: 53, question: "What does NOT instruction do?", options: ["Negates a value (two's complement)", "Inverts all bits (one's complement)", "Does nothing", "Logical NOT operation"], correctAnswer: 1, explanation: "NOT performs a bitwise complement, flipping all bits (0→1 and 1→0). This is one's complement. For two's complement negation, use NEG.", topic: "Instructions" },
  { id: 54, question: "What does NEG RAX do?", options: ["Makes RAX negative", "Computes two's complement negation of RAX", "Flips sign bit only", "Nothing"], correctAnswer: 1, explanation: "NEG computes the two's complement negation: RAX = 0 - RAX. It effectively converts positive to negative and vice versa for signed values.", topic: "Instructions" },
  { id: 55, question: "What does INC do?", options: ["Increases by any amount", "Increments by 1", "Includes a value", "Initializes counter"], correctAnswer: 1, explanation: "INC (increment) adds 1 to its operand. INC RAX is equivalent to ADD RAX, 1 but with a shorter encoding.", topic: "Instructions" },
  { id: 56, question: "What is the result of OR RAX, 0x1?", options: ["Sets RAX to 1", "Sets the lowest bit of RAX to 1", "Clears the lowest bit", "Compares with 1"], correctAnswer: 1, explanation: "OR with 0x1 sets the least significant bit to 1 while preserving all other bits. This is a common idiom to ensure a value is odd or set a flag bit.", topic: "Instructions" },
  { id: 57, question: "What does MOVZX do?", options: ["Moves with zero extension", "Moves to external memory", "Moves with XOR", "Moves zero values only"], correctAnswer: 0, explanation: "MOVZX (Move with Zero Extension) copies a smaller source to a larger destination, filling the upper bits with zeros. Used for unsigned values.", topic: "Instructions" },
  { id: 58, question: "What does MOVSX do differently from MOVZX?", options: ["Uses sign extension instead of zero extension", "Moves signed values only", "Moves to segment registers", "No difference"], correctAnswer: 0, explanation: "MOVSX (Move with Sign Extension) extends the sign bit of the source to fill the upper bits. This preserves the signed value when extending to a larger register.", topic: "Instructions" },
  { id: 59, question: "What does CDQ/CQO instruction do?", options: ["Clears data queue", "Sign-extends EAX/RAX into EDX:EAX or RDX:RAX for division", "Computes data quality", "Creates data query"], correctAnswer: 1, explanation: "CDQ sign-extends EAX into EDX:EAX, and CQO sign-extends RAX into RDX:RAX. These prepare signed dividends for the IDIV instruction.", topic: "Instructions" },
  { id: 60, question: "What registers does DIV RBX use and modify?", options: ["Only RBX", "Divides RDX:RAX by RBX, quotient in RAX, remainder in RDX", "RAX only", "All general registers"], correctAnswer: 1, explanation: "DIV divides the 128-bit value RDX:RAX by the operand. The quotient goes in RAX and the remainder in RDX. For 32-bit division, it uses EDX:EAX.", topic: "Instructions" },

  // ==================== Topic 5: Control Flow (Questions 61-70) ====================
  { id: 61, question: "What does JMP instruction do?", options: ["Jumps only if condition met", "Unconditionally transfers control to the target address", "Joins multiple paths", "Jump to main program"], correctAnswer: 1, explanation: "JMP (Jump) unconditionally transfers execution to the specified target address. It's used for loops, goto-style control flow, and function tail calls.", topic: "Control Flow" },
  { id: 62, question: "When does JE (Jump if Equal) jump?", options: ["When ZF = 0", "When ZF = 1", "When CF = 1", "Always"], correctAnswer: 1, explanation: "JE (Jump if Equal, also called JZ - Jump if Zero) jumps when the Zero Flag is set (ZF=1), typically after a CMP or TEST where the operands were equal.", topic: "Control Flow" },
  { id: 63, question: "What is the difference between JB and JL?", options: ["No difference", "JB is for unsigned comparison, JL is for signed comparison", "JB is below, JL is less", "JB is faster"], correctAnswer: 1, explanation: "JB (Jump if Below) uses unsigned comparison (checks CF), while JL (Jump if Less) uses signed comparison (checks SF≠OF). Use JB for unsigned values, JL for signed.", topic: "Control Flow" },
  { id: 64, question: "What does CALL instruction do?", options: ["Calls a system API", "Pushes return address and jumps to function", "Only jumps to function", "Calculates address"], correctAnswer: 1, explanation: "CALL pushes the address of the next instruction onto the stack (return address) and then jumps to the target function address.", topic: "Control Flow" },
  { id: 65, question: "What does RET instruction do?", options: ["Returns a value", "Pops return address from stack and jumps to it", "Resets the program", "Returns to operating system"], correctAnswer: 1, explanation: "RET pops the return address from the stack into RIP, returning control to the instruction after the CALL that invoked the current function.", topic: "Control Flow" },
  { id: 66, question: "What does JNE/JNZ check?", options: ["ZF = 1", "ZF = 0 (result was not zero/operands were not equal)", "CF = 0", "OF = 1"], correctAnswer: 1, explanation: "JNE (Jump if Not Equal) and JNZ (Jump if Not Zero) jump when ZF=0, meaning the previous comparison showed the operands were not equal.", topic: "Control Flow" },
  { id: 67, question: "What does a conditional jump right after CMP RAX, 10 check?", options: ["If RAX equals 10", "The relationship between RAX and 10", "If 10 is valid", "Memory comparison"], correctAnswer: 1, explanation: "CMP RAX, 10 computes RAX - 10 and sets flags. A following conditional jump checks the relationship: JE if RAX==10, JL if RAX<10 (signed), JB if RAX<10 (unsigned), etc.", topic: "Control Flow" },
  { id: 68, question: "What is a short jump vs near jump?", options: ["Short is faster", "Short jump has limited range (-128 to +127), near can reach any address in segment", "Near is newer", "No practical difference"], correctAnswer: 1, explanation: "Short jumps use a 1-byte signed displacement (-128 to +127 bytes from RIP). Near jumps use a 4-byte displacement allowing larger ranges. Assemblers typically choose automatically.", topic: "Control Flow" },
  { id: 69, question: "What does LOOP instruction do?", options: ["Creates an infinite loop", "Decrements RCX and jumps if RCX ≠ 0", "Loops through memory", "Loops registers"], correctAnswer: 1, explanation: "LOOP decrements RCX (without affecting flags) and jumps to the target if RCX is not zero. It's used for count-controlled loops.", topic: "Control Flow" },
  { id: 70, question: "What is a 'fall-through' in assembly control flow?", options: ["An error condition", "When execution continues to the next instruction without jumping", "A type of crash", "Stack overflow"], correctAnswer: 1, explanation: "Fall-through occurs when a conditional jump is not taken and execution continues to the next sequential instruction. It's intentionally used in switch-case implementations.", topic: "Control Flow" },

  // ==================== Topic 6: Stack Operations (Questions 71-75) ====================
  { id: 71, question: "What does PUSH RAX do to RSP?", options: ["Increments RSP by 8", "Decrements RSP by 8 and stores RAX at new RSP", "Doesn't change RSP", "Adds RAX to RSP"], correctAnswer: 1, explanation: "PUSH decrements RSP (stack grows downward) by the operand size (8 bytes for 64-bit) and stores the value at the new top of stack.", topic: "Stack Operations" },
  { id: 72, question: "What does POP RBX do?", options: ["Clears RBX", "Loads value at RSP into RBX and increments RSP", "Decrements RSP", "Removes RBX from CPU"], correctAnswer: 1, explanation: "POP reads the value at the current stack top (RSP), stores it in the destination, and increments RSP (by 8 bytes for 64-bit) to 'remove' the value from the stack.", topic: "Stack Operations" },
  { id: 73, question: "In x86-64, which direction does the stack grow?", options: ["Toward higher addresses", "Toward lower addresses (downward)", "Both directions", "Depends on OS"], correctAnswer: 1, explanation: "The x86 stack grows downward - PUSH decrements RSP, POP increments it. Lower addresses are 'higher' on the stack.", topic: "Stack Operations" },
  { id: 74, question: "What is a stack frame?", options: ["A GUI element", "The region of stack memory used by a single function invocation", "A type of frame buffer", "Error handling structure"], correctAnswer: 1, explanation: "A stack frame contains a function's local variables, saved registers, and return address. It's created when a function is called and destroyed when it returns.", topic: "Stack Operations" },
  { id: 75, question: "What does 'sub rsp, 0x20' typically do at function start?", options: ["Subtracts a value", "Allocates 32 bytes of stack space for local variables/shadow space", "Checks stack size", "Creates stack overflow"], correctAnswer: 1, explanation: "SUB RSP, 0x20 allocates 32 bytes on the stack by moving the stack pointer down. In Windows x64, this often includes the 32-byte 'shadow space' for register arguments.", topic: "Stack Operations" },
];

const QuizSection: React.FC = () => {
  const [quizState, setQuizState] = useState<'start' | 'active' | 'results'>('start');
  const [questions, setQuestions] = useState<QuizQuestion[]>([]);
  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState<{ [key: number]: number }>({});
  const [showExplanation, setShowExplanation] = useState(false);
  const [score, setScore] = useState(0);

  const QUESTIONS_PER_QUIZ = 10;

  const startQuiz = () => {
    // Shuffle and select 10 random questions
    const shuffled = [...questionBank].sort(() => Math.random() - 0.5);
    const selected = shuffled.slice(0, QUESTIONS_PER_QUIZ);
    setQuestions(selected);
    setCurrentQuestionIndex(0);
    setSelectedAnswers({});
    setShowExplanation(false);
    setScore(0);
    setQuizState('active');
  };

  const handleAnswerSelect = (answerIndex: number) => {
    if (showExplanation) return;
    setSelectedAnswers(prev => ({
      ...prev,
      [currentQuestionIndex]: answerIndex
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
      setQuizState('results');
    }
  };

  const currentQuestion = questions[currentQuestionIndex];
  const selectedAnswer = selectedAnswers[currentQuestionIndex];
  const isCorrect = selectedAnswer === currentQuestion?.correctAnswer;

  if (quizState === 'start') {
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <QuizIcon sx={{ fontSize: 64, color: "#f97316", mb: 2 }} />
        <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
          Assembly Language Quiz
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 500, mx: "auto" }}>
          Test your understanding of assembly language concepts with {QUESTIONS_PER_QUIZ} randomly selected questions from our 75-question bank. Topics include Assembly Basics, Registers, Memory Addressing, Instructions, Control Flow, and Stack Operations.
        </Typography>
        <Button
          variant="contained"
          size="large"
          onClick={startQuiz}
          sx={{
            bgcolor: "#f97316",
            "&:hover": { bgcolor: "#ea580c" },
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

  if (quizState === 'results') {
    const percentage = Math.round((score / QUESTIONS_PER_QUIZ) * 100);
    const isPassing = percentage >= 70;
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <EmojiEventsIcon sx={{ fontSize: 80, color: isPassing ? "#22c55e" : "#f97316", mb: 2 }} />
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
          Quiz Complete!
        </Typography>
        <Typography variant="h5" sx={{ fontWeight: 700, color: isPassing ? "#22c55e" : "#f97316", mb: 2 }}>
          {score} / {QUESTIONS_PER_QUIZ} ({percentage}%)
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 3, maxWidth: 400, mx: "auto" }}>
          {isPassing 
            ? "Great job! You have a solid understanding of assembly language concepts." 
            : "Keep studying! Review the modules above and try again."}
        </Typography>
        <Button
          variant="contained"
          size="large"
          onClick={startQuiz}
          startIcon={<RefreshIcon />}
          sx={{
            bgcolor: "#f97316",
            "&:hover": { bgcolor: "#ea580c" },
            px: 4,
            py: 1.5,
            fontWeight: 700,
          }}
        >
          Try Again
        </Button>
      </Box>
    );
  }

  if (!currentQuestion) return null;

  return (
    <Box sx={{ py: 2 }}>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
          <Chip 
            label={`Question ${currentQuestionIndex + 1}/${QUESTIONS_PER_QUIZ}`} 
            size="small" 
            sx={{ bgcolor: alpha("#f97316", 0.15), color: "#f97316", fontWeight: 700 }} 
          />
          <Chip label={currentQuestion.topic} size="small" variant="outlined" />
        </Box>
        <Chip 
          label={`Score: ${score}/${currentQuestionIndex + (showExplanation ? 1 : 0)}`} 
          size="small" 
          sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} 
        />
      </Box>

      {/* Progress bar */}
      <Box sx={{ mb: 3, bgcolor: alpha("#f97316", 0.1), borderRadius: 1, height: 8 }}>
        <Box 
          sx={{ 
            width: `${((currentQuestionIndex + (showExplanation ? 1 : 0)) / QUESTIONS_PER_QUIZ) * 100}%`, 
            bgcolor: "#f97316", 
            borderRadius: 1, 
            height: "100%",
            transition: "width 0.3s ease"
          }} 
        />
      </Box>

      <Typography variant="h6" sx={{ fontWeight: 700, mb: 3 }}>
        {currentQuestion.question}
      </Typography>

      <RadioGroup value={selectedAnswer ?? ""} onChange={(e) => handleAnswerSelect(parseInt(e.target.value))}>
        {currentQuestion.options.map((option, idx) => (
          <Paper
            key={idx}
            sx={{
              p: 2,
              mb: 1.5,
              borderRadius: 2,
              cursor: showExplanation ? "default" : "pointer",
              border: `2px solid ${
                showExplanation
                  ? idx === currentQuestion.correctAnswer
                    ? "#22c55e"
                    : idx === selectedAnswer
                    ? "#ef4444"
                    : "transparent"
                  : selectedAnswer === idx
                  ? "#f97316"
                  : "transparent"
              }`,
              bgcolor: showExplanation
                ? idx === currentQuestion.correctAnswer
                  ? alpha("#22c55e", 0.1)
                  : idx === selectedAnswer
                  ? alpha("#ef4444", 0.1)
                  : "transparent"
                : selectedAnswer === idx
                ? alpha("#f97316", 0.1)
                : "transparent",
              transition: "all 0.2s ease",
              "&:hover": {
                bgcolor: showExplanation ? undefined : alpha("#f97316", 0.05),
              },
            }}
            onClick={() => handleAnswerSelect(idx)}
          >
            <FormControlLabel
              value={idx}
              control={<Radio sx={{ color: "#f97316", "&.Mui-checked": { color: "#f97316" } }} />}
              label={option}
              sx={{ m: 0, width: "100%" }}
              disabled={showExplanation}
            />
          </Paper>
        ))}
      </RadioGroup>

      {!showExplanation ? (
        <Button
          variant="contained"
          fullWidth
          onClick={handleSubmitAnswer}
          disabled={selectedAnswer === undefined}
          sx={{
            mt: 2,
            bgcolor: "#f97316",
            "&:hover": { bgcolor: "#ea580c" },
            "&:disabled": { bgcolor: alpha("#f97316", 0.3) },
            py: 1.5,
            fontWeight: 700,
          }}
        >
          Submit Answer
        </Button>
      ) : (
        <Box sx={{ mt: 3 }}>
          <Alert
            severity={isCorrect ? "success" : "error"}
            sx={{ mb: 2, borderRadius: 2 }}
          >
            <AlertTitle sx={{ fontWeight: 700 }}>
              {isCorrect ? "🎉 Correct!" : "❌ Incorrect"}
            </AlertTitle>
            {currentQuestion.explanation}
          </Alert>
          <Button
            variant="contained"
            fullWidth
            onClick={handleNextQuestion}
            sx={{
              bgcolor: "#f97316",
              "&:hover": { bgcolor: "#ea580c" },
              py: 1.5,
              fontWeight: 700,
            }}
          >
            {currentQuestionIndex < questions.length - 1 ? "Next Question" : "See Results"}
          </Button>
        </Box>
      )}
    </Box>
  );
};

// ==================== MAIN PAGE ====================
export default function AssemblyGuidePage() {
  const navigate = useNavigate();
  const theme = useTheme();

  const pageContext = `Assembly Language Programming Guide - A comprehensive learning resource for understanding assembly language, the low-level programming language that provides direct access to CPU instructions. This guide covers x86 and x86-64 architecture, registers, memory addressing, instruction sets, calling conventions, and practical applications in reverse engineering, malware analysis, and security research. Part of the Software Engineering section under Mobile Security.`;

  // Navigation state
  const [navDrawerOpen, setNavDrawerOpen] = useState(false);
  const [activeSection, setActiveSection] = useState<string>("");
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));

  // Module navigation items
  const moduleNavItems = [
    { id: "introduction", label: "Introduction", icon: "📖" },
    { id: "module-1", label: "1. CPU Architecture", icon: "🔧" },
    { id: "module-2", label: "2. x86-64 Registers", icon: "📊" },
    { id: "module-3", label: "3. Memory Addressing", icon: "💾" },
    { id: "module-4", label: "4. Data Movement", icon: "↔️" },
    { id: "module-5", label: "5. Arithmetic & Logic", icon: "➕" },
    { id: "module-6", label: "6. Control Flow", icon: "🔀" },
    { id: "module-7", label: "7. Stack & Functions", icon: "📚" },
    { id: "module-8", label: "8. Syscalls & Interrupts", icon: "⚡" },
    { id: "module-9", label: "9. SIMD & Vectors", icon: "🚀" },
    { id: "module-10", label: "10. Reverse Engineering", icon: "🔍" },
    { id: "module-11", label: "11. Shellcode Dev", icon: "🐚" },
    { id: "module-12", label: "12. ARM Assembly", icon: "📱" },
    { id: "quiz-section", label: "Quiz", icon: "❓" },
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
    handleScroll(); // Initial check
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  // Scroll to top/bottom helpers
  const scrollToTop = () => window.scrollTo({ top: 0, behavior: "smooth" });
  const scrollToBottom = () => window.scrollTo({ top: document.body.scrollHeight, behavior: "smooth" });

  const quickStats = [
    { label: "Modules", value: "12", color: "#f97316" },
    { label: "Exercises", value: "TBD", color: "#3b82f6" },
    { label: "Quiz Questions", value: "75", color: "#22c55e" },
    { label: "Difficulty", value: "Intermediate", color: "#8b5cf6" },
  ];

  // Calculate progress based on active section
  const currentIndex = moduleNavItems.findIndex(item => item.id === activeSection);
  const progressPercent = currentIndex >= 0 ? ((currentIndex + 1) / moduleNavItems.length) * 100 : 0;

  // Desktop sidebar navigation component
  const sidebarNav = (
    <Paper
      elevation={0}
      sx={{
        width: 220,
        flexShrink: 0,
        position: "sticky",
        top: 80,
        maxHeight: "calc(100vh - 100px)",
        overflowY: "auto",
        borderRadius: 3,
        border: `1px solid ${alpha("#f97316", 0.15)}`,
        bgcolor: alpha(theme.palette.background.paper, 0.6),
        display: { xs: "none", lg: "block" },
        "&::-webkit-scrollbar": {
          width: 6,
        },
        "&::-webkit-scrollbar-thumb": {
          bgcolor: alpha("#f97316", 0.3),
          borderRadius: 3,
        },
      }}
    >
      <Box sx={{ p: 2 }}>
        <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 1, color: "#f97316", display: "flex", alignItems: "center", gap: 1 }}>
          <ListAltIcon sx={{ fontSize: 18 }} />
          Course Navigation
        </Typography>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
            <Typography variant="caption" color="text.secondary">Progress</Typography>
            <Typography variant="caption" sx={{ fontWeight: 600, color: "#f97316" }}>{Math.round(progressPercent)}%</Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progressPercent}
            sx={{
              height: 6,
              borderRadius: 3,
              bgcolor: alpha("#f97316", 0.1),
              "& .MuiLinearProgress-bar": {
                bgcolor: "#f97316",
                borderRadius: 3,
              },
            }}
          />
        </Box>
        <Divider sx={{ mb: 1 }} />
        <List dense sx={{ mx: -1 }}>
          {moduleNavItems.map((item) => (
            <ListItem
              key={item.id}
              onClick={() => scrollToSection(item.id)}
              sx={{
                borderRadius: 1.5,
                mb: 0.25,
                py: 0.5,
                cursor: "pointer",
                bgcolor: activeSection === item.id ? alpha("#f97316", 0.15) : "transparent",
                borderLeft: activeSection === item.id ? `3px solid #f97316` : "3px solid transparent",
                "&:hover": {
                  bgcolor: alpha("#f97316", 0.08),
                },
                transition: "all 0.15s ease",
              }}
            >
              <ListItemIcon sx={{ minWidth: 24, fontSize: "0.9rem" }}>
                {item.icon}
              </ListItemIcon>
              <ListItemText
                primary={
                  <Typography
                    variant="caption"
                    sx={{
                      fontWeight: activeSection === item.id ? 700 : 500,
                      color: activeSection === item.id ? "#f97316" : "text.secondary",
                      fontSize: "0.75rem",
                    }}
                  >
                    {item.label}
                  </Typography>
                }
              />
            </ListItem>
          ))}
        </List>
      </Box>
    </Paper>
  );

  return (
    <LearnPageLayout pageTitle="Assembly Language Programming" pageContext={pageContext}>
      {/* Floating Navigation Button - Mobile Only */}
      <Tooltip title="Navigate Modules" placement="left">
        <Fab
          color="primary"
          onClick={() => setNavDrawerOpen(true)}
          sx={{
            position: "fixed",
            bottom: 90,
            right: 24,
            zIndex: 1000,
            bgcolor: "#f97316",
            "&:hover": { bgcolor: "#ea580c" },
            boxShadow: `0 4px 20px ${alpha("#f97316", 0.4)}`,
            display: { xs: "flex", lg: "none" },
          }}
        >
          <ListAltIcon />
        </Fab>
      </Tooltip>

      {/* Scroll to Top Button - Mobile Only */}
      <Tooltip title="Scroll to Top" placement="left">
        <Fab
          size="small"
          onClick={scrollToTop}
          sx={{
            position: "fixed",
            bottom: 150,
            right: 28,
            zIndex: 1000,
            bgcolor: alpha("#f97316", 0.15),
            color: "#f97316",
            "&:hover": { bgcolor: alpha("#f97316", 0.25) },
            display: { xs: "flex", lg: "none" },
          }}
        >
          <KeyboardArrowUpIcon />
        </Fab>
      </Tooltip>

      {/* Scroll to Bottom Button - Mobile Only */}
      <Tooltip title="Scroll to Bottom" placement="left">
        <Fab
          size="small"
          onClick={scrollToBottom}
          sx={{
            position: "fixed",
            bottom: 32,
            right: 28,
            zIndex: 1000,
            bgcolor: alpha("#f97316", 0.15),
            color: "#f97316",
            "&:hover": { bgcolor: alpha("#f97316", 0.25) },
            display: { xs: "flex", lg: "none" },
          }}
        >
          <KeyboardArrowDownIcon />
        </Fab>
      </Tooltip>

      {/* Navigation Drawer */}
      <Drawer
        anchor="right"
        open={navDrawerOpen}
        onClose={() => setNavDrawerOpen(false)}
        PaperProps={{
          sx: {
            width: isMobile ? "85%" : 320,
            bgcolor: theme.palette.background.paper,
            backgroundImage: "none",
          },
        }}
      >
        <Box sx={{ p: 2 }}>
          <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 700, display: "flex", alignItems: "center", gap: 1 }}>
              <MenuBookIcon sx={{ color: "#f97316" }} />
              Course Navigation
            </Typography>
            <IconButton onClick={() => setNavDrawerOpen(false)} size="small">
              <CloseIcon />
            </IconButton>
          </Box>
          
          <Divider sx={{ mb: 2 }} />

          {/* Progress indicator */}
          <Box sx={{ mb: 2, p: 1.5, borderRadius: 2, bgcolor: alpha("#f97316", 0.05) }}>
            <Typography variant="caption" color="text.secondary">
              12 Modules • 75 Quiz Questions
            </Typography>
          </Box>

          {/* Navigation List */}
          <List dense sx={{ mx: -1 }}>
            {moduleNavItems.map((item) => (
              <ListItem
                key={item.id}
                onClick={() => scrollToSection(item.id)}
                sx={{
                  borderRadius: 2,
                  mb: 0.5,
                  cursor: "pointer",
                  bgcolor: activeSection === item.id ? alpha("#f97316", 0.15) : "transparent",
                  borderLeft: activeSection === item.id ? `3px solid #f97316` : "3px solid transparent",
                  "&:hover": {
                    bgcolor: alpha("#f97316", 0.1),
                  },
                  transition: "all 0.2s ease",
                }}
              >
                <ListItemIcon sx={{ minWidth: 32, fontSize: "1.1rem" }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Typography
                      variant="body2"
                      sx={{
                        fontWeight: activeSection === item.id ? 700 : 500,
                        color: activeSection === item.id ? "#f97316" : "text.primary",
                      }}
                    >
                      {item.label}
                    </Typography>
                  }
                />
                {activeSection === item.id && (
                  <Chip
                    label="Current"
                    size="small"
                    sx={{
                      height: 20,
                      fontSize: "0.65rem",
                      bgcolor: alpha("#f97316", 0.2),
                      color: "#f97316",
                    }}
                  />
                )}
              </ListItem>
            ))}
          </List>

          <Divider sx={{ my: 2 }} />

          {/* Quick Actions */}
          <Box sx={{ display: "flex", gap: 1 }}>
            <Button
              size="small"
              variant="outlined"
              onClick={scrollToTop}
              startIcon={<KeyboardArrowUpIcon />}
              sx={{ flex: 1, borderColor: alpha("#f97316", 0.3), color: "#f97316" }}
            >
              Top
            </Button>
            <Button
              size="small"
              variant="outlined"
              onClick={() => scrollToSection("quiz-section")}
              startIcon={<QuizIcon />}
              sx={{ flex: 1, borderColor: alpha("#f97316", 0.3), color: "#f97316" }}
            >
              Quiz
            </Button>
          </Box>
        </Box>
      </Drawer>

      {/* Main Layout with Sidebar */}
      <Box sx={{ display: "flex", gap: 3, maxWidth: 1400, mx: "auto", px: { xs: 2, sm: 3 }, py: 4 }}>
        {/* Desktop Sidebar */}
        {sidebarNav}

        {/* Main Content */}
        <Box sx={{ flex: 1, minWidth: 0 }}>
        {/* Back Button */}
        <Chip
          component={Link}
          to="/learn"
          icon={<ArrowBackIcon />}
          label="Back to Learning Hub"
          clickable
          variant="outlined"
          sx={{ borderRadius: 2, mb: 3 }}
        />

        {/* Hero Banner */}
        <Paper
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#f97316", 0.15)} 0%, ${alpha("#ea580c", 0.15)} 50%, ${alpha("#dc2626", 0.15)} 100%)`,
            border: `1px solid ${alpha("#f97316", 0.2)}`,
            position: "relative",
            overflow: "hidden",
          }}
        >
          {/* Decorative background elements */}
          <Box
            sx={{
              position: "absolute",
              top: -50,
              right: -50,
              width: 200,
              height: 200,
              borderRadius: "50%",
              background: `radial-gradient(circle, ${alpha("#f97316", 0.1)} 0%, transparent 70%)`,
            }}
          />
          <Box
            sx={{
              position: "absolute",
              bottom: -30,
              left: "30%",
              width: 150,
              height: 150,
              borderRadius: "50%",
              background: `radial-gradient(circle, ${alpha("#dc2626", 0.1)} 0%, transparent 70%)`,
            }}
          />
          
          <Box sx={{ position: "relative", zIndex: 1 }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 3, mb: 3 }}>
              <Box
                sx={{
                  width: 80,
                  height: 80,
                  borderRadius: 3,
                  background: `linear-gradient(135deg, #f97316, #dc2626)`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  boxShadow: `0 8px 32px ${alpha("#f97316", 0.3)}`,
                }}
              >
                <MemoryIcon sx={{ fontSize: 44, color: "white" }} />
              </Box>
              <Box>
                <Typography variant="h3" sx={{ fontWeight: 800, mb: 0.5 }}>
                  Assembly Language Programming
                </Typography>
                <Typography variant="h6" color="text.secondary" sx={{ fontWeight: 400 }}>
                  Master the language of the machine
                </Typography>
              </Box>
            </Box>
            
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
              <Chip label="Intermediate" color="warning" />
              <Chip label="x86/x64" sx={{ bgcolor: alpha("#3b82f6", 0.15), color: "#3b82f6", fontWeight: 600 }} />
              <Chip label="Registers" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600 }} />
              <Chip label="Memory" sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 600 }} />
              <Chip label="Software Engineering" sx={{ bgcolor: alpha("#f97316", 0.15), color: "#f97316", fontWeight: 600 }} />
            </Box>

            {/* Quick Stats */}
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

        {/* ==================== DETAILED INTRODUCTION ==================== */}
        <Paper
          id="introduction"
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <Box
              sx={{
                width: 48,
                height: 48,
                borderRadius: 2,
                background: `linear-gradient(135deg, #f97316, #dc2626)`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <SchoolIcon sx={{ color: "white", fontSize: 28 }} />
            </Box>
            What is Assembly Language?
          </Typography>
          
          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            Imagine you're trying to communicate with someone who only understands a very specific, primitive language—one where 
            every instruction must be extremely precise and there's no room for ambiguity. That's essentially what <strong>assembly 
            language</strong> is: a way for humans to communicate directly with the <strong>central processing unit (CPU)</strong> of 
            a computer. While high-level programming languages like Python, JavaScript, or C++ provide abstractions that make 
            programming easier for humans, assembly language strips away all those conveniences and gives you raw, direct control 
            over the hardware.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            At its core, every computer program—whether it's a web browser, a video game, or a mobile app—eventually gets 
            translated into <strong>machine code</strong>: a sequence of binary numbers (1s and 0s) that the CPU can understand 
            and execute. However, writing programs in pure binary is virtually impossible for humans. Assembly language provides 
            a thin layer of human-readable <strong>mnemonics</strong> (short abbreviations) that map directly to machine code 
            instructions. Instead of writing <code style={{ background: alpha("#f97316", 0.1), padding: "2px 6px", borderRadius: 4 }}>10110000 01100001</code>, 
            you can write <code style={{ background: alpha("#f97316", 0.1), padding: "2px 6px", borderRadius: 4 }}>MOV AL, 0x61</code>—which 
            tells the CPU to move the hexadecimal value 0x61 into the AL register. The <strong>assembler</strong> (a special 
            program) then converts your assembly code into the actual binary machine code the CPU needs.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            What makes assembly language unique—and challenging—is that it's <strong>architecture-specific</strong>. The assembly 
            language you write for an Intel x86 processor is completely different from what you'd write for an ARM processor 
            (common in smartphones) or a MIPS processor (used in some embedded systems). Each CPU architecture has its own 
            set of instructions, registers, and conventions. This is why we often refer to "x86 assembly" or "ARM assembly" 
            rather than just "assembly language" in general. In this guide, we'll focus primarily on <strong>x86 and x86-64 
            (also called AMD64 or Intel 64)</strong> assembly, which is the dominant architecture for desktop computers, 
            laptops, and servers.
          </Typography>

          <Alert severity="info" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Why Should You Learn Assembly?</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Learning assembly language might seem daunting, but it's an <strong>invaluable skill</strong> for security 
              professionals, reverse engineers, malware analysts, and anyone who wants to truly understand how computers 
              work at the lowest level. When you analyze malware, exploit vulnerabilities, or debug complex software issues, 
              you'll frequently encounter assembly code. Understanding it transforms you from someone who just uses tools 
              into someone who truly comprehends what's happening inside the machine.
            </Typography>
          </Alert>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#3b82f6" }}>
            The CPU: Understanding the Heart of Computation
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            Before diving into assembly instructions, you need to understand what the CPU actually does. The <strong>Central 
            Processing Unit</strong> is the "brain" of your computer—it's the chip that executes all the instructions that 
            make software work. At a fundamental level, a CPU performs four basic operations in a continuous cycle called 
            the <strong>fetch-decode-execute cycle</strong>:
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { step: "1. Fetch", desc: "The CPU retrieves the next instruction from memory (RAM) using the instruction pointer register", color: "#3b82f6", icon: "📥" },
              { step: "2. Decode", desc: "The CPU interprets the instruction to understand what operation to perform", color: "#8b5cf6", icon: "🔍" },
              { step: "3. Execute", desc: "The CPU performs the actual operation (arithmetic, data movement, comparison, etc.)", color: "#22c55e", icon: "⚡" },
              { step: "4. Store", desc: "Results are written back to registers or memory, and the cycle repeats", color: "#f97316", icon: "💾" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.step}>
                <Paper
                  sx={{
                    p: 2.5,
                    height: "100%",
                    borderRadius: 2,
                    bgcolor: alpha(item.color, 0.05),
                    border: `1px solid ${alpha(item.color, 0.15)}`,
                  }}
                >
                  <Typography variant="h5" sx={{ mb: 1 }}>{item.icon}</Typography>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color, mb: 1 }}>
                    {item.step}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>
                    {item.desc}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            This cycle happens <strong>billions of times per second</strong> on modern CPUs. A 3 GHz processor can execute 
            roughly 3 billion cycles per second! Each assembly instruction you write corresponds to one or more of these 
            cycles. When you write assembly code, you're directly controlling what the CPU does at each step—there's no 
            compiler making decisions for you, no runtime interpreting your code. You have complete, precise control.
          </Typography>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#22c55e" }}>
            Registers: The CPU's Fast Storage
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            <strong>Registers</strong> are small, extremely fast storage locations built directly into the CPU. Think of them 
            as the CPU's "working memory"—they hold the data that the CPU is actively processing. While your computer might 
            have 16 GB of RAM, it only has a handful of registers (typically 16-32 general-purpose registers in modern x86-64 
            CPUs). However, registers are <strong>thousands of times faster</strong> to access than RAM because they're 
            physically located inside the CPU chip itself.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            In x86-64 architecture, the main <strong>general-purpose registers</strong> are: <strong>RAX, RBX, RCX, RDX, RSI, 
            RDI, RBP, RSP, R8-R15</strong>. Each of these is 64 bits (8 bytes) wide. You can also access smaller portions of 
            these registers—for example, <strong>EAX</strong> is the lower 32 bits of RAX, <strong>AX</strong> is the lower 
            16 bits, and <strong>AL</strong> and <strong>AH</strong> are the lower and upper 8 bits of AX, respectively. This 
            backward compatibility exists because x86-64 evolved from the older 16-bit and 32-bit x86 architectures.
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
              Key x86-64 Registers and Their Common Uses:
            </Typography>
            <Grid container spacing={2}>
              {[
                { reg: "RAX", use: "Accumulator - function return values, arithmetic results" },
                { reg: "RBX", use: "Base register - general purpose, callee-saved" },
                { reg: "RCX", use: "Counter - loop counters, 4th function argument (Windows)" },
                { reg: "RDX", use: "Data - I/O operations, 3rd function argument" },
                { reg: "RSI", use: "Source Index - string operations, 2nd function argument (Linux)" },
                { reg: "RDI", use: "Destination Index - string operations, 1st function argument (Linux)" },
                { reg: "RBP", use: "Base Pointer - stack frame base reference" },
                { reg: "RSP", use: "Stack Pointer - always points to top of stack" },
                { reg: "RIP", use: "Instruction Pointer - address of next instruction to execute" },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={4} key={item.reg}>
                  <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                    <Chip label={item.reg} size="small" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 700, minWidth: 50 }} />
                    <Typography variant="body2" color="text.secondary">{item.use}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#8b5cf6" }}>
            Memory and the Stack
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            While registers provide fast storage, they're extremely limited in capacity. Programs need to store much more 
            data than can fit in registers, which is where <strong>memory (RAM)</strong> comes in. In assembly, you frequently 
            move data between registers and memory. Memory is organized as a linear sequence of bytes, each with a unique 
            <strong>address</strong>. You can think of memory as a massive array where each index is an address and each 
            element is a byte.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            One of the most important regions of memory is the <strong>stack</strong>. The stack is a Last-In-First-Out (LIFO) 
            data structure used to manage function calls, local variables, and saved register values. When you call a function, 
            the CPU <strong>pushes</strong> the return address onto the stack so it knows where to resume execution after the 
            function returns. Local variables are also stored on the stack. The <strong>RSP (Stack Pointer)</strong> register 
            always points to the current top of the stack, and the <strong>RBP (Base Pointer)</strong> typically points to 
            the base of the current function's stack frame.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            Understanding the stack is <strong>absolutely critical</strong> for security work. Buffer overflow exploits, 
            return-oriented programming (ROP), and many other attack techniques rely on manipulating the stack. When you 
            see exploit code or analyze malware, you'll constantly be tracing how values move on and off the stack.
          </Typography>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#f97316" }}>
            Common Assembly Instructions
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            Assembly instructions can be broadly categorized into several types: <strong>data movement</strong>, 
            <strong>arithmetic/logic</strong>, <strong>control flow</strong>, and <strong>stack operations</strong>. 
            Let's look at the most important ones you'll encounter:
          </Typography>

          <Grid container spacing={3} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6", mb: 2 }}>
                  Data Movement
                </Typography>
                <List dense>
                  {[
                    { instr: "MOV dest, src", desc: "Copy data from source to destination" },
                    { instr: "LEA dest, [addr]", desc: "Load effective address (compute address without dereferencing)" },
                    { instr: "XCHG a, b", desc: "Exchange values between two locations" },
                    { instr: "MOVZX dest, src", desc: "Move with zero extension" },
                    { instr: "MOVSX dest, src", desc: "Move with sign extension" },
                  ].map((item) => (
                    <ListItem key={item.instr} sx={{ py: 0.5, px: 0 }}>
                      <ListItemText 
                        primary={<code style={{ color: "#3b82f6", fontWeight: 600 }}>{item.instr}</code>}
                        secondary={item.desc}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>
                  Arithmetic & Logic
                </Typography>
                <List dense>
                  {[
                    { instr: "ADD dest, src", desc: "Add source to destination" },
                    { instr: "SUB dest, src", desc: "Subtract source from destination" },
                    { instr: "MUL src", desc: "Unsigned multiply (result in RAX:RDX)" },
                    { instr: "AND/OR/XOR", desc: "Bitwise logical operations" },
                    { instr: "SHL/SHR", desc: "Shift left/right (bit manipulation)" },
                  ].map((item) => (
                    <ListItem key={item.instr} sx={{ py: 0.5, px: 0 }}>
                      <ListItemText 
                        primary={<code style={{ color: "#22c55e", fontWeight: 600 }}>{item.instr}</code>}
                        secondary={item.desc}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 2 }}>
                  Control Flow
                </Typography>
                <List dense>
                  {[
                    { instr: "JMP address", desc: "Unconditional jump to address" },
                    { instr: "JE/JZ", desc: "Jump if equal / jump if zero" },
                    { instr: "JNE/JNZ", desc: "Jump if not equal / not zero" },
                    { instr: "CMP a, b", desc: "Compare two values (sets flags)" },
                    { instr: "TEST a, b", desc: "Bitwise AND for flag setting" },
                  ].map((item) => (
                    <ListItem key={item.instr} sx={{ py: 0.5, px: 0 }}>
                      <ListItemText 
                        primary={<code style={{ color: "#8b5cf6", fontWeight: 600 }}>{item.instr}</code>}
                        secondary={item.desc}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#f97316", mb: 2 }}>
                  Stack & Functions
                </Typography>
                <List dense>
                  {[
                    { instr: "PUSH src", desc: "Push value onto stack (decrements RSP)" },
                    { instr: "POP dest", desc: "Pop value from stack (increments RSP)" },
                    { instr: "CALL address", desc: "Push return address and jump to function" },
                    { instr: "RET", desc: "Pop return address and jump back" },
                    { instr: "LEAVE", desc: "Restore stack frame (MOV RSP, RBP; POP RBP)" },
                  ].map((item) => (
                    <ListItem key={item.instr} sx={{ py: 0.5, px: 0 }}>
                      <ListItemText 
                        primary={<code style={{ color: "#f97316", fontWeight: 600 }}>{item.instr}</code>}
                        secondary={item.desc}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Divider sx={{ my: 4 }} />

          <Typography variant="h5" sx={{ fontWeight: 700, mb: 3, color: "#dc2626" }}>
            Why Assembly Matters for Security
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.1rem" }}>
            As a security professional, you might wonder why you need to learn something so low-level when there are 
            plenty of high-level tools available. The answer is that <strong>many security tasks require understanding 
            assembly</strong>. Here are the key areas where assembly knowledge is essential:
          </Typography>

          <Grid container spacing={3} sx={{ mb: 4 }}>
            {[
              {
                title: "Reverse Engineering",
                desc: "When you analyze compiled software (binaries), you're looking at disassembled code—assembly. Whether you're analyzing malware, understanding proprietary protocols, or finding vulnerabilities in closed-source software, you need to read and understand assembly.",
                icon: <BuildIcon sx={{ fontSize: 28 }} />,
                color: "#3b82f6",
              },
              {
                title: "Exploit Development",
                desc: "Writing exploits often requires crafting shellcode (small assembly programs), understanding how buffer overflows corrupt the stack, and knowing how to redirect program execution. This is impossible without assembly knowledge.",
                icon: <SecurityIcon sx={{ fontSize: 28 }} />,
                color: "#ef4444",
              },
              {
                title: "Malware Analysis",
                desc: "Malware authors often use assembly-level tricks to evade detection, implement anti-debugging techniques, and perform low-level system manipulation. Analyzing malware means reading a lot of assembly code.",
                icon: <CodeIcon sx={{ fontSize: 28 }} />,
                color: "#8b5cf6",
              },
              {
                title: "Debugging & Crash Analysis",
                desc: "When software crashes, the information you get (crash dumps, stack traces) is at the assembly level. Understanding registers, the stack, and instruction flow helps you diagnose complex bugs.",
                icon: <TerminalIcon sx={{ fontSize: 28 }} />,
                color: "#22c55e",
              },
            ].map((item) => (
              <Grid item xs={12} md={6} key={item.title}>
                <Paper
                  sx={{
                    p: 3,
                    height: "100%",
                    borderRadius: 3,
                    bgcolor: alpha(item.color, 0.03),
                    border: `1px solid ${alpha(item.color, 0.15)}`,
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                    <Box sx={{ color: item.color }}>{item.icon}</Box>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: item.color }}>
                      {item.title}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.8 }}>
                    {item.desc}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Getting Started</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Don't be intimidated by assembly! While it has a steep learning curve, the fundamental concepts are 
              straightforward once you understand them. Start by learning the basic instructions (MOV, ADD, SUB, JMP, 
              CALL, RET), understand how the stack works, and practice reading disassembled code in tools like Ghidra, 
              IDA Pro, or even just <code>objdump</code>. The modules below will guide you through each concept step by step.
            </Typography>
          </Alert>
        </Paper>

        {/* ==================== DETAILED COURSE MODULES ==================== */}
        <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
          <SchoolIcon sx={{ color: "#f97316" }} />
          Course Modules
        </Typography>

        {/* MODULE 1: CPU Architecture Fundamentals */}
        <Paper
          id="module-1"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#3b82f6", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 1" sx={{ bgcolor: alpha("#3b82f6", 0.15), color: "#3b82f6", fontWeight: 700 }} />
            <Typography variant="h5" sx={{ fontWeight: 800 }}>
              CPU Architecture Fundamentals
            </Typography>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Before you can write or understand assembly language, you need a solid grasp of how the <strong>Central Processing Unit 
            (CPU)</strong> works. The CPU is the "brain" of the computer—it's the chip responsible for executing all the instructions 
            that make software run. Modern CPUs are incredibly complex, containing billions of transistors, but the fundamental 
            concepts have remained consistent since the earliest processors.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            At the heart of CPU operation is the <strong>fetch-decode-execute cycle</strong> (also called the instruction cycle). 
            This is the fundamental process by which a CPU processes each instruction:
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6", mb: 2 }}>
                  The Fetch-Decode-Execute Cycle
                </Typography>
                <List dense>
                  {[
                    { step: "1. Fetch", desc: "The CPU reads the next instruction from memory using the address in the Program Counter (PC/RIP). The instruction is loaded into the Instruction Register." },
                    { step: "2. Decode", desc: "The Control Unit decodes the instruction to determine what operation to perform, which registers or memory locations are involved, and what addressing mode is used." },
                    { step: "3. Execute", desc: "The CPU performs the operation—this might involve the ALU for arithmetic, accessing memory, or updating registers." },
                    { step: "4. Writeback", desc: "Results are written to the destination (register or memory). The PC is updated to point to the next instruction, and the cycle repeats." },
                  ].map((item) => (
                    <ListItem key={item.step} sx={{ py: 1, px: 0, alignItems: "flex-start" }}>
                      <ListItemIcon sx={{ minWidth: 32, mt: 0.5 }}>
                        <CheckCircleIcon sx={{ color: "#3b82f6", fontSize: 18 }} />
                      </ListItemIcon>
                      <ListItemText 
                        primary={<Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.step}</Typography>}
                        secondary={item.desc}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 2 }}>
                  Key CPU Components
                </Typography>
                <List dense>
                  {[
                    { comp: "ALU (Arithmetic Logic Unit)", desc: "Performs all arithmetic (add, subtract, multiply) and logical (AND, OR, XOR) operations." },
                    { comp: "Control Unit", desc: "Decodes instructions and generates control signals to coordinate CPU operations." },
                    { comp: "Registers", desc: "Small, fast storage locations for data being actively processed." },
                    { comp: "Cache", desc: "Fast memory layers (L1, L2, L3) between CPU and RAM to reduce latency." },
                    { comp: "Bus Interface", desc: "Connects CPU to memory and peripherals via address, data, and control buses." },
                  ].map((item) => (
                    <ListItem key={item.comp} sx={{ py: 1, px: 0, alignItems: "flex-start" }}>
                      <ListItemIcon sx={{ minWidth: 32, mt: 0.5 }}>
                        <MemoryIcon sx={{ color: "#8b5cf6", fontSize: 18 }} />
                      </ListItemIcon>
                      <ListItemText 
                        primary={<Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{item.comp}</Typography>}
                        secondary={item.desc}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Modern CPUs incorporate several performance optimizations that make them incredibly fast. <strong>Pipelining</strong> allows 
            multiple instructions to be in different stages of the fetch-decode-execute cycle simultaneously—while one instruction is 
            executing, the next is being decoded, and the one after that is being fetched. <strong>Superscalar execution</strong> allows 
            multiple instructions to execute in parallel using multiple execution units. <strong>Branch prediction</strong> attempts to 
            guess which way conditional jumps will go, speculatively executing instructions along the predicted path.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Clock speed</strong> (measured in GHz) indicates how many cycles the CPU performs per second. A 4 GHz CPU performs 
            4 billion cycles per second. However, not all instructions complete in a single cycle—complex instructions may take multiple 
            cycles, and memory access can cause the CPU to wait (stall) for data. This is why raw clock speed isn't the only measure of 
            CPU performance.
          </Typography>

          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Security Implications</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Understanding CPU architecture is crucial for security research. Famous vulnerabilities like <strong>Spectre</strong> and 
              <strong> Meltdown</strong> exploit speculative execution to leak sensitive data. Side-channel attacks exploit cache timing 
              differences to extract cryptographic keys. As a security professional, understanding these low-level details helps you 
              comprehend how such attacks work and how to defend against them.
            </Typography>
          </Alert>
        </Paper>

        {/* MODULE 2: x86-64 Register Deep Dive */}
        <Paper
          id="module-2"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#22c55e", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 2" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 700 }} />
            <Typography variant="h5" sx={{ fontWeight: 800 }}>
              x86-64 Register Deep Dive
            </Typography>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Registers are the fastest storage available to the CPU—accessing a register is nearly instantaneous compared to memory access 
            which can take hundreds of clock cycles. The x86-64 architecture provides <strong>16 general-purpose registers</strong> (GPRs), 
            each 64 bits wide, plus several special-purpose registers. Understanding registers is fundamental to reading and writing 
            assembly code.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            General-Purpose Registers
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            The 16 GPRs in x86-64 are: <strong>RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8-R15</strong>. The first eight (RAX-RSP) are 
            extensions of the original 16-bit registers from the 8086 processor, while R8-R15 were added with the x86-64 extension. Each 
            64-bit register can be accessed in smaller portions:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, mb: 2, color: "#22c55e", fontFamily: "monospace" }}>
              Register Naming Convention (using RAX as example):
            </Typography>
            <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", sm: "repeat(2, 1fr)", md: "repeat(4, 1fr)" }, gap: 2 }}>
              {[
                { name: "RAX", bits: "64 bits", desc: "Full 64-bit register" },
                { name: "EAX", bits: "32 bits", desc: "Lower 32 bits of RAX" },
                { name: "AX", bits: "16 bits", desc: "Lower 16 bits of RAX" },
                { name: "AL / AH", bits: "8 bits each", desc: "Lower / Upper 8 bits of AX" },
              ].map((reg) => (
                <Paper key={reg.name} sx={{ p: 2, bgcolor: alpha("#22c55e", 0.05), borderRadius: 2 }}>
                  <Typography variant="h6" sx={{ fontWeight: 800, fontFamily: "monospace", color: "#22c55e" }}>{reg.name}</Typography>
                  <Typography variant="caption" color="text.secondary" display="block">{reg.bits}</Typography>
                  <Typography variant="body2" sx={{ mt: 1 }}>{reg.desc}</Typography>
                </Paper>
              ))}
            </Box>
          </Paper>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6", mb: 2 }}>
                  Traditional Register Roles
                </Typography>
                <List dense>
                  {[
                    { reg: "RAX", role: "Accumulator - arithmetic results, function return values, syscall numbers" },
                    { reg: "RBX", role: "Base register - general purpose, callee-saved, historically for base addressing" },
                    { reg: "RCX", role: "Counter - loop iterations (LOOP, REP), shift counts, 4th arg (Windows)" },
                    { reg: "RDX", role: "Data - I/O operations, high bits of multiply/divide, 3rd argument" },
                    { reg: "RSI", role: "Source Index - string source, 2nd argument (System V ABI)" },
                    { reg: "RDI", role: "Destination Index - string destination, 1st argument (System V ABI)" },
                  ].map((item) => (
                    <ListItem key={item.reg} sx={{ py: 0.5, px: 0 }}>
                      <ListItemText 
                        primary={<Chip label={item.reg} size="small" sx={{ bgcolor: alpha("#3b82f6", 0.15), color: "#3b82f6", fontWeight: 700, fontFamily: "monospace" }} />}
                        secondary={<Typography variant="body2" sx={{ mt: 0.5 }}>{item.role}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#f97316", mb: 2 }}>
                  Stack & Pointer Registers
                </Typography>
                <List dense>
                  {[
                    { reg: "RSP", role: "Stack Pointer - ALWAYS points to current top of stack. Modified by PUSH/POP/CALL/RET." },
                    { reg: "RBP", role: "Base Pointer - typically points to base of current stack frame for stable local variable access." },
                    { reg: "RIP", role: "Instruction Pointer - address of next instruction. Cannot be directly modified except by jumps/calls." },
                    { reg: "R8-R15", role: "Additional GPRs added in x86-64. R8-R9 used for 5th-6th args (System V). All general purpose." },
                  ].map((item) => (
                    <ListItem key={item.reg} sx={{ py: 0.5, px: 0 }}>
                      <ListItemText 
                        primary={<Chip label={item.reg} size="small" sx={{ bgcolor: alpha("#f97316", 0.15), color: "#f97316", fontWeight: 700, fontFamily: "monospace" }} />}
                        secondary={<Typography variant="body2" sx={{ mt: 0.5 }}>{item.role}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            The FLAGS Register (RFLAGS)
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            The FLAGS register is a special register containing single-bit flags that indicate the results of arithmetic and logical 
            operations. These flags are crucial for conditional branching—after a CMP or TEST instruction sets the flags, conditional 
            jumps check these flags to decide whether to branch. The most important flags are:
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { flag: "ZF", name: "Zero Flag", desc: "Set if result is zero. CMP A, B sets ZF=1 if A equals B.", color: "#3b82f6" },
              { flag: "SF", name: "Sign Flag", desc: "Set to MSB of result. Indicates negative result in signed arithmetic.", color: "#22c55e" },
              { flag: "CF", name: "Carry Flag", desc: "Set on unsigned overflow/underflow. Used for multi-precision arithmetic.", color: "#f97316" },
              { flag: "OF", name: "Overflow Flag", desc: "Set on signed overflow. Result too large/small for destination.", color: "#8b5cf6" },
              { flag: "PF", name: "Parity Flag", desc: "Set if low byte has even number of 1 bits. Legacy, rarely used.", color: "#6b7280" },
              { flag: "AF", name: "Auxiliary Flag", desc: "BCD arithmetic carry from bit 3 to 4. Legacy, rarely used.", color: "#6b7280" },
            ].map((f) => (
              <Grid item xs={6} sm={4} key={f.flag}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(f.color, 0.05), border: `1px solid ${alpha(f.color, 0.15)}`, height: "100%" }}>
                  <Chip label={f.flag} size="small" sx={{ bgcolor: alpha(f.color, 0.15), color: f.color, fontWeight: 700, fontFamily: "monospace", mb: 1 }} />
                  <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{f.name}</Typography>
                  <Typography variant="caption" color="text.secondary">{f.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Key Insight</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              When reading disassembly, pay close attention to which flags each instruction modifies. Instructions like <code>MOV</code> and 
              <code> LEA</code> don't modify flags, while <code>ADD</code>, <code>SUB</code>, and <code>CMP</code> do. The <code>TEST</code> 
              instruction performs AND and sets flags without storing the result—it's commonly used to check if a register is zero 
              (<code>TEST RAX, RAX</code>) before a conditional jump.
            </Typography>
          </Alert>
        </Paper>

        {/* MODULE 3: Memory Addressing Modes */}
        <Paper
          id="module-3"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 3" sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 700 }} />
            <Typography variant="h5" sx={{ fontWeight: 800 }}>
              Memory Addressing Modes
            </Typography>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            One of the most powerful features of x86 assembly is its flexible <strong>memory addressing modes</strong>. These determine 
            how the CPU calculates the memory address for an instruction. Understanding addressing modes is essential for reading 
            disassembly—they're used constantly for array access, structure field access, stack variables, and pointer dereferencing.
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            The general formula for x86-64 memory addressing is: <strong>[base + index × scale + displacement]</strong>, where:
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
            <Grid container spacing={2}>
              {[
                { part: "Base", desc: "Any general-purpose register (RAX, RBX, etc.). Holds a base address.", example: "[RBX]" },
                { part: "Index", desc: "Any GPR except RSP. Used for array indexing.", example: "[RBX + RCX]" },
                { part: "Scale", desc: "Multiplier for index: 1, 2, 4, or 8. Matches common data type sizes.", example: "[RBX + RCX*4]" },
                { part: "Displacement", desc: "A constant offset (8-bit or 32-bit signed value).", example: "[RBX + 16]" },
              ].map((item) => (
                <Grid item xs={12} sm={6} md={3} key={item.part}>
                  <Box>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6" }}>{item.part}</Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.desc}</Typography>
                    <Chip label={item.example} size="small" sx={{ fontFamily: "monospace", bgcolor: alpha("#8b5cf6", 0.1) }} />
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Common Addressing Mode Examples
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { 
                mode: "Immediate", 
                syntax: "MOV RAX, 42", 
                desc: "Value is embedded in instruction. No memory access.",
                use: "Loading constants into registers",
                color: "#3b82f6"
              },
              { 
                mode: "Register Direct", 
                syntax: "MOV RAX, RBX", 
                desc: "Copies value from one register to another.",
                use: "Moving data between registers",
                color: "#22c55e"
              },
              { 
                mode: "Register Indirect", 
                syntax: "MOV RAX, [RBX]", 
                desc: "RBX holds address, load value from that address.",
                use: "Pointer dereferencing",
                color: "#f97316"
              },
              { 
                mode: "Base + Displacement", 
                syntax: "MOV RAX, [RBP-8]", 
                desc: "Address = RBP - 8. Common for stack variables.",
                use: "Local variable access",
                color: "#8b5cf6"
              },
              { 
                mode: "Base + Index", 
                syntax: "MOV RAX, [RBX+RCX]", 
                desc: "Address = RBX + RCX. Two registers combined.",
                use: "Flexible pointer math",
                color: "#ec4899"
              },
              { 
                mode: "Scaled Index", 
                syntax: "MOV RAX, [RBX+RCX*8]", 
                desc: "Address = RBX + (RCX × 8). Index multiplied.",
                use: "Array of 8-byte elements (QWORD array)",
                color: "#14b8a6"
              },
              { 
                mode: "Full SIB", 
                syntax: "MOV RAX, [RBX+RCX*4+16]", 
                desc: "All components: base + scaled index + offset.",
                use: "Array inside structure at offset",
                color: "#a855f7"
              },
              { 
                mode: "RIP-Relative", 
                syntax: "MOV RAX, [RIP+offset]", 
                desc: "Address relative to instruction pointer.",
                use: "Global variables in PIC/PIE code",
                color: "#ef4444"
              },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.mode}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha(item.color, 0.03), border: `1px solid ${alpha(item.color, 0.15)}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color, mb: 1 }}>{item.mode}</Typography>
                  <Chip 
                    label={item.syntax} 
                    size="small" 
                    sx={{ fontFamily: "monospace", bgcolor: alpha(item.color, 0.1), color: item.color, fontWeight: 600, mb: 1.5 }} 
                  />
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>{item.desc}</Typography>
                  <Typography variant="caption" sx={{ color: item.color, fontWeight: 600 }}>
                    Use: {item.use}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            The LEA Instruction
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            <code style={{ background: alpha("#f97316", 0.1), padding: "2px 8px", borderRadius: 4, fontWeight: 600 }}>LEA</code> (Load 
            Effective Address) is a powerful instruction that computes an address using the full addressing mode capabilities but stores 
            the <em>address itself</em> rather than the value at that address. This makes it incredibly useful for:
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#f97316", 0.05) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>Address Calculation</Typography>
                <code style={{ fontSize: "0.85rem" }}>LEA RAX, [RBX+16]</code>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Computes RBX+16 and stores in RAX. Like pointer arithmetic.
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#f97316", 0.05) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>Fast Arithmetic</Typography>
                <code style={{ fontSize: "0.85rem" }}>LEA RAX, [RBX+RBX*2]</code>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Computes RBX × 3 in one instruction without modifying flags!
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha("#f97316", 0.05) }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#f97316", mb: 1 }}>Three-Operand Add</Typography>
                <code style={{ fontSize: "0.85rem" }}>LEA RAX, [RBX+RCX+4]</code>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Adds three values into a different destination register.
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Size Specifiers
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            When the assembler can't infer the operand size from context, you must specify it using a <strong>size directive</strong>:
          </Typography>

          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1.5, mb: 4 }}>
            {[
              { dir: "BYTE PTR", size: "1 byte (8 bits)", color: "#3b82f6" },
              { dir: "WORD PTR", size: "2 bytes (16 bits)", color: "#22c55e" },
              { dir: "DWORD PTR", size: "4 bytes (32 bits)", color: "#f97316" },
              { dir: "QWORD PTR", size: "8 bytes (64 bits)", color: "#8b5cf6" },
              { dir: "XMMWORD PTR", size: "16 bytes (128 bits)", color: "#ec4899" },
              { dir: "YMMWORD PTR", size: "32 bytes (256 bits)", color: "#14b8a6" },
            ].map((item) => (
              <Chip 
                key={item.dir}
                label={`${item.dir} = ${item.size}`} 
                sx={{ bgcolor: alpha(item.color, 0.1), color: item.color, fontWeight: 600, fontFamily: "monospace" }} 
              />
            ))}
          </Box>

          <Alert severity="warning" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Common Pitfall</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Be careful with 32-bit register writes in x86-64: writing to a 32-bit register (like EAX) automatically <strong>zero-extends 
              to 64 bits</strong>, clearing the upper 32 bits of RAX. Writing to 8-bit or 16-bit registers (AL, AX) does NOT zero-extend—the 
              upper bits are preserved. This is a common source of bugs when porting 32-bit code to 64-bit.
            </Typography>
          </Alert>
        </Paper>

        {/* MODULE 4: Data Movement Instructions */}
        <Paper
          id="module-4"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#f97316", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 4" sx={{ bgcolor: alpha("#f97316", 0.15), color: "#f97316", fontWeight: 700 }} />
            <Typography variant="h5" sx={{ fontWeight: 800 }}>
              Data Movement Instructions
            </Typography>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Data movement is the most fundamental category of assembly instructions—you'll see these instructions more than any other 
            in real disassembly. At its core, programming is about moving data: from memory to registers, between registers, from 
            registers back to memory. Mastering data movement instructions is essential for understanding any assembly code.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            The MOV Instruction Family
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            <code style={{ background: alpha("#f97316", 0.1), padding: "2px 8px", borderRadius: 4, fontWeight: 600 }}>MOV</code> is 
            the workhorse of assembly language. It copies data from a source operand to a destination operand. Despite its name, 
            MOV doesn't actually "move" data—it <strong>copies</strong> it, leaving the source unchanged.
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { syntax: "MOV RAX, RBX", desc: "Register to register: Copy RBX value into RAX", note: "Both must be same size", color: "#3b82f6" },
              { syntax: "MOV RAX, [RBX]", desc: "Memory to register: Load value from address in RBX into RAX", note: "Dereferences RBX as pointer", color: "#22c55e" },
              { syntax: "MOV [RAX], RBX", desc: "Register to memory: Store RBX value at address in RAX", note: "Writes to memory location", color: "#8b5cf6" },
              { syntax: "MOV RAX, 0x1234", desc: "Immediate to register: Load constant value into RAX", note: "Immediate = constant in instruction", color: "#f97316" },
              { syntax: "MOV QWORD PTR [RAX], 0", desc: "Immediate to memory: Store zero at address in RAX", note: "Size specifier required", color: "#ec4899" },
              { syntax: "MOV RAX, [RBP-8]", desc: "Stack variable access: Load local variable into RAX", note: "Common pattern for locals", color: "#14b8a6" },
            ].map((item) => (
              <Grid item xs={12} sm={6} key={item.syntax}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha(item.color, 0.03), border: `1px solid ${alpha(item.color, 0.15)}` }}>
                  <Chip label={item.syntax} size="small" sx={{ fontFamily: "monospace", bgcolor: alpha(item.color, 0.15), color: item.color, fontWeight: 700, mb: 1.5 }} />
                  <Typography variant="body2" sx={{ fontWeight: 600, mb: 0.5 }}>{item.desc}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.note}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="warning" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>MOV Restrictions</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              You <strong>cannot</strong> MOV directly from memory to memory! Both operands can't be memory addresses. To copy 
              memory-to-memory, you must use a register as intermediate: <code>MOV RAX, [src]; MOV [dst], RAX</code>. Also, 
              immediate values cannot be 64-bit when the destination is memory—use a register first.
            </Typography>
          </Alert>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Extended MOV Instructions
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>
                  MOVZX - Zero Extension
                </Typography>
                <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8 }}>
                  Copies a smaller value to a larger register, filling upper bits with zeros. Used for <strong>unsigned</strong> values.
                </Typography>
                <List dense>
                  {[
                    { ex: "MOVZX EAX, BL", desc: "8-bit BL → 32-bit EAX (upper 24 bits = 0)" },
                    { ex: "MOVZX RAX, WORD PTR [RBX]", desc: "16-bit memory → 64-bit RAX" },
                    { ex: "MOVZX ECX, AL", desc: "Common for char → int conversion" },
                  ].map((item) => (
                    <ListItem key={item.ex} sx={{ py: 0.5, px: 0 }}>
                      <ListItemText
                        primary={<code style={{ color: "#22c55e", fontSize: "0.85rem" }}>{item.ex}</code>}
                        secondary={item.desc}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 2 }}>
                  MOVSX - Sign Extension
                </Typography>
                <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8 }}>
                  Copies a smaller value to a larger register, extending the sign bit. Used for <strong>signed</strong> values.
                </Typography>
                <List dense>
                  {[
                    { ex: "MOVSX EAX, BL", desc: "If BL=0xFF (-1), EAX=0xFFFFFFFF" },
                    { ex: "MOVSXD RAX, EAX", desc: "32-bit signed → 64-bit (special form)" },
                    { ex: "MOVSX RCX, BYTE PTR [RDI]", desc: "Signed byte from memory to 64-bit" },
                  ].map((item) => (
                    <ListItem key={item.ex} sx={{ py: 0.5, px: 0 }}>
                      <ListItemText
                        primary={<code style={{ color: "#8b5cf6", fontSize: "0.85rem" }}>{item.ex}</code>}
                        secondary={item.desc}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            Other Essential Data Movement
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { instr: "XCHG", syntax: "XCHG RAX, RBX", desc: "Exchange: Atomically swap two values. No temp register needed. Implicit LOCK prefix when memory involved.", color: "#3b82f6" },
              { instr: "LEA", syntax: "LEA RAX, [RBX+RCX*4]", desc: "Load Effective Address: Compute address without memory access. Great for pointer math and fast multiplication.", color: "#22c55e" },
              { instr: "PUSH", syntax: "PUSH RAX", desc: "Push onto stack: RSP -= 8, then store RAX at [RSP]. Grows stack downward.", color: "#f97316" },
              { instr: "POP", syntax: "POP RBX", desc: "Pop from stack: Load [RSP] into RBX, then RSP += 8. Shrinks stack upward.", color: "#8b5cf6" },
              { instr: "CMOV", syntax: "CMOVZ RAX, RBX", desc: "Conditional move: Only moves if condition (Zero flag) is true. Avoids branch misprediction.", color: "#ec4899" },
              { instr: "BSWAP", syntax: "BSWAP EAX", desc: "Byte swap: Reverses byte order. Converts between big-endian and little-endian.", color: "#14b8a6" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.instr}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha(item.color, 0.03), border: `1px solid ${alpha(item.color, 0.15)}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color }}>{item.instr}</Typography>
                  <Chip label={item.syntax} size="small" sx={{ fontFamily: "monospace", fontSize: "0.75rem", bgcolor: alpha(item.color, 0.1), my: 1 }} />
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Recognizing Patterns</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              In disassembly, <code>XOR EAX, EAX</code> is a common idiom to zero a register (shorter encoding than MOV). 
              <code> LEA RAX, [RAX+RAX]</code> doubles RAX without using MUL. When you see <code>MOV RDI, RSI; REP MOVSB</code>, 
              that's a string copy operation (like memcpy). Learning these patterns helps you read assembly faster.
            </Typography>
          </Alert>
        </Paper>

        {/* MODULE 5: Arithmetic & Logic Operations */}
        <Paper
          id="module-5"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#ec4899", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 5" sx={{ bgcolor: alpha("#ec4899", 0.15), color: "#ec4899", fontWeight: 700 }} />
            <Typography variant="h5" sx={{ fontWeight: 800 }}>
              Arithmetic & Logic Operations
            </Typography>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            The ALU (Arithmetic Logic Unit) is the computational heart of the CPU. Arithmetic and logical instructions perform 
            calculations on data—everything from simple addition to complex bit manipulation. These instructions also set the 
            <strong> FLAGS register</strong>, which is crucial for conditional branching.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            Basic Arithmetic
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6", mb: 2 }}>
                  Addition & Subtraction
                </Typography>
                <List dense>
                  {[
                    { instr: "ADD RAX, RBX", desc: "RAX = RAX + RBX. Sets CF on unsigned overflow, OF on signed overflow." },
                    { instr: "SUB RAX, 10", desc: "RAX = RAX - 10. Sets flags as if doing RAX + (-10)." },
                    { instr: "ADC RAX, RBX", desc: "Add with carry: RAX = RAX + RBX + CF. For multi-precision math." },
                    { instr: "SBB RAX, RBX", desc: "Subtract with borrow: RAX = RAX - RBX - CF." },
                    { instr: "INC RAX", desc: "Increment: RAX = RAX + 1. Doesn't affect CF (legacy reason)." },
                    { instr: "DEC RAX", desc: "Decrement: RAX = RAX - 1. Also doesn't affect CF." },
                    { instr: "NEG RAX", desc: "Two's complement negation: RAX = 0 - RAX." },
                  ].map((item) => (
                    <ListItem key={item.instr} sx={{ py: 0.5, px: 0 }}>
                      <ListItemText
                        primary={<code style={{ color: "#3b82f6", fontWeight: 600, fontSize: "0.9rem" }}>{item.instr}</code>}
                        secondary={item.desc}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>
                  Multiplication & Division
                </Typography>
                <List dense>
                  {[
                    { instr: "MUL RBX", desc: "Unsigned: RDX:RAX = RAX × RBX. 128-bit result split across two registers." },
                    { instr: "IMUL RBX", desc: "Signed multiply: RDX:RAX = RAX × RBX (signed interpretation)." },
                    { instr: "IMUL RAX, RBX", desc: "Two-operand form: RAX = RAX × RBX (truncated to 64 bits)." },
                    { instr: "IMUL RAX, RBX, 10", desc: "Three-operand: RAX = RBX × 10. Very convenient!" },
                    { instr: "DIV RBX", desc: "Unsigned: RAX = RDX:RAX ÷ RBX, RDX = remainder." },
                    { instr: "IDIV RBX", desc: "Signed division. Requires sign-extending RAX into RDX first (CQO)." },
                    { instr: "CQO", desc: "Sign-extend RAX into RDX:RAX. Required before IDIV." },
                  ].map((item) => (
                    <ListItem key={item.instr} sx={{ py: 0.5, px: 0 }}>
                      <ListItemText
                        primary={<code style={{ color: "#22c55e", fontWeight: 600, fontSize: "0.9rem" }}>{item.instr}</code>}
                        secondary={item.desc}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Alert severity="error" sx={{ mb: 4, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Division Exceptions</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Division by zero causes a <strong>#DE (Divide Error) exception</strong>—your program will crash! Also, if the 
              quotient doesn't fit in RAX (dividend too large relative to divisor), you get the same exception. Always validate 
              the divisor before DIV/IDIV instructions. For IDIV, always use CQO/CDQ first to sign-extend the dividend.
            </Typography>
          </Alert>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Bitwise Logical Operations
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Bitwise operations work on individual bits and are essential for flag manipulation, masking, encryption, and 
            low-level data processing. They operate bit-by-bit across the entire operand.
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { op: "AND", truth: "1 AND 1 = 1, else 0", use: "Clearing bits (masking)", example: "AND RAX, 0xFF → Keep only low byte", color: "#3b82f6" },
              { op: "OR", truth: "0 OR 0 = 0, else 1", use: "Setting bits", example: "OR RAX, 0x01 → Set lowest bit", color: "#22c55e" },
              { op: "XOR", truth: "Same = 0, Different = 1", use: "Toggling bits, encryption", example: "XOR RAX, RAX → Zero register", color: "#f97316" },
              { op: "NOT", truth: "Flips all bits", use: "Bitwise complement", example: "NOT RAX → One's complement", color: "#8b5cf6" },
              { op: "TEST", truth: "AND without storing", use: "Check bits without modifying", example: "TEST RAX, RAX → Check if zero", color: "#ec4899" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.op}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha(item.color, 0.03), border: `1px solid ${alpha(item.color, 0.15)}` }}>
                  <Typography variant="h6" sx={{ fontWeight: 800, color: item.color }}>{item.op}</Typography>
                  <Typography variant="caption" display="block" sx={{ fontFamily: "monospace", mb: 1 }}>{item.truth}</Typography>
                  <Typography variant="body2" sx={{ fontWeight: 600, mb: 0.5 }}>{item.use}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.example}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
            Shift & Rotate Instructions
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#14b8a6", 0.05), border: `1px solid ${alpha("#14b8a6", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#14b8a6", mb: 2 }}>Shift Operations</Typography>
                <List dense>
                  {[
                    { instr: "SHL RAX, 3", desc: "Shift left: RAX = RAX × 8. Fills with zeros on right." },
                    { instr: "SHR RAX, 2", desc: "Shift right (logical): RAX = RAX ÷ 4. Fills with zeros on left. Unsigned." },
                    { instr: "SAR RAX, 1", desc: "Shift right (arithmetic): Preserves sign bit. For signed division by 2." },
                    { instr: "SHLD RAX, RBX, 8", desc: "Double-precision shift left: Shift RAX left, fill from RBX." },
                  ].map((item) => (
                    <ListItem key={item.instr} sx={{ py: 0.5, px: 0 }}>
                      <ListItemText
                        primary={<code style={{ color: "#14b8a6", fontWeight: 600 }}>{item.instr}</code>}
                        secondary={item.desc}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#a855f7", 0.05), border: `1px solid ${alpha("#a855f7", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#a855f7", mb: 2 }}>Rotate Operations</Typography>
                <List dense>
                  {[
                    { instr: "ROL RAX, 4", desc: "Rotate left: Bits that fall off left wrap to right. No data loss." },
                    { instr: "ROR RAX, 8", desc: "Rotate right: Bits wrap from right to left." },
                    { instr: "RCL RAX, 1", desc: "Rotate through carry: CF becomes part of the rotation." },
                    { instr: "RCR RAX, 1", desc: "Rotate right through carry: 65-bit rotation including CF." },
                  ].map((item) => (
                    <ListItem key={item.instr} sx={{ py: 0.5, px: 0 }}>
                      <ListItemText
                        primary={<code style={{ color: "#a855f7", fontWeight: 600 }}>{item.instr}</code>}
                        secondary={item.desc}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Optimization Tricks</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Compilers use shifts instead of multiply/divide for powers of 2: <code>SHL RAX, 2</code> = RAX × 4. 
              <code> LEA RAX, [RAX+RAX*4]</code> = RAX × 5. XOR is used for fast zeroing and in XOR-swap algorithms. 
              Recognizing these patterns helps you understand optimized code in disassembly.
            </Typography>
          </Alert>
        </Paper>

        {/* MODULE 6: Control Flow & Branching */}
        <Paper
          id="module-6"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#14b8a6", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 6" sx={{ bgcolor: alpha("#14b8a6", 0.15), color: "#14b8a6", fontWeight: 700 }} />
            <Typography variant="h5" sx={{ fontWeight: 800 }}>
              Control Flow & Branching
            </Typography>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Control flow instructions determine the order in which instructions execute. Without them, programs would just 
            run linearly from start to end. <strong>Jumps</strong> (branches) allow conditionals, loops, and function calls—the 
            building blocks of all program logic. Understanding control flow is critical for following program logic in disassembly.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
            Comparison Instructions
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Before a conditional jump, you need to set the FLAGS. The two main instructions for this are <strong>CMP</strong> and 
            <strong> TEST</strong>:
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6", mb: 2 }}>CMP - Compare</Typography>
                <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8 }}>
                  <code>CMP A, B</code> computes A - B and sets flags, but <strong>discards the result</strong>. The operands 
                  remain unchanged.
                </Typography>
                <List dense>
                  {[
                    { ex: "CMP RAX, 10", flag: "ZF=1 if RAX equals 10" },
                    { ex: "CMP RAX, RBX", flag: "SF=1 if RAX < RBX (signed)" },
                    { ex: "After CMP:", flag: "Use Jcc to branch based on flags" },
                  ].map((item) => (
                    <ListItem key={item.ex} sx={{ py: 0.5, px: 0 }}>
                      <ListItemText
                        primary={<code style={{ color: "#3b82f6" }}>{item.ex}</code>}
                        secondary={item.flag}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>TEST - Bit Test</Typography>
                <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.8 }}>
                  <code>TEST A, B</code> computes A AND B and sets flags, but <strong>discards the result</strong>. Great for 
                  checking specific bits.
                </Typography>
                <List dense>
                  {[
                    { ex: "TEST RAX, RAX", flag: "ZF=1 if RAX is zero" },
                    { ex: "TEST RAX, 1", flag: "ZF=0 if RAX is odd" },
                    { ex: "TEST AL, 0x80", flag: "SF=1 if high bit of AL set" },
                  ].map((item) => (
                    <ListItem key={item.ex} sx={{ py: 0.5, px: 0 }}>
                      <ListItemText
                        primary={<code style={{ color: "#22c55e" }}>{item.ex}</code>}
                        secondary={item.flag}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            Conditional Jumps (Jcc)
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Conditional jumps check FLAGS and jump only if the condition is met. There are many variants for different 
            comparisons. It's important to use the right one for <strong>signed vs unsigned</strong> comparisons!
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 2 }}>Equality & Zero</Typography>
                <List dense>
                  {[
                    { jmp: "JE / JZ", cond: "Jump if Equal / Zero", flag: "ZF = 1" },
                    { jmp: "JNE / JNZ", cond: "Jump if Not Equal / Not Zero", flag: "ZF = 0" },
                  ].map((item) => (
                    <ListItem key={item.jmp} sx={{ py: 1, px: 0 }}>
                      <ListItemText
                        primary={<Chip label={item.jmp} size="small" sx={{ bgcolor: alpha("#3b82f6", 0.15), color: "#3b82f6", fontWeight: 700, fontFamily: "monospace" }} />}
                        secondary={<><Typography variant="caption" display="block">{item.cond}</Typography><Typography variant="caption" color="text.secondary">({item.flag})</Typography></>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>Unsigned Comparison</Typography>
                <List dense>
                  {[
                    { jmp: "JA / JNBE", cond: "Jump if Above", flag: "CF=0 AND ZF=0" },
                    { jmp: "JAE / JNB / JNC", cond: "Jump if Above or Equal", flag: "CF = 0" },
                    { jmp: "JB / JNAE / JC", cond: "Jump if Below (Carry)", flag: "CF = 1" },
                    { jmp: "JBE / JNA", cond: "Jump if Below or Equal", flag: "CF=1 OR ZF=1" },
                  ].map((item) => (
                    <ListItem key={item.jmp} sx={{ py: 0.5, px: 0 }}>
                      <ListItemText
                        primary={<Chip label={item.jmp} size="small" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 600, fontFamily: "monospace", fontSize: "0.7rem" }} />}
                        secondary={<><Typography variant="caption" display="block">{item.cond}</Typography><Typography variant="caption" color="text.secondary">({item.flag})</Typography></>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 2 }}>Signed Comparison</Typography>
                <List dense>
                  {[
                    { jmp: "JG / JNLE", cond: "Jump if Greater", flag: "ZF=0 AND SF=OF" },
                    { jmp: "JGE / JNL", cond: "Jump if Greater or Equal", flag: "SF = OF" },
                    { jmp: "JL / JNGE", cond: "Jump if Less", flag: "SF ≠ OF" },
                    { jmp: "JLE / JNG", cond: "Jump if Less or Equal", flag: "ZF=1 OR SF≠OF" },
                  ].map((item) => (
                    <ListItem key={item.jmp} sx={{ py: 0.5, px: 0 }}>
                      <ListItemText
                        primary={<Chip label={item.jmp} size="small" sx={{ bgcolor: alpha("#f97316", 0.15), color: "#f97316", fontWeight: 600, fontFamily: "monospace", fontSize: "0.7rem" }} />}
                        secondary={<><Typography variant="caption" display="block">{item.cond}</Typography><Typography variant="caption" color="text.secondary">({item.flag})</Typography></>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Unconditional Jumps & Loops
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { instr: "JMP label", desc: "Unconditional jump to label. Used for goto, loop back, switch-case fall-through.", color: "#8b5cf6" },
              { instr: "JMP RAX", desc: "Indirect jump: Jump to address in RAX. Used for function pointers, vtables, switch jumptables.", color: "#ec4899" },
              { instr: "LOOP label", desc: "Decrement RCX, jump if RCX ≠ 0. Simple counted loop (but rarely used—slower than DEC+JNZ).", color: "#14b8a6" },
              { instr: "LOOPE/LOOPZ", desc: "Loop while equal: Decrement RCX, jump if RCX ≠ 0 AND ZF = 1.", color: "#3b82f6" },
              { instr: "LOOPNE/LOOPNZ", desc: "Loop while not equal: Decrement RCX, jump if RCX ≠ 0 AND ZF = 0.", color: "#22c55e" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={4} key={item.instr}>
                <Paper sx={{ p: 2.5, borderRadius: 2, bgcolor: alpha(item.color, 0.03), border: `1px solid ${alpha(item.color, 0.15)}` }}>
                  <Chip label={item.instr} size="small" sx={{ fontFamily: "monospace", bgcolor: alpha(item.color, 0.15), color: item.color, fontWeight: 700, mb: 1.5 }} />
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
            Common Control Flow Patterns
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#ef4444", 0.03), border: `1px solid ${alpha("#ef4444", 0.15)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ef4444", mb: 1 }}>If Statement</Typography>
                <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#ef4444", 0.05), p: 1.5, borderRadius: 1, overflow: "auto" }}>
{`CMP RAX, 10
JNE else_label
  ; if block
  JMP end_if
else_label:
  ; else block
end_if:`}
                </Box>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#22c55e", mb: 1 }}>While Loop</Typography>
                <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#22c55e", 0.05), p: 1.5, borderRadius: 1, overflow: "auto" }}>
{`loop_start:
  CMP RCX, 0
  JE loop_end
  ; loop body
  DEC RCX
  JMP loop_start
loop_end:`}
                </Box>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#3b82f6", 0.03), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#3b82f6", mb: 1 }}>For Loop (optimized)</Typography>
                <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#3b82f6", 0.05), p: 1.5, borderRadius: 1, overflow: "auto" }}>
{`  MOV RCX, 10
loop_start:
  ; loop body
  DEC RCX
  JNZ loop_start
; falls through when done`}
                </Box>
              </Paper>
            </Grid>
          </Grid>

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Reverse Engineering Tip</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              When analyzing disassembly, look for CMP/TEST followed by conditional jumps—that's the core of program logic. 
              A <code>TEST RAX, RAX; JZ error</code> is checking for NULL pointers. Watch for <code>CMP [var], 0; JG</code> 
              patterns that indicate bounds checking. Understanding these patterns lets you reconstruct the original if/while/for 
              statements from assembly.
            </Typography>
          </Alert>
        </Paper>

        {/* MODULE 7: The Stack & Function Calls */}
        <Paper
          id="module-7"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#a855f7", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 7" sx={{ bgcolor: alpha("#a855f7", 0.15), color: "#a855f7", fontWeight: 700 }} />
            <Typography variant="h5" sx={{ fontWeight: 800 }}>
              The Stack & Function Calls
            </Typography>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            The <strong>stack</strong> is one of the most important concepts in assembly language and security research. It's a 
            region of memory used for storing local variables, function arguments, return addresses, and saved registers. Understanding 
            the stack is <strong>absolutely critical</strong> for exploit development, reverse engineering, and debugging.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#a855f7" }}>
            Stack Fundamentals
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            The stack is a <strong>Last-In-First-Out (LIFO)</strong> data structure. In x86/x64, it grows <strong>downward</strong> 
            toward lower memory addresses. The <strong>RSP</strong> register always points to the current top of the stack 
            (the most recently pushed value).
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#a855f7", 0.05), border: `1px solid ${alpha("#a855f7", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#a855f7", mb: 2 }}>
                  PUSH Operation
                </Typography>
                <Box component="pre" sx={{ fontSize: "0.8rem", fontFamily: "monospace", bgcolor: alpha("#a855f7", 0.1), p: 2, borderRadius: 1, mb: 2 }}>
{`PUSH RAX  ; is equivalent to:
SUB RSP, 8        ; Decrement RSP by 8
MOV [RSP], RAX    ; Store RAX at new top`}
                </Box>
                <List dense>
                  {[
                    "RSP decreases (stack grows down)",
                    "Value is written to memory at [RSP]",
                    "64-bit push = 8 bytes, 32-bit = 4 bytes",
                  ].map((item, idx) => (
                    <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ fontSize: 16, color: "#a855f7" }} /></ListItemIcon>
                      <ListItemText primary={<Typography variant="body2">{item}</Typography>} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>
                  POP Operation
                </Typography>
                <Box component="pre" sx={{ fontSize: "0.8rem", fontFamily: "monospace", bgcolor: alpha("#22c55e", 0.1), p: 2, borderRadius: 1, mb: 2 }}>
{`POP RBX   ; is equivalent to:
MOV RBX, [RSP]    ; Load value from top
ADD RSP, 8        ; Increment RSP by 8`}
                </Box>
                <List dense>
                  {[
                    "Value is read from memory at [RSP]",
                    "RSP increases (stack shrinks up)",
                    "Data isn't erased—just no longer 'on' stack",
                  ].map((item, idx) => (
                    <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ fontSize: 16, color: "#22c55e" }} /></ListItemIcon>
                      <ListItemText primary={<Typography variant="body2">{item}</Typography>} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#3b82f6" }}>
            Function Call Mechanics
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            When a function is called using <code style={{ background: alpha("#3b82f6", 0.1), padding: "2px 6px", borderRadius: 4 }}>CALL</code>, 
            the CPU automatically pushes the return address onto the stack. When the function executes 
            <code style={{ background: alpha("#3b82f6", 0.1), padding: "2px 6px", borderRadius: 4 }}> RET</code>, it pops this 
            address and jumps back.
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 2 }}>CALL Instruction</Typography>
                <Box component="pre" sx={{ fontSize: "0.8rem", fontFamily: "monospace", bgcolor: alpha("#3b82f6", 0.1), p: 2, borderRadius: 1, mb: 2 }}>
{`CALL function  ; is equivalent to:
PUSH RIP       ; Save return address
JMP function   ; Jump to function`}
                </Box>
                <Typography variant="body2" color="text.secondary">
                  The return address is the address of the instruction immediately after the CALL.
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 2 }}>RET Instruction</Typography>
                <Box component="pre" sx={{ fontSize: "0.8rem", fontFamily: "monospace", bgcolor: alpha("#f97316", 0.1), p: 2, borderRadius: 1, mb: 2 }}>
{`RET            ; is equivalent to:
POP RIP        ; Pop return address
               ; (jumps to that address)`}
                </Box>
                <Typography variant="body2" color="text.secondary">
                  RET can optionally clean up stack bytes: <code>RET 16</code> pops return addr then adds 16 to RSP.
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Stack Frame Structure
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Each function call creates a <strong>stack frame</strong>—a region of stack containing that function's data. The 
            <strong> RBP</strong> (Base Pointer) typically marks the frame's base, providing a stable reference for local variables.
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#22c55e", 0.03), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>Typical Stack Frame Layout (High to Low Address):</Typography>
            <Box component="pre" sx={{ fontSize: "0.8rem", fontFamily: "monospace", bgcolor: alpha("#22c55e", 0.1), p: 2, borderRadius: 1 }}>
{`┌─────────────────────────────┐ Higher addresses
│    Caller's stack frame     │
├─────────────────────────────┤
│  Arguments (if stack-passed)│ [RBP+16], [RBP+24], ...
├─────────────────────────────┤
│    Return Address           │ [RBP+8] (pushed by CALL)
├─────────────────────────────┤
│    Saved RBP                │ [RBP] (pushed at function start)
├─────────────────────────────┤ ← RBP points here
│    Local variable 1         │ [RBP-8]
├─────────────────────────────┤
│    Local variable 2         │ [RBP-16]
├─────────────────────────────┤
│    ... more locals ...      │
├─────────────────────────────┤
│    Saved registers          │
├─────────────────────────────┤ ← RSP points here
│    (red zone / free space)  │
└─────────────────────────────┘ Lower addresses`}
            </Box>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            Function Prologue & Epilogue
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#ec4899", 0.05), border: `1px solid ${alpha("#ec4899", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ec4899", mb: 2 }}>Function Prologue</Typography>
                <Box component="pre" sx={{ fontSize: "0.8rem", fontFamily: "monospace", bgcolor: alpha("#ec4899", 0.1), p: 2, borderRadius: 1, mb: 2 }}>
{`function:
  PUSH RBP          ; Save caller's base pointer
  MOV RBP, RSP      ; Set up new base pointer
  SUB RSP, 32       ; Allocate 32 bytes for locals`}
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Sets up the stack frame for the new function.
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#14b8a6", 0.05), border: `1px solid ${alpha("#14b8a6", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#14b8a6", mb: 2 }}>Function Epilogue</Typography>
                <Box component="pre" sx={{ fontSize: "0.8rem", fontFamily: "monospace", bgcolor: alpha("#14b8a6", 0.1), p: 2, borderRadius: 1, mb: 2 }}>
{`  MOV RSP, RBP      ; Deallocate locals
  POP RBP           ; Restore caller's base pointer
  RET               ; Return to caller
; Or simply:
  LEAVE             ; = MOV RSP,RBP + POP RBP
  RET`}
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Tears down the frame and returns to caller.
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            Calling Conventions
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 2 }}>System V AMD64 ABI (Linux/macOS)</Typography>
                <List dense>
                  {[
                    { label: "Args 1-6:", value: "RDI, RSI, RDX, RCX, R8, R9" },
                    { label: "Float args:", value: "XMM0-XMM7" },
                    { label: "Return:", value: "RAX (and RDX for 128-bit)" },
                    { label: "Callee-saved:", value: "RBX, RBP, R12-R15" },
                    { label: "Red zone:", value: "128 bytes below RSP usable" },
                  ].map((item) => (
                    <ListItem key={item.label} sx={{ py: 0.25, px: 0 }}>
                      <ListItemText
                        primary={<Typography variant="body2"><strong>{item.label}</strong> {item.value}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 2 }}>Microsoft x64 ABI (Windows)</Typography>
                <List dense>
                  {[
                    { label: "Args 1-4:", value: "RCX, RDX, R8, R9" },
                    { label: "Float args:", value: "XMM0-XMM3" },
                    { label: "Return:", value: "RAX" },
                    { label: "Callee-saved:", value: "RBX, RBP, RDI, RSI, R12-R15" },
                    { label: "Shadow space:", value: "32 bytes always reserved" },
                  ].map((item) => (
                    <ListItem key={item.label} sx={{ py: 0.25, px: 0 }}>
                      <ListItemText
                        primary={<Typography variant="body2"><strong>{item.label}</strong> {item.value}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Alert severity="error" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Security: Stack Buffer Overflows</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              The stack is the target of <strong>buffer overflow attacks</strong>. If a function writes past the bounds of a 
              local buffer, it can overwrite the saved RBP and <strong>return address</strong>. By controlling the return address, 
              an attacker can redirect execution to malicious code. Modern mitigations include <strong>stack canaries</strong>, 
              <strong> ASLR</strong>, and <strong>NX/DEP</strong> (non-executable stack).
            </Typography>
          </Alert>
        </Paper>

        {/* MODULE 8: System Calls & Interrupts */}
        <Paper
          id="module-8"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#ef4444", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 8" sx={{ bgcolor: alpha("#ef4444", 0.15), color: "#ef4444", fontWeight: 700 }} />
            <Typography variant="h5" sx={{ fontWeight: 800 }}>
              System Calls & Interrupts
            </Typography>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            User programs can't directly access hardware or perform privileged operations—they must ask the <strong>operating 
            system kernel</strong> to do it for them. This is done through <strong>system calls (syscalls)</strong>. Understanding 
            syscalls is essential for shellcode development, malware analysis, and understanding how programs interact with the OS.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
            User Mode vs Kernel Mode
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#3b82f6", mb: 2 }}>User Mode (Ring 3)</Typography>
                <List dense>
                  {[
                    "Where normal applications run",
                    "Limited access to memory and hardware",
                    "Cannot execute privileged instructions",
                    "Memory protected by virtual addressing",
                    "Must use syscalls for OS services",
                  ].map((item, idx) => (
                    <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ fontSize: 16, color: "#3b82f6" }} /></ListItemIcon>
                      <ListItemText primary={<Typography variant="body2">{item}</Typography>} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#ef4444", 0.05), border: `1px solid ${alpha("#ef4444", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#ef4444", mb: 2 }}>Kernel Mode (Ring 0)</Typography>
                <List dense>
                  {[
                    "Where the OS kernel runs",
                    "Full access to all hardware and memory",
                    "Can execute any CPU instruction",
                    "Handles syscalls from user programs",
                    "A crash here = system crash (BSOD/panic)",
                  ].map((item, idx) => (
                    <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ fontSize: 16, color: "#ef4444" }} /></ListItemIcon>
                      <ListItemText primary={<Typography variant="body2">{item}</Typography>} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Making System Calls
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            On x86-64 Linux, the <code style={{ background: alpha("#22c55e", 0.1), padding: "2px 6px", borderRadius: 4 }}>SYSCALL</code> 
            instruction transitions to kernel mode. On 32-bit systems, <code>INT 0x80</code> was used. Windows uses 
            <code> SYSCALL</code> too, but through the NTDLL layer.
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>Linux x86-64 Syscall Convention</Typography>
                <List dense>
                  {[
                    { reg: "RAX", use: "Syscall number (e.g., 1 = write, 60 = exit)" },
                    { reg: "RDI", use: "1st argument" },
                    { reg: "RSI", use: "2nd argument" },
                    { reg: "RDX", use: "3rd argument" },
                    { reg: "R10", use: "4th argument (NOT RCX!)" },
                    { reg: "R8", use: "5th argument" },
                    { reg: "R9", use: "6th argument" },
                    { reg: "RAX", use: "Return value (negative = error)" },
                  ].map((item) => (
                    <ListItem key={item.reg + item.use} sx={{ py: 0.25, px: 0 }}>
                      <ListItemText
                        primary={<Typography variant="body2"><Chip label={item.reg} size="small" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 700, fontFamily: "monospace", mr: 1 }} />{item.use}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 2 }}>Example: Write "Hello" to stdout</Typography>
                <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#f97316", 0.1), p: 2, borderRadius: 1 }}>
{`section .data
  msg: db "Hello", 10    ; String + newline

section .text
  global _start
_start:
  mov rax, 1             ; syscall: write
  mov rdi, 1             ; fd: stdout
  mov rsi, msg           ; buffer address
  mov rdx, 6             ; length
  syscall                ; invoke kernel
  
  mov rax, 60            ; syscall: exit
  mov rdi, 0             ; exit code 0
  syscall`}
                </Box>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Common Linux Syscalls
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { num: "0", name: "read", desc: "Read from file descriptor", args: "fd, buf, count" },
              { num: "1", name: "write", desc: "Write to file descriptor", args: "fd, buf, count" },
              { num: "2", name: "open", desc: "Open a file", args: "path, flags, mode" },
              { num: "3", name: "close", desc: "Close file descriptor", args: "fd" },
              { num: "9", name: "mmap", desc: "Map memory", args: "addr, len, prot, flags, fd, off" },
              { num: "10", name: "mprotect", desc: "Change memory protection", args: "addr, len, prot" },
              { num: "57", name: "fork", desc: "Create child process", args: "(none)" },
              { num: "59", name: "execve", desc: "Execute program", args: "path, argv, envp" },
              { num: "60", name: "exit", desc: "Terminate process", args: "status" },
              { num: "62", name: "kill", desc: "Send signal to process", args: "pid, sig" },
              { num: "63", name: "uname", desc: "Get system info", args: "buf" },
              { num: "102", name: "getuid", desc: "Get user ID", args: "(none)" },
            ].map((sc) => (
              <Grid item xs={6} sm={4} md={3} key={sc.num}>
                <Paper sx={{ p: 2, height: "100%", borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.1)}` }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                    <Chip label={sc.num} size="small" sx={{ bgcolor: alpha("#8b5cf6", 0.15), color: "#8b5cf6", fontWeight: 700, fontFamily: "monospace", minWidth: 32 }} />
                    <Typography variant="subtitle2" sx={{ fontWeight: 700 }}>{sc.name}</Typography>
                  </Box>
                  <Typography variant="caption" color="text.secondary" display="block">{sc.desc}</Typography>
                  <Typography variant="caption" sx={{ fontFamily: "monospace", fontSize: "0.65rem" }}>{sc.args}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
            Interrupts
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Interrupts</strong> are signals that cause the CPU to stop what it's doing and handle an event. They can be 
            hardware-triggered (keyboard, timer, disk) or software-triggered (INT instruction, exceptions).
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { type: "Hardware Interrupts", desc: "External events: keyboard input, network packets, timer ticks. CPU stops, saves state, runs interrupt handler.", color: "#3b82f6" },
              { type: "Software Interrupts", desc: "INT instruction triggers interrupt. INT 0x80 was Linux syscall, INT 3 is debugger breakpoint (0xCC opcode).", color: "#22c55e" },
              { type: "Exceptions", desc: "CPU-generated: divide by zero (#DE), page fault (#PF), general protection (#GP). Some can be recovered from.", color: "#ef4444" },
            ].map((item) => (
              <Grid item xs={12} md={4} key={item.type}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha(item.color, 0.03), border: `1px solid ${alpha(item.color, 0.15)}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color, mb: 1 }}>{item.type}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Shellcode & Syscalls</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Shellcode often uses direct syscalls to avoid library dependencies. A minimal Linux execve("/bin/sh") shellcode 
              sets up RAX=59, RDI=address of "/bin/sh", RSI=0, RDX=0, then SYSCALL. Understanding syscalls lets you write 
              position-independent code and understand what malware is doing at the OS level.
            </Typography>
          </Alert>
        </Paper>

        {/* MODULE 9: SIMD & Vector Instructions */}
        <Paper
          id="module-9"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#06b6d4", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 9" sx={{ bgcolor: alpha("#06b6d4", 0.15), color: "#06b6d4", fontWeight: 700 }} />
            <Typography variant="h5" sx={{ fontWeight: 800 }}>
              SIMD & Vector Instructions
            </Typography>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>SIMD (Single Instruction, Multiple Data)</strong> instructions process multiple data elements in parallel using 
            wide registers. Originally designed for multimedia (MMX, SSE), they're now everywhere—from video encoding to 
            cryptography to string operations. When analyzing optimized code, you'll frequently encounter these instructions.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            SIMD Register Sets
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { name: "MMX (MM0-MM7)", bits: "64-bit", desc: "Original SIMD. 8 registers aliased to x87 FPU. Integers only. Largely obsolete.", color: "#6b7280" },
              { name: "SSE (XMM0-XMM15)", bits: "128-bit", desc: "16 registers in x64. Handles 4 floats, 2 doubles, or various integer packs.", color: "#3b82f6" },
              { name: "AVX (YMM0-YMM15)", bits: "256-bit", desc: "Extends XMM to 256 bits. Lower 128 bits = corresponding XMM register.", color: "#22c55e" },
              { name: "AVX-512 (ZMM0-ZMM31)", bits: "512-bit", desc: "32 registers, 512 bits each. Massive parallelism. Server/workstation CPUs.", color: "#f97316" },
            ].map((item) => (
              <Grid item xs={12} sm={6} key={item.name}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha(item.color, 0.03), border: `1px solid ${alpha(item.color, 0.15)}` }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color }}>{item.name}</Typography>
                    <Chip label={item.bits} size="small" sx={{ bgcolor: alpha(item.color, 0.1), fontSize: "0.7rem" }} />
                  </Box>
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            How SIMD Works
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            SIMD packs multiple values into one register and operates on all of them simultaneously. For example, an XMM register 
            can hold four 32-bit floats, and <code>ADDPS</code> adds four pairs of floats in a single instruction.
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.03), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 2 }}>XMM Register Data Interpretations</Typography>
            <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#8b5cf6", 0.1), p: 2, borderRadius: 1 }}>
{`128-bit XMM Register can be viewed as:
┌────────────────────────────────────────────────────────────────┐
│                     1 x 128-bit value                          │  (for AES, etc.)
├───────────────────────────────┬────────────────────────────────┤
│         64-bit double         │         64-bit double          │  2 x doubles (PD)
├───────────────┬───────────────┼───────────────┬────────────────┤
│  32-bit float │  32-bit float │  32-bit float │  32-bit float  │  4 x floats (PS)
├───────┬───────┼───────┬───────┼───────┬───────┼───────┬────────┤
│ 16-bit│ 16-bit│ 16-bit│ 16-bit│ 16-bit│ 16-bit│ 16-bit│ 16-bit │  8 x words
├───┬───┼───┬───┼───┬───┼───┬───┼───┬───┼───┬───┼───┬───┼───┬────┤
│8b │8b │8b │8b │8b │8b │8b │8b │8b │8b │8b │8b │8b │8b │8b │ 8b │  16 x bytes
└───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴───┴────┘`}
            </Box>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            Common SSE/AVX Instructions
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>Data Movement</Typography>
                <List dense>
                  {[
                    { instr: "MOVAPS xmm1, xmm2", desc: "Move aligned packed single (must be 16-byte aligned)" },
                    { instr: "MOVUPS xmm1, [mem]", desc: "Move unaligned packed single (slower but flexible)" },
                    { instr: "MOVD xmm1, eax", desc: "Move doubleword (32-bit) to/from XMM" },
                    { instr: "MOVQ xmm1, rax", desc: "Move quadword (64-bit) to/from XMM" },
                    { instr: "PXOR xmm1, xmm1", desc: "XOR with self = zero register (common idiom)" },
                  ].map((item) => (
                    <ListItem key={item.instr} sx={{ py: 0.5, px: 0 }}>
                      <ListItemText
                        primary={<code style={{ color: "#22c55e", fontSize: "0.8rem" }}>{item.instr}</code>}
                        secondary={item.desc}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 2 }}>Arithmetic & Comparison</Typography>
                <List dense>
                  {[
                    { instr: "ADDPS xmm1, xmm2", desc: "Add packed singles (4 floats parallel)" },
                    { instr: "MULPD xmm1, xmm2", desc: "Multiply packed doubles (2 doubles)" },
                    { instr: "PADDD xmm1, xmm2", desc: "Add packed doublewords (4 x 32-bit ints)" },
                    { instr: "PCMPEQB xmm1, xmm2", desc: "Compare bytes for equality (for string ops)" },
                    { instr: "PMAXUB xmm1, xmm2", desc: "Packed maximum unsigned bytes" },
                  ].map((item) => (
                    <ListItem key={item.instr} sx={{ py: 0.5, px: 0 }}>
                      <ListItemText
                        primary={<code style={{ color: "#f97316", fontSize: "0.8rem" }}>{item.instr}</code>}
                        secondary={item.desc}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            SIMD in the Real World
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { use: "String Operations", desc: "memcpy, strlen, strcmp often use SSE for 16+ bytes at once. PCMPEQB finds characters fast.", color: "#3b82f6" },
              { use: "Cryptography", desc: "AES-NI provides hardware AES encryption in ~4 cycles per block. PCLMULQDQ for GCM mode.", color: "#22c55e" },
              { use: "Media Processing", desc: "Video codecs, image processing, audio DSP all rely heavily on SIMD for performance.", color: "#f97316" },
              { use: "Math Libraries", desc: "Linear algebra, FFT, physics simulations use SIMD for parallel computation.", color: "#8b5cf6" },
            ].map((item) => (
              <Grid item xs={12} sm={6} md={3} key={item.use}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha(item.color, 0.03), border: `1px solid ${alpha(item.color, 0.15)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color, mb: 1 }}>{item.use}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Reverse Engineering Note</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              When you see XMM registers in disassembly, don't panic! Often they're just being used for efficient memory copies or 
              zeroing. <code>MOVAPS [RSP+0x20], XMM0</code> after <code>PXOR XMM0, XMM0</code> is just zeroing 16 bytes of stack. 
              Look for patterns: loops with XMM usually mean vectorized operations. Recognize common library functions that use SIMD.
            </Typography>
          </Alert>
        </Paper>

        {/* MODULE 10: Assembly in Reverse Engineering */}
        <Paper
          id="module-10"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#10b981", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 10" sx={{ bgcolor: alpha("#10b981", 0.15), color: "#10b981", fontWeight: 700 }} />
            <Typography variant="h5" sx={{ fontWeight: 800 }}>
              Assembly in Reverse Engineering
            </Typography>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Reverse engineering</strong> is the art of understanding software without access to its source code. Assembly 
            language is the foundation of this discipline—when you reverse engineer a binary, you're reading the compiler's output: 
            raw machine instructions. Mastering pattern recognition in assembly is what separates novice reversers from experts.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#10b981" }}>
            Disassemblers vs Decompilers
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#10b981", 0.05), border: `1px solid ${alpha("#10b981", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#10b981", mb: 2 }}>Disassemblers</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Convert machine code → assembly. Shows exactly what the CPU executes.
                </Typography>
                <List dense>
                  {[
                    { tool: "Ghidra", desc: "Free, NSA-developed, excellent decompiler" },
                    { tool: "IDA Pro", desc: "Industry standard, expensive but powerful" },
                    { tool: "Binary Ninja", desc: "Modern UI, good IL, mid-range price" },
                    { tool: "radare2/Cutter", desc: "Free, scriptable, steep learning curve" },
                    { tool: "objdump", desc: "Basic CLI disassembler, comes with binutils" },
                  ].map((item) => (
                    <ListItem key={item.tool} sx={{ py: 0.25, px: 0 }}>
                      <ListItemText
                        primary={<Typography variant="body2"><strong>{item.tool}:</strong> {item.desc}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
                <Typography variant="h6" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 2 }}>Decompilers</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Attempt to reconstruct C/C++ from assembly. Output is approximate, not original source.
                </Typography>
                <List dense>
                  {[
                    "Variable names are lost (var_8, param_1)",
                    "Types are inferred, often wrong",
                    "Control flow may be restructured",
                    "Optimizations make output ugly",
                    "Always verify against assembly!",
                  ].map((item, idx) => (
                    <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ fontSize: 16, color: "#8b5cf6" }} /></ListItemIcon>
                      <ListItemText primary={<Typography variant="body2">{item}</Typography>} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            Recognizing Common Patterns
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            Compilers generate predictable patterns. Learning these lets you quickly identify what code is doing without reading 
            every instruction.
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 2 }}>If-Else Pattern</Typography>
                <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#f97316", 0.1), p: 2, borderRadius: 1 }}>
{`; if (eax == 5) { ... } else { ... }
CMP EAX, 5
JNE else_branch      ; Jump if NOT equal
  ; ... if-true code ...
  JMP end_if
else_branch:
  ; ... else code ...
end_if:`}
                </Box>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#3b82f6", 0.05), border: `1px solid ${alpha("#3b82f6", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#3b82f6", mb: 2 }}>For Loop Pattern</Typography>
                <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#3b82f6", 0.1), p: 2, borderRadius: 1 }}>
{`; for (int i = 0; i < 10; i++)
XOR ECX, ECX         ; i = 0
loop_start:
  CMP ECX, 10        ; i < 10?
  JGE loop_end       ; exit if i >= 10
  ; ... loop body ...
  INC ECX            ; i++
  JMP loop_start
loop_end:`}
                </Box>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>Switch/Jump Table</Typography>
                <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#22c55e", 0.1), p: 2, borderRadius: 1 }}>
{`; switch(eax) with jump table
CMP EAX, 4           ; Check bounds
JA default_case      ; Out of range
LEA RDX, [jump_table]
MOVSXD RAX, [RDX+RAX*4]
ADD RAX, RDX
JMP RAX              ; Indirect jump`}
                </Box>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#ec4899", 0.05), border: `1px solid ${alpha("#ec4899", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#ec4899", mb: 2 }}>Virtual Function Call (C++)</Typography>
                <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#ec4899", 0.1), p: 2, borderRadius: 1 }}>
{`; obj->virtualMethod()
MOV RAX, [RCX]       ; Load vtable ptr
MOV RDX, RCX         ; this pointer
CALL [RAX+0x18]      ; Call vtable[3]
; Offset reveals which virtual method`}
                </Box>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
            Identifying Library Functions
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            {[
              { name: "strlen", pattern: "Loop with REPNE SCASB or byte comparison until null", color: "#3b82f6" },
              { name: "memcpy", pattern: "REP MOVSB/MOVSQ or SSE moves in a loop", color: "#22c55e" },
              { name: "strcmp", pattern: "Byte comparison loop until mismatch or null", color: "#f97316" },
              { name: "malloc", pattern: "Call to external symbol, return value used as pointer", color: "#8b5cf6" },
            ].map((item) => (
              <Grid item xs={12} sm={6} key={item.name}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha(item.color, 0.03), border: `1px solid ${alpha(item.color, 0.15)}` }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 700, color: item.color }}>{item.name}</Typography>
                  <Typography variant="body2" color="text.secondary">{item.pattern}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Pro Tip: FLIRT Signatures</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              IDA Pro and Ghidra can automatically identify statically-linked library functions using <strong>FLIRT signatures</strong>. 
              This saves huge amounts of time—suddenly that 200-instruction blob is labeled "memcpy" and you can move on. 
              Apply signature databases for common libraries (glibc, MSVC CRT, OpenSSL) early in your analysis.
            </Typography>
          </Alert>
        </Paper>

        {/* MODULE 11: Shellcode Development */}
        <Paper
          id="module-11"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#ef4444", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 11" sx={{ bgcolor: alpha("#ef4444", 0.15), color: "#ef4444", fontWeight: 700 }} />
            <Typography variant="h5" sx={{ fontWeight: 800 }}>
              Shellcode Development
            </Typography>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>Shellcode</strong> is small, position-independent machine code designed to be injected and executed in another 
            process's memory. Historically used to spawn shells (hence the name), modern shellcode can download payloads, establish 
            reverse connections, or perform any arbitrary action. Writing shellcode is the ultimate test of assembly mastery.
          </Typography>

          <Alert severity="warning" sx={{ mb: 3, borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>⚠️ Educational Purposes Only</AlertTitle>
            <Typography variant="body2">
              Shellcode knowledge is essential for security research, CTFs, and understanding exploits. Never use these techniques 
              on systems without explicit authorization. Unauthorized access is illegal.
            </Typography>
          </Alert>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ef4444" }}>
            Shellcode Requirements
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { req: "Position Independent", desc: "Must work regardless of where it's loaded in memory. No absolute addresses—use relative addressing (RIP-relative, LEA, CALL/POP tricks).", color: "#ef4444" },
              { req: "No Null Bytes", desc: "Null bytes (0x00) terminate strings. Many injection vectors treat shellcode as a string. Use XOR encoding or avoid instructions that produce nulls.", color: "#f97316" },
              { req: "Self-Contained", desc: "Can't rely on imports or libraries being at known addresses. Must resolve function addresses dynamically or use syscalls directly.", color: "#22c55e" },
              { req: "Small Size", desc: "Buffer sizes are often limited. Every byte counts. Use short instruction encodings, avoid unnecessary setup.", color: "#3b82f6" },
            ].map((item) => (
              <Grid item xs={12} sm={6} key={item.req}>
                <Paper sx={{ p: 2.5, height: "100%", borderRadius: 2, bgcolor: alpha(item.color, 0.03), border: `1px solid ${alpha(item.color, 0.15)}` }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700, color: item.color, mb: 1 }}>{item.req}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.6 }}>{item.desc}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Position-Independent Techniques
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 2 }}>CALL/POP Technique (x86)</Typography>
                <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#8b5cf6", 0.1), p: 2, borderRadius: 1, mb: 2 }}>
{`; Get address of data after the CALL
JMP short get_string
got_string:
  POP RSI            ; RSI = address of string
  ; ... use string ...
  
get_string:
  CALL got_string    ; Pushes addr of next instr
  db "/bin/sh", 0    ; String data here`}
                </Box>
                <Typography variant="body2" color="text.secondary">
                  CALL pushes return address, POP retrieves it. Classic shellcode technique.
                </Typography>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>RIP-Relative (x64)</Typography>
                <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#22c55e", 0.1), p: 2, borderRadius: 1, mb: 2 }}>
{`; x64 supports RIP-relative addressing
LEA RSI, [RIP+string_data]
; ... use string ...

string_data:
  db "/bin/sh", 0`}
                </Box>
                <Typography variant="body2" color="text.secondary">
                  x86-64 makes this easier with native RIP-relative LEA.
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#f97316" }}>
            Avoiding Null Bytes
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#f97316", 0.03), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
            <Grid container spacing={2}>
              {[
                { bad: "MOV EAX, 0", good: "XOR EAX, EAX", why: "XOR reg with itself = 0, no nulls" },
                { bad: "MOV EAX, 1", good: "XOR EAX, EAX; INC EAX", why: "Or: PUSH 1; POP RAX" },
                { bad: "MOV RAX, 0x68732f6e69622f", good: "Use XOR encoding", why: "XOR payload with key, decode at runtime" },
                { bad: "MOV [addr], 0", good: "XOR EAX, EAX; MOV [addr], EAX", why: "Use zeroed register instead" },
              ].map((item, idx) => (
                <Grid item xs={12} sm={6} key={idx}>
                  <Box sx={{ p: 2, bgcolor: alpha("#f97316", 0.05), borderRadius: 1 }}>
                    <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#ef4444", textDecoration: "line-through" }}>{item.bad}</Typography>
                    <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#22c55e", fontWeight: 700 }}>{item.good}</Typography>
                    <Typography variant="caption" color="text.secondary">{item.why}</Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            Classic Linux x64 execve Shellcode
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.03), border: `1px solid ${alpha("#06b6d4", 0.15)}` }}>
            <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#06b6d4", 0.1), p: 2, borderRadius: 1 }}>
{`; execve("/bin/sh", NULL, NULL) - 27 bytes
; Syscall 59 = execve on Linux x64

global _start
section .text
_start:
  xor    rdx, rdx          ; envp = NULL
  push   rdx               ; Push null terminator
  mov    rax, 0x68732f6e69622f2f  ; "//bin/sh"
  push   rax               ; Push string
  mov    rdi, rsp          ; rdi = pointer to "/bin/sh"
  push   rdx               ; NULL
  push   rdi               ; pointer to string
  mov    rsi, rsp          ; rsi = argv array
  xor    rax, rax
  mov    al, 59            ; syscall number (avoids nulls)
  syscall                  ; Execute!`}
            </Box>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
              This spawns a shell. The string is pushed onto the stack to avoid using a data section with absolute addresses.
            </Typography>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            Windows Shellcode Challenges
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#ec4899", 0.05), border: `1px solid ${alpha("#ec4899", 0.15)}` }}>
                <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                  Windows shellcode is more complex because you can't easily use syscalls directly (numbers change between versions). 
                  Instead, you must:
                </Typography>
                <List dense>
                  {[
                    "Find kernel32.dll base address via PEB (Process Environment Block)",
                    "Parse kernel32's export table to find GetProcAddress and LoadLibraryA",
                    "Use these to dynamically resolve any other Windows API function",
                    "Handle both 32-bit and 64-bit differences (WoW64)",
                  ].map((item, idx) => (
                    <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ fontSize: 16, color: "#ec4899" }} /></ListItemIcon>
                      <ListItemText primary={<Typography variant="body2">{item}</Typography>} />
                    </ListItem>
                  ))}
                </List>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                  Tools like msfvenom generate Windows shellcode that handles all this complexity for you.
                </Typography>
              </Paper>
            </Grid>
          </Grid>

          <Alert severity="success" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>Testing Shellcode Safely</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              Use a shellcode runner in a VM: allocate executable memory (VirtualAlloc with PAGE_EXECUTE_READWRITE or mmap with 
              PROT_EXEC), copy shellcode there, cast to function pointer, call it. Tools: <code>shellcode_tester</code>, 
              <code>pwntools</code>, or write your own minimal C loader.
            </Typography>
          </Alert>
        </Paper>

        {/* MODULE 12: ARM Assembly Basics */}
        <Paper
          id="module-12"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#06b6d4", 0.2)}`,
          }}
        >
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
            <Chip label="Module 12" sx={{ bgcolor: alpha("#06b6d4", 0.15), color: "#06b6d4", fontWeight: 700 }} />
            <Typography variant="h5" sx={{ fontWeight: 800 }}>
              ARM Assembly Basics
            </Typography>
          </Box>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            <strong>ARM</strong> powers virtually every smartphone, tablet, and embedded device—plus Apple Silicon Macs and growing 
            server adoption. As a security researcher, you <em>will</em> encounter ARM binaries. ARM uses a <strong>RISC 
            (Reduced Instruction Set Computer)</strong> design, which differs significantly from x86's CISC approach.
          </Typography>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#06b6d4" }}>
            ARM vs x86: Key Differences
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            {[
              { feature: "Architecture", arm: "RISC - simple instructions, load/store", x86: "CISC - complex instructions, memory operands" },
              { feature: "Instruction Size", arm: "Fixed 32-bit (ARM) or 16/32-bit (Thumb)", x86: "Variable 1-15 bytes" },
              { feature: "Registers", arm: "16 general purpose (R0-R15)", x86: "Fewer GPRs, more specialized" },
              { feature: "Condition Codes", arm: "Almost every instruction can be conditional", x86: "Only branch instructions check flags" },
              { feature: "Memory Access", arm: "Only via LDR/STR instructions", x86: "Most instructions can access memory" },
            ].map((item) => (
              <Grid item xs={12} key={item.feature}>
                <Paper sx={{ p: 2, borderRadius: 2, bgcolor: alpha("#06b6d4", 0.03), border: `1px solid ${alpha("#06b6d4", 0.1)}` }}>
                  <Grid container spacing={2}>
                    <Grid item xs={12} sm={3}><Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#06b6d4" }}>{item.feature}</Typography></Grid>
                    <Grid item xs={12} sm={4.5}><Typography variant="body2"><strong>ARM:</strong> {item.arm}</Typography></Grid>
                    <Grid item xs={12} sm={4.5}><Typography variant="body2"><strong>x86:</strong> {item.x86}</Typography></Grid>
                  </Grid>
                </Paper>
              </Grid>
            ))}
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#22c55e" }}>
            ARM Registers (32-bit ARM)
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>General Purpose Registers</Typography>
                <List dense>
                  {[
                    { reg: "R0-R3", use: "Arguments and return values" },
                    { reg: "R4-R11", use: "Callee-saved (local variables)" },
                    { reg: "R12 (IP)", use: "Intra-procedure scratch register" },
                    { reg: "R13 (SP)", use: "Stack Pointer" },
                    { reg: "R14 (LR)", use: "Link Register (return address)" },
                    { reg: "R15 (PC)", use: "Program Counter (current instruction)" },
                  ].map((item) => (
                    <ListItem key={item.reg} sx={{ py: 0.25, px: 0 }}>
                      <ListItemText
                        primary={<Typography variant="body2"><Chip label={item.reg} size="small" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 700, fontFamily: "monospace", mr: 1, minWidth: 70 }} />{item.use}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 2 }}>AArch64 (ARM64) Registers</Typography>
                <List dense>
                  {[
                    { reg: "X0-X7", use: "Arguments and return values" },
                    { reg: "X8", use: "Indirect result location (syscall number on Linux)" },
                    { reg: "X9-X15", use: "Caller-saved temporaries" },
                    { reg: "X16-X17", use: "Intra-procedure call scratch" },
                    { reg: "X19-X28", use: "Callee-saved" },
                    { reg: "X29 (FP)", use: "Frame Pointer" },
                    { reg: "X30 (LR)", use: "Link Register" },
                    { reg: "SP", use: "Stack Pointer (not a GPR)" },
                  ].map((item) => (
                    <ListItem key={item.reg} sx={{ py: 0.25, px: 0 }}>
                      <ListItemText
                        primary={<Typography variant="body2"><Chip label={item.reg} size="small" sx={{ bgcolor: alpha("#f97316", 0.15), color: "#f97316", fontWeight: 700, fontFamily: "monospace", mr: 1, minWidth: 70 }} />{item.use}</Typography>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#8b5cf6" }}>
            Essential ARM Instructions
          </Typography>

          <Grid container spacing={2} sx={{ mb: 4 }}>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#8b5cf6", 0.05), border: `1px solid ${alpha("#8b5cf6", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#8b5cf6", mb: 2 }}>Data Processing</Typography>
                <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#8b5cf6", 0.1), p: 2, borderRadius: 1 }}>
{`MOV R0, #10      ; R0 = 10
MOV R1, R0       ; R1 = R0
ADD R2, R0, R1   ; R2 = R0 + R1
SUB R3, R2, #5   ; R3 = R2 - 5
MUL R4, R0, R1   ; R4 = R0 * R1
AND R5, R0, #0xF ; R5 = R0 & 0xF
ORR R6, R0, R1   ; R6 = R0 | R1
EOR R7, R0, R1   ; R7 = R0 ^ R1
CMP R0, R1       ; Set flags`}
                </Box>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#22c55e", 0.05), border: `1px solid ${alpha("#22c55e", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#22c55e", mb: 2 }}>Load/Store</Typography>
                <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#22c55e", 0.1), p: 2, borderRadius: 1 }}>
{`LDR R0, [R1]     ; Load from [R1]
STR R0, [R1]     ; Store to [R1]
LDR R0, [R1, #4] ; Load [R1+4]
LDR R0, [R1, #4]!; Pre-index, R1+=4
LDR R0, [R1], #4 ; Post-index
LDRB R0, [R1]    ; Load byte
LDRH R0, [R1]    ; Load halfword
LDMIA R0!, {R1-R4} ; Load multiple
STMDB SP!, {R4-R6, LR} ; Push`}
                </Box>
              </Paper>
            </Grid>
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, height: "100%", borderRadius: 2, bgcolor: alpha("#f97316", 0.05), border: `1px solid ${alpha("#f97316", 0.15)}` }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 700, color: "#f97316", mb: 2 }}>Branching</Typography>
                <Box component="pre" sx={{ fontSize: "0.75rem", fontFamily: "monospace", bgcolor: alpha("#f97316", 0.1), p: 2, borderRadius: 1 }}>
{`B label          ; Branch
BL function      ; Branch & Link
BX LR            ; Return (branch to LR)
BLX R0           ; Call via register
BEQ label        ; Branch if equal
BNE label        ; Branch if not equal
BGT label        ; Branch if >
BLT label        ; Branch if <
BGE label        ; Branch if >=
BLE label        ; Branch if <=`}
                </Box>
              </Paper>
            </Grid>
          </Grid>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#ec4899" }}>
            Conditional Execution (ARM32)
          </Typography>

          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, fontSize: "1.05rem" }}>
            ARM's most unique feature: <strong>almost any instruction can be made conditional</strong> by adding a condition suffix. 
            This avoids branch penalties and makes code more compact.
          </Typography>

          <Paper sx={{ p: 3, mb: 4, borderRadius: 2, bgcolor: alpha("#ec4899", 0.03), border: `1px solid ${alpha("#ec4899", 0.15)}` }}>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ec4899", mb: 1 }}>Condition Suffixes</Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                  {[
                    { code: "EQ", mean: "Equal (Z=1)" },
                    { code: "NE", mean: "Not Equal" },
                    { code: "GT", mean: "Greater Than" },
                    { code: "LT", mean: "Less Than" },
                    { code: "GE", mean: "Greater/Equal" },
                    { code: "LE", mean: "Less/Equal" },
                    { code: "CS/HS", mean: "Carry Set" },
                    { code: "CC/LO", mean: "Carry Clear" },
                  ].map((c) => (
                    <Chip key={c.code} label={`${c.code}: ${c.mean}`} size="small" sx={{ bgcolor: alpha("#ec4899", 0.1), fontSize: "0.7rem" }} />
                  ))}
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" sx={{ fontWeight: 700, color: "#ec4899", mb: 1 }}>Example: if (R0 == 0) R1 = 5;</Typography>
                <Box component="pre" sx={{ fontSize: "0.8rem", fontFamily: "monospace", bgcolor: alpha("#ec4899", 0.1), p: 2, borderRadius: 1 }}>
{`CMP R0, #0       ; Compare R0 with 0
MOVEQ R1, #5     ; Only executes if Z=1
; No branch needed!`}
                </Box>
              </Grid>
            </Grid>
          </Paper>

          <Typography variant="h6" sx={{ fontWeight: 700, mb: 2, color: "#14b8a6" }}>
            Thumb Mode
          </Typography>

          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={12}>
              <Paper sx={{ p: 3, borderRadius: 2, bgcolor: alpha("#14b8a6", 0.05), border: `1px solid ${alpha("#14b8a6", 0.15)}` }}>
                <Typography variant="body1" sx={{ mb: 2, lineHeight: 1.8 }}>
                  <strong>Thumb</strong> is a 16-bit instruction set that provides better code density. <strong>Thumb-2</strong> 
                  mixes 16-bit and 32-bit instructions. Most modern ARM code (especially on mobile) uses Thumb-2.
                </Typography>
                <List dense>
                  {[
                    "Thumb instructions are 16 bits (half the size of ARM)",
                    "Switch to Thumb: BX with LSB=1; switch to ARM: BX with LSB=0",
                    "Ghidra/IDA can usually auto-detect, but may need hints",
                    "iOS and Android apps are typically compiled as Thumb-2",
                  ].map((item, idx) => (
                    <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                      <ListItemIcon sx={{ minWidth: 28 }}><CheckCircleIcon sx={{ fontSize: 16, color: "#14b8a6" }} /></ListItemIcon>
                      <ListItemText primary={<Typography variant="body2">{item}</Typography>} />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </Grid>

          <Alert severity="info" sx={{ borderRadius: 2 }}>
            <AlertTitle sx={{ fontWeight: 700 }}>ARM Reverse Engineering Tips</AlertTitle>
            <Typography variant="body2" sx={{ lineHeight: 1.8 }}>
              When reversing ARM: watch for <code>BL</code> (function calls), identify the calling convention (AAPCS), note that 
              <code> PC</code> reads as current instruction + 8 (ARM) or + 4 (Thumb). For iOS, binaries are often 
              FAT/Universal—extract the arm64 slice with <code>lipo</code>. Android native libs (.so) are usually ARM or ARM64 ELF files.
            </Typography>
          </Alert>
        </Paper>

        {/* Course Completion */}
        <Paper
          sx={{
            p: 4,
            mb: 5,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#f97316", 0.1)} 0%, ${alpha("#22c55e", 0.1)} 100%)`,
            border: `2px solid ${alpha("#f97316", 0.3)}`,
            textAlign: "center",
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 2 }}>
            🎉 Congratulations!
          </Typography>
          <Typography variant="h6" sx={{ mb: 3, color: "text.secondary" }}>
            You've completed the Assembly Language Fundamentals course
          </Typography>
          <Typography variant="body1" sx={{ mb: 3, lineHeight: 1.9, maxWidth: 800, mx: "auto" }}>
            You now have a solid foundation in x86-64 assembly language, from basic CPU architecture through to ARM basics 
            and shellcode development. This knowledge is essential for reverse engineering, exploit development, malware 
            analysis, and deep security research. Keep practicing with CTF challenges, analyze real binaries, and build 
            your skills through hands-on experience!
          </Typography>
          <Box sx={{ display: "flex", justifyContent: "center", gap: 2, flexWrap: "wrap" }}>
            <Chip label="12 Modules Completed" sx={{ bgcolor: alpha("#f97316", 0.15), color: "#f97316", fontWeight: 700 }} />
            <Chip label="75 Quiz Questions Available" sx={{ bgcolor: alpha("#22c55e", 0.15), color: "#22c55e", fontWeight: 700 }} />
            <Chip label="x86-64 & ARM Covered" sx={{ bgcolor: alpha("#3b82f6", 0.15), color: "#3b82f6", fontWeight: 700 }} />
          </Box>
        </Paper>

        {/* ==================== QUIZ SECTION ==================== */}
        <Paper
          id="quiz-section"
          sx={{
            p: 4,
            mb: 4,
            borderRadius: 4,
            bgcolor: alpha(theme.palette.background.paper, 0.6),
            border: `1px solid ${alpha("#f97316", 0.2)}`,
          }}
        >
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 3, display: "flex", alignItems: "center", gap: 2 }}>
            <QuizIcon sx={{ color: "#f97316" }} />
            Knowledge Check
          </Typography>
          <QuizSection />
        </Paper>

        {/* ==================== BACK TO LEARNING HUB ==================== */}
        <Paper
          sx={{
            p: 4,
            borderRadius: 4,
            background: `linear-gradient(135deg, ${alpha("#f97316", 0.1)} 0%, ${alpha("#3b82f6", 0.1)} 100%)`,
            border: `1px solid ${alpha("#f97316", 0.2)}`,
            textAlign: "center",
          }}
        >
          <Typography variant="h5" sx={{ fontWeight: 700, mb: 2 }}>
            Continue Your Learning Journey
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Explore more topics in the Learning Hub to build your cybersecurity skills.
          </Typography>
          <Button
            variant="contained"
            size="large"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate("/learn")}
            sx={{
              bgcolor: "#f97316",
              "&:hover": { bgcolor: "#ea580c" },
              px: 4,
              py: 1.5,
              fontWeight: 700,
            }}
          >
            Back to Learning Hub
          </Button>
        </Paper>
        </Box>
      </Box>
    </LearnPageLayout>
  );
}