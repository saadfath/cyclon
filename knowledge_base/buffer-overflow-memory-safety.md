# Buffer Overflow and Memory Safety (C and C++)

**CWE:** CWE-119, CWE-120, CWE-125, CWE-416, CWE-190
**OWASP:** A06 Vulnerable and Outdated Components

## What it is
Memory errors in C and C++ let programs read or write outside allocated memory, use freed memory, or overflow numbers, which can cause crashes or code execution.

## How it happens
The language does not check bounds. Typical errors: copying more bytes than a buffer holds, forgetting the terminating character in strings, wrong size calculations, integer overflow in size math, using memory after freeing it, freeing twice, and leaking memory.

## Signs in code
Unbounded string functions such as strcpy, strcat, sprintf and gets. Loops with off-by-one limits. Allocation size computed from multiplication without overflow checks. Pointers used after free, no null check after allocation.

## Severity and context
High to critical in code handling external input, such as parsers and network services. Lower in small local tools.

## Likely false positives
Bounded copies where sizes are verified and tested, and fixed-size constants known at compile time.

## How to fix
Prefer bounded functions and always track buffer sizes. Check allocation results and overflow in size math. Set pointers to null after free. Build with warnings and sanitizers during testing, and use tools such as Valgrind. Consider memory-safe languages for new parsers.

## Related scanner signals
Compiler warnings, SAST rules on banned functions, sanitizer and Valgrind results.
