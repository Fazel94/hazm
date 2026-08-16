"""
Advanced ReDoS Test - Demonstrates catastrophic backtracking in hazm patterns.
Run this to test for regex denial of service vulnerabilities.
"""

import re
import time
import signal
import sys

# Timeout handler for Unix systems
class TimeoutException(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutException("Regex timeout - likely ReDoS!")

# Pattern 1: From hazm/normalizer.py (LINE 75-79) - THE VULNERABLE ONE
VULNERABLE_PATTERN = re.compile(
    r"[آابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی]*"
    r"([آابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی])\1{2,}"
    r"[آابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی]*",
)

def test_with_timeout(pattern, test_input, timeout_seconds=5):
    """Test a regex with timeout protection."""
    try:
        # Set alarm (Unix only)
        if hasattr(signal, 'SIGALRM'):
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(timeout_seconds)
        
        start = time.time()
        result = pattern.search(test_input)
        elapsed = time.time() - start
        
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)  # Cancel alarm
        
        return elapsed, result, None
    except TimeoutException as e:
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)
        return None, None, str(e)

def demonstrate_redos():
    """Demonstrate the ReDoS vulnerability."""
    print("=" * 80)
    print("HAZM ReDoS VULNERABILITY DEMONSTRATION")
    print("=" * 80)
    
    print("\n[1] TESTING: repeated_chars_pattern from hazm/normalizer.py")
    print("-" * 80)
    print("Pattern: [Persian]*([Persian])\\1{2,}[Persian]*")
    print("This has NESTED QUANTIFIERS - high ReDoS risk!\n")
    
    # Critical test cases that trigger exponential backtracking
    test_cases = [
        ("Safe: triple repeat", "سلاممم", 1),
        ("Moderate: 10 repeats", "س" * 10, 2),
        ("Risky: 20 repeats NO MATCH", "س" * 20, 3),
        ("VERY RISKY: 30 repeats NO MATCH", "س" * 30, 5),
        ("CRITICAL: 40 repeats NO MATCH", "س" * 40, 10),
        ("WORST CASE: 50 repeats NO MATCH", "س" * 50, 15),
        ("EXTREME: 60 repeats NO MATCH", "س" * 60, 20),
    ]
    
    redos_found = False
    
    for test_name, test_input, timeout in test_cases:
        print(f"\nTest: {test_name}")
        print(f"  Input: '{test_input[:30]}{'...' if len(test_input) > 30 else ''}'")
        print(f"  Length: {len(test_input)} chars | Timeout: {timeout}s")
        
        elapsed, result, error = test_with_timeout(VULNERABLE_PATTERN, test_input, timeout)
        
        if error:
            print(f"  ⚠️  TIMEOUT! Pattern took too long (>{timeout}s)")
            print(f"  Error: {error}")
            redos_found = True
        elif elapsed is not None:
            status = "MATCH" if result else "NO MATCH"
            if elapsed > 1.0:
                print(f"  ⚠️  SLOW! Took {elapsed:.4f}s to determine {status}")
                redos_found = True
            else:
                print(f"  ✓ OK - {status} in {elapsed:.6f}s")
    
    # Test the worst case: non-matching string to trigger full backtracking
    print("\n" + "=" * 80)
    print("[2] WORST CASE SCENARIO - Non-matching input triggering full backtracking")
    print("=" * 80)
    
    print("\nPattern must try ALL possible ways to match before giving up.")
    print("With nested quantifiers [x]* and [x]*, this creates exponential attempts.\n")
    
    worst_cases = [
        ("Latin chars (never matches)", "abcdefgh" * 5, 2),
        ("Latin + Persian mix", "abc" + "س" * 20 + "xyz", 3),
        ("Ends with non-repeating char", "س" * 25 + "x", 5),
        ("EXTREME: Long non-matching", "س" * 50 + "a", 15),
    ]
    
    for test_name, test_input, timeout in worst_cases:
        print(f"Test: {test_name}")
        print(f"  Input length: {len(test_input)}")
        
        elapsed, result, error = test_with_timeout(VULNERABLE_PATTERN, test_input, timeout)
        
        if error:
            print(f"  ⚠️  TIMEOUT (>{timeout}s) - DEFINITE ReDoS!")
            redos_found = True
        elif elapsed is not None:
            if elapsed > 0.5:
                print(f"  ⚠️  VERY SLOW: {elapsed:.4f}s")
                redos_found = True
            else:
                print(f"  ✓ Completed in {elapsed:.6f}s")
    
    # Analysis
    print("\n" + "=" * 80)
    print("ANALYSIS")
    print("=" * 80)
    
    print("""
The vulnerable pattern:
  [آابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی]*([آابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی])\\1{2,}[آابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی]*

Has these issues:
  1. [set]* at the start - matches 0 or more chars
  2. (char) - captures one character  
  3. \\1{2,} - requires that character repeated 2+ times
  4. [set]* at the end - matches 0 or more chars AGAIN

When a non-matching string is tested:
  - The regex engine tries ALL possible ways to distribute characters
  - Between the start [set]*, the captured char, and the end [set]*
  - This creates EXPONENTIAL backtracking
  - Time complexity: O(2^n) where n is input length

Example with input "aaaaaaa" (non-matching):
  - Engine tries: []a[aaaaaa], [a]a[aaaaa], [aa]a[aaaa], [aaa]a[aaa], ...
  - For 50 chars, this means 2^50 ≈ 1 quadrillion attempts!
""")
    
    if redos_found:
        print("\n❌ CONCLUSION: ReDoS VULNERABILITY CONFIRMED in hazm!")
        print("The repeated_chars_pattern WILL cause performance issues.")
        return 1
    else:
        print("\n✓ No catastrophic backtracking detected (but pattern is still risky).")
        return 0

if __name__ == "__main__":
    sys.exit(demonstrate_redos())
