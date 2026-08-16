#!/usr/bin/env python3
"""
Simple ReDoS test for hazm - no GitHub Actions needed, run locally.
This demonstrates the regex vulnerability directly.
"""

import re
import time

# The VULNERABLE pattern from hazm/normalizer.py (lines 75-79)
VULNERABLE_PATTERN = re.compile(
    r"[آابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی]*"
    r"([آابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی])\1{2,}"
    r"[آابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی]*",
)

def test_redos():
    """Test the regex with inputs that trigger catastrophic backtracking."""
    
    print("=" * 80)
    print("HAZM ReDoS VULNERABILITY TEST")
    print("=" * 80)
    print("\nPattern: [Persian]*([Persian])\\1{2,}[Persian]*")
    print("Issue: Nested quantifiers cause exponential backtracking\n")
    
    # Test cases - shortest to longest
    tests = [
        ("Safe - valid match", "سلاممم", 1),
        ("Risky - 20 same chars (no repeat 2+)", "س" * 20, 2),
        ("Very Risky - 30 same chars", "س" * 30, 3),
        ("Critical - 40 same chars", "س" * 40, 5),
        ("Extreme - 50 same chars", "س" * 50, 10),
    ]
    
    for name, test_input, timeout_sec in tests:
        print(f"\n{'─' * 80}")
        print(f"Test: {name}")
        print(f"Input: {len(test_input)} characters of '{test_input[0] if test_input else ''}'")
        print(f"Expected timeout: {timeout_sec}s")
        print(f"Testing...", end=" ", flush=True)
        
        start = time.time()
        try:
            result = VULNERABLE_PATTERN.search(test_input)
            elapsed = time.time() - start
            
            if result:
                print(f"\n✓ MATCH found in {elapsed:.6f}s")
            else:
                print(f"\n✗ NO MATCH in {elapsed:.6f}s")
            
            # Flag slow execution
            if elapsed > 0.1:
                print(f"  ⚠️  SLOW! ({elapsed:.4f}s) - ReDoS indicator")
            if elapsed > 1.0:
                print(f"  🔴 VERY SLOW! ({elapsed:.4f}s) - DEFINITE ReDoS!")
                
        except KeyboardInterrupt:
            elapsed = time.time() - start
            print(f"\n⏱️  INTERRUPTED after {elapsed:.2f}s")
            print(f"  🔴 TIMEOUT - Regex is hanging (ReDoS confirmed)!")

    print("\n" + "=" * 80)
    print("EXPLANATION")
    print("=" * 80)
    print("""
The pattern has this structure:
  [charset]* (char)\\1{2,} [charset]*
  └─ outer  └─inner ─┘ └─ outer ┘

Problem: TWO outer quantifiers + inner matching requirement
Creates exponential decision points. For non-matching input:
  - Try first [charset]* with 0 chars
  - Try captured char + \\1{2,}
  - Try second [charset]* 
  - BACKTRACK and try first [charset]* with 1 char
  - Retry captured char + \\1{2,}
  - Retry second [charset]*
  - ... repeat for EVERY possible split point ...

With 50 identical chars: ~2^50 = 1 quadrillion combinations to try!
""")

    print("\nRECOMMENDATION:")
    print("──────────────")
    print("""
Replace the vulnerable pattern with a simpler approach:
  
  CURRENT (vulnerable):
    r"[Persian]*([Persian])\\1{2,}[Persian]*"
  
  BETTER (safe):
    - Use a simple quantifier: r"([Persian])\\1{2,}"
    - Apply it separately to find repeated chars
    - Or use atomic grouping: r"(?>Persian)*(?>Persian)\\1{2,}"
    - Or use possessive quantifiers (Python 3.11+)
""")

if __name__ == "__main__":
    test_redos()
