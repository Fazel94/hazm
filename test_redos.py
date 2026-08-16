"""
Test script to check for ReDoS (Regular Expression Denial of Service) vulnerabilities in Hazm.
This tests the potentially vulnerable regex patterns identified in the normalizer.
"""

import re
import time
import sys

# Pattern from hazm/normalizer.py line 75-79
VULNERABLE_PATTERN = re.compile(
    r"[آابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی]*"
    r"([آابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی])\1{2,}"
    r"[آابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی]*",
)

# Pattern from hazm/normalizer.py line 72-74
REPEAT_PATTERN = re.compile(
    r"([آابپتثجچحخدذرزژسشصضطظعغفقکگلمنوهی])\1{2,}",
)

# Pattern from hazm/constants.py for affix spacing
PUNC_AFTER = r"\.:!،؛؟»\]\)\}"
PUNC_BEFORE = r"«\[\(\{"
LOOKAHEAD_PATTERN = re.compile(
    r"(?<=[^\n\d "
    + PUNC_AFTER
    + PUNC_BEFORE
    + r"]{2}) (تر(ین?)?|گری?|های?)(?=[ \n"
    + PUNC_AFTER
    + PUNC_BEFORE
    + r"]|$)",
)

def test_pattern(pattern, test_cases, pattern_name):
    """Test a regex pattern with various inputs and measure execution time."""
    print(f"\n{'='*70}")
    print(f"Testing: {pattern_name}")
    print(f"Pattern: {pattern.pattern[:100]}...")
    print(f"{'='*70}")
    
    for test_name, test_input in test_cases:
        print(f"\n[{test_name}]")
        print(f"Input length: {len(test_input)} characters")
        print(f"Input (truncated): {test_input[:50]}..." if len(test_input) > 50 else f"Input: {test_input}")
        
        start_time = time.time()
        try:
            # Set timeout using signal (Unix-like systems only)
            result = pattern.search(test_input)
            elapsed = time.time() - start_time
            
            if result:
                print(f"✓ MATCH found in {elapsed:.6f} seconds")
            else:
                print(f"✗ NO MATCH in {elapsed:.6f} seconds")
            
            # Flag if it takes too long
            if elapsed > 1.0:
                print(f"⚠️  POTENTIAL ReDoS! Took {elapsed:.3f} seconds")
                return True
                
        except KeyboardInterrupt:
            print(f"⚠️  TIMEOUT/INTERRUPTED - Likely ReDoS vulnerability!")
            return True
        except Exception as e:
            print(f"❌ Error: {e}")
    
    return False

def main():
    print("HAZM ReDoS Vulnerability Test Suite")
    print("Testing for Regular Expression Denial of Service patterns\n")
    
    # Test cases: (name, input_string)
    vulnerable_test_cases = [
        ("Normal case - triple repeat", "سلاممم"),
        ("Normal case - many repeats", "سلامممممم"),
        ("Persian char repeated 5 times", "ااااا"),
        ("Persian char repeated 10 times", "آآآآآآآآآآ"),
        ("Persian char repeated 20 times", "ب" * 20),
        ("Persian char repeated 50 times", "پ" * 50),
        ("Persian char repeated 100 times", "ت" * 100),
        ("Persian char repeated 200 times", "ث" * 200),
        ("Persian char repeated 500 times", "ج" * 500),
        ("Mixed Persian chars - worst case", "ااب" * 100),  # Alternating to trigger backtracking
        ("Long string with no match", "abc" * 200),
        ("Non-Persian repeated with Persian prefix", "ا" * 500 + "xyz"),
    ]
    
    lookahead_test_cases = [
        ("Normal case", "تر تر"),
        ("With punctuation", "کتاب تر."),
        ("Multiple trs", "تر تر تر تر"),
        ("Long prefix", "ش" * 50 + " تر"),
        ("Repeated pattern", "میں تر میں تر میں تر"),
        ("Many chars before", "ش" * 100 + " تر"),
        ("With negative lookahead", "ش" * 200 + " تر "),
        ("Alternating pattern", ("شتی تر " * 50)),
    ]
    
    found_redos = False
    
    # Test the vulnerable pattern
    print("\n" + "█" * 70)
    print("TESTING VULNERABLE PATTERN: repeated_chars_pattern")
    print("█" * 70)
    
    if test_pattern(VULNERABLE_PATTERN, vulnerable_test_cases, "repeated_chars_pattern (Vulnerable)"):
        found_redos = True
    
    # Test the simpler repeat pattern
    print("\n" + "█" * 70)
    print("TESTING: more_than_two_repeat_pattern")
    print("█" * 70)
    
    if test_pattern(REPEAT_PATTERN, vulnerable_test_cases, "more_than_two_repeat_pattern"):
        found_redos = True
    
    # Test lookahead pattern
    print("\n" + "█" * 70)
    print("TESTING: LOOKAHEAD_PATTERN (affix spacing)")
    print("█" * 70)
    
    if test_pattern(LOOKAHEAD_PATTERN, lookahead_test_cases, "Lookahead Pattern"):
        found_redos = True
    
    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    if found_redos:
        print("⚠️  POTENTIAL ReDoS VULNERABILITIES DETECTED!")
        print("These patterns may cause significant performance issues.")
        sys.exit(1)
    else:
        print("✓ No catastrophic backtracking detected in test cases.")
        print("Note: This doesn't guarantee safety - more edge cases may exist.")
        sys.exit(0)

if __name__ == "__main__":
    main()
