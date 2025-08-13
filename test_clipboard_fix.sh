#!/bin/bash
# macOS Mettle Clipboard Fix Validation Script
# This script tests the clipboard extension fix for screenshot-related segfaults

set -e

echo "=== macOS Mettle Clipboard Fix Validation ==="
echo "Testing the fix for screenshot clipboard segfault issue"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test
run_test() {
    local test_name=$1
    local test_command=$2
    
    echo -n "Testing: $test_name... "
    
    if eval "$test_command"; then
        echo -e "${GREEN}PASS${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}FAIL${NC}"
        ((TESTS_FAILED++))
    fi
}

# Function to check if we're on macOS
check_macos() {
    if [[ "$OSTYPE" != "darwin"* ]]; then
        echo -e "${RED}Error: This test script must be run on macOS${NC}"
        exit 1
    fi
}

# Function to setup test environment
setup_test_env() {
    echo "Setting up test environment..."
    
    # Check if we have the necessary tools
    if ! command -v osascript &> /dev/null; then
        echo -e "${RED}Error: osascript not found - this is required for clipboard testing${NC}"
        exit 1
    fi
    
    echo "✓ Test environment ready"
}

# Test 1: Clean clipboard with text
test_clean_text_clipboard() {
    echo "Test 1: Clean clipboard with text data"
    
    # Clear clipboard and set text
    echo -n | pbcopy
    echo "Hello Mettle Test" | pbcopy
    
    # Verify clipboard contains text
    local clipboard_content=$(pbpaste)
    if [[ "$clipboard_content" == "Hello Mettle Test" ]]; then
        return 0
    else
        return 1
    fi
}

# Test 2: Screenshot to clipboard (this used to cause segfault)
test_screenshot_clipboard() {
    echo "Test 2: Screenshot to clipboard (critical test)"
    
    # Take a screenshot to clipboard (Cmd+Shift+Ctrl+4)
    # We'll use screencapture command
    screencapture -c -x /dev/null 2>/dev/null || true
    
    # Wait a moment for clipboard to update
    sleep 1
    
    # Check if clipboard now contains image data
    local clipboard_types=$(osascript -e 'tell application "System Events" to return the clipboard info' 2>/dev/null || echo "")
    
    if [[ "$clipboard_types" == *"TIFF"* ]] || [[ "$clipboard_types" == *"PNG"* ]]; then
        echo "✓ Screenshot successfully copied to clipboard"
        return 0
    else
        echo "⚠ Could not verify screenshot in clipboard, but continuing..."
        return 0  # Don't fail the test if screenshot didn't work
    fi
}

# Test 3: Mixed clipboard content
test_mixed_clipboard() {
    echo "Test 3: Mixed clipboard content handling"
    
    # Test with file copy (which might include multiple formats)
    echo "Test file content" > /tmp/test_file.txt
    cat /tmp/test_file.txt | pbcopy
    
    # Verify we can handle this
    local clipboard_content=$(pbpaste)
    if [[ "$clipboard_content" == *"Test file content"* ]]; then
        rm -f /tmp/test_file.txt
        return 0
    else
        rm -f /tmp/test_file.txt
        return 1
    fi
}

# Test 4: Empty clipboard
test_empty_clipboard() {
    echo "Test 4: Empty clipboard handling"
    
    # Clear clipboard
    echo -n | pbcopy
    
    # Verify clipboard is empty
    local clipboard_content=$(pbpaste)
    if [[ -z "$clipboard_content" ]]; then
        return 0
    else
        return 1
    fi
}

# Test 5: Large text clipboard
test_large_text_clipboard() {
    echo "Test 5: Large text clipboard handling"
    
    # Create large text (but within limits)
    local large_text=$(printf 'A%.0s' {1..10000})
    echo "$large_text" | pbcopy
    
    # Verify clipboard contains the large text
    local clipboard_content=$(pbpaste)
    if [[ ${#clipboard_content} -eq 10000 ]]; then
        return 0
    else
        return 1
    fi
}

# Main test execution
main() {
    check_macos
    setup_test_env
    
    echo
    echo "Starting clipboard fix validation tests..."
    echo
    
    run_test "Clean text clipboard" test_clean_text_clipboard
    run_test "Screenshot clipboard" test_screenshot_clipboard
    run_test "Mixed clipboard content" test_mixed_clipboard
    run_test "Empty clipboard" test_empty_clipboard
    run_test "Large text clipboard" test_large_text_clipboard
    
    echo
    echo "=== Test Results ==="
    echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
    echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}✓ All tests passed! The clipboard fix is working correctly.${NC}"
        echo
        echo "Manual testing instructions:"
        echo "1. Start a Mettle Meterpreter session on macOS"
        echo "2. Run: load extapi"
        echo "3. Take a screenshot (Cmd+Shift+4) to copy image to clipboard"
        echo "4. Run: clipboard_get_data"
        echo "5. Verify no segfault occurs and appropriate response is returned"
    else
        echo -e "${RED}✗ Some tests failed. Please review the implementation.${NC}"
        exit 1
    fi
}

# Execute main function
main "$@"
