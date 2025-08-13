@echo off
REM Windows batch script to validate the macOS clipboard fix
REM This script provides instructions for manual testing on macOS

echo === macOS Mettle Clipboard Fix Validation ===
echo Testing the fix for screenshot clipboard segfault issue
echo.

echo IMPORTANT: This script provides testing instructions for macOS
echo Please run these commands on a macOS system with Mettle
echo.

echo === Manual Testing Instructions ===
echo.
echo 1. Clean Text Test:
echo    echo "Hello Mettle Test" ^| pbcopy
echo    In Mettle: clipboard_get_data
echo.
echo 2. Screenshot Test (Critical):
echo    Take screenshot: Cmd+Shift+Ctrl+4
echo    In Mettle: clipboard_get_data
echo    Verify: No segfault occurs
echo.
echo 3. Empty Clipboard Test:
echo    echo -n ^| pbcopy
echo    In Mettle: clipboard_get_data
echo.
echo 4. Large Text Test:
echo    python -c "print('A' * 10000)" ^| pbcopy
echo    In Mettle: clipboard_get_data
echo.
echo 5. Debug Mode Test:
echo    In Mettle: set debug true
echo    Take screenshot and run clipboard_get_data
echo    Check logs for format detection messages
echo.

echo === Expected Behavior ===
echo - Text clipboard: Returns text content
echo - Image clipboard: Returns empty string (no crash)
echo - Mixed content: Returns text if available, empty otherwise
echo - Empty clipboard: Returns empty string
echo - Large text: Returns text within 1MB limit
echo.

echo === Verification Steps ===
echo 1. Build Mettle with the fix
echo 2. Start Meterpreter session on macOS
echo 3. Run: load extapi
echo 4. Execute the test scenarios above
echo 5. Verify no segmentation faults occur
echo.

pause
