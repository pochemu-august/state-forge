@echo off
setlocal EnableDelayedExpansion

set "LOG_DIR=logs"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

set "FMT_LOG=%LOG_DIR%\fmt.log"
set "CLIPPY_LOG=%LOG_DIR%\clippy.log"
set "CHECK_LOG=%LOG_DIR%\check.log"
set "TEST_LOG=%LOG_DIR%\test.log"

set "ERRORS=0"
set "STATUS_FMT=[PASS]"
set "STATUS_CLIPPY=[PASS]"
set "STATUS_CHECK=[PASS]"
set "STATUS_TEST=[PASS]"

echo.
echo ====================================================================
echo   state-forge: Rust Code Analysis and Verification
echo ====================================================================
echo.

echo [1/4] Checking code style (cargo fmt)...
cargo fmt --all -- --check > "%FMT_LOG%" 2>&1
if %ERRORLEVEL% neq 0 (
    set "STATUS_FMT=[FAIL]"
    set /a ERRORS+=1
)

echo [2/4] Checking code logic and idioms (cargo clippy)...
cargo clippy --workspace --all-targets --all-features > "%CLIPPY_LOG%" 2>&1
if %ERRORLEVEL% neq 0 (
    set "STATUS_CLIPPY=[FAIL]"
    set /a ERRORS+=1
)

echo [3/4] Checking workspace compilation (cargo check)...
cargo check --workspace --all-targets > "%CHECK_LOG%" 2>&1
if %ERRORLEVEL% neq 0 (
    set "STATUS_CHECK=[FAIL]"
    set /a ERRORS+=1
)

echo [4/4] Running unit and integration tests (cargo test)...
cargo test --workspace > "%TEST_LOG%" 2>&1
if %ERRORLEVEL% neq 0 (
    set "STATUS_TEST=[FAIL]"
    set /a ERRORS+=1
)

echo.
echo ====================================================================
echo                     ANALYSIS SUMMARY REPORT
echo ====================================================================
echo  1. Code Style ^(rustfmt^)       : !STATUS_FMT!   - Log: %FMT_LOG%
echo  2. Code Logic ^(clippy^)        : !STATUS_CLIPPY!   - Log: %CLIPPY_LOG%
echo  3. Compilation ^(cargo check^)  : !STATUS_CHECK!   - Log: %CHECK_LOG%
echo  4. Tests Suite ^(cargo test^)   : !STATUS_TEST!   - Log: %TEST_LOG%
echo ====================================================================

if !ERRORS! equ 0 (
    echo  RESULT: ALL CHECKS PASSED SUCCESSFULLY!
    echo ====================================================================
    exit /b 0
) else (
    echo  RESULT: !ERRORS! CHECK^(S^) FAILED! Check the log files above.
    echo ====================================================================
    exit /b 1
)
