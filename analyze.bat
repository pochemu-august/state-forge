@echo off
setlocal EnableDelayedExpansion

if /i "%~1"=="run" goto :CMD_RUN
if /i "%~1"=="help" goto :CMD_HELP
if /i "%~1"=="-h" goto :CMD_HELP
if /i "%~1"=="--help" goto :CMD_HELP
goto :CMD_ANALYZE

:CMD_HELP
echo.
echo Usage:
echo   analyze.bat               - Run full code analysis (fmt, clippy, check, test)
echo   analyze.bat run           - Interactive run / demo launcher
echo   analyze.bat run [PID]     - Build and attach interceptor to specific PID
echo.
exit /b 0

:CMD_RUN
echo.
echo ====================================================================
echo   state-forge: Building and Running
echo ====================================================================
echo.
echo [*] Compiling workspace...
cargo build --workspace
if %ERRORLEVEL% neq 0 (
    echo [!] Build failed!
    exit /b %ERRORLEVEL%
)

set "PID_ARG=%~2"
if not "%PID_ARG%"=="" goto :DO_ATTACH

echo.
echo Select run option:
echo   1. Attach to existing process by PID
echo   2. Launch demo target process in a new window
echo.
set /p CHOICE="Enter choice [1-2] (default: 2): "
if "%CHOICE%"=="1" (
    set /p PID_ARG="Enter target process PID: "
) else (
    echo [*] Starting test-target process in a separate window...
    start "state-forge: Test Target" cmd /c "cargo run -p test-target && pause"
    echo.
    set /p PID_ARG="Enter the PID displayed in test-target window: "
)

:DO_ATTACH
if "%PID_ARG%"=="" (
    echo [!] Error: PID cannot be empty.
    exit /b 1
)

echo.
echo [*] Launching state-forge-cli for PID %PID_ARG%...
cargo run -p state-forge-cli -- %PID_ARG%
exit /b %ERRORLEVEL%

:CMD_ANALYZE
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
echo  1. Code Style (rustfmt)       : !STATUS_FMT!   - Log: %FMT_LOG%
echo  2. Code Logic (clippy)        : !STATUS_CLIPPY!   - Log: %CLIPPY_LOG%
echo  3. Compilation (cargo check)  : !STATUS_CHECK!   - Log: %CHECK_LOG%
echo  4. Tests Suite (cargo test)   : !STATUS_TEST!   - Log: %TEST_LOG%
echo ====================================================================

if !ERRORS! equ 0 goto :ALL_PASSED

echo  RESULT: !ERRORS! CHECK FAILURES DETECTED! Check the log files above.
echo ====================================================================
exit /b 1

:ALL_PASSED
echo  RESULT: ALL CHECKS PASSED SUCCESSFULLY!
echo ====================================================================
exit /b 0
