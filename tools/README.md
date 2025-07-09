# Tools Directory

This directory contains utility scripts and tools for development, testing, and validation of the email parser.

## Directory Structure

### `/debug/`
Scripts for debugging and analyzing email parsing issues:
- `debug_attachment.py` - Debug attachment parsing
- `debug_proofpoint_msg.py` - Debug Proofpoint message parsing  
- `analyze_duplication.py` - Analyze duplicate content issues
- `analyze_structure.py` - Analyze email structure parsing

### `/testing/`
Test scripts for validating functionality:
- `test_all_fixes.py` - Test all recent fixes
- `test_attachment_fix.py` - Test attachment parsing fixes
- `test_local.py` - Local testing script
- `test_new_structure.py` - Test new structure parsing
- `test_msg_detection_fix.py` - Test MSG detection fixes
- `test_msg_nested_fix.py` - Test nested MSG parsing fixes

### `/validation/`
Scripts for validating and comparing parser output:
- `validate_implementation.py` - Validate parser implementation
- `verify_artifacts.py` - Verify parsing artifacts
- `compare_results.py` - Compare parsing results
- `structure_comparison.py` - Compare structure outputs

### `/examples/`
Documentation and example scripts:
- `detailed_structure_example.py` - Example of detailed structure output

## Usage

These tools are for development purposes only and are not part of the core email parsing functionality. Run them from the repository root to ensure proper module imports.