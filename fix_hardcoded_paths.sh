#!/bin/bash
# Fix hardcoded /home/ubuntu/dlnk paths

echo "🔧 Fixing hardcoded paths in Python files..."

# Get current directory
CURRENT_DIR="/mnt/c/projecattack/manus"

# Find and replace all occurrences
find . -type f -name "*.py" -exec sed -i \
  "s|/home/ubuntu/dlnk/workspace|${CURRENT_DIR}/workspace|g" {} +

echo "✅ Fixed hardcoded paths!"
echo ""
echo "Changed paths from:"
echo "  /home/ubuntu/dlnk/workspace"
echo "To:"
echo "  ${CURRENT_DIR}/workspace"
echo ""
echo "Run this to verify:"
echo "  grep -r '/home/ubuntu/dlnk' . --include='*.py' | wc -l"
echo "  (should be 0)"

