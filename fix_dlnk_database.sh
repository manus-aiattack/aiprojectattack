#!/bin/bash

# Fix dlnk_FINAL/api/routes/auth_routes.py
if [ -f "dlnk_FINAL/api/routes/auth_routes.py" ]; then
    sed -i 's/^db = Database()$/# db = Database()  # Fixed: Use shared instance from main.py/' dlnk_FINAL/api/routes/auth_routes.py
    echo "✅ Fixed: dlnk_FINAL/api/routes/auth_routes.py"
fi

# Fix dlnk_FINAL/api/routes/files.py
if [ -f "dlnk_FINAL/api/routes/files.py" ]; then
    sed -i 's/^db = Database()$/# db = Database()  # Fixed: Use shared instance from main.py/' dlnk_FINAL/api/routes/files.py
    echo "✅ Fixed: dlnk_FINAL/api/routes/files.py"
fi

# Fix dlnk_FINAL/api/routes/monitoring.py
if [ -f "dlnk_FINAL/api/routes/monitoring.py" ]; then
    sed -i 's/^db = Database()$/# db = Database()  # Fixed: Use shared instance from main.py/' dlnk_FINAL/api/routes/monitoring.py
    echo "✅ Fixed: dlnk_FINAL/api/routes/monitoring.py"
fi

echo ""
echo "✅ All dlnk_FINAL files fixed!"
