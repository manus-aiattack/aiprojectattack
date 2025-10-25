#!/bin/bash

# Fix dlnk_FINAL/advanced_agents/zero_day_hunter.py
sed -i 's|self.results_dir = "/mnt/c/projecattack/manus/workspace/loot/zero_day"|workspace_dir = os.getenv("WORKSPACE_DIR", "workspace"); self.results_dir = os.path.join(workspace_dir, "loot", "zero_day")|g' dlnk_FINAL/advanced_agents/zero_day_hunter.py

# Fix dlnk_FINAL/agents/exploit_database_agent.py
sed -i 's|self.exploits_dir = "/mnt/c/projecattack/manus/workspace/exploits"|workspace_dir = os.getenv("WORKSPACE_DIR", "workspace"); self.exploits_dir = os.path.join(workspace_dir, "exploits")|g' dlnk_FINAL/agents/exploit_database_agent.py

# Fix dlnk_FINAL/agents/privilege_escalation_agent_weaponized.py
sed -i 's|self.scripts_dir = "/mnt/c/projecattack/manus/workspace/scripts"|workspace_dir = os.getenv("WORKSPACE_DIR", "workspace"); self.scripts_dir = os.path.join(workspace_dir, "scripts")|g' dlnk_FINAL/agents/privilege_escalation_agent_weaponized.py

# Fix dlnk_FINAL/data_exfiltration/exfiltrator.py
sed -i 's|self.base_dir = f"/mnt/c/projecattack/manus/workspace/loot/exfiltrated/{attack_id}"|workspace_dir = os.getenv("WORKSPACE_DIR", "workspace"); self.base_dir = os.path.join(workspace_dir, "loot", "exfiltrated", attack_id)|g' dlnk_FINAL/data_exfiltration/exfiltrator.py

echo "✅ Fixed all files in dlnk_FINAL directory"
