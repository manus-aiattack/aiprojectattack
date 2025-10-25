"""GCP Cloud Attack Agents"""

# Import all GCP agents
try:
    from .cloud_functions_agent import *
except ImportError:
    pass

try:
    from .compute_engine_agent import *
except ImportError:
    pass

try:
    from .iam_privesc_agent import *
except ImportError:
    pass

try:
    from .secret_manager_agent import *
except ImportError:
    pass

try:
    from .storage_bucket_agent import *
except ImportError:
    pass
