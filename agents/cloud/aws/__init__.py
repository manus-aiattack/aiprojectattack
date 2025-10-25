"""
AWS Cloud Attack Agents
"""

# Import all AWS agents
try:
    from .iam_privesc_agent import *
except ImportError:
    pass

try:
    from .lambda_exploit_agent import *
except ImportError:
    pass

try:
    from .rds_exploit_agent import *
except ImportError:
    pass

try:
    from .s3_enumeration_agent import *
except ImportError:
    pass

try:
    from .secrets_manager_agent import *
except ImportError:
    pass

