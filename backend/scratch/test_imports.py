import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    print("Testing dependencies import...")
    import app.dependencies
    print("Dependencies imported successfully!")
    
    print("Testing admin router import...")
    import app.routers.admin
    print("Admin router imported successfully!")
    
    print("Testing main app import...")
    from app.main import app
    print("FastAPI app imported successfully! No syntax or import errors.")
except Exception as e:
    print("IMPORT ERROR:", str(e))
    sys.exit(1)
