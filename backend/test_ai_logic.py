import requests
import json
import time

URL = "http://localhost:8000/api/v1/ai-analysis/explain"

# I need an auth token to hit the endpoint. Let me see how the app generates auth tokens.
# Or maybe I can just tell the user to test it through the UI, since I can't easily bypass the auth without the frontend or knowing the JWT secret.
