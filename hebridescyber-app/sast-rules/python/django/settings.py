# Annotated test cases for settings.yaml (run: opengrep test sast-rules/).
import os

# ruleid: py-django-debug-enabled
DEBUG = True

if os.environ.get("DJANGO_LOCAL"):
    # ok: py-django-debug-enabled
    DEBUG = True

# ok: py-django-debug-enabled
TEMPLATE_DEBUG = True
