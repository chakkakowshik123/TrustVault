"""Shared Jinja2Templates instance with helper globals."""
from pathlib import Path
from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = Path(__file__).parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.globals["hasattr"] = hasattr
templates.env.globals["isinstance"] = isinstance
templates.env.globals["str"] = str
templates.env.globals["len"] = len
