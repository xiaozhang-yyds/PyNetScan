from jinja2 import Environment, FileSystemLoader, select_autoescape
from datetime import datetime
from weasyprint import HTML
import json
import os

env = Environment(
    loader=FileSystemLoader(searchpath=os.path.join(os.path.dirname(__file__), "templates")),
    autoescape=select_autoescape(["html"])
)

def generate(data, fmt="html"):
    template = env.get_template("report.html")
    html = template.render(scan=data, generated=datetime.now())

    if fmt == "pdf":
        path = "report.pdf"
        HTML(string=html).write_pdf(path)
    elif fmt == "json":
        path = "report.json"
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    else:
        path = "report.html"
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
    return path