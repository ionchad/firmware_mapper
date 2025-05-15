def generate_html_report(suspicious_files, cve_matches):
    with open("report.html", "w", encoding="utf-8") as f:
        f.write("<h1>Firmware Report (Windows)</h1>\n")

        f.write("<h2>Suspicious Files</h2>\n<ul>\n")
        for path, issues in suspicious_files.items():
            f.write(f"<li><b>{path}</b>: {issues}</li>\n")
        f.write("</ul>\n")

        f.write("<h2>Matched CVEs</h2>\n<ul>\n")
        for cve_id, matched_kw, severity, score, description in cve_matches:
            color = "red" if score >= 7 else "orange" if score >= 4 else "green"
            f.write(f"<li><b>{cve_id}</b> [{matched_kw}] <span style='color:{color}'>({severity}, score={score})</span><br>{description}</li>\n")
        f.write("</ul>\n")
