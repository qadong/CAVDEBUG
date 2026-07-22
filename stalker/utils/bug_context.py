def format_bug_context(profile: dict | None) -> str:
    if not isinstance(profile, dict):
        return ""

    description = str(profile.get("bug_description") or "").strip()
    if not description and profile.get("secbench"):
        description = str(profile.get("constraint") or "").strip()
    bug_report = str(profile.get("bug_report") or "").strip()

    sections = []
    if description:
        sections.append(f"## Bug Description\n\n```text\n{description}\n```")
    if bug_report:
        sections.append(
            "## Original Bug Report\n\n"
            "This report may contain developer analysis and intended-fix knowledge. "
            "Use it as supporting context, but validate it against the checked-out source and runtime evidence.\n\n"
            f"```text\n{bug_report}\n```"
        )
    if not sections:
        return ""
    return "\n\n".join(sections) + "\n\n"
