"""AST helpers: resolve call targets through import aliases."""
import ast


def _dotted_name(node: ast.AST) -> str | None:
    """Return the dotted name for a Name/Attribute chain (e.g. os.path.join)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _build_alias_map(tree: ast.AST) -> dict[str, str]:
    """Map local binding -> canonical dotted name from import statements, so
    aliased/`from` imports resolve to their real target.

    `import subprocess as sp` -> {"sp": "subprocess"};
    `from os import system as s` -> {"s": "os.system"}.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    aliases[a.asname] = a.name
                else:
                    top = a.name.split(".")[0]
                    aliases[top] = top
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for a in node.names:
                local = a.asname or a.name
                aliases[local] = f"{module}.{a.name}" if module else a.name
    return aliases


def _resolve_call_name(func: ast.AST, aliases: dict[str, str]) -> str | None:
    """Resolve a call target to its canonical dotted name using import aliases."""
    dotted = _dotted_name(func)
    if not dotted:
        return None
    parts = dotted.split(".")
    if parts[0] in aliases:
        return ".".join([aliases[parts[0]]] + parts[1:])
    return dotted
