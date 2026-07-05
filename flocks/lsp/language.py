"""
LSP Language mappings

Maps file extensions to language IDs for LSP servers.
Based on Flocks' ported src/lsp/language.ts
"""

from typing import Dict, Optional


# Extension to language ID mapping
# Matches TypeScript LANGUAGE_EXTENSIONS
LANGUAGE_EXTENSIONS: Dict[str, str] = {
    ".abap": "abap",
    ".bat": "bat",
    ".bib": "bibtex",
    ".bibtex": "bibtex",
    ".clj": "clojure",
    ".cljs": "clojure",
    ".cljc": "clojure",
    ".edn": "clojure",
    ".coffee": "coffeescript",
    ".c": "c",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".cc": "cpp",
    ".c++": "cpp",
    ".cs": "csharp",
    ".css": "css",
    ".d": "d",
    ".pas": "pascal",
    ".pascal": "pascal",
    ".diff": "diff",
    ".patch": "diff",
    ".dart": "dart",
    ".dockerfile": "dockerfile",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".ets": "typescript",
    ".hrl": "erlang",
    ".fs": "fsharp",
    ".fsi": "fsharp",
    ".fsx": "fsharp",
    ".fsscript": "fsharp",
    ".gitcommit": "git-commit",
    ".gitrebase": "git-rebase",
    ".go": "go",
    ".groovy": "groovy",
    ".gleam": "gleam",
    ".hbs": "handlebars",
    ".handlebars": "handlebars",
    ".hs": "haskell",
    ".lhs": "haskell",
    ".html": "html",
    ".htm": "html",
    ".ini": "ini",
    ".java": "java",
    ".js": "javascript",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".jsx": "javascriptreact",
    ".json": "json",
    ".tex": "latex",
    ".latex": "latex",
    ".less": "less",
    ".lua": "lua",
    ".makefile": "makefile",
    "makefile": "makefile",
    ".md": "markdown",
    ".markdown": "markdown",
    ".m": "objective-c",
    ".mm": "objective-cpp",
    ".pl": "perl",
    ".pm": "perl",
    ".pm6": "perl6",
    ".php": "php",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".pug": "jade",
    ".jade": "jade",
    ".py": "python",
    ".r": "r",
    ".cshtml": "razor",
    ".razor": "razor",
    ".rb": "ruby",
    ".rake": "ruby",
    ".gemspec": "ruby",
    ".ru": "ruby",
    ".erb": "erb",
    ".html.erb": "erb",
    ".js.erb": "erb",
    ".css.erb": "erb",
    ".json.erb": "erb",
    ".rs": "rust",
    ".scss": "scss",
    ".sass": "sass",
    ".scala": "scala",
    ".shader": "shaderlab",
    ".sh": "shellscript",
    ".bash": "shellscript",
    ".zsh": "shellscript",
    ".ksh": "shellscript",
    ".sql": "sql",
    ".svelte": "svelte",
    ".swift": "swift",
    ".ts": "typescript",
    ".tsx": "typescriptreact",
    ".mts": "typescript",
    ".cts": "typescript",
    ".mtsx": "typescriptreact",
    ".ctsx": "typescriptreact",
    ".xml": "xml",
    ".xsl": "xsl",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".vue": "vue",
    ".zig": "zig",
    ".zon": "zig",
    ".astro": "astro",
    ".ml": "ocaml",
    ".mli": "ocaml",
    ".tf": "terraform",
    ".tfvars": "terraform-vars",
    ".hcl": "hcl",
    ".nix": "nix",
    ".typ": "typst",
    ".typc": "typst",
}


def get_language_id(extension: str) -> str:
    """
    Get language ID for file extension
    
    Args:
        extension: File extension (with or without leading dot)
        
    Returns:
        Language ID or "plaintext" if unknown
    """
    # Normalize extension
    if not extension.startswith("."):
        extension = "." + extension
    
    return LANGUAGE_EXTENSIONS.get(extension.lower(), "plaintext")


def get_language_for_file(filepath: str) -> str:
    """
    Get language ID for a file path
    
    Args:
        filepath: File path
        
    Returns:
        Language ID
    """
    import os
    
    # Handle special filenames without extension
    basename = os.path.basename(filepath).lower()
    if basename in LANGUAGE_EXTENSIONS:
        return LANGUAGE_EXTENSIONS[basename]
    
    # Get extension
    _, ext = os.path.splitext(filepath)
    return get_language_id(ext)


def get_extensions_for_language(language_id: str) -> list:
    """
    Get all extensions for a language ID
    
    Args:
        language_id: Language ID
        
    Returns:
        List of extensions
    """
    return [ext for ext, lang in LANGUAGE_EXTENSIONS.items() if lang == language_id]


# Symbol kind enum matching LSP specification
class SymbolKind:
    """LSP Symbol kinds"""
    File = 1
    Module = 2
    Namespace = 3
    Package = 4
    Class = 5
    Method = 6
    Property = 7
    Field = 8
    Constructor = 9
    Enum = 10
    Interface = 11
    Function = 12
    Variable = 13
    Constant = 14
    String = 15
    Number = 16
    Boolean = 17
    Array = 18
    Object = 19
    Key = 20
    Null = 21
    EnumMember = 22
    Struct = 23
    Event = 24
    Operator = 25
    TypeParameter = 26


# Commonly searched symbol kinds
SEARCHABLE_SYMBOL_KINDS = [
    SymbolKind.Class,
    SymbolKind.Function,
    SymbolKind.Method,
    SymbolKind.Interface,
    SymbolKind.Variable,
    SymbolKind.Constant,
    SymbolKind.Struct,
    SymbolKind.Enum,
]


# Diagnostic severity levels
class DiagnosticSeverity:
    """LSP Diagnostic severity levels"""
    Error = 1
    Warning = 2
    Information = 3
    Hint = 4
    
    @classmethod
    def to_string(cls, severity: int) -> str:
        """Convert severity to string"""
        return {
            1: "ERROR",
            2: "WARN",
            3: "INFO",
            4: "HINT",
        }.get(severity, "UNKNOWN")
