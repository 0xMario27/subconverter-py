"""String manipulation utilities ported from C++ utils/string.cpp."""

import re
from typing import List


def starts_with(s: str, prefix: str) -> bool:
    """Check if string starts with prefix."""
    return s.startswith(prefix)


def ends_with(s: str, suffix: str) -> bool:
    """Check if string ends with suffix."""
    return s.endswith(suffix)


def trim(s: str) -> str:
    """Trim whitespace from both ends."""
    return s.strip()


def split(s: str, delimiter: str = ",") -> List[str]:
    """Split string by delimiter (default comma)."""
    if not s:
        return []
    return s.split(delimiter)


def join(lst: List[str], delimiter: str = ",") -> str:
    """Join strings with delimiter."""
    return delimiter.join(lst)


def replace_all(s: str, old: str, new: str) -> str:
    """Replace all occurrences of old with new."""
    return s.replace(old, new)


def replace_all_distinct(s: str, old: str, new: str) -> str:
    """Replace all distinct occurrences (same as replace_all in Python)."""
    return s.replace(old, new)


def str_find(s: str, sub: str) -> int:
    """Find substring, return -1 if not found."""
    return s.find(sub)


def count_least(s: str, ch: str, n: int) -> bool:
    """Check if string contains at least n occurrences of character."""
    return s.count(ch) >= n


def get_line_break(content: str) -> str:
    """Detect line break character used in content."""
    if '\r\n' in content:
        return '\r\n'
    elif '\n' in content:
        return '\n'
    return '\r'


def trim_of(s: str, ch: str) -> str:
    """Trim specific character from both ends."""
    if isinstance(ch, str) and len(ch) > 0:
        return s.strip(ch)
    return s


def is_link(s: str) -> bool:
    """Check if string is a URL."""
    return s.startswith("http://") or s.startswith("https://")


def remove_brackets(s: str) -> str:
    """Remove brackets from hostname (IPv6 address)."""
    result = s
    left = result.find('[')
    right = result.find(']')
    if left != -1 and right != -1 and right > left:
        result = result[:right] + result[right + 1:]
        result = result[:left] + result[left + 1:]
    return result


def reg_find(s: str, pattern: str) -> bool:
    """Check if pattern matches anywhere in string."""
    try:
        return bool(re.search(pattern, s))
    except re.error:
        return False


def reg_match(s: str, pattern: str) -> bool:
    """Check if pattern matches entire string."""
    try:
        return bool(re.match(pattern, s))
    except re.error:
        return False


def reg_valid(pattern: str) -> bool:
    """Check if regex pattern is valid."""
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def reg_replace(s: str, pattern: str, repl: str, count: int = 0) -> str:
    """Regex replace."""
    try:
        return re.sub(pattern, repl, s, count=count)
    except re.error:
        return s


def reg_get_match(s: str, pattern: str, *groups) -> bool:
    """Get regex match groups from a string. Returns list of matched groups."""
    try:
        m = re.search(pattern, s)
        if not m:
            return None
        result = list(m.groups())
        return result
    except re.error:
        return None


def is_ipv4(s: str) -> bool:
    """Check if string is a valid IPv4 address."""
    parts = s.split('.')
    if len(parts) != 4:
        return False
    for p in parts:
        try:
            n = int(p)
            if n < 0 or n > 255:
                return False
        except ValueError:
            return False
    return True


def file_exist(path: str) -> bool:
    """Check if file exists."""
    import os
    return os.path.isfile(path)


def file_get(path: str, scope_limit: bool = True) -> str:
    """Read file content."""
    import os
    try:
        if not scope_limit or os.path.isfile(path):
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
    except Exception:
        pass
    return ""


def file_write(path: str, content: str, overwrite: bool = True) -> bool:
    """Write content to file."""
    import os
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        mode = 'w' if overwrite else 'a'
        with open(path, mode, encoding='utf-8') as f:
            f.write(content)
        return True
    except Exception:
        return False


def to_int(s: str, default: int = 0) -> int:
    """Convert string to int with default."""
    try:
        return int(s)
    except (ValueError, TypeError):
        return default


def file_copy(src: str, dst: str) -> bool:
    """Copy file."""
    import shutil
    try:
        shutil.copy2(src, dst)
        return True
    except Exception:
        return False
