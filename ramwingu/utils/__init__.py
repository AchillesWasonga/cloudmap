# ramwingu/utils package

# Re-export the formatter helpers so callers (and tests) can use
# ``from ramwingu import utils; utils.format_output(...)`` without reaching
# into the ``output_formatter`` module directly.
from ramwingu.utils.output_formatter import format_output, format_table

__all__ = ["format_output", "format_table"]
