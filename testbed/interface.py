# This module contains the code related to the interface of the testbed. This
# includes functions to print styled headers, footers, and section dividers
# for the various variations of the testbed. 

# ANSI color codes
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
DIM    = "\033[2m"

WIDTH = 60


def _format_duration(value):
    if value is None:
        return "N/A"
    return f"{value:.3f}s"


def _format_size(value):
    if value is None:
        return "N/A"
    return f"{value:.0f} B ({value / 1024:.2f} KB)"

def print_header(variations: list):
    """Print a styled header for the testbed."""
    print()
    print(CYAN + BOLD + "=" * WIDTH + RESET)
    print(CYAN + BOLD + "  Verifiable ZKP Testbed".center(WIDTH) + RESET)
    print(CYAN + BOLD + "  DISSECT Project".center(WIDTH) + RESET)
    print(CYAN + BOLD + "=" * WIDTH + RESET)
    print(DIM + f"  Registered variations: {', '.join(variations)}".ljust(WIDTH) + RESET)
    print(CYAN + DIM + "-" * WIDTH + RESET)
    print()

def print_variation_header(variation: str, index: int, total: int):
    """Print a styled section header for a variation."""
    print(YELLOW + BOLD + f"  [{index}/{total}] Running: {variation.upper()}".ljust(WIDTH) + RESET)
    print(YELLOW + DIM + "  " + "-" * (WIDTH - 2) + RESET)

def print_variation_footer(variation: str):
    """Print a styled section footer for a variation."""
    print(GREEN + f"  ✓ Completed: {variation}".ljust(WIDTH) + RESET)
    print()

def print_footer(total: int):
    """Print a styled footer for the testbed."""
    print(CYAN + DIM + "-" * WIDTH + RESET)
    print(GREEN + BOLD + f"  All {total} variation(s) completed successfully.".ljust(WIDTH) + RESET)
    print(CYAN + BOLD + "=" * WIDTH + RESET)
    print()


def print_summary_table(summary: list):
    """Print a summary table with one row per variation."""
    columns = [
        ("Variation", 14),
        ("Proof Generation Time", 30),
        ("Proof Size", 22),
        ("Verification Time", 20),
    ]
    table_width = sum(width for _, width in columns) + len(columns) + 1

    def row(values: list):
        cells = [f" {value:<{width - 2}}" for value, (_, width) in zip(values, columns)]
        return "|" + "|".join(cells) + "|"

    print(CYAN + BOLD + "  Summary" + RESET)
    print(CYAN + DIM + "-" * table_width + RESET)
    print(BOLD + row([header for header, _ in columns]) + RESET)
    print(CYAN + DIM + "-" * table_width + RESET)

    for item in summary:
        print(row([
            item["variation"],
            _format_duration(item["proof_time"]),
            _format_size(item["proof_size"]),
            _format_duration(item["verification_time"]),
        ]))

    print(CYAN + DIM + "-" * table_width + RESET)
    print()
