from __future__ import annotations

from dataclasses import dataclass


class PromQLInjectionError(ValueError):
    """Raised when a PromQL expression cannot be parsed safely."""


@dataclass(frozen=True)
class Token:
    kind: str
    value: str
    start: int
    end: int


@dataclass(frozen=True)
class VectorSelector:
    start: int
    end: int
    text: str


@dataclass(frozen=True)
class PromQLAst:
    selectors: tuple[VectorSelector, ...]


KEYWORDS = {
    "and",
    "bool",
    "by",
    "group_left",
    "group_right",
    "ignoring",
    "offset",
    "on",
    "or",
    "unless",
    "without",
}
AGGREGATORS = {
    "avg",
    "bottomk",
    "count",
    "count_values",
    "group",
    "max",
    "min",
    "quantile",
    "stddev",
    "stdvar",
    "sum",
    "topk",
}
LABEL_LIST_KEYWORDS = {"by", "without", "on", "ignoring", "group_left", "group_right"}


def inject_cluster_label(query: str, cluster_id: str) -> str:
    normalized_query = str(query or "").strip()
    normalized_cluster_id = str(cluster_id or "").strip()
    if not normalized_query:
        raise PromQLInjectionError("query is required")
    if not normalized_cluster_id:
        raise PromQLInjectionError("cluster_id is required")

    ast = PromQLParser(normalized_query).parse()
    if not ast.selectors:
        return normalized_query

    rewritten = normalized_query
    for selector in sorted(ast.selectors, key=lambda item: item.start, reverse=True):
        replacement = _inject_selector(selector.text, normalized_cluster_id)
        rewritten = rewritten[: selector.start] + replacement + rewritten[selector.end :]
    return rewritten


class PromQLParser:
    """Small PromQL lexer/parser focused on vector selector AST nodes.

    The proxy does not need to evaluate PromQL. It needs a syntax-aware AST pass
    that finds vector selector spans while ignoring strings, function names,
    aggregation label lists, range selectors, and binary operator modifiers.
    """

    def __init__(self, query: str):
        self.query = query
        self.tokens = _tokenize(query)

    def parse(self) -> PromQLAst:
        selectors: list[VectorSelector] = []
        covered: list[tuple[int, int]] = []

        for index, token in enumerate(self.tokens):
            if token.value != "{":
                continue
            end_index = self._matching(index, "{", "}")
            previous = _previous_significant(self.tokens, index)
            start = token.start
            if previous and previous.kind == "IDENT" and previous.end == token.start and not _is_keyword(previous):
                start = previous.start
            selectors.append(VectorSelector(start, self.tokens[end_index].end, self.query[start : self.tokens[end_index].end]))
            covered.append((start, self.tokens[end_index].end))

        label_list_depths = self._label_list_depths()
        for index, token in enumerate(self.tokens):
            if token.kind != "IDENT":
                continue
            if _is_covered(token, covered) or _is_keyword(token):
                continue
            if any(token.start >= start and token.end <= end for start, end in label_list_depths):
                continue
            if self._is_function_or_aggregator(index):
                continue
            if self._is_duration_unit(index):
                continue
            selectors.append(VectorSelector(token.start, token.end, token.value))

        unique = {(selector.start, selector.end): selector for selector in selectors}
        return PromQLAst(selectors=tuple(sorted(unique.values(), key=lambda item: item.start)))

    def _matching(self, index: int, open_value: str, close_value: str) -> int:
        depth = 0
        for cursor in range(index, len(self.tokens)):
            value = self.tokens[cursor].value
            if value == open_value:
                depth += 1
            elif value == close_value:
                depth -= 1
                if depth == 0:
                    return cursor
        raise PromQLInjectionError(f"unmatched {open_value}")

    def _label_list_depths(self) -> list[tuple[int, int]]:
        spans: list[tuple[int, int]] = []
        for index, token in enumerate(self.tokens):
            if token.kind != "IDENT" or token.value.lower() not in LABEL_LIST_KEYWORDS:
                continue
            next_token = _next_significant(self.tokens, index)
            if not next_token or next_token.value != "(":
                continue
            end_index = self._matching(self.tokens.index(next_token), "(", ")")
            spans.append((next_token.start, self.tokens[end_index].end))
        return spans

    def _is_function_or_aggregator(self, index: int) -> bool:
        token = self.tokens[index]
        next_token = _next_significant(self.tokens, index)
        if next_token and next_token.value == "(":
            return True
        if token.value.lower() in AGGREGATORS and next_token and next_token.value.lower() in {"by", "without"}:
            return True
        return False

    def _is_duration_unit(self, index: int) -> bool:
        previous = _previous_significant(self.tokens, index)
        token = self.tokens[index]
        return bool(previous and previous.kind == "NUMBER" and previous.end == token.start and token.value in {"ms", "s", "m", "h", "d", "w", "y"})


def _tokenize(query: str) -> list[Token]:
    tokens: list[Token] = []
    index = 0
    while index < len(query):
        char = query[index]
        if char.isspace():
            index += 1
            continue
        if char in "'\"":
            start = index
            quote = char
            index += 1
            escaped = False
            while index < len(query):
                current = query[index]
                index += 1
                if escaped:
                    escaped = False
                    continue
                if current == "\\":
                    escaped = True
                    continue
                if current == quote:
                    break
            else:
                raise PromQLInjectionError("unterminated string literal")
            tokens.append(Token("STRING", query[start:index], start, index))
            continue
        if _is_ident_start(char):
            start = index
            index += 1
            while index < len(query) and _is_ident_part(query[index]):
                index += 1
            tokens.append(Token("IDENT", query[start:index], start, index))
            continue
        if char.isdigit() or char == ".":
            start = index
            index += 1
            while index < len(query) and (query[index].isdigit() or query[index] == "."):
                index += 1
            tokens.append(Token("NUMBER", query[start:index], start, index))
            continue
        if query[index : index + 2] in {"!=", "=~", "!~", ">=", "<=", "=="}:
            tokens.append(Token("OP", query[index : index + 2], index, index + 2))
            index += 2
            continue
        tokens.append(Token("PUNCT", char, index, index + 1))
        index += 1
    return tokens


def _is_ident_start(char: str) -> bool:
    return char.isalpha() or char in "_:"


def _is_ident_part(char: str) -> bool:
    return char.isalnum() or char in "_:"


def _previous_significant(tokens: list[Token], index: int) -> Token | None:
    cursor = index - 1
    while cursor >= 0:
        return tokens[cursor]
    return None


def _next_significant(tokens: list[Token], index: int) -> Token | None:
    cursor = index + 1
    while cursor < len(tokens):
        return tokens[cursor]
    return None


def _is_keyword(token: Token) -> bool:
    return token.value.lower() in KEYWORDS


def _is_covered(token: Token, spans: list[tuple[int, int]]) -> bool:
    return any(token.start >= start and token.end <= end for start, end in spans)


def _inject_selector(selector: str, cluster_id: str) -> str:
    metric, labels = _split_selector(selector)
    cluster_matcher = f'cluster_id="{_escape_label_value(cluster_id)}"'
    if labels is None:
        return f"{metric}{{{cluster_matcher}}}"

    kept = [part for part in _split_label_matchers(labels) if _label_name(part) != "cluster_id"]
    kept.append(cluster_matcher)
    return f"{metric}{{{','.join(kept)}}}"


def _split_selector(selector: str) -> tuple[str, str | None]:
    brace_index = selector.find("{")
    if brace_index < 0:
        return selector, None
    if not selector.endswith("}"):
        raise PromQLInjectionError("invalid vector selector")
    return selector[:brace_index], selector[brace_index + 1 : -1]


def _split_label_matchers(labels: str) -> list[str]:
    parts: list[str] = []
    start = 0
    index = 0
    quote = ""
    escaped = False
    while index < len(labels):
        char = labels[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char == ",":
            part = labels[start:index].strip()
            if part:
                parts.append(part)
            start = index + 1
        index += 1
    if quote:
        raise PromQLInjectionError("unterminated label value")
    last = labels[start:].strip()
    if last:
        parts.append(last)
    return parts


def _label_name(matcher: str) -> str:
    index = 0
    while index < len(matcher) and matcher[index].isspace():
        index += 1
    start = index
    while index < len(matcher) and _is_ident_part(matcher[index]):
        index += 1
    return matcher[start:index]


def _escape_label_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')
