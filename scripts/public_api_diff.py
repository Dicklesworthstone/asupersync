#!/usr/bin/env python3
"""Public API surface diff over rustdoc JSON (asupersync-bi2462.139).

AGENTS.md makes v0.4.3 compatibility a hard release gate, and until now nothing
compared the public surface below the crate root. This is that comparison.

  surface JSON       One normalized line per public fact: every item reachable
                     through public modules and `pub use` re-exports, its
                     signature, public fields and variants, trait items, inherent
                     methods, and the trait impls of each public type, including
                     auto traits, each with its impl's generics. Blanket impls,
                     named lifetimes in impl headers and the unstable auto traits
                     (Freeze, UnsafeUnpin) are left out: callers cannot observe them.
  diff BASE HEAD     Compare two rustdoc JSON files and print
                       -   a fact whose identity is gone (item, impl, method, field)
                       !   a breaking addition: a new required trait item, a field
                           on a constructible struct, a variant on an exhaustive enum
                       ~-/~+  the same identity with a different signature or bounds
                           (review: a relaxation is compatible, a tightening is not)
                       +   an addition
                     Exit 1 when anything is -, ! or ~; 0 when the surface only grew.

The lane (rustdoc JSON needs the pinned nightly; both sides must use the SAME
toolchain so the JSON format_version matches):

  cargo +nightly-2026-08-31 rustdoc -p asupersync --lib [--features ...] \
      -- -Zunstable-options --output-format json          # -> target/doc/asupersync.json

Build BASE from the crates.io package of the release (curl
https://static.crates.io/crates/asupersync/asupersync-0.4.3.crate, extract, append an
empty `[workspace]` table, run the same command in it), HEAD from the tree under
test, then run `python3 scripts/public_api_diff.py diff base.json head.json`.
`cargo rustdoc` is not an RCH-interceptable command; run the whole sequence as
`rch exec --job --result-dir <dir> -- bash -c '...'`, which downloads its own clean
sources because `--job` takes no `--base`. The contract test
tests/public_api_diff_contract.rs renders its fixtures with the pinned rustdoc, so
a JSON format change fails there first.
"""

from __future__ import annotations

import json
import sys
from typing import Any

MAX_DEPTH = 24
# Auto traits stable code cannot name or bound on; their presence is not part of the compatible surface.
# (StructuralPartialEq is kept: losing it forbids using the type's constants as match patterns.)
UNSTABLE_AUTO_TRAITS = frozenset({"core::marker::Freeze", "core::marker::UnsafeUnpin"})


class Surface:
    def __init__(self, doc: dict[str, Any]) -> None:
        self.doc = doc
        self.index = doc["index"]
        self.paths = doc.get("paths", {})
        self.crate = self.item(doc["root"])["name"]
        self.lines: set[str] = set()

    def item(self, ident: Any) -> dict[str, Any] | None:
        if ident is None:
            return None
        return self.index.get(str(ident))

    # ---------------------------------------------------------------- types
    def path_name(self, path: dict[str, Any]) -> str:
        summary = self.paths.get(str(path.get("id")))
        if summary and summary.get("crate_id") != 0:
            name = "::".join(summary["path"])
        else:
            name = path["path"].split("::")[-1]
        return name + self.args(path.get("args"))

    def args(self, args: Any) -> str:
        if not args:
            return ""
        if "angle_bracketed" in args:
            ab = args["angle_bracketed"]
            parts = [self.arg(a) for a in ab.get("args", [])]
            for c in ab.get("constraints", []):
                binding = c.get("binding", {})
                if "equality" in binding:
                    term = binding["equality"]
                    value = self.ty(term["type"]) if "type" in term else json.dumps(term, sort_keys=True)
                    parts.append(f"{c['name']}{self.args(c.get('args'))} = {value}")
                else:
                    parts.append(f"{c['name']}: {self.bounds(binding.get('constraint', []))}")
            return f"<{', '.join(parts)}>" if parts else ""
        if "parenthesized" in args:
            p = args["parenthesized"]
            out = f" -> {self.ty(p['output'])}" if p.get("output") else ""
            return f"({', '.join(self.ty(t) for t in p['inputs'])}){out}"
        return f"<{json.dumps(args, sort_keys=True)}>"

    def arg(self, arg: Any) -> str:
        if isinstance(arg, str):
            return arg
        if "lifetime" in arg:
            return arg["lifetime"]
        if "type" in arg:
            return self.ty(arg["type"])
        if "const" in arg:
            return arg["const"].get("expr", "{const}")
        return json.dumps(arg, sort_keys=True)

    def bound(self, bound: dict[str, Any]) -> str:
        if "trait_bound" in bound:
            tb = bound["trait_bound"]
            prefix = {"maybe": "?", "maybe_const": "~const "}.get(tb.get("modifier", "none"), "")
            hrtb = self.generic_params(tb.get("generic_params", []))
            return f"{'for' + hrtb + ' ' if hrtb else ''}{prefix}{self.path_name(tb['trait'])}"
        if "outlives" in bound:
            return bound["outlives"]
        return json.dumps(bound, sort_keys=True)

    def bounds(self, bounds: list[dict[str, Any]]) -> str:
        return " + ".join(sorted(self.bound(b) for b in bounds))

    def ty(self, ty: Any) -> str:
        if ty is None:
            return "()"
        if isinstance(ty, str):
            return ty
        (kind, value), = ty.items()
        if kind == "resolved_path":
            return self.path_name(value)
        if kind == "generic" or kind == "primitive":
            return value
        if kind == "tuple":
            return f"({', '.join(self.ty(t) for t in value)})"
        if kind == "slice":
            return f"[{self.ty(value)}]"
        if kind == "array":
            return f"[{self.ty(value['type'])}; {value['len']}]"
        if kind == "borrowed_ref":
            life = f"{value['lifetime']} " if value.get("lifetime") else ""
            return f"&{life}{'mut ' if value['is_mutable'] else ''}{self.ty(value['type'])}"
        if kind == "raw_pointer":
            return f"*{'mut' if value['is_mutable'] else 'const'} {self.ty(value['type'])}"
        if kind == "impl_trait":
            return f"impl {self.bounds(value)}"
        if kind == "dyn_trait":
            traits = sorted(self.path_name(t["trait"]) for t in value["traits"])
            life = f" + {value['lifetime']}" if value.get("lifetime") else ""
            return f"dyn {' + '.join(traits)}{life}"
        if kind == "qualified_path":
            trait = value.get("trait")
            self_ty = self.ty(value["self_type"])
            suffix = f"::{value['name']}{self.args(value.get('args'))}"
            if not trait or not trait.get("path"):
                return f"{self_ty}{suffix}"
            return f"<{self_ty} as {self.path_name(trait)}>{suffix}"
        if kind == "function_pointer":
            sig = value["sig"]
            return f"fn({', '.join(self.ty(t) for _, t in sig['inputs'])}) -> {self.ty(sig.get('output'))}"
        return json.dumps(ty, sort_keys=True)

    def generic_params(self, params: list[dict[str, Any]], impl_scope: bool = False) -> str:
        out = []
        for p in params:
            kind = p["kind"]
            if "lifetime" in kind:
                if impl_scope:
                    # Naming a lifetime in an impl header (`impl<'a, P> S<'a, P>` vs `impl<P> S<'_, P>`)
                    # does not change what callers can do.
                    continue
                outlives = kind["lifetime"].get("outlives", [])
                out.append(p["name"] + (f": {' + '.join(outlives)}" if outlives else ""))
            elif "type" in kind:
                t = kind["type"]
                if t.get("is_synthetic"):
                    continue
                b = self.bounds(t.get("bounds", []))
                d = f" = {self.ty(t['default'])}" if t.get("default") else ""
                out.append(p["name"] + (f": {b}" if b else "") + d)
            elif "const" in kind:
                out.append(f"const {p['name']}: {self.ty(kind['const']['type'])}")
        return f"<{', '.join(out)}>" if out else ""

    def generics(self, generics: dict[str, Any] | None, impl_scope: bool = False) -> str:
        if not generics:
            return ""
        text = self.generic_params(generics.get("params", []), impl_scope)
        preds = []
        for w in generics.get("where_predicates", []):
            if "bound_predicate" in w:
                bp = w["bound_predicate"]
                preds.append(f"{self.ty(bp['type'])}: {self.bounds(bp['bounds'])}")
            elif "lifetime_predicate" in w and not impl_scope:
                lp = w["lifetime_predicate"]
                preds.append(f"{lp['lifetime']}: {' + '.join(lp['outlives'])}")
            elif "eq_predicate" in w:
                preds.append(json.dumps(w, sort_keys=True))
        if preds:
            text += f" where {', '.join(sorted(preds))}"
        return text

    def fn_sig(self, f: dict[str, Any]) -> str:
        header = f.get("header", {})
        flags = "".join(w + " " for w, on in (("const", header.get("is_const")), ("async", header.get("is_async")),
                                             ("unsafe", header.get("is_unsafe"))) if on)
        params = self.generic_params(f.get("generics", {}).get("params", []))
        where = self.generics({"params": [], "where_predicates": f.get("generics", {}).get("where_predicates", [])})
        sig = f["sig"]
        inputs = ", ".join(self.ty(t) for _, t in sig["inputs"])
        out = f" -> {self.ty(sig['output'])}" if sig.get("output") is not None else ""
        return f"{flags}fn{params}({inputs}){out}{where}"

    # ---------------------------------------------------------------- walk
    def non_exhaustive(self, item: dict[str, Any]) -> bool:
        return any("non_exhaustive" in json.dumps(a) for a in item.get("attrs", []))

    def emit(self, line: str) -> None:
        self.lines.add(line)

    def record(self, path: str, item: dict[str, Any], depth: int, seen: set[tuple[str, int]]) -> None:
        (kind, inner), = item["inner"].items()
        if kind == "module":
            self.emit(f"mod {path}")
            self.walk_module(path, inner, depth + 1, seen)
        elif kind in ("struct", "union"):
            g = self.generics(inner.get("generics"))
            if kind == "struct":
                shape = inner["kind"]
                if shape == "unit":
                    form, fields = "unit", []
                elif "tuple" in shape:
                    form, fields = "tuple", shape["tuple"]
                else:
                    form, fields = "plain", shape["plain"]["fields"]
                stripped = (shape.get("plain", {}).get("has_stripped_fields", False) if isinstance(shape, dict) else False) \
                    or (form == "tuple" and any(f is None for f in fields))
            else:
                form, fields, stripped = "union", inner["fields"], inner.get("has_stripped_fields", False)
            exhaustive = not stripped and not self.non_exhaustive(item)
            self.emit(f"{kind} {path}{g} [{form}] constructible={exhaustive}")
            for pos, fid in enumerate(fields):
                field = self.item(fid)
                if field is not None:
                    name = field["name"] if form != "tuple" else str(pos)
                    self.emit(f"field {path}.{name}: {self.ty(field['inner']['struct_field'])}")
            self.impls(path, inner.get("impls", []))
        elif kind == "enum":
            self.emit(f"enum {path}{self.generics(inner.get('generics'))} non_exhaustive={self.non_exhaustive(item)}")
            for vid in inner.get("variants", []):
                v = self.item(vid)
                if v is None:
                    continue
                vk = v["inner"]["variant"]["kind"]
                if vk == "plain":
                    shape = ""
                elif "tuple" in vk:
                    shape = "(" + ", ".join(self.ty(self.item(f)["inner"]["struct_field"]) if f is not None else "_"
                                            for f in vk["tuple"]) + ")"
                else:
                    shape = "{" + ", ".join(f"{self.item(f)['name']}: {self.ty(self.item(f)['inner']['struct_field'])}"
                                            for f in vk["struct"]["fields"]) + "}"
                self.emit(f"variant {path}::{v['name']}{shape}")
            self.impls(path, inner.get("impls", []))
        elif kind == "function":
            self.emit(f"fn {path} {self.fn_sig(inner)}")
        elif kind == "trait":
            flags = "".join(w + " " for w, on in (("auto", inner.get("is_auto")), ("unsafe", inner.get("is_unsafe"))) if on)
            sup = self.bounds(inner.get("bounds", []))
            self.emit(f"trait {path}{self.generics(inner.get('generics'))}{': ' + sup if sup else ''} {flags}"
                      f"dyn_compatible={inner.get('is_dyn_compatible')}".rstrip())
            for tid in inner.get("items", []):
                ti = self.item(tid)
                if ti is None:
                    continue
                (tk, tv), = ti["inner"].items()
                if tk == "function":
                    req = "provided" if tv.get("has_body") else "required"
                    self.emit(f"trait_fn {path}::{ti['name']} {req} {self.fn_sig(tv)}")
                elif tk == "assoc_type":
                    self.emit(f"trait_type {path}::{ti['name']}{self.generics(tv.get('generics'))}"
                              f"{': ' + self.bounds(tv.get('bounds', [])) if tv.get('bounds') else ''}"
                              f"{' (default)' if tv.get('type') else ''}")
                elif tk == "assoc_const":
                    self.emit(f"trait_const {path}::{ti['name']}: {self.ty(tv.get('type'))}")
        elif kind == "type_alias":
            self.emit(f"type {path}{self.generics(inner.get('generics'))} = {self.ty(inner['type'])}")
        elif kind == "constant":
            self.emit(f"const {path}: {self.ty(inner['type'])}")
        elif kind == "static":
            self.emit(f"static {'mut ' if inner.get('is_mutable') else ''}{path}: {self.ty(inner['type'])}")
        elif kind in ("macro", "proc_macro"):
            self.emit(f"macro {path}")
        elif kind == "trait_alias":
            self.emit(f"trait_alias {path}")
        else:
            self.emit(f"{kind} {path}")

    def impls(self, path: str, impl_ids: list[Any]) -> None:
        for iid in impl_ids:
            imp = self.item(iid)
            if imp is None:
                continue
            im = imp["inner"]["impl"]
            if im.get("blanket_impl") is not None:
                continue
            impl_generics = self.generics(im.get("generics"), impl_scope=True)
            scope = f" [impl{impl_generics}]" if impl_generics else ""
            if im.get("trait") is None:
                for mid in im.get("items", []):
                    m = self.item(mid)
                    if m is None or m.get("visibility") != "public":
                        continue
                    (mk, mv), = m["inner"].items()
                    if mk == "function":
                        self.emit(f"method {path}::{m['name']}{scope} {self.fn_sig(mv)}")
                    elif mk == "assoc_const":
                        self.emit(f"assoc_const {path}::{m['name']}{scope}: {self.ty(mv.get('type'))}")
                continue
            trait = self.path_name(im["trait"])
            if trait in UNSTABLE_AUTO_TRAITS:
                continue
            neg = "!" if im.get("is_negative") else ""
            self.emit(f"impl {path}: {neg}{trait}{scope}")

    def walk_module(self, prefix: str, module: dict[str, Any], depth: int, seen: set[tuple[str, int]]) -> None:
        if depth > MAX_DEPTH:
            return
        for ident in module.get("items", []):
            item = self.item(ident)
            if item is None:
                continue
            (kind, inner), = item["inner"].items()
            if kind == "impl":
                continue
            if kind == "use":
                target = self.item(inner.get("id"))
                if inner.get("is_glob"):
                    if target is not None and "module" in target["inner"]:
                        self.walk_module(prefix, target["inner"]["module"], depth + 1, seen)
                    elif target is not None and "enum" in target["inner"]:
                        for vid in target["inner"]["enum"]["variants"]:
                            v = self.item(vid)
                            if v is not None:
                                self.emit(f"variant_use {prefix}::{v['name']}")
                    continue
                path = f"{prefix}::{inner['name']}"
                if target is None:
                    self.emit(f"use {path} = {inner.get('source')}")
                    continue
                item = target
            else:
                if item.get("visibility") != "public" or item.get("name") is None:
                    continue
                path = f"{prefix}::{item['name']}"
            key = (path, item["id"])
            if key in seen:
                continue
            seen.add(key)
            self.record(path, item, depth, seen)

    def build(self) -> list[str]:
        root = self.item(self.doc["root"])
        self.walk_module(self.crate, root["inner"]["module"], 0, set())
        return sorted(self.lines)


def surface(path: str) -> list[str]:
    with open(path, encoding="utf-8") as handle:
        doc = json.load(handle)
    return Surface(doc).build()


def breaking_additions(base: set[str], added: list[str]) -> list[str]:
    """Additions that break downstream code even though nothing was removed."""
    traits = {item_name(line) for line in base if line.startswith("trait ")}
    constructible = {item_name(line) for line in base
                     if line.startswith(("struct ", "union ")) and line.endswith("constructible=True")}
    exhaustive = {item_name(line) for line in base
                  if line.startswith("enum ") and line.endswith("non_exhaustive=False")}
    out = []
    for line in added:
        kind = line.split(" ", 1)[0]
        name = item_name(line)
        owner = name.rsplit("::", 1)[0]
        if kind == "trait_fn" and " required " in line and owner in traits:
            out.append(line)
        elif kind == "trait_type" and not line.endswith("(default)") and owner in traits:
            out.append(line)
        elif kind == "field" and name.split(".")[0] in constructible:
            out.append(line)
        elif kind == "variant" and owner in exhaustive:
            out.append(line)
    return out


def item_name(line: str) -> str:
    """The path a surface line is about: generics, impl scope and a trailing `:` removed (never `::`)."""
    name = line.split(" ", 1)[1].split(" ", 1)[0]
    for stop in ("<", "[", "(", "{"):
        name = name.split(stop, 1)[0]
    return name[:-1] if name.endswith(":") and not name.endswith("::") else name


def fact_key(line: str) -> str:
    """The identity of a surface fact without its signature: what must still exist after a change."""
    kind, rest = line.split(" ", 1)
    if kind == "impl":
        path, trait = rest.split(": ", 1)
        return f"impl {path}: {trait.split(' [impl')[0].split('<')[0]}"
    return f"{kind} {item_name(line)}"


def classify(base: set[str], head: set[str]) -> tuple[list[str], list[tuple[list[str], list[str]]], list[str], list[str]]:
    """Split a diff into facts whose identity vanished, facts whose signature changed, breaking additions and plain additions."""
    removed, added = base - head, head - base
    head_keys: dict[str, list[str]] = {}
    for line in head:
        head_keys.setdefault(fact_key(line), []).append(line)
    gone, changed_by_key = [], {}
    for line in sorted(removed):
        key = fact_key(line)
        if key in head_keys:
            changed_by_key.setdefault(key, ([], []))[0].append(line)
        else:
            gone.append(line)
    for line in sorted(added):
        key = fact_key(line)
        if key in changed_by_key:
            changed_by_key[key][1].append(line)
    changed_new = {line for _, new in changed_by_key.values() for line in new}
    breaking = breaking_additions(base, sorted(added))
    plain = [line for line in sorted(added) if line not in changed_new and line not in breaking]
    return gone, [changed_by_key[k] for k in sorted(changed_by_key)], breaking, plain


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "surface":
        sys.stdout.write("".join(line + "\n" for line in surface(argv[1])))
        return 0
    if len(argv) == 3 and argv[0] == "diff":
        base, head = set(surface(argv[1])), set(surface(argv[2]))
        gone, changed, breaking, plain = classify(base, head)
        for line in gone:
            print(f"- {line}")
        for line in breaking:
            print(f"! {line}")
        for old, new in changed:
            for line in old:
                print(f"~- {line}")
            for line in new:
                print(f"~+ {line}")
        for line in plain:
            print(f"+ {line}")
        print(f"# base={len(base)} head={len(head)} removed={len(gone)} breaking_additions={len(breaking)} "
              f"changed={len(changed)} added={len(plain)}", file=sys.stderr)
        return 1 if gone or breaking or changed else 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
