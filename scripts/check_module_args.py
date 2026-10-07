#!/usr/bin/env python3
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""Check the module arguments of Ansible tasks against each module's options.

ansible-lint does not catch unknown module arguments (for example
`k8s_info: label_selector:` instead of `label_selectors:`), and the static
test playbooks never run those tasks. This script reads every task in the
given role task/handler/test files and playbooks and reports arguments that are
neither an option nor an alias of the module (from `ansible-doc -j`).

Usage (repo root, with the collections of requirements installed):
  python3 scripts/check_module_args.py roles playbooks
Exits 1 if any unknown argument or unresolvable module is found.
"""

import json
import pathlib
import subprocess
import sys

import yaml
from ansible.playbook.block import Block
from ansible.playbook.handler import Handler
from ansible.playbook.task import Task

# Task and block keywords; every other key of a task is the module.
KEYWORDS = set(Task.fattributes) | set(Block.fattributes) | set(Handler.fattributes) | {"local_action"}
# Free-form modules, and modules that pass extra arguments on to another
# module. Matched by full name (short or ansible.builtin.).
SKIP = {
    "add_host", "command", "group_by", "meta", "package", "raw", "script",
    "set_fact", "set_stats", "shell",
}
SKIP |= {"ansible.builtin." + m for m in SKIP}
PLAY_SECTIONS = ("pre_tasks", "tasks", "post_tasks", "handlers")


def is_play(item):
    return isinstance(item, dict) and ("hosts" in item or "import_playbook" in item)


def task_files(paths):
    for p in map(pathlib.Path, paths):
        files = [p] if p.is_file() else sorted(list(p.rglob("*.yaml")) + list(p.rglob("*.yml")))
        for f in files:
            parts = set(f.parts)
            if p.is_file() or parts & {"tasks", "handlers", "playbooks", "tests"}:
                yield f


def walk(tasks, found, unchecked):
    for t in tasks or []:
        if not isinstance(t, dict):
            continue
        if "local_action" in t or "action" in t:
            unchecked.append(str(t.get("local_action") or t.get("action")).split()[0])
        for k in ("block", "rescue", "always"):
            walk(t.get(k), found, unchecked)
        for mod in (k for k in t if k not in KEYWORDS):
            if mod in SKIP or mod.startswith("with_"):
                continue
            args = t[mod]
            if args is None:
                args = {}
            if not isinstance(args, dict):
                # key=value strings and templated args cannot be checked.
                if not isinstance(args, str) or "=" in args or "{{" in args:
                    unchecked.append(mod)
                continue
            extra = t.get("args") if isinstance(t.get("args"), dict) else {}
            found.append((t.get("name", "?"), mod, set(args) | set(extra)))


def options(modules):
    out = subprocess.run(["ansible-doc", "-j", *sorted(modules)], capture_output=True, text=True)
    try:
        docs = json.loads(out.stdout)
    except json.JSONDecodeError:
        sys.exit(f"ansible-doc failed (rc={out.returncode}):\n{out.stderr.strip()}")
    spec = {}
    for mod in modules:
        doc = (docs.get(mod) or {}).get("doc")
        if doc is None:
            continue
        names = set()
        for name, opt in (doc.get("options") or {}).items():
            names.add(name)
            names.update(opt.get("aliases") or [])
        spec[mod] = names
    return spec


def main(argv):
    calls, unchecked = [], []
    for f in task_files(argv or ["roles", "playbooks"]):
        try:
            data = yaml.safe_load(f.read_text())
        except yaml.YAMLError as e:
            print(f"{f}: cannot parse YAML: {e}")
            return 1
        if not isinstance(data, list):
            continue
        found = []
        if any(is_play(item) for item in data):
            for play in data:
                if isinstance(play, dict):
                    for s in PLAY_SECTIONS:
                        walk(play.get(s), found, unchecked)
        else:
            walk(data, found, unchecked)
        calls += [(f, *c) for c in found]

    spec = options({mod for _, _, mod, _ in calls})
    problems = []
    for f, name, mod, args in calls:
        if mod not in spec:
            problems.append(f"{f}: {name}: module '{mod}' not found by ansible-doc")
        elif args - spec[mod] - {"_raw_params"}:
            problems.append(f"{f}: {name}: {mod}: unknown argument(s) {sorted(args - spec[mod] - {'_raw_params'})}")
    if not calls:
        problems.append(f"no module calls found under {argv}")
    print("\n".join(sorted(problems)) or f"OK: {len(calls)} module calls, {len(spec)} modules")
    if unchecked:
        print(f"not checked (free-form or templated args): {len(unchecked)}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
