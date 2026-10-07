#!/usr/bin/env python3
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""Validate objects against a CRD's openAPIV3Schema, strictly (offline).

    crd_validate.py <rendered-chart.yaml> <objects.yaml>

Every object in objects.yaml is checked against the schema of its kind and
apiVersion taken from the CustomResourceDefinitions in rendered-chart.yaml (the
`helm template` output). The API server prunes unknown fields silently, so a
misspelt field would be lost without an error; here every object schema that
lists properties (and neither additionalProperties nor
x-kubernetes-preserve-unknown-fields) rejects unknown fields. Needs PyYAML and
jsonschema. Exit 1 on any error.
"""
import copy
import sys

import jsonschema
import yaml


def strict(schema):
    s = copy.deepcopy(schema)

    def walk(node):
        if isinstance(node, dict):
            if (node.get("type") == "object" and "properties" in node
                    and "additionalProperties" not in node
                    and not node.get("x-kubernetes-preserve-unknown-fields")):
                node["additionalProperties"] = False
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(s)
    # metadata is validated by the API server, not by the CRD schema.
    s.setdefault("properties", {})["metadata"] = {"type": "object"}
    return s


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    with open(sys.argv[1]) as f:
        docs = [d for d in yaml.safe_load_all(f) if d]
    schemas = {}
    for d in docs:
        if d.get("kind") != "CustomResourceDefinition":
            continue
        group, kind = d["spec"]["group"], d["spec"]["names"]["kind"]
        for v in d["spec"]["versions"]:
            if v.get("served"):
                schemas[(group + "/" + v["name"], kind)] = strict(v["schema"]["openAPIV3Schema"])
    with open(sys.argv[2]) as f:
        objects = [o for o in yaml.safe_load_all(f) if o]
    if not objects:
        print("no objects to validate", file=sys.stderr)
        return 1
    errors = 0
    for o in objects:
        key = (o.get("apiVersion"), o.get("kind"))
        name = o.get("metadata", {}).get("name", "?")
        if key not in schemas:
            print(f"FAIL {key[1]}/{name}: no served CRD version for {key[0]}")
            errors += 1
            continue
        found = sorted(jsonschema.Draft7Validator(schemas[key]).iter_errors(o), key=lambda e: list(e.path))
        for e in found:
            print(f"FAIL {key[1]}/{name}: {'.'.join(str(p) for p in e.path) or '<root>'}: {e.message}")
        errors += len(found)
        if not found:
            print(f"ok   {key[1]}/{name}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
