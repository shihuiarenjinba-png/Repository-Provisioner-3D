"""Deterministic per-product repository names. No remote GitHub writes.

A later privileged workflow must verify source SHA, CI, license and QA evidence
before using the proposed name. This tool does NOT create repositories.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import sys

SLUG=re.compile(r"^[a-z][a-z0-9-]{3,40}$")
GIT_SHA=re.compile(r"^[0-9a-f]{40}$")
KINDS={"app","game","3d-game"}
OWNER="shihuiarenjinba-png"

def propose(product:dict,kind:str)->dict:
    if kind not in KINDS:raise ValueError("unsupported Factory kind")
    if not isinstance(product,dict) or product.get("kind")!=kind:
        raise ValueError("source kind mismatch")
    slug=product.get("slug")
    src=product.get("source_sha")
    if not isinstance(slug,str) or not SLUG.fullmatch(slug):
        raise ValueError("invalid product slug")
    if not isinstance(src,str) or not GIT_SHA.fullmatch(src):
        raise ValueError("source commit must be exact verified Git SHA")
    if product.get("status") not in ("WINDOWS_QA_REQUIRED","GODOT_QA_REQUIRED"):
        raise ValueError("only QA candidate names accepted")
    repo={"app":"app","game":"game","3d-game":"game3d"}[kind]+"-"+slug
    suffix=sha256((kind+":"+slug+":"+src).encode()).hexdigest()[:10]
    name=(repo[:75].rstrip("-")+"-"+suffix).lower()
    return {"schema_version":1,"source_type":kind,"source_sha":src,
            "product_slug":slug,"proposed_repository":OWNER+"/"+name,
            "state":"NAME_PROPOSAL_ONLY","create_allowed":False,
            "store_submission_allowed":False,
            "note":"Availability, ownership, source evidence and QA still need verification."}

def main(argv=None):
    p=argparse.ArgumentParser()
    p.add_argument("--kind",choices=sorted(KINDS),required=True)
    p.add_argument("--input",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args(argv)
    try:
        data=json.loads(args.input.read_text(encoding="utf-8"))
        proposal=propose(data,args.kind)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(proposal,indent=2)+"\n",encoding="utf-8")
        print(proposal["proposed_repository"],proposal["state"])
        return 0
    except (OSError,ValueError,TypeError) as e:
        print("HOLD:",str(e),file=sys.stderr)
        return 2
if __name__=="__main__":
    sys.exit(main())
