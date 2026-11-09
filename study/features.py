"""Extract per-test-case code regions and a propagator-template id from OWASP Benchmark Java."""
import hashlib
import re

def _norm(line):
    line = re.sub(r"BenchmarkTest\d+", "T", line)
    line = re.sub(r'"[^"]*"', "S", line)
    line = re.sub(r"\d+", "N", line)
    line = re.sub(r"//.*$", "", line)
    return re.sub(r"\s+", " ", line).strip()

def propagator_block(src):
    """Lines from the 'String bar' declaration up to the next blank line.
    If the dataflow lives in a helper (doSomething), use that method body instead."""
    lines = src.splitlines()
    m = re.search(r"doSomething\([^)]*\)[^{]*\{", src)
    if m:
        body = src[m.end():]
        depth, out = 1, []
        for ch_line in body.splitlines():
            depth += ch_line.count("{") - ch_line.count("}")
            if depth <= 0:
                break
            out.append(ch_line)
        block = out
    else:
        block, on = [], False
        for l in lines:
            if re.search(r"\bString bar\b", l):
                on = True
            if on:
                if not l.strip():
                    break
                block.append(l)
    return [b for b in (_norm(x) for x in block) if b]

def template_id(src):
    return hashlib.md5("\n".join(propagator_block(src)).encode()).hexdigest()[:10]
