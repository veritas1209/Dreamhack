import sys
import pickle

HEXS = "0123456789abcdef"
HEX = frozenset(HEXS)


# ---------------------------------------------------------------------------
# 1) Parse the binary grammar format
# ---------------------------------------------------------------------------
# Layout (all multi-byte ints are big-endian, 2 bytes):
#   header : "RULES" + 7 bytes                       (first rule starts at 0x0c)
#   rule   : <namelen><name><altcount>{alt}<msglen><message>
#   alt    : <elemcount>{element}
#   element: 01 <char>                 -> literal
#            02 <namelen> <name>       -> reference to another rule
def parse_rules(path):
    data = open(path, "rb").read()
    assert data[:5] == b"RULES", "bad magic; not a RULES file"

    def u16(p):
        return (data[p] << 8) | data[p + 1]

    rules, msgs, order = {}, {}, []
    pos = 12  # skip "RULES" + 7 header bytes
    while pos < len(data):
        if pos + 2 > len(data):
            break
        nl = u16(pos); pos += 2
        name = data[pos:pos + nl].decode("latin1"); pos += nl
        altc = u16(pos); pos += 2
        alts = []
        for _ in range(altc):
            ec = u16(pos); pos += 2
            elems = []
            for _ in range(ec):
                t = data[pos]; pos += 1
                if t == 1:                       # literal char
                    elems.append(("lit", chr(data[pos]))); pos += 1
                elif t == 2:                     # reference
                    ln = u16(pos); pos += 2
                    elems.append(("ref", data[pos:pos + ln].decode("latin1"))); pos += ln
                else:
                    raise SystemExit("bad element type %d at %s" % (t, hex(pos - 1)))
            alts.append(elems)
        ml = u16(pos); pos += 2
        msgs[name] = data[pos:pos + ml].decode("latin1"); pos += ml
        rules[name] = alts
        order.append(name)

    assert pos == len(data), "parser did not consume the whole file (%s/%s)" % (hex(pos), hex(len(data)))
    return rules, msgs, order


# ---------------------------------------------------------------------------
# 2) Helpers: rule length and per-position projection (allowed char sets)
# ---------------------------------------------------------------------------
def make_helpers(rules):
    Lmemo = {}
    def length(n):
        if n in Lmemo:
            return Lmemo[n]
        L = 0
        for el in rules[n][0]:               # all alts share the same length
            L += 1 if el[0] == "lit" else (1 if el[1] == "any" else length(el[1]))
        Lmemo[n] = L
        return L

    Pmemo = {}
    def proj(n):
        """Return a list of `length(n)` frozensets: the union, per position, of
        every character that can appear there across all alternatives."""
        if n in Pmemo:
            return Pmemo[n]
        L = length(n)
        sets = [set() for _ in range(L)]
        for alt in rules[n]:
            off = 0
            for el in alt:
                if el[0] == "lit":
                    sets[off].add(el[1]); off += 1
                elif el[1] == "any":
                    sets[off] |= HEX; off += 1
                else:
                    for j, s in enumerate(proj(el[1])):
                        sets[off + j] |= s
                    off += length(el[1])
        res = [frozenset(s) for s in sets]
        Pmemo[n] = res
        return res

    return length, proj


# ---------------------------------------------------------------------------
# 3) Build the 91 "boxes" (per-position allowed sets) from filter alternatives
# ---------------------------------------------------------------------------
def build_boxes(rules, length, proj):
    boxes = []
    for alt in rules["filter"]:
        pos = []
        for el in alt:
            if el[0] == "lit":
                pos.append(frozenset(el[1]))
            elif el[1] == "any":
                pos.append(HEX)
            else:
                pos.extend(proj(el[1]))
        assert len(pos) == 64, "filter alternative does not cover 64 positions (%d)" % len(pos)
        boxes.append(pos)
    return boxes


# ---------------------------------------------------------------------------
# 4) Solve the CSP: find every 64-hex string that escapes ALL boxes
# ---------------------------------------------------------------------------
def solve(boxes, max_solutions=6):
    # For each box keep only its restricted positions (allowed-set size < 16).
    cons = []
    for box in boxes:
        cons.append([(i, set(s)) for i, s in enumerate(box) if len(s) < 16])

    def propagate(domains):
        """Unit-propagation on 'at least one restricted position must escape its
        box's allowed set'. Returns False on contradiction."""
        changed = True
        while changed:
            changed = False
            for rc in cons:
                satisfied = False
                candidates = []
                for pos, allowed in rc:
                    if not (domains[pos] & allowed):
                        satisfied = True; break          # this pos always escapes
                    if domains[pos] - allowed:
                        candidates.append((pos, allowed))  # this pos *can* escape
                if satisfied:
                    continue
                if not candidates:
                    return False                          # box unavoidable -> dead end
                if len(candidates) == 1:                  # forced: this pos must escape
                    pos, allowed = candidates[0]
                    new = domains[pos] - allowed
                    if new != domains[pos]:
                        domains[pos] = new; changed = True
                        if not new:
                            return False
        return True

    domains = [set(HEX) for _ in range(64)]
    if not propagate(domains):
        return []

    solutions = []
    def search(domains):
        idx, best = -1, 99
        for i, d in enumerate(domains):
            if 1 < len(d) < best:
                best = len(d); idx = i
        if idx == -1:                                     # all singletons -> a solution
            solutions.append("".join(next(iter(d)) for d in domains)); return
        for v in sorted(domains[idx]):
            nd = [set(d) for d in domains]
            nd[idx] = {v}
            if propagate(nd):
                search(nd)
            if len(solutions) > max_solutions:
                return

    search(domains)
    return solutions


# ---------------------------------------------------------------------------
# 5) Optional: verify a candidate against the real binary
# ---------------------------------------------------------------------------
def verify_with_binary(binary, rules_path, candidate):
    import subprocess
    out = subprocess.run(
        [binary, rules_path],
        input=candidate + "\n\n",
        capture_output=True, text=True,
    ).stdout
    return out


def main():
    rules_path = sys.argv[1] if len(sys.argv) > 1 else "rules"
    binary = sys.argv[2] if len(sys.argv) > 2 else None

    rules, msgs, order = parse_rules(rules_path)
    print("[*] parsed %d rules" % len(rules))
    print("[*] start rule 'line' alternatives:", rules["line"])
    print("[*] 'correct' message:", repr(msgs.get("correct", "")))

    length, proj = make_helpers(rules)
    boxes = build_boxes(rules, length, proj)
    print("[*] built %d filter boxes" % len(boxes))

    sols = solve(boxes)
    print("[*] solutions found:", len(sols))
    for s in sols:
        print("    " + s)

    if len(sols) == 1:
        flag = "DH{%s}" % sols[0]
        print("\n[+] FLAG =", flag)
        if binary:
            print("\n[*] verifying against binary ...")
            print(verify_with_binary(binary, rules_path, sols[0]).rstrip())


if __name__ == "__main__":
    main()