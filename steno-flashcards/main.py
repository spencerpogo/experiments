import sys
import itertools

import lxml.etree as etree
from plover_stroke import BaseStroke


key_fill_on = "#7109AA"
key_fill_off = "#e9d9f2"


def find_by_id(elt, xml_id):
    results = elt.xpath(f"//*[@id = $id]", id=xml_id)
    if len(results) != 1:
        raise AssertionError(
            f"expected {xml_id!r} to return one result, instead got {len(results)}"
        )
    return results[0]


class Stroke(BaseStroke):
    pass


def get_key_classes(key):
    if key == "*":
        return [
            f"{side}Star{height}"
            for side, height in itertools.product(
                ("left", "right"), ("Upper", "Lower")
            )
        ]

    if key == "#":
        return ["rightNumberBar"]

    if len(key) != 2:
        raise AssertionError()

    a, b = key
    if b == "-":
        left = True
        letter = a
    elif a == "-":
        left = False
        letter = b
    else:
        raise AssertionError()

    side = "left" if left else "right"
    return [f"{side}{letter}"]


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.svg> <stroke>")
        sys.exit(1)

    Stroke.setup(
        """
        #
        S- T- K- P- W- H- R-
        A- O-
        *
        -E -U
        -F -R -P -B -L -G -T -S -D -Z
        """.split()
    )
    s = Stroke(sys.argv[2])
    print(s.keys())

    with open(sys.argv[1], "rb") as f:
        svg = etree.parse(f)

    ids = []
    for k in s.keys():
        ids += get_key_classes(k)

    for i in ids:
        key = find_by_id(svg, f"{i}Key")
        print(key.tag)
        key.set("fill", key_fill_on)
    
    new_rule = "background-color: rgb(15, 14, 17);"
    root = svg.getroot()
    assert root.tag.split("}")[-1] == "svg"
    root.set("style", root.get("style", "") + new_rule)

    with open(f"{s}.svg", "wb") as f:
        f.write(etree.tostring(svg, pretty_print=True))


if __name__ == "__main__":
    main()
