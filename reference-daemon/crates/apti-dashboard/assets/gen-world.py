#!/usr/bin/env python3
"""Generate world.tsv from Natural Earth 1:110m admin-0 countries (public
domain): https://github.com/nvkelso/natural-earth-vector, file
geojson/ne_110m_admin_0_countries.geojson.

Usage: gen-world.py ne_110m_admin_0_countries.geojson > world.tsv

Output: a `#viewBox` line, then one `ISO\tname\tSVG path` line per country,
in the Equal Earth projection. Antarctica is left out.
"""
import json
import math
import sys

A1, A2, A3, A4 = 1.340264, -0.081106, 0.000893, 0.003796
M = math.sqrt(3) / 2
WIDTH = 1000.0
X_MAX = math.pi / (M * A1)  # x at the equator for lon = 180
SCALE = WIDTH / (2 * X_MAX)
LAT_MIN = -58.0


def project(lon, lat):
    lam, phi = math.radians(lon), math.radians(max(lat, LAT_MIN))
    t = math.asin(M * math.sin(phi))
    t2, t6 = t * t, t ** 6
    x = lam * math.cos(t) / (M * (A1 + 3 * A2 * t2 + t6 * (7 * A3 + 9 * A4 * t2)))
    y = t * (A1 + A2 * t2 + t6 * (A3 + A4 * t2))
    return x * SCALE + WIDTH / 2, -y * SCALE


Y_TOP = project(0, 90)[1]
Y_BOTTOM = project(0, LAT_MIN)[1]
HEIGHT = Y_BOTTOM - Y_TOP

# Areas that GeoIP databases report under another code.
MERGE = {"N. Cyprus": "CY", "Somaliland": "SO"}
# Shorter display names than ADMIN.
NAMES = {"US": "United States"}


def ring(coords):
    pts = []
    for lon, lat in coords:
        x, y = project(lon, lat)
        p = (round(x * 10), round((y - Y_TOP) * 10))
        if not pts or p != pts[-1]:
            pts.append(p)
    if len(pts) < 3:
        return ""
    out = [f"M{pts[0][0] / 10:g} {pts[0][1] / 10:g}"]
    for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
        out.append(f"l{(x1 - x0) / 10:g} {(y1 - y0) / 10:g}")
    return "".join(out) + "z"


def main():
    data = json.load(open(sys.argv[1], encoding="utf-8"))
    countries = {}
    for f in data["features"]:
        p = f["properties"]
        cc = MERGE.get(p["NAME"], p["ISO_A2_EH"])
        if cc in ("-99", "AQ"):
            continue
        g = f["geometry"]
        polys = g["coordinates"] if g["type"] == "MultiPolygon" else [g["coordinates"]]
        d = "".join(ring(r) for poly in polys for r in poly)
        name, path = countries.get(cc, (None, ""))
        if p["NAME"] not in MERGE:
            name = NAMES.get(cc, p["ADMIN"])
        countries[cc] = (name, path + d)
    print(f"#viewBox 0 0 {WIDTH:g} {math.ceil(HEIGHT)}")
    for cc in sorted(countries):
        name, d = countries[cc]
        print(f"{cc}\t{name}\t{d}")


main()
