// apti-dashboard: time slider, filters and country selection. Without this
// script the page shows the latest window for all behaviours and origins.
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const data = JSON.parse($("apti-data").textContent);
  const SVG = "http://www.w3.org/2000/svg";
  const nf = new Intl.NumberFormat("en");
  const pct = new Intl.NumberFormat("en", { style: "percent", maximumFractionDigits: 1 });

  const behavior = $("behavior");
  const origin = $("origin");
  const frame = $("frame");
  const play = $("play");
  const spark = $("spark");
  const paths = new Map();
  for (const p of document.querySelectorAll("#map path[data-cc]")) {
    paths.set(p.dataset.cc, p);
  }

  const nameOf = (cc) => data.names[cc] || cc;
  const fmt = (d) => d.toISOString().slice(0, 16).replace("T", " ");

  // Same formula as `frames::class` in Rust.
  const classOf = (n, max) => {
    if (n === 0) return 0;
    if (max <= 1) return data.classes;
    const c = Math.ceil((data.classes * Math.log1p(n)) / Math.log1p(max));
    return Math.min(data.classes, Math.max(1, c));
  };

  // [class, lowest count, highest count] of each class that occurs.
  const legendRanges = (max) => {
    const out = [];
    for (let n = 1; n <= max; n++) {
      const c = classOf(n, max);
      const last = out[out.length - 1];
      if (last && last[0] === c) last[2] = n;
      else out.push([c, n, n]);
    }
    return out;
  };

  const series = () =>
    data.series[Number(behavior.value) * data.origins.length + Number(origin.value)];

  const cell = (text, cls) => {
    const td = document.createElement("td");
    td.textContent = text;
    if (cls) td.className = cls;
    return td;
  };

  function renderLegend(max) {
    const ul = $("legend");
    const items = [[0, 0, 0], ...legendRanges(max)];
    ul.replaceChildren(
      ...items.map(([c, lo, hi]) => {
        const li = document.createElement("li");
        li.className = "q" + c;
        li.textContent = lo === hi ? nf.format(lo) : nf.format(lo) + "–" + nf.format(hi);
        return li;
      }),
    );
  }

  function renderSpark(s, current) {
    const n = s.totals.length;
    const top = Math.max(1, ...s.totals);
    spark.setAttribute("viewBox", `0 0 ${n} 100`);
    spark.replaceChildren(
      ...s.totals.map((t, i) => {
        const r = document.createElementNS(SVG, "rect");
        const h = t ? Math.max(2, (t / top) * 100) : 0.5;
        r.setAttribute("x", i + 0.1);
        r.setAttribute("width", 0.8);
        r.setAttribute("y", 100 - h);
        r.setAttribute("height", h);
        if (i === current) r.setAttribute("class", "on");
        const title = document.createElementNS(SVG, "title");
        title.textContent = `${fmt(new Date(data.frames[i]))} UTC: ${nf.format(t)}`;
        r.append(title);
        r.addEventListener("click", () => {
          stop();
          frame.value = i;
          render();
        });
        return r;
      }),
    );
  }

  // Observables behind the counts; absent if `show_observables` is off.
  const det = data.details;
  const stepSeconds =
    data.frames.length > 1
      ? (Date.parse(data.frames[1]) - Date.parse(data.frames[0])) / 1000
      : data.windowHours * 3600;
  const MAX_ROWS = 500;
  let selected = null;

  function select(cc) {
    selected = selected === cc ? null : cc;
    render();
  }

  const countryLabel = (cc) => {
    if (!det) return document.createTextNode(nameOf(cc));
    const b = document.createElement("button");
    b.type = "button";
    b.className = "link";
    b.textContent = nameOf(cc);
    b.setAttribute("aria-pressed", String(cc === selected));
    b.addEventListener("click", () => select(cc));
    return b;
  };

  const lines = (items) => {
    const td = document.createElement("td");
    for (const t of items) {
      const span = document.createElement("span");
      span.className = "line";
      span.textContent = t;
      td.append(span);
    }
    return td;
  };

  function renderDetails(i) {
    if (!det) return;
    $("details-clear").hidden = selected === null;
    const tbody = $("details-rows");
    // A selected country: its findings in the window, like the map. None:
    // all findings of the last step before the slider position.
    const ci = selected === null ? -1 : data.countries.indexOf(selected);
    const hi = Date.parse(data.frames[i]) / 1000;
    const lo = hi - (selected === null ? stepSeconds : data.windowHours * 3600);
    const b = Number(behavior.value);
    const o = Number(origin.value);
    const rows = new Map();
    const actors = new Set();
    for (const [key, fb, fo, actor, start, end, count] of det.findings) {
      if (start > hi || end < lo || (b && fb !== b) || (o && fo !== o)) continue;
      if (selected !== null && !det.observableCountries[key].includes(ci)) continue;
      let r = rows.get(key);
      if (!r) {
        r = { key, behaviors: new Set(), actors: new Map(), count: 0, last: end };
        rows.set(key, r);
      }
      r.behaviors.add(data.behaviors[fb]);
      const a = r.actors.get(actor) || { count: 0, indicator: false };
      if (count < 0) a.indicator = true;
      else {
        a.count += count;
        r.count += count;
      }
      r.actors.set(actor, a);
      r.last = Math.max(r.last, end);
      actors.add(actor);
    }
    const sorted = [...rows.values()].sort(
      (x, y) =>
        y.count - x.count ||
        y.last - x.last ||
        det.observables[x.key].localeCompare(det.observables[y.key]),
    );

    if (selected === null) {
      const from = fmt(new Date(lo * 1000));
      $("details-title").textContent = `All findings, ${from} – ${fmt(new Date(hi * 1000))} UTC`;
    } else $("details-title").textContent = `Observables in ${nameOf(selected)}`;
    const period = selected === null ? "in this period" : "in this window";
    let summary = `${nf.format(sorted.length)} ${period}, reported by ${nf.format(actors.size)} ${actors.size === 1 ? "actor" : "actors"}.`;
    if (sorted.length > MAX_ROWS) summary += ` Showing the first ${nf.format(MAX_ROWS)}.`;
    if (selected === null) summary += " Select a country on the map or in the table to see its whole window.";
    $("details-summary").textContent = summary;

    const trs = sorted.slice(0, MAX_ROWS).map((r) => {
      const tr = document.createElement("tr");
      const reporters = [...r.actors]
        .sort((x, y) => y[1].count - x[1].count)
        .map(([a, v]) => {
          const parts = [];
          if (v.count) parts.push(nf.format(v.count) + "×");
          if (v.indicator) parts.push("indicator");
          return `${det.actors[a]}: ${parts.join(", ")}`;
        });
      tr.append(
        cell(det.observables[r.key], "mono"),
        lines(det.observableCountries[r.key].map((c) => nameOf(data.countries[c]))),
        lines([...r.behaviors].sort()),
        lines(reporters),
        cell(r.count ? nf.format(r.count) : "–", "n"),
        cell(fmt(new Date(r.last * 1000))),
      );
      return tr;
    });
    if (!trs.length) {
      const tr = document.createElement("tr");
      const td = cell("No findings in this window.", "empty");
      td.colSpan = 6;
      tr.append(td);
      trs.push(tr);
    }
    tbody.replaceChildren(...trs);
  }

  function render() {
    const s = series();
    const i = Number(frame.value);
    const flat = s.counts[i];
    const counts = new Map();
    for (let k = 0; k < flat.length; k += 2) {
      counts.set(data.countries[flat[k]], flat[k + 1]);
    }

    for (const [cc, p] of paths) {
      const n = counts.get(cc) || 0;
      p.setAttribute("class", "q" + classOf(n, s.max) + (cc === selected ? " sel" : ""));
      p.querySelector("title").textContent = `${nameOf(cc)}: ${nf.format(n)}`;
    }
    // Draw the selected country's outline on top of its neighbours.
    const sel = paths.get(selected);
    if (sel) sel.parentNode.append(sel);

    const end = new Date(data.frames[i]);
    const start = new Date(end.getTime() - data.windowHours * 3600e3);
    $("window-label").textContent = `${fmt(start)} – ${fmt(end)} UTC`;
    $("total").textContent = nf.format(s.totals[i]);

    const total = s.totals[i];
    const rows = [];
    let unknown = 0;
    for (const [cc, n] of counts) {
      if (cc === "ZZ") unknown = n;
      else if (rows.length < 10) {
        const tr = document.createElement("tr");
        if (cc === selected) tr.className = "sel";
        const name = document.createElement("td");
        name.append(countryLabel(cc));
        tr.append(name, cell(nf.format(n), "n"), cell(pct.format(n / total), "n"));
        rows.push(tr);
      }
    }
    if (!rows.length) {
      const tr = document.createElement("tr");
      const td = cell("No findings in this window.", "empty");
      td.colSpan = 3;
      tr.append(td);
      rows.push(tr);
    }
    $("top").replaceChildren(...rows);
    const note = $("unknown");
    note.replaceChildren();
    if (unknown) {
      const text = `${nf.format(unknown)} without a known country`;
      if (det) {
        const b = countryLabel("ZZ");
        b.textContent = text;
        note.append(b);
      } else note.textContent = text + ".";
    }

    renderLegend(s.max);
    renderSpark(s, i);
    renderDetails(i);
  }

  let timer = null;
  function stop() {
    if (timer !== null) clearInterval(timer);
    timer = null;
    play.textContent = "Play";
    play.setAttribute("aria-pressed", "false");
  }
  function start() {
    if (Number(frame.value) >= Number(frame.max)) frame.value = 0;
    play.textContent = "Pause";
    play.setAttribute("aria-pressed", "true");
    render();
    timer = setInterval(() => {
      if (Number(frame.value) >= Number(frame.max)) {
        stop();
        return;
      }
      frame.value = Number(frame.value) + 1;
      render();
    }, 700);
  }

  play.addEventListener("click", () => (timer === null ? start() : stop()));
  frame.addEventListener("input", () => {
    stop();
    render();
  });
  behavior.addEventListener("change", render);
  origin.addEventListener("change", render);

  if (det) {
    for (const [cc, p] of paths) p.addEventListener("click", () => select(cc));
    $("map").classList.add("selectable");
    $("details-clear").addEventListener("click", () => select(null));
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && selected !== null) select(null);
    });
    $("details").hidden = false;
  }
  $("controls").hidden = false;
  $("timeline").hidden = false;
  render();
})();
