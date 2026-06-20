// SPDX-License-Identifier: AGPL-3.0-or-later
/* Audit Forge — UI behaviors, made re-invocable for the SPA.
   AFUI.hydrate(root) wires reveal / count-up / tabs / echidna toggle / editor /
   FAQ / finding accordions / the live hero terminal within `root`, and is called
   after every view render. The ticker is wired once. */
(function () {
  "use strict";
  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  var SAMPLE_HTML =
    '<span class="cm">// SPDX-License-Identifier: MIT</span>\n' +
    '<span class="kw">pragma</span> solidity ^0.8.8;\n\n' +
    '<span class="kw">contract</span> <span class="ty">VulnerableVault</span> {\n' +
    '    <span class="kw">mapping</span>(<span class="ty">address</span> =&gt; <span class="ty">uint256</span>) <span class="kw">public</span> balances;\n\n' +
    '    <span class="kw">function</span> deposit() <span class="kw">external payable</span> {\n' +
    '        balances[msg.sender] += msg.value;\n' +
    '    }\n\n' +
    '    <span class="cm">// SWC-107: state written *after* the external call</span>\n' +
    '    <span class="kw">function</span> withdraw() <span class="kw">external</span> {\n' +
    '        <span class="ty">uint256</span> amount = balances[msg.sender];\n' +
    '        (<span class="ty">bool</span> ok, ) = msg.sender.call{value: amount}(<span class="cm">""</span>);\n' +
    '        <span class="kw">require</span>(ok, <span class="cm">"transfer failed"</span>);\n' +
    '        balances[msg.sender] = 0;\n' +
    '    }\n' +
    '}';

  // ---- ticker: duplicate the belt once for a seamless loop ----
  var belt = document.getElementById("tickerBelt");
  if (belt && !belt.dataset.doubled) { belt.innerHTML += belt.innerHTML; belt.dataset.doubled = "1"; }

  var cleanups = [];
  function clearCleanups() { cleanups.forEach(function (fn) { try { fn(); } catch (e) {} }); cleanups = []; }

  function reveal(root) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } });
    }, { threshold: 0.12 });
    root.querySelectorAll(".reveal, .diagram").forEach(function (el) {
      var r = el.getBoundingClientRect();
      if (reduced || r.top < window.innerHeight * 1.15) { el.classList.add("in", "snap"); }
      else { io.observe(el); }
    });
    cleanups.push(function () { io.disconnect(); });
  }

  function countUp(el) {
    var target = parseFloat(el.dataset.count);
    var prefix = el.dataset.prefix || "", suffix = el.dataset.suffix || "";
    if (isNaN(target)) return;
    if (reduced) { el.textContent = prefix + target + suffix; return; }
    var start = null;
    function frame(ts) {
      if (!start) start = ts;
      var p = Math.min((ts - start) / 1100, 1), eased = 1 - Math.pow(1 - p, 3);
      el.textContent = prefix + Math.round(target * eased) + suffix;
      if (p < 1) requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
  }
  function stats(root) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) { e.target.querySelectorAll("[data-count]").forEach(countUp); io.unobserve(e.target); } });
    }, { threshold: 0.4 });
    root.querySelectorAll(".statsbar, .page-stats").forEach(function (el) {
      var r = el.getBoundingClientRect();
      if (r.top < window.innerHeight * 1.15) el.querySelectorAll("[data-count]").forEach(countUp);
      else io.observe(el);
    });
    cleanups.push(function () { io.disconnect(); });
  }

  function tabs(root) {
    root.querySelectorAll(".tabs .tab").forEach(function (tab) {
      tab.addEventListener("click", function () {
        root.querySelectorAll(".tabs .tab").forEach(function (t) { t.classList.remove("active"); });
        root.querySelectorAll(".tab-pane").forEach(function (p) { p.classList.remove("active"); });
        tab.classList.add("active");
        var pane = root.querySelector('.tab-pane[data-pane="' + tab.dataset.tab + '"]');
        if (pane) pane.classList.add("active");
      });
    });
  }

  function echidna(root) {
    root.querySelectorAll(".toggle").forEach(function (t) {
      t.addEventListener("click", function (e) { e.preventDefault(); t.classList.toggle("on"); });
    });
  }

  function editor(root) {
    var gutter = root.querySelector("#gutter"), code = root.querySelector("#code");
    if (gutter && code) {
      var renumber = function () {
        var lines = code.textContent.split("\n").length, html = "";
        for (var i = 1; i <= Math.max(lines, 8); i++) html += "<span>" + i + "</span>";
        gutter.innerHTML = html;
      };
      renumber();
      code.addEventListener("input", renumber);
      var sampleBtn = root.querySelector("#loadSample");
      if (sampleBtn) sampleBtn.addEventListener("click", function () { code.innerHTML = SAMPLE_HTML; renumber(); });
    }
  }

  function faq(root) {
    root.querySelectorAll(".faq-item").forEach(function (item) {
      var q = item.querySelector(".faq-q"), a = item.querySelector(".faq-a");
      if (!q || !a) return;
      q.addEventListener("click", function () {
        var open = item.classList.contains("open");
        root.querySelectorAll(".faq-item.open").forEach(function (o) {
          o.classList.remove("open"); var oa = o.querySelector(".faq-a"); if (oa) oa.style.maxHeight = "0px";
        });
        if (!open) { item.classList.add("open"); a.style.maxHeight = a.scrollHeight + "px"; }
      });
    });
  }

  function findings(root) {
    root.querySelectorAll(".finding .f-head").forEach(function (head) {
      head.addEventListener("click", function () { head.closest(".finding").classList.toggle("open"); });
    });
  }

  function terminal(root) {
    var term = root.querySelector("#termBody");
    if (!term) return;
    var lines = Array.prototype.slice.call(term.querySelectorAll(".tline"));
    var sum = term.querySelector(".term-sum");
    var meter = term.querySelector(".term-sum .meter i");
    var timers = [], stopped = false;
    function later(fn, ms) { timers.push(setTimeout(fn, ms)); }
    function reset() {
      timers.forEach(clearTimeout); timers = [];
      lines.forEach(function (l) { l.classList.remove("on", "spin"); var r = l.querySelector(".res"); if (r) r.innerHTML = r.dataset.final; });
      if (sum) sum.classList.remove("on"); if (meter) meter.style.width = "0%";
    }
    function run() {
      if (stopped || !document.contains(term)) return;
      reset();
      if (reduced) { lines.forEach(function (l) { l.classList.add("on"); }); if (sum) sum.classList.add("on"); if (meter) meter.style.width = "87%"; return; }
      var t = 500;
      lines.forEach(function (l) {
        var res = l.querySelector(".res"), final = res ? res.dataset.final : "", dur = parseInt(l.dataset.dur, 10) || 900;
        later(function () { l.classList.add("on", "spin"); if (res) res.textContent = "running…"; }, t);
        later(function () { l.classList.remove("spin"); if (res) res.innerHTML = final; }, t + dur);
        t += 340;
      });
      t += 1400;
      later(function () { if (sum) sum.classList.add("on"); if (meter) later(function () { meter.style.width = "87%"; }, 80); }, t);
      later(run, t + 9000);
    }
    var io = new IntersectionObserver(function (entries) { if (entries[0].isIntersecting) { io.disconnect(); run(); } }, { threshold: 0.3 });
    io.observe(term);
    cleanups.push(function () { stopped = true; timers.forEach(clearTimeout); io.disconnect(); });
  }

  window.AFUI = {
    hydrate: function (root) {
      root = root || document;
      clearCleanups();
      [reveal, stats, tabs, echidna, editor, faq, findings, terminal].forEach(function (fn) {
        try { fn(root); } catch (e) { /* never let one widget break the page */ }
      });
    }
  };
})();
