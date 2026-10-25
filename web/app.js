/**
 * INCIDENT TIME MACHINE // NIGHT SHIFT FORENSICS CONTROLLER
 * Real-time deterministic log reconstruction, topology radar, and forensics telemetry.
 */

(function () {
  "use strict";

  // System State
  let currentMode = "local"; // 'local' | 'remote'
  let cachedReport = null;
  let activeFilter = "all";
  let activeServiceFilter = null;
  let activeTraceFilter = null;
  let topologyNodes = [];
  let topologyEdges = [];
  let topologyAnimFrameId = null;

  // DOM Elements
  const modeLocalBtn = document.getElementById("mode-local");
  const modeRemoteBtn = document.getElementById("mode-remote");
  const brandModeLabel = document.getElementById("brand-mode-label");
  const connectionStatus = document.getElementById("connection-status");
  const connectionText = document.getElementById("connection-text");
  const hudClock = document.getElementById("hud-clock");
  const hudRegion = document.getElementById("hud-region");
  const hudLambda = document.getElementById("hud-lambda");

  const fixtureSelect = document.getElementById("fixture-select");
  const btnAnalyze = document.getElementById("btn-analyze");
  const btnRefresh = document.getElementById("btn-refresh");
  const investigationStatus = document.getElementById("investigation-status");

  const statEvents = document.getElementById("stat-events");
  const statEarliestService = document.getElementById("stat-earliest-service");
  const statEarliestId = document.getElementById("stat-earliest-id");
  const statTraces = document.getElementById("stat-traces");
  const statUnknowns = document.getElementById("stat-unknowns");

  const alertBanner = document.getElementById("alert-banner");
  const loadingState = document.getElementById("loading-state");
  const causationBox = document.getElementById("causation-disclaimer-box");
  const causationBody = document.getElementById("causation-disclaimer-body");

  const timelineList = document.getElementById("timeline-list");
  const tracesList = document.getElementById("traces-list");
  const hypothesesList = document.getElementById("hypotheses-list");
  const unknownsList = document.getElementById("unknowns-list");
  const filterPills = document.querySelectorAll(".filter-pills .pill");

  const topologyCanvas = document.getElementById("topology-canvas");
  const topologyStatus = document.getElementById("topology-status-readout");

  // Modal Elements
  const eventModal = document.getElementById("event-modal");
  const modalClose = document.getElementById("modal-close");
  const modalEventId = document.getElementById("modal-event-id");
  const modalEventService = document.getElementById("modal-event-service");
  const modalEventTime = document.getElementById("modal-event-time");
  const modalEventLevel = document.getElementById("modal-event-level");
  const modalEventReq = document.getElementById("modal-event-req");
  const modalEventIdx = document.getElementById("modal-event-idx");
  const modalEventMsg = document.getElementById("modal-event-msg");
  const modalEventJson = document.getElementById("modal-event-json");

  // =========================================================================
  // Initialization & Boot Sequence
  // =========================================================================

  document.addEventListener("DOMContentLoaded", () => {
    initClock();
    initSpotlightCards();
    initEventListeners();
    initModal();
    initTopologyRadar();
    fetchSystemStatus();
    loadFixtures().then(() => {
      if (fixtureSelect.value) {
        executeAnalysis();
      }
    });
  });

  function initSpotlightCards() {
    document.querySelectorAll(".spotlight-card").forEach((card) => {
      card.addEventListener("mousemove", (e) => {
        const rect = card.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        card.style.setProperty("--mouse-x", `${x}px`);
        card.style.setProperty("--mouse-y", `${y}px`);
      });
      card.addEventListener("mouseleave", () => {
        card.style.setProperty("--mouse-x", "-500px");
        card.style.setProperty("--mouse-y", "-500px");
      });
    });
  }

  function initClock() {
    function updateClock() {
      const now = new Date();
      const iso = now.toISOString(); // e.g. 2026-10-25T18:24:00.123Z
      const timePart = iso.slice(11, 23); // 18:24:00.123
      if (hudClock) {
        hudClock.textContent = `${timePart} UTC`;
      }
    }
    updateClock();
    setInterval(updateClock, 100);
  }

  function animateRollingNumber(el, targetVal, duration = 350) {
    if (typeof targetVal !== "number" || isNaN(targetVal)) {
      el.textContent = targetVal;
      return;
    }
    const startTime = performance.now();
    function step(now) {
      const progress = Math.min((now - startTime) / duration, 1);
      const ease = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      const val = Math.floor(ease * targetVal);
      el.textContent = val;
      if (progress < 1) {
        requestAnimationFrame(step);
      } else {
        el.textContent = targetVal;
      }
    }
    requestAnimationFrame(step);
  }

  function initEventListeners() {
    modeLocalBtn.addEventListener("click", () => setMode("local"));
    modeRemoteBtn.addEventListener("click", () => setMode("remote"));
    btnAnalyze.addEventListener("click", executeAnalysis);
    btnRefresh.addEventListener("click", () => {
      fetchSystemStatus();
      loadFixtures();
    });

    filterPills.forEach((pill) => {
      pill.addEventListener("click", () => {
        filterPills.forEach((p) => p.classList.remove("active"));
        pill.classList.add("active");
        activeFilter = pill.getAttribute("data-filter") || "all";
        renderTimeline();
      });
    });
  }

  function setMode(mode) {
    currentMode = mode;
    if (mode === "local") {
      modeLocalBtn.classList.add("active");
      modeRemoteBtn.classList.remove("active");
      brandModeLabel.textContent = "LOCAL ENGINE ACTIVE";
      brandModeLabel.className = "brand-mode-badge text-green";
    } else {
      modeRemoteBtn.classList.add("active");
      modeLocalBtn.classList.remove("active");
      brandModeLabel.textContent = "AWS LAMBDA ROUTE ACTIVE (ap-southeast-2)";
      brandModeLabel.className = "brand-mode-badge text-cyan";
    }
  }

  // =========================================================================
  // API Integration
  // =========================================================================

  async function fetchSystemStatus() {
    try {
      const res = await fetch("/api/status");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      connectionStatus.className = "hud-status status-healthy";
      connectionText.textContent = "BRIDGE ONLINE";

      if (hudRegion) hudRegion.textContent = data.active_region || "ap-southeast-2";
      if (hudLambda) hudLambda.textContent = data.lambda_function || "incident-time-machine";

      if (investigationStatus) {
        investigationStatus.textContent = data.aws_credentials_configured
          ? "BRIDGE ONLINE // AWS CREDENTIALS ACTIVE"
          : "BRIDGE ONLINE // LOCAL ENGINE READY";
      }
    } catch (err) {
      connectionStatus.className = "hud-status";
      connectionText.textContent = "BRIDGE OFFLINE";
      if (investigationStatus) investigationStatus.textContent = "OFFLINE // START SERVER";
      showAlert("error", `Cannot connect to local bridge server: ${err.message}. Run: python -m src.incident_time_machine.server`);
    }
  }

  async function loadFixtures() {
    try {
      const res = await fetch("/api/fixtures");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      fixtureSelect.innerHTML = "";
      (data.fixtures || []).forEach((fix) => {
        const opt = document.createElement("option");
        opt.value = fix.name;
        opt.textContent = `[${fix.name}] // ${fix.description}`;
        if (fix.name === "incident_out_of_order.json") {
          opt.selected = true;
        }
        fixtureSelect.appendChild(opt);
      });

      if (fixtureSelect.options.length === 0) {
        fixtureSelect.innerHTML = "<option disabled selected>NO LOG FIXTURES LOCATED IN /fixtures</option>";
      }
    } catch (err) {
      showAlert("error", `Failed to load fixture library: ${err.message}`);
    }
  }

  async function executeAnalysis() {
    const selectedFixture = fixtureSelect.value;
    if (!selectedFixture) {
      showAlert("error", "Select an incident log fixture before triggering reconstruction.");
      return;
    }

    clearAlert();
    setLoading(true);
    if (investigationStatus) {
      investigationStatus.textContent = `PROCESSING // RUNNING INGESTION ON ${selectedFixture.toUpperCase()}...`;
    }

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode: currentMode, fixture: selectedFixture }),
      });

      const data = await res.json();

      if (!res.ok || data.status === "error") {
        const errCode = data.error_code || `HTTP_${res.status}`;
        const errMsg = data.message || "Failed to process incident.";
        showAlert("error", `Analysis Error [${errCode}]: ${errMsg}`);
        if (errCode === "NO_CREDENTIALS") {
          showAlert(
            "error",
            `AWS Credentials Missing: Set AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY in your shell or toggle to LOCAL engine mode.`
          );
        }
        if (investigationStatus) investigationStatus.textContent = `HALTED // ERROR: ${errCode}`;
        return;
      }

      const report = data.report || {};
      cachedReport = report;
      activeServiceFilter = null;
      activeTraceFilter = null;

      populateDashboard(report, data.execution_mode);
      if (investigationStatus) {
        investigationStatus.textContent = `COMPLETED // ${data.execution_mode.toUpperCase()} // ${report.timeline ? report.timeline.length : 0} EVENTS SEQUENCED`;
      }
    } catch (err) {
      showAlert("error", `Network bridge failure: ${err.message}`);
      if (investigationStatus) investigationStatus.textContent = `NETWORK ERROR // BRIDGE UNREACHABLE`;
    } finally {
      setLoading(false);
    }
  }

  // =========================================================================
  // Forensics Dashboard Rendering
  // =========================================================================

  function populateDashboard(report, executionMode) {
    const timeline = report.timeline || [];
    const traces = report.traces || {};
    const earliest = report.earliest_recorded_error;
    const hypotheses = report.hypotheses || [];
    const unknowns = report.unknowns || [];

    // 1. Metrics Ribbon with React Bits Rolling Number Animation
    animateRollingNumber(statEvents, timeline.length);
    animateRollingNumber(statTraces, Object.keys(traces).length);
    animateRollingNumber(statUnknowns, unknowns.length);

    if (earliest && earliest.event_id) {
      statEarliestService.textContent = earliest.service || "UNKNOWN";
      statEarliestId.textContent = `${earliest.event_id} [${earliest.level}]`;
      statEarliestService.className = "metric-value font-mono text-rose";
    } else {
      statEarliestService.textContent = "NOMINAL";
      statEarliestId.textContent = "Zero errors detected in log slice";
      statEarliestService.className = "metric-value font-mono text-green";
    }

    // 2. Anti-Causation Disclaimer Box
    causationBox.classList.remove("hidden");
    if (earliest && earliest.event_id) {
      causationBox.style.background = "linear-gradient(135deg, rgba(245, 158, 11, 0.08) 0%, rgba(13, 20, 36, 0.95) 100%)";
      causationBox.style.borderColor = "rgba(245, 158, 11, 0.45)";
      causationBody.innerHTML = `
        Earliest recorded error manifested in <code>${escapeHtml(earliest.service)}</code> 
        (Event ID: <code>${escapeHtml(earliest.event_id)}</code>) at 
        <code>${escapeHtml(earliest.timestamp_iso || earliest.timestamp || "")}</code>.<br><br>
        <strong>Crucial Analytical Guardrail:</strong> Chronological sequence does <em>NOT</em> establish root cause. 
        This error may merely be a downstream symptom of silent infrastructure saturation, unmonitored container memory pressure, or network latency prior to first error log.
      `;
    } else {
      causationBox.style.background = "linear-gradient(135deg, rgba(0, 255, 136, 0.08) 0%, rgba(13, 20, 36, 0.95) 100%)";
      causationBox.style.borderColor = "rgba(0, 255, 136, 0.35)";
      causationBody.innerHTML = `
        <strong>Baseline Healthy Traffic Confirmed:</strong> No errors or warnings were recorded across observed microservices.<br>
        <em>Limitation Notice:</em> Absence of error logs does not establish global system health; silent dropouts or uninstrumented third-party services cannot be ruled out.
      `;
    }

    // 3. Render Forensics Panels
    renderTimeline();
    renderTraces(traces);
    renderHypotheses(hypotheses);
    renderUnknowns(unknowns);

    // 4. Update Topology Radar Nodes & Edges
    buildTopologyGraph(timeline, traces, earliest);
  }

  // =========================================================================
  // Timeline Renderer with Event Selection
  // =========================================================================

  function renderTimeline() {
    if (!cachedReport || !cachedReport.timeline) {
      timelineList.innerHTML = `
        <div class="empty-state">
          <div class="empty-crosshair">+</div>
          <p class="font-mono">NO ACTIVE TIMELINE</p>
          <span class="empty-sub">Ingest a log stream to reconstruct chronology.</span>
        </div>`;
      return;
    }

    const timeline = cachedReport.timeline;
    const earliestId = cachedReport.earliest_recorded_error?.event_id;

    const filtered = timeline.filter((evt) => {
      // Severity Filter
      if (activeFilter !== "all" && (evt.level || "").toUpperCase() !== activeFilter) {
        return false;
      }
      // Service Filter (from Topology Click)
      if (activeServiceFilter && evt.service !== activeServiceFilter) {
        return false;
      }
      // Trace Filter (from Trace Click)
      if (activeTraceFilter && evt.request_id !== activeTraceFilter) {
        return false;
      }
      return true;
    });

    if (filtered.length === 0) {
      timelineList.innerHTML = `
        <div class="empty-state">
          <p class="font-mono">NO EVENTS MATCH FILTER</p>
          <button class="pill" style="margin-top:0.6rem" onclick="window.__itmResetFilters()">RESET ALL FILTERS</button>
        </div>`;
      return;
    }

    timelineList.innerHTML = filtered
      .map((evt, idx) => {
        const isEarliest = earliestId && evt.event_id === earliestId;
        const level = (evt.level || "INFO").toUpperCase();
        const levelClass =
          level === "ERROR"
            ? "level-error"
            : level === "WARN"
            ? "level-warn"
            : level === "DEBUG"
            ? "level-debug"
            : "level-info";

        const badgeClass =
          level === "ERROR"
            ? "badge-error"
            : level === "WARN"
            ? "badge-warn"
            : level === "DEBUG"
            ? "badge-debug"
            : "badge-info";

        const reqTag = evt.request_id
          ? `<span class="trace-tag">[TRACE: ${escapeHtml(evt.request_id)}]</span>`
          : `<span class="text-dim">NO TRACE ID</span>`;

        return `
          <div class="timeline-item ${levelClass} ${isEarliest ? "is-earliest" : ""}" 
               id="evt-${escapeHtml(evt.event_id)}" 
               data-event-id="${escapeHtml(evt.event_id)}"
               title="Click to inspect raw forensic event data">
            <div class="timeline-top">
              <div class="timeline-badges">
                <span class="badge ${badgeClass}">${escapeHtml(level)}</span>
                <span class="service-tag">${escapeHtml(evt.service || "unknown")}</span>
                ${isEarliest ? `<span class="badge badge-earliest">FIRST RECORDED ERROR</span>` : ""}
              </div>
              <span class="timestamp-text">${escapeHtml(evt.timestamp_iso || evt.timestamp || "")}</span>
            </div>
            <div class="timeline-msg font-mono">${escapeHtml(evt.message || "")}</div>
            <div class="timeline-footer">
              <span class="event-id-tag">EVENT: <code>${escapeHtml(evt.event_id)}</code></span>
              <span>${reqTag}</span>
            </div>
          </div>
        `;
      })
      .join("");

    // Attach click listeners to open detail modal
    timelineList.querySelectorAll(".timeline-item").forEach((el) => {
      el.addEventListener("click", () => {
        const eid = el.getAttribute("data-event-id");
        const found = timeline.find((e) => e.event_id === eid);
        if (found) {
          openEventModal(found);
        }
      });
    });
  }

  // =========================================================================
  // Distributed Trace Waterfall
  // =========================================================================

  function renderTraces(traces) {
    const traceKeys = Object.keys(traces);
    if (traceKeys.length === 0) {
      tracesList.innerHTML = `<div class="empty-state"><p class="font-mono">NO CORRELATED TRACES</p></div>`;
      return;
    }

    tracesList.innerHTML = traceKeys
      .map((key) => {
        const tr = traces[key];
        const services = tr.services || [];
        const hasError = tr.has_error;
        const isSelected = activeTraceFilter === key;

        const hopsHtml = services
          .map((svc) => `<span class="hop-pill">${escapeHtml(svc)}</span>`)
          .join('<span class="hop-arrow">→</span>');

        return `
          <div class="trace-item ${isSelected ? "trace-selected" : ""}" data-trace-id="${escapeHtml(key)}" title="Click to filter timeline by this trace">
            <div class="trace-top">
              <span class="trace-id">${escapeHtml(key)}</span>
              <span class="badge ${hasError ? "badge-error" : "badge-info"}">
                ${hasError ? "DEGRADED" : "NOMINAL"} (${tr.event_ids ? tr.event_ids.length : 0} EVENTS)
              </span>
            </div>
            <div class="trace-hops">
              ${hopsHtml}
            </div>
          </div>
        `;
      })
      .join("");

    tracesList.querySelectorAll(".trace-item").forEach((el) => {
      el.addEventListener("click", () => {
        const tid = el.getAttribute("data-trace-id");
        if (activeTraceFilter === tid) {
          activeTraceFilter = null;
        } else {
          activeTraceFilter = tid;
        }
        renderTimeline();
        renderTraces(traces);
      });
    });
  }

  // =========================================================================
  // Evidence-Backed Hypotheses & Unknowns
  // =========================================================================

  function renderHypotheses(hypotheses) {
    if (!hypotheses || hypotheses.length === 0) {
      hypothesesList.innerHTML = `<div class="empty-state"><p class="font-mono">NO HYPOTHESES</p></div>`;
      return;
    }

    hypothesesList.innerHTML = hypotheses
      .map((hyp) => {
        const conf = (hyp.confidence || "MEDIUM").toUpperCase();
        const confClass = conf === "HIGH" ? "conf-high" : "conf-med";

        const chipsHtml = (hyp.evidence_event_ids || [])
          .map((eid) => `<span class="evidence-chip" data-jump-to="${escapeHtml(eid)}" title="Jump to event ${escapeHtml(eid)}">${escapeHtml(eid)}</span>`)
          .join("");

        const uncHtml = (hyp.uncertainties || [])
          .map((u) => `<li>${escapeHtml(u)}</li>`)
          .join("");

        return `
          <div class="hypothesis-item">
            <div class="hypothesis-header">
              <span class="hyp-id">[${escapeHtml(hyp.hypothesis_id || "HYP")}]</span>
              <span class="conf-pill ${confClass}">CONFIDENCE: ${escapeHtml(conf)}</span>
            </div>
            <p class="hyp-claim">${escapeHtml(hyp.claim || "")}</p>
            <div class="evidence-strip">
              <span>SUPPORTING CITATIONS:</span>
              ${chipsHtml}
            </div>
            ${uncHtml ? `<ul class="hyp-uncertainties">${uncHtml}</ul>` : ""}
          </div>
        `;
      })
      .join("");

    hypothesesList.querySelectorAll(".evidence-chip").forEach((chip) => {
      chip.addEventListener("click", (e) => {
        e.stopPropagation();
        const targetId = chip.getAttribute("data-jump-to");
        jumpToTimelineEvent(targetId);
      });
    });
  }

  function renderUnknowns(unknowns) {
    if (!unknowns || unknowns.length === 0) {
      unknownsList.innerHTML = `<div class="empty-state"><p class="font-mono">NO TELEMETRY GAPS</p></div>`;
      return;
    }

    unknownsList.innerHTML = unknowns
      .map((u) => `<div class="unknown-item">${escapeHtml(u)}</div>`)
      .join("");
  }

  function jumpToTimelineEvent(eventId) {
    activeFilter = "all";
    activeServiceFilter = null;
    activeTraceFilter = null;
    filterPills.forEach((p) => p.classList.toggle("active", p.getAttribute("data-filter") === "all"));
    renderTimeline();

    const el = document.getElementById(`evt-${eventId}`);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      el.style.boxShadow = "0 0 20px rgba(0, 240, 255, 0.8)";
      el.style.borderColor = "var(--electric-cyan)";
      setTimeout(() => {
        el.style.boxShadow = "";
        el.style.borderColor = "";
      }, 2000);
    }
  }

  // =========================================================================
  // Interactive Service Topology Radar
  // =========================================================================

  function initTopologyRadar() {
    if (!topologyCanvas) return;
    resizeTopologyCanvas();
    window.addEventListener("resize", resizeTopologyCanvas);
    startTopologyAnimation();

    // Canvas click to select service node
    topologyCanvas.addEventListener("click", (e) => {
      const rect = topologyCanvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;

      // Find clicked node
      for (const node of topologyNodes) {
        const dx = x - node.x;
        const dy = y - node.y;
        if (Math.sqrt(dx * dx + dy * dy) < node.radius + 8) {
          activeServiceFilter = activeServiceFilter === node.id ? null : node.id;
          topologyStatus.textContent = activeServiceFilter
            ? `RADAR FILTER: [${activeServiceFilter.toUpperCase()}] // CLICK AGAIN TO RESET`
            : "SYSTEM RADAR: ALL SERVICES VISIBLE";
          renderTimeline();
          break;
        }
      }
    });
  }

  function resizeTopologyCanvas() {
    if (!topologyCanvas) return;
    const container = document.getElementById("topology-container");
    if (!container) return;
    const w = container.clientWidth;
    const h = container.clientHeight || 240;
    const dpr = window.devicePixelRatio || 1;

    topologyCanvas.width = w * dpr;
    topologyCanvas.height = h * dpr;
    topologyCanvas.style.width = `${w}px`;
    topologyCanvas.style.height = `${h}px`;

    const ctx = topologyCanvas.getContext("2d");
    if (ctx) ctx.scale(dpr, dpr);
  }

  function buildTopologyGraph(timeline, traces, earliestError) {
    const services = new Set();
    const errorServices = new Set();

    timeline.forEach((evt) => {
      if (evt.service) services.add(evt.service);
      if (evt.level === "ERROR" && evt.service) errorServices.add(evt.service);
    });

    const serviceList = Array.from(services);
    const container = document.getElementById("topology-container");
    const width = container?.clientWidth || 800;
    const height = 240;
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) * 0.35;

    // Arrange nodes circularly on radar
    topologyNodes = serviceList.map((svc, i) => {
      const angle = (i / serviceList.length) * Math.PI * 2 - Math.PI / 2;
      const hasError = errorServices.has(svc);
      const isEarliest = earliestError && earliestError.service === svc;
      return {
        id: svc,
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius,
        radius: isEarliest ? 16 : 12,
        hasError,
        isEarliest,
        pulsePhase: Math.random() * Math.PI * 2,
      };
    });

    // Build edges from trace service connections
    topologyEdges = [];
    Object.values(traces).forEach((tr) => {
      const sList = tr.services || [];
      for (let i = 0; i < sList.length - 1; i++) {
        const fromSvc = sList[i];
        const toSvc = sList[i + 1];
        if (fromSvc !== toSvc) {
          topologyEdges.push({
            from: fromSvc,
            to: toSvc,
            hasError: tr.has_error,
            particlePos: Math.random(),
          });
        }
      }
    });

    topologyStatus.textContent = `SYSTEM RADAR: ${topologyNodes.length} SERVICES OBSERVED // ${topologyEdges.length} TRACE FLOWS`;
  }

  function startTopologyAnimation() {
    if (!topologyCanvas) return;
    const ctx = topologyCanvas.getContext("2d");
    let lastTime = performance.now();

    function render(now) {
      const delta = (now - lastTime) / 1000;
      lastTime = now;

      const container = document.getElementById("topology-container");
      const width = container?.clientWidth || 800;
      const height = 240;

      ctx.clearRect(0, 0, width, height);

      // 1. Draw Radar Grid & Concentric Rings
      const centerX = width / 2;
      const centerY = height / 2;

      ctx.strokeStyle = "rgba(158, 148, 128, 0.25)";
      ctx.lineWidth = 1;

      // Concentric circles
      [0.2, 0.4, 0.65, 0.9].forEach((rFactor) => {
        ctx.beginPath();
        ctx.arc(centerX, centerY, height * 0.42 * rFactor, 0, Math.PI * 2);
        ctx.stroke();
      });

      // Crosshairs
      ctx.beginPath();
      ctx.moveTo(centerX, 15);
      ctx.lineTo(centerX, height - 15);
      ctx.moveTo(centerX - height * 0.45, centerY);
      ctx.lineTo(centerX + height * 0.45, centerY);
      ctx.stroke();

      // 2. Draw Edges with Traveling Telemetry Particles
      topologyEdges.forEach((edge) => {
        const nFrom = topologyNodes.find((n) => n.id === edge.from);
        const nTo = topologyNodes.find((n) => n.id === edge.to);
        if (!nFrom || !nTo) return;

        // Line
        ctx.beginPath();
        ctx.moveTo(nFrom.x, nFrom.y);
        ctx.lineTo(nTo.x, nTo.y);
        ctx.strokeStyle = edge.hasError ? "rgba(194, 41, 41, 0.35)" : "rgba(35, 32, 28, 0.2)";
        ctx.lineWidth = 1.25;
        ctx.stroke();

        // Particle
        edge.particlePos = (edge.particlePos + delta * 0.65) % 1;
        const px = nFrom.x + (nTo.x - nFrom.x) * edge.particlePos;
        const py = nFrom.y + (nTo.y - nFrom.y) * edge.particlePos;

        ctx.beginPath();
        ctx.arc(px, py, 2.5, 0, Math.PI * 2);
        ctx.fillStyle = edge.hasError ? "#c22929" : "#d94826";
        ctx.fill();
      });

      // 3. Draw Service Nodes
      topologyNodes.forEach((node) => {
        node.pulsePhase += delta * 3;
        const pulse = (Math.sin(node.pulsePhase) + 1) * 0.5;
        const isFiltered = activeServiceFilter && activeServiceFilter !== node.id;

        // Pulse Ring
        if (node.hasError) {
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + pulse * 5, 0, Math.PI * 2);
          ctx.strokeStyle = `rgba(194, 41, 41, ${0.3 + pulse * 0.4})`;
          ctx.lineWidth = 1.25;
          ctx.stroke();
        }

        // Core Node
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        ctx.fillStyle = isFiltered
          ? "rgba(180, 172, 158, 0.4)"
          : node.hasError
          ? "#c22929"
          : "#2b7431";
        ctx.fill();

        ctx.strokeStyle = "#1c1917";
        ctx.lineWidth = 1;
        ctx.stroke();

        // Node Label
        ctx.font = '10px "JetBrains Mono", monospace';
        ctx.fillStyle = isFiltered ? "#8c8273" : "#1c1917";
        ctx.textAlign = "center";
        ctx.fillText(node.id, node.x, node.y + node.radius + 14);
      });

      topologyAnimFrameId = requestAnimationFrame(render);
    }

    if (topologyAnimFrameId) cancelAnimationFrame(topologyAnimFrameId);
    topologyAnimFrameId = requestAnimationFrame(render);
  }

  // =========================================================================
  // Detailed Telemetry Modal
  // =========================================================================

  function initModal() {
    modalClose.addEventListener("click", closeModal);
    eventModal.addEventListener("click", (e) => {
      if (e.target === eventModal) closeModal();
    });
    window.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeModal();
    });
  }

  function openEventModal(evt) {
    modalEventId.textContent = `[${evt.event_id || "EVT"}]`;
    modalEventService.textContent = evt.service || "unknown-service";
    modalEventTime.textContent = evt.timestamp_iso || evt.timestamp || "--";
    modalEventLevel.textContent = evt.level || "INFO";
    modalEventReq.textContent = evt.request_id || "None";
    modalEventIdx.textContent = evt.event_id ? evt.event_id.replace("evt-", "") : "--";

    modalEventMsg.textContent = evt.message || "";
    modalEventJson.textContent = JSON.stringify(evt, null, 2);

    eventModal.classList.remove("hidden");
  }

  function closeModal() {
    eventModal.classList.add("hidden");
  }

  // Global helper to reset filters
  window.__itmResetFilters = function () {
    activeFilter = "all";
    activeServiceFilter = null;
    activeTraceFilter = null;
    filterPills.forEach((p) => p.classList.toggle("active", p.getAttribute("data-filter") === "all"));
    topologyStatus.textContent = "SYSTEM RADAR: ALL SERVICES VISIBLE";
    renderTimeline();
    if (cachedReport) renderTraces(cachedReport.traces || {});
  };

  // =========================================================================
  // UI Helpers
  // =========================================================================

  function setLoading(isLoading) {
    if (isLoading) {
      loadingState.classList.remove("hidden");
      btnAnalyze.disabled = true;
      btnAnalyze.style.opacity = "0.5";
    } else {
      loadingState.classList.add("hidden");
      btnAnalyze.disabled = false;
      btnAnalyze.style.opacity = "1";
    }
  }

  function showAlert(type, message) {
    alertBanner.className = `alert-banner ${type === "error" ? "alert-error" : "alert-info"}`;
    alertBanner.textContent = message;
    alertBanner.classList.remove("hidden");
  }

  function clearAlert() {
    alertBanner.classList.add("hidden");
    alertBanner.textContent = "";
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
})();
