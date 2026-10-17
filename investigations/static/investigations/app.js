(() => {
  const form = document.querySelector("#analyze-form");
  const input = document.querySelector("#traceback");
  const repositoryInput = document.querySelector("#repository");
  const count = document.querySelector("#char-count");
  const button = document.querySelector("#submit-button");
  const resetButton = document.querySelector("#reset-button");
  const notice = document.querySelector("#notice");
  const processing = document.querySelector("#processing");
  const results = document.querySelector("#results");
  const resultContent = document.querySelector("#result-content");
  const csrfToken = form.querySelector("[name=csrfmiddlewaretoken]").value;
  const endpoint = form.action;

  input.addEventListener("input", () => { count.textContent = `${input.value.length.toLocaleString()} / 50,000`; });

  resetButton.addEventListener("click", () => {
    form.reset(); input.value = ""; count.textContent = "0 / 50,000";
    results.hidden = true; notice.hidden = true; resetButton.hidden = true;
    input.focus();
  });

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function section(title) {
    const node = element("section", "result-section");
    node.append(element("h3", "", title));
    return node;
  }

  function listSection(title, items, ordered = false) {
    const node = section(title);
    if (!Array.isArray(items) || !items.length) node.append(element("p", "empty", "None provided."));
    else {
      const list = element(ordered ? "ol" : "ul");
      items.forEach(item => list.append(element("li", "", typeof item === "string" ? item : JSON.stringify(item))));
      node.append(list);
    }
    return node;
  }

  function renderDiagnosis(data) {
    resultContent.replaceChildren();
    const shell = element("article", "result-shell");
    const header = element("div", "result-top");
    header.append(element("h2", "", "Investigation report"));
    const fallback = data.diagnosis_mode !== "gemma";
    header.append(element("span", `badge${fallback ? " fallback" : ""}`, fallback ? "LIMITED ANALYSIS" : "GEMMA ANALYSIS"));
    shell.append(header);
    const body = element("div", "result-body");

    const summary = section("Summary"); summary.append(element("p", "", data.summary || "No summary was returned.")); body.append(summary);
    const cause = section("Likely cause"); cause.append(element("p", "", data.likely_cause || "No cause was returned.")); body.append(cause);

    if (data.repository) {
      const repository = section("Pinned repository revision");
      repository.append(element("p", "", `${data.repository.full_name || "GitHub repository"} @ ${data.repository.commit_sha || "unknown revision"}`));
      repository.append(element("p", "repository-meta", `Graphify: ${data.repository.graphify_source || "source fallback"} · unresolved frames: ${data.repository.unresolved_frames ?? 0}`));
      body.append(repository);
    }

    const evidence = section("Validated evidence");
    if (Array.isArray(data.evidence) && data.evidence.length) {
      const cards = element("div", "evidence");
      data.evidence.forEach(item => {
        const card = element("div", "evidence-card");
        card.append(element("span", "evidence-path", item.source_path || "Unknown source"));
        card.append(element("span", "evidence-lines", `L${item.start_line}–L${item.end_line}`));
        card.append(element("p", "", item.explanation || "")); cards.append(card);
      });
      evidence.append(cards);
    } else evidence.append(element("p", "empty", "No source citation passed validation."));
    body.append(evidence);

    body.append(listSection("Model hypotheses", data.hypotheses));
    body.append(listSection("Recommended steps", data.recommended_steps, true));
    body.append(listSection("Limitations", data.limitations));

    const facts = element("section", "result-section"); facts.append(element("h3", "", "Evidence provenance"));
    const grid = element("div", "facts-grid");
    const traces = [...(data.exception_type ? [`Exception: ${data.exception_type}`] : []), ...(data.traceback_facts || []).map(x => `${x.source_path}:${x.line}${x.function ? ` · ${x.function}` : ""}`)];
    const sources = (data.source_facts || []).map(x => `${x.source_path}:${x.start_line}–${x.end_line}`);
    const graphs = (data.graph_relationships || []).map(edge => `${edge.from} —${edge.relationship}→ ${edge.to} [${edge.evidence_type}]`);
    [ ["OBSERVED TRACEBACK FRAMES", traces], ["RETRIEVED SOURCE RANGES", sources] ].forEach(([title, values]) => {
      const box = element("div", "fact-box"); box.append(element("h4", "", title));
      if (!values.length) box.append(element("span", "empty", "None available."));
      else { const ul = element("ul"); values.forEach(value => ul.append(element("li", "", value))); box.append(ul); }
      grid.append(box);
    });
    const graphBox = element("div", "fact-box graph-box"); graphBox.append(element("h4", "", "GRAPHIFY CONTEXT"));
    const graphStatus = data.graphify_status || "unavailable";
    const graphMessage = graphStatus === "used" ? "Relationships from the readable graph index; each edge is marked extracted or inferred." : graphStatus === "available_no_matches" ? "Graph index is available, but no relevant relationships matched these frames." : "Graphify context is unavailable; direct source retrieval was used.";
    graphBox.append(element("span", "graph-state", graphMessage));
    if (graphs.length) { const ul = element("ul"); graphs.forEach(value => ul.append(element("li", "graph-edge", value))); graphBox.append(ul); }
    grid.append(graphBox);
    facts.append(grid); body.append(facts);
    shell.append(body); resultContent.append(shell); results.hidden = false;
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();
    notice.hidden = true; notice.className = "notice"; results.hidden = true;
    resetButton.hidden = true;
    button.disabled = true; button.querySelector("span").textContent = "Analyzing…";
    processing.hidden = false; processing.setAttribute("aria-busy", "true");
    processing.querySelector("#processing-message").textContent = "Analyzing traceback and gathering evidence…";
    const controller = new AbortController();
    const requestTimeout = window.setTimeout(() => controller.abort(), 45_000);
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        credentials: "same-origin",
        signal: controller.signal,
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken, "Accept": "application/json" },
        body: JSON.stringify({ traceback: input.value, ...(repositoryInput.value.trim() ? { repository: repositoryInput.value.trim() } : {}) })
      });
      const data = await response.json().catch(() => ({}));
      if (data.diagnosis_mode === "fallback") {
        renderDiagnosis(data); resetButton.hidden = false;
        notice.hidden = false; notice.className = response.ok ? "notice info" : "notice error";
        notice.textContent = data.likely_cause || "Automated diagnosis is unavailable; showing the available traceback and source analysis.";
      } else if (!response.ok) {
        throw new Error(data.error || `Analysis failed (HTTP ${response.status}).`);
      } else {
        renderDiagnosis(data); resetButton.hidden = false;
        notice.hidden = false; notice.className = "notice info";
        notice.textContent = "Analysis complete. Review the validated evidence and limitations below.";
      }
      if (!results.hidden) results.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
    } catch (error) {
      notice.hidden = false;
      notice.className = "notice error";
      notice.textContent = error.name === "AbortError" ? "The request took too long. Please try again with a shorter traceback." : error instanceof TypeError ? "Could not reach TraceGraph. Check that the server is running and try again." : error.message;
    } finally {
      window.clearTimeout(requestTimeout);
      processing.hidden = true; processing.setAttribute("aria-busy", "false");
      button.disabled = false; button.querySelector("span").textContent = "Analyze traceback";
    }
  });
})();
