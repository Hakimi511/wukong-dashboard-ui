(() => {
  const $ = (selector) => document.querySelector(selector);
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (ch) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[ch]));
  const number = (value) => { const parsed = Number(value); return Number.isFinite(parsed) ? parsed : NaN; };
  const percent = (value) => Number.isFinite(number(value)) ? `${(number(value) * 100).toFixed(2)}%` : "—";
  let workbench = null;

  function mode() { return workbench?.presentation_modes?.find((item) => item.id === $("#mode").value) || workbench?.presentation_modes?.[0] || {}; }
  function render() {
    const current = mode(); const performance = current.performance || {}; const ic = current.rank_ic_12m || {};
    $("#cards").innerHTML = [
      ["年化", percent(performance.cagr), `${performance.period_start || "—"} ～ ${performance.period_end || "—"}`],
      ["最大回撤", percent(performance.max_drawdown), performance.price_basis || "—"],
      ["12M Rank IC", number(ic.mean_ic).toFixed(3), `${ic.months || "—"}个月 · 正值率 ${percent(ic.positive_ratio)}`],
      ["初始本金", number(performance.initial_capital).toLocaleString("zh-CN"), "生产口径来自规格文件"],
    ].map(([label, value, detail]) => `<article class="card"><span>${esc(label)}</span><b>${esc(value)}</b><span>${esc(detail)}</span></article>`).join("");
    $("#factor-evidence").innerHTML = `<p>${esc(current.description || "—")}</p><dl><dt>样本期</dt><dd>${esc(ic.period_start || "—")} ～ ${esc(ic.period_end || "—")}</dd><dt>月度 ICIR</dt><dd>${Number.isFinite(number(ic.icir_monthly)) ? number(ic.icir_monthly).toFixed(3) : "—"}（HAC 未提供则保持空值）</dd><dt>状态</dt><dd>${esc(current.status || "—")}</dd></dl>`;
    const audit = workbench.audit || {}; const pit = audit.pit || {}; const reconciliation = audit.ledger_reconciliation || {}; const source = performance.source || "—";
    $("#provenance").innerHTML = `<dl><dt>数据截止日</dt><dd>${esc(workbench.data_as_of || "—")}</dd><dt>来源文件</dt><dd>${esc(source)}</dd><dt>PIT</dt><dd>${esc(pit.status || "—")} · 未来数据泄漏 ${esc(pit.future_leak_count ?? "—")}</dd><dt>账本勾稽</dt><dd>${esc(reconciliation.status || "—")} · 唯一正式账本与摘要/规格一致性</dd><dt>运行程序</dt><dd>build_factor_workbench.py</dd></dl>`;
    $("#audit-status").textContent = `审计：${pit.status || "—"} · 勾稽：${reconciliation.status || "—"} · ${workbench.read_only ? "只读" : "请检查"}`;
  }
  async function init() {
    try { const response = await fetch("/api/production/factor_workbench.json", {cache:"no-store"}); if (!response.ok) throw new Error(`HTTP ${response.status}`); workbench = await response.json(); $("#mode").addEventListener("change", render); render(); }
    catch (error) { $("#audit-status").textContent = "读取失败"; $("#factor-evidence").textContent = `生产证据读取失败：${error.message}`; }
  }
  init();
})();
