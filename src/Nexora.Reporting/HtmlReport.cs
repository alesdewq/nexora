using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json.Nodes;

namespace Nexora.Reporting;

/// <summary>
/// Автономный HTML-отчёт: без скриптов и внешних ресурсов, всё содержимое экранируется. Уровень риска всегда подписан текстом,
/// цвет — только дополнительная подсказка.
/// </summary>
public static class HtmlReport
{
    private static readonly CultureInfo Ru = CultureInfo.GetCultureInfo("ru-RU");

    public static string Render(ReportDocument d)
    {
        var sb = new StringBuilder(64 * 1024);
        var m = d.Meta;
        sb.Append("<!doctype html><html lang=\"ru\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        sb.Append("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">");
        sb.Append("<title>").Append(E($"Отчёт {m.Product} — {m.Started.ToLocalTime().ToString("dd.MM.yyyy HH:mm", Ru)}")).Append("</title><style>").Append(Css).Append("</style></head><body><main>");

        sb.Append("<header><h1>Отчёт ").Append(E(m.Product)).Append("</h1><p class=\"muted\">")
          .Append(E($"Версия {m.Version} · {m.Started.ToLocalTime().ToString("dd.MM.yyyy HH:mm", Ru)} · длительность {Duration(m.Duration)} · компьютер {m.ComputerName} · {m.OsSummary}"))
          .Append(m.Elevated ? " · запуск с правами администратора" : " · запуск без прав администратора").Append("</p>");
        if (d.Masked) sb.Append("<p class=\"note\">Чувствительные данные (имя компьютера, пользователей, IP- и MAC-адреса) в этом отчёте замаскированы.</p>");
        else sb.Append("<p class=\"note warn\">Отчёт может содержать имена учётных записей, имя компьютера, локальные адреса и пути к файлам. Передавайте его только тем, кому доверяете.</p>");
        sb.Append("</header>");

        // Сводка
        var counts = d.CountBySeverity();
        sb.Append("<section><h2>Итог</h2><p>").Append(E(m.Summary)).Append("</p><ul class=\"chips\">");
        foreach (var s in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Info })
            sb.Append("<li class=\"sev ").Append(Cls(s)).Append("\">").Append(Icon(s)).Append(' ').Append(E(s.ToDisplay())).Append(": <b>")
              .Append(counts.GetValueOrDefault(s)).Append("</b></li>");
        sb.Append("<li class=\"sev nc\">").Append(Icon(Severity.NotChecked)).Append(" Не удалось проверить: <b>").Append(d.NotCheckedCount).Append("</b></li></ul>");
        sb.Append("<p class=\"muted\">Отсутствие замечаний не означает, что компьютер безопасен или исправен: проверяются только перечисленные пункты.</p>");
        sb.Append("<p><b>Выполненные модули:</b> ").Append(E(string.Join(", ", d.ExecutedModules))).Append("</p>");
        if (d.SkippedModules.Count > 0)
        {
            sb.Append("<p><b>Пропущенные модули:</b></p><ul>");
            foreach (var s in d.SkippedModules) sb.Append("<li>").Append(E($"{s.Module}: {s.Reason}")).Append("</li>");
            sb.Append("</ul>");
        }
        sb.Append("</section>");

        // Находки по разделам
        foreach (var group in d.Findings.GroupBy(f => f.Section).OrderBy(g => g.Key))
        {
            sb.Append("<section><h2>").Append(E(group.Key.ToDisplay())).Append("</h2>");
            foreach (var f in group.OrderBy(Order).ThenBy(f => f.Title, StringComparer.CurrentCulture)) Finding(sb, f);
            sb.Append("</section>");
        }

        if (d.Data is not null)
        {
            sb.Append("<section><h2>Технические данные</h2><p class=\"muted\">Сведения, собранные во время проверки (источник для выводов выше).</p>");
            foreach (var (key, value) in d.Data)
            {
                sb.Append("<details><summary>").Append(E(key)).Append("</summary>");
                Node(sb, value, 0);
                sb.Append("</details>");
            }
            sb.Append("</section>");
        }
        sb.Append("<footer class=\"muted\">").Append(E($"{m.Product} {m.Version}. Отчёт создан локально; NEXORA не отправляет данные в сеть.")).Append("</footer>");
        sb.Append("</main></body></html>");
        return sb.ToString();
    }

    private static int Order(ReportedFinding f) => f.Status switch
    {
        CheckStatus.Finding => 10 - (int)f.Severity,
        CheckStatus.Unavailable or CheckStatus.Failed => 20,
        _ => 30,
    };

    private static void Finding(StringBuilder sb, ReportedFinding f)
    {
        var sev = f.Status == CheckStatus.Ok ? "ok" : Cls(f.Severity);
        var label = f.Status == CheckStatus.Ok ? "Норма" : f.Severity.ToDisplay();
        sb.Append("<article class=\"f ").Append(sev).Append("\"><h3><span class=\"badge ").Append(sev).Append("\">")
          .Append(f.Status == CheckStatus.Ok ? "✓" : Icon(f.Severity)).Append(' ').Append(E(label)).Append("</span> ").Append(E(f.Title)).Append("</h3>");
        sb.Append("<dl>");
        Row(sb, "Что обнаружено", f.WhatFound);
        if (f.Status == CheckStatus.Finding)
        {
            Row(sb, "Тип вывода", f.Kind.ToDisplay());
            Row(sb, "Почему это важно", f.WhyItMatters);
            Row(sb, "Что рекомендуется", f.Recommendation);
            Row(sb, "Возможные последствия", f.Consequences);
            Row(sb, "Автоматическое действие", f.AutomatedActionAvailable ? "доступно в NEXORA (с подтверждением)" : "нет — решение и действие за вами");
        }
        Row(sb, "Надёжность вывода", f.Confidence.ToDisplay());
        if (f.Resolution is { } r && r.Status != ResolutionStatus.None)
            Row(sb, "Статус устранения", $"{r.Status.ToDisplay()} ({r.At.ToLocalTime().ToString("dd.MM.yyyy", Ru)}){(string.IsNullOrWhiteSpace(r.Note) ? "" : $": {r.Note}")}");
        sb.Append("<dt>Источник данных</dt><dd><ul>");
        foreach (var e in f.Evidence) sb.Append("<li><code>").Append(E(e.Source)).Append("</code>").Append(e.Detail.Length > 0 ? " — " + E(e.Detail) : "").Append("</li>");
        sb.Append("</ul></dd>");
        if (f.Limitations.Count > 0)
        {
            sb.Append("<dt>Ограничения</dt><dd><ul>");
            foreach (var l in f.Limitations) sb.Append("<li>").Append(E(l)).Append("</li>");
            sb.Append("</ul></dd>");
        }
        sb.Append("</dl></article>");
    }

    private static void Row(StringBuilder sb, string name, string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        sb.Append("<dt>").Append(E(name)).Append("</dt><dd>").Append(E(value)).Append("</dd>");
    }

    private const int MaxDepth = 6, MaxRows = 300;

    private static void Node(StringBuilder sb, JsonNode? node, int depth)
    {
        if (depth > MaxDepth) { sb.Append('…'); return; }
        switch (node)
        {
            case null: sb.Append("<span class=\"muted\">нет</span>"); break;
            case JsonObject o when o.ContainsKey("source") && (o.ContainsKey("value") || o.ContainsKey("unavailable")):
                // Measured<T>: значение или «данные недоступны»
                if (o["unavailable"] is { } why) sb.Append("<span class=\"nc-text\">данные недоступны: ").Append(E(why.ToString())).Append("</span>");
                else Node(sb, o["value"], depth + 1);
                sb.Append(" <small class=\"muted\">[").Append(E(o["source"]?.ToString() ?? "")).Append("]</small>");
                break;
            case JsonObject o:
                sb.Append("<table>");
                foreach (var (k, v) in o) { sb.Append("<tr><th>").Append(E(k)).Append("</th><td>"); Node(sb, v, depth + 1); sb.Append("</td></tr>"); }
                sb.Append("</table>");
                break;
            case JsonArray a when a.Count == 0: sb.Append("<span class=\"muted\">пусто</span>"); break;
            case JsonArray a when a.All(x => x is JsonObject xo && xo.All(kv => kv.Value is not JsonObject and not JsonArray)):
                var cols = a.OfType<JsonObject>().SelectMany(x => x.Select(kv => kv.Key)).Distinct().ToList();
                sb.Append("<div class=\"scroll\"><table class=\"grid\"><tr>");
                foreach (var c in cols) sb.Append("<th>").Append(E(c)).Append("</th>");
                sb.Append("</tr>");
                foreach (var row in a.OfType<JsonObject>().Take(MaxRows))
                {
                    sb.Append("<tr>");
                    foreach (var c in cols) sb.Append("<td>").Append(E(row[c]?.ToString() ?? "")).Append("</td>");
                    sb.Append("</tr>");
                }
                sb.Append("</table></div>");
                if (a.Count > MaxRows) sb.Append("<p class=\"muted\">").Append(E($"Показано {MaxRows} из {a.Count}.")).Append("</p>");
                break;
            case JsonArray a:
                sb.Append("<ol>");
                foreach (var x in a.Take(MaxRows)) { sb.Append("<li>"); Node(sb, x, depth + 1); sb.Append("</li>"); }
                sb.Append("</ol>");
                break;
            default: sb.Append(E(node.ToString())); break;
        }
    }

    private static string Cls(Severity s) => s switch
    {
        Severity.Critical => "crit", Severity.High => "high", Severity.Medium => "med", Severity.Info => "info", _ => "nc",
    };

    private static string Icon(Severity s) => s switch
    {
        Severity.Critical => "⛔", Severity.High => "▲", Severity.Medium => "◆", Severity.Info => "ℹ", _ => "?",
    };

    private static string Duration(TimeSpan t) => t.TotalMinutes >= 1 ? $"{(int)t.TotalMinutes} мин {t.Seconds} с" : $"{t.TotalSeconds:0} с";

    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

    private const string Css = """
:root{--bg:#f7f8fa;--fg:#1b1f27;--muted:#5e6673;--card:#fff;--line:#e3e6eb;--crit:#b91c1c;--high:#c2410c;--med:#a16207;--info:#1d4ed8;--ok:#15803d;--nc:#6b7280}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--fg:#e7e9ee;--muted:#9aa1ae;--card:#171a21;--line:#2a2f3a;--crit:#f87171;--high:#fb923c;--med:#facc15;--info:#93c5fd;--ok:#4ade80;--nc:#9ca3af}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 "Segoe UI",system-ui,sans-serif}
main{max-width:1000px;margin:0 auto;padding:24px 16px}h1{margin:0 0 4px}h2{margin:32px 0 12px;font-size:20px}h3{margin:0 0 8px;font-size:16px}
.muted{color:var(--muted)}.note{padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--card)}.warn{border-left:4px solid var(--med)}
.chips{display:flex;flex-wrap:wrap;gap:8px;padding:0;list-style:none}.chips li{padding:4px 10px;border:1px solid var(--line);border-radius:999px;background:var(--card)}
.f{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--nc);border-radius:8px;padding:12px 14px;margin:10px 0}
.f.crit{border-left-color:var(--crit)}.f.high{border-left-color:var(--high)}.f.med{border-left-color:var(--med)}.f.info{border-left-color:var(--info)}.f.ok{border-left-color:var(--ok)}
.badge{font-size:12px;padding:2px 8px;border-radius:999px;border:1px solid currentColor;white-space:nowrap}
.badge.crit,.sev.crit{color:var(--crit)}.badge.high,.sev.high{color:var(--high)}.badge.med,.sev.med{color:var(--med)}.badge.info,.sev.info{color:var(--info)}.badge.ok{color:var(--ok)}.badge.nc,.sev.nc,.nc-text{color:var(--nc)}
dl{display:grid;grid-template-columns:200px 1fr;gap:4px 12px;margin:0}dt{color:var(--muted)}dd{margin:0}dd ul{margin:0;padding-left:18px}
code{font-family:Consolas,monospace;font-size:13px;word-break:break-all}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px;margin:8px 0}summary{cursor:pointer;font-weight:600}
table{border-collapse:collapse;font-size:13px;margin:4px 0}th,td{border:1px solid var(--line);padding:3px 6px;text-align:left;vertical-align:top}th{color:var(--muted);font-weight:500}
.scroll{overflow-x:auto}footer{margin-top:40px}
@media (max-width:640px){dl{grid-template-columns:1fr}dt{margin-top:6px}}
@media print{details{break-inside:avoid}details>*{display:block}}
""";
}
