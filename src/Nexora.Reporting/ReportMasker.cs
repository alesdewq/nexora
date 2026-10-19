using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Nexora.Reporting;

/// <summary>Что скрывать при экспорте.</summary>
public sealed record MaskOptions(string? ComputerName, IReadOnlyList<string> UserNames, string? UserProfilePath)
{
    public bool MaskIpAddresses { get; init; } = true;
    public bool MaskMacAddresses { get; init; } = true;
}

/// <summary>Маскирование имени компьютера, имён пользователей, пути профиля, IP- и MAC-адресов во всём отчёте.</summary>
public static partial class ReportMasker
{
    public const string ComputerPlaceholder = "<компьютер>", UserPlaceholder = "<пользователь>";

    [GeneratedRegex(@"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")]
    private static partial Regex Ipv4();

    [GeneratedRegex(@"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%\d+)?(?![\w:])")]
    private static partial Regex Ipv6Candidate();

    [GeneratedRegex(@"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")]
    private static partial Regex Mac();

    public static ReportDocument Mask(ReportDocument doc, MaskOptions o)
    {
        var m = new Func<string?, string?>(s => MaskText(s, o));
        return doc with
        {
            Masked = true,
            Meta = doc.Meta with { ComputerName = ComputerPlaceholder, Summary = m(doc.Meta.Summary)!, OsSummary = m(doc.Meta.OsSummary)! },
            Findings = doc.Findings.Select(f => f with
            {
                Title = m(f.Title)!, WhatFound = m(f.WhatFound)!, WhyItMatters = m(f.WhyItMatters), Recommendation = m(f.Recommendation),
                Consequences = m(f.Consequences),
                Evidence = f.Evidence.Select(e => new Evidence(m(e.Source)!, m(e.Detail)!)).ToList(),
                Limitations = f.Limitations.Select(l => m(l)!).ToList(),
                Resolution = f.Resolution is null ? null : f.Resolution with { Note = m(f.Resolution.Note) },
            }).ToList(),
            SkippedModules = doc.SkippedModules.Select(s => s with { Reason = m(s.Reason)! }).ToList(),
            Data = doc.Data is null ? null : (JsonObject)MaskNode(doc.Data.DeepClone(), o)!,
        };
    }

    public static string? MaskText(string? s, MaskOptions o)
    {
        if (string.IsNullOrEmpty(s)) return s;
        if (!string.IsNullOrWhiteSpace(o.UserProfilePath))
            s = s.Replace(o.UserProfilePath.TrimEnd('\\'), $@"C:\Users\{UserPlaceholder}", StringComparison.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(o.ComputerName) && o.ComputerName.Length >= 2)
            s = Regex.Replace(s, $@"(?<![\w-]){Regex.Escape(o.ComputerName)}(?![\w-])", ComputerPlaceholder, RegexOptions.IgnoreCase);
        foreach (var user in o.UserNames.Where(u => u.Length >= 3).Distinct(StringComparer.OrdinalIgnoreCase).OrderByDescending(u => u.Length))
            s = Regex.Replace(s, $@"(?<![\w-]){Regex.Escape(user)}(?![\w-])", UserPlaceholder, RegexOptions.IgnoreCase);
        if (o.MaskMacAddresses) s = Mac().Replace(s, "<MAC>");
        if (o.MaskIpAddresses)
        {
            s = Ipv4().Replace(s, x => IPAddress.TryParse(x.Value, out var a) && !IsHarmless(a) ? "<IP>" : x.Value);
            s = Ipv6Candidate().Replace(s, x =>
                IPAddress.TryParse(x.Value.Split('%')[0], out var a) && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && !IsHarmless(a)
                    ? "<IPv6>" : x.Value);
        }
        return s;
    }

    /// <summary>0.0.0.0, ::, localhost не раскрывают ничего о сети пользователя.</summary>
    private static bool IsHarmless(IPAddress a) => IPAddress.IsLoopback(a) || a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any) || a.Equals(IPAddress.Broadcast);

    private static JsonNode? MaskNode(JsonNode? node, MaskOptions o)
    {
        switch (node)
        {
            case JsonObject obj:
                foreach (var key in obj.Select(kv => kv.Key).ToList())
                    obj[key] = MaskNode(obj[key], o);
                return obj;
            case JsonArray arr:
                for (var i = 0; i < arr.Count; i++) arr[i] = MaskNode(arr[i], o);
                return arr;
            case JsonValue v when v.TryGetValue<string>(out var s):
                return JsonValue.Create(MaskText(s, o));
            default:
                return node;
        }
    }
}
