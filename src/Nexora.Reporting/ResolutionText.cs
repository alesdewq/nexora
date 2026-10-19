namespace Nexora.Reporting;

public static class ResolutionText
{
    public static string ToDisplay(this ResolutionStatus s) => s switch
    {
        ResolutionStatus.None => "не отмечено",
        ResolutionStatus.InProgress => "в работе",
        ResolutionStatus.Resolved => "устранено",
        ResolutionStatus.Accepted => "принято как есть",
        _ => s.ToString(),
    };
}
