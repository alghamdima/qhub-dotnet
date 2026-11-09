namespace Qhub.Tests.Support;

public static class Pending
{
    /// <summary>
    /// Marks a Behavior Contract test as not implemented yet (reported as skipped). <paramref name="awaitingQ1"/> is for
    /// corrected rules whose Q1 box in MODERNIZATION_BRIEF.md is not ticked.
    /// </summary>
    public static void Rule(string ruleId, bool awaitingQ1 = false) =>
        Assert.Inconclusive(awaitingQ1 ? $"pending: {ruleId}, awaiting Q1" : $"pending: {ruleId}");
}
