namespace Qhub.Domain;

public sealed class TrafficStat
{
    public DateOnly Day { get; set; }
    public long BytesServed { get; set; }
    public int Downloads { get; set; }
}
