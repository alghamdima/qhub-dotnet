using Microsoft.Extensions.Configuration;
using Qhub.Configuration;

namespace Qhub.Tests.Configuration;

[TestClass]
public sealed class QhubOptionsTests
{
    [TestMethod]
    public void SecretIsReadFromItsFileVariant()
    {
        var file = Path.GetTempFileName();
        File.WriteAllText(file, "fake-file-password\n");

        var options = Load(new() { ["QHUB_ADMIN_PASSWORD_FILE"] = file });

        Assert.AreEqual("fake-file-password", options.AdminPassword);
        Assert.IsEmpty(options.LoadErrors);
    }

    [TestMethod]
    public void SettingBothFormsOfASecretIsAnError()
    {
        var options = Load(new() { ["QHUB_DB_CONNECTION"] = "Server=fake", ["QHUB_DB_CONNECTION_FILE"] = "fake-path" });

        var result = new QhubOptionsValidator().Validate(null, options);

        Assert.Contains("Set QHUB_DB_CONNECTION or QHUB_DB_CONNECTION_FILE, not both", result.Failures!);
    }

    static QhubOptions Load(Dictionary<string, string?> values)
    {
        var options = new QhubOptions();
        options.Load(new ConfigurationBuilder().AddInMemoryCollection(values).Build());
        return options;
    }
}
