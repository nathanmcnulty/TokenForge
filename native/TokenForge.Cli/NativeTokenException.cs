using System.Text.RegularExpressions;

internal sealed class NativeTokenException : Exception
{
    public string Code { get; }
    public string Reason { get; }
    public string[] IdentityErrorCodes { get; }
    public int? HttpStatus { get; }
    public NativeTokenException(string code, string diagnostic)
    {
        Code = code;
        Reason = code == "TokenPolicyRejected" ? diagnostic switch
        {
            "Token identity or client does not match the profile." => "IdentityOrClientMismatch",
            "Token resource or delegated scopes do not match the request." => "ScopeOrResourceMismatch",
            "Token has unknown or insufficient remaining lifetime." => "TokenLifetimeInsufficient",
            "Token exceeds the profile additional-scope policy." => "AdditionalScopePolicyExceeded",
            _ => "ValidationFailed"
        } : (diagnostic.StartsWith("Silent authorization", StringComparison.Ordinal) || diagnostic.StartsWith("Silent browser authorization", StringComparison.Ordinal)) ? "SilentAuthorizationDeclined" : diagnostic.StartsWith("Identity transport", StringComparison.Ordinal) ? "TransportFailed" : diagnostic.StartsWith("Token request failed", StringComparison.Ordinal) ? "TokenEndpointRejected" : "ValidationFailed";
        IdentityErrorCodes = Regex.Matches(diagnostic, @"\bAADSTS([0-9]{4,9})\b").Select(m => m.Groups[1].Value).Distinct().Take(5).ToArray();
        var status = Regex.Match(diagnostic, @"\bHTTP ([1-5][0-9]{2})\b");
        HttpStatus = status.Success ? int.Parse(status.Groups[1].Value) : null;
    }
}
