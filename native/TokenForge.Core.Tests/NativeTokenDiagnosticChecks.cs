using TokenForge.Core.V0100;

internal static class NativeTokenDiagnosticChecks
{
    public static void Run(Action<bool> check)
    {
        var now = DateTimeOffset.UtcNow;
        void Verify(string expected, string tenant="a", string audience="https://graph.microsoft.com", string[]? scopes=null, DateTimeOffset? expiry=null)
        {
            try { TokenPolicy.Validate(tenant,"b","c",audience,"a","b","c","00000003-0000-0000-c000-000000000000",scopes ?? new[]{"User.Read"},new[]{"User.Read"},true,expiry ?? now.AddHours(1),now.AddHours(1),0,0,false,now); }
            catch(Exception error)
            {
                var failure=new NativeTokenException("TokenPolicyRejected",error.Message);
                check(failure.Reason==expected);check(failure.IdentityErrorCodes.Length==0);check(failure.HttpStatus==null);return;
            }
            throw new Exception("Expected issued-policy rejection.");
        }
        Verify("IdentityOrClientMismatch",tenant:"wrong");
        Verify("ScopeOrResourceMismatch",audience:"https://example.test");
        Verify("ScopeOrResourceMismatch",scopes:new[]{"Mail.Read"});
        Verify("TokenLifetimeInsufficient",expiry:now.AddSeconds(30));
        Verify("AdditionalScopePolicyExceeded",scopes:new[]{"User.Read","Mail.Read"});
        var privateDiagnostic="synthetic-private-cookie Token exceeds the profile additional-scope policy.";
        check(new NativeTokenException("TokenPolicyRejected",privateDiagnostic).Reason=="ValidationFailed");
        check(new NativeTokenException("TokenAcquisitionFailed","Token exceeds the profile additional-scope policy.").Reason=="ValidationFailed");
        var decline=new NativeTokenException("TokenAcquisitionFailed","Silent browser authorization declined. AADSTS65002 AADSTS65002 HTTP 400 synthetic-private-cookie");
        check(decline.Reason=="SilentAuthorizationDeclined");check(decline.IdentityErrorCodes.SequenceEqual(new[]{"65002"}));check(decline.HttpStatus==400);
        check(!decline.Message.Contains("synthetic-private",StringComparison.Ordinal));
        check(new NativeTokenException("TokenPolicyRejected","Unknown synthetic-private error.").Reason=="ValidationFailed");
    }
}
