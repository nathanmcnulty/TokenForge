using System;
using System.Collections.Generic;
using System.Linq;

namespace TokenForge.Core.V0100
{
    // Credential-free inputs only. OAuth and secret ownership stay outside this policy boundary.
    public static class TokenPolicy
    {
        public static int Validate(string tenant, string principal, string client, string audience,
            string expectedTenant, string expectedPrincipal, string expectedClient, string resource,
            string[] issuedScopes, string[] requestedScopes, bool hasDelegatedClaim,
            DateTimeOffset? jwtExpiry, DateTimeOffset? responseExpiry, int maximumAdditionalScopes,
            int responseAdditionalScopeCount, bool allowExpired, DateTimeOffset now)
        {
            if (string.IsNullOrEmpty(expectedClient) || string.IsNullOrEmpty(client) || string.IsNullOrEmpty(expectedTenant) || string.IsNullOrEmpty(expectedPrincipal) ||
                !string.Equals(tenant, expectedTenant, StringComparison.Ordinal) ||
                !string.Equals(principal, expectedPrincipal, StringComparison.Ordinal) ||
                !string.Equals(client, expectedClient, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Token identity or client does not match the profile.");
            var audiences = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { resource };
            if (resource == "00000003-0000-0000-c000-000000000000") audiences.Add("https://graph.microsoft.com");
            if (resource == "797f4846-ba00-4fd7-ba43-dac1f8f63013")
            {
                audiences.Add("https://management.azure.com");
                audiences.Add("https://management.core.windows.net");
            }
            var issued = new HashSet<string>(issuedScopes ?? Array.Empty<string>(), StringComparer.Ordinal);
            var requested = new HashSet<string>(requestedScopes ?? Array.Empty<string>(), StringComparer.Ordinal);
            if (requested.Count == 0 || !hasDelegatedClaim || string.IsNullOrEmpty(audience) ||
                !audiences.Contains(audience.TrimEnd('/')) || !requested.IsSubsetOf(issued))
                throw new InvalidOperationException("Token resource or delegated scopes do not match the request.");
            if (!jwtExpiry.HasValue || !responseExpiry.HasValue || (!allowExpired &&
                (jwtExpiry.Value <= now.AddMinutes(2) || responseExpiry.Value <= now.AddMinutes(2))))
                throw new InvalidOperationException("Token has unknown or insufficient remaining lifetime.");
            issued.ExceptWith(requested);
            issued.ExceptWith(new[] { "openid", "profile", "email", "offline_access" });
            if (responseAdditionalScopeCount < 0 || maximumAdditionalScopes < 0 || issued.Count > maximumAdditionalScopes ||
                responseAdditionalScopeCount > maximumAdditionalScopes)
                throw new InvalidOperationException("Token exceeds the profile additional-scope policy.");
            return issued.Count;
        }
    }
}
