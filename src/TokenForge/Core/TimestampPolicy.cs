#nullable enable
using System;
using System.Globalization;

namespace TokenForge.Core.V0240
{
    // PowerShell JSON projections may contain DateTime values instead of strings.
    // Preserve their Kind rather than stringifying and reinterpreting in the local zone.
    public static class TimestampPolicy
    {
        public static bool TryParse(object? value, out DateTimeOffset timestamp)
        {
            timestamp = default;
            try { timestamp = Parse(value); return true; }
            catch { return false; }
        }

        public static DateTimeOffset Parse(object? value)
        {
            try
            {
                if (value is DateTimeOffset offset) return offset;
                if (value is DateTime date) return new DateTimeOffset(date);
                // Retain historical current-culture string parsing for existing records.
                if (value is string text) return DateTimeOffset.Parse(text, CultureInfo.CurrentCulture);
                throw new InvalidOperationException();
            }
            catch { throw new InvalidOperationException("Timestamp is invalid. Details suppressed."); }
        }
    }
}
