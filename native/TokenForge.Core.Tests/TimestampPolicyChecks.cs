using System.Globalization;
using TokenForge.Core.V0240;

static class TimestampPolicyChecks
{
 public static void Run(Action<bool> check, Action<Action> reject)
 {
  var utc=new DateTime(2026,10,11,1,16,41,DateTimeKind.Utc);
  check(TimestampPolicy.Parse(utc).UtcDateTime==utc);
  check(TimestampPolicy.Parse(utc).Offset==TimeSpan.Zero);
  var offset=new DateTimeOffset(2026,10,11,9,16,41,TimeSpan.FromHours(8));
  check(TimestampPolicy.Parse(offset)==new DateTimeOffset(utc));
  check(TimestampPolicy.Parse(offset).Offset==offset.Offset);
  check(TimestampPolicy.Parse(utc.ToLocalTime())==new DateTimeOffset(utc));
  check(TimestampPolicy.Parse("2026-10-11T01:16:41Z")==new DateTimeOffset(utc));
  check(TimestampPolicy.Parse("2026-10-11T09:16:41+08:00")==new DateTimeOffset(utc));
  var previous=CultureInfo.CurrentCulture;
  try {
   CultureInfo.CurrentCulture=CultureInfo.GetCultureInfo("fr-FR");
   var legacy=TimestampPolicy.Parse("17/10/2026 12:34:56");
   check(legacy.Year==2026 && legacy.Month==10 && legacy.Day==17 && legacy.Hour==12);
  }finally{CultureInfo.CurrentCulture=previous;}
  check(TimestampPolicy.TryParse(utc,out var projected) && projected.UtcDateTime==utc);
  check(!TimestampPolicy.TryParse("synthetic-secret",out projected) && projected==default);
  check(!TimestampPolicy.TryParse(null,out projected));
  reject(()=>TimestampPolicy.Parse(null));reject(()=>TimestampPolicy.Parse(1));reject(()=>TimestampPolicy.Parse(new object()));
  try{TimestampPolicy.Parse("synthetic-secret");throw new Exception("Expected rejection.");}
  catch(InvalidOperationException error){check(error.InnerException==null && !error.ToString().Contains("synthetic-secret"));}
 }
}
