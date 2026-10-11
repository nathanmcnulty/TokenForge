BeforeAll {Import-Module "$PSScriptRoot/../src/TokenForge/TokenForge.psd1" -Force}
Describe 'Shared profile configuration validation through the module' {
 BeforeEach {
  $base=if($IsMacOS){$TestDrive -replace '^/var/','/private/var/'}else{$TestDrive}
  $root=Join-Path $base ([guid]::NewGuid().ToString())
  $null=New-TokenForgeProfile -Name lab -Tenant example.test -Root $root
  $path=Join-Path $root lab/profile.json
 }
 It 'rejects exact, escaped, and case-colliding duplicate configuration fields' {
  $json=Get-Content $path -Raw
  foreach($field in @('Name','Na\u006de','name')){
   ('{"'+$field+'":"lab",'+$json.Substring($json.IndexOf('{')+1))|Set-Content $path
   {Get-TokenForgeProfile -Name lab -Root $root}|Should -Throw '*Details suppressed*'
  }
 }
 It 'keeps ISO offset timestamps readable as the existing UTC projection' {
  $profile=Get-Content $path -Raw|ConvertFrom-Json -AsHashtable
  $profile.CreatedAt='2026-10-07T05:00:00-07:00';$profile.UpdatedAt='2026-10-07T20:00:00+08:00'
  $profile|ConvertTo-Json -Depth 4|Set-Content $path
  $read=Get-TokenForgeProfile -Name lab -Root $root
  foreach($field in @('CreatedAt','UpdatedAt')){([DateTimeOffset]$read.$field).ToUniversalTime()|Should -Be ([DateTimeOffset]'2026-10-07T12:00:00Z')}
 }
 It 'preserves the existing process-culture timestamp parsing' {
  $previous=[Threading.Thread]::CurrentThread.CurrentCulture
  try{
   [Threading.Thread]::CurrentThread.CurrentCulture=[Globalization.CultureInfo]::GetCultureInfo('en-GB')
   $profile=Get-Content $path -Raw|ConvertFrom-Json -AsHashtable
   $profile.CreatedAt='31/12/2025 12:00:00 +00:00';$profile.UpdatedAt=$profile.CreatedAt
   $profile|ConvertTo-Json -Depth 4|Set-Content $path
   (Get-TokenForgeProfile -Name lab -Root $root).CreatedAt|Should -Be $profile.CreatedAt
  }finally{[Threading.Thread]::CurrentThread.CurrentCulture=$previous}
 }
}
