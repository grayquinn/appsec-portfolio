# OWASP Top 10 — My Personal Reference Notes
**Written by:** Grayson Quinn  
**Stack:** C#, ASP.NET Core MVC, REST APIs, SQL Server, Azure DevOps  
**Goal:** Defensive Application Security Engineering  
**Last Updated:** May 2026

> These are my personal notes on the OWASP Top 10 written from my perspective 
> as a C# .NET developer. I'm using this as both a study reference and a reminder 
> of what to look for when doing secure code review. Every example is written in 
> C# because that's my stack and that's what I'll be securing.

---

## A01 — Broken Access Control

This one hit me the hardest when I first learned about it because I realized 
it's something that's easy to miss when you're heads down building features. 
You build a controller, you wire up the database query, everything works — but 
you never stopped to ask "should THIS user be allowed to see THIS data?"

Broken access control is basically when the app doesn't properly enforce who 
can do what. The most common version I keep seeing is called IDOR — Insecure 
Direct Object Reference. That's when a user can just change an ID in a URL or 
request body and get someone else's data back.

In my day-to-day C# work this shows up when you query by an ID that came 
from the user without checking ownership:

```csharp
// This is the problem — I'm just finding the record by ID
// without checking if the logged in user actually owns it
[HttpGet("/api/orders/{id}")]
public IActionResult GetOrder(int id)
{
    var order = db.Orders.Find(id);
    return Ok(order); // anyone who knows any order ID gets it
}
```

The fix is always to tie the query back to the authenticated user:

```csharp
// Now I'm verifying the order actually belongs to who's asking
[HttpGet("/api/orders/{id}")]
[Authorize]
public IActionResult GetOrder(int id)
{
    var userId = User.GetUserId();
    var order = db.Orders
        .Where(o => o.Id == id && o.UserId == userId)
        .FirstOrDefault();

    if (order == null) return Forbid();
    return Ok(order);
}
```

**What I remind myself:** The `[Authorize]` attribute just checks if you're 
logged in. It doesn't check if you're allowed to touch THIS specific record. 
That ownership check has to be done manually every single time.

**Real world risk for apps like mine:** Internal insurance apps that handle 
policy data, claims, and personal information are perfect targets for this. 
An employee with basic access could potentially view other employees' records 
or policy data just by incrementing an ID. Even internal apps need this.

**OWASP rank:** #1 — most common vulnerability found in real apps today.

---

## A02 — Cryptographic Failures

This one is about sensitive data not being protected properly — either stored 
in plain text, transmitted without encryption, or protected with algorithms 
that are outdated and crackable.

The most obvious version is storing passwords in plain text. But the sneaky 
version that catches developers off guard is using MD5 or SHA1 to hash 
passwords. Those algorithms are broken — an attacker with your database can 
crack MD5 hashed passwords in seconds using rainbow tables. I had no idea 
how fast that was until I started studying this.

```csharp
// These are both wrong — MD5 and SHA1 are broken for passwords
user.Password = Convert.ToBase64String(
    MD5.HashData(Encoding.UTF8.GetBytes(password)));

user.Password = Convert.ToBase64String(
    SHA1.HashData(Encoding.UTF8.GetBytes(password)));
```

The correct approach for passwords is bcrypt, Argon2, or PBKDF2 — these are 
specifically designed to be slow, which makes brute forcing them impractical:

```csharp
// bcrypt is intentionally slow — that's the whole point
// workFactor: 12 means 2^12 iterations
using BCrypt.Net;

user.PasswordHash = BCrypt.HashPassword(password, workFactor: 12);

// Verifying on login:
bool isValid = BCrypt.Verify(inputPassword, user.PasswordHash);
```

**What I remind myself:** There's a difference between hashing and encryption. 
Hashing is one-way — you hash a password and compare hashes. Encryption is 
two-way — you can decrypt it. Passwords should always be hashed, never 
encrypted. If you can retrieve a plain text password from your system, 
something is wrong.

**Real world risk for apps like mine:** Insurance apps handle personal 
information, login credentials, and potentially health data. If our database 
got breached and passwords were stored with MD5, every user account would be 
compromised in hours. ASP.NET Identity handles this correctly by default — 
the risk is when developers roll their own auth or touch the password logic.

**Key rules I follow:**
- Never MD5 or SHA1 for passwords
- Always HTTPS — never HTTP for anything sensitive
- Never log passwords, SSNs, or card numbers
- Use Azure Key Vault for secrets — never hardcode them

---

## A03 — Injection

This is the classic one everyone talks about and for good reason — it's been 
on the OWASP list since the beginning. Injection is when user input gets 
passed directly to an interpreter — a database, OS shell, LDAP server — 
without being sanitized first. The attacker writes code instead of data.

SQL injection is the most common version. The reason this clicked so hard 
for me is because I know SQL Server well. The moment I saw a string 
concatenation query I immediately understood why it was dangerous:

```csharp
// I've seen code like this before — it looks harmless but it's not
// Attacker enters: ' OR '1'='1'--
string query = "SELECT * FROM Users WHERE Email = '" 
               + userInput + "'";

// That becomes:
// SELECT * FROM Users WHERE Email = '' OR '1'='1'--'
// The OR '1'='1' is always true — returns every user in the database
// The -- comments out the rest of the query
```

The good news for me as a .NET developer is that Entity Framework 
parameterizes queries automatically:

```csharp
// Entity Framework does this safely — no injection possible
var user = db.Users
    .Where(u => u.Email == email)
    .FirstOrDefault();

// If I have to write raw SQL for some reason:
// ALWAYS use parameters, never string concatenation
var users = db.Users.FromSqlRaw(
    "SELECT * FROM Users WHERE Email = {0}", email);
```

**What I remind myself:** Entity Framework protects me by default but the 
danger zone is `FromSqlRaw()` with string building, stored procedures that 
concatenate input, or any legacy code that predates EF. Those are what I 
look for in code reviews.

**Real world risk for apps like mine:** SQL injection in an insurance 
application could expose every policy record, claim, and personal data point 
in the database in a single attack. It's also one of the most automated 
attacks — tools like sqlmap can test thousands of injection points 
automatically. If it's there, someone will find it.

**Beyond SQL — injection applies to:**
- LDAP queries
- OS commands (Process.Start with user input)
- XML/XPath queries
- Any place where user input becomes part of a command

---

## A04 — Insecure Design

This one is different from the others because it's not a bug you can patch. 
The security problem is baked into how the feature was designed before a 
single line of code was written. You can't fix it by updating a library or 
sanitizing an input — you have to redesign the feature entirely.

The example that made this click for me was a password reset flow that sends 
a 4-digit PIN. That sounds reasonable until you realize there are only 10,000 
possible combinations. An attacker can write a script to try all of them. 
The design itself is the vulnerability.

```csharp
// This design is broken before it's even coded
// 4 digits = 10,000 combinations = brutable in minutes
int pin = random.Next(1000, 9999);
// Even if the code is perfectly written, the design fails

// Secure design uses cryptographically random tokens
// that are practically impossible to guess
string resetToken = Convert.ToBase64String(
    RandomNumberGenerator.GetBytes(32)
);
// 256 bits of randomness — not brutable in any reasonable time
// Also needs: expiry time, one-time use, rate limiting
```

**What I remind myself:** This is why threat modeling matters. Before I build 
a feature I should ask "how would someone abuse this?" The STRIDE framework 
is what AppSec engineers use — Spoofing, Tampering, Repudiation, Information 
Disclosure, Denial of Service, Elevation of Privilege. Run every feature 
through those six lenses during design.

**Real world risk for apps like mine:** Insurance apps have complex business 
workflows — policy approvals, claims submissions, payment processing. Each 
of those workflows has potential for insecure design if nobody is asking 
"how would an attacker abuse this flow?" during the design phase. This is 
exactly the kind of thing an AppSec engineer catches before development starts.

**Key design questions I ask now:**
- What happens if someone submits this 1000 times?
- What happens if someone changes this ID to someone else's?
- What happens if someone skips step 2 of this multi-step process?
- Is there rate limiting on this action?

---

## A05 — Security Misconfiguration

The software is fine. The way it's set up is the problem. This is one of 
the most common vulnerabilities in real enterprise applications because it's 
easy to set something up for development and forget to change it before 
going to production.

The version that hits closest to home for me as a .NET Azure DevOps developer 
is debug mode left on in production. When ASPNETCORE_ENVIRONMENT is set to 
Development in production, users see full stack traces when something breaks. 
That stack trace tells an attacker your framework version, your file paths, 
your database structure — basically a roadmap.

```csharp
// appsettings.json — dangerous if this goes to production
{
    "DetailedErrors": true,
    "ASPNETCORE_ENVIRONMENT": "Development"
}
// Full stack traces visible to anyone who hits an error

// appsettings.Production.json — what it should be
{
    "DetailedErrors": false,
    "ASPNETCORE_ENVIRONMENT": "Production"  
}
// Generic error page for users
// Full details logged server-side only where only I can see them
```

**What I remind myself:** Misconfiguration isn't just about debug mode. 
It's also secrets committed to Git, default admin passwords never changed, 
unnecessary features left enabled, Azure storage containers accidentally 
set to public, and CORS policies that are too permissive. In my Azure DevOps 
work this is something I think about with every pipeline and every deployment.

**Real world risk for apps like mine:** I've worked on CI/CD pipelines 
extensively. A secret accidentally committed to a Git repo — a connection 
string, an API key, an Azure credential — is a real misconfiguration risk 
in that environment. Tools like GitGuardian and GitHub's secret scanning 
exist specifically for this reason.

**Key things I check:**
- Is debug mode off in production?
- Are there any secrets in appsettings.json committed to Git?
- Are default passwords changed on every service?
- Is the Azure storage container actually private?
- Are error responses generic to users but detailed in logs?

---

## A06 — Vulnerable and Outdated Components

Your code is perfectly written. A library you're using has a known security 
hole. An attacker exploits the library, not your code. This is the one that 
keeps me up a little bit now that I understand it — because every single 
NuGet package and npm dependency in my projects is a potential attack surface 
that I didn't write and can't fully control.

Log4Shell in 2021 is the example everyone uses. One Java logging library 
had a remote code execution vulnerability and it took down thousands of 
companies worldwide — companies whose own code was perfectly fine. The 
library they were using wasn't.

```csharp
// In my .csproj files I might have something like:
<PackageReference Include="SomePackage" Version="2.1.0" />

// If version 2.1.0 has CVE-2023-XXXXX — remote code execution —
// my entire application is vulnerable even if my code is perfect

// How to check:
dotnet list package --vulnerable
// This command shows any NuGet packages with known CVEs
```

**What I remind myself:** This is exactly why SCA (Software Composition 
Analysis) tools exist. Snyk and Dependabot scan your dependencies automatically 
and alert you when a CVE is found in something you're using. In my Azure 
DevOps CI/CD pipelines, adding a Snyk scan is a one-step security improvement 
that catches this automatically on every build.

**Real world risk for apps like mine:** ASP.NET Core, Entity Framework, 
Newtonsoft.Json, and every other package I use regularly gets security 
updates. If I'm not keeping them updated and scanning for CVEs I'm 
potentially running known vulnerabilities in production without knowing it.

**How I plan to address this:**
- Add `dotnet list package --vulnerable` to CI/CD pipeline
- Enable Dependabot on GitHub repos
- Add Snyk scanning to Azure DevOps pipelines
- Remove unused packages — less surface area = less risk
- Subscribe to security advisories for key dependencies

---

## A07 — Identification and Authentication Failures

This is everything wrong with how login and session management gets 
implemented. No brute force protection, weak password requirements, 
session tokens that never expire, credentials in URLs, broken remember me 
functionality. The end result is account takeover — someone logs into the 
app as you.

What made this real for me is understanding credential stuffing. Attackers 
buy lists of leaked username/password combinations from previous breaches 
and try them against your app automatically. If your users reuse passwords 
from other sites — which most people do — and you have no rate limiting or 
lockout, those accounts get taken over without the attacker even needing to 
brute force anything.

```csharp
// No rate limiting, no lockout — attacker can try forever
[HttpPost("/login")]
public IActionResult Login(string email, string password)
{
    if (db.Users.Any(u => u.Email == email 
                       && u.Password == password))
    {
        Session["userId"] = email; // session never expires
        return Ok();
    }
    return Unauthorized(); // silent failure, no lockout
}

// The correct approach — ASP.NET Identity handles this
services.Configure<IdentityOptions>(options =>
{
    // Lock account after 5 failed attempts for 15 minutes
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.DefaultLockoutTimeSpan = 
        TimeSpan.FromMinutes(15);
    
    // Require strong passwords
    options.Password.RequiredLength = 12;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireDigit = true;
});
```

**What I remind myself:** ASP.NET Identity exists for a reason. It handles 
password hashing, account lockout, and session management correctly out of 
the box. The risk is always when developers bypass it and roll their own 
authentication. If I ever see custom auth code in a codebase during a 
security review, that's the first place I look.

**Real world risk for apps like mine:** An insurance app with employee 
logins handling sensitive policy and claims data is exactly the type of 
target credential stuffing attacks go after. One compromised employee 
account could expose thousands of customer records.

**Key things I look for:**
- Is there account lockout after failed attempts?
- Are sessions invalidated on logout?
- Are JWT tokens short-lived with refresh tokens?
- Are passwords validated for strength server-side?
- Is MFA available for sensitive operations?

---

## A08 — Software and Data Integrity Failures

This one is about making sure the code and updates your app uses haven't 
been tampered with. The scary version is a supply chain attack — where an 
attacker gets inside your build pipeline or a dependency repository and 
injects malicious code into your software before it even ships.

SolarWinds in 2020 is the textbook example. Attackers compromised 
SolarWinds' build system and inserted malicious code into legitimate 
software updates that were then distributed to thousands of customers 
including government agencies. The customers' own code was fine. The 
update mechanism was compromised.

```html
<!-- Loading a script from CDN without integrity verification -->
<!-- If this CDN gets compromised you serve malware to your users -->
<script src="https://cdn.example.com/library.min.js"></script>

<!-- Subresource Integrity (SRI) — browser verifies the hash -->
<!-- If the file was tampered with the browser refuses to run it -->
<script 
    src="https://cdn.example.com/library.min.js"
    integrity="sha384-oqVuAfXRKap7fdgceMaMo..."
    crossorigin="anonymous">
</script>
```

**What I remind myself:** In my Azure DevOps CI/CD work, the pipeline 
configuration itself is a high-value attack target. If an attacker can 
modify my pipeline YAML they can inject malicious steps into my build 
process. Pipeline code should be treated with the same security review 
process as production application code — because it effectively is 
production code.

**Real world risk for apps like mine:** Any JavaScript loaded from a CDN 
in our web apps, any NuGet package pulled during a pipeline build, any 
Docker image pulled from a registry — all of these are integrity risks if 
not verified. This is where package signing and checksum verification matter.

**Key practices:**
- Use SRI hashes for CDN scripts
- Verify package checksums in CI/CD
- Use private NuGet feeds for internal packages
- Treat pipeline YAML like production code
- Review any new dependencies before adding them

---

## A09 — Security Logging and Monitoring Failures

If you don't log it you can't detect it. That's the whole thing in one 
sentence. This vulnerability is about apps that don't log security events, 
don't monitor those logs, or don't alert when something suspicious happens. 
The result is attackers operating inside your systems for months without 
anyone knowing.

The stat that made this real for me is that the average breach goes 
undetected for over 200 days. That's not because the evidence wasn't there — 
it's because nobody was watching the logs or the logs didn't exist.

This one connects directly to where I want to go with Detection Engineering 
eventually. Detection engineers depend on applications logging the right 
things. If a developer doesn't log failed login attempts, no detection rule 
in the world can catch a brute force attack against that endpoint.

```csharp
// No logging — security events disappear into the void
[HttpPost("/login")]
public IActionResult Login(LoginModel model)
{
    if (!IsValid(model)) 
        return Unauthorized();
    // 50,000 failed attempts could happen here
    // and nobody would ever know
}

// Proper security logging — who, what, when, from where
[HttpPost("/login")]
public IActionResult Login(LoginModel model)
{
    var ip = HttpContext.Connection.RemoteIpAddress?.ToString();
    var timestamp = DateTime.UtcNow;

    if (!IsValid(model))
    {
        _logger.LogWarning(
            "SECURITY: Failed login attempt for {Email} " +
            "from IP {IP} at {Timestamp}",
            model.Email, ip, timestamp);
        return Unauthorized();
    }

    _logger.LogInformation(
        "SECURITY: Successful login for {Email} " + 
        "from IP {IP} at {Timestamp}",
        model.Email, ip, timestamp);
    return Ok();
}
```

**What I remind myself:** Never log the password itself or any sensitive 
data — only the fact that an event happened, who it involved, when, and 
from where. The goal is enough context to investigate an incident without 
creating a new security problem by logging things you shouldn't.

**Real world risk for apps like mine:** An insurance app with no security 
logging is flying blind. If someone is slowly exfiltrating policy data one 
record at a time there's nothing to detect it. Proper logging fed into a 
SIEM like Azure Sentinel creates the visibility needed to catch that kind 
of low-and-slow attack.

**What every app should log:**
- Every failed login — who, when, from where
- Every successful login
- Every access control failure (403 responses)
- Every input validation failure
- Any privilege escalation action
- Any sensitive data access

**What to NEVER log:**
- Passwords (even failed ones)
- Full credit card numbers
- SSNs or government IDs
- Session tokens or API keys

---

## A10 — Server-Side Request Forgery (SSRF)

This was the one I hadn't heard of before studying AppSec and it's now one 
of the ones I think about most. SSRF is when an app fetches a URL that the 
user provides — and an attacker points it at internal infrastructure that 
should never be reachable from the outside.

The most dangerous target is the cloud metadata endpoint. In AWS it's 
`http://169.254.169.254/latest/meta-data/` and in Azure it's 
`http://169.254.169.254/metadata/instance`. These endpoints return the 
server's own cloud credentials — IAM roles, access tokens, everything. 
An attacker who gets your app to fetch that URL gets your cloud keys.

```csharp
// Any feature that fetches a user-supplied URL is potentially vulnerable
// URL preview, image fetch, webhook, PDF generator — all of these

[HttpPost("/preview")]
public async Task<IActionResult> PreviewUrl(string url)
{
    // Attacker submits: http://169.254.169.254/latest/meta-data/
    // Our server fetches our own AWS/Azure credentials
    // and returns them to the attacker
    var response = await _httpClient.GetAsync(url);
    return Ok(await response.Content.ReadAsStringAsync());
}

// Safe version — validate and restrict what URLs are allowed
[HttpPost("/preview")]
public async Task<IActionResult> PreviewUrl(string url)
{
    // Parse the URL first
    if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
        return BadRequest("Invalid URL");

    // Whitelist only allowed domains
    var allowedHosts = new[] { "trusted-partner.com", "cdn.oursite.com" };
    if (!allowedHosts.Contains(uri.Host.ToLower()))
        return BadRequest("Domain not permitted");

    // Block private/internal IP ranges
    if (await IsInternalAddress(uri.Host))
        return BadRequest("Internal addresses not permitted");

    var response = await _httpClient.GetAsync(uri);
    return Ok(await response.Content.ReadAsStringAsync());
}
```

**What I remind myself:** Any feature I build that takes a URL and makes 
an HTTP request with it needs SSRF protection. This includes image upload 
features that fetch from a URL, webhook handlers, URL preview features, 
PDF generators that render remote content, and any API integration that 
passes through a user-supplied URL.

**Real world risk for apps like mine:** Insurance apps with integrations 
to external services — document generation, third-party APIs, email 
services — could have SSRF vectors in those integration points. Given 
that our apps run on Azure, an SSRF attack that hits the Azure metadata 
endpoint could expose our Azure managed identity credentials.

**Private IP ranges to always block:**
```
10.0.0.0/8        — Private network
172.16.0.0/12     — Private network  
192.168.0.0/16    — Private network
127.0.0.0/8       — Localhost
169.254.0.0/16    — Cloud metadata (the dangerous one)
::1               — IPv6 localhost
```

---

## Quick Reference — All 10 at a Glance

| # | Vulnerability | One Line Summary | My C# Risk |
|---|---|---|---|
| A01 | Broken Access Control | Verify ownership on every resource | Missing ownership checks in controller queries |
| A02 | Cryptographic Failures | Use bcrypt, always HTTPS, no MD5 | Custom auth bypassing ASP.NET Identity |
| A03 | Injection | Never concatenate user input into queries | Raw SQL with string building |
| A04 | Insecure Design | Threat model before you build | No rate limiting on sensitive workflows |
| A05 | Security Misconfiguration | Lock down every environment | Debug mode, secrets in Git, public storage |
| A06 | Vulnerable Components | Scan and update your dependencies | Outdated NuGet packages with CVEs |
| A07 | Auth Failures | Use ASP.NET Identity, add lockout, MFA | Custom auth, no lockout, weak sessions |
| A08 | Integrity Failures | Verify what your pipeline runs | Pipeline YAML tampering, CDN scripts |
| A09 | Logging Failures | Log who, what, when, where | Missing security event logging |
| A10 | SSRF | Whitelist URLs, block internal IPs | Features that fetch user-supplied URLs |

---

## What This Means for My AppSec Path

Going through these 10 vulnerabilities as a C# .NET developer made me 
realize something — I've probably written code that had some of these 
issues without knowing it. Not because I was careless but because nobody 
taught me to think about it from an attacker's perspective.

That's exactly what AppSec engineering is. It's bringing the attacker's 
perspective into the development process so these issues get caught before 
they ship. As someone who's been on the builder side for 3 years I think 
I have a unique advantage — I understand why developers write vulnerable 
code, which makes me better at finding it and explaining how to fix it.

---

*These notes are personal and written from my own understanding. 
They reference my actual tech stack and the kinds of applications 
I've built professionally. Updated as my knowledge grows.*
