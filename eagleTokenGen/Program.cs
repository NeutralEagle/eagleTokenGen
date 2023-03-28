using System.Net;
using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Text;

bool debug = false;

const int portLen = 5;
string? sn;

#region prep and ui
if (!debug)
{
    Console.Write("Input MS serial number in format (504F94A00000): ");
    do { sn = Console.ReadLine(); if (sn == null) sn = ""; }
    while (sn.Length != 12 && !sn.StartsWith("504F94"));
}//automatic start //manual start
else sn = "504F94A07B77"; 

string getip = httpGet($"https://dns.loxonecloud.com/?getip&snr={sn}");
if (!getip.StartsWith('<')) 
{
    Console.WriteLine($"Error: {getip}");
    Console.ReadKey();
    Environment.Exit(0); 
}
string ip = getip.Split("\"")[5];
string port = ip[^portLen..];
ip = ip[..(ip.Length - portLen - 1)];
string url = $"https://{ip.Replace('.', '-')}.{sn}.dyndns.loxonecloud.com:{port}";

string? user = "admin"; //debug = default username = admin
if (!debug) 
{
    Console.Write("Input username (case sensitive): ");
    user = Console.ReadLine(); 

} //user input username

string? password = "loxone"; //debug = default password = loxone
if(!debug)
{
    Console.Write("Input password (case sensitive): ");
    password = Console.ReadLine(); 
} //user input password

const char permission = '4';

string uuidRandom = $"{BytesToString(byteGen(4))}-{BytesToString(byteGen(2))}-{BytesToString(byteGen(2))}-{BytesToString(byteGen(8))}";
const string info = "doesntmatter";
#endregion

#region token
string? json = getJsonObj(url,$"/jdev/sys/getkey2/{user}", debug);
Root? getkey2 = new();
if (json != null)
{ getkey2 = JsonConvert.DeserializeObject<Root>(json); }
#pragma warning disable CS8602 // Přístup přes ukazatel k možnému odkazu s hodnotou null
if (getkey2 == null || getkey2.LL.value.key == null || getkey2.LL.value.salt ==null || getkey2.LL.value.hashAlg ==null)
{
    Console.WriteLine($"Error fetching getkey2");
    Console.ReadKey();
    Environment.Exit(0);
}
#pragma warning restore CS8602 // Přístup přes ukazatel k možnému odkazu s hodnotou null
string? key = getkey2.LL.value.key;
string? salt = getkey2.LL.value.salt;
string? hashAlg = getkey2.LL.value.hashAlg;
string? asciikey = ConvertHex(key);

if (debug == true)
{
    Console.WriteLine($"\r\nkey                 = {key}");
    Console.WriteLine($"salt                = {salt}");
    Console.WriteLine($"hashAlg             = {hashAlg}");
    Console.WriteLine($"asciiKey            = {asciikey}");
    Console.WriteLine($"user                = {user}");
    Console.WriteLine($"password            = {password}");
    Console.WriteLine($"randomUUID          = {uuidRandom} ");
    Console.WriteLine($"IP                  = {ip}");
    Console.WriteLine($"Port                = {port}");
    Console.WriteLine($"URL                 = {url}\r\n");
}
if (hashAlg != "SHA1" && hashAlg != "SHA256")
{
    Console.WriteLine("Not SHA256/SHA1 alg, not yet implemented. Used alg: " + hashAlg);
    Console.ReadKey();
    Environment.Exit(0);
}

string tokenURL;
string hashedPass = "";
string hmacString = "";
string passString = $"{password}:{salt}";
if (debug == true) Console.WriteLine($"password:salt       = {passString}");

if (hashAlg == "SHA256") { hashedPass = sha256_hash(passString); }
else if (hashAlg == "SHA1") { hashedPass = sha1_hash(passString); }
if (debug == true) Console.WriteLine($"{hashAlg}              = {hashedPass}");

hashedPass = hashedPass.ToUpper();
if (debug == true) Console.WriteLine($"{hashAlg} to Upper     = {hashedPass}");

string userString = $"{user}:{hashedPass}";
if (debug == true) Console.WriteLine($"user:{hashAlg}         = {userString}");

if (hashAlg == "SHA256") { hmacString = HMACSHA256Encode(userString, asciikey); }
else if (hashAlg == "SHA1") { hmacString = HMACSHA1Encode(userString, asciikey); }
hmacString = hmacString.ToLower();
if (debug == true) Console.WriteLine($"HMAC {hashAlg}         = {hmacString}");

tokenURL = $"/jdev/sys/getjwt/{hmacString}/{user}/{permission}/{uuidRandom}/{info}";
if (debug == true) Console.WriteLine($"URL                 = {tokenURL}\r\n");

string jsonToken = getJsonObj(url, tokenURL, debug);


Root? tokenResponse;
if (jsonToken != null)
{
    tokenResponse = JsonConvert.DeserializeObject<Root>(jsonToken);
    if (tokenResponse == null)
    {
        Console.WriteLine("Token was null");
        Console.ReadKey();
        Environment.Exit(0);
    }else    
    if (tokenResponse.LL == null)
    {
        Console.WriteLine("Token was null");
        Console.ReadKey();
        Environment.Exit(0);
    }else
    if (tokenResponse.LL.value == null)
    {
        Console.WriteLine("Token was null");
        Console.ReadKey();
        Environment.Exit(0);
    }
    if (tokenResponse.LL.code == "200")
        {
            Console.Write($"\r\nToken generated:\r\n{tokenResponse.LL.value.token}\r\n");

            Console.Write($"Token is valid until: {LoxTimeStampToDateTime(tokenResponse.LL.value.validUntil)}");
        }
else Console.WriteLine($"Something went wrong when requesting the token, erroc code: {tokenResponse.LL.code}");
}
Console.ReadKey();


#endregion


#region tokenhelpers
static string HMACSHA256Encode(string input, string key)
{
    byte[] k = Encoding.ASCII.GetBytes(key);
    HMACSHA256 myhmacsha256 = new(k);
    byte[] byteArray = Encoding.ASCII.GetBytes(input);
    using MemoryStream stream = new(byteArray);
    return byteToHex(myhmacsha256.ComputeHash(stream));
}
static string HMACSHA1Encode(string input, string key)
{
    byte[] k = Encoding.ASCII.GetBytes(key);
    HMACSHA1 myhmacsha1 = new(k);
    byte[] byteArray = Encoding.ASCII.GetBytes(input);
    using MemoryStream stream = new(byteArray);
    return byteToHex(myhmacsha1.ComputeHash(stream));
}
static String sha256_hash(String value)
{
    StringBuilder Sb = new();

    using (SHA256 hash = SHA256.Create())
    {
        Encoding enc = Encoding.ASCII;
        Byte[] result = hash.ComputeHash(enc.GetBytes(value));

        foreach (Byte b in result)
            Sb.Append(b.ToString("x2"));
    }

    return Sb.ToString();
}

static String sha1_hash(String value)
{
    StringBuilder Sb = new();

    using (SHA1 hash = SHA1.Create())
    {
        Encoding enc = Encoding.ASCII;
        Byte[] result = hash.ComputeHash(enc.GetBytes(value));

        foreach (Byte b in result)
            Sb.Append(b.ToString("x2"));
    }

    return Sb.ToString();
}

static string byteToHex(byte[] ba)
{
    return BitConverter.ToString(ba).Replace("-", "");
}
static string httpGet(string url)
{
#pragma warning disable SYSLIB0014 // Typ nebo člen je zastaralý.
    WebRequest? request = WebRequest.Create(url);
#pragma warning restore SYSLIB0014 // Typ nebo člen je zastaralý.
    request.Method = "GET";

    try
    {
        using var webResponse = request.GetResponse();
        using var webStream = webResponse.GetResponseStream();

        using var reader = new StreamReader(webStream);
        var data = reader.ReadToEnd();
        return data;
    }
    catch (Exception ex)
    {
        return ex.Message;
    }
    
    
}

static string ConvertHex(String hexString)
{
    try
    {
        string ascii = string.Empty;

        for (int i = 0; i < hexString.Length; i += 2)
        {
            String hs = string.Empty;

            hs = hexString.Substring(i, 2);
            uint decval = System.Convert.ToUInt32(hs, 16);
            char character = System.Convert.ToChar(decval);
            ascii += character;

        }

        return ascii;
    }
    catch (Exception ex) { Console.WriteLine(ex.Message); }

    return string.Empty;
}
static string getJsonObj(string ip, string command, bool debug)
{

    string? json = httpGet(ip + command);
    if(debug == true)Console.WriteLine(json);
    return json;
}
#endregion

#region Helpers
static DateTime LoxTimeStampToDateTime(double unixTimeStamp)
{
    // Unix timestamp is seconds past epoch
    DateTime dateTime = new(2009, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
    dateTime = dateTime.AddSeconds(unixTimeStamp).ToLocalTime();
    return dateTime;
}

static byte[] byteGen(int bytes)
{
    byte[] output = new byte[bytes];
    Random random = new();   
    random.NextBytes(output);
    return output;
}

static string BytesToString(byte[] hash)
{
    return BitConverter.ToString(hash).Replace("-", "").ToLower();
}
#endregion

#region json format
#pragma warning disable CA1050 // Deklarujte typy v názvových prostorech.
#pragma warning disable IDE1006 // Styly pojmenování
public class Root

{
    public LL? LL { get; set; }
}
public class LL
{
    //public string? control { get; set; }

    public string? code { get; set; }

    public Value? value { get; set; }
}
public class Value
{
    public string? key { get; set; }
    public string? salt { get; set; }
    public string? hashAlg { get; set; }
    public string? token { get; set; }
    public double validUntil { get; set; }
    //public int tokenRights { get; set; }
    //public bool unsecurePass { get; set; }


}
#pragma warning restore IDE1006  // Styly pojmenování
#pragma warning restore CA1050 // Deklarujte typy v názvových prostorech.
#endregion