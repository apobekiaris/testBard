using System;
using System.Security.Cryptography;
using System.Text;

namespace Xpand.Extensions.StringExtensions{
    public static partial class StringExtensions{
        public static byte[] Combine(this string s, string other) {
            using (var sha256 = SHA256.Create()) {
                var aBytes = Encoding.UTF8.GetBytes(s);
                var bBytes = Encoding.UTF8.GetBytes(other);
                var aBase64Length = (aBytes.Length + 2) / 3 * 4;
                var bBase64Length = (bBytes.Length + 2) / 3 * 4;

                char[] delimiterChars = { '|' };
                var combinedLength = aBase64Length + delimiterChars.Length + bBase64Length;
                var combinedChars = new char[combinedLength];

                Span<char> combinedSpan = combinedChars;
                if (!Convert.TryToBase64Chars(aBytes, combinedSpan, out var aEncodedChars))
                    throw new InvalidOperationException("Failed to encode the first string to Base64.");
                combinedSpan = combinedSpan.Slice(aEncodedChars);
                delimiterChars.CopyTo(combinedSpan);
                combinedSpan = combinedSpan.Slice(delimiterChars.Length);
                if (!Convert.TryToBase64Chars(bBytes, combinedSpan, out _))
                    throw new InvalidOperationException("Failed to encode the second string to Base64.");

                var combinedBytes = Encoding.UTF8.GetBytes(combinedChars);
                var hashBytes = sha256.ComputeHash(combinedBytes);
                return hashBytes;
            }
        }

        public static byte[] Bytes(this string s, Encoding encoding = null) 
            => s == null ? Array.Empty<byte>() : (encoding ?? Encoding.UTF8).GetBytes(s);
    }
}
using System;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static int LevenshteinDistance(this string source, string target) {
            // degenerate cases
            if (source == target) return 0;
            if (source.Length == 0) return target.Length;
            if (target.Length == 0) return source.Length;

            // create two work vectors of integer distances
            int[] v0 = new int[target.Length + 1];
            int[] v1 = new int[target.Length + 1];

            // initialize v0 (the previous row of distances)
            // this row is A[0][i]: edit distance for an empty s
            // the distance is just the number of characters to delete from t
            for (int i = 0; i < v0.Length; i++)
                v0[i] = i;

            for (int i = 0; i < source.Length; i++)
            {
                // calculate v1 (current row distances) from the previous row v0

                // first element of v1 is A[i+1][0]
                //   edit distance is delete (i+1) chars from s to match empty t
                v1[0] = i + 1;

                // use formula to fill in the rest of the row
                for (int j = 0; j < target.Length; j++)
                {
                    var cost = (source[i] == target[j]) ? 0 : 1;
                    v1[j + 1] = Math.Min(v1[j] + 1, Math.Min(v0[j + 1] + 1, v0[j] + cost));
                }

                // copy v1 (current row) to v0 (previous row) for next iteration
                for (int j = 0; j < v0.Length; j++)
                    v0[j] = v1[j];
            }

            return v1[target.Length];
        }
        /// <summary>
        /// Calculate percentage similarity of two strings
        /// <param name="source">Source String to Compare with</param>
        /// <param name="target">Targeted String to Compare</param>
        /// <returns>Return Similarity between two strings from 0 to 1.0</returns>
        /// </summary>
        public static double CalculateSimilarity(this string source, string target) {
            if ((source == null) || (target == null)) return 0.0;
            if ((source.Length == 0) || (target.Length == 0)) return 0.0;
            if (source == target) return 1.0;

            int stepsToSame = LevenshteinDistance(source, target);
            return (1.0 - (stepsToSame / (double)Math.Max(source.Length, target.Length)));
        }
    }
}
using System;
using System.CodeDom.Compiler;
using System.Text.RegularExpressions;

namespace Xpand.Extensions.StringExtensions{
    public static partial class StringExtensions{
        public static string CleanCodeName(this string s) {
            var regex = new Regex(@"[^\p{Ll}\p{Lu}\p{Lt}\p{Lo}\p{Nd}\p{Nl}\p{Mn}\p{Mc}\p{Cf}\p{Pc}\p{Lm}]");
            string ret = regex.Replace(s + "", "");
            if (!(string.IsNullOrEmpty(ret)) && !Char.IsLetter(ret, 0) && !CodeDomProvider.CreateProvider("C#").IsValidIdentifier(ret))
                ret = string.Concat("_", ret);
            return ret;

        }

    }
}
using System.Collections.Generic;
using System.Linq;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static string CommonStart(this IEnumerable<string> strings) {
            var namespaces = strings.Where(s => s != null).ToArray();
            return Enumerable.Range(0, namespaces.Min(s => s.Length))
                .Reverse()
                .Select(len => new {len, possibleMatch = namespaces.First().Substring(0, len)})
                .Where(t => namespaces.All(f => f.StartsWith(t.possibleMatch)))
                .Select(t => t.possibleMatch).First().Trim('.');
        }
    }
}
namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static string EnsureEmpty(this string source)
            => source ?? string.Empty;
    }
}
using Xpand.Extensions.LinqExtensions;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static string EnsureEndWith(this string s, string end)
            => !s.EndsWith(end) ? new[] { s, end }.JoinString() : s;
    }
}
namespace Xpand.Extensions.StringExtensions{
    public static partial class StringExtensions{
        public static string FirstCharacterToLower(this string str) =>
            string.IsNullOrEmpty(str) || char.IsLower(str, 0) ? str : char.ToLowerInvariant(str[0]) + str.Substring(1);
    }
}
namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static string FirstCharacterToUpper(this string str) =>
            string.IsNullOrEmpty(str) || char.IsUpper(str, 0) ? str : char.ToUpperInvariant(str[0]) + str.Substring(1);
    }
}
using System.IO;
using System.IO.Compression;
using Xpand.Extensions.StreamExtensions;

namespace Xpand.Extensions.StringExtensions{
    public static partial class StringExtensions{
        public static byte[] GZip(this string s,CompressionLevel compressionLevel=CompressionLevel.Optimal){
            using var memoryStream = new MemoryStream(s.Bytes());
            return memoryStream.GZip(compressionLevel);
        }
    }
}
using Xpand.Extensions.LinqExtensions;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static string Inject(this string injectToString, int positionToInject, string stringToInject) 
            => new[] { injectToString.Substring(0, positionToInject), stringToInject,
                injectToString.Substring(positionToInject) }.JoinString();
    }
}
using Xpand.Extensions.LinqExtensions;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static string StringFormat(this object s, params object[] args) {
            var value = $"{s}";
            return string.IsNullOrEmpty(value)?args.Join(""):string.Format($"{s}",args);
        }
    }
}
using System;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static bool IsEqualIgnoreCase(this string s, string other) 
            => StringComparer.InvariantCultureIgnoreCase.Equals(s, other);

        public static bool IsEqual(this string s, string other) {
            return StringComparer.InvariantCulture.Equals(s, other);
        }
    }
}
using System.Text.RegularExpressions;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        private static readonly Regex IsGuidRegex = new(@"^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$", RegexOptions.Compiled);
        public static bool IsGuid(this string candidate)
            => candidate != null && IsGuidRegex.IsMatch(candidate);
    }
}
namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static bool IsNullOrEmpty(this string strString)
            => string.IsNullOrEmpty(strString);
        public static bool IsNotNullOrEmpty(this string strString)
            => !string.IsNullOrEmpty(strString);
    }
}
using System.Text.RegularExpressions;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static bool IsNumeric(this string strString) 
            => Regex.IsMatch(strString, "\\A\\b\\d+\\b\\z");
    }
}
using System;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static bool IsWellFormedUri(this string address, UriKind uriKind = UriKind.RelativeOrAbsolute) 
            => Uri.IsWellFormedUriString(address, uriKind);
    }
}
using System;
using System.Linq;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static bool IsWhiteSpace(this string value) => value.All(Char.IsWhiteSpace);
    }
}
namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static string Keep(this string s, int characters) 
            =>characters<s.Length? s.Remove(0, characters):s;
    }
}
using System.IO;
using System.Text;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static MemoryStream MemoryStream(this string s, Encoding encoding = null) => new(s.Bytes(encoding));
    }
}
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
        public static byte[] Protect(this byte[] bytes, DataProtectionScope scope = DataProtectionScope.LocalMachine) 
            => ProtectedData.Protect(bytes, null,scope);

        [SuppressMessage("Interoperability", "CA1416:Validate platform compatibility")]
        public static byte[] Protect(this string s, DataProtectionScope scope = DataProtectionScope.LocalMachine) 
            => s.Bytes().Protect(scope);
    }
}
using System;
using System.Text.RegularExpressions;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static string RemoveComments(this string s) {
            var blockComments = @"/\*(.*?)\*/";
            var lineComments = @"//(.*?)\r?\n";
            var strings = @"""((\\[^\n]|[^""\n])*)""";
            var verbatimStrings = @"@(""[^""]*"")+";
            return Regex.Replace(s, blockComments + "|" + lineComments + "|" + strings + "|" + verbatimStrings,
                me => me.Value.StartsWith("/*") || me.Value.StartsWith("//")
                    ? me.Value.StartsWith("//") ? Environment.NewLine : "" : me.Value, RegexOptions.Singleline);
        }
    }
}
using System.Globalization;
using System.Linq;
using System.Text;
using Xpand.Extensions.LinqExtensions;


namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static string RemoveDiacritics(this string s) 
            => s.Normalize(NormalizationForm.FormD)
                .Where(c => CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark)
                .JoinString();
    }
}
using System.Linq;

namespace Xpand.Extensions.StringExtensions{
    public static partial class StringExtensions{
        public static string Repeat(this string s, int nummber,string seperator="") => string.Join(seperator,Enumerable.Repeat(s, nummber));
    }
}
using System.Net;
using System.Security;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static SecureString ToSecureString(this string s)
            => new NetworkCredential("", s).SecurePassword;
        
        public static string GetString(this SecureString secureString)
            => new NetworkCredential("",secureString).Password;
        
    }
}
using System;

namespace Xpand.Extensions.StringExtensions{
    public static partial class StringExtensions{
        public static string[] Split(this string str, char separator) 
            => str.Split(new[] { separator }, StringSplitOptions.RemoveEmptyEntries);
        
        public static string SplitCamelCase(string input) => System.Text.RegularExpressions.Regex
                .Replace(input, "([A-Z])", " $1", System.Text.RegularExpressions.RegexOptions.Compiled).Trim();
    }
}
using System;
using System.Security.Cryptography;
using System.Text;

namespace Xpand.Extensions.StringExtensions{
	public static partial class StringExtensions{
		public static Guid ToGuid(this string s){
			if (!Guid.TryParse(s, out var guid)) {
                using var md5 = MD5.Create();
                var data = md5.ComputeHash(Encoding.Default.GetBytes(s));
                return new Guid(data);
            }

			return guid;
		}
	}
}
using System.Collections.Generic;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static IEnumerable<string> ToLines(this string input) {
            using System.IO.StringReader reader = new System.IO.StringReader($"{input}");
            while (reader.ReadLine() is { } line) {
                yield return line;
            }
        }
    }
}
using System.CodeDom;
using System.CodeDom.Compiler;
using System.IO;

namespace Xpand.Extensions.StringExtensions{
    public static partial class StringExtensions{
        public static string ToLiteral(this string input){
            using (var writer = new StringWriter()){
                using (var codeDomProvider = CodeDomProvider.CreateProvider("CSharp")){
                    codeDomProvider.GenerateCodeFromExpression(new CodePrimitiveExpression(input), writer, null);
                    return writer.ToString();
                }
            }
        }
    }
}
using System.Web;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static string UrlEncode(this string s) 
            => HttpUtility.UrlEncode(s);
    }
}
using System;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static long Val(this string value) {
            string returnVal = String.Empty;
            MatchCollection collection = Regex.Matches(value, "\\d+");
            returnVal = collection.Cast<Match>().Aggregate(returnVal, (current, match) => current + match.ToString());
            return Convert.ToInt64(returnVal);
        }

        public static int ValInt32(this string x) {
            var regex = new Regex("[-+]?\\b\\d+\\b", RegexOptions.Compiled);
            var match = regex.Match(x + "");
            return match.Success ? int.Parse(match.Value, NumberFormatInfo.InvariantInfo) : 0;
        }

        public static double ValDouble(this string x) {
            var regex = new Regex("[-+]?\\b(?:[0-9]*\\.)?[0-9]+\\b", RegexOptions.Compiled);
            var match = regex.Match(x + "");
            return match.Success ? double.Parse(match.Value, NumberFormatInfo.InvariantInfo) : 0;
        }
    }
}
using System;
using System.Text.RegularExpressions;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static String WildCardToRegular(this String value) 
            => "^" + Regex.Escape(value).Replace("\\*", ".*") + "$";
    }
}
namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static string XmlDecode(this string value) 
            => value.Replace("&amp;", "&").Replace("&apos;", "'").Replace("&quot;", "\"").Replace("&lt;", "<").Replace("&gt;", ">");
    }
}
namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static string XmlEncode(this string value)
            => value.TrimEnd((char) 1).Replace("&", "&amp;").Replace("'", "&apos;").Replace("\"", "&quot;")
                .Replace("<", "&lt;").Replace(">", "&gt;");
    }
}
using System;
using System.IO;
using System.Text;
using System.Xml;

namespace Xpand.Extensions.StringExtensions {
    public static partial class StringExtensions {
        public static String XmlPrint(this String xml) {
            if (string.IsNullOrEmpty(xml))
                return xml;
            String result = "";

            var mStream = new MemoryStream();
            var writer = new XmlTextWriter(mStream, Encoding.Unicode);
            var document = new XmlDocument();

            try {
                document.LoadXml(xml);
                writer.Formatting = Formatting.Indented;
                document.WriteContentTo(writer);
                writer.Flush();
                mStream.Flush();
                mStream.Position = 0;
                var sReader = new StreamReader(mStream);
                var formattedXml = sReader.ReadToEnd();

                result = formattedXml;
            }
            catch (XmlException) { }

            mStream.Close();
            writer.Close();

            return result;
        }
    }
}
