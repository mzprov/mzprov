using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Mzprov;

// Canonical content hashing for mzML. Operates on spectrum content (not
// XML serialization), byte-for-byte compatible with
// spec/canonicalization-mzml-v0.md and the Python reference.
internal static class CanonicalizeMzml
{
    private static readonly XNamespace Ns = "http://psi.hupo.org/ms/mzml";
    private static readonly byte[] US = { 0x1F };
    private static readonly byte[] RS = { 0x1E };
    private static readonly byte[] MzmlContentDomain = Encoding.ASCII.GetBytes("timsim.mzml.v0\x1f");

    private static class Cv
    {
        public const string MsLevel = "MS:1000511";
        public const string ScanStartTime = "MS:1000016";
        public const string PositiveScan = "MS:1000130";
        public const string NegativeScan = "MS:1000129";
        public const string SelectedIonMz = "MS:1000744";
        public const string ChargeState = "MS:1000041";
        public const string IsoTarget = "MS:1000827";
        public const string IsoLowerOff = "MS:1000828";
        public const string IsoUpperOff = "MS:1000829";
        public const string BinaryF64 = "MS:1000523";
        public const string BinaryF32 = "MS:1000521";
        public const string BinaryI64 = "MS:1000522";
        public const string BinaryI32 = "MS:1000519";
        public const string NoCompression = "MS:1000576";
        public const string ZlibCompression = "MS:1000574";
        public const string NumpressLinear = "MS:1002312";
        public const string NumpressPic = "MS:1002313";
        public const string NumpressSlof = "MS:1002314";
        public const string IonMobility = "MS:1002476";
        public const string IonMobilityAlt = "MS:1003006";
    }

    private static readonly HashSet<string> KnownArrayRoleAccessions = new(StringComparer.Ordinal)
    {
        "MS:1000514", "MS:1000515", "MS:1000516", "MS:1000517", "MS:1000595",
        "MS:1000617", "MS:1000786", "MS:1000820", "MS:1000821", "MS:1000822",
        "MS:1002476", "MS:1002477", "MS:1002478", "MS:1003006", "MS:1003007",
        "MS:1003008", "MS:1003153",
    };

    private static readonly HashSet<string> KnownEncodingAccessions = new(StringComparer.Ordinal)
    {
        "MS:1000519", "MS:1000521", "MS:1000522", "MS:1000523", "MS:1000574",
        "MS:1000576", "MS:1002312", "MS:1002313", "MS:1002314",
    };

    public static byte[] Run(string mzmlPath)
    {
        if (!File.Exists(mzmlPath))
        {
            throw new FileNotFoundException($"mzml file not found: {mzmlPath}");
        }

        XDocument doc;
        try
        {
            using var reader = XmlReader.Create(mzmlPath, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit });
            doc = XDocument.Load(reader);
        }
        catch (XmlException e)
        {
            throw new MalformedSidecarException($"mzml file is not valid XML: {e.Message}");
        }

        var root = doc.Root!;
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        sha.AppendData(Encoding.ASCII.GetBytes("TIMSIM-MZML-CANONICAL-v0\x1f"));

        int spectrumCount = 0;
        foreach (var spectrum in SpectraSorted(root))
        {
            sha.AppendData(SpectrumRecord(spectrum));
            spectrumCount++;
        }

        sha.AppendData(Encoding.ASCII.GetBytes(
            "\x1fspectrum_count\x1f" + spectrumCount.ToString(CultureInfo.InvariantCulture) + "\x1f"));
        return sha.GetHashAndReset();
    }

    public static byte[] ComposeMzmlContentHash(byte[] mzmlHash, byte[] configHash)
    {
        using var ms = new MemoryStream();
        ms.Write(MzmlContentDomain, 0, MzmlContentDomain.Length);
        ms.Write(mzmlHash, 0, mzmlHash.Length);
        ms.Write(US, 0, US.Length);
        ms.Write(configHash, 0, configHash.Length);
        return SHA256.HashData(ms.ToArray());
    }

    private static IEnumerable<XElement> SpectraSorted(XElement root)
    {
        var indexed = new List<(int Index, XElement Spectrum)>();
        foreach (var s in root.Descendants(Ns + "spectrum"))
        {
            string raw = s.Attribute("index")?.Value ?? "";
            if (!int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out int idx))
            {
                string sid = s.Attribute("id")?.Value ?? "";
                throw new MalformedSidecarException(
                    $"mzml spectrum '{sid}' has missing or non-integer index");
            }
            indexed.Add((idx, s));
        }
        indexed.Sort((a, b) => a.Index.CompareTo(b.Index));
        return indexed.Select(t => t.Spectrum);
    }

    private static byte[] SpectrumRecord(XElement spectrum)
    {
        string specId = spectrum.Attribute("id")?.Value ?? "";
        string rawIndex = spectrum.Attribute("index")?.Value ?? "";
        if (!int.TryParse(rawIndex, NumberStyles.Integer, CultureInfo.InvariantCulture, out int index))
        {
            throw new MalformedSidecarException(
                $"mzml spectrum '{specId}' has missing or non-integer index attribute");
        }

        string msLevel = CvValue(spectrum, Cv.MsLevel) ?? "";
        byte[] polarity = ExtractPolarity(spectrum);
        double? rt = ExtractRtSeconds(spectrum);
        double? mob = ExtractIonMobility(spectrum);
        var precursor = ExtractPrecursor(spectrum);

        var arrays = new List<(string Role, byte[] Tag, long Count, byte[] Digest)>();
        var bdal = spectrum.Element(Ns + "binaryDataArrayList");
        if (bdal != null)
        {
            foreach (var bda in bdal.Elements(Ns + "binaryDataArray"))
            {
                string roleLabel = ArrayRoleLabel(bda);
                byte[] payload = DecodeBinaryArray(bda);
                byte[] tag = ArrayPrecisionTag(bda);
                int width = PrecisionWidth(tag);
                long count = width != 0 ? payload.Length / width : 0;
                byte[] digest = Encoding.ASCII.GetBytes(Canonicalize.ToHexLower(SHA256.HashData(payload)));
                arrays.Add((roleLabel, tag, count, digest));
            }
        }
        arrays.Sort((a, b) => string.CompareOrdinal(a.Role, b.Role));

        var parts = new List<byte[]>();
        void Emit(string key, byte[] value) =>
            parts.Add(Concat(US, Encoding.ASCII.GetBytes(key), US, value, US));

        Emit("spec_index", Ascii(index.ToString(CultureInfo.InvariantCulture)));
        Emit("spec_id", Encoding.UTF8.GetBytes(specId));
        Emit("ms_level", Ascii(msLevel));
        Emit("polarity", polarity);
        Emit("rt_sec", rt.HasValue ? Ieee754Hex(rt.Value) : Array.Empty<byte>());
        Emit("mobility", mob.HasValue ? Ieee754Hex(mob.Value) : Array.Empty<byte>());

        if (precursor is null)
        {
            Emit("prec_target", Array.Empty<byte>());
            Emit("prec_lower", Array.Empty<byte>());
            Emit("prec_upper", Array.Empty<byte>());
            Emit("prec_selected", Array.Empty<byte>());
            Emit("prec_charge", Array.Empty<byte>());
        }
        else
        {
            Emit("prec_target", precursor.Target.HasValue ? Ieee754Hex(precursor.Target.Value) : Array.Empty<byte>());
            Emit("prec_lower", precursor.Lower.HasValue ? Ieee754Hex(precursor.Lower.Value) : Array.Empty<byte>());
            Emit("prec_upper", precursor.Upper.HasValue ? Ieee754Hex(precursor.Upper.Value) : Array.Empty<byte>());
            Emit("prec_selected", precursor.SelectedMz.HasValue ? Ieee754Hex(precursor.SelectedMz.Value) : Array.Empty<byte>());
            Emit("prec_charge", precursor.Charge.HasValue ? Ascii(precursor.Charge.Value.ToString(CultureInfo.InvariantCulture)) : Array.Empty<byte>());
        }

        Emit("array_count", Ascii(arrays.Count.ToString(CultureInfo.InvariantCulture)));
        foreach (var (role, prec, count, digest) in arrays)
        {
            Emit("array_role", Ascii(role));
            Emit("array_precision", prec);
            Emit("array_value_count", Ascii(count.ToString(CultureInfo.InvariantCulture)));
            Emit("array_hash", digest);
        }

        return Concat(Concat(parts.ToArray()), RS);
    }

    // ----- field extraction -----

    private static byte[] ExtractPolarity(XElement spectrum)
    {
        if (CvPresent(spectrum, Cv.PositiveScan)) return Encoding.ASCII.GetBytes("+");
        if (CvPresent(spectrum, Cv.NegativeScan)) return Encoding.ASCII.GetBytes("-");
        return Encoding.ASCII.GetBytes("?");
    }

    private static double? ExtractRtSeconds(XElement spectrum)
    {
        var scanList = spectrum.Element(Ns + "scanList");
        var scan = scanList?.Element(Ns + "scan");
        if (scan is null) return null;
        foreach (var cv in scan.Elements(Ns + "cvParam"))
        {
            if (cv.Attribute("accession")?.Value == Cv.ScanStartTime)
            {
                if (!TryParseDouble(cv.Attribute("value")?.Value, out double value))
                {
                    return null;
                }
                if (cv.Attribute("unitAccession")?.Value == "UO:0000031") // minute
                {
                    value *= 60.0;
                }
                return value;
            }
        }
        return null;
    }

    private static double? ExtractIonMobility(XElement spectrum)
    {
        foreach (string accession in new[] { Cv.IonMobility, Cv.IonMobilityAlt })
        {
            string? v = CvValueRecursive(spectrum, accession);
            if (v != null && TryParseDouble(v, out double parsed))
            {
                return parsed;
            }
        }
        return null;
    }

    private sealed class Precursor
    {
        public double? Target;
        public double? Lower;
        public double? Upper;
        public double? SelectedMz;
        public int? Charge;

        public bool Any => Target.HasValue || Lower.HasValue || Upper.HasValue ||
                           SelectedMz.HasValue || Charge.HasValue;
    }

    private static Precursor? ExtractPrecursor(XElement spectrum)
    {
        var plist = spectrum.Element(Ns + "precursorList");
        var precursor = plist?.Element(Ns + "precursor");
        if (precursor is null) return null;

        var result = new Precursor();
        var iso = precursor.Element(Ns + "isolationWindow");
        if (iso != null)
        {
            if (TryParseDouble(CvValue(iso, Cv.IsoTarget), out double t)) result.Target = t;
            if (TryParseDouble(CvValue(iso, Cv.IsoLowerOff), out double lo)) result.Lower = lo;
            if (TryParseDouble(CvValue(iso, Cv.IsoUpperOff), out double up)) result.Upper = up;
        }

        var sion = precursor.Element(Ns + "selectedIonList")?.Element(Ns + "selectedIon");
        if (sion != null)
        {
            if (TryParseDouble(CvValue(sion, Cv.SelectedIonMz), out double mz)) result.SelectedMz = mz;
            string? charge = CvValue(sion, Cv.ChargeState);
            if (charge != null && int.TryParse(charge, NumberStyles.Integer, CultureInfo.InvariantCulture, out int c))
            {
                result.Charge = c;
            }
        }

        return result.Any ? result : null;
    }

    // ----- binary array -----

    private static byte[] DecodeBinaryArray(XElement bda)
    {
        foreach (string acc in new[] { Cv.NumpressLinear, Cv.NumpressPic, Cv.NumpressSlof })
        {
            if (CvPresent(bda, acc))
            {
                throw new ProvenanceException(
                    $"mzml binaryDataArray uses numpress compression ({acc}); not supported in canonicalize_mzml v0");
            }
        }

        var binaryEl = bda.Element(Ns + "binary");
        if (binaryEl is null)
        {
            throw new MalformedSidecarException("mzml binaryDataArray is missing the inner <binary> element");
        }
        string text = (binaryEl.Value ?? "").Trim();
        if (text.Length == 0)
        {
            return Array.Empty<byte>();
        }

        byte[] raw;
        try
        {
            raw = Convert.FromBase64String(text);
        }
        catch (FormatException e)
        {
            throw new MalformedSidecarException($"mzml binaryDataArray has undecodable base64 content: {e.Message}");
        }

        if (CvPresent(bda, Cv.ZlibCompression))
        {
            try
            {
                using var input = new MemoryStream(raw);
                using var zlib = new ZLibStream(input, CompressionMode.Decompress);
                using var output = new MemoryStream();
                zlib.CopyTo(output);
                raw = output.ToArray();
            }
            catch (Exception e) when (e is InvalidDataException or IOException)
            {
                throw new MalformedSidecarException($"mzml binaryDataArray has undecompressable zlib payload: {e.Message}");
            }
        }

        return raw;
    }

    private static byte[] ArrayPrecisionTag(XElement bda)
    {
        if (CvPresent(bda, Cv.BinaryF64)) return Encoding.ASCII.GetBytes("f64");
        if (CvPresent(bda, Cv.BinaryF32)) return Encoding.ASCII.GetBytes("f32");
        if (CvPresent(bda, Cv.BinaryI64)) return Encoding.ASCII.GetBytes("i64");
        if (CvPresent(bda, Cv.BinaryI32)) return Encoding.ASCII.GetBytes("i32");
        return Encoding.ASCII.GetBytes("??");
    }

    private static int PrecisionWidth(byte[] tag)
    {
        string t = Encoding.ASCII.GetString(tag);
        if (t == "f64" || t == "i64") return 8;
        if (t == "f32" || t == "i32") return 4;
        return 0;
    }

    private static string ArrayRoleLabel(XElement bda)
    {
        foreach (var cv in bda.Elements(Ns + "cvParam"))
        {
            string acc = cv.Attribute("accession")?.Value ?? "";
            if (KnownArrayRoleAccessions.Contains(acc))
            {
                return acc;
            }
        }
        foreach (var cv in bda.Elements(Ns + "cvParam"))
        {
            string acc = cv.Attribute("accession")?.Value ?? "";
            if (acc.Length > 0 && !KnownEncodingAccessions.Contains(acc))
            {
                return "unknown:" + acc;
            }
        }
        throw new MalformedSidecarException("binaryDataArray has no cvParam identifying its array role");
    }

    // ----- cvParam helpers -----

    private static string? CvValue(XElement element, string accession)
    {
        foreach (var child in element.Elements(Ns + "cvParam"))
        {
            if (child.Attribute("accession")?.Value == accession)
            {
                return child.Attribute("value")?.Value;
            }
        }
        return null;
    }

    private static bool CvPresent(XElement element, string accession)
    {
        foreach (var child in element.Elements(Ns + "cvParam"))
        {
            if (child.Attribute("accession")?.Value == accession)
            {
                return true;
            }
        }
        return false;
    }

    private static string? CvValueRecursive(XElement element, string accession)
    {
        foreach (var child in element.Descendants(Ns + "cvParam"))
        {
            if (child.Attribute("accession")?.Value == accession)
            {
                return child.Attribute("value")?.Value;
            }
        }
        return null;
    }

    // ----- byte helpers -----

    private static byte[] Ieee754Hex(double value)
    {
        byte[] be = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(be);
        }
        return Encoding.ASCII.GetBytes(Canonicalize.ToHexLower(be));
    }

    private static bool TryParseDouble(string? s, out double value)
    {
        if (s is null)
        {
            value = 0;
            return false;
        }
        // Mirror Python float(): accept decimal/exponent and inf/nan spellings.
        return double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out value)
            || TryParseSpecialFloat(s, out value);
    }

    private static bool TryParseSpecialFloat(string s, out double value)
    {
        string t = s.Trim().ToLowerInvariant();
        switch (t)
        {
            case "inf":
            case "+inf":
            case "infinity":
            case "+infinity":
                value = double.PositiveInfinity;
                return true;
            case "-inf":
            case "-infinity":
                value = double.NegativeInfinity;
                return true;
            case "nan":
            case "+nan":
            case "-nan":
                value = double.NaN;
                return true;
            default:
                value = 0;
                return false;
        }
    }

    private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

    private static byte[] Concat(params byte[][] parts)
    {
        int total = 0;
        foreach (var p in parts) total += p.Length;
        var result = new byte[total];
        int offset = 0;
        foreach (var p in parts)
        {
            Array.Copy(p, 0, result, offset, p.Length);
            offset += p.Length;
        }
        return result;
    }
}
