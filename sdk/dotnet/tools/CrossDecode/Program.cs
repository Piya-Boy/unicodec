using System.Security.Cryptography;
using Ubc;
using Ubc.Tests.Support;

namespace Ubc.CrossDecode;

/// <summary>
/// Cross-decode CLI matching the Rust example's and Java CLI's contract: {@code --vectors DIR
/// --work DIR --cases a,b,c [--write | --verify]}. Invoked by scripts/cross-decode.mjs so
/// .NET participates in the Go/Node/Python/Rust/Java/.NET cross-decode matrix.
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        try
        {
            Run(args);
            return 0;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine(e.Message);
            return 1;
        }
    }

    private static void Run(string[] args)
    {
        var arguments = ParseArguments(args);
        var manifest = VectorManifest.Read(arguments.VectorsRoot);
        byte[] canonicalKey = manifest.CanonicalKey();

        foreach (var id in arguments.CaseIds)
        {
            var vector = manifest.Vectors.FirstOrDefault(v => v.Id == id)
                ?? throw new InvalidOperationException($"manifest vector is missing: {id}");
            if (vector.ExpectError is not null)
            {
                throw new InvalidOperationException($"negative cross-decode case is not allowed: {id}");
            }
            if (vector.Input is null)
            {
                throw new InvalidOperationException($"{id}: positive vector has no input");
            }
            byte[] input = File.ReadAllBytes(SafeChild(arguments.VectorsRoot, vector.Input));
            byte[] expected = File.ReadAllBytes(SafeChild(arguments.VectorsRoot, vector.Expected));
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(expected), vector.ExpectedSha256))
            {
                throw new InvalidOperationException($"{id}: expected artifact SHA-256 differs from vectors.json");
            }

            if (arguments.Write)
            {
                byte[] container = vector.Encode(input);
                if (!container.AsSpan().SequenceEqual(expected))
                {
                    throw new InvalidOperationException($"{id}: .NET encode differs from shared artifact");
                }
                File.WriteAllBytes(SafeChild(arguments.WorkDir, $"{id}.dotnet.ubc"), container);
            }
            else
            {
                byte[] key = vector.Options?.Key ?? canonicalKey;
                foreach (var producer in new[] { "go", "node", "python", "rust", "java", "dotnet" })
                {
                    byte[] container = File.ReadAllBytes(SafeChild(arguments.WorkDir, $"{id}.{producer}.ubc"));
                    var decoded = vector.Decode(container, key);
                    if (decoded.Error is not null)
                    {
                        throw new InvalidOperationException($"{id}: .NET rejected {producer} container with {decoded.Error}");
                    }
                    if (!decoded.Data!.AsSpan().SequenceEqual(input))
                    {
                        throw new InvalidOperationException($"{id}: .NET-decoded {producer} plaintext differs from manifest input");
                    }
                    var expectedMetadata = vector.Options?.Metadata ?? new List<MetadataEntry>();
                    if (!MetadataEquals(decoded.Metadata!, expectedMetadata))
                    {
                        throw new InvalidOperationException($"{id}: .NET-decoded {producer} metadata differs from manifest");
                    }
                    byte[] reencoded = vector.Encode(decoded.Data!);
                    if (!reencoded.AsSpan().SequenceEqual(expected))
                    {
                        throw new InvalidOperationException($"{id}: {producer}-to-.NET re-encode is not byte-identical");
                    }
                    if (!container.AsSpan().SequenceEqual(expected))
                    {
                        throw new InvalidOperationException($"{id}: fresh {producer} container differs from shared artifact");
                    }
                }
            }
        }
    }

    private static bool MetadataEquals(List<MetadataEntry> actual, List<MetadataEntry> expected)
    {
        if (actual.Count != expected.Count)
        {
            return false;
        }
        for (int i = 0; i < actual.Count; i++)
        {
            if (actual[i].Tag != expected[i].Tag || !actual[i].Value.AsSpan().SequenceEqual(expected[i].Value))
            {
                return false;
            }
        }
        return true;
    }

    private static string SafeChild(string root, string child)
    {
        if (string.IsNullOrEmpty(child))
        {
            throw new ArgumentException("manifest path must be a non-empty relative path");
        }
        string target = Path.GetFullPath(Path.Combine(root, child));
        string normalizedRoot = Path.GetFullPath(root) + Path.DirectorySeparatorChar;
        if (!target.StartsWith(normalizedRoot, StringComparison.Ordinal))
        {
            throw new ArgumentException($"manifest path escapes vectors root: {child}");
        }
        return target;
    }

    private sealed record Arguments(string VectorsRoot, string WorkDir, List<string> CaseIds, bool Write);

    private static Arguments ParseArguments(string[] args)
    {
        string? vectorsRoot = null;
        string? workDir = null;
        string? cases = null;
        bool? write = null;
        int i = 0;
        while (i < args.Length)
        {
            string argument = args[i];
            switch (argument)
            {
                case "--vectors":
                    vectorsRoot = args[++i];
                    break;
                case "--work":
                    workDir = args[++i];
                    break;
                case "--cases":
                    cases = args[++i];
                    break;
                case "--write":
                    if (write is not null)
                    {
                        throw new ArgumentException("--write/--verify specified more than once");
                    }
                    write = true;
                    break;
                case "--verify":
                    if (write is not null)
                    {
                        throw new ArgumentException("--write/--verify specified more than once");
                    }
                    write = false;
                    break;
                default:
                    throw new ArgumentException($"unexpected argument: {argument}");
            }
            i++;
        }
        string resolvedVectorsRoot = ExistingDirectory(vectorsRoot, "vectors");
        string resolvedWorkDir = ExistingDirectory(workDir, "work");
        if (cases is null)
        {
            throw new ArgumentException("--cases is required");
        }
        if (write is null)
        {
            throw new ArgumentException("exactly one of --write or --verify is required");
        }
        var seen = new HashSet<string>();
        var caseIds = new List<string>();
        foreach (var id in cases.Split(','))
        {
            if (!SafeId(id) || !seen.Add(id))
            {
                throw new ArgumentException($"unsafe or duplicate case id: {id}");
            }
            caseIds.Add(id);
        }
        if (caseIds.Count == 0)
        {
            throw new ArgumentException("--cases must not be empty");
        }
        return new Arguments(resolvedVectorsRoot, resolvedWorkDir, caseIds, write.Value);
    }

    private static bool SafeId(string id) =>
        !string.IsNullOrEmpty(id) && System.Text.RegularExpressions.Regex.IsMatch(id, "^[a-z0-9]+(-[a-z0-9]+)*$");

    private static string ExistingDirectory(string? path, string label)
    {
        if (string.IsNullOrEmpty(path))
        {
            throw new ArgumentException($"--{label} is required");
        }
        string resolved = Path.GetFullPath(path);
        if (!Directory.Exists(resolved))
        {
            throw new ArgumentException($"{label} path is not a directory");
        }
        return resolved;
    }
}
