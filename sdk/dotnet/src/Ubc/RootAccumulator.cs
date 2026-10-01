using System.Security.Cryptography;

namespace Ubc;

/// <summary>
/// SPEC.md section 4's root_hash accumulator: plain SHA-256 over root_input for plain
/// containers, or a keyed HMAC-SHA-256 (HKDF-derived root_key) for encrypted containers.
/// Wraps the two so encoder/decoder code can call Update() without branching on mode.
/// </summary>
internal sealed class RootAccumulator : IDisposable
{
    private readonly HashAlgorithm? _digest;
    private readonly HMAC? _mac;
    private byte[]? _hash;

    private RootAccumulator(HashAlgorithm? digest, HMAC? mac)
    {
        _digest = digest;
        _mac = mac;
    }

    internal static RootAccumulator Plain() => new(SHA256.Create(), null);

    internal static RootAccumulator Keyed(byte[] rootKey) => new(null, new HMACSHA256(rootKey));

    internal void Update(ReadOnlySpan<byte> data)
    {
        if (_hash is not null)
        {
            throw new InvalidOperationException("RootAccumulator already finished");
        }
        byte[] buffer = data.ToArray();
        if (_digest is not null)
        {
            _digest.TransformBlock(buffer, 0, buffer.Length, null, 0);
        }
        else
        {
            _mac!.TransformBlock(buffer, 0, buffer.Length, null, 0);
        }
    }

    internal byte[] Finish()
    {
        if (_hash is not null)
        {
            return _hash;
        }
        if (_digest is not null)
        {
            _digest.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            _hash = _digest.Hash!;
        }
        else
        {
            _mac!.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            _hash = _mac.Hash!;
        }
        return _hash;
    }

    public void Dispose()
    {
        _digest?.Dispose();
        _mac?.Dispose();
    }
}
