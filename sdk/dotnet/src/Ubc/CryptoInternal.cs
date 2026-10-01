using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Ubc;

/// <summary>
/// Shared AES-256-GCM / HMAC-SHA-256 primitives (SPEC.md sections 3-4), used by both the
/// one-shot <see cref="Crypto"/> path and the streaming Encoder/Decoder. Keeping a single
/// implementation here means the two paths cannot silently diverge on nonce, AAD, or
/// root-key derivation.
/// </summary>
internal static class CryptoInternal
{
    internal const int GcmTagSize = 16;
    private static readonly byte[] RootInfo = "UBC1 root authentication"u8.ToArray();
    private const int NonceSize = 12;

    internal static byte[] RootKey(byte[] key, byte[] baseNonce)
    {
        byte[] prk = HMACSHA256.HashData(baseNonce, key);
        byte[] info = new byte[RootInfo.Length + 1];
        RootInfo.CopyTo(info, 0);
        info[^1] = 0x01;
        return HMACSHA256.HashData(prk, info);
    }

    internal static byte[] ChunkNonce(byte[] baseNonce, ulong index)
    {
        Span<byte> indexBytes = stackalloc byte[NonceSize];
        BinaryPrimitives.WriteUInt64LittleEndian(indexBytes[..8], index);
        var nonce = new byte[NonceSize];
        for (int i = 0; i < NonceSize; i++)
        {
            nonce[i] = (byte)(baseNonce[i] ^ indexBytes[i]);
        }
        return nonce;
    }

    internal static byte[] ChunkAad(byte[] headerBytes, byte[] metadataDigest, ulong index)
    {
        var buffer = new byte[headerBytes.Length + metadataDigest.Length + 8];
        headerBytes.CopyTo(buffer, 0);
        metadataDigest.CopyTo(buffer, headerBytes.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(buffer.AsSpan(headerBytes.Length + metadataDigest.Length, 8), index);
        return buffer;
    }

    internal static byte[] GcmEncrypt(byte[] key, byte[] nonce, ReadOnlySpan<byte> plaintext, byte[] aad)
    {
        using var aes = new AesGcm(key, GcmTagSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[GcmTagSize];
        aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);
        var result = new byte[ciphertext.Length + tag.Length];
        ciphertext.CopyTo(result, 0);
        tag.CopyTo(result, ciphertext.Length);
        return result;
    }

    /// <summary>
    /// Throws <see cref="AuthenticationTagMismatchException"/> (caught by callers as
    /// ERR_CHUNK_AUTH) on tag failure. Verified experimentally that AesGcm.Decrypt zeroes
    /// the output buffer rather than leaving partial/garbage plaintext on a failed tag.
    /// </summary>
    internal static byte[] GcmDecrypt(byte[] key, byte[] nonce, ReadOnlySpan<byte> body, byte[] aad)
    {
        int ciphertextLength = body.Length - GcmTagSize;
        var ciphertext = body[..ciphertextLength];
        var tag = body[ciphertextLength..];
        var plaintext = new byte[ciphertextLength];
        using var aes = new AesGcm(key, GcmTagSize);
        aes.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        return plaintext;
    }

    internal static byte[] Sha256(ReadOnlySpan<byte> data) => SHA256.HashData(data);
}
