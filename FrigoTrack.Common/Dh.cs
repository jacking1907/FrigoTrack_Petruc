using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

namespace FrigoTrack.Common;

/// <summary>
/// Scambio di chiavi Diffie-Hellman scritto a mano.
/// Gruppo 14 di RFC 3526 (2048 bit): p = 2^2048 - 2^1984 - 1 + 2^64 * (floor(2^1918 * pi) + 124476), g = 2.
/// Si usa solo BigInteger.ModPow (potenza modulare): il resto dello scambio e' qui.
/// </summary>
public static class Dh
{
    private const string PHex =
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
        "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
        "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
        "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
        "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

    public static readonly BigInteger P = FromHex(PHex);
    public static readonly BigInteger G = 2;

    /// <summary>Segreto casuale (a oppure b) nell'intervallo [2, p-2].</summary>
    public static BigInteger CreatePrivateKey()
    {
        // 8 byte in piu' di p: dopo il modulo la distorsione e' trascurabile
        byte[] bytes = RandomNumberGenerator.GetBytes(256 + 8);
        BigInteger r = new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        return r % (P - 3) + 2;
    }

    /// <summary>A = g^a mod p (client) oppure B = g^b mod p (server).</summary>
    public static BigInteger PublicKey(BigInteger secret) => BigInteger.ModPow(G, secret, P);

    /// <summary>K = B^a mod p (client) oppure K = A^b mod p (server).</summary>
    public static BigInteger SharedSecret(BigInteger otherPublic, BigInteger secret)
        => BigInteger.ModPow(otherPublic, secret, P);

    /// <summary>Rifiuta chiavi pubbliche banali (0, 1, p-1, fuori intervallo).</summary>
    public static bool IsValidPublic(BigInteger value) => value > 1 && value < P - 1;

    /// <summary>Chiave AES-256: SHA-256 del segreto condiviso (K e' di 2048 bit, AES vuole 32 byte).</summary>
    public static byte[] DeriveKey(BigInteger k)
    {
        byte[] raw = k.ToByteArray(isUnsigned: true, isBigEndian: true);
        byte[] padded = new byte[256];                       // lunghezza fissa: 2048 bit
        raw.CopyTo(padded, 256 - raw.Length);
        return SHA256.HashData(padded);
    }

    /// <summary>Intero -> stringa esadecimale (come viaggia nei messaggi JSON).</summary>
    public static string ToHex(BigInteger n)
    {
        string s = n.ToString("x", CultureInfo.InvariantCulture).TrimStart('0');
        return s.Length == 0 ? "0" : s;
    }

    /// <summary>Stringa esadecimale -> intero positivo.</summary>
    public static BigInteger FromHex(string hex)
        => BigInteger.Parse("0" + hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture);
}
