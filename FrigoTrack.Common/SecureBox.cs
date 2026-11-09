using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace FrigoTrack.Common;

/// <summary>Busta non decifrabile o manomessa (tag, nonce o Base64 sbagliati).</summary>
public class DecryptException : Exception
{
    public DecryptException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>Decifratura riuscita, ma il contenuto non e' JSON valido.</summary>
public class PayloadException : Exception
{
    public PayloadException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>
/// Busta cifrata con AES-256-GCM. Formato in rete (schemas/envelope.json):
///   { "session_id": ..., "nonce": base64, "ciphertext": base64, "tag": base64 }
/// Il session_id e' autenticato come "dato associato" (AAD): una busta non si puo' spostare
/// su un'altra sessione senza far fallire il tag.
/// </summary>
public static class SecureBox
{
    public const int NonceSize = 12;   // 96 bit, casuale per ogni messaggio
    public const int TagSize = 16;     // 128 bit

    /// <summary>Cifra un messaggio applicativo e produce la busta.</summary>
    public static JsonObject Seal(byte[] key, string sessionId, JsonNode message)
        => SealText(key, sessionId, message.ToJsonString());

    /// <summary>Come Seal, ma cifra un testo qualsiasi (nei test serve per inviare anche JSON non valido).</summary>
    public static JsonObject SealText(byte[] key, string sessionId, string text)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] plaintext = Encoding.UTF8.GetBytes(text);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSize];

        using AesGcm aes = new(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, Encoding.ASCII.GetBytes(sessionId));

        return new JsonObject
        {
            ["session_id"] = sessionId,
            ["nonce"] = Convert.ToBase64String(nonce),
            ["ciphertext"] = Convert.ToBase64String(ciphertext),
            ["tag"] = Convert.ToBase64String(tag),
        };
    }

    /// <summary>
    /// Decifra una busta (gia' validata con envelope.json) e restituisce il JSON interno.
    /// DecryptException: tag/nonce/Base64 sbagliati, quindi non si elabora nulla.
    /// PayloadException: decifrato bene ma il testo non e' JSON.
    /// </summary>
    public static JsonElement Open(byte[] key, JsonElement envelope)
    {
        byte[] plaintext;
        try
        {
            byte[] nonce = Convert.FromBase64String(envelope.GetProperty("nonce").GetString()!);
            byte[] ciphertext = Convert.FromBase64String(envelope.GetProperty("ciphertext").GetString()!);
            byte[] tag = Convert.FromBase64String(envelope.GetProperty("tag").GetString()!);
            string sessionId = envelope.GetProperty("session_id").GetString()!;

            if (nonce.Length != NonceSize || tag.Length != TagSize)
                throw new DecryptException("lunghezza di nonce o tag errata");

            plaintext = new byte[ciphertext.Length];
            using AesGcm aes = new(key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, Encoding.ASCII.GetBytes(sessionId));   // verifica il tag
        }
        catch (Exception e) when (e is CryptographicException or FormatException
                                     or KeyNotFoundException or InvalidOperationException
                                     or ArgumentException)
        {
            throw new DecryptException("decifratura o verifica del tag fallita", e);
        }

        try
        {
            using JsonDocument doc = JsonDocument.Parse(plaintext);   // rifiuta NaN, Infinity e JSON malformato
            return doc.RootElement.Clone();
        }
        catch (JsonException e)
        {
            throw new PayloadException("il contenuto decifrato non e' JSON valido", e);
        }
    }

    /// <summary>Il nonce in Base64 (serve al server per riconoscere buste ripetute).</summary>
    public static string NonceOf(JsonElement envelope) => envelope.GetProperty("nonce").GetString()!;
}
