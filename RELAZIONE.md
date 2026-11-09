# Relazione – FrigoTrack

## Scelte tecniche

- **C# / .NET 8 con ASP.NET Core**: è il linguaggio che conosco. Il server usa le minimal API e gestisce le richieste in parallelo; le sessioni sono conservate in una struttura concorrente e l'archivio usa un lock.
- **Diffie-Hellman scritto a mano** (`Dh.cs`): `A = g^a mod p` e `K = B^a mod p` sono calcolati con `BigInteger.ModPow`, cioè la funzione di potenza modulare del linguaggio, come chiede la traccia. Gruppo 14 di RFC 3526 (2048 bit, primo sicuro, `g = 2`). I segreti `a` e `b` vengono da `RandomNumberGenerator`. La chiave AES è `SHA-256(K)`: K è di 2048 bit e AES-256 vuole 32 byte, quindi serve una riduzione a lunghezza fissa.
- **Cifratura AES-256-GCM** (`AesGcm` di .NET, usata solo per il cifrario, non per lo scambio di chiavi). GCM dà riservatezza e autenticità: il `tag` rileva qualsiasi modifica. Il `session_id` è dato associato (AAD).
- **Ordine "decifra, poi valida"**: busta valida, poi sessione, poi decifratura con verifica del tag, poi schema del messaggio. Se la decifratura fallisce si risponde 400 e non si elabora nulla (c'è un test: l'archivio resta vuoto).
- **JSON Schema**: 10 schemi in `schemas/`, con `type`, `required`, `enum`, `minimum`/`maximum`, `pattern`, `format`, `additionalProperties: false`. Il validatore è scritto da me (`SchemaValidator.cs`) e supporta questi vincoli; l'errore riporta il campo, anche per campi mancanti ed extra.
- **Interi grandi come stringhe esadecimali** nell'handshake: 2048 bit non stanno in un numero JSON.
- **Archivio**: un file JSON con la lista delle misure. L'archivio usa un lock per evitare scritture contemporanee.

## Semplificazioni

Per mantenere il progetto adatto al livello del corso, non sono state aggiunte funzioni extra come anti-replay e scadenza automatica delle sessioni. Il progetto mantiene i controlli richiesti dalla traccia: validazione dei messaggi, controllo della sessione, cifratura AES-GCM e verifica del tag.

## Limiti noti

1. **Handshake non autenticato**: Diffie-Hellman non autentica. Un attaccante attivo (man-in-the-middle) può fare l'handshake con entrambi. Servirebbe una firma o un segreto condiviso in anticipo (certificati o PSK), che la traccia non richiede.
2. **Nessuna identità del sensore**: la sessione non è legata a un `sensor_id`, quindi un client potrebbe inviare misure a nome di un altro sensore.
3. **Nessuna rotazione della chiave nella sessione**: le chiavi sono effimere (una per sessione, cancellata alla chiusura), ma una sessione lunga usa sempre la stessa.
4. **Metadati visibili**: lunghezza delle buste, momenti degli invii, `session_id` e indirizzi IP.
5. **Errori in chiaro** per busta malformata o sessione inesistente: sono generici e senza dati, ma visibili.
6. **Archivio semplice**: il file viene riscritto per intero a ogni misura. Va bene per un prototipo, non per migliaia di sensori (servirebbe un database).
7. **Sessioni in memoria**: si perdono al riavvio del server. In produzione si userebbe HTTPS e un server configurato per l'esposizione in rete.
8. **Nessuna protezione anti-replay**: una busta già inviata potrebbe essere ripresentata. È una semplificazione didattica da migliorare in un sistema reale.
