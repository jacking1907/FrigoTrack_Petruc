# Relazione – FrigoTrack

## Cosa ho fatto

Ho fatto il progetto in C# con .NET 8, perché è il linguaggio che conosco meglio. Il client simula tre sensori: una cella per farmaci, un camion per alimenti e una cella per surgelati. Ogni sensore manda delle misure di temperatura al server. Il server le controlla, le salva in un file JSON e risponde con una conferma. Se la temperatura esce dall'intervallo giusto per quel tipo di merce, la risposta contiene anche un allarme.

## Come proteggo i messaggi

Per prima cosa client e server si mettono d'accordo su una chiave con Diffie-Hellman. Il calcolo sta in `Dh.cs`: uso `BigInteger.ModPow` per calcolare `g^a mod p` e `B^a mod p`. Ho usato un gruppo standard a 2048 bit (RFC 3526, gruppo 14), così il numero primo non lo scelgo io. In rete passano solo `A` e `B`, la chiave no.

Dal segreto condiviso ricavo la chiave AES con SHA-256. Serve perché il segreto è lungo 2048 bit e AES-256 vuole una chiave di 32 byte.

Poi cifro ogni messaggio con AES-256-GCM. Ogni messaggio ha un nonce casuale e un tag. Se qualcuno cambia anche un solo bit, il tag non torna e il server risponde 400 senza elaborare niente. Ho messo anche il `session_id` tra i dati autenticati, così una busta non si può spostare su un'altra sessione.

Il server prima decifra e poi controlla il messaggio con JSON Schema. L'ordine conta: se il messaggio è stato modificato non ha senso guardarne il contenuto. Gli schemi sono 10 file nella cartella `schemas/`, uno per ogni tipo di messaggio, e quando un messaggio è sbagliato l'errore dice anche quale campo.

## Cosa ho semplificato

Rispetto alla prima versione ho tolto tre cose: la protezione contro i messaggi ripetuti (replay), la scadenza delle sessioni e la scrittura del file con un file temporaneo. Non erano richieste dalla traccia e rendevano il codice più lungo da spiegare. Ho tolto anche il test sul replay.

## Test e Git

I test sono in `FrigoTrack.Tests`: 31 test, che con le varianti diventano 39 casi, e passano tutti. Controllano l'handshake, una misura valida, una non valida, una busta manomessa, una sessione inesistente e gli errori 400, 401 e 404.

Ho diviso il lavoro in 5 commit: Diffie-Hellman, schemi e validazione, cifratura e server, client, test e documentazione.

## Limiti

1. L'handshake non è autenticato. Un attaccante che si mette in mezzo (man-in-the-middle) potrebbe fare l'handshake con tutti e due. Servirebbero certificati o un segreto condiviso prima, ma la traccia non li chiede.
2. La sessione non è legata a un sensore, quindi un client potrebbe mandare misure a nome di un altro.
3. Senza protezione anti-replay, una busta già inviata potrebbe essere rimandata.
4. Il file delle misure viene riscritto per intero a ogni misura. Per un prototipo va bene, con tanti sensori servirebbe un database.
5. Le sessioni stanno in memoria e si perdono se il server si riavvia.
