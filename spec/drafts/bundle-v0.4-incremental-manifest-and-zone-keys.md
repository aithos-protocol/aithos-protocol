# Bundle v0.4 — manifest incrémental & clés de zone (BRIEF de design)

> **Statut : BRIEF à valider** — ce document est le design P3+P4 issu de la
> campagne perf de juin 2026 (voir `PLAN-SEALING-SCALE-2026-06-10.md` côté
> provider). Une fois validé, il devient la spec détaillée et pilote
> l'implémentation : serveur → protocol-client → SDK → app → e2e.

## 1. Problème (mesuré)

En v0.3, **chaque édition réécrit le manifest entier** : tous les descripteurs
de toutes les zones, avec les wraps inline (un par section × destinataire).
Conséquences mesurées pendant la campagne :

| Geste (v0.3) | 209 sections | 1000 sections | Pourquoi |
|---|---|---|---|
| Edit 1 section (délégué, chaud) | ~4 s | ~ | manifest entier (re-build, JCS, upload, re-validation serveur) + resync grants (list/get_mandate) + vérifs fraîches |
| Edit 1 section (owner) | ~ | ~2.0 s | manifest entier |
| sealGrant zone | ~ | ~3.1 s | un wrap ajouté à CHAQUE section de la zone |
| Révocation dure (rotate) | ~ | re-chiffrement des corps | nouvelle DEK par section |

Le coût d'édition est **linéaire en taille de zone**, pas en taille du delta.
C'est le mur structurel restant.

## 2. Modèle v0.4 — vue d'ensemble

Trois changements solidaires :

1. **Le manifest devient O(1)** : il ne contient plus les descripteurs mais des
   références content-addressed vers des objets de zone. Seul le manifest est
   signé (JCS, comme aujourd'hui) ; l'intégrité du reste découle des sha.
2. **Les wraps sortent du manifest** (et des objets visibles anonymement) :
   ils vivent dans des objets servis uniquement sur canal authentifié.
3. **Clé maîtresse par zone chiffrée** : un mandat de zone reçoit UN wrap
   (la clé de zone), pas un par section. Les DEK par section demeurent,
   scellées symétriquement sous la clé de zone.

### 2.1 Objets (tous content-addressed, immuables, stockés comme les blobs)

```
ZoneShard          — 1/N de l'index d'une zone (partition par section_id)
  entries[]: {
    section_id, title | title_cipher,        # circle: titre clair (spec inchangée)
    blob_sha, sha256_of_plaintext, gamma_ref,
    enc_dek, dek_kid                          # AEAD(zoneKey, DEK, ad=section_id)
  }

KeyRing            — par zone chiffrée, minuscule (destinataires × ~120 o)
  { zone_key_id, wraps[]: { recipient, wrap(zoneKey → kex pk) } }
  # recipient garde le format v0.3 : "granteeId#pubkeyMultibase" | "did#zone-kex"
  # l'owner y figure TOUJOURS (kex de zone)

ExtraWraps         — par zone, normalement vide ; wraps par-section pour les
  { entries[]: { section_id, wraps[] } }      # grants #id=/#prefix=/#tag= sans clé de zone
```

`title_cipher` (self) devient `AEAD(DEK, title)` — plus simple que v0.3 (qui
scellait le titre par destinataire) : qui peut ouvrir le corps peut lire le
titre, mêmes destinataires par construction.

### 2.2 Manifest v0.4 (signé, ~3 Ko quelle que soit la taille)

```
{ spec_version: "0.4", subject_did, edition_height, prev_hash, created_at,
  sha256_of_did_json,
  zones: {
    public: { shard_shas[], n },
    circle: { shard_shas[], keyring_sha, extrawraps_sha, n },
    self:   { … } },
  proof }
```

### 2.3 Sharding déterministe

`shard_count = next_pow2(ceil(n / 128))`, borné à [1..64], partition par
`sha256(section_id)`. Une petite zone = 1 shard (zéro sur-coût) ; à 1000
sections = 8 shards d'~16 Ko. Le franchissement d'un seuil re-écrit la zone
une fois (rare, amorti). Éditer une section = réécrire **son** shard.

## 3. Ce que ça change (chiffres attendus)

| Geste (v0.4) | Coût | vs v0.3 |
|---|---|---|
| Edit 1 section | blob + 1 shard (~16 Ko) + manifest (~3 Ko) ; diff serveur sur le shard changé | **O(delta)** — attendu < 1 s chaud, ~1,5 s froid |
| Edit délégué | idem ; **plus aucun crawl list/get_mandate** (la clé de zone couvre déjà les délégués de zone ; les ExtraWraps existants sont portés tels quels — doctrine additive) | -2 round-trips séquentiels |
| sealGrant (mandat de zone) | 1 wrap dans le KeyRing + manifest | **O(1)** — de 3,1 s à ~0,3 s |
| sealGrant (mandat #id) | réécrire l'entrée ExtraWraps | O(1) |
| pruneWraps | épure KeyRing + ExtraWraps | O(destinataires) |
| Révocation dure d'un délégué de zone | rotation : nouvelle zone key + re-wrap symétrique des enc_dek (tous les shards) + KeyRing neuf — **corps intouchés, aucun re-chiffrement de blob** | de « re-chiffrer la zone » à « réécrire ~130 Ko d'objets » à 1000 sections |
| index() (lecture) | manifest + shards de la zone en 1 batch | ≈ aujourd'hui |
| section() (open) | shard déjà en cache → 1 fetch de blob + unwrap local | ≈ aujourd'hui |
| Privacy historique des délégués | KeyRing/ExtraWraps servis **uniquement authentifié** → un lecteur anonyme ne voit plus AUCUN label de destinataire (v0.3 : wraps visibles dans le manifest) | réglé structurellement |

## 4. Sémantique de sécurité (les nuances à acter)

- **Gate / prune / rotate inchangés.** Le serveur reste le garde-fou instantané
  (mandat vérifié par requête, did.json frais pour l'époque, ConsistentRead
  révocations). La rotation reste l'acte cryptographique rare et explicite.
- **`reseal({mode:"rotate"})` en v0.4 = rotation de la clé de zone** : coupe
  tout détenteur de l'ancienne clé pour les éditions futures, sans re-chiffrer
  les corps. Nuance assumée (et à documenter tel quel) : un ancien délégué qui
  aurait archivé des DEK par section pourrait encore déchiffrer d'anciens blobs
  s'il les obtenait — or il ne les obtiendra pas : le serveur le gate, et les
  blobs circle/self ne quittent jamais le canal authentifié. Même posture que
  ta conclusion sur « casser le wrap » : la coupure d'accès réel est servie par
  le gate ; la rotation coupe la voie crypto pour la suite.
- **`reseal({mode:"rotate-deep"})` (nouveau, optionnel)** : l'effacement
  cryptographique fort — nouvelles DEK + re-chiffrement des corps (coût v0.3).
  Réservé aux cas « ce contenu ne doit plus exister pour personne ».
- **Un mandat de zone = la clé de zone.** Granularité inchangée pour les
  scopes : #id/#prefix/#tag continuent de passer par des wraps par section
  (ExtraWraps), sans recevoir la clé de zone.
- **Anonyme** : index circle (titres clairs) et public inchangés — les shards
  publics/circle suivent l'ACL du manifest actuel ; ils ne contiennent plus
  aucune info de destinataire.
- **#tag-on-self** : posture inchangée (fail-closed serveur, débat P3/P4
  d'origine non rouvert ici).

## 5. Migration v0.3 → v0.4

- **Dual-read partout** (serveur + client), discriminé par `spec_version`.
- **Le format est piloté par l'owner** : son premier publish avec un client
  v0.4 migre l'Ethos en une édition. La migration est **bon marché** : les
  blobs sont portés par sha (zéro re-upload, zéro re-chiffrement) ; l'owner
  déchiffre localement ses propres wraps v0.3 pour obtenir les DEK, génère les
  clés de zone, scelle `enc_dek`, construit shards/KeyRing/ExtraWraps.
- **Continuité des délégués** : les mandats actifs sont portés — scope de zone
  → wrap dans le KeyRing (la pubkey kex est dans le label v0.3) ; scope
  par-section → ExtraWraps. Révoqués/expirés : élagués (doctrine prune).
- **Un délégué n'initie jamais la migration** : sur un sujet v0.3 il continue
  d'écrire du v0.3. Le serveur accepte les publishes v0.3 sans limite de durée
  pour l'instant.
- Bundles de mandat, did.json, époque, enveloppes §11 : **inchangés**.

## 6. Ce qui ne change PAS (périmètre verrouillé)

Surface API (`Ethos`/zones/sections/mandates/sealGrant/reseal/pruneWraps),
grammaire des scopes §4.8.2′, enveloppes §11, chaîne d'éditions
(height/prev_hash), blobs content-addressed, did.json + époque de révocation,
politique « blobs circle/self jamais hors canal authentifié », sémantique
anonyme/public, et le contrat des 34 e2e existants (ils doivent rester verts
tels quels).

## 7. Impacts par repo

| Repo | Travaux |
|---|---|
| Aithos-protocol | cette spec (détaillée après validation) |
| aithos-provider | publish v0.4 (objets dans l'enveloppe, sha vérifiés, carry par objets, diff d'autorisation par shard changé), `aithos.get_ethos_objects` (batch ≤64, missing[], ACL = manifest pour shards / authentifié pour KeyRing+ExtraWraps), dual-read, GC étendu aux objets (runbook) |
| protocol-client | writer/reader v0.4, migration owner, sealGrant O(1), rotate/rotate-deep, dual-read |
| aithos-sdk | mêmes surfaces publiques ; caches par shard ; `reseal` modes ; rien de visible pour l'app au-delà des perfs |
| aithos-app-example | aucun changement fonctionnel attendu (vitrine du gain) |
| e2e | 34 existants verts + nouveaux : migration, lecture croisée v0.3/v0.4, sealGrant O(1), rotate zone-key, ExtraWraps #id, privacy KeyRing anonyme |

## 8. Critères d'acceptation (mêmes points de mesure que la campagne)

À 1000 sections/zone sur dev : edit owner ET délégué < 1,5 s à froid, < 1 s à
chaud ; sealGrant zone < 0,5 s ; rotation zone < 10 s sans re-upload de corps ;
index()/section() au niveau actuel ou mieux ; migration d'un Ethos 1000
sections < 10 s ; suite e2e complète verte ; testable de bout en bout sur
aithos-app-example.

## 9. Risques & contreparties

1. **Plus d'objets = plus d'états partiels possibles.** Mitigé par le
   content-addressing : tout est immuable, le manifest signé est le seul point
   de vérité, un publish est atomique côté serveur (row DDB en dernier, comme
   aujourd'hui).
2. **Re-shard au franchissement de seuil** : réécriture ponctuelle de la zone
   (sans corps). Rare et amorti ; le seuil en puissance de 2 évite l'effet
   yo-yo.
3. **GC** : les vieux shards/keyrings s'accumulent comme les vieux blobs —
   même posture append-only + GC offline (extension du runbook existant).
4. **Deux formats à maintenir** le temps de la transition (dual-read). Borné :
   les e2e couvrent la croisée, et la migration est automatique côté owner.
