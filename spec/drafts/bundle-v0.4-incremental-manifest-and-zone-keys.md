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
{ aithos: "0.4.0", bundle_id, subject_did, subject_handle, display_name,
  edition: { version, created_at, supersedes, prev_hash, height },
  zones: {
    public: { n, shard_count, shard_shas[] },
    circle: { n, shard_count, shard_shas[], keyring_sha, extrawraps_sha },
    self:   { … } },
  integrity: { sha256_of_did_json, manifest_signature } }   // enveloppe v0.3 conservée
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

- **Dual-read partout** (serveur + client), discriminé par `aithos`.
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

---

# Partie II — Spécification normative (v0.4)

Tout ce qui n'est pas redéfini ici hérite de v0.3 (drafts per-section-encryption,
section-level-mandates, section-verb-scopes) : enveloppes §11, chaîne d'éditions,
blobs, construction de wrap §3.6 (X25519-HKDF-SHA256-AEAD), grammaire des scopes,
did.json/époque.

## N1. Objets content-addressed

Un **objet** est un document JSON canonicalisé **JCS (RFC 8785)** ; son
identifiant est `sha256(bytes_canoniques)` en hex minuscule. Stockage :
`ethos/{did}/objects/{sha}` (espace distinct des blobs — ACL et GC propres).
Les objets sont immuables ; toute « modification » est un nouvel objet référencé
par le manifest suivant. Chaque objet porte `{"object": "<type>", "v": 1, ...}`
comme discriminant.

## N2. ZoneShard

```jsonc
{ "object": "zone_shard", "v": 1,
  "zone": "circle",
  "entries": [ {
      "section_id": "…",
      "title": "…",            // public/circle : clair (spec v0.3 inchangée)
      "tags": ["…"],           // optionnel, clair là où title est clair
      "title_cipher": { "n": "...", "ct": "..." },  // self : AEAD(DEK) — voir N3
      "blob_sha": "…", "sha256_of_plaintext": "…", "gamma_ref": "…",
      "approx_size_bytes": 1234,                        // hint P3 (optionnel, à coût zéro)
      "enc_dek": { "kid": "zk…", "n": "…", "c": "…" }   // absent ⇢ voir N9.3
  } ] }
```

- Tri des `entries` par `section_id` (bytewise) — déterminisme du sha.
- **Sharding** : `shard_count = next_pow2(ceil(n/128))` borné à `[1, 64]`,
  recalculé à chaque édition à partir du nombre TOTAL de sections de la zone ;
  `shard_index = u32be(sha256(section_id)[0..4]) mod shard_count`. Un
  changement de `shard_count` (franchissement de seuil) réécrit tous les
  shards de la zone (corps intouchés).
- `public` : `entries` sans `enc_dek` ni `title_cipher` (blobs en clair).
- `self` : `title`/`tags` ABSENTS, `title_cipher` REQUIS :
  `XChaCha20-Poly1305(DEK, n, jcs({title, tags?}))`,
  AAD = `"aithos-title-v2\0" ‖ subject_did ‖ "\0" ‖ section_id`.
  (v2 : scellé sous la DEK de section — qui ouvre le corps lit le titre ;
  mêmes destinataires par construction, contrat v0.3 conservé.)

## N3. Clé de zone & `enc_dek`

- **Clé de zone** : 32 octets aléatoires, identifiée par
  `kid = "zk" ‖ 16 hex aléatoires`. Une par zone chiffrée (`circle`, `self`).
- **`enc_dek`** : `XChaCha20-Poly1305(zone_key, n, DEK)`,
  AAD = `"aithos-dek-v1\0" ‖ subject_did ‖ "\0" ‖ zone ‖ "\0" ‖ section_id ‖ "\0" ‖ kid`.
  La DEK de section reste celle qui chiffre le blob (et `title_cipher` en self) —
  les blobs v0.3 sont donc portables tels quels.
- Une zone a UN `kid` courant ; après rotation, toutes les entrées portent le
  nouveau `kid` (la réécriture des shards fait partie de l'édition de rotation —
  un manifest ne référence jamais deux `kid` pour une même zone).

## N4. KeyRing & ExtraWraps (canal authentifié uniquement)

```jsonc
{ "object": "keyring", "v": 1, "zone": "circle", "kid": "zk…",
  "wraps": [ { "recipient": "<label v0.3 inchangé>",
               "wrap": { /* §3.6 sur jcs({kid, zone_key}) */ } } ] }

{ "object": "extra_wraps", "v": 1, "zone": "circle",
  "entries": [ { "section_id": "…",
                 "wraps": [ { "recipient": "…", "wrap": { /* §3.6 sur DEK — IDENTIQUE v0.3 */ } } ] } ] }
```

- `recipient` : format v0.3 (`granteeId#pubkeyMultibase` | `did#<zone>-kex`).
- L'owner (`did#<zone>-kex`) figure TOUJOURS dans le keyring.
- Les wraps d'ExtraWraps sont bit-à-bit le format v0.3 (migration = copie).
- `entries` et `wraps` triés (section_id, puis recipient) — déterminisme.

## N5. Manifest v0.4

```jsonc
{ "aithos": "0.4.0", "bundle_id": "…", "subject_did": "…",
  "subject_handle": "…", "display_name": "…",
  "edition": { "version": "…", "created_at": "…", "supersedes": null,
               "prev_hash": "…", "height": 107 },
  "zones": {
    "public": { "n": 3,   "shard_count": 1, "shard_shas": ["…"] },
    "circle": { "n": 209, "shard_count": 2, "shard_shas": ["…","…"],
                 "keyring_sha": "…", "extrawraps_sha": "…" },
    "self":   { "n": 12,  "shard_count": 1, "shard_shas": ["…"],
                 "keyring_sha": "…" } },
  "integrity": { "sha256_of_did_json": "…",
                  "manifest_signature": { /* §3.8′ inchangé : owner #public ou délégué+authorized_by, JCS valeur blanche */ } } }
```

`extrawraps_sha` optionnel (absent ⇔ aucune entrée). `prev_hash` : inchangé
(sha du manifest précédent canonique). La signature ne couvre QUE ce document ;
l'intégrité des objets/blobs découle des sha qu'il référence (et récursivement).

## N6. Publish (extension de l'enveloppe §11)

`aithos.publish_ethos_edition` accepte en v0.4 :
`params = { manifest, objects: { "<sha>": b64, … }, blobs: { "<sha>": b64, … } }`.

Validation serveur (ordre normatif) :

1. Enveloppe §11, signature manifest, `height/prev_hash` (chaîne linéaire,
   `-32030` sur conflit), `sha256_of_did_json` — inchangés.
2. **Intégrité** : chaque clé d'`objects`/`blobs` = sha256 réel du contenu ;
   chaque sha référencé par le manifest (shards, keyring, extrawraps) ∈
   `objects` uploadés ∪ objets référencés par l'édition précédente (carry par
   induction — l'analogue exact de `carriedShaSet`).
3. **Carry des corps** : pour chaque shard ABSENT de l'édition précédente
   (nouveau sha), chaque `entries[].blob_sha` ∈ `blobs` uploadés ∪
   `carriedShaSet(prev)`. Les shards repris à l'identique ne sont pas relus.
4. **Autorisation déléguée** (si l'enveloppe porte un mandat) : vérif du mandat
   (did.json FRAIS, époque, révocation ConsistentRead — inchangé), puis diff
   limité aux shards changés : par zone, `entries(prev_shards_changés)` vs
   `entries(new_shards_changés)` → ops `create/edit/delete` par `section_id`
   (création = id nouveau ; edit = blob_sha/plain_sha/title*/enc_dek changé ;
   delete = id disparu), mapping verbes §4.8.2′ + sélecteurs inchangés.
   Règles structurelles : `keyring_sha` ne change QUE dans un publish owner ;
   une entrée d'ExtraWraps ne change que si l'op correspondante sur ce
   `section_id` est autorisée ; `shard_count` stable hors publish owner sauf
   si le re-shard est rendu nécessaire par un `create` autorisé.
5. Persistance : objets+blobs en parallèle, row DDB en DERNIER (inchangé).

Dual-write : le serveur continue d'accepter les publishes v0.3 (un sujet migré
en v0.4 REFUSE un publish v0.3 ultérieur : `aithos` ne régresse jamais —
erreur dédiée `-32045 ethos_spec_version_regression`).

## N7. Lectures

- `aithos.get_ethos_manifest` : renvoie le manifest tel que stocké (`aithos` 0.3.0 ou 0.4.0).
- **Nouveau** `aithos.get_ethos_objects` : `{ did, shas: [≤64] }` →
  `{ objects: [{sha, b64}], missing: [sha] }` (absent ≡ interdit, pas d'oracle).
  ACL par type d'objet : `zone_shard` suit l'ACL du manifest (lecteur anonyme
  admis — un shard n'expose plus aucun label de destinataire) ; `keyring` et
  `extra_wraps` exigent la read-auth (owner ou délégué actif du sujet, comme
  les blobs circle/self aujourd'hui).
- Blobs : `aithos.get_ethos_section`/`get_ethos_sections` inchangés.

## N8. Algorithme de lecture (informatif mais attendu des clients)

Owner/délégué : manifest → shards de la zone (1 batch `get_ethos_objects`) →
keyring (authentifié) → déballer la clé de zone (cache de session par kid) →
`enc_dek` → DEK → blob. Si pas de clé de zone (grant par-section) : ExtraWraps.
`readable(entry)` = (clé de zone détenue ∧ `enc_dek` présent) ∨ (entrée
ExtraWraps à mon label) — calculable sans toucher aux corps, comme en v0.3.
Anonyme : `public` intégral ; `circle` titres/ids ; `self` ids seuls. Délégué
sans accès : mêmes surfaces que l'anonyme (parité v0.3 conservée).

## N9. Algorithmes d'écriture

1. **Edit/add/delete owner** : réécrire le(s) shard(s) touché(s) (+ blob),
   manifest, publish. En éditant une section, l'owner refresh son `enc_dek`
   sous le `kid` courant et purge de l'entrée ExtraWraps les labels de mandats
   morts (auto-nettoyage v0.3 conservé, désormais par section ET par objet).
2. **Edit délégué (zone)** : il détient la clé de zone → nouvelle DEK, blob,
   `enc_dek` sous le kid courant, shard, manifest. AUCUNE résolution de grants.
3. **Create délégué SANS clé de zone** (fence `#prefix=`/append) : DEK générée,
   entrée SANS `enc_dek`, ExtraWraps = {auteur, owner} (contrat v0.3 « sealed
   to both » conservé). Le prochain edit owner de la section (ou `sealGrant`)
   la dote d'un `enc_dek` — règle « resync à l'édition » inchangée.
4. **sealGrant** (owner) : scope de zone → wrap ajouté au keyring (O(1)) ;
   scope par-section → wraps DEK dans ExtraWraps pour les sections couvertes
   (l'owner déballe les DEK via ses `enc_dek` — aucune lecture de corps).
5. **pruneWraps** (owner) : retire des keyring/ExtraWraps les labels de mandats
   révoqués/expirés. Métadonnée pure, sémantique v0.3 inchangée.
6. **reseal({mode:"rotate"})** (owner) : nouvelle clé de zone (nouveau kid),
   keyring re-scellé aux grants actifs + owner, `enc_dek` de TOUTES les entrées
   re-scellés (symétrique), shards réécrits, corps intouchés.
7. **reseal({mode:"rotate-deep"})** (owner) : rotate + nouvelles DEK + blobs
   re-chiffrés et re-uploadés (+ `title_cipher` self) — l'effacement fort.

## N10. Migration v0.3 → v0.4 (publish owner, une édition)

1. Lire le manifest v0.3 ; pour chaque section chiffrée, déballer SON wrap
   owner → DEK (local, aucune lecture de corps).
2. Générer les clés de zone ; construire shards (champs portés tels quels,
   `blob_sha` carried, `enc_dek` scellé), keyring (owner + mandats ACTIFS à
   scope de zone — pubkey extraite du label v0.3), ExtraWraps (wraps v0.3
   copiés bit-à-bit pour les mandats actifs par-section ; morts élagués).
3. Publier `aithos: "0.4.0"`, `height+1` : uploads = objets + manifest,
   zéro blob. Le serveur valide le carry intégral via `carriedShaSet(prev)`.
4. Un délégué n'initie JAMAIS la migration : sur un sujet v0.3 il écrit du
   v0.3. Les bundles de mandat sont inchangés et valides des deux côtés.

## N11. GC

Les objets rejoignent les blobs dans le périmètre du GC offline : vivant =
référencé par une édition retenue. Extension du runbook existant
(RUNBOOK-MANDATE-GC) — aucune nouvelle primitive.

## N12. Erreurs nouvelles

| Code | Nom | Quand |
|---|---|---|
| -32043 | `ethos_object_missing` | sha référencé ni uploadé ni porté |
| -32044 | `ethos_object_hash_mismatch` | contenu ≠ sha annoncé |
| -32045 | `ethos_spec_version_regression` | publish v0.3 sur sujet v0.4 |
| -32046 | `ethos_keyring_forbidden` | keyring/shard_count modifié hors publish owner |

## N13. Conformité

Les 34 e2e v0.3 passent inchangés sur un sujet migré (mêmes surfaces SDK).
Nouveaux cas : M1 migration porte l'accès des délégués actifs ; M2 croisé
(délégué v0.3 → sujet migré) ; M3 sealGrant zone O(1) observable ; M4 rotate
coupe un délégué de zone sans re-upload de corps ; M5 rotate-deep re-chiffre ;
M6 anonyme ne peut pas lire keyring/extrawraps (`missing`) ; M7 fence-create
sans clé de zone puis resync owner ; M8 régression de version refusée.
