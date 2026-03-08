# Cahier des charges — SecureNET

- **Projet** : SecureNET
- **Version** : 1.0.0
- **Date** : 2026-03-08
- **Statut** : Draft
- **Auteur** : Équipe SecureNET
- **Références de forme** : structure inspirée des pratiques ISO/IEC/IEEE 29148 (ingénierie des exigences)

## 1. Objet du document
Ce document formalise les besoins, exigences, contraintes, critères de validation et livrables du projet SecureNET.

## 2. Contexte et finalité
SecureNET vise la mise en place d’un réseau privé de routeurs (SNET Routers) permettant le transport de trafic utilisateur avec :
- confidentialité,
- intégrité,
- authenticité,
- non-répudiation.

## 3. Portée
### 3.1 Inclus
- Logiciel routeur SecureNET.
- Communications inter-routeurs.
- Gestion des certificats et signatures.
- Mécanisme de routage multi-sauts.
- Journalisation des événements réseau/administratifs.
- Support Linux et Windows.

### 3.2 Exclus (phase ultérieure)
- Interface graphique d’administration.
- Supervision centralisée avancée.
- Optimisations haute échelle (très grands volumes).

## 4. Parties prenantes
- **Sponsor / Décideur** : propriétaire du réseau SecureNET.
- **Administrateur réseau** : définit politiques, certificats, délégations.
- **Équipe développement** : implémente le routeur/protocole.
- **Équipe sécurité** : valide conformité cryptographique et architecture.
- **Exploitants** : déploient et maintiennent les nœuds.

## 5. Glossaire
- **SNET Router** : nœud logiciel participant au réseau SecureNET.
- **Handshake** : phase d’initialisation cryptographique d’une session.
- **P2P** : communication point-à-point.
- **Broadcast** : diffusion vers plusieurs nœuds selon politique.
- **TTL** : durée de vie d’un message/paquet pour limiter la propagation.

## 6. Hypothèses et contraintes
### 6.1 Hypothèses
- Le réseau peut être partiellement hostile (interception possible).
- Les nœuds disposent d’une horloge système correcte.
- OpenSSL est disponible sur les environnements cibles.

### 6.2 Contraintes
- Implémentation en C.
- Dépendance cryptographique principale : OpenSSL (API EVP).
- Compatibilité Linux et Windows obligatoire.
- Documentation technique en Markdown.

## 7. Exigences fonctionnelles
> Convention normative :
> - **MUST** = obligatoire
> - **SHOULD** = recommandé
> - **MAY** = optionnel

| ID | Exigence | Priorité | Critère d’acceptation |
|---|---|---|---|
| F-001 | Le routeur MUST établir une connexion TCP vers un autre routeur. | Haute | Connexion validée entre 2 nœuds en test d’intégration. |
| F-002 | Le routeur MUST accepter des connexions entrantes TCP. | Haute | Un nœud écoute et accepte au moins 1 client distant. |
| F-003 | Le protocole MUST définir des opcodes de contrôle/erreur normalisés. | Haute | Table d’opcodes versionnée et test de décodage réussi. |
| F-004 | Le système MUST supporter le mode P2P. | Haute | Message relayé de A vers B avec ACK valide. |
| F-005 | Le système MUST supporter le mode broadcast contrôlé. | Haute | Diffusion à N nœuds selon politique active. |
| F-006 | Le routage MUST permettre un chemin par défaut de 3 sauts. | Haute | Un flux traverse 3 routeurs en environnement de test. |
| F-007 | Le timeout inter-communications MUST être configurable; valeur par défaut 500 ms. | Moyenne | Paramètre modifiable et valeur par défaut appliquée. |
| F-008 | Le routeur MUST exposer des logs exploitables (erreur, session, routage). | Haute | Journaux structurés et filtrables par niveau. |

## 8. Exigences de sécurité
| ID | Exigence | Priorité | Critère d’acceptation |
|---|---|---|---|
| S-001 | Le handshake MUST utiliser un mécanisme asymétrique sûr (ex. RSA-OAEP ou équivalent). | Haute | Négociation validée + test de non-régression crypto. |
| S-002 | Le chiffrement de session MUST utiliser un algorithme authentifié moderne (ex. AES-256-GCM). | Haute | Chiffrement/déchiffrement + tag d’authentification validés. |
| S-003 | Les nœuds MUST être authentifiés par certificat signé administrateur (ou délégation autorisée). | Haute | Certificat non signé rejeté. |
| S-004 | Les certificats MUST inclure identifiant nœud, période de validité, clé publique, signature admin, empreinte. | Haute | Parsing et validation complète des champs obligatoires. |
| S-005 | Un certificat expiré MUST être refusé. | Haute | Test avec certificat expiré rejeté systématiquement. |
| S-006 | L’intégrité/authenticité des messages MUST être vérifiable (signature ou MAC). | Haute | Message altéré détecté et rejeté. |

## 9. Exigences non fonctionnelles
| ID | Exigence | Priorité | Critère d’acceptation |
|---|---|---|---|
| NF-001 | Le code MUST compiler sans erreur sur Linux et Windows. | Haute | Pipeline CI vert sur 2 plateformes. |
| NF-002 | Les modules bas niveau SHOULD remonter les erreurs sans `exit()` brutal. | Haute | API retourne codes d’erreur documentés. |
| NF-003 | Le protocole MUST être documenté de manière non ambiguë (tailles, formats, états). | Haute | Spécification protocole validée en revue technique. |
| NF-004 | Les logs SHOULD être horodatés et corrélables par identifiant de session. | Moyenne | Corrélation possible d’un flux complet. |
| NF-005 | La couverture de tests SHOULD atteindre au moins 70% sur modules critiques. | Moyenne | Rapport de couverture produit en CI. |

## 10. Interfaces et données
### 10.1 Interfaces réseau
- Transport : TCP.
- Schéma de message : en-tête + payload + métadonnées d’intégrité.
- Gestion des erreurs par opcode dédié.

### 10.2 Format protocole binaire v1 (normatif)
- **Endianess** : network byte order (big-endian) pour les champs multi-octets.
- **Header fixe** : 5 octets.
- **Layout** :
  - `byte 0` : `magic` = `0x53`.
  - `byte 1` : `version` = `0x01`.
  - `byte 2` : `opcode` (table des opcodes SNET).
  - `byte 3-4` : `payload_len` (`uint16`, big-endian).
- **Payload** :
  - taille variable de `0` à `65535` octets,
  - une charge utile vide (`payload_len = 0`) est autorisée pour les messages de contrôle.
- **Règles de validation** :
  - `magic` et `version` MUST correspondre à la version supportée,
  - si `expected_opcode` est renseigné et différent de `opcode`, le paquet est rejeté,
  - si `payload_len > buffer_reception`, le paquet est rejeté.

### 10.3 Codes de retour I/O (implémentation C)
- `-1` : argument invalide.
- `-2` : erreur de réception (`recv`).
- `-3` : en-tête invalide (`magic/version`).
- `-4` : opcode inattendu.
- `-5` : longueur payload trop grande pour le buffer.
- `-6` : erreur d’envoi (`send`).
- `-100` : fonctionnalité non supportée sur la plateforme courante.

### 10.4 API de réception (mode dynamique)
- `SNET_receiveTCP(...)` : mode strict avec `expected_opcode`.
- `SNET_receivePacketTCP(...)` : mode dynamique qui renvoie l’opcode effectivement reçu.

### 10.5 Données de certificat
- Identité : IPv4/IPv6/DNS.
- Dates : création, expiration.
- Clé publique : format PEM/DER documenté.
- Signature admin : format documenté.
- Empreinte : SHA-256 minimum (SHA-512 recommandé).

## 11. Conformité et gouvernance
- Les exigences MUST être traçables (ID unique).
- Toute modification MUST être versionnée.
- Les décisions crypto MUST être validées par revue sécurité.
- Les journaux SHOULD éviter les données sensibles en clair.

## 12. Stratégie de tests
### 12.1 Tests unitaires
- Crypto : génération, chiffrement/déchiffrement, signature/validation.
- Protocole : encodage/décodage opcodes et formats.

### 12.2 Tests d’intégration
- Liaison entre 2 nœuds.
- Chemin 3 sauts.
- Broadcast avec TTL/politique.
- Rejet d’un certificat invalide/expiré.

### 12.3 Tests de robustesse
- Nœud distant indisponible.
- Paquet malformé.
- Opcode inconnu.
- Rejeu simple d’un message signé.

## 13. Critères de recette
Le projet est recevable si :
1. 100% des exigences **Haute** sont validées.
2. Aucun défaut critique de sécurité n’est ouvert.
3. Build et tests d’intégration passent sur Linux et Windows.
4. La documentation d’exploitation et protocole est livrée.

## 14. Livrables
- Code source du routeur SecureNET.
- Documentation protocole.
- Guide d’installation/exploitation.
- Rapport de tests (unitaires + intégration + sécurité).
- Journal des décisions techniques (ADR recommandé).

## 15. Planning macro (indicatif)
1. **Phase A — Socle** : transport TCP + structure protocole.
2. **Phase B — Sécurité** : handshake + certificats + validation.
3. **Phase C — Routage** : multi-sauts + politiques de propagation.
4. **Phase D — Durcissement** : tests, logs, CI multi-plateforme.
5. **Phase E — Recette** : conformité exigences et livraison.

## 16. Matrice de traçabilité (extrait)
| Exigence | Design | Implémentation | Test |
|---|---|---|---|
| F-001 | DOC-PROTO-01 | `platforms/*` sockets | IT-001 |
| F-006 | DOC-ROUTE-01 | module routage | IT-003 |
| S-003 | DOC-PKI-01 | module certificats | SEC-002 |
| NF-001 | DOC-BUILD-01 | scripts build/CI | CI-ALL |

## 17. Risques principaux
- Ambiguïtés de spécification (taille paquet/en-têtes).
- Dette technique cross-platform si Windows traité tardivement.
- Mauvais choix crypto ou paramétrage faible.
- Absence de tests d’intégration réalistes.

## 18. Gestion des changements
- Toute exigence ajoutée/modifiée doit :
  - recevoir un nouvel ID ou une révision,
  - indiquer impact planning/technique,
  - être revalidée en revue.
