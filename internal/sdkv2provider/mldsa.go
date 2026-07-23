package sdkv2provider

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// mlDsaAlgByOID maps ML-DSA SubjectPublicKeyInfo OIDs (FIPS 204) to RFC 9964 alg values.
var mlDsaAlgByOID = map[string]string{
	"2.16.840.1.101.3.4.3.17": "ML-DSA-44",
	"2.16.840.1.101.3.4.3.18": "ML-DSA-65",
	"2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}

// mlDsaPubLen is the FIPS 204 public key length per parameter set, used to reject a
// malformed SPKI whose OID is valid but whose key bytes are the wrong size.
var mlDsaPubLen = map[string]int{
	"ML-DSA-44": 1312,
	"ML-DSA-65": 1952,
	"ML-DSA-87": 2592,
}

// mlDsaSPKI is the ASN.1 SubjectPublicKeyInfo; ML-DSA carries no algorithm parameters.
type mlDsaSPKI struct {
	Algorithm struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	PublicKey asn1.BitString
}

// mldsaFromSPKI decodes a DER SPKI to the RFC 9964 alg and raw key for an ML-DSA OID,
// or ok=false so the caller falls through to RSA/EC. Uses encoding/asn1, not crypto/x509,
// so it does not depend on a Go release adding ML-DSA to ParsePKIXPublicKey.
func mldsaFromSPKI(der []byte) (alg string, pub []byte, ok bool) {
	var spki mlDsaSPKI
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil || len(rest) != 0 {
		return "", nil, false
	}
	alg, ok = mlDsaAlgByOID[spki.Algorithm.Algorithm.String()]
	if !ok {
		return "", nil, false
	}
	pub = spki.PublicKey.RightAlign()
	if len(pub) != mlDsaPubLen[alg] {
		return "", nil, false
	}
	return alg, pub, true
}

// akpThumbprint is the RFC 7638 thumbprint input for an AKP key: alg, kty, pub, sorted.
type akpThumbprint struct {
	Alg string `json:"alg"`
	Kty string `json:"kty"`
	Pub string `json:"pub"`
}

// mldsaJWK renders an ML-DSA public key as an RFC 9964 AKP JWK, returning the JWK JSON
// and the hex RFC 7638 thumbprint id (as for RSA/EC). algOverride, kid, use apply if set.
func mldsaJWK(detectedAlg string, pub []byte, kid, use, algOverride string) (jwks, id string, err error) {
	// An ML-DSA key's algorithm is fixed by its parameter set, so reject an override
	// that would make the JWK claim a different alg from the key.
	if algOverride != "" && algOverride != detectedAlg {
		return "", "", fmt.Errorf("alg %q does not match the ML-DSA key (%s)", algOverride, detectedAlg)
	}
	alg := detectedAlg
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)

	m := map[string]string{
		"kty": "AKP",
		"alg": alg,
		"pub": pubB64,
	}
	if kid != "" {
		m["kid"] = kid
	}
	if use != "" {
		m["use"] = use
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", "", err
	}

	tb, err := json.Marshal(akpThumbprint{Alg: alg, Kty: "AKP", Pub: pubB64})
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(tb)
	return string(b), hex.EncodeToString(sum[:]), nil
}
