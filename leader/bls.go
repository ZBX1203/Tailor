package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"sort"
	"sync"
	"sync/atomic"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func decodeG2NoSubgroup(buf []byte, p *bls12381.G2Affine) error {
	var rdr bytes.Reader
	rdr.Reset(buf)
	dec := bls12381.NewDecoder(&rdr, bls12381.NoSubgroupChecks())
	return dec.Decode(p)
}

var blsKeys = make(map[string]*blsKey)
var keysOnce sync.Once
var globalAggKeyCache = &AggregatedKeyCache{}

var (
	blsDST        = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
	g1Gen         bls12381.G1Affine
	negG1         bls12381.G1Affine
	gnarkInitOnce sync.Once
)

var hashToG2Cache sync.Map

func cachedHashToG2(data []byte) (bls12381.G2Affine, error) {
	key := string(data)
	if cached, ok := hashToG2Cache.Load(key); ok {
		return cached.(bls12381.G2Affine), nil
	}
	hm, err := bls12381.HashToG2(data, blsDST)
	if err != nil {
		return hm, err
	}
	hashToG2Cache.Store(key, hm)
	return hm, nil
}

func initGnarkBLS() {
	gnarkInitOnce.Do(func() {
		_, _, g1, _ := bls12381.Generators()
		g1Gen = g1
		negG1.Neg(&g1Gen)
		log.Println("✅ [BLS] initialized gnark-crypto/bls12-381")
	})
}

type AggregatedKeyCache struct {
	cache sync.Map
	stats struct {
		hits   uint64
		misses uint64
	}
}

func computeNodeListHash(nodeIDs []string) string {
	sorted := make([]string, len(nodeIDs))
	copy(sorted, nodeIDs)
	sort.Strings(sorted)

	h := sha256.New()
	for _, id := range sorted {
		h.Write([]byte(id))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (c *AggregatedKeyCache) GetAggregatedPublicKey(nodeIDs []string) (bls12381.G1Affine, error) {
	if len(nodeIDs) == 0 {
		return bls12381.G1Affine{}, fmt.Errorf("empty node list")
	}

	cacheKey := computeNodeListHash(nodeIDs)

	if cached, ok := c.cache.Load(cacheKey); ok {
		atomic.AddUint64(&c.stats.hits, 1)
		return cached.(bls12381.G1Affine), nil
	}

	atomic.AddUint64(&c.stats.misses, 1)

	seen := make(map[string]struct{}, len(nodeIDs))
	for _, id := range nodeIDs {
		if _, dup := seen[id]; dup {
			return bls12381.G1Affine{}, fmt.Errorf("duplicate participant %s in aggregation list", id)
		}
		seen[id] = struct{}{}
	}

	firstKey, ok := blsKeys[nodeIDs[0]]
	if !ok {
		return bls12381.G1Affine{}, fmt.Errorf("no BLS key found for node %s", nodeIDs[0])
	}

	var aggJac bls12381.G1Jac
	aggJac.FromAffine(&firstKey.publicKey)

	for i := 1; i < len(nodeIDs); i++ {
		key, ok := blsKeys[nodeIDs[i]]
		if !ok {
			return bls12381.G1Affine{}, fmt.Errorf("no BLS key found for node %s", nodeIDs[i])
		}
		aggJac.AddMixed(&key.publicKey)
	}

	var aggPk bls12381.G1Affine
	aggPk.FromJacobian(&aggJac)

	c.cache.Store(cacheKey, aggPk)
	return aggPk, nil
}

func VerifyWithPreAggregatedKey(nodeIDs []string, msg []byte, sigBytes []byte) bool {
	initGnarkBLS()

	aggPk, err := globalAggKeyCache.GetAggregatedPublicKey(nodeIDs)
	if err != nil {
		log.Printf("[BLS pre-aggregate verify] failed to get aggregate public key: %v", err)
		return false
	}

	var sig bls12381.G2Affine
	if _, err := sig.SetBytes(sigBytes); err != nil {
		log.Printf("[BLS pre-aggregate verify] signature deserialization failed or point not in subgroup: %v", err)
		return false
	}

	hm, err := cachedHashToG2(msg)
	if err != nil {
		log.Printf("[BLS pre-aggregate verify] HashToG2 failed: %v", err)
		return false
	}

	check, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{negG1, aggPk},
		[]bls12381.G2Affine{sig, hm},
	)
	if err != nil {
		log.Printf("[BLS pre-aggregate verify] PairingCheck failed: %v", err)
		return false
	}
	return check
}

func GetAggKeysCacheStats() (hits, misses uint64, hitRate float64, cacheSize int) {
	hits = atomic.LoadUint64(&globalAggKeyCache.stats.hits)
	misses = atomic.LoadUint64(&globalAggKeyCache.stats.misses)
	total := hits + misses
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}
	size := 0
	globalAggKeyCache.cache.Range(func(_, _ interface{}) bool {
		size++
		return true
	})
	cacheSize = size
	return
}

type blsSignature struct {
	NodeID string
	Sig    bls12381.G2Affine
}

func DecodeBLSPoint(sigBytes []byte) (bls12381.G2Affine, error) {
	var p bls12381.G2Affine
	if _, err := p.SetBytes(sigBytes); err != nil {
		return p, err
	}
	return p, nil
}

type blsKey struct {
	privateKey *big.Int
	publicKey  bls12381.G1Affine
}

func generateGnarkKeyPair() (*big.Int, bls12381.G1Affine) {
	var skElem fr.Element
	if _, err := skElem.SetRandom(); err != nil {
		log.Panicf("failed to generate random scalar: %v", err)
	}
	sk := skElem.BigInt(new(big.Int))

	var pk bls12381.G1Affine
	pk.ScalarMultiplication(&g1Gen, sk)

	return sk, pk
}

func GenerateBLSKeys(nodeIDs []string) {
	keysOnce.Do(func() {
		initGnarkBLS()
		for _, nodeID := range nodeIDs {
			sk, pk := generateGnarkKeyPair()
			blsKeys[nodeID] = &blsKey{privateKey: sk, publicKey: pk}
			log.Printf("Generated BLS key for %s", nodeID)
		}
	})
}

func GetBLSKey(nodeID string) *blsKey {
	key, ok := blsKeys[nodeID]
	if !ok {
		log.Panicf("no BLS key found for node %s", nodeID)
	}
	return key
}

func (k *blsKey) Sign(data []byte) []byte {
	initGnarkBLS()

	if failureMode == 1 {
		if _, isMalicious := maliciousNodeTable[nodeID]; isMalicious {
			data = []byte("byzantine_fake_digest")
		}
	}
	hm, err := cachedHashToG2(data)
	if err != nil {
		log.Panicf("failed to hash to G2: %v", err)
	}
	var sig bls12381.G2Affine
	sig.ScalarMultiplication(&hm, k.privateKey)
	res := sig.Bytes()
	return res[:]
}

func (k *blsKey) AggregateSigs(sigs []blsSignature) []byte {
	if len(sigs) == 0 {
		log.Panicf("no signatures to aggregate")
	}

	var aggJac bls12381.G2Jac
	aggJac.FromAffine(&sigs[0].Sig)
	for i := 1; i < len(sigs); i++ {
		aggJac.AddMixed(&sigs[i].Sig)
	}

	var result bls12381.G2Affine
	result.FromJacobian(&aggJac)
	res := result.Bytes()
	return res[:]
}

func (k *blsKey) VerifyPoint(data []byte, sigPoint bls12381.G2Affine) bool {
	initGnarkBLS()

	hm, err := cachedHashToG2(data)
	if err != nil {
		log.Printf("failed to hash to G2: %v", err)
		return false
	}

	check, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{negG1, k.publicKey},
		[]bls12381.G2Affine{sigPoint, hm},
	)
	if err != nil {
		log.Printf("pairing check failed: %v", err)
		return false
	}
	return check
}

func (k *blsKey) Verify(data []byte, sig []byte) bool {
	var sigPoint bls12381.G2Affine
	if _, err := sigPoint.SetBytes(sig); err != nil {
		log.Printf("failed to unmarshal signature: %v", err)
		return false
	}
	return k.VerifyPoint(data, sigPoint)
}

func NewSignatureFromBytes(sigBytes []byte) ([]byte, error) {
	return sigBytes, nil
}

func AllBLSKeyFilesExist(nodeIDs []string) bool {
	if _, err := os.Stat("bls_keys"); os.IsNotExist(err) {
		return false
	}
	for _, id := range nodeIDs {
		if _, err := os.Stat("bls_keys/" + id + "_bls_priv.bin"); os.IsNotExist(err) {
			return false
		}
	}
	if _, err := os.Stat("bls_keys/bls_pubkeys.json"); os.IsNotExist(err) {
		return false
	}
	return true
}

func GenerateAndSaveAllBLSKeys(nodeIDs []string) {
	initGnarkBLS()
	if err := os.MkdirAll("bls_keys", 0755); err != nil {
		log.Fatalf("cannot create bls_keys directory: %v", err)
	}

	existingPubkeys := map[string][]byte{}
	if data, err := os.ReadFile("bls_keys/bls_pubkeys.json"); err == nil {
		json.Unmarshal(data, &existingPubkeys)
	}

	newKeyCount := 0
	for _, id := range nodeIDs {
		privFile := "bls_keys/" + id + "_bls_priv.bin"
		if _, err := os.Stat(privFile); err == nil {
			log.Printf("BLS key for node %s already exists, skipping generation", id)
			continue
		}

		sk, pk := generateGnarkKeyPair()

		skBytes := sk.FillBytes(make([]byte, 32))
		os.WriteFile(privFile, skBytes, 0600)

		pkBytes := pk.Bytes()
		existingPubkeys[id] = pkBytes[:]
		newKeyCount++
		log.Printf("✅ generated new BLS key for node %s", id)
	}

	data, _ := json.MarshalIndent(existingPubkeys, "", "  ")
	os.WriteFile("bls_keys/bls_pubkeys.json", data, 0644)

	if newKeyCount > 0 {
		log.Printf("✅ done: added BLS keys for %d nodes", newKeyCount)
	} else {
		log.Println("✅ BLS keys already exist for all nodes")
	}
}

func LoadMyBLSKey(nodeID string) {
	initGnarkBLS()
	privBytes, err := os.ReadFile("bls_keys/" + nodeID + "_bls_priv.bin")
	if err != nil {
		log.Fatalf("cannot read private key: %v", err)
	}
	sk := new(big.Int).SetBytes(privBytes)

	var pk bls12381.G1Affine
	pk.ScalarMultiplication(&g1Gen, sk)

	blsKeys[nodeID] = &blsKey{privateKey: sk, publicKey: pk}
}

func LoadAllPublicKeys() {
	data, err := os.ReadFile("bls_keys/bls_pubkeys.json")
	if err != nil {
		log.Fatalf("cannot read public key file: %v", err)
	}
	var pubkeys map[string][]byte
	if err := json.Unmarshal(data, &pubkeys); err != nil {
		log.Fatalf("failed to parse public key file: %v", err)
	}
	for id, pubBytes := range pubkeys {
		var pk bls12381.G1Affine
		if _, err := pk.SetBytes(pubBytes); err != nil {
			log.Fatalf("failed to deserialize public key for %s: %v", id, err)
		}
		if _, ok := blsKeys[id]; !ok {
			blsKeys[id] = &blsKey{}
		}
		blsKeys[id].publicKey = pk
	}
}
