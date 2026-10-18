package sync_provider

import (
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/symbioticfi/relay/internal/client/repository/cached"
	"github.com/symbioticfi/relay/internal/entity"
	entity_processor "github.com/symbioticfi/relay/internal/usecase/entity-processor"
	symbiotic "github.com/symbioticfi/relay/symbiotic/entity"
	"github.com/symbioticfi/relay/symbiotic/usecase/crypto"
)

const ecdsaKeyTag = symbiotic.KeyTag(0x10)

// validatorSetAt builds a validator set for the epoch with one validator per entry of
// active, which tells whether that validator is active.
func validatorSetAt(t *testing.T, epoch symbiotic.Epoch, active ...bool) (symbiotic.ValidatorSet, []crypto.PrivateKey) {
	t.Helper()
	validatorSet, privateKeys := createTestValidatorSetWithMultipleValidators(t, len(active))
	validatorSet.Epoch = epoch
	for i, isActive := range active {
		validatorSet.Validators[i].IsActive = isActive
	}
	return validatorSet, privateKeys
}

func saveValidatorSets(t *testing.T, repo cached.Repository, prev, next symbiotic.ValidatorSet) {
	t.Helper()
	require.NoError(t, repo.SaveNextValsetData(t.Context(), entity.NextValsetData{
		NextValidatorSet:     next,
		NextNetworkConfig:    randomNetworkConfig(),
		PrevValidatorSet:     prev,
		PrevNetworkConfig:    randomNetworkConfig(),
		SignatureRequest:     nil,
		ValidatorSetMetadata: symbiotic.ValidatorSetMetadata{},
	}))
}

// saveRequest stores a signature request without any signature and returns its id.
func saveRequest(t *testing.T, repo cached.Repository, keyTag symbiotic.KeyTag, epoch symbiotic.Epoch) (common.Hash, symbiotic.SignatureRequest) {
	t.Helper()
	req := symbiotic.SignatureRequest{
		KeyTag:        keyTag,
		RequiredEpoch: epoch,
		Message:       randomBytes(t, 100),
	}
	msgHash, err := crypto.HashMessage(keyTag.Type(), req.Message)
	require.NoError(t, err)
	requestID := symbiotic.Signature{MessageHash: msgHash, KeyTag: keyTag, Epoch: epoch}.RequestID()
	require.NoError(t, repo.SaveSignatureRequest(t.Context(), requestID, req))
	return requestID, req
}

func newWantSyncer(t *testing.T, repo cached.Repository, epochsToSync uint64, maxRequests int) (*Syncer, *entity_processor.EntityProcessor) {
	t.Helper()
	entityProcessor, err := entity_processor.NewEntityProcessor(entity_processor.Config{
		Repo:                     repo,
		Aggregator:               createMockAggregator(t),
		AggProofSignal:           createMockAggProofSignal(t),
		SignatureProcessedSignal: createMockSignatureProcessedSignal(t),
		Metrics:                  doNothingMetrics{},
	})
	require.NoError(t, err)
	syncer, err := New(Config{
		Repo:                        repo,
		EntityProcessor:             entityProcessor,
		EpochsToSync:                epochsToSync,
		MaxSignatureRequestsPerSync: maxRequests,
		MaxResponseSignatureCount:   100,
		MaxAggProofRequestsPerSync:  100,
		MaxResponseAggProofCount:    100,
	})
	require.NoError(t, err)
	return syncer, entityProcessor
}

func processSignature(t *testing.T, entityProcessor *entity_processor.EntityProcessor, privateKey crypto.PrivateKey, req symbiotic.SignatureRequest) {
	t.Helper()
	require.NoError(t, entityProcessor.ProcessSignature(t.Context(), signRequest(t, privateKey, req), false))
}

func wantedIndices(t *testing.T, syncer *Syncer) map[common.Hash][]uint32 {
	t.Helper()
	request, err := syncer.BuildWantSignaturesRequest(t.Context())
	require.NoError(t, err)
	wanted := make(map[common.Hash][]uint32, len(request.WantSignatures))
	for requestID, bitmap := range request.WantSignatures {
		wanted[requestID] = bitmap.ToArray()
	}
	return wanted
}

func TestBuildWantSignaturesRequest_RequestWithoutSignatures(t *testing.T) {
	t.Parallel()

	for name, newRepo := range backends() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			repo := newRepo(t)
			validatorSet, _ := validatorSetAt(t, 1, true, true, true)
			saveValidatorSets(t, repo, validatorSet, validatorSet)
			requestID, _ := saveRequest(t, repo, symbiotic.KeyTag(15), 1)

			syncer, _ := newWantSyncer(t, repo, 1, 100)

			require.Equal(t, map[common.Hash][]uint32{requestID: {0, 1, 2}}, wantedIndices(t, syncer))
		})
	}
}

// Without a signature map the indices have to come from the validator set of the
// request's epoch, which here differs from the latest one. They must be the active
// validator indices that the signature map of the request uses once a signature arrives.
func TestBuildWantSignaturesRequest_UsesValidatorSetOfRequestEpoch(t *testing.T) {
	t.Parallel()

	for name, newRepo := range backends() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			repo := newRepo(t)
			// Epoch 1: 4 validators, the second one inactive, so 3 active indices.
			epoch1Set, epoch1Keys := validatorSetAt(t, 1, true, false, true, true)
			// Epoch 2 (latest): 5 active validators.
			epoch2Set, _ := validatorSetAt(t, 2, true, true, true, true, true)
			saveValidatorSets(t, repo, epoch1Set, epoch2Set)

			latestEpoch, err := repo.GetLatestValidatorSetEpoch(t.Context())
			require.NoError(t, err)
			require.Equal(t, symbiotic.Epoch(2), latestEpoch)

			epoch1RequestID, epoch1Request := saveRequest(t, repo, symbiotic.KeyTag(15), 1)
			epoch2RequestID, _ := saveRequest(t, repo, symbiotic.KeyTag(15), 2)

			syncer, entityProcessor := newWantSyncer(t, repo, 1, 100)

			require.Equal(t, map[common.Hash][]uint32{
				epoch1RequestID: {0, 1, 2},
				epoch2RequestID: {0, 1, 2, 3, 4},
			}, wantedIndices(t, syncer))

			// The last validator of epoch 1 has active index 2. Once its signature is
			// saved, the request is asked for through its signature map, in the same
			// index space.
			_, activeIndex, err := repo.GetValidatorByKey(t.Context(), 1, symbiotic.KeyTag(15), epoch1Keys[3].PublicKey().OnChain())
			require.NoError(t, err)
			require.Equal(t, uint32(2), activeIndex)
			processSignature(t, entityProcessor, epoch1Keys[3], epoch1Request)

			require.Equal(t, map[common.Hash][]uint32{
				epoch1RequestID: {0, 1},
				epoch2RequestID: {0, 1, 2, 3, 4},
			}, wantedIndices(t, syncer))
		})
	}
}

func TestBuildWantSignaturesRequest_SkipsAggregatedAndSignedRequests(t *testing.T) {
	t.Parallel()

	for name, newRepo := range backends() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			repo := newRepo(t)
			validatorSet, privateKeys := validatorSetAt(t, 1, true, true, true)
			saveValidatorSets(t, repo, validatorSet, validatorSet)
			syncer, entityProcessor := newWantSyncer(t, repo, 1, 100)

			// Aggregation key request whose proof already exists: nothing to ask for.
			aggregatedID, aggregated := saveRequest(t, repo, symbiotic.KeyTag(15), 1)
			msgHash, err := crypto.HashMessage(aggregated.KeyTag.Type(), aggregated.Message)
			require.NoError(t, err)
			require.NoError(t, repo.SaveProof(t.Context(), symbiotic.AggregationProof{
				MessageHash: msgHash,
				KeyTag:      aggregated.KeyTag,
				Epoch:       aggregated.RequiredEpoch,
				Proof:       randomBytes(t, 32),
			}))
			require.Equal(t, aggregatedID, symbiotic.AggregationProof{MessageHash: msgHash, KeyTag: aggregated.KeyTag, Epoch: aggregated.RequiredEpoch}.RequestID())

			// Request with one local signature: asked for the missing ones only.
			partialID, partial := saveRequest(t, repo, symbiotic.KeyTag(15), 1)
			processSignature(t, entityProcessor, privateKeys[1], partial)

			// Request with all signatures: nothing to ask for.
			_, complete := saveRequest(t, repo, symbiotic.KeyTag(15), 1)
			for _, privateKey := range privateKeys {
				processSignature(t, entityProcessor, privateKey, complete)
			}

			// Non aggregation key request without signatures: asked for all validators.
			ecdsaID, _ := saveRequest(t, repo, ecdsaKeyTag, 1)

			require.Equal(t, map[common.Hash][]uint32{
				partialID: {0, 2},
				ecdsaID:   {0, 1, 2},
			}, wantedIndices(t, syncer))
		})
	}
}

func TestBuildWantSignaturesRequest_RequestsWithoutSignaturesRespectLimits(t *testing.T) {
	t.Parallel()

	for name, newRepo := range backends() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			repo := newRepo(t)
			epoch1Set, _ := validatorSetAt(t, 1, true, true)
			epoch2Set, _ := validatorSetAt(t, 2, true, true)
			saveValidatorSets(t, repo, epoch1Set, epoch2Set)

			epoch1RequestID, _ := saveRequest(t, repo, symbiotic.KeyTag(15), 1)
			epoch2Requests := make(map[common.Hash]struct{})
			for range 3 {
				requestID, _ := saveRequest(t, repo, symbiotic.KeyTag(15), 2)
				epoch2Requests[requestID] = struct{}{}
			}

			// EpochsToSync 0 only scans the latest epoch.
			syncer, _ := newWantSyncer(t, repo, 0, 100)
			wanted := wantedIndices(t, syncer)
			require.Len(t, wanted, 3)
			for requestID := range wanted {
				require.Contains(t, epoch2Requests, requestID)
			}

			// EpochsToSync 1 also reaches epoch 1.
			syncer, _ = newWantSyncer(t, repo, 1, 100)
			wanted = wantedIndices(t, syncer)
			require.Len(t, wanted, 4)
			require.Equal(t, []uint32{0, 1}, wanted[epoch1RequestID])

			// MaxSignatureRequestsPerSync caps the requests, newest epoch first.
			syncer, _ = newWantSyncer(t, repo, 1, 2)
			wanted = wantedIndices(t, syncer)
			require.Len(t, wanted, 2)
			for requestID := range wanted {
				require.Contains(t, epoch2Requests, requestID)
			}
		})
	}
}

// Requests from the pending index scan count towards MaxSignatureRequestsPerSync.
func TestBuildWantSignaturesRequest_PendingRequestsShareLimit(t *testing.T) {
	t.Parallel()

	for name, newRepo := range backends() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			repo := newRepo(t)
			validatorSet, privateKeys := validatorSetAt(t, 1, true, true)
			saveValidatorSets(t, repo, validatorSet, validatorSet)
			syncer, entityProcessor := newWantSyncer(t, repo, 1, 1)

			partialID, partial := saveRequest(t, repo, symbiotic.KeyTag(15), 1)
			processSignature(t, entityProcessor, privateKeys[0], partial)
			saveRequest(t, repo, symbiotic.KeyTag(15), 1)

			require.Equal(t, map[common.Hash][]uint32{partialID: {1}}, wantedIndices(t, syncer))
		})
	}
}

type requestsWithoutSignaturesRepo struct {
	repo

	requestIDs  []common.Hash
	requests    map[common.Hash]symbiotic.SignatureRequest
	activeCount map[symbiotic.Epoch]uint32
	countErr    error
}

func (r *requestsWithoutSignaturesRepo) GetLatestValidatorSetEpoch(context.Context) (symbiotic.Epoch, error) {
	return 1, nil
}

func (r *requestsWithoutSignaturesRepo) GetSignatureRequestsWithoutAggregationProof(context.Context, symbiotic.Epoch, int, common.Hash) ([]symbiotic.SignatureRequestWithID, error) {
	return nil, nil
}

func (r *requestsWithoutSignaturesRepo) GetSignatureRequestIDsByEpoch(_ context.Context, epoch symbiotic.Epoch, _ int, _ []byte) ([]common.Hash, []byte, error) {
	if epoch != 1 {
		return nil, nil, nil
	}
	return r.requestIDs, nil, nil
}

func (r *requestsWithoutSignaturesRepo) GetSignatureMap(context.Context, common.Hash) (entity.SignatureMap, error) {
	return entity.SignatureMap{}, entity.ErrEntityNotFound
}

func (r *requestsWithoutSignaturesRepo) GetSignatureRequest(_ context.Context, requestID common.Hash) (symbiotic.SignatureRequest, error) {
	req, ok := r.requests[requestID]
	if !ok {
		return symbiotic.SignatureRequest{}, entity.ErrEntityNotFound
	}
	return req, nil
}

func (r *requestsWithoutSignaturesRepo) GetAggregationProof(context.Context, common.Hash) (symbiotic.AggregationProof, error) {
	return symbiotic.AggregationProof{}, entity.ErrEntityNotFound
}

func (r *requestsWithoutSignaturesRepo) GetActiveValidatorCountByEpoch(_ context.Context, epoch symbiotic.Epoch) (uint32, error) {
	if r.countErr != nil {
		return 0, r.countErr
	}
	count, ok := r.activeCount[epoch]
	if !ok {
		return 0, entity.ErrEntityNotFound
	}
	return count, nil
}

// A request that is gone or whose validator set is not stored anymore is skipped,
// while other repository errors fail the sync round as before.
func TestBuildWantSignaturesRequest_RequestsWithoutSignaturesLookupErrors(t *testing.T) {
	t.Parallel()

	removed, withoutValidatorSet, wanted := common.Hash{1}, common.Hash{2}, common.Hash{3}
	r := &requestsWithoutSignaturesRepo{
		requestIDs: []common.Hash{removed, withoutValidatorSet, wanted},
		requests: map[common.Hash]symbiotic.SignatureRequest{
			withoutValidatorSet: {KeyTag: symbiotic.KeyTag(15), RequiredEpoch: 0, Message: nil},
			wanted:              {KeyTag: symbiotic.KeyTag(15), RequiredEpoch: 1, Message: nil},
		},
		activeCount: map[symbiotic.Epoch]uint32{1: 2},
	}
	s := &Syncer{cfg: Config{Repo: r, EpochsToSync: 1, MaxSignatureRequestsPerSync: 10}}

	require.Equal(t, map[common.Hash][]uint32{wanted: {0, 1}}, wantedIndices(t, s))

	r.countErr = errors.New("database unavailable")
	_, err := s.BuildWantSignaturesRequest(t.Context())
	require.ErrorIs(t, err, r.countErr)
}
