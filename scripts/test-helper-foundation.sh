#!/usr/bin/env bash
# Linux admission and opt-in execution foundations. No helper installation.
set -euo pipefail
repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$repo_root"
if [ "$(uname -s)" != Linux ]; then
  echo 'Helper foundation requires Linux filesystem and flock semantics.' >&2
  exit 1
fi
test_log="$(mktemp /tmp/agp-helper-tests.XXXXXXXX.log)"
trap 'rm -f -- "$test_log"' EXIT
"${GO:-go}" test -race -count=1 -timeout=3m -v ./internal/helper | tee "$test_log"
if rg -q -- '--- (SKIP|FAIL):' "$test_log"; then
  echo 'Helper foundation requires every mandatory test without SKIP/FAIL.' >&2
  exit 1
fi
for required in \
  TestAdmissionDurableReplayAndRecoveryBlocker \
  TestAdmissionRejectsChangedTaskAndIdempotencyReuse \
  TestAdmissionCurrentChecksAndPins \
  TestAdmissionEpochAndRollbackSequence \
  TestAdmissionBaselineAndSequenceBoundaries \
  TestAdmissionConcurrentDistinctTasksAndHandles \
  TestAdmissionClosedContract \
  TestAdmissionTrustPurposeAndTampering \
  TestAdmissionSignedPlanTargetBinding \
  TestAdmissionPlanPurposeAndSignatureCannotBeReused \
  TestAdmissionMissingPlanRejectsNewButPreservesHistoricalReplay \
  TestAdmissionOwnedTreeBinding \
  TestAdmissionOwnedTreeDriftDoesNotConsumeSequence \
  TestAdmissionOwnedTreeRechecksAfterAuthorization \
  TestAdmissionOwnedTreeHistoricalReplayWithoutFilesystem \
  TestAdmissionDurabilityFailures \
  TestAdmissionProcessCrash \
  TestStoreCreateOpenExclusiveAndNoReset \
  TestStoreIncompleteInitializationIsNotReset \
  TestStoreCallbackAndCancellationDoNotMutate \
  TestStoreConcurrentReadTransactionsAreSerialized \
  TestStoreCloseRacesSafelyWithTransactions \
  TestStoreRejectsInsecureAncestryAndInstallation \
  TestStoreDetectsReplacementOrTamperingBeforeCallback \
  TestStoreOpenRejectsUnsafeFilesWithoutFollowing \
  TestStorePreservesOrphanTemporary \
  TestStoreOpenRejectsMalformedOrUnboundSnapshot \
  TestStoreDurabilityFailurePoisonsUntilReopen \
  TestStoreActualProcessCrashReopensWholeSnapshot \
  TestExecutionSuccessDurableReplayOutboxAndCurrentLedgerBase \
  TestExecutionFailedSequenceRetainedAndExplicitRollbackIsNewTask \
  TestExecutionEffectBoundaryRevokeExpiryAndTreeDrift \
  TestExecutionCancellationRecoversWithIndependentBoundedContext \
  TestExecutionHealthyTargetSurvivesLostReloadResponseAndPartition \
  TestExecutionCrashRecoveryFromDurableCheckpoint \
  TestExecutionUnknownThirdStateBlocksNewWorkUntilExactBaseRecovery \
  TestExecutionLedgerRejectsResetForeignStateAndMutation \
  TestExecutionInitializationRequiresServingGenerationAndFullVerification \
  TestExecutionReceiptRequiresPinnedHelperIdentityAndExactSignedOutcome \
  TestExecutionDurabilityFaultBeforeActivationNeverRunsEffects \
  TestExecutionLedgerDescriptorCollisionsRejected \
  TestExecutionWaitingObserverHonorsCancellation \
  TestExecutionUnresolvedRecoveryContainsServiceAndRecordsSanitizedFailure \
  TestExecutionPoisonedLedgerStillContainsUnresolvedActivatedRuntime \
  TestExecutionAfterActivatingFsyncRequiresFreshLiveFence \
  TestExecutionActivationCannotOutliveFreshProof
do
  if ! rg -q -- "^--- PASS: ${required} \\(" "$test_log"; then
    echo "Missing mandatory helper test: ${required}" >&2
    exit 1
  fi
done
"${GO:-go}" vet ./internal/helper
echo 'Admission/store and opt-in execution foundation passed with controlled adapters; native root apply is not qualified.'
