//! Building and parsing the `TransactionEnvelope` that wraps a signed
//! Soroban authorization entry for the x402 `exact` scheme on Stellar. This
//! lives in `sorocharge-x402`, not `sorocharge-signer`: building the actual
//! invoked operation and transaction envelope is protocol-adapter work,
//! outside `sorocharge-signer`'s scope of "build/sign/verify one auth
//! entry."

use sorocharge_signer::{Address, ChargeParams, SignedEntry, Signer};
use stellar_xdr::{
    AccountId, DecoratedSignature, HostFunction, Int128Parts, InvokeContractArgs,
    InvokeHostFunctionOp, Memo, MuxedAccount, Operation, OperationBody, Preconditions, PublicKey,
    ScAddress, ScSymbol, ScVal, SequenceNumber, Signature, SignatureHint,
    SorobanAuthorizationEntry, SorobanCredentials, Transaction, TransactionEnvelope,
    TransactionExt, TransactionV1Envelope, Uint256, VecM,
};

use crate::error::X402Error;

/// The all-zeros account, used as the placeholder transaction source when
/// building the client-side payment transaction. The facilitator replaces
/// the source account, sequence number, and fee entirely at settlement (per
/// spec, it "MUST NOT use the client's fee bid"), so this placeholder only
/// has to avoid colliding with a real address — which the all-zeros account
/// never can, since it corresponds to no valid keypair.
const PLACEHOLDER_SOURCE_ACCOUNT: [u8; 32] = [0u8; 32];

fn xdr_err(reason: impl Into<String>) -> X402Error {
    X402Error::XdrEncodingFailed {
        reason: reason.into(),
    }
}

fn transfer_symbol() -> Result<ScSymbol, X402Error> {
    "transfer"
        .try_into()
        .map(ScSymbol)
        .map_err(|_| xdr_err("\"transfer\" symbol"))
}

fn build_transfer_host_function(params: &ChargeParams) -> Result<HostFunction, X402Error> {
    let amount_parts = Int128Parts {
        hi: (params.amount >> 64) as i64,
        lo: (params.amount & (u64::MAX as i128)) as u64,
    };
    let args: VecM<ScVal> = vec![
        ScVal::Address(params.payer.clone()),
        ScVal::Address(params.recipient.clone()),
        ScVal::I128(amount_parts),
    ]
    .try_into()
    .map_err(|_| xdr_err("transfer args"))?;
    Ok(HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: params.asset_contract.clone(),
        function_name: transfer_symbol()?,
        args,
    }))
}

/// Builds the `TransactionEnvelope` a client sends to the resource server:
/// a single `invokeHostFunction` operation calling SEP-41 `transfer`,
/// carrying `signed_entry` as its sole authorization entry, on the
/// all-zeros placeholder source account with a zero fee and sequence
/// number — all three are meaningless here because the facilitator
/// replaces them wholesale at settlement.
pub(crate) fn build_payment_transaction_envelope(
    params: &ChargeParams,
    signed_entry: &SignedEntry,
) -> Result<TransactionEnvelope, X402Error> {
    let host_function = build_transfer_host_function(params)?;
    let auth: VecM<SorobanAuthorizationEntry> = vec![signed_entry.as_xdr().clone()]
        .try_into()
        .map_err(|_| xdr_err("auth entries"))?;
    let operation = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function,
            auth,
        }),
    };
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(PLACEHOLDER_SOURCE_ACCOUNT)),
        fee: 0,
        seq_num: SequenceNumber(0),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![operation]
            .try_into()
            .map_err(|_| xdr_err("operations"))?,
        ext: TransactionExt::V0,
    };
    Ok(TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    }))
}

/// The `(contract, from, to, amount)` a SEP-41 `transfer` invocation
/// authorizes.
///
/// `pub` only so the `fuzzing`-gated re-export in `lib.rs` can name it; the
/// enclosing `tx` module is private, so this is not part of the crate's
/// normal public surface.
pub struct TransferArgs {
    pub asset_contract: Address,
    pub from: Address,
    pub to: Address,
    pub amount: i128,
}

/// Parses `envelope` as exactly one `invokeHostFunction` operation
/// authorizing a bare SEP-41 `transfer(from, to, amount)` — no more, no
/// fewer operations, no sub-invocations beyond the transfer — with exactly
/// one authorization entry, using a credential type the `exact` scheme on
/// Stellar allows.
///
/// # Errors
///
/// Returns [`X402Error::UnexpectedTransactionShape`] for anything other
/// than that exact shape, and [`X402Error::ForbiddenCredentialType`] for
/// `sorobanCredentialsSourceAccount` or `sorobanCredentialsAddressWithDelegates`
/// — the spec explicitly forbids both for this scheme, even though
/// `sorocharge-signer` itself can build/verify one of them (`Delegated`)
/// for other protocols.
pub fn parse_payment_transaction(
    envelope: &TransactionEnvelope,
) -> Result<(TransferArgs, Transaction, SorobanAuthorizationEntry), X402Error> {
    let TransactionEnvelope::Tx(TransactionV1Envelope { tx, .. }) = envelope else {
        return Err(X402Error::UnexpectedTransactionShape {
            reason: "expected a v1 (ENVELOPE_TYPE_TX) transaction envelope".to_string(),
        });
    };
    let [operation] = tx.operations.as_slice() else {
        return Err(X402Error::UnexpectedTransactionShape {
            reason: "expected exactly one operation".to_string(),
        });
    };
    let OperationBody::InvokeHostFunction(invoke_op) = &operation.body else {
        return Err(X402Error::UnexpectedTransactionShape {
            reason: "expected an invokeHostFunction operation".to_string(),
        });
    };
    let HostFunction::InvokeContract(invoke_args) = &invoke_op.host_function else {
        return Err(X402Error::UnexpectedTransactionShape {
            reason: "expected hostFunctionTypeInvokeContract".to_string(),
        });
    };
    if invoke_args.function_name != transfer_symbol()? {
        return Err(X402Error::UnexpectedTransactionShape {
            reason: "expected function \"transfer\"".to_string(),
        });
    }
    let [ScVal::Address(from), ScVal::Address(to), ScVal::I128(amount_parts)] =
        invoke_args.args.as_slice()
    else {
        return Err(X402Error::UnexpectedTransactionShape {
            reason: "expected exactly 3 args: address, address, i128".to_string(),
        });
    };
    let amount = (i128::from(amount_parts.hi) << 64) | i128::from(amount_parts.lo);

    let [auth_entry] = invoke_op.auth.as_slice() else {
        return Err(X402Error::UnexpectedTransactionShape {
            reason: "expected exactly one authorization entry".to_string(),
        });
    };
    if !auth_entry.root_invocation.sub_invocations.is_empty() {
        return Err(X402Error::UnexpectedTransactionShape {
            reason: "authorization entry must not contain sub-invocations".to_string(),
        });
    }
    // The operation's own invocation and the authorization entry's
    // authorized invocation are independent fields in the XDR; nothing
    // stops a client from making them differ. On real execution a mismatch
    // here would just fail `require_auth` inside the token contract, but
    // checking it explicitly fails fast instead of wasting a submission.
    let expected_function = stellar_xdr::SorobanAuthorizedFunction::ContractFn(invoke_args.clone());
    if auth_entry.root_invocation.function != expected_function {
        return Err(X402Error::UnexpectedTransactionShape {
            reason: "authorization entry's invocation does not match the operation's call"
                .to_string(),
        });
    }
    match &auth_entry.credentials {
        SorobanCredentials::Address(_) | SorobanCredentials::AddressV2(_) => {}
        SorobanCredentials::SourceAccount | SorobanCredentials::AddressWithDelegates(_) => {
            return Err(X402Error::ForbiddenCredentialType);
        }
    }

    Ok((
        TransferArgs {
            asset_contract: invoke_args.contract_address.clone(),
            from: from.clone(),
            to: to.clone(),
            amount,
        },
        tx.clone(),
        auth_entry.clone(),
    ))
}

/// Rebuilds a parsed payment transaction with `source` as the source
/// account, `fee` as the fee, and `resources` refreshed from a
/// settlement-time simulation, preserving the operations and authorization
/// entries unchanged (per spec: "preserving all operations and auth
/// entries").
pub(crate) fn rebuild_for_settlement(
    tx: &Transaction,
    source: AccountId,
    fee: u32,
    seq_num: SequenceNumber,
    ext: TransactionExt,
) -> Transaction {
    let AccountId(public_key) = source;
    Transaction {
        source_account: MuxedAccount::Ed25519(match public_key {
            PublicKey::PublicKeyTypeEd25519(key) => key,
        }),
        fee,
        seq_num,
        cond: Preconditions::None,
        memo: Memo::None,
        operations: tx.operations.clone(),
        ext,
    }
}

/// Signs `tx` for submission with `signer`'s key over its
/// network-identified hash, producing a fully-signed V1
/// `TransactionEnvelope`. Reuses `sorocharge_signer::Signer` (an interface
/// generic over "sign this 32-byte digest") for a transaction-level
/// signature rather than a Soroban authorization-entry signature — a
/// different preimage, the same underlying ed25519 operation.
pub(crate) fn sign_transaction(
    tx: Transaction,
    signer: &dyn Signer,
    network_id: [u8; 32],
) -> Result<TransactionEnvelope, X402Error> {
    let ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(public_key)))) =
        signer.address()
    else {
        return Err(xdr_err("facilitator signer must be an Ed25519 account"));
    };
    let hash = tx
        .hash(network_id)
        .map_err(|e| xdr_err(format!("transaction hash: {e}")))?;
    let raw_signature = signer.sign_preimage(&hash)?;
    let hint = SignatureHint([
        public_key[28],
        public_key[29],
        public_key[30],
        public_key[31],
    ]);
    let decorated = DecoratedSignature {
        hint,
        signature: Signature(
            raw_signature
                .to_vec()
                .try_into()
                .map_err(|_| xdr_err("signature bytes"))?,
        ),
    };
    Ok(TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: vec![decorated]
            .try_into()
            .map_err(|_| xdr_err("signatures"))?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as DalekSigner, SigningKey};
    use sorocharge_signer::{build_charge_entry, sign_entry, CredentialKind};

    struct TestSigner {
        signing_key: SigningKey,
        address: Address,
    }

    impl Signer for TestSigner {
        fn sign_preimage(
            &self,
            preimage: &[u8],
        ) -> Result<[u8; 64], sorocharge_signer::SorochargeError> {
            Ok(self.signing_key.sign(preimage).to_bytes())
        }

        fn address(&self) -> Address {
            self.address.clone()
        }
    }

    fn test_params() -> ChargeParams {
        ChargeParams {
            asset_contract: "CAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGGJH"
                .parse()
                .unwrap(),
            amount: 42_000_000,
            payer: "GDIEVMRSOQV3JKZ2CNUL2RQV4TTNAISKW4NAC25PQUQKGMWJO6DTOAE7"
                .parse()
                .unwrap(),
            recipient: "GCQJVJPUPJTVTABP7FK7RXBNFIKKLSM5EO7JP6DECJ77SOBUKWSPB64N"
                .parse()
                .unwrap(),
            valid_until_ledger: 999_999,
        }
    }

    #[test]
    fn build_then_parse_round_trips_the_transfer_args() {
        let params = test_params();
        let signer = TestSigner {
            signing_key: SigningKey::from_bytes(&[0x11u8; 32]),
            address: params.payer.clone(),
        };
        let unsigned = build_charge_entry(&params, CredentialKind::Legacy).unwrap();
        let signed = sign_entry(unsigned, &signer, "Test SDF Network ; September 2015").unwrap();

        let envelope = build_payment_transaction_envelope(&params, &signed).unwrap();
        let (transfer, _tx, auth_entry) = parse_payment_transaction(&envelope).unwrap();

        assert_eq!(transfer.asset_contract, params.asset_contract);
        assert_eq!(transfer.from, params.payer);
        assert_eq!(transfer.to, params.recipient);
        assert_eq!(transfer.amount, params.amount);
        assert_eq!(auth_entry.credentials, signed.as_xdr().credentials);
    }

    #[test]
    fn parse_rejects_an_envelope_with_no_operations() {
        let params = test_params();
        let signer = TestSigner {
            signing_key: SigningKey::from_bytes(&[0x11u8; 32]),
            address: params.payer.clone(),
        };
        let unsigned = build_charge_entry(&params, CredentialKind::Legacy).unwrap();
        let signed = sign_entry(unsigned, &signer, "Test SDF Network ; September 2015").unwrap();
        let envelope = build_payment_transaction_envelope(&params, &signed).unwrap();

        let TransactionEnvelope::Tx(v1) = envelope else {
            unreachable!("build_payment_transaction_envelope always returns a v1 envelope")
        };
        // Zero operations authorizes no transfer at all, let alone a
        // single bare SEP-41 `transfer(from, to, amount)`.
        let mut tx = v1.tx;
        tx.operations = VecM::default();
        let tampered = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: v1.signatures,
        });

        let result = parse_payment_transaction(&tampered);
        assert!(matches!(
            result,
            Err(X402Error::UnexpectedTransactionShape { .. })
        ));
    }

    #[test]
    fn parse_rejects_delegated_credentials() {
        let params = test_params();
        let delegate: Address = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJ3XHA"
            .parse()
            .unwrap_or_else(|_| params.recipient.clone());
        let unsigned = build_charge_entry(
            &params,
            CredentialKind::Delegated {
                signers: vec![delegate],
            },
        )
        .unwrap();
        // Not actually signed — parse_payment_transaction rejects the
        // credential type before any signature is inspected.
        let signed = SignedEntry::from_xdr(unsigned.as_xdr().clone());

        let envelope = build_payment_transaction_envelope(&params, &signed).unwrap();
        let result = parse_payment_transaction(&envelope);

        assert!(matches!(result, Err(X402Error::ForbiddenCredentialType)));
    }

    #[test]
    fn parse_rejects_source_account_credentials() {
        let params = test_params();
        // Build a valid entry with Legacy credentials, then replace with SourceAccount
        // since CredentialKind doesn't include SourceAccount (it has no signature to build/verify)
        let unsigned = build_charge_entry(&params, CredentialKind::Legacy).unwrap();
        let mut auth_entry = unsigned.as_xdr().clone();
        auth_entry.credentials = SorobanCredentials::SourceAccount;
        let signed = SignedEntry::from_xdr(auth_entry);

        let envelope = build_payment_transaction_envelope(&params, &signed).unwrap();
        let result = parse_payment_transaction(&envelope);

        assert!(matches!(result, Err(X402Error::ForbiddenCredentialType)));
    }

    #[test]
    fn parse_rejects_sub_invocations() {
        let params = test_params();
        let signer = TestSigner {
            signing_key: SigningKey::from_bytes(&[0x11u8; 32]),
            address: params.payer.clone(),
        };
        let unsigned = build_charge_entry(&params, CredentialKind::Legacy).unwrap();
        let signed = sign_entry(unsigned, &signer, "Test SDF Network ; September 2015").unwrap();
        let envelope = build_payment_transaction_envelope(&params, &signed).unwrap();

        let TransactionEnvelope::Tx(v1) = envelope else {
            unreachable!()
        };
        let mut operations: Vec<_> = v1.tx.operations.iter().cloned().collect();
        let OperationBody::InvokeHostFunction(op) = &mut operations[0].body else {
            unreachable!()
        };
        let mut auth: Vec<_> = op.auth.iter().cloned().collect();
        let root = auth[0].root_invocation.clone();
        auth[0].root_invocation.sub_invocations = vec![root].try_into().unwrap();
        op.auth = auth.try_into().unwrap();
        let mut tx = v1.tx;
        tx.operations = operations.try_into().unwrap();
        let tampered = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: v1.signatures,
        });

        let result = parse_payment_transaction(&tampered);
        assert!(matches!(
            result,
            Err(X402Error::UnexpectedTransactionShape { .. })
        ));
    }

    /// A `Signer` whose key fails must surface as exactly `Signing`, so a
    /// caller can tell a key failure apart from every other `X402Error`.
    #[test]
    fn sign_transaction_propagates_signer_failures_as_signing() {
        struct FailingSigner {
            address: Address,
        }

        impl Signer for FailingSigner {
            fn sign_preimage(
                &self,
                _preimage: &[u8],
            ) -> Result<[u8; 64], sorocharge_signer::SorochargeError> {
                Err(sorocharge_signer::SorochargeError::SigningFailed {
                    reason: "boom".to_string(),
                })
            }

            fn address(&self) -> Address {
                self.address.clone()
            }
        }

        let params = test_params();
        let good = TestSigner {
            signing_key: SigningKey::from_bytes(&[0x11u8; 32]),
            address: params.payer.clone(),
        };
        let unsigned = build_charge_entry(&params, CredentialKind::Legacy).unwrap();
        let signed = sign_entry(unsigned, &good, "Test SDF Network ; September 2015").unwrap();
        let envelope = build_payment_transaction_envelope(&params, &signed).unwrap();
        let TransactionEnvelope::Tx(v1) = envelope else {
            unreachable!("build_payment_transaction_envelope always returns a v1 envelope")
        };

        let failing = FailingSigner {
            address: params.payer.clone(),
        };
        match sign_transaction(v1.tx, &failing, [0u8; 32]) {
            Err(X402Error::Signing(_)) => {}
            other => panic!("expected Signing, got {other:?}"),
        }
    }

    /// A signer whose address is not an Ed25519 account cannot become a
    /// transaction source, so `sign_transaction` must fail as exactly
    /// `XdrEncodingFailed` — a value that does not fit its XDR-constrained
    /// shape, not a signing or shape error.
    #[test]
    fn sign_transaction_rejects_a_non_account_signer_as_xdr_encoding_failed() {
        use stellar_xdr::ContractId;

        struct ContractSigner {
            address: Address,
        }

        impl Signer for ContractSigner {
            fn sign_preimage(
                &self,
                _preimage: &[u8],
            ) -> Result<[u8; 64], sorocharge_signer::SorochargeError> {
                Ok([0u8; 64])
            }

            fn address(&self) -> Address {
                self.address.clone()
            }
        }

        let params = test_params();
        let good = TestSigner {
            signing_key: SigningKey::from_bytes(&[0x11u8; 32]),
            address: params.payer.clone(),
        };
        let unsigned = build_charge_entry(&params, CredentialKind::Legacy).unwrap();
        let signed = sign_entry(unsigned, &good, "Test SDF Network ; September 2015").unwrap();
        let envelope = build_payment_transaction_envelope(&params, &signed).unwrap();
        let TransactionEnvelope::Tx(v1) = envelope else {
            unreachable!("build_payment_transaction_envelope always returns a v1 envelope")
        };

        let contract_signer = ContractSigner {
            address: ScAddress::Contract(ContractId(stellar_xdr::Hash([0xabu8; 32]))),
        };
        match sign_transaction(v1.tx, &contract_signer, [0u8; 32]) {
            Err(X402Error::XdrEncodingFailed { reason }) => {
                assert!(
                    reason.contains("Ed25519 account"),
                    "expected the facilitator-signer reason, got {reason:?}"
                );
            }
            other => panic!("expected XdrEncodingFailed, got {other:?}"),
        }
    }
}
