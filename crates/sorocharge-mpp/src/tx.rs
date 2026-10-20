//! Building and parsing the `TransactionEnvelope` for MPP's `"stellar"`
//! `"charge"` method — sponsored (pull, all-zeros placeholder source) and
//! unsponsored (pull, fully-signed real transaction) variants, plus
//! server-side parsing and settlement rebuilding.

use sorocharge_signer::{Address, ChargeParams, SignedEntry, Signer};
use stellar_xdr::{
    AccountId, DecoratedSignature, HostFunction, Int128Parts, InvokeContractArgs,
    InvokeHostFunctionOp, Memo, MuxedAccount, Operation, OperationBody, Preconditions, PublicKey,
    ScAddress, ScSymbol, ScVal, SequenceNumber, Signature, SignatureHint,
    SorobanAuthorizationEntry, SorobanCredentials, SorobanTransactionData, TimeBounds, TimePoint,
    Transaction, TransactionEnvelope, TransactionExt, TransactionV1Envelope, Uint256, VecM,
};

use crate::error::MppError;

/// The all-zeros account: the required placeholder transaction source for
/// sponsored (`feePayer: true`) pull-mode payments, which the server
/// replaces entirely at settlement.
pub(crate) const PLACEHOLDER_SOURCE_ACCOUNT: [u8; 32] = [0u8; 32];

fn xdr_err(reason: impl Into<String>) -> MppError {
    MppError::XdrEncodingFailed {
        reason: reason.into(),
    }
}

fn transfer_symbol() -> Result<ScSymbol, MppError> {
    "transfer"
        .try_into()
        .map(ScSymbol)
        .map_err(|_| xdr_err("\"transfer\" symbol"))
}

fn build_transfer_host_function(params: &ChargeParams) -> Result<HostFunction, MppError> {
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

fn build_invoke_operation(
    params: &ChargeParams,
    signed_entry: &SignedEntry,
) -> Result<Operation, MppError> {
    let host_function = build_transfer_host_function(params)?;
    let auth: VecM<SorobanAuthorizationEntry> = vec![signed_entry.as_xdr().clone()]
        .try_into()
        .map_err(|_| xdr_err("auth entries"))?;
    Ok(Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function,
            auth,
        }),
    })
}

/// Builds the sponsored-flow (`feePayer: true`) transaction: the all-zeros
/// placeholder source, zero fee and sequence number, and no outer
/// signature — only the authorization entry is signed. The server replaces
/// source/sequence/fee wholesale at settlement.
pub(crate) fn build_sponsored_envelope(
    params: &ChargeParams,
    signed_entry: &SignedEntry,
) -> Result<TransactionEnvelope, MppError> {
    let operation = build_invoke_operation(params, signed_entry)?;
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

/// Builds the unsponsored-flow (`feePayer: false`) transaction: a real
/// source account, sequence number, fee, and `timeBounds.maxTime`. The
/// caller supplies the payer's next sequence number and the fee/resource
/// data a settlement-time-equivalent simulation already derived — this
/// function only assembles and (via [`sign_transaction`]) signs the
/// result; it does not itself call RPC.
pub(crate) fn build_unsponsored_transaction(
    params: &ChargeParams,
    signed_entry: &SignedEntry,
    source: AccountId,
    seq_num: SequenceNumber,
    fee: u32,
    soroban_data: SorobanTransactionData,
    max_time_unix: u64,
) -> Result<Transaction, MppError> {
    let operation = build_invoke_operation(params, signed_entry)?;
    let AccountId(PublicKey::PublicKeyTypeEd25519(source_key)) = source;
    Ok(Transaction {
        source_account: MuxedAccount::Ed25519(source_key),
        fee,
        seq_num,
        cond: Preconditions::Time(TimeBounds {
            min_time: TimePoint(0),
            max_time: TimePoint(max_time_unix),
        }),
        memo: Memo::None,
        operations: vec![operation]
            .try_into()
            .map_err(|_| xdr_err("operations"))?,
        ext: TransactionExt::V1(soroban_data),
    })
}

/// The `(contract, from, to, amount)` a SEP-41 `transfer` invocation
/// authorizes.
///
/// `pub` only so the `fuzzing`-gated re-export in `lib.rs` can name it; the
/// enclosing `tx` module is private, so this is not part of the crate's
/// normal public surface.
#[derive(Debug)]
pub struct TransferArgs {
    pub asset_contract: Address,
    pub from: Address,
    pub to: Address,
    pub amount: i128,
}

/// Parses `envelope` as exactly one `invokeHostFunction` operation
/// authorizing a bare SEP-41 `transfer(from, to, amount)`, with exactly one
/// authorization entry using the legacy `sorobanCredentialsAddress`
/// credential type — the *only* type `draft-stellar-charge-00` permits for
/// pull mode. Unlike x402's `exact` scheme (which allows `AddressV2` too),
/// this spec never mentions CAP-71 at all; it was drafted before Protocol
/// 28 and pins to the legacy credential exclusively.
pub fn parse_payment_transaction(
    envelope: &TransactionEnvelope,
) -> Result<(TransferArgs, Transaction, SorobanAuthorizationEntry), MppError> {
    let TransactionEnvelope::Tx(TransactionV1Envelope { tx, .. }) = envelope else {
        return Err(MppError::UnexpectedTransactionShape {
            reason: "expected a v1 (ENVELOPE_TYPE_TX) transaction envelope".to_string(),
        });
    };
    let [operation] = tx.operations.as_slice() else {
        return Err(MppError::UnexpectedTransactionShape {
            reason: "expected exactly one operation".to_string(),
        });
    };
    let OperationBody::InvokeHostFunction(invoke_op) = &operation.body else {
        return Err(MppError::UnexpectedTransactionShape {
            reason: "expected an invokeHostFunction operation".to_string(),
        });
    };
    let HostFunction::InvokeContract(invoke_args) = &invoke_op.host_function else {
        return Err(MppError::UnexpectedTransactionShape {
            reason: "expected hostFunctionTypeInvokeContract".to_string(),
        });
    };
    if invoke_args.function_name != transfer_symbol()? {
        return Err(MppError::UnexpectedTransactionShape {
            reason: "expected function \"transfer\"".to_string(),
        });
    }
    let [ScVal::Address(from), ScVal::Address(to), ScVal::I128(amount_parts)] =
        invoke_args.args.as_slice()
    else {
        return Err(MppError::UnexpectedTransactionShape {
            reason: "expected exactly 3 args: address, address, i128".to_string(),
        });
    };
    let amount = (i128::from(amount_parts.hi) << 64) | i128::from(amount_parts.lo);

    let [auth_entry] = invoke_op.auth.as_slice() else {
        return Err(MppError::UnexpectedTransactionShape {
            reason: "expected exactly one authorization entry".to_string(),
        });
    };
    if !auth_entry.root_invocation.sub_invocations.is_empty() {
        return Err(MppError::UnexpectedTransactionShape {
            reason: "authorization entry must not contain sub-invocations".to_string(),
        });
    }
    let expected_function = stellar_xdr::SorobanAuthorizedFunction::ContractFn(invoke_args.clone());
    if auth_entry.root_invocation.function != expected_function {
        return Err(MppError::UnexpectedTransactionShape {
            reason: "authorization entry's invocation does not match the operation's call"
                .to_string(),
        });
    }
    if !matches!(auth_entry.credentials, SorobanCredentials::Address(_)) {
        return Err(MppError::ForbiddenCredentialType);
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

/// Rebuilds a parsed sponsored-flow transaction with the server as source
/// account, preserving operations and authorization entries unchanged.
pub(crate) fn rebuild_for_settlement(
    tx: &Transaction,
    source: AccountId,
    fee: u32,
    seq_num: SequenceNumber,
    soroban_data: SorobanTransactionData,
) -> Transaction {
    let AccountId(PublicKey::PublicKeyTypeEd25519(source_key)) = source;
    Transaction {
        source_account: MuxedAccount::Ed25519(source_key),
        fee,
        seq_num,
        cond: Preconditions::None,
        memo: Memo::None,
        operations: tx.operations.clone(),
        ext: TransactionExt::V1(soroban_data),
    }
}

/// Signs `tx` for submission over its network-identified hash, producing a
/// fully-signed V1 `TransactionEnvelope`.
pub(crate) fn sign_transaction(
    tx: Transaction,
    signer: &dyn Signer,
    network_id: [u8; 32],
) -> Result<TransactionEnvelope, MppError> {
    let ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(public_key)))) =
        signer.address()
    else {
        return Err(xdr_err("signer must be an Ed25519 account"));
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
    use sorocharge_signer::{build_charge_entry, sign_entry, CredentialKind, SorochargeError};

    struct TestSigner {
        signing_key: SigningKey,
        address: Address,
    }

    impl Signer for TestSigner {
        fn sign_preimage(&self, preimage: &[u8]) -> Result<[u8; 64], SorochargeError> {
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

        let envelope = build_sponsored_envelope(&params, &signed).unwrap();
        let (transfer, _tx, auth_entry) = parse_payment_transaction(&envelope).unwrap();

        assert_eq!(transfer.asset_contract, params.asset_contract);
        assert_eq!(transfer.from, params.payer);
        assert_eq!(transfer.to, params.recipient);
        assert_eq!(transfer.amount, params.amount);
        assert!(matches!(
            auth_entry.credentials,
            SorobanCredentials::Address(_)
        ));
    }

    #[test]
    fn parse_rejects_address_v2_credentials() {
        let params = test_params();
        let signer = TestSigner {
            signing_key: SigningKey::from_bytes(&[0x11u8; 32]),
            address: params.payer.clone(),
        };
        // AddressV2 is valid for sorocharge-signer and for x402, but
        // draft-stellar-charge-00 permits only the legacy
        // sorobanCredentialsAddress arm.
        let unsigned = build_charge_entry(&params, CredentialKind::AddressV2).unwrap();
        let signed = sign_entry(unsigned, &signer, "Test SDF Network ; September 2015").unwrap();

        let envelope = build_sponsored_envelope(&params, &signed).unwrap();
        let result = parse_payment_transaction(&envelope);

        assert!(matches!(result, Err(MppError::ForbiddenCredentialType)));
    }

    #[test]
    fn parse_rejects_wrong_number_of_operations() {
        let params = test_params();
        let signer = TestSigner {
            signing_key: SigningKey::from_bytes(&[0x11u8; 32]),
            address: params.payer.clone(),
        };
        let unsigned = build_charge_entry(&params, CredentialKind::Legacy).unwrap();
        let signed = sign_entry(unsigned, &signer, "Test SDF Network ; September 2015").unwrap();

        // Build an envelope with zero operations
        let envelope = build_sponsored_envelope(&params, &signed).unwrap();
        let TransactionEnvelope::Tx(mut v1) = envelope else {
            panic!()
        };
        v1.tx.operations = vec![].try_into().unwrap();
        let envelope = TransactionEnvelope::Tx(v1);
        let result = parse_payment_transaction(&envelope);
        assert!(
            matches!(result, Err(MppError::UnexpectedTransactionShape { ref reason }) if reason.contains("exactly one operation")),
            "expected UnexpectedTransactionShape for zero operations, got {result:?}"
        );

        // Build an envelope with two operations
        let envelope = build_sponsored_envelope(&params, &signed).unwrap();
        let TransactionEnvelope::Tx(mut v1) = envelope else {
            panic!()
        };
        let op = v1.tx.operations[0].clone();
        v1.tx.operations = vec![op.clone(), op].try_into().unwrap();
        let envelope = TransactionEnvelope::Tx(v1);
        let result = parse_payment_transaction(&envelope);
        assert!(
            matches!(result, Err(MppError::UnexpectedTransactionShape { ref reason }) if reason.contains("exactly one operation")),
            "expected UnexpectedTransactionShape for two operations, got {result:?}"
        );
    }

    #[test]
    fn parse_rejects_non_invoke_host_function_operation() {
        let params = test_params();
        let signer = TestSigner {
            signing_key: SigningKey::from_bytes(&[0x11u8; 32]),
            address: params.payer.clone(),
        };
        let unsigned = build_charge_entry(&params, CredentialKind::Legacy).unwrap();
        let signed = sign_entry(unsigned, &signer, "Test SDF Network ; September 2015").unwrap();

        let envelope = build_sponsored_envelope(&params, &signed).unwrap();
        let TransactionEnvelope::Tx(mut v1) = envelope else {
            panic!()
        };
        // Replace the invokeHostFunction operation with a payment operation
        v1.tx.operations = vec![stellar_xdr::Operation {
            source_account: None,
            body: stellar_xdr::OperationBody::Payment(stellar_xdr::PaymentOp {
                destination: stellar_xdr::MuxedAccount::Ed25519(stellar_xdr::Uint256([3u8; 32])),
                asset: stellar_xdr::Asset::Native,
                amount: 100,
            }),
        }]
        .try_into()
        .unwrap();
        let envelope = TransactionEnvelope::Tx(v1);
        let result = parse_payment_transaction(&envelope);
        assert!(
            matches!(result, Err(MppError::UnexpectedTransactionShape { ref reason }) if reason.contains("invokeHostFunction")),
            "expected UnexpectedTransactionShape for non-invokeHostFunction op, got {result:?}"
        );
    }

    #[test]
    fn parse_rejects_wrong_function_name() {
        let params = test_params();
        let signer = TestSigner {
            signing_key: SigningKey::from_bytes(&[0x11u8; 32]),
            address: params.payer.clone(),
        };
        let unsigned = build_charge_entry(&params, CredentialKind::Legacy).unwrap();
        let signed = sign_entry(unsigned, &signer, "Test SDF Network ; September 2015").unwrap();

        let envelope = build_sponsored_envelope(&params, &signed).unwrap();
        let TransactionEnvelope::Tx(mut v1) = envelope else {
            panic!()
        };
        // Change the function name from "transfer" to "something_else"
        let mut invoke_op = match &v1.tx.operations[0].body {
            stellar_xdr::OperationBody::InvokeHostFunction(op) => op.clone(),
            _ => panic!(),
        };
        let stellar_xdr::HostFunction::InvokeContract(ref mut args) = invoke_op.host_function
        else {
            panic!()
        };
        args.function_name = "something_else".try_into().unwrap();
        v1.tx.operations = vec![stellar_xdr::Operation {
            source_account: None,
            body: stellar_xdr::OperationBody::InvokeHostFunction(invoke_op),
        }]
        .try_into()
        .unwrap();
        let envelope = TransactionEnvelope::Tx(v1);
        let result = parse_payment_transaction(&envelope);
        assert!(
            matches!(result, Err(MppError::UnexpectedTransactionShape { ref reason }) if reason.contains("function \"transfer\"")),
            "expected UnexpectedTransactionShape for wrong function name, got {result:?}"
        );
    }

    #[test]
    fn parse_rejects_wrong_number_of_args() {
        let params = test_params();
        let signer = TestSigner {
            signing_key: SigningKey::from_bytes(&[0x11u8; 32]),
            address: params.payer.clone(),
        };
        let unsigned = build_charge_entry(&params, CredentialKind::Legacy).unwrap();
        let signed = sign_entry(unsigned, &signer, "Test SDF Network ; September 2015").unwrap();

        let envelope = build_sponsored_envelope(&params, &signed).unwrap();
        let TransactionEnvelope::Tx(mut v1) = envelope else {
            panic!()
        };
        // Change to 2 args instead of 3
        let mut invoke_op = match &v1.tx.operations[0].body {
            stellar_xdr::OperationBody::InvokeHostFunction(op) => op.clone(),
            _ => panic!(),
        };
        let stellar_xdr::HostFunction::InvokeContract(ref mut args) = invoke_op.host_function
        else {
            panic!()
        };
        args.args = vec![
            stellar_xdr::ScVal::Address(params.payer.clone()),
            stellar_xdr::ScVal::Address(params.recipient.clone()),
        ]
        .try_into()
        .unwrap();
        v1.tx.operations = vec![stellar_xdr::Operation {
            source_account: None,
            body: stellar_xdr::OperationBody::InvokeHostFunction(invoke_op),
        }]
        .try_into()
        .unwrap();
        let envelope = TransactionEnvelope::Tx(v1);
        let result = parse_payment_transaction(&envelope);
        assert!(
            matches!(result, Err(MppError::UnexpectedTransactionShape { ref reason }) if reason.contains("expected exactly 3 args")),
            "expected UnexpectedTransactionShape for wrong number of args, got {result:?}"
        );
    }

    #[test]
    fn parse_rejects_wrong_arg_types() {
        let params = test_params();
        let signer = TestSigner {
            signing_key: SigningKey::from_bytes(&[0x11u8; 32]),
            address: params.payer.clone(),
        };
        let unsigned = build_charge_entry(&params, CredentialKind::Legacy).unwrap();
        let signed = sign_entry(unsigned, &signer, "Test SDF Network ; September 2015").unwrap();

        let envelope = build_sponsored_envelope(&params, &signed).unwrap();
        let TransactionEnvelope::Tx(mut v1) = envelope else {
            panic!()
        };
        // Change arg types: use U128 instead of Address for first arg
        let mut invoke_op = match &v1.tx.operations[0].body {
            stellar_xdr::OperationBody::InvokeHostFunction(op) => op.clone(),
            _ => panic!(),
        };
        let stellar_xdr::HostFunction::InvokeContract(ref mut args) = invoke_op.host_function
        else {
            panic!()
        };
        args.args = vec![
            stellar_xdr::ScVal::U128(stellar_xdr::UInt128Parts { hi: 0, lo: 0 }),
            stellar_xdr::ScVal::Address(params.recipient.clone()),
            stellar_xdr::ScVal::I128(stellar_xdr::Int128Parts {
                hi: 0,
                lo: 42_000_000,
            }),
        ]
        .try_into()
        .unwrap();
        v1.tx.operations = vec![stellar_xdr::Operation {
            source_account: None,
            body: stellar_xdr::OperationBody::InvokeHostFunction(invoke_op),
        }]
        .try_into()
        .unwrap();
        let envelope = TransactionEnvelope::Tx(v1);
        let result = parse_payment_transaction(&envelope);
        assert!(
            matches!(result, Err(MppError::UnexpectedTransactionShape { ref reason }) if reason.contains("expected exactly 3 args: address, address, i128")),
            "expected UnexpectedTransactionShape for wrong arg types, got {result:?}"
        );
    }

    #[test]
    fn parse_rejects_multiple_auth_entries() {
        let params = test_params();
        let signer = TestSigner {
            signing_key: SigningKey::from_bytes(&[0x11u8; 32]),
            address: params.payer.clone(),
        };
        let unsigned = build_charge_entry(&params, CredentialKind::Legacy).unwrap();
        let signed = sign_entry(unsigned, &signer, "Test SDF Network ; September 2015").unwrap();

        let envelope = build_sponsored_envelope(&params, &signed).unwrap();
        let TransactionEnvelope::Tx(mut v1) = envelope else {
            panic!()
        };
        // Add a second auth entry
        let mut invoke_op = match &v1.tx.operations[0].body {
            stellar_xdr::OperationBody::InvokeHostFunction(op) => op.clone(),
            _ => panic!(),
        };
        invoke_op.auth = vec![invoke_op.auth[0].clone(), invoke_op.auth[0].clone()]
            .try_into()
            .unwrap();
        v1.tx.operations = vec![stellar_xdr::Operation {
            source_account: None,
            body: stellar_xdr::OperationBody::InvokeHostFunction(invoke_op),
        }]
        .try_into()
        .unwrap();
        let envelope = TransactionEnvelope::Tx(v1);
        let result = parse_payment_transaction(&envelope);
        assert!(
            matches!(result, Err(MppError::UnexpectedTransactionShape { ref reason }) if reason.contains("exactly one authorization entry")),
            "expected UnexpectedTransactionShape for multiple auth entries, got {result:?}"
        );
    }

    #[test]
    fn parse_rejects_auth_entry_with_sub_invocations() {
        let params = test_params();
        let signer = TestSigner {
            signing_key: SigningKey::from_bytes(&[0x11u8; 32]),
            address: params.payer.clone(),
        };
        let unsigned = build_charge_entry(&params, CredentialKind::Legacy).unwrap();
        let signed = sign_entry(unsigned, &signer, "Test SDF Network ; September 2015").unwrap();

        let envelope = build_sponsored_envelope(&params, &signed).unwrap();
        let TransactionEnvelope::Tx(mut v1) = envelope else {
            panic!()
        };
        // Add a sub-invocation to the auth entry
        let mut invoke_op = match &v1.tx.operations[0].body {
            stellar_xdr::OperationBody::InvokeHostFunction(op) => op.clone(),
            _ => panic!(),
        };
        let mut auth_entry = invoke_op.auth[0].clone();
        auth_entry.root_invocation.sub_invocations =
            vec![auth_entry.root_invocation.clone()].try_into().unwrap();
        invoke_op.auth = vec![auth_entry].try_into().unwrap();
        v1.tx.operations = vec![stellar_xdr::Operation {
            source_account: None,
            body: stellar_xdr::OperationBody::InvokeHostFunction(invoke_op),
        }]
        .try_into()
        .unwrap();
        let envelope = TransactionEnvelope::Tx(v1);
        let result = parse_payment_transaction(&envelope);
        assert!(
            matches!(result, Err(MppError::UnexpectedTransactionShape { ref reason }) if reason.contains("sub-invocations")),
            "expected UnexpectedTransactionShape for auth entry with sub-invocations, got {result:?}"
        );
    }

    #[test]
    fn parse_rejects_auth_entry_invocation_mismatch() {
        let params = test_params();
        let signer = TestSigner {
            signing_key: SigningKey::from_bytes(&[0x11u8; 32]),
            address: params.payer.clone(),
        };
        let unsigned = build_charge_entry(&params, CredentialKind::Legacy).unwrap();
        let signed = sign_entry(unsigned, &signer, "Test SDF Network ; September 2015").unwrap();

        let envelope = build_sponsored_envelope(&params, &signed).unwrap();
        let TransactionEnvelope::Tx(mut v1) = envelope else {
            panic!()
        };
        // Change the auth entry's function to not match the operation
        let mut invoke_op = match &v1.tx.operations[0].body {
            stellar_xdr::OperationBody::InvokeHostFunction(op) => op.clone(),
            _ => panic!(),
        };
        let mut auth_entry = invoke_op.auth[0].clone();
        auth_entry.root_invocation.function =
            stellar_xdr::SorobanAuthorizedFunction::ContractFn(stellar_xdr::InvokeContractArgs {
                contract_address: params.asset_contract.clone(),
                function_name: "other_func".try_into().unwrap(),
                args: vec![].try_into().unwrap(),
            });
        invoke_op.auth = vec![auth_entry].try_into().unwrap();
        v1.tx.operations = vec![stellar_xdr::Operation {
            source_account: None,
            body: stellar_xdr::OperationBody::InvokeHostFunction(invoke_op),
        }]
        .try_into()
        .unwrap();
        let envelope = TransactionEnvelope::Tx(v1);
        let result = parse_payment_transaction(&envelope);
        assert!(
            matches!(result, Err(MppError::UnexpectedTransactionShape { ref reason }) if reason.contains("authorization entry's invocation does not match")),
            "expected UnexpectedTransactionShape for auth entry invocation mismatch, got {result:?}"
        );
    }
}
