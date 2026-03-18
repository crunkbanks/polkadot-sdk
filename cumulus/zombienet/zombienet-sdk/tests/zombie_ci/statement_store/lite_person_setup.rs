// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

//! E2E test for lite person setup via pallet-people-lite extrinsics
//!
//! Exercises the full flow on a live individuality runtime via zombienet:
//! 1. Grant attestation allowance to a verifier (sudo call).
//! 2. Generate candidate keys and a ring-VRF keypair.
//! 3. Submit `PeopleLite::attest` with `consumer_registration: None`

use codec::Encode;
use log::info;
use sp_core::{sr25519, Pair};
use verifiable::{ring_vrf_impl::BandersnatchVrfVerifiable as Crypto, GenerateVerifiable};
use zombienet_sdk::subxt::{
	dynamic::Value,
	ext::scale_value::value,
	tx::{signer::Signer, DynamicPayload},
};

use super::sudo_helpers::{
	spawn_network, submit_signed_extrinsic, submit_sudo_extrinsic, CustomConfig,
};

/// Matches `indiv_pallet_people_lite::MSG_PREFIX`
pub(super) const MSG_PREFIX: &[u8; 30] = b"pop:people-lite:register using";

/// Creates a `Sudo::sudo(PeopleLite::increase_attestation_allowance { account, count })` call
pub(super) fn create_increase_allowance_call(account_bytes: Vec<u8>, count: u32) -> DynamicPayload {
	zombienet_sdk::subxt::tx::dynamic(
		"Sudo",
		"sudo",
		vec![value! {
			PeopleLite(increase_attestation_allowance {
				account: Value::from_bytes(account_bytes),
				count: Value::u128(count as u128)
			})
		}],
	)
}

/// Creates a `PeopleLite::attest` call with `consumer_registration: None`
pub(super) fn create_attest_call(
	candidate_bytes: Vec<u8>,
	sr25519_signature_bytes: Vec<u8>,
	ring_vrf_key_inner: Vec<u8>,
	proof_of_ownership_bytes: Vec<u8>,
) -> DynamicPayload {
	zombienet_sdk::subxt::tx::dynamic(
		"PeopleLite",
		"attest",
		vec![
			// AccountId32 = [u8; 32]
			Value::from_bytes(candidate_bytes),
			// MultiSignature is an enum; Sr25519 wraps a [u8; 64]
			Value::unnamed_variant("Sr25519", vec![Value::from_bytes(sr25519_signature_bytes)]),
			// EncodedPublicKey is a newtype struct around [u8; 32]
			Value::unnamed_composite(vec![Value::from_bytes(ring_vrf_key_inner)]),
			// Plain VRF signature is [u8; 96]
			Value::from_bytes(proof_of_ownership_bytes),
			Value::unnamed_variant("None", vec![]),
		],
	)
}

#[tokio::test(flavor = "multi_thread")]
async fn lite_person_setup_via_extrinsics() -> Result<(), anyhow::Error> {
	let _ = env_logger::try_init_from_env(
		env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
	);

	let network = spawn_network(&["alice"]).await?;
	let node = network.get_node("alice")?;
	let para_client = node.wait_client::<CustomConfig>().await?;

	let alice = zombienet_sdk::subxt_signer::sr25519::dev::alice();
	let alice_account_id =
		<zombienet_sdk::subxt_signer::sr25519::Keypair as Signer<CustomConfig>>::account_id(
			&alice,
		);

	info!("Granting attestation allowance to Alice...");
	let increase_call = create_increase_allowance_call(alice_account_id.0.to_vec(), 1);
	let mut nonce = para_client.tx().account_nonce(&alice_account_id).await?;
	info!("Alice nonce before increase_allowance: {nonce}");
	let _tx_stream =
		submit_sudo_extrinsic(&para_client, &increase_call, &alice, nonce).await?;
	nonce += 1;
	info!("Attestation allowance granted");

	let candidate_pair = sr25519::Pair::from_seed(&[77u8; 32]);
	let candidate_account: [u8; 32] = candidate_pair.public().0;

	let ring_secret = Crypto::new_secret([42u8; 32]);
	let ring_member = Crypto::member_from_secret(&ring_secret);

	// build the attestation message: MSG_PREFIX ++ encode(candidate) ++ encode(ring_vrf_key)
	let msg = {
		let candidate_encoded = candidate_account.encode();
		let ring_member_encoded = ring_member.encode();
		[MSG_PREFIX.as_slice(), &candidate_encoded, &ring_member_encoded].concat()
	};
	let candidate_sig = candidate_pair.sign(&msg);

	// Ring-VRF proof
	let proof_of_ownership =
		Crypto::sign(&ring_secret, &msg).expect("ring VRF signing should succeed");

	info!("Submitting PeopleLite::attest call with nonce {nonce}...");
	let attest_call = create_attest_call(
		candidate_account.to_vec(),
		candidate_sig.0.to_vec(),
		ring_member.0.to_vec(),
		proof_of_ownership.to_vec(),
	);
	let block_hash =
		submit_signed_extrinsic(&para_client, &attest_call, &alice, nonce).await?;
	info!("Attest call succeeded — lite person registered (block {block_hash:?})");

	// verify the candidate appears in LitePeople storage
	let lite_people_query = zombienet_sdk::subxt::dynamic::storage("PeopleLite", "LitePeople", vec![
		Value::from_bytes(candidate_account.to_vec()),
	]);
	let entry = para_client.storage().at(block_hash).fetch(&lite_people_query).await?;
	assert!(entry.is_some(), "Candidate should be registered in LitePeople storage");
	info!("Verified: candidate is present in LitePeople storage");

	info!("Lite person setup test passed");
	Ok(())
}
