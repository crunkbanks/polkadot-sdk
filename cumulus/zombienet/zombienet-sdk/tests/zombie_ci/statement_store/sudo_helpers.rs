// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Sudo extrinsic helpers and custom subxt config for statement store tests
//!
//! Contains the `CustomConfig` type needed to submit extrinsics on
//! people-westend, plus helpers that set statement allowances at runtime
//! via `Sudo::sudo(System::set_storage(...))`

use std::path::PathBuf;

use anyhow::anyhow;
use codec::Encode;
use log::info;
use scale_info::PortableRegistry;
use sp_core::Pair;
use sp_statement_store::{statement_allowance_key, StatementAllowance};
use subxt::{
	config::{
		substrate::SubstrateConfig,
		transaction_extensions::{
			ChargeAssetTxPayment, ChargeTransactionPayment, CheckGenesis, CheckMetadataHash,
			CheckMortality, CheckNonce, CheckSpecVersion, CheckTxVersion, VerifySignature,
		},
		ClientState, Config, DefaultExtrinsicParamsBuilder, TransactionExtension,
	},
	dynamic::Value,
	ext::{frame_decode, scale_value::value},
	transactions::Signer,
	utils::H256,
	OnlineClient,
};
use zombienet_sdk::{LocalFileSystem, Network, NetworkConfigBuilder};

use super::common::get_keypair;

pub struct VerifyMultiSignature<T: Config>(VerifySignature<T>);

impl<T: Config> frame_decode::extrinsics::TransactionExtension<PortableRegistry>
	for VerifyMultiSignature<T>
{
	const NAME: &str = "VerifyMultiSignature";

	fn encode_value_to(
		&self,
		type_id: u32,
		type_resolver: &PortableRegistry,
		v: &mut Vec<u8>,
	) -> Result<(), frame_decode::extrinsics::TransactionExtensionError> {
		self.0.encode_value_to(type_id, type_resolver, v)
	}

	fn encode_value_for_signer_payload_to(
		&self,
		type_id: u32,
		type_resolver: &PortableRegistry,
		v: &mut Vec<u8>,
	) -> Result<(), frame_decode::extrinsics::TransactionExtensionError> {
		self.0.encode_value_for_signer_payload_to(type_id, type_resolver, v)
	}

	fn encode_implicit_to(
		&self,
		type_id: u32,
		type_resolver: &PortableRegistry,
		v: &mut Vec<u8>,
	) -> Result<(), frame_decode::extrinsics::TransactionExtensionError> {
		self.0.encode_implicit_to(type_id, type_resolver, v)
	}
}

impl<T: Config> TransactionExtension<T> for VerifyMultiSignature<T> {
	type Decoded = <VerifySignature<T> as TransactionExtension<T>>::Decoded;
	type Params = ();

	fn new(
		client: &ClientState<T>,
		params: Self::Params,
	) -> Result<Self, subxt::error::TransactionExtensionError> {
		Ok(VerifyMultiSignature(VerifySignature::new(client, params)?))
	}

	fn inject_signature(&mut self, account_id: &T::AccountId, signature: &T::Signature) {
		self.0.inject_signature(account_id, signature);
	}
}

pub struct RestrictOrigins;

impl frame_decode::extrinsics::TransactionExtension<PortableRegistry> for RestrictOrigins {
	const NAME: &str = "RestrictOrigins";

	fn encode_value_to(
		&self,
		_type_id: u32,
		_type_resolver: &PortableRegistry,
		v: &mut Vec<u8>,
	) -> Result<(), frame_decode::extrinsics::TransactionExtensionError> {
		v.push(0x00);
		Ok(())
	}

	fn encode_implicit_to(
		&self,
		_type_id: u32,
		_type_resolver: &PortableRegistry,
		_v: &mut Vec<u8>,
	) -> Result<(), frame_decode::extrinsics::TransactionExtensionError> {
		Ok(())
	}
}

impl<T: Config> TransactionExtension<T> for RestrictOrigins {
	type Decoded = u8;
	type Params = ();

	fn new(
		_client: &ClientState<T>,
		_params: Self::Params,
	) -> Result<Self, subxt::error::TransactionExtensionError> {
		Ok(RestrictOrigins)
	}
}

/// Custom config for the people-westend parachain with custom transaction extensions
#[derive(Debug, Clone)]
pub struct CustomConfig(SubstrateConfig);

impl Default for CustomConfig {
	fn default() -> Self {
		CustomConfig(SubstrateConfig::new())
	}
}

impl Config for CustomConfig {
	type AccountId = <SubstrateConfig as Config>::AccountId;
	type Address = subxt::utils::MultiAddress<Self::AccountId, ()>;
	type Signature = <SubstrateConfig as Config>::Signature;
	type Hasher = <SubstrateConfig as Config>::Hasher;
	type Header = <SubstrateConfig as Config>::Header;
	type AssetId = <SubstrateConfig as Config>::AssetId;
	type TransactionExtensions = (
		VerifyMultiSignature<Self>,
		CheckSpecVersion,
		CheckTxVersion,
		CheckNonce,
		CheckGenesis<Self>,
		CheckMortality<Self>,
		ChargeAssetTxPayment<Self>,
		ChargeTransactionPayment,
		CheckMetadataHash,
		RestrictOrigins,
	);

	fn genesis_hash(&self) -> Option<subxt::config::HashFor<Self>> {
		self.0.genesis_hash()
	}

	fn spec_and_transaction_version_for_block_number(
		&self,
		block_number: u64,
	) -> Option<(u32, u32)> {
		self.0.spec_and_transaction_version_for_block_number(block_number)
	}

	fn metadata_for_spec_version(
		&self,
		spec_version: u32,
	) -> Option<subxt::metadata::ArcMetadata> {
		self.0.metadata_for_spec_version(spec_version)
	}

	fn set_metadata_for_spec_version(
		&self,
		spec_version: u32,
		metadata: subxt::metadata::ArcMetadata,
	) {
		self.0.set_metadata_for_spec_version(spec_version, metadata)
	}
}

pub(super) async fn online_client_from_node(
	node: &zombienet_sdk::NetworkNode,
) -> Result<OnlineClient<CustomConfig>, anyhow::Error> {
	let ws_uri = node.ws_uri();
	let client = OnlineClient::<CustomConfig>::from_insecure_url(ws_uri).await?;
	Ok(client)
}

/// Creates storage items for custom per-participant allowances
pub(super) fn create_allowance_items(
	allowances: &[(u32, StatementAllowance)],
) -> Vec<(Vec<u8>, Vec<u8>)> {
	let mut items = Vec::with_capacity(allowances.len());
	for (idx, allowance) in allowances {
		let keypair = get_keypair(*idx);
		let account_id = keypair.public();
		let storage_key = statement_allowance_key(account_id.0);
		items.push((storage_key.to_vec(), allowance.encode()));
	}
	items
}

/// Creates uniform allowance storage items for a range of participants
pub(super) fn create_uniform_allowance_items(
	count: u32,
	allowance: StatementAllowance,
) -> Vec<(Vec<u8>, Vec<u8>)> {
	let allowance_encoded = allowance.encode();
	let mut items = Vec::with_capacity(count as usize);
	for idx in 0..count {
		let keypair = get_keypair(idx);
		let account_id = keypair.public();
		let storage_key = statement_allowance_key(account_id.0);
		items.push((storage_key.to_vec(), allowance_encoded.clone()));
	}
	items
}

/// Creates a sudo -> frame_system::set_storage call to set statement allowances
fn create_set_storage_call(
	items: Vec<(Vec<u8>, Vec<u8>)>,
) -> subxt::transactions::DynamicPayload<Vec<Value>> {
	let items_value: Vec<Value> = items
		.into_iter()
		.map(|(key, value)| value!((Value::from_bytes(key), Value::from_bytes(value))))
		.collect();

	subxt::transactions::dynamic(
		"Sudo",
		"sudo",
		vec![value! {
			System(set_storage { items: items_value })
		}],
	)
}

/// Builds params for our CustomConfig's 10 transaction extensions (9 defaults + RestrictOrigins)
fn build_params(nonce: u64) -> <
	<CustomConfig as Config>::TransactionExtensions
	as subxt::config::TransactionExtensions<CustomConfig>
>::Params {
	let (a, b, c, d, e, f, g, h, i) = DefaultExtrinsicParamsBuilder::<CustomConfig>::new()
		.immortal()
		.nonce(nonce)
		.build();
	(a, b, c, d, e, f, g, h, i, ())
}

/// Submits an extrinsic with an explicit nonce and waits for it to be finalized.
pub(super) async fn submit_sudo_extrinsic<S: Signer<CustomConfig>>(
	client: &OnlineClient<CustomConfig>,
	call: &subxt::transactions::DynamicPayload<Vec<Value>>,
	signer: &S,
	nonce: u64,
) -> Result<H256, anyhow::Error> {
	let tx_in_block = client
		.tx()
		.await?
		.sign_and_submit_then_watch(call, signer, build_params(nonce))
		.await?
		.wait_for_finalized()
		.await?;

	tx_in_block.wait_for_success().await?;
	Ok(tx_in_block.block_hash())
}

/// Gets the current nonce for an account
async fn get_account_nonce(
	client: &OnlineClient<CustomConfig>,
	account_id: &<CustomConfig as Config>::AccountId,
) -> Result<u64, anyhow::Error> {
	let nonce = client.tx().await?.account_nonce(account_id).await?;
	Ok(nonce)
}

/// Sets statement allowances via sudo -> frame_system::set_storage extrinsic
async fn set_allowances_via_sudo(
	para_client: &OnlineClient<CustomConfig>,
	items: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<(), anyhow::Error> {
	info!("Setting {} statement allowances via sudo...", items.len());

	let alice = subxt_signer::sr25519::dev::alice();
	let alice_account_id =
		<subxt_signer::sr25519::Keypair as Signer<CustomConfig>>::account_id(&alice);

	let current_nonce = get_account_nonce(para_client, &alice_account_id).await?;
	let set_storage_call = create_set_storage_call(items);

	let block_hash =
		submit_sudo_extrinsic(para_client, &set_storage_call, &alice, current_nonce).await?;
	info!("Statement allowances set and finalized in block {:?}", block_hash);

	Ok(())
}

/// Spawns a network with the sudo-enabled chain spec without setting any allowances
pub(super) async fn spawn_network(
	collators: &[&str],
) -> Result<Network<LocalFileSystem>, anyhow::Error> {
	spawn_network_inner(collators, 0).await
}

async fn spawn_network_inner(
	collators: &[&str],
	participant_count: usize,
) -> Result<Network<LocalFileSystem>, anyhow::Error> {
	let images = zombienet_sdk::environment::get_images_from_env();

	let base_dir = std::env::var("ZOMBIENET_SDK_BASE_DIR")
		.ok()
		.map(PathBuf::from)
		.unwrap_or_else(|| std::env::temp_dir().join(format!("zombienet-{}", std::process::id())));
	std::fs::create_dir_all(&base_dir)
		.map_err(|e| anyhow!("Failed to create base directory: {}", e))?;

	let config = NetworkConfigBuilder::new()
		.with_relaychain(|r| {
			r.with_chain("westend-local")
				.with_default_command("polkadot")
				.with_default_image(images.polkadot.as_str())
				.with_default_args(vec!["-lparachain=debug".into()])
				.with_validator(|node| node.with_name("validator-0"))
				.with_validator(|node| node.with_name("validator-1"))
		})
		.with_parachain(|p| {
			let mut args = vec![
				"--force-authoring".into(),
				"--authoring".into(),
				"slot-based".into(),
				"--max-runtime-instances=32".into(),
				"-linfo,statement-store=info,statement-gossip=info".into(),
				"--enable-statement-store".into(),
			];
			if participant_count > 0 {
				args.push(
					format!("--rpc-max-connections={}", participant_count + 1000)
						.as_str()
						.into(),
				);
				args.push(
					format!(
						"--rpc-max-subscriptions-per-connection={}",
						(participant_count * 16).max(32)
					)
					.as_str()
					.into(),
				);
			}

			let p = p
				.with_id(2101)
				.with_chain_spec_path("https://raw.githubusercontent.com/paritytech/chainspecs/denzelpenzel/versi-people-2101/versi/parachain/versi-people-2101/chainspec.json")
				.with_default_command("polkadot-parachain")
				.with_default_image(images.cumulus.as_str())
				.with_default_args(args)
				.with_collator(|n| n.with_name(collators[0]));

			collators[1..]
				.iter()
				.fold(p, |acc, &name| acc.with_collator(|n| n.with_name(name)))
		})
		.with_global_settings(|global_settings| {
			global_settings.with_base_dir(base_dir.to_str().expect("Valid UTF-8 path"))
		})
		.build()
		.map_err(|e| {
			let errs = e.into_iter().map(|e| e.to_string()).collect::<Vec<_>>().join(" ");
			anyhow!("config errs: {errs}")
		})?;

	let spawn_fn = zombienet_sdk::environment::get_spawn_fn();
	let network = spawn_fn(config).await?;
	assert!(network.wait_until_is_up(60).await.is_ok());

	info!("Waiting for parachain to produce blocks...");
	let first_collator = collators[0];
	let node = network.get_node(first_collator)?;
	node.wait_metric_with_timeout("block_height{status=\"best\"}", |height| height >= 1.0, 300u64)
		.await?;
	info!("Parachain is producing blocks");

	Ok(network)
}

/// Spawns a network with the sudo-enabled chain spec and sets allowances at runtime
pub(super) async fn spawn_network_sudo(
	collators: &[&str],
	allowance_items: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<Network<LocalFileSystem>, anyhow::Error> {
	let network = spawn_network_inner(collators, allowance_items.len()).await?;
	let node = network.get_node(collators[0])?;
	let para_client = online_client_from_node(node).await?;
	set_allowances_via_sudo(&para_client, allowance_items).await?;
	Ok(network)
}

/// Submits a signed (non-sudo) extrinsic and waits for finalization
pub(super) async fn submit_signed_extrinsic<S: Signer<CustomConfig>>(
	client: &OnlineClient<CustomConfig>,
	call: &subxt::transactions::DynamicPayload<Vec<Value>>,
	signer: &S,
	nonce: u64,
) -> Result<H256, anyhow::Error> {
	let tx_in_block = client
		.tx()
		.await?
		.sign_and_submit_then_watch(call, signer, build_params(nonce))
		.await?
		.wait_for_finalized()
		.await?;

	tx_in_block.wait_for_success().await?;
	Ok(tx_in_block.block_hash())
}
