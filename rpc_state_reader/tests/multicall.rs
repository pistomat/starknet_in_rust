use std::sync::Arc;

use cairo_vm::felt::{felt_str, Felt252};
use rpc_state_reader::rpc_state::{BlockValue, RpcBlockInfo, RpcChain, RpcState};
use starknet_api::{
    block::BlockNumber,
    core::{ClassHash as SNClassHash, ContractAddress, PatriciaKey},
    hash::StarkHash,
    state::StorageKey,
};
use starknet_in_rust::{
    core::errors::state_errors::StateError,
    definitions::{
        block_context::{BlockContext, StarknetChainId, StarknetOsConfig},
        constants::{
            DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS, DEFAULT_CONTRACT_STORAGE_COMMITMENT_TREE_HEIGHT,
            DEFAULT_GLOBAL_STATE_COMMITMENT_TREE_HEIGHT, DEFAULT_INVOKE_TX_MAX_N_STEPS,
            DEFAULT_VALIDATE_MAX_N_STEPS,
        },
    },
    execution::{
        execution_entry_point::ExecutionEntryPoint, CallType, TransactionExecutionContext,
    },
    services::api::contract_classes::compiled_class::CompiledClass,
    state::{
        cached_state::{CachedState, ContractClassCache},
        state_api::StateReader,
        state_cache::StorageEntry,
        BlockInfo, ExecutionResourcesManager,
    },
    transaction::{InvokeFunction, Transaction},
    utils::{calculate_sn_keccak, Address, ClassHash},
    EntryPointType,
};

pub struct RpcStateReader(RpcState);

impl StateReader for RpcStateReader {
    fn get_contract_class(&self, class_hash: &ClassHash) -> Result<CompiledClass, StateError> {
        let hash = SNClassHash(StarkHash::new(*class_hash).unwrap());
        Ok(CompiledClass::from(self.0.get_contract_class(&hash)))
    }

    fn get_class_hash_at(&self, contract_address: &Address) -> Result<ClassHash, StateError> {
        let address = ContractAddress(
            PatriciaKey::try_from(
                StarkHash::new(contract_address.clone().0.to_be_bytes()).unwrap(),
            )
            .unwrap(),
        );
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(self.0.get_class_hash_at(&address).0.bytes());
        Ok(bytes)
    }

    fn get_nonce_at(&self, contract_address: &Address) -> Result<Felt252, StateError> {
        let address = ContractAddress(
            PatriciaKey::try_from(
                StarkHash::new(contract_address.clone().0.to_be_bytes()).unwrap(),
            )
            .unwrap(),
        );
        let nonce = self.0.get_nonce_at(&address);
        Ok(Felt252::from_bytes_be(nonce.bytes()))
    }
    fn get_storage_at(&self, storage_entry: &StorageEntry) -> Result<Felt252, StateError> {
        let (contract_address, key) = storage_entry;
        let address = ContractAddress(
            PatriciaKey::try_from(
                StarkHash::new(contract_address.clone().0.to_be_bytes()).unwrap(),
            )
            .unwrap(),
        );
        let key = StorageKey(PatriciaKey::try_from(StarkHash::new(*key).unwrap()).unwrap());
        let value = self.0.get_storage_at(&address, &key);
        Ok(Felt252::from_bytes_be(value.bytes()))
    }
    fn get_compiled_class_hash(&self, class_hash: &ClassHash) -> Result<[u8; 32], StateError> {
        let address =
            ContractAddress(PatriciaKey::try_from(StarkHash::new(*class_hash).unwrap()).unwrap());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(self.0.get_class_hash_at(&address).0.bytes());
        Ok(bytes)
    }
}

#[test]
fn test_multicall() {
    // An attempt to recreate the execution of the following transaction:
    // https://starkscan.co/tx/0x036951b882702c3e5ce97a0f43f473edfc97c405471f6ecb34e54e47c0898130

    let fee_token_address = Address(felt_str!(
        "049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
        16
    ));

    let block_number = BlockNumber(373172); // The actual block number is 373173, but we need to simulate on top of the previous block
    let block = BlockValue::Number(block_number);
    let chain = RpcChain::MainNet;

    // Create the state reader
    let rpc_state_reader = RpcStateReader(RpcState::new_infura(chain, block));
    let gas_price = rpc_state_reader.0.get_gas_price(block_number.0).unwrap();

    // Get values for block context before giving ownership of the reader
    let chain_id = match rpc_state_reader.0.chain {
        RpcChain::MainNet => StarknetChainId::MainNet,
        RpcChain::TestNet => StarknetChainId::TestNet,
        RpcChain::TestNet2 => StarknetChainId::TestNet2,
    };
    let starknet_os_config =
        StarknetOsConfig::new(chain_id.to_felt(), fee_token_address, gas_price);
    let block_info = {
        let RpcBlockInfo {
            block_number,
            block_timestamp,
            sequencer_address,
            ..
        } = rpc_state_reader.0.get_block_info();

        let block_number = block_number.0;
        let block_timestamp = block_timestamp.0;
        let sequencer_address = Address(Felt252::from_bytes_be(sequencer_address.0.key().bytes()));

        BlockInfo {
            block_number,
            block_timestamp,
            gas_price,
            sequencer_address,
        }
    };

    let class_cache = ContractClassCache::default();
    let mut state = CachedState::new(Arc::new(rpc_state_reader), class_cache);

    // Create the simulated call
    let entry_point = "__execute__";
    let entry_point_selector = Felt252::from_bytes_be(&calculate_sn_keccak(entry_point.as_bytes()));

    let caller_address = Address(Felt252::from(0));
    let contract_address = Address(felt_str!(
        "06ceb6970259a55b3957fabf5f0349913c6d025c817ad4edf86032f5d0f1223d",
        16
    ));
    let class_hash = felt_str!(
        "025ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918",
        16
    );

    let calldata = vec![
        felt_str!("2"),
        felt_str!("2368576823837625528275935341135881659748932889268308403712618244410713532584"),
        felt_str!("949021990203918389843157787496164629863144228991510976554585288817234167820"),
        felt_str!("0"),
        felt_str!("3"),
        felt_str!("2651722879560814669652856477504602945267782506345687644982244092997176673782"),
        felt_str!("1329909728320632088402217562277154056711815095720684343816173432540100887380"),
        felt_str!("3"),
        felt_str!("3"),
        felt_str!("6"),
        felt_str!("2651722879560814669652856477504602945267782506345687644982244092997176673782"),
        felt_str!("390000"),
        felt_str!("0"),
        felt_str!("3079107775878510901627160921564752917210725156658308953446041504620125168189"),
        felt_str!("390000"),
        felt_str!("0"),
    ];

    // let entry_point = ExecutionEntryPoint::new(
    //     contract_address,
    //     call_data,
    //     entry_point_selector,
    //     caller_address,
    //     EntryPointType::External,
    //     CallType::Call.into(),
    //     class_hash.to_be_bytes().into(),
    //     // None,
    //     u128::MAX,
    // );
    // dbg!(&entry_point);

    let tx = Transaction::InvokeFunction(
        InvokeFunction::new(
            contract_address,
            entry_point_selector,
            1000000,
            1.into(),
            calldata,
            vec![],
            StarknetChainId::MainNet.to_felt(),
            Some(17.into()),
        )
        .unwrap(),
    );

    // Set up the call context
    let block_context = BlockContext::new(
        starknet_os_config,
        DEFAULT_CONTRACT_STORAGE_COMMITMENT_TREE_HEIGHT,
        DEFAULT_GLOBAL_STATE_COMMITMENT_TREE_HEIGHT,
        DEFAULT_CAIRO_RESOURCE_FEE_WEIGHTS.clone(),
        DEFAULT_INVOKE_TX_MAX_N_STEPS,
        DEFAULT_VALIDATE_MAX_N_STEPS,
        block_info,
        Default::default(),
        true,
    );

    // Execute the call
    let simulation_tx = tx.create_for_simulation(
        true,
        false,
        true,
        true,
        true,
    );
    let result = simulation_tx.execute(&mut state, &block_context, u128::MAX);
    dbg!(&result);

    assert!(result.is_ok());
}
