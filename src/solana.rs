use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signature::Keypair,
    signer::Signer,
};
use solana_system_interface::instruction as system_instruction;
use spl_token::instruction as token_instruction;
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey, VerifyingKey, Signature as Ed25519Signature, Verifier};
use base64::{Engine as _, engine::general_purpose};
use crate::errors::ApiError;
use crate::models::*;
use std::str::FromStr;

// Constants for validation limits
const MAX_DECIMALS: u8 = 9;
const MAX_MESSAGE_LENGTH: usize = 10_000; // Reasonable limit for message size
const SOLANA_PUBKEY_LENGTH: usize = 32;
const ED25519_SIGNATURE_LENGTH: usize = 64;
const SOLANA_KEYPAIR_LENGTH: usize = 64;

// Helper function to validate base58 encoded public keys
fn validate_pubkey(pubkey_str: &str) -> Result<Pubkey, ApiError> {
    if pubkey_str.trim().is_empty() {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    
    // Prevent extremely long strings that could cause DoS
    if pubkey_str.len() > 100 {
        return Err(ApiError::InvalidPublicKey("Public key string too long".to_string()));
    }
    
    // Check if it's a valid base58 string
    match bs58::decode(pubkey_str).into_vec() {
        Ok(bytes) => {
            if bytes.len() != SOLANA_PUBKEY_LENGTH {
                return Err(ApiError::InvalidPublicKey("Public key must be 32 bytes".to_string()));
            }
        }
        Err(_) => return Err(ApiError::InvalidPublicKey("Invalid base58 encoding".to_string())),
    }
    
    // Parse as Solana public key
    Pubkey::from_str(pubkey_str).map_err(|_| {
        ApiError::InvalidPublicKey("Invalid Solana public key format".to_string())
    })
}

// Helper function to validate amounts (with reasonable upper limits)
fn validate_amount(amount: u64, field_name: &str) -> Result<(), ApiError> {
    if amount == 0 {
        return Err(ApiError::InvalidInput(format!("{} must be greater than 0", field_name)));
    }
    
    // Prevent overflow attacks with reasonable upper bound
    if amount > u64::MAX / 2 {
        return Err(ApiError::InvalidInput(format!("{} is too large", field_name)));
    }
    
    Ok(())
}

// Helper function to validate non-empty strings and message lengths
fn validate_required_field(value: &str, _field_name: &str) -> Result<(), ApiError> {
    if value.trim().is_empty() {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    Ok(())
}

// Helper function to validate message content
fn validate_message(message: &str) -> Result<(), ApiError> {
    validate_required_field(message, "message")?;
    
    if message.len() > MAX_MESSAGE_LENGTH {
        return Err(ApiError::InvalidInput("Message too long".to_string()));
    }
    
    Ok(())
}

// Generating a fresh Solana keypair
pub fn generate_keypair() -> Result<KeypairResponse, ApiError> {
    let keypair = Keypair::new();
    let pubkey = bs58::encode(keypair.pubkey().to_bytes()).into_string();
    let secret = bs58::encode(keypair.to_bytes()).into_string();
    
    Ok(KeypairResponse { pubkey, secret })
}

// Create token mint instruction
pub fn create_token_instruction(request: CreateTokenRequest) -> Result<InstructionResponse, ApiError> {
    // Validate required fields
    validate_required_field(&request.mint_authority, "mintAuthority")?;
    validate_required_field(&request.mint, "mint")?;
    
    // Validate public keys
    let mint_authority = validate_pubkey(&request.mint_authority)?;
    let mint = validate_pubkey(&request.mint)?;
    
    // Validate decimals (reasonable range for SPL tokens)
    if request.decimals > MAX_DECIMALS {
        return Err(ApiError::InvalidInput("Decimals cannot exceed 9".to_string()));
    }
    
    let instruction = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint,
        &mint_authority,
        Some(&mint_authority),
        request.decimals,
    ).map_err(|e| ApiError::InstructionError(format!("Failed to create mint instruction: {}", e)))?;
    
    convert_instruction_to_response(instruction)
}

// Create mint-to instruction
pub fn create_mint_instruction(request: MintTokenRequest) -> Result<InstructionResponse, ApiError> {
    // Validate required fields
    validate_required_field(&request.mint, "mint")?;
    validate_required_field(&request.destination, "destination")?;
    validate_required_field(&request.authority, "authority")?;
    validate_amount(request.amount, "amount")?;
    
    // Validate public keys
    let mint = validate_pubkey(&request.mint)?;
    let destination = validate_pubkey(&request.destination)?;
    let authority = validate_pubkey(&request.authority)?;
    
    let instruction = token_instruction::mint_to(
        &spl_token::id(),
        &mint,
        &destination,
        &authority,
        &[],
        request.amount,
    ).map_err(|e| ApiError::InstructionError(format!("Failed to create mint instruction: {}", e)))?;
    
    convert_instruction_to_response(instruction)
}

// Sign messages with Ed25519
pub fn sign_message(request: SignMessageRequest) -> Result<SignMessageResponse, ApiError> {
    // Validate required fields and message length
    validate_message(&request.message)?;
    validate_required_field(&request.secret, "secret")?;
    
    // Decode the secret key
    let secret_bytes = bs58::decode(&request.secret)
        .into_vec()
        .map_err(|_| ApiError::InvalidSecretKey("Invalid base58 encoding".to_string()))?;
    
    if secret_bytes.len() != SOLANA_KEYPAIR_LENGTH {
        return Err(ApiError::InvalidSecretKey("Secret key must be 64 bytes".to_string()));
    }
    
    // Create signing key from the first 32 bytes (ed25519 private key)
    let signing_key_bytes: [u8; 32] = secret_bytes[0..32].try_into()
        .map_err(|_| ApiError::InvalidSecretKey("Invalid secret key format".to_string()))?;
    
    let signing_key = SigningKey::from_bytes(&signing_key_bytes);
    
    // Sign the message
    let signature = signing_key.sign(request.message.as_bytes());
    
    // Get public key
    let public_key = signing_key.verifying_key();
    let pubkey_str = bs58::encode(public_key.to_bytes()).into_string();
    
    Ok(SignMessageResponse {
        signature: general_purpose::STANDARD.encode(signature.to_bytes()),
        public_key: pubkey_str,
        message: request.message,
    })
}

pub fn verify_message(request: VerifyMessageRequest) -> Result<VerifyMessageResponse, ApiError> {
    // Validate required fields and message length
    validate_message(&request.message)?;
    validate_required_field(&request.signature, "signature")?;
    validate_required_field(&request.pubkey, "pubkey")?;
    
    // Decode public key
    let pubkey_bytes = bs58::decode(&request.pubkey)
        .into_vec()
        .map_err(|_| ApiError::InvalidPublicKey("Invalid base58 encoding".to_string()))?;
    
    if pubkey_bytes.len() != SOLANA_PUBKEY_LENGTH {
        return Err(ApiError::InvalidPublicKey("Public key must be 32 bytes".to_string()));
    }
    
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes.try_into().unwrap())
        .map_err(|_| ApiError::InvalidPublicKey("Invalid public key format".to_string()))?;
    
    // Decode signature
    let signature_bytes = general_purpose::STANDARD.decode(&request.signature)
        .map_err(|_| ApiError::InvalidSignature("Invalid base64 encoding for signature".to_string()))?;
    
    if signature_bytes.len() != ED25519_SIGNATURE_LENGTH {
        return Err(ApiError::InvalidSignature("Signature must be 64 bytes".to_string()));
    }
    
    let signature = Ed25519Signature::from_bytes(
        &signature_bytes.try_into()
            .map_err(|_| ApiError::InvalidSignature("Invalid signature format".to_string()))?
    );
    
    let valid = verifying_key.verify(request.message.as_bytes(), &signature).is_ok();
    
    Ok(VerifyMessageResponse {
        valid,
        message: request.message,
        pubkey: request.pubkey,
    })
}

pub fn create_sol_transfer_instruction(request: SendSolRequest) -> Result<SolInstructionResponse, ApiError> {
    // Validate required fields
    validate_required_field(&request.from, "from")?;
    validate_required_field(&request.to, "to")?;
    validate_amount(request.lamports, "lamports")?;
    
    // Validate public keys
    let from = validate_pubkey(&request.from)?;
    let to = validate_pubkey(&request.to)?;
    
    let instruction = system_instruction::transfer(&from, &to, request.lamports);
    
    Ok(SolInstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts: instruction.accounts.iter().map(|acc| acc.pubkey.to_string()).collect(),
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    })
}

pub fn create_token_transfer_instruction(request: SendTokenRequest) -> Result<TokenInstructionResponse, ApiError> {
    // Validate required fields
    validate_required_field(&request.destination, "destination")?;
    validate_required_field(&request.mint, "mint")?;
    validate_required_field(&request.owner, "owner")?;
    validate_amount(request.amount, "amount")?;
    
    // Validate public keys
    let mint = validate_pubkey(&request.mint)?;
    let owner = validate_pubkey(&request.owner)?;
    let destination = validate_pubkey(&request.destination)?;
    
    // For SPL token transfers, we need to get the associated token accounts
    let source_ata = spl_associated_token_account::get_associated_token_address(&owner, &mint);
    let dest_ata = spl_associated_token_account::get_associated_token_address(&destination, &mint);
    
    let instruction = token_instruction::transfer(
        &spl_token::id(),
        &source_ata,
        &dest_ata,
        &owner,
        &[],
        request.amount,
    ).map_err(|e| ApiError::InstructionError(format!("Failed to create token transfer instruction: {}", e)))?;
    
    convert_instruction_to_token_response(instruction)
}

fn convert_instruction_to_response(instruction: Instruction) -> Result<InstructionResponse, ApiError> {
    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| AccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
            is_writable: acc.is_writable,
        })
        .collect();
    
    Ok(InstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    })
}

fn convert_instruction_to_token_response(instruction: Instruction) -> Result<TokenInstructionResponse, ApiError> {
    let accounts = instruction
        .accounts
        .iter()
        .map(|acc| TokenAccountInfo {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        })
        .collect();
    
    Ok(TokenInstructionResponse {
        program_id: instruction.program_id.to_string(),
        accounts,
        instruction_data: general_purpose::STANDARD.encode(&instruction.data),
    })
}