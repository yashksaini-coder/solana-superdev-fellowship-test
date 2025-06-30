use axum::{extract::Json, response::Json as ResponseJson};
use crate::errors::ApiError;
use crate::models::*;
use crate::solana;
use tracing::info;

// Generate keypair endpoint
pub async fn generate_keypair() -> Result<ResponseJson<ApiResponse<KeypairResponse>>, ApiError> {
    info!("Generating new keypair");
    
    let keypair = solana::generate_keypair()?;
    
    info!("Keypair generated successfully");
    Ok(ResponseJson(ApiResponse::success(keypair)))
}

// Create token endpoint
pub async fn create_token(
    Json(payload): Json<CreateTokenRequest>,
) -> Result<ResponseJson<ApiResponse<InstructionResponse>>, ApiError> {
    info!("Creating token with mint: {}", payload.mint);
    
    // Validate all required fields upfront
    if payload.mint_authority.trim().is_empty() {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    if payload.mint.trim().is_empty() {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    
    let instruction = solana::create_token_instruction(payload)?;
    
    info!("Token creation instruction generated successfully");
    Ok(ResponseJson(ApiResponse::success(instruction)))
}

// Mint token endpoint
pub async fn mint_token(
    Json(payload): Json<MintTokenRequest>,
) -> Result<ResponseJson<ApiResponse<InstructionResponse>>, ApiError> {
    info!("Minting tokens to: {}", payload.destination);
    
    // Validate all required fields upfront
    if payload.mint.trim().is_empty() {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    if payload.destination.trim().is_empty() {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    if payload.authority.trim().is_empty() {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    if payload.amount == 0 {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    
    let instruction = solana::create_mint_instruction(payload)?;
    
    info!("Token mint instruction generated successfully");
    Ok(ResponseJson(ApiResponse::success(instruction)))
}

// Sign message endpoint
pub async fn sign_message(
    Json(payload): Json<SignMessageRequest>,
) -> Result<ResponseJson<ApiResponse<SignMessageResponse>>, ApiError> {
    info!("Signing message");
    
    // Validate all required fields upfront
    if payload.message.trim().is_empty() {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    if payload.secret.trim().is_empty() {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    
    let result = solana::sign_message(payload)?;
    
    info!("Message signed successfully");
    Ok(ResponseJson(ApiResponse::success(result)))
}

// Verify message endpoint
pub async fn verify_message(
    Json(payload): Json<VerifyMessageRequest>,
) -> Result<ResponseJson<ApiResponse<VerifyMessageResponse>>, ApiError> {
    info!("Verifying message signature");
    
    // Validate all required fields upfront
    if payload.message.trim().is_empty() {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    if payload.signature.trim().is_empty() {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    if payload.pubkey.trim().is_empty() {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    
    let result = solana::verify_message(payload)?;
    
    info!("Message verification completed");
    Ok(ResponseJson(ApiResponse::success(result)))
}

// Send SOL endpoint
pub async fn send_sol(
    Json(payload): Json<SendSolRequest>,
) -> Result<ResponseJson<ApiResponse<SolInstructionResponse>>, ApiError> {
    info!("Creating SOL transfer from {} to {}", payload.from, payload.to);
    
    // Validate all required fields upfront
    if payload.from.trim().is_empty() {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    if payload.to.trim().is_empty() {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    if payload.lamports == 0 {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    
    let instruction = solana::create_sol_transfer_instruction(payload)?;
    
    info!("SOL transfer instruction generated successfully");
    Ok(ResponseJson(ApiResponse::success(instruction)))
}

// Send token endpoint
pub async fn send_token(
    Json(payload): Json<SendTokenRequest>,
) -> Result<ResponseJson<ApiResponse<TokenInstructionResponse>>, ApiError> {
    info!("Creating token transfer to: {}", payload.destination);
    
    // Validate all required fields upfront
    if payload.destination.trim().is_empty() {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    if payload.mint.trim().is_empty() {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    if payload.owner.trim().is_empty() {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    if payload.amount == 0 {
        return Err(ApiError::InvalidInput("Missing required fields".to_string()));
    }
    
    let instruction = solana::create_token_transfer_instruction(payload)?;
    
    info!("Token transfer instruction generated successfully");
    Ok(ResponseJson(ApiResponse::success(instruction)))
}