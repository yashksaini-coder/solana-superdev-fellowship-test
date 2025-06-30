use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use crate::models::ApiResponse;

#[derive(Debug)]
pub enum ApiError {
    InvalidInput(String),
    InvalidPublicKey(String),
    InvalidSecretKey(String),
    InvalidSignature(String),
    VerificationError(String),
    InstructionError(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            ApiError::InvalidPublicKey(msg) => write!(f, "Invalid public key: {}", msg),
            ApiError::InvalidSecretKey(msg) => write!(f, "Invalid secret key: {}", msg),
            ApiError::InvalidSignature(msg) => write!(f, "Invalid signature: {}", msg),
            ApiError::VerificationError(msg) => write!(f, "Verification error: {}", msg),
            ApiError::InstructionError(msg) => write!(f, "Instruction error: {}", msg),
        }
    }
}

impl std::error::Error for ApiError {}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let error_msg = match &self {
            ApiError::InvalidInput(msg) if msg.contains("required") => "Missing required fields".to_string(),
            _ => self.to_string(),
        };
        
        // Return HTTP 400 for errors as per task specification
        let response_body = ApiResponse::<()>::error(error_msg);
        
        (StatusCode::BAD_REQUEST, Json(response_body)).into_response()
    }
}

impl From<solana_sdk::pubkey::ParsePubkeyError> for ApiError {
    fn from(err: solana_sdk::pubkey::ParsePubkeyError) -> Self {
        ApiError::InvalidPublicKey(err.to_string())
    }
}

impl From<bs58::decode::Error> for ApiError {
    fn from(err: bs58::decode::Error) -> Self {
        ApiError::InvalidInput(format!("Base58 decode error: {}", err))
    }
}

impl From<base64::DecodeError> for ApiError {
    fn from(err: base64::DecodeError) -> Self {
        ApiError::InvalidInput(format!("Base64 decode error: {}", err))
    }
}

impl From<ed25519_dalek::SignatureError> for ApiError {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        ApiError::VerificationError(err.to_string())
    }
}

impl From<spl_token::error::TokenError> for ApiError {
    fn from(err: spl_token::error::TokenError) -> Self {
        ApiError::InstructionError(format!("Token error: {}", err))
    }
}

impl From<solana_sdk::program_error::ProgramError> for ApiError {
    fn from(err: solana_sdk::program_error::ProgramError) -> Self {
        ApiError::InstructionError(format!("Program error: {}", err))
    }
}