use serde::{Deserialize, Serialize};

// Standard API Response wrapper
#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn error(error: String) -> ApiResponse<()> {
        ApiResponse {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

// Keypair response
#[derive(Serialize)]
pub struct KeypairResponse {
    pub pubkey: String,
    pub secret: String,
}

// Token creation request
#[derive(Deserialize)]
pub struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    pub mint_authority: String,
    pub mint: String,
    pub decimals: u8,
}

// Token mint request
#[derive(Deserialize)]
pub struct MintTokenRequest {
    pub mint: String,
    pub destination: String,
    pub authority: String,
    pub amount: u64,
}

// Message signing request
#[derive(Deserialize)]
pub struct SignMessageRequest {
    pub message: String,
    pub secret: String,
}

// Message signing response
#[derive(Serialize)]
pub struct SignMessageResponse {
    pub signature: String,
    pub public_key: String,
    pub message: String,
}

// Message verification request
#[derive(Deserialize)]
pub struct VerifyMessageRequest {
    pub message: String,
    pub signature: String,
    pub pubkey: String,
}

// Message verification response
#[derive(Serialize)]
pub struct VerifyMessageResponse {
    pub valid: bool,
    pub message: String,
    pub pubkey: String,
}

// SOL transfer request
#[derive(Deserialize)]
pub struct SendSolRequest {
    pub from: String,
    pub to: String,
    pub lamports: u64,
}

// Token transfer request
#[derive(Deserialize)]
pub struct SendTokenRequest {
    pub destination: String,
    pub mint: String,
    pub owner: String,
    pub amount: u64,
}

// Account info for instruction responses
#[derive(Serialize)]
pub struct AccountInfo {
    pub pubkey: String,
    #[serde(rename = "is_signer")]
    pub is_signer: bool,
    #[serde(rename = "is_writable")]
    pub is_writable: bool,
}

// Account info for token transfer responses (matches task spec exactly)
#[derive(Serialize)]
pub struct TokenAccountInfo {
    pub pubkey: String,
    #[serde(rename = "isSigner")]
    pub is_signer: bool,
}

// Instruction response
#[derive(Serialize)]
pub struct InstructionResponse {
    pub program_id: String,
    pub accounts: Vec<AccountInfo>,
    pub instruction_data: String,
}

// Token transfer specific instruction response
#[derive(Serialize)]
pub struct TokenInstructionResponse {
    pub program_id: String,
    pub accounts: Vec<TokenAccountInfo>,
    pub instruction_data: String,
}

// Simplified instruction response for SOL transfers
#[derive(Serialize)]
pub struct SolInstructionResponse {
    pub program_id: String,
    pub accounts: Vec<String>,
    pub instruction_data: String,
}