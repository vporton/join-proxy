use chrono::{DateTime, Utc};
use diesel::prelude::*;

use crate::schema::refresh_tokens;

#[derive(Insertable)]
#[diesel(table_name = refresh_tokens)]
pub struct NewRefreshToken {
    pub token_hash: Vec<u8>,
    pub owner_principal: String,
    pub client_id: String,
    pub scope: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
