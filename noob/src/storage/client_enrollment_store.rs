use sea_orm::entity::prelude::*;

// server pubkeys from enrollment
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "client_enrollment")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    pub server_noise_pubkey: Vec<u8>,
    pub server_ml_kem_pubkey: Vec<u8>,
    pub tls_cert_fingerprint: Vec<u8>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

// single row id
pub const ROW_ID: i32 = 1;
