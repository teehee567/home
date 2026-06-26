use sea_orm::entity::prelude::*;

// node identity keys
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "node_identity")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i32,
    pub noise_private: Vec<u8>,
    pub noise_public: Vec<u8>,
    pub ml_kem_dk: Vec<u8>,
    pub ml_kem_ek: Vec<u8>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

// single row id
pub const ROW_ID: i32 = 1;
