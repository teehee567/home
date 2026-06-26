use sea_orm::entity::prelude::*;

// per user opaque creds
#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "opaque_user")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub username: String,
    pub registration_record: Vec<u8>,
    pub at_rest_blob: Vec<u8>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
