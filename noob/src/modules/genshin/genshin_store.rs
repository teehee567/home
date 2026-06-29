use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "wish_record")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub uid: String,
    pub gacha_type: String,
    pub item_id: String,
    pub count: String,
    pub time: String,
    pub name: String,
    pub item_type: String,
    pub rank_type: String,
    pub lang: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
