use crate::errors::ServiceError;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone)]
pub struct Product {
    pub id: String,
    pub title: String,
    pub price: i64,
    pub currency: String,
    pub image_url: Option<String>,
    pub inventory: i32,
}

#[derive(Clone)]
pub struct ProductCatalog {
    products: Arc<RwLock<HashMap<String, Product>>>,
}

impl ProductCatalog {
    pub fn new() -> Self {
        let mut products = HashMap::new();

        products.insert(
            "item_123".to_string(),
            Product {
                id: "item_123".to_string(),
                title: "Red T-Shirt".to_string(),
                price: 2500,
                currency: "USD".to_string(),
                image_url: Some("https://example.com/images/red-shirt.jpg".to_string()),
                inventory: 250,
            },
        );

        products.insert(
            "laptop_pro_16_inch".to_string(),
            Product {
                id: "laptop_pro_16_inch".to_string(),
                title: "MacBook Pro 16".to_string(),
                price: 349900,
                currency: "USD".to_string(),
                image_url: Some("https://example.com/images/macbook-pro.jpg".to_string()),
                inventory: 12,
            },
        );

        products.insert(
            "wireless_mouse".to_string(),
            Product {
                id: "wireless_mouse".to_string(),
                title: "Wireless Mouse".to_string(),
                price: 7999,
                currency: "USD".to_string(),
                image_url: Some("https://example.com/images/wireless-mouse.jpg".to_string()),
                inventory: 500,
            },
        );

        Self {
            products: Arc::new(RwLock::new(products)),
        }
    }

    pub fn get(&self, product_id: &str) -> Result<Product, ServiceError> {
        let products = self.products.read().map_err(|_| {
            ServiceError::Internal("Failed to read product catalog".to_string())
        })?;
        products
            .get(product_id)
            .cloned()
            .ok_or_else(|| ServiceError::InvalidInput(format!("Unknown item id {}", product_id)))
    }

    pub fn check_inventory(&self, product_id: &str, quantity: i32) -> Result<(), ServiceError> {
        let product = self.get(product_id)?;
        if quantity > product.inventory {
            return Err(ServiceError::InvalidInput(format!(
                "Item {} has only {} units remaining",
                product_id, product.inventory
            )));
        }
        Ok(())
    }
}

impl Default for ProductCatalog {
    fn default() -> Self {
        Self::new()
    }
}
