//! Product Catalog
//!
//! Hybrid product catalog that uses iCommerce Products + Inventory APIs
//! with fallback to static products for legacy/testing mode.

use crate::commerce::CommerceEngine;
use crate::commerce_adapter::decimal_to_cents;
use crate::errors::ServiceError;
use rust_decimal::Decimal;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Product representation for UCP checkout
#[derive(Debug, Clone)]
pub struct Product {
    pub id: String,
    pub title: String,
    pub price: i64,      // In cents
    pub currency: String,
    pub image_url: Option<String>,
    pub inventory: i32,
}

/// Product catalog with optional iCommerce backend
#[derive(Clone)]
pub struct ProductCatalog {
    /// iCommerce engine for real product/inventory data
    commerce: Option<CommerceEngine>,
    /// Fallback static products (for testing or legacy mode)
    static_products: Arc<RwLock<HashMap<String, Product>>>,
    /// Default currency when not specified
    default_currency: String,
}

impl ProductCatalog {
    /// Create a new ProductCatalog with iCommerce backend
    pub fn new_with_commerce(commerce: CommerceEngine) -> Self {
        Self {
            commerce: Some(commerce),
            static_products: Arc::new(RwLock::new(HashMap::new())),
            default_currency: "USD".to_string(),
        }
    }

    /// Create a ProductCatalog with static products (for testing/legacy)
    pub fn new() -> Self {
        let mut products = HashMap::new();

        // Default demo products
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
            commerce: None,
            static_products: Arc::new(RwLock::new(products)),
            default_currency: "USD".to_string(),
        }
    }

    /// Get a product by ID (SKU)
    ///
    /// First tries iCommerce, then falls back to static products
    pub fn get(&self, product_id: &str) -> Result<Product, ServiceError> {
        // Try iCommerce first
        if let Some(ref commerce) = self.commerce {
            if let Some(product) = self.get_from_icommerce(commerce, product_id)? {
                return Ok(product);
            }
        }

        // Fall back to static products
        self.get_from_static(product_id)
    }

    /// Check if there's sufficient inventory for the product
    pub fn check_inventory(&self, product_id: &str, quantity: i32) -> Result<(), ServiceError> {
        // Try iCommerce first
        if let Some(ref commerce) = self.commerce {
            let has_stock = commerce.inventory()
                .has_stock(product_id, Decimal::from(quantity))
                .map_err(|e| ServiceError::Internal(e.to_string()))?;

            if !has_stock {
                // Get actual stock level for better error message
                if let Ok(Some(stock)) = commerce.inventory().get_stock(product_id) {
                    return Err(ServiceError::InvalidInput(format!(
                        "Item {} has only {} units remaining",
                        product_id,
                        stock.total_available.round()
                    )));
                }
                return Err(ServiceError::InvalidInput(format!(
                    "Insufficient stock for item {}",
                    product_id
                )));
            }
            return Ok(());
        }

        // Fall back to static inventory check
        let product = self.get_from_static(product_id)?;
        if quantity > product.inventory {
            return Err(ServiceError::InvalidInput(format!(
                "Item {} has only {} units remaining",
                product_id, product.inventory
            )));
        }
        Ok(())
    }

    /// Get product from iCommerce
    fn get_from_icommerce(
        &self,
        commerce: &CommerceEngine,
        sku: &str,
    ) -> Result<Option<Product>, ServiceError> {
        // Try to get product variant by SKU
        let variant = commerce.products()
            .get_variant_by_sku(sku)
            .map_err(|e| ServiceError::Internal(e.to_string()))?;

        if let Some(variant) = variant {
            // Get inventory level
            let inventory = commerce.inventory()
                .get_stock(sku)
                .map_err(|e| ServiceError::Internal(e.to_string()))?
                .map(|stock| stock.total_available.round().to_string().parse::<i32>().unwrap_or(0))
                .unwrap_or(0);

            return Ok(Some(Product {
                id: variant.sku,
                title: variant.name,
                price: decimal_to_cents(variant.price),
                currency: self.default_currency.clone(),
                image_url: None, // ProductVariant doesn't have image_url
                inventory,
            }));
        }

        Ok(None)
    }

    /// Get product from static catalog
    fn get_from_static(&self, product_id: &str) -> Result<Product, ServiceError> {
        let products = self.static_products.read().map_err(|_| {
            ServiceError::Internal("Failed to read product catalog".to_string())
        })?;
        products
            .get(product_id)
            .cloned()
            .ok_or_else(|| ServiceError::InvalidInput(format!("Unknown item id {}", product_id)))
    }

    /// Add a static product (for testing)
    #[cfg(test)]
    pub fn add_static_product(&self, product: Product) -> Result<(), ServiceError> {
        let mut products = self.static_products.write().map_err(|_| {
            ServiceError::Internal("Failed to write product catalog".to_string())
        })?;
        products.insert(product.id.clone(), product);
        Ok(())
    }
}

impl Default for ProductCatalog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_static_product() {
        let catalog = ProductCatalog::new();

        let product = catalog.get("item_123").unwrap();
        assert_eq!(product.id, "item_123");
        assert_eq!(product.title, "Red T-Shirt");
        assert_eq!(product.price, 2500);
    }

    #[test]
    fn test_get_unknown_product() {
        let catalog = ProductCatalog::new();

        let result = catalog.get("unknown_item");
        assert!(result.is_err());
    }

    #[test]
    fn test_check_inventory_sufficient() {
        let catalog = ProductCatalog::new();

        let result = catalog.check_inventory("item_123", 10);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_inventory_insufficient() {
        let catalog = ProductCatalog::new();

        let result = catalog.check_inventory("item_123", 500);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_static_product() {
        let catalog = ProductCatalog::new();

        let product = Product {
            id: "test_item".to_string(),
            title: "Test Item".to_string(),
            price: 1000,
            currency: "USD".to_string(),
            image_url: None,
            inventory: 100,
        };

        catalog.add_static_product(product).unwrap();

        let retrieved = catalog.get("test_item").unwrap();
        assert_eq!(retrieved.title, "Test Item");
    }
}
