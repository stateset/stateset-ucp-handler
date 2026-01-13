//! Commerce Engine Wrapper
//!
//! Provides thread-safe access to the stateset-embedded Commerce instance.
//! This wrapper enables sharing the commerce engine across async handlers.

use std::sync::Arc;
use stateset_embedded::{
    Commerce, CommerceError,
    Carts, Orders, Products, Inventory, Promotions, Tax, Customers,
    Analytics, Payments, Shipments, Returns,
};

/// Thread-safe wrapper around the iCommerce engine
///
/// This wrapper provides:
/// - Shared ownership via Arc
/// - Access to all commerce APIs (carts, orders, products, etc.)
/// - Initialization from file path or in-memory database
#[derive(Clone)]
pub struct CommerceEngine {
    inner: Arc<Commerce>,
}

impl CommerceEngine {
    /// Create a new CommerceEngine with SQLite database at the given path
    ///
    /// # Arguments
    /// * `db_path` - Path to SQLite database file (created if not exists)
    ///               Use ":memory:" for in-memory database (testing)
    ///
    /// # Example
    /// ```ignore
    /// let engine = CommerceEngine::new("./commerce.db")?;
    /// let engine = CommerceEngine::new(":memory:")?; // for testing
    /// ```
    pub fn new(db_path: &str) -> Result<Self, CommerceError> {
        let commerce = Commerce::new(db_path)?;
        Ok(Self {
            inner: Arc::new(commerce),
        })
    }

    /// Create a new CommerceEngine from an existing Commerce instance
    pub fn from_commerce(commerce: Commerce) -> Self {
        Self {
            inner: Arc::new(commerce),
        }
    }

    // ========================================================================
    // Core Commerce APIs
    // ========================================================================

    /// Access the Carts API for checkout session management
    ///
    /// Provides: create, get, update, add_item, set_shipping, complete, etc.
    pub fn carts(&self) -> Carts {
        self.inner.carts()
    }

    /// Access the Orders API for order lifecycle management
    ///
    /// Provides: create, get, update_status, ship, deliver, cancel, etc.
    pub fn orders(&self) -> Orders {
        self.inner.orders()
    }

    /// Access the Products API for catalog management
    ///
    /// Provides: create, get, get_variant_by_sku, list, etc.
    pub fn products(&self) -> Products {
        self.inner.products()
    }

    /// Access the Inventory API for stock management
    ///
    /// Provides: get_stock, has_stock, adjust, reserve, confirm_reservation, etc.
    pub fn inventory(&self) -> Inventory {
        self.inner.inventory()
    }

    /// Access the Customers API for customer management
    ///
    /// Provides: create, get, get_by_email, find_or_create, etc.
    pub fn customers(&self) -> Customers {
        self.inner.customers()
    }

    // ========================================================================
    // Business Logic APIs
    // ========================================================================

    /// Access the Promotions API for discount and coupon management
    ///
    /// Provides: create, validate_coupon, apply, record_usage, etc.
    pub fn promotions(&self) -> Promotions {
        self.inner.promotions()
    }

    /// Access the Tax API for tax calculation
    ///
    /// Provides: calculate, get_effective_rate, jurisdiction management, etc.
    pub fn tax(&self) -> Tax {
        self.inner.tax()
    }

    /// Access the Analytics API for reporting
    ///
    /// Provides: sales_summary, top_products, demand_forecast, etc.
    pub fn analytics(&self) -> Analytics {
        self.inner.analytics()
    }

    // ========================================================================
    // Fulfillment APIs
    // ========================================================================

    /// Access the Payments API for payment processing
    ///
    /// Provides: create, get, refund, etc.
    pub fn payments(&self) -> Payments {
        self.inner.payments()
    }

    /// Access the Shipments API for shipping management
    ///
    /// Provides: create, add_event, update_status, etc.
    pub fn shipments(&self) -> Shipments {
        self.inner.shipments()
    }

    /// Access the Returns API for RMA management
    ///
    /// Provides: create, approve, reject, process, etc.
    pub fn returns(&self) -> Returns {
        self.inner.returns()
    }

    // ========================================================================
    // Convenience Methods
    // ========================================================================

    /// Get the underlying Commerce instance (for advanced use cases)
    pub fn inner(&self) -> &Commerce {
        &self.inner
    }
}

impl std::fmt::Debug for CommerceEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommerceEngine")
            .field("inner", &"Commerce { ... }")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commerce_engine_creation() {
        // Test in-memory database creation
        let engine = CommerceEngine::new(":memory:");
        assert!(engine.is_ok());
    }

    #[test]
    fn test_commerce_engine_clone() {
        let engine = CommerceEngine::new(":memory:").unwrap();
        let cloned = engine.clone();

        // Both should point to the same underlying Commerce instance
        assert!(std::ptr::eq(
            engine.inner.as_ref() as *const _,
            cloned.inner.as_ref() as *const _
        ));
    }
}
