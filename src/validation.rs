use crate::errors::ServiceError;

pub fn normalize_currency(currency: &str) -> Result<String, ServiceError> {
    let trimmed = currency.trim();
    if trimmed.len() != 3 || !trimmed.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(ServiceError::InvalidInput(
            "Currency must be a 3-letter ISO 4217 code".to_string(),
        ));
    }
    Ok(trimmed.to_uppercase())
}

pub fn validate_quantity(quantity: i32) -> Result<(), ServiceError> {
    if quantity <= 0 {
        return Err(ServiceError::InvalidInput(
            "Quantity must be greater than 0".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_checkout_id(expected: &str, provided: &str) -> Result<(), ServiceError> {
    if expected != provided {
        return Err(ServiceError::InvalidInput(
            "Checkout id does not match URL".to_string(),
        ));
    }
    Ok(())
}
