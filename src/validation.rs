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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_currency_accepts_uppercase() {
        let value = normalize_currency("USD").unwrap();
        assert_eq!(value, "USD");
    }

    #[test]
    fn normalize_currency_normalizes_lowercase() {
        let value = normalize_currency("eur").unwrap();
        assert_eq!(value, "EUR");
    }

    #[test]
    fn normalize_currency_rejects_wrong_length() {
        let err = normalize_currency("US").unwrap_err();
        assert!(matches!(err, ServiceError::InvalidInput(_)));
    }

    #[test]
    fn normalize_currency_rejects_non_alpha() {
        let err = normalize_currency("U1D").unwrap_err();
        assert!(matches!(err, ServiceError::InvalidInput(_)));
    }

    #[test]
    fn validate_quantity_allows_positive() {
        assert!(validate_quantity(1).is_ok());
    }

    #[test]
    fn validate_quantity_rejects_zero() {
        let err = validate_quantity(0).unwrap_err();
        assert!(matches!(err, ServiceError::InvalidInput(_)));
    }

    #[test]
    fn validate_quantity_rejects_negative() {
        let err = validate_quantity(-5).unwrap_err();
        assert!(matches!(err, ServiceError::InvalidInput(_)));
    }

    #[test]
    fn validate_checkout_id_accepts_match() {
        assert!(validate_checkout_id("chk_123", "chk_123").is_ok());
    }

    #[test]
    fn validate_checkout_id_rejects_mismatch() {
        let err = validate_checkout_id("chk_123", "chk_456").unwrap_err();
        assert!(matches!(err, ServiceError::InvalidInput(_)));
    }
}
