# JWKS to PEM Converter

A minimal browser-based tool that converts a single JSON Web Key (JWK) to PEM (Privacy-Enhanced Mail) format. This tool runs entirely in your browser with no server required.

## Supported Key Types

### RSA Keys
```json
{
  "kty": "RSA",
  "e": "AQAB",
  "kid": "your-key-id",
  "n": "base64url-encoded-modulus"
}
```

### Elliptic Curve Keys
```json
{
  "kty": "EC",
  "crv": "P-256",
  "kid": "your-key-id",
  "x": "base64url-encoded-x-coordinate",
  "y": "base64url-encoded-y-coordinate"
}
```

Supported EC curves:
- P-256 (secp256r1)
- P-384 (secp384r1)
- P-521 (secp521r1)

## Usage

### Single Key Format
```json
{
  "kty": "RSA",
  "e": "AQAB",
  "kid": "my-key-id",
  "n": "jYSBylvVpnJIubCCfDL0gfjNG0VdnIZJoa4-ZueCHw6cew08u_fxliIG..."
}
```


## Disclaimer

⚠️ **This tool is intended for development and testing purposes only.** The author takes no responsibility for any issues that may arise from using this tool in production environments. Always validate and test cryptographic keys thoroughly before using them in production systems.


⚠️ This tool runs entirely in your browser - no data is transmitted to any external servers. Your keys remain private and secure on your local machine.

