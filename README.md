CityPay TOTP
============

[![Build Status](https://circleci.com/gh/citypay/citypay-js-totp.svg?&style=shield)](https://circleci.com/gh/citypay/citypay-js-totp)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/2b95d00edc1c445dbbc28126539d1c70)](https://www.codacy.com/app/CityPay/citypay-js-totp?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=citypay/citypay-js-totp&amp;utm_campaign=Badge_Grade)

The CityPay TOTP enables to generate and validate TOTP's.

### TOTP encryption
CityPay TOTP allows for HmacSHA1, HmacSHA256 and HmacSHA512 encryption

### TOTP validation
validates TOTP's and allows validation with a specified delay window or default value of 1

## Example Usage

```javascript
const TOTP = require("../index").TOTP;

...
//TOTP params
let token = '3132333435363738393031323334353637383930'
let time = Date.now() / 1000
let steps = TOTP.generateSteps(time)
let returnDigits = "8"

// Generate TOTP
let totp = TOTP.generateTOTP(token, steps, returnDigits)

// Validate TOTP
let isValid = TOTP.validateSHA1(token, totp, time, returnDigits)

```
