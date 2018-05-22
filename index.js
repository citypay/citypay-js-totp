const CryptoJS = require("crypto-js");

let TOTP = function () {
};

//                   0  1   2    3     4      5       6        7         8
const DigitsPower = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000];
const T0 = 0;
const DefaultReturnDigits = '6';
const X = 30;

function wordToByteArray(word, length) {
    let ba = [];
    if (length > 0) {
        ba.push(word >>> 24);
    }
    if (length > 1) {
        ba.push((word >>> 16) & 0xFF);
    }
    if (length > 2) {
        ba.push((word >>> 8) & 0xFF);
    }
    if (length > 3) {
        ba.push(word & 0xFF);
    }
    return ba;
}

function wordArrayToByteArray(wordArray, length) {
    if (wordArray.hasOwnProperty("sigBytes") && wordArray.hasOwnProperty("words")) {
        length = wordArray.sigBytes;
        wordArray = wordArray.words;
    }
    let result = [], bytes, i = 0;
    while (length > 0) {
        bytes = wordToByteArray(wordArray[i], Math.min(4, length));
        length -= bytes.length;
        result.push(bytes);
        i++;
    }
    return [].concat.apply([], result);
}

TOTP.prototype.generateSteps = function (utc, t0 = T0) {
    let T = Math.floor((utc - t0) / X);

    return T.toString(16).padStart(16, '0').toUpperCase();
};

let hmacSHA1 = (msg, k) => CryptoJS.HmacSHA1(msg, k);
let hmacSHA256 = (msg, k) => CryptoJS.HmacSHA256(msg, k);
let hmacSHA512 = (msg, k) => CryptoJS.HmacSHA512(msg, k);

TOTP.prototype.generateTOTP = function (key, steps, returnDigits, algorithm = hmacSHA1) {
    if (steps.length !== 16) {
        throw new Error('Steps should be 16 digits');
    }
    let codeDigits = parseInt(returnDigits);
    let msg = CryptoJS.enc.Hex.parse(steps);
    let k = CryptoJS.enc.Hex.parse(key);

    let hash = wordArrayToByteArray(algorithm(msg, k));
    let offset = hash[hash.length - 1] & 0xf;
    let binary = ((hash[offset] & 0x7f) << 24) |
        ((hash[offset + 1] & 0xff) << 16) |
        ((hash[offset + 2] & 0xff) << 8) |
        ((hash[offset + 3] & 0xff));

    let otp = binary % DigitsPower[codeDigits];
    let result = otp.toString(10);

    return result.padStart(codeDigits, "0");
};

TOTP.prototype.generateTOTP256 = function (key, steps, returnDigits) {
    return this.generateTOTP(key, steps, returnDigits, hmacSHA256);
};

TOTP.prototype.generateTOTP512 = function (key, steps, returnDigits) {
    return this.generateTOTP(key, steps, returnDigits, hmacSHA512);
};

TOTP.prototype.validateSHA1 = function (key, totp,
                                        time = Date.now() / 1000,
                                        returnDigits = DefaultReturnDigits,
                                        transmissionDelayWindow = 1) {
    return this.validate(key, totp, time, returnDigits, transmissionDelayWindow, hmacSHA1);
};

TOTP.prototype.validateSHA256 = function (key,
                                          totp,
                                          time = Date.now() / 1000,
                                          returnDigits = DefaultReturnDigits,
                                          transmissionDelayWindow = 1) {
    return this.validate(key, totp, time, returnDigits, transmissionDelayWindow, hmacSHA256);
};

TOTP.prototype.validateSHA512 = function (key,
                                          totp,
                                          time = Date.now() / 1000,
                                          returnDigits = DefaultReturnDigits,
                                          transmissionDelayWindow = 1) {
    return this.validate(key, totp, time, returnDigits, transmissionDelayWindow, hmacSHA512);
};

TOTP.prototype.validate = function (key, totp,
                                    time = Date.now() / 1000,
                                    returnDigits = DefaultReturnDigits,
                                    transmissionDelayWindow = 1,
                                    algorithm) {
    if (algorithm === "HmacSHA1") {
        algorithm = hmacSHA1;
    }
    else if (algorithm === "HmacSHA256") {
        algorithm = hmacSHA256;
    }
    else if (algorithm === "HmacSHA512") {
        algorithm = hmacSHA512;
    }
    let i;
    for (i = 0; i <= transmissionDelayWindow; i++) {
        let steps = this.generateSteps(time - (i * X), T0);
        let result = this.generateTOTP(key, steps, returnDigits, algorithm);
        if (result === totp) {
            return true;
        }
    }
    return false;
};
exports.TOTP = new TOTP();