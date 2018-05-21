const CryptoJS = require("crypto-js");

let TOTP = function () {};
//                   0  1   2    3     4      5       6        7         8
const DigitsPower = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000];
const T0 = 0;
const DefaultReturnDigits = '6';
const X = 30;

TOTP.prototype.generateSteps = function(utc, t0 = T0)
{
    let T = Math.floor((utc - t0) / X);

    return T.toString(16).padStart(16, '0').toUpperCase();
};

TOTP.prototype.generateTOTP = function(key, steps, returnDigits, algorithm = 'HmacSHA1'){
    if (steps.length!==16){
        throw new Error('Steps should be 16 digits');
    }
    const codeDigits = parseInt(returnDigits);

    return (CryptoJS.HmacSHA1(steps, key).toString())
};




//-------------------
let sha1 = (message, key) => CryptoJS.HmacSHA1(message, key);

function eg(message, key, cryptoFn) {
    cryptoFn(message, key);
}

function srcSha1(message, key) {

    eq(message, key, () => CryptoJS.HmacSHA1(message, key));
}

exports.TOTP = new TOTP();