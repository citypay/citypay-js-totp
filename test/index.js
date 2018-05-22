"use strict";
let expect = require('chai').expect;
let TOTP = require('../index').TOTP;

describe('js Generate TOTP', function () {
    "use strict";
    let testTokenSHA1 = '3132333435363738393031323334353637383930';
    let testTokenSHA256 = '3132333435363738393031323334353637383930313233343536373839303132';
    let testTokenSHA512 =
        '3132333435363738393031323334353637383930' +
        '3132333435363738393031323334353637383930' +
        '3132333435363738393031323334353637383930' +
        '31323334';

    it('should generate steps', function () {
        // get current utc
        // new Date().getTime()/1000 or Date.now()/1000
        console.log('Generating Steps');
        expect('0000000000000001').to.be.equal(TOTP.generateSteps(59));
        expect('0000000000000002').to.be.equal(TOTP.generateSteps(60));
        expect('00000000023523EC').to.be.equal(TOTP.generateSteps(1111111109));
        expect('00000000023523ED').to.be.equal(TOTP.generateSteps(1111111111));
        expect('000000000273EF07').to.be.equal(TOTP.generateSteps(1234567890));
        expect('0000000003F940AA').to.be.equal(TOTP.generateSteps(2000000000));
        expect('0000000027BC86AA').to.be.equal(TOTP.generateSteps(20000000000));
    });

    it('should generate SHA1 TOTP', function () {
        console.log('Generating SHA1 TOTP');
        expect('94287082').to.be.equal(TOTP.generateTOTP(testTokenSHA1, TOTP.generateSteps(59), '8'));
        expect('07081804').to.be.equal(TOTP.generateTOTP(testTokenSHA1, TOTP.generateSteps(1111111109), '8'));
        expect('14050471').to.be.equal(TOTP.generateTOTP(testTokenSHA1, TOTP.generateSteps(1111111111), '8'));
        expect('89005924').to.be.equal(TOTP.generateTOTP(testTokenSHA1, TOTP.generateSteps(1234567890), '8'));
        expect('69279037').to.be.equal(TOTP.generateTOTP(testTokenSHA1, TOTP.generateSteps(2000000000), '8'));
        expect('65353130').to.be.equal(TOTP.generateTOTP(testTokenSHA1, TOTP.generateSteps(20000000000), '8'));
    });

    it('should generate SHA256 TOTP', function () {
        console.log('Generating SHA256 TOTP');
        expect('46119246').to.be.equal(TOTP.generateTOTP256(testTokenSHA256, TOTP.generateSteps(59), '8'));
        expect('68084774').to.be.equal(TOTP.generateTOTP256(testTokenSHA256, TOTP.generateSteps(1111111109), '8'));
        expect('67062674').to.be.equal(TOTP.generateTOTP256(testTokenSHA256, TOTP.generateSteps(1111111111), '8'));
        expect('91819424').to.be.equal(TOTP.generateTOTP256(testTokenSHA256, TOTP.generateSteps(1234567890), '8'));
        expect('90698825').to.be.equal(TOTP.generateTOTP256(testTokenSHA256, TOTP.generateSteps(2000000000), '8'));
        expect('77737706').to.be.equal(TOTP.generateTOTP256(testTokenSHA256, TOTP.generateSteps(20000000000), '8'));
    });

    it('should generate SHA512 TOTP', function () {
        console.log('Generating SHA512 TOTP');
        expect('90693936').to.be.equal(TOTP.generateTOTP512(testTokenSHA512, TOTP.generateSteps(59), '8'));
        expect('25091201').to.be.equal(TOTP.generateTOTP512(testTokenSHA512, TOTP.generateSteps(1111111109), '8'));
        expect('99943326').to.be.equal(TOTP.generateTOTP512(testTokenSHA512, TOTP.generateSteps(1111111111), '8'));
        expect('93441116').to.be.equal(TOTP.generateTOTP512(testTokenSHA512, TOTP.generateSteps(1234567890), '8'));
        expect('38618901').to.be.equal(TOTP.generateTOTP512(testTokenSHA512, TOTP.generateSteps(2000000000), '8'));
        expect('47863826').to.be.equal(TOTP.generateTOTP512(testTokenSHA512, TOTP.generateSteps(20000000000), '8'));
    });

});

describe('js Validate TOTP', function () {
    "use strict";
    let testTokenSHA1 = '3132333435363738393031323334353637383930';
    let testTokenSHA256 = '3132333435363738393031323334353637383930313233343536373839303132';
    let testTokenSHA512 =
        '3132333435363738393031323334353637383930' +
        '3132333435363738393031323334353637383930' +
        '3132333435363738393031323334353637383930' +
        '31323334';

    it('should validate SHA1 TOTP', function () {
        console.log('Validating SHA1 TOTP');
        expect(true).to.be.equal(TOTP.validateSHA1(testTokenSHA1, "94287082", 59, "8"));
        expect(true).to.be.equal(TOTP.validateSHA1(testTokenSHA1, "94287082", 30, "8"));
        expect(true).to.be.equal(TOTP.validate(testTokenSHA1, "94287082", 30, "8",1,"HmacSHA1"));
    });

    it('should validate SHA1 TOTP with delay', function () {
        console.log('Validating SHA1 TOTP with delay');
        expect(true).to.be.equal(TOTP.validateSHA1(testTokenSHA1, "94287082", 89, "8",1));
        expect(false).to.be.equal(TOTP.validateSHA1(testTokenSHA1, "94287082", 90, "8",1));
        expect(true).to.be.equal(TOTP.validateSHA1(testTokenSHA1, "94287082", 90, "8",2));
    });

    it('should validate SHA256 TOTP', function () {
        console.log('Validating SHA256 TOTP');
        expect(true).to.be.equal(TOTP.validateSHA256(testTokenSHA256, "46119246", 59, "8"));
        expect(true).to.be.equal(TOTP.validateSHA256(testTokenSHA256, "46119246", 30, "8"));
        expect(true).to.be.equal(TOTP.validate(testTokenSHA256, "46119246", 30, "8",1,"HmacSHA256"));
    });

    it('should validate SHA256 TOTP with delay', function () {
        console.log('Validating SHA256 TOTP with delay');
        expect(true).to.be.equal(TOTP.validateSHA256(testTokenSHA256, "46119246", 89, "8",1));
        expect(false).to.be.equal(TOTP.validateSHA256(testTokenSHA256, "46119246", 90, "8",1));
        expect(true).to.be.equal(TOTP.validateSHA256(testTokenSHA256, "46119246", 90, "8",2));
    });

    it('should validate SHA512 TOTP', function () {
        console.log('Validating SHA512 TOTP');
        expect(true).to.be.equal(TOTP.validateSHA512(testTokenSHA512, "90693936", 59, "8"));
        expect(true).to.be.equal(TOTP.validateSHA512(testTokenSHA512, "90693936", 30, "8"));
        expect(true).to.be.equal(TOTP.validate(testTokenSHA512, "90693936", 30, "8",1,"HmacSHA512"));

    });

    it('should validate SHA512 TOTP with delay', function () {
        console.log('Validating SHA512 TOTP with delay');
        expect(true).to.be.equal(TOTP.validateSHA512(testTokenSHA512, "90693936", 89, "8",1));
        expect(false).to.be.equal(TOTP.validateSHA512(testTokenSHA512, "90693936", 90, "8",1));
        expect(true).to.be.equal(TOTP.validateSHA512(testTokenSHA512, "90693936", 90, "8",2));
    });

});