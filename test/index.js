let expect = require('chai').expect;
let TOTP = require('../index').TOTP;

describe('js TOTP', function () {
    let testToken = '3132333435363738393031323334353637383930';
    it('should generate steps', function () {
        // get current utc
        // new Date().getTime()/1000 or Date.now()/1000
        expect('0000000000000001').to.be.equal(TOTP.generateSteps(59));
        expect('0000000000000002').to.be.equal(TOTP.generateSteps(60));
        expect('00000000023523EC').to.be.equal(TOTP.generateSteps(1111111109));
        expect('00000000023523ED').to.be.equal(TOTP.generateSteps(1111111111));
        expect('000000000273EF07').to.be.equal(TOTP.generateSteps(1234567890));
        expect('0000000003F940AA').to.be.equal(TOTP.generateSteps(2000000000));
        expect('0000000027BC86AA').to.be.equal(TOTP.generateSteps(20000000000));
    });

    it('should generate SHA1 TOTP', function () {
        expect('94287082').to.be.equal(TOTP.generateTOTP(testToken,TOTP.generateSteps(59),'8'));

    });

});