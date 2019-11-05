'use strict';
const PasswordStorage = require('../PasswordStorage');


// Make sure truncated hashes don't validate.
function truncatedHashTest() {
    var uservar = "password!";
    var goodHash = "";
    var badHash = "";
    var badHashLength = 0;

    try {
        goodHash = PasswordStorage.createHash(uservar);
    } catch (error) {
        console.log(e.getMessage());
        return false;
    }
    badHashLength = goodHash.length;

    do {
        badHashLength -= 1;
        badHash = goodHash.substring(0, badHashLength);

        var raised = false;
        try {
            PasswordStorage.verifyPassword(uservar, badHash);
        } catch (e){
            if (e instanceof PasswordStorage.InvalidHashException){
                raised = true;
            }else{
                console.log(e.getMessage());
            return false;
            }
        }

        if (!raised) {
            console.log("Truncated hash test: FAIL " +
                "(At hash length of " +
                badHashLength + ")"
                );
            return false;
        }

    // The loop goes on until it is two characters away from the last : it
    // finds. This is because the PBKDF2 function requires a hash that's at
    // least 2 characters long.
    } while (badHash.charAt(badHashLength - 3) != ':');

    console.log("Truncated hash test: pass");
}

/**
 * Tests the basic functionality of the PasswordStorage class
 */
function basicTests()
{
    try
    {
        // Test password validation
        var failure = false;
        for(var i = 0; i < 10; i++)
        {
            var password = ""+i;
            var hash = PasswordStorage.createHash(password);
            var secondHash = PasswordStorage.createHash(password);
            if(hash===secondHash) {
                console.log("FAILURE: TWO HASHES ARE EQUAL!");
                failure = true;
            }
            var wrongPassword = ""+(i+1);
            if(PasswordStorage.verifyPassword(wrongPassword, hash)) {
                console.log("FAILURE: WRONG PASSWORD ACCEPTED!");
                failure = true;
            }
            if(!PasswordStorage.verifyPassword(password, hash)) {
                console.log("FAILURE: GOOD PASSWORD NOT ACCEPTED!");
                failure = true;
            }
        }
        if(failure) {
            console.log("TESTS FAILED!");
            return false;
        }
    }
    catch(error)
    {
        console.log("ERROR: " + error);
        return false;
    }
}

function testHashFunctionChecking()
{
    try {
        var hash = PasswordStorage.createHash("foobar");
        hash = hash.replace("sha1:", "sha256:");

        var raised = false;
        try {
            PasswordStorage.verifyPassword("foobar", hash);
        } catch (e){
            if (e instanceof PasswordStorage.CannotPerformOperationException) {
            raised = true;
            }
        }

        if (raised) {
            console.log("Algorithm swap: pass");
        } else {
            console.log("Algorithm swap: FAIL");
            return false;
        }
    } catch (e) {
        console.error(e);
        return false;
    }

}


basicTests();
truncatedHashTest();
testHashFunctionChecking();