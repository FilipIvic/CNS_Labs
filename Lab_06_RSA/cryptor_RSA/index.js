const { default: axios } = require("axios");
const crypto = require("crypto")

//---------------------------------------------------
// Send signed DH public key
//---------------------------------------------------

async function sendSignedDHPublicKey(key, signature, url="http://localhost:3000/asymmetric/dh/client"){

    await axios.post(url, {key, signature});
}

//---------------------------------------------------
// Send a public RSA key to server
//---------------------------------------------------

async function sendRSAPublicKey(key, url="http://localhost:3000/asymmetric/rsa/client"){

    await axios.post(url, {key});
}

//---------------------------------------------------
// GET a public RSA key from server
//---------------------------------------------------

async function getRSAPublicKey(url="http://localhost:3000/asymmetric/rsa/server"){

    const response = await axios.get(url);
    return response.data;
}

//---------------------------------------------------
// GET the challenge from server
//---------------------------------------------------

async function getChallenge(url="http://localhost:3000/asymmetric/dh-challenge/server"){

    const response = await axios.get(url);
    return response.data;
}

//---------------------------------------------------
// Generate public/private RSA key pair
//---------------------------------------------------

function generateRSAKeyPair() {
    const RSAKeyPairOptions = {
        modulusLength: 2048,
        publicKeyEncoding: {
          type: 'pkcs1',
          format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs1',
            format: 'pem'
        }
      };

    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", RSAKeyPairOptions);

    return { publicKey, privateKey };
}

//---------------------------------------------------
// Generate public/private DH key pair
//---------------------------------------------------

function generateDHKeyPair() {
    const DH = crypto.getDiffieHellman("modp15")
    DH.generateKeys();
    return DH;
}

//---------------------------------------------------
// Sign a message using RSA
//---------------------------------------------------

function signWithRSA(message, RSAPrivateKey){
    const sign = crypto.createSign("RSA-SHA256");
    sign.write(message);
    sign.end();
    const signature = sign.sign(RSAPrivateKey, "hex");

    return signature;
}

//---------------------------------------------------
// Verify RSA signature
//---------------------------------------------------

function verifyRSASignature(message , signature, RSAPublicKey){
    const verify = crypto.createVerify("RSA-SHA256");
    verify.write(message);
    verify.end();
    const signature_valid = verify.verify(Buffer.from(RSAPublicKey, "hex"), signature, "hex");

    if(!signature_valid){throw Error("Invalid signature!!")};

    return true;
}

//---------------------------------------------------
// Decryptor
//---------------------------------------------------

function decrypt({mode, key, iv = Buffer.alloc(0), ciphertext, padding = true, inputEncoding = "hex", outputEncoding = "utf8"}) {
    const decipher = crypto.createDecipheriv(mode, key, iv);
    decipher.setAutoPadding(padding);

    let plaintext = decipher.update(ciphertext, inputEncoding, outputEncoding);
    plaintext += decipher.final(outputEncoding);
    
    return { plaintext };
}


//---------------------------------------------------
// main()
//---------------------------------------------------

async function main() {
    // STEP 0: Generate public/private key pairs
    const { publicKey: clientRSAPublicKey, privateKey: clientRSAPrivateKey } = generateRSAKeyPair();
    // console.log(clientRSAPublicKey);
    // console.log(clientRSAPrivateKey);

    const clientDHKeyPair = generateDHKeyPair();
    // console.log("-----BEGIN DH parameters/key-----")
    // console.log("Group generator: ", clientDHKeyPair.getGenerator("hex"));
    // console.log("Group prime: ", clientDHKeyPair.getPrime("hex"));
    // console.log("DH public key: ", clientDHKeyPair.getPublicKey("hex"));
    // console.log("DH private key: ", clientDHKeyPair.getPrivateKey("hex"));
    // console.log("-----END DH parameters/key-----")

    // STEP 1: Send RSA_pub_C to server
    await sendRSAPublicKey(Buffer.from(clientRSAPublicKey).toString("hex"));

    // STEP 2: Get RSA_pub_S from server
    const { key: serverRSAPublicKey } = await getRSAPublicKey();
    // console.log(Buffer.from(serverRSAPublicKey, "hex").toString());

    // STEP 3: Send DH_pub_C signed RSA_priv_C
    let signature = signWithRSA(clientDHKeyPair.getPublicKey("hex"), clientRSAPrivateKey);
    // console.log(signature);
    await sendSignedDHPublicKey(clientDHKeyPair.getPublicKey("hex"), signature);

    // STEP 4: Get DH_pub_S and encrypted challenge
    const response = await getChallenge();
    // console.log(response);

    const serverDHPublicKey = response.key;
    signature = response.signature;
    const challenge = response.challenge;

    // STEP 5: Verify server's signature
    verifyRSASignature(serverDHPublicKey + clientDHKeyPair.getPublicKey("hex"), signature, serverRSAPublicKey)

    //---------------------------------------------------
    // Compute a DH shared key/secret between S and C,
    // and use it to dervie a 256bit AES key
    //---------------------------------------------------

    const DHSharedKey = clientDHKeyPair.computeSecret(Buffer.from(serverDHPublicKey, "hex"));
    // console.log(DHSharedKey.toString("hex"));

    const derivedAESKey = crypto.pbkdf2Sync(DHSharedKey, "ServerClient", 1, 32, "sha512");
    // console.log(derivedAESKey);

    //---------------------------------------------------
    // Finally, decrypt the challenge with derived key
    //---------------------------------------------------

    const { plaintext } = decrypt({
        mode: "aes-256-ctr",
        iv: Buffer.from(challenge.iv, "hex"),
        key: derivedAESKey,
        ciphertext: challenge.ciphertext
    });
    
    // Voila!
    console.log("\n");
    console.log("CHALLENGE:", challenge);
    console.log("\n");
    console.log("PLAINTEXT:", plaintext);
    console.log("\n");

}

main();