const axios = require("axios");

async function getChallenge() {
  try {
    const response = await axios.get("http://localhost:3000/ctr/challenge");
    return response.data;
  } catch (error) {
    console.error(error.message);
  }
}

async function queryCryptoOracle({
  url = "http://localhost:3000/ctr",
  plaintext = "",
} = {}) {
  try {
    const response = await axios.post(url, {
      plaintext,
    });

    return response.data;
  } catch (error) {
    console.error(error.message);
  }
}

function xor(buf1, buf2) {
    const result = Buffer.alloc(buf1.length);

    for (let i = 0; i < buf1.length; i++) {
        result[i] = buf1[i] ^ buf2[i];
    }

    return result;
}

async function main() {
  //1. get the challange
  const challenge = await getChallenge();
  console.log(challenge);

  const CHALLENGE_BUFFER = Buffer.from(challenge.ciphertext, "hex");
  console.log(CHALLENGE_BUFFER);

  //2. create known plaintext - filled with 0000...
  const KNOWN_PLAINTEXT = Buffer.alloc(CHALLENGE_BUFFER.length).toString("hex");
  console.log(KNOWN_PLAINTEXT);

  //3. send known plaintext
  const KEYWORD = "norris";
  let decrypted;

  for(;;) {
    const { ciphertext } = await queryCryptoOracle({
      plaintext: KNOWN_PLAINTEXT
    });

    decrypted = xor(CHALLENGE_BUFFER, Buffer.from(ciphertext, "hex"));

    if(decrypted.toString().toLocaleLowerCase().includes(KEYWORD)){
      break;
    }
  }
  console.log(decrypted.toString());
}

// call the main function
main();