const axios = require("axios");

// Async function with optional arguments; if arguments omitted use the provided default values
async function queryCryptoOracle({
  url = "http://localhost:3000/ecb",
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

let cookie = "";
const ALPHABET = "abcdefghijklmnopqrstuvwxyz";

// Multiple sequential oracle queries
async function main() {
  for (let count = 0; count < 16; count++) {
    let data = await queryCryptoOracle({ plaintext: "x".repeat(15 - count) });
    let ciphertext = data.ciphertext.slice(0, 32);

    for (let char of ALPHABET) {
      // console.log("Testing character: " + char);
      data = await queryCryptoOracle({
        plaintext: "x".repeat(15 - count) + cookie + char,
      });
      let ciphertext_char = data.ciphertext.slice(0, 32);

      if (ciphertext === ciphertext_char) {
        cookie = cookie + char;
        console.log("Current cookie: " + cookie);
        break;
      }
    }
  }
}

// call the main function
main();
