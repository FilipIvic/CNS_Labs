const axios = require("axios");

async function getWordlist() {
  try {
    const response = await axios.get("http://localhost:3000/wordlist.txt");
    return response.data;
  } catch (error) {
    console.error(error.message);
  }
}

async function getChallenge() {
  try {
    const response = await axios.get("http://localhost:3000/cbc/iv/challenge");
    return response.data;
  } catch (error) {
    console.error(error.message);
  }
}

async function queryCryptoOracle({
  url = "http://localhost:3000/cbc/iv",
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

/**
 * Pad the given plaintext according to PKCS#7;
 * please note that this implementation supports
 * only plaintexts of length up to 16 bytes.
 */
function addPadding(plaintext) {
  const pad = 16 - plaintext.length;
  const sourceBuffer = Buffer.from(plaintext);
  const targetBuffer = pad > 0 ? Buffer.alloc(16, pad) : Buffer.alloc(32, 16);
  sourceBuffer.copy(targetBuffer, 0, 0);

  return targetBuffer;
}

/**
 * Increment a 128-bit integer by the given addend;
 * the max addend is MAX_SAFE_INTEGER in JS, i.e., (2^53 - 1).
 * If addend is not provided it defaults to 1.
 */
const MAX_32_INTEGER = Math.pow(2, 32) - 1;

function incrementIv(bigint, addend = 1, offset = 12) {
  // assert(Number.isSafeInteger(addend), "Addend not a safe integer");

  if (offset < 0) return;

  const current = bigint.readUInt32BE(offset);
  const sum = current + addend;

  if (sum <= MAX_32_INTEGER) {
    return bigint.writeUInt32BE(sum, offset);
  }

  const reminder = sum % (MAX_32_INTEGER + 1);
  const carry = Math.floor(sum / MAX_32_INTEGER);

  bigint.writeUInt32BE(reminder, offset);
  incrementIv(bigint, carry, offset - 4);
}

function xor(buf1, buf2) {
    const result = Buffer.alloc(buf1.length);

    for (let i = 0; i < buf1.length; i++) {
        result[i] = buf1[i] ^ buf2[i];
    }

    return result;
}

async function main() {
  // 1. get the wordlist
  const wordlist = (await getWordlist()).split("\n");
  console.log(wordlist);

  // 2. get the challenge -> IV_V, C_V
  const {iv: challengeIV, ciphertext: challengeCiphertext,} = await getChallenge();

  const challengeIVBuffer = Buffer.from(challengeIV, "hex");

  // 3.1. post "00" -> IV_CURRENT, C_CURRENT
  const {iv: currentIV} = await queryCryptoOracle({plaintext: "00"});
  const nextIVBuffer = Buffer.from(currentIV, "hex");

  //3. for (word of wordlist)
  for (word of wordlist) {
    console.log("Testing: " + word);

    // 3.2. IV_NEXT = IV_CURRENT + 4
    incrementIv(nextIVBuffer, 4);
    console.log(nextIVBuffer);

    // 3.3. p_A = addPadding(word) XOR IV_V XOR IV_NEXT
    const paddedWordBuffer = addPadding(word);
    console.log(paddedWordBuffer);
    
    const plaintextBuffer = xor (xor(paddedWordBuffer, challengeIVBuffer), nextIVBuffer);
    console.log(plaintextBuffer);

    // 3.4. post p_A -> IV_A, C_A  (IV_A = IV_NEXT)
    const data = await queryCryptoOracle({plaintext: plaintextBuffer.toString("hex")});
    console.log(data);

    // 3.5. if (C_V == C_A.slice(0,32)) output word; break
    if (challengeCiphertext == data.ciphertext.slice(0, 32)){
        console.log(`The secret challenge word: "${word}"`);
        break;
    }
  }
}

// call the main function
main();