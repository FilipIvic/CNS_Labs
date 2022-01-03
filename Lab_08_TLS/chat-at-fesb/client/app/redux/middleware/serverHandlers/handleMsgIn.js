import { serverMsg } from "app/redux/actions/serverActions.js";
import { JSONparse } from "app/utils/safeJSON.js";
import { clientError } from "app/redux/actions/clientActions.js";
import { loadKey } from "./utils.js";
import CryptoProvider from "../../../services/security/CryptoProvider";
import crypto from "crypto";

export default ({ getState, dispatch }, next, action) => {
  const {
    meta: { serialized }
  } = action;
  if (!serialized) return next(action);

  let msg = JSONparse(action.payload);

  if (Object.is(msg, undefined)) {
    return dispatch(clientError(`JSON.parse error: ${data}`));
  }

  if (msg.id) {
    const { credentials } = getState();

    //===================================================
    // Try to load an encryption key for this client id;
    // please note that this is a remote client.
    //===================================================
    const key = loadKey(msg.id, credentials);

    //===================================================
    // If the encryption key is successfully loaded,
    // it is implied that all incoming messages from this
    // remote client will be encrypted with that key.
    // So, we decrypt the messages before reading them.
    //===================================================
    if (key) {
      const MAC_received = Buffwer.from(msg.authTag, "hex");
      delete msg.authTag;

      const hmac = crypto.createHmac("sha256", key.slice(32));
      const MAC_calculated = hmac.update(JSON.stringify(msg)).digest();

      if(crypto.timingSafeEqual(MAC_received,MAC_calculated)){
        // You should implement anti-replay protection here
        const {plaintext} = CryptoProvider.decrypt("CBC", {
          ciphertext: msg.content,
          key: key.slice(0,32),
          iv: Buffer.from(msg.iv, "hex"),
        });

        msg.content = plaintext;
      } else{
        msg.content = "!!! Message NOT authentic !!!"
      }
    }
  }

  dispatch(serverMsg(msg));
};
