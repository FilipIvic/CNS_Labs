// Info: config is an alias to "config/default.json" file
// (the alias is set in webpack.config.js).
import { Constants } from "config";
import crypto from "crypto";
import serverAPI from "app/services/server-api/ServerAPI.js";
import { msgSent } from "app/redux/actions/clientActions.js";
import { loadKey } from "./utils.js";
import CryptoProvider from "../../../services/security/CryptoProvider"

const { MsgType } = Constants;

export default ({ getState, dispatch }, next, action) => {
  const {
    meta: { wrapped },
  } = action;
  if (wrapped) return next(action);

  const {
    client: { nickname, id },
    credentials,
  } = getState();

  //===================================================
  // Try to load an encryption key for this client id
  //===================================================
  const key = loadKey(id, credentials);

  //===================================================
  // If the encryption key is successfully loaded,
  // it is implied that all outgoing messages from this
  // client will be encrypted with that key.
  //===================================================
  const msg_in_plaintext = {
    type: MsgType.BROADCAST,
    id,
    nickname,
    timestamp: Date.now(),
    content: key ? `ENCRYPTED(${action.payload})` : action.payload,
  };

  const msg = {...msg_in_plaintext}

  if (key){
    const {iv, ciphertext} = CryptoProvider.encrypt("CBC", {
      key: key.slice(0,32),
      iv: crypto.randomBytes(16),
      plaintext: action.payload
    });

    const hmac = crypto.createHmac("sha256", key.slice(32));
    msg.content = ciphertext;
    msg.iv = iv;
    msg.authTag = hmac.update(JSON.stringify(msg)).digest("hex");
  }

  //===================================================
  // The resulting protected (CBC + HMAC) message
  // might look something like shown below:
  //
  //   msg = {
  //     type: "4",
  //     id: "3261434470825227",
  //     nickname: "Alice",
  //     timestamp: 1593720594459,
  //     content: "c850fcee1c9c7c3ee9c4fd4a621eda18057cce3f2eb5261e",
  //     iv: "2a24b323a7dc1c6dc31ab216d576d59f",
  //     authTag: "d3dc95ec39457edb366c19b4ad926638"
  //   }
  //====================================================

  serverAPI.send(msg).then(dispatch(msgSent(msg_in_plaintext)));
};
