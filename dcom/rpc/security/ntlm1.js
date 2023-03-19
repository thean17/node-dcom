var NTLMKeyFactory = require('./ntlmkeyfactory');
var NtlmFlags = require('./ntlmflags');
const NetworkDataRepresentation = require('../../ndr/networkdatarepresentation');

const PROTECTION_LEVEL_INTEGRITY = 5;
const PROTECTION_LEVEL_PRIVACY = 6;

const NTLMAuthentication = {
  AUTHENTICATION_SERVICE_NTLM: 10,
}

const Security = {
  PROTECTION_LEVEL_PRIVACY: 6,
}

class Ntlm1
{
  constructor(flags, sessionKey, isServer)
  {
    this.NTLM1_VERIFIER_LENGTH = 16;

    this.keyFactory = new NTLMKeyFactory();
    this.isServer = isServer;
    this.protectionLevel = ((flags & NtlmFlags.NTLMSSP_NEGOTIATE_SEAL) != 0) ?
      PROTECTION_LEVEL_PRIVACY : PROTECTION_LEVEL_INTEGRITY;

    // TODO: PORT THIS MISSING FUNCTIONS
    this.clientSigningKey = this.keyFactory.generateClientSigningKeyUsingNegotiatedSecondarySessionKey(sessionKey);
    var clientSealingKey = this.keyFactory.generateClientSealingKeyUsingNegotiatedSecondarySessionKey(sessionKey);

    this.serverSigningKey = this.keyFactory.generateServerSigningKeyUsingNegotiatedSecondarySessionKey(sessionKey);
    var serverSealingKey = this.keyFactory.generateServerSealingKeyUsingNegotiatedSecondarySessionKey(sessionKey);

    this.clientCipher = this.keyFactory.getARCFOUR(Buffer.from(clientSealingKey));
    this.serverCipehr = this.keyFactory.getARCFOUR(Buffer.from(serverSealingKey));

    this.requestCounter = 0;
    this.responseCounter = 0;
  }

  getVerifierLength()
  {
    return this.NTLM1_VERIFIER_LENGTH;
  }

  getAuthenticationService()
  {
    return NTLMAuthentication.AUTHENTICATION_SERVICE_NTLM;
  }

  getProtectionLevel()
  {
    return this.protectionLevel;
  }

  processIncoming(ndr, index, length, verifierIndex, isFragmented)
  {
    try {
      var buffer = ndr.getBuffer();

      var signingKey = null;
      var cipher = null;

      if (!this.isServer) {
        signingKey = this.serverSigningKey;
        cipher = this.serverCipehr;
      } else {
        signingKey = this.clientSigningKey;
        cipher = this.clientCipher;
      }

      var data = [];
      var data_length = 16;
      data.concat(ndr.getBuffer().getBuffer().slice(index, data_length));

      if (this.getProtectionLevel() === Security.PROTECTION_LEVEL_PRIVACY) {
        data = this.applyARC4(data, signingKey)
        var aux = data.slice(0, data.length);
        var aux_i = index;
        while (aux.length > 0) {
          ndr.getBuffer().buf.splice(aux_i, 0, aux.shift());
        }
      }

      var verifier = this.keyFactory.signingPt1(this.responseCounter, signingKey,
        buffer.getBuffer());
      this.keyFactory.signingPt2(verifier, cipher);

      buffer.setIndex(verifierIndex);

      var signing = [];
      ndr.readOctectArray(signing, 0, signing.length);

      if (this.keyFactory.compareSignature(verifier, signing)) {
         throw new Error("Message out of sequence. Perhaps the user being used to run this application is different from the one under which the COM server is running !.");
      }

      this.responseCounter++;
    } catch (err) {
      throw new Error(err);
    }
  }

  /**
   * 
   * @param {NetworkDataRepresentation} ndr 
   * @param {number} index Starting index of the Request payload
   * @param {number} length Lenght of the Request payload
   * @param {number} verifierIndex Starting index of Auth Info
   * @param {boolean} isFragmented 
   */
  processOutgoing(ndr, index, length, verifierIndex, isFragmented)
  {
    try {
      var buffer = ndr.getBuffer();

      var signingKey = null;

      if (this.isServer) {
        signingKey = this.serverSigningKey;
      } else {
        signingKey = this.clientSigningKey;
      }

      var verifier = this.keyFactory.signingPt1(this.requestCounter, signingKey,
        buffer.getBuffer(), verifierIndex);
      var data = ndr.getBuffer().buf.slice(index, index + length);

      if (this.getProtectionLevel() == Security.PROTECTION_LEVEL_PRIVACY) {
        console.log("data: ", data)
        var data2 = this.applyARC4(data, Buffer.from(signingKey));
        console.log("data2: ", data2)

        buffer.replace(data2, index, data2.length);
      }

      verifier = this.signingPt2(Buffer.from(verifier), Buffer.from(signingKey));
      buffer.replace(verifier, verifierIndex, verifier.length);

      this.requestCounter++;
    } catch (e) {
      throw new Error("General error: " + e);
    }
  }

  applyARC4(data, key) {
    const cipher = this.keyFactory.getARCFOUR(key);

    return [...cipher.update(data), ...cipher.final()];
  }

  /**
   * 
   * @param {Array<number>} verifier 
   * @param {Buffer} key
   */
  signingPt2(verifier, key) {
    const buffer = this.applyARC4(verifier.slice(4, 12), key);

    return [...verifier.slice(4), ...buffer]
  }
}

module.exports = Ntlm1;
