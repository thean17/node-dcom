var Crypto = require('crypto');
var HashMap = require('hashmap');
var Responses = require('./responses');

class NTLMKeyFactory
{
  constructor()
  {
	  this.clientSigningMagicConstant = [0x73,0x65,0x73,0x73,0x69,0x6f,0x6e,0x20,0x6b,0x65,0x79,0x20,0x74,0x6f,0x20,0x63,0x6c,0x69,0x65,0x6e,0x74,0x2d,0x74,0x6f,0x2d,0x73,0x65,0x72,0x76,0x65,0x72,0x20,0x73
		,0x69,0x67,0x6e,0x69,0x6e,0x67,0x20,0x6b,0x65,0x79,0x20,0x6d,0x61,0x67,0x69,0x63,0x20,0x63,0x6f,0x6e,0x73,0x74,0x61,0x6e,0x74,0x00];//"session key to client-to-server signing key magic constant";
	  this.serverSigningMagicConstant = [0x73,0x65,0x73,0x73,0x69,0x6f,0x6e,0x20,0x6b,0x65,0x79,0x20,0x74,0x6f,0x20,0x73,0x65,0x72,0x76,0x65,0x72,0x2d,0x74,0x6f,0x2d,0x63,0x6c,0x69,0x65,0x6e,0x74,0x20,0x73
		,0x69,0x67,0x6e,0x69,0x6e,0x67,0x20,0x6b,0x65,0x79,0x20,0x6d,0x61,0x67,0x69,0x63,0x20,0x63,0x6f,0x6e,0x73,0x74,0x61,0x6e,0x74,0x00];//"session key to server-to-client signing key magic constant";
	  this.clientSealingMagicConstant = [0x73,0x65,0x73,0x73,0x69,0x6f,0x6e,0x20,0x6b,0x65,0x79,0x20,0x74,0x6f,0x20,0x63,0x6c,0x69,0x65,0x6e,0x74,0x2d,0x74,0x6f,0x2d,0x73,0x65,0x72,0x76,0x65,0x72,0x20,0x73
		,0x65,0x61,0x6c,0x69,0x6e,0x67,0x20,0x6b,0x65,0x79,0x20,0x6d,0x61,0x67,0x69,0x63,0x20,0x63,0x6f,0x6e,0x73,0x74,0x61,0x6e,0x74,0x00];//"session key to client-to-server sealing key magic constant";
	  this.serverSealingMagicConstant = [0x73,0x65,0x73,0x73,0x69,0x6f,0x6e,0x20,0x6b,0x65,0x79,0x20,0x74,0x6f,0x20,0x73,0x65,0x72,0x76,0x65,0x72,0x2d,0x74,0x6f,0x2d,0x63,0x6c,0x69,0x65,0x6e,0x74,0x20,0x73
		,0x65,0x61,0x6c,0x69,0x6e,0x67,0x20,0x6b,0x65,0x79,0x20,0x6d,0x61,0x67,0x69,0x63,0x20,0x63,0x6f,0x6e,0x73,0x74,0x61,0x6e,0x74,0x00];//"session key to server-to-client sealing key magic constant";
  }

  encryptSecondarySessionKey(plainData, key) {
    var rc4 = Crypto.createCipheriv('rc4', Buffer.from(key), '');

    return [...rc4.update(Buffer.from(plainData))]
  }

  getNTLMUserSessionKey(password)
  {
    var key = [16];
    var ntlmHash = new Responses().ntlmHash(password);
    var md4 = Crypto.createHash('md4');
    md4.update(ntlmHash);
    key = [...md4.digest()];
    return key;
  }

  getNTLMv2UserSessionKey(target, user, password, challenge, blob)
  {
    var key = [16];
    var ntlm2Hash = new Responses().nlmv2Hash(target, user, password);
    var data = [challenge.length + blob.length];

    data.concat(challenge.slice(0, challenge.length));
    var aux = blob.slice(0, blob.length);
    var aux_i = challen.length;
    while (aux.length > 0) {
      data.splice(aux_i++, 0, aux.shift());
    }

    var mac = new Responses().hmacMD5(data, ntlm2Hash);
    key = new Responses().hmacMD5(mac, ntlm2Hash);
    return key;
  }

  getNTLM2SessionResponseUserSessionKey(password, servernonce)
  {
    return new Responses().hmacMD5(servernonce, this.getNTLMUserSessionKey(password));
  }

  getSecondarySessionKey()
  {
    var key = [16];
    key = [...Crypto.randomBytes(16)];
    return key;
  }

  getARCFOUR(key)
  {
    return Crypto.createCipheriv('rc4', key, '' );
  }

  /**
   * 
   * @param {Array<number>} sessionKey 
   */
  generateClientSigningKeyUsingNegotiatedSecondarySessionKey(secondarySessionKey)
  {
    const dataforhash = [...secondarySessionKey, ...this.clientSigningMagicConstant];
    
    const byteArray = new Uint8Array(dataforhash);

    const md5 = Crypto.createHash('md5');

    return [...md5.update(byteArray).digest()]
  }

  /**
   * 
   * @param {Array<number>} sessionKey 
   */
  generateClientSealingKeyUsingNegotiatedSecondarySessionKey(secondarySessionKey)
  {
      const dataforhash = [...secondarySessionKey, ...this.clientSealingMagicConstant];

      const byteArray = new Uint8Array(dataforhash);

      const md5 = Crypto.createHash('md5');

      return [...md5.update(byteArray).digest()]
  }

  /**
   * 
   * @param {Array<number>} sessionKey 
   */
  generateServerSigningKeyUsingNegotiatedSecondarySessionKey(secondarySessionKey)
  {
      const dataforhash = [...secondarySessionKey, ...this.serverSigningMagicConstant];

      const byteArray = new Uint8Array(dataforhash);

      const md5 = Crypto.createHash('md5');

      return [...md5.update(byteArray).digest()]
  }

  /**
   * 
   * @param {Array<number>} sessionKey 
   */
  generateServerSealingKeyUsingNegotiatedSecondarySessionKey(secondarySessionKey)
  {
      const dataforhash = [...secondarySessionKey, this.serverSealingMagicConstant];

      const byteArray = new Uint8Array(dataforhash);

      const md5 = Crypto.createHash('md5');

      return [...md5.update(byteArray).digest()]
  }

  /**
   * 
   * @param {number} sequenceNumber 
   * @param {Array<number>} signingKey 
   * @param {Array<number>} data
   * @param {number} lengthOfBuffer 
   * @returns 
   */
  signingPt1(sequenceNumber, signingKey, data, lengthOfBuffer) {
    const seqNumPlusData = [
      (sequenceNumber & 0xFF),
      ((sequenceNumber >> 8) & 0xFF),
      ((sequenceNumber >> 16) & 0xFF),
      ((sequenceNumber >> 24) & 0xFF),
      ...data.slice(0, lengthOfBuffer)
    ];

    const retval = [
      0x01, //Version number LE 1.
      0x0,
      0x0,
      0x0,
      ...new Responses().hmacMD5(seqNumPlusData, signingKey).slice(0, 8), // System.arraycopy(sign, 0, retval, 4, 8);
      (sequenceNumber & 0xFF),
      ((sequenceNumber >> 8) & 0xFF),
      ((sequenceNumber >> 16) & 0xFF),
      ((sequenceNumber >> 24) & 0xFF)
    ];

    return retval;
  }
}

module.exports = NTLMKeyFactory;